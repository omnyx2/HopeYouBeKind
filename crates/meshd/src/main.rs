//! **meshd** — the v2 multi-mesh control-plane daemon (`docs/MESH_V2.md`).
//!
//! Holds this computer's [`MeshContainer`] and serves the v2 IPC
//! ([`lattice_mesh::ipc`]) over a unix socket: create / inspect / select meshes.
//! This is the **control plane only** — there is no data plane yet (no TUN demux,
//! per-mesh crypto, or discovery), so packets do not flow; the GUI can already
//! show real mesh state, create meshes, populate rosters, and pick exits.
//!
//! State is in-memory (lost on restart). Master keypairs are **placeholders**
//! (random bytes) until the membership/crypto core lands.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use lattice_mesh::charter::{GenesisCharter, InviteTopology, RecipherTrigger};
use lattice_mesh::ipc::{MemberView, MeshDetail, MeshSummary, PolicyView, Request, Response};
use lattice_mesh::{Member, Mesh, MeshContainer};
use lattice_proto::wire_v2::MeshId;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

const DEFAULT_SOCKET: &str = "/tmp/lattice-meshd.sock";

#[derive(Default)]
struct State {
    container: MeshContainer,
    /// Creator-held master private keys (placeholder bytes for now), per mesh.
    masters: HashMap<MeshId, [u8; 32]>,
    /// The mesh currently selected for egress (the §1 cur-mesh).
    current: Option<MeshId>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let socket = std::env::args().nth(1).unwrap_or_else(|| DEFAULT_SOCKET.to_string());
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)?;
    eprintln!("meshd: listening on {socket}");

    let state = Arc::new(Mutex::new(State::default()));
    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let (rd, mut wr) = stream.into_split();
            let mut lines = BufReader::new(rd).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.trim().is_empty() {
                    continue;
                }
                let resp = match serde_json::from_str::<Request>(&line) {
                    Ok(req) => handle(req, &mut state.lock().unwrap()),
                    Err(e) => Response::Error {
                        message: format!("bad request: {e}"),
                    },
                };
                let mut out = serde_json::to_string(&resp).unwrap_or_else(|_| {
                    "{\"Error\":{\"message\":\"encode failed\"}}".to_string()
                });
                out.push('\n');
                if wr.write_all(out.as_bytes()).await.is_err() {
                    break;
                }
            }
        });
    }
}

fn handle(req: Request, st: &mut State) -> Response {
    match req {
        Request::CreateMesh {
            name,
            my_name,
            max_members,
        } => create_mesh(st, name, my_name, max_members),

        Request::ListMeshes => {
            let cur = st.current;
            let mut meshes: Vec<MeshSummary> = st
                .container
                .iter()
                .map(|m| MeshSummary {
                    id: m.id,
                    name: m.name.clone(),
                    members: m.roster.len(),
                    epoch: m.epoch,
                    exit: m.exit,
                    is_current: cur == Some(m.id),
                })
                .collect();
            meshes.sort_by_key(|s| s.id);
            Response::Meshes(meshes)
        }

        Request::MeshInfo { mesh } => match st.container.get(mesh) {
            Some(m) => Response::Mesh(detail(m)),
            None => no_mesh(mesh),
        },

        Request::AdmitMember {
            mesh,
            name,
            pubkey_hex,
        } => {
            let pubkey = match parse_hex32(&pubkey_hex) {
                Some(p) => p,
                None => {
                    return Response::Error {
                        message: "pubkey must be 64 hex chars".into(),
                    }
                }
            };
            match st.container.get_mut(mesh) {
                Some(m) => {
                    let max = m.charter.max_members;
                    match m.roster.admit(Member { name, pubkey }, max) {
                        Ok(_) => Response::Ok,
                        Err(e) => Response::Error {
                            message: e.to_string(),
                        },
                    }
                }
                None => no_mesh(mesh),
            }
        }

        Request::SetExit { mesh, exit } => {
            let ok = match st.container.get_mut(mesh) {
                Some(m) => {
                    if let Some(e) = exit {
                        if !m.roster.contains(e) {
                            return Response::Error {
                                message: format!("no member {e} in mesh {mesh}"),
                            };
                        }
                    }
                    m.exit = exit;
                    true
                }
                None => false,
            };
            if !ok {
                return no_mesh(mesh);
            }
            // A current mesh with no exit can't egress — drop the selection.
            if exit.is_none() && st.current == Some(mesh) {
                st.current = None;
            }
            Response::Ok
        }

        Request::SetCurrent { mesh } => match mesh {
            None => {
                st.current = None;
                Response::Ok
            }
            Some(id) => match st.container.get(id) {
                Some(m) if m.exit.is_some() => {
                    st.current = Some(id);
                    Response::Ok
                }
                Some(_) => Response::Error {
                    message: format!("set an exit for mesh {id} before making it current"),
                },
                None => no_mesh(id),
            },
        },

        Request::RemoveMesh { mesh } => {
            if st.container.remove(mesh).is_some() {
                st.masters.remove(&mesh);
                if st.current == Some(mesh) {
                    st.current = None;
                }
                Response::Ok
            } else {
                no_mesh(mesh)
            }
        }

        Request::GetPolicy => {
            let default = match st.current.and_then(|id| st.container.get(id)) {
                Some(m) => match m.exit {
                    Some(e) => format!("via mesh {} exit {}", m.id, e),
                    None => "direct".into(),
                },
                None => "direct".into(),
            };
            Response::Policy(PolicyView {
                default,
                current_mesh: st.current,
            })
        }
    }
}

fn create_mesh(st: &mut State, name: String, my_name: String, max_members: u8) -> Response {
    let id = match (1u8..=255).find(|id| st.container.get(*id).is_none()) {
        Some(id) => id,
        None => {
            return Response::Error {
                message: "too many meshes on this computer (max 255)".into(),
            }
        }
    };
    // Placeholder keypairs — real keygen lands with the membership/crypto core.
    let master_pubkey: [u8; 32] = rand::random();
    let master_priv: [u8; 32] = rand::random();
    let creator_pubkey: [u8; 32] = rand::random();

    let charter = GenesisCharter {
        master_pubkey,
        invite: InviteTopology::OpenChain,
        trigger: RecipherTrigger::Quorum { k: 2 },
        max_members,
        initial_cipher: "noise-ik-chachapoly".into(),
        overlay_prefix: [100, 80],
    };
    if let Err(e) = charter.validate() {
        return Response::Error {
            message: e.to_string(),
        };
    }

    let mut mesh = Mesh::new(id, name, charter, 1);
    // The creator joins as member #1.
    if let Err(e) = mesh.roster.admit(
        Member {
            name: my_name,
            pubkey: creator_pubkey,
        },
        max_members,
    ) {
        return Response::Error {
            message: e.to_string(),
        };
    }
    st.container.add(mesh);
    st.masters.insert(id, master_priv);
    Response::MeshCreated { mesh: id }
}

fn detail(m: &Mesh) -> MeshDetail {
    let mut members: Vec<MemberView> = m
        .roster
        .iter()
        .map(|(id, mem)| MemberView {
            id,
            name: mem.name.clone(),
            pubkey_fp: fp(&mem.pubkey),
            is_me: id == m.me,
        })
        .collect();
    members.sort_by_key(|x| x.id);
    MeshDetail {
        id: m.id,
        name: m.name.clone(),
        epoch: m.epoch,
        me: m.me,
        exit: m.exit,
        invite: format!("{:?}", m.charter.invite),
        trigger: format!("{:?}", m.charter.trigger),
        max_members: m.charter.max_members,
        cipher: m.charter.initial_cipher.clone(),
        members,
    }
}

fn no_mesh(id: MeshId) -> Response {
    Response::Error {
        message: format!("no mesh {id}"),
    }
}

fn fp(pk: &[u8; 32]) -> String {
    pk[..4].iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
