//! **meshd** — the v2 multi-mesh control-plane daemon (`docs/MESH_V2.md`).
//!
//! Holds this computer's meshes and serves the v2 IPC (`lattice_mesh::ipc`) over a
//! unix socket. Backed by the REAL membership engine (`lattice_mesh::membership`):
//! each mesh has a master keypair, members are admitted via **signed certs**, and
//! the roster is the set of certs that validly chain to the master. The discovery
//! "where" (endpoints) and the data plane arrive later. State is in-memory.

use std::collections::HashSet;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use lattice_mesh::charter::{GenesisCharter, InviteTopology, RecipherTrigger};
use lattice_mesh::crypto::suite;
use lattice_mesh::dataplane::MeshDataPlane;
use lattice_mesh::ipc::{MemberView, MeshDetail, MeshSummary, PolicyView, Request, Response};
use lattice_mesh::membership::{valid_members, Cert, MasterKey, MemberKey, PubKey};
use lattice_mesh::Mesh;
use lattice_proto::wire_v2::{MemberId, MeshId};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

const DEFAULT_SOCKET: &str = "/tmp/lattice-meshd.sock";

/// One mesh plus the real trust state for it.
struct MeshState {
    mesh: Mesh,
    /// The mesh's root of trust. We created the mesh, so we hold the master key
    /// (the creator). Its private half never leaves this node.
    master: MasterKey,
    /// This node's own member keypair in this mesh.
    my_key: MemberKey,
    /// Every known cert. The roster = those that validly chain to the master.
    certs: Vec<Cert>,
    /// The mesh's shared symmetric secret (epoch 0) — keys the data-plane cipher.
    #[allow(dead_code)] // read once the run loop spawns (P6.3c)
    secret: [u8; 32],
    /// The per-mesh data plane (framing + crypto). Built now; dormant until P6.3c
    /// gives it a real TUN + transport.
    #[allow(dead_code)]
    dataplane: MeshDataPlane,
}

impl MeshState {
    fn topology(&self) -> InviteTopology {
        self.mesh.charter.invite
    }
    /// The validated roster (certs chaining to the master), id-sorted.
    fn roster(&self) -> Vec<Cert> {
        let mut v: Vec<Cert> =
            valid_members(&self.mesh.charter.master_pubkey, &self.certs, self.topology())
                .into_iter()
                .cloned()
                .collect();
        v.sort_by_key(|c| c.id);
        v
    }
    /// This node's in-mesh id (from its own cert).
    fn my_id(&self) -> MemberId {
        let me = self.my_key.pubkey();
        self.certs.iter().find(|c| c.member == me).map(|c| c.id).unwrap_or(0)
    }
}

#[derive(Default)]
struct State {
    meshes: HashMap<MeshId, MeshState>,
    /// The mesh currently selected for egress (the §1 cur-mesh).
    current: Option<MeshId>,
    /// Whether the data-plane mode is on (`DATA_PLANE=1`). For P6.3a it only marks
    /// intent + logs; the TUN/transport run loop spawns at P6.3c.
    data_plane: bool,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let socket = std::env::args().nth(1).unwrap_or_else(|| DEFAULT_SOCKET.to_string());
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)?;
    eprintln!("meshd: listening on {socket}");

    let state = Arc::new(Mutex::new(State::default()));
    let data_plane = matches!(std::env::var("DATA_PLANE").as_deref(), Ok("1"));
    state.lock().unwrap().data_plane = data_plane;
    eprintln!(
        "meshd: data-plane mode {}",
        if data_plane {
            "ON (per-mesh dataplane built; run loop spawns at P6.3c)"
        } else {
            "off"
        }
    );
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
        Request::CreateMesh { name, my_name, max_members } => {
            create_mesh(st, name, my_name, max_members)
        }

        Request::ListMeshes => {
            let cur = st.current;
            let mut meshes: Vec<MeshSummary> = st
                .meshes
                .values()
                .map(|ms| MeshSummary {
                    id: ms.mesh.id,
                    name: ms.mesh.name.clone(),
                    members: ms.roster().len(),
                    epoch: ms.mesh.epoch,
                    exit: ms.mesh.exit,
                    is_current: cur == Some(ms.mesh.id),
                })
                .collect();
            meshes.sort_by_key(|s| s.id);
            Response::Meshes(meshes)
        }

        Request::MeshInfo { mesh } => match st.meshes.get(&mesh) {
            Some(ms) => Response::Mesh(detail(ms)),
            None => no_mesh(mesh),
        },

        Request::AdmitMember { mesh, name, pubkey_hex } => {
            let pubkey = match parse_hex32(&pubkey_hex) {
                Some(p) => p,
                None => return Response::Error { message: "pubkey must be 64 hex chars".into() },
            };
            let ms = match st.meshes.get_mut(&mesh) {
                Some(m) => m,
                None => return no_mesh(mesh),
            };
            let roster = ms.roster();
            if roster.len() >= ms.mesh.charter.max_members as usize {
                return Response::Error {
                    message: format!("mesh is full (max {})", ms.mesh.charter.max_members),
                };
            }
            if roster.iter().any(|c| c.member == pubkey) {
                return Response::Error { message: "already a member".into() };
            }
            let used: HashSet<MemberId> = roster.iter().map(|c| c.id).collect();
            let id = match (1u8..=254).find(|i| !used.contains(i)) {
                Some(i) => i,
                None => return Response::Error { message: "no free member id".into() },
            };
            // The master (held by this node) issues the cert binding the member.
            let cert = ms.master.issue(pubkey, id, &name, now_ms());
            ms.certs.push(cert);
            Response::Ok
        }

        Request::SetExit { mesh, exit } => {
            let ok = match st.meshes.get_mut(&mesh) {
                Some(ms) => {
                    if let Some(e) = exit {
                        if !ms.roster().iter().any(|c| c.id == e) {
                            return Response::Error {
                                message: format!("no member {e} in mesh {mesh}"),
                            };
                        }
                    }
                    ms.mesh.exit = exit;
                    true
                }
                None => false,
            };
            if !ok {
                return no_mesh(mesh);
            }
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
            Some(id) => match st.meshes.get(&id) {
                Some(ms) if ms.mesh.exit.is_some() => {
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
            if st.meshes.remove(&mesh).is_some() {
                if st.current == Some(mesh) {
                    st.current = None;
                }
                Response::Ok
            } else {
                no_mesh(mesh)
            }
        }

        Request::GetPolicy => {
            let default = match st.current.and_then(|id| st.meshes.get(&id)) {
                Some(ms) => match ms.mesh.exit {
                    Some(e) => format!("via mesh {} exit {}", ms.mesh.id, e),
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
    let id = match (1u8..=255).find(|id| !st.meshes.contains_key(id)) {
        Some(id) => id,
        None => {
            return Response::Error {
                message: "too many meshes on this computer (max 255)".into(),
            }
        }
    };
    let master = MasterKey::generate();
    let my_key = MemberKey::generate();
    let charter = GenesisCharter {
        master_pubkey: master.network(),
        invite: InviteTopology::OpenChain,
        trigger: RecipherTrigger::Quorum { k: 2 },
        max_members,
        initial_cipher: "noise-ik-chachapoly".into(),
        overlay_prefix: [100, 80],
    };
    if let Err(e) = charter.validate() {
        return Response::Error { message: e.to_string() };
    }
    // The creator is member #1, with a master-signed cert.
    let cert = master.issue(my_key.pubkey(), 1, &my_name, now_ms());
    // The mesh's shared symmetric secret + its per-mesh data plane (dormant until
    // the run loop spawns, P6.3c).
    let prefix = charter.overlay_prefix;
    let cipher_name = charter.initial_cipher.clone();
    let secret: [u8; 32] = rand::random();
    let dataplane = MeshDataPlane::new(id, 1, prefix, suite(&cipher_name, &secret, 0));
    let mesh = Mesh::new(id, name, charter, 1);
    if st.data_plane {
        eprintln!(
            "meshd: data-plane built for mesh {id} (overlay {}.{}.{id}.1)",
            prefix[0], prefix[1]
        );
    }
    st.meshes.insert(
        id,
        MeshState {
            mesh,
            master,
            my_key,
            certs: vec![cert],
            secret,
            dataplane,
        },
    );
    Response::MeshCreated { mesh: id }
}

fn detail(ms: &MeshState) -> MeshDetail {
    let me = ms.my_key.pubkey();
    let members: Vec<MemberView> = ms
        .roster()
        .iter()
        .map(|c| MemberView {
            id: c.id,
            name: c.name.clone(),
            pubkey_fp: fp(&c.member),
            is_me: c.member == me,
        })
        .collect();
    let ch = &ms.mesh.charter;
    MeshDetail {
        id: ms.mesh.id,
        name: ms.mesh.name.clone(),
        epoch: ms.mesh.epoch,
        me: ms.my_id(),
        exit: ms.mesh.exit,
        invite: format!("{:?}", ch.invite),
        trigger: format!("{:?}", ch.trigger),
        max_members: ch.max_members,
        cipher: ch.initial_cipher.clone(),
        members,
    }
}

fn no_mesh(id: MeshId) -> Response {
    Response::Error { message: format!("no mesh {id}") }
}

fn fp(pk: &PubKey) -> String {
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
