//! **meshd** — the v2 multi-mesh control-plane daemon (`docs/MESH_V2.md`).
//!
//! Holds this computer's meshes and serves the v2 IPC (`lattice_mesh::ipc`) over a
//! unix socket. Backed by the REAL membership engine (`lattice_mesh::membership`):
//! each mesh has a master keypair, members are admitted via **signed certs**, and
//! the roster is the set of certs that validly chain to the master.
//!
//! With `DATA_PLANE=1` (and root for the TUN) each mesh also runs a live data-plane
//! loop (`lattice_meshrun::run`): a per-mesh TUN + UDP socket carrying sealed
//! packets. The loop shares a peer table + exit selection with this control plane,
//! so the IPC reports live endpoints/liveness (P6.3d) and steers egress live.

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use lattice_mesh::charter::{GenesisCharter, InviteTopology, RecipherTrigger};
use lattice_mesh::crypto::suite;
use lattice_mesh::dataplane::MeshDataPlane;
use lattice_mesh::ipc::{MemberView, MeshDetail, MeshSummary, PolicyView, Request, Response};
use lattice_mesh::membership::{valid_members, Cert, MasterKey, MemberKey, PubKey};
use lattice_mesh::Mesh;
use lattice_meshrun::{seed_links, Link, PeerLinks, SharedExit};
use lattice_net::udp::UdpTransport;
use lattice_proto::wire_v2::{MemberId, MeshId};
use lattice_proto::VirtualIp;
use lattice_tun::{open as tun_open, TunConfig};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

const DEFAULT_SOCKET: &str = "/tmp/lattice-meshd.sock";
/// A member is "live" if heard from within this window.
const LIVE_WINDOW_MS: u64 = 30_000;
/// Per-mesh UDP base port (mesh id is added).
const UDP_BASE_PORT: u16 = 42000;
/// Overlay MTU for meshd-run data planes (matches meshrun's conservative default).
const OVERLAY_MTU: u16 = 1280;

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
    /// Held for future rekey / re-bringup / distribution to joiners (keydist).
    #[allow(dead_code)]
    secret: [u8; 32],
    /// Live peer table, shared with this mesh's data-plane loop (endpoints +
    /// last-seen). Empty until peers are seeded (SetPeer) or heard from.
    links: PeerLinks,
    /// The egress member, shared with the loop so SetExit steers it live.
    exit_sel: SharedExit,
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
    /// Whether to spawn data-plane loops (`DATA_PLANE=1`).
    data_plane: bool,
}

/// Everything `bringup_dataplane` needs to spawn a mesh's live loop — built inside
/// the locked handler, executed (async TUN/UDP open) after the lock is released.
struct Bringup {
    mesh_id: MeshId,
    my_id: MemberId,
    prefix: [u8; 2],
    secret: [u8; 32],
    cipher: String,
    links: PeerLinks,
    exit_sel: SharedExit,
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
        if data_plane { "ON (per-mesh TUN+UDP loops; needs root)" } else { "off" }
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
                    Ok(req) => {
                        // Handle under the lock; do any async data-plane bringup AFTER
                        // releasing it (TUN/UDP open is async and must not block IPC).
                        let (resp, bringup) = {
                            let mut st = state.lock().unwrap();
                            handle(req, &mut st)
                        };
                        if let Some(b) = bringup {
                            bringup_dataplane(b).await;
                        }
                        resp
                    }
                    Err(e) => Response::Error { message: format!("bad request: {e}") },
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

/// Open the per-mesh TUN + UDP and spawn the data-plane loop. Failures (e.g. no
/// root for the TUN) are logged and non-fatal: meshd keeps serving the control
/// plane. The `links`/`exit_sel` handles are shared with [`MeshState`].
async fn bringup_dataplane(b: Bringup) {
    let overlay = Ipv4Addr::new(b.prefix[0], b.prefix[1], b.mesh_id, b.my_id);
    let tun = match tun_open(TunConfig {
        address: VirtualIp(overlay),
        prefix_len: 24,
        mtu: OVERLAY_MTU,
    })
    .await
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!("meshd: data-plane TUN open failed for mesh {} (need root?): {e}", b.mesh_id);
            return;
        }
    };
    let bind = SocketAddr::from(([0, 0, 0, 0], UDP_BASE_PORT.wrapping_add(b.mesh_id as u16)));
    let transport = match UdpTransport::bind(bind).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("meshd: data-plane UDP bind {bind} failed for mesh {}: {e}", b.mesh_id);
            return;
        }
    };
    let dp = MeshDataPlane::new(b.mesh_id, b.my_id, b.prefix, suite(&b.cipher, &b.secret, 0));
    eprintln!("meshd: data-plane LIVE for mesh {} — overlay {overlay}/24, udp {bind}", b.mesh_id);
    tokio::spawn(lattice_meshrun::run(dp, tun, transport, b.links, b.exit_sel));
}

fn handle(req: Request, st: &mut State) -> (Response, Option<Bringup>) {
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
            (Response::Meshes(meshes), None)
        }

        Request::MeshInfo { mesh } => match st.meshes.get(&mesh) {
            Some(ms) => (Response::Mesh(detail(ms)), None),
            None => (no_mesh(mesh), None),
        },

        Request::AdmitMember { mesh, name, pubkey_hex } => {
            let pubkey = match parse_hex32(&pubkey_hex) {
                Some(p) => p,
                None => return (err("pubkey must be 64 hex chars"), None),
            };
            let ms = match st.meshes.get_mut(&mesh) {
                Some(m) => m,
                None => return (no_mesh(mesh), None),
            };
            let roster = ms.roster();
            if roster.len() >= ms.mesh.charter.max_members as usize {
                return (err(&format!("mesh is full (max {})", ms.mesh.charter.max_members)), None);
            }
            if roster.iter().any(|c| c.member == pubkey) {
                return (err("already a member"), None);
            }
            let used: HashSet<MemberId> = roster.iter().map(|c| c.id).collect();
            let id = match (1u8..=254).find(|i| !used.contains(i)) {
                Some(i) => i,
                None => return (err("no free member id"), None),
            };
            // The master (held by this node) issues the cert binding the member.
            let cert = ms.master.issue(pubkey, id, &name, now_ms());
            ms.certs.push(cert);
            (Response::Ok, None)
        }

        Request::SetExit { mesh, exit } => {
            let ok = match st.meshes.get_mut(&mesh) {
                Some(ms) => {
                    if let Some(e) = exit {
                        if !ms.roster().iter().any(|c| c.id == e) {
                            return (err(&format!("no member {e} in mesh {mesh}")), None);
                        }
                    }
                    ms.mesh.exit = exit;
                    // Steer the live data-plane loop's egress.
                    *ms.exit_sel.lock().unwrap() = exit;
                    true
                }
                None => false,
            };
            if !ok {
                return (no_mesh(mesh), None);
            }
            if exit.is_none() && st.current == Some(mesh) {
                st.current = None;
            }
            (Response::Ok, None)
        }

        Request::SetPeer { mesh, member, endpoint } => {
            let addr: SocketAddr = match endpoint.parse() {
                Ok(a) => a,
                Err(_) => return (err(&format!("bad endpoint '{endpoint}' (want ip:port)")), None),
            };
            match st.meshes.get(&mesh) {
                Some(ms) => {
                    ms.links
                        .lock()
                        .unwrap()
                        .insert(member, Link { endpoint: addr, last_seen_ms: 0 });
                    (Response::Ok, None)
                }
                None => (no_mesh(mesh), None),
            }
        }

        Request::SetCurrent { mesh } => match mesh {
            None => {
                st.current = None;
                (Response::Ok, None)
            }
            Some(id) => match st.meshes.get(&id) {
                Some(ms) if ms.mesh.exit.is_some() => {
                    st.current = Some(id);
                    (Response::Ok, None)
                }
                Some(_) => (err(&format!("set an exit for mesh {id} before making it current")), None),
                None => (no_mesh(id), None),
            },
        },

        Request::RemoveMesh { mesh } => {
            if st.meshes.remove(&mesh).is_some() {
                if st.current == Some(mesh) {
                    st.current = None;
                }
                (Response::Ok, None)
            } else {
                (no_mesh(mesh), None)
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
            (Response::Policy(PolicyView { default, current_mesh: st.current }), None)
        }
    }
}

fn create_mesh(
    st: &mut State,
    name: String,
    my_name: String,
    max_members: u8,
) -> (Response, Option<Bringup>) {
    let id = match (1u8..=255).find(|id| !st.meshes.contains_key(id)) {
        Some(id) => id,
        None => return (err("too many meshes on this computer (max 255)"), None),
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
        return (err(&e.to_string()), None);
    }
    // The creator is member #1, with a master-signed cert.
    let cert = master.issue(my_key.pubkey(), 1, &my_name, now_ms());
    let prefix = charter.overlay_prefix;
    let cipher = charter.initial_cipher.clone();
    let secret: [u8; 32] = rand::random();
    let links = seed_links(HashMap::new());
    let exit_sel: SharedExit = Arc::new(Mutex::new(None));
    let mesh = Mesh::new(id, name, charter, 1);
    // If data-plane mode is on, ask the async caller to bring up this mesh's loop
    // (sharing the same links/exit handles we store below).
    let bringup = st.data_plane.then(|| Bringup {
        mesh_id: id,
        my_id: 1,
        prefix,
        secret,
        cipher,
        links: Arc::clone(&links),
        exit_sel: Arc::clone(&exit_sel),
    });
    st.meshes.insert(
        id,
        MeshState { mesh, master, my_key, certs: vec![cert], secret, links, exit_sel },
    );
    (Response::MeshCreated { mesh: id }, bringup)
}

fn detail(ms: &MeshState) -> MeshDetail {
    let me = ms.my_key.pubkey();
    let now = now_ms();
    let links = ms.links.lock().unwrap();
    let members: Vec<MemberView> = ms
        .roster()
        .iter()
        .map(|c| {
            let is_me = c.member == me;
            let link = links.get(&c.id).copied();
            let endpoint = link.map(|l| l.endpoint.to_string());
            let state = if is_me {
                "me".to_string()
            } else {
                match link {
                    Some(l) if l.last_seen_ms != 0 && now.saturating_sub(l.last_seen_ms) < LIVE_WINDOW_MS => {
                        "live".into()
                    }
                    Some(_) => "idle".into(),
                    None => "unknown".into(),
                }
            };
            MemberView { id: c.id, name: c.name.clone(), pubkey_fp: fp(&c.member), is_me, endpoint, state }
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

fn err(message: &str) -> Response {
    Response::Error { message: message.to_string() }
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
