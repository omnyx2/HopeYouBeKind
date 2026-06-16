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
use lattice_mesh::ipc::{
    InviteBlob, MemberView, MeshDetail, MeshSummary, PolicyView, Request, Response,
};
use lattice_mesh::keydist::{seal_secret, EncKey};
use lattice_mesh::membership::{valid_members, Cert, MasterKey, MemberKey, PubKey};
use lattice_mesh::Mesh;
use lattice_meshrun::{seed_links, Link, PeerLinks, SharedEndpoint, SharedExit};
use lattice_net::udp::UdpTransport;
use lattice_proto::wire_v2::{MemberId, MeshId};
use lattice_proto::VirtualIp;
use lattice_tun::{open as tun_open, TunConfig};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

#[allow(dead_code)] // ported from v1: some restore/disable paths aren't wired yet.
mod exit; // OS plumbing for full-tunnel egress (client routes + exit NAT), from v1.

/// Where meshd listens for the GUI/CLI. A unix domain socket on macOS/Linux; a
/// named pipe on Windows — same newline-JSON protocol either way.
#[cfg(unix)]
const DEFAULT_SOCKET: &str = "/tmp/lattice-meshd.sock";
#[cfg(windows)]
const DEFAULT_SOCKET: &str = r"\\.\pipe\lattice-meshd";
/// Public resolver used for full-tunnel DNS (routed through the exit).
const FULL_TUNNEL_DNS: &str = "1.1.1.1";
/// A member is "live" if heard from within this window.
const LIVE_WINDOW_MS: u64 = 30_000;
/// Per-mesh UDP base port (mesh id is added).
const UDP_BASE_PORT: u16 = 42000;
/// Overlay MTU for meshd-run data planes (matches meshrun's conservative default).
const OVERLAY_MTU: u16 = 1280;

/// One mesh plus the real trust state for it.
struct MeshState {
    mesh: Mesh,
    /// The mesh's root of trust. `Some` only on the creator (it holds the master
    /// key and can issue invites); a joiner installs the mesh with `None`.
    master: Option<MasterKey>,
    /// This node's own member keypair in this mesh.
    my_key: MemberKey,
    /// This node's encryption key in this mesh (receives sealed secrets — rekeys).
    #[allow(dead_code)]
    my_enc: EncKey,
    /// Every known cert. The roster = those that validly chain to the master.
    certs: Vec<Cert>,
    /// The mesh's shared symmetric secret (epoch 0) — keys the data-plane cipher.
    /// Held for rekey / re-bringup / sealing to joiners (keydist).
    secret: [u8; 32],
    /// Live peer table, shared with this mesh's data-plane loop (endpoints +
    /// last-seen). Empty until peers are seeded (SetPeer) or heard from.
    links: PeerLinks,
    /// The egress member, shared with the loop so SetExit steers it live.
    exit_sel: SharedExit,
    /// The OS interface name of this mesh's TUN (set at bringup) — needed to divert
    /// the default route for full-tunnel egress.
    tun_name: Option<String>,
    /// This node's own advertised data-plane endpoint (`ip:port`), shared with the
    /// run loop. Set at bringup; the loop upgrades it to our public address when a
    /// public peer reflects it (P-D3). Read by CreateInvite to hand joiners (P-D1).
    my_endpoint: SharedEndpoint,
    /// This mesh's local data-plane UDP port (set at bringup; 0 = not up). Advertised
    /// in the LAN beacon so same-router peers reach us directly (P-D4).
    dp_port: u16,
    /// Abort handle for this mesh's data-plane loop (set at bringup). `RemoveMesh`
    /// aborts it so the loop's future is dropped, freeing its TUN + UDP socket —
    /// otherwise the port leaks and a re-created mesh can't bind it.
    dp_task: Option<tokio::task::AbortHandle>,
}

impl MeshState {
    fn topology(&self) -> InviteTopology {
        self.mesh.charter.invite
    }
    /// The validated roster (certs chaining to the master), id-sorted.
    fn roster(&self) -> Vec<Cert> {
        let mut v: Vec<Cert> = valid_members(
            &self.mesh.charter.master_pubkey,
            &self.certs,
            self.topology(),
        )
        .into_iter()
        .cloned()
        .collect();
        v.sort_by_key(|c| c.id);
        v
    }
    /// This node's in-mesh id (from its own cert).
    fn my_id(&self) -> MemberId {
        let me = self.my_key.pubkey();
        self.certs
            .iter()
            .find(|c| c.member == me)
            .map(|c| c.id)
            .unwrap_or(0)
    }
}

#[derive(Default)]
struct State {
    meshes: HashMap<MeshId, MeshState>,
    /// The mesh currently selected for egress (the §1 cur-mesh).
    current: Option<MeshId>,
    /// Whether to spawn data-plane loops (`DATA_PLANE=1`).
    data_plane: bool,
    /// Freshly minted identities (member + enc keypair) awaiting an invite, keyed
    /// by member public key. Drained when `JoinMesh` consumes one.
    pending: HashMap<PubKey, (MemberKey, EncKey)>,
}

/// Work the IPC handler defers to the async caller (it can't `.await` or spawn
/// under the state lock): data-plane bringup, or arming the full-tunnel watchdog.
enum PostAction {
    Bringup(Bringup),
    /// Full tunnel just went up for this mesh — start the kill-switch.
    ArmKillSwitch(MeshId),
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
    my_endpoint: SharedEndpoint,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let socket = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_SOCKET.to_string());

    let state = Arc::new(Mutex::new(State::default()));
    let data_plane = matches!(std::env::var("DATA_PLANE").as_deref(), Ok("1"));
    state.lock().unwrap().data_plane = data_plane;
    eprintln!(
        "meshd: data-plane mode {}",
        if data_plane {
            "ON (per-mesh TUN+UDP loops; needs root)"
        } else {
            "off"
        }
    );
    // P-D4: one LAN-discovery beacon for the whole node. Each round it snapshots the
    // live meshes (those with a data plane up) and advertises/seeds them, so same-LAN
    // peers find each other with no WAN. Best-effort; harmless when data plane is off.
    if data_plane {
        let st = Arc::clone(&state);
        tokio::spawn(lattice_meshrun::run_lan_discovery(move || {
            let st = st.lock().unwrap();
            st.meshes
                .values()
                .filter(|m| m.dp_port != 0)
                .map(|m| lattice_meshrun::LanMesh {
                    tag: lattice_mesh::crypto::lan_tag(&m.secret),
                    member_id: m.my_id(),
                    dp_port: m.dp_port,
                    links: Arc::clone(&m.links),
                })
                .collect()
        }));
    }

    eprintln!("meshd: listening on {socket}");
    accept_loop(&socket, state).await
}

/// Accept IPC connections forever. The transport is platform-specific (unix socket
/// vs named pipe) but the per-connection protocol ([`serve_conn`]) is shared.
#[cfg(unix)]
async fn accept_loop(socket: &str, state: Arc<Mutex<State>>) -> anyhow::Result<()> {
    let _ = std::fs::remove_file(socket);
    let listener = tokio::net::UnixListener::bind(socket)?;
    // meshd runs as root (for the TUN) but the desktop app connects as the logged-in
    // user, so make the socket world-rw — otherwise the GUI can't reach it.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o666));
    }
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(serve_conn(stream, Arc::clone(&state)));
    }
}

#[cfg(windows)]
async fn accept_loop(pipe: &str, state: Arc<Mutex<State>>) -> anyhow::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;
    // Named pipes are connection-instanced: create an instance, wait for a client,
    // hand it off, then create the next instance for the following client.
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(pipe)?;
    loop {
        server.connect().await?;
        let connected = server;
        server = ServerOptions::new().create(pipe)?;
        tokio::spawn(serve_conn(connected, Arc::clone(&state)));
    }
}

/// One IPC connection: newline-JSON [`Request`] in, [`Response`] out, until close.
async fn serve_conn<S>(stream: S, state: Arc<Mutex<State>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (rd, mut wr) = tokio::io::split(stream);
    let mut lines = BufReader::new(rd).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(&line) {
            Ok(req) => {
                // Handle under the lock; do any async data-plane bringup AFTER
                // releasing it (TUN/UDP open is async and must not block IPC).
                let (resp, action) = {
                    let mut st = state.lock().unwrap();
                    handle(req, &mut st)
                };
                match action {
                    Some(PostAction::Bringup(b)) => bringup_dataplane(b, Arc::clone(&state)).await,
                    Some(PostAction::ArmKillSwitch(mesh)) => {
                        arm_kill_switch(mesh, Arc::clone(&state))
                    }
                    None => {}
                }
                resp
            }
            Err(e) => Response::Error {
                message: format!("bad request: {e}"),
            },
        };
        let mut out = serde_json::to_string(&resp)
            .unwrap_or_else(|_| "{\"Error\":{\"message\":\"encode failed\"}}".to_string());
        out.push('\n');
        if wr.write_all(out.as_bytes()).await.is_err() {
            break;
        }
    }
}

/// Open the per-mesh TUN + UDP and spawn the data-plane loop. Failures (e.g. no
/// root for the TUN) are logged and non-fatal: meshd keeps serving the control
/// plane. The `links`/`exit_sel` handles are shared with [`MeshState`].
async fn bringup_dataplane(b: Bringup, state: Arc<Mutex<State>>) {
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
            eprintln!(
                "meshd: data-plane TUN open failed for mesh {} (need root?): {e}",
                b.mesh_id
            );
            return;
        }
    };
    // Per-mesh port = base + mesh id, unless MESHD_BIND_PORT pins one explicitly
    // (single-mesh demos / firewalled hosts that only have one open port, e.g. the
    // Oracle OCI security list).
    let port = std::env::var("MESHD_BIND_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| UDP_BASE_PORT.wrapping_add(b.mesh_id as u16));
    let bind = SocketAddr::from(([0, 0, 0, 0], port));
    let transport = match UdpTransport::bind(bind).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "meshd: data-plane UDP bind {bind} failed for mesh {}: {e}",
                b.mesh_id
            );
            return;
        }
    };
    let dp = MeshDataPlane::new(b.mesh_id, b.my_id, b.prefix, suite(&b.cipher, &b.secret, 0));
    // Record the TUN name (needed to divert the default route for full-tunnel) and
    // make this node able to serve as an exit for others — ip_forward + NAT, which
    // is idempotent and unused unless a peer routes through us (reuses v1 exit.rs).
    let tun_name = tun.name().map(|s| s.to_string());
    {
        if let Some(ms) = state.lock().unwrap().meshes.get_mut(&b.mesh_id) {
            ms.tun_name = tun_name.clone();
            ms.dp_port = port; // local data-plane port — advertised in the LAN beacon
        }
    }
    exit::enable_nat();
    // This node's own reachable address, advertised in the endpoint gossip so peers
    // can reach us without a manual SetPeer (docs/DISCOVERY.md §2). A public node
    // (the Oracle exit) PINS it via MESHD_ADVERTISE=ip:port — never overridden;
    // otherwise we start at the primary LAN address (same-router peers) and the run
    // loop upgrades it to our public address when a public peer reflects it (P-D3).
    let pinned = std::env::var("MESHD_ADVERTISE").is_ok();
    let advertise: Option<SocketAddr> = std::env::var("MESHD_ADVERTISE")
        .ok()
        .and_then(|s| s.parse().ok())
        .or_else(|| local_ip().map(|ip| SocketAddr::new(ip, port)));
    *b.my_endpoint.lock().unwrap() = advertise;
    eprintln!(
        "meshd: data-plane LIVE for mesh {} — overlay {overlay}/24, udp {bind}, iface {tun_name:?}, advertise {advertise:?} pinned={pinned}",
        b.mesh_id
    );
    let task = tokio::spawn(lattice_meshrun::run(
        dp,
        tun,
        transport,
        b.links,
        b.exit_sel,
        b.my_id,
        Arc::clone(&b.my_endpoint),
        pinned,
    ));
    // Record the loop's abort handle so RemoveMesh can stop it (freeing the port/TUN).
    if let Some(ms) = state.lock().unwrap().meshes.get_mut(&b.mesh_id) {
        ms.dp_task = Some(task.abort_handle());
    }
}

/// Best-effort primary local IP — the source address the OS picks to reach the
/// internet (no packet is actually sent; `connect` on a UDP socket just selects the
/// route). Used as our advertised gossip endpoint when MESHD_ADVERTISE is unset.
fn local_ip() -> Option<std::net::IpAddr> {
    let s = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    s.connect(("8.8.8.8", 80)).ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

/// Kill-switch watchdog (from v1). Full tunnel diverts the host default route
/// through the exit; if that path can't carry traffic the host is stranded OFFLINE.
/// Every ~20s probe the internet THROUGH the tunnel (TCP connect to 1.1.1.1:443 —
/// it travels TUN→exit, so success proves the exit forwards). The moment a probe
/// fails, auto-revert to direct internet so the user is never cut off.
fn arm_kill_switch(mesh: MeshId, state: Arc<Mutex<State>>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            // Stop watching once egress moved off this mesh (user changed it).
            if state.lock().unwrap().current != Some(mesh) {
                return;
            }
            let alive = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::net::TcpStream::connect("1.1.1.1:443"),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);
            if !alive {
                let mut st = state.lock().unwrap();
                if st.current == Some(mesh) {
                    eprintln!(
                        "meshd kill-switch: full-tunnel exit not passing traffic — reverting to direct internet"
                    );
                    exit::restore_routes();
                    exit::restore_dns();
                    st.current = None;
                }
                return; // reverted (or someone else did) — stop probing
            }
        }
    });
}

fn handle(req: Request, st: &mut State) -> (Response, Option<PostAction>) {
    match req {
        Request::CreateMesh {
            name,
            my_name,
            max_members,
            cipher,
        } => create_mesh(st, name, my_name, max_members, cipher),

        Request::Ciphers => (
            Response::Ciphers(
                lattice_mesh::crypto::available_ciphers()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            ),
            None,
        ),

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

        Request::AdmitMember {
            mesh,
            name,
            pubkey_hex,
        } => {
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
                return (
                    err(&format!(
                        "mesh is full (max {})",
                        ms.mesh.charter.max_members
                    )),
                    None,
                );
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
            // Note: this is a local admit only — it does NOT hand the joiner the
            // mesh secret. Use CreateInvite for a node that will actually connect.
            let cert = match ms.master.as_ref() {
                Some(m) => m.issue(pubkey, id, &name, now_ms()),
                None => return (err("only the mesh creator can admit members"), None),
            };
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
                exit::restore_routes();
                exit::restore_dns();
            }
            (Response::Ok, None)
        }

        Request::SetPeer {
            mesh,
            member,
            endpoint,
        } => {
            let addr: SocketAddr = match endpoint.parse() {
                Ok(a) => a,
                Err(_) => {
                    return (
                        err(&format!("bad endpoint '{endpoint}' (want ip:port)")),
                        None,
                    )
                }
            };
            match st.meshes.get(&mesh) {
                Some(ms) => {
                    ms.links.lock().unwrap().insert(
                        member,
                        Link {
                            endpoint: addr,
                            last_seen_ms: 0,
                        },
                    );
                    (Response::Ok, None)
                }
                None => (no_mesh(mesh), None),
            }
        }

        Request::SetCurrent { mesh } => match mesh {
            None => {
                st.current = None;
                // Back to the default network: undo the full-tunnel diversion.
                exit::restore_routes();
                exit::restore_dns();
                (Response::Ok, None)
            }
            Some(id) => {
                // Collect the exit's TUN + physical endpoint, then divert all traffic
                // through it (full tunnel). Early-return on the error cases.
                let plan = match st.meshes.get(&id) {
                    Some(ms) if ms.mesh.exit.is_some() => {
                        let exit_id = ms.mesh.exit.unwrap();
                        let exit_ip = ms
                            .links
                            .lock()
                            .unwrap()
                            .get(&exit_id)
                            .map(|l| l.endpoint.ip());
                        (ms.tun_name.clone(), exit_ip)
                    }
                    Some(_) => {
                        return (
                            err(&format!(
                                "set an exit for mesh {id} before making it current"
                            )),
                            None,
                        )
                    }
                    None => return (no_mesh(id), None),
                };
                st.current = Some(id);
                let action = match plan {
                    (Some(tun), Some(ip)) => {
                        exit::route_through(&tun, ip);
                        if let Ok(dns) = FULL_TUNNEL_DNS.parse() {
                            exit::set_dns(&[dns]);
                        }
                        // Arm the kill-switch: auto-revert if the exit can't carry traffic.
                        Some(PostAction::ArmKillSwitch(id))
                    }
                    _ => {
                        eprintln!(
                            "meshd: full-tunnel not plumbed for mesh {id} — TUN or exit endpoint unknown (is the data plane up + exit reachable?)"
                        );
                        None
                    }
                };
                (Response::Ok, action)
            }
        },

        Request::RemoveMesh { mesh } => {
            if let Some(ms) = st.meshes.remove(&mesh) {
                // Stop the data-plane loop so its TUN + UDP socket are dropped — else
                // the port leaks and a re-created mesh on the same port can't bind.
                if let Some(task) = &ms.dp_task {
                    task.abort();
                }
                if st.current == Some(mesh) {
                    st.current = None;
                    exit::restore_routes();
                    exit::restore_dns();
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
            (
                Response::Policy(PolicyView {
                    default,
                    current_mesh: st.current,
                }),
                None,
            )
        }

        Request::NewIdentity => {
            let member = MemberKey::generate();
            let enc = EncKey::generate();
            let member_pubkey_hex = hex(&member.pubkey());
            let enc_pubkey_hex = hex(&enc.public());
            st.pending.insert(member.pubkey(), (member, enc));
            (
                Response::Identity {
                    member_pubkey_hex,
                    enc_pubkey_hex,
                },
                None,
            )
        }

        Request::CreateInvite {
            mesh,
            name,
            member_pubkey_hex,
            enc_pubkey_hex,
        } => {
            let member_pk = match parse_hex32(&member_pubkey_hex) {
                Some(p) => p,
                None => return (err("member_pubkey must be 64 hex chars"), None),
            };
            let enc_pk = match parse_hex32(&enc_pubkey_hex) {
                Some(p) => p,
                None => return (err("enc_pubkey must be 64 hex chars"), None),
            };
            let ms = match st.meshes.get_mut(&mesh) {
                Some(m) => m,
                None => return (no_mesh(mesh), None),
            };
            let master = match ms.master.as_ref() {
                Some(m) => m,
                None => return (err("only the mesh creator can issue invites"), None),
            };
            let roster = ms.roster();
            if roster.len() >= ms.mesh.charter.max_members as usize {
                return (
                    err(&format!(
                        "mesh is full (max {})",
                        ms.mesh.charter.max_members
                    )),
                    None,
                );
            }
            if roster.iter().any(|c| c.member == member_pk) {
                return (err("already a member"), None);
            }
            let used: HashSet<MemberId> = roster.iter().map(|c| c.id).collect();
            let id = match (1u8..=254).find(|i| !used.contains(i)) {
                Some(i) => i,
                None => return (err("no free member id"), None),
            };
            // Issue the cert and seal the mesh secret to the joiner's enc key.
            let cert = master.issue(member_pk, id, &name, now_ms());
            let sealed_secret = seal_secret(&enc_pk, &ms.secret);
            // Bootstrap endpoints for the joiner (P-D1): our own advertised address
            // first, then every peer we already reach. The joiner seeds its data
            // plane with these so it can send to us (and them) before gossip
            // converges — no manual SetPeer needed.
            let mut endpoints: Vec<(MemberId, String)> = Vec::new();
            if let Some(ep) = *ms.my_endpoint.lock().unwrap() {
                endpoints.push((ms.my_id(), ep.to_string()));
            }
            for (m, link) in ms.links.lock().unwrap().iter() {
                endpoints.push((*m, link.endpoint.to_string()));
            }
            ms.certs.push(cert);
            let blob = InviteBlob {
                mesh_id: ms.mesh.id,
                mesh_name: ms.mesh.name.clone(),
                charter: ms.mesh.charter.clone(),
                member_id: id,
                certs: ms.certs.clone(),
                sealed_secret,
                endpoints,
            };
            (Response::Invite(blob), None)
        }

        Request::JoinMesh { invite } => join_mesh(st, invite),
    }
}

fn join_mesh(st: &mut State, invite: InviteBlob) -> (Response, Option<PostAction>) {
    if st.meshes.contains_key(&invite.mesh_id) {
        return (err(&format!("already in mesh {}", invite.mesh_id)), None);
    }
    // The cert the creator issued to us tells us which pending identity to use.
    let my_cert = match invite.certs.iter().find(|c| c.id == invite.member_id) {
        Some(c) => c,
        None => return (err("invite has no cert for the assigned member id"), None),
    };
    let (my_key, my_enc) = match st.pending.remove(&my_cert.member) {
        Some(pair) => pair,
        None => {
            return (
                err("no pending identity for this invite — call NewIdentity first"),
                None,
            )
        }
    };
    // Open the sealed mesh secret with our encryption key.
    let secret = match my_enc.open(&invite.sealed_secret) {
        Some(s) => s,
        None => return (err("could not open the sealed secret (wrong key?)"), None),
    };
    // Verify our cert actually chains to the charter's master before adopting.
    let roster = valid_members(
        &invite.charter.master_pubkey,
        &invite.certs,
        invite.charter.invite,
    );
    if !roster
        .iter()
        .any(|c| c.id == invite.member_id && c.member == my_key.pubkey())
    {
        return (
            err("our cert does not validate against the master — bad invite"),
            None,
        );
    }
    let prefix = invite.charter.overlay_prefix;
    let cipher = invite.charter.initial_cipher.clone();
    // Seed the data plane with the bootstrap endpoints the inviter handed us (P-D1):
    // we can reach the inviter (and any peers it knew) immediately, before gossip
    // converges. Skip our own id and any unparseable address.
    let mut seed: HashMap<MemberId, SocketAddr> = HashMap::new();
    for (m, ep) in &invite.endpoints {
        if *m == invite.member_id {
            continue;
        }
        if let Ok(addr) = ep.parse() {
            seed.insert(*m, addr);
        }
    }
    let links = seed_links(seed);
    let exit_sel: SharedExit = Arc::new(Mutex::new(None));
    let my_endpoint: SharedEndpoint = Arc::new(Mutex::new(None));
    let mesh = Mesh::new(
        invite.mesh_id,
        invite.mesh_name.clone(),
        invite.charter,
        invite.member_id,
    );
    let bringup = st.data_plane.then(|| Bringup {
        mesh_id: invite.mesh_id,
        my_id: invite.member_id,
        prefix,
        secret,
        cipher,
        links: Arc::clone(&links),
        exit_sel: Arc::clone(&exit_sel),
        my_endpoint: Arc::clone(&my_endpoint),
    });
    st.meshes.insert(
        invite.mesh_id,
        MeshState {
            mesh,
            master: None,
            my_key,
            my_enc,
            certs: invite.certs,
            secret,
            links,
            exit_sel,
            tun_name: None,
            my_endpoint,
            dp_port: 0,
            dp_task: None,
        },
    );
    (
        Response::MeshCreated {
            mesh: invite.mesh_id,
        },
        bringup.map(PostAction::Bringup),
    )
}

fn create_mesh(
    st: &mut State,
    name: String,
    my_name: String,
    max_members: u8,
    cipher: Option<String>,
) -> (Response, Option<PostAction>) {
    let id = match (1u8..=255).find(|id| !st.meshes.contains_key(id)) {
        Some(id) => id,
        None => return (err("too many meshes on this computer (max 255)"), None),
    };
    // The data-plane cipher is fixed at creation (P-C1, the GUI dropbox). Validate
    // the chosen name against the registry; default if unspecified.
    let cipher = cipher.unwrap_or_else(|| lattice_mesh::crypto::DEFAULT_CIPHER.to_string());
    if !lattice_mesh::crypto::is_known_cipher(&cipher) {
        return (
            err(&format!(
                "unknown cipher '{cipher}'; one of {:?}",
                lattice_mesh::crypto::available_ciphers()
            )),
            None,
        );
    }
    let master = MasterKey::generate();
    let my_key = MemberKey::generate();
    let charter = GenesisCharter {
        master_pubkey: master.network(),
        invite: InviteTopology::OpenChain,
        trigger: RecipherTrigger::Quorum { k: 2 },
        max_members,
        initial_cipher: cipher,
        overlay_prefix: [100, 80],
    };
    if let Err(e) = charter.validate() {
        return (err(&e.to_string()), None);
    }
    // The creator is member #1, with a master-signed cert.
    let cert = master.issue(my_key.pubkey(), 1, &my_name, now_ms());
    let my_enc = EncKey::generate();
    let prefix = charter.overlay_prefix;
    let cipher = charter.initial_cipher.clone();
    let secret: [u8; 32] = rand::random();
    let links = seed_links(HashMap::new());
    let exit_sel: SharedExit = Arc::new(Mutex::new(None));
    let my_endpoint: SharedEndpoint = Arc::new(Mutex::new(None));
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
        my_endpoint: Arc::clone(&my_endpoint),
    });
    st.meshes.insert(
        id,
        MeshState {
            mesh,
            master: Some(master),
            my_key,
            my_enc,
            certs: vec![cert],
            secret,
            links,
            exit_sel,
            tun_name: None,
            my_endpoint,
            dp_port: 0,
            dp_task: None,
        },
    );
    (
        Response::MeshCreated { mesh: id },
        bringup.map(PostAction::Bringup),
    )
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
                    Some(l)
                        if l.last_seen_ms != 0
                            && now.saturating_sub(l.last_seen_ms) < LIVE_WINDOW_MS =>
                    {
                        "live".into()
                    }
                    Some(_) => "idle".into(),
                    None => "unknown".into(),
                }
            };
            MemberView {
                id: c.id,
                name: c.name.clone(),
                pubkey_fp: fp(&c.member),
                is_me,
                endpoint,
                state,
            }
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
    Response::Error {
        message: format!("no mesh {id}"),
    }
}

fn err(message: &str) -> Response {
    Response::Error {
        message: message.to_string(),
    }
}

fn fp(pk: &PubKey) -> String {
    pk[..4].iter().map(|b| format!("{b:02x}")).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
