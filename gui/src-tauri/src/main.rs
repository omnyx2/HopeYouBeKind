// Lattice GUI — Tauri shell.
//
// This Rust layer is the bridge between the web front-end and the privileged
// daemon. The `#[tauri::command]` functions below are what the front-end calls
// via `invoke(...)`. For v0.1 they return local placeholder state; in v0.4 they
// connect to the daemon over IPC (lattice_proto::ipc) and forward real data.
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use lattice_proto::ipc::{Request, Response};
use serde::Serialize;

/// Where the daemon listens. (Configurable via the GUI settings in a later pass.)
const SOCKET: &str = "/tmp/lattice.sock";

#[derive(Serialize)]
struct StatusView {
    running: bool,
    virtual_ip: Option<String>,
    fingerprint: String,
    node_id: String,
    public_addr: Option<String>,
    exit_node: Option<String>,
    is_exit: bool,
    relay: Option<String>,
}

#[derive(Serialize)]
struct FlowView {
    peer: Option<String>,
    protocol: String,
    local: String,
    remote: String,
    tx_packets: u64,
    tx_bytes: u64,
    rx_packets: u64,
    rx_bytes: u64,
    last_active_secs: u64,
}

#[derive(Serialize)]
struct NetworkInfoView {
    network_id: Option<String>,
    fingerprint: Option<String>,
    is_admin: bool,
    member_count: usize,
    revocation_count: usize,
}

#[derive(Serialize)]
struct PeerView {
    virtual_ip: String,
    fingerprint: String,
    status: String,
    endpoint: Option<String>,
    node_id: String,
    os: Option<String>,
}

#[tauri::command]
async fn get_status() -> Result<StatusView, String> {
    match lattice_ipc::request(SOCKET, Request::Status).await {
        Ok(Response::Status(s)) => Ok(StatusView {
            running: s.running,
            virtual_ip: s.virtual_ip.map(|v| v.to_string()),
            fingerprint: s.id.fingerprint(),
            node_id: s.id.to_hex(),
            public_addr: s.public_addr.map(|a| a.to_string()),
            exit_node: s.exit_node.map(|id| id.to_hex()),
            is_exit: s.is_exit,
            relay: s.relay.map(|a| a.to_string()),
        }),
        Ok(Response::Error { message }) => Err(message),
        Ok(_) => Err("unexpected response".into()),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
async fn list_peers() -> Result<Vec<PeerView>, String> {
    match lattice_ipc::request(SOCKET, Request::Peers).await {
        Ok(Response::Peers(peers)) => Ok(peers
            .into_iter()
            .map(|p| PeerView {
                virtual_ip: p.virtual_ip.to_string(),
                fingerprint: p.id.fingerprint(),
                status: format!("{:?}", p.status).to_lowercase(),
                endpoint: p.endpoints.first().map(|e| e.to_string()),
                node_id: p.id.to_hex(),
                os: p.os,
            })
            .collect()),
        Ok(Response::Error { message }) => Err(message),
        Ok(_) => Err("unexpected response".into()),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
async fn list_flows() -> Result<Vec<FlowView>, String> {
    match lattice_ipc::request(SOCKET, Request::Flows).await {
        Ok(Response::Flows(flows)) => Ok(flows
            .into_iter()
            .map(|f| FlowView {
                peer: f.peer.map(|id| id.fingerprint()),
                protocol: f.protocol,
                local: f.local,
                remote: f.remote,
                tx_packets: f.tx_packets,
                tx_bytes: f.tx_bytes,
                rx_packets: f.rx_packets,
                rx_bytes: f.rx_bytes,
                last_active_secs: f.last_active_secs,
            })
            .collect()),
        Ok(Response::Error { message }) => Err(message),
        Ok(_) => Err("unexpected response".into()),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
async fn network_info() -> Result<NetworkInfoView, String> {
    match lattice_ipc::request(SOCKET, Request::NetworkInfo).await {
        Ok(Response::NetworkInfo(n)) => Ok(NetworkInfoView {
            network_id: n.network_id,
            fingerprint: n.fingerprint,
            is_admin: n.is_admin,
            member_count: n.member_count,
            revocation_count: n.revocation_count,
        }),
        Ok(Response::Error { message }) => Err(message),
        Ok(_) => Err("unexpected response".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// Adopt a join token issued for this node. This is the ONLY membership action
/// the user GUI performs — admin capabilities (issue/revoke, holding the network
/// CA key) are deliberately kept out of the user surface and live in the
/// separate admin CLI/tooling instead.
#[tauri::command]
async fn join_network(token: String) -> Result<(), String> {
    send(Request::JoinNetwork {
        token: token.trim().to_string(),
    })
    .await
}

#[tauri::command]
async fn mesh_up() -> Result<(), String> {
    send(Request::Up).await
}

#[tauri::command]
async fn mesh_down() -> Result<(), String> {
    send(Request::Down).await
}

async fn send(req: Request) -> Result<(), String> {
    match lattice_ipc::request(SOCKET, req).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

fn parse_node_id(hex: &str) -> Option<lattice_proto::NodeId> {
    if hex.len() != 64 {
        return None;
    }
    let mut id = [0u8; 32];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(lattice_proto::NodeId(id))
}

/// Route this node's internet traffic through a peer (by full hex id), or
/// `None` to go direct again.
#[tauri::command]
async fn set_exit(node_id: Option<String>) -> Result<(), String> {
    let parsed = match node_id {
        Some(hex) => Some(parse_node_id(&hex).ok_or("invalid node id")?),
        None => None,
    };
    send(Request::SetExit { node_id: parsed }).await
}

/// Volunteer (or stop) as an exit node for other peers.
#[tauri::command]
async fn allow_exit(enabled: bool) -> Result<(), String> {
    send(Request::AllowExit { enabled }).await
}

/// Set (empty string clears) the relay used to reach hard-NAT peers.
#[tauri::command]
async fn set_relay(addr: String) -> Result<(), String> {
    let parsed = if addr.trim().is_empty() {
        None
    } else {
        Some(
            addr.trim()
                .parse::<std::net::SocketAddr>()
                .map_err(|_| "invalid relay address (need ip:port)")?,
        )
    };
    send(Request::SetRelay { addr: parsed }).await
}

/// Reach a peer (by full hex node id) through the configured relay.
#[tauri::command]
async fn relay_peer(node_id: String) -> Result<(), String> {
    let id = parse_node_id(node_id.trim()).ok_or("invalid node id (need 64 hex chars)")?;
    send(Request::RelayPeer { node_id: id }).await
}

/// Manually pin a peer from a `<node-id>@<ip:port>` string — connect across the
/// internet without discovery (e.g. to a port-forwarded node).
#[tauri::command]
async fn add_peer(spec: String) -> Result<(), String> {
    let (id_hex, addr_str) = spec
        .split_once('@')
        .ok_or("format: <node-id>@<ip:port>")?;
    let node_id = parse_node_id(id_hex.trim()).ok_or("invalid node id (need 64 hex chars)")?;
    let addr: std::net::SocketAddr = addr_str.trim().parse().map_err(|_| "invalid ip:port")?;
    send(Request::AddPeer { node_id, addr }).await
}

/// Start the bundled daemon as root via the macOS admin prompt. Creating the TUN
/// device requires privileges; this is the one moment the user authenticates.
#[cfg(target_os = "macos")]
#[tauri::command]
async fn start_daemon(app: tauri::AppHandle) -> Result<(), String> {
    let daemon = app
        .path_resolver()
        .resolve_resource("resources/lattice-daemon")
        .ok_or("bundled daemon not found")?;
    let path = daemon.to_string_lossy().to_string();
    if path.contains('\'') {
        return Err("daemon path contains an unsupported character".into());
    }
    // Run detached, logging to /tmp, with administrator privileges.
    let script = format!(
        "do shell script \"'{path}' --bind 0.0.0.0:41000 > /tmp/lattice-daemon.log 2>&1 &\" with administrator privileges"
    );
    let status = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err("authentication cancelled or failed".into())
    }
}

/// Stop the daemon (needs admin since it runs as root).
#[cfg(target_os = "macos")]
#[tauri::command]
async fn stop_daemon() -> Result<(), String> {
    // Kill by PID file and by the bound UDP port — NOT by process-name pattern.
    // The daemon's process command is its full path (so killall/pkill -x miss
    // it), and pkill -f '…lattice-daemon…' self-matches the shell running it.
    let script = "do shell script \"kill -9 $(cat /tmp/lattice-daemon.pid 2>/dev/null) 2>/dev/null; \
                  lsof -ti udp:41000 2>/dev/null | xargs kill -9 2>/dev/null; \
                  rm -f /tmp/lattice.sock /tmp/lattice-daemon.pid; true\" \
                  with administrator privileges"
        .to_string();
    let _ = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .status();
    Ok(())
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
async fn start_daemon(_app: tauri::AppHandle) -> Result<(), String> {
    Err("GUI daemon control is implemented for macOS; on Linux run `sudo lattice-daemon`".into())
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
async fn stop_daemon() -> Result<(), String> {
    Err("GUI daemon control is implemented for macOS".into())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_status,
            list_peers,
            list_flows,
            network_info,
            join_network,
            mesh_up,
            mesh_down,
            start_daemon,
            stop_daemon,
            set_exit,
            allow_exit,
            add_peer,
            set_relay,
            relay_peer
        ])
        .run(tauri::generate_context!())
        .expect("error while running Lattice GUI");
}
