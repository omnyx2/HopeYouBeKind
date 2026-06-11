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
}

#[derive(Serialize)]
struct PeerView {
    virtual_ip: String,
    fingerprint: String,
    status: String,
    endpoint: Option<String>,
    node_id: String,
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
            })
            .collect()),
        Ok(Response::Error { message }) => Err(message),
        Ok(_) => Err("unexpected response".into()),
        Err(e) => Err(e.to_string()),
    }
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
    let script =
        "do shell script \"pkill -x lattice-daemon\" with administrator privileges".to_string();
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
            mesh_up,
            mesh_down,
            start_daemon,
            stop_daemon,
            set_exit,
            allow_exit,
            add_peer
        ])
        .run(tauri::generate_context!())
        .expect("error while running Lattice GUI");
}
