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
}

#[derive(Serialize)]
struct PeerView {
    virtual_ip: String,
    fingerprint: String,
    status: String,
}

#[tauri::command]
async fn get_status() -> Result<StatusView, String> {
    match lattice_ipc::request(SOCKET, Request::Status).await {
        Ok(Response::Status(s)) => Ok(StatusView {
            running: s.running,
            virtual_ip: s.virtual_ip.map(|v| v.to_string()),
            fingerprint: s.id.fingerprint(),
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
        "do shell script \"'{path}' > /tmp/lattice-daemon.log 2>&1 &\" with administrator privileges"
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
            stop_daemon
        ])
        .run(tauri::generate_context!())
        .expect("error while running Lattice GUI");
}
