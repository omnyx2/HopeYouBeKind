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

use serde::Serialize;

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
fn get_status() -> StatusView {
    // TODO(v0.4): send ipc::Request::Status to the daemon and map the response.
    StatusView {
        running: false,
        virtual_ip: None,
        fingerprint: "00000000".into(),
    }
}

#[tauri::command]
fn list_peers() -> Vec<PeerView> {
    // TODO(v0.4): send ipc::Request::Peers to the daemon.
    Vec::new()
}

#[tauri::command]
fn mesh_up() {
    // TODO(v0.4): send ipc::Request::Up to the daemon.
}

#[tauri::command]
fn mesh_down() {
    // TODO(v0.4): send ipc::Request::Down to the daemon.
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_status,
            list_peers,
            mesh_up,
            mesh_down
        ])
        .run(tauri::generate_context!())
        .expect("error while running Lattice GUI");
}
