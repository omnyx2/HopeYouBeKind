// Lattice Admin Console — Tauri shell.
//
// The administrator counterpart to the user GUI. Where the user GUI deliberately
// hides admin capability (commit 826c362), this app re-exposes it: membership
// management (enroll / evict), and — in later phases — a packet-level traffic
// inspector and a crypto-suite swap lab. See docs/ADMIN_CONSOLE.md.
//
// This Rust layer only bridges the web front-end to the daemon over the local
// IPC socket (lattice_proto::ipc); all authority lives in the daemon (it answers
// admin requests only when it holds the network CA, i.e. was started with
// --network-key).
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use lattice_proto::ipc::{Request, Response};
use serde::Serialize;

/// Where the admin daemon listens. The console attaches to an already-running
/// admin node; it never spawns a daemon.
const SOCKET: &str = "/tmp/lattice.sock";

#[derive(Serialize)]
struct StatusView {
    running: bool,
    virtual_ip: Option<String>,
    fingerprint: String,
    node_id: String,
    public_addr: Option<String>,
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

#[derive(Serialize)]
struct MemberView {
    node_id: String,
    fingerprint: String,
    serial: u64,
    label: Option<String>,
    revoked: bool,
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
        }),
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

/// Admin: the member roster the network CA has issued certs to.
#[tauri::command]
async fn list_members() -> Result<Vec<MemberView>, String> {
    match lattice_ipc::request(SOCKET, Request::Members).await {
        Ok(Response::Members(members)) => Ok(members
            .into_iter()
            .map(|m| MemberView {
                node_id: m.node_id,
                fingerprint: m.fingerprint,
                serial: m.serial,
                label: m.label,
                revoked: m.revoked,
            })
            .collect()),
        Ok(Response::Error { message }) => Err(message),
        Ok(_) => Err("unexpected response".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// Admin: issue a membership cert for a node id, returning the hex join token to
/// hand to that node (which then runs `lattice net join <token>`).
#[tauri::command]
async fn issue_cert(node_id: String, label: Option<String>) -> Result<String, String> {
    let id = parse_node_id(node_id.trim()).ok_or("invalid node id (need 64 hex chars)")?;
    let label = label.and_then(|l| {
        let t = l.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    });
    match lattice_ipc::request(SOCKET, Request::IssueCert { node_id: id, label }).await {
        Ok(Response::Token(token)) => Ok(token),
        Ok(Response::Error { message }) => Err(message),
        Ok(_) => Err("unexpected response".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// Admin: evict a member (revoke its cert). The revocation gossips to the mesh on
/// the next keepalive tick and the peer's session is dropped everywhere.
#[tauri::command]
async fn revoke_member(node_id: String) -> Result<(), String> {
    let id = parse_node_id(node_id.trim()).ok_or("invalid node id (need 64 hex chars)")?;
    match lattice_ipc::request(SOCKET, Request::RevokeMember { node_id: id }).await {
        Ok(Response::Done) => Ok(()),
        Ok(Response::Error { message }) => Err(message),
        Ok(_) => Err("unexpected response".into()),
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

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_status,
            network_info,
            list_peers,
            list_members,
            issue_cert,
            revoke_member
        ])
        .run(tauri::generate_context!())
        .expect("error while running Lattice Admin");
}
