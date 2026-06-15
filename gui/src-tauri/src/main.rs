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

use lattice_proto::flow::{FlowAction, FlowMatch, FlowRule, FlowScope};
use lattice_proto::ipc::{Request, Response};
use serde::Serialize;

/// Where the daemon listens. (Configurable via the GUI settings in a later pass.)
const SOCKET: &str = "/tmp/lattice.sock";

/// Where the v2 multi-mesh control-plane daemon (`meshd`) listens.
const MESHD_SOCKET: &str = "/tmp/lattice-meshd.sock";

/// Proxy one newline-JSON request to `meshd` and hand back its response line. The
/// v2 multi-mesh logic lives in the front-end + meshd; this is just the socket
/// bridge (browsers/JS can't open a unix socket).
#[cfg(unix)]
#[tauri::command]
fn meshd(request: String) -> Result<String, String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    let stream = UnixStream::connect(MESHD_SOCKET)
        .map_err(|e| format!("meshd not running ({MESHD_SOCKET}): {e}"))?;
    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    let mut line = request;
    line.push('\n');
    writer.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    let mut resp = String::new();
    BufReader::new(stream)
        .read_line(&mut resp)
        .map_err(|e| e.to_string())?;
    Ok(resp.trim_end().to_string())
}

#[cfg(not(unix))]
#[tauri::command]
fn meshd(_request: String) -> Result<String, String> {
    Err("meshd is available on macOS/Linux".into())
}

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

#[derive(Serialize)]
struct FlowRuleView {
    /// Storage index in the daemon's table — what `FlowDel` deletes by. Stable
    /// across the priority-sort we do for display, so the GUI's delete button
    /// removes the row the user actually sees (not whatever sits at that sorted
    /// position). Mirrors the `[i]` numbering the CLI prints.
    index: usize,
    priority: u16,
    matcher: String,
    action: String,
}

fn fmt_flow_match(m: &FlowMatch) -> String {
    let mut p = Vec::new();
    match m.scope {
        Some(FlowScope::Overlay) => p.push("scope=overlay".to_string()),
        Some(FlowScope::Internet) => p.push("scope=internet".to_string()),
        None => {}
    }
    if let Some((ip, len)) = m.dst_cidr {
        p.push(format!("dst={ip}/{len}"));
    }
    if let Some(pr) = m.proto {
        let n = match pr {
            6 => "tcp".into(),
            17 => "udp".into(),
            1 => "icmp".into(),
            x => x.to_string(),
        };
        p.push(format!("proto={n}"));
    }
    if let Some(dp) = m.dport {
        p.push(format!("dport={dp}"));
    }
    if p.is_empty() {
        "*".into()
    } else {
        p.join(" ")
    }
}

fn fmt_flow_action(a: &FlowAction) -> String {
    match a {
        FlowAction::ToOverlayOwner => "overlay-owner".into(),
        FlowAction::ToExit(None) => "exit(configured)".into(),
        FlowAction::ToExit(Some(id)) => format!("exit({})", id.fingerprint()),
        FlowAction::ToPeer(id) => format!("peer({})", id.fingerprint()),
        FlowAction::Local => "local".into(),
        FlowAction::Drop => "DROP".into(),
    }
}

/// The SDN flow table (admin-signed, shared by every node). Admin-only — a member
/// node's daemon answers "not an admin node", which we surface as an empty table.
#[tauri::command]
async fn list_flow_rules() -> Result<Vec<FlowRuleView>, String> {
    match lattice_ipc::request(SOCKET, Request::FlowList).await {
        Ok(Response::FlowRules(rules)) => {
            // Display highest-priority first (evaluation order), but carry each
            // rule's ORIGINAL storage index so the delete button targets the
            // right rule — `FlowDel` removes by storage position, not by the
            // sorted order shown here.
            let mut order: Vec<usize> = (0..rules.len()).collect();
            order.sort_by(|&a, &b| rules[b].priority.cmp(&rules[a].priority));
            Ok(order
                .into_iter()
                .map(|i| {
                    let r: &FlowRule = &rules[i];
                    FlowRuleView {
                        index: i,
                        priority: r.priority,
                        matcher: fmt_flow_match(&r.match_),
                        action: fmt_flow_action(&r.action),
                    }
                })
                .collect())
        }
        // Not admin (or no rules) → empty table; the GUI shows the default note.
        Ok(Response::Error { .. }) => Ok(Vec::new()),
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

/// Like `send`, but surfaces a daemon-side `Response::Error` as `Err` instead of
/// swallowing it. The flow-table edits are admin-gated — a member node replies
/// "not an admin node", and the user needs to see that rather than a false "ok".
async fn send_checked(req: Request) -> Result<(), String> {
    match lattice_ipc::request(SOCKET, req).await {
        Ok(Response::Error { message }) => Err(message),
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Parse a GUI `--action`-style string into a `FlowAction`. Mirrors the CLI's
/// `parse_action` so the GUI and `lattice flow add` accept the same vocabulary.
fn parse_flow_action(s: &str) -> Result<FlowAction, String> {
    Ok(match s.trim() {
        "drop" => FlowAction::Drop,
        "local" => FlowAction::Local,
        "overlay" => FlowAction::ToOverlayOwner,
        "exit" => FlowAction::ToExit(None),
        other => {
            if let Some(hex) = other.strip_prefix("exit:") {
                FlowAction::ToExit(Some(
                    parse_node_id(hex.trim()).ok_or("invalid exit node id (need 64 hex chars)")?,
                ))
            } else if let Some(hex) = other.strip_prefix("peer:") {
                FlowAction::ToPeer(
                    parse_node_id(hex.trim()).ok_or("invalid peer node id (need 64 hex chars)")?,
                )
            } else {
                return Err(format!(
                    "unknown action '{other}' (drop|local|overlay|exit|exit:<id>|peer:<id>)"
                ));
            }
        }
    })
}

/// Build a `FlowMatch` from the GUI form fields. Empty/absent fields are
/// wildcards. Mirrors the CLI's `build_match`.
fn build_flow_match(
    scope: Option<String>,
    dst: Option<String>,
    proto: Option<String>,
    dport: Option<u16>,
) -> Result<FlowMatch, String> {
    let scope = match scope.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => None,
        Some("overlay") => Some(FlowScope::Overlay),
        Some("internet") => Some(FlowScope::Internet),
        Some(o) => return Err(format!("unknown scope '{o}' (overlay|internet)")),
    };
    let dst_cidr = match dst.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => None,
        Some(s) => {
            let (ip, len) = match s.split_once('/') {
                Some((ip, len)) => (
                    ip.trim(),
                    len.trim().parse().map_err(|_| "bad prefix length".to_string())?,
                ),
                None => (s, 32u8),
            };
            if len > 32 {
                return Err("prefix length must be 0–32".into());
            }
            Some((ip.parse().map_err(|_| "bad destination IP".to_string())?, len))
        }
    };
    let proto = match proto.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => None,
        Some("tcp") => Some(6),
        Some("udp") => Some(17),
        Some("icmp") => Some(1),
        Some(n) => Some(n.parse().map_err(|_| format!("bad protocol '{n}'"))?),
    };
    Ok(FlowMatch {
        scope,
        dst_cidr,
        proto,
        dport,
    })
}

/// Admin: append a rule to the signed SDN flow table. Republished in the
/// manifest and hot-reloaded by every node. Member nodes get "not an admin".
#[tauri::command]
async fn add_flow_rule(
    priority: u16,
    scope: Option<String>,
    dst: Option<String>,
    proto: Option<String>,
    dport: Option<u16>,
    action: String,
) -> Result<(), String> {
    let rule = FlowRule {
        priority,
        match_: build_flow_match(scope, dst, proto, dport)?,
        action: parse_flow_action(&action)?,
    };
    send_checked(Request::FlowAdd { rule }).await
}

/// Admin: delete the flow rule at `index` (the storage index carried by
/// `list_flow_rules`).
#[tauri::command]
async fn del_flow_rule(index: usize) -> Result<(), String> {
    send_checked(Request::FlowDel { index }).await
}

/// Admin: clear the flow table — every node reverts to the built-in default.
#[tauri::command]
async fn clear_flow_rules() -> Result<(), String> {
    send_checked(Request::FlowClear).await
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
async fn set_exit(node_id: Option<String>, split: Option<bool>) -> Result<(), String> {
    let parsed = match node_id {
        Some(hex) => Some(parse_node_id(&hex).ok_or("invalid node id")?),
        None => None,
    };
    // Split tunnel forwards to the exit but leaves the OS default route alone
    // (non-disruptive — won't knock the host offline); full tunnel diverts all
    // internet traffic out through the exit.
    send(Request::SetExit {
        node_id: parsed,
        full_tunnel: !split.unwrap_or(false),
    })
    .await
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

/// Start the bundled daemon elevated via UAC. Creating the Wintun adapter needs
/// Administrator; `Start-Process -Verb RunAs` is the one moment the user consents.
#[cfg(windows)]
#[tauri::command]
async fn start_daemon(app: tauri::AppHandle) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    // Prefer the bundled daemon; fall back to one sitting next to the GUI exe
    // (the unbundled `cargo tauri dev` / `cargo run` layout).
    let daemon = app
        .path_resolver()
        .resolve_resource("resources/lattice-daemon.exe")
        .filter(|p| p.exists())
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("lattice-daemon.exe")))
                .filter(|p| p.exists())
        })
        .ok_or("bundled daemon (lattice-daemon.exe) not found")?;

    // Persist identity under the app data dir — the unix default /var/lib/lattice
    // does not exist on Windows.
    let data_dir = app
        .path_resolver()
        .app_data_dir()
        .ok_or("could not resolve the app data directory")?;
    std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
    let identity = data_dir.join("identity.key");

    // Creating the Wintun adapter needs wintun.dll on the DLL search path
    // (next to the daemon, or in System32). When it's absent the daemon would
    // fail to open the TUN and exit immediately; fall back to a headless node
    // (--no-tun: control plane + discovery, no packet forwarding) so "Start
    // node" still brings the daemon up and status reflects it as running.
    let has_wintun = daemon
        .parent()
        .map(|d| d.join("wintun.dll").exists())
        .unwrap_or(false)
        || std::env::var_os("SystemRoot")
            .map(|root| std::path::Path::new(&root).join("System32\\wintun.dll").exists())
            .unwrap_or(false);

    // Single-quote for PowerShell: double any embedded quote.
    let daemon = daemon.to_string_lossy().replace('\'', "''");
    let identity = identity.to_string_lossy().replace('\'', "''");
    // Only the Wintun adapter needs Administrator; a headless node doesn't, so
    // skip the UAC prompt in that case.
    let (no_tun, run_as) = if has_wintun {
        ("", "-Verb RunAs ")
    } else {
        (",'--no-tun'", "")
    };
    let ps = format!(
        "Start-Process -FilePath '{daemon}' \
         -ArgumentList '--bind','0.0.0.0:41000','--identity','{identity}'{no_tun} \
         {run_as}-WindowStyle Hidden"
    );
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err("could not start the node — elevation was declined".into())
    }
}

/// Stop the daemon. A headless node runs unprivileged, so a plain taskkill ends
/// it; an elevated (Wintun) daemon can only be killed elevated, so fall back to
/// a UAC-prompting kill when the plain one doesn't succeed.
#[cfg(windows)]
#[tauri::command]
async fn stop_daemon() -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let plain = std::process::Command::new("taskkill")
        .args(["/F", "/IM", "lattice-daemon.exe"])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
    if matches!(plain, Ok(s) if s.success()) {
        return Ok(());
    }

    // Either access was denied (elevated daemon) — retry with elevation.
    let ps = "Start-Process -FilePath 'taskkill' \
              -ArgumentList '/F','/IM','lattice-daemon.exe' \
              -Verb RunAs -WindowStyle Hidden";
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", ps])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
#[tauri::command]
async fn start_daemon(_app: tauri::AppHandle) -> Result<(), String> {
    Err("GUI daemon control is implemented for macOS and Windows; on Linux run `sudo lattice-daemon`".into())
}

#[cfg(all(unix, not(target_os = "macos")))]
#[tauri::command]
async fn stop_daemon() -> Result<(), String> {
    Err("GUI daemon control is implemented for macOS and Windows".into())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_status,
            list_peers,
            list_flows,
            list_flow_rules,
            add_flow_rule,
            del_flow_rule,
            clear_flow_rules,
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
            relay_peer,
            meshd
        ])
        .run(tauri::generate_context!())
        .expect("error while running Lattice GUI");
}
