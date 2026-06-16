// Lattice GUI — Tauri shell (v2).
//
// The web front-end talks ONLY to `meshd` (the v2 multi-mesh control plane) through
// the single `meshd` proxy command below; all UI logic lives in the front-end +
// meshd. See docs/GUI.md and docs/GUI_PAGES.md. The legacy v1 daemon controls were
// removed per docs/GUI_PAGES.md §5.
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

/// Where the v2 mesh control-plane daemon (`meshd`) listens.
const MESHD_SOCKET: &str = "/tmp/lattice-meshd.sock";

/// Proxy one newline-JSON request to `meshd` and hand back its response line.
/// Browsers/JS can't open a unix socket, so this thin bridge is the GUI's only
/// native code.
/// Proxy one request to meshd. ASYNC + on a blocking thread + with socket
/// timeouts, so a slow/unresponsive meshd can NEVER hang the webview: the UI thread
/// is never touched, and every call returns (or errors) within a few seconds
/// instead of leaving a wedged blocking read that piles up across the 3s polls.
#[cfg(unix)]
#[tauri::command]
async fn meshd(request: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || -> Result<String, String> {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixStream;
        use std::time::Duration;
        let stream = UnixStream::connect(MESHD_SOCKET)
            .map_err(|e| format!("meshd not running ({MESHD_SOCKET}): {e}"))?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
        let mut line = request;
        line.push('\n');
        writer
            .write_all(line.as_bytes())
            .map_err(|e| e.to_string())?;
        let mut resp = String::new();
        BufReader::new(stream)
            .read_line(&mut resp)
            .map_err(|e| e.to_string())?;
        Ok(resp.trim_end().to_string())
    })
    .await
    .map_err(|e| format!("meshd bridge task failed: {e}"))?
}

#[cfg(not(unix))]
#[tauri::command]
fn meshd(_request: String) -> Result<String, String> {
    Err("meshd is available on macOS/Linux".into())
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            ensure_meshd(app);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![meshd])
        .run(tauri::generate_context!())
        .expect("error while running Lattice GUI");
}

/// On startup make sure the privileged `meshd` daemon is running. If it isn't,
/// launch the bundled binary with a ONE-TIME elevation prompt — the OS's native
/// auth dialog, NOT a terminal — so Lattice is a clean double-click with no manual
/// `sudo meshd`. Best-effort: in dev (no bundled binary) or if already running, do
/// nothing.
fn ensure_meshd(app: &tauri::App) {
    if meshd_running() {
        return;
    }
    let meshd = match app.path_resolver().resolve_resource("resources/meshd") {
        Some(p) if p.exists() => p.to_string_lossy().to_string(),
        _ => {
            eprintln!("Lattice: bundled meshd not found (dev build?) — start meshd manually");
            return;
        }
    };
    launch_meshd_elevated(&meshd);
    // Give meshd a moment to bind its socket before the UI starts polling.
    std::thread::sleep(std::time::Duration::from_millis(1800));
}

#[cfg(unix)]
fn meshd_running() -> bool {
    std::os::unix::net::UnixStream::connect(MESHD_SOCKET).is_ok()
}
#[cfg(not(unix))]
fn meshd_running() -> bool {
    false
}

/// macOS: `do shell script ... with administrator privileges` → native auth dialog
/// (no terminal); `&` detaches meshd as a background daemon.
#[cfg(target_os = "macos")]
fn launch_meshd_elevated(meshd: &str) {
    let script = format!(
        "do shell script \"DATA_PLANE=1 '{meshd}' '{MESHD_SOCKET}' >/tmp/lattice-meshd.log 2>&1 &\" \
         with administrator privileges \
         with prompt \"Lattice needs administrator access to create the VPN tunnel.\""
    );
    let _ = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .status();
}

/// Linux: pkexec shows a graphical PolicyKit auth dialog on the desktop; setsid +
/// redirect detaches meshd as a background daemon.
#[cfg(target_os = "linux")]
fn launch_meshd_elevated(meshd: &str) {
    let cmd = format!(
        "setsid env DATA_PLANE=1 '{meshd}' '{MESHD_SOCKET}' >/tmp/lattice-meshd.log 2>&1 &"
    );
    let _ = std::process::Command::new("pkexec")
        .args(["sh", "-c", &cmd])
        .status();
}

/// Windows: UAC elevation via PowerShell `Start-Process -Verb RunAs` (hidden window).
#[cfg(target_os = "windows")]
fn launch_meshd_elevated(meshd: &str) {
    let ps = format!(
        "Start-Process -FilePath '{meshd}' -ArgumentList '{MESHD_SOCKET}' -Verb RunAs -WindowStyle Hidden"
    );
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .status();
}
