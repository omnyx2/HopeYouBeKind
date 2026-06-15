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
        writer.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
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
        .invoke_handler(tauri::generate_handler![meshd])
        .run(tauri::generate_context!())
        .expect("error while running Lattice GUI");
}
