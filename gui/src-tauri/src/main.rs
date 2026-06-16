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

/// Where the v2 mesh control-plane daemon (`meshd`) listens: a unix domain socket
/// on macOS/Linux, a named pipe on Windows.
#[cfg(unix)]
const MESHD_SOCKET: &str = "/tmp/lattice-meshd.sock";
#[cfg(windows)]
const MESHD_SOCKET: &str = r"\\.\pipe\lattice-meshd";

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

/// Windows: a named pipe client is just the pipe path opened as a file. Same
/// newline-JSON protocol; run on a blocking thread so the UI never stalls.
#[cfg(windows)]
#[tauri::command]
async fn meshd(request: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || -> Result<String, String> {
        use std::fs::OpenOptions;
        use std::io::{BufRead, BufReader, Write};
        // ERROR_PIPE_BUSY (231): every server pipe instance is momentarily busy. The
        // GUI polls several endpoints at once, so retry briefly instead of failing.
        let pipe = {
            let mut tries = 0;
            loop {
                match OpenOptions::new().read(true).write(true).open(MESHD_SOCKET) {
                    Ok(p) => break p,
                    Err(e) if e.raw_os_error() == Some(231) && tries < 40 => {
                        tries += 1;
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                    Err(e) => return Err(format!("meshd not running ({MESHD_SOCKET}): {e}")),
                }
            }
        };
        let mut line = request;
        line.push('\n');
        (&pipe)
            .write_all(line.as_bytes())
            .map_err(|e| e.to_string())?;
        let mut resp = String::new();
        BufReader::new(&pipe)
            .read_line(&mut resp)
            .map_err(|e| e.to_string())?;
        Ok(resp.trim_end().to_string())
    })
    .await
    .map_err(|e| format!("meshd bridge task failed: {e}"))?
}

#[cfg(not(any(unix, windows)))]
#[tauri::command]
fn meshd(_request: String) -> Result<String, String> {
    Err("meshd is available on macOS/Linux/Windows".into())
}

/// The repo whose GitHub Releases hold the desktop installers.
const RELEASES_REPO: &str = "omnyx2/HopeYouBeKind";

/// Is dotted version `a` strictly newer than `b`? Compares numeric components
/// (`1.2.0` vs `1.10.0`); a non-numeric or missing component sorts as 0.
fn version_gt(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.trim_start_matches('v')
            .split(['.', '-', '+'])
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let (va, vb) = (parse(a), parse(b));
    for i in 0..va.len().max(vb.len()) {
        let (x, y) = (
            va.get(i).copied().unwrap_or(0),
            vb.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return x > y;
        }
    }
    false
}

/// Check GitHub Releases for a newer desktop build. Done here in Rust (off the
/// webview) so the CSP/allowlist stays locked down. Returns the current + latest
/// versions, whether an update is available, and the release page URL.
#[tauri::command]
fn check_update(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let current = app.package_info().version.to_string();
    let url = format!("https://api.github.com/repos/{RELEASES_REPO}/releases/latest");
    let body: serde_json::Value = ureq::get(&url)
        .set("User-Agent", "Lattice-Updater")
        .set("Accept", "application/vnd.github+json")
        .timeout(std::time::Duration::from_secs(8))
        .call()
        .map_err(|e| format!("update check failed: {e}"))?
        .into_json()
        .map_err(|e| e.to_string())?;
    let latest = body["tag_name"]
        .as_str()
        .unwrap_or("")
        .trim_start_matches('v');
    let page = body["html_url"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://github.com/{RELEASES_REPO}/releases/latest"));
    Ok(serde_json::json!({
        "current": current,
        "latest": latest,
        "available": !latest.is_empty() && version_gt(latest, &current),
        "url": page,
    }))
}

/// Open a URL in the user's default browser (the release/download page). Uses the OS
/// opener directly so it works regardless of the locked-down Tauri shell scope.
#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("refusing to open a non-http(s) URL".into());
    }
    #[cfg(target_os = "macos")]
    let (cmd, args) = ("open", vec![url.as_str()]);
    #[cfg(target_os = "windows")]
    let (cmd, args) = ("cmd", vec!["/C", "start", "", url.as_str()]);
    #[cfg(target_os = "linux")]
    let (cmd, args) = ("xdg-open", vec![url.as_str()]);
    std::process::Command::new(cmd)
        .args(args)
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Raise a native desktop notification (used for attack detection). Done in Rust so
/// it works without opening up the webview's notification permission/CSP.
#[tauri::command]
fn notify(app: tauri::AppHandle, title: String, body: String) -> Result<(), String> {
    tauri::api::notification::Notification::new(&app.config().tauri.bundle.identifier)
        .title(title)
        .body(body)
        .show()
        .map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            ensure_meshd(app);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            meshd,
            check_update,
            open_url,
            notify
        ])
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
    #[cfg(windows)]
    let resource = "resources/meshd.exe";
    #[cfg(not(windows))]
    let resource = "resources/meshd";
    let meshd = match app.path_resolver().resolve_resource(resource) {
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
#[cfg(windows)]
fn meshd_running() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(MESHD_SOCKET)
        .is_ok()
}
#[cfg(not(any(unix, windows)))]
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
