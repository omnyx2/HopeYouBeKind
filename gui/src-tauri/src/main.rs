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

/// The app version (from tauri.conf.json) — shown small in the GUI corner.
#[tauri::command]
fn app_version(app: tauri::AppHandle) -> String {
    app.package_info().version.to_string()
}

/// The tray menu (docs/LIFECYCLE.md §3): a live status line, open, and TWO explicit
/// quits — the default keeps the VPN running (the daemon is a background service the
/// GUI merely observes), the other stops it. Window close hides to the tray.
fn tray() -> tauri::SystemTray {
    use tauri::{CustomMenuItem, SystemTray, SystemTrayMenu, SystemTrayMenuItem};
    let menu = SystemTrayMenu::new()
        .add_item(CustomMenuItem::new("status", "Lattice — 상태 확인 중…").disabled())
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(CustomMenuItem::new("open", "Lattice 열기"))
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(CustomMenuItem::new("quit_keep", "종료 (VPN 유지)"))
        .add_item(CustomMenuItem::new("quit_stop", "종료 + VPN 중지"));
    SystemTray::new().with_menu(menu)
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            ensure_meshd(&app.handle());
            Ok(())
        })
        .system_tray(tray())
        .on_system_tray_event(|app, event| {
            use tauri::{Manager, SystemTrayEvent};
            let show = |app: &tauri::AppHandle| {
                if let Some(w) = app.get_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            };
            match event {
                // Left-click opens the window where the OS delivers clicks (Windows/Linux;
                // macOS shows the menu natively).
                SystemTrayEvent::LeftClick { .. } => show(app),
                SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                    "open" => show(app),
                    // Default quit: the GUI goes away, the VPN (a background service)
                    // keeps running — ownership belongs to the OS service manager /
                    // the user's explicit choice, not to this window's lifetime.
                    "quit_keep" => app.exit(0),
                    // Explicit full stop: restore routes/DNS and stop the daemon.
                    "quit_stop" => {
                        send_shutdown();
                        app.exit(0);
                    }
                    _ => {}
                },
                _ => {}
            }
        })
        .on_window_event(|event| {
            // Closing the window hides to the tray instead of quitting — the app (and
            // the VPN) stay up. Quit explicitly from the tray menu.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event.event() {
                let _ = event.window().hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            meshd,
            check_update,
            open_url,
            notify,
            app_version,
            tray_status,
            daemon_status,
            daemon_start,
            set_daemon_boot,
            set_gui_autostart
        ])
        .build(tauri::generate_context!())
        .expect("error while running Lattice GUI")
        .run(|_app, _event| {
            // NOTE: the old handler sent Shutdown on ExitRequested — that was the
            // GUI-owns-the-daemon model's orphan guard. Under the service model
            // (docs/LIFECYCLE.md §1) an outliving daemon is the FEATURE; only the
            // tray's "종료 + VPN 중지" stops it.
        });
}

// ---- lifecycle commands (docs/LIFECYCLE.md) -----------------------------------------

/// Update the tray's status line + tooltip. The front-end calls this from its poll
/// tick — it already knows the daemon/egress state better than anyone.
#[tauri::command]
fn tray_status(app: tauri::AppHandle, summary: String) {
    let item = app.tray_handle().get_item("status");
    let _ = item.set_title(format!("Lattice — {summary}"));
    #[cfg(not(target_os = "linux"))] // tooltips are unsupported on libappindicator
    let _ = app
        .tray_handle()
        .set_tooltip(&format!("Lattice — {summary}"));
}

/// One snapshot for the Settings panel: is the daemon reachable, is boot-start
/// installed, is GUI login-autostart installed.
#[tauri::command]
fn daemon_status() -> serde_json::Value {
    serde_json::json!({
        "running": meshd_running(),
        "boot": daemon_boot_enabled(),
        "gui_autostart": gui_autostart_enabled(),
    })
}

/// Start the daemon on demand (the Settings button / first-run path). Same elevated
/// launch `setup` uses; returns whether the socket answered afterwards.
#[tauri::command]
async fn daemon_start(app: tauri::AppHandle) -> Result<bool, String> {
    if meshd_running() {
        return Ok(true);
    }
    tauri::async_runtime::spawn_blocking(move || {
        ensure_meshd(&app);
        for _ in 0..20 {
            if meshd_running() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        meshd_running()
    })
    .await
    .map_err(|e| e.to_string())
}

/// Install/remove the OS boot service for meshd (docs/LIFECYCLE.md §2) — one
/// elevation prompt either way. Enabling first stops a manually-launched daemon so
/// the service instance takes over cleanly (the single-instance guard would
/// otherwise make launchd/systemd flap against it).
#[tauri::command]
async fn set_daemon_boot(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || set_daemon_boot_blocking(&app, enabled))
        .await
        .map_err(|e| e.to_string())?
}

/// Install/remove GUI login autostart — per-user, no elevation.
#[tauri::command]
fn set_gui_autostart(enabled: bool) -> Result<(), String> {
    set_gui_autostart_impl(enabled)
}

#[cfg(target_os = "macos")]
const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/dev.lattice.meshd.plist";

#[cfg(target_os = "macos")]
fn daemon_boot_enabled() -> bool {
    std::path::Path::new(LAUNCHD_PLIST).exists()
}

/// macOS boot service = a LaunchDaemon. KeepAlive only on CRASH (SuccessfulExit=false):
/// a clean exit — the Shutdown IPC, or the single-instance guard deferring — must NOT
/// bounce back, or "종료 + VPN 중지" would fight launchd forever.
#[cfg(target_os = "macos")]
fn set_daemon_boot_blocking(app: &tauri::AppHandle, enabled: bool) -> Result<(), String> {
    if !enabled {
        let script = format!(
            "do shell script \"launchctl unload -w {LAUNCHD_PLIST} 2>/dev/null; rm -f {LAUNCHD_PLIST}\" \
             with administrator privileges \
             with prompt \"Lattice: 부팅 시 VPN 자동 시작을 해제합니다.\""
        );
        return run_osascript(&script);
    }
    let meshd = app
        .path_resolver()
        .resolve_resource("resources/meshd")
        .filter(|p| p.exists())
        .ok_or("bundled meshd not found (dev build?)")?;
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.lattice.meshd</string>
  <key>ProgramArguments</key><array>
    <string>{meshd}</string>
    <string>{sock}</string>
  </array>
  <key>EnvironmentVariables</key><dict><key>DATA_PLANE</key><string>1</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>StandardOutPath</key><string>/tmp/lattice-meshd.log</string>
  <key>StandardErrorPath</key><string>/tmp/lattice-meshd.log</string>
</dict></plist>
"#,
        meshd = meshd.to_string_lossy(),
        sock = MESHD_SOCKET
    );
    // Write the plist UNPRIVILEGED to a temp file, then one admin shell installs it —
    // no plist-in-AppleScript quoting, and the daemon swap is a clean handover: stop
    // the manual daemon (world-writable socket, no sudo needed for the IPC — but we're
    // already elevated here) and let launchd own it from now on.
    let tmp = std::env::temp_dir().join("dev.lattice.meshd.plist");
    std::fs::write(&tmp, plist).map_err(|e| e.to_string())?;
    send_shutdown(); // hand over: the service instance becomes the one owner
    let script = format!(
        "do shell script \"install -m 644 -o root -g wheel '{tmp}' {LAUNCHD_PLIST} \
         && launchctl unload -w {LAUNCHD_PLIST} 2>/dev/null; launchctl load -w {LAUNCHD_PLIST}\" \
         with administrator privileges \
         with prompt \"Lattice: 부팅 시 VPN 자동 시작을 설정합니다.\"",
        tmp = tmp.to_string_lossy()
    );
    run_osascript(&script)
}

#[cfg(target_os = "macos")]
fn run_osascript(script: &str) -> Result<(), String> {
    let st = std::process::Command::new("osascript")
        .arg("-e")
        .arg(script)
        .status()
        .map_err(|e| e.to_string())?;
    if st.success() {
        Ok(())
    } else {
        Err("권한 요청이 취소되었거나 실패했습니다".into())
    }
}

#[cfg(target_os = "linux")]
const SYSTEMD_UNIT: &str = "/etc/systemd/system/lattice-meshd.service";

#[cfg(target_os = "linux")]
fn daemon_boot_enabled() -> bool {
    std::path::Path::new(SYSTEMD_UNIT).exists()
}

/// Linux boot service = the SAME systemd unit `lattice install-service` writes (one
/// definition, two installers), installed via pkexec.
#[cfg(target_os = "linux")]
fn set_daemon_boot_blocking(app: &tauri::AppHandle, enabled: bool) -> Result<(), String> {
    let pkexec = |cmd: &str| -> Result<(), String> {
        let st = std::process::Command::new("pkexec")
            .args(["sh", "-c", cmd])
            .status()
            .map_err(|e| e.to_string())?;
        if st.success() {
            Ok(())
        } else {
            Err("권한 요청이 취소되었거나 실패했습니다".into())
        }
    };
    if !enabled {
        return pkexec(&format!(
            "systemctl disable --now lattice-meshd 2>/dev/null; rm -f {SYSTEMD_UNIT}; systemctl daemon-reload"
        ));
    }
    let meshd = app
        .path_resolver()
        .resolve_resource("resources/meshd")
        .filter(|p| p.exists())
        .ok_or("bundled meshd not found (dev build?)")?;
    let unit = format!(
        "[Unit]\nDescription=Lattice mesh VPN daemon (meshd)\nAfter=network-online.target\nWants=network-online.target\n\n\
         [Service]\nType=simple\nEnvironment=\"DATA_PLANE=1\"\nExecStart={} {}\nRestart=always\nRestartSec=3\nUser=root\n\
         AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW\n\n[Install]\nWantedBy=multi-user.target\n",
        meshd.to_string_lossy(),
        MESHD_SOCKET
    );
    let tmp = std::env::temp_dir().join("lattice-meshd.service");
    std::fs::write(&tmp, unit).map_err(|e| e.to_string())?;
    send_shutdown(); // hand over to the service instance
    pkexec(&format!(
        "install -m 644 '{}' {SYSTEMD_UNIT} && systemctl daemon-reload && systemctl enable --now lattice-meshd",
        tmp.to_string_lossy()
    ))
}

#[cfg(target_os = "windows")]
fn daemon_boot_enabled() -> bool {
    std::process::Command::new("schtasks")
        .args(["/Query", "/TN", r"Lattice\meshd"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Windows boot service = a Task Scheduler ONSTART task running a %ProgramData% copy
/// as SYSTEM (a native service is a later step — docs/LIFECYCLE.md §2/§7).
#[cfg(target_os = "windows")]
fn set_daemon_boot_blocking(app: &tauri::AppHandle, enabled: bool) -> Result<(), String> {
    let elevated = |inner: &str| -> Result<(), String> {
        let ps = format!(
            "Start-Process -FilePath 'powershell' -ArgumentList '-NoProfile','-NonInteractive','-Command','{}' -Verb RunAs -Wait -WindowStyle Hidden",
            inner.replace('\'', "''")
        );
        let st = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
            .status()
            .map_err(|e| e.to_string())?;
        if st.success() {
            Ok(())
        } else {
            Err("권한 요청이 취소되었거나 실패했습니다".into())
        }
    };
    if !enabled {
        return elevated(r"schtasks /Delete /TN 'Lattice\meshd' /F");
    }
    let bundled = app
        .path_resolver()
        .resolve_resource("resources/meshd.exe")
        .filter(|p| p.exists())
        .ok_or("bundled meshd not found (dev build?)")?;
    send_shutdown(); // hand over to the task instance
    let staged = r"C:\ProgramData\Lattice\meshd.exe";
    elevated(&format!(
        "New-Item -ItemType Directory -Force 'C:\\ProgramData\\Lattice' | Out-Null; \
         Copy-Item -Force '{}' '{staged}'; \
         schtasks /Create /TN 'Lattice\\meshd' /TR '\"{staged}\" --data-plane' /SC ONSTART /RU SYSTEM /RL HIGHEST /F; \
         schtasks /Run /TN 'Lattice\\meshd'",
        bundled.to_string_lossy()
    ))
}

// ---- GUI login autostart (per-user, no elevation) ----

#[cfg(target_os = "macos")]
fn gui_agent_plist() -> Option<std::path::PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|h| std::path::PathBuf::from(h).join("Library/LaunchAgents/dev.lattice.gui.plist"))
}

#[cfg(target_os = "macos")]
fn gui_autostart_enabled() -> bool {
    gui_agent_plist().map(|p| p.exists()).unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn set_gui_autostart_impl(enabled: bool) -> Result<(), String> {
    let plist = gui_agent_plist().ok_or("no HOME")?;
    if !enabled {
        let _ = std::fs::remove_file(&plist);
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    if let Some(dir) = plist.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.lattice.gui</string>
  <key>ProgramArguments</key><array><string>{}</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
"#,
        exe.to_string_lossy()
    );
    std::fs::write(&plist, body).map_err(|e| e.to_string())
}

#[cfg(target_os = "linux")]
fn gui_desktop_file() -> Option<std::path::PathBuf> {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| std::path::PathBuf::from(h).join(".config")))
        .ok()?;
    Some(base.join("autostart/lattice.desktop"))
}

#[cfg(target_os = "linux")]
fn gui_autostart_enabled() -> bool {
    gui_desktop_file().map(|p| p.exists()).unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn set_gui_autostart_impl(enabled: bool) -> Result<(), String> {
    let f = gui_desktop_file().ok_or("no HOME")?;
    if !enabled {
        let _ = std::fs::remove_file(&f);
        return Ok(());
    }
    if let Some(dir) = f.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let body = format!(
        "[Desktop Entry]\nType=Application\nName=Lattice\nExec={}\nX-GNOME-Autostart-enabled=true\n",
        exe.to_string_lossy()
    );
    std::fs::write(&f, body).map_err(|e| e.to_string())
}

#[cfg(target_os = "windows")]
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

#[cfg(target_os = "windows")]
fn gui_autostart_enabled() -> bool {
    std::process::Command::new("reg")
        .args(["query", RUN_KEY, "/v", "Lattice"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn set_gui_autostart_impl(enabled: bool) -> Result<(), String> {
    if !enabled {
        let _ = std::process::Command::new("reg")
            .args(["delete", RUN_KEY, "/v", "Lattice", "/f"])
            .status();
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let st = std::process::Command::new("reg")
        .args([
            "add",
            RUN_KEY,
            "/v",
            "Lattice",
            "/t",
            "REG_SZ",
            "/d",
            &exe.to_string_lossy(),
            "/f",
        ])
        .status()
        .map_err(|e| e.to_string())?;
    if st.success() {
        Ok(())
    } else {
        Err("registry write failed".into())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn daemon_boot_enabled() -> bool {
    false
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn set_daemon_boot_blocking(_app: &tauri::AppHandle, _e: bool) -> Result<(), String> {
    Err("unsupported platform".into())
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn gui_autostart_enabled() -> bool {
    false
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn set_gui_autostart_impl(_e: bool) -> Result<(), String> {
    Err("unsupported platform".into())
}

/// Tell the running `meshd` to stop itself (the `Shutdown` IPC). Best-effort: if the
/// daemon isn't up, do nothing. The socket is world-writable, so no elevation is needed.
#[cfg(unix)]
fn send_shutdown() {
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    if let Ok(mut s) = UnixStream::connect(MESHD_SOCKET) {
        let _ = s.write_all(b"\"Shutdown\"\n");
        let _ = s.flush();
        std::thread::sleep(std::time::Duration::from_millis(250)); // let meshd ack + exit
    }
}

#[cfg(windows)]
fn send_shutdown() {
    use std::fs::OpenOptions;
    use std::io::Write;
    if let Ok(pipe) = OpenOptions::new().read(true).write(true).open(MESHD_SOCKET) {
        let _ = (&pipe).write_all(b"\"Shutdown\"\n");
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// On startup make sure the privileged `meshd` daemon is running. If it isn't,
/// launch the bundled binary with a ONE-TIME elevation prompt — the OS's native
/// auth dialog, NOT a terminal — so Lattice is a clean double-click with no manual
/// `sudo meshd`. Best-effort: in dev (no bundled binary) or if already running, do
/// nothing.
#[cfg(not(windows))]
fn ensure_meshd(app: &tauri::AppHandle) {
    if meshd_running() {
        return;
    }
    // On Unix a running binary can be overwritten in place (the live process keeps its
    // inode), so the install-dir copy is safe to run directly and updates land fine.
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

/// Windows: run meshd from a per-user COPY (`%LOCALAPPDATA%\Lattice\meshd.exe`), NEVER
/// directly from the install dir. Windows cannot overwrite a running `.exe`, so running
/// `resources\meshd.exe` would lock it — the installer then silently keeps the OLD daemon
/// on every update (the GUI updates, meshd does not; the exact "reinstalled but still
/// broken" bug). Running from a copy keeps the install-dir binary unlocked, so the
/// installer always replaces it. On the next launch we notice the bundled binary is newer
/// than our copy, stop the stale daemon via the `Shutdown` IPC (world-writable pipe — no
/// elevation), refresh the copy, and relaunch. A normal launch (no update, daemon already
/// current) is a no-op, so a running VPN is left alone.
#[cfg(windows)]
fn ensure_meshd(app: &tauri::AppHandle) {
    let bundled = match app.path_resolver().resolve_resource("resources/meshd.exe") {
        Some(p) if p.exists() => p,
        _ => {
            eprintln!("Lattice: bundled meshd not found (dev build?) — start meshd manually");
            return;
        }
    };
    let run_dir = std::path::PathBuf::from(
        std::env::var("LOCALAPPDATA").unwrap_or_else(|_| r"C:\Windows\Temp".to_string()),
    )
    .join("Lattice");
    let run_copy = run_dir.join("meshd.exe");

    let newer = !run_copy.exists() || files_differ(&bundled, &run_copy);
    let running = meshd_running();

    // Daemon already up AND current — leave the running VPN untouched.
    if running && !newer {
        return;
    }
    // A newer meshd was just installed: stop the stale daemon so we can replace the copy.
    if running && newer {
        send_shutdown();
        for _ in 0..20 {
            if !meshd_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(150));
        }
    }
    let _ = std::fs::create_dir_all(&run_dir);
    if newer || !run_copy.exists() {
        if let Err(e) = std::fs::copy(&bundled, &run_copy) {
            // Copy failed (e.g. the old daemon didn't exit in time and still locks the copy).
            // Fall back to the install-dir binary so the VPN still comes up this session.
            eprintln!("Lattice: could not stage meshd copy ({e}); running bundled directly");
            launch_meshd_elevated(&bundled.to_string_lossy());
            std::thread::sleep(std::time::Duration::from_millis(1800));
            return;
        }
    }
    launch_meshd_elevated(&run_copy.to_string_lossy());
    // Give meshd a moment to bind its pipe before the UI starts polling.
    std::thread::sleep(std::time::Duration::from_millis(1800));
}

/// Cheap "are these two files different?": compare length, then full bytes on a tie. Run
/// once at startup, so reading two ~2-3 MB binaries is negligible.
#[cfg(windows)]
fn files_differ(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(ma), Ok(mb)) => {
            if ma.len() != mb.len() {
                return true;
            }
            match (std::fs::read(a), std::fs::read(b)) {
                (Ok(da), Ok(db)) => da != db,
                _ => true,
            }
        }
        _ => true,
    }
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
/// Launch meshd.exe **directly** with clean args: the socket + `--data-plane`. No `cmd`
/// wrapper, no env var, no output redirect, no extra quoting — every one of those was a
/// failure mode under RunAs (the cmd redirect to an elevated `%TEMP%` that doesn't exist
/// aborted the launch with "path not found"). `--data-plane` enables the data plane
/// without needing an inherited env var; meshd writes its own log to a temp file.
#[cfg(target_os = "windows")]
fn launch_meshd_elevated(meshd: &str) {
    // Do NOT pass the pipe path as an argument: `\\.\pipe\…` backslashes get mangled
    // going through PowerShell/ShellExecute, so meshd would create a DIFFERENTLY-named
    // pipe than the one this GUI connects to (-> os error 2, and the GUI relaunches meshd
    // forever). meshd falls back to its DEFAULT_SOCKET constant, which is byte-for-byte
    // the same value as MESHD_SOCKET here — so the names always match.
    let ps = format!(
        "Start-Process -FilePath '{meshd}' -ArgumentList '--data-plane' \
         -Verb RunAs -WindowStyle Hidden"
    );
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .status();
}
