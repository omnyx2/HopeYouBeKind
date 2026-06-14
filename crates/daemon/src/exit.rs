//! Exit-node OS plumbing.
//!
//! Two sides:
//! - **client**: divert the host's default route through the tunnel so all
//!   internet traffic enters the mesh (pinning a host route to the exit's
//!   physical endpoint via the real gateway so the tunnel itself doesn't loop);
//! - **exit**: enable IP forwarding + source NAT so tunnelled traffic reaches
//!   the internet as the exit's address.
//!
//! ⚠️ This changes the system routing table and needs root. Every change is
//! saved and restored (`restore_routes`). Untested across the full two-machine
//! path — verify on a spare host. See `docs/EXIT_NODE.md`.

use std::net::IpAddr;
#[cfg(any(unix, windows))]
use std::process::Command;

/// Where we stash the original default route so we can put it back.
#[cfg(unix)]
const SAVED: &str = "/tmp/lattice-saved-default";

#[cfg(any(unix, windows))]
fn run(cmd: &str, args: &[&str]) {
    match Command::new(cmd).args(args).status() {
        Ok(s) if s.success() => {}
        Ok(s) => tracing::warn!(cmd, ?args, "command exited {s}"),
        Err(e) => tracing::warn!(cmd, error = %e, "failed to run"),
    }
}

// ----------------------------- macOS -----------------------------
#[cfg(target_os = "macos")]
pub fn route_through(tun: &str, exit_ip: IpAddr) {
    let Some(gw) = macos_default_gateway() else {
        tracing::warn!("no default gateway found; exit routes not applied");
        return;
    };
    let _ = std::fs::write(SAVED, &gw);
    // Keep the path to the exit's physical endpoint off the tunnel (no loop).
    run("route", &["-q", "add", "-host", &exit_ip.to_string(), &gw]);
    // Send everything else into the tunnel.
    run("route", &["-q", "change", "default", "-interface", tun]);
    tracing::warn!(%exit_ip, tun, "default route diverted through exit node");
}

#[cfg(target_os = "macos")]
pub fn restore_routes() {
    if let Ok(gw) = std::fs::read_to_string(SAVED) {
        run("route", &["-q", "change", "default", gw.trim()]);
        let _ = std::fs::remove_file(SAVED);
        tracing::info!("default route restored");
    }
}

#[cfg(target_os = "macos")]
fn macos_default_gateway() -> Option<String> {
    let out = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
        l.trim()
            .strip_prefix("gateway:")
            .map(|g| g.trim().to_string())
    })
}

/// Where we record that pf was off before we enabled it, so `disable_nat` can
/// put pf back the way it found it (and not leave the user's pf forced on).
#[cfg(target_os = "macos")]
const PF_WAS_OFF: &str = "/tmp/lattice-pf-was-off";

#[cfg(target_os = "macos")]
fn macos_default_iface() -> Option<String> {
    let out = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
        l.trim()
            .strip_prefix("interface:")
            .map(|s| s.trim().to_string())
    })
}

#[cfg(target_os = "macos")]
pub fn enable_nat() {
    run("sysctl", &["-w", "net.inet.ip.forwarding=1"]);
    let Some(wan) = macos_default_iface() else {
        tracing::warn!("no default interface; macOS exit NAT not applied");
        return;
    };
    // Source-NAT tunnelled (overlay-range) traffic out the WAN. A ruleset with
    // only a nat rule leaves the filter ruleset empty == default-pass, so
    // forwarded packets (tun→WAN, enabled by ip.forwarding) pass and get NAT'd.
    let conf = format!("nat on {wan} from 100.64.0.0/10 to any -> ({wan})\n");
    if std::fs::write("/tmp/lattice-pf.conf", &conf).is_err() {
        tracing::warn!("could not write pf ruleset; exit NAT not applied");
        return;
    }
    // Remember pf's prior state so we can restore it. `pfctl -s info` starts with
    // "Status: Enabled" or "Status: Disabled".
    let was_enabled = Command::new("pfctl")
        .args(["-s", "info"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("Status: Enabled"))
        .unwrap_or(false);
    if !was_enabled {
        let _ = std::fs::write(PF_WAS_OFF, "1");
    }
    run("pfctl", &["-f", "/tmp/lattice-pf.conf"]);
    run("pfctl", &["-e"]); // harmless "already enabled" if it was on
    tracing::warn!(wan, "macOS exit NAT enabled (pf nat 100.64.0.0/10 -> WAN)");
}

#[cfg(target_os = "macos")]
pub fn disable_nat() {
    // Restore the system pf ruleset, then put pf's enabled/disabled state back.
    run("pfctl", &["-f", "/etc/pf.conf"]);
    if std::fs::remove_file(PF_WAS_OFF).is_ok() {
        run("pfctl", &["-d"]); // pf was off before us → turn it back off
    }
    let _ = std::fs::remove_file("/tmp/lattice-pf.conf");
    run("sysctl", &["-w", "net.inet.ip.forwarding=0"]);
}

// ----------------------------- Linux -----------------------------
#[cfg(target_os = "linux")]
pub fn route_through(tun: &str, exit_ip: IpAddr) {
    let Some((gw, dev)) = linux_default_route() else {
        tracing::warn!("no default route found; exit routes not applied");
        return;
    };
    let _ = std::fs::write(SAVED, format!("{gw} {dev}"));
    run(
        "ip",
        &[
            "route",
            "add",
            &format!("{exit_ip}/32"),
            "via",
            &gw,
            "dev",
            &dev,
        ],
    );
    run("ip", &["route", "replace", "default", "dev", tun]);
    tracing::warn!(%exit_ip, tun, "default route diverted through exit node");
}

#[cfg(target_os = "linux")]
pub fn restore_routes() {
    if let Ok(s) = std::fs::read_to_string(SAVED) {
        let mut it = s.split_whitespace();
        if let (Some(gw), Some(dev)) = (it.next(), it.next()) {
            run(
                "ip",
                &["route", "replace", "default", "via", gw, "dev", dev],
            );
        }
        let _ = std::fs::remove_file(SAVED);
        tracing::info!("default route restored");
    }
}

#[cfg(target_os = "linux")]
fn linux_default_route() -> Option<(String, String)> {
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let toks: Vec<&str> = text.split_whitespace().collect();
    let gw = toks
        .iter()
        .position(|&t| t == "via")
        .and_then(|i| toks.get(i + 1))
        .map(|s| s.to_string())?;
    let dev = toks
        .iter()
        .position(|&t| t == "dev")
        .and_then(|i| toks.get(i + 1))
        .map(|s| s.to_string())?;
    Some((gw, dev))
}

#[cfg(target_os = "linux")]
pub fn enable_nat() {
    run("sysctl", &["-w", "net.ipv4.ip_forward=1"]);
    if let Some((_, wan)) = linux_default_route() {
        run(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "100.64.0.0/10",
                "-o",
                &wan,
                "-j",
                "MASQUERADE",
            ],
        );
        // INSERT at the top, not append: distros like RHEL/Oracle Linux ship a
        // default `FORWARD -j REJECT` rule, so an appended ACCEPT never runs and
        // forwarded (exit) traffic is rejected. -I puts us before that REJECT.
        run(
            "iptables",
            &["-I", "FORWARD", "1", "-s", "100.64.0.0/10", "-j", "ACCEPT"],
        );
        run(
            "iptables",
            &["-I", "FORWARD", "1", "-d", "100.64.0.0/10", "-j", "ACCEPT"],
        );
        tracing::warn!(wan, "exit NAT enabled (masquerade)");
    }
}

#[cfg(target_os = "linux")]
pub fn disable_nat() {
    if let Some((_, wan)) = linux_default_route() {
        run(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                "100.64.0.0/10",
                "-o",
                &wan,
                "-j",
                "MASQUERADE",
            ],
        );
    }
    run("sysctl", &["-w", "net.ipv4.ip_forward=0"]);
}

// ----------------------------- Windows -----------------------------
// Routes/NAT via PowerShell cmdlets (Get/New/Remove-NetRoute, *-NetNat). The
// TUN is the Wintun adapter named "Lattice". Requires Administrator. Untested
// across the full path — verify on a spare host.
#[cfg(target_os = "windows")]
const WIN_SAVED: &str = r"C:\Windows\Temp\lattice-saved-route.txt";

#[cfg(target_os = "windows")]
fn ps(script: &str) {
    run(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", script],
    );
}

#[cfg(target_os = "windows")]
pub fn route_through(tun: &str, exit_ip: IpAddr) {
    // Save the current default route (gateway + ifIndex), pin a host route to the
    // exit's physical endpoint via that gateway (so the tunnel doesn't loop), then
    // override the default with two /1 routes via the TUN (more specific than
    // 0.0.0.0/0, so they win without deleting the real default — OpenVPN-style).
    let script = format!(
        r#"
$ErrorActionPreference='SilentlyContinue'
$def = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1
'{exit}' | Set-Content -Path '{saved}'
$idx = (Get-NetAdapter -Name '{tun}').ifIndex
New-NetRoute -DestinationPrefix '{exit}/32' -NextHop $def.NextHop -InterfaceIndex $def.ifIndex -RouteMetric 1 -PolicyStore ActiveStore
New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceIndex $idx -NextHop 0.0.0.0 -RouteMetric 1 -PolicyStore ActiveStore
New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceIndex $idx -NextHop 0.0.0.0 -RouteMetric 1 -PolicyStore ActiveStore
"#,
        saved = WIN_SAVED,
        tun = tun,
        exit = exit_ip
    );
    ps(&script);
    tracing::warn!(%exit_ip, tun, "default route diverted through exit node (windows)");
}

#[cfg(target_os = "windows")]
pub fn restore_routes() {
    let script = format!(
        r#"
$ErrorActionPreference='SilentlyContinue'
Remove-NetRoute -DestinationPrefix '0.0.0.0/1' -Confirm:$false
Remove-NetRoute -DestinationPrefix '128.0.0.0/1' -Confirm:$false
if (Test-Path '{saved}') {{
  $exit = (Get-Content '{saved}').Trim()
  Remove-NetRoute -DestinationPrefix "$exit/32" -Confirm:$false
  Remove-Item '{saved}'
}}
"#,
        saved = WIN_SAVED
    );
    ps(&script);
    tracing::info!("default route restored (windows)");
}

#[cfg(target_os = "windows")]
pub fn enable_nat() {
    // Forward between interfaces + WinNAT for the overlay range.
    ps("Set-NetIPInterface -Forwarding Enabled -ErrorAction SilentlyContinue");
    ps("if (-not (Get-NetNat -Name Lattice -ErrorAction SilentlyContinue)) { New-NetNat -Name Lattice -InternalIPInterfaceAddressPrefix 100.64.0.0/10 }");
    tracing::warn!("windows exit NAT enabled (WinNAT 100.64.0.0/10)");
}

#[cfg(target_os = "windows")]
pub fn disable_nat() {
    ps("Remove-NetNat -Name Lattice -Confirm:$false -ErrorAction SilentlyContinue");
}

// ------------------------- other platforms -------------------------
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn route_through(_tun: &str, _exit_ip: IpAddr) {
    tracing::warn!("exit-node routing not implemented on this platform");
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn restore_routes() {}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn enable_nat() {
    tracing::warn!("exit-node NAT not implemented on this platform");
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn disable_nat() {}
