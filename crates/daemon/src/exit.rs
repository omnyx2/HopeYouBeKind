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
use std::process::Command;

/// Where we stash the original default route so we can put it back.
const SAVED: &str = "/tmp/lattice-saved-default";

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

#[cfg(target_os = "macos")]
pub fn enable_nat() {
    run("sysctl", &["-w", "net.inet.ip.forwarding=1"]);
    tracing::warn!("IP forwarding on; macOS source-NAT needs a pf rule (see docs/EXIT_NODE.md)");
}

#[cfg(target_os = "macos")]
pub fn disable_nat() {
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
        run(
            "iptables",
            &["-A", "FORWARD", "-s", "100.64.0.0/10", "-j", "ACCEPT"],
        );
        run(
            "iptables",
            &["-A", "FORWARD", "-d", "100.64.0.0/10", "-j", "ACCEPT"],
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

// ------------------------- other platforms -------------------------
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn route_through(_tun: &str, _exit_ip: IpAddr) {
    tracing::warn!("exit-node routing not implemented on this platform");
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn restore_routes() {}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn enable_nat() {
    tracing::warn!("exit-node NAT not implemented on this platform");
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn disable_nat() {}
