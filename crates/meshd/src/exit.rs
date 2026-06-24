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
//!
//! ## Public API (each fn is defined three times — one per `#[cfg(target_os)]` macOS/Linux/
//! Windows — plus a no-op fallback; the per-OS bodies differ but the CONTRACT below is shared).
//! When editing, change ALL three OS branches: a fix to one does not touch the others.
//!
//! **Client side (the node consuming an exit):**
//! - [`route_through`]`(tun, exit_ip)` — turn full-tunnel ON: pin a `/32` to `exit_ip` via the
//!   REAL gateway (so the encrypted outer packets to the exit DON'T re-enter the tunnel), then
//!   point the default route at `tun`. **Invariant: pin BEFORE diverting, and divert only if the
//!   pin succeeded** — otherwise the exit's own outer packets loop into the tun (flood, no
//!   egress, kill-switch revert). The pin must be idempotent (delete any stale `/32` first).
//!   Saves the prior gateway + the pinned IP to disk for `restore_routes`.
//! - [`restore_routes`]`()` — turn full-tunnel OFF: put the saved default gateway back and delete
//!   the `/32` pin. Symmetric inverse of `route_through`. Best-effort (logs failures).
//! - [`set_dns`]`(servers)` / [`restore_dns`]`()` — point the host resolver through the tunnel and
//!   back. Saves the prior DNS config. Called alongside route_through/restore_routes so DNS isn't
//!   answered by a local resolver the exit can't reach.
//! - [`clear_exit_pin`]`()` — drop the `/32` pin + saved-gateway bookkeeping WITHOUT touching the
//!   live default route. For the network-change watcher: a pin made via the OLD gateway
//!   blackholes the exit after a network switch, and a stale saved-gateway would make a later
//!   `restore_routes` install a DEAD default. Clear them when not full-tunnelling / before re-pin.
//! - [`current_gateway`]`()` — the real default gateway as a stable string; the netchange watcher
//!   polls it to detect Wi-Fi↔cellular/new-network transitions. Must return the PHYSICAL gateway,
//!   never our own tun (macOS reports the tun as an iface, not an IP — filtered out).
//!
//! **Exit side (the node serving others):**
//! - [`enable_nat`]`(isolate)` — turn this node into an exit: enable IP forwarding + source-NAT
//!   the overlay range (`100.64.0.0/10`) out the WAN. `isolate` adds a rule pinning traffic we
//!   forward FOR OTHERS to the real WAN. **⚠ `isolate` must only apply to traffic from OTHER
//!   members, never our own** — the `100.64/10` selector also matches THIS node's own overlay IP,
//!   so the caller gates `isolate` to real (pinned) exit nodes; a plain client must pass
//!   `isolate=false` (else its own full-tunnel egress gets diverted off the tun → broken). The
//!   rules are NOT fully idempotent across OSes (Linux appends iptables dups on each call).
//! - [`disable_nat`]`()` — undo `enable_nat`: remove the NAT/forwarding rules and the isolate
//!   routing, restore the prior firewall state.
//!
//! Bookkeeping is on-disk temp files (`SAVED`, `EXIT_HOST_SAVED`, `DNS_SAVED`, pf/route state)
//! so a meshd restart can still restore. Helpers: [`run`] (fire-and-forget) /
//! [`run_checked`] (surfaces the error) wrap shell-outs; the OS gateway/iface lookups parse the
//! platform route tool.

use std::net::IpAddr;
#[cfg(any(unix, windows))]
use std::process::Command;

/// Where we stash the original default route so we can put it back.
#[cfg(unix)]
const SAVED: &str = "/tmp/lattice-saved-default";
/// Where we stash the original DNS config so `restore_dns` can put it back.
#[cfg(unix)]
const DNS_SAVED: &str = "/tmp/lattice-saved-resolv";
/// Where we record the `/32` host route to the exit's physical endpoint that
/// `route_through` pins (so the tunnel doesn't loop). `restore_routes` reads it to
/// delete that route — otherwise it lingers and a later connect to the exit IP fails
/// with `EADDRNOTAVAIL` once the diverted default is gone.
#[cfg(unix)]
const EXIT_HOST_SAVED: &str = "/tmp/lattice-saved-exit-host";

#[cfg(any(unix, windows))]
fn run(cmd: &str, args: &[&str]) {
    match Command::new(cmd).args(args).status() {
        Ok(s) if s.success() => {}
        Ok(s) => tracing::warn!(cmd, ?args, "command exited {s}"),
        Err(e) => tracing::warn!(cmd, error = %e, "failed to run"),
    }
}

/// Like [`run`] but returns the failure instead of swallowing it, so the apply
/// paths (route/DNS) can surface a real error to the user (dp_error) rather than
/// silently claiming success while the OS-side plumbing never took effect.
#[cfg(any(unix, windows))]
fn run_checked(cmd: &str, args: &[&str]) -> Result<(), String> {
    // Capture output (not inherit) so a non-zero exit can surface the tool's own
    // stderr — e.g. PowerShell's reason — instead of a bare "exited exit code: 1".
    match Command::new(cmd).args(args).output() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let reason = String::from_utf8_lossy(&o.stderr);
            let reason = reason.trim();
            let reason = if reason.is_empty() {
                String::from_utf8_lossy(&o.stdout).trim().to_string()
            } else {
                reason.to_string()
            };
            // Keep the message short: the exit code plus the first line of any reason.
            let head = reason.lines().next().unwrap_or("").trim();
            let m = if head.is_empty() {
                format!("`{cmd}` exited {}", o.status)
            } else {
                format!("`{cmd}` exited {}: {head}", o.status)
            };
            tracing::warn!("{m}");
            Err(m)
        }
        Err(e) => {
            let m = format!("`{cmd}` failed to launch: {e}");
            tracing::warn!("{m}");
            Err(m)
        }
    }
}

// ----------------------------- macOS -----------------------------
/// macOS full-tunnel ON (see module header `route_through` contract). Pins `exit_ip/32` via the
/// real gateway (`route add -host`, idempotent: delete-first), then `route change default
/// -interface tun`. Fail-closed: the default is diverted ONLY if the pin succeeded, so a failed
/// pin can't loop the exit's own outer packets into the tun. Saves gateway→`SAVED`, exit→`EXIT_HOST_SAVED`.
#[cfg(target_os = "macos")]
pub fn route_through(tun: &str, exit_ip: IpAddr) -> Result<(), String> {
    let Some(gw) = macos_default_gateway() else {
        return Err("no default gateway found; exit routes not applied".into());
    };
    let _ = std::fs::write(SAVED, &gw);
    // Keep the path to the exit's physical endpoint off the tunnel (no loop). Record
    // it so restore_routes can delete it — a left-behind /32 to the exit IP makes a
    // later connect to that IP fail with EADDRNOTAVAIL.
    let _ = std::fs::write(EXIT_HOST_SAVED, exit_ip.to_string());
    let mut errs = Vec::new();
    // Idempotent pin: drop any stale /32 to the exit first (a prior full-tunnel cycle whose
    // restore raced a kill-switch revert can leave one — possibly via the OLD tun). Without
    // this, `route add -host` fails with "File exists" and the stale (often tun-pointing)
    // route stays, so the exit's own outer tunnel packets loop back into the tun.
    let es = exit_ip.to_string();
    run("route", &["-q", "delete", "-host", &es]);
    if let Err(e) = run_checked("route", &["-q", "add", "-host", &es, &gw]) {
        errs.push(e);
    }
    // Only divert the default INTO the tunnel once the exit endpoint is pinned OFF it. If the
    // pin failed, diverting would route the outer tunnel packets (to the exit's public IP)
    // back into the tun → a packet flood that never reaches the exit and a kill-switch revert.
    // Fail closed instead: leave the default alone and surface the error.
    if errs.is_empty() {
        if let Err(e) = run_checked("route", &["-q", "change", "default", "-interface", tun]) {
            errs.push(e);
        }
    }
    if errs.is_empty() {
        tracing::warn!(%exit_ip, tun, "default route diverted through exit node");
        Ok(())
    } else {
        Err(errs.join("; "))
    }
}

/// macOS full-tunnel OFF (inverse of [`route_through`]): restore the saved default gateway and
/// delete the `/32` exit pin. Best-effort.
#[cfg(target_os = "macos")]
pub fn restore_routes() {
    if let Ok(gw) = std::fs::read_to_string(SAVED) {
        run("route", &["-q", "change", "default", gw.trim()]);
        let _ = std::fs::remove_file(SAVED);
        tracing::info!("default route restored");
    }
    // Tear down the pinned host route to the exit's physical endpoint.
    if let Ok(exit_ip) = std::fs::read_to_string(EXIT_HOST_SAVED) {
        run("route", &["-q", "delete", "-host", exit_ip.trim()]);
        let _ = std::fs::remove_file(EXIT_HOST_SAVED);
    }
}

/// Remove left-behind full-tunnel route bookkeeping WITHOUT touching the live default
/// route. Used by the network-change watcher: a `/32` pin made via the OLD gateway
/// blackholes the exit's IP after the network changes (`connect()` → `EADDRNOTAVAIL`),
/// and a stale `SAVED` default gateway would make a later `restore_routes` point the
/// default at a DEAD gateway (no internet). Both only legitimately exist while a full
/// tunnel is active, so when we're not (or are about to re-pin) we clear them.
#[cfg(target_os = "macos")]
pub fn clear_exit_pin() {
    if let Ok(exit_ip) = std::fs::read_to_string(EXIT_HOST_SAVED) {
        run("route", &["-q", "delete", "-host", exit_ip.trim()]);
        let _ = std::fs::remove_file(EXIT_HOST_SAVED);
    }
    // Drop a stale saved default gateway so a later `restore_routes` can't apply a dead one.
    let _ = std::fs::remove_file(SAVED);
}

/// The current default gateway (a stable string while the network is unchanged) — the
/// network-change watcher polls this to detect Wi-Fi↔cellular / new-network transitions.
#[cfg(target_os = "macos")]
pub fn current_gateway() -> Option<String> {
    macos_default_gateway()
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
            // Only a real next-hop IP counts. When full-tunnel diverts the default route
            // through our own mesh tun, `route get default` reports the gateway as an
            // interface/link (e.g. `index: 21 utun6`), NOT an IP — that is *our own*
            // tunnel, not a physical network change, so it must not trigger self-healing
            // (otherwise the netchange watcher fights the full-tunnel route it set).
            .filter(|g| g.parse::<std::net::IpAddr>().is_ok())
    })
}

/// Where we record that pf was off before we enabled it, so `disable_nat` can
/// put pf back the way it found it (and not leave the user's pf forced on).
#[cfg(target_os = "macos")]
const PF_WAS_OFF: &str = "/tmp/lattice-pf-was-off";

/// The interface of the current default route (e.g. `en0`) — the WAN we NAT/route-to out of.
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

/// macOS exit NAT (see module header `enable_nat` contract). Enables IP forwarding and writes a
/// pf ruleset: `nat on <wan> from 100.64.0.0/10 -> (<wan>)`, plus — when `isolate` — a
/// `pass out route-to (<wan> <gw>) from 100.64.0.0/10` that pins forwarded traffic to the real
/// WAN. ⚠ That selector also matches THIS node's OWN overlay IP, so the caller must pass
/// `isolate=true` ONLY for a real exit node (a client would divert its own egress off the tun).
/// Remembers pf's prior on/off state in `PF_WAS_OFF` for [`disable_nat`].
#[cfg(target_os = "macos")]
pub fn enable_nat(isolate: bool) {
    run("sysctl", &["-w", "net.inet.ip.forwarding=1"]);
    let Some(wan) = macos_default_iface() else {
        tracing::warn!("no default interface; macOS exit NAT not applied");
        return;
    };
    // Source-NAT tunnelled (overlay-range) traffic out the WAN. A ruleset with
    // only a nat rule leaves the filter ruleset empty == default-pass, so
    // forwarded packets (tun→WAN, enabled by ip.forwarding) pass and get NAT'd.
    let mut conf = format!("nat on {wan} from 100.64.0.0/10 to any -> ({wan})\n");
    // Exit-policy ISOLATE (docs/EXIT_POLICY.md): force traffic we forward FOR OTHERS
    // (sourced from the overlay range) out the real gateway via pf `route-to`, so it leaves
    // our own WAN even if our own full-tunnel later diverts the default route to the tun.
    // The gateway is captured now, while the default route is still the real one.
    if isolate {
        if let Some(gw) = macos_default_gateway() {
            conf.push_str(&format!(
                "pass out route-to ({wan} {gw}) inet from 100.64.0.0/10 to any\n"
            ));
            tracing::warn!(
                wan,
                gw,
                "exit-policy isolate: pf route-to pins forwarded traffic to real WAN"
            );
        }
    }
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

/// macOS undo [`enable_nat`]: reload the system pf ruleset (`/etc/pf.conf`), restore pf's prior
/// on/off state (off again if `PF_WAS_OFF`), drop our ruleset file, disable IP forwarding.
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

/// The network service (e.g. "Wi-Fi") whose device is the current default-route
/// interface — what `networksetup` keys DNS changes on. Maps `macos_default_iface()`'s device
/// name to the human service name via `networksetup -listnetworkserviceorder`.
#[cfg(target_os = "macos")]
fn macos_primary_service() -> Option<String> {
    let iface = macos_default_iface()?;
    let out = Command::new("networksetup")
        .args(["-listnetworkserviceorder"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // Blocks look like:  "(1) Wi-Fi"  then  "(Hardware Port: Wi-Fi, Device: en0)".
    let mut last_service: Option<String> = None;
    for line in text.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix('(') {
            if let Some((_, name)) = rest.split_once(") ") {
                last_service = Some(name.trim().to_string());
            }
        }
        if l.contains(&format!("Device: {iface})")) {
            return last_service;
        }
    }
    None
}

/// macOS full-tunnel DNS (see module header `set_dns` contract): point the primary network
/// service's resolvers at `servers` via `networksetup -setdnsservers`, saving the service name to
/// `DNS_SAVED` for [`restore_dns`]. No-op on empty `servers`.
#[cfg(target_os = "macos")]
pub fn set_dns(servers: &[IpAddr]) -> Result<(), String> {
    if servers.is_empty() {
        return Ok(());
    }
    let Some(svc) = macos_primary_service() else {
        return Err("no primary network service; DNS not set".into());
    };
    let _ = std::fs::write(DNS_SAVED, &svc);
    let mut args = vec!["-setdnsservers".to_string(), svc.clone()];
    args.extend(servers.iter().map(|s| s.to_string()));
    run_checked(
        "networksetup",
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    tracing::warn!(service = %svc, ?servers, "DNS pointed through the tunnel (full tunnel)");
    Ok(())
}

/// macOS undo [`set_dns`]: clear our DNS override on the saved service (back to DHCP-provided).
#[cfg(target_os = "macos")]
pub fn restore_dns() {
    if let Ok(svc) = std::fs::read_to_string(DNS_SAVED) {
        // "Empty" clears our override, returning the service to DHCP-provided DNS.
        run("networksetup", &["-setdnsservers", svc.trim(), "Empty"]);
        let _ = std::fs::remove_file(DNS_SAVED);
        tracing::info!("DNS restored");
    }
}

// ----------------------------- Linux -----------------------------
/// Linux full-tunnel ON (see module header `route_through` contract). `ip route add
/// <exit_ip>/32 via <gw> dev <dev>` to pin the exit off the tunnel, then `ip route replace
/// default dev <tun>`. Saves `<gw> <dev>`→`SAVED`, exit→`EXIT_HOST_SAVED`. (`ip route replace`
/// is idempotent on the default; the /32 add is not delete-first here — Linux `add` of an
/// existing route errors but `replace`d default still applies.)
#[cfg(target_os = "linux")]
pub fn route_through(tun: &str, exit_ip: IpAddr) -> Result<(), String> {
    let Some((gw, dev)) = linux_default_route() else {
        return Err("no default route found; exit routes not applied".into());
    };
    let _ = std::fs::write(SAVED, format!("{gw} {dev}"));
    // Record the pinned host route so restore_routes can tear it down (else it
    // lingers and a later connect to the exit IP fails once default is restored).
    let _ = std::fs::write(EXIT_HOST_SAVED, exit_ip.to_string());
    let mut errs = Vec::new();
    if let Err(e) = run_checked(
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
    ) {
        errs.push(e);
    }
    if let Err(e) = run_checked("ip", &["route", "replace", "default", "dev", tun]) {
        errs.push(e);
    }
    if errs.is_empty() {
        tracing::warn!(%exit_ip, tun, "default route diverted through exit node");
        Ok(())
    } else {
        Err(errs.join("; "))
    }
}

/// Linux full-tunnel OFF (inverse of [`route_through`]): `ip route replace default via <gw> dev
/// <dev>` from `SAVED`, then delete the `/32` exit pin.
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
    // Tear down the pinned /32 to the exit's physical endpoint.
    if let Ok(exit_ip) = std::fs::read_to_string(EXIT_HOST_SAVED) {
        run("ip", &["route", "del", &format!("{}/32", exit_ip.trim())]);
        let _ = std::fs::remove_file(EXIT_HOST_SAVED);
    }
}

/// Linux: drop the `/32` exit pin + saved-default bookkeeping without touching the live default
/// (see module header `clear_exit_pin` contract — used by the netchange watcher).
#[cfg(target_os = "linux")]
pub fn clear_exit_pin() {
    if let Ok(exit_ip) = std::fs::read_to_string(EXIT_HOST_SAVED) {
        run("ip", &["route", "del", &format!("{}/32", exit_ip.trim())]);
        let _ = std::fs::remove_file(EXIT_HOST_SAVED);
    }
    // Drop a stale saved default route so a later `restore_routes` can't apply a dead one.
    let _ = std::fs::remove_file(SAVED);
}

/// Linux: the real default gateway IP (see module header `current_gateway` contract).
#[cfg(target_os = "linux")]
pub fn current_gateway() -> Option<String> {
    linux_default_route().map(|(gw, _)| gw)
}

/// Point the host resolver at `servers` (full-tunnel DNS). Backs up the current
/// `/etc/resolv.conf` — a symlink (systemd-resolved stub) or a plain file — and
/// replaces it with a static one. So DNS goes through the tunnel to the exit's
/// in-mesh resolver instead of a local/campus resolver the exit can't reach.
#[cfg(target_os = "linux")]
pub fn set_dns(servers: &[IpAddr]) -> Result<(), String> {
    if servers.is_empty() {
        return Ok(());
    }
    if let Ok(target) = std::fs::read_link("/etc/resolv.conf") {
        let _ = std::fs::write(DNS_SAVED, format!("link:{}", target.display()));
    } else if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        let _ = std::fs::write(DNS_SAVED, format!("file:{content}"));
    } else {
        let _ = std::fs::write(DNS_SAVED, "none:");
    }
    let mut conf = String::new();
    for s in servers {
        conf.push_str(&format!("nameserver {s}\n"));
    }
    let _ = std::fs::remove_file("/etc/resolv.conf");
    std::fs::write("/etc/resolv.conf", conf)
        .map_err(|e| format!("could not write /etc/resolv.conf: {e}"))?;
    tracing::warn!(?servers, "DNS pointed through the tunnel (full tunnel)");
    Ok(())
}

/// Linux undo [`set_dns`]: restore the saved `/etc/resolv.conf` (re-create the systemd-resolved
/// symlink, or rewrite the saved file content).
#[cfg(target_os = "linux")]
pub fn restore_dns() {
    if let Ok(saved) = std::fs::read_to_string(DNS_SAVED) {
        let _ = std::fs::remove_file("/etc/resolv.conf");
        if let Some(t) = saved.strip_prefix("link:") {
            let _ = std::os::unix::fs::symlink(t.trim(), "/etc/resolv.conf");
        } else if let Some(c) = saved.strip_prefix("file:") {
            let _ = std::fs::write("/etc/resolv.conf", c);
        }
        let _ = std::fs::remove_file(DNS_SAVED);
        tracing::info!("DNS restored");
    }
}

/// Parse `ip route show default` into `(gateway, dev)` — the real next-hop + WAN interface.
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

/// Side routing table + rule priority for exit-policy ISOLATE (docs/EXIT_POLICY.md).
#[cfg(target_os = "linux")]
const ISO_TABLE: &str = "100";
#[cfg(target_os = "linux")]
const ISO_PRIO: &str = "1000";

/// Linux exit NAT (see module header `enable_nat` contract). IP forwarding + iptables
/// `POSTROUTING MASQUERADE` for `100.64.0.0/10` out the WAN + `FORWARD ACCEPT` inserted at the
/// TOP (before any distro default `FORWARD -j REJECT`). When `isolate`, adds source-based
/// routing: a side table [`ISO_TABLE`] (`default via <gw> dev <wan>`) + `ip rule from
/// 100.64.0.0/10 lookup <table>`, so forwarded (overlay-sourced) traffic leaves the real WAN even
/// if this node also full-tunnels. ⚠ Same own-IP caveat as the macOS `route-to`: only for real
/// exits. NOT idempotent — iptables rules append (dup) on every call (cleanup is a TODO).
#[cfg(target_os = "linux")]
pub fn enable_nat(isolate: bool) {
    run("sysctl", &["-w", "net.ipv4.ip_forward=1"]);
    if let Some((gw, wan)) = linux_default_route() {
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
        if isolate {
            // Exit-policy ISOLATE: pin traffic we forward FOR OTHERS (sourced from the
            // overlay range 100.64/10) to the REAL default gateway via a side table, so it
            // leaves our own WAN even if our own full-tunnel later diverts the main-table
            // default. Our own traffic (real src IP) is unaffected and still follows main.
            run(
                "ip",
                &[
                    "route", "replace", "default", "via", &gw, "dev", &wan, "table", ISO_TABLE,
                ],
            );
            // `ip rule add` isn't idempotent — clear any stale duplicate first (ok if absent).
            let _ = Command::new("ip")
                .args(["rule", "del", "from", "100.64.0.0/10", "lookup", ISO_TABLE])
                .status();
            run(
                "ip",
                &[
                    "rule",
                    "add",
                    "from",
                    "100.64.0.0/10",
                    "lookup",
                    ISO_TABLE,
                    "priority",
                    ISO_PRIO,
                ],
            );
            tracing::warn!(
                gw,
                table = ISO_TABLE,
                "exit-policy isolate: forwarded traffic pinned to real WAN"
            );
        }
    }
}

/// Linux undo [`enable_nat`]: delete the MASQUERADE rule, tear down the isolate `ip rule` + flush
/// the side table, disable IP forwarding. (FORWARD ACCEPT rules are left; harmless.)
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
    // Tear down the isolate source-routing (harmless if it was never installed).
    let _ = Command::new("ip")
        .args(["rule", "del", "from", "100.64.0.0/10", "lookup", ISO_TABLE])
        .status();
    let _ = Command::new("ip")
        .args(["route", "flush", "table", ISO_TABLE])
        .status();
    run("sysctl", &["-w", "net.ipv4.ip_forward=0"]);
}

// ----------------------------- Windows -----------------------------
// Routes/NAT via PowerShell cmdlets (Get/New/Remove-NetRoute, *-NetNat). The
// TUN is the Wintun adapter named "Lattice". Requires Administrator. Untested
// across the full path — verify on a spare host.
#[cfg(target_os = "windows")]
const WIN_SAVED: &str = r"C:\Windows\Temp\lattice-saved-route.txt";

/// Run a PowerShell `script` fire-and-forget via the full `System32` powershell path (meshd runs
/// elevated with a minimal PATH, so a bare `powershell` can fail to launch).
#[cfg(target_os = "windows")]
fn ps(script: &str) {
    // Full path: meshd runs elevated (RunAs) with a possibly minimal PATH, so a bare
    // "powershell" can fail with "path not found".
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let pwsh = format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe");
    run(
        &pwsh,
        &["-NoProfile", "-NonInteractive", "-Command", script],
    );
}

/// Like [`ps`] but returns whether powershell.exe could be launched and exited 0.
/// Note: the apply scripts use `$ErrorActionPreference='SilentlyContinue'`, so this
/// catches "powershell not found / not elevated", not per-cmdlet failures.
#[cfg(target_os = "windows")]
fn ps_checked(script: &str) -> Result<(), String> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let pwsh = format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe");
    run_checked(
        &pwsh,
        &["-NoProfile", "-NonInteractive", "-Command", script],
    )
}

/// Windows full-tunnel ON (see module header `route_through` contract). Pins `exit_ip/32` via the
/// saved default's next-hop, then overrides the default with two `/1` routes via the Wintun
/// adapter (`0.0.0.0/1` + `128.0.0.0/1` — more specific than `0.0.0.0/0`, so they win WITHOUT
/// deleting the real default, OpenVPN-style). Idempotent: deletes any prior `/1` and `{exit}/32`
/// first (a leftover made `New-NetRoute` fail "already exists" → the "not fully applied" bug).
#[cfg(target_os = "windows")]
pub fn route_through(tun: &str, exit_ip: IpAddr) -> Result<(), String> {
    // Save the current default route (gateway + ifIndex), pin a host route to the
    // exit's physical endpoint via that gateway (so the tunnel doesn't loop), then
    // override the default with two /1 routes via the TUN (more specific than
    // 0.0.0.0/0, so they win without deleting the real default — OpenVPN-style).
    // `Stop` makes errors terminating so try/catch can report a real reason and a
    // distinct exit code. The `$def`/`$idx` guards turn the two silent-null traps
    // (no default route, missing TUN) into clear messages. Deleting any pre-existing
    // routes first makes a re-apply idempotent: a leftover 0.0.0.0/1 or {exit}/32
    // from a prior run made `New-NetRoute` fail with "already exists" → exit 1, which
    // is exactly the "full-tunnel not fully applied" the user hit on the second toggle.
    let script = format!(
        r#"
$ErrorActionPreference='Stop'
try {{
  $def = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
  if (-not $def) {{ throw 'no default route (0.0.0.0/0) found; not connected to a network?' }}
  $idx = (Get-NetAdapter -Name '{tun}' -ErrorAction SilentlyContinue).ifIndex
  if (-not $idx) {{ throw 'Lattice TUN adapter "{tun}" not found; is the data plane up?' }}
  '{exit}' | Set-Content -Path '{saved}'
  Remove-NetRoute -DestinationPrefix '{exit}/32' -Confirm:$false -ErrorAction SilentlyContinue
  Remove-NetRoute -DestinationPrefix '0.0.0.0/1' -Confirm:$false -ErrorAction SilentlyContinue
  Remove-NetRoute -DestinationPrefix '128.0.0.0/1' -Confirm:$false -ErrorAction SilentlyContinue
  New-NetRoute -DestinationPrefix '{exit}/32' -NextHop $def.NextHop -InterfaceIndex $def.ifIndex -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
  New-NetRoute -DestinationPrefix '0.0.0.0/1' -InterfaceIndex $idx -NextHop 0.0.0.0 -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
  New-NetRoute -DestinationPrefix '128.0.0.0/1' -InterfaceIndex $idx -NextHop 0.0.0.0 -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
  exit 0
}} catch {{
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 1
}}
"#,
        saved = WIN_SAVED,
        tun = tun,
        exit = exit_ip
    );
    ps_checked(&script)?;
    tracing::warn!(%exit_ip, tun, "default route diverted through exit node (windows)");
    Ok(())
}

/// Windows full-tunnel OFF (inverse of [`route_through`]): remove the two `/1` overrides (this is
/// what hands the default back to the real gateway) + the `/32` pin. Each removal is independent
/// and a real failure is logged — if it silently fails (e.g. not elevated) the `/1` routes
/// survive and ALL traffic stays on the dead tunnel (internet looks broken with no clue).
#[cfg(target_os = "windows")]
pub fn restore_routes() {
    // Symmetric with `route_through`: removing the two /1 overrides is what hands the
    // default back to the real gateway. If this silently fails (e.g. not elevated) the
    // /1 routes survive and ALL traffic stays pointed at the now-dead tunnel — internet
    // looks broken with no clue why. So each remove is independent (a failure on one
    // can't skip the rest) and a real failure is logged with its reason.
    let script = format!(
        r#"
$ErrorActionPreference='Continue'
$errs = @()
foreach ($p in @('0.0.0.0/1','128.0.0.0/1')) {{
  try {{ Remove-NetRoute -DestinationPrefix $p -Confirm:$false -ErrorAction Stop }}
  catch {{ if ($_.Exception.Message -notmatch 'No matching|not found') {{ $errs += "$p: $($_.Exception.Message)" }} }}
}}
if (Test-Path '{saved}') {{
  $exit = (Get-Content '{saved}').Trim()
  try {{ Remove-NetRoute -DestinationPrefix "$exit/32" -Confirm:$false -ErrorAction Stop }} catch {{}}
  Remove-Item '{saved}' -ErrorAction SilentlyContinue
}}
if ($errs.Count -gt 0) {{ [Console]::Error.WriteLine(($errs -join '; ')); exit 1 }}
exit 0
"#,
        saved = WIN_SAVED
    );
    match ps_checked(&script) {
        Ok(()) => tracing::info!("default route restored (windows)"),
        Err(e) => tracing::warn!("restore_routes failed — internet may stay on a dead tunnel: {e}"),
    }
}

/// Windows: drop the `/32` exit pin + saved-route bookkeeping without touching the live default
/// (see module header `clear_exit_pin` contract).
#[cfg(target_os = "windows")]
pub fn clear_exit_pin() {
    let script = format!(
        r#"
$ErrorActionPreference='SilentlyContinue'
if (Test-Path '{saved}') {{
  $exit = (Get-Content '{saved}').Trim()
  Remove-NetRoute -DestinationPrefix "$exit/32" -Confirm:$false
  Remove-Item '{saved}'
}}
"#,
        saved = WIN_SAVED
    );
    ps(&script);
}

/// Windows: the real default-route next-hop IP (see module header `current_gateway` contract).
#[cfg(target_os = "windows")]
pub fn current_gateway() -> Option<String> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let pwsh = format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe");
    let out = Command::new(pwsh)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop",
        ])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Windows exit NAT (see module header `enable_nat` contract). Enables interface forwarding +
/// `New-NetNat` (WinNAT) for `100.64.0.0/10`. `isolate` is BEST-EFFORT only: WinNAT egresses via
/// the system route, so forwarded traffic leaves the real adapter UNLESS this node also
/// full-tunnels (Windows has no simple source-based routing — full source-pinning is a TODO).
#[cfg(target_os = "windows")]
pub fn enable_nat(isolate: bool) {
    // Forward between interfaces + WinNAT for the overlay range.
    ps("Set-NetIPInterface -Forwarding Enabled -ErrorAction SilentlyContinue");
    ps("if (-not (Get-NetNat -Name Lattice -ErrorAction SilentlyContinue)) { New-NetNat -Name Lattice -InternalIPInterfaceAddressPrefix 100.64.0.0/10 }");
    tracing::warn!("windows exit NAT enabled (WinNAT 100.64.0.0/10)");
    // Exit-policy ISOLATE on Windows is best-effort: WinNAT egresses via the system route
    // to the destination, so when this node is NOT itself full-tunnelling, forwarded
    // traffic already leaves the real adapter (isolate holds). But Windows has no simple
    // source-based routing, so if this node ALSO full-tunnels its own traffic, forwarded
    // traffic can follow that default (chain-like). Full source-pinning (a policy route /
    // separate NAT scope) is a TODO — see docs/EXIT_POLICY.md §4. Linux/macOS pin it.
    if isolate {
        tracing::warn!(
            "exit-policy isolate on windows is best-effort (no source-based routing); \
             forwarded traffic may follow this node's own full-tunnel if one is set"
        );
    }
}

/// Windows undo [`enable_nat`]: remove the `Lattice` WinNAT instance.
#[cfg(target_os = "windows")]
pub fn disable_nat() {
    ps("Remove-NetNat -Name Lattice -Confirm:$false -ErrorAction SilentlyContinue");
}

/// Windows full-tunnel DNS (see module header `set_dns` contract): set the `Lattice` adapter's
/// DNS to the first server (full-tunnel routes it through the exit).
#[cfg(target_os = "windows")]
pub fn set_dns(servers: &[IpAddr]) -> Result<(), String> {
    if let Some(first) = servers.first() {
        // Set the Lattice adapter's DNS; full-tunnel routes it through the exit.
        ps_checked(&format!(
            "Set-DnsClientServerAddress -InterfaceAlias 'Lattice' -ServerAddresses '{first}' -ErrorAction SilentlyContinue"
        ))?;
    }
    Ok(())
}

/// Windows undo [`set_dns`]: reset the `Lattice` adapter's DNS to automatic.
#[cfg(target_os = "windows")]
pub fn restore_dns() {
    ps("Set-DnsClientServerAddress -InterfaceAlias 'Lattice' -ResetServerAddresses -ErrorAction SilentlyContinue");
}

// ------------------------- other platforms -------------------------
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn route_through(_tun: &str, _exit_ip: IpAddr) -> Result<(), String> {
    Err("exit-node routing not implemented on this platform".into())
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn restore_routes() {}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn enable_nat(_isolate: bool) {
    tracing::warn!("exit-node NAT not implemented on this platform");
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn disable_nat() {}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn set_dns(_servers: &[IpAddr]) -> Result<(), String> {
    Ok(())
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn restore_dns() {}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn clear_exit_pin() {}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn current_gateway() -> Option<String> {
    None
}
