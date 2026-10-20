//! **meshd** — the v2 multi-mesh control-plane daemon (`docs/MESH_V2.md`).
//!
//! Holds this computer's meshes and serves the v2 IPC (`lattice_mesh::ipc`) over a
//! unix socket. Backed by the REAL membership engine (`lattice_mesh::membership`):
//! each mesh has a master keypair, members are admitted via **signed certs**, and
//! the roster is the set of certs that validly chain to the master.
//!
//! With `DATA_PLANE=1` (and root for the TUN) each mesh also runs a live data-plane
//! loop (`lattice_meshrun::run`): a per-mesh TUN + UDP socket carrying sealed
//! packets. The loop shares a peer table + exit selection with this control plane,
//! so the IPC reports live endpoints/liveness (P6.3d) and steers egress live.
//!
//! ## Edit-risk (key fns carry a `RISK:` tag — same scheme as `exit.rs`/`meshrun`)
//! Most of this file is control-plane bookkeeping (🟢/🟡). The dangerous parts:
//! - 🔴 [`bringup_dataplane`] — opens the per-mesh TUN/UDP, applies routes/NAT, arms the
//!   kill-switch. Where full-tunnel is wired; touches the live host network.
//! - 🔴 [`arm_kill_switch`] — the probe that reverts full-tunnel if the exit "isn't passing
//!   traffic"; a false revert (or a missing one) is a connectivity bug. (`Opkts=0` has many
//!   causes — see docs/ERRORS.md before touching.)
//! - 🔴 [`shutdown_daemon`] — restores routes/DNS before aborting the data plane; if it skips a
//!   restore the host is left on a dead tunnel.
//! - 🟡 [`handle`] — the central IPC request dispatcher; mutates ALL mesh state and emits the
//!   `PostAction`s (bringup / kill-switch / shutdown). Big match; easy to mis-wire a new request.
//! - 🟡 [`serve_conn`]/[`scope_gate`]/[`ext_subscribe`] — the IPC connection: bounded outbound
//!   channel (backpressure), shutdown-ack flush, and connector scope checks re-read from the LIVE
//!   grant (not a snapshot). See the extensions-framework notes.
//! - 🟡 [`peer_allowed`] — the socket-peer uid gate (who may talk to the daemon).
//! The data-plane loop itself lives in `lattice_meshrun` (its own edit-risk legend).

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use lattice_mesh::charter::{
    ExitPolicy, ExpelPolicy, GenesisCharter, HeaderPlacement, InviteTopology, RecipherTrigger,
};
use lattice_mesh::crypto::suite;
use lattice_mesh::dataplane::MeshDataPlane;
use lattice_mesh::ipc::{
    ExtensionView, FlowView, InviteBlob, MemberView, MeshDetail, MeshSummary, PeerTrafficView,
    PolicyView, Request, Response, ServiceView, TrafficView,
};
use lattice_mesh::keydist::{seal_secret, EncKey};
use lattice_mesh::membership::{
    effective_members, valid_members, Cert, GrantCert, MasterKey, MemberKey, PubKey, Revocation,
};
use lattice_mesh::registry::{self, ServiceEntry, ServiceRecord};
use lattice_mesh::Mesh;
use lattice_meshrun::{
    seed_links, DecryptFailStat, DecryptFails, Link, LoopCmd, LoopEvent, PeerLinks, Recipher,
    SharedEndpoint, SharedExit, SharedSplitRoutes, SharedTraffic, Traffic, CTRL_ALLCLEAR,
    CTRL_ATTACK, CTRL_FLOWS, CTRL_QGRANT, CTRL_REGISTRY, CTRL_REVOKE, CTRL_ROSTER,
};
use lattice_net::udp::UdpTransport;
use lattice_proto::flow::FlowRule;
use lattice_proto::wire_v2::{MemberId, MeshId};
use lattice_proto::VirtualIp;
use lattice_tun::{open as tun_open, TunConfig};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc::UnboundedSender;

mod state;
use state::*;

mod dht; // node-wide DHT rendezvous (re-find a moved peer by pubkey) — docs/DHT_RENDEZVOUS.md
mod dns_split; // domain-based split-tunnel: DNS-driven per-domain exit routing (docs/SPLIT_TUNNEL.md)
mod exit; // OS plumbing for full-tunnel egress (client routes + exit NAT)

/// Where meshd listens for the GUI/CLI. A unix domain socket on macOS/Linux; a
/// named pipe on Windows — same newline-JSON protocol either way.
#[cfg(unix)]
const DEFAULT_SOCKET: &str = "/tmp/lattice-meshd.sock";
#[cfg(windows)]
const DEFAULT_SOCKET: &str = r"\\.\pipe\lattice-meshd";
/// Public resolver used for full-tunnel DNS (routed through the exit).
const FULL_TUNNEL_DNS: &str = "1.1.1.1";
/// A member is "live" if heard from within this window.
const LIVE_WINDOW_MS: u64 = 30_000;
/// How long an invited-but-not-yet-joined member id stays reserved (so back-to-back
/// invites get distinct ids). After this, an unused reservation is reclaimed.
const INVITE_RESERVE_MS: u64 = 3_600_000; // 1 hour
/// A decrypt-fail (a frame from a known endpoint that didn't open) is "recent" — and so
/// worth surfacing as a split-brain warning — if it happened within this window. Wider
/// than the live window so a transient mismatch lingers long enough to be seen + acted on.
const DECRYPT_FAIL_WINDOW_MS: u64 = 120_000;
/// Per-mesh UDP base port (mesh id is added).
const UDP_BASE_PORT: u16 = 42000;
/// DHT rendezvous (`MESHD_DHT=1`): how often to republish our own record and look up
/// any mesh member we have no fresh endpoint for (docs/DHT_RENDEZVOUS.md).
const DHT_RECONNECT_TICK_SECS: u64 = 25;
/// How often to gossip our membership roster (signed certs) to peers so a member
/// admitted via a third node propagates to everyone (the roster converges).
const ROSTER_GOSSIP_TICK_SECS: u64 = 20;
/// Defensive caps on gossiped state. A roster cert is merged on a network match
/// even before it validates to the master (`roster()` filters invalid ones out),
/// so without a cap a malicious/buggy member could grow `certs` without bound by
/// gossiping junk. Member ids are 1 byte (≤254 live members), so these ceilings sit
/// far above any legitimate mesh and only ever bite an abuse case.
const MAX_GOSSIP_BYTES: usize = 64 * 1024;
const MAX_ROSTER_CERTS: usize = 1024;
const MAX_REVOCATIONS: usize = 512;
const MAX_FLOW_RULES: usize = 512;
/// How often to poll the host's default gateway for a network change (Wi-Fi↔cellular,
/// sleep/wake, a new network after an outage). Cheap; routes/endpoints only refresh on an
/// actual change.
const NETCHANGE_TICK_SECS: u64 = 8;
/// Overlay MTU for meshd-run data planes (matches meshrun's conservative default).
const OVERLAY_MTU: u16 = 1280;
/// Live-paired self-destruct (P-C4): how often to check liveness, and how long the
/// mesh may sit below the live threshold before it wipes itself.
const SELF_DESTRUCT_TICK_SECS: u64 = 15;
const SELF_DESTRUCT_GRACE_SECS: u64 = 180;
/// Attack-response grace (P-C7): after an attack alert, how long the creator has to
/// send an all-clear before every member self-destructs (one-veto, fail-deadly).
const ATTACK_GRACE_SECS: u64 = 30;

/// Append a diagnostic line to a `lattice-meshd.log`. On Windows the GUI runs meshd
/// elevated + hidden with no console (RunAs can't redirect output), so this file is the
/// only window into what happened. Best-effort, written to EVERY candidate that opens —
/// under RunAs the elevating account's `%TEMP%` may not exist, but `C:\Windows\Temp`
/// always does — so the log is findable regardless of which account elevated.
fn diag_log(msg: &str) {
    use std::io::Write;
    // `mut` is only exercised by the Windows-only push below.
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut paths = vec![std::env::temp_dir().join("lattice-meshd.log")];
    #[cfg(windows)]
    paths.push(std::path::PathBuf::from(
        r"C:\Windows\Temp\lattice-meshd.log",
    ));
    for p in paths {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)
        {
            let _ = writeln!(f, "{msg}");
        }
    }
}

/// Like `elog!`, but also mirrors the line to the diagnostic log file (above).
macro_rules! elog {
    ($($a:tt)*) => {{
        let s = format!($($a)*);
        eprintln!("{s}");
        crate::diag_log(&s);
    }};
}

mod ipcserve;
use ipcserve::*;

mod ext;
use ext::*;

mod watch;
use watch::*;

mod view;
use view::*;

mod parse;
use parse::*;

mod persist;
use persist::*;

/// 🟢 Unix epoch milliseconds (control-plane timestamps).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Startup self-check (docs/DAEMON_SELF_HEALING.md). Full-tunnel state is NOT persisted, so
/// on a fresh start it is always OFF — any leftover full-tunnel route bookkeeping is stale
/// from a previous run that didn't clean up (crash / `kill -9` / reboot / network change
/// while diverted). A stale exit `/32` pin blackholes that IP (`connect` → `EADDRNOTAVAIL`)
/// and a stale saved default-gateway would make a later revert point the default route at a
/// DEAD gateway. Clear both at boot so the daemon starts from a known-good route state.
/// (Extend with further boot-time sanity cleanups as they come up.)
fn startup_preflight() {
    exit::clear_exit_pin();
    elog!("meshd: startup preflight — cleared any stale full-tunnel route bookkeeping");
}

/// **RISK 🔴 HIGH** — apply the per-mesh `exitable` flag: enable or disable forwarding+NAT for
/// this mesh's overlay subnet so its members can (or can't) use us as their internet exit
/// (docs/EXIT_SHARING.md). Only this mesh's subnet is touched — other meshes are unaffected.
async fn apply_exitable(mesh: MeshId, state: Arc<Mutex<State>>) {
    // Snapshot: is it now exitable (or a pinned exit), and this mesh's subnet + isolate policy.
    let info = {
        let st = state.lock().unwrap();
        st.meshes.get(&mesh).map(|ms| {
            let p = ms.mesh.charter.overlay_prefix;
            let subnet = format!("{}.{}.{}.0/24", p[0], p[1], mesh);
            let isolate = matches!(ms.mesh.charter.exit_policy, ExitPolicy::Isolate);
            (ms.exitable, subnet, isolate)
        })
    };
    let Some((exitable, subnet, policy_isolate)) = info else {
        return;
    };
    let pinned = std::env::var("MESHD_ADVERTISE").is_ok();
    let serve = exitable || pinned;
    let isolate = policy_isolate && pinned;
    let _ = tokio::task::spawn_blocking(move || {
        if serve {
            exit::enable_nat(&subnet, isolate);
        } else {
            exit::disable_nat(&subnet);
        }
    })
    .await;
    elog!(
        "meshd: mesh {mesh} exitable={exitable} — {} as an exit for its members",
        if serve { "serving" } else { "NOT serving" }
    );
}

/// Add a local split-tunnel rule (idempotent on `domain`). Persisted; takes effect the next time
/// split mode is turned on for that mesh.
fn split_add(st: &mut State, domain: String, mesh: MeshId, exit: MemberId) -> Response {
    let domain = domain.trim().trim_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return err("empty domain");
    }
    let Some(ms) = st.meshes.get(&mesh) else {
        return no_mesh(mesh);
    };
    // Guard the recurring "can't connect" trap: an exit must be a REAL other member, not yourself
    // and not an unknown id. `0` = fall back to the mesh's configured exit.
    if exit != 0 {
        if exit == ms.my_id() {
            return err(
                "exit can't be this node itself — pick another member (e.g. the exit node)",
            );
        }
        if !ms.roster().iter().any(|c| c.id == exit) {
            return err("no such member in this mesh for the exit");
        }
    }
    st.split_rules.retain(|r| r.domain != domain);
    st.split_rules
        .push(dns_split::SplitRule { domain, mesh, exit });
    Response::Ok
}

/// Remove a local split-tunnel rule by exact domain.
fn split_del(st: &mut State, domain: String) -> Response {
    let domain = domain.trim().trim_matches('.').to_ascii_lowercase();
    let before = st.split_rules.len();
    st.split_rules.retain(|r| r.domain != domain);
    if st.split_rules.len() == before {
        err("no such split rule")
    } else {
        Response::Ok
    }
}

/// Project the split-tunnel state for the CLI/GUI.
fn split_list(st: &State) -> Response {
    Response::Split(lattice_mesh::ipc::SplitView {
        rules: st
            .split_rules
            .iter()
            .map(|r| lattice_mesh::ipc::SplitRuleView {
                domain: r.domain.clone(),
                mesh: r.mesh,
                exit: r.exit,
            })
            .collect(),
        active_mesh: st.split.as_ref().map(|s| s.mesh),
    })
}

#[tokio::main]
/// **RISK 🟡 MED** — daemon startup: log the build id, set up the event bus + extension grants,
/// load persisted meshes (and bring up their data planes if `DATA_PLANE`), then serve the IPC
/// socket/pipe. The single-instance behaviour + restore-from-disk live here.
async fn main() -> anyhow::Result<()> {
    // Route meshrun's diagnostics (relay decisions, direct-path recovery, reflexion,
    // re-cipher) through elog!'s sinks — stderr + the diag file. On Windows the GUI
    // runs meshd elevated+hidden, so the file is the ONLY place those lines were
    // previously lost (they went to an unreadable stderr).
    lattice_meshrun::set_log_sink(|s| {
        eprintln!("{s}");
        diag_log(s);
    });
    // First line in the log: proves meshd actually launched (vs the GUI's launcher
    // failing before this point), and records the args we got.
    let argv: Vec<String> = std::env::args().collect();
    elog!(
        "meshd: started pid={} args={:?}",
        std::process::id(),
        &argv[1..]
    );
    // Identify exactly which build this is, so "old vs new binary got mixed up" is answerable
    // straight from the log (CARGO_PKG_VERSION + git SHA stamped by build.rs).
    elog!(
        "meshd: version v{} build {}",
        env!("CARGO_PKG_VERSION"),
        env!("LATTICE_BUILD")
    );
    // The socket is the first non-flag argument; flags (`--data-plane`) may come in any
    // order. Falling back to the platform default lets a bare `meshd` still work.
    let socket = std::env::args()
        .skip(1)
        .find(|a| !a.starts_with("--"))
        .unwrap_or_else(|| DEFAULT_SOCKET.to_string());

    let state = Arc::new(Mutex::new(State::default()));
    // Enable the data plane via either `DATA_PLANE=1` (unix launchers) or a
    // `--data-plane` flag (the Windows launcher — passing a flag avoids the fragile
    // env-through-elevation quoting that left meshd not starting at all).
    let data_plane = matches!(std::env::var("DATA_PLANE").as_deref(), Ok("1"))
        || std::env::args().any(|a| a == "--data-plane");
    // Single-instance guard, run BEFORE any data-plane bringup: if a healthy meshd already owns the
    // socket, exit now (a deferring start must never create — then orphan — a TUN). A root
    // data-plane daemon takes the socket over from a rootless (data-plane-less) owner instead.
    #[cfg(unix)]
    if should_defer_to_socket_owner(&socket, data_plane) {
        elog!("meshd: another meshd already owns {socket} — deferring to it, exiting (no second instance)");
        return Ok(());
    }
    let pdir = persist_dir();
    {
        let mut st = state.lock().unwrap();
        st.data_plane = data_plane;
        st.persist_dir.clone_from(&pdir);
        // Extension event bus + persisted grants (docs/EXTENSIONS.md). The bus lives for
        // the daemon's lifetime; connector connections subscribe on demand.
        let (bus, _) = tokio::sync::broadcast::channel::<MeshEvent>(EVENT_BUS_CAP);
        st.bus = Some(bus);
        if let Some(dir) = &pdir {
            st.split_rules = load_split(dir);
            if !st.split_rules.is_empty() {
                elog!(
                    "meshd: loaded {} split-tunnel rule(s)",
                    st.split_rules.len()
                );
            }
            st.default_mesh = load_default_mesh(dir);
            st.extensions = load_extensions(dir);
            if !st.extensions.is_empty() {
                elog!("meshd: loaded {} extension grant(s)", st.extensions.len());
            }
        }
    }
    elog!(
        "meshd: data-plane mode {}",
        if data_plane {
            "ON (per-mesh TUN+UDP loops; needs root)"
        } else {
            "off"
        }
    );
    // Startup preflight: full-tunnel is never active on a fresh start (it isn't persisted),
    // so ANY leftover full-tunnel route bookkeeping is stale from a previous run that didn't
    // clean up (crash / kill -9 / reboot / network change while diverted). Left behind, a
    // stale exit /32 blackholes that IP (connect → EADDRNOTAVAIL) and a stale saved
    // default-gateway would make a later revert point the default at a DEAD gateway. Clean
    // both at boot so the daemon starts from a known-good route state.
    if data_plane {
        startup_preflight();
    }
    // P-S1: reload persisted meshes so a reboot / network change doesn't drop us from
    // them; bring each data plane back up at its live secret/epoch/cipher.
    if let Some(dir) = &pdir {
        let mut persisted = load_persisted(dir);
        // Update migration: merge in the pre-update backup (ExportState) for any mesh the
        // normal persist dir didn't carry over (e.g. a clean reinstall wiped it). The
        // persist dir is authoritative for ids it already has; new ids come from backup.
        // Then delete the backup — it's a one-shot hand-off across the update.
        let backup_path = migration_backup_path();
        let backup = load_backup(&backup_path);
        if !backup.is_empty() {
            let have: HashSet<MeshId> = persisted.iter().map(|p| p.mesh_id).collect();
            let mut merged = 0;
            for p in backup {
                if !have.contains(&p.mesh_id) {
                    persisted.push(p);
                    merged += 1;
                }
            }
            let _ = std::fs::remove_file(&backup_path);
            if merged > 0 {
                elog!(
                    "meshd: imported {merged} mesh(es) from update backup {}",
                    backup_path.display()
                );
            }
        }
        let mut bringups = Vec::new();
        {
            let mut st = state.lock().unwrap();
            for p in persisted {
                let (ms, b) = restore_mesh(p);
                st.meshes.insert(ms.mesh.id, ms);
                if data_plane {
                    bringups.push(b);
                }
            }
            if !st.meshes.is_empty() {
                elog!(
                    "meshd: restored {} mesh(es) from {}",
                    st.meshes.len(),
                    dir.display()
                );
            }
        }
        // Persist the merged set so the imported meshes land in the normal dir too.
        persist(&state.lock().unwrap());
        for b in bringups {
            bringup_dataplane(b, Arc::clone(&state)).await;
        }
        // Re-enable split-tunnel if it was on before the restart (its data plane is up now). The
        // rules already loaded; this restores the on/off state so a domain bypass survives a reboot.
        if let Some(m) = load_split_active(dir) {
            if state.lock().unwrap().meshes.contains_key(&m) {
                split_enable(m, Arc::clone(&state)).await;
                elog!("meshd: re-enabled split-tunnel for mesh {m} (persisted on/off state)");
            }
        }
        // Re-apply a persisted FULL-tunnel egress so "route everything through this mesh" survives a
        // restart (was the "keeps falling back to Default network" bug — only split was sticky). Set
        // the intent now (so the GUI/CLI show it and the network-change loop re-asserts it), but let
        // `restore_full_tunnel` do the actual divert only once the exit is reachable — never black-hole
        // the default route at boot to a not-yet-connected exit.
        if let Some(m) = load_egress(dir) {
            if state.lock().unwrap().meshes.contains_key(&m) {
                {
                    let mut st = state.lock().unwrap();
                    st.current = Some(m);
                    st.full_tunnel = true;
                }
                elog!("meshd: full-tunnel egress mesh {m} remembered; applying once its exit is reachable");
                restore_full_tunnel(m, Arc::clone(&state));
            }
        }
    }
    // P-D4: one LAN-discovery beacon for the whole node. Each round it snapshots the
    // live meshes (those with a data plane up) and advertises/seeds them, so same-LAN
    // peers find each other with no WAN. Best-effort; harmless when data plane is off.
    if data_plane {
        let st = Arc::clone(&state);
        tokio::spawn(lattice_meshrun::run_lan_discovery(move || {
            let st = st.lock().unwrap();
            st.meshes
                .values()
                .filter(|m| m.dp_port != 0)
                .map(|m| lattice_meshrun::LanMesh {
                    tag: lattice_mesh::crypto::lan_tag(&m.secret),
                    member_id: m.my_id(),
                    dp_port: m.dp_port,
                    links: Arc::clone(&m.links),
                })
                .collect()
        }));
    }

    // DHT rendezvous: a node-wide Kademlia overlay that re-finds a peer whose address
    // changed with no overlapping live window (docs/DHT_RENDEZVOUS.md). ON by default
    // whenever the data plane is up (3-platform live-verified); set `MESHD_DHT=0` to
    // opt out. Availability-only — if the overlay is empty/unreachable, behaviour is
    // exactly the pre-DHT first-contact discovery, so it can't destabilise the data plane.
    let dht_enabled = std::env::var("MESHD_DHT").as_deref() != Ok("0");
    if data_plane && dht_enabled {
        let dht_port: u16 = std::env::var("MESHD_DHT_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(UDP_BASE_PORT.wrapping_add(900));
        let bind = SocketAddr::from(([0, 0, 0, 0], dht_port));
        // Bootstrap seeds: explicit MESHD_DHT_BOOTSTRAP (the always-on public node is the
        // natural one), plus any peer endpoints we already know from persisted meshes.
        let mut seeds: Vec<SocketAddr> = std::env::var("MESHD_DHT_BOOTSTRAP")
            .ok()
            .map(|s| s.split(',').filter_map(|a| a.trim().parse().ok()).collect())
            .unwrap_or_default();
        {
            let st = state.lock().unwrap();
            for ms in st.meshes.values() {
                for l in ms.links.lock().unwrap().values() {
                    seeds.push(l.endpoint);
                }
            }
        }
        seeds.sort();
        seeds.dedup();
        match dht::DhtService::start(bind, seeds).await {
            Ok(svc) => {
                state.lock().unwrap().dht = Some(svc);
                spawn_dht_reconnect(Arc::clone(&state));
                elog!("meshd: DHT rendezvous ON (udp {bind})");
            }
            Err(e) => elog!("meshd: DHT rendezvous failed to start on {bind}: {e}"),
        }
    }

    // Roster gossip: propagate membership (signed certs) so a node admitted via one
    // member converges to everyone — endpoints already gossiped, the roster didn't.
    if data_plane {
        spawn_roster_gossip(Arc::clone(&state));
    }

    // Network-change self-healing: detect the host's IP/gateway changing (Wi-Fi↔cellular,
    // sleep/wake, a new network after an outage) and re-establish routes + re-learn our
    // address so peers re-discover us (docs/DYNAMIC_NETWORK.md).
    if data_plane {
        spawn_netchange_watcher(Arc::clone(&state));
    }

    elog!("meshd: listening on {socket}");
    accept_loop(&socket, state).await
}

/// **RISK 🔴 HIGH** — restores routes/DNS BEFORE aborting the data plane; skipping a restore
/// leaves the host on a dead tunnel (no internet). Keep the restore-then-teardown order.
/// Cleanly stop the daemon (the `Shutdown` request): if a full tunnel is up, restore the
/// host's routes/DNS first so closing the TUN doesn't strand the default route on a dead
/// interface; otherwise just clear any stale exit pin. Then abort every mesh's data-plane
/// loop (dropping its TUN + freeing its UDP ports) and exit. On-disk mesh state is left
/// intact — a later start restores it.
async fn shutdown_daemon(state: &Arc<Mutex<State>>) {
    elog!("meshd: shutdown requested — restoring routes, aborting data plane, exiting");
    let (full_tunnel, split_on) = {
        let st = state.lock().unwrap();
        (st.full_tunnel, st.split.is_some())
    };
    let _ = tokio::task::spawn_blocking(move || {
        if full_tunnel {
            exit::restore_routes();
            exit::restore_dns();
        } else {
            // A split-tunnel also pointed the host resolver at meshd's 127.0.0.1 proxy — restore it
            // so DNS keeps working after we exit (otherwise the resolver dies with the daemon).
            if split_on {
                exit::restore_dns();
            }
            exit::clear_exit_pin();
        }
    })
    .await;
    {
        let st = state.lock().unwrap();
        for ms in st.meshes.values() {
            if let Some(t) = &ms.dp_task {
                t.abort();
            }
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    std::process::exit(0);
}

/// **RISK 🔴 HIGH** — opens the live TUN/UDP, applies routes/NAT, arms the kill-switch; where
/// full-tunnel is wired (the macOS regressions surfaced through here). Touches the host network.
/// Open the per-mesh TUN + UDP and spawn the data-plane loop. Failures (e.g. no
/// root for the TUN) are logged and non-fatal: meshd keeps serving the control
/// plane. The `links`/`exit_sel` handles are shared with [`MeshState`].
async fn bringup_dataplane(b: Bringup, state: Arc<Mutex<State>>) {
    let overlay = Ipv4Addr::new(b.prefix[0], b.prefix[1], b.mesh_id, b.my_id);
    let tun = match tun_open(TunConfig {
        address: VirtualIp(overlay),
        prefix_len: 24,
        mtu: OVERLAY_MTU,
    })
    .await
    {
        Ok(t) => t,
        Err(e) => {
            elog!(
                "meshd: data-plane TUN open failed for mesh {} (need root?): {e}",
                b.mesh_id
            );
            return;
        }
    };
    // Per-mesh port = base + mesh id, unless MESHD_BIND_PORT pins one explicitly
    // (single-mesh demos / firewalled hosts that only have one open port, e.g. the
    // Oracle OCI security list).
    let port = std::env::var("MESHD_BIND_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| UDP_BASE_PORT.wrapping_add(b.mesh_id as u16));
    let bind = SocketAddr::from(([0, 0, 0, 0], port));
    // Self-heal a busy port instead of silently leaving the data plane dead. EADDRINUSE
    // here is almost always a just-removed mesh's socket still closing, or a zombie meshd
    // exiting after the single-instance guard kicks in — both clear within a few seconds.
    // Retry with backoff so the mesh comes up on its own once the port frees, and if it
    // never does, log LOUDLY (the old behaviour failed open: the GUI showed the mesh as
    // "joined" while nothing could send/receive — exactly the "joined but can't find each
    // other" symptom).
    let transport = {
        let mut t = None;
        for attempt in 1..=12u32 {
            match UdpTransport::bind(bind).await {
                Ok(tr) => {
                    if attempt > 1 {
                        elog!(
                            "meshd: data-plane UDP {bind} bound for mesh {} on retry {attempt}",
                            b.mesh_id
                        );
                    }
                    t = Some(tr);
                    break;
                }
                Err(e) => {
                    elog!(
                        "meshd: data-plane UDP bind {bind} busy for mesh {} (try {attempt}/12): {e} — retrying in 500ms",
                        b.mesh_id
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }
        match t {
            Some(tr) => tr,
            None => {
                elog!(
                    "meshd: data-plane UDP bind {bind} FAILED for mesh {} after 12 tries — another process holds the port; mesh data plane is DOWN",
                    b.mesh_id
                );
                if let Some(ms) = state.lock().unwrap().meshes.get_mut(&b.mesh_id) {
                    ms.dp_error =
                        Some(format!("data-plane port {port} is held by another process"));
                }
                return;
            }
        }
    };
    let mut dp = MeshDataPlane::new(
        b.mesh_id,
        b.my_id,
        b.prefix,
        suite(&b.cipher, &b.secret, b.epoch),
        &b.secret,
        b.header_placement,
    );
    // Apply this mesh's SDN flow table (default or persisted/edited) to the live data
    // plane so route decisions honour it from the first packet (docs/FLOW_TABLE.md).
    if !b.flows.is_empty() {
        dp.set_flows(b.flows);
    }
    // Record the TUN name (needed to divert the default route for full-tunnel) and
    // make this node able to serve as an exit for others — ip_forward + NAT, which
    // is idempotent and unused unless a peer routes through us (reuses v1 exit.rs).
    let tun_name = tun.name().map(|s| s.to_string());
    // Exit-egress policy (docs/EXIT_POLICY.md): under Isolate, enable_nat also pins
    // traffic we forward for others to our real WAN. Default Isolate if the mesh is gone.
    let (isolate, serve) = {
        let mut st = state.lock().unwrap();
        let policy_isolate = st
            .meshes
            .get(&b.mesh_id)
            .map(|ms| matches!(ms.mesh.charter.exit_policy, ExitPolicy::Isolate))
            .unwrap_or(true);
        let exitable = st
            .meshes
            .get(&b.mesh_id)
            .map(|ms| ms.exitable)
            .unwrap_or(false);
        if let Some(ms) = st.meshes.get_mut(&b.mesh_id) {
            ms.tun_name = tun_name.clone();
            ms.dp_port = port; // local data-plane port — advertised in the LAN beacon
            ms.dp_error = None; // bound cleanly — clear any prior "port busy" error
        }
        // SERVE AS AN EXIT for this mesh ONLY if the user made it `exitable` — or this is a
        // dedicated pinned exit (MESHD_ADVERTISE). Default OFF: a mesh member (incl. an intruder)
        // can't route their internet through this node unless it explicitly opted in for that
        // mesh. Blast radius stays on nodes that chose to serve (docs/EXIT_SHARING.md).
        let is_exit_node = std::env::var("MESHD_ADVERTISE").is_ok();
        // The isolate `route-to`/side-route pins forwarded traffic to our real WAN; its selector
        // also matches THIS node's own overlay IP, so only a real pinned exit gets it (a client
        // would divert its own full-tunnel egress off the tun and wedge). Regression: 5cfa960.
        (policy_isolate && is_exit_node, exitable || is_exit_node)
    };
    // Reconcile NAT to the exitable decision at every bringup. Serving → NAT this mesh's OWN
    // subnet only (never all 100.64/10). NOT serving → disable_nat, which also PURGES any legacy
    // all-overlay MASQUERADE left by older always-on builds — else a previously-always-on node
    // would keep forwarding for everyone despite `exitable=off` (caught by a cross-node test).
    {
        let subnet = format!("{}.{}.{}.0/24", b.prefix[0], b.prefix[1], b.mesh_id);
        let _ = tokio::task::spawn_blocking(move || {
            if serve {
                exit::enable_nat(&subnet, isolate);
            } else {
                exit::disable_nat(&subnet);
            }
        })
        .await;
    }
    // This node's own reachable address, advertised in the endpoint gossip so peers
    // can reach us without a manual SetPeer (docs/DISCOVERY.md §2). A public node
    // (the Oracle exit) PINS it via MESHD_ADVERTISE=ip:port — never overridden;
    // otherwise we start at the primary LAN address (same-router peers) and the run
    // loop upgrades it to our public address when a public peer reflects it (P-D3).
    let pinned = std::env::var("MESHD_ADVERTISE").is_ok();
    let advertise: Option<SocketAddr> = std::env::var("MESHD_ADVERTISE")
        .ok()
        .and_then(|s| s.parse().ok())
        .or_else(|| local_ip().map(|ip| SocketAddr::new(ip, port)));
    *b.my_endpoint.lock().unwrap() = advertise;
    elog!(
        "meshd: data-plane LIVE for mesh {} — overlay {overlay}/24, udp {bind}, iface {tun_name:?}, advertise {advertise:?} pinned={pinned}",
        b.mesh_id
    );
    // P-C3 re-cipher channels: cmd (meshd→loop, trigger) + applied (loop→meshd, so we
    // update our stored secret/epoch/cipher when a re-cipher lands — initiated or
    // received).
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<LoopCmd>();
    let (applied_tx, applied_rx) = tokio::sync::mpsc::unbounded_channel::<LoopEvent>();
    let task = tokio::spawn(lattice_meshrun::run(lattice_meshrun::DataPlaneHandles {
        dp,
        tun,
        transport,
        links: b.links,
        exit: b.exit_sel,
        my_id: b.my_id,
        my_endpoint: Arc::clone(&b.my_endpoint),
        endpoint_pinned: pinned,
        loop_cmd: cmd_rx,
        loop_event: applied_tx,
        fails: b.decrypt_fails,
        traffic: b.traffic,
        split_routes: b.split_routes,
    }));
    // Record the loop's abort handle (RemoveMesh stops it) + the command sender.
    if let Some(ms) = state.lock().unwrap().meshes.get_mut(&b.mesh_id) {
        ms.dp_task = Some(task.abort_handle());
        ms.loop_cmd = Some(cmd_tx);
    }
    // Drain loop events (re-cipher / attack signals / gossip merges) — see
    // watch::spawn_loop_event_drain.
    spawn_loop_event_drain(b.mesh_id, Arc::clone(&state), applied_rx);
    // P-C4 live-paired self-destruct watchdog.
    spawn_self_destruct_watchdog(b.mesh_id, Arc::clone(&state));
}

/// Best-effort primary local IP — the source address the OS picks to reach the
/// internet (no packet is actually sent; `connect` on a UDP socket just selects the
/// route). Used as our advertised gossip endpoint when MESHD_ADVERTISE is unset.
fn local_ip() -> Option<std::net::IpAddr> {
    let s = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    s.connect(("8.8.8.8", 80)).ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

/// This host's real **physical LAN address** (e.g. en0 `192.168.x.x`), read straight from
/// the NIC list (`getifaddrs`) rather than a route lookup. Unlike [`local_ip`], this is NOT
/// distorted when full-tunnel diverts the default route through the overlay — so it's a
/// stable "which network am I physically on" signal for topology grouping. Picks the first
/// up, non-loopback, RFC1918 IPv4, skipping the mesh overlay (`100.64.0.0/10`) and tunnels.
/// 🟢 This host's primary private LAN IPv4 (for the LAN beacon / advertise address). Unix.
#[cfg(unix)]
fn local_lan_ipv4() -> Option<std::net::Ipv4Addr> {
    use std::net::Ipv4Addr;
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return None;
        }
        let mut found: Option<Ipv4Addr> = None;
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            if ifa.ifa_addr.is_null() {
                continue;
            }
            let sa = &*ifa.ifa_addr;
            if sa.sa_family as i32 != libc::AF_INET {
                continue;
            }
            let flags = ifa.ifa_flags as i32;
            if flags & libc::IFF_LOOPBACK != 0 || flags & libc::IFF_UP == 0 {
                continue;
            }
            let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
            // s_addr is 4 bytes in network order = the octets a.b.c.d, in order.
            let octets: [u8; 4] = sin.sin_addr.s_addr.to_ne_bytes();
            let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
            let o = ip.octets();
            let is_overlay = o[0] == 100 && (o[1] & 0xc0) == 64; // 100.64.0.0/10 (our overlay)
            if ip.is_loopback() || ip.is_link_local() || is_overlay || !ip.is_private() {
                continue;
            }
            found = Some(ip);
            break;
        }
        libc::freeifaddrs(ifap);
        found
    }
}

/// 🟢 This host's primary private LAN IPv4 (for the LAN beacon / advertise address). Non-unix.
#[cfg(not(unix))]
fn local_lan_ipv4() -> Option<std::net::Ipv4Addr> {
    match local_ip() {
        Some(std::net::IpAddr::V4(v4)) if v4.is_private() => Some(v4),
        _ => None,
    }
}

/// **RISK 🔴 HIGH** — auto-reverts full-tunnel if the exit "isn't passing traffic". A false
/// revert cuts a working VPN; a missing one strands the host. `Opkts=0`/"not passing" has MANY
/// causes (pf rule, route loop, wrong exit, wedge) — read docs/ERRORS.md before changing the probe.
/// Kill-switch watchdog (from v1). Full tunnel diverts the host default route
/// through the exit; if that path can't carry traffic the host is stranded OFFLINE.
/// Every ~20s probe the internet THROUGH the tunnel (TCP connect to 1.1.1.1:443 —
/// it travels TUN→exit, so success proves the exit forwards). The moment a probe
/// fails, auto-revert to direct internet so the user is never cut off.
/// **RISK 🔴 HIGH** — turn ON domain split-tunnel (docs/SPLIT_TUNNEL.md): point the host resolver
/// at our local DNS proxy and spawn it, so this mesh's rules pull matched domains' IPs into the
/// mesh via `/32` routes. Does NOT change the default route — normal internet is untouched.
/// Idempotent-ish: a prior session is stopped first.
async fn split_enable(mesh: MeshId, state: Arc<Mutex<State>>) {
    // Stop any prior session cleanly first.
    split_disable(Arc::clone(&state)).await;

    // Snapshot what the proxy needs: the mesh's tun name, its split-routes handle (shared with
    // the data-plane loop), and the rules for THIS mesh.
    let (tun, split_routes, rules) = {
        let st = state.lock().unwrap();
        let m = st.meshes.get(&mesh);
        let tun = m.and_then(|m| m.tun_name.clone());
        let split_routes = m.map(|m| Arc::clone(&m.split_routes));
        let rules: Vec<dns_split::SplitRule> = st
            .split_rules
            .iter()
            .filter(|r| r.mesh == mesh)
            .cloned()
            .collect();
        (tun, split_routes, rules)
    };
    let Some(split_routes) = split_routes else {
        elog!("meshd: split-tunnel: mesh {mesh} not found");
        return;
    };
    let Some(tun) = tun else {
        elog!("meshd: split-tunnel: mesh {mesh} has no data-plane tun (is the data plane up?)");
        return;
    };

    // Detect the real upstream resolver BEFORE we hijack DNS, so normal names still resolve.
    let upstream = tokio::task::spawn_blocking(dns_split::detect_upstream)
        .await
        .unwrap_or_else(|_| "1.1.1.1:53".parse().unwrap());

    // Point the host resolver at our proxy (backs up the prior DNS for restore).
    let loopback = std::net::IpAddr::from([127, 0, 0, 1]);
    if let Err(e) = tokio::task::spawn_blocking(move || exit::set_dns(&[loopback]))
        .await
        .unwrap_or(Ok(()))
    {
        elog!("meshd: split-tunnel: could not set host DNS to the proxy: {e}");
        return;
    }

    let injected = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    let task = tokio::spawn(dns_split::run_proxy(
        tun.clone(),
        rules,
        upstream,
        std::sync::Arc::clone(&injected),
        Arc::clone(&split_routes),
    ));
    {
        let mut st = state.lock().unwrap();
        st.split = Some(SplitActive {
            mesh,
            task,
            injected,
        });
        // Split SELECTS this mesh (so it's visible + `SetCurrent(None)` turns it off) but is NOT a
        // full tunnel — general traffic stays direct. Only mark it if we didn't clobber an active
        // full tunnel.
        if !st.full_tunnel {
            st.current = Some(mesh);
        }
        persist_split_active(&st); // survive restart (docs/SPLIT_TUNNEL.md)
    }
    elog!("meshd: split-tunnel ON for mesh {mesh} (upstream {upstream}, tun {tun})");
}

/// **RISK 🔴 HIGH** — turn OFF domain split-tunnel: abort the proxy, remove every injected `/32`
/// host route, and restore the host DNS. Safe no-op if split mode was already off.
async fn split_disable(state: Arc<Mutex<State>>) {
    let active = {
        let mut st = state.lock().unwrap();
        let active = st.split.take();
        // Clear the data-plane split-route table for that mesh so its traffic reverts to normal.
        if let Some(a) = &active {
            if let Some(m) = st.meshes.get(&a.mesh) {
                m.split_routes.lock().unwrap().clear();
            }
        }
        // A split selection deselects the mesh when it stops (back to the default network); a full
        // tunnel keeps its own `current`.
        if !st.full_tunnel {
            st.current = None;
        }
        persist_split_active(&st); // clears the persisted "on" marker
        active
    };
    let Some(active) = active else { return };
    active.task.abort();
    let ips: Vec<Ipv4Addr> = active.injected.lock().unwrap().iter().copied().collect();
    tokio::task::spawn_blocking(move || {
        for ip in ips {
            exit::unroute_host(ip);
        }
        exit::restore_dns();
    })
    .await
    .ok();
    elog!("meshd: split-tunnel OFF (routes + DNS restored)");
}

fn arm_kill_switch(mesh: MeshId, state: Arc<Mutex<State>>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            // Stop watching once egress moved off this mesh (user changed it).
            if state.lock().unwrap().current != Some(mesh) {
                return;
            }
            let alive = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::net::TcpStream::connect("1.1.1.1:443"),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);
            if !alive {
                let mut st = state.lock().unwrap();
                if st.current == Some(mesh) {
                    elog!(
                        "meshd kill-switch: full-tunnel exit not passing traffic — reverting to direct internet"
                    );
                    exit::restore_routes();
                    exit::restore_dns();
                    st.current = None;
                }
                return; // reverted (or someone else did) — stop probing
            }
        }
    });
}

/// Re-apply a persisted full-tunnel egress after a restart, **safely**. The intent (`current` +
/// `full_tunnel`) is already set by the caller; this waits (bounded) for the exit's endpoint to be
/// learned before diverting the default route — a boot-time divert to an exit that isn't reachable
/// yet would black-hole the default route and the kill-switch would rip it back down (internet
/// flaps). So we hold until the exit is live, then apply DNS + route exactly like the interactive
/// `SetCurrent` path and arm the kill-switch. Bails if the user changed egress meanwhile.
fn restore_full_tunnel(mesh: MeshId, state: Arc<Mutex<State>>) {
    tokio::spawn(async move {
        // ~40 * 3s ≈ 2 min for the exit link to be learned (handshake + gossip). If it never
        // comes up we keep the *intent* (a network change or manual toggle still applies it).
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            let plan = {
                let st = state.lock().unwrap();
                // User picked another egress / went to default network, or the mesh is gone.
                if st.current != Some(mesh) || !st.full_tunnel {
                    return;
                }
                let Some(ms) = st.meshes.get(&mesh) else {
                    return;
                };
                let Some(exit_id) = ms.mesh.exit else { return };
                let tun = ms.tun_name.clone();
                let ip = ms
                    .links
                    .lock()
                    .unwrap()
                    .get(&exit_id)
                    .map(|l| l.endpoint.ip());
                (tun, ip)
            };
            // Exit endpoint not learned yet → keep waiting (do NOT divert to a dead exit).
            let (Some(tun), Some(ip)) = plan else {
                continue;
            };
            let errs = tokio::task::spawn_blocking(move || {
                let mut errs: Vec<String> = Vec::new();
                // DNS first, then route — same order as SetCurrent (see its comment).
                if let Ok(dns) = FULL_TUNNEL_DNS.parse() {
                    if let Err(e) = exit::set_dns(&[dns]) {
                        errs.push(format!("DNS: {e}"));
                    }
                }
                if let Err(e) = exit::route_through(&tun, ip) {
                    errs.push(format!("route: {e}"));
                }
                errs
            })
            .await
            .unwrap_or_else(|_| vec!["route task join error".into()]);
            {
                let mut st = state.lock().unwrap();
                if let Some(ms) = st.meshes.get_mut(&mesh) {
                    ms.dp_error = if errs.is_empty() {
                        None
                    } else {
                        Some(format!(
                            "full-tunnel restore not fully applied — {}",
                            errs.join("; ")
                        ))
                    };
                }
            }
            elog!(
                "meshd: restored full-tunnel egress for mesh {mesh} (persisted across restart){}",
                if errs.is_empty() {
                    ""
                } else {
                    " — with errors"
                }
            );
            arm_kill_switch(mesh, state); // same watchdog as the interactive path
            return;
        }
        elog!(
            "meshd: full-tunnel egress for mesh {mesh} still remembered but its exit never became reachable this boot — a network change or manual re-select will apply it"
        );
    });
}

/// **RISK 🟡 MED** — the central IPC request dispatcher (a big `match` over [`Request`]). Mutates
/// all mesh state under the lock and returns a [`Response`] + an optional [`PostAction`] (the
/// async/side-effecting work — data-plane bringup, kill-switch arm, shutdown — done by the caller
/// AFTER releasing the lock). Mis-wiring a new request arm (or doing async work here) is the
/// common bug. Connector-gated requests are pre-screened by [`scope_gate`].
fn handle(req: Request, st: &mut State) -> (Response, Option<PostAction>) {
    match req {
        Request::CreateMesh {
            name,
            my_name,
            max_members,
            cipher,
            self_destruct,
            master_gated,
            expel,
            header,
            exit_policy,
            join,
        } => create_mesh(
            st,
            name,
            my_name,
            max_members,
            cipher,
            self_destruct,
            master_gated,
            expel,
            header,
            exit_policy,
            join,
        ),

        Request::ExpelMember { mesh, member } => expel_member(st, mesh, member),

        Request::Ciphers => (
            Response::Ciphers(
                lattice_mesh::crypto::available_ciphers()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            ),
            None,
        ),

        Request::Recipher { mesh, cipher } => recipher(st, mesh, cipher),

        Request::ReportAttack { mesh } => {
            // One-veto, fail-deadly (P-C7 §7): any member flagging an attack broadcasts
            // an alert and arms the destroy grace locally. Unless the creator sends an
            // all-clear within the grace, every member self-destructs.
            let Some(ms) = st.meshes.get_mut(&mesh) else {
                return (no_mesh(mesh), None);
            };
            let peers: Vec<MemberId> = ms.links.lock().unwrap().keys().copied().collect();
            if let Some(tx) = &ms.loop_cmd {
                let _ = tx.send(LoopCmd::SendControl(CTRL_ATTACK, Vec::new(), peers));
            }
            if ms.attack_armed_at.is_none() {
                ms.attack_armed_at = Some(now_ms());
            }
            elog!(
                "meshd: mesh {mesh} ATTACK reported — alert broadcast, destroy grace armed ({ATTACK_GRACE_SECS}s)"
            );
            (Response::Ok, None)
        }

        Request::AllClear { mesh } => {
            // Only the creator (holds the master key) can call off an attack (§7).
            let Some(ms) = st.meshes.get_mut(&mesh) else {
                return (no_mesh(mesh), None);
            };
            if ms.master.is_none() {
                return (err("only the mesh creator can issue an all-clear"), None);
            }
            let peers: Vec<MemberId> = ms.links.lock().unwrap().keys().copied().collect();
            if let Some(tx) = &ms.loop_cmd {
                let _ = tx.send(LoopCmd::SendControl(CTRL_ALLCLEAR, Vec::new(), peers));
            }
            ms.attack_armed_at = None;
            elog!("meshd: mesh {mesh} ALL-CLEAR issued by creator — destroy grace cancelled");
            (Response::Ok, None)
        }

        Request::ExportState { path } => export_state(st, path),
        Request::ListMeshes => {
            let cur = st.current;
            let def = st.default_mesh;
            let now = now_ms();
            let mut meshes: Vec<MeshSummary> = st
                .meshes
                .values()
                .map(|ms| MeshSummary {
                    id: ms.mesh.id,
                    name: ms.mesh.name.clone(),
                    members: ms.roster().len(),
                    epoch: ms.epoch,
                    exit: ms.mesh.exit,
                    is_current: cur == Some(ms.mesh.id),
                    exitable: ms.exitable,
                    attack_armed_secs_left: ms.attack_armed_at.map(|armed| {
                        ATTACK_GRACE_SECS.saturating_sub(now.saturating_sub(armed) / 1000)
                    }),
                    is_creator: ms.master.is_some(),
                    is_default: def == Some(ms.mesh.id),
                })
                .collect();
            meshes.sort_by_key(|s| s.id);
            (Response::Meshes(meshes), None)
        }

        Request::MeshInfo { mesh } => match st.meshes.get(&mesh) {
            Some(ms) => (Response::Mesh(detail(ms)), None),
            None => (no_mesh(mesh), None),
        },

        Request::TrafficStats { mesh } => (Response::Traffic(traffic_view(st, mesh)), None),

        Request::AdmitMember {
            mesh,
            name,
            pubkey_hex,
        } => admit_member(st, mesh, name, pubkey_hex),

        Request::SetExit { mesh, exit } => {
            let ok = match st.meshes.get_mut(&mesh) {
                Some(ms) => {
                    if let Some(e) = exit {
                        if !ms.roster().iter().any(|c| c.id == e) {
                            return (err(&format!("no member {e} in mesh {mesh}")), None);
                        }
                    }
                    ms.mesh.exit = exit;
                    // Steer the live data-plane loop's egress.
                    *ms.exit_sel.lock().unwrap() = exit;
                    true
                }
                None => false,
            };
            if !ok {
                return (no_mesh(mesh), None);
            }
            if exit.is_none() && st.current == Some(mesh) {
                st.current = None;
                exit::restore_routes();
                exit::restore_dns();
                persist_egress(st); // egress went away with the exit — forget it too
            }
            // The exit designation must survive a restart: without it, a persisted full-tunnel
            // egress can't be re-applied at boot (`restore_full_tunnel` needs `mesh.exit`), so the
            // node would still fall back to the default network. (Was unpersisted — sibling of the
            // egress-persistence bug.)
            persist(st);
            (Response::Ok, None)
        }

        Request::SetPeer {
            mesh,
            member,
            endpoint,
        } => {
            let addr: SocketAddr = match endpoint.parse() {
                Ok(a) => a,
                Err(_) => {
                    return (
                        err(&format!("bad endpoint '{endpoint}' (want ip:port)")),
                        None,
                    )
                }
            };
            match st.meshes.get(&mesh) {
                Some(ms) => {
                    ms.links.lock().unwrap().insert(
                        member,
                        Link {
                            endpoint: addr,
                            last_seen_ms: 0,
                            last_direct_ms: 0,
                        },
                    );
                    (Response::Ok, None)
                }
                None => (no_mesh(mesh), None),
            }
        }

        Request::SetDefaultMesh { mesh } => {
            // A persisted view/selection hint only — does NOT change routing (unlike SetCurrent).
            match mesh {
                Some(id) if !st.meshes.contains_key(&id) => (no_mesh(id), None),
                _ => {
                    st.default_mesh = mesh;
                    persist_default_mesh(st);
                    (Response::Ok, None)
                }
            }
        }

        Request::SetCurrent { mesh } => set_current(st, mesh),

        Request::RemoveMesh { mesh } => {
            if let Some(ms) = st.meshes.remove(&mesh) {
                // Stop the data-plane loop so its TUN + UDP socket are dropped — else
                // the port leaks and a re-created mesh on the same port can't bind.
                if let Some(task) = &ms.dp_task {
                    task.abort();
                }
                if st.current == Some(mesh) {
                    st.current = None;
                    exit::restore_routes();
                    exit::restore_dns();
                    persist_egress(st); // removed mesh was the egress — forget it across restarts
                }
                emit(
                    st,
                    "peer",
                    Some(mesh),
                    serde_json::json!({ "kind": "mesh_removed", "mesh": mesh }),
                );
                (Response::Ok, None)
            } else {
                (no_mesh(mesh), None)
            }
        }

        Request::Shutdown => (Response::Ok, Some(PostAction::Shutdown)),

        Request::GetPolicy => {
            // General egress is only "via mesh" under a FULL tunnel; a split selection leaves
            // general traffic direct (only matched domains follow the mesh exit).
            let default = match st
                .current
                .filter(|_| st.full_tunnel)
                .and_then(|id| st.meshes.get(&id))
            {
                Some(ms) => match ms.mesh.exit {
                    Some(e) => format!("via mesh {} exit {}", ms.mesh.id, e),
                    None => "direct".into(),
                },
                None => "direct".into(),
            };
            (
                Response::Policy(PolicyView {
                    default,
                    current_mesh: st.current,
                }),
                None,
            )
        }

        Request::GetFlows { mesh } => match st.meshes.get(&mesh) {
            Some(ms) => (Response::FlowRules(ms.flows.clone()), None),
            None => (no_mesh(mesh), None),
        },

        Request::SetFlows { mesh, flows } => set_flows(st, mesh, flows),

        Request::NewIdentity => {
            let member = MemberKey::generate();
            let enc = EncKey::generate();
            let member_pubkey_hex = hex(&member.pubkey());
            let enc_pubkey_hex = hex(&enc.public());
            st.pending.insert(member.pubkey(), (member, enc));
            (
                Response::Identity {
                    member_pubkey_hex,
                    enc_pubkey_hex,
                    issued_at: now_ms(), // P-C6 time-expire
                },
                None,
            )
        }

        Request::InviteAlgorithms => (
            Response::Ciphers(
                lattice_mesh::invitewrap::invite_algorithms()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            ),
            None,
        ),

        // --- extensions / connectors (docs/EXTENSIONS.md) --------------------------
        Request::EnableExtension {
            id,
            scopes,
            all_meshes,
            meshes,
        } => (enable_extension(st, id, scopes, all_meshes, meshes), None),
        Request::DisableExtension { id } => match st.extensions.get_mut(&id) {
            Some(g) => {
                g.enabled = false;
                (Response::Ok, None)
            }
            None => (err("unknown extension"), None),
        },
        Request::ListExtensions => (
            Response::Extensions(st.extensions.values().map(|g| g.view()).collect()),
            None,
        ),
        Request::Advertise {
            mesh,
            proto,
            port,
            name,
            meta,
        } => (advertise(st, mesh, proto, port, name, meta), None),
        Request::Unadvertise { mesh, proto } => (unadvertise(st, mesh, proto), None),
        Request::ListServices { mesh, proto } => (list_services(st, mesh, proto), None),

        // --- domain split-tunnel (docs/SPLIT_TUNNEL.md), local to this node ------------------
        Request::SplitAdd { domain, mesh, exit } => (split_add(st, domain, mesh, exit), None),
        Request::SplitDel { domain } => (split_del(st, domain), None),
        Request::SplitList => (split_list(st), None),
        Request::SplitOn { mesh } => {
            if !st.meshes.contains_key(&mesh) {
                (no_mesh(mesh), None)
            } else {
                // `split_enable` selects the mesh (sets `current`, leaves `full_tunnel` false) on
                // success, so a failed bringup never leaves a dangling selection.
                (Response::Ok, Some(PostAction::SplitOn(mesh)))
            }
        }
        // `split_disable` deselects the mesh (back to the default network) when it stops.
        Request::SplitOff => (Response::Ok, Some(PostAction::SplitOff)),

        Request::SetExitable { mesh, enabled } => {
            if let Some(ms) = st.meshes.get_mut(&mesh) {
                ms.exitable = enabled;
                (Response::Ok, Some(PostAction::ApplyExitable(mesh)))
            } else {
                (no_mesh(mesh), None)
            }
        }

        Request::CreateInvite {
            mesh,
            name,
            member_pubkey_hex,
            enc_pubkey_hex,
            issued_at,
            algo,
        } => create_invite(
            st,
            mesh,
            name,
            member_pubkey_hex,
            enc_pubkey_hex,
            issued_at,
            algo,
        ),

        Request::CreateQuickInvite {
            mesh,
            name: _name,
            max_uses,
            ttl_secs,
            algo,
        } => create_quick_invite(st, mesh, max_uses, ttl_secs, algo),

        Request::JoinMesh { invite, algo, name } => {
            // P-C6: unwrap with the out-of-band algorithm before installing.
            let algo = algo.unwrap_or_else(|| lattice_mesh::invitewrap::DEFAULT_ALGO.to_string());
            let plain =
                match lattice_mesh::invitewrap::unwrap(&algo, &invite.salt, invite.n, &invite.ct) {
                    Some(p) => p,
                    None => {
                        return (
                            err("could not open the invite — wrong algorithm or corrupt code"),
                            None,
                        )
                    }
                };
            // A quick (bearer) invite is tagged; a classic one is raw JSON (docs/JOIN_MODES.md §4).
            if let Some(body) = plain.strip_prefix(lattice_mesh::ipc::QUICK_TAG) {
                match serde_json::from_slice::<lattice_mesh::ipc::QuickInviteBlob>(body) {
                    Ok(blob) => join_quick(st, blob, name),
                    Err(e) => (err(&format!("bad quick-invite contents: {e}")), None),
                }
            } else {
                match serde_json::from_slice::<InviteBlob>(&plain) {
                    Ok(blob) => join_mesh(st, blob),
                    Err(e) => (err(&format!("bad invite contents: {e}")), None),
                }
            }
        }

        // Per-connection session requests are intercepted in `serve_conn` (they need the
        // connection's session + outbound channel); they never reach the stateless handler.
        Request::Hello { .. } | Request::Subscribe { .. } => (
            err("session request must be sent on a connector connection"),
            None,
        ),
    }
}

/// `Recipher` (P-C3): rotate the mesh secret — quorum-gated (≥60% online), then
/// announce to every reachable peer via the loop. Extracted from `handle` (Phase 3).
fn recipher(
    st: &mut State,
    mesh: MeshId,
    cipher: Option<String>,
) -> (Response, Option<PostAction>) {
    let ms = match st.meshes.get(&mesh) {
        Some(m) => m,
        None => return (no_mesh(mesh), None),
    };
    // Quorum: self + peers heard within the liveness window ≥ ⌈0.6·N⌉.
    let n = ms.roster().len().max(1);
    let now = now_ms();
    let online = 1 + ms
        .links
        .lock()
        .unwrap()
        .values()
        .filter(|l| now.saturating_sub(l.last_seen_ms) < LIVE_WINDOW_MS)
        .count();
    let threshold = quorum_threshold(n);
    if online < threshold {
        return (
            err(&format!(
                "re-cipher needs ≥60% online — {online}/{n} up, need {threshold}"
            )),
            None,
        );
    }
    let new_cipher = cipher.unwrap_or_else(|| ms.cipher.clone());
    if !lattice_mesh::crypto::is_known_cipher(&new_cipher) {
        return (err(&format!("unknown cipher '{new_cipher}'")), None);
    }
    // Announce to every known peer (offline ones won't receive it → evicted).
    let peers: Vec<MemberId> = ms.links.lock().unwrap().keys().copied().collect();
    let r = Recipher {
        epoch: ms.epoch + 1,
        cipher: new_cipher,
        secret: rand::random(),
    };
    match &ms.loop_cmd {
        Some(tx) => {
            let _ = tx.send(LoopCmd::Recipher(r, peers));
            (Response::Ok, None)
        }
        None => (err("data plane is not running; can't re-cipher"), None),
    }
}

/// `ExportState` — write the update-migration snapshot (every mesh, pretty JSON,
/// 0600). Extracted from `handle` (Phase 3).
fn export_state(st: &State, path: Option<String>) -> (Response, Option<PostAction>) {
    let target = path
        .map(PathBuf::from)
        .unwrap_or_else(migration_backup_path);
    let snapshot: Vec<PersistedMesh> = st.meshes.values().map(to_persisted).collect();
    match serde_json::to_vec_pretty(&snapshot) {
        Ok(json) => match std::fs::write(&target, &json) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600));
                }
                elog!(
                    "meshd: exported {} mesh(es) to {}",
                    snapshot.len(),
                    target.display()
                );
                (Response::Ok, None)
            }
            Err(e) => (err(&format!("could not write backup: {e}")), None),
        },
        Err(e) => (err(&format!("could not serialize state: {e}")), None),
    }
}

/// `AdmitMember` — local, cert-only admit by pubkey (no secret handed out; use
/// CreateInvite for a node that will actually connect). Creator only.
/// Extracted from `handle` (Phase 3).
fn admit_member(
    st: &mut State,
    mesh: MeshId,
    name: String,
    pubkey_hex: String,
) -> (Response, Option<PostAction>) {
    let pubkey = match parse_hex32(&pubkey_hex) {
        Some(p) => p,
        None => return (err("pubkey must be 64 hex chars"), None),
    };
    let ms = match st.meshes.get_mut(&mesh) {
        Some(m) => m,
        None => return (no_mesh(mesh), None),
    };
    let roster = ms.roster();
    if roster.len() >= ms.mesh.charter.max_members as usize {
        return (
            err(&format!(
                "mesh is full (max {})",
                ms.mesh.charter.max_members
            )),
            None,
        );
    }
    if roster.iter().any(|c| c.member == pubkey) {
        return (err("already a member"), None);
    }
    let used: HashSet<MemberId> = roster.iter().map(|c| c.id).collect();
    let id = match (1u8..=254).find(|i| !used.contains(i)) {
        Some(i) => i,
        None => return (err("no free member id"), None),
    };
    // The master (held by this node) issues the cert binding the member.
    // Note: this is a local admit only — it does NOT hand the joiner the
    // mesh secret. Use CreateInvite for a node that will actually connect.
    let cert = match ms.master.as_ref() {
        Some(m) => m.issue(pubkey, id, &name, now_ms()),
        None => return (err("only the mesh creator can admit members"), None),
    };
    ms.certs.push(cert);
    (Response::Ok, None)
}

/// `SetCurrent` — select/clear the FULL-tunnel egress mesh: divert or restore the
/// default route + DNS, persist the selection, arm the kill-switch. 🔴 the
/// full-tunnel wiring. Extracted from `handle` (Phase 3).
fn set_current(st: &mut State, mesh: Option<MeshId>) -> (Response, Option<PostAction>) {
    match mesh {
        None => {
            st.current = None;
            st.full_tunnel = false;
            persist_egress(st); // forget the full-tunnel egress across restarts
                                // Back to the default network means NOTHING routes through a mesh: also drop
                                // split-tunnel (its DNS hijack + injected /32s) so "default" is truly direct.
            if st.split.is_some() {
                return (Response::Ok, Some(PostAction::SplitOff));
            }
            // Undo the full-tunnel diversion.
            exit::restore_routes();
            exit::restore_dns();
            (Response::Ok, None)
        }
        Some(id) => {
            // Collect the exit's TUN + physical endpoint, then divert all traffic
            // through it (full tunnel). Early-return on the error cases.
            let plan = match st.meshes.get(&id) {
                Some(ms) if ms.mesh.exit.is_some() => {
                    let exit_id = ms.mesh.exit.unwrap();
                    let exit_ip = ms
                        .links
                        .lock()
                        .unwrap()
                        .get(&exit_id)
                        .map(|l| l.endpoint.ip());
                    (ms.tun_name.clone(), exit_ip)
                }
                Some(_) => {
                    return (
                        err(&format!(
                            "set an exit for mesh {id} before making it current"
                        )),
                        None,
                    )
                }
                None => return (no_mesh(id), None),
            };
            st.current = Some(id);
            st.full_tunnel = true;
            persist_egress(st); // remember this full-tunnel egress across restarts
            let action = match plan {
                (Some(tun), Some(ip)) => {
                    // Point DNS through the tunnel BEFORE diverting the default
                    // route: `set_dns` keys off the primary network service, which
                    // it derives from the current default interface — once the
                    // route is on the TUN that lookup finds the tunnel (no service)
                    // and DNS is silently left on the now-unreachable LAN resolver.
                    let mut errs: Vec<String> = Vec::new();
                    if let Ok(dns) = FULL_TUNNEL_DNS.parse() {
                        if let Err(e) = exit::set_dns(&[dns]) {
                            errs.push(format!("DNS: {e}"));
                        }
                    }
                    if let Err(e) = exit::route_through(&tun, ip) {
                        errs.push(format!("route: {e}"));
                    }
                    // Don't claim full-tunnel is on when the OS-side plumbing
                    // failed — surface it so the GUI/CLI show why traffic isn't
                    // flowing instead of a silently-broken "VPN on".
                    if let Some(ms) = st.meshes.get_mut(&id) {
                        ms.dp_error = if errs.is_empty() {
                            None
                        } else {
                            Some(format!(
                                "full-tunnel not fully applied — {}",
                                errs.join("; ")
                            ))
                        };
                    }
                    // Arm the kill-switch: auto-revert if the exit can't carry traffic.
                    Some(PostAction::ArmKillSwitch(id))
                }
                _ => {
                    elog!(
                        "meshd: full-tunnel not plumbed for mesh {id} — TUN or exit endpoint unknown (is the data plane up + exit reachable?)"
                    );
                    None
                }
            };
            (Response::Ok, action)
        }
    }
}

/// `SetFlows` — replace the mesh's SDN flow table: bump the version, push it to
/// the live data plane, persist, gossip (newest version wins).
/// Extracted from `handle` (Phase 3).
fn set_flows(st: &mut State, mesh: MeshId, flows: Vec<FlowRule>) -> (Response, Option<PostAction>) {
    let Some(ms) = st.meshes.get_mut(&mesh) else {
        return (no_mesh(mesh), None);
    };
    ms.flow_version += 1;
    ms.flows = flows.clone();
    let version = ms.flow_version;
    // Apply to the live data plane so the next packet routes by the new table.
    if let Some(tx) = &ms.loop_cmd {
        let _ = tx.send(LoopCmd::SetFlows(flows.clone()));
    }
    // Gossip `version(8 BE) ‖ bincode(flows)` to peers (newest version wins).
    if let Some(tx) = ms.loop_cmd.clone() {
        let peers: Vec<MemberId> = ms.links.lock().unwrap().keys().copied().collect();
        if !peers.is_empty() {
            if let Ok(enc) = bincode::serialize(&flows) {
                let mut body = version.to_be_bytes().to_vec();
                body.extend_from_slice(&enc);
                let _ = tx.send(LoopCmd::SendControl(CTRL_FLOWS, body, peers));
            }
        }
    }
    persist(st);
    elog!(
        "meshd: mesh {mesh} flow table set to v{version} ({} rules)",
        flows.len()
    );
    (
        Response::Info {
            message: format!("flow table updated (v{version}, {} rules)", flows.len()),
        },
        None,
    )
}

/// The shared "who may invite" gate (CreateInvite + CreateQuickInvite): the master
/// holder may always invite; otherwise the mesh must be OpenChain (any verified
/// member signs the joiner's cert with their own key — it chains back to the
/// master through the inviter's own cert) AND we must be a verified member.
/// Returns the validated roster on success.
fn invite_gate(ms: &MeshState) -> Result<Vec<Cert>, Response> {
    let roster = ms.roster();
    if ms.master.is_none() {
        if ms.mesh.charter.invite != InviteTopology::OpenChain {
            return Err(err(
                "only the mesh creator can invite in a master-gated mesh",
            ));
        }
        if !roster.iter().any(|c| c.member == ms.my_key.pubkey()) {
            return Err(err("you must be a verified member of this mesh to invite"));
        }
    }
    Ok(roster)
}

/// Bootstrap endpoints for a joiner (P-D1): our own advertised address first, then
/// every peer we already reach — the joiner seeds its data plane with these so it
/// can send before gossip converges (no manual SetPeer).
fn bootstrap_endpoints(ms: &MeshState) -> Vec<(MemberId, String)> {
    let mut endpoints: Vec<(MemberId, String)> = Vec::new();
    if let Some(ep) = *ms.my_endpoint.lock().unwrap() {
        endpoints.push((ms.my_id(), ep.to_string()));
    }
    for (m, link) in ms.links.lock().unwrap().iter() {
        endpoints.push((*m, link.endpoint.to_string()));
    }
    endpoints
}

/// `CreateInvite` — issue a SECURE invite: TTL-check the joiner's identity code,
/// gate who may invite, reserve a member id, issue the cert (master- or
/// member-signed), seal the secret, wrap under (algo, salt, n) (P-C6).
/// Extracted from `handle` (Phase 3).
#[allow(clippy::too_many_arguments)]
fn create_invite(
    st: &mut State,
    mesh: MeshId,
    name: String,
    member_pubkey_hex: String,
    enc_pubkey_hex: String,
    issued_at: u64,
    algo: Option<String>,
) -> (Response, Option<PostAction>) {
    // P-C6: reject a stale identity code.
    if issued_at != 0
        && now_ms().saturating_sub(issued_at) > lattice_mesh::invitewrap::IDENTITY_TTL_SECS * 1000
    {
        return (
            err("identity code expired — ask the joiner for a fresh one"),
            None,
        );
    }
    let algo = algo.unwrap_or_else(|| lattice_mesh::invitewrap::DEFAULT_ALGO.to_string());
    if !lattice_mesh::invitewrap::is_known_algo(&algo) {
        return (err(&format!("unknown invite algorithm '{algo}'")), None);
    }
    let member_pk = match parse_hex32(&member_pubkey_hex) {
        Some(p) => p,
        None => return (err("member_pubkey must be 64 hex chars"), None),
    };
    let enc_pk = match parse_hex32(&enc_pubkey_hex) {
        Some(p) => p,
        None => return (err("enc_pubkey must be 64 hex chars"), None),
    };
    let ms = match st.meshes.get_mut(&mesh) {
        Some(m) => m,
        None => return (no_mesh(mesh), None),
    };
    // Who may invite? In an OpenChain mesh (the default) ANY verified member can —
    // they sign the joiner's cert with their own member key and it chains back to
    // the master through the inviter's own cert (membership::valid_members). Only a
    // MasterGated mesh restricts invites to the creator (the master-key holder).
    let roster = match invite_gate(ms) {
        Ok(r) => r,
        Err(resp) => return (resp, None),
    };
    if roster.len() >= ms.mesh.charter.max_members as usize {
        return (
            err(&format!(
                "mesh is full (max {})",
                ms.mesh.charter.max_members
            )),
            None,
        );
    }
    if roster.iter().any(|c| c.member == member_pk) {
        return (err("already a member"), None);
    }
    // Pick the joiner's id, reserving ids already handed out in invites that have
    // not yet joined — otherwise inviting several people in a row (before any of
    // them connect and gossip back) would assign them all the same "next free" id.
    // First prune reservations that have since joined, or expired.
    let now = now_ms();
    ms.invited.retain(|(iid, pk, at)| {
        now.saturating_sub(*at) < INVITE_RESERVE_MS
            && !roster.iter().any(|c| c.id == *iid || &c.member == pk)
    });
    // Re-inviting the same pubkey reuses its reserved id (idempotent); else take the
    // lowest id free in BOTH the roster and the outstanding reservations.
    let id = if let Some((iid, _, _)) = ms.invited.iter().find(|(_, pk, _)| *pk == member_pk) {
        *iid
    } else {
        let mut used: HashSet<MemberId> = roster.iter().map(|c| c.id).collect();
        used.extend(ms.invited.iter().map(|(iid, _, _)| *iid));
        match (1u8..=254).find(|i| !used.contains(i)) {
            Some(i) => {
                ms.invited.push((i, member_pk, now));
                i
            }
            None => return (err("no free member id"), None),
        }
    };
    // Issue the cert: the master signs it if we're the creator; otherwise we (a
    // member) sign an open-chain invite cert with our own key — either way it
    // chains to the master. Then seal the mesh secret to the joiner's enc key.
    let cert = match ms.master.as_ref() {
        Some(m) => m.issue(member_pk, id, &name, now_ms()),
        None => ms.my_key.invite(
            ms.mesh.charter.master_pubkey,
            member_pk,
            id,
            &name,
            now_ms(),
        ),
    };
    let sealed_secret = seal_secret(&enc_pk, &ms.secret);
    // Bootstrap endpoints for the joiner (P-D1): our own advertised address
    // first, then every peer we already reach. The joiner seeds its data
    // plane with these so it can send to us (and them) before gossip
    // converges — no manual SetPeer needed.
    let endpoints = bootstrap_endpoints(ms);
    // Do NOT add the invitee to our OWN roster here: creating an invite must never
    // make a node a "member" that never connected (that phantom then gossips
    // mesh-wide). The joiner gets its cert in the blob below; once it actually JOINS
    // and connects, its cert propagates back via roster gossip and it becomes a real
    // member then — membership tracks connection, not a dangling invite.
    let mut blob_certs = ms.certs.clone();
    blob_certs.push(cert);
    let blob = InviteBlob {
        mesh_id: ms.mesh.id,
        mesh_name: ms.mesh.name.clone(),
        charter: ms.mesh.charter.clone(),
        member_id: id,
        certs: blob_certs,
        sealed_secret,
        endpoints,
        epoch: ms.epoch,           // bring the joiner up at the live epoch (P-C3)
        cipher: ms.cipher.clone(), // ...and the live cipher (may differ post-re-cipher)
    };
    // P-C6: wrap the blob under (algo, fresh salt, n). The joiner needs `algo`
    // (out-of-band) to open it.
    let plain = match serde_json::to_vec(&blob) {
        Ok(b) => b,
        Err(e) => return (err(&format!("serialize invite: {e}")), None),
    };
    let salt: [u8; 32] = rand::random();
    let n: u32 = rand::random();
    let ct = lattice_mesh::invitewrap::wrap(&algo, &salt, n, &plain);
    (
        Response::Invite(lattice_mesh::ipc::WrappedInvite { salt, n, ct }),
        None,
    )
}

/// `CreateQuickInvite` — issue a QUICK (bearer) invite: a signed Grant + the RAW
/// secret, refused on a SecureOnly charter floor (docs/JOIN_MODES.md).
/// Extracted from `handle` (Phase 3).
fn create_quick_invite(
    st: &mut State,
    mesh: MeshId,
    max_uses: u32,
    ttl_secs: u64,
    algo: Option<String>,
) -> (Response, Option<PostAction>) {
    let algo = algo.unwrap_or_else(|| lattice_mesh::invitewrap::DEFAULT_ALGO.to_string());
    if !lattice_mesh::invitewrap::is_known_algo(&algo) {
        return (err(&format!("unknown invite algorithm '{algo}'")), None);
    }
    if max_uses == 0 {
        return (err("max_uses must be at least 1"), None);
    }
    let ms = match st.meshes.get_mut(&mesh) {
        Some(m) => m,
        None => return (no_mesh(mesh), None),
    };
    // Charter floor: a mesh created `SecureOnly` refuses quick (bearer) invites so a member
    // can't weaken it (docs/JOIN_MODES.md §7).
    if ms.mesh.charter.join_floor == lattice_mesh::charter::JoinFloor::SecureOnly {
        return (
            err("this mesh only allows secure invites (created with --join secure)"),
            None,
        );
    }
    // Same "who may invite" gate as CreateInvite: master, or a verified member in OpenChain.
    if let Err(resp) = invite_gate(ms) {
        return (resp, None);
    }
    let grant_id: [u8; 16] = rand::random();
    let expires_at = now_ms().saturating_add(ttl_secs.saturating_mul(1000));
    // Issue the grant: master-signed if we're the creator, else an OpenChain member grant.
    let grant = match ms.master.as_ref() {
        Some(m) => m.grant(grant_id, max_uses, expires_at, now_ms()),
        None => ms.my_key.grant(
            ms.mesh.charter.master_pubkey,
            grant_id,
            max_uses,
            expires_at,
            now_ms(),
        ),
    };
    // Bootstrap endpoints (P-D1), same as CreateInvite.
    let endpoints = bootstrap_endpoints(ms);
    let blob = lattice_mesh::ipc::QuickInviteBlob {
        mesh_id: ms.mesh.id,
        mesh_name: ms.mesh.name.clone(),
        charter: ms.mesh.charter.clone(),
        grant,
        secret: ms.secret, // RAW (bearer) — see docs/JOIN_MODES.md §4
        epoch: ms.epoch,
        cipher: ms.cipher.clone(),
        certs: ms.certs.clone(),
        grant_certs: ms.grant_certs.clone(),
        endpoints,
    };
    // Tag the plaintext so `join` can tell a quick blob from a classic one, then wrap it with
    // the exact same P-C6 machinery.
    let mut plain = lattice_mesh::ipc::QUICK_TAG.to_vec();
    match serde_json::to_vec(&blob) {
        Ok(b) => plain.extend_from_slice(&b),
        Err(e) => return (err(&format!("serialize quick invite: {e}")), None),
    }
    let salt: [u8; 32] = rand::random();
    let n: u32 = rand::random();
    let ct = lattice_mesh::invitewrap::wrap(&algo, &salt, n, &plain);
    (
        Response::Invite(lattice_mesh::ipc::WrappedInvite { salt, n, ct }),
        None,
    )
}

/// **RISK 🟡 MED** — install a mesh from an invite blob (keys, roster, endpoints) and persist it;
/// returns a `Bringup` PostAction so the caller starts its data plane. Mesh-lifecycle correctness.
fn join_mesh(st: &mut State, invite: InviteBlob) -> (Response, Option<PostAction>) {
    if st.meshes.contains_key(&invite.mesh_id) {
        return (err(&format!("already in mesh {}", invite.mesh_id)), None);
    }
    // The cert the creator issued to us tells us which pending identity to use.
    let my_cert = match invite.certs.iter().find(|c| c.id == invite.member_id) {
        Some(c) => c,
        None => return (err("invite has no cert for the assigned member id"), None),
    };
    let (my_key, my_enc) = match st.pending.remove(&my_cert.member) {
        Some(pair) => pair,
        None => {
            return (
                err("no pending identity for this invite — call NewIdentity first"),
                None,
            )
        }
    };
    // Open the sealed mesh secret with our encryption key.
    let secret = match my_enc.open(&invite.sealed_secret) {
        Some(s) => s,
        None => return (err("could not open the sealed secret (wrong key?)"), None),
    };
    // Verify our cert actually chains to the charter's master before adopting.
    let roster = valid_members(
        &invite.charter.master_pubkey,
        &invite.certs,
        invite.charter.invite,
    );
    if !roster
        .iter()
        .any(|c| c.id == invite.member_id && c.member == my_key.pubkey())
    {
        return (
            err("our cert does not validate against the master — bad invite"),
            None,
        );
    }
    // Prefer the invite's live cipher (post-re-cipher); fall back to the charter's.
    let cipher = if invite.cipher.is_empty() {
        invite.charter.initial_cipher.clone()
    } else {
        invite.cipher.clone()
    };
    let epoch = invite.epoch; // bring the data plane up at the mesh's live epoch (P-C3)
                              // Seed the data plane with the bootstrap endpoints the inviter handed us (P-D1):
                              // we can reach the inviter (and any peers it knew) immediately, before gossip
                              // converges. Skip our own id and any unparseable address.
    let mut seed: HashMap<MemberId, SocketAddr> = HashMap::new();
    for (m, ep) in &invite.endpoints {
        if *m == invite.member_id {
            continue;
        }
        if let Ok(addr) = ep.parse() {
            seed.insert(*m, addr);
        }
    }
    let mut mesh = Mesh::new(
        invite.mesh_id,
        invite.mesh_name.clone(),
        invite.charter,
        invite.member_id,
    );
    mesh.epoch = epoch;
    let (ms, bringup) = NewMesh {
        mesh,
        master: None,
        my_key,
        my_enc,
        certs: invite.certs,
        revocations: Vec::new(),
        grant_certs: Vec::new(),
        secret,
        cipher,
        epoch,
        exit: None,
        exitable: false,
        seed,
        flows: lattice_proto::flow::default_table(),
        flow_version: 0,
    }
    .build();
    let bringup = st.data_plane.then_some(bringup);
    st.meshes.insert(invite.mesh_id, ms);
    emit(
        st,
        "peer",
        Some(invite.mesh_id),
        serde_json::json!({ "kind": "mesh_added", "mesh": invite.mesh_id }),
    );
    (
        Response::MeshCreated {
            mesh: invite.mesh_id,
        },
        bringup.map(PostAction::Bringup),
    )
}

/// **RISK 🟡 MED** — install a mesh from a QUICK (bearer) invite (docs/JOIN_MODES.md): no pending
/// identity, no sealed secret. We generate a fresh key, self-issue a cert authorized by the invite's
/// signed [`Grant`], adopt the RAW secret, and bring up the data plane. `wanted_name` is the joiner's
/// chosen name (`None` ⇒ `node-<id>`).
fn join_quick(
    st: &mut State,
    blob: lattice_mesh::ipc::QuickInviteBlob,
    wanted_name: Option<String>,
) -> (Response, Option<PostAction>) {
    if st.meshes.contains_key(&blob.mesh_id) {
        return (err(&format!("already in mesh {}", blob.mesh_id)), None);
    }
    let master = blob.charter.master_pubkey;
    // Validate the grant: right network, valid signature, not expired, and its issuer is the master
    // or a verified member of the roster carried in the blob.
    if blob.grant.network != master || !blob.grant.sig_ok() {
        return (err("quick invite: grant is invalid"), None);
    }
    if now_ms() >= blob.grant.expires_at {
        return (err("quick invite has expired — ask for a fresh code"), None);
    }
    let roster = valid_members(&master, &blob.certs, blob.charter.invite);
    let issuer_ok =
        blob.grant.issuer == master || roster.iter().any(|c| c.member == blob.grant.issuer);
    if !issuer_ok {
        return (
            err("quick invite: grant issuer is not an authorized member"),
            None,
        );
    }
    // Pick the lowest free member id we can see (races on a reusable code converge later, §6).
    let mut used: HashSet<MemberId> = blob.certs.iter().map(|c| c.id).collect();
    used.extend(blob.grant_certs.iter().map(|q| q.id));
    let id = match (1u8..=254).find(|i| !used.contains(i)) {
        Some(i) => i,
        None => return (err("mesh is full (no free member id)"), None),
    };
    let name = wanted_name.unwrap_or_else(|| format!("node-{id}"));
    // Generate our own identity (no NewIdentity ceremony) and self-register as a separate GrantCert
    // (kept OUT of `certs` so the classic roster wire format is untouched — docs/JOIN_MODES.md).
    let my_key = MemberKey::generate();
    let my_enc = EncKey::generate();
    let my_qcert = my_key.grant_cert(blob.grant.clone(), id, &name, now_ms());
    let certs = blob.certs.clone();
    let mut grant_certs = blob.grant_certs.clone();
    grant_certs.push(my_qcert);
    // Confirm our self-registration validates under the grant.
    let cert_valid = valid_members(&master, &certs, blob.charter.invite);
    let ok = lattice_mesh::membership::grant_members(
        &master,
        &cert_valid,
        &grant_certs,
        blob.charter.invite,
    )
    .iter()
    .any(|q| q.member == my_key.pubkey());
    if !ok {
        return (
            err("quick invite: our self-registration does not validate under the grant"),
            None,
        );
    }
    let secret = blob.secret; // RAW bearer secret
    let cipher = if blob.cipher.is_empty() {
        blob.charter.initial_cipher.clone()
    } else {
        blob.cipher.clone()
    };
    let epoch = blob.epoch;
    let mut seed: HashMap<MemberId, SocketAddr> = HashMap::new();
    for (m, ep) in &blob.endpoints {
        if *m == id {
            continue;
        }
        if let Ok(addr) = ep.parse() {
            seed.insert(*m, addr);
        }
    }
    let mut mesh = Mesh::new(
        blob.mesh_id,
        blob.mesh_name.clone(),
        blob.charter.clone(),
        id,
    );
    mesh.epoch = epoch;
    let (ms, bringup) = NewMesh {
        mesh,
        master: None,
        my_key,
        my_enc,
        certs,
        revocations: Vec::new(),
        grant_certs,
        secret,
        cipher,
        epoch,
        exit: None,
        exitable: false,
        seed,
        flows: lattice_proto::flow::default_table(),
        flow_version: 0,
    }
    .build();
    let bringup = st.data_plane.then_some(bringup);
    st.meshes.insert(blob.mesh_id, ms);
    emit(
        st,
        "peer",
        Some(blob.mesh_id),
        serde_json::json!({ "kind": "mesh_added", "mesh": blob.mesh_id }),
    );
    (
        Response::MeshCreated { mesh: blob.mesh_id },
        bringup.map(PostAction::Bringup),
    )
}

/// **RISK 🟡 MED** — genesis a brand-new mesh (master keypair, charter, self as first member) and
/// persist it; returns a `Bringup` PostAction. Mesh-lifecycle correctness.
fn create_mesh(
    st: &mut State,
    name: String,
    my_name: String,
    max_members: u8,
    cipher: Option<String>,
    self_destruct: Option<bool>,
    master_gated: Option<bool>,
    expel: Option<String>,
    header: Option<String>,
    exit_policy: Option<String>,
    join: Option<String>,
) -> (Response, Option<PostAction>) {
    // Lowest-strength join method this mesh accepts (docs/JOIN_MODES.md §7): `secure` locks out
    // quick (bearer) invites; anything else (default) allows the inviter to choose per invite.
    let join_floor = match join.as_deref() {
        Some("secure") | Some("secure-only") | Some("secureonly") => {
            lattice_mesh::charter::JoinFloor::SecureOnly
        }
        _ => lattice_mesh::charter::JoinFloor::Any,
    };
    // The mesh id is the real key, but a human picks a mesh by NAME and the GUI lists
    // meshes by name — so two same-named meshes render as indistinguishable "peer" rows
    // and any name-based lookup becomes ambiguous. Keep names non-empty + unique on this
    // computer at creation. (JoinMesh is a separate path: joining someone else's mesh that
    // happens to share a name is still allowed; the UI disambiguates those by #id.)
    let want = name.trim();
    if want.is_empty() {
        return (err("mesh name cannot be empty"), None);
    }
    if let Some((eid, _)) = st
        .meshes
        .iter()
        .find(|(_, m)| m.mesh.name.trim().eq_ignore_ascii_case(want))
    {
        return (
            err(&format!(
                "a mesh named \"{want}\" already exists on this computer (#{eid}) — pick another name"
            )),
            None,
        );
    }
    let id = match (1u8..=255).find(|id| !st.meshes.contains_key(id)) {
        Some(id) => id,
        None => return (err("too many meshes on this computer (max 255)"), None),
    };
    // The data-plane cipher is fixed at creation (P-C1, the GUI dropbox). Validate
    // the chosen name against the registry; default if unspecified.
    let cipher = cipher.unwrap_or_else(|| lattice_mesh::crypto::DEFAULT_CIPHER.to_string());
    if !lattice_mesh::crypto::is_known_cipher(&cipher) {
        return (
            err(&format!(
                "unknown cipher '{cipher}'; one of {:?}",
                lattice_mesh::crypto::available_ciphers()
            )),
            None,
        );
    }
    // Expulsion (membership-revocation) policy — chosen at genesis, fixed for life.
    let expel = match parse_expel(expel.as_deref()) {
        Ok(p) => p,
        Err(e) => return (err(&e), None),
    };
    // Header-placement (P-C5) policy — where the sealed header sits; default random.
    let header_placement = match parse_header_placement(header.as_deref()) {
        Ok(p) => p,
        Err(e) => return (err(&e), None),
    };
    // Exit egress policy (docs/EXIT_POLICY.md) — isolate (default) vs chain.
    let exit_policy = match parse_exit_policy(exit_policy.as_deref()) {
        Ok(p) => p,
        Err(e) => return (err(&e), None),
    };
    let master = MasterKey::generate();
    let my_key = MemberKey::generate();
    let charter = GenesisCharter {
        master_pubkey: master.network(),
        invite: if master_gated == Some(true) {
            InviteTopology::MasterGated
        } else {
            InviteTopology::OpenChain
        },
        trigger: RecipherTrigger::Quorum { k: 2 },
        max_members,
        initial_cipher: cipher,
        overlay_prefix: [100, 80],
        self_destruct: if self_destruct == Some(true) {
            lattice_mesh::charter::SelfDestruct::OnIsolation
        } else {
            lattice_mesh::charter::SelfDestruct::Off
        },
        expel,
        header_placement,
        exit_policy,
        join_floor, // docs/JOIN_MODES.md §7 (plumbed from CreateMesh in phase 4)
    };
    if let Err(e) = charter.validate() {
        return (err(&e.to_string()), None);
    }
    // The creator is member #1, with a master-signed cert.
    let cert = master.issue(my_key.pubkey(), 1, &my_name, now_ms());
    let my_enc = EncKey::generate();
    let cipher = charter.initial_cipher.clone();
    let secret: [u8; 32] = rand::random();
    let mesh = Mesh::new(id, name, charter, 1);
    // If data-plane mode is on, ask the async caller to bring up this mesh's loop
    // (sharing the same links/exit handles NewMesh::build wires into both halves).
    let (ms, bringup) = NewMesh {
        mesh,
        master: Some(master),
        my_key,
        my_enc,
        certs: vec![cert],
        revocations: Vec::new(),
        grant_certs: Vec::new(),
        secret,
        cipher,
        epoch: 0,
        exit: None,
        exitable: false,
        seed: HashMap::new(),
        flows: lattice_proto::flow::default_table(),
        flow_version: 0,
    }
    .build();
    let bringup = st.data_plane.then_some(bringup);
    st.meshes.insert(id, ms);
    emit(
        st,
        "peer",
        Some(id),
        serde_json::json!({ "kind": "mesh_added", "mesh": id }),
    );
    (
        Response::MeshCreated { mesh: id },
        bringup.map(PostAction::Bringup),
    )
}

/// Expel (revoke) a member under the mesh's `ExpelPolicy`. Builds or co-signs a signed
/// revocation, records it locally (so `roster()` drops the member once it is authorized),
/// and gossips it. Returns an info message noting whether it took effect now or needs more
/// quorum co-signers. Re-cipher only denies keys; THIS is what removes a member.
fn expel_member(st: &mut State, mesh: MeshId, member: MemberId) -> (Response, Option<PostAction>) {
    let Some(ms) = st.meshes.get_mut(&mesh) else {
        return (no_mesh(mesh), None);
    };
    let net = ms.mesh.charter.master_pubkey;
    let policy = ms.mesh.charter.expel;
    if policy == ExpelPolicy::None {
        return (
            err("this mesh does not allow expulsion (expel policy = none, fixed at creation)"),
            None,
        );
    }
    // Resolve the target's pubkey + inviter from the current roster.
    let Some(target) = ms.roster().into_iter().find(|c| c.id == member) else {
        return (err(&format!("no member #{member} in this mesh")), None);
    };
    let (target_pk, target_inviter, target_name) = (target.member, target.inviter, target.name);
    if target_pk == ms.my_key.pubkey() {
        return (
            err("can't expel yourself — use Remove/wipe to leave the mesh"),
            None,
        );
    }
    let now = now_ms();
    let am_master = ms.master.is_some();
    let my_pub = ms.my_key.pubkey();
    // Produce this node's signature iff it is authorized to contribute one.
    let sig = match policy {
        ExpelPolicy::None => unreachable!(),
        ExpelPolicy::CreatorOnly => {
            if !am_master {
                return (
                    err("only the mesh creator may expel here (policy = creator-only)"),
                    None,
                );
            }
            ms.master.as_ref().unwrap().revoke_sig(&target_pk)
        }
        ExpelPolicy::InviterChain => {
            if am_master {
                ms.master.as_ref().unwrap().revoke_sig(&target_pk)
            } else if my_pub == target_inviter {
                ms.my_key.revoke_sig(&net, &target_pk)
            } else {
                return (
                    err(&format!(
                        "only the master or the member who invited '{target_name}' may expel it (policy = inviter-chain)"
                    )),
                    None,
                );
            }
        }
        // Any member contributes one co-signature; effective at k (policy = quorum).
        ExpelPolicy::Quorum { .. } => ms.my_key.revoke_sig(&net, &target_pk),
    };
    // Fold into an existing revocation for this member (reuse its issued_at so co-signers
    // accumulate over gossip), else start a new one.
    match ms.revocations.iter_mut().find(|r| r.member == target_pk) {
        Some(existing) => {
            if !existing.signers.iter().any(|s| s.signer == sig.signer) {
                existing.signers.push(sig);
            }
        }
        None => ms
            .revocations
            .push(Revocation::new(net, target_pk, now, sig)),
    }
    // Gossip the updated revocation set now (it is also re-gossiped periodically).
    if let Some(tx) = ms.loop_cmd.clone() {
        let peers: Vec<MemberId> = ms.links.lock().unwrap().keys().copied().collect();
        if !peers.is_empty() {
            if let Ok(body) = bincode::serialize(&ms.revocations) {
                let _ = tx.send(LoopCmd::SendControl(CTRL_REVOKE, body, peers));
            }
        }
    }
    let gone = !ms.roster().iter().any(|c| c.member == target_pk);
    let message = if gone {
        format!("expelled '{target_name}' (#{member}) — removed from the roster.")
    } else if let ExpelPolicy::Quorum { k } = policy {
        let have = ms
            .revocations
            .iter()
            .find(|r| r.member == target_pk)
            .map(|r| r.valid_signers().len())
            .unwrap_or(0);
        format!("expel of '{target_name}' proposed — {have}/{k} co-signers; each other member runs the same `expel` to reach {k}.")
    } else {
        format!("expel of '{target_name}' recorded.")
    };
    elog!("meshd: {message}");
    (Response::Info { message }, None)
}

// ---- extensions / connectors (docs/EXTENSIONS.md) ----------------------------------

#[cfg(test)]
mod tests {
    use super::{
        dns_split, load_default_mesh, load_egress, load_extensions, load_split, load_split_active,
        persist_default_mesh, persist_egress, persist_extensions, persist_split,
        persist_split_active, quorum_threshold, request_mutates, ExtensionGrant, SplitActive,
        State,
    };

    /// Fresh scratch dir per test (parallel-safe: tag + pid).
    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("lattice-{tag}-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn quorum_threshold_is_ceil_60pct() {
        // ⌈0.6·n⌉ — the re-cipher quorum + self-destruct floor.
        assert_eq!(quorum_threshold(1), 1);
        assert_eq!(quorum_threshold(2), 2);
        assert_eq!(quorum_threshold(3), 2); // ceil(1.8)
        assert_eq!(quorum_threshold(4), 3); // ceil(2.4)
        assert_eq!(quorum_threshold(5), 3); // ceil(3.0)
        assert_eq!(quorum_threshold(10), 6);
    }

    // The "keeps falling back to Default network" fix: a FULL-tunnel egress must survive a restart,
    // a split selection must NOT be mistaken for one, and going to the default network forgets it.
    #[test]
    fn egress_persists_only_for_full_tunnel_and_survives_reload() {
        let dir = std::env::temp_dir().join(format!("lattice-egress-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut st = State::default();
        st.persist_dir = Some(dir.clone());

        // No egress yet → file absent.
        persist_egress(&st);
        assert_eq!(load_egress(&dir), None);

        // Split selection (current set, full_tunnel = false) must NOT persist as full-tunnel egress.
        st.current = Some(7);
        st.full_tunnel = false;
        persist_egress(&st);
        assert_eq!(
            load_egress(&dir),
            None,
            "split selection must not be a sticky egress"
        );

        // Full tunnel → remembered across a (simulated) restart.
        st.full_tunnel = true;
        persist_egress(&st);
        assert_eq!(
            load_egress(&dir),
            Some(7),
            "full-tunnel egress should survive restart"
        );

        // Default network (SetCurrent None) → forgotten.
        st.current = None;
        st.full_tunnel = false;
        persist_egress(&st);
        assert_eq!(
            load_egress(&dir),
            None,
            "default network clears the persisted egress"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // `request_mutates` must list every request that changes persistent mesh state — a missed
    // variant means the change is silently lost on the next restart (AdmitMember was exactly
    // that: the cert was pushed into `ms.certs` but never saved). When adding a Request
    // variant, decide here whether it belongs in the table. (SetDefaultMesh / SetFlows /
    // SplitOn / SplitOff persist inline via their own files, so they are deliberately absent.)
    #[test]
    fn request_mutates_lists_every_persisting_request() {
        use lattice_mesh::ipc::{Request, WrappedInvite};
        let mutating = [
            Request::CreateMesh {
                name: "m".into(),
                my_name: "a".into(),
                max_members: 8,
                cipher: None,
                self_destruct: None,
                master_gated: None,
                expel: None,
                header: None,
                exit_policy: None,
                join: None,
            },
            Request::JoinMesh {
                invite: WrappedInvite {
                    salt: [0; 32],
                    n: 0,
                    ct: Vec::new(),
                },
                algo: None,
                name: None,
            },
            Request::CreateInvite {
                mesh: 1,
                name: "a".into(),
                member_pubkey_hex: String::new(),
                enc_pubkey_hex: String::new(),
                issued_at: 0,
                algo: None,
            },
            Request::AdmitMember {
                mesh: 1,
                name: "a".into(),
                pubkey_hex: String::new(),
            },
            Request::SetExit {
                mesh: 1,
                exit: None,
            },
            Request::SetPeer {
                mesh: 1,
                member: 2,
                endpoint: "127.0.0.1:1".into(),
            },
            Request::SetCurrent { mesh: None },
            Request::RemoveMesh { mesh: 1 },
            Request::Recipher {
                mesh: 1,
                cipher: None,
            },
            Request::AllClear { mesh: 1 },
            Request::ExpelMember { mesh: 1, member: 2 },
            Request::EnableExtension {
                id: "x".into(),
                scopes: Vec::new(),
                all_meshes: false,
                meshes: Vec::new(),
            },
            Request::DisableExtension { id: "x".into() },
            Request::SplitAdd {
                domain: "d".into(),
                mesh: 1,
                exit: 0,
            },
            Request::SplitDel { domain: "d".into() },
            Request::SetExitable {
                mesh: 1,
                enabled: true,
            },
        ];
        for r in &mutating {
            assert!(request_mutates(r), "must persist after {r:?}");
        }
        let read_only = [
            Request::ListMeshes,
            Request::MeshInfo { mesh: 1 },
            Request::Ciphers,
            Request::TrafficStats { mesh: None },
            Request::GetPolicy,
            Request::GetFlows { mesh: 1 },
            Request::SplitList,
            Request::ListExtensions,
            Request::NewIdentity,
            Request::InviteAlgorithms,
            // A quick invite only MINTS a grant (it travels inside the blob); local state
            // doesn't change until a joiner self-registers (which arrives via JoinMesh/gossip).
            Request::CreateQuickInvite {
                mesh: 1,
                name: None,
                max_uses: 1,
                ttl_secs: 60,
                algo: None,
            },
        ];
        for r in &read_only {
            assert!(!request_mutates(r), "must not trigger a persist: {r:?}");
        }
    }

    // Lock the on-disk format of split.json before any persistence refactor touches it.
    #[test]
    fn split_rules_roundtrip() {
        let dir = tmpdir("split");
        let st = State {
            persist_dir: Some(dir.clone()),
            split_rules: vec![dns_split::SplitRule {
                domain: "example.com".into(),
                mesh: 3,
                exit: 7,
            }],
            ..Default::default()
        };
        persist_split(&st);
        let loaded = load_split(&dir);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].domain, "example.com");
        assert_eq!(loaded[0].mesh, 3);
        assert_eq!(loaded[0].exit, 7);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // split-active.json: on → survives reload; off → the marker file is removed.
    #[tokio::test]
    async fn split_active_roundtrips_and_off_removes_marker() {
        let dir = tmpdir("split-active");
        let mut st = State {
            persist_dir: Some(dir.clone()),
            ..Default::default()
        };
        persist_split_active(&st);
        assert_eq!(load_split_active(&dir), None);
        st.split = Some(SplitActive {
            mesh: 5,
            task: tokio::spawn(async {}),
            injected: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        });
        persist_split_active(&st);
        assert_eq!(load_split_active(&dir), Some(5));
        if let Some(s) = st.split.take() {
            s.task.abort();
        }
        persist_split_active(&st);
        assert_eq!(
            load_split_active(&dir),
            None,
            "split off removes the marker"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // default-mesh.json: round-trip, clear, and the 0600 perms its sibling files already had.
    #[test]
    fn default_mesh_roundtrips_clears_and_is_private() {
        let dir = tmpdir("default-mesh");
        let mut st = State {
            persist_dir: Some(dir.clone()),
            default_mesh: Some(9),
            ..Default::default()
        };
        persist_default_mesh(&st);
        assert_eq!(load_default_mesh(&dir), Some(9));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("default-mesh.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "default-mesh.json must be 0600 like its sibling state files"
            );
        }
        st.default_mesh = None;
        persist_default_mesh(&st);
        assert_eq!(load_default_mesh(&dir), None, "clearing removes the file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // extensions.json: a grant (incl. per-mesh scoping fields) survives a reload intact.
    #[test]
    fn extension_grants_roundtrip() {
        let dir = tmpdir("extensions");
        let mut st = State {
            persist_dir: Some(dir.clone()),
            ..Default::default()
        };
        st.extensions.insert(
            "minisync".into(),
            ExtensionGrant {
                id: "minisync".into(),
                token: "tok".into(),
                scopes: vec!["events:peer".into()],
                enabled: true,
                all_meshes: false,
                meshes: vec![2, 4],
            },
        );
        persist_extensions(&st);
        let loaded = load_extensions(&dir);
        let g = loaded.get("minisync").expect("grant survives reload");
        assert_eq!(g.token, "tok");
        assert_eq!(g.scopes, vec!["events:peer".to_string()]);
        assert!(g.enabled);
        assert!(!g.all_meshes);
        assert_eq!(g.meshes, vec![2, 4]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
