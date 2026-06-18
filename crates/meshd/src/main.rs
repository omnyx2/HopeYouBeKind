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

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use lattice_mesh::charter::{GenesisCharter, InviteTopology, RecipherTrigger};
use lattice_mesh::crypto::suite;
use lattice_mesh::dataplane::MeshDataPlane;
use lattice_mesh::ipc::{
    InviteBlob, MemberView, MeshDetail, MeshSummary, PolicyView, Request, Response,
};
use lattice_mesh::keydist::{seal_secret, EncKey};
use lattice_mesh::membership::{valid_members, Cert, MasterKey, MemberKey, PubKey};
use lattice_mesh::Mesh;
use lattice_meshrun::{
    seed_links, DecryptFailStat, DecryptFails, Link, LoopCmd, LoopEvent, PeerLinks, Recipher,
    SharedEndpoint, SharedExit, CTRL_ALLCLEAR, CTRL_ATTACK, CTRL_ROSTER,
};
use lattice_net::udp::UdpTransport;
use lattice_proto::wire_v2::{MemberId, MeshId};
use lattice_proto::VirtualIp;
use lattice_tun::{open as tun_open, TunConfig};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc::UnboundedSender;

mod dht;
#[allow(dead_code)] // ported from v1: some restore/disable paths aren't wired yet.
mod exit; // OS plumbing for full-tunnel egress (client routes + exit NAT), from v1. // node-wide DHT rendezvous (re-find a moved peer by pubkey) — docs/DHT_RENDEZVOUS.md.

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
/// Overlay MTU for meshd-run data planes (matches meshrun's conservative default).
const OVERLAY_MTU: u16 = 1280;
/// Live-paired self-destruct (P-C4): how often to check liveness, and how long the
/// mesh may sit below the live threshold before it wipes itself.
const SELF_DESTRUCT_TICK_SECS: u64 = 15;
const SELF_DESTRUCT_GRACE_SECS: u64 = 180;
/// Attack-response grace (P-C7): after an attack alert, how long the creator has to
/// send an all-clear before every member self-destructs (one-veto, fail-deadly).
const ATTACK_GRACE_SECS: u64 = 30;

/// ⌈0.6·n⌉ — the shared threshold: the re-cipher quorum (§5-4) and the live-paired
/// self-destruct floor (§5-2). Below this many live members the mesh secret is (by
/// the threshold-sharing model) unrecoverable, so the mesh self-destructs.
fn quorum_threshold(n: usize) -> usize {
    (3 * n + 4) / 5
}

/// Append a diagnostic line to a `lattice-meshd.log`. On Windows the GUI runs meshd
/// elevated + hidden with no console (RunAs can't redirect output), so this file is the
/// only window into what happened. Best-effort, written to EVERY candidate that opens —
/// under RunAs the elevating account's `%TEMP%` may not exist, but `C:\Windows\Temp`
/// always does — so the log is findable regardless of which account elevated.
fn diag_log(msg: &str) {
    use std::io::Write;
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

/// One mesh plus the real trust state for it.
struct MeshState {
    mesh: Mesh,
    /// The mesh's root of trust. `Some` only on the creator (it holds the master
    /// key and can issue invites); a joiner installs the mesh with `None`.
    master: Option<MasterKey>,
    /// This node's own member keypair in this mesh.
    my_key: MemberKey,
    /// This node's encryption key in this mesh (receives sealed secrets — rekeys).
    #[allow(dead_code)]
    my_enc: EncKey,
    /// Every known cert. The roster = those that validly chain to the master.
    certs: Vec<Cert>,
    /// The mesh's shared symmetric secret (epoch 0) — keys the data-plane cipher.
    /// Held for rekey / re-bringup / sealing to joiners (keydist).
    secret: [u8; 32],
    /// Live peer table, shared with this mesh's data-plane loop (endpoints +
    /// last-seen). Empty until peers are seeded (SetPeer) or heard from.
    links: PeerLinks,
    /// The egress member, shared with the loop so SetExit steers it live.
    exit_sel: SharedExit,
    /// The OS interface name of this mesh's TUN (set at bringup) — needed to divert
    /// the default route for full-tunnel egress.
    tun_name: Option<String>,
    /// This node's own advertised data-plane endpoint (`ip:port`), shared with the
    /// run loop. Set at bringup; the loop upgrades it to our public address when a
    /// public peer reflects it (P-D3). Read by CreateInvite to hand joiners (P-D1).
    my_endpoint: SharedEndpoint,
    /// This mesh's local data-plane UDP port (set at bringup; 0 = not up). Advertised
    /// in the LAN beacon so same-router peers reach us directly (P-D4).
    dp_port: u16,
    /// Non-fatal data-plane bring-up error (e.g. the UDP port is held by another
    /// process), surfaced in `MeshInfo` so the GUI can show "data plane DOWN" instead
    /// of a mesh that looks joined but silently can't send or receive. `None` = healthy.
    dp_error: Option<String>,
    /// Abort handle for this mesh's data-plane loop (set at bringup). `RemoveMesh`
    /// aborts it so the loop's future is dropped, freeing its TUN + UDP socket —
    /// otherwise the port leaks and a re-created mesh can't bind it.
    dp_task: Option<tokio::task::AbortHandle>,
    /// The mesh's **current** data-plane cipher + epoch (P-C3). Start from the
    /// charter; a re-cipher rotates `secret`, bumps `epoch`, and may change `cipher`.
    cipher: String,
    epoch: u64,
    /// Sender into this mesh's data-plane loop (re-cipher trigger / attack signals,
    /// set at bringup).
    loop_cmd: Option<UnboundedSender<LoopCmd>>,
    /// When an attack alert armed the destroy grace (P-C7); `None` = not armed. Set on
    /// `ReportAttack` / a received alert, cleared by the creator's all-clear; the
    /// self-destruct watchdog wipes the mesh once the grace elapses.
    attack_armed_at: Option<u64>,
    /// Frames that arrived on this mesh's socket but failed to decrypt, keyed by source
    /// IP — shared with the data-plane loop. A nonzero count from a known peer's
    /// endpoint IP is the "peer is on a different mesh/epoch" signal, surfaced as a
    /// health warning + per-member reason in `MeshInfo` instead of a silent drop.
    decrypt_fails: DecryptFails,
}

impl MeshState {
    fn topology(&self) -> InviteTopology {
        self.mesh.charter.invite
    }
    /// The validated roster (certs chaining to the master), id-sorted.
    fn roster(&self) -> Vec<Cert> {
        let mut v: Vec<Cert> = valid_members(
            &self.mesh.charter.master_pubkey,
            &self.certs,
            self.topology(),
        )
        .into_iter()
        .cloned()
        .collect();
        v.sort_by_key(|c| c.id);
        v
    }
    /// This node's in-mesh id (from its own cert).
    fn my_id(&self) -> MemberId {
        let me = self.my_key.pubkey();
        self.certs
            .iter()
            .find(|c| c.member == me)
            .map(|c| c.id)
            .unwrap_or(0)
    }
}

#[derive(Default)]
struct State {
    meshes: HashMap<MeshId, MeshState>,
    /// The mesh currently selected for egress (the §1 cur-mesh).
    current: Option<MeshId>,
    /// Whether to spawn data-plane loops (`DATA_PLANE=1`).
    data_plane: bool,
    /// Freshly minted identities (member + enc keypair) awaiting an invite, keyed
    /// by member public key. Drained when `JoinMesh` consumes one.
    pending: HashMap<PubKey, (MemberKey, EncKey)>,
    /// Where meshes are persisted (P-S1); `None` = persistence off. Saved on every
    /// state change, pruned on self-destruct/remove, reloaded at startup so a reboot
    /// (or a network change) doesn't drop the node from its meshes.
    persist_dir: Option<PathBuf>,
    /// Node-wide DHT rendezvous (`MESHD_DHT=1`); `None` = off. Re-finds a peer whose
    /// address changed with no overlapping live window — docs/DHT_RENDEZVOUS.md.
    dht: Option<Arc<dht::DhtService>>,
}

/// Work the IPC handler defers to the async caller (it can't `.await` or spawn
/// under the state lock): data-plane bringup, or arming the full-tunnel watchdog.
enum PostAction {
    Bringup(Bringup),
    /// Full tunnel just went up for this mesh — start the kill-switch.
    ArmKillSwitch(MeshId),
}

/// Everything `bringup_dataplane` needs to spawn a mesh's live loop — built inside
/// the locked handler, executed (async TUN/UDP open) after the lock is released.
struct Bringup {
    mesh_id: MeshId,
    my_id: MemberId,
    prefix: [u8; 2],
    secret: [u8; 32],
    cipher: String,
    epoch: u64,
    links: PeerLinks,
    exit_sel: SharedExit,
    my_endpoint: SharedEndpoint,
    decrypt_fails: DecryptFails,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---- P-S1 persistence: survive reboots / network changes ---------------------
// v1 stores keys/secret in plaintext JSON with 0600 perms. NOTE: this trades the
// RAM-only ephemerality for reboot-survival; a self-destruct / RemoveMesh deletes the
// file too, so the ephemeral property still holds for those. At-rest encryption is a
// follow-on (P-S1b).

/// The on-disk form of one mesh.
#[derive(Serialize, Deserialize)]
struct PersistedMesh {
    mesh_id: MeshId,
    mesh_name: String,
    charter: GenesisCharter,
    certs: Vec<Cert>,
    secret: [u8; 32],
    epoch: u64,
    cipher: String,
    member_seed: [u8; 32],
    enc_bytes: [u8; 32],
    master_seed: Option<[u8; 32]>,
    exit: Option<MemberId>,
    /// Last-known peer endpoints — re-seeded on load so reconnect is fast (discovery
    /// then re-learns the rest, e.g. after a network change).
    peers: Vec<(MemberId, String)>,
}

/// Where to persist (env `MESHD_STATE_DIR`, else `$HOME/.lattice/meshd`), or `None`
/// if `MESHD_NO_PERSIST` is set or no home is found. Creates the dir (0700).
fn persist_dir() -> Option<PathBuf> {
    if std::env::var("MESHD_NO_PERSIST").is_ok() {
        return None;
    }
    let dir = std::env::var("MESHD_STATE_DIR")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".lattice/meshd"))
        })?;
    std::fs::create_dir_all(&dir).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Some(dir)
}

fn mesh_file(dir: &std::path::Path, id: MeshId) -> PathBuf {
    dir.join(format!("mesh-{id}.json"))
}

/// Snapshot one live mesh into its serializable persisted form. Shared by on-disk
/// persistence and the `ExportState` update-migration backup.
fn to_persisted(ms: &MeshState) -> PersistedMesh {
    PersistedMesh {
        mesh_id: ms.mesh.id,
        mesh_name: ms.mesh.name.clone(),
        charter: ms.mesh.charter.clone(),
        certs: ms.certs.clone(),
        secret: ms.secret,
        epoch: ms.epoch,
        cipher: ms.cipher.clone(),
        member_seed: ms.my_key.to_seed(),
        enc_bytes: ms.my_enc.to_bytes(),
        master_seed: ms.master.as_ref().map(|m| m.to_seed()),
        exit: *ms.exit_sel.lock().unwrap(),
        peers: ms
            .links
            .lock()
            .unwrap()
            .iter()
            .map(|(m, l)| (*m, l.endpoint.to_string()))
            .collect(),
    }
}

/// Where the update-migration backup lives: env `MESHD_IMPORT`, else
/// `<tempdir>/lattice-mesh-backup.json`. `ExportState` writes it before an update and
/// startup reads (then deletes) it, so a reinstall never drops a node from its meshes
/// even if the persist dir is wiped.
fn migration_backup_path() -> PathBuf {
    std::env::var("MESHD_IMPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("lattice-mesh-backup.json"))
}

/// Read the update-migration backup (a JSON array of meshes) if present.
fn load_backup(path: &std::path::Path) -> Vec<PersistedMesh> {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Vec<PersistedMesh>>(&b).ok())
        .unwrap_or_default()
}

/// Save all current meshes and prune files for meshes that are gone (so a
/// self-destruct / RemoveMesh erases the on-disk copy too).
fn persist(st: &State) {
    let Some(dir) = &st.persist_dir else { return };
    for ms in st.meshes.values() {
        let p = to_persisted(ms);
        if let Ok(json) = serde_json::to_vec_pretty(&p) {
            let f = mesh_file(dir, ms.mesh.id);
            if std::fs::write(&f, &json).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600));
                }
            }
        }
    }
    // Prune meshes no longer present.
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if let Some(idstr) = name
                .strip_prefix("mesh-")
                .and_then(|s| s.strip_suffix(".json"))
            {
                if let Ok(id) = idstr.parse::<MeshId>() {
                    if !st.meshes.contains_key(&id) {
                        let _ = std::fs::remove_file(e.path());
                    }
                }
            }
        }
    }
}

/// Load persisted meshes from disk (startup).
fn load_persisted(dir: &std::path::Path) -> Vec<PersistedMesh> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with("mesh-") {
                if let Ok(bytes) = std::fs::read(e.path()) {
                    if let Ok(p) = serde_json::from_slice::<PersistedMesh>(&bytes) {
                        out.push(p);
                    }
                }
            }
        }
    }
    out.sort_by_key(|p| p.mesh_id);
    out
}

/// Rebuild a `MeshState` (+ a `Bringup`) from its persisted form (startup).
fn restore_mesh(p: PersistedMesh) -> (MeshState, Bringup) {
    let my_key = MemberKey::from_seed(&p.member_seed);
    let my_enc = EncKey::from_bytes(&p.enc_bytes);
    let master = p.master_seed.map(|s| MasterKey::from_seed(&s));
    let my_pub = my_key.pubkey();
    let my_id = p
        .certs
        .iter()
        .find(|c| c.member == my_pub)
        .map(|c| c.id)
        .unwrap_or(0);
    let prefix = p.charter.overlay_prefix;
    let mut mesh = Mesh::new(p.mesh_id, p.mesh_name.clone(), p.charter, my_id);
    mesh.epoch = p.epoch;
    mesh.exit = p.exit;
    let mut seed: HashMap<MemberId, SocketAddr> = HashMap::new();
    for (m, ep) in &p.peers {
        if let Ok(a) = ep.parse() {
            seed.insert(*m, a);
        }
    }
    let links = seed_links(seed);
    let exit_sel: SharedExit = Arc::new(Mutex::new(p.exit));
    let my_endpoint: SharedEndpoint = Arc::new(Mutex::new(None));
    let decrypt_fails: DecryptFails = Arc::new(Mutex::new(HashMap::new()));
    let bringup = Bringup {
        mesh_id: p.mesh_id,
        my_id,
        prefix,
        secret: p.secret,
        cipher: p.cipher.clone(),
        epoch: p.epoch,
        links: Arc::clone(&links),
        exit_sel: Arc::clone(&exit_sel),
        my_endpoint: Arc::clone(&my_endpoint),
        decrypt_fails: Arc::clone(&decrypt_fails),
    };
    let ms = MeshState {
        mesh,
        master,
        my_key,
        my_enc,
        certs: p.certs,
        secret: p.secret,
        links,
        exit_sel,
        tun_name: None,
        my_endpoint,
        dp_port: 0,
        dp_error: None,
        dp_task: None,
        cipher: p.cipher,
        epoch: p.epoch,
        loop_cmd: None,
        attack_armed_at: None,
        decrypt_fails,
    };
    (ms, bringup)
}

/// Whether a request mutates persistent mesh state (⇒ re-save afterward).
fn request_mutates(req: &Request) -> bool {
    matches!(
        req,
        Request::CreateMesh { .. }
            | Request::JoinMesh { .. }
            | Request::CreateInvite { .. }
            | Request::SetExit { .. }
            | Request::SetPeer { .. }
            | Request::SetCurrent { .. }
            | Request::RemoveMesh { .. }
            | Request::Recipher { .. }
            | Request::AllClear { .. }
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // First line in the log: proves meshd actually launched (vs the GUI's launcher
    // failing before this point), and records the args we got.
    let argv: Vec<String> = std::env::args().collect();
    elog!(
        "meshd: started pid={} args={:?}",
        std::process::id(),
        &argv[1..]
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
    let pdir = persist_dir();
    {
        let mut st = state.lock().unwrap();
        st.data_plane = data_plane;
        st.persist_dir.clone_from(&pdir);
    }
    elog!(
        "meshd: data-plane mode {}",
        if data_plane {
            "ON (per-mesh TUN+UDP loops; needs root)"
        } else {
            "off"
        }
    );
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

    elog!("meshd: listening on {socket}");
    accept_loop(&socket, state).await
}

/// Accept IPC connections forever. The transport is platform-specific (unix socket
/// vs named pipe) but the per-connection protocol ([`serve_conn`]) is shared.
#[cfg(unix)]
async fn accept_loop(socket: &str, state: Arc<Mutex<State>>) -> anyhow::Result<()> {
    // Single-instance guard. Blindly `remove_file` + re-`bind` would steal the socket
    // from a meshd that is ALREADY running — but that old instance keeps its TUNs and
    // its already-bound data-plane UDP ports, turning into a zombie that blocks the new
    // instance's data plane (`Address already in use`) while the GUI unknowingly talks
    // to whichever won the socket. So: if a live meshd answers on this path, defer to it
    // and exit cleanly instead of orphaning it.
    if std::os::unix::net::UnixStream::connect(socket).is_ok() {
        elog!("meshd: another meshd already owns {socket} — deferring to it, exiting (no second instance)");
        return Ok(());
    }
    // No live owner: a leftover socket file is stale — safe to remove and take over.
    let _ = std::fs::remove_file(socket);
    let listener = tokio::net::UnixListener::bind(socket)?;
    // meshd runs as root (for the TUN) but the desktop app connects as the logged-in
    // user, so make the socket world-rw — otherwise the GUI can't reach it.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o666));
    }
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(serve_conn(stream, Arc::clone(&state)));
    }
}

#[cfg(windows)]
async fn accept_loop(pipe: &str, state: Arc<Mutex<State>>) -> anyhow::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;
    // A POOL of concurrent pipe instances so several simultaneous GUI requests don't get
    // ERROR_PIPE_BUSY (os error 231). The EXTRA instances are best-effort: if the OS
    // won't grant more, we run with however many we got rather than exiting — exiting
    // here was fatal (meshd kept starting, hitting "listening", then dying, so the GUI
    // relaunched it in a loop).
    const POOL: usize = 8;
    let pipe = pipe.to_string();
    // The first instance claims the pipe name. If THIS fails another meshd already owns
    // the pipe, so exit (don't run two).
    let first = match ServerOptions::new()
        .first_pipe_instance(true)
        .max_instances(254)
        .create(&pipe)
    {
        Ok(s) => s,
        Err(e) => {
            elog!("meshd: cannot create pipe {pipe} (another instance already running?): {e}");
            return Err(e.into());
        }
    };
    let mut instances = 1usize;
    for _ in 1..POOL {
        match ServerOptions::new().max_instances(254).create(&pipe) {
            Ok(s) => {
                instances += 1;
                tokio::spawn(pipe_worker(s, pipe.clone(), Arc::clone(&state)));
            }
            Err(e) => {
                elog!("meshd: pipe pool stopped at {instances} instance(s): {e}");
                break;
            }
        }
    }
    elog!("meshd: pipe server ready ({instances} instance(s)) — accepting clients");
    // Run the first worker inline so accept_loop never returns while serving.
    pipe_worker(first, pipe, state).await;
    Ok(())
}

/// One pipe-pool worker: wait for a client, immediately re-arm a fresh listening
/// instance (so the pool's listener count never dips), then serve the connection.
#[cfg(windows)]
async fn pipe_worker(
    mut server: tokio::net::windows::named_pipe::NamedPipeServer,
    pipe: String,
    state: Arc<Mutex<State>>,
) {
    use tokio::net::windows::named_pipe::ServerOptions;
    loop {
        if server.connect().await.is_err() {
            match ServerOptions::new().max_instances(254).create(&pipe) {
                Ok(s) => {
                    server = s;
                    continue;
                }
                Err(_) => return,
            }
        }
        let connected = server;
        server = match ServerOptions::new().max_instances(254).create(&pipe) {
            Ok(s) => s,
            Err(_) => return,
        };
        serve_conn(connected, Arc::clone(&state)).await;
    }
}

/// One IPC connection: newline-JSON [`Request`] in, [`Response`] out, until close.
async fn serve_conn<S>(stream: S, state: Arc<Mutex<State>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (rd, mut wr) = tokio::io::split(stream);
    let mut lines = BufReader::new(rd).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(&line) {
            Ok(req) => {
                // Handle under the lock; do any async data-plane bringup AFTER
                // releasing it (TUN/UDP open is async and must not block IPC).
                let mutates = request_mutates(&req);
                let (resp, action) = {
                    let mut st = state.lock().unwrap();
                    handle(req, &mut st)
                };
                match action {
                    Some(PostAction::Bringup(b)) => bringup_dataplane(b, Arc::clone(&state)).await,
                    Some(PostAction::ArmKillSwitch(mesh)) => {
                        arm_kill_switch(mesh, Arc::clone(&state))
                    }
                    None => {}
                }
                if mutates {
                    persist(&state.lock().unwrap()); // P-S1: save after a state change
                }
                resp
            }
            Err(e) => Response::Error {
                message: format!("bad request: {e}"),
            },
        };
        let mut out = serde_json::to_string(&resp)
            .unwrap_or_else(|_| "{\"Error\":{\"message\":\"encode failed\"}}".to_string());
        out.push('\n');
        if wr.write_all(out.as_bytes()).await.is_err() {
            break;
        }
    }
}

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
    let dp = MeshDataPlane::new(
        b.mesh_id,
        b.my_id,
        b.prefix,
        suite(&b.cipher, &b.secret, b.epoch),
        &b.secret,
    );
    // Record the TUN name (needed to divert the default route for full-tunnel) and
    // make this node able to serve as an exit for others — ip_forward + NAT, which
    // is idempotent and unused unless a peer routes through us (reuses v1 exit.rs).
    let tun_name = tun.name().map(|s| s.to_string());
    {
        if let Some(ms) = state.lock().unwrap().meshes.get_mut(&b.mesh_id) {
            ms.tun_name = tun_name.clone();
            ms.dp_port = port; // local data-plane port — advertised in the LAN beacon
            ms.dp_error = None; // bound cleanly — clear any prior "port busy" error
        }
    }
    // enable_nat shells out (pfctl/sysctl on unix, several PowerShell cmdlets on
    // Windows) — synchronous + slow, so run it off the async runtime to avoid stalling
    // IPC while a mesh is brought up.
    let _ = tokio::task::spawn_blocking(exit::enable_nat).await;
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
    let (applied_tx, mut applied_rx) = tokio::sync::mpsc::unbounded_channel::<LoopEvent>();
    let task = tokio::spawn(lattice_meshrun::run(
        dp,
        tun,
        transport,
        b.links,
        b.exit_sel,
        b.my_id,
        Arc::clone(&b.my_endpoint),
        pinned,
        cmd_rx,
        applied_tx,
        b.decrypt_fails,
    ));
    // Record the loop's abort handle (RemoveMesh stops it) + the command sender.
    if let Some(ms) = state.lock().unwrap().meshes.get_mut(&b.mesh_id) {
        ms.dp_task = Some(task.abort_handle());
        ms.loop_cmd = Some(cmd_tx);
    }
    // Drain loop events: a re-cipher landing (sync secret/epoch/cipher) or a P-C7
    // attack signal (arm / cancel the destroy grace).
    let st = Arc::clone(&state);
    let mid = b.mesh_id;
    tokio::spawn(async move {
        while let Some(ev) = applied_rx.recv().await {
            let mut state = st.lock().unwrap();
            let Some(ms) = state.meshes.get_mut(&mid) else {
                continue;
            };
            let mut persist_after = false;
            match ev {
                LoopEvent::Recipher(r) => {
                    ms.secret = r.secret;
                    ms.epoch = r.epoch;
                    ms.mesh.epoch = r.epoch;
                    ms.cipher = r.cipher;
                    persist_after = true; // P-S1: the new secret must reach disk
                }
                LoopEvent::Control(CTRL_ATTACK) => {
                    if ms.attack_armed_at.is_none() {
                        elog!("meshd: mesh {mid} ATTACK ALERT received — destroy grace armed ({ATTACK_GRACE_SECS}s; creator can all-clear)");
                        ms.attack_armed_at = Some(now_ms());
                    }
                }
                LoopEvent::Control(CTRL_ALLCLEAR) => {
                    if ms.attack_armed_at.take().is_some() {
                        elog!("meshd: mesh {mid} ALL-CLEAR received — destroy grace cancelled");
                    }
                }
                LoopEvent::Control(_) => {}
                // A peer gossiped its roster — merge any new cert for THIS mesh that we
                // don't already hold; `roster()` re-validates the chain to the master, so
                // pushing is safe (an invalid cert just never counts). This is what makes
                // a member added via a third node propagate to everyone.
                LoopEvent::Roster(bytes) => {
                    if let Ok(incoming) = bincode::deserialize::<Vec<Cert>>(&bytes) {
                        let net = ms.mesh.charter.master_pubkey;
                        let before = ms.roster().len();
                        for c in incoming {
                            if c.network == net
                                && !ms
                                    .certs
                                    .iter()
                                    .any(|h| h.member == c.member && h.id == c.id)
                            {
                                ms.certs.push(c);
                            }
                        }
                        let after = ms.roster().len();
                        if after > before {
                            elog!("meshd: mesh {mid} roster grew {before} -> {after} via gossip");
                            persist_after = true;
                        }
                    }
                }
            }
            if persist_after {
                persist(&state);
            }
        }
    });
    // P-C4 live-paired self-destruct watchdog.
    spawn_self_destruct_watchdog(b.mesh_id, Arc::clone(&state));
}

/// Membership roster gossip. Every `ROSTER_GOSSIP_TICK_SECS`, send each mesh's validated
/// roster (signed certs) to its peers; the receiver merges any new, valid cert. Endpoints
/// already gossip (P-D2) but the **roster** did not — so a node admitted via one member
/// never reached the others. This closes that: membership converges like endpoints do.
/// (One UDP frame per mesh; fine for small meshes — large rosters would need chunking.)
fn spawn_roster_gossip(state: Arc<Mutex<State>>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(ROSTER_GOSSIP_TICK_SECS)).await;
            let sends: Vec<(Vec<u8>, Vec<MemberId>, UnboundedSender<LoopCmd>)> = {
                let st = state.lock().unwrap();
                st.meshes
                    .values()
                    .filter_map(|ms| {
                        let tx = ms.loop_cmd.clone()?;
                        let certs = ms.roster();
                        if certs.len() < 2 {
                            return None; // solo — nothing to propagate
                        }
                        let body = bincode::serialize(&certs).ok()?;
                        let peers: Vec<MemberId> =
                            ms.links.lock().unwrap().keys().copied().collect();
                        if peers.is_empty() {
                            return None;
                        }
                        Some((body, peers, tx))
                    })
                    .collect()
            };
            for (body, peers, tx) in sends {
                let _ = tx.send(LoopCmd::SendControl(CTRL_ROSTER, body, peers));
            }
        }
    });
}

/// DHT rendezvous reconnect loop (`MESHD_DHT=1`, docs/DHT_RENDEZVOUS.md). Every
/// `DHT_RECONNECT_TICK_SECS`: (1) **republish** our own signed endpoint record for each
/// mesh so a moved peer can re-find us, and (2) for each roster member we have **no fresh
/// endpoint** for, DHT-**look up** their record and seed the endpoint into the peer table
/// — the same seam `SetPeer`/gossip use. This is what closes the "both moved with no
/// overlap" gap that first-contact discovery (P-D1..D4) can't. All work is snapshotted
/// under the lock and the network round-trips happen lock-free.
fn spawn_dht_reconnect(state: Arc<Mutex<State>>) {
    struct Work {
        mesh: MeshId,
        network: PubKey,
        my_seed: [u8; 32],
        my_endpoint: Option<SocketAddr>,
        /// roster members with no fresh endpoint: (member id, their pubkey).
        missing: Vec<(MemberId, PubKey)>,
    }
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(DHT_RECONNECT_TICK_SECS)).await;
            let Some(dht) = state.lock().unwrap().dht.clone() else {
                continue;
            };
            let now = now_ms();
            let work: Vec<Work> = {
                let st = state.lock().unwrap();
                st.meshes
                    .values()
                    .map(|ms| {
                        let me = ms.my_id();
                        let links = ms.links.lock().unwrap();
                        let missing = ms
                            .roster()
                            .into_iter()
                            .filter(|c| c.id != me)
                            .filter(|c| match links.get(&c.id) {
                                Some(l) => {
                                    l.last_seen_ms == 0
                                        || now.saturating_sub(l.last_seen_ms) >= LIVE_WINDOW_MS
                                }
                                None => true,
                            })
                            .map(|c| (c.id, c.member))
                            .collect();
                        Work {
                            mesh: ms.mesh.id,
                            network: ms.mesh.charter.master_pubkey,
                            my_seed: ms.my_key.to_seed(),
                            my_endpoint: *ms.my_endpoint.lock().unwrap(),
                            missing,
                        }
                    })
                    .collect()
            };
            for w in work {
                // (1) Republish our current endpoint so peers that lost us can re-find it.
                if let Some(ep) = w.my_endpoint {
                    let key = MemberKey::from_seed(&w.my_seed);
                    let rec = key.publish_endpoints(w.network, vec![ep], now, now);
                    dht.publish(&rec).await;
                }
                // (2) Re-discover each member we can't currently reach.
                for (mid, pk) in w.missing {
                    let Some(rec) = dht.lookup(pk).await else {
                        continue;
                    };
                    // verify() (sig + member) already passed inside lookup; require the
                    // record to belong to THIS mesh before trusting its endpoint.
                    if rec.network != w.network {
                        continue;
                    }
                    if let Some(&ep) = rec.endpoints.first() {
                        let st = state.lock().unwrap();
                        if let Some(ms) = st.meshes.get(&w.mesh) {
                            ms.links
                                .lock()
                                .unwrap()
                                .entry(mid)
                                .or_insert(Link {
                                    endpoint: ep,
                                    last_seen_ms: 0,
                                })
                                .endpoint = ep;
                        }
                        elog!(
                            "meshd: DHT re-discovered mesh {} member {mid} at {ep}",
                            w.mesh
                        );
                    }
                }
            }
        }
    });
}

/// Live-paired self-destruct (P-C4, docs/PROTOCOL_DESIGN.md §5-2): once a mesh has
/// been healthy (≥ the live threshold), if it then sits **below** the threshold for
/// `SELF_DESTRUCT_GRACE_SECS`, the secret is (by the threshold-sharing model)
/// unrecoverable — so we wipe it and drop the mesh. A still-forming mesh (never yet
/// at quorum) is exempt, so onboarding doesn't trip it. `MESHD_NO_SELF_DESTRUCT=1`
/// disables it. (v1 = cooperative wipe; true never-hold-the-secret Shamir sharing is
/// P-C4b.)
fn spawn_self_destruct_watchdog(mesh_id: MeshId, state: Arc<Mutex<State>>) {
    if std::env::var("MESHD_NO_SELF_DESTRUCT").is_ok() {
        return;
    }
    tokio::spawn(async move {
        let mut established = false;
        let mut below_since: Option<u64> = None;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(SELF_DESTRUCT_TICK_SECS)).await;
            let now = now_ms();
            let mut st = state.lock().unwrap();
            let Some(ms) = st.meshes.get(&mesh_id) else {
                return; // mesh already gone (RemoveMesh / earlier self-destruct)
            };
            let armed = ms.attack_armed_at;
            let n = ms.roster().len().max(1);
            let live = 1 + ms
                .links
                .lock()
                .unwrap()
                .values()
                .filter(|l| {
                    l.last_seen_ms != 0 && now.saturating_sub(l.last_seen_ms) < LIVE_WINDOW_MS
                })
                .count();
            let threshold = quorum_threshold(n);

            // P-C7: an attack alert that the creator never cleared ⇒ fail-deadly.
            let attack =
                matches!(armed, Some(t) if now.saturating_sub(t) >= ATTACK_GRACE_SECS * 1000);

            // P-C4: an established mesh that has sat below the live threshold past grace.
            // Opt-in per mesh (charter.self_destruct): a laptop-friendly mesh leaves this
            // off so a sleeping member never nukes the keys; only `OnIsolation` arms it.
            let liveness_armed =
                ms.mesh.charter.self_destruct == lattice_mesh::charter::SelfDestruct::OnIsolation;
            let mut starved = false;
            if live >= threshold {
                established = true;
                below_since = None;
            } else if established && liveness_armed {
                let since = *below_since.get_or_insert(now);
                starved = now.saturating_sub(since) >= SELF_DESTRUCT_GRACE_SECS * 1000;
            }

            if !attack && !starved {
                continue;
            }
            let reason = if attack {
                format!("attack alert un-cleared after {ATTACK_GRACE_SECS}s (one-veto, P-C7)")
            } else {
                format!("live {live}/{n} below threshold {threshold} for {SELF_DESTRUCT_GRACE_SECS}s (live-paired, P-C4)")
            };
            elog!("meshd: mesh {mesh_id} SELF-DESTRUCT — {reason}");
            if let Some(mut gone) = st.meshes.remove(&mesh_id) {
                gone.secret.iter_mut().for_each(|byte| *byte = 0); // wipe the secret
                if let Some(t) = &gone.dp_task {
                    t.abort();
                }
                if st.current == Some(mesh_id) {
                    st.current = None;
                    exit::restore_routes();
                    exit::restore_dns();
                }
            }
            persist(&st); // P-S1: erase the on-disk copy too (keeps the ephemeral property)
            return;
        }
    });
}

/// Best-effort primary local IP — the source address the OS picks to reach the
/// internet (no packet is actually sent; `connect` on a UDP socket just selects the
/// route). Used as our advertised gossip endpoint when MESHD_ADVERTISE is unset.
fn local_ip() -> Option<std::net::IpAddr> {
    let s = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    s.connect(("8.8.8.8", 80)).ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

/// Kill-switch watchdog (from v1). Full tunnel diverts the host default route
/// through the exit; if that path can't carry traffic the host is stranded OFFLINE.
/// Every ~20s probe the internet THROUGH the tunnel (TCP connect to 1.1.1.1:443 —
/// it travels TUN→exit, so success proves the exit forwards). The moment a probe
/// fails, auto-revert to direct internet so the user is never cut off.
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

fn handle(req: Request, st: &mut State) -> (Response, Option<PostAction>) {
    match req {
        Request::CreateMesh {
            name,
            my_name,
            max_members,
            cipher,
            self_destruct,
            master_gated,
        } => create_mesh(
            st,
            name,
            my_name,
            max_members,
            cipher,
            self_destruct,
            master_gated,
        ),

        Request::Ciphers => (
            Response::Ciphers(
                lattice_mesh::crypto::available_ciphers()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            ),
            None,
        ),

        Request::Recipher { mesh, cipher } => {
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

        Request::ExportState { path } => {
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
                            let _ = std::fs::set_permissions(
                                &target,
                                std::fs::Permissions::from_mode(0o600),
                            );
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
        Request::ListMeshes => {
            let cur = st.current;
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
                    attack_armed_secs_left: ms.attack_armed_at.map(|armed| {
                        ATTACK_GRACE_SECS.saturating_sub(now.saturating_sub(armed) / 1000)
                    }),
                    is_creator: ms.master.is_some(),
                })
                .collect();
            meshes.sort_by_key(|s| s.id);
            (Response::Meshes(meshes), None)
        }

        Request::MeshInfo { mesh } => match st.meshes.get(&mesh) {
            Some(ms) => (Response::Mesh(detail(ms)), None),
            None => (no_mesh(mesh), None),
        },

        Request::AdmitMember {
            mesh,
            name,
            pubkey_hex,
        } => {
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
            }
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
                        },
                    );
                    (Response::Ok, None)
                }
                None => (no_mesh(mesh), None),
            }
        }

        Request::SetCurrent { mesh } => match mesh {
            None => {
                st.current = None;
                // Back to the default network: undo the full-tunnel diversion.
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
                let action = match plan {
                    (Some(tun), Some(ip)) => {
                        // Point DNS through the tunnel BEFORE diverting the default
                        // route: `set_dns` keys off the primary network service, which
                        // it derives from the current default interface — once the
                        // route is on the TUN that lookup finds the tunnel (no service)
                        // and DNS is silently left on the now-unreachable LAN resolver.
                        if let Ok(dns) = FULL_TUNNEL_DNS.parse() {
                            exit::set_dns(&[dns]);
                        }
                        exit::route_through(&tun, ip);
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
        },

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
                }
                (Response::Ok, None)
            } else {
                (no_mesh(mesh), None)
            }
        }

        Request::GetPolicy => {
            let default = match st.current.and_then(|id| st.meshes.get(&id)) {
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

        Request::CreateInvite {
            mesh,
            name,
            member_pubkey_hex,
            enc_pubkey_hex,
            issued_at,
            algo,
        } => {
            // P-C6: reject a stale identity code.
            if issued_at != 0
                && now_ms().saturating_sub(issued_at)
                    > lattice_mesh::invitewrap::IDENTITY_TTL_SECS * 1000
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
            let roster = ms.roster();
            if ms.master.is_none() {
                if ms.mesh.charter.invite != InviteTopology::OpenChain {
                    return (
                        err("only the mesh creator can invite in a master-gated mesh"),
                        None,
                    );
                }
                if !roster.iter().any(|c| c.member == ms.my_key.pubkey()) {
                    return (
                        err("you must be a verified member of this mesh to invite"),
                        None,
                    );
                }
            }
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
            let used: HashSet<MemberId> = roster.iter().map(|c| c.id).collect();
            let id = match (1u8..=254).find(|i| !used.contains(i)) {
                Some(i) => i,
                None => return (err("no free member id"), None),
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
            let mut endpoints: Vec<(MemberId, String)> = Vec::new();
            if let Some(ep) = *ms.my_endpoint.lock().unwrap() {
                endpoints.push((ms.my_id(), ep.to_string()));
            }
            for (m, link) in ms.links.lock().unwrap().iter() {
                endpoints.push((*m, link.endpoint.to_string()));
            }
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
                epoch: ms.epoch, // bring the joiner up at the live epoch (P-C3)
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

        Request::JoinMesh { invite, algo } => {
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
            match serde_json::from_slice::<InviteBlob>(&plain) {
                Ok(blob) => join_mesh(st, blob),
                Err(e) => (err(&format!("bad invite contents: {e}")), None),
            }
        }
    }
}

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
    let prefix = invite.charter.overlay_prefix;
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
    let links = seed_links(seed);
    let exit_sel: SharedExit = Arc::new(Mutex::new(None));
    let my_endpoint: SharedEndpoint = Arc::new(Mutex::new(None));
    let decrypt_fails: DecryptFails = Arc::new(Mutex::new(HashMap::new()));
    let mut mesh = Mesh::new(
        invite.mesh_id,
        invite.mesh_name.clone(),
        invite.charter,
        invite.member_id,
    );
    mesh.epoch = epoch;
    let bringup = st.data_plane.then(|| Bringup {
        mesh_id: invite.mesh_id,
        my_id: invite.member_id,
        prefix,
        secret,
        cipher: cipher.clone(),
        epoch,
        links: Arc::clone(&links),
        exit_sel: Arc::clone(&exit_sel),
        my_endpoint: Arc::clone(&my_endpoint),
        decrypt_fails: Arc::clone(&decrypt_fails),
    });
    st.meshes.insert(
        invite.mesh_id,
        MeshState {
            mesh,
            master: None,
            my_key,
            my_enc,
            certs: invite.certs,
            secret,
            links,
            exit_sel,
            tun_name: None,
            my_endpoint,
            dp_port: 0,
            dp_error: None,
            dp_task: None,
            cipher,
            epoch,
            loop_cmd: None,
            attack_armed_at: None,
            decrypt_fails,
        },
    );
    (
        Response::MeshCreated {
            mesh: invite.mesh_id,
        },
        bringup.map(PostAction::Bringup),
    )
}

fn create_mesh(
    st: &mut State,
    name: String,
    my_name: String,
    max_members: u8,
    cipher: Option<String>,
    self_destruct: Option<bool>,
    master_gated: Option<bool>,
) -> (Response, Option<PostAction>) {
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
    };
    if let Err(e) = charter.validate() {
        return (err(&e.to_string()), None);
    }
    // The creator is member #1, with a master-signed cert.
    let cert = master.issue(my_key.pubkey(), 1, &my_name, now_ms());
    let my_enc = EncKey::generate();
    let prefix = charter.overlay_prefix;
    let cipher = charter.initial_cipher.clone();
    let secret: [u8; 32] = rand::random();
    let links = seed_links(HashMap::new());
    let exit_sel: SharedExit = Arc::new(Mutex::new(None));
    let my_endpoint: SharedEndpoint = Arc::new(Mutex::new(None));
    let decrypt_fails: DecryptFails = Arc::new(Mutex::new(HashMap::new()));
    let mesh = Mesh::new(id, name, charter, 1);
    // If data-plane mode is on, ask the async caller to bring up this mesh's loop
    // (sharing the same links/exit handles we store below).
    let bringup = st.data_plane.then(|| Bringup {
        mesh_id: id,
        my_id: 1,
        prefix,
        secret,
        cipher: cipher.clone(),
        epoch: 0,
        links: Arc::clone(&links),
        exit_sel: Arc::clone(&exit_sel),
        my_endpoint: Arc::clone(&my_endpoint),
        decrypt_fails: Arc::clone(&decrypt_fails),
    });
    st.meshes.insert(
        id,
        MeshState {
            mesh,
            master: Some(master),
            my_key,
            my_enc,
            certs: vec![cert],
            secret,
            links,
            exit_sel,
            tun_name: None,
            my_endpoint,
            dp_port: 0,
            dp_error: None,
            dp_task: None,
            cipher,
            epoch: 0,
            loop_cmd: None,
            attack_armed_at: None,
            decrypt_fails,
        },
    );
    (
        Response::MeshCreated { mesh: id },
        bringup.map(PostAction::Bringup),
    )
}

fn detail(ms: &MeshState) -> MeshDetail {
    let me = ms.my_key.pubkey();
    let now = now_ms();
    // Snapshot decrypt-fail stats (frames from a known endpoint that didn't open). A
    // recent fail from a member's endpoint IP is the "different mesh / different epoch"
    // signal — it turns an opaque `idle` into an explained one and raises a warning.
    let fails = ms.decrypt_fails.lock().unwrap().clone();
    let recent_fail = |ip: std::net::IpAddr| -> Option<u64> {
        fails.get(&ip).and_then(|s: &DecryptFailStat| {
            (s.count > 0 && now.saturating_sub(s.last_ms) < DECRYPT_FAIL_WINDOW_MS)
                .then_some(s.count)
        })
    };
    let links = ms.links.lock().unwrap();
    let members: Vec<MemberView> = ms
        .roster()
        .iter()
        .map(|c| {
            let is_me = c.member == me;
            let link = links.get(&c.id).copied();
            let endpoint = link.map(|l| l.endpoint.to_string());
            // `state` is the legacy badge ({me,live,idle,unknown}); `reason` explains an
            // idle/unknown peer in plain language so the user isn't left guessing why.
            let (state, reason): (String, Option<String>) = if is_me {
                ("me".into(), None)
            } else {
                match link {
                    Some(l)
                        if l.last_seen_ms != 0
                            && now.saturating_sub(l.last_seen_ms) < LIVE_WINDOW_MS =>
                    {
                        ("live".into(), None)
                    }
                    Some(l) => {
                        let why = if let Some(n) = recent_fail(l.endpoint.ip()) {
                            format!(
                                "이 주소에서 온 프레임 {n}건이 복호 실패 — 상대가 다른 mesh이거나 \
                                 epoch 불일치일 수 있음 (재초대 필요)"
                            )
                        } else if l.last_seen_ms == 0 {
                            "주소만 알고 아직 한 번도 수신 못함 — 상대 데몬이 꺼졌거나 방화벽/NAT가 \
                             막는 중일 수 있음"
                                .into()
                        } else {
                            "최근 30초간 수신 없음 — 상대가 오프라인이거나 IP가 바뀌었을 수 있음".into()
                        };
                        ("idle".into(), Some(why))
                    }
                    None => (
                        "unknown".into(),
                        Some("엔드포인트 미상 — 아직 상대 위치를 모름 (discovery/DHT 대기)".into()),
                    ),
                }
            };
            MemberView {
                id: c.id,
                name: c.name.clone(),
                pubkey_fp: fp(&c.member),
                is_me,
                endpoint,
                state,
                reason,
            }
        })
        .collect();
    // Health + attack state for the GUI (G-0): live count, the self-destruct floor,
    // and the attack countdown.
    let live = 1 + links
        .values()
        .filter(|l| l.last_seen_ms != 0 && now.saturating_sub(l.last_seen_ms) < LIVE_WINDOW_MS)
        .count();
    // Known peer endpoint IPs (name, ip) — captured while `links` is held, for warnings.
    let known_eps: Vec<(String, std::net::IpAddr)> = ms
        .roster()
        .iter()
        .filter(|c| c.member != me)
        .filter_map(|c| links.get(&c.id).map(|l| (c.name.clone(), l.endpoint.ip())))
        .collect();
    drop(links);
    let threshold = quorum_threshold(ms.roster().len().max(1));
    // Mesh-level warnings: the daemon SAYS what it already knows instead of dropping it.
    let mut warnings: Vec<String> = Vec::new();
    let mut warned_ips: std::collections::HashSet<std::net::IpAddr> =
        std::collections::HashSet::new();
    for (name, ip) in &known_eps {
        if let Some(n) = recent_fail(*ip) {
            if warned_ips.insert(*ip) {
                warnings.push(format!(
                    "⚠ '{name}'({ip})에서 온 프레임 {n}건이 복호 실패 — 다른 mesh이거나 epoch \
                     불일치 의심. 양쪽의 network id(net {})가 같은지 확인하세요.",
                    fp(&ms.mesh.charter.master_pubkey)
                ));
            }
        }
    }
    if ms.attack_armed_at.is_none()
        && ms.mesh.charter.self_destruct == lattice_mesh::charter::SelfDestruct::OnIsolation
        && live < threshold
    {
        warnings.push(format!(
            "⚠ 온라인 {live} < floor {threshold} — ephemeral mesh가 임계 미만입니다. \
             멤버가 더 떨어지면 self-destruct로 mesh가 사라질 수 있습니다."
        ));
    }
    if let Some(e) = &ms.dp_error {
        warnings.push(format!("⛔ data plane DOWN: {e}"));
    }
    let attack_armed_secs_left = ms.attack_armed_at.map(|armed| {
        let elapsed = now.saturating_sub(armed) / 1000;
        ATTACK_GRACE_SECS.saturating_sub(elapsed)
    });
    let ch = &ms.mesh.charter;
    MeshDetail {
        id: ms.mesh.id,
        name: ms.mesh.name.clone(),
        epoch: ms.epoch,
        me: ms.my_id(),
        exit: ms.mesh.exit,
        invite: format!("{:?}", ch.invite),
        trigger: format!("{:?}", ch.trigger),
        max_members: ch.max_members,
        cipher: ms.cipher.clone(), // current cipher (may differ from charter post-re-cipher)
        members,
        live,
        threshold,
        attack_armed_secs_left,
        is_creator: ms.master.is_some(),
        self_destruct: ch.self_destruct == lattice_mesh::charter::SelfDestruct::OnIsolation,
        dp_error: ms.dp_error.clone(),
        warnings,
        network_fp: fp(&ch.master_pubkey),
    }
}

fn no_mesh(id: MeshId) -> Response {
    Response::Error {
        message: format!("no mesh {id}"),
    }
}

fn err(message: &str) -> Response {
    Response::Error {
        message: message.to_string(),
    }
}

fn fp(pk: &PubKey) -> String {
    pk[..4].iter().map(|b| format!("{b:02x}")).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::quorum_threshold;

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
}
