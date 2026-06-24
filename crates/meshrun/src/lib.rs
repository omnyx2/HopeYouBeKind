//! v2 data-plane runner (docs/DATA_PLANE.md P2): one loop tying a TUN, a transport,
//! and a mesh's [`MeshDataPlane`]. Outbound packets from the TUN are routed →
//! sealed → sent to the destination member's endpoint; inbound frames are opened
//! and written back to the TUN.
//!
//! The peer table ([`PeerLinks`]) and exit selection ([`SharedExit`]) are shared
//! handles: the loop updates a peer's endpoint + last-seen as frames arrive, and a
//! supervisor (the standalone binary, or `meshd`) reads them for live status and
//! writes the exit live. This is the seam P6.3c/d builds the daemon + GUI on.
//!
//! ## Edit-risk (each fn's `///` carries a `RISK:` tag — same scheme as `exit.rs`)
//! - 🔴 **HIGH** — the data-plane hot path or the ON-WIRE FORMAT. Blast radius = ALL overlay +
//!   exit traffic, AND cross-version interop. **Wire-compat invariant: frame/payload layouts and
//!   `CTRL_*` tag VALUES are append-only.** Changing the bytes of [`encode_gossip`]/[`encode_recipher`]/
//!   the seal format, or renumbering a `CTRL_*`, breaks every node still on the old build (the
//!   mesh runs MIXED versions — Oracle was 3 minor versions behind this session). Add new tags at
//!   the end; never reorder/repurpose. Test a new↔old node pair before shipping.
//! - 🟡 **MED** — routing/relay decisions and parsers ([`pick_route`]/[`pick_relay`]/
//!   [`apply_gossip_table`]/[`parse_flow`]/[`ipv4_dst`]). Wrong logic silently mis-routes or drops
//!   overlay packets (e.g. the old insert-only gossip merge pinned a dead address forever).
//! - 🟢 **LOW** — pure helpers ([`now_ms`]/[`is_public`]/[`seed_links`]).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use lattice_mesh::dataplane::{Inbound, MeshDataPlane, RouteDecision};
use lattice_net::Transport;
use lattice_proto::wire_v2::MemberId;
use lattice_tun::TunDevice;

pub mod lan;
pub use lan::{run_lan_discovery, LanMesh};

/// What we know about how to reach a peer, and when we last heard from it.
#[derive(Clone, Copy, Debug)]
pub struct Link {
    /// Where to send this peer's frames (seeded out-of-band, then kept fresh from
    /// the source address of inbound frames — peers roam / sit behind NAT).
    pub endpoint: SocketAddr,
    /// Unix-ms of the last frame received from this peer by **any** path (direct OR
    /// relayed); 0 = never heard (a seed). Drives liveness.
    pub last_seen_ms: u64,
    /// Unix-ms of the last frame received **directly** from this peer (its UDP source was
    /// the peer itself, not a relay hop); 0 = no direct path confirmed. When this is
    /// stale, the peer is presumed unreachable directly and overlay traffic is relayed
    /// through a public node (docs/RELAY.md).
    pub last_direct_ms: u64,
}

/// The mesh's live peer table, shared between the run loop and its supervisor.
pub type PeerLinks = Arc<Mutex<HashMap<MemberId, Link>>>;

/// One source IP's record of frames that arrived but **failed to open** (decrypt).
#[derive(Clone, Copy, Debug, Default)]
pub struct DecryptFailStat {
    /// How many frames from this IP failed to decrypt.
    pub count: u64,
    /// Unix-ms of the most recent failure.
    pub last_ms: u64,
}

/// Frames received on a mesh's socket that did NOT open under our key — keyed by source
/// IP. A frame that fails to decrypt is normally just internet noise on the UDP port and
/// is dropped silently; but if the source IP matches a peer we *know how to reach* (a
/// roster member's endpoint), the far more likely cause is that the peer is on a
/// **different mesh** or a **different epoch**. Recording it lets the supervisor turn a
/// silent drop into an actionable health warning instead (the split-brain signal).
pub type DecryptFails = Arc<Mutex<HashMap<IpAddr, DecryptFailStat>>>;

/// Per-peer byte/packet counters for the traffic monitor (rx = we received, tx = we sent).
#[derive(Clone, Copy, Debug, Default)]
pub struct PeerTraffic {
    pub rx_bytes: u64,
    pub rx_pkts: u64,
    pub tx_bytes: u64,
    pub tx_pkts: u64,
}

/// One recorded overlay packet for the flow-detail view — the 5-tuple of an app packet
/// that crossed the TUN (out = we sent it to `member`, in = we received it from `member`).
#[derive(Clone, Copy, Debug)]
pub struct FlowEvent {
    pub at_ms: u64,
    pub out: bool,
    pub member: MemberId,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub bytes: u16,
    /// The packet was routed via the exit (internet-bound), not to an in-mesh member.
    pub via_exit: bool,
}

/// How many recent flow events to keep per mesh (a ring; oldest drops).
const FLOW_RING_CAP: usize = 200;

/// A mesh's live traffic: per-peer totals + a ring of recent overlay flows. Shared with the
/// supervisor (meshd), which projects it into the GUI's traffic monitor.
#[derive(Default)]
pub struct Traffic {
    pub per_peer: HashMap<MemberId, PeerTraffic>,
    pub recent: std::collections::VecDeque<FlowEvent>,
}

impl Traffic {
    /// Count one overlay packet `p` to/from `member` and (if it parses as IPv4) record its
    /// 5-tuple in the recent ring.
    fn record(&mut self, member: MemberId, out: bool, p: &[u8], via_exit: bool) {
        let e = self.per_peer.entry(member).or_default();
        let len = p.len() as u64;
        if out {
            e.tx_bytes += len;
            e.tx_pkts += 1;
        } else {
            e.rx_bytes += len;
            e.rx_pkts += 1;
        }
        if let Some(mut ev) = parse_flow(p) {
            ev.at_ms = now_ms();
            ev.out = out;
            ev.member = member;
            ev.via_exit = via_exit;
            if self.recent.len() >= FLOW_RING_CAP {
                self.recent.pop_front();
            }
            self.recent.push_back(ev);
        }
    }
}

/// Shared traffic handle (run loop writes, supervisor reads).
pub type SharedTraffic = Arc<Mutex<Traffic>>;

/// **RISK 🟡 MED** (parser — only feeds the traffic monitor; a wrong parse mis-labels a flow, no routing impact).
/// Parse the IPv4 5-tuple of a raw overlay packet for the flow-detail view. Fields
/// `at_ms/out/member/via_exit` are filled by the caller. `None` if not IPv4.
fn parse_flow(p: &[u8]) -> Option<FlowEvent> {
    if p.len() < 20 || (p[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((p[0] & 0x0f) as usize) * 4;
    let proto = p[9];
    let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
    let (sport, dport) = if (proto == 6 || proto == 17) && p.len() >= ihl + 4 {
        (
            u16::from_be_bytes([p[ihl], p[ihl + 1]]),
            u16::from_be_bytes([p[ihl + 2], p[ihl + 3]]),
        )
    } else {
        (0, 0)
    };
    Some(FlowEvent {
        at_ms: 0,
        out: false,
        member: 0,
        src,
        dst,
        proto,
        sport,
        dport,
        bytes: p.len().min(u16::MAX as usize) as u16,
        via_exit: false,
    })
}

/// The member that internet-bound traffic egresses through (the exit). Shared so a
/// supervisor can change egress live (the GUI's egress toggle) without a respawn.
pub type SharedExit = Arc<Mutex<Option<MemberId>>>;

/// This node's own advertised endpoint (`ip:port`), shared so a supervisor (meshd)
/// reads the current value for invites/gossip while the run loop updates it — it
/// changes when a public peer reflects our public (reflexive) address to us (P-D3).
pub type SharedEndpoint = Arc<Mutex<Option<SocketAddr>>>;

/// **RISK 🟢 LOW** (pure predicate).
/// Is `ip` a globally-routable (public) address? Used to decide whether to trust a
/// peer's reflexion of our address: only a peer reaching us over the public internet
/// observes our public NAT mapping (P-D3). Private/loopback/link-local/CGNAT = not.
fn is_public(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            let cgnat = o[0] == 100 && (64..=127).contains(&o[1]); // 100.64.0.0/10
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || cgnat)
        }
        std::net::IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified()),
    }
}

/// **RISK 🟢 LOW** (pure clock read). Unix epoch milliseconds (best-effort; 0 if the clock is before the epoch).
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Build a [`PeerLinks`] from seed endpoints (last_seen = 0 until they speak).
pub fn seed_links(endpoints: HashMap<MemberId, SocketAddr>) -> PeerLinks {
    let map = endpoints
        .into_iter()
        .map(|(m, endpoint)| {
            (
                m,
                Link {
                    endpoint,
                    last_seen_ms: 0,
                    last_direct_ms: 0,
                },
            )
        })
        .collect();
    Arc::new(Mutex::new(map))
}

/// **RISK 🟡 MED** (parser on the hot path — used to route every outbound packet).
/// The IPv4 destination of a raw IP packet (`TunDevice` yields raw IP — the macOS
/// AF header is stripped by `lattice-tun`). `None` if it isn't IPv4.
pub fn ipv4_dst(p: &[u8]) -> Option<Ipv4Addr> {
    if p.len() < 20 || (p[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(p[16], p[17], p[18], p[19]))
}

/// Endpoint gossip / keepalive interval (also the NAT-keepalive cadence, docs/
/// DISCOVERY.md §3,§6).
const GOSSIP_INTERVAL_SECS: u64 = 20;

/// A peer is "directly reachable" iff we got a **direct** frame from it within this
/// window. Just over `GOSSIP_INTERVAL_SECS` so one missed keepalive doesn't flap us onto
/// the relay. When a peer's direct path is stale, overlay traffic to it is relayed
/// through a public node (docs/RELAY.md).
const DIRECT_OK_MS: u64 = 25_000;

/// How often (per peer) the relay-fallback decisions are logged, so a permanently
/// unreachable peer can't spam the log on every packet.
const RELAY_LOG_THROTTLE_MS: u64 = 15_000;

/// Where to route one outbound overlay frame for member `to`.
#[derive(Debug, PartialEq)]
enum Route {
    /// Send straight to the peer's own endpoint.
    Direct(SocketAddr),
    /// Send to a relay member's endpoint; the relay opens the header, sees `dst = to`,
    /// and forwards it (docs/RELAY.md). `via` = the relay's address, `member` = its id.
    Relay { via: SocketAddr, member: MemberId },
    /// No direct path and no relay — the frame is dropped (logged, throttled).
    None,
}

/// Is member `m`'s direct path fresh enough to use? (a direct frame within `DIRECT_OK_MS`)
fn directly_reachable(lk: &Link, now: u64) -> bool {
    lk.last_direct_ms != 0 && now.saturating_sub(lk.last_direct_ms) < DIRECT_OK_MS
}

/// **RISK 🟡 MED** (relay selection — feeds [`pick_route`]).
/// Pick a relay for `to`: a **directly-reachable, public** member (≠ `to`). The `exit`
/// (the designated always-on public node) is preferred; otherwise any live public peer.
fn pick_relay(
    links: &HashMap<MemberId, Link>,
    to: MemberId,
    exit: Option<MemberId>,
    now: u64,
) -> Option<(MemberId, SocketAddr)> {
    let ok = |m: MemberId, lk: &Link| {
        m != to && directly_reachable(lk, now) && is_public(lk.endpoint.ip())
    };
    if let Some(ex) = exit {
        if let Some(lk) = links.get(&ex) {
            if ok(ex, lk) {
                return Some((ex, lk.endpoint));
            }
        }
    }
    links
        .iter()
        .find(|(m, lk)| ok(**m, lk))
        .map(|(m, lk)| (*m, lk.endpoint))
}

/// **RISK 🟡 MED** (routing decision — wrong → overlay packets to a peer go nowhere / loop).
/// Decide how to reach `to`: direct if its direct path is fresh; else relay through a
/// public node; else best-effort direct (so NAT punching can still establish it); else
/// nothing (docs/RELAY.md).
fn pick_route(
    links: &HashMap<MemberId, Link>,
    to: MemberId,
    exit: Option<MemberId>,
    now: u64,
) -> Route {
    let target = links.get(&to);
    if let Some(t) = target {
        if directly_reachable(t, now) {
            return Route::Direct(t.endpoint);
        }
    }
    if let Some((member, via)) = pick_relay(links, to, exit, now) {
        return Route::Relay { via, member };
    }
    if let Some(t) = target {
        return Route::Direct(t.endpoint); // best-effort: keep punching toward direct
    }
    Route::None
}

/// **RISK 🟡 MED** (regression site: the old insert-only merge pinned a dead address forever).
/// Merge a gossiped endpoint table into our links. A peer we already know is updated only
/// when we have NO fresh direct path to it: a directly-learned address is more accurate
/// than a third party's gossip, but a stale entry must yield so a peer whose address
/// changed can be re-discovered. (The old insert-only merge pinned a stale address forever,
/// so once a node held a dead address for a peer, gossip could never correct it —
/// docs/RELAY.md.)
fn apply_gossip_table(
    links: &mut HashMap<MemberId, Link>,
    table: &[(MemberId, SocketAddr)],
    my_id: MemberId,
    now: u64,
) {
    for &(m, ep) in table {
        if m == my_id {
            continue; // never learn our own id from gossip (a self-entry pollutes the table)
        }
        match links.get_mut(&m) {
            None => {
                links.insert(
                    m,
                    Link {
                        endpoint: ep,
                        last_seen_ms: 0,
                        last_direct_ms: 0,
                    },
                );
            }
            // Stale (no fresh direct path) → adopt the gossiped address; it may be current.
            Some(existing) if !directly_reachable(existing, now) => {
                existing.endpoint = ep;
            }
            // Fresh direct path → keep our own, more accurate address.
            Some(_) => {}
        }
    }
}

/// **RISK 🔴 HIGH** (ON-WIRE FORMAT — see module header; append-only, old nodes must still parse).
/// Encode the gossip payload (sealed): the endpoint table as `id ip:port` lines,
/// plus an optional `self ip:port` line = "where I observe YOU (the recipient)",
/// the reflexion that lets a NAT'd peer learn its public address (P-D3).
fn encode_gossip(table: &[(MemberId, SocketAddr)], reflect: Option<SocketAddr>) -> Vec<u8> {
    let mut s = String::new();
    for (m, a) in table {
        s.push_str(&format!("{m} {a}\n"));
    }
    if let Some(r) = reflect {
        s.push_str(&format!("self {r}\n"));
    }
    s.into_bytes()
}

/// **RISK 🔴 HIGH** (ON-WIRE FORMAT — inverse of [`encode_gossip`]; must tolerate old/garbage lines).
/// Decode a gossip payload → (endpoint table, our reflexive address if the sender
/// reported one). Unknown/garbage lines are skipped (older senders sent no `self`).
fn decode_gossip(payload: &[u8]) -> (Vec<(MemberId, SocketAddr)>, Option<SocketAddr>) {
    let mut table = Vec::new();
    let mut reflect = None;
    for line in String::from_utf8_lossy(payload).lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("self ") {
            if let Ok(a) = rest.trim().parse() {
                reflect = Some(a);
            }
        } else if let Some((m, a)) = line.split_once(' ') {
            if let (Ok(m), Ok(a)) = (m.parse::<MemberId>(), a.parse()) {
                table.push((m, a));
            }
        }
    }
    (table, reflect)
}

/// Control-frame sub-tags (the first byte of a `Control` payload): gossip vs a
/// re-cipher announce (P-C3), so one frame type carries both.
const CTRL_GOSSIP: u8 = 0x01;
const CTRL_RECIPHER: u8 = 0x02;

/// A re-cipher: the new cipher epoch (P-C3, docs/PROTOCOL_DESIGN.md §11). Used both
/// as the meshd→loop command and as the on-wire announce payload.
#[derive(Clone)]
pub struct Recipher {
    pub epoch: u64,
    pub cipher: String,
    pub secret: [u8; 32],
}

/// A command from the supervisor (meshd) into the data-plane loop.
pub enum LoopCmd {
    /// Re-cipher: announce to `peers` (old cipher) then swap locally (P-C3).
    Recipher(Recipher, Vec<MemberId>),
    /// Seal a tagged `Control` payload and send it to `peers` (P-C7 attack signals).
    SendControl(u8, Vec<u8>, Vec<MemberId>),
    /// Apply a new SDN flow table to the live data plane (docs/FLOW_TABLE.md).
    SetFlows(Vec<lattice_proto::flow::FlowRule>),
}

/// An event from the data-plane loop up to the supervisor.
pub enum LoopEvent {
    /// A re-cipher landed (update the stored secret/epoch/cipher).
    Recipher(Recipher),
    /// A control signal arrived (P-C7): the sub-tag (0x03 attack alert / 0x04 all-clear).
    Control(u8),
    /// A peer gossiped its membership roster (`CTRL_ROSTER`): the sealed-then-opened
    /// cert bytes. The supervisor merges any new, valid certs so the roster converges
    /// across the mesh (a node added via a third member reaches everyone).
    Roster(Vec<u8>),
    /// A peer gossiped membership revocations (`CTRL_REVOKE`): signed expulsions. The
    /// supervisor merges them (accumulating quorum co-signers) so an expulsion converges
    /// across the mesh the same way the roster does.
    Revoke(Vec<u8>),
    /// A peer gossiped its SDN flow table (`CTRL_FLOWS`): `version(8 BE) ‖ bincode(flows)`.
    /// The supervisor adopts it if the version is newer, then applies it to the data plane.
    Flows(Vec<u8>),
    /// A peer gossiped its advertised services (`CTRL_REGISTRY`): `json(Vec<ServiceRecord>)`.
    /// The supervisor merges them (newest-per-(member, proto) wins, soft-state) so the
    /// service registry converges across the mesh (docs/EXTENSIONS.md §6).
    Registry(Vec<u8>),
}

/// meshd→loop command channel (re-cipher, attack signals).
pub type LoopCmdRx = tokio::sync::mpsc::UnboundedReceiver<LoopCmd>;
/// loop→meshd event channel (re-cipher applied, attack signal received).
pub type LoopEventTx = tokio::sync::mpsc::UnboundedSender<LoopEvent>;

/// **RISK 🔴 HIGH** (ON-WIRE tag values — APPEND-ONLY; renumbering breaks mixed-version meshes.
/// Old nodes ignore an unknown tag via the `_ => {}` dispatch, so new tags are safe at the end).
/// Control-frame sub-tags for the attack-response control plane (P-C7).
pub const CTRL_ATTACK: u8 = 0x03;
pub const CTRL_ALLCLEAR: u8 = 0x04;
/// Membership roster gossip: the sender's cert set, so the roster converges across the
/// mesh (a node admitted via one member propagates to all). Carried like other control
/// frames; merged + re-validated by the supervisor.
pub const CTRL_ROSTER: u8 = 0x05;
/// Membership revocation gossip: signed expulsions, merged + re-validated by the
/// supervisor so an expelled member converges out of the roster mesh-wide (§ expulsion).
pub const CTRL_REVOKE: u8 = 0x06;
/// SDN flow-table gossip: `version(8 BE) ‖ bincode(Vec<FlowRule>)`. Newest version wins;
/// the supervisor applies an adopted table to the data plane (docs/FLOW_TABLE.md).
pub const CTRL_FLOWS: u8 = 0x07;
/// Service-registry gossip: `json(Vec<ServiceRecord>)`. Soft state, newest-per-(member,
/// proto) wins; the supervisor merges it for connector discovery (docs/EXTENSIONS.md §6).
pub const CTRL_REGISTRY: u8 = 0x08;

/// **RISK 🔴 HIGH** (ON-WIRE FORMAT — this byte layout is also the meshd→loop command; append-only).
/// Encode a re-cipher announce: `[epoch(8 BE)][cipher_len(1)][cipher][secret(32)]`.
fn encode_recipher(r: &Recipher) -> Vec<u8> {
    let cb = r.cipher.as_bytes();
    let mut v = Vec::with_capacity(8 + 1 + cb.len() + 32);
    v.extend_from_slice(&r.epoch.to_be_bytes());
    v.push(cb.len() as u8);
    v.extend_from_slice(cb);
    v.extend_from_slice(&r.secret);
    v
}

/// **RISK 🔴 HIGH** (ON-WIRE FORMAT — inverse of [`encode_recipher`]; length-checks the buffer).
fn decode_recipher(b: &[u8]) -> Option<Recipher> {
    if b.len() < 9 {
        return None;
    }
    let epoch = u64::from_be_bytes(b[0..8].try_into().ok()?);
    let clen = b[8] as usize;
    if b.len() < 9 + clen + 32 {
        return None;
    }
    let cipher = String::from_utf8(b[9..9 + clen].to_vec()).ok()?;
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&b[9 + clen..9 + clen + 32]);
    Some(Recipher {
        epoch,
        cipher,
        secret,
    })
}

/// **RISK 🔴 HIGH** — the data-plane HOT LOOP (TUN↔transport, seal/open, route/relay, gossip).
/// Blast radius = all overlay + exit traffic; a wrong edit can drop/mis-route every packet.
/// Run the data-plane loop until the TUN or transport closes. `links` maps a member
/// id → where to reach it + liveness (seeded from the invite, learned + gossiped
/// thereafter); `exit` is the egress member for non-mesh traffic. `my_endpoint` is
/// this node's own advertised address (shared with the supervisor); the loop upgrades
/// it to our public address when a public peer reflects it (P-D3), unless
/// `endpoint_pinned` (an explicit MESHD_ADVERTISE for a known public node).
#[allow(clippy::too_many_arguments)]
pub async fn run<X: Transport + 'static>(
    mut dp: MeshDataPlane,
    mut tun: Box<dyn TunDevice>,
    transport: X,
    links: PeerLinks,
    exit: SharedExit,
    my_id: MemberId,
    my_endpoint: SharedEndpoint,
    endpoint_pinned: bool,
    mut loop_cmd: LoopCmdRx,
    loop_event: LoopEventTx,
    fails: DecryptFails,
    traffic: SharedTraffic,
) {
    let mut gossip = tokio::time::interval(std::time::Duration::from_secs(GOSSIP_INTERVAL_SECS));
    // Per-peer last-logged time for relay-fallback decisions, so a stuck peer can't spam.
    let mut relay_log_at: HashMap<MemberId, u64> = HashMap::new();
    loop {
        tokio::select! {
            // App traffic out of the TUN → route to its member, else (internet-bound)
            // to the exit member, which NATs it out (P4; NAT is OS-side, exit.rs).
            outbound = tun.read_packet() => {
                let Ok(p) = outbound else { break };
                // Route via the SDN flow table (docs/FLOW_TABLE.md): the default table is
                // overlay → owner, internet → exit, but an admin can program any policy.
                let exit_now = *exit.lock().unwrap();
                if let RouteDecision::Send { to, via_exit } = dp.decide(&p, exit_now) {
                    // Pick a path: direct if the peer is directly reachable, else relay the
                    // frame through a public node, which forwards it on (docs/RELAY.md).
                    let now = now_ms();
                    let route = pick_route(&links.lock().unwrap(), to, exit_now, now);
                    let sealed = dp.seal_to(to, &p);
                    match route {
                        Route::Direct(addr) => {
                            traffic.lock().unwrap().record(to, true, &p, via_exit);
                            let _ = transport.send_to(&sealed, addr).await;
                        }
                        Route::Relay { via, member } => {
                            traffic.lock().unwrap().record(to, true, &p, via_exit);
                            // The frame's header dst is `to`; the relay opens it and forwards.
                            let _ = transport.send_to(&sealed, via).await;
                            let last = relay_log_at.get(&to).copied().unwrap_or(0);
                            if now.saturating_sub(last) >= RELAY_LOG_THROTTLE_MS {
                                relay_log_at.insert(to, now);
                                eprintln!(
                                    "meshrun: relaying overlay → member {to} via relay member {member} ({via}) — no direct path"
                                );
                            }
                        }
                        Route::None => {
                            let last = relay_log_at.get(&to).copied().unwrap_or(0);
                            if now.saturating_sub(last) >= RELAY_LOG_THROTTLE_MS {
                                relay_log_at.insert(to, now);
                                eprintln!(
                                    "meshrun: dropping overlay frame for member {to} — not directly reachable and no relay available"
                                );
                            }
                        }
                    }
                }
            }
            // A frame from a peer → deliver / relay / merge gossip.
            inbound = transport.recv_from() => {
                let Ok((frame, from)) = inbound else { break };
                // Open the frame first: post-P-C5 the wire header is sealed + floated, so
                // the only trustworthy sender id is the AUTHENTICATED one `recv` returns
                // (a raw plaintext parse recovers nothing). `None` ⇒ not ours / unopenable.
                let Some((src, msg)) = dp.recv(&frame) else {
                    // The frame did not open under our key. If its source IP matches a
                    // peer we know how to reach, this is the split-brain signal — the
                    // peer is on a different mesh or epoch — so record it for the
                    // supervisor to warn on. Otherwise it's internet noise: drop quietly.
                    let known = links
                        .lock()
                        .unwrap()
                        .values()
                        .any(|l| l.endpoint.ip() == from.ip());
                    if known {
                        let mut f = fails.lock().unwrap();
                        let e = f.entry(from.ip()).or_default();
                        e.count += 1;
                        e.last_ms = now_ms();
                    }
                    continue;
                };
                // Roaming + liveness: re-learn the sender's endpoint from the UDP source
                // on the spot, so a NAT'd / moved peer is reachable again (§6) — this is
                // what lets the exit reply to a client's real public address instead of a
                // stale advertised LAN one. Never learn our OWN id (a relayed/looped frame
                // can carry src==us); a self-entry pollutes the table and shows up as our
                // endpoint.
                if src != my_id {
                    let now = now_ms();
                    let mut l = links.lock().unwrap();
                    // A frame whose UDP source is some OTHER member's endpoint is a relayed
                    // hop, not `src` speaking to us directly. Keep `src` alive, but do NOT
                    // adopt the relay's address as `src`'s endpoint — that would pin us to
                    // the relay forever and pollute the gossip table (docs/RELAY.md).
                    let relayed = l.iter().any(|(m, lk)| *m != src && lk.endpoint == from);
                    let e = l.entry(src).or_insert(Link {
                        endpoint: from,
                        last_seen_ms: 0,
                        last_direct_ms: 0,
                    });
                    e.last_seen_ms = now;
                    if !relayed {
                        // Direct frame: this is the peer's real, current address.
                        let recovered = e.last_direct_ms == 0;
                        e.endpoint = from;
                        e.last_direct_ms = now;
                        if recovered {
                            eprintln!(
                                "meshrun: direct path to member {src} established ({from})"
                            );
                        }
                    }
                }
                match msg {
                    Inbound::Deliver(inner) => {
                        traffic.lock().unwrap().record(src, false, &inner, false);
                        let _ = tun.write_packet(&inner).await;
                    }
                    // Control frame: gossip (endpoint table) or a re-cipher announce,
                    // told apart by the first payload byte.
                    Inbound::Control(payload) => match payload.first().copied() {
                        Some(CTRL_GOSSIP) => {
                            let (table, reflect) = decode_gossip(&payload[1..]);
                            {
                                let mut l = links.lock().unwrap();
                                apply_gossip_table(&mut l, &table, my_id, now_ms());
                            }
                            // P-D3: a peer reaching us from a PUBLIC source observed our
                            // public NAT mapping and reflected it back. Adopt it as our
                            // advertised endpoint (unless pinned) so peers on other
                            // networks can reach us; the next gossip tick re-advertises it.
                            if !endpoint_pinned && is_public(from.ip()) {
                                if let Some(observed) = reflect {
                                    let mut me = my_endpoint.lock().unwrap();
                                    if *me != Some(observed) {
                                        eprintln!(
                                            "meshrun: learned public address {observed} (reflected by {from}) — re-advertising"
                                        );
                                        *me = Some(observed);
                                    }
                                }
                            }
                        }
                        // P-C3: a member re-ciphered the mesh. We could open this frame
                        // (so it's authentic), so swap our data plane to the new epoch
                        // in place and report it up to the supervisor.
                        Some(CTRL_RECIPHER) => {
                            if let Some(r) = decode_recipher(&payload[1..]) {
                                eprintln!("meshrun: re-cipher → epoch {} cipher {}", r.epoch, r.cipher);
                                dp.recipher(
                                    lattice_mesh::crypto::suite(&r.cipher, &r.secret, r.epoch),
                                    &r.secret,
                                );
                                let _ = loop_event.send(LoopEvent::Recipher(r));
                            }
                        }
                        // P-C7: an attack alert or the creator's all-clear — hand it
                        // up so the supervisor arms / cancels the destroy grace.
                        Some(tag @ (CTRL_ATTACK | CTRL_ALLCLEAR)) => {
                            let _ = loop_event.send(LoopEvent::Control(tag));
                        }
                        // Membership roster gossip — hand the cert bytes up to the
                        // supervisor to merge + re-validate (the frame already opened, so
                        // it came from a member sharing this mesh's secret).
                        Some(CTRL_ROSTER) => {
                            let _ = loop_event.send(LoopEvent::Roster(payload[1..].to_vec()));
                        }
                        // Membership revocation gossip — hand the signed expulsions up to
                        // the supervisor to merge + re-validate (same path as the roster).
                        Some(CTRL_REVOKE) => {
                            let _ = loop_event.send(LoopEvent::Revoke(payload[1..].to_vec()));
                        }
                        // SDN flow-table gossip — the supervisor adopts a newer version and
                        // sends it back down via LoopCmd::SetFlows to apply to the data plane.
                        Some(CTRL_FLOWS) => {
                            let _ = loop_event.send(LoopEvent::Flows(payload[1..].to_vec()));
                        }
                        // Service-registry gossip — hand the advertised services up to the
                        // supervisor to merge (soft state, newest-per-(member, proto) wins).
                        Some(CTRL_REGISTRY) => {
                            let _ = loop_event.send(LoopEvent::Registry(payload[1..].to_vec()));
                        }
                        _ => {}
                    },
                    // P5 relay: we're a hop, not the destination — pass the frame on
                    // unchanged (we don't need to decrypt the body to forward). We are the
                    // relay node here (docs/RELAY.md). Never forward back toward the sender
                    // (a frame whose dst we'd reach via `src`'s own address would loop).
                    Inbound::Forward { to } => {
                        let endpoint = links.lock().unwrap().get(&to).map(|l| l.endpoint);
                        match endpoint {
                            Some(addr) if addr != from => {
                                let _ = transport.send_to(&frame, addr).await;
                            }
                            Some(_) => {} // would echo straight back to where it came from — drop
                            None => {
                                let last = relay_log_at.get(&to).copied().unwrap_or(0);
                                let now = now_ms();
                                if now.saturating_sub(last) >= RELAY_LOG_THROTTLE_MS {
                                    relay_log_at.insert(to, now);
                                    eprintln!(
                                        "meshrun: relay asked to forward to member {to} but its endpoint is unknown — dropping"
                                    );
                                }
                            }
                        }
                    }
                }
            }
            // Every ~20s: gossip our endpoint table to each known peer (also the NAT
            // keepalive + liveness ping). The first tick fires immediately → fast
            // bootstrap from the invite-seeded links.
            _ = gossip.tick() => {
                let now = now_ms();
                let my_ep = *my_endpoint.lock().unwrap();
                let gossip_exit = *exit.lock().unwrap();
                let (peers, table, snapshot) = {
                    let l = links.lock().unwrap();
                    let mut table: Vec<(MemberId, SocketAddr)> =
                        l.iter().map(|(m, lk)| (*m, lk.endpoint)).collect();
                    if let Some(ep) = my_ep {
                        table.push((my_id, ep));
                    }
                    // (member, endpoint, is-its-direct-path-fresh)
                    let peers: Vec<(MemberId, SocketAddr, bool)> = l
                        .iter()
                        .map(|(m, lk)| (*m, lk.endpoint, directly_reachable(lk, now)))
                        .collect();
                    (peers, table, l.clone())
                };
                for (m, addr, direct) in peers {
                    // Per-peer payload: the shared table + a `self` line telling THIS
                    // peer where we observe it, so a NAT'd peer learns its public
                    // address from us if we're public (P-D3). Tagged as gossip.
                    let mut payload = vec![CTRL_GOSSIP];
                    payload.extend_from_slice(&encode_gossip(&table, Some(addr)));
                    // Always send DIRECT — this is also the NAT-punch attempt that lets a
                    // direct path (re)form, so a relayed peer upgrades to direct (docs/RELAY.md).
                    let _ = transport.send_to(&dp.seal_control(m, &payload), addr).await;
                    // If the direct path is stale, ALSO keepalive via a relay so liveness +
                    // the relay path stay up and the peer hears us (its replies then relay
                    // back). No reflexion on the relayed copy (we don't observe them directly).
                    if !direct {
                        if let Some((_rm, raddr)) = pick_relay(&snapshot, m, gossip_exit, now) {
                            let mut rpayload = vec![CTRL_GOSSIP];
                            rpayload.extend_from_slice(&encode_gossip(&table, None));
                            let _ = transport.send_to(&dp.seal_control(m, &rpayload), raddr).await;
                        }
                    }
                }
            }
            // A command from the supervisor: re-cipher (P-C3) or send a tagged Control
            // signal to peers (P-C7 attack alert / all-clear).
            Some(cmd) = loop_cmd.recv() => match cmd {
                LoopCmd::Recipher(r, peers) => {
                    // Announce with the CURRENT (old) cipher so present members read it,
                    // then swap our own data plane and report back up.
                    let mut payload = vec![CTRL_RECIPHER];
                    payload.extend_from_slice(&encode_recipher(&r));
                    for m in peers {
                        let endpoint = links.lock().unwrap().get(&m).map(|l| l.endpoint);
                        if let Some(addr) = endpoint {
                            let _ = transport.send_to(&dp.seal_control(m, &payload), addr).await;
                        }
                    }
                    eprintln!("meshrun: re-ciphered (initiator) → epoch {} cipher {}", r.epoch, r.cipher);
                    dp.recipher(
                        lattice_mesh::crypto::suite(&r.cipher, &r.secret, r.epoch),
                        &r.secret,
                    );
                    let _ = loop_event.send(LoopEvent::Recipher(r));
                }
                LoopCmd::SetFlows(flows) => {
                    dp.set_flows(flows); // apply a programmed table to the live data plane
                }
                LoopCmd::SendControl(tag, body, peers) => {
                    let mut payload = vec![tag];
                    payload.extend_from_slice(&body);
                    for m in peers {
                        let endpoint = links.lock().unwrap().get(&m).map(|l| l.endpoint);
                        if let Some(addr) = endpoint {
                            let _ = transport.send_to(&dp.seal_control(m, &payload), addr).await;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use lattice_mesh::crypto::suite;
    use lattice_net::memory::duplex;
    use lattice_tun::memory::MemoryTun;

    fn dp(my_id: MemberId) -> MeshDataPlane {
        // Mesh 3, overlay prefix 100.80, shared secret ⇒ same key for both nodes.
        MeshDataPlane::new(
            3,
            my_id,
            [100, 80],
            suite("default", &[42u8; 32], 0),
            &[42u8; 32],
            lattice_mesh::charter::HeaderPlacement::Random,
        )
    }

    fn exit(member: Option<MemberId>) -> SharedExit {
        Arc::new(Mutex::new(member))
    }

    fn ep(addr: Option<SocketAddr>) -> SharedEndpoint {
        Arc::new(Mutex::new(addr))
    }

    // Dummy re-cipher channels for tests that don't exercise P-C3: the cmd receiver's
    // sender is dropped (recv → None → branch disabled); the applied sender's receiver
    // is dropped (send is a harmless error).
    fn dummy_cmd() -> LoopCmdRx {
        tokio::sync::mpsc::unbounded_channel().1
    }
    fn dummy_applied() -> LoopEventTx {
        tokio::sync::mpsc::unbounded_channel().0
    }
    fn no_fails() -> DecryptFails {
        Arc::new(Mutex::new(HashMap::new()))
    }
    fn no_traffic() -> SharedTraffic {
        Arc::new(Mutex::new(Traffic::default()))
    }

    fn ipv4_to(dst: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0u8; 28]; // 20B IPv4 header + 8B payload
        p[0] = 0x45; // v4, ihl 5
        p[16..20].copy_from_slice(&dst.octets());
        p[20..].copy_from_slice(b"ping-pkt");
        p
    }

    #[tokio::test]
    async fn two_nodes_in_mesh_packet_flows_end_to_end() {
        let a_addr: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let b_addr: SocketAddr = "10.0.0.2:2".parse().unwrap();
        let (ta, tb) = duplex(a_addr, b_addr);
        let (atun, ahandle) = MemoryTun::new();
        let (btun, mut bhandle) = MemoryTun::new();

        let a_eps = seed_links(std::iter::once((2u8, b_addr)).collect());
        let b_eps = seed_links(std::iter::once((1u8, a_addr)).collect());

        tokio::spawn(run(
            dp(1),
            Box::new(atun),
            ta,
            a_eps,
            exit(None),
            1,
            ep(None),
            false,
            dummy_cmd(),
            dummy_applied(),
            no_fails(),
            no_traffic(),
        )); // Alice (member 1)
        tokio::spawn(run(
            dp(2),
            Box::new(btun),
            tb,
            b_eps,
            exit(None),
            2,
            ep(None),
            false,
            dummy_cmd(),
            dummy_applied(),
            no_fails(),
            no_traffic(),
        )); // Bob   (member 2)

        // Inject an IP packet at Alice's TUN, destined for Bob's overlay IP.
        let packet = ipv4_to("100.80.3.2".parse().unwrap()); // mesh 3, member 2
        ahandle.inject.send(packet.clone()).await.unwrap();

        // It should come out of Bob's TUN, decrypted and intact.
        let got = tokio::time::timeout(Duration::from_secs(2), bhandle.observe.recv())
            .await
            .expect("timed out — packet did not cross the mesh")
            .expect("bob's tun closed");
        assert_eq!(got, packet);
    }

    #[tokio::test]
    async fn internet_bound_packet_is_routed_to_the_exit_member() {
        // Alice (member 1) sends all internet traffic via exit member 2 (Bob).
        let a_addr: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let b_addr: SocketAddr = "10.0.0.2:2".parse().unwrap();
        let (ta, tb) = duplex(a_addr, b_addr);
        let (atun, ahandle) = MemoryTun::new();
        let (btun, mut bhandle) = MemoryTun::new();

        let a_eps = seed_links(std::iter::once((2u8, b_addr)).collect());
        let b_eps = seed_links(std::iter::once((1u8, a_addr)).collect());

        tokio::spawn(run(
            dp(1),
            Box::new(atun),
            ta,
            a_eps,
            exit(Some(2)),
            1,
            ep(None),
            false,
            dummy_cmd(),
            dummy_applied(),
            no_fails(),
            no_traffic(),
        )); // exit = member 2
        tokio::spawn(run(
            dp(2),
            Box::new(btun),
            tb,
            b_eps,
            exit(None),
            2,
            ep(None),
            false,
            dummy_cmd(),
            dummy_applied(),
            no_fails(),
            no_traffic(),
        ));

        // A real internet destination (not in the mesh /24) → goes to the exit.
        let packet = ipv4_to("1.1.1.1".parse().unwrap());
        ahandle.inject.send(packet.clone()).await.unwrap();

        // The exit member receives the inner packet (it would then NAT it out).
        let got = tokio::time::timeout(Duration::from_secs(2), bhandle.observe.recv())
            .await
            .expect("timed out — internet packet did not reach the exit")
            .expect("exit tun closed");
        assert_eq!(got, packet);
    }

    /// A test-only in-memory N-node network: `send_to(addr)` delivers to whoever
    /// bound `addr`, so we can wire more than the point-to-point `duplex`.
    mod hub {
        use super::*;
        use tokio::sync::mpsc;

        type Inbox = mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>;

        #[derive(Clone, Default)]
        pub struct Hub(Arc<Mutex<std::collections::HashMap<SocketAddr, Inbox>>>);

        impl Hub {
            pub fn node(&self, addr: SocketAddr) -> Router {
                let (tx, rx) = mpsc::unbounded_channel();
                self.0.lock().unwrap().insert(addr, tx);
                Router {
                    me: addr,
                    hub: self.clone(),
                    rx: tokio::sync::Mutex::new(rx),
                }
            }
        }

        pub struct Router {
            me: SocketAddr,
            hub: Hub,
            rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>,
        }

        #[async_trait::async_trait]
        impl lattice_net::Transport for Router {
            async fn send_to(
                &self,
                data: &[u8],
                dest: SocketAddr,
            ) -> Result<(), lattice_net::NetError> {
                if let Some(tx) = self.hub.0.lock().unwrap().get(&dest) {
                    let _ = tx.send((data.to_vec(), self.me));
                }
                Ok(())
            }
            async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr), lattice_net::NetError> {
                self.rx
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| lattice_net::NetError::Discovery("hub closed".into()))
            }
            fn local_addr(&self) -> Result<SocketAddr, lattice_net::NetError> {
                Ok(self.me)
            }
        }
    }

    #[tokio::test]
    async fn relay_forwards_a_frame_to_an_unreachable_member() {
        let net = hub::Hub::default();
        let a: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:2".parse().unwrap();
        let c: SocketAddr = "10.0.0.3:3".parse().unwrap();
        let (atun, ahandle) = MemoryTun::new();
        let (btun, _bh) = MemoryTun::new();
        let (ctun, mut ch) = MemoryTun::new();

        // A reaches C only via the relay B; B reaches C directly.
        let a_eps = seed_links(std::iter::once((3u8, b)).collect());
        let b_eps = seed_links(std::iter::once((3u8, c)).collect());
        let c_eps = seed_links(HashMap::new());

        tokio::spawn(run(
            dp(1),
            Box::new(atun),
            net.node(a),
            a_eps,
            exit(None),
            1,
            ep(None),
            false,
            dummy_cmd(),
            dummy_applied(),
            no_fails(),
            no_traffic(),
        ));
        tokio::spawn(run(
            dp(2),
            Box::new(btun),
            net.node(b),
            b_eps,
            exit(None),
            2,
            ep(None),
            false,
            dummy_cmd(),
            dummy_applied(),
            no_fails(),
            no_traffic(),
        )); // relay hop
        tokio::spawn(run(
            dp(3),
            Box::new(ctun),
            net.node(c),
            c_eps,
            exit(None),
            3,
            ep(None),
            false,
            dummy_cmd(),
            dummy_applied(),
            no_fails(),
            no_traffic(),
        ));

        let packet = ipv4_to("100.80.3.3".parse().unwrap()); // member 3 = C
        ahandle.inject.send(packet.clone()).await.unwrap();

        let got = tokio::time::timeout(Duration::from_secs(2), ch.observe.recv())
            .await
            .expect("timed out — relayed packet did not reach C")
            .expect("c's tun closed");
        assert_eq!(got, packet);
    }

    #[test]
    fn gossip_payload_roundtrips() {
        let table = vec![
            (1u8, "10.0.0.1:42001".parse().unwrap()),
            (7u8, "203.0.113.9:42007".parse().unwrap()),
        ];
        let reflect: SocketAddr = "198.51.100.7:55000".parse().unwrap();
        let bytes = encode_gossip(&table, Some(reflect));
        let (got_table, got_reflect) = decode_gossip(&bytes);
        assert_eq!(got_table, table);
        assert_eq!(got_reflect, Some(reflect));
        // Garbage lines are skipped, the table survives, no `self` ⇒ no reflexion.
        let (t, r) = decode_gossip(b"not a line\n2 1.2.3.4:5\nbad");
        assert_eq!(t.len(), 1);
        assert_eq!(r, None);
    }

    /// A doesn't know C's endpoint at start; B knows both. After the first gossip
    /// tick (fires immediately) B tells A about C, and A can then reach C directly.
    #[tokio::test]
    async fn gossip_propagates_an_unknown_members_endpoint() {
        let net = hub::Hub::default();
        let a: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:2".parse().unwrap();
        let c: SocketAddr = "10.0.0.3:3".parse().unwrap();
        let (atun, _ah) = MemoryTun::new();
        let (btun, _bh) = MemoryTun::new();
        let (ctun, _ch) = MemoryTun::new();

        // A knows only B; B knows A and C; C knows only B. A has NO route to C.
        let a_eps = seed_links(std::iter::once((2u8, b)).collect());
        let b_eps = seed_links([(1u8, a), (3u8, c)].into_iter().collect());
        let c_eps = seed_links(std::iter::once((2u8, b)).collect());
        let a_view = Arc::clone(&a_eps);

        tokio::spawn(run(
            dp(1),
            Box::new(atun),
            net.node(a),
            a_eps,
            exit(None),
            1,
            ep(Some(a)),
            false,
            dummy_cmd(),
            dummy_applied(),
            no_fails(),
            no_traffic(),
        ));
        tokio::spawn(run(
            dp(2),
            Box::new(btun),
            net.node(b),
            b_eps,
            exit(None),
            2,
            ep(Some(b)),
            false,
            dummy_cmd(),
            dummy_applied(),
            no_fails(),
            no_traffic(),
        ));
        tokio::spawn(run(
            dp(3),
            Box::new(ctun),
            net.node(c),
            c_eps,
            exit(None),
            3,
            ep(Some(c)),
            false,
            dummy_cmd(),
            dummy_applied(),
            no_fails(),
            no_traffic(),
        ));

        // Poll A's link table until C (member 3) appears, learned via B's gossip.
        let learned = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(l) = a_view.lock().unwrap().get(&3u8) {
                    break l.endpoint;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("A never learned C's endpoint from gossip");
        assert_eq!(learned, c);
    }

    fn link(ep: &str, last_direct: u64) -> Link {
        Link {
            endpoint: ep.parse().unwrap(),
            last_seen_ms: last_direct.max(1),
            last_direct_ms: last_direct,
        }
    }

    #[test]
    fn pick_route_relays_through_a_public_node_when_direct_is_dead() {
        let now = 1_000_000u64;
        let pub_b: SocketAddr = "203.0.113.2:2".parse().unwrap();
        let mut links = HashMap::new();
        links.insert(2u8, link("203.0.113.2:2", now)); // B: public + directly reachable
        links.insert(3u8, link("10.0.0.3:3", 0)); // C: private, never heard directly

        // Direct to C is dead → relay through the public node B.
        assert_eq!(
            pick_route(&links, 3, None, now),
            Route::Relay {
                via: pub_b,
                member: 2
            }
        );

        // C's direct path is fresh → go direct.
        links.get_mut(&3).unwrap().last_direct_ms = now;
        assert!(matches!(pick_route(&links, 3, None, now), Route::Direct(_)));

        // Direct dead again AND no public relay (B is now private) → best-effort direct to C.
        links.get_mut(&3).unwrap().last_direct_ms = 0;
        links.insert(2u8, link("10.0.0.2:2", now));
        assert!(matches!(pick_route(&links, 3, None, now), Route::Direct(_)));

        // Unknown member with no relay → nothing.
        links.clear();
        assert_eq!(pick_route(&links, 9, None, now), Route::None);
    }

    #[test]
    fn gossip_updates_a_stale_endpoint_but_keeps_a_fresh_direct_one() {
        let now = 1_000_000u64;
        let mut links = HashMap::new();
        links.insert(4u8, link("192.168.0.4:42001", 0)); // 4: stale — never heard directly
        links.insert(5u8, link("10.0.0.5:42001", now)); // 5: fresh direct path
        let table: Vec<(MemberId, SocketAddr)> = vec![
            (1, "203.0.113.1:42001".parse().unwrap()), // our own id → must be ignored
            (4, "203.0.113.4:42001".parse().unwrap()), // gossip: 4 moved
            (5, "203.0.113.5:42001".parse().unwrap()), // gossip: 5 moved (but we have it direct)
            (9, "203.0.113.9:42001".parse().unwrap()), // a brand-new member
        ];
        apply_gossip_table(&mut links, &table, 1, now);

        // stale 4 → adopt the gossiped address (re-discovery the old or_insert couldn't do).
        assert_eq!(links[&4].endpoint, "203.0.113.4:42001".parse().unwrap());
        // fresh-direct 5 → keep our own, more accurate address (gossip ignored).
        assert_eq!(links[&5].endpoint, "10.0.0.5:42001".parse().unwrap());
        // brand-new 9 → inserted.
        assert_eq!(links[&9].endpoint, "203.0.113.9:42001".parse().unwrap());
        // our own id (1) → never learned from gossip.
        assert!(!links.contains_key(&1));
    }

    #[test]
    fn pick_relay_prefers_the_exit_and_skips_stale_or_private_peers() {
        let now = 1_000_000u64;
        let mut links = HashMap::new();
        links.insert(2u8, link("203.0.113.2:2", now)); // public + live
        links.insert(4u8, link("198.51.100.4:4", now)); // also public + live
        links.insert(5u8, link("203.0.113.5:5", now - 60_000)); // public but STALE direct
        links.insert(6u8, link("10.0.0.6:6", now)); // live but PRIVATE
                                                    // Exit (member 4) is preferred when it qualifies.
        assert_eq!(
            pick_relay(&links, 3, Some(4), now),
            Some((4, "198.51.100.4:4".parse().unwrap()))
        );
        // No exit hint → any live public peer (2 or 4); stale (5) and private (6) excluded.
        let r = pick_relay(&links, 3, None, now).unwrap();
        assert!(
            r.0 == 2 || r.0 == 4,
            "relay must be a live public peer, got {}",
            r.0
        );
        // Never relay through the target itself.
        assert_ne!(pick_relay(&links, 4, Some(4), now).map(|(m, _)| m), Some(4));
    }

    #[test]
    fn is_public_classifies_addresses() {
        let pub_ = |s: &str| is_public(s.parse().unwrap());
        assert!(pub_("203.0.113.10")); // a public exit node (RFC 5737 example range)
        assert!(pub_("203.0.113.9"));
        assert!(!pub_("10.0.0.5")); // campus LAN
        assert!(!pub_("192.168.0.5"));
        assert!(!pub_("172.16.4.4"));
        assert!(!pub_("100.100.0.1")); // CGNAT
        assert!(!pub_("127.0.0.1"));
        assert!(!pub_("169.254.1.1"));
    }

    /// P-D3: a NAT'd node (B) advertises only its LAN address; a PUBLIC peer (A)
    /// observes B's public mapping and reflects it in gossip. B adopts it as its own
    /// advertised endpoint, so other-network peers can later reach B.
    #[tokio::test]
    async fn reflexion_from_a_public_peer_upgrades_our_endpoint() {
        let net = hub::Hub::default();
        // A is public; B sits behind NAT — the hub delivers B's frames to A stamped
        // with B's *public* source (what A would see on the internet).
        let a_pub: SocketAddr = "198.51.100.10:41000".parse().unwrap();
        let b_lan: SocketAddr = "10.0.0.2:2".parse().unwrap();
        let b_public: SocketAddr = "203.0.113.55:50000".parse().unwrap();
        let (atun, _ah) = MemoryTun::new();
        let (btun, _bh) = MemoryTun::new();

        // A knows B at its public address; B knows A. B advertises only its LAN addr.
        let a_eps = seed_links(std::iter::once((2u8, b_public)).collect());
        let b_eps = seed_links(std::iter::once((1u8, a_pub)).collect());
        let b_ep = ep(Some(b_lan));
        let b_view = Arc::clone(&b_ep);

        // A is pinned-public; B is not pinned and starts at its LAN address.
        tokio::spawn(run(
            dp(1),
            Box::new(atun),
            net.node(a_pub),
            a_eps,
            exit(None),
            1,
            ep(Some(a_pub)),
            true,
            dummy_cmd(),
            dummy_applied(),
            no_fails(),
            no_traffic(),
        ));
        tokio::spawn(run(
            dp(2),
            Box::new(btun),
            net.node(b_public),
            b_eps,
            exit(None),
            2,
            b_ep,
            false,
            dummy_cmd(),
            dummy_applied(),
            no_fails(),
            no_traffic(),
        ));

        // B should adopt the public address A reflected (the `self` line in A's gossip).
        let upgraded = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let cur = *b_view.lock().unwrap();
                if cur == Some(b_public) {
                    break cur;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("B never upgraded its endpoint from A's reflexion");
        assert_eq!(upgraded, Some(b_public));
    }

    #[test]
    fn recipher_payload_roundtrips() {
        let r = Recipher {
            epoch: 7,
            cipher: "timewindow".into(),
            secret: [3u8; 32],
        };
        let got = decode_recipher(&encode_recipher(&r)).unwrap();
        assert_eq!(got.epoch, 7);
        assert_eq!(got.cipher, "timewindow");
        assert_eq!(got.secret, [3u8; 32]);
        assert!(decode_recipher(b"short").is_none());
    }

    /// P-C3 end-to-end: A initiates a re-cipher (via the cmd channel); the announce
    /// reaches B (read with the OLD cipher), both swap to the new epoch in place, and
    /// traffic keeps flowing on the new key.
    #[tokio::test]
    async fn recipher_rotates_both_nodes_and_traffic_keeps_flowing() {
        let a_addr: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let b_addr: SocketAddr = "10.0.0.2:2".parse().unwrap();
        let (ta, tb) = duplex(a_addr, b_addr);
        let (atun, ahandle) = MemoryTun::new();
        let (btun, mut bhandle) = MemoryTun::new();
        let a_eps = seed_links(std::iter::once((2u8, b_addr)).collect());
        let b_eps = seed_links(std::iter::once((1u8, a_addr)).collect());

        let (a_cmd_tx, a_cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let (b_applied_tx, mut b_applied_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(run(
            dp(1),
            Box::new(atun),
            ta,
            a_eps,
            exit(None),
            1,
            ep(None),
            false,
            a_cmd_rx,
            dummy_applied(),
            no_fails(),
            no_traffic(),
        ));
        tokio::spawn(run(
            dp(2),
            Box::new(btun),
            tb,
            b_eps,
            exit(None),
            2,
            ep(None),
            false,
            dummy_cmd(),
            b_applied_tx,
            no_fails(),
            no_traffic(),
        ));

        // Baseline: a packet flows on the original cipher.
        let p1 = ipv4_to("100.80.3.2".parse().unwrap());
        ahandle.inject.send(p1.clone()).await.unwrap();
        let got1 = tokio::time::timeout(Duration::from_secs(2), bhandle.observe.recv())
            .await
            .expect("baseline packet timed out")
            .unwrap();
        assert_eq!(got1, p1);

        // A re-ciphers to a fresh secret; wait for B to report it applied.
        a_cmd_tx
            .send(LoopCmd::Recipher(
                Recipher {
                    epoch: 1,
                    cipher: "default".into(),
                    secret: [99u8; 32],
                },
                vec![2],
            ))
            .unwrap();
        let ev = tokio::time::timeout(Duration::from_secs(2), b_applied_rx.recv())
            .await
            .expect("B never applied the re-cipher")
            .unwrap();
        let LoopEvent::Recipher(applied) = ev else {
            panic!("expected a Recipher event");
        };
        assert_eq!(applied.epoch, 1);

        // Traffic still flows — now on the new key.
        let p2 = ipv4_to("100.80.3.2".parse().unwrap());
        ahandle.inject.send(p2.clone()).await.unwrap();
        let got2 = tokio::time::timeout(Duration::from_secs(2), bhandle.observe.recv())
            .await
            .expect("post-re-cipher packet timed out")
            .unwrap();
        assert_eq!(got2, p2);
    }
}
