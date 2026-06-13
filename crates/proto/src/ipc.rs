//! The contract between the privileged daemon and its unprivileged clients
//! (the CLI and the Tauri GUI). Requests go client→daemon, responses come back.
//!
//! Transport is a local-only channel (Unix socket / Windows named pipe); these
//! types are the payloads, serialized as JSON for easy cross-language consumption
//! from the GUI frontend.

use serde::{Deserialize, Serialize};

use crate::{NodeId, PeerInfo, VirtualIp};

/// A command from a client to the daemon.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Bring the mesh interface up.
    Up,
    /// Tear the mesh interface down.
    Down,
    /// Current node + mesh status.
    Status,
    /// List known peers.
    Peers,
    /// Route this node's internet traffic through `node_id` (or `None` to stop
    /// using an exit node and go direct again).
    SetExit { node_id: Option<NodeId> },
    /// Allow (or stop allowing) this node to act as an exit for others.
    AllowExit { enabled: bool },
    /// Manually pin a peer by node id + physical address — connect across the
    /// internet without discovery (e.g. to a port-forwarded node).
    AddPeer {
        node_id: NodeId,
        addr: std::net::SocketAddr,
    },
    /// Set (or clear with `None`) the relay this node uses to reach peers that
    /// can't be connected to directly.
    SetRelay { addr: Option<std::net::SocketAddr> },
    /// Reach a peer (by node id) through the configured relay.
    RelayPeer { node_id: NodeId },
    /// Live traffic flows seen crossing the tunnel — what is talking to what.
    Flows,
    /// This node's membership / network status.
    NetworkInfo,
    /// Adopt a membership certificate (hex token) issued for us — join its network.
    JoinNetwork { token: String },
    /// Admin only: issue a membership cert for `node_id`; returns a join token.
    IssueCert {
        node_id: NodeId,
        label: Option<String>,
    },
    /// Admin only: evict a member (revoke its certificate) by node id.
    RevokeMember { node_id: NodeId },
    /// Admin only: designate (or undesignate) a member as a relay. Published in
    /// the signed `NetworkManifest`; nodes route unreachable pairs through it.
    DesignateRelay { node_id: NodeId, on: bool },
    /// Admin only: list the members this node's CA has issued certs to.
    Members,
    /// Admin: the crypto suites this node can run (the swap-lab catalogue).
    CryptoSuites,
    /// Admin: the active crypto suite.
    CryptoCurrent,
    /// Admin: swap the active crypto suite by name → drops + re-handshakes all
    /// sessions under it. SECURITY-SENSITIVE (changes the live tunnel crypto), so
    /// gated by the `--admin-allow` capability list like the packet capture.
    SetCryptoSuite { name: String },
    /// Admin: per-suite handshake comparison metrics (init/resp bytes, median ms).
    CryptoStats,
    /// Admin: per-peer live session detail (suite, age, rekey countdown, counters).
    SessionDetails,
    /// Health check: every virtual IP on the mesh (this node + all peers) in one
    /// shot. SECURITY-SENSITIVE — it hands out the whole network's address map,
    /// so the daemon only answers a caller whose process name is on its
    /// `--health-allow` list (default `minisync`). See docs/HEALTH_CHECK.md.
    HealthCheck,
    /// Admin: start capturing per-packet detail into the daemon's bounded ring
    /// buffer. SECURITY-SENSITIVE — captured packets are DECRYPTED plaintext, so
    /// this is gated by the `--admin-allow` process-name list (empty = disabled).
    /// See docs/ADMIN_CONSOLE.md §B.
    CaptureStart { filter: CaptureFilter },
    /// Admin: stop capturing and clear the packet ring.
    CaptureStop,
    /// Admin: report the current capture state without draining packets.
    CaptureStatus,
    /// Admin: drain captured packets with `seq > after` (cursor poll), oldest
    /// first. Pass `after: 0` for the first poll.
    Packets { after: u64 },
}

/// The daemon's reply.
///
/// Adjacently tagged (`{"ok": <variant>, "data": <payload>}`): a sequence payload
/// like `Peers(Vec<…>)` cannot be *internally* tagged (serde can only inline a
/// tag into a map), so the content lives in a separate `data` field.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "ok", content = "data", rename_all = "snake_case")]
pub enum Response {
    Status(NodeStatus),
    Peers(Vec<PeerInfo>),
    Flows(Vec<FlowRecord>),
    NetworkInfo(NetworkInfo),
    Members(Vec<MemberEntry>),
    /// Every virtual IP on the mesh (this node + all peers), from `HealthCheck`.
    Health(Vec<HealthEntry>),
    /// State of the packet capture (from CaptureStart/Stop/Status).
    CaptureState(CaptureState),
    /// Captured packets newer than the polled cursor (from `Packets`).
    Packets(Vec<PacketRecord>),
    /// The crypto suites this node can run (from `CryptoSuites`).
    CryptoSuites(Vec<CryptoSuiteInfo>),
    /// The active crypto suite (from `CryptoCurrent`).
    CryptoSuite(CryptoSuiteInfo),
    /// Per-suite handshake comparison metrics (from `CryptoStats`).
    CryptoStats(Vec<SuiteStat>),
    /// Per-peer live session detail (from `SessionDetails`).
    SessionDetails(Vec<SessionDetail>),
    /// A join token (hex-encoded membership cert) handed back from `IssueCert`.
    Token(String),
    /// A command that returns no data succeeded.
    Done,
    /// Something went wrong; `message` is human-readable.
    Error {
        message: String,
    },
}

/// Snapshot of this node's state for the GUI dashboard.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeStatus {
    pub id: NodeId,
    pub virtual_ip: Option<VirtualIp>,
    /// Our public (reflexive) address as seen via STUN, if known.
    pub public_addr: Option<std::net::SocketAddr>,
    pub running: bool,
    pub peer_count: usize,
    /// The peer we're routing internet traffic through, if any.
    pub exit_node: Option<NodeId>,
    /// Whether we're acting as an exit node for others.
    pub is_exit: bool,
    /// The relay address currently configured, if any.
    pub relay: Option<std::net::SocketAddr>,
}

/// This node's membership status for the GUI/CLI network panel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// The network (mesh) id this node belongs to, hex — `None` in open mode.
    pub network_id: Option<String>,
    /// Short fingerprint of the network id, for display.
    pub fingerprint: Option<String>,
    /// Whether this node holds the network CA key (can issue/revoke).
    pub is_admin: bool,
    /// How many members the CA has issued certs to (admin only; else 0).
    pub member_count: usize,
    /// How many revocations this node currently knows about.
    pub revocation_count: usize,
}

/// One node's entry in a mesh health-check report: its virtual IP, a short id
/// fingerprint, and its reachability from this node's point of view.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthEntry {
    /// The node's overlay (virtual) IP.
    pub virtual_ip: VirtualIp,
    /// Short fingerprint of the node id, for display.
    pub fingerprint: String,
    /// "self" for this node, else the peer status ("connected", "connecting",
    /// "known", "lost").
    pub status: String,
}

/// Optional narrowing for a packet capture. An empty filter (all `None`)
/// captures every plaintext packet crossing the tunnel.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CaptureFilter {
    /// Only packets attributed to this peer (matched against its short
    /// fingerprint, case-insensitive prefix).
    pub peer: Option<String>,
    /// Only this protocol ("tcp", "udp", "icmp", or a raw number).
    pub protocol: Option<String>,
    /// Only flows touching this port (as source or destination).
    pub port: Option<u16>,
}

/// The live state of the daemon's packet capture (from CaptureStart/Stop/Status).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaptureState {
    /// Whether capture is currently running.
    pub active: bool,
    /// Packets currently held in the ring.
    pub buffered: usize,
    /// Ring capacity (packets).
    pub cap: usize,
    /// Per-packet capture limit in bytes (longer packets are truncated).
    pub snaplen: usize,
    /// Packets evicted from the ring because it was full (history lost).
    pub dropped: u64,
    /// The filter in effect.
    pub filter: CaptureFilter,
}

/// One captured plaintext packet — the unit the admin packet inspector renders.
/// `bytes` holds the captured packet starting at the IPv4 header, truncated to
/// the capture snaplen; `length` is the packet's true (pre-truncation) length.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketRecord {
    /// Monotonic capture sequence number (the cursor for `Packets { after }`).
    pub seq: u64,
    /// Wall-clock capture time, milliseconds since the Unix epoch.
    pub at_ms: u64,
    /// Direction relative to this node: "tx" (outbound) or "rx" (inbound).
    pub dir: String,
    /// Short fingerprint of the peer carrying this packet.
    pub peer: Option<String>,
    /// Protocol name ("TCP", "UDP", "ICMP", "IP/<n>").
    pub protocol: String,
    /// Source endpoint ("ip" or "ip:port").
    pub src: String,
    /// Destination endpoint ("ip" or "ip:port").
    pub dst: String,
    /// True packet length in bytes (may exceed `bytes.len()` if truncated).
    pub length: u32,
    /// TCP flags, e.g. "SYN,ACK" (only for TCP).
    pub tcp_flags: Option<String>,
    /// TCP sequence number (only for TCP).
    pub tcp_seq: Option<u32>,
    /// TCP acknowledgement number (only for TCP).
    pub tcp_ack: Option<u32>,
    /// The captured packet bytes (IPv4 header onward), snaplen-truncated.
    pub bytes: Vec<u8>,
}

/// One member in an admin node's registry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberEntry {
    pub node_id: String,
    pub fingerprint: String,
    pub serial: u64,
    pub label: Option<String>,
    pub revoked: bool,
    /// Whether the admin has designated this member as a relay.
    #[serde(default)]
    pub relay: bool,
}

/// One crypto suite in the swap-lab catalogue. The `spec` is split into its Noise
/// components so the console can show a side-by-side comparison.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoSuiteInfo {
    /// Stable selector name, e.g. `noise-ik-aesgcm`.
    pub name: String,
    /// Noise handshake pattern, e.g. `IK`.
    pub pattern: String,
    /// Diffie-Hellman group, e.g. `25519`.
    pub dh: String,
    /// AEAD cipher, e.g. `ChaChaPoly` / `AESGCM`.
    pub aead: String,
    /// Hash function, e.g. `BLAKE2s` / `SHA256`.
    pub hash: String,
    /// Whether this is the node's active suite.
    pub active: bool,
}

/// Aggregated handshake metrics for one suite — the swap-lab comparison row.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SuiteStat {
    pub name: String,
    /// Handshakes completed under this suite (sample size).
    pub handshakes: u64,
    /// Bytes on the wire for the most recent HANDSHAKE_INIT.
    pub init_bytes: u32,
    /// Bytes on the wire for the most recent HANDSHAKE_RESP.
    pub resp_bytes: u32,
    /// Median initiator handshake wall-clock (INIT sent → session established), ms.
    pub median_ms: u32,
}

/// Live detail for one peer session — the swap-lab session inspector (read-only).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionDetail {
    /// Peer fingerprint (short node id).
    pub peer: String,
    /// Crypto suite this session was established under.
    pub suite: String,
    /// How long the session has been alive.
    pub age_secs: u64,
    /// Seconds until a proactive rekey is due (negative once overdue).
    pub rekey_in_secs: i64,
    /// Outbound AEAD counter (packets sealed).
    pub send_counter: u64,
    /// Highest inbound packet counter accepted by the replay window.
    pub replay_latest: u64,
    /// Packets the replay window rejected (replays / too old).
    pub replay_rejects: u64,
}

/// One aggregated traffic flow observed crossing the tunnel. The engine groups
/// packets by `(peer, protocol, local endpoint, remote endpoint)` and counts
/// bytes/packets in each direction — this is what the GUI's traffic monitor
/// renders so the user can see exactly what is flowing between peers.
///
/// "Local" is this node's side of the conversation (our virtual IP/port);
/// "remote" is the other end — a peer's virtual IP for mesh traffic, or a public
/// address for internet traffic carried through an exit node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowRecord {
    /// The mesh peer carrying this flow, if attributable to one.
    pub peer: Option<NodeId>,
    /// Transport protocol name: "TCP", "UDP", "ICMP", or "IP/<n>".
    pub protocol: String,
    /// Our side of the conversation, "ip" or "ip:port".
    pub local: String,
    /// The far side, "ip" or "ip:port".
    pub remote: String,
    /// Packets/bytes we sent out over this flow (local → remote).
    pub tx_packets: u64,
    pub tx_bytes: u64,
    /// Packets/bytes we received on this flow (remote → local).
    pub rx_packets: u64,
    pub rx_bytes: u64,
    /// Seconds since the flow last carried a packet (lower = more recent).
    pub last_active_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every response variant — including the `Vec` payload that broke internal
    /// tagging — must serialize to JSON and parse back.
    #[test]
    fn responses_round_trip_as_json() {
        let cases = vec![
            Response::Status(NodeStatus {
                id: NodeId([1u8; 32]),
                virtual_ip: None,
                public_addr: None,
                running: true,
                peer_count: 0,
                exit_node: None,
                is_exit: false,
                relay: None,
            }),
            Response::Peers(vec![]),
            Response::Flows(vec![FlowRecord {
                peer: Some(NodeId([2u8; 32])),
                protocol: "TCP".into(),
                local: "100.64.0.1:54321".into(),
                remote: "100.64.0.2:22".into(),
                tx_packets: 3,
                tx_bytes: 180,
                rx_packets: 2,
                rx_bytes: 1400,
                last_active_secs: 1,
            }]),
            Response::Done,
            Response::Error {
                message: "nope".into(),
            },
        ];
        for r in cases {
            let json = serde_json::to_string(&r).expect("serialize");
            let back: Response = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(format!("{r:?}"), format!("{back:?}"), "round-trip: {json}");
        }
    }
}
