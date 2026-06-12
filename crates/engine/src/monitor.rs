//! Traffic monitor: a passive observer of every plaintext packet that crosses
//! the tunnel, so the GUI can show exactly what is flowing between peers.
//!
//! The engine records each decrypted packet here — outbound just before it is
//! sealed and sent, inbound just after it is opened. Packets are aggregated into
//! **flows** keyed by `(peer, protocol, local endpoint, remote endpoint)`, with
//! per-direction packet and byte counters. A flow's "local" side is always this
//! node (our virtual IP); "remote" is the peer's virtual IP for mesh traffic, or
//! a public address for internet traffic carried through an exit node.
//!
//! On top of the always-on flow aggregation there is an **opt-in per-packet
//! capture** (the admin packet inspector, docs/ADMIN_CONSOLE.md §B): when armed,
//! each matching packet is also pushed, snaplen-truncated, into a bounded ring
//! buffer that the admin console drains by cursor. Capture is off by default and
//! the hot path only pays an atomic load when it is.
//!
//! State is bounded: at most [`MAX_FLOWS`] flows and [`CAPTURE_CAP`] packets are
//! kept, evicting the oldest when full, so a long-running node can't grow
//! unbounded.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use lattice_proto::ipc::{CaptureFilter, CaptureState, FlowRecord, PacketRecord};
use lattice_proto::NodeId;

/// Cap on the number of distinct flows tracked at once. Beyond this, the
/// least-recently-active flow is evicted to make room.
const MAX_FLOWS: usize = 512;

/// Cap on the number of captured packets held in the ring at once.
const CAPTURE_CAP: usize = 4096;

/// Per-packet capture limit: bytes beyond this are not stored (the record still
/// reports the true `length`). Bounds memory and limits incidental capture.
const CAPTURE_SNAPLEN: usize = 2048;

/// Which way a packet was travelling relative to this node.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    /// Left this node toward a peer (read from our TUN, sealed, sent).
    Tx,
    /// Arrived from a peer (received, opened) and delivered locally.
    Rx,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::Tx => "tx",
            Direction::Rx => "rx",
        }
    }
}

/// The identity of a flow — both directions of one conversation collapse onto
/// the same key, so `tx` and `rx` counters accumulate on a single record.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    peer: NodeId,
    protocol: u8,
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
}

/// Running counters for one flow.
struct FlowStat {
    tx_packets: u64,
    tx_bytes: u64,
    rx_packets: u64,
    rx_bytes: u64,
    last: Instant,
}

/// One captured packet, kept in the ring until drained or evicted.
struct CapturedPacket {
    seq: u64,
    at_ms: u64,
    dir: Direction,
    peer: NodeId,
    parsed: Parsed,
    length: u32,
    bytes: Vec<u8>,
}

/// The parsed, ready-to-match form of a [`CaptureFilter`].
#[derive(Default)]
struct CompiledFilter {
    peer_fp: Option<String>,
    protocol: Option<u8>,
    port: Option<u16>,
}

impl CompiledFilter {
    fn compile(filter: &CaptureFilter) -> Self {
        CompiledFilter {
            peer_fp: filter
                .peer
                .as_ref()
                .map(|p| p.trim().to_lowercase())
                .filter(|p| !p.is_empty()),
            protocol: filter.protocol.as_ref().and_then(|p| protocol_number(p)),
            port: filter.port.filter(|p| *p != 0),
        }
    }

    /// Does a packet attributed to `peer` match this filter?
    fn matches(&self, peer: NodeId, parsed: &Parsed) -> bool {
        if let Some(fp) = &self.peer_fp {
            if !peer.fingerprint().to_lowercase().starts_with(fp) {
                return false;
            }
        }
        if let Some(proto) = self.protocol {
            if parsed.protocol != proto {
                return false;
            }
        }
        if let Some(port) = self.port {
            if parsed.src_port != port && parsed.dst_port != port {
                return false;
            }
        }
        true
    }
}

/// The opt-in per-packet capture ring.
struct Capture {
    filter: CaptureFilter,
    compiled: CompiledFilter,
    ring: VecDeque<CapturedPacket>,
    next_seq: u64,
    dropped: u64,
}

impl Default for Capture {
    fn default() -> Self {
        Capture {
            filter: CaptureFilter::default(),
            compiled: CompiledFilter::default(),
            ring: VecDeque::new(),
            next_seq: 1,
            dropped: 0,
        }
    }
}

/// A passive, thread-safe collector of tunnel traffic. Cheap to clone the `Arc`
/// the engine holds; locking is brief (per-packet counter bump). The per-packet
/// capture is a separate, opt-in layer gated by an atomic so the inactive path
/// stays lock-free.
#[derive(Default)]
pub struct TrafficMonitor {
    flows: Mutex<HashMap<FlowKey, FlowStat>>,
    capture_active: AtomicBool,
    capture: Mutex<Capture>,
}

impl TrafficMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one plaintext IP packet attributed to `peer`, travelling `dir`.
    /// Non-IPv4 or truncated packets are ignored (nothing to attribute).
    pub fn record(&self, peer: NodeId, dir: Direction, packet: &[u8]) {
        let Some(parsed) = parse_packet(packet) else {
            return;
        };
        // Normalise to (local, remote) so both directions share one key: on Tx we
        // are the source, on Rx we are the destination.
        let (local_ip, local_port, remote_ip, remote_port) = match dir {
            Direction::Tx => (
                parsed.src_ip,
                parsed.src_port,
                parsed.dst_ip,
                parsed.dst_port,
            ),
            Direction::Rx => (
                parsed.dst_ip,
                parsed.dst_port,
                parsed.src_ip,
                parsed.src_port,
            ),
        };
        let key = FlowKey {
            peer,
            protocol: parsed.protocol,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
        };
        let now = Instant::now();
        let len = packet.len() as u64;

        let mut flows = self.flows.lock().unwrap();
        let stat = flows.entry(key).or_insert_with(|| FlowStat {
            tx_packets: 0,
            tx_bytes: 0,
            rx_packets: 0,
            rx_bytes: 0,
            last: now,
        });
        match dir {
            Direction::Tx => {
                stat.tx_packets += 1;
                stat.tx_bytes += len;
            }
            Direction::Rx => {
                stat.rx_packets += 1;
                stat.rx_bytes += len;
            }
        }
        stat.last = now;

        // Bound memory: if we've gone over budget, drop the stalest flow. Only
        // runs on the insert that tipped us over, so it's rare.
        if flows.len() > MAX_FLOWS {
            if let Some(stale) = flows.iter().min_by_key(|(_, s)| s.last).map(|(k, _)| *k) {
                flows.remove(&stale);
            }
        }
        drop(flows);

        // Per-packet capture (opt-in). Lock-free fast path when not capturing.
        if self.capture_active.load(Ordering::Relaxed) {
            self.capture_packet(peer, dir, parsed, packet);
        }
    }

    /// Append a matching packet to the capture ring (called only while armed).
    fn capture_packet(&self, peer: NodeId, dir: Direction, parsed: Parsed, packet: &[u8]) {
        let mut cap = self.capture.lock().unwrap();
        if !cap.compiled.matches(peer, &parsed) {
            return;
        }
        let seq = cap.next_seq;
        cap.next_seq += 1;
        let at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let take = packet.len().min(CAPTURE_SNAPLEN);
        let pkt = CapturedPacket {
            seq,
            at_ms,
            dir,
            peer,
            parsed,
            length: packet.len() as u32,
            bytes: packet[..take].to_vec(),
        };
        cap.ring.push_back(pkt);
        while cap.ring.len() > CAPTURE_CAP {
            cap.ring.pop_front();
            cap.dropped += 1;
        }
    }

    /// Arm the capture with `filter`, clearing any previous buffer. Returns the
    /// new state.
    pub fn capture_start(&self, filter: CaptureFilter) -> CaptureState {
        {
            let mut cap = self.capture.lock().unwrap();
            cap.compiled = CompiledFilter::compile(&filter);
            cap.filter = filter;
            cap.ring.clear();
            cap.dropped = 0;
            // keep next_seq monotonic across restarts so stale cursors don't alias
        }
        self.capture_active.store(true, Ordering::Relaxed);
        self.capture_status()
    }

    /// Disarm the capture and clear its buffer. Returns the new state.
    pub fn capture_stop(&self) -> CaptureState {
        self.capture_active.store(false, Ordering::Relaxed);
        let mut cap = self.capture.lock().unwrap();
        cap.ring.clear();
        cap.dropped = 0;
        drop(cap);
        self.capture_status()
    }

    /// Current capture state, without draining packets.
    pub fn capture_status(&self) -> CaptureState {
        let active = self.capture_active.load(Ordering::Relaxed);
        let cap = self.capture.lock().unwrap();
        CaptureState {
            active,
            buffered: cap.ring.len(),
            cap: CAPTURE_CAP,
            snaplen: CAPTURE_SNAPLEN,
            dropped: cap.dropped,
            filter: cap.filter.clone(),
        }
    }

    /// Captured packets with `seq > after`, oldest first (cursor poll).
    pub fn packets_since(&self, after: u64) -> Vec<PacketRecord> {
        let cap = self.capture.lock().unwrap();
        cap.ring
            .iter()
            .filter(|p| p.seq > after)
            .map(|p| {
                let pr = &p.parsed;
                PacketRecord {
                    seq: p.seq,
                    at_ms: p.at_ms,
                    dir: p.dir.as_str().into(),
                    peer: Some(p.peer.fingerprint()),
                    protocol: protocol_name(pr.protocol),
                    src: fmt_endpoint(pr.src_ip, pr.src_port, pr.protocol),
                    dst: fmt_endpoint(pr.dst_ip, pr.dst_port, pr.protocol),
                    length: p.length,
                    tcp_flags: pr.tcp_flags.map(fmt_tcp_flags),
                    tcp_seq: pr.tcp_seq,
                    tcp_ack: pr.tcp_ack,
                    bytes: p.bytes.clone(),
                }
            })
            .collect()
    }

    /// A snapshot of all current flows, most-recently-active first.
    pub fn snapshot(&self) -> Vec<FlowRecord> {
        let flows = self.flows.lock().unwrap();
        let now = Instant::now();
        let mut out: Vec<FlowRecord> = flows
            .iter()
            .map(|(k, s)| FlowRecord {
                peer: Some(k.peer),
                protocol: protocol_name(k.protocol),
                local: fmt_endpoint(k.local_ip, k.local_port, k.protocol),
                remote: fmt_endpoint(k.remote_ip, k.remote_port, k.protocol),
                tx_packets: s.tx_packets,
                tx_bytes: s.tx_bytes,
                rx_packets: s.rx_packets,
                rx_bytes: s.rx_bytes,
                last_active_secs: now.duration_since(s.last).as_secs(),
            })
            .collect();
        out.sort_by(|a, b| {
            a.last_active_secs
                .cmp(&b.last_active_secs)
                .then_with(|| (b.tx_bytes + b.rx_bytes).cmp(&(a.tx_bytes + a.rx_bytes)))
        });
        out
    }
}

/// The fields we pull out of an IPv4 packet to classify a flow and (when
/// capturing) describe a packet.
#[derive(Clone, Copy)]
struct Parsed {
    protocol: u8,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    tcp_flags: Option<u8>,
    tcp_seq: Option<u32>,
    tcp_ack: Option<u32>,
}

/// Parse the IPv4 header (plus TCP/UDP ports, and TCP flags/seq/ack when
/// present). Returns `None` for non-IPv4 or too-short packets.
fn parse_packet(packet: &[u8]) -> Option<Parsed> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let protocol = packet[9];
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    // TCP (6) and UDP (17) carry ports in the first 4 bytes of their header.
    let (src_port, dst_port) = if matches!(protocol, 6 | 17) && packet.len() >= ihl + 4 {
        (
            u16::from_be_bytes([packet[ihl], packet[ihl + 1]]),
            u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]),
        )
    } else {
        (0, 0)
    };

    // TCP also carries seq (4..8), ack (8..12), and flags (low 6 bits of byte 13).
    let (tcp_flags, tcp_seq, tcp_ack) = if protocol == 6 && packet.len() >= ihl + 14 {
        (
            Some(packet[ihl + 13] & 0x3f),
            Some(u32::from_be_bytes([
                packet[ihl + 4],
                packet[ihl + 5],
                packet[ihl + 6],
                packet[ihl + 7],
            ])),
            Some(u32::from_be_bytes([
                packet[ihl + 8],
                packet[ihl + 9],
                packet[ihl + 10],
                packet[ihl + 11],
            ])),
        )
    } else {
        (None, None, None)
    };

    Some(Parsed {
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        tcp_flags,
        tcp_seq,
        tcp_ack,
    })
}

/// Human-readable protocol name for the GUI.
fn protocol_name(proto: u8) -> String {
    match proto {
        1 => "ICMP".into(),
        6 => "TCP".into(),
        17 => "UDP".into(),
        other => format!("IP/{other}"),
    }
}

/// Parse a protocol filter string ("tcp"/"udp"/"icmp"/"ip/<n>"/"<n>") to a number.
fn protocol_number(name: &str) -> Option<u8> {
    match name.trim().to_lowercase().as_str() {
        "icmp" => Some(1),
        "tcp" => Some(6),
        "udp" => Some(17),
        other => other
            .strip_prefix("ip/")
            .unwrap_or(other)
            .parse::<u8>()
            .ok(),
    }
}

/// Render the TCP flag bits as a compact "SYN,ACK" style string.
fn fmt_tcp_flags(flags: u8) -> String {
    const NAMES: [(u8, &str); 6] = [
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
    ];
    let set: Vec<&str> = NAMES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if set.is_empty() {
        "—".into()
    } else {
        set.join(",")
    }
}

/// Format an endpoint, omitting the `:0` placeholder for portless protocols.
fn fmt_endpoint(ip: Ipv4Addr, port: u16, proto: u8) -> String {
    if matches!(proto, 6 | 17) {
        format!("{ip}:{port}")
    } else {
        ip.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal IPv4+TCP packet from src:sport → dst:dport of `total` bytes.
    fn tcp_packet(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, total: usize) -> Vec<u8> {
        let mut p = vec![0u8; total.max(34)];
        p[0] = 0x45; // IPv4, IHL 5
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[33] = 0x12; // flags byte: SYN|ACK (0x02 | 0x10)
        p
    }

    #[test]
    fn both_directions_collapse_onto_one_flow() {
        let mon = TrafficMonitor::new();
        let peer = NodeId([9u8; 32]);
        let me = [100, 64, 0, 1];
        let them = [100, 64, 0, 2];

        // Our app:54321 → peer:22, then the reply peer:22 → our app:54321.
        mon.record(peer, Direction::Tx, &tcp_packet(me, 54321, them, 22, 60));
        mon.record(peer, Direction::Rx, &tcp_packet(them, 22, me, 54321, 1400));

        let flows = mon.snapshot();
        assert_eq!(flows.len(), 1, "the two directions must share one flow");
        let f = &flows[0];
        assert_eq!(f.protocol, "TCP");
        assert_eq!(f.local, "100.64.0.1:54321");
        assert_eq!(f.remote, "100.64.0.2:22");
        assert_eq!(f.tx_packets, 1);
        assert_eq!(f.tx_bytes, 60);
        assert_eq!(f.rx_packets, 1);
        assert_eq!(f.rx_bytes, 1400);
    }

    #[test]
    fn non_ipv4_is_ignored() {
        let mon = TrafficMonitor::new();
        mon.record(NodeId([1u8; 32]), Direction::Tx, &[0x60, 0, 0]); // IPv6-ish
        assert!(mon.snapshot().is_empty());
    }

    #[test]
    fn capture_is_off_until_armed_then_records_matching_packets() {
        let mon = TrafficMonitor::new();
        let peer = NodeId([9u8; 32]);
        let me = [100, 64, 0, 1];
        let them = [100, 64, 0, 2];

        // Not armed: nothing captured even though flows still aggregate.
        mon.record(peer, Direction::Tx, &tcp_packet(me, 1234, them, 22, 60));
        assert!(mon.packets_since(0).is_empty());
        assert!(!mon.capture_status().active);

        // Arm with a TCP/port-22 filter and send two packets (one matching).
        let st = mon.capture_start(CaptureFilter {
            peer: None,
            protocol: Some("tcp".into()),
            port: Some(22),
        });
        assert!(st.active);
        mon.record(peer, Direction::Tx, &tcp_packet(me, 4444, them, 22, 60)); // match
        mon.record(peer, Direction::Tx, &tcp_packet(me, 4444, them, 80, 60)); // wrong port

        let pkts = mon.packets_since(0);
        assert_eq!(pkts.len(), 1, "only the port-22 packet matches");
        let p = &pkts[0];
        assert_eq!(p.protocol, "TCP");
        assert_eq!(p.dst, "100.64.0.2:22");
        assert_eq!(p.dir, "tx");
        assert_eq!(p.tcp_flags.as_deref(), Some("SYN,ACK"));

        // Cursor poll past the last seq returns nothing.
        assert!(mon.packets_since(p.seq).is_empty());

        // Stop clears the buffer and disarms.
        let st = mon.capture_stop();
        assert!(!st.active);
        assert!(mon.packets_since(0).is_empty());
    }
}
