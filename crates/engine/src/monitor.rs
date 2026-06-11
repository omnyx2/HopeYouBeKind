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
//! State is bounded: at most [`MAX_FLOWS`] are kept, evicting the
//! least-recently-active when full, so a long-running node can't grow unbounded.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::Instant;

use lattice_proto::ipc::FlowRecord;
use lattice_proto::NodeId;

/// Cap on the number of distinct flows tracked at once. Beyond this, the
/// least-recently-active flow is evicted to make room.
const MAX_FLOWS: usize = 512;

/// Which way a packet was travelling relative to this node.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    /// Left this node toward a peer (read from our TUN, sealed, sent).
    Tx,
    /// Arrived from a peer (received, opened) and delivered locally.
    Rx,
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

/// A passive, thread-safe collector of tunnel traffic. Cheap to clone the `Arc`
/// the engine holds; locking is brief (per-packet counter bump).
#[derive(Default)]
pub struct TrafficMonitor {
    flows: Mutex<HashMap<FlowKey, FlowStat>>,
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

/// The fields we pull out of an IPv4 packet to classify a flow.
struct Parsed {
    protocol: u8,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

/// Parse the IPv4 header (and TCP/UDP ports when present). Returns `None` for
/// non-IPv4 or too-short packets.
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

    Some(Parsed {
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
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
        let mut p = vec![0u8; total.max(24)];
        p[0] = 0x45; // IPv4, IHL 5
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
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
}
