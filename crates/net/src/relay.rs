//! Relay (DERP-style) for peers that can't connect directly (e.g. both behind
//! CGNAT). A relay node is a dumb forwarder: it maps `node id -> last-seen
//! address` and shuttles relay frames between them. It never sees plaintext —
//! the Noise session stays end-to-end between the two endpoints.
//!
//! Clients use [`RelayTransport`], a decorator over their UDP transport:
//! - traffic addressed to a *relayed* peer is wrapped and sent to the relay;
//! - relay frames from the relay are unwrapped and surfaced to the engine as if
//!   they arrived directly — via a stable **synthetic address** per peer, so the
//!   engine needs no relay awareness at all.
//!
//! Frame: `[0xF0][dest node id (32)][src node id (32)][inner datagram]`. A frame
//! with an all-zero `dest` is a registration (tells the relay our address). The
//! `0xF0` tag is deliberately outside the `lattice_proto::wire::MessageType`
//! range (`0x01..=0x05`) so a relay node can demultiplex relay frames from mesh
//! frames on its *own mesh socket* — no separate relay port needed.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::{NetError, Transport};

/// Relay-frame tag. Must stay outside `wire::MessageType`'s `0x01..=0x05` so it
/// can't be mistaken for a mesh frame on a shared socket.
const RELAY: u8 = 0xF0;
const HDR: usize = 1 + 32 + 32;
const ZERO_ID: [u8; 32] = [0u8; 32];

/// Frame `inner` for delivery to `dest`, stamped with our id `src`.
pub fn encode(dest: &[u8; 32], src: &[u8; 32], inner: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(HDR + inner.len());
    f.push(RELAY);
    f.extend_from_slice(dest);
    f.extend_from_slice(src);
    f.extend_from_slice(inner);
    f
}

/// Parse a relay frame into `(dest, src, inner)`.
pub fn decode(buf: &[u8]) -> Option<([u8; 32], [u8; 32], &[u8])> {
    if buf.len() < HDR || buf[0] != RELAY {
        return None;
    }
    let mut dest = [0u8; 32];
    let mut src = [0u8; 32];
    dest.copy_from_slice(&buf[1..33]);
    src.copy_from_slice(&buf[33..65]);
    Some((dest, src, &buf[HDR..]))
}

// ===== L1 anonymity: opaque relay circuits (see docs/ANONYMITY.md) =====
// A DATA frame carries a per-leg opaque circuit id instead of plaintext node ids,
// so an underlay eavesdropper on one leg can't track the origin by its stable
// cert-bound identity. `[0xF2]` SETUP frames (handled at a higher layer over the
// origin↔relay Noise session) install circuits; here is the data-plane.

/// Opaque per-leg circuit id (never a node id).
pub type Cid = [u8; 16];
/// DATA frame tag: `[0xF1][cid:16][inner]`. Outside wire::MessageType (0x01..=0x05).
const CIRCUIT_DATA: u8 = 0xF1;
/// SETUP frame tag: `[0xF2][cid:16][noise-sealed setup]` — reserved; installs a circuit.
pub const CIRCUIT_SETUP: u8 = 0xF2;
const CIRCUIT_HDR: usize = 1 + 16;

/// Wrap `inner` for a circuit leg identified by `cid`.
pub fn encode_circuit(cid: &Cid, inner: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(CIRCUIT_HDR + inner.len());
    f.push(CIRCUIT_DATA);
    f.extend_from_slice(cid);
    f.extend_from_slice(inner);
    f
}

/// Parse a circuit DATA frame into `(cid, inner)`.
pub fn decode_circuit(buf: &[u8]) -> Option<(Cid, &[u8])> {
    if buf.len() < CIRCUIT_HDR || buf[0] != CIRCUIT_DATA {
        return None;
    }
    let mut cid = [0u8; 16];
    cid.copy_from_slice(&buf[1..17]);
    Some((cid, &buf[CIRCUIT_HDR..]))
}

/// A relay's circuit table: each INCOMING cid maps to the (outgoing cid, next addr).
/// A circuit installs BOTH directions (`cid_OR→(cid_RP, P_addr)` and
/// `cid_RP→(cid_OR, O_addr)`), so forwarding is direction-agnostic and a relayed
/// frame never carries a node id — only opaque, per-leg-distinct circuit ids.
#[derive(Default)]
pub struct CircuitTable {
    hops: HashMap<Cid, (Cid, SocketAddr)>,
}

impl CircuitTable {
    /// Install one direction of a circuit: a frame arriving on `in_cid` is rewritten
    /// to `out_cid` and sent to `out_addr`.
    pub fn install(&mut self, in_cid: Cid, out_cid: Cid, out_addr: SocketAddr) {
        self.hops.insert(in_cid, (out_cid, out_addr));
    }

    /// Forget a circuit leg (e.g. on teardown / timeout).
    pub fn remove(&mut self, in_cid: &Cid) {
        self.hops.remove(in_cid);
    }

    /// Rewrite a DATA frame to its next hop: returns `(rewritten frame, next addr)`,
    /// or `None` if `buf` isn't a DATA frame or no circuit matches its cid.
    pub fn forward(&self, buf: &[u8]) -> Option<(Vec<u8>, SocketAddr)> {
        let (in_cid, inner) = decode_circuit(buf)?;
        let (out_cid, out_addr) = self.hops.get(&in_cid)?;
        Some((encode_circuit(out_cid, inner), *out_addr))
    }
}

/// The relay forwarder loop: learn each sender's address, forward by dest id.
/// Run this on a publicly reachable UDP socket (`--relay-bind`).
pub async fn run_relay(socket: tokio::net::UdpSocket) -> std::io::Result<()> {
    let mut registry: HashMap<[u8; 32], SocketAddr> = HashMap::new();
    let mut buf = vec![0u8; 2048];
    loop {
        let (n, from) = socket.recv_from(&mut buf).await?;
        let Some((dest, src, inner)) = decode(&buf[..n]) else {
            continue;
        };
        registry.insert(src, from); // any frame registers the sender
        if dest != ZERO_ID {
            if let Some(&dest_addr) = registry.get(&dest) {
                let frame = encode(&dest, &src, inner);
                let _ = socket.send_to(&frame, dest_addr).await;
            }
        }
    }
}

/// Per-peer synthetic addresses (TEST-NET-1 `192.0.2.0/24`) that stand in for a
/// relayed peer's "endpoint" inside the engine — never put on the wire.
#[derive(Default)]
struct Synth {
    to_addr: HashMap<[u8; 32], SocketAddr>,
    to_id: HashMap<SocketAddr, [u8; 32]>,
    next: u8,
}

/// Wraps a transport so relayed peers look direct to the engine.
pub struct RelayTransport<T> {
    inner: T,
    relay_addr: Mutex<Option<SocketAddr>>,
    self_id: [u8; 32],
    synth: Mutex<Synth>,
    /// `node id -> last-seen address`, learned from relay frames while acting as a
    /// relay server, so we can forward by destination id (DERP-style).
    fwd: Mutex<HashMap<[u8; 32], SocketAddr>>,
    /// `peer id -> the relay address its frames last arrived through`. When a
    /// relayed frame reaches us, we remember which relay delivered it and reply to
    /// that peer back through the SAME relay — even if our own configured relay is
    /// a different (possibly unreachable) address. Makes the return path symmetric
    /// through whatever bridge actually works, which matters when the bridge is
    /// multi-homed and our handshake-time address for it is stale.
    relay_path: Mutex<HashMap<[u8; 32], SocketAddr>>,
    /// Whether this node forwards relay frames addressed to *other* nodes (it was
    /// designated a relay by the admin manifest). Off by default: a plain client
    /// only unwraps frames addressed to itself.
    relay_server: AtomicBool,
}

impl<T: Transport> RelayTransport<T> {
    /// `relay_addr = None` makes this a pure pass-through (no relay configured).
    pub fn new(inner: T, relay_addr: Option<SocketAddr>, self_id: [u8; 32]) -> Self {
        Self {
            inner,
            relay_addr: Mutex::new(relay_addr),
            self_id,
            synth: Mutex::new(Synth::default()),
            fwd: Mutex::new(HashMap::new()),
            relay_path: Mutex::new(HashMap::new()),
            relay_server: AtomicBool::new(false),
        }
    }

    /// Set (or clear) the relay address at runtime.
    pub fn set_relay(&self, addr: Option<SocketAddr>) {
        *self.relay_addr.lock().unwrap() = addr;
    }

    /// Become (or stop being) a relay server — forward relay frames destined for
    /// other nodes on this same mesh socket. Driven by the admin manifest: a node
    /// that finds itself in the manifest's `relays` list turns this on.
    pub fn set_relay_server(&self, on: bool) {
        self.relay_server.store(on, Ordering::Relaxed);
    }

    /// Whether we're currently acting as a relay server.
    pub fn is_relay_server(&self) -> bool {
        self.relay_server.load(Ordering::Relaxed)
    }

    /// The relay address currently in use, if any.
    pub fn current_relay(&self) -> Option<SocketAddr> {
        *self.relay_addr.lock().unwrap()
    }

    /// The synthetic endpoint the engine should use to reach `peer` via the
    /// relay (stable per peer). Feed this as the peer's discovery endpoint.
    pub fn endpoint_for(&self, peer: [u8; 32]) -> SocketAddr {
        let mut s = self.synth.lock().unwrap();
        if let Some(&a) = s.to_addr.get(&peer) {
            return a;
        }
        s.next = s.next.wrapping_add(1);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, s.next)), 1);
        s.to_addr.insert(peer, addr);
        s.to_id.insert(addr, peer);
        addr
    }

    /// Seed the forwarding table with a peer's known address, so this node can
    /// relay frames to it WITHOUT waiting for that peer to register over the relay.
    /// The daemon calls this for every directly-connected peer: an elected bridge
    /// is by definition connected to both ends of the pair it bridges, so it can
    /// forward to each at the address its own direct session uses — robust even
    /// when a multi-homed/NAT'd endpoint can't deliver a relay registration.
    pub fn learn(&self, id: [u8; 32], addr: SocketAddr) {
        self.fwd.lock().unwrap().insert(id, addr);
    }

    /// Tell the relay our address (so peers can be forwarded to us).
    pub async fn register(&self) -> Result<(), NetError> {
        if let Some(relay) = self.current_relay() {
            let frame = encode(&ZERO_ID, &self.self_id, &[]);
            self.inner.send_to(&frame, relay).await?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl<T: Transport> Transport for RelayTransport<T> {
    async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<(), NetError> {
        let peer = self.synth.lock().unwrap().to_id.get(&dest).copied();
        if let Some(peer) = peer {
            // Relayed peer: wrap and send THROUGH a relay. Prefer the relay this
            // peer's frames last reached us through (the proven-working return path),
            // falling back to our configured relay for the first packet.
            let via = self
                .relay_path
                .lock()
                .unwrap()
                .get(&peer)
                .copied()
                .or_else(|| self.current_relay());
            if let Some(via) = via {
                let frame = encode(&peer, &self.self_id, data);
                return self.inner.send_to(&frame, via).await;
            }
        }
        self.inner.send_to(data, dest).await
    }

    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr), NetError> {
        loop {
            let (data, from) = self.inner.recv_from().await?;
            // Classify by the relay tag, not the source address: a relay server
            // multiplexes relay frames and mesh frames on one socket, and a
            // client's relay may be observed at a NAT-mapped source.
            let Some((dest, src, inner)) = decode(&data) else {
                return Ok((data, from)); // an ordinary mesh datagram
            };
            // Remember where every sender lives (registrations and data frames
            // alike) so we can forward to it by id. Learned unconditionally so any
            // node can act as an *automatically elected* relay bridge — a peer
            // only ever registers with a node it picked as its relay, so this map
            // is bounded to those who opted in (see the daemon's bridge election).
            self.fwd.lock().unwrap().insert(src, from);
            if dest == self.self_id {
                // Relayed to us — remember which relay delivered it so our replies
                // to `src` go back through the same (working) bridge, then unwrap and
                // surface as the peer's synthetic endpoint so the engine treats it
                // like a direct datagram.
                self.relay_path.lock().unwrap().insert(src, from);
                let synth = self.endpoint_for(src);
                return Ok((inner.to_vec(), synth));
            }
            if dest != ZERO_ID {
                // Forward to the destination's last-seen address. Drop if unknown
                // (the dest hasn't registered with us) — so we only ever relay for
                // peers that elected us, never arbitrary strangers.
                let dest_addr = self.fwd.lock().unwrap().get(&dest).copied();
                if let Some(addr) = dest_addr {
                    let _ = self.inner.send_to(&data, addr).await;
                }
            }
            // Registration, or not addressed to us — nothing to surface; keep reading.
        }
    }

    fn local_addr(&self) -> Result<SocketAddr, NetError> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp::UdpTransport;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    #[test]
    fn frame_round_trips() {
        let dest = [1u8; 32];
        let src = [2u8; 32];
        let f = encode(&dest, &src, b"hello");
        let (d, s, inner) = decode(&f).unwrap();
        assert_eq!(d, dest);
        assert_eq!(s, src);
        assert_eq!(inner, b"hello");
        assert!(decode(b"\x01short").is_none());

        // A mesh frame (a `MessageType` byte in 0x01..=0x05, here Revocation 0x05,
        // padded past HDR) must NOT be mistaken for a relay frame on a shared
        // socket — the tag (0xF0) is what disambiguates.
        let mesh_like = {
            let mut v = vec![0x05u8];
            v.extend_from_slice(&[7u8; HDR]);
            v
        };
        assert!(
            decode(&mesh_like).is_none(),
            "a 0x05-tagged mesh frame must not classify as a relay frame"
        );
    }

    /// A real relay forwarder + two clients over localhost UDP: A→relay→B and
    /// B→relay→A, with relayed peers surfaced as synthetic direct addresses.
    #[tokio::test]
    async fn relay_forwards_both_directions_over_udp() {
        let relay_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        tokio::spawn(run_relay(relay_sock));

        let a_id = [0xAA; 32];
        let b_id = [0xBB; 32];
        let ta = Arc::new(RelayTransport::new(
            UdpTransport::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            Some(relay_addr),
            a_id,
        ));
        let tb = Arc::new(RelayTransport::new(
            UdpTransport::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            Some(relay_addr),
            b_id,
        ));

        // B registers so the relay knows where to forward to it.
        tb.register().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A → B (via the relay), addressed to B's synthetic endpoint.
        let synth_b = ta.endpoint_for(b_id);
        ta.send_to(b"hello via relay", synth_b).await.unwrap();

        let (data, from_b) = tokio::time::timeout(Duration::from_secs(2), tb.recv_from())
            .await
            .expect("B should receive the relayed packet")
            .unwrap();
        assert_eq!(data, b"hello via relay");

        // B → A: reply to the synthetic address it saw — relays back to A.
        tb.send_to(b"reply via relay", from_b).await.unwrap();
        let (data2, _) = tokio::time::timeout(Duration::from_secs(2), ta.recv_from())
            .await
            .expect("A should receive the relayed reply")
            .unwrap();
        assert_eq!(data2, b"reply via relay");
    }

    /// The auto-relay path: instead of a standalone `run_relay`, a node in
    /// `relay_server` mode forwards relay frames on its *own mesh socket*. Two
    /// clients pointed at it exchange traffic A→R→B and B→R→A — proving the
    /// unified mesh-socket relay (the address others use is just R's endpoint).
    #[tokio::test]
    async fn relay_server_mode_forwards_on_shared_socket() {
        let r_id = [0xCC; 32];
        let a_id = [0xAA; 32];
        let b_id = [0xBB; 32];

        // The relay node: a RelayTransport in server mode (no relay of its own).
        let r = Arc::new(RelayTransport::new(
            UdpTransport::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            None,
            r_id,
        ));
        r.set_relay_server(true);
        let r_addr = r.local_addr().unwrap();

        let ta = Arc::new(RelayTransport::new(
            UdpTransport::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            Some(r_addr),
            a_id,
        ));
        let tb = Arc::new(RelayTransport::new(
            UdpTransport::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            Some(r_addr),
            b_id,
        ));

        // Drive the relay server's receive loop — forwarding is a side effect of
        // `recv_from` (frames not addressed to R never surface; they're relayed).
        {
            let r = Arc::clone(&r);
            tokio::spawn(async move {
                loop {
                    if r.recv_from().await.is_err() {
                        break;
                    }
                }
            });
        }

        // Both clients register so the relay learns their addresses by id.
        ta.register().await.unwrap();
        tb.register().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A → B over the shared-socket relay.
        let synth_b = ta.endpoint_for(b_id);
        ta.send_to(b"hi over shared relay", synth_b).await.unwrap();
        let (data, from_b) = tokio::time::timeout(Duration::from_secs(2), tb.recv_from())
            .await
            .expect("B should receive the relayed packet")
            .unwrap();
        assert_eq!(data, b"hi over shared relay");

        // B → A, replying to the synthetic endpoint it saw.
        tb.send_to(b"reply", from_b).await.unwrap();
        let (data2, _) = tokio::time::timeout(Duration::from_secs(2), ta.recv_from())
            .await
            .expect("A should receive the relayed reply")
            .unwrap();
        assert_eq!(data2, b"reply");
    }

    /// Automatic relay-bridge election: a node that was NEVER designated a relay
    /// server (`set_relay_server` is never called) still forwards relay frames for
    /// peers that registered with it. This is what lets any well-connected node be
    /// elected as a bridge on the fly — the daemon's bridge election points two
    /// clients at it and they rendezvous through it with no manual designation.
    #[tokio::test]
    async fn undesignated_node_forwards_for_registrants() {
        let r_id = [0x11; 32];
        let a_id = [0x22; 32];
        let b_id = [0x33; 32];

        // R is a plain node — NOT a relay server (the key difference).
        let r = Arc::new(RelayTransport::new(
            UdpTransport::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            None,
            r_id,
        ));
        assert!(
            !r.is_relay_server(),
            "R must not be a designated relay server"
        );
        let r_addr = r.local_addr().unwrap();

        let ta = Arc::new(RelayTransport::new(
            UdpTransport::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            Some(r_addr),
            a_id,
        ));
        let tb = Arc::new(RelayTransport::new(
            UdpTransport::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            Some(r_addr),
            b_id,
        ));

        {
            let r = Arc::clone(&r);
            tokio::spawn(async move {
                loop {
                    if r.recv_from().await.is_err() {
                        break;
                    }
                }
            });
        }

        // Both clients elect R and register — R learns their addresses by id even
        // though it was never told to be a relay.
        ta.register().await.unwrap();
        tb.register().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let synth_b = ta.endpoint_for(b_id);
        ta.send_to(b"bridged with no designation", synth_b)
            .await
            .unwrap();
        let (data, _) = tokio::time::timeout(Duration::from_secs(2), tb.recv_from())
            .await
            .expect("B should receive the relayed packet via the undesignated bridge")
            .unwrap();
        assert_eq!(data, b"bridged with no designation");
    }

    /// L1 anonymity: a relay rewrites a circuit DATA frame to a DIFFERENT per-leg
    /// cid in BOTH directions, carrying no node id on the wire. (docs/ANONYMITY.md)
    #[test]
    fn circuit_forwards_both_ways_without_node_ids() {
        let o_addr: SocketAddr = "127.0.0.1:1001".parse().unwrap();
        let p_addr: SocketAddr = "127.0.0.1:2002".parse().unwrap();
        let cid_or: Cid = [0x11; 16];
        let cid_rp: Cid = [0x22; 16];

        // Relay R installs both directions of the O–R–P circuit.
        let mut r = CircuitTable::default();
        r.install(cid_or, cid_rp, p_addr); // forward O→P
        r.install(cid_rp, cid_or, o_addr); // return P→O

        // Forward: O→R on cid_or → R rewrites to cid_rp toward P.
        let f = encode_circuit(&cid_or, b"hello");
        let (out, addr) = r.forward(&f).expect("forward circuit");
        assert_eq!(addr, p_addr);
        let (cid, inner) = decode_circuit(&out).unwrap();
        assert_eq!(cid, cid_rp, "cid must change per leg");
        assert_eq!(inner, b"hello");
        // Frame is exactly [tag][16-byte cid][payload] — no 32-byte node id anywhere.
        assert_eq!(out.len(), CIRCUIT_HDR + 5);

        // Return: P→R on cid_rp → R rewrites to cid_or toward O.
        let f2 = encode_circuit(&cid_rp, b"reply");
        let (out2, addr2) = r.forward(&f2).expect("return circuit");
        assert_eq!(addr2, o_addr);
        assert_eq!(decode_circuit(&out2).unwrap().0, cid_or);

        // Unknown cid → not forwarded.
        assert!(r.forward(&encode_circuit(&[0x99; 16], b"x")).is_none());
    }
}
