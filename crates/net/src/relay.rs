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
//! Frame: `[0x05][dest node id (32)][src node id (32)][inner datagram]`. A frame
//! with an all-zero `dest` is a registration (tells the relay our address).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;

use crate::{NetError, Transport};

const RELAY: u8 = 0x05;
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
    relay_addr: Option<SocketAddr>,
    self_id: [u8; 32],
    synth: Mutex<Synth>,
}

impl<T: Transport> RelayTransport<T> {
    /// `relay_addr = None` makes this a pure pass-through (no relay configured).
    pub fn new(inner: T, relay_addr: Option<SocketAddr>, self_id: [u8; 32]) -> Self {
        Self {
            inner,
            relay_addr,
            self_id,
            synth: Mutex::new(Synth::default()),
        }
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

    /// Tell the relay our address (so peers can be forwarded to us).
    pub async fn register(&self) -> Result<(), NetError> {
        if let Some(relay) = self.relay_addr {
            let frame = encode(&ZERO_ID, &self.self_id, &[]);
            self.inner.send_to(&frame, relay).await?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl<T: Transport> Transport for RelayTransport<T> {
    async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<(), NetError> {
        if let Some(relay) = self.relay_addr {
            let peer = self.synth.lock().unwrap().to_id.get(&dest).copied();
            if let Some(peer) = peer {
                // Relayed peer: wrap and send to the relay instead.
                let frame = encode(&peer, &self.self_id, data);
                return self.inner.send_to(&frame, relay).await;
            }
        }
        self.inner.send_to(data, dest).await
    }

    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr), NetError> {
        loop {
            let (data, from) = self.inner.recv_from().await?;
            if self.relay_addr == Some(from) {
                if let Some((dest, src, inner)) = decode(&data) {
                    if dest == self.self_id {
                        let synth = self.endpoint_for(src);
                        return Ok((inner.to_vec(), synth));
                    }
                    continue; // a relay frame, but not for us
                }
            }
            return Ok((data, from));
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
}
