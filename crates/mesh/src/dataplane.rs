//! v2 data plane — the per-mesh framing + crypto path (docs/DATA_PLANE.md).
//!
//! **Phase 1 (loopback):** the pure logic — no TUN, no sockets. Given an inner IP
//! packet it builds a wire-v2 frame (header ‖ seq ‖ AEAD), and given a frame it
//! opens + decides (deliver to us / forward). The TUN read/write and the transport
//! send/recv that wrap this land in later phases.
//!
//! Frame layout (docs/DATA_PLANE.md §10): `header(5) ‖ seq(8, BE) ‖ ciphertext`,
//! where `seq` is the AEAD nonce and the 5-byte header is the AEAD associated data
//! (so a tampered header or a wrong `seq` fails to open).

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};

use lattice_proto::wire_v2::{self, FrameType, Header, MemberId, MeshId};

use crate::crypto::MeshSuite;

/// What an inbound frame resolves to.
#[derive(Debug, PartialEq, Eq)]
pub enum Inbound {
    /// The decrypted inner packet is for us — write it to the TUN.
    Deliver(Vec<u8>),
    /// A decrypted control-plane payload (endpoint gossip / keepalive) — for the run
    /// loop, NOT the TUN.
    Control(Vec<u8>),
    /// Not for us — relay the frame on to member `to` (the relay path, a later phase).
    Forward { to: MemberId },
}

/// One node's view of one mesh's data plane.
pub struct MeshDataPlane {
    mesh_id: MeshId,
    my_id: MemberId,
    /// First two octets of this mesh's overlay /24 (the §2 prefix; charter-chosen).
    overlay_prefix: [u8; 2],
    suite: Box<dyn MeshSuite>,
    /// Outbound counter — the per-message AEAD nonce. Atomic so the run loop can
    /// seal and recv concurrently behind a shared `&MeshDataPlane`.
    send_seq: AtomicU64,
}

impl MeshDataPlane {
    pub fn new(
        mesh_id: MeshId,
        my_id: MemberId,
        overlay_prefix: [u8; 2],
        suite: Box<dyn MeshSuite>,
    ) -> Self {
        Self {
            mesh_id,
            my_id,
            overlay_prefix,
            suite,
            send_seq: AtomicU64::new(0),
        }
    }

    /// Which member (if any) owns the overlay address `dst` in this mesh: the
    /// `/24` is `prefix.prefix.mesh_id.0`, host octet = the 1-byte member id.
    pub fn route(&self, dst: Ipv4Addr) -> Option<MemberId> {
        let o = dst.octets();
        if o[0] == self.overlay_prefix[0] && o[1] == self.overlay_prefix[1] && o[2] == self.mesh_id
        {
            let k = o[3];
            if (1..=254).contains(&k) {
                return Some(k);
            }
        }
        None
    }

    /// Frame a payload for member `dst`: `header ‖ seq ‖ seal(payload)`.
    fn seal_frame(&self, dst: MemberId, ft: FrameType, payload: &[u8]) -> Vec<u8> {
        let header = Header::new(self.mesh_id, self.my_id, dst, ft);
        let aad = wire_v2::encode(header, &[]); // the 5 header bytes
        let seq = self.send_seq.fetch_add(1, Ordering::Relaxed);
        let ct = self.suite.seal(seq, payload, &aad);
        let mut body = Vec::with_capacity(8 + ct.len());
        body.extend_from_slice(&seq.to_be_bytes());
        body.extend_from_slice(&ct);
        wire_v2::encode(header, &body)
    }

    /// Frame an inner IP packet for member `dst` (the data path).
    pub fn seal_to(&self, dst: MemberId, inner: &[u8]) -> Vec<u8> {
        self.seal_frame(dst, FrameType::Transport, inner)
    }

    /// Frame a control payload (endpoint gossip / keepalive) for member `dst`.
    pub fn seal_control(&self, dst: MemberId, payload: &[u8]) -> Vec<u8> {
        self.seal_frame(dst, FrameType::Control, payload)
    }

    /// Parse + open an inbound frame. `None` if it isn't ours / fails to open.
    pub fn recv(&self, frame: &[u8]) -> Option<Inbound> {
        let (header, rest) = wire_v2::decode(frame)?;
        if header.mesh != self.mesh_id {
            return None; // a different mesh's frame
        }
        if header.dst != self.my_id {
            // Relay path (a later phase decrypts nothing — it just forwards).
            return Some(Inbound::Forward { to: header.dst });
        }
        if rest.len() < 8 {
            return None;
        }
        let seq = u64::from_be_bytes(rest[0..8].try_into().ok()?);
        let aad = wire_v2::encode(header, &[]);
        let pt = self.suite.open(seq, &rest[8..], &aad)?;
        Some(match header.frame_type {
            FrameType::Control => Inbound::Control(pt),
            _ => Inbound::Deliver(pt),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite;

    const SECRET: [u8; 32] = [42u8; 32];
    const PREFIX: [u8; 2] = [100, 80];

    fn node(my_id: MemberId) -> MeshDataPlane {
        // Same mesh (id 3), same secret + epoch ⇒ same shared key.
        MeshDataPlane::new(3, my_id, PREFIX, suite("default", &SECRET, 0))
    }

    #[test]
    fn loopback_seal_then_open() {
        let alice = node(1);
        let bob = node(2);
        let packet = b"an inner IP packet (pretend)";
        let frame = alice.seal_to(2, packet);
        assert_eq!(bob.recv(&frame), Some(Inbound::Deliver(packet.to_vec())));
    }

    #[test]
    fn frame_addressed_to_someone_else_is_forwarded() {
        let alice = node(1);
        let bob = node(2);
        let frame = alice.seal_to(7, b"for member 7");
        // bob (id 2) is not the dst → forward, no decrypt.
        assert_eq!(bob.recv(&frame), Some(Inbound::Forward { to: 7 }));
    }

    #[test]
    fn other_mesh_frame_is_dropped() {
        let alice = node(1);
        let other_mesh = MeshDataPlane::new(9, 2, PREFIX, suite("default", &SECRET, 0));
        let frame = alice.seal_to(2, b"x");
        assert_eq!(other_mesh.recv(&frame), None); // mesh id mismatch
    }

    #[test]
    fn tampered_frame_fails_to_open() {
        let alice = node(1);
        let bob = node(2);
        let mut frame = alice.seal_to(2, b"secret");
        let n = frame.len();
        frame[n - 1] ^= 0xff; // flip a ciphertext byte
        assert_eq!(bob.recv(&frame), None);
    }

    #[test]
    fn overlay_route_maps_host_octet_to_member() {
        let alice = node(1);
        assert_eq!(alice.route("100.80.3.7".parse().unwrap()), Some(7)); // mesh 3, member 7
        assert_eq!(alice.route("100.80.9.7".parse().unwrap()), None); // wrong mesh octet
        assert_eq!(alice.route("1.1.1.1".parse().unwrap()), None); // internet
        assert_eq!(alice.route("100.80.3.0".parse().unwrap()), None); // .0 reserved
    }
}
