//! v2 data plane — the per-mesh framing + crypto path (docs/DATA_PLANE.md).
//!
//! **Phase 1 (loopback):** the pure logic — no TUN, no sockets. Given an inner IP
//! packet it builds a wire-v2 frame (header ‖ seq ‖ AEAD), and given a frame it
//! opens + decides (deliver to us / forward). The TUN read/write and the transport
//! send/recv that wrap this land in later phases.
//!
//! Frame layout (P-C2, docs/PROTOCOL_DESIGN.md §5-3): `seq(8, BE) ‖ sealed_header ‖
//! body_ct`. `seq` is the AEAD nonce (plaintext). The header is sealed with a
//! **time-windowed key** ([`HeaderCrypto`]) so nothing on the wire is constant /
//! fingerprintable; the body with the per-mesh **dropbox cipher** ([`MeshSuite`]),
//! authenticating the plaintext header as AAD (a tampered header or wrong `seq`
//! fails). A relay opens only the header to read `dst`.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};

use lattice_proto::wire_v2::{self, FrameType, Header, MemberId, MeshId};

use crate::crypto::{HeaderCrypto, MeshSuite, TAG_LEN};

/// On the wire the header is sealed (P-C2): the 5 header bytes + the AEAD tag.
const SEALED_HEADER_LEN: usize = wire_v2::HEADER_LEN + TAG_LEN;

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
    /// Body cipher — the per-mesh dropbox suite (P-C1).
    suite: Box<dyn MeshSuite>,
    /// Header cipher — the time-windowed key that seals the wire header (P-C2).
    header: HeaderCrypto,
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
        secret: &[u8; 32],
    ) -> Self {
        Self {
            mesh_id,
            my_id,
            overlay_prefix,
            suite,
            header: HeaderCrypto::new(secret, mesh_id),
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

    /// Frame a payload for member `dst`: `seq(8) ‖ sealed_header(21) ‖ body_ct`
    /// (P-C2). The header is sealed with the time-windowed key (no cleartext on the
    /// wire); the body with the dropbox cipher, AAD = the plaintext header so a
    /// tampered header is detected. Both AEADs use `seq` as the nonce.
    fn seal_frame(&self, dst: MemberId, ft: FrameType, payload: &[u8]) -> Vec<u8> {
        let header = Header::new(self.mesh_id, self.my_id, dst, ft);
        let hdr_bytes = wire_v2::encode(header, &[]); // the 5 plaintext header bytes
        let seq = self.send_seq.fetch_add(1, Ordering::Relaxed);
        let body_ct = self.suite.seal(seq, payload, &hdr_bytes);
        let hdr_ct = self.header.seal(seq, &hdr_bytes); // 5 + tag = SEALED_HEADER_LEN
        let mut frame = Vec::with_capacity(8 + hdr_ct.len() + body_ct.len());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&hdr_ct);
        frame.extend_from_slice(&body_ct);
        frame
    }

    /// Frame an inner IP packet for member `dst` (the data path).
    pub fn seal_to(&self, dst: MemberId, inner: &[u8]) -> Vec<u8> {
        self.seal_frame(dst, FrameType::Transport, inner)
    }

    /// Frame a control payload (endpoint gossip / keepalive) for member `dst`.
    pub fn seal_control(&self, dst: MemberId, payload: &[u8]) -> Vec<u8> {
        self.seal_frame(dst, FrameType::Control, payload)
    }

    /// Parse + open an inbound frame. `None` if it isn't ours / fails to open. Layout
    /// is `seq(8) ‖ sealed_header ‖ body_ct` (P-C2): open the header with the
    /// time-windowed key first (a non-member can't, which also drops foreign frames),
    /// then route off the recovered header; only the destination opens the body.
    pub fn recv(&self, frame: &[u8]) -> Option<Inbound> {
        if frame.len() < 8 + SEALED_HEADER_LEN {
            return None;
        }
        let seq = u64::from_be_bytes(frame[0..8].try_into().ok()?);
        let hdr_bytes = self.header.open(seq, &frame[8..8 + SEALED_HEADER_LEN])?;
        let (header, _) = wire_v2::decode(&hdr_bytes)?;
        if header.mesh != self.mesh_id {
            return None; // a different mesh's frame
        }
        if header.dst != self.my_id {
            // Relay path: we opened only the header to read `dst`; forward the frame
            // (body still sealed) on to the next hop, untouched.
            return Some(Inbound::Forward { to: header.dst });
        }
        let pt = self
            .suite
            .open(seq, &frame[8 + SEALED_HEADER_LEN..], &hdr_bytes)?;
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
        MeshDataPlane::new(3, my_id, PREFIX, suite("default", &SECRET, 0), &SECRET)
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
        let other_mesh = MeshDataPlane::new(9, 2, PREFIX, suite("default", &SECRET, 0), &SECRET);
        let frame = alice.seal_to(2, b"x");
        assert_eq!(other_mesh.recv(&frame), None); // mesh id mismatch (header won't open)
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
    fn header_is_sealed_and_gated_to_members() {
        let alice = node(1);
        let frame = alice.seal_to(2, b"hi");
        // P-C2: no cleartext v2 header on the wire — byte 0 is the seq counter, and
        // the frame head does not parse as a plaintext header.
        assert_ne!(frame[0], wire_v2::VERSION);
        // A non-member (different secret) can't open the header ⇒ recovers nothing.
        let outsider =
            MeshDataPlane::new(3, 2, PREFIX, suite("default", &[7u8; 32], 0), &[7u8; 32]);
        assert_eq!(outsider.recv(&frame), None);
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
