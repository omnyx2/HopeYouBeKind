//! v2 data plane — the per-mesh framing + crypto path (docs/DATA_PLANE.md).
//!
//! **Phase 1 (loopback):** the pure logic — no TUN, no sockets. Given an inner IP
//! packet it builds a wire-v2 frame (header ‖ seq ‖ AEAD), and given a frame it
//! opens + decides (deliver to us / forward). The TUN read/write and the transport
//! send/recv that wrap this land in later phases.
//!
//! Logical frame = `seq(8, BE) ‖ sealed_header ‖ body_ct`: `seq` is the AEAD nonce,
//! the header is sealed with a **time-windowed key** ([`HeaderCrypto`], P-C2), the
//! body with the per-mesh **dropbox cipher** ([`MeshSuite`]) over the plaintext header
//! as AAD (a tampered header / wrong `seq` fails). P-C5 then [`Scramble`]s the wire
//! form — `seq` is XOR-masked and the sealed header floats to a per-frame offset
//! inside the body — so nothing constant sits at a fixed position to fingerprint. A
//! relay un-scrambles + opens only the header to read `dst`.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};

use lattice_proto::wire_v2::{self, FrameType, Header, MemberId, MeshId};

use crate::crypto::{HeaderCrypto, MeshSuite, Scramble, TAG_LEN};

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
    /// Frame scramble — floats the sealed header + masks `seq` so nothing is at a
    /// fixed offset to fingerprint (P-C5).
    scramble: Scramble,
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
            scramble: Scramble::new(secret),
            send_seq: AtomicU64::new(0),
        }
    }

    /// Swap to a new cipher epoch **in place** (P-C3 re-cipher): replace the body
    /// suite + header crypto and reset the nonce counter (a fresh key restarts at
    /// seq 0). The TUN/UDP, overlay, and member ids are untouched — only the keys
    /// change, so the run loop can re-cipher without respawning.
    pub fn recipher(&mut self, suite: Box<dyn MeshSuite>, secret: &[u8; 32]) {
        self.suite = suite;
        self.header = HeaderCrypto::new(secret, self.mesh_id);
        self.scramble = Scramble::new(secret);
        self.send_seq.store(0, Ordering::Relaxed);
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

    /// Frame a payload for member `dst`. The logical parts are `seq(8) ‖
    /// sealed_header(21) ‖ body_ct` (P-C2: header time-windowed, body the dropbox
    /// cipher with the plaintext header as AAD). P-C5 then **scrambles** the wire form:
    /// the seq is XOR-masked and the sealed header is spliced into the body at a
    /// per-frame offset, so nothing constant sits at a fixed position.
    fn seal_frame(&self, dst: MemberId, ft: FrameType, payload: &[u8]) -> Vec<u8> {
        let header = Header::new(self.mesh_id, self.my_id, dst, ft);
        let hdr_bytes = wire_v2::encode(header, &[]); // the 5 plaintext header bytes
        let seq = self.send_seq.fetch_add(1, Ordering::Relaxed);
        let body_ct = self.suite.seal(seq, payload, &hdr_bytes);
        let hdr_ct = self.header.seal(seq, &hdr_bytes); // SEALED_HEADER_LEN bytes
        let off = self.scramble.header_offset(seq, body_ct.len());
        let mut frame = Vec::with_capacity(8 + hdr_ct.len() + body_ct.len());
        frame.extend_from_slice(&self.scramble.mask_seq(seq.to_be_bytes()));
        frame.extend_from_slice(&body_ct[..off]);
        frame.extend_from_slice(&hdr_ct);
        frame.extend_from_slice(&body_ct[off..]);
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

    /// Parse + open an inbound frame, returning the **authenticated** source member id
    /// alongside the resolved [`Inbound`]. `None` if it isn't ours / fails to open. Undo
    /// the P-C5 scramble (unmask seq, lift the sealed header out of the body), open the
    /// header with the time-windowed key (a non-member can't, which also drops foreign
    /// frames), route off it, and only the destination opens the body.
    ///
    /// The returned `src` comes from the opened (authenticated) header — the run loop
    /// uses it for src-learn/roaming. A raw plaintext parse of the wire frame can't
    /// recover it post-scramble (the header is sealed + floated), so this is the only
    /// trustworthy source of the sender id.
    pub fn recv(&self, frame: &[u8]) -> Option<(MemberId, Inbound)> {
        if frame.len() < 8 + SEALED_HEADER_LEN {
            return None;
        }
        // Undo the P-C5 scramble: unmask seq, then lift the sealed header back out of
        // the body at its per-frame offset.
        let seq = u64::from_be_bytes(self.scramble.mask_seq(frame[0..8].try_into().ok()?));
        let scrambled = &frame[8..];
        let body_len = scrambled.len() - SEALED_HEADER_LEN;
        let off = self.scramble.header_offset(seq, body_len);
        let hdr_ct = &scrambled[off..off + SEALED_HEADER_LEN];
        let body_ct = [&scrambled[..off], &scrambled[off + SEALED_HEADER_LEN..]].concat();
        let hdr_bytes = self.header.open(seq, hdr_ct)?;
        let (header, _) = wire_v2::decode(&hdr_bytes)?;
        if header.mesh != self.mesh_id {
            return None; // a different mesh's frame
        }
        if header.dst != self.my_id {
            // Relay path: we opened only the header to read `dst`; forward the frame
            // (body still sealed) on to the next hop, untouched.
            return Some((header.src, Inbound::Forward { to: header.dst }));
        }
        let pt = self.suite.open(seq, &body_ct, &hdr_bytes)?;
        Some((
            header.src,
            match header.frame_type {
                FrameType::Control => Inbound::Control(pt),
                _ => Inbound::Deliver(pt),
            },
        ))
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
        assert_eq!(
            bob.recv(&frame),
            Some((1, Inbound::Deliver(packet.to_vec())))
        );
    }

    #[test]
    fn frame_addressed_to_someone_else_is_forwarded() {
        let alice = node(1);
        let bob = node(2);
        let frame = alice.seal_to(7, b"for member 7");
        // bob (id 2) is not the dst → forward, no decrypt.
        assert_eq!(bob.recv(&frame), Some((1, Inbound::Forward { to: 7 })));
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
    fn recipher_swaps_keys_in_place() {
        let mut alice = node(1);
        let bob = node(2);
        let old = alice.seal_to(2, b"old-epoch");
        assert_eq!(
            bob.recv(&old),
            Some((1, Inbound::Deliver(b"old-epoch".to_vec())))
        );

        // Alice re-ciphers to a fresh secret/epoch; Bob (still on the old key) can't
        // open her new frame — until he re-ciphers to the same new secret too.
        let new_secret = [7u8; 32];
        alice.recipher(suite("default", &new_secret, 1), &new_secret);
        let neu = alice.seal_to(2, b"new-epoch");
        assert_eq!(bob.recv(&neu), None);

        let mut bob2 = node(2);
        bob2.recipher(suite("default", &new_secret, 1), &new_secret);
        assert_eq!(
            bob2.recv(&neu),
            Some((1, Inbound::Deliver(b"new-epoch".to_vec())))
        );
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
