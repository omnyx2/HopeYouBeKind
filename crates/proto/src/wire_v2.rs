//! On-wire framing for the **Lattice Tunnel Protocol v2** (LTP/2): the multi-mesh
//! header. See `docs/MESH_V2.md` §6.
//!
//! This is the v2 clean-break format. It lives **beside** the v1 [`crate::wire`]
//! module during the migration — v1 and v2 frames do **not** interoperate (the
//! leading byte distinguishes them: v1's first byte is a `MessageType`
//! `0x01..=0x05`, v2's is the version [`VERSION`]).
//!
//! This module is the header **codec** (the 5 logical bytes below). As of P-C2 the
//! data plane no longer puts these bytes on the wire in the clear: it **seals the
//! header** with a time-windowed key (`crypto::HeaderCrypto`, docs/PROTOCOL_DESIGN.md
//! §5-3) so nothing constant/fingerprintable is exposed. A relay — itself a member —
//! opens just the header to read `dst` and forwards the (still-sealed) body; the
//! header is also authenticated as the body AEAD's associated data.
//!
//! ```text
//!   0       1        2       3       4        5 .. N
//!   +-------+--------+-------+-------+--------+-----------+
//!   | ver   | meshid | src   | dst   | type   |  payload  |
//!   +-------+--------+-------+-------+--------+-----------+
//!     1B      1B       1B      1B      1B       (cipher output)
//! ```
//!
//! For a `Transport` frame the decrypted payload is a raw L3 IP packet; `dst` is
//! the recipient's in-mesh id, or the **exit node's** id for internet-bound egress.

use serde::{Deserialize, Serialize};

/// The protocol version this module encodes (`ver`, byte 0). v1 frames carry a
/// `MessageType` in byte 0 (`0x01..=0x05`), so they can never collide with this.
pub const VERSION: u8 = 2;

/// Fixed header length: `ver | meshid | src | dst | type`.
pub const HEADER_LEN: usize = 5;

/// A mesh's 1-byte handle on this computer (the `meshid` field). A node belongs to
/// many meshes; this numbers them locally — 256 distinct values per computer.
pub type MeshId = u8;

/// A member's 1-byte in-mesh address — its join-order id (the §2 "name as CIDR").
/// Valid members are `1..=254`; `0` and `255` are reserved.
pub type MemberId = u8;

/// Reserved member id: unset / no member.
pub const MEMBER_UNSET: MemberId = 0;
/// Reserved member id: broadcast to the whole mesh.
pub const MEMBER_BROADCAST: MemberId = 255;

/// The `type` byte — what kind of frame this is.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum FrameType {
    /// Noise handshake message 1.
    HandshakeInit = 0x01,
    /// Noise handshake message 2.
    HandshakeResp = 0x02,
    /// Tunnelled data — the decrypted payload is a raw L3 IP packet.
    Transport = 0x03,
    /// Authenticated keepalive — empty payload.
    Keepalive = 0x04,
    /// Control plane: re-cipher/rekey, expel, capture-alert, roster/cert gossip.
    Control = 0x05,
}

impl FrameType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::HandshakeInit),
            0x02 => Some(Self::HandshakeResp),
            0x03 => Some(Self::Transport),
            0x04 => Some(Self::Keepalive),
            0x05 => Some(Self::Control),
            _ => None,
        }
    }
}

/// A parsed v2 header (the 5 leading bytes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    pub version: u8,
    pub mesh: MeshId,
    pub src: MemberId,
    pub dst: MemberId,
    pub frame_type: FrameType,
}

impl Header {
    /// A header for a frame in `mesh` from `src` to `dst`, at the current
    /// protocol [`VERSION`].
    pub fn new(mesh: MeshId, src: MemberId, dst: MemberId, frame_type: FrameType) -> Self {
        Self {
            version: VERSION,
            mesh,
            src,
            dst,
            frame_type,
        }
    }
}

/// Read just the version byte without committing to the v2 layout — lets a
/// dispatcher route a datagram to the right version's parser. `None` if empty.
pub fn peek_version(buf: &[u8]) -> Option<u8> {
    buf.first().copied()
}

/// Frame `payload` behind `header`: the 5 header bytes followed by `payload`.
pub fn encode(header: Header, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(header.version);
    out.push(header.mesh);
    out.push(header.src);
    out.push(header.dst);
    out.push(header.frame_type as u8);
    out.extend_from_slice(payload);
    out
}

/// Parse a v2 datagram into its header and payload slice. Returns `None` if the
/// buffer is too short, the version is not [`VERSION`] (a different version needs a
/// different parser — dispatch on [`peek_version`] first), or the type byte is
/// unknown.
pub fn decode(buf: &[u8]) -> Option<(Header, &[u8])> {
    if buf.len() < HEADER_LEN || buf[0] != VERSION {
        return None;
    }
    let frame_type = FrameType::from_u8(buf[4])?;
    let header = Header {
        version: buf[0],
        mesh: buf[1],
        src: buf[2],
        dst: buf[3],
        frame_type,
    };
    Some((header, &buf[HEADER_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_header_and_payload() {
        let h = Header::new(7, 3, 9, FrameType::Transport);
        let frame = encode(h, b"ip-packet");
        let (got, payload) = decode(&frame).unwrap();
        assert_eq!(got, h);
        assert_eq!(got.version, VERSION);
        assert_eq!(got.mesh, 7);
        assert_eq!(got.src, 3);
        assert_eq!(got.dst, 9);
        assert_eq!(got.frame_type, FrameType::Transport);
        assert_eq!(payload, b"ip-packet");
    }

    #[test]
    fn empty_payload_keepalive_is_header_only() {
        let h = Header::new(1, 1, MEMBER_BROADCAST, FrameType::Keepalive);
        let frame = encode(h, b"");
        assert_eq!(frame.len(), HEADER_LEN);
        let (got, payload) = decode(&frame).unwrap();
        assert_eq!(got.frame_type, FrameType::Keepalive);
        assert_eq!(got.dst, MEMBER_BROADCAST);
        assert!(payload.is_empty());
    }

    #[test]
    fn encode_len_is_header_plus_payload() {
        let h = Header::new(0, 1, 2, FrameType::Control);
        assert_eq!(encode(h, &[0u8; 100]).len(), HEADER_LEN + 100);
    }

    #[test]
    fn decode_rejects_short() {
        assert!(decode(&[]).is_none());
        assert!(decode(&[VERSION, 0, 0, 0]).is_none()); // 4 bytes, need 5
    }

    #[test]
    fn decode_rejects_wrong_version() {
        // A v1 transport frame (`MessageType::Transport` 0x03 in byte 0) must not
        // be misread as v2.
        assert!(decode(&[0x03, 0, 0, 0, 0x03]).is_none());
        assert!(decode(&[99, 1, 2, 3, 0x03]).is_none());
    }

    #[test]
    fn decode_rejects_unknown_type() {
        assert!(decode(&[VERSION, 1, 2, 3, 0xff]).is_none());
        assert!(decode(&[VERSION, 1, 2, 3, 0x00]).is_none());
    }

    #[test]
    fn peek_version_reads_byte_zero() {
        assert_eq!(peek_version(&[VERSION, 1, 2, 3, 0x03]), Some(VERSION));
        assert_eq!(peek_version(&[]), None);
    }
}
