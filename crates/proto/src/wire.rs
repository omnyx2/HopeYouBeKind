//! On-wire framing for the Lattice Tunnel Protocol (LTP).
//!
//! See `docs/PROTOCOL.md` for the authoritative spec. This module only defines
//! the message *kinds* and the 4-byte header layout; encryption lives in
//! `lattice-crypto`.

use serde::{Deserialize, Serialize};

/// First byte of every datagram: what kind of message this is.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    HandshakeInit = 0x01,
    HandshakeResp = 0x02,
    Transport = 0x03,
    Keepalive = 0x04,
}

impl MessageType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::HandshakeInit),
            0x02 => Some(Self::HandshakeResp),
            0x03 => Some(Self::Transport),
            0x04 => Some(Self::Keepalive),
            _ => None,
        }
    }
}

/// Fixed 4-byte datagram header: `[type, reserved, reserved, reserved]`.
pub const HEADER_LEN: usize = 4;

/// Maximum plaintext payload we attempt to tunnel in one datagram, chosen to
/// stay under a typical 1500-byte path MTU after framing + AEAD overhead.
pub const MAX_PAYLOAD: usize = 1380;

/// Frame a payload into a datagram: 4-byte header followed by `payload`.
pub fn encode(msg_type: MessageType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(msg_type as u8);
    out.extend_from_slice(&[0, 0, 0]); // reserved
    out.extend_from_slice(payload);
    out
}

/// Parse a datagram into its type and payload slice. Returns `None` if the
/// buffer is too short or the type byte is unknown.
pub fn decode(buf: &[u8]) -> Option<(MessageType, &[u8])> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let msg_type = MessageType::from_u8(buf[0])?;
    Some((msg_type, &buf[HEADER_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let frame = encode(MessageType::Transport, b"payload");
        let (t, payload) = decode(&frame).unwrap();
        assert_eq!(t, MessageType::Transport);
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn decode_rejects_short_and_unknown() {
        assert!(decode(&[0x03]).is_none()); // too short
        assert!(decode(&[0xff, 0, 0, 0]).is_none()); // unknown type
    }
}
