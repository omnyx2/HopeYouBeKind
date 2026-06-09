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
