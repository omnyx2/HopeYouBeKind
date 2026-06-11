//! The Lattice Tunnel Protocol handshake and session — the custom protocol
//! built on Noise-IK primitives (see `docs/PROTOCOL.md`).
//!
//! Two-message IK handshake (the initiator already knows the responder's static
//! key — it is the peer's identity, learned via discovery):
//!
//! ```text
//!   initiator                         responder
//!      │  ── HANDSHAKE_INIT (msg 1) ──▶  │   reads init, learns initiator's
//!      │                                 │   static key (mutual auth)
//!      │  ◀─ HANDSHAKE_RESP (msg 2) ──   │
//!      ▼                                 ▼
//!   transport mode                    transport mode   (AEAD both ways)
//! ```
//!
//! Both sides end in a [`NoiseSession`] that AEAD-seals/opens transport packets.
//!
//! Nonce handling: the session uses snow's **stateless** transport — each packet
//! carries an explicit 8-byte counter used as the AEAD nonce, with a sliding
//! replay window. This survives the packet loss and reordering of real UDP; an
//! in-order stateful transport desyncs on the first lost/reordered packet.

use std::time::Duration;

use crate::rekey::RekeyPolicy;
use crate::replay::ReplayWindow;
use crate::{CryptoError, TunnelSession, NOISE_PARAMS};

fn params() -> snow::params::NoiseParams {
    NOISE_PARAMS.parse().expect("NOISE_PARAMS is a valid spec")
}

/// The initiator side of an in-progress handshake. Hold this between sending the
/// init message and receiving the response, then [`Handshake::complete`] it.
pub struct Handshake {
    state: snow::HandshakeState,
}

/// Result of a responder accepting an init message: the established session plus
/// the response datagram to send back, and the initiator's authenticated static
/// public key (so the engine knows *who* connected).
pub struct PendingHandshake {
    pub session: NoiseSession,
    pub response: Vec<u8>,
    pub remote_static: Vec<u8>,
    /// The (authenticated) metadata payload the initiator sent — e.g. its OS.
    pub remote_payload: Vec<u8>,
}

impl Handshake {
    /// Begin a handshake toward a peer whose static public key we already know.
    /// `payload` is small authenticated metadata (e.g. our OS) carried in the
    /// init message. Returns the handshake and the `HANDSHAKE_INIT` bytes.
    pub fn initiate(
        local_private: &[u8],
        remote_public: &[u8],
        payload: &[u8],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        let mut state = snow::Builder::new(params())
            .local_private_key(local_private)
            .remote_public_key(remote_public)
            .build_initiator()?;
        let mut buf = vec![0u8; 1024];
        let n = state.write_message(payload, &mut buf)?;
        buf.truncate(n);
        Ok((Self { state }, buf))
    }

    /// Finish the handshake using the responder's `HANDSHAKE_RESP` message.
    /// Returns the live session and the responder's metadata payload.
    pub fn complete(mut self, response: &[u8]) -> Result<(NoiseSession, Vec<u8>), CryptoError> {
        let mut scratch = vec![0u8; 1024];
        let n = self.state.read_message(response, &mut scratch)?;
        let peer_payload = scratch[..n].to_vec();
        let transport = self.state.into_stateless_transport_mode()?;
        Ok((NoiseSession::new(transport), peer_payload))
    }
}

/// Accept an incoming `HANDSHAKE_INIT` as the responder. `payload` is our
/// metadata to send back. Produces the live session, the `HANDSHAKE_RESP`, the
/// initiator's static key, and the initiator's metadata payload.
pub fn respond(
    local_private: &[u8],
    init: &[u8],
    payload: &[u8],
) -> Result<PendingHandshake, CryptoError> {
    let mut state = snow::Builder::new(params())
        .local_private_key(local_private)
        .build_responder()?;

    let mut scratch = vec![0u8; 1024];
    let n = state.read_message(init, &mut scratch)?;
    let remote_payload = scratch[..n].to_vec();

    // IK reveals the initiator's static key during the handshake.
    let remote_static = state
        .get_remote_static()
        .ok_or(CryptoError::NotEstablished)?
        .to_vec();

    let mut response = vec![0u8; 1024];
    let n = state.write_message(payload, &mut response)?;
    response.truncate(n);

    let transport = state.into_stateless_transport_mode()?;
    Ok(PendingHandshake {
        session: NoiseSession::new(transport),
        response,
        remote_static,
        remote_payload,
    })
}

/// A live, authenticated tunnel: AEAD-seals outbound packets and opens inbound
/// ones with ChaCha20-Poly1305, keys established by the handshake.
///
/// Uses snow's **stateless** transport: each packet carries an explicit 8-byte
/// counter used as the AEAD nonce, so packet loss and reordering on the UDP path
/// don't desync the session (the in-order stateful mode breaks on the first
/// lost/reordered packet). A sliding [`ReplayWindow`] rejects duplicates/old.
pub struct NoiseSession {
    transport: snow::StatelessTransportState,
    send_counter: u64,
    replay: ReplayWindow,
    rekey: RekeyPolicy,
}

impl NoiseSession {
    fn new(transport: snow::StatelessTransportState) -> Self {
        Self {
            transport,
            send_counter: 0,
            replay: ReplayWindow::new(),
            rekey: RekeyPolicy::default(),
        }
    }

    /// Whether this session should be renegotiated, given how long it has lived.
    /// The caller owns the clock (tracks the session's creation time).
    pub fn rekey_due(&self, age: Duration) -> bool {
        self.rekey.due(age)
    }
}

impl TunnelSession for NoiseSession {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.send_counter;
        self.send_counter = self.send_counter.wrapping_add(1);
        // Wire: [counter (8, big-endian)] [AEAD ciphertext = plaintext + 16 tag].
        let mut out = vec![0u8; 8 + plaintext.len() + 16];
        out[..8].copy_from_slice(&nonce.to_be_bytes());
        let n = self
            .transport
            .write_message(nonce, plaintext, &mut out[8..])?;
        out.truncate(8 + n);
        self.rekey.record();
        Ok(out)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < 8 {
            return Err(CryptoError::AuthFailed);
        }
        let nonce = u64::from_be_bytes(ciphertext[..8].try_into().expect("8 bytes"));
        let mut out = vec![0u8; ciphertext.len() - 8];
        let n = self
            .transport
            .read_message(nonce, &ciphertext[8..], &mut out)
            .map_err(|_| CryptoError::AuthFailed)?;
        // Authentic — now drop replays / too-old packets (window is 1-based).
        if !self.replay.check_and_update(nonce.wrapping_add(1)) {
            return Err(CryptoError::AuthFailed);
        }
        out.truncate(n);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    /// Full IK handshake between two fresh identities, then encrypted traffic in
    /// both directions — the core proof that the custom tunnel works.
    #[test]
    fn handshake_then_bidirectional_transport() {
        let initiator = Identity::generate().unwrap();
        let responder = Identity::generate().unwrap();

        // 1. initiator → INIT (carrying metadata "macos")
        let (hs, init_msg) =
            Handshake::initiate(initiator.private_key(), responder.public_key(), b"macos").unwrap();

        // 2. responder accepts, learns initiator identity + metadata, → RESP
        let pending = respond(responder.private_key(), &init_msg, b"linux").unwrap();
        assert_eq!(
            pending.remote_static,
            initiator.public_key(),
            "responder must authenticate the initiator's static key"
        );
        assert_eq!(
            pending.remote_payload, b"macos",
            "carried the initiator's OS"
        );

        // 3. initiator completes, learning the responder's metadata
        let (mut init_session, resp_meta) = hs.complete(&pending.response).unwrap();
        assert_eq!(resp_meta, b"linux", "carried the responder's OS");
        let mut resp_session = pending.session;

        // 4. initiator → responder
        let msg = b"ping over the lattice tunnel";
        let sealed = init_session.encrypt(msg).unwrap();
        assert_ne!(&sealed[..], &msg[..], "must actually be encrypted");
        assert_eq!(resp_session.decrypt(&sealed).unwrap(), msg);

        // 5. responder → initiator
        let reply = b"pong";
        let sealed = resp_session.encrypt(reply).unwrap();
        assert_eq!(init_session.decrypt(&sealed).unwrap(), reply);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let (hs, init) = Handshake::initiate(a.private_key(), b.public_key(), b"").unwrap();
        let pending = respond(b.private_key(), &init, b"").unwrap();
        let (mut sa, _) = hs.complete(&pending.response).unwrap();
        let mut sb = pending.session;

        let mut sealed = sa.encrypt(b"secret").unwrap();
        sealed[0] ^= 0xff; // flip a bit
        assert!(matches!(sb.decrypt(&sealed), Err(CryptoError::AuthFailed)));
    }

    /// The real-world failure: UDP loses/reorders packets. The stateless session
    /// must still decrypt out-of-order packets and reject replays — the in-order
    /// stateful mode broke on the first reordered packet.
    #[test]
    fn tolerates_reordering_and_rejects_replays() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let (hs, init) = Handshake::initiate(a.private_key(), b.public_key(), b"").unwrap();
        let pending = respond(b.private_key(), &init, b"").unwrap();
        let (mut sa, _) = hs.complete(&pending.response).unwrap();
        let mut sb = pending.session;

        // Seal three packets in order...
        let p0 = sa.encrypt(b"zero").unwrap();
        let p1 = sa.encrypt(b"one").unwrap();
        let p2 = sa.encrypt(b"two").unwrap();

        // ...but deliver them out of order — all must still open.
        assert_eq!(sb.decrypt(&p2).unwrap(), b"two");
        assert_eq!(sb.decrypt(&p0).unwrap(), b"zero");
        assert_eq!(sb.decrypt(&p1).unwrap(), b"one");

        // A replayed packet is rejected.
        assert!(matches!(sb.decrypt(&p1), Err(CryptoError::AuthFailed)));
    }
}
