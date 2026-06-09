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
//! Nonce handling: v0.2 uses snow's in-order stateful transport, which is
//! correct for the single-host loopback milestone. The explicit per-packet
//! counter + sliding replay window from PROTOCOL.md is layered on in v0.7, when
//! we move to lossy/reordering UDP paths.

use std::time::Duration;

use crate::rekey::RekeyPolicy;
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
}

impl Handshake {
    /// Begin a handshake toward a peer whose static public key we already know.
    /// Returns the in-progress handshake and the `HANDSHAKE_INIT` message bytes.
    pub fn initiate(
        local_private: &[u8],
        remote_public: &[u8],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        let mut state = snow::Builder::new(params())
            .local_private_key(local_private)
            .remote_public_key(remote_public)
            .build_initiator()?;
        let mut buf = vec![0u8; 1024];
        let n = state.write_message(&[], &mut buf)?;
        buf.truncate(n);
        Ok((Self { state }, buf))
    }

    /// Finish the handshake using the responder's `HANDSHAKE_RESP` message.
    pub fn complete(mut self, response: &[u8]) -> Result<NoiseSession, CryptoError> {
        let mut scratch = vec![0u8; 1024];
        self.state.read_message(response, &mut scratch)?;
        let transport = self.state.into_transport_mode()?;
        Ok(NoiseSession::new(transport))
    }
}

/// Accept an incoming `HANDSHAKE_INIT` as the responder. Produces the live
/// session, the `HANDSHAKE_RESP` to send back, and the initiator's static key.
pub fn respond(local_private: &[u8], init: &[u8]) -> Result<PendingHandshake, CryptoError> {
    let mut state = snow::Builder::new(params())
        .local_private_key(local_private)
        .build_responder()?;

    let mut scratch = vec![0u8; 1024];
    state.read_message(init, &mut scratch)?;

    // IK reveals the initiator's static key during the handshake.
    let remote_static = state
        .get_remote_static()
        .ok_or(CryptoError::NotEstablished)?
        .to_vec();

    let mut response = vec![0u8; 1024];
    let n = state.write_message(&[], &mut response)?;
    response.truncate(n);

    let transport = state.into_transport_mode()?;
    Ok(PendingHandshake {
        session: NoiseSession::new(transport),
        response,
        remote_static,
    })
}

/// A live, authenticated tunnel: AEAD-seals outbound packets and opens inbound
/// ones with ChaCha20-Poly1305, keys established by the handshake. Tracks usage
/// so the engine can renegotiate per the [`RekeyPolicy`].
pub struct NoiseSession {
    transport: snow::TransportState,
    rekey: RekeyPolicy,
}

impl NoiseSession {
    fn new(transport: snow::TransportState) -> Self {
        Self {
            transport,
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
        // AEAD adds a 16-byte tag.
        let mut out = vec![0u8; plaintext.len() + 16];
        let n = self.transport.write_message(plaintext, &mut out)?;
        out.truncate(n);
        self.rekey.record();
        Ok(out)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = vec![0u8; ciphertext.len()];
        let n = self
            .transport
            .read_message(ciphertext, &mut out)
            .map_err(|_| CryptoError::AuthFailed)?;
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

        // 1. initiator → INIT
        let (hs, init_msg) =
            Handshake::initiate(initiator.private_key(), responder.public_key()).unwrap();

        // 2. responder accepts, learns initiator identity, → RESP
        let pending = respond(responder.private_key(), &init_msg).unwrap();
        assert_eq!(
            pending.remote_static,
            initiator.public_key(),
            "responder must authenticate the initiator's static key"
        );

        // 3. initiator completes
        let mut init_session = hs.complete(&pending.response).unwrap();
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
        let (hs, init) = Handshake::initiate(a.private_key(), b.public_key()).unwrap();
        let pending = respond(b.private_key(), &init).unwrap();
        let mut sa = hs.complete(&pending.response).unwrap();
        let mut sb = pending.session;

        let mut sealed = sa.encrypt(b"secret").unwrap();
        sealed[0] ^= 0xff; // flip a bit
        assert!(matches!(sb.decrypt(&sealed), Err(CryptoError::AuthFailed)));
    }
}
