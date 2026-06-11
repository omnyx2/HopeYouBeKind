//! Pluggable tunnel crypto — the seam for swapping the session encryption.
//!
//! The engine never names a concrete cipher: it drives a [`CryptoSuite`], which
//! owns the *whole* cryptographic story for one tunnel — the handshake
//! choreography, what gets authenticated, and the per-packet AEAD. Noise-IK
//! ([`NoiseSuite`]) is the default and only production suite today, but research
//! suites (post-quantum KEM handshakes, alternative AEADs, experimental framing)
//! drop in by implementing this trait and handing the engine a different `Arc`.
//!
//! Two hard requirements every suite must meet, because the membership layer
//! (network certs / revocation) is built *on top* of the suite and trusts it:
//!  1. The handshake mutually **authenticates the peer's identity key** — the
//!     returned `peer_identity` is the peer's real long-term public key, not an
//!     unverified claim.
//!  2. Sessions are confidential + integrity-protected and survive UDP loss /
//!     reordering (no in-order assumption).

use crate::{CryptoError, Handshake, NoiseSession, TunnelSession};

/// A complete tunnel crypto scheme: handshake + session encryption. Cloneable as
/// an `Arc<dyn CryptoSuite>`; one instance is shared across all of a node's
/// peers (it holds no per-peer state — that lives in the returned objects).
pub trait CryptoSuite: Send + Sync {
    /// Short stable name, e.g. `"noise-ik"`. For selection and logging.
    fn name(&self) -> &'static str;

    /// Begin a handshake toward a peer whose identity (static public) key we
    /// already know. `payload` is small authenticated data carried in the first
    /// message (the membership layer puts the node's cert here). Returns the
    /// in-progress handshake and the first wire message to send.
    fn initiate(
        &self,
        local_private: &[u8],
        remote_public: &[u8],
        payload: &[u8],
    ) -> Result<(Box<dyn HandshakeState>, Vec<u8>), CryptoError>;

    /// Accept an incoming first message as the responder.
    fn respond(
        &self,
        local_private: &[u8],
        init: &[u8],
        payload: &[u8],
    ) -> Result<Accepted, CryptoError>;
}

/// An initiator's handshake awaiting the responder's reply. Boxed and held by
/// the engine between sending the init and receiving the response. `Send + Sync`
/// for the same reason as [`TunnelSession`](crate::TunnelSession).
pub trait HandshakeState: Send + Sync {
    /// Finish the handshake with the responder's reply. Yields the live session
    /// and the responder's authenticated `payload`.
    fn complete(
        self: Box<Self>,
        response: &[u8],
    ) -> Result<(Box<dyn TunnelSession>, Vec<u8>), CryptoError>;
}

/// What a responder gets from accepting a handshake init.
pub struct Accepted {
    /// The established session (already in transport mode).
    pub session: Box<dyn TunnelSession>,
    /// The wire message to send back to the initiator.
    pub response: Vec<u8>,
    /// The initiator's **authenticated** identity (static public) key.
    pub peer_identity: Vec<u8>,
    /// The initiator's authenticated `payload` (membership cert + metadata).
    pub peer_payload: Vec<u8>,
}

/// The default production suite: `Noise_IK_25519_ChaChaPoly_BLAKE2s` with an
/// explicit-nonce stateless transport + replay window. Wraps the [`Handshake`]
/// / [`respond`](crate::respond) / [`NoiseSession`] primitives in this crate.
#[derive(Default, Clone, Copy)]
pub struct NoiseSuite;

impl CryptoSuite for NoiseSuite {
    fn name(&self) -> &'static str {
        "noise-ik"
    }

    fn initiate(
        &self,
        local_private: &[u8],
        remote_public: &[u8],
        payload: &[u8],
    ) -> Result<(Box<dyn HandshakeState>, Vec<u8>), CryptoError> {
        let (hs, init) = Handshake::initiate(local_private, remote_public, payload)?;
        Ok((Box::new(NoiseHandshake(hs)), init))
    }

    fn respond(
        &self,
        local_private: &[u8],
        init: &[u8],
        payload: &[u8],
    ) -> Result<Accepted, CryptoError> {
        let pending = crate::respond(local_private, init, payload)?;
        Ok(Accepted {
            session: Box::new(pending.session) as Box<dyn TunnelSession>,
            response: pending.response,
            peer_identity: pending.remote_static,
            peer_payload: pending.remote_payload,
        })
    }
}

/// Boxable initiator handshake for the Noise suite.
struct NoiseHandshake(Handshake);

impl HandshakeState for NoiseHandshake {
    fn complete(
        self: Box<Self>,
        response: &[u8],
    ) -> Result<(Box<dyn TunnelSession>, Vec<u8>), CryptoError> {
        let (session, payload) = self.0.complete(response)?;
        Ok((Box::new(session) as Box<dyn TunnelSession>, payload))
    }
}

// Allow `NoiseSession` to be used as a trait object source above.
impl From<NoiseSession> for Box<dyn TunnelSession> {
    fn from(s: NoiseSession) -> Self {
        Box::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    /// The default suite, driven only through the `CryptoSuite` trait, completes
    /// a handshake and carries authenticated traffic both ways — proving the
    /// abstraction is sufficient for the engine without naming Noise.
    #[test]
    fn noise_suite_round_trips_via_the_trait() {
        let suite = NoiseSuite;
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();

        let (hs, init) = suite
            .initiate(a.private_key(), b.public_key(), b"cert-a")
            .unwrap();
        let accepted = suite.respond(b.private_key(), &init, b"cert-b").unwrap();

        assert_eq!(
            accepted.peer_identity,
            a.public_key(),
            "responder authenticates the initiator's real identity key"
        );
        assert_eq!(accepted.peer_payload, b"cert-a");

        let (mut a_sess, b_payload) = hs.complete(&accepted.response).unwrap();
        assert_eq!(b_payload, b"cert-b");
        let mut b_sess = accepted.session;

        let sealed = a_sess.encrypt(b"hello over the suite").unwrap();
        assert_eq!(b_sess.decrypt(&sealed).unwrap(), b"hello over the suite");
        let sealed = b_sess.encrypt(b"reply").unwrap();
        assert_eq!(a_sess.decrypt(&sealed).unwrap(), b"reply");
    }
}
