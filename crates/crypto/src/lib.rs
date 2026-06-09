//! Lattice Tunnel Protocol (LTP) — the custom encrypted tunnel.
//!
//! We design the *protocol* (identity, handshake choreography, session framing,
//! rekeying — see `docs/PROTOCOL.md`) on top of *vetted* primitives from the
//! Noise framework (`snow`). We do not implement ciphers ourselves.
//!
//! The crate provides node identity, the [`TunnelSession`] trait, a real
//! Noise-IK handshake + session (in [`session`]), and an in-memory passthrough
//! session for testing the engine without crypto.

use lattice_proto::NodeId;
use zeroize::Zeroize;

pub mod session;

pub use session::{respond, Handshake, NoiseSession, PendingHandshake};

/// The Noise pattern + primitive suite LTP uses. Mirrors WireGuard's choices
/// because they are well analyzed: mutual auth, forward secrecy, AEAD.
pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("noise error: {0}")]
    Noise(#[from] snow::Error),
    #[error("session not established")]
    NotEstablished,
    #[error("decryption/authentication failed")]
    AuthFailed,
}

/// A node's long-term Curve25519 identity. The private key never leaves the
/// device and is zeroized on drop.
pub struct Identity {
    public: Vec<u8>,
    private: Vec<u8>,
}

impl Identity {
    /// Generate a fresh identity keypair.
    pub fn generate() -> Result<Self, CryptoError> {
        // NOISE_PARAMS is a compile-time constant in a known-good format, so a
        // parse failure here is a programmer error, not a runtime condition.
        let params = NOISE_PARAMS.parse().expect("NOISE_PARAMS is a valid spec");
        let kp = snow::Builder::new(params).generate_keypair()?;
        Ok(Self {
            public: kp.public,
            private: kp.private,
        })
    }

    /// Reconstruct an identity from previously persisted key bytes.
    pub fn from_keys(public: Vec<u8>, private: Vec<u8>) -> Self {
        Self { public, private }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    pub fn private_key(&self) -> &[u8] {
        &self.private
    }

    /// In v0 the 32-byte Curve25519 public key *is* the node identity.
    pub fn node_id(&self) -> NodeId {
        let mut id = [0u8; 32];
        let n = self.public.len().min(32);
        id[..n].copy_from_slice(&self.public[..n]);
        NodeId(id)
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

/// A live, authenticated tunnel to one peer. Encrypts outbound overlay packets
/// and decrypts inbound ones. Implementations own the AEAD/replay state.
pub trait TunnelSession: Send {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// A no-op session that copies bytes through unchanged. **Tests only** — lets us
/// exercise the engine's packet loop without standing up a real handshake.
#[derive(Default)]
pub struct PassthroughSession;

impl TunnelSession for PassthroughSession {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(plaintext.to_vec())
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(ciphertext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_has_32_byte_pubkey_and_stable_node_id() {
        let id = Identity::generate().expect("keygen");
        assert_eq!(id.public_key().len(), 32);
        // node_id is deterministic from the public key
        let again = Identity::from_keys(id.public_key().to_vec(), id.private_key().to_vec());
        assert_eq!(id.node_id(), again.node_id());
    }
}
