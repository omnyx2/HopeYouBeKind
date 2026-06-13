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

pub mod cookie;
pub mod custom;
pub mod rekey;
pub mod replay;
pub mod session;
pub mod suite;

pub use cookie::CookieMaker;
pub use rekey::RekeyPolicy;
pub use replay::ReplayWindow;
pub use session::{respond, Handshake, NoiseSession, PendingHandshake};
pub use suite::{
    registry, suite_by_name, Accepted, CryptoSuite, HandshakeState, NoiseSuite, NOISE_AESGCM,
    NOISE_CHACHAPOLY,
};

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

    /// Load a saved identity (32-byte private ++ 32-byte public), or `None` if
    /// the file is missing or malformed.
    pub fn load(path: &std::path::Path) -> Option<Self> {
        let bytes = std::fs::read(path).ok()?;
        if bytes.len() != 64 {
            return None;
        }
        Some(Self::from_keys(bytes[32..].to_vec(), bytes[..32].to_vec()))
    }

    /// Persist this identity to `path` (creating parent dirs), with 0600 perms.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.private);
        bytes.extend_from_slice(&self.public);
        std::fs::write(path, &bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Load the identity at `path`, or generate a fresh one and save it there.
    pub fn load_or_generate(path: &std::path::Path) -> Result<Self, CryptoError> {
        if let Some(id) = Self::load(path) {
            return Ok(id);
        }
        let id = Self::generate()?;
        let _ = id.save(path); // best-effort; ephemeral if the path isn't writable
        Ok(id)
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
///
/// `Send + Sync` because the engine keeps sessions in shared state and its async
/// loop holds `&self` across `.await` points; sessions are only ever mutated
/// through `&mut`, so this is sound.
pub trait TunnelSession: Send + Sync {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Whether this session should be renegotiated, given how long it has been
    /// alive (`age`). Surfaces the suite's rekey policy to the engine, which uses
    /// it to drive a proactive re-handshake (WireGuard's REKEY_AFTER_TIME) for
    /// forward secrecy and nonce-exhaustion avoidance. The caller owns the clock
    /// (it tracks each session's creation time). A suite with no rekey policy may
    /// always return `false`.
    fn rekey_due(&self, age: std::time::Duration) -> bool;

    /// A read-only snapshot of this session's transport counters — for the admin
    /// crypto-lab session inspector. Default: zeros (suites that don't track them).
    fn stats(&self) -> SessionStats {
        SessionStats::default()
    }
}

/// Live transport counters for one session, surfaced to the crypto-lab inspector.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionStats {
    /// Outbound AEAD nonce/counter — how many packets we've sealed.
    pub send_counter: u64,
    /// Highest inbound packet counter accepted by the replay window.
    pub replay_latest: u64,
    /// Packets rejected as replays or too-old by the replay window.
    pub replay_rejects: u64,
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
    fn rekey_due(&self, _age: std::time::Duration) -> bool {
        false // the passthrough test session never rekeys
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
