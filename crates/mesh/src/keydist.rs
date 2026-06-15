//! v2 key distribution (docs/DATA_PLANE.md P3): seal a mesh's shared secret to a
//! joiner so only they can read it. A member carries an X25519 [`EncKey`] alongside
//! its ed25519 identity ([`crate::membership`]); the inviter does an ephemeral ECDH
//! with the joiner's enc pubkey and AEAD-wraps the 32-byte secret — the NaCl
//! sealed-box construction. The joiner's cert advertises its enc pubkey so any
//! member can seal to it (binding lands in the membership integration).

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// A member's X25519 encryption key (separate from its ed25519 signing identity).
pub struct EncKey(StaticSecret);

impl EncKey {
    pub fn generate() -> Self {
        Self(StaticSecret::random_from_rng(rand::rngs::OsRng))
    }
    /// Restore from the 32-byte secret (node-persisted with the rest of its join
    /// material).
    pub fn from_bytes(b: &[u8; 32]) -> Self {
        Self(StaticSecret::from(*b))
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    /// The X25519 public key others seal to.
    pub fn public(&self) -> [u8; 32] {
        PublicKey::from(&self.0).to_bytes()
    }
    /// Open a secret sealed to our public key; `None` if it wasn't for us or was
    /// tampered.
    pub fn open(&self, sealed: &SealedSecret) -> Option<[u8; 32]> {
        let shared = self.0.diffie_hellman(&PublicKey::from(sealed.ephemeral_pub));
        let key = derive_key(shared.as_bytes(), &sealed.ephemeral_pub, &self.public());
        let pt = ChaCha20Poly1305::new(Key::from_slice(&key))
            .decrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: &sealed.ct, aad: b"" })
            .ok()?;
        pt.try_into().ok()
    }
}

/// A 32-byte mesh secret sealed to a member's X25519 public key.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SealedSecret {
    pub ephemeral_pub: [u8; 32],
    /// 32-byte secret + 16-byte AEAD tag.
    pub ct: Vec<u8>,
}

/// Seal `secret` to the recipient's X25519 public key `to`. Fresh ephemeral key per
/// call, so the all-zero nonce is safe (never reused under the derived key).
pub fn seal_secret(to: &[u8; 32], secret: &[u8; 32]) -> SealedSecret {
    let eph = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(*to));
    let key = derive_key(shared.as_bytes(), &eph_pub, to);
    let ct = ChaCha20Poly1305::new(Key::from_slice(&key))
        .encrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: secret, aad: b"" })
        .expect("sealed-box encrypt");
    SealedSecret { ephemeral_pub: eph_pub, ct }
}

fn derive_key(shared: &[u8; 32], eph_pub: &[u8; 32], recipient_pub: &[u8; 32]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(b"lattice-mesh-sealedbox-v2");
    h.update(shared);
    h.update(eph_pub);
    h.update(recipient_pub);
    let mut k = [0u8; 32];
    k.copy_from_slice(&h.finalize());
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_then_open_round_trip() {
        let bob = EncKey::generate();
        let secret = [7u8; 32];
        let sealed = seal_secret(&bob.public(), &secret);
        assert_eq!(bob.open(&sealed), Some(secret));
    }

    #[test]
    fn another_key_cannot_open() {
        let bob = EncKey::generate();
        let eve = EncKey::generate();
        let sealed = seal_secret(&bob.public(), &[7u8; 32]);
        assert_eq!(eve.open(&sealed), None);
    }

    #[test]
    fn tampered_seal_fails() {
        let bob = EncKey::generate();
        let mut sealed = seal_secret(&bob.public(), &[7u8; 32]);
        sealed.ct[0] ^= 0xff;
        assert_eq!(bob.open(&sealed), None);
    }

    #[test]
    fn persisted_key_still_opens() {
        // A node that persisted its enc key (the §0.1 node-local material) can open
        // a secret sealed to it after a restart.
        let saved = EncKey::generate().to_bytes();
        let pubk = EncKey::from_bytes(&saved).public();
        let sealed = seal_secret(&pubk, &[9u8; 32]);
        assert_eq!(EncKey::from_bytes(&saved).open(&sealed), Some([9u8; 32]));
    }
}
