//! v2 per-mesh symmetric crypto (docs/MESH_V2.md §4–§5).
//!
//! Each mesh encrypts its frames under an **epoch key** derived from that epoch's
//! shared secret + the monotonic epoch number (§5). The default suite is
//! ChaCha20-Poly1305 AEAD; the research **manifold / time-window** cipher will be a
//! second suite, selected by the charter's `initial_cipher`.
//!
//! The epoch is mixed into key derivation, so a re-cipher (new epoch with a fresh
//! secret) yields an unrelated key: an expelled node's old-epoch key can't read the
//! new traffic. Replay protection and the nonce counter live in the data plane; the
//! header is passed here as AEAD associated data so tampering is detected.

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

/// Bytes the AEAD appends (Poly1305 tag).
pub const TAG_LEN: usize = 16;

/// A mesh's AEAD bound to one epoch.
pub struct MeshCipher {
    epoch: u64,
    cipher: ChaCha20Poly1305,
}

impl MeshCipher {
    /// Build the cipher for `epoch` from that epoch's shared `secret`.
    pub fn new(secret: &[u8; 32], epoch: u64) -> Self {
        let key = epoch_key(secret, epoch);
        Self {
            epoch,
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Seal `plaintext` under `nonce` (a per-epoch counter), authenticating `aad`
    /// (the v2 header). Returns `ciphertext || tag`.
    pub fn seal(&self, nonce: u64, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        self.cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes(nonce)),
                Payload { msg: plaintext, aad },
            )
            .expect("chacha20poly1305 seal")
    }

    /// Open `ciphertext`; `None` if authentication fails (wrong key/epoch/aad or
    /// tampering).
    pub fn open(&self, nonce: u64, ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        self.cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes(nonce)),
                Payload { msg: ciphertext, aad },
            )
            .ok()
    }
}

/// The **cipher seam** — a mesh's symmetric suite, kept deliberately separate so the
/// data plane is suite-agnostic. The research time-window cipher
/// (docs/CIPHER_TIMEWINDOW.md) will be a second `impl MeshSuite`, dropped in here
/// without touching any caller. It is **parked** for now; we ship the simple
/// default.
pub trait MeshSuite: Send + Sync {
    /// Suite name (logged / matched against `charter.initial_cipher`).
    fn name(&self) -> &'static str;
    /// Seal `plaintext` under per-message `seq`, authenticating `aad` (the header).
    fn seal(&self, seq: u64, plaintext: &[u8], aad: &[u8]) -> Vec<u8>;
    /// Open; `None` on auth failure (or, for forward-secure suites, once the key for
    /// `seq` has been erased).
    fn open(&self, seq: u64, ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>>;
}

impl MeshSuite for MeshCipher {
    fn name(&self) -> &'static str {
        "chachapoly-epoch"
    }
    fn seal(&self, seq: u64, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        MeshCipher::seal(self, seq, plaintext, aad)
    }
    fn open(&self, seq: u64, ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        MeshCipher::open(self, seq, ciphertext, aad)
    }
}

/// Build a mesh's cipher suite by name (from `charter.initial_cipher`). For now
/// every name maps to the simple epoch-keyed default; the research time-window
/// suite lands here later (one extra match arm + impl).
pub fn suite(_name: &str, secret: &[u8; 32], epoch: u64) -> Box<dyn MeshSuite> {
    Box::new(MeshCipher::new(secret, epoch))
}

fn epoch_key(secret: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(b"lattice-mesh-epoch-v2");
    h.update(secret);
    h.update(epoch.to_be_bytes());
    let mut k = [0u8; 32];
    k.copy_from_slice(&h.finalize());
    k
}

/// 96-bit nonce: the low 64 bits hold the per-epoch counter (the high 32 stay 0).
fn nonce_bytes(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [9u8; 32];
    const AAD: &[u8] = b"\x02\x07\x01\x09\x03"; // a stand-in v2 header

    #[test]
    fn seal_open_round_trip() {
        let c = MeshCipher::new(&SECRET, 0);
        let ct = c.seal(1, b"hello mesh", AAD);
        assert_ne!(ct, b"hello mesh"); // actually encrypted
        assert_eq!(c.open(1, &ct, AAD).unwrap(), b"hello mesh");
    }

    #[test]
    fn wrong_aad_fails() {
        let c = MeshCipher::new(&SECRET, 0);
        let ct = c.seal(1, b"hi", AAD);
        assert!(c.open(1, &ct, b"different header").is_none());
    }

    #[test]
    fn wrong_nonce_fails() {
        let c = MeshCipher::new(&SECRET, 0);
        let ct = c.seal(1, b"hi", AAD);
        assert!(c.open(2, &ct, AAD).is_none());
    }

    #[test]
    fn different_epoch_cannot_open() {
        let e0 = MeshCipher::new(&SECRET, 0);
        let e1 = MeshCipher::new(&SECRET, 1);
        let ct = e0.seal(1, b"epoch-0 only", AAD);
        assert!(e1.open(1, &ct, AAD).is_none()); // epoch is in the key derivation
        assert_eq!(e0.open(1, &ct, AAD).unwrap(), b"epoch-0 only");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let c = MeshCipher::new(&SECRET, 0);
        let mut ct = c.seal(1, b"hi", AAD);
        ct[0] ^= 0xff;
        assert!(c.open(1, &ct, AAD).is_none());
    }

    #[test]
    fn distinct_nonces_give_distinct_ciphertext() {
        let c = MeshCipher::new(&SECRET, 0);
        assert_ne!(c.seal(1, b"same", AAD), c.seal(2, b"same", AAD));
    }

    #[test]
    fn suite_seam_round_trips() {
        let s = suite("noise-ik-chachapoly", &SECRET, 0);
        assert_eq!(s.name(), "chachapoly-epoch");
        let ct = s.seal(1, b"via the seam", AAD);
        assert_eq!(s.open(1, &ct, AAD).unwrap(), b"via the seam");
        assert!(s.open(2, &ct, AAD).is_none());
    }
}
