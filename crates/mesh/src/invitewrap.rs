//! P-C6 invite-code wrapper + identity expiry (docs/PROTOCOL_DESIGN.md §2).
//!
//! The joiner's **identity code** carries an `issued_at` and expires
//! ([`IDENTITY_TTL_SECS`]), so a stale code can't be re-used. The inviter turns the
//! [`InviteBlob`](crate::ipc::InviteBlob) into an **invite code** by sealing it under
//! a key derived from a per-invite salt + the inviter's integer `n` **and the chosen
//! transform algorithm** — whose name is **not on the wire**. The joiner must learn
//! the algorithm out-of-band (ask the inviter), so a leaked invite code is useless
//! without it; a wrong guess fails the AEAD (which P-C7 counts toward the 3-strike
//! lockout).
//!
//! This is an **obscurity / friction layer** (§8-3): the genuine secret — the mesh
//! secret, x25519-sealed to the joiner's enc key — lives *inside* the wrapped blob.

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

/// How long a freshly-minted identity code stays valid (seconds).
pub const IDENTITY_TTL_SECS: u64 = 600;

/// The default transform algorithm.
pub const DEFAULT_ALGO: &str = "mix-chacha-v1";

/// The registered transform algorithms — the secret the joiner must know (§2). Each
/// is just a KDF domain; picking the wrong one derives the wrong key, so the unwrap
/// fails. (More can be added; the *choice* is the obscurity.)
pub fn invite_algorithms() -> &'static [&'static str] {
    &[DEFAULT_ALGO, "mix-chacha-alt"]
}

pub fn is_known_algo(a: &str) -> bool {
    invite_algorithms().contains(&a)
}

fn mix_key(algo: &str, salt: &[u8; 32], n: u32) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(b"lattice-invite-wrap-v1");
    h.update(algo.as_bytes());
    h.update(salt);
    h.update(n.to_be_bytes());
    let mut k = [0u8; 32];
    k.copy_from_slice(&h.finalize());
    k
}

/// Seal `plain` (a serialized `InviteBlob`) under (algo, salt, n). A zero nonce is
/// safe: the key is unique per invite because `salt` is fresh-random each time.
pub fn wrap(algo: &str, salt: &[u8; 32], n: u32, plain: &[u8]) -> Vec<u8> {
    let key = mix_key(algo, salt, n);
    ChaCha20Poly1305::new(Key::from_slice(&key))
        .encrypt(
            Nonce::from_slice(&[0u8; 12]),
            Payload {
                msg: plain,
                aad: b"",
            },
        )
        .expect("invite wrap")
}

/// Open a wrapped invite. `None` if the algorithm/salt/n don't match (e.g. the joiner
/// guessed the wrong algorithm) or the bytes were tampered with.
pub fn unwrap(algo: &str, salt: &[u8; 32], n: u32, ct: &[u8]) -> Option<Vec<u8>> {
    let key = mix_key(algo, salt, n);
    ChaCha20Poly1305::new(Key::from_slice(&key))
        .decrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: ct, aad: b"" })
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trips() {
        let salt = [5u8; 32];
        let ct = wrap(DEFAULT_ALGO, &salt, 42, b"the invite blob");
        assert_ne!(ct, b"the invite blob");
        assert_eq!(
            unwrap(DEFAULT_ALGO, &salt, 42, &ct).unwrap(),
            b"the invite blob"
        );
    }

    #[test]
    fn wrong_algorithm_or_params_fail() {
        let salt = [5u8; 32];
        let ct = wrap(DEFAULT_ALGO, &salt, 42, b"secret");
        // Wrong algorithm (the joiner guessed wrong) → fails.
        assert!(unwrap("mix-chacha-alt", &salt, 42, &ct).is_none());
        // Wrong n / salt → fails.
        assert!(unwrap(DEFAULT_ALGO, &salt, 43, &ct).is_none());
        assert!(unwrap(DEFAULT_ALGO, &[6u8; 32], 42, &ct).is_none());
    }

    #[test]
    fn algorithm_registry() {
        assert!(is_known_algo(DEFAULT_ALGO));
        assert!(is_known_algo("mix-chacha-alt"));
        assert!(!is_known_algo("nope"));
    }
}
