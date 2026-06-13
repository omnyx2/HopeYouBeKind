//! ============================================================================
//!  CUSTOM CIPHER TEMPLATE — write your own encryption algorithm here.
//! ============================================================================
//!
//! This is a working, registered, swappable [`CryptoSuite`] scaffold. It already
//! compiles, round-trips in the admin crypto bench, and demonstrates a
//! time-window ("data unrecoverable after the window passes"). To make it YOUR
//! cipher, edit the two clearly-marked blocks in [`CustomSession::encrypt`] and
//! [`CustomSession::decrypt`] below — that's where your algorithm lives.
//!
//! ## Where to write code (and nothing else needs touching)
//! 1. `CustomSession::encrypt` — your encryption.   ← THE TWO PLACES
//! 2. `CustomSession::decrypt` — your decryption + the time-window reject.
//! Optionally: `CustomSession::from_handshake` (how the key is derived),
//! `CustomSuite::{name,spec}` (rename it), and the `WINDOW` constant.
//!
//! ## Build & test loop
//! ```text
//! cargo build -p lattice-daemon -p lattice-cli   # compile your cipher in
//! # restart the daemon, then:
//! lattice crypto swap custom-template            # make it the active suite
//! lattice crypto encrypt "hello"                 # → ciphertext hex
//! lattice crypto decrypt <hex>                   # → hello   (within the window)
//! # wait past WINDOW, then:
//! lattice crypto decrypt <hex>                   # → rejected (unrecoverable)
//! ```
//! Or use the admin GUI → Crypto Lab → "Encrypt / decrypt bench".
//!
//! The handshake (Noise-IK below) only does KEY AGREEMENT + peer authentication;
//! you normally keep it and just write the session cipher. See
//! `docs/CRYPTO_SUITE.md` for the full guide.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use blake2::digest::consts::U32;
use blake2::digest::Mac;

use crate::suite::{Accepted, CryptoSuite, HandshakeState};
use crate::{CryptoError, SessionStats, TunnelSession};

/// A BLAKE2s keyed MAC, used as the demo keystream PRF. (Just a placeholder —
/// your real cipher decides its own primitives.)
type Prf = blake2::Blake2sMac<U32>;

/// The Noise pattern used ONLY for key agreement + authenticating the peer. Keep
/// it (recommended — you get a real X25519 exchange for free) and write your
/// cipher in the session below, or swap it out if your scheme owns the handshake.
const KEX: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// ★ DEMO time window. Replace with your scheme's window. A ciphertext older than
/// this is refused by `decrypt` → "data unrecoverable after the window passes".
const WINDOW: Duration = Duration::from_secs(30);

/// ★ Your suite. Rename it and its `name()` (that's the `crypto swap <name>`
/// selector), then register it in `registry()` (crates/crypto/src/suite.rs).
#[derive(Clone, Copy, Default)]
pub struct CustomSuite;

impl CryptoSuite for CustomSuite {
    fn name(&self) -> &'static str {
        "custom-template" // ← `lattice crypto swap custom-template`
    }

    fn spec(&self) -> &'static str {
        "Custom_IK_25519_XorDemo_BLAKE2s" // shown in the catalogue; descriptive only
    }

    fn initiate(
        &self,
        local_private: &[u8],
        remote_public: &[u8],
        payload: &[u8],
    ) -> Result<(Box<dyn HandshakeState>, Vec<u8>), CryptoError> {
        let mut hs = snow::Builder::new(KEX.parse().expect("valid KEX spec"))
            .local_private_key(local_private)
            .remote_public_key(remote_public)
            .build_initiator()?;
        let mut buf = vec![0u8; 1024];
        let n = hs.write_message(payload, &mut buf)?;
        buf.truncate(n);
        Ok((Box::new(CustomHandshake(hs)), buf))
    }

    fn respond(
        &self,
        local_private: &[u8],
        init: &[u8],
        payload: &[u8],
    ) -> Result<Accepted, CryptoError> {
        let mut hs = snow::Builder::new(KEX.parse().expect("valid KEX spec"))
            .local_private_key(local_private)
            .build_responder()?;
        let mut scratch = vec![0u8; 1024];
        let n = hs.read_message(init, &mut scratch)?;
        let peer_payload = scratch[..n].to_vec();
        let peer_identity = hs
            .get_remote_static()
            .ok_or(CryptoError::NotEstablished)?
            .to_vec();
        let mut response = vec![0u8; 1024];
        let n = hs.write_message(payload, &mut response)?;
        response.truncate(n);
        Ok(Accepted {
            session: Box::new(CustomSession::from_handshake(&hs)),
            response,
            peer_identity,
            peer_payload,
        })
    }
}

/// The initiator's half of the handshake (you rarely need to touch this).
struct CustomHandshake(snow::HandshakeState);

impl HandshakeState for CustomHandshake {
    fn complete(
        mut self: Box<Self>,
        response: &[u8],
    ) -> Result<(Box<dyn TunnelSession>, Vec<u8>), CryptoError> {
        let mut scratch = vec![0u8; 1024];
        let n = self.0.read_message(response, &mut scratch)?;
        let peer_payload = scratch[..n].to_vec();
        Ok((Box::new(CustomSession::from_handshake(&self.0)), peer_payload))
    }
}

/// ★ Your live session. Add whatever state your cipher needs.
pub struct CustomSession {
    /// Shared key from the handshake.
    key: [u8; 32],
    /// Demo nonce source. Your cipher may use this differently or not at all.
    send_counter: u64,
}

impl CustomSession {
    /// Derive the session key from the completed handshake.
    ///
    /// NOTE: this uses the (public) handshake transcript hash, so both ends agree
    /// without snow exposing its secret keys. That is enough to TEST your cipher
    /// but is **not confidential** against an eavesdropper. For real secrecy,
    /// derive `key` from an actual shared secret (your own X25519 ECDH, or expose
    /// the Noise session keys). The crypto bench exercises your cipher's
    /// behaviour, not the key agreement.
    fn from_handshake(hs: &snow::HandshakeState) -> Self {
        let mut key = [0u8; 32];
        key.copy_from_slice(&hs.get_handshake_hash()[..32]);
        Self {
            key,
            send_counter: 0,
        }
    }
}

impl TunnelSession for CustomSession {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // ╔════════════════════════════════════════════════════════════════════╗
        // ║  ▼▼▼  YOUR ENCRYPTION ALGORITHM GOES HERE  ▼▼▼                       ║
        // ║                                                                      ║
        // ║  `self.key` is the shared key. Return the ciphertext bytes, embedding ║
        // ║  whatever your `decrypt` needs to (a) reproduce the keystream and    ║
        // ║  (b) know the time window (here: an issued-at timestamp).            ║
        // ║                                                                      ║
        // ║  The DEMO below is a counter-prefixed XOR keystream with an embedded ║
        // ║  unix timestamp — NOT secure, just so the template round-trips.      ║
        // ║  Replace the whole block with your manifold / time-window scheme.    ║
        // ╚════════════════════════════════════════════════════════════════════╝
        let issued_at = now_secs();
        let counter = self.send_counter;
        self.send_counter = self.send_counter.wrapping_add(1);

        let ks = keystream(&self.key, counter, plaintext.len());
        let mut out = Vec::with_capacity(16 + plaintext.len());
        out.extend_from_slice(&issued_at.to_be_bytes()); // wire: [issued_at(8)]
        out.extend_from_slice(&counter.to_be_bytes()); //        [counter(8)]
        out.extend(plaintext.iter().zip(ks).map(|(p, k)| p ^ k)); // [body]
        Ok(out)
        // ▲▲▲  END YOUR ENCRYPTION ALGORITHM  ▲▲▲
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // ╔════════════════════════════════════════════════════════════════════╗
        // ║  ▼▼▼  YOUR DECRYPTION ALGORITHM GOES HERE  ▼▼▼                       ║
        // ║                                                                      ║
        // ║  ★ THE TIME WINDOW LIVES HERE: return `Err(CryptoError::AuthFailed)`  ║
        // ║    once the data is older than your window. That `Err` is what the   ║
        // ║    bench shows as "✗ rejected" = the data is unrecoverable.          ║
        // ║                                                                      ║
        // ║  Demo below: reject if `now - issued_at > WINDOW`, else XOR back.     ║
        // ╚════════════════════════════════════════════════════════════════════╝
        if ciphertext.len() < 16 {
            return Err(CryptoError::AuthFailed);
        }
        let issued_at = u64::from_be_bytes(ciphertext[0..8].try_into().expect("8 bytes"));
        if now_secs().saturating_sub(issued_at) > WINDOW.as_secs() {
            return Err(CryptoError::AuthFailed); // window passed → unrecoverable
        }
        let counter = u64::from_be_bytes(ciphertext[8..16].try_into().expect("8 bytes"));
        let body = &ciphertext[16..];
        let ks = keystream(&self.key, counter, body.len());
        Ok(body.iter().zip(ks).map(|(c, k)| c ^ k).collect())
        // ▲▲▲  END YOUR DECRYPTION ALGORITHM  ▲▲▲
    }

    fn rekey_due(&self, _age: Duration) -> bool {
        false // your scheme may want time/usage-based rekeying; off for the template
    }

    fn stats(&self) -> SessionStats {
        SessionStats {
            send_counter: self.send_counter,
            ..Default::default()
        }
    }
}

/// Current unix time in seconds (for the demo window). Replace with whatever clock
/// your scheme uses.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Demo keystream: PRF(key, counter ‖ block_index) chained to `len` bytes. Purely
/// a placeholder so the template compiles and round-trips — replace with your
/// cipher's own transform.
fn keystream(key: &[u8; 32], counter: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut block: u32 = 0;
    while out.len() < len {
        let mut mac = <Prf as Mac>::new_from_slice(key).expect("32-byte key is valid");
        mac.update(&counter.to_be_bytes());
        mac.update(&block.to_be_bytes());
        out.extend_from_slice(&mac.finalize().into_bytes());
        block += 1;
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    /// The template must compile and round-trip through the trait, so it is a
    /// usable starting point the moment you swap to it.
    #[test]
    fn custom_template_round_trips() {
        let suite = CustomSuite;
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let (hs, init) = suite.initiate(a.private_key(), b.public_key(), b"").unwrap();
        let accepted = suite.respond(b.private_key(), &init, b"").unwrap();
        let (mut enc, _) = hs.complete(&accepted.response).unwrap();
        let mut dec = accepted.session;

        let ct = enc.encrypt(b"manifold test").unwrap();
        assert_ne!(&ct[..], b"manifold test");
        assert_eq!(dec.decrypt(&ct).unwrap(), b"manifold test");
    }
}
