//! Stateless cookie challenge for handshake-flood mitigation.
//!
//! Under load a responder can reply to a `HANDSHAKE_INIT` with a cookie instead
//! of allocating session state, and only proceed once the initiator echoes it.
//! The cookie is a keyed MAC over the initiator's address, so the responder
//! verifies it without storing anything — a spoofed source address can't echo a
//! valid cookie because packets to it never arrive. See PROTOCOL.md.

use std::net::SocketAddr;

use blake2::digest::consts::U32;
use blake2::digest::Mac;

/// BLAKE2s keyed MAC producing a 32-byte tag.
type CookieMac = blake2::Blake2sMac<U32>;

pub const COOKIE_LEN: usize = 32;

/// Issues and verifies cookies under a process-local secret. Rotate the secret
/// periodically so old cookies expire.
pub struct CookieMaker {
    secret: [u8; 32],
}

impl CookieMaker {
    pub fn new(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    /// A maker seeded with fresh random secret.
    pub fn random() -> Self {
        use rand::Rng;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill(&mut secret[..]);
        Self::new(secret)
    }

    /// The cookie an initiator at `client` must echo: `MAC(secret, client)`.
    pub fn issue(&self, client: SocketAddr) -> [u8; COOKIE_LEN] {
        let mut mac =
            <CookieMac as Mac>::new_from_slice(&self.secret).expect("32-byte key is valid");
        mac.update(client.to_string().as_bytes());
        let tag = mac.finalize().into_bytes();
        let mut cookie = [0u8; COOKIE_LEN];
        cookie.copy_from_slice(&tag);
        cookie
    }

    /// Constant-time check that `cookie` is the one we'd issue for `client`.
    pub fn verify(&self, client: SocketAddr, cookie: &[u8]) -> bool {
        ct_eq(&self.issue(client), cookie)
    }
}

/// Constant-time byte comparison (no early return on first mismatch).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_round_trips_and_binds_to_client_address() {
        let maker = CookieMaker::new([42u8; 32]);
        let client: SocketAddr = "203.0.113.7:55000".parse().unwrap();

        let cookie = maker.issue(client);
        assert!(maker.verify(client, &cookie));

        let spoofed: SocketAddr = "203.0.113.8:55000".parse().unwrap();
        assert!(
            !maker.verify(spoofed, &cookie),
            "cookie is bound to the address"
        );

        let mut tampered = cookie;
        tampered[0] ^= 1;
        assert!(!maker.verify(client, &tampered));
    }

    #[test]
    fn different_secrets_yield_different_cookies() {
        let client: SocketAddr = "198.51.100.1:1234".parse().unwrap();
        let a = CookieMaker::new([1u8; 32]).issue(client);
        let b = CookieMaker::new([2u8; 32]).issue(client);
        assert_ne!(a, b);
    }
}
