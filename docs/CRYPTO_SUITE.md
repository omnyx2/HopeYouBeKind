# Pluggable tunnel crypto (`CryptoSuite`)

The engine never names a concrete cipher. It drives a **`CryptoSuite`** — a trait
that owns the *entire* cryptographic story for one tunnel: the handshake
choreography, what gets authenticated, and the per-packet AEAD. Noise-IK is the
default and only production suite, but the seam exists so alternative schemes
(post-quantum KEM handshakes, different AEADs, experimental framing) can be
researched and swapped **without touching the node runtime**.

This is deliberately separate from [membership](MEMBERSHIP.md): the suite secures
the channel and authenticates the peer's identity key; membership decides whether
that identity is allowed in. You can change one without the other.

## The trait

```rust
// crates/crypto/src/suite.rs
pub trait CryptoSuite: Send + Sync {
    fn name(&self) -> &'static str;

    fn initiate(&self, local_private: &[u8], remote_public: &[u8], payload: &[u8])
        -> Result<(Box<dyn HandshakeState>, Vec<u8>), CryptoError>;

    fn respond(&self, local_private: &[u8], init: &[u8], payload: &[u8])
        -> Result<Accepted, CryptoError>;
}

pub trait HandshakeState: Send + Sync {
    fn complete(self: Box<Self>, response: &[u8])
        -> Result<(Box<dyn TunnelSession>, Vec<u8>), CryptoError>;
}

pub struct Accepted {
    pub session: Box<dyn TunnelSession>,
    pub response: Vec<u8>,
    pub peer_identity: Vec<u8>,   // the peer's AUTHENTICATED static public key
    pub peer_payload: Vec<u8>,    // authenticated handshake payload (carries the cert)
}

pub trait TunnelSession: Send + Sync {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
}
```

The two-message flow the engine expects:

```
initiator                                   responder
  initiate(priv, peer_pub, payload) ─ init ─▶ respond(priv, init, payload) → Accepted
  complete(response) → (session, peer_payload) ◀─ response ─
  ───────────────── transport: session.encrypt / .decrypt ─────────────────
```

## Two requirements every suite must meet

The membership layer is built *on top* of the suite and trusts it, so a suite
must:

1. **Mutually authenticate the peer's identity key.** `respond` returns
   `peer_identity` and the membership layer binds the cert to it; the returned
   key must be the peer's real long-term public key, not an unverified claim.
2. **Tolerate UDP loss/reordering.** Sessions are confidential and
   integrity-protected with no in-order assumption (the default uses an explicit
   per-packet nonce + a sliding replay window).

## Implementing a research suite

1. Add a type that implements `CryptoSuite` (and a `HandshakeState` for the
   initiator side, and a `TunnelSession` for the live session). Build on vetted
   primitives — don't hand-roll ciphers.
2. Inject it: `Engine::with_suite(identity, config, Arc::new(MySuite))` instead of
   `Engine::new(...)` (which defaults to `NoiseSuite`). Both ends of a tunnel must
   run the same suite — it changes the wire handshake.

The default `NoiseSuite` (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) is a thin wrapper
over `crates/crypto`'s existing handshake/session primitives — a good reference
for what a suite has to provide.

## Why it's a clean seam

- The engine stores `Arc<dyn CryptoSuite>` and `Box<dyn TunnelSession>` — it has
  no compile-time dependency on Noise.
- Wire format is owned entirely by the suite; the engine only frames messages
  (`HandshakeInit` / `HandshakeResp` / `Transport`) around the suite's bytes.
- The default suite's wire format is unchanged from before the refactor, so
  extracting the seam was behaviour-preserving.

## Status

`CryptoSuite` / `NoiseSuite` are implemented and the engine is fully on the trait
(`crates/crypto/src/suite.rs`, `crates/engine`). Suite **selection by config/flag**
(`--crypto <name>`) and a registry of research suites are not wired yet — today
you choose the suite in code via `Engine::with_suite`.
