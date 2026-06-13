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

## Drop in your own cipher — START HERE

There is a ready-to-edit template: **`crates/crypto/src/custom.rs`** (`CustomSuite`
/ `CustomSession`). It already compiles, is registered, and works in the admin
crypto bench. You write your algorithm in **two places**, both clearly marked with
`▼▼▼ YOUR … ALGORITHM GOES HERE ▼▼▼` banners:

| Edit | Location | What goes there |
| --- | --- | --- |
| **1** | `CustomSession::encrypt` (`custom.rs`) | your encryption — return ciphertext bytes, embedding whatever `decrypt` needs (a nonce/counter, and a timestamp if your scheme has a time window) |
| **2** | `CustomSession::decrypt` (`custom.rs`) | your decryption — and **return `Err(CryptoError::AuthFailed)` once your time window has passed**; that `Err` is what makes the data unrecoverable (the bench shows "✗ rejected") |

Optional knobs in the same file: `WINDOW` (the demo time window), `from_handshake`
(how the session key is derived — see its note on confidentiality), and
`CustomSuite::{name, spec}` (rename your suite; `name()` is the `crypto swap`
selector). You normally **keep the Noise-IK handshake** for key agreement + peer
authentication and only write the session cipher.

To register a *second* suite (or rename), add `Arc::new(YourSuite)` to `registry()`
in `crates/crypto/src/suite.rs`.

### Build → swap → test loop

```text
cargo build -p lattice-daemon -p lattice-cli     # compile your cipher in
# restart the daemon (Stop the Windows daemon BEFORE building — it locks the .exe)
lattice crypto swap custom-template              # make it the active suite (rename as you like)
lattice crypto encrypt "hello"                   # → ciphertext hex
lattice crypto decrypt <hex>                     # → hello       (within the window)
#   …wait past your WINDOW…
lattice crypto decrypt <hex>                     # → rejected    (data unrecoverable)
```

Or use the admin console → **Crypto Lab → "Encrypt / decrypt bench"** (plaintext →
ciphertext, ciphertext → plaintext or ✗ rejected). The bench is self-contained (a
local session pair under the active suite), so you don't need two real nodes to
test the cipher. Keep the bench session alive between an encrypt and a later
decrypt — don't swap suites or restart in between, or the pair is rebuilt.

The default `NoiseSuite` (`Noise_IK_25519_ChaChaPoly_BLAKE2s`,
`crates/crypto/src/suite.rs`) is the reference implementation built on the crate's
vetted primitives. Build on vetted primitives — don't hand-roll ciphers unless
that *is* the research.

## Implementing a research suite (manual injection)

Outside the registry/bench flow you can also inject a suite directly:
`Engine::with_suite(identity, config, Arc::new(MySuite))` instead of
`Engine::new(...)`. The daemon's `--crypto <name>` flag resolves a registered
suite at startup; the admin `SetCryptoSuite` IPC / `lattice crypto swap` hot-swaps
it at runtime (dropping + re-handshaking every session). Both ends of a tunnel
must run the same suite — it changes the wire handshake.

## Why it's a clean seam

- The engine stores `Arc<dyn CryptoSuite>` and `Box<dyn TunnelSession>` — it has
  no compile-time dependency on Noise.
- Wire format is owned entirely by the suite; the engine only frames messages
  (`HandshakeInit` / `HandshakeResp` / `Transport`) around the suite's bytes.
- The default suite's wire format is unchanged from before the refactor, so
  extracting the seam was behaviour-preserving.

## Status

Fully wired. `CryptoSuite` / `TunnelSession` (`crates/crypto/src/suite.rs`,
`lib.rs`) drive the engine; a **registry** (`registry()` / `suite_by_name()`) lists
the available suites — `noise-ik-chachapoly` (default), `noise-ik-aesgcm`, and the
`custom-template` scaffold. **Selection** is wired three ways: the `--crypto <name>`
daemon flag (startup), `lattice crypto swap <name>` / the admin `SetCryptoSuite`
IPC (runtime hot-swap → drops + re-handshakes every session), and
`Engine::with_suite` (in code). The admin **Crypto Lab** adds a side-by-side
handshake comparison, a live session inspector, and an **encrypt/decrypt bench**
(`lattice crypto encrypt|decrypt`) for testing a cipher in isolation — including
"encrypt now, decrypt later" for time-window schemes.
