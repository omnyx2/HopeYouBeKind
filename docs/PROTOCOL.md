# Lattice Tunnel Protocol (LTP) — v0 draft

> This is the design document for the **custom encrypted tunnel** — the core
> research contribution. It specifies the protocol we design; it deliberately
> does **not** reinvent cryptographic primitives. Primitives come from the Noise
> Protocol Framework (`snow` crate); LTP defines how we *use* them.

## Design goals

1. **Confidentiality + integrity + authenticity** of every overlay packet.
2. **Mutual authentication** — both peers prove possession of their static key.
3. **Forward secrecy** — compromise of long-term keys does not decrypt past
   sessions.
4. **Replay protection** — a captured datagram cannot be re-injected.
5. **Identity-bound addressing** — a node's virtual IP is derived from its
   public key, so you cannot trivially impersonate another node's address.

## Cryptographic foundation (NOT designed by us — vetted)

| Concern        | Choice                                   |
| -------------- | ---------------------------------------- |
| Handshake      | Noise `IK` pattern                       |
| DH             | Curve25519                               |
| AEAD           | ChaCha20-Poly1305                        |
| Hash           | BLAKE2s                                  |

The Noise `IK` pattern gives mutual auth with the initiator knowing the
responder's static key up front (we do — it is the peer's identity, distributed
via discovery). This mirrors WireGuard's choices because they are well analyzed.

## Identity & addressing

- A node's **identity** is a Curve25519 static keypair, generated once and
  stored locally (never leaves the device).
- The **NodeId** is `BLAKE2s(static_public_key)` truncated — a stable,
  collision-resistant handle used in discovery and the peer registry.
- The **virtual IP** is derived deterministically from the NodeId inside the
  overlay CGNAT range `100.64.0.0/10`. (Collision handling: see `overlay`.)

## What WE design (the research surface)

These are the parts LTP specifies on top of Noise — the parts worth writing up:

### 1. Session framing

```
Datagram on the wire (inside one UDP packet):

  0       1               4                        N
  +-------+---------------+------------------------+
  | type  |   reserved    |        payload         |
  +-------+---------------+------------------------+

  type 0x01  HANDSHAKE_INIT      payload = Noise msg 1
  type 0x02  HANDSHAKE_RESP      payload = Noise msg 2
  type 0x03  TRANSPORT           payload = counter(8B) || AEAD ciphertext
  type 0x04  KEEPALIVE           payload = empty (authenticated)
```

### 2. Rekeying policy (our parameters)

- A session rekeys after **N = 2^60 messages** or **T = 120 s**, whichever first.
- Initiator-driven; responder accepts a new handshake at any time and atomically
  swaps the live session once the first valid transport message arrives under
  the new keys (avoids a drop window).

### 3. Replay window

- Per-session monotonic 64-bit counter, validated with a sliding bitmap window
  of size 2048 (à la IPsec anti-replay). Out-of-window or duplicate → drop.

### 4. Cookie / DoS mitigation (roadmap)

- Under load, responder may reply to `HANDSHAKE_INIT` with a stateless cookie
  the initiator must echo, so we don't allocate session state for spoofed IPs.

## Threat model (summary — full version in SECURITY.md)

- **In scope:** passive eavesdropper, active MITM, replay, address spoofing,
  handshake-flood DoS.
- **Out of scope (v0):** traffic-analysis resistance (packet sizing/timing),
  post-quantum security, malicious-but-authenticated peers.

## Open research questions (good thesis material)

- Can we bound handshake-flood cost without a central server issuing cookies?
- Does deriving the virtual IP from the key (vs. central allocation) meaningfully
  reduce the trust surface, and what are the collision/migration costs?
- Serverless rekey coordination across a churning mesh.
