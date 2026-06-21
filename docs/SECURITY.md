# Security model

## Assets we protect
- **Node identity keys** (Curve25519 static private keys) — stored locally,
  never transmitted, wiped from memory with `zeroize`.
- **Overlay traffic** — confidentiality, integrity, authenticity in transit.

## Adversaries (in scope)
> The table below describes the **v1 engine** (Noise-IK sessions). The **v2 mesh data
> plane** (current) seals each frame with a per-mesh dropbox cipher + time-windowed
> header + P-C5 scramble; its specifics are in [`DATA_PLANE.md`](DATA_PLANE.md) /
> [`CRYPTO_SURFACE.md`](CRYPTO_SURFACE.md), and the operational hardening is in
> [Hardening (v0.6.1)](#hardening-v061) below.

| Adversary             | Capability                              | Mitigation                             |
| --------------------- | --------------------------------------- | -------------------------------------- |
| Passive eavesdropper  | reads all UDP datagrams                 | AEAD encryption (ChaCha20-Poly1305)    |
| Active MITM           | drops/injects/modifies datagrams        | Noise IK mutual auth + AEAD integrity  |
| Replayer              | re-sends captured datagrams             | per-session counter + sliding window   |
| Address spoofer       | claims another node's virtual IP        | virtual IP derived from public key     |
| Handshake flooder     | spams HANDSHAKE_INIT to exhaust state   | stateless cookie challenge (roadmap)   |

## Out of scope (v0 — documented honestly)
- Traffic-analysis resistance (size/timing correlation).
- Post-quantum security.
- Defense against a *valid, authenticated* peer behaving maliciously inside the
  mesh (mitigated later by overlay ACLs / per-port policy).
- Endpoint compromise (if the OS is owned, keys are exposed).

## Trust & distribution
- **Serverless** means there is no central authority vouching for identities.
  v0 uses **trust-on-first-use** plus out-of-band key/NodeId verification (the
  GUI shows a short fingerprint to compare). A future web-of-trust or optional
  signing authority is a roadmap item, not a requirement.

## Hardening (v0.6.1)
Operational hardening of the v2 mesh data plane / daemon. See
[`ERRORS.md`](ERRORS.md) (2026-06-21) for the rationale and live validation.

- **Data-plane nonce — no reuse across restarts.** The AEAD nonce is the send
  counter (`seq`). Body/header keys derive from the *persisted* secret+epoch, so a
  restart keeps the same key; the counter therefore seeds from a **random 63-bit
  per-boot start** instead of 0 (resetting to 0 would replay nonces under the same
  key — ChaCha20-Poly1305 keystream reuse). Wire-compatible: the receiver derives the
  nonce from the transmitted `seq`, so old and new nodes interoperate.
- **Local control socket — opt-in uid allow-list.** The daemon's unix socket is
  world-rw so the root daemon's user-level GUI can reach it; the daemon also reads the
  peer's uid (`SO_PEERCRED` / `getpeereid`). The default trusts local processes; set
  `LATTICE_ALLOW_UID=<uid>[,uid…]` to restrict the socket to root + the daemon's uid +
  `$SUDO_UID` + the listed uids (for shared/multi-user hosts). Refusals are logged.
- **Bounded gossip.** Roster/revocation/flow gossip is size-capped
  (`MAX_GOSSIP_BYTES` = 64 KiB) with per-collection caps (certs 1024, revocations 512,
  flow-rules 512), so a member gossiping junk can't grow a peer's memory without bound.
- **No silent route/DNS failure.** Full-tunnel route/DNS setup surfaces OS-side
  failures via `dp_error` (shown by `lattice info` / the GUI) instead of reporting a
  silently-broken "VPN on".

These narrow the "malicious valid peer" / "untrusted local process" surface but do not
remove it: a mesh member still shares the mesh key and can read/relay mesh traffic, and
the socket default still trusts local processes. Invite only those you trust; use
`LATTICE_ALLOW_UID` on multi-user hosts.

## Reporting
Until a public channel exists, report vulnerabilities privately to the
maintainer. Do not open public issues for exploitable findings.

## Engineering rules that back this model
- No `unwrap()`/`expect()` on untrusted-input paths (`proto`, `crypto`, `net`).
- Key material is `Zeroize`-wrapped and never logged.
- Parsers for wire formats are fuzz-tested (see CI, roadmap v0.7).
