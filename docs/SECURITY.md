# Security model

## Assets we protect
- **Node identity keys** (Curve25519 static private keys) — stored locally,
  never transmitted, wiped from memory with `zeroize`.
- **Overlay traffic** — confidentiality, integrity, authenticity in transit.

## Adversaries (in scope)
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

## Reporting
Until a public channel exists, report vulnerabilities privately to the
maintainer. Do not open public issues for exploitable findings.

## Engineering rules that back this model
- No `unwrap()`/`expect()` on untrusted-input paths (`proto`, `crypto`, `net`).
- Key material is `Zeroize`-wrapped and never logged.
- Parsers for wire formats are fuzz-tested (see CI, roadmap v0.7).
