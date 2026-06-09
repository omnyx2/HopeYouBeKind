# Changelog

All notable changes to Lattice are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the API and on-wire protocol are unstable: minor
bumps (`0.x.0`) may break compatibility, patch bumps (`0.0.x`) are additive/fixes.

## [Unreleased]

## [0.2.0] — 2026-06-09

### Added
- **Custom encrypted tunnel (LTP):** real Noise-IK handshake + AEAD session in
  `lattice-crypto` (`Handshake`, `respond`, `NoiseSession`). Mutual auth, the
  responder learns the initiator's static key, tampered ciphertext is rejected.
- **Datagram framing** in `lattice-proto::wire` (`encode`/`decode`).
- **Engine packet loop:** TUN ⇄ route ⇄ encrypt ⇄ transport, with eager
  handshake on peer discovery. End-to-end test tunnels a packet between two
  in-memory nodes with no root or real NIC.
- **macOS utun device** (`lattice-tun`): real `utun` creation, address/route
  setup, async read/write (runs under `sudo`).
- **In-memory `Transport` pair** and `Overlay::set_status` for testing.
- **Daemon** now opens the real TUN device, binds UDP, starts mDNS, and runs
  the engine (peer discovery browse arrives in v0.3).

## [0.1.0] — 2026-06-09

### Added
- Initial Cargo workspace and crate boundaries (proto, crypto, tun, net,
  overlay, engine, daemon, cli).
- Architecture, protocol, roadmap, and security design documents.
- CI (fmt, clippy, test, 3-OS build matrix) and tag-driven release workflow.

## [0.1.0] — 2026-06-09

### Added
- Project scaffold and module skeletons.

[Unreleased]: https://github.com/your-org/lattice/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/your-org/lattice/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/your-org/lattice/releases/tag/v0.1.0
