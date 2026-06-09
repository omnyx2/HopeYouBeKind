# Changelog

All notable changes to Lattice are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the API and on-wire protocol are unstable: minor
bumps (`0.x.0`) may break compatibility, patch bumps (`0.0.x`) are additive/fixes.

## [Unreleased]

### Added
- **`lattice-dht`**: a Kademlia DHT for serverless peer rendezvous — XOR distance
  metric, k-bucket routing table, iterative node/value lookup, and a
  `Rendezvous` impl (publish candidates to the k closest nodes; look them up by
  node id). Verified by a 40-node in-memory simulated network.
- **`DhtNode`**: a real UDP DHT server with a request-id-demuxing transport
  (background serve loop + matched query replies). Verified with 3 nodes over
  localhost UDP.
- **Daemon DHT wiring**: `--dht-bind`, `--dht-bootstrap`, and `--peer <hex-id>`.
  The daemon runs a DHT node, publishes its STUN candidate under its node id, and
  resolves `--peer` ids via the DHT, feeding endpoints to the engine through a
  merged `ChannelDiscovery` (mDNS + DHT). Verified live (binds, publishes).
- **`--no-tun`** headless daemon mode (control plane without root) and
  `ChannelDiscovery` for merging discovery sources.

### Fixed
- IPC `Response` now uses adjacent serde tagging so the `Peers(Vec)` payload
  serializes (internal tagging cannot tag a sequence); regression test added.

## [0.7.0] — 2026-06-09

### Added — v0.7 hardening
- **Replay window** (`lattice-crypto::replay`): sliding-window anti-replay over a
  monotonic packet counter (accept-once, reject duplicates/too-old, allow
  in-window reorder).
- **Rekey policy** (`lattice-crypto::rekey`): rekey after a message ceiling or
  max age; wired into `NoiseSession` (`rekey_due`).
- **Stateless handshake cookie** (`lattice-crypto::cookie`): BLAKE2s-keyed MAC
  bound to the initiator's address for handshake-flood mitigation.
- **Fuzz targets** (`fuzz/`): libfuzzer harnesses for the datagram and STUN
  parsers.

### Added — v0.6 NAT traversal
- `lattice-net::nat`: RFC 5389 STUN binding codec, `reflexive_address()`, and
  `punch()`. Engine hole-punches across all candidate endpoints and routes via
  the winning session; daemon logs its STUN public address. `Rendezvous` trait
  scopes the remaining serverless-DHT work.

### Added — v0.5 cross-platform data plane
- Real Linux `/dev/net/tun` and Windows Wintun TUN devices. Workspace
  cross-compiles for macOS, Linux, and Windows.

### Added — v0.4 control plane
- `lattice-ipc` crate (newline-JSON over a Unix socket); daemon IPC server backed
  by a cloneable `EngineHandle`; CLI speaks real IPC; GUI commands call the
  daemon. Mesh up/down is a live toggle.

### Added — v0.3 LAN discovery
- Real mDNS advertise + browse in `lattice-net` (`_lattice._udp.local`),
  surfacing peers to the engine's auto-handshake.

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

[Unreleased]: https://github.com/your-org/lattice/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/your-org/lattice/compare/v0.2.0...v0.7.0
[0.2.0]: https://github.com/your-org/lattice/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/your-org/lattice/releases/tag/v0.1.0
