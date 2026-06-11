# Changelog

All notable changes to Lattice are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the API and on-wire protocol are unstable: minor
bumps (`0.x.0`) may break compatibility, patch bumps (`0.0.x`) are additive/fixes.

## [Unreleased]

### Added
- **Pluggable tunnel crypto (`CryptoSuite`)**: the engine no longer names a
  concrete cipher — it drives an `Arc<dyn CryptoSuite>` that owns the whole
  handshake + session-encryption story. `NoiseSuite` (Noise-IK) is the default;
  alternative schemes drop in by implementing the trait. `Engine::with_suite`
  injects one. Wire format unchanged for the default.
- **Mesh membership with a network CA (`lattice-membership`)**: a network is an
  Ed25519 keypair whose public half is the `NetworkId` (the stable, shareable
  mesh id). The CA admits nodes by signing a `MemberCert` (binds a node's
  identity key to the network, with serial + optional expiry) and evicts them by
  signing a `Revocation`. The engine presents its cert in the handshake and
  rejects peers without a valid, unrevoked cert for the network; revocations
  gossip across the mesh (`MessageType::Revocation`) and drop evicted peers.
  Membership is orthogonal to the crypto suite. Open mode (no network) keeps the
  prior behaviour.
- **Mesh management UX** (daemon/CLI/GUI): `--network-key` makes a node the admin
  (holds the CA, self-issues its cert); `--member-cert` joins with an issued
  token. IPC + `lattice net {info,issue,join,revoke,members}` + a GUI **Mesh**
  tab drive the serverless enrollment flow: admin issues a join token for a
  node id, that node pastes it to join, and the admin can list and revoke
  members (eviction propagates over the mesh). Admins keep a member registry so
  serials stay stable across restarts.

### Fixed
- **Membership re-verification on join**: joining a network at runtime now drops
  existing sessions so they re-handshake and are re-verified under the network —
  previously a session formed in open mode stayed unauthenticated and wasn't
  bound to a cert serial, so a later revocation couldn't evict it. Reconnection
  is now prompt (handshakes are re-initiated to known peers each keepalive tick,
  not only on a discovery re-emit), which also fixes slow reconnection after a
  dropped session. Validated live with three Docker nodes: runtime enroll → full
  mesh → revoke → eviction across the whole mesh.

- **Traffic monitor**: a passive per-flow observer of everything crossing the
  tunnel. `lattice-engine` gained a `monitor` module (`TrafficMonitor`) that
  records each plaintext packet on the outbound (pre-encrypt) and inbound
  (post-decrypt) paths, aggregating by `(peer, protocol, local, remote)` with
  per-direction packet/byte counters; both directions collapse onto one flow.
  Bounded to 512 flows. Surfaced over IPC (`Request::Flows`/`Response::Flows`,
  `FlowRecord`), via the CLI (`lattice flows`), and in a new GUI **Traffic** tab
  (live table + sent/received totals, with a freeze toggle). The on-wire peer
  protocol is unchanged — the monitor is passive and the IPC addition is
  backward-compatible. Verified live over a real Mac↔Ubuntu LAN tunnel
  (ICMP/TCP/UDP flows captured with correct ports and bidirectional counts).

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

- **GUI dashboard expansion**: shows the node's public (STUN) address, full
  copyable node id (to share for `--peer`), and each peer's physical endpoint.
  `NodeStatus` gained a `public_addr` field (set by the daemon after STUN).
- **`docs/FEATURES.md`**: a categorized status table of everything implemented.

### Fixed
- IPC `Response` now uses adjacent serde tagging so the `Peers(Vec)` payload
  serializes (internal tagging cannot tag a sequence); regression test added.
- mDNS surfaced IPv6 candidates that an IPv4 socket couldn't dial (EINVAL),
  aborting handshakes — now filtered to IPv4, and a bad candidate no longer
  aborts the others.
- IPC socket is chmod 0666 so the unprivileged CLI/GUI connect without sudo.

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
