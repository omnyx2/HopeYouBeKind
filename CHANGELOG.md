# Changelog

All notable changes to Lattice are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the API and on-wire protocol are unstable: minor
bumps (`0.x.0`) may break compatibility, patch bumps (`0.0.x`) are additive/fixes.

> **Note:** the `[Unreleased]` / `[0.x.0]` sections below pre-date the v2 rewrite and
> describe the **v1 engine** (Noise-IK, network CA). v2 release notes start here.

## [0.7.10] — 2026-07-25

### Changed
- **`lattice ls` / `status` now surface an active split-tunnel.** While split is on, the host
  resolver is pointed at meshd's `127.0.0.1:53` proxy and matched domains route via a mesh exit —
  even when no mesh is selected for egress (`is_current=false`, shown as `direct`/Default). That
  state was previously only visible via `lattice split list`, so a node could be hijacking DNS +
  routing some domains through a mesh with no hint in the main status. Both views now print a
  `split-tunnel: ON (mesh #N …) — host DNS → meshd` line.

### Fixed
- **Serving/pinned-exit nodes never purged legacy all-overlay forwarding rules.** The
  `100.64.0.0/10` legacy-rule purge added in v0.7.8 ran only in `disable_nat` (the non-serving
  path), so a pinned exit (`MESHD_ADVERTISE`) — which only ever calls `enable_nat` — kept every
  leftover `FORWARD -s/-d 100.64.0.0/10 ACCEPT` rule from an older always-on build (found 130
  accumulated on the live Oracle exit via a post-network-change cross-check). Harmless on a
  `FORWARD -P ACCEPT` host but a forwarding-policy leak on `FORWARD -P DROP` (it would forward for
  meshes the node never opted into). `enable_nat` now runs the same purge on the serving path.

### Known limitations (documented, not yet fixed)
- **Split-tunnel / full-tunnel are IPv4-only.** The overlay is IPv4 (`100.64.0.0/10`); on a
  dual-stack network a matched domain that resolves to IPv6 (AAAA) egresses directly over IPv6,
  bypassing the mesh exit. Force IPv4 (`curl -4`) to route via the exit. See docs/SPLIT_TUNNEL.md.
- Changing a split rule's exit member on an already-active rule needs `split off`/`split on` to
  re-inject the route (the previous flow stays cached until then).

## [0.7.9] — 2026-07-25

### Fixed
- **Pinned exit's overlay silently broke (isolate + per-subnet NAT regression).** After v0.7.8 made
  the exit NAT/`isolate` rules per-subnet (`100.80.<id>.0/24`), the Linux `ip rule from <subnet>
  lookup <iso-table>` (and the macOS pf `route-to ... to any`) also matched the exit node's OWN
  overlay IP — which sits inside that subnet — so the node's member↔member replies were diverted
  out the real WAN instead of the tun. A pinned exit (`MESHD_ADVERTISE`) could still be reached
  via gossip but its data path to other members died (overlay ssh/ping timed out) until a
  reconcile. Fix: overlay-destined traffic now bypasses the isolate rule — Linux adds a
  higher-priority `to 100.64.0.0/10 lookup main` rule; macOS uses `to ! 100.64.0.0/10`. Only
  forwarded INTERNET traffic isolates to the real WAN. Diagnosed by diffing against the last
  working baseline (per CLAUDE.md), live-verified Mac↔Oracle.

## [0.7.8] — 2026-07-25

### Fixed
- **`exitable=off` now actually stops serving as an exit.** A node upgraded from an older
  always-on build kept leftover `100.64.0.0/10` MASQUERADE iptables rules, so it forwarded ALL
  overlay traffic for everyone regardless of the per-mesh `exitable` toggle. meshd now reconciles
  NAT at bringup (serve → NAT this mesh's subnet; not serving → disable + **purge every legacy
  all-overlay rule**). Found via a cross-node test.

## [0.7.7] — 2026-07-25

### Added
- **Per-mesh `exitable` — opt-in serving as an internet exit** (docs/EXIT_SHARING.md). Whether a
  mesh's members may use THIS node's internet as their exit is now a per-mesh toggle, **default
  OFF**. A mesh member (incl. an intruder) can't route their internet through a node unless it
  explicitly made that mesh exitable — an in-mesh attacker's blast radius stays on nodes that
  chose to serve. Only the exitable mesh's own subnet (`100.80.<id>.0/24`) is NAT'd, so serving
  one mesh never proxies another. Dedicated pinned exits (`MESHD_ADVERTISE`) stay exitable
  automatically. `lattice exitable <mesh> [on|off]` + a toggle in the User-mode Meshes list.
  Serving is decoupled from consuming.

## [0.7.6] — 2026-07-23

### Added
- **Per-domain split-tunnel exit** — each split rule now carries its OWN exit member
  (`lattice split add <domain> <mesh> <exit>`), independent of the mesh-wide exit. So normal
  traffic keeps using your own network and you never touch the mesh exit. Guarded: the exit can't
  be this node itself or an unknown member (fixes the "set exit to self → can't connect" trap).
  Live-verified: with the mesh exit set to *none*, `pornhub.com` still egressed via the chosen
  member (Oracle) while everything else stayed direct. GUI: an exit-member picker on the split card.

## [0.7.5] — 2026-07-23

### Added
- **Domain split-tunnel** (docs/SPLIT_TUNNEL.md) — keep normal internet direct, but send specific
  domains (and their subdomains, e.g. `*.pornhub.com`) out through a chosen mesh exit. meshd runs
  a local DNS proxy that learns the domain→IP mapping and injects a `/32` route into the mesh tun
  for matched IPs only; the default route is never touched. `lattice split add/rm/list/on/off` +
  a Configs GUI card. Local to each node, never gossiped. Live-verified (a `*.pornhub.com`
  connection egressed via the exit while everything else stayed direct).
- **Connection book** — `lattice conns <mesh>` shows a per-member key→value view of the
  auto-discovered path: `direct` / `relay` / `offline`, endpoint, and last-seen age. `MemberView`
  gains `path` + `last_seen_secs`. The learned endpoint was already persisted for fast reconnect;
  this surfaces which path each member was auto-connected over.

## [0.7.4] — 2026-06-24

### Fixed
- **macOS full-tunnel broken by two exit-routing regressions** (latent since v0.7.0, exposed
  once a non-stale build was deployed). (1) The `isolate` exit policy installed a pf `route-to`
  rule selecting `100.64.0.0/10` on **every** node; that range also matches the node's OWN
  overlay IP, so on a full-tunnel client pf diverted its own egress back out the physical WAN
  (utun saw no packets → kill-switch reverted). (2) `route_through` diverted the default route
  into the tunnel **even when the exit /32 pin failed**, and the macOS pin wasn't idempotent, so
  a stale /32 from a prior cycle made the exit's own outer packets loop back into the tunnel.
  Fixes: the isolate `route-to` rule only installs on a node that actually serves as an exit
  (publicly-reachable / `MESHD_ADVERTISE` pinned); the macOS pin is now delete-first idempotent
  and the default is diverted **only after** the pin succeeds (fail closed). See `docs/ERRORS.md`.

### Added
- **Extensions / connector framework (daemon side)** — `meshd` can now host external
  connector programs over its existing IPC socket (docs/EXTENSIONS.md). Connectors are
  separate processes that authenticate with `Hello{id,token}`, `Subscribe` to scope-gated
  event topics (`peer`/`service`/`exit`/`health`) to receive a server-pushed `Event`
  stream, and use a mesh-wide **service registry** (`Advertise`/`Unadvertise`/
  `ListServices`, gossiped via `CTRL_REGISTRY` 0x08, soft-state with TTL expiry) to
  discover each other on the overlay. Grants are created with `EnableExtension{id,scopes}`
  and persisted to `extensions.json` (0600); a bounded `broadcast` event bus keeps a slow
  connector from ever back-pressuring the data plane. Wire-compatible (additive IPC +
  control tag).
- **Extensions GUI page** — a User-mode **Extensions** tab to enable connectors with
  per-scope approval (risk-labelled), see/disable existing grants and copy their token,
  and browse services discovered across all meshes. The first connector (MiniSync) is
  still to come.
- **Per-mesh extension scoping** — an extension grant now carries which meshes it may
  touch (`all_meshes` or an explicit `meshes` allow-list), chosen at enable time. The
  daemon enforces it on `Advertise`/`Unadvertise`/`ListServices` and filters the event
  stream by mesh, so enabling one connector never silently exposes a mesh the user didn't
  pick. Grants written before this load as "no meshes" (must be re-granted).

### Tooling / docs
- **Build-identity stamp** — `meshd` logs `version vX.Y.Z build <git-sha>` at startup, so the
  running binary is always identifiable (a stale binary had been masking regressions for hours).
- **`scripts/build-app.sh`** — one correct desktop build with anti-stale / anti-mix gates;
  **BUILD.md** build charter, **CLAUDE.md** working agreement, and a **blast-radius regression
  map** in `docs/ERRORS.md` ("edit X → re-test Y, because…").
- **Windows `meshd.exe` VERSIONINFO** (via `winres`) to cut Defender false-positives on the
  unsigned sidecar.

## [0.7.1] — 2026-06-22

### Fixed
- **Invite: CLI ↔ GUI identity-code interop** — the CLI minted identity codes with
  `{member_pubkey_hex, enc_pubkey_hex, issued_at}` while the GUI only accepted the short
  `{m,e,t}` form, so a code made on one tool failed on the other with “invalid join code”.
  Both sides now accept either form. (Workaround on older builds: keep the whole
  identity→invite→join chain on a single tool.)

## [0.7.0] — 2026-06-21

Topology insight, distributed-exit routing policy, and discovery robustness. Charter
change is backward-compatible (serde-default); data plane stays wire-compatible.

### Added
- **Exit policy (genesis choice): `isolate` (default) vs `chain`** — how a node egresses
  internet traffic it forwards *as an exit for others*. `isolate` pins forwarded traffic
  to the exit's own real WAN (no multi-hop chains/loops, even if that node full-tunnels its
  own traffic); `chain` lets it follow the exit's tunnel (onion). Member↔member traffic is
  always direct regardless. Picked at `lattice new --exit-policy` / the GUI create screen,
  shown in `info`. Mechanism: Linux `ip rule` (live-verified), macOS pf `route-to`, Windows
  best-effort. Design + rationale: [`docs/EXIT_POLICY.md`](docs/EXIT_POLICY.md).
- **Topology: true network grouping** — the GUI groups nodes by the physical network they
  sit on (your LAN vs each remote NAT) into a clustered community graph with soft region
  blobs and live per-node addresses. The daemon reports each node's real LAN address
  (`getifaddrs`, not a route lookup, so full-tunnel doesn't distort it) and its own endpoint.
- **CI opsec guard** — `scripts/opsec-scan.sh` fails CI if a real infra IP / credential /
  personal path reaches a tracked file (the repo is public).

### Fixed
- **Discovery: gossip refreshes a stale peer endpoint** (was insert-only), so a peer that
  changed address can be re-discovered instead of being pinned to a dead one forever.

## [0.6.1] — 2026-06-21

Early-access hardening of the v2 data plane / daemon. Wire-compatible — new and old
nodes interoperate. See [`docs/SECURITY.md`](docs/SECURITY.md#hardening-v061) and
[`docs/ERRORS.md`](docs/ERRORS.md) (2026-06-21) for rationale + live validation.

### Fixed / Security
- **No nonce reuse across restarts.** The data-plane AEAD counter (`seq`, the nonce)
  reset to 0 on every start while the key persisted, replaying nonces under the same
  key (keystream reuse). It now seeds from a random 63-bit per-boot start. Receiver
  derives the nonce from the transmitted `seq`, so this needs no wire/peer change.
- **No silent full-tunnel failure.** Route/DNS setup now surfaces OS-side failures via
  `dp_error` (shown in `lattice info` / the GUI) instead of a silently-broken "VPN on".
- **Bounded gossip.** Size guard (64 KiB) + caps on merged certs/revocations/flow-rules
  so a member can't grow a peer's memory without bound.

### Added
- **`LATTICE_ALLOW_UID`** — opt-in control-socket access control. The daemon reads the
  peer uid (`SO_PEERCRED`/`getpeereid`); default is permissive (the GUI connects as the
  user), set this to restrict the socket to root + the daemon's uid + `$SUDO_UID` +
  listed uids on shared/multi-user hosts.

Validated live: rolled to Oracle (seed+exit) and a Linux node over the real internet
while Mac/Windows stayed on the prior build — peers re-linked across restarts with zero
decrypt failures, full-tunnel egress verified, uid gate refused/allowed as expected.

## [0.6.0] — 2026-06-20

First official public release of the v2 product. Serverless mesh VPN with per-node
overlay IPs, public-node relay (NAT traversal fallback), DHT rendezvous, full/split
tunnel exit, flow table, membership (invite-chain + expel + re-cipher), CLI + GUI.
Live-verified across macOS, Linux, and Windows. New copy-paste README front page.

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
