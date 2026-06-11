# Implemented features

A snapshot of what Lattice does today (v0.7.0). Legend: ✅ working & tested ·
⚠️ working subset / needs integration · 🔜 designed, not built.

## Data plane (moving the packets)

| Feature | Status | Where |
| --- | --- | --- |
| Virtual NIC — macOS `utun` | ✅ | `crates/tun` (`macos.rs`) |
| Virtual NIC — Linux `/dev/net/tun` | ✅ | `crates/tun` (`linux.rs`) |
| Virtual NIC — Windows Wintun | ⚠️ compiles; needs a Windows test pass | `crates/tun` (`windows.rs`) |
| Custom encrypted tunnel (Noise-IK handshake) | ✅ | `crates/crypto` (`session.rs`) |
| AEAD transport session (ChaCha20-Poly1305) | ✅ | `crates/crypto` |
| Packet loop: TUN ⇄ route ⇄ encrypt ⇄ transport | ✅ | `crates/engine` |
| Headless mode (`--no-tun`, no root) | ✅ | `crates/daemon`, `crates/tun` (`NullTun`) |

## Control plane (deciding the topology)

| Feature | Status | Where |
| --- | --- | --- |
| Identity = Curve25519 keypair; node id = public key | ✅ | `crates/crypto`, `crates/proto` |
| Virtual IP derived from node id (`100.64.0.0/10`) | ✅ | `crates/overlay` |
| Peer registry + routing table | ✅ | `crates/overlay` |
| Eager handshake on peer discovery | ✅ | `crates/engine` |
| Connected-endpoint routing (per-peer best path) | ✅ | `crates/engine` |
| Mesh up/down toggle | ✅ | `crates/engine` (`EngineHandle`) |
| Keepalive: peer reachability + NAT-binding refresh | ✅ | `crates/engine` |
| Drop stale "ghost" peers after timeout | ✅ | `crates/engine` |

## Discovery & NAT traversal (finding peers)

| Feature | Status | Where |
| --- | --- | --- |
| LAN discovery over mDNS (`_lattice._udp.local`) | ✅ | `crates/net` (`discovery`) |
| STUN reflexive (public) address (RFC 5389) | ✅ | `crates/net` (`nat`) |
| UDP hole punching across all candidates | ✅ | `crates/engine`, `crates/net` |
| Kademlia DHT rendezvous (XOR, k-buckets, lookup) | ✅ | `crates/dht` |
| DHT over real UDP (request-id demux server) | ✅ | `crates/dht` (`server.rs`) |
| Daemon DHT wiring (`--dht-bind/-bootstrap/--peer`) | ✅ | `crates/daemon` |
| Manual peer pin (`--peer-addr <id>@<ip:port>`, GUI add) | ✅ | `crates/daemon`, `gui/` |
| Public bootstrap node (stable internet entry point) | 🔜 | operational, not code |
| Manual peer pin (`--peer-addr <id>@<ip:port>`) | ✅ | `crates/daemon` |
| Relay (DERP-style) — forward via a third node for CGNAT | ⚠️ transport+relay tested; needs cross-network test | `crates/net` (`relay.rs`), `crates/daemon` |
| Stable persisted node identity | ✅ | `crates/crypto`, `crates/daemon` |
| Per-peer OS shown (carried in the handshake) | ✅ | `crates/engine`, `gui/`, `crates/cli` |

## Process & user experience

| Feature | Status | Where |
| --- | --- | --- |
| Privileged daemon hosting the engine | ✅ | `crates/daemon` |
| Local IPC (newline-JSON over Unix socket) | ✅ | `crates/ipc` |
| CLI: `status` / `peers` / `up` / `down` | ✅ | `crates/cli` |
| Desktop GUI (Tauri) | ✅ | `gui/` |
| GUI: start/stop the daemon (admin prompt) | ✅ | `gui/` (bundles the daemon) |
| GUI: live dashboard (status, mesh toggle, peers) | ✅ | `gui/` |
| GUI: virtual IP, node id, public address — copyable | ✅ | `gui/` |
| Exit node — route internet via a peer, pick it in the GUI | ⚠️ engine+GUI done; OS plumbing needs 2-machine test | `crates/engine`, `crates/daemon` (`exit.rs`), `gui/` |
| Windows named-pipe IPC | 🔜 | (Unix socket today) |

## Security

| Feature | Status | Where |
| --- | --- | --- |
| Mutual auth + forward secrecy (Noise IK) | ✅ | `crates/crypto` |
| Tamper detection (AEAD), tested | ✅ | `crates/crypto` |
| Replay window (sliding anti-replay) | ⚠️ component done; AEAD-binding pending | `crates/crypto` (`replay.rs`) |
| Rekey policy (count/age), wired into sessions | ✅ | `crates/crypto` (`rekey.rs`) |
| Stateless handshake cookie (flood mitigation) | ⚠️ component done; wire into flood path | `crates/crypto` (`cookie.rs`) |
| Keys zeroized; never logged | ✅ | `crates/crypto` |
| Fuzz targets for wire/STUN parsers | ✅ | `fuzz/` |

## Platforms & distribution

| Feature | Status |
| --- | --- |
| Builds on macOS / Linux / Windows | ✅ (all three cross-compile) |
| macOS `.app` bundle (runnable, ad-hoc signed) | ✅ |
| Static Linux binaries (musl, "paste & run") | ✅ (`dist-linux/`) |
| Signed/notarized installers, auto-update | 🔜 |

## What is NOT here yet (deferred specs)

These are intentionally future work — see `docs/ROADMAP.md`:

- **Relay fallback** — route through a third reachable node when two peers can't
  connect directly (the cross-NAT safety net).
- **Multi-hop mesh routing** — forward packets through several mesh nodes.
- **Exit node** — send a node's general internet traffic out through another node.
- **Per-port ACLs** — the "specific port vs. all ports" policy as firewall rules.
- **Public bootstrap node** + peer liveness/keepalive.

## Verification at a glance

- 35 unit/integration tests pass (crypto handshake, replay window, Kademlia
  publish→lookup over real UDP, IPC round-trip, engine end-to-end tunnel, …).
- `clippy -D warnings` and `rustfmt --check` clean.
- Live-verified: two real machines on a LAN auto-discover, handshake, and carry
  encrypted `ping` traffic by virtual IP.
