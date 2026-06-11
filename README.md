<h1 align="center">Lattice</h1>

<p align="center">
  <i>A serverless mesh VPN that fuses every node into one overlay SDN.</i>
</p>

---

Install the app on any set of machines and they self-assemble into a single,
private, encrypted network — as if they were all plugged into the same switch,
no matter where they physically are. No central server to run, no accounts.

> **Status:** `0.7.0` — working serverless mesh. Real Noise-IK tunnel, mDNS LAN
> discovery, NAT hole punching, daemon/CLI/GUI control plane, cross-platform TUN
> (macOS/Linux/Windows), and hardening components (replay window, rekey, cookie).
> Remaining infra (DHT rendezvous, GUI packaging, AEAD-bound replay) is tracked
> in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## What it is

- **Mesh overlay** — every node gets a stable virtual IP (e.g. `100.64.x.x`) and
  can reach every other node directly, peer-to-peer.
- **Serverless** — peers discover each other on the LAN via mDNS and (roadmap)
  across the internet via a DHT + NAT hole-punching. No coordination server.
- **Custom encrypted tunnel** — the handshake/session protocol is our own
  design, built on *vetted* cryptographic primitives (the Noise framework via
  the `snow` crate), not hand-rolled ciphers. See [`docs/PROTOCOL.md`](docs/PROTOCOL.md).
- **GUI-first** — a Tauri desktop app is the primary interface; a `lattice` CLI
  and a background daemon back it.
- **Cross-platform** — macOS, Windows, Linux.

## Architecture at a glance

```
        ┌────────────────────────────┐
        │   GUI (Tauri)  /  CLI       │   user-facing control
        └─────────────┬──────────────┘
                      │ IPC (local socket)
        ┌─────────────▼──────────────┐
        │   lattice-daemon           │   privileged background service
        │  ┌──────────────────────┐  │
        │  │   lattice-engine     │  │   node runtime / orchestration
        │  ├──────────┬───────────┤  │
        │  │ overlay  │   net     │  │   control plane + transport/discovery
        │  ├──────────┼───────────┤  │
        │  │  crypto  │   tun     │  │   data plane: tunnel + virtual NIC
        │  └──────────┴───────────┘  │
        └────────────────────────────┘
```

Each box is its own crate so features, tests, and version bumps move
independently. Full detail in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Quick start (developers)

```bash
# Build & sanity-check the whole core workspace (no privileges needed)
cargo check
cargo test

# Run lints exactly as CI does
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings

# Run the daemon (needs elevated privileges to create the TUN device)
sudo cargo run -p lattice-daemon

# Talk to it from another terminal
cargo run -p lattice-cli -- status
```

GUI setup lives in [`gui/README.md`](gui/README.md).

## Repository layout

| Path                | What lives there                                        |
| ------------------- | ------------------------------------------------------- |
| `crates/proto`      | Shared wire types, message framing, IPC contract        |
| `crates/crypto`     | The custom encrypted-tunnel protocol (handshake/session)|
| `crates/tun`        | Cross-platform virtual network interface (TUN)          |
| `crates/net`        | UDP transport, NAT traversal, mDNS/DHT peer discovery   |
| `crates/overlay`    | SDN control plane: virtual-IP allocation, routing table |
| `crates/engine`     | Node runtime that wires the planes together             |
| `crates/membership` | Network CA: identity, member certs, revocation          |
| `crates/dht`        | Kademlia DHT for serverless peer rendezvous             |
| `crates/ipc`        | Local daemon⇄GUI/CLI control protocol (Unix socket)     |
| `crates/daemon`     | Privileged background service + IPC server              |
| `crates/cli`        | Terminal control client                                 |
| `gui/`              | Tauri desktop application                                |
| `docs/`             | Guides, architecture, protocol spec, roadmap, security  |

## Documentation

Start with **[`docs/USAGE.md`](docs/USAGE.md)** (build & run, every workflow),
then the per-feature guides indexed in **[`docs/README.md`](docs/README.md)**:
[membership](docs/MEMBERSHIP.md), [pluggable crypto](docs/CRYPTO_SUITE.md),
[traffic monitor](docs/TRAFFIC_MONITOR.md), [exit node](docs/EXIT_NODE.md),
[relay](docs/RELAY.md). There's also a write-up of the design in
[`docs/blog/`](docs/blog/building-a-serverless-mesh-vpn.md).

## License

MIT — see [`LICENSE-MIT`](LICENSE-MIT). Uses the WireGuard-style Noise protocol
design via the MIT-licensed `snow` crate; "WireGuard" is a trademark of Jason A.
Donenfeld and this project is not affiliated with or endorsed by it.
