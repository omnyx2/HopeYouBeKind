# Lattice documentation

Lattice is a **serverless mesh VPN / overlay SDN**: install it on N machines and
they self-assemble into one private, encrypted network — no coordination server.

Start here, then dive into the feature guide you need.

## Getting started

- **[USAGE.md](USAGE.md)** — build it, run a node, and drive every workflow from
  the GUI and CLI. **Read this first.**

## Feature guides

| Guide | What it covers |
| --- | --- |
| [MEMBERSHIP.md](MEMBERSHIP.md) | Closed networks: network identity, the serverless CA, enrolling nodes (join tokens), and evicting them (revocation). |
| [CRYPTO_SUITE.md](CRYPTO_SUITE.md) | The pluggable tunnel-crypto seam — swap the handshake/cipher (e.g. for research) without touching the engine. |
| [TRAFFIC_MONITOR.md](TRAFFIC_MONITOR.md) | Live per-flow view of everything crossing the tunnel (GUI Traffic tab / `lattice flows`). |
| [EXIT_NODE.md](EXIT_NODE.md) | Route a node's general internet traffic out through a chosen peer. |
| [RELAY.md](RELAY.md) | Forward encrypted traffic through a third node when two peers can't connect directly (CGNAT). |
| [HEALTH_CHECK.md](HEALTH_CHECK.md) | ⚠️ **Security-sensitive.** Dump every node's virtual IP at once, gated by a (weak) process-name allow-list. Read the security impact before enabling. |
| [ADMIN_CONSOLE.md](ADMIN_CONSOLE.md) | Design/plan for the standalone mesh **admin console** (`gui-admin/`): membership & eviction, full packet-level traffic inspector, runtime crypto-suite swap lab. |

## Design & reference

| Doc | What it covers |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Crate layout and how the planes fit together. |
| [PROTOCOL.md](PROTOCOL.md) | The Lattice Tunnel Protocol — handshake, framing, sessions. |
| [SECURITY.md](SECURITY.md) | Threat model and cryptographic choices. |
| [FEATURES.md](FEATURES.md) | Status table — what works today, what's partial, what's planned. |
| [ROADMAP.md](ROADMAP.md) | What's next. |

## Blog

- [blog/building-a-serverless-mesh-vpn.md](blog/building-a-serverless-mesh-vpn.md)
  — the story of how Lattice is built: the custom tunnel, serverless discovery,
  pluggable crypto, and a CA you can run with no server.
