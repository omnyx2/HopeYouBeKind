# Lattice documentation

Lattice is a **serverless mesh VPN / overlay SDN**: install it on N machines and
they self-assemble into one private, encrypted network — no coordination server.

Start here, then dive into the feature guide you need.

> **Which stack?** The current product is the **v2 multi-mesh** stack (`meshd` +
> the `lattice` CLI). The original **v1** single-mesh/CA stack has been archived
> under [`../legacy/`](../legacy/README.md); its docs moved to `../legacy/docs/`
> and are tagged _(v1 legacy)_ below.

## Getting started (v2 — current)

- **[guides/getting-started.en.md](guides/getting-started.en.md)** ·
  **[한국어](guides/getting-started.ko.md)** — zero to a working mesh VPN with the
  friendly `lattice` CLI. **Read this first.**
- **[guides/cookbook.en.md](guides/cookbook.en.md)** · **[한국어](guides/cookbook.ko.md)**
  — feature recipes (private LAN, full tunnel, ephemeral meshes, re-cipher, …).
- [MESH_V2.md](MESH_V2.md), [DATA_PLANE.md](DATA_PLANE.md),
  [DISCOVERY.md](DISCOVERY.md), [PROTOCOL_DESIGN.md](PROTOCOL_DESIGN.md) — v2 internals.

## Feature guides

| Guide | What it covers |
| --- | --- |
| [MEMBERSHIP.md](MEMBERSHIP.md) | Closed networks: network identity, the serverless CA, enrolling nodes (join tokens), and evicting them (revocation). |
| [EXIT_NODE.md](EXIT_NODE.md) | Route a node's general internet traffic out through a chosen peer. |
| [../legacy/docs/CRYPTO_SUITE.md](../legacy/docs/CRYPTO_SUITE.md) | _(v1 legacy)_ The pluggable tunnel-crypto seam — swap the handshake/cipher without touching the engine. |
| [../legacy/docs/TRAFFIC_MONITOR.md](../legacy/docs/TRAFFIC_MONITOR.md) | _(v1 legacy)_ Live per-flow view of everything crossing the tunnel (`lattice flows`). |
| [../legacy/docs/RELAY.md](../legacy/docs/RELAY.md) | _(v1 legacy)_ Forward encrypted traffic through a third node when two peers can't connect directly (CGNAT). |
| [../legacy/docs/HEALTH_CHECK.md](../legacy/docs/HEALTH_CHECK.md) | _(v1 legacy)_ ⚠️ **Security-sensitive.** Dump every node's virtual IP at once, gated by a (weak) process-name allow-list. |
| [../legacy/docs/ADMIN_CONSOLE.md](../legacy/docs/ADMIN_CONSOLE.md) | _(v1 legacy)_ The standalone admin console (`legacy/gui-admin/`): membership & eviction, packet inspector, crypto-suite swap lab. |

## Design & reference

| Doc | What it covers |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Crate layout and how the planes fit together. |
| [SDN_DHT_ARCHITECTURE.md](SDN_DHT_ARCHITECTURE.md) | **Design** — the SDN×DHT control plane: a global admin-signed network map distributed serverlessly over the DHT (decentralized distribution, centralized admin authority). Auto full-mesh + programmable routing. |
| [../legacy/docs/PROTOCOL.md](../legacy/docs/PROTOCOL.md) | _(v1 legacy)_ The Lattice Tunnel Protocol — handshake, framing, sessions. |
| [SECURITY.md](SECURITY.md) | Threat model and cryptographic choices. |
| [FEATURES.md](FEATURES.md) | Status table — what works today, what's partial, what's planned. |
| [ROADMAP.md](ROADMAP.md) | What's next. |

## Blog

- [blog/building-a-serverless-mesh-vpn.md](blog/building-a-serverless-mesh-vpn.md)
  — the story of how Lattice is built: the custom tunnel, serverless discovery,
  pluggable crypto, and a CA you can run with no server.
