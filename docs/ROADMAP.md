# Roadmap

Milestones are sized so each one is independently demoable. Versions follow
SemVer; everything pre-`1.0` may break the wire protocol between minor versions.

## v0.1 — Scaffold ✅ (current)
- Workspace, crate boundaries, trait interfaces, docs, CI/release pipelines.

## v0.2 — Single-host loopback tunnel
- `tun` real device on **macOS** (dev platform first).
- `crypto` LTP handshake + transport over an in-memory transport.
- `engine` packet loop: TUN ⇄ crypto ⇄ transport, two nodes on one machine.
- **Demo:** ping between two virtual IPs on the same host through the tunnel.

## v0.3 — Two hosts on a LAN
- `net` real UDP transport + mDNS discovery (`_lattice._udp.local`).
- `overlay` peer registry + key-derived virtual IP allocation.
- **Demo:** two laptops on the same Wi-Fi auto-discover and ping over the mesh.

## v0.4 — Daemon + CLI + GUI MVP
- `daemon` hosts the engine, exposes IPC; `cli status/up/down/peers`.
- Tauri GUI: node on/off, peer list with live status, copyable virtual IP.
- macOS packaging (`.app` + notarization path documented).

## v0.5 — Cross-platform data plane
- `tun` for **Linux** (`/dev/net/tun`) and **Windows** (Wintun).
- CI build matrix produces installers for all three.

## v0.6 — Internet-wide serverless mesh
- Kademlia **DHT** rendezvous (no coordination server).
- **NAT traversal:** STUN-style reflexive discovery + UDP hole punching.
- Fallback relay (DERP-like) only when hole-punching fails — still serverless,
  any node can volunteer as a relay.

## v0.7 — Hardening
- Replay window, rekeying parameters, handshake-flood cookies (see PROTOCOL.md).
- Fuzzing of `proto`/`crypto` parsers; `cargo-deny` + audit gates in CI.

## v1.0 — Stable
- Frozen wire protocol with a version negotiation byte.
- Signed/notarized installers for all platforms, auto-update channel.

## Backlog / stretch
- Per-port vs. all-port policy (ACLs): expose the "지정된 포트 또는 전포트"
  control as overlay firewall rules in the GUI.
- Exit-node mode (route a peer's full internet traffic through another node).
- Mobile (iOS/Android) via the same `engine` core behind a platform VPN API.
