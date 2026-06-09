# Roadmap

Milestones are sized so each one is independently demoable. Versions follow
SemVer; everything pre-`1.0` may break the wire protocol between minor versions.

## v0.1 — Scaffold ✅
- Workspace, crate boundaries, trait interfaces, docs, CI/release pipelines.

## v0.2 — Single-host loopback tunnel ✅
- `tun` real `utun` device on **macOS** (dev platform first).
- `crypto` real Noise-IK handshake + AEAD transport session.
- `engine` packet loop: TUN ⇄ crypto ⇄ transport, with eager handshake on
  discovery. Verified end-to-end between two in-memory nodes (no root needed).
- `daemon` wires the real data plane together (runs under `sudo`).
- **Live demo (manual, needs sudo):** see "Running the live tunnel" below.

## v0.3 — Two hosts on a LAN ◀ (current)
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

## Running the live tunnel (v0.2, macOS, needs sudo)

The automated proof of the data plane is the end-to-end test (no privileges):

```bash
cargo test -p lattice-engine packet_tunnels_end_to_end_between_two_nodes
```

To exercise the *real* `utun` device, run the daemon with elevated privileges.
It creates a `utunN` interface, assigns this node's overlay IP, and routes the
overlay subnet through it:

```bash
sudo cargo run -p lattice-daemon
# in another terminal:
ifconfig | grep -A3 utun        # see the interface + its 100.64.x.x address
```

Peer-to-peer discovery over the LAN (so two machines find each other and the
tunnel carries real ping traffic) is the v0.3 milestone — until then the daemon
holds the interface up but surfaces no peers.

## Backlog / stretch
- Per-port vs. all-port policy (ACLs): expose the "지정된 포트 또는 전포트"
  control as overlay firewall rules in the GUI.
- Exit-node mode (route a peer's full internet traffic through another node).
- Mobile (iOS/Android) via the same `engine` core behind a platform VPN API.
