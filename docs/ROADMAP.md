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

## v0.3 — Two hosts on a LAN ✅
- `net` real UDP transport + mDNS discovery (`_lattice._udp.local`).
- `overlay` peer registry + key-derived virtual IP allocation.
- **Demo:** two laptops on the same Wi-Fi auto-discover and ping over the mesh.

## v0.4 — Daemon + CLI + GUI MVP ✅ (GUI packaging pending)
- `daemon` hosts the engine, exposes IPC; `cli status/up/down/peers`.
- `lattice-ipc` (newline-JSON / Unix socket); GUI Tauri commands call the daemon.
- *Remaining:* macOS `.app` packaging + notarization; Windows named-pipe IPC.

## v0.5 — Cross-platform data plane ✅
- `tun` for **Linux** (`/dev/net/tun`) and **Windows** (Wintun). Whole workspace
  cross-compiles for macOS / Linux / Windows.
- *Remaining:* CI produces packaged installers (binaries build today).

## v0.6 — Internet-wide serverless mesh ✅
- **NAT traversal:** STUN reflexive discovery + UDP hole punching across all
  candidate endpoints. ✅
- **Kademlia DHT** rendezvous (`lattice-dht`): XOR distance, k-bucket routing,
  iterative lookup; implements `Rendezvous`. Verified by a 40-node simulated
  network and by 3 real nodes over localhost UDP with request-id demux. ✅
- **Daemon wiring:** `--dht-bind` runs a DHT node (UDP server + demux transport),
  publishes our STUN candidate under our node id, and `--peer <id>` resolves a
  peer's candidates via the DHT and feeds them to the engine. ✅
- *Remaining:* public bootstrap node(s) as a stable entry point, and a DERP-like
  fallback relay for when hole punching fails.

## v0.7 — Hardening ✅ (components) ◀ (current)
- Replay window, rekey policy (wired into sessions), stateless handshake cookie,
  fuzz targets for the parsers. `cargo-deny` gates in CI.
- *Remaining:* bind the replay counter to the AEAD nonce (needs the move off
  snow's in-order transport); wire the cookie into the responder's flood path.

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

## Backlog / future specs (deferred)

Connectivity (makes the mesh reach anywhere, reliably):
- **Relay fallback (DERP-style):** when two peers can't connect directly, route
  their *still end-to-end encrypted* packets through a third node both can reach.
  Any node can volunteer; no dedicated server. This is the cross-NAT safety net.
- **Multi-hop mesh routing:** forward packets through several mesh nodes toward
  the destination (a generalization of relay).
- **Public bootstrap node + peer keepalive/liveness** (drop stale peers).

Capabilities:
- **Exit-node mode:** route a node's full internet traffic out through another
  node (appear on the internet as that node).
- **Per-port vs. all-port policy (ACLs):** the "지정된 포트 또는 전포트" control
  as overlay firewall rules in the GUI.
- **Mobile (iOS/Android)** via the same `engine` core behind a platform VPN API.

Hardening / packaging:
- Bind the replay counter to the AEAD nonce; wire the cookie into the flood path.
- Signed/notarized installers; Windows named-pipe IPC.
