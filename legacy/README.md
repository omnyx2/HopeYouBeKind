# Legacy (v1) — archived

This folder holds the **v1 Lattice stack**: the original single-mesh, admin/CA-based
serverless VPN. It is **not the current product** and is kept only for reference and
history. The current direction is the **v2 multi-mesh** stack (`crates/mesh`,
`crates/meshd`, `crates/meshrun`, driven by `scripts/lattice` and the `gui/`
desktop app). See [`../docs/MESH_V2.md`](../docs/MESH_V2.md).

## What's here

### `legacy/crates/` — the v1 crates
| Crate | What it was |
| --- | --- |
| `crypto` | The custom Noise-IK tunnel (handshake, session, replay window, rekey, cookie) + a pluggable `CryptoSuite` seam and a crypto-swap template. |
| `engine` | The v1 node runtime: packet loop, sessions, WireGuard-style timers, SDN flow-table data plane, traffic monitor + packet capture, crypto-swap lab. |
| `overlay` | Identity-derived virtual-IP allocation + routing table (`100.64.0.0/10`). |
| `membership` | The network CA: signed member certs, revocation, signed member-directory + network-manifest (the SDN control plane). |
| `dht` | A Kademlia DHT for serverless peer rendezvous (XOR distance, k-buckets, request-id-demuxing UDP server, re-bootstrap healing). |
| `ipc` | The v1 daemon⇄client IPC transport (newline-JSON over a unix socket / named pipe, with peer-credential gating). |
| `daemon` | `lattice-daemon`: the privileged v1 service (TUN, transport, engine, DHT, relay, admin CA). |
| `cli` | `lattice`: the v1 terminal client (`status`/`peers`/`up`/`down`/`net`/`crypto`/`capture`/`exit`/`flow`). |

These remain Cargo **workspace members** (see the root `Cargo.toml`) so they keep
compiling and don't rot, but they are not part of the v2 product and the v2 crates
do not depend on any of them. The shared base crates (`proto`, `tun`, `net`) stayed
under `crates/` because both stacks use them.

### `legacy/gui-admin/` — the v1 admin console
A separate Tauri app that drove the v1 daemon's admin features (membership/eviction,
the packet inspector, the runtime crypto-suite swap lab). It speaks the v1 IPC
(`lattice_ipc` + `lattice_proto::ipc`).

### `legacy/docs/` — v1 documentation
`USAGE.md`, `PROTOCOL.md`, `RELAY.md`, `HEALTH_CHECK.md`, `ADMIN_CONSOLE.md`,
`CRYPTO_SUITE.md`, `TRAFFIC_MONITOR.md` — operator/feature guides for the v1 daemon.
(Some docs that still describe live v2 features — membership, exit node, discovery,
the data plane — were left under `docs/`.)

### `legacy/dist-linux/`
Prebuilt **v1** static Linux binaries (`lattice`, `lattice-daemon`) + their `RUN.txt`.
These do **not** match the v2 `meshd` the GUI ships; they're kept only as the old
release artifact. (Gitignored — not committed.)

## Building the v1 stack

It still builds as part of the workspace:

```sh
cargo build -p lattice-daemon -p lattice-cli
sudo ./target/debug/lattice-daemon        # the v1 daemon
./target/debug/lattice status             # the v1 CLI
```
