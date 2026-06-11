# Using Lattice

A practical guide: build it, run a node, and drive the common workflows from the
GUI and the CLI. For what each feature *is*, see the per-feature guides linked
from [docs/README.md](README.md).

## Mental model in 30 seconds

- Install the node on N machines; they self-assemble into one encrypted overlay.
- Each node gets a stable **virtual IP** in `100.64.0.0/10`, derived from its
  identity. Reach a peer by that IP (`ping 100.x.y.z`, `ssh user@100.x.y.z`).
- A **daemon** (root, owns the virtual NIC) does the work; a **GUI** and a **CLI**
  are thin clients that talk to it over a local socket.
- Optionally close the mesh into a named network with [membership](MEMBERSHIP.md).

## Build

Prerequisites: Rust (the repo pins the toolchain via `rust-toolchain.toml`).

```sh
# Core workspace (daemon, cli, crates):
cargo build --release -p lattice-daemon -p lattice-cli

# macOS GUI app (needs the stable toolchain for the Tauri deps):
cd gui && RUSTUP_TOOLCHAIN=stable npx tauri build --bundles app
# → gui/src-tauri/target/release/bundle/macos/Lattice.app

# Static Linux binaries (paste-and-run on any x86_64 Linux):
cargo zigbuild --release --target x86_64-unknown-linux-musl -p lattice-daemon -p lattice-cli
```

> Editing the GUI? After changing `gui/`, rebuild the app **and fully quit &
> reopen** `Lattice.app` — a running instance keeps its old front-end.

## Run a node

### macOS (GUI)

1. Open `Lattice.app`.
2. **Status → Start node.** You'll be asked for your password once — creating the
   virtual network interface needs admin rights.
3. The dot turns green ("online"). Your virtual IP, node id, and public address
   are shown (click to copy).

### Linux / headless (CLI)

```sh
sudo ./lattice-daemon --bind 0.0.0.0:41000        # needs root for the TUN device
./lattice status                                   # talk to it (no root needed)
./lattice peers
```

Add `--no-tun` to run a control-plane-only node with no root (no packet
forwarding) — handy for testing membership and discovery.

Useful daemon flags: `--bind`, `--ipc-socket`, `--identity <path>` (stable node
id), `--peer-addr <id>@<ip:port>` (manual peer pin), `--network-key`,
`--member-cert` (see membership), `--relay` / `--relay-bind` (see relay),
`--dht-bind` / `--dht-bootstrap` / `--peer` (internet rendezvous).

## CLI reference

```sh
lattice status                 # this node: id, virtual ip, mesh up/down, peers
lattice peers                  # known peers and their status
lattice up | down              # bring the overlay up / down
lattice flows                  # live traffic flows crossing the tunnel
lattice net info               # membership: network id, role, counts
lattice net issue <node-id> [--label L]   # admin: mint a join token
lattice net join <token>       # adopt a token → join that network
lattice net members            # admin: list enrolled members
lattice net revoke <node-id>   # admin: evict a member
```

All commands accept `--ipc-socket <path>` to target a specific daemon.

## Common workflows

### Two machines on a LAN

1. Start a node on each (GUI Start, or `sudo lattice-daemon`).
2. They auto-discover over mDNS and handshake. Check `lattice peers` →
   `Connected`.
3. From A: `ping <B's virtual IP>`, or `ssh user@<B's virtual IP>`.

If they don't find each other (e.g. Wi-Fi that blocks multicast), pin directly:
start one with `--peer-addr <other-node-id>@<other-lan-ip>:41000` (or use the
GUI **Peers → Add a peer**).

### Create a closed network and enroll a node

See [MEMBERSHIP.md](MEMBERSHIP.md) for the full flow. Short version:

```sh
# Admin:
sudo lattice-daemon --bind 0.0.0.0:41000 --network-key ~/.lattice/net.key
lattice net issue <joiner-node-id> --label laptop     # → token

# Joiner (paste the token):
lattice net join <token>
# later, admin evicts:
lattice net revoke <joiner-node-id>
```

In the GUI this is the **Mesh** tab: Issue a token, the joiner pastes it into
**Join**, and you **Revoke** from the Members list.

### Route your internet through a peer (exit node)

See [EXIT_NODE.md](EXIT_NODE.md). On the exit: turn on **Act as exit node**. On
the client: pick the exit under **Exit through**. Verify with
`curl https://ifconfig.me`.

### Reach a peer behind hard NAT (relay)

See [RELAY.md](RELAY.md). Run a relay somewhere reachable
(`--relay-bind 0.0.0.0:42000`); point both peers at it (`--relay <ip>:42000`).

### Watch what's flowing

Open the **Traffic** tab (or `lattice flows`) and generate some overlay traffic.
See [TRAFFIC_MONITOR.md](TRAFFIC_MONITOR.md).

## Troubleshooting

- **GUI shows DEMO data / fake "connected"** — it's not talking to a real daemon
  (running outside Tauri). Launch the bundled `Lattice.app`.
- **"could not reach daemon"** — the daemon isn't running, or you're pointing at
  the wrong `--ipc-socket`.
- **Peers won't connect on Wi-Fi** — multicast/mDNS is often filtered; use a
  manual `--peer-addr` pin.
- **GUI didn't pick up my change** — fully quit (Cmd+Q) and reopen `Lattice.app`.
- **Both ends must run the same build** — the on-wire protocol changes between
  feature milestones (e.g. adding membership changed the handshake payload).
