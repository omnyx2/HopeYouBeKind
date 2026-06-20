<h1 align="center">Lattice</h1>

<p align="center">
  <i>A serverless mesh VPN — fuse your machines into one private network, anywhere.</i>
</p>

<p align="center">
  <a href="https://github.com/omnyx2/HopeYouBeKind/releases/latest"><b>⬇ Download</b></a> ·
  <a href="docs/guides/getting-started.en.md">Getting started</a> ·
  <a href="docs/guides/getting-started.ko.md">시작하기</a>
</p>

---

Install Lattice on any set of machines and they self-assemble into **one private,
encrypted network**. Every node gets a stable virtual IP and can reach every other node
**directly, peer-to-peer — across NAT and firewalls, with no port-forwarding, no central
server, and no accounts.**

> **Status:** early-access / research prototype (v0.5.x). Live-verified across **macOS,
> Linux, and Windows** over the real internet. Built for your own machines / trusted
> members — see [Security](#security).

## What you can do with it

- **🖥 Reach any machine from anywhere.** SSH / RDP / VNC into your home or lab box at its
  mesh IP (`ssh you@100.80.1.4`) even though it sits behind a school/office NAT —
  **no port-forwarding, no public IP.**
- **🔒 A private LAN over the internet.** Your laptop, server, and home PC all see each
  other on `100.80.x.x` as if plugged into one switch. End-to-end encrypted
  (ChaCha20-Poly1305).
- **🌍 Full-tunnel VPN.** Route all your internet through any node (`lattice vpn`) and
  browse as if you were there (its egress IP / region).
- **🧱 Punch through restrictive networks.** A NAT'd box reaches *out* to a public node;
  you reach back *in* over the tunnel. A public node also **auto-relays** when two peers
  can't connect directly.

## Install

### Desktop app — macOS · Windows · Linux

Grab the installer from the **[latest release](https://github.com/omnyx2/HopeYouBeKind/releases/latest)**:

| OS | File |
|----|------|
| macOS (Apple Silicon) | `Lattice_*_aarch64.dmg` |
| Windows | `Lattice_*_x64-setup.exe` |
| Linux | `lattice_*_amd64.deb`  or  `lattice_*_amd64.AppImage` |

Launch it — it asks once for admin access to create the tunnel, then you're in.

### Headless / server — CLI + daemon

```sh
git clone https://github.com/omnyx2/HopeYouBeKind.git && cd HopeYouBeKind
cargo build --release -p lattice-meshd     # build the daemon
sudo ./scripts/lattice install             # put the `lattice` CLI on your PATH
sudo lattice up                            # start the daemon (creates the tunnel)
lattice status                             # check it's running
```

No Rust toolchain? Download the prebuilt daemon from the release
([`meshd-Linux-X64`](https://github.com/omnyx2/HopeYouBeKind/releases/latest/download/meshd-Linux-X64),
also macOS-ARM64 / Windows-X64), then `export LATTICE_MESHD=/path/to/meshd` and
`sudo lattice up`. (The CLI needs only Python 3.)

## Quick start — two machines in one mesh

**Machine A** — create the mesh:
```sh
lattice new home --me alice          # you become member #1
```

**Machine B** — mint an identity:
```sh
lattice id                           # prints a one-line code → send it to A
```

**Machine A** — invite B with that code:
```sh
lattice invite home bob <B's-id-code>   # prints a one-line invite code → send it back to B
```

**Machine B** — join, then reach A over the tunnel:
```sh
lattice join <invite-code>
lattice info home                    # both show 'live' + their overlay IP (100.80.1.x)
ssh alice@100.80.1.1                  # A is member #1 → 100.80.1.1
```

That's it — A and B are now one encrypted mesh, reachable by their `100.80.1.x` addresses
from anywhere.

**Want a public seed/exit node?** On an always-on cloud VM (open UDP 41000+41001):
```sh
sudo lattice install-service --advertise <PUBLIC_IP>:41000 --dht-port 41001   # start at boot
sudo lattice serve-exit home          # make this node the mesh's internet exit
```
NAT'd clients then bootstrap off it: `sudo lattice up --dht-bootstrap <PUBLIC_IP>:41001`.

→ **Full walk-throughs:**
[Getting started](docs/guides/getting-started.en.md) ([한국어](docs/guides/getting-started.ko.md)) ·
[Cookbook](docs/guides/cookbook.en.md) ·
[Server setup](docs/guides/server-setup.en.md) ·
[CLI reference](docs/guides/cli-reference.en.md)

## Features

- **Serverless discovery** — invite endpoints + 20 s gossip + reflexive STUN + LAN
  multicast beacon + **DHT rendezvous**. No coordination server.
- **Relay** — a public node forwards traffic when two peers can't connect directly
  (symmetric-NAT / blocked-path fallback), with NAT-keepalive so the path stays open.
- **Membership** — admin-free invite chain (any member can invite); per-mesh expel policy;
  key rotation (re-cipher) that evicts offline members.
- **Routing** — full-tunnel / split-tunnel internet exit, plus an OpenFlow-style
  **flow table** for custom routing rules, gossiped to all members.
- **Crypto** — per-mesh cipher (ChaCha20-Poly1305), floating header placement, attack
  alert + liveness self-destruct.
- **Tools** — a `lattice` CLI (daemon lifecycle, invite flow, `doctor`, traffic monitor)
  and a Tauri **GUI** (peers, topology, traffic, overlay IPs).
- **Resilient** — persists meshes to disk and self-heals across network changes
  (Wi-Fi ↔ cellular, new IP) so nodes rejoin automatically.
- **Cross-platform** — macOS, Linux, Windows.

## How it works

Each machine runs a small daemon (`meshd`) that creates a per-mesh **TUN** device and a
UDP socket. Members share a mesh secret; every frame is sealed (ChaCha20-Poly1305) and
sent peer-to-peer, with the public node relaying when direct paths fail. The CLI/GUI talk
to the daemon over a local socket — the daemon is the single authoritative actor; the GUI
just visualizes it. Architecture detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) ·
[`docs/MESH_V2.md`](docs/MESH_V2.md).

```
crates/proto · tun · net      shared wire types, virtual NIC, UDP transport + relay
crates/mesh                   per-mesh crypto, membership, charter, flow table, IPC contract
crates/meshrun                the data-plane loop (TUN ⇄ sealed UDP ⇄ peers/relay)
crates/meshd                  the daemon: control plane, discovery, persistence, IPC server
scripts/lattice               the zero-dependency Python CLI
gui/                          the Tauri desktop app
```
(The original v1 stack is archived under [`legacy/`](legacy/README.md).)

## Security

This is an **early-access prototype**, built for **your own machines and trusted members**:

- **Members share the mesh key** — any member can read/relay the mesh's traffic. Invite
  only people/devices you trust. (App-layer encryption like SSH/TLS still protects content
  end-to-end on top of the tunnel.)
- The local control socket trusts **local processes** on that machine — run it on
  machines you control.
- Not yet hardened for hostile multi-tenant use. For your own fleet, a home/lab/office
  setup, or a research deployment, it's ready to use today.

## License

**Source-available, noncommercial** — see [`LICENSE`](LICENSE). Free for personal and
research use. Two things require contacting the author (**omnyx2@gmail.com**) first:
**commercial use** (needs a separate license) and **publishing an academic paper** based
on this software (needs permission; the author must be credited if requested).
