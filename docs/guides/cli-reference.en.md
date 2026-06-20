# Lattice CLI operator reference

*(한국어판: [cli-reference.ko.md](cli-reference.ko.md))*

Everything an operator needs to run and manage Lattice from the command line — **no
GUI, no hand-holding**. Pairs with the beginner [getting-started](getting-started.en.md)
and [cookbook](cookbook.en.md). Two pieces:

- **`meshd`** — the per-machine daemon (control plane + data plane). One per machine.
- **`lattice`** — a zero-dependency Python CLI (`scripts/lattice`) that talks to `meshd`
  over its local socket. Same machine only.

---

## 0. Copy-paste cheat sheet (TL;DR)

Two machines: a **server** with a public IP (the seed/exit) and a **client** (laptop
behind NAT). Replace `<PUBLIC_IP>` with the server's public IP. Sections 1–7 explain
every line; this is the whole thing, copy-pasteable.

**① SERVER — build once, run, create the mesh** *(open UDP 41000 + 41001 in your cloud firewall first)*

```sh
git clone https://github.com/omnyx2/HopeYouBeKind.git && cd HopeYouBeKind
cargo build --release -p lattice-meshd
sudo ln -sf "$PWD/scripts/lattice" /usr/local/bin/lattice

sudo DATA_PLANE=1 MESHD_BIND_PORT=41000 MESHD_DHT_PORT=41001 \
  MESHD_ADVERTISE=<PUBLIC_IP>:41000 \
  ./target/release/meshd /tmp/meshd.sock &
export LATTICE_SOCK=/tmp/meshd.sock

lattice new corp --me seed          # you are member #1
```

**② CLIENT — build once, run, join** *(get the invite via the 3 steps below)*

```sh
git clone https://github.com/omnyx2/HopeYouBeKind.git && cd HopeYouBeKind
cargo build --release -p lattice-meshd
sudo ln -sf "$PWD/scripts/lattice" /usr/local/bin/lattice

sudo DATA_PLANE=1 MESHD_DHT_BOOTSTRAP=<PUBLIC_IP>:41001 \
  ./target/release/meshd &

lattice id                          # 1) prints your identity code — send the line to the server
#    server admin runs:  lattice invite corp laptop <that-id-code>   -> prints an invite code
lattice join <INVITE_CODE>          # 2) paste the invite code here
lattice info corp                   # 3) everyone should show 'live'
```

**③ FULL VPN — send all the client's internet through the server**

```sh
lattice exit corp seed              # pick the server as the exit
lattice vpn corp                    # route everything through it
curl -s https://ifconfig.co         # should print the SERVER's public IP
lattice off                         # back to direct internet
```

---

## 1. Build & install

```sh
# from the repo root — build the daemon (release)
cargo build --release -p lattice-meshd
# the binary: target/release/meshd

# put the CLI on PATH (symlink into /usr/local/bin; --copy to copy instead)
sudo ./scripts/lattice install
lattice --help            # built-in help; `lattice <cmd> --help` per command
```

Requirements: Rust (stable) to build; Python 3 for the CLI; root/admin to run the data
plane (it creates a TUN device). The CLI needs nothing but Python 3.

---

## 2. Run the daemon

`meshd` listens on a local socket and (with the data plane on) creates one TUN device
+ one UDP socket **per mesh**. It must run as **root** (Linux/macOS) or **elevated**
(Windows) for the TUN.

**The easy way (headless server)** — the CLI manages the daemon for you, so you never
hand-write env vars or sudo lines:

```sh
sudo lattice up                 # start meshd in the background (data plane on)
lattice status                  # daemon health + meshes / exit / traffic (--watch N)
lattice logs -f                 # follow the daemon log
lattice down                    # stop it cleanly (no sudo — over the IPC socket)
# pin a public address (exit/seed node) and start at boot:
sudo lattice install-service --advertise <public-ip>:41000
```

`lattice up` auto-detects the `meshd` binary (repo build dir, the installed app, or
`$LATTICE_MESHD`), re-launches it under `sudo` for the TUN, and waits until the socket
answers. Flags: `--advertise IP:PORT`, `--state-dir DIR`, `--dht-port N`, `--no-dht`,
`--foreground`, `--log FILE`.

**The manual way** (equivalent, for reference):

```sh
# Linux / macOS — data plane on, foreground (Ctrl-C to stop)
sudo DATA_PLANE=1 ./target/release/meshd
# socket: /tmp/lattice-meshd.sock   (override by passing a path as the first arg)
```

Control-plane-only (no TUN, no root — for inspecting state / scripting): omit
`DATA_PLANE`. You can create/join meshes but no traffic flows until a data-plane daemon
runs.

### Environment variables (authoritative)

| Variable | Default | Purpose |
|---|---|---|
| `DATA_PLANE=1` | off | Bring up the per-mesh TUN+UDP data plane (needs root/admin). Without it, control plane only. |
| `MESHD_DHT=0` | **on** (when data plane up) | Opt **out** of DHT rendezvous (re-find moved peers). On by default; set `=0` to disable. |
| `MESHD_DHT_PORT` | `42900` | DHT overlay UDP port. **Must be reachable** (firewall-open) for this node to serve as a DHT peer/seed. |
| `MESHD_DHT_BOOTSTRAP` | — | Comma list `ip:port,…` of DHT seed nodes (a public node's DHT port). Clients point this at the seed. |
| `MESHD_BIND_PORT` | `42000 + mesh_id` | Pin the per-mesh data-plane UDP port. Use on single-open-port hosts (cloud firewalls). |
| `MESHD_ADVERTISE` | auto (reflexive) | Pin this node's publicly reachable `ip:port` data-plane endpoint. Set on **public seed/exit nodes**; clients behind NAT learn theirs automatically. |
| `MESHD_STATE_DIR` | `$HOME/.lattice/meshd` | Where meshes persist (0700 dir, 0600 JSON). |
| `MESHD_NO_PERSIST=1` | off | Disable on-disk persistence (RAM only; meshes vanish on restart). |
| `MESHD_NO_SELF_DESTRUCT=1` | off | Disable the liveness self-destruct watchdog (P-C4). |
| `MESHD_IMPORT` | `<tmp>/lattice-mesh-backup.json` | Path of the update-migration backup read once at startup. |
| `LATTICE_SOCK` | `/tmp/lattice-meshd.sock` | (CLI) which daemon socket to talk to. Or `lattice --sock <path>`. |

### Ports & sockets

- **IPC**: unix socket `/tmp/lattice-meshd.sock` (Linux/macOS) or named pipe
  `\\.\pipe\lattice-meshd` (Windows). Override the unix path by passing it as the first
  CLI-less arg to `meshd`.
- **Mesh data plane**: UDP `MESHD_BIND_PORT` (or `42000+mesh_id`).
- **DHT rendezvous**: UDP `MESHD_DHT_PORT` (default `42900`).

> **Firewalled / cloud hosts:** open the mesh port **and** the DHT port (UDP) in both
> the cloud security list and the host firewall. The DHT default `42900` is often *not*
> in the open range — pin `MESHD_DHT_PORT` to a port you've opened.

---

## 3. `lattice` command reference

`lattice [--sock PATH] <command> [args]`. Mesh/member args accept an **id or a name**.

| Command | What it does |
|---|---|
| `ls` | List meshes on this machine. |
| `info <mesh>` | Show one mesh: members, liveness, endpoints, exit, health. |
| `doctor [mesh]` | Diagnose mesh health (idle reasons, decrypt-fail/split-brain) and suggest fixes. |
| `new <name> [--me NAME] [--max N] [--cipher C] [--ephemeral] [--master-gated] [--expel POLICY] [--header PLACEMENT]` | Create a mesh (you become member #1). |
| `id` | Mint an identity code (give this to a mesh host so they can invite you). |
| `invite <mesh> <name> <id_code> [--algo A]` | (host) Mint an invite for a joiner's identity code. |
| `join <invite_code> [--algo A]` | Join a mesh from an invite code. |
| `exit <mesh> <member>` | Pick which member is the internet exit. |
| `vpn <mesh>` | Route **all** internet traffic through that mesh's exit (full tunnel). |
| `off` | Stop full tunnel; back to direct internet. |
| `traffic [mesh] [--detail]` | Traffic monitor: per-peer bytes/packets (`--detail` adds recent flows). |
| `recipher <mesh> [--cipher C]` | Rotate the mesh key (evicts offline members). |
| `expel <mesh> <member>` | Expel (revoke) a member, per the mesh's expel policy. |
| `attack <mesh>` | Raise an attack alert (one-veto, fail-deadly self-destruct). |
| `allclear <mesh>` | (creator) Cancel an attack alert. |
| `rm <mesh>` | Wipe a mesh from this machine. |
| `ciphers` / `algos` | List data-plane ciphers / invite-wrap algorithms. |
| `policy` | Show the current routing policy. |
| `backup [path]` | Snapshot meshes to a file (update migration). |
| `flows <mesh> [--block CIDR\|--exit CIDR\|--reset]` | Show/edit the SDN flow table (routing rules; gossiped to all members). |
| `raw '<json>'` | Send a raw IPC request (escape hatch). |
| **— server / daemon —** | |
| `up [meshd flags]` | Start meshd in the background (headless; auto-sudo for the TUN). |
| `down` | Stop the daemon cleanly over the socket (no sudo). |
| `restart [meshd flags]` | `down` then `up`. |
| `status [--watch N]` | Daemon health + meshes / exit / traffic, optionally live. |
| `logs [-f] [-n N]` | Show/tail the daemon log. |
| `serve-exit <mesh> [--advertise IP:PORT]` | Make THIS node the mesh's internet exit. |
| `install-service [meshd flags]` | Install + enable a systemd unit (Linux; start at boot). |
| `uninstall-service` | Remove the systemd unit (Linux). |
| `install [--prefix DIR] [--copy]` | Put `lattice` on PATH. |

---

## 4. The invite → join flow (3 steps, 2 machines)

Membership is admin-free: **any** member can invite (unless the mesh is `--master-gated`).

```sh
# joiner (machine B): mint an identity code, send the ONE line to the host
lattice id
#  eyJtZW1iZXJfcHVia2V5...    <- one line

# host (machine A): mint an invite for that code, send the ONE line back
lattice invite home bob eyJtZW1iZXJfcHVia2V5...
#  eyJzYWx0Ijog...           <- one line

# joiner (machine B): join
lattice join eyJzYWx0Ijog...
lattice info home            # both members should show 'live'
```

Identity codes expire (~10 min, P-C6). For secrecy, the host may pass `--algo` to
`invite`; the joiner must use the same `--algo` on `join` (tell them out-of-band).

**Headless shortcut** — `invite`/`join` read the code from **stdin** when given `-`, so
the whole exchange pipes between machines you can SSH into:

```sh
# host pulls the joiner's identity code over SSH and mints the invite in one line
ssh joiner lattice id | lattice invite home bob -
# ...then hand the printed invite code back (or pipe it the other way)
```

---

## 5. Deploy a multi-node mesh (1 public seed + NAT clients)

This is the verified topology: one always-on **public node** (cloud VM with a public IP)
acts as the data-plane exit/relay **and** the DHT bootstrap seed; every other node sits
behind NAT and finds peers automatically (gossip + reflexive STUN + DHT rendezvous).

### 5a. Public seed/exit node (systemd)

Open UDP **41000** (mesh) and **41001** (DHT) in the cloud security list **and** the host
firewall. Then **one command** installs + enables the boot service:

```sh
sudo lattice install-service --advertise <PUBLIC_IP>:41000 --dht-port 41001
lattice status                                  # active + reachable
sudo lattice serve-exit corp                    # make this node the mesh's exit
```

That writes `/etc/systemd/system/lattice-meshd.service`, `daemon-reload`s, and
`enable --now`s it. Manage it with `lattice status` / `lattice logs -f` /
`journalctl -u lattice-meshd -f`, or `sudo lattice uninstall-service` to remove.

<details><summary>Equivalent hand-written unit (for reference)</summary>

```ini
# /etc/systemd/system/meshd-node.service
[Unit]
Description=Lattice meshd (public exit/relay + DHT seed)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=DATA_PLANE=1
Environment=MESHD_BIND_PORT=41000
Environment=MESHD_DHT_PORT=41001
Environment=MESHD_ADVERTISE=<PUBLIC_IP>:41000
ExecStart=/path/to/meshd /tmp/meshd.sock
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now meshd-node.service
sudo systemctl status meshd-node.service        # expect: active (running)
LATTICE_SOCK=/tmp/meshd.sock lattice ls         # talk to it
```

</details>

On the seed, create the mesh and become member #1:

```sh
export LATTICE_SOCK=/tmp/meshd.sock
lattice new corp --me seed
```

### 5b. Client node (behind NAT)

```sh
sudo lattice up --dht-bootstrap <PUBLIC_IP>:41001
# (manual equivalent: sudo DATA_PLANE=1 MESHD_DHT_BOOTSTRAP=<PUBLIC_IP>:41001 ./target/release/meshd)
```

Then run the [invite/join flow](#4-the-invite--join-flow-3-steps-2-machines): client
`lattice id` → seed `lattice invite corp <name> <id>` → client `lattice join <invite>`.

A client that learns only the inviter's address still re-discovers the other peers via
the DHT seed — `lattice info corp` shows all members `live`. Turn on the full tunnel:

```sh
# on a client: send all internet traffic out through the public seed
lattice exit corp seed
lattice vpn corp
curl -s https://ifconfig.co        # should show the seed's public IP
lattice off                        # back to direct internet
```

---

## 6. Per-OS notes

| OS | TUN | Elevation | IPC | CLI |
|---|---|---|---|---|
| Linux | `/dev/net/tun` | `sudo` | unix socket | `lattice` directly |
| macOS | `utun` | `sudo` | unix socket | `lattice` directly |
| Windows | Wintun (driver embedded in `meshd.exe`) | **elevated** process | named pipe `\\.\pipe\lattice-meshd` | see note ↓ |

**Windows:** run `meshd.exe` **elevated** (the data plane needs admin for Wintun).
Headless over SSH, a scheduled task launched with PowerShell `Start-ScheduledTask`
(created `/ru SYSTEM /rl highest`) runs it elevated without an interactive UAC prompt.
The Python `lattice` CLI uses a unix socket, so it does **not** drive a Windows daemon
directly — use the desktop GUI, or a named-pipe IPC client, to issue `NewIdentity` /
`JoinMesh` on Windows. DHT/mesh ports still need to be allowed in Windows Firewall.

---

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `meshd not running (… ): No such file/Connection refused` | Daemon isn't up, or wrong `LATTICE_SOCK`. Start `meshd`; check the socket path. |
| `info` shows a member `unknown` / endpoint `—` | Peer not reachable yet. Check both data-plane ports are open; the DHT/gossip converge within ~30 s. |
| A member stays `unknown` and a **public node** never connects (esp. a GUI-created mesh) | A node behind NAT can't auto-find a public peer unless its `meshd` was launched with `MESHD_DHT_BOOTSTRAP=<PUBLIC_IP>:41001`. The **GUI launches `meshd` without that**, so point it once: **Peers tab → the `unknown` member → "set address" → `<PUBLIC_IP>:41000`** (or the Overview "Peer address" card). CLI equivalent: `lattice raw '{"SetPeer":{"mesh":N,"member":M,"endpoint":"<PUBLIC_IP>:41000"}}'`. After one packet, reflexion + gossip take over and everyone converges. A **CLI client started with `MESHD_DHT_BOOTSTRAP`** skips this entirely. |
| GUI/`info` shows **data plane DOWN** | The mesh's UDP port is held by another process (a stale/second `meshd`). `meshd` retries the bind for a few seconds; kill the stale daemon and it recovers (single-instance guard prevents new ones from orphaning a live one). |
| `cannot create pipe … (os error 5)` (Windows) | Another `meshd` already owns the pipe. Stop it first (or reboot — Lattice does not auto-start). |
| Two nodes can't connect across the internet | Both behind NAT with no public path — add a public seed node and point `MESHD_DHT_BOOTSTRAP` + `exit` at it. |
| Mesh vanished after restart | `MESHD_NO_PERSIST` was set, or `MESHD_STATE_DIR` differs (root vs user `$HOME`). The daemon persists under the **running user's** `$HOME/.lattice/meshd`. |

Inspect anything with the raw escape hatch:

```sh
lattice raw '"ListMeshes"'
lattice raw '{"MeshInfo":{"mesh":1}}'
```
