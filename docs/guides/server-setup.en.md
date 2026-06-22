# Server setup — run a Lattice node headless

A practical quickstart for putting a node on an **always-on server** (a cloud VM,
a home box, a Raspberry Pi) with **no GUI** — everything from the terminal. A server
is usually the **public exit / DHT seed** the other (NAT'd) nodes find and route through.

For the full command/env reference see [CLI operator reference](cli-reference.en.md).
This page is the "just get me running" path.

---

## 0. Two install paths — new here? Use **Path A**

There are two ways to stand up a server node. **If you've never built from source, or you
just want it running fast, use Path A** — no Rust, no compiling. Only take Path B when you
need to edit the code or build the very latest commit.

### Path A — no build (recommended · beginners) ⭐

Grab the **prebuilt `meshd`** binary for your OS/arch from the
[Releases page](https://github.com/omnyx2/HopeYouBeKind/releases/latest) and run it as-is.
Ubuntu (x86-64) example:

```sh
# 1. download the prebuilt daemon + CLI (copy line by line)
mkdir -p ~/lattice && cd ~/lattice
curl -fL -o meshd https://github.com/omnyx2/HopeYouBeKind/releases/latest/download/meshd-Linux-X64
chmod +x meshd
curl -fL -o lattice https://raw.githubusercontent.com/omnyx2/HopeYouBeKind/main/scripts/lattice
chmod +x lattice

# 2. tell the CLI which daemon to use (also put these two lines in ~/.bashrc)
export LATTICE_MESHD=~/lattice/meshd
export PATH="$HOME/lattice:$PATH"

# 3. start at boot as a service (public exit/seed: pin your public ip + open ports)
sudo -E lattice install-service --advertise <PUBLIC_IP>:41000 --bind-port 41000 --dht-port 41001

# 4. check it
lattice status
```

> On an ARM server (Raspberry Pi, Ampere/Graviton) download **`meshd-Linux-ARM64`**
> instead of `meshd-Linux-X64`. If `uname -m` says `aarch64`/`arm64`, you're on ARM.

That's it — a running, boot-persistent daemon. Continue to §1 (ports) and §3 (mesh).

### Path B — build from source (when you need to edit code / latest commit)

Building needs the **Rust toolchain and a C linker**. A bare server usually has neither, so
you'll hit `cargo: command not found` or `linker 'cc' not found` — install them first:

```sh
# Ubuntu/Debian: build tools + Rust (one time)
sudo apt update && sudo apt install -y build-essential git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"          # add cargo to the current shell (new SSH sessions get it automatically)

# then clone + build (a few minutes depending on CPU)
git clone https://github.com/omnyx2/HopeYouBeKind.git && cd HopeYouBeKind
cargo build --release -p lattice-meshd      # produces target/release/meshd
sudo ./scripts/lattice install              # put the `lattice` CLI on PATH

# start at boot as a service
sudo lattice install-service --advertise <PUBLIC_IP>:41000 --bind-port 41000 --dht-port 41001
lattice status
```

> If the build is killed for out-of-memory (`signal: 9, SIGKILL`) — common on 1 GB VMs —
> add temporary swap: `sudo fallocate -l 2G /swap && sudo chmod 600 /swap && sudo mkswap /swap && sudo swapon /swap`.

---

## 1. Prerequisites

- **Linux** (systemd) for `install-service`; macOS works with `lattice up` (no GUI service).
- **Root** — the daemon creates a TUN device and edits routes. The CLI auto-uses `sudo`.
- **Open UDP ports** in *both* the cloud security list **and** the host firewall:
  - **41000** — the mesh data plane (`--bind-port`).
  - **41001** — DHT rendezvous (`--dht-port`), so this node can be a discovery seed.
  - The DHT default is `42900`; pin it to a port you've actually opened.
- **No build needed** for the common case — Path A (§0) uses a prebuilt binary. Only Path B
  (from source) needs Rust + `build-essential`, and §0 spells out installing them.

```sh
# Oracle Cloud / Ubuntu example — open the host firewall (cloud security list is separate)
sudo ufw allow 41000/udp && sudo ufw allow 41001/udp
```

---

## 2. Run the daemon

### As a boot service (recommended)

```sh
sudo lattice install-service --advertise <PUBLIC_IP>:41000 --bind-port 41000 --dht-port 41001
```

This writes `/etc/systemd/system/lattice-meshd.service`, `daemon-reload`s, and
`enable --now`s it. The daemon now starts on every boot and restarts on crash.

| Manage it | Command |
|---|---|
| Health at a glance | `lattice status`  (`--watch 2` for a live view) |
| Follow logs | `lattice logs -f`  ·  `journalctl -u lattice-meshd -f` |
| Restart | `sudo lattice restart`  ·  `sudo systemctl restart lattice-meshd` |
| Stop | `sudo systemctl stop lattice-meshd` |
| Remove the service | `sudo lattice uninstall-service` |

> `lattice down` cleanly stops the daemon over the socket (no sudo), but the service's
> `Restart` policy may not bring it back automatically — use `systemctl restart` /
> `sudo lattice restart` to start it again.

### Without a service (foreground / ad-hoc)

```sh
sudo lattice up --advertise <PUBLIC_IP>:41000 --bind-port 41000 --dht-port 41001
#   --foreground to keep it in this terminal (Ctrl-C to stop); else it backgrounds.
lattice status
sudo lattice down        # stop it
```

`lattice up` auto-detects the `meshd` binary (repo build dir, an installed app, or
`$LATTICE_MESHD`), elevates with `sudo` for the TUN, and waits until the socket answers.

---

## 3. Create or join a mesh

### This server creates the mesh (it's the first node)

```sh
lattice new corp --me seed         # you become member #1 "seed"
lattice serve-exit corp            # make THIS server the mesh's internet exit
```

### This server joins an existing mesh

The invite flow is two one-line codes. Headless, it **pipes over SSH**:

```sh
# from a machine that can SSH into both: pull the server's identity, mint the invite
ssh server lattice id | lattice invite corp seed -
#   -> prints an invite code; hand it back to the server:
ssh server lattice join <invite-code>
```

Or run each step by hand (copy the one-line codes between terminals):
`server: lattice id` → `host: lattice invite corp seed <id>` → `server: lattice join <invite>`.

Confirm everyone is connected:

```sh
lattice info corp        # every member should read 'live'
lattice doctor           # health check + suggested fixes if not
```

---

## 4. Client nodes (behind NAT) bootstrap off this seed

On each client, point the DHT at this server's public address — it then finds every
peer automatically (gossip + reflexive STUN + DHT rendezvous):

```sh
sudo lattice up --dht-bootstrap <PUBLIC_IP>:41001
```

Then run the invite/join flow (§3). A client that only learned the inviter's address
still re-discovers the others through the seed.

---

## 5. Day-to-day operations

```sh
lattice ls                       # meshes on this node
lattice status --watch 2         # live dashboard (great in an SSH pane)
lattice info corp                # members, liveness, endpoints, exit
lattice doctor                   # diagnose idle/health problems
lattice traffic --detail         # per-peer bytes + recent flows (who talked to whom)
lattice flows corp --block 1.1.1.1   # SDN routing rule (gossiped to all members)
lattice exit corp seed           # set which member is the exit
lattice recipher corp            # rotate the key (evicts offline members)
lattice expel corp <member>      # remove a member (per the mesh's expel policy)
```

State persists under the **running user's** home — for the root service that is
`/root/.lattice/meshd` (0700 dir, 0600 JSON). It reloads on restart, so reboots and
network changes don't drop the node. Network changes (new IP, roaming) self-heal
automatically; see [DYNAMIC_NETWORK](../DYNAMIC_NETWORK.md).

---

## 6. Updating the server

```sh
cd HopeYouBeKind && git pull
cargo build --release -p lattice-meshd        # or drop in a new standalone binary
sudo systemctl restart lattice-meshd          # picks up the new binary
lattice status                                # confirm it's back + meshes reloaded
```

Mesh state survives the restart (it's persisted). Keep every node on a compatible
version — roster/flow gossip and the wire format assume a matching `meshd`.

---

## Troubleshooting

| Symptom | Check |
|---|---|
| `meshd not reachable … Is the daemon running?` | `lattice status`; `systemctl status lattice-meshd`; `journalctl -u lattice-meshd -e`. |
| A peer shows `idle` / not `live` | `lattice doctor`. Usually the UDP ports aren't open end-to-end, or the two nodes are on different network ids (split-brain). |
| `binary not found` in `lattice status` | The CLI couldn't locate `meshd`. Set `export LATTICE_MESHD=/path/to/meshd`. |
| Exit traffic doesn't leave | The exit node needs ip-forwarding + NAT (auto-enabled while the data plane is up) **and** the cloud firewall must allow forwarding/egress. |
| Two daemons fighting for a port | Only one `meshd` per host. Remove any old/hand-written unit before `install-service`. |
