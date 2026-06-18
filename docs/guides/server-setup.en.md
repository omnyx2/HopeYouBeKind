# Server setup — run a Lattice node headless

A practical quickstart for putting a node on an **always-on server** (a cloud VM,
a home box, a Raspberry Pi) with **no GUI** — everything from the terminal. A server
is usually the **public exit / DHT seed** the other (NAT'd) nodes find and route through.

For the full command/env reference see [CLI operator reference](cli-reference.en.md).
This page is the "just get me running" path.

---

## 0. TL;DR (a server in 4 commands)

```sh
# 1. build the daemon
git clone https://github.com/omnyx2/HopeYouBeKind.git && cd HopeYouBeKind
cargo build --release -p lattice-meshd

# 2. put the CLI on PATH
sudo ./scripts/lattice install

# 3. start at boot as a service (public exit/seed: pin your public ip + open ports)
sudo lattice install-service --advertise <PUBLIC_IP>:41000 --bind-port 41000 --dht-port 41001

# 4. check it
lattice status
```

That's a running, boot-persistent daemon. Now create or join a mesh (§3).

> **No Rust on the box?** Download the prebuilt **standalone `meshd`** for your
> OS/arch from the [Releases page](https://github.com/omnyx2/HopeYouBeKind/releases)
> (e.g. `meshd-Linux-X64`, `meshd-Linux-ARM64`), `chmod +x` it, and point the CLI at
> it: `export LATTICE_MESHD=/path/to/meshd`. Steps 2–4 are unchanged.

---

## 1. Prerequisites

- **Linux** (systemd) for `install-service`; macOS works with `lattice up` (no GUI service).
- **Root** — the daemon creates a TUN device and edits routes. The CLI auto-uses `sudo`.
- **Open UDP ports** in *both* the cloud security list **and** the host firewall:
  - **41000** — the mesh data plane (`--bind-port`).
  - **41001** — DHT rendezvous (`--dht-port`), so this node can be a discovery seed.
  - The DHT default is `42900`; pin it to a port you've actually opened.
- To build on the box you need Rust (`rustup`, stable) — or use the prebuilt binary above.

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
