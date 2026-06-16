# Make your first VPN with Lattice (beginner guide)

> 한국어: [getting-started.ko.md](getting-started.ko.md)

Lattice is a **serverless mesh VPN**. You install it on a few machines and they
join into one private encrypted network — no central server, no accounts. This
guide takes you from zero to **"all my laptop's traffic exits through my home
server in another country."**

You'll use the `lattice` CLI (`scripts/lattice`). It talks to the `meshd`
daemon over a local socket so you never write JSON by hand.

---

## 0. Concepts in 30 seconds

- **Mesh** — a private network. One computer can be in several meshes at once.
- **Member** — one machine in a mesh. Members get an overlay IP
  `100.80.<mesh>.<member>` (e.g. `100.80.1.1`) and can reach each other directly.
- **Creator** — whoever runs `lattice new`. They hold the mesh's master key and
  can invite people. No admin server is involved.
- **Exit** — the member whose internet connection everyone else can route
  through (that's the "VPN" part). Optional.

---

## 1. Start the daemon

`meshd` needs root (it creates a TUN network interface) and the `DATA_PLANE=1`
environment variable to actually move packets.

```sh
# from the repo root — build once
RUSTUP_TOOLCHAIN=stable cargo build -p lattice-meshd

# run it (root, data plane on). Keep this running in a terminal.
sudo DATA_PLANE=1 ./target/debug/meshd /tmp/lattice-meshd.sock
```

On a **public server** (your exit node) also advertise its address so others can
find it:

```sh
sudo DATA_PLANE=1 MESHD_BIND_PORT=41000 MESHD_ADVERTISE=<public-ip>:41000 \
     ./target/release/meshd /tmp/meshd.sock
```

Put the CLI on your `PATH` for convenience:

```sh
sudo ln -sf "$PWD/scripts/lattice" /usr/local/bin/lattice
lattice ls          # should print "no meshes yet"
```

---

## 2. Create a mesh (on machine A)

```sh
lattice new home --me alice
# created mesh #1 'home' — you are 'alice'.
```

`alice` is now member `#1` at overlay IP `100.80.1.1`.

---

## 3. Invite a second machine (machine B)

Membership is invite-based and needs **two copy-pastes** between the machines
(send them over any chat — they're safe to pass around):

**On machine B** — mint an identity code:

```sh
lattice id
# eyJtZW1iZXJfcHVia2V5X2hleCI6IC4uLg...      <- copy this one line
```

**On machine A** — turn that code into an invite for "bob":

```sh
lattice invite home bob eyJtZW1iZXJfcHVia2V5X2hleCI6IC4uLg...
# eyJzYWx0IjogWzk2LC4uLg...                   <- copy this one line back
```

**On machine B** — join with the invite:

```sh
lattice join eyJzYWx0IjogWzk2LC4uLg...
# joined mesh #1. `lattice info 1` to see peers.
```

That's it. Check both sides:

```sh
lattice info home
#   members:
#     #1   alice   live   ...
#     #2   bob     live   ...
```

You can now reach machine A from machine B at its overlay IP — e.g.
`ssh alice@100.80.1.1`, copy files, run anything. The traffic is encrypted and
peer-to-peer.

> The identity code **expires in ~10 minutes** — mint it right before inviting.

---

## 4. Turn it into a full VPN (route all traffic through an exit)

Say machine A is a server in Japan and you (machine B) want your whole laptop to
appear in Japan.

```sh
# on machine B: pick alice (member #1) as the exit, then route everything through it
lattice exit home alice
lattice vpn home
# full tunnel ON — all internet traffic now exits via mesh 1.
```

Verify your public IP changed:

```sh
curl https://1.1.1.1/cdn-cgi/trace | grep -E 'ip=|loc='
# ip=<machine A's public IP>   loc=JP
```

DNS and routing are handled for you. To go back to normal internet:

```sh
lattice off
# full tunnel OFF — back to direct internet.
```

If the exit ever dies while you're tunnelled, a **kill-switch** auto-reverts you
to direct internet so you're never stranded.

---

## 5. Everyday commands

```sh
lattice ls                 # all meshes on this computer
lattice info <mesh>        # members, who's live, the exit, the cipher
lattice exit <mesh> <who>  # choose the internet exit
lattice vpn <mesh>         # full tunnel on
lattice off                # full tunnel off
lattice rm <mesh>          # leave / wipe a mesh from this computer
lattice raw '<json>'       # escape hatch: send a raw request
```

`<mesh>` and `<who>` accept **names or numbers** (`home` or `1`, `alice` or `1`).

---

## Where next

- **Feature cookbook** (private LAN, ephemeral meshes, key rotation, attack
  response, cipher choice, and more): [cookbook.en.md](cookbook.en.md)
- Protocol internals: [`../MESH_V2.md`](../MESH_V2.md),
  [`../PROTOCOL_DESIGN.md`](../PROTOCOL_DESIGN.md)
- Discovery / NAT traversal: [`../DISCOVERY.md`](../DISCOVERY.md)

## Troubleshooting

| Symptom | Fix |
|---|---|
| `meshd not reachable` | The daemon isn't running, or wrong socket. Start `meshd`, or pass `--sock <path>`. |
| `join` says `already in mesh` | This computer is already a member of that mesh. |
| `invite` says identity is too old | The code expired (~10 min). Re-run `lattice id` and try again. |
| Full tunnel, but no internet | You're likely on an old build — DNS/route handling was fixed in `0.7.0`. Rebuild `meshd`. |
| Peers stuck `idle`, never `live` | They can't reach each other's UDP port. On a public exit set `MESHD_ADVERTISE`; check firewalls. |
