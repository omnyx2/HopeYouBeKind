# Lattice feature cookbook (beginner-friendly)

> 한국어: [cookbook.ko.md](cookbook.ko.md)

This is a set of short, copy-paste **recipes** for everyday things you can do
with Lattice, the **serverless mesh VPN**. Each recipe says what you get, when to
use it, the exact `lattice` commands, and a caveat or two. If you've never used
Lattice before, read [getting-started.en.md](getting-started.en.md) first — it
gets you from zero to a working mesh. Everything below uses the same `lattice`
CLI talking to the `meshd` daemon; `<mesh>` and `<member>` accept **names or
numbers** (e.g. `home` or `1`, `alice` or `1`).

## Recipes

1. [Private LAN between your machines (no exit)](#1-private-lan-between-your-machines-no-exit)
2. [Full-tunnel VPN / bypass geo-blocks](#2-full-tunnel-vpn--bypass-geo-blocks)
3. [Several meshes on one computer](#3-several-meshes-on-one-computer)
4. [Ephemeral / self-destructing mesh](#4-ephemeral--self-destructing-mesh)
5. [Attack response (panic button)](#5-attack-response-panic-button)
6. [Rotate the key / evict offline members (re-cipher)](#6-rotate-the-key--evict-offline-members-re-cipher)
7. [Choosing a cipher](#7-choosing-a-cipher)
8. [Invite secrecy (algorithms)](#8-invite-secrecy-algorithms)
9. [Survives reboot & network change (persistence)](#9-survives-reboot--network-change-persistence)
10. [Automatic peer discovery / NAT traversal](#10-automatic-peer-discovery--nat-traversal)
11. [Always-on protections (nothing to configure)](#11-always-on-protections-nothing-to-configure)
12. [Updating Lattice (and keeping your meshes)](#12-updating-lattice-and-keeping-your-meshes)
- [Coming soon / planned (design only — not usable yet)](#coming-soon--planned-design-only--not-usable-yet)

---

## 1. Private LAN between your machines (no exit)

**What you get:** an encrypted private LAN — reach any peer at
`100.80.<mesh>.<member>` from any other machine in the mesh.

**When to use:** SSH, file copy, a private web service, a game server — anything
you'd do over a LAN, but across the internet and encrypted. This is the simplest
use of Lattice. No exit, no VPN toggle needed.

Once two machines have joined the same mesh (see the getting-started guide), each
member has an overlay IP `100.80.<meshid>.<memberid>`. Just use it:

```sh
lattice info home          # find each member's overlay IP and id
ssh user@100.80.1.2        # reach member #2 of mesh #1
scp file.tar user@100.80.1.2:/tmp/
curl http://100.80.1.3:8080/
```

**Caveats:** the overlay link MTU is **1280** — if an app needs a larger MTU
it should clamp to that. Peers show as `live` in `lattice info` only once they've
actually reached each other; if they stay `idle`, see recipe 10.

---

## 2. Full-tunnel VPN / bypass geo-blocks

**What you get:** all your internet traffic exits through another member's
connection, so your public IP becomes *theirs*.

**When to use:** appear in another country, or reach a site that's blocked on your
current network but open on the exit's network.

Pick an exit member, then turn the tunnel on:

```sh
lattice exit home alice    # route through member 'alice'
lattice vpn home           # full tunnel ON — everything exits via 'alice'
```

Check it worked, then turn it off when done:

```sh
curl https://1.1.1.1/cdn-cgi/trace | grep -E 'ip=|loc='   # should show alice's IP
lattice off                # back to direct internet
```

**Caveats:** DNS and routing are handled for you automatically (this was fixed in
**0.7.0** — on older builds full tunnel could break DNS). If the exit member dies
while you're tunnelled, a **kill-switch** auto-reverts you to direct internet so
you're never stranded.

---

## 3. Several meshes on one computer

**What you get:** one machine in many meshes at once, each isolated with its own
cipher and address range.

**When to use:** keep a `work` mesh and a `home` mesh separate on the same laptop;
they never see each other's traffic.

```sh
lattice new work --me alice
lattice new home --me alice
lattice ls                 # lists every mesh on this computer
```

Each mesh gets its own overlay range `100.80.<meshid>.x`, so member #2 of mesh #1
is `100.80.1.2` while member #2 of mesh #2 is `100.80.2.2`.

**Caveats:** member ids are 1 byte, so a mesh holds **up to 254 members**. Only
one mesh can be the full-tunnel exit at a time (`lattice vpn` switches to it);
in-mesh LAN access (recipe 1) works on all of them simultaneously.

---

## 4. Ephemeral / self-destructing mesh

**What you get:** a mesh whose keys are **wiped (unrecoverable)** if too few
members stay online — the network evaporates instead of lingering.

**When to use:** a short-lived sensitive group where the data shouldn't outlive
the people in the room.

```sh
lattice new secret --ephemeral
lattice info secret        # shows "ephemeral (self-destruct when isolated)"
```

This is **off by default** — a normal mesh is persistent (recipe 9). It's off by
default on purpose: a laptop that simply goes to sleep shouldn't nuke a small
mesh.

**Caveats:** self-destruct fires when **live members drop below the 60% floor**
(`ceil(0.6 * N)`) and stay there for the grace window (**180s**). Once the keys
are wiped they're gone — there is no recovery; you'd have to create and re-invite
from scratch. `lattice info` always tells you whether a mesh is persistent or
ephemeral.

---

## 5. Attack response (panic button)

**What you get:** a mesh-wide alarm that self-destructs **every** member's keys
unless the creator cancels it in time.

**When to use:** you believe a member or device is compromised and you want the
whole mesh to burn down now.

```sh
lattice attack home        # raises the alarm on every member
```

If the alert was a false alarm, **only the creator** can stand it down — and they
must do it within a short grace window (**30s**):

```sh
lattice allclear home      # (creator only) cancel the self-destruct
```

**Caveats:** this is **one-veto, fail-deadly** — if nobody runs `allclear` in
time, everyone self-destructs. It is **independent of recipe 4** and is **always
available**, even on persistent meshes. Use it deliberately.

---

## 6. Rotate the key / evict offline members (re-cipher)

**What you get:** a fresh mesh secret and a bumped epoch; members who were offline
at that moment are evicted.

**When to use:** routine key rotation, or to cut off a member who lost a device —
re-cipher while they're offline and they can't open new traffic until re-invited.

```sh
lattice recipher home              # rotate the key, bump the epoch
lattice recipher home --cipher chachapoly-epoch   # also switch cipher (recipe 7)
```

**Caveats:** re-cipher needs **at least 60% of the roster online** to succeed.
Anyone offline at that instant is **evicted** — they can't decrypt new traffic
until you `invite` them again. This is the only way to change a mesh's cipher
after creation.

---

## 7. Choosing a cipher

**What you get:** control over the data-plane cipher that encrypts your traffic.

**When to use:** at mesh creation, or when you want to switch (via re-cipher).

```sh
lattice ciphers            # list available data-plane ciphers
lattice new home --cipher chachapoly-epoch
```

Available ciphers:

- **`chachapoly-epoch`** — the default, recommended for normal use.
- **`timewindow`** — **EXPERIMENTAL research cipher**. Don't use it for anything
  you care about; it's here for crypto research, not production.

**Caveats:** the cipher is **fixed at creation** (`lattice new --cipher <name>`).
Changing it later is a re-cipher (recipe 6: `lattice recipher home --cipher
<name>`), which also rotates the key and evicts offline members.

---

## 8. Invite secrecy (algorithms)

**What you get:** an extra shared-secret layer on the invite, so only someone you
told the algorithm name to (out-of-band) can open it.

**When to use:** when even an intercepted invite code should be useless to an
outsider.

```sh
lattice algos                                 # list invite-wrap algorithms
lattice invite home bob <id-code> --algo <name>   # wrap the invite
lattice join <invite-code> --algo <name>          # joiner must know <name>
```

**Caveats:** the joiner must learn `<name>` **out-of-band** (in person, over a
separate channel) — the invite code itself doesn't reveal it. The **default works
without `--algo`**; only add this when you specifically want the extra secrecy
layer.

---

## 9. Survives reboot & network change (persistence)

**What you get:** your meshes are saved to disk automatically and reloaded when
`meshd` starts, so a reboot or a Wi-Fi switch doesn't drop you from the mesh.

**When to use:** it's automatic — you don't do anything. This is the default
(non-ephemeral) behavior.

Environment knobs on the `meshd` daemon:

```sh
# disable on-disk persistence entirely
sudo DATA_PLANE=1 MESHD_NO_PERSIST=1 ./target/debug/meshd /tmp/lattice-meshd.sock

# relocate where state is stored (default ~/.lattice/meshd)
sudo DATA_PLANE=1 MESHD_STATE_DIR=/path/to/state ./target/debug/meshd /tmp/lattice-meshd.sock
```

**Caveats:** state files are written for you; don't hand-edit them. A
self-destruct (recipe 4/5) or `lattice rm <mesh>` also **erases the on-disk
copy** — persistence won't bring a wiped mesh back.

---

## 10. Automatic peer discovery / NAT traversal

**What you get:** peers find each other automatically — you normally never set
peer addresses by hand.

**When to use:** it's automatic. Peers are learned from the invite, from a ~20s
gossip exchange, from reflexive public-address discovery (via a public peer), and
from a LAN multicast beacon for machines on the same network.

The only manual step is on a **public node** (e.g. a cloud exit), which should
advertise its reachable address so others behind NAT can connect to it:

```sh
sudo DATA_PLANE=1 MESHD_BIND_PORT=41000 MESHD_ADVERTISE=<public-ip>:41000 \
     ./target/release/meshd /tmp/lattice-meshd.sock
```

**Caveats:** if two peers are both behind strict NATs and neither is public, they
may not be directly reachable and stay `idle` in `lattice info` — route through a
public member instead. Set `MESHD_ADVERTISE` to a real, reachable `ip:port`.

---

## 11. Always-on protections (nothing to configure)

**What you get:** baseline security that's on by default, with no flags.

**When to use:** always — it's automatic.

- Traffic is encrypted with a **split header/body cipher**.
- The wire frame is **scrambled to resist fingerprinting**.
- Full-tunnel mode has a **kill-switch** that reverts you to direct internet if
  the exit dies (recipe 2).

**Caveats:** none to configure — there are no commands here. This recipe is just
to let you know these protections exist.

---

## 12. Updating Lattice (and keeping your meshes)

**What you get:** the desktop app tells you when a newer version exists and
preserves your mesh membership across the reinstall.

**When to use:** automatic — a banner appears at the top of the app when an update
is available.

- On launch the app checks GitHub Releases for a newer version. If there is one, an
  **Update** banner appears (or **Later** to dismiss).
- **Update** first backs up every mesh to `<tempdir>/lattice-mesh-backup.json`, then
  opens the download page. Install the new version and reopen Lattice — the new
  `meshd` re-imports the backup (then deletes it), so you stay in all your meshes
  even if the install wiped local state.
- From the CLI you can take the same backup manually before any reinstall:

```sh
lattice backup                 # snapshot to <tempdir>/lattice-mesh-backup.json
lattice backup /path/to/x.json # or a chosen path
```

- The **Windows installer** offers per-user or per-machine install; the **MSI**
  shows a Change / Repair / Remove menu when you run it again on an installed copy.

**Caveats:** the backup is a one-shot hand-off — `meshd` deletes it after importing.
Normal persistence (recipe 9) already survives most updates; this backup is the
safety net for a clean reinstall that wipes the state dir.

---

## Coming soon / planned (design only — not usable yet)

These are **designed but NOT implemented in the CLI yet** — there are no `lattice`
commands for them today. Do not rely on them:

- **In-mesh DNS names** — reach peers by name instead of `100.80.x.y`. Design:
  [`../MESH_DNS.md`](../MESH_DNS.md).
- **Per-app / per-site split tunnel** — send only some apps or sites through the
  exit while the rest goes direct. Design: [`../AUTO_EXIT.md`](../AUTO_EXIT.md).

Until these ship, use full-tunnel (recipe 2) for VPN routing and overlay IPs
(recipe 1) to reach peers.
