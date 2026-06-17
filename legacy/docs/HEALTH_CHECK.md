# Mesh health check

> ⚠️ **This feature deliberately weakens security. Read "Security impact" before
> enabling or relying on it.**

The health check returns **every virtual IP on the mesh in one shot** — this node
plus every peer it knows — so an external helper (e.g. a monitoring/sync agent)
can see the whole overlay's addressing at a glance, without walking the peer list
or holding any mesh credentials itself.

```
$ minisync health
100.64.0.13  cb2aacf0  self
100.64.0.11   c2b92574  connected
100.64.0.10   7dbce35e  connected
```

Each row is `virtual-ip  fingerprint  status`, where status is `self` or the
peer's reachability (`connected` / `connecting` / `known` / `lost`).

## Why this is off the normal path

Everything else a client asks the daemon (status, peers, flows, membership) is
scoped to *this* node's own view and is fine for any local user to read. The
health check is different: it is a **single endpoint that dumps the entire
network's address map**. That is exactly the reconnaissance an attacker wants —
the full list of live overlay hosts to scan or target. So it is gated, and the
gate itself is weak, which is why it lives in its own document.

## Access control: process-name allow-list

The daemon answers `HealthCheck` **only** when the connecting process's name is on
its allow-list. The list is set with `--health-allow` and defaults to a single
name, `minisync`:

```
lattice-daemon ...                          # only a process named "minisync" may call it
lattice-daemon ... --health-allow minisync --health-allow mon-agent   # several allowed
lattice-daemon ... --health-allow ""        # disable the health check entirely
```

The daemon learns the caller's name from the **Unix-socket peer credentials** —
`SO_PEERCRED` (Linux) / `LOCAL_PEERPID` (macOS) gives the client's PID, resolved
to a name via `/proc/<pid>/comm` (Linux) or the executable basename (macOS). No
name on the list ⇒ no name matches ⇒ the request is refused:

```
$ lattice health
error: health check denied for process "lattice" (allowed: ["minisync"])
```

To call it, the requesting program must **be** an allowed name. The bundled
`lattice` CLI has a `health` subcommand, but invoked as `lattice` it is denied by
design; run it as a binary named `minisync` (your agent, or a copy/symlink of the
CLI) to be allowed.

## Security impact (read this)

**Process-name matching is a convenience gate, NOT a trust boundary. It
materially lowers the security of a node that enables it.**

- **A name is not an identity.** Any local user can name (or rename) a binary
  `minisync`, or `exec` after `argv[0]`-spoofing, and pass the gate. There is no
  signature, capability, or credential check — only the string.
- **It exposes the whole overlay.** Once past the gate, the caller gets every
  live node's virtual IP at once — a ready-made target list. Without this
  feature, that map never leaves the daemon in one piece.
- **The blast radius is local.** The IPC socket is `0666` (so the unprivileged
  GUI/CLI can talk to the root daemon), meaning *any* local process can attempt
  the call. The gate only stops processes that aren't willing to be named
  `minisync` — i.e. essentially nobody who is trying.

Net effect: enabling the health check trades the daemon's "least-exposure"
posture for the convenience of one well-known helper reading the topology. That
is an acceptable trade **only** on a node where you trust every local process, or
where the overlay map is not sensitive.

If you need real authorization here, this gate is the wrong tool — it would need
to be replaced with something that proves identity (a per-client token/secret, a
UID allow-list, an `SO_PEERCRED` UID check, or a signed request), not a name.
That hardening is intentionally out of scope; the feature ships as a deliberately
low-friction, low-assurance convenience.

## How to disable

Pass `--health-allow ""` (empty) to the daemon. With no names allowed, every
`HealthCheck` is refused and the topology stays inside the daemon.

## Wire detail

- IPC request `HealthCheck` → response `Health(Vec<HealthEntry>)`, where
  `HealthEntry { virtual_ip, fingerprint, status }` (see `lattice_proto::ipc`).
- The authorization happens in the daemon's IPC handler using the caller name
  surfaced by `lattice_ipc::serve`; the `lattice-ipc` layer resolves it once per
  connection from the socket peer credentials.
