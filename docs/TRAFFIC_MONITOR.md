# Traffic monitor

The traffic monitor is a passive observer of **everything that crosses the
tunnel** — so you can see exactly what is flowing between peers, by protocol and
endpoint, in real time.

## What it captures

Every plaintext IP packet is recorded on the way out (just before it is
encrypted) and on the way in (just after it is decrypted), then aggregated into
**flows**. A flow is keyed by `(peer, protocol, local endpoint, remote endpoint)`
and both directions collapse onto one record, so a single conversation shows up
once with separate ↑ sent / ↓ received counters.

Each flow carries:

- **protocol** — TCP, UDP, ICMP, or `IP/<n>` for others.
- **local** ↔ **remote** — `ip:port` for TCP/UDP, `ip` otherwise. "Local" is this
  node; "remote" is the peer's virtual IP (mesh traffic) or a public address
  (internet traffic carried through an [exit node](EXIT_NODE.md)).
- **tx / rx packets and bytes**.
- **last active** — seconds since the flow last carried a packet.

State is bounded (at most 512 flows; the least-recently-active is evicted), so a
long-running node never grows without limit.

## Using it

### GUI — the **Traffic** tab

- Totals at the top: **▲ Sent** / **▼ Received** / active **Flows**.
- A live table of flows (protocol badge, local ↔ remote with the peer
  fingerprint, ↑/↓ bytes and packets, last-active), refreshed every ~2 s.
  Recently-active rows are highlighted.
- A **live** toggle freezes the view so you can inspect a snapshot.

### CLI

```sh
lattice flows
# ICMP   100.64.0.10        <-> 100.64.0.11        ↑5p/420B ↓5p/420B  1s ago
# TCP    100.64.0.10:43348  <-> 100.64.0.11:22     ↑8p/377B ↓7p/434B  5s ago
```

Generate some traffic over the overlay (e.g. `ping <peer-virtual-ip>` or
`ssh user@<peer-virtual-ip>`) and it appears immediately.

## How it works

`crates/engine/src/monitor.rs` defines a `TrafficMonitor` the engine holds. It
parses the IPv4 header (and TCP/UDP ports) and bumps per-flow counters under a
brief lock — no allocation per packet beyond the flow entry, no effect on the
data path's correctness. The daemon exposes a snapshot over IPC
(`Request::Flows`), which the CLI and GUI render.

## Privacy note

The monitor reads **packet metadata** (addresses, ports, sizes, counts) of
traffic that already passes through this node — it does **not** record payloads
and only sees the plaintext that this node is an endpoint or exit for. It is a
local diagnostic, not a logging or wiretap facility; nothing is persisted to disk.
