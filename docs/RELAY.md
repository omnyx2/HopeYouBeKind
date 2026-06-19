# Overlay peer relay (NAT fallback through a public node)

## Problem

Two mesh members behind NAT often can't reach each other **directly**: symmetric /
CGNAT mappings can't be hole-punched, and some networks block UDP to a given peer
outright. The v2 data plane (`meshrun::run`) only ever sent overlay frames **directly**
to the destination's endpoint (`crates/meshrun/src/lib.rs`, the `RouteDecision::Send`
arm) — if that path was dead, the frame was simply lost and the peer showed `idle`.

Internet traffic already escapes this via the **exit** (flow `internet → ToExit`), but
**overlay peer↔peer** traffic had no fallback. A public, mutually-reachable node (the
exit / DHT seed, e.g. an always-on cloud VM) was right there but unused for relaying.

## Design

When a member can't reach `to` directly, send `to`'s frame to a **relay member** that
*is* reachable and can forward it. The forwarding half already existed: a frame's header
carries `dst`, and any member can open the header and, if `dst != self`, forward the
frame on (`MeshDataPlane::recv → Inbound::Forward`, `dataplane.rs`). We only needed the
**sending** half + reachability tracking.

### Reachability: direct vs relayed

`Link` gains `last_direct_ms` alongside `last_seen_ms`:

- `last_seen_ms` — last frame from this peer by **any** path (liveness; unchanged).
- `last_direct_ms` — last frame that arrived **directly** from the peer (not via a relay).

On receive, a frame whose UDP source equals *another* member's endpoint is a **relayed
hop**: it keeps the sender alive (`last_seen_ms`) but must **not** overwrite the sender's
real endpoint with the relay's address (that would pin us to the relay forever and
pollute gossip). Only a **direct** frame updates `endpoint` + `last_direct_ms`.

A peer is **directly reachable** iff `now − last_direct_ms < DIRECT_OK_MS` (25 s — just
over the 20 s keepalive cadence, so one missed keepalive is tolerated).

### Route selection (per outbound frame)

```
pick_route(to):
  if to is directly reachable      → Direct(to.endpoint)
  else if a relay exists           → Relay(via relay.endpoint)   # frame's dst=to; relay forwards
  else if we have any endpoint     → Direct(to.endpoint)         # best-effort: lets NAT punching establish
  else                             → None                        # logged
```

A **relay** is a *directly-reachable* member (≠ `to`) with a **public** endpoint — the
**exit is preferred** (it's the designated always-on public node), else any directly-live
public peer. The relay frame is just `seal_to(to, …)` sent to the relay's address: the
relay opens the header, sees `dst = to ≠ self`, and forwards it unchanged.

### Keeping the path warm + NAT punching

- The 20 s gossip/keepalive still fires **directly** to every peer — this is what lets a
  direct path (re)establish via hole-punching, so a relayed peer **upgrades to direct**
  the moment NAT allows. Relay is a *fallback*, never sticky.
- Additionally, each gossip tick sends a keepalive to every **non-direct** peer **via a
  relay**, so liveness + the relay path stay up even with no app traffic, and the peer
  learns we're alive (so its replies relay back to us → bidirectional automatically).

### Logging & recovery

All of this is best-effort and self-healing; everything notable is logged (throttled, so
a dead peer can't spam the log):

- `relaying overlay → member N via relay member R (addr)` — first time we fall back.
- `direct path to member N recovered — relay no longer needed` — when it upgrades back.
- `no path to member N: not directly reachable and no relay available` — fully stuck.
- `relay: dropping frame for member N — no endpoint known` — a relay asked to forward to
  a peer it can't reach.

Recovery is automatic: direct is retried every keepalive; relay covers the gap; the
endpoint table self-corrects (relayed frames never pin the wrong address).

## Trust / safety

Relaying exposes nothing new: every member already shares the mesh key, so a relay could
always read any frame it forwards — that's the mesh's existing trust model. A relay only
forwards toward the frame's `dst`; a frame whose `dst` it can't reach is dropped (logged),
so there are no forwarding loops in normal topologies.

## Not covered (future)

- Relay selection is "any live public peer / the exit"; no latency-based or multi-hop
  selection. One public hop is enough for the star-with-public-seed topology.
- No relay-capacity limits / fairness; fine while the public node is the operator's own.
