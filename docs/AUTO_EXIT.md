# Auto-Exit — Distributed Per-Destination Censorship Bypass

## The idea
Today an "exit" is ONE fixed node (e.g. Oracle/Tokyo) you route through. But
different networks censor different things (campus blocks X, dorm blocks Y, Japan
blocks neither). So instead of a single fixed exit, make the **mesh a distributed
pool of exits** and pick, **per destination**, the *best node that can actually
reach it*.

> Each node uses its own local network normally. When the local network **blocks a
> destination**, the mesh detects it, **every node tries that destination from its
> own network**, and the blocked node routes *that destination only* through the
> **nearest node that can reach it**.

This generalizes the exit concept: any mesh node is a potential exit; the mesh
chooses the optimal one **per-destination, dynamically**.

## Two split-tunnel modes (full tunnel is separate + already works)
1. **Whitelist (manual)** — the user pins "destination D → exit via node N" (or
   "always direct"). Explicit, user-controlled. The xvideos/pornhub bypass we did
   by hand is this, automated into the UI.
2. **Auto (distributed)** — the loop below. No list; self-healing; censorship-aware.

Both modes write the SAME structure — the **signed flow table** (`docs/FLOW_TABLE.md`).
Auto auto-populates rules; whitelist adds them by hand. One policy store.

## The Auto loop
```
1. DETECT   a direct connection fails with a censorship signature
            (TLS ClientHello → RST = SNI block; the exact thing we observed on
             xvideos/pornhub: conn OK, tls=0). Also: DNS poisoning, RST-on-SYN.
2. QUERY    ask the mesh "who can reach destination X?" — each node tries X from
            its OWN network and reports {reachable?, RTT-to-X}.
3. SELECT   among nodes that reach X, pick the *nearest* (see open question #2).
4. ROUTE    send X's traffic (only X) via that node as a per-destination exit.
5. SHARE    cache "X reachable via N (rtt)" and gossip it across the mesh so other
            blocked nodes reuse it; re-probe periodically (networks change).
```

## What already exists vs what's new
Reuses (mostly built):
- **QUERY/SHARE** ← the **connectivity records** we built for auto-relay election,
  extended from "which mesh peers I reach" to "which external destinations/networks
  I reach."
- **ROUTE** ← the **exit-node** data plane — but chosen per-destination, not fixed.
- **POLICY** ← the **flow table** (`on_outbound` already evaluates match→action);
  auto adds rules, whitelist adds rules — same table.
- **SELECT** ← the **auto-relay election** pattern (pick the best reachable node).

New pieces:
1. **Censorship detection** — the daemon must see direct traffic. ⇒ route ALL
   internet via the TUN, but the flow table's DEFAULT action is a NEW
   **`Direct`/`LocalEgress`** (send out the node's real local network, NOT the
   mesh). Only flagged destinations get `ToExit(node)`. So the flow table becomes
   the routing brain for *all* traffic; `Direct` is the fast path, exits the
   exception. Detection watches the `Direct` path for the RST/block signature.
2. **External-reachability probe + map** — a node can test "do I reach X?" and the
   mesh aggregates a {destination → {node: rtt}} map (the connectivity record,
   extended). Bounded/cached so it isn't a probe storm.
3. **Nearest-capable selection** — rank reachable nodes for X and route via the best.

## Open design questions (decide before building)
1. **`Direct` action + all-traffic-via-TUN** — confirmed direction? It makes the
   flow table govern every packet (direct fast-path + exit exceptions). Big but it's
   the only way the daemon can *detect* a block on otherwise-direct traffic.
2. **"Nearest" metric** — RTT from the exit node to X (best destination-side path)?
   or total `me→exit (mesh) + exit→X (internet)`? Total latency is usually what the
   user feels, but destination-side RTT is simpler to gossip. Probably total, with
   destination-RTT as the gossiped component + known mesh-leg cost added locally.
3. **Probe timing** — lazy (probe only when a block is detected, lowest cost, adds
   first-hit latency) vs eager (background reachability map, instant failover, more
   traffic). Likely lazy-with-cache + periodic refresh.
4. **Detection robustness** — distinguish *censorship* (RST-after-ClientHello, DNS
   poison) from a *genuinely dead* site (timeout, real 4xx/5xx) to avoid needlessly
   tunnelling. Don't auto-route a site that's just down.
5. **Trust** — a malicious node could claim/deny reachability. For now mesh members
   are trusted; later, attest probes.

## One-line summary
**The mesh is a per-destination, latency-optimized, censorship-aware exit pool; the
signed flow table is the policy store; Auto fills it by detecting blocks and electing
the nearest capable node, Whitelist fills it by hand.** Builds directly on the exit
node + connectivity records + flow table + auto-relay election already shipped.

## Build order (after the open questions are settled)
1. Flow `Direct` action + route all internet via TUN (flow table = full routing brain).
2. Censorship detector on the `Direct` path (RST-after-ClientHello first).
3. External-reachability probe + extend connectivity records to destinations.
4. Nearest-capable selection → auto-add `ToExit(node)` flow rule + per-dest route.
5. Gossip/cache the reachability map; periodic re-probe; auto-cleanup of routes
   (also fixes the stale-exit-route bug from `docs`/[[lattice-exit-node]]).
6. GUI: Full / Off / Whitelist now; Auto toggle once the above lands.
