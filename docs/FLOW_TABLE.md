# SDN flow table — OpenFlow-style programmable forwarding for the mesh

This refines the *"SDN routing & policy"* layer of
[SDN_DHT_ARCHITECTURE.md](SDN_DHT_ARCHITECTURE.md) §7 from a coarse group→group
ACL into a fine-grained, **OpenFlow-style flow table**: a single, ordered
*match → action* abstraction that unifies everything the data plane decides —
mesh routing, relay, exit/VPN, DNS, external isolation (kill-switch), and
per-application authorization.

The authority + distribution model is unchanged and inherited from the SDN doc:
**the admin (CA holder) is the controller; the signed `NetworkManifest` over the
DHT is the southbound channel; every node is its own switch.** This doc only
changes *what* the admin programs and *how a node enforces it*.

---

## 1. Why one flow table

Today the data plane's decisions are scattered and hard-coded:

| Decision | Today (ad-hoc) |
| --- | --- |
| mesh packet → which peer | `overlay.route(dst)` in `on_outbound` |
| internet packet → exit | `exit_node` Option + `set_exit_node` |
| who may exit | `exit_eligible` (manifest) |
| who relays | `relays` (manifest) |
| who may reach whom | `Policy` group→group (coarse) |
| DNS, isolation, app-auth | **nonexistent** |

Each is a separate field, IPC call, or toggle. A flow table makes them **one
data structure** the admin programs and every node evaluates identically:

```
priority  match { … }                                   → action
────────────────────────────────────────────────────────────────────
  100      scope=overlay, dst=100.64.0.0/10             → ToPeer(owner)   # mesh is open
   90      proto=udp, dport=53                          → ToExit(dns_node) # DNS to our resolver
   80      scope=internet, src_uid∈AUTHORIZED           → ToExit(oracle)   # only authorized apps VPN out
   10      scope=internet                               → Drop             # everyone else: no internet
    0      *                                            → Drop             # default-deny = kill-switch
```

Add a capability ⇒ add a rule. Nothing else changes.

---

## 2. OpenFlow → Lattice mapping

| OpenFlow | Lattice |
| --- | --- |
| Switch (match/action pipeline) | each node's **engine** (`crates/engine` `on_outbound`/`on_inbound`) |
| Flow table | an ordered `Vec<FlowRule>` held by the engine |
| Controller | the **admin** (holds the network CA) — the only writer |
| Southbound (controller→switch) | the **admin-signed `NetworkManifest`**, distributed over the **DHT** (no OF-channel, no TCP to a controller) |
| PacketIn (miss → controller) | **omitted in v1** (proactive only — see §6); optional later |
| FlowMod (install/modify) | admin edits the manifest, bumps `version`, re-signs, republishes |
| Match fields | IP 5-tuple + mesh scope + (for app-auth) source uid/program |
| Actions | `ToPeer` / `ToExit` / `Local` / `Drop` (and later `ToController`, `Mark`) |

The key divergence from real OpenFlow: there is **no central switch fabric and no
live controller channel**. The controller publishes a *signed program* that nodes
fetch from a dumb DHT and enforce locally. Authority is the **signature**, not a
connection. (This is the whole thesis of the SDN×DHT doc.)

---

## 3. Data model

```rust
/// One match→action rule. Evaluated highest-priority-first; first match wins.
struct FlowRule {
    priority: u16,
    match_: Match,
    action: Action,
}

/// What a packet must look like to hit this rule. All present fields must match
/// (AND); absent fields are wildcards.
struct Match {
    scope:    Option<Scope>,      // Overlay (dst ∈ vip_subnet) | Internet (else)
    dst:      Option<IpCidr>,     // destination prefix
    src:      Option<IpCidr>,     // source prefix (overlay src, usually self's VIP)
    proto:    Option<u8>,         // 6=TCP, 17=UDP, 1=ICMP
    dport:    Option<u16>,        // destination port
    src_uid:  Option<UidSet>,     // host-side: which local app/uid emitted it (§7)
    group:    Option<GroupId>,    // peer/membership group (from MemberDirectory)
}

enum Scope { Overlay, Internet }

enum Action {
    ToPeer(NodeId),   // tunnel to this mesh peer (normal overlay routing)
    ToExit(NodeId),   // forward to this exit node (VPN / DNS / internet)
    Local,            // deliver to this host's stack (we are the destination/exit)
    Drop,             // discard — isolation / kill-switch / deny
    // future: ToController (reactive), Mark(fwmark), Mirror(node) for the DPI tap
}
```

- **Ordering:** rules are sorted by `priority` desc; the **first match wins**
  (OpenFlow semantics). A terminal `priority 0, match *, Drop` makes the table
  **default-deny** — the foundation of isolation and the kill-switch.
- **Two tables, one model:** `on_outbound` (host→tun) and `on_inbound`
  (tun→host/forward) both evaluate the table; `Scope`/direction distinguish them.
  An exit node's "should I forward this to the internet?" becomes a `Local`/`Drop`
  decision on inbound, replacing today's `allow_exit` bool.

---

## 4. Where it runs (the pipeline)

`crates/engine` already parses `dst` and branches overlay-vs-internet in
`on_outbound` — that branch **becomes the flow lookup**:

```
on_outbound(packet):
    fields = parse(packet)                  // dst, src, proto, dport (already done)
    fields.src_uid = lookup_owner(packet)   // §7, host-side, best-effort
    rule = flow_table.first_match(fields)   // ordered, first-match-wins
    match rule.action:
        ToPeer(id) | ToExit(id) -> endpoint = endpoint_for(id); seal; send
        Local                   -> tun.write(packet)        // we're the exit/dest
        Drop                    -> return                   // isolated / denied
```

So the engine change is contained: replace the hard-coded `if overlay {…} else
{exit_node}` with `flow_table.first_match(...)`. The existing relay/exit
*mechanics* (DERP relay, NAT) are unchanged — the table only **chooses** them.

The flow table is loaded from the manifest by the daemon's manifest consumer
(same loop that today reads `relays`), and hot-reloaded on `version` bump.

---

## 5. Expressing every capability as rules

| Capability (what the user asked for) | Rule(s) |
| --- | --- |
| **Mesh is open internally** | `prio 100: scope=Overlay → ToPeer(owner)` |
| **Relay for unreachable pairs** | `ToPeer` resolves to a relay endpoint when no direct path (control-plane decision, as today) — no new rule needed |
| **Exit / full-tunnel VPN** | `prio 50: scope=Internet → ToExit(oracle)` |
| **DNS via our own resolver** (no Google/Cloudflare) | `prio 90: proto=udp, dport=53 → ToExit(dns_node)` where `dns_node` runs a resolver on its overlay IP (§8) |
| **Strict external isolation + kill-switch** | terminal `prio 0: * → Drop`. Nothing leaks; if the exit/tunnel is down, traffic is *dropped*, never sent out the local NIC |
| **Only authorized apps use the mesh** (minisync-style) | `prio 80: scope=Internet, src_uid∈AUTHORIZED → ToExit(...)`; unauthorized apps fall through to `Drop` |
| **Per-group ACL** (the old Policy) | `match.group` + `ToPeer`/`Drop` — subsumes the coarse group→group rules |

This is the payoff: the three layers from the discussion (exit-hosted DNS,
external isolation, app authorization) are **not three subsystems — they are three
rows in one signed table.**

---

## 6. Proactive vs reactive (a deliberate choice)

Real OpenFlow is often *reactive*: a table miss generates a **PacketIn** to the
controller, which installs a flow. That needs a **live controller connection** —
exactly what a serverless mesh refuses to require (the admin laptop may be
offline).

**v1 is fully proactive:** the admin pre-computes the whole table, signs it, and
publishes it; a miss falls through to the terminal `Drop` (fail-closed). No
controller needed at packet time.

A *hybrid* is possible later: a node could `ToController` (tunnel the first packet
of an unknown flow to the admin **when reachable**) for dynamic policy, falling
back to `Drop` when the admin is offline. Out of scope for v1, but the `Action`
enum leaves room.

---

## 7. App identity — the hard, interesting part

`src_uid` (which local program emitted a packet) is what makes "only minisync may
use the mesh" possible, and it's the least trivial field because the packet on the
TUN no longer carries the originating PID/UID.

Options, in increasing order of strength:

1. **uid/gid match (Linux):** correlate the packet's source port with the owning
   socket (`/proc/net/{tcp,udp}` → inode → fd → pid → uid), or push enforcement
   into `iptables -m owner --uid-owner` / a cgroup, marking authorized traffic
   before it reaches the TUN. Cheapest; coarse (per-user, not per-binary).
2. **cgroup / per-app network namespace:** run authorized apps in a cgroup (or a
   netns wired only to the TUN); the kernel tags their traffic. Robust; needs
   launching apps under the policy.
3. **Local broker socket:** authorized apps talk to the daemon over the existing
   IPC (which is *already* gated by `--admin-allow`/`--health-allow` process-name
   checks) and get mesh access via that channel, not the raw TUN. Strongest
   binding (ties to a vetted program), but apps must be mesh-aware.

v1 can ship option 1 (uid sets in the directory/manifest) and treat 2–3 as
research extensions. This field is where the project's "only my authorized
programs receive data from this network" requirement actually lives.

> macOS/Windows have analogous hooks (pf `user`, WFP `ALE` filters); cross-platform
> `src_uid` is a documented gap, like the IPv6 gap in EXIT_NODE.md.

---

## 8. The exit-hosted resolver (DNS without a public nameserver)

Tied to the DNS rule (§5). The exit node is a *forwarder*, not a resolver — a DNS
query is just a UDP packet to *some* `:53`. To keep DNS inside the mesh:

- Run a recursive resolver (unbound/dnsmasq/systemd-resolved) on the **DNS node**
  (e.g. the Oracle exit), bound to its **overlay IP** (`100.x:53`).
- Manifest names it (`dns_node`); clients set their resolver to that overlay IP.
- The flow rule `udp/53 → ToExit(dns_node)` sends queries through the tunnel to
  it. **DNS never leaves the user's infrastructure**, and full-tunnel no longer
  breaks name resolution (the failure we hit: campus/private resolvers
  `10.0.0.53` / `203.237.32.x` are unreachable from a public exit).
- The daemon, when a DNS rule is active, points the host resolver at the overlay
  DNS IP and restores it on revert (the route_through ↔ restore_routes pattern,
  extended to DNS).

---

## 9. Manifest wire-format extension

Add to the admin-signed `NetworkManifest` (membership crate), versioned + CA-signed:

```
NetworkManifest {
  …existing… (network_id, version, vip_subnet, crypto_policy, relays,
              exit_eligible, issued_at, sig)
  dns_node:  Option<node_id>,     // who runs the mesh resolver
  flows:     Vec<FlowRule>,       // the ordered flow table (§3)
}
```

- Backward-compatible: an empty `flows` ⇒ the engine uses the legacy
  overlay-then-exit default (no regression).
- Signed as one unit; readers reject lower `version`/unsigned (existing rule).
- `groups` referenced by `Match.group` come from the `MemberDirectory` (§4 of the
  SDN doc already has `groups: [..]` per member).

---

## 10. Differences from OpenFlow (summary)

1. **No central fabric / live controller** — signed program over a dumb DHT.
2. **Proactive, fail-closed** — miss ⇒ default-deny `Drop`, not PacketIn.
3. **Authority = CA signature**, not an OF-channel; tamper-proof by construction.
4. **Per-node, identical** — every node holds the *same* signed table and enforces
   locally; there is no master switch.
5. **Match includes membership + app identity**, not just L2/L3 headers.

---

## 11. Phased plan

Each phase builds **and runs** on Mac + Ubuntu + Windows ([[verify-all-three-platforms]]).

- **Phase 1 — flow-table skeleton.** `FlowRule`/`Match`/`Action` types; add
  `flows` to the manifest (signed); engine `on_outbound` evaluates the table.
  Re-express *today's* behavior as rules (overlay→peer, internet→exit) — zero
  regression. Admin can publish a table; nodes hot-reload on version bump.
- **Phase 2 — isolation + kill-switch.** Terminal default-deny `Drop`; full-tunnel
  installs a fail-closed firewall so nothing leaks if the tunnel drops. Fixes the
  dual-home default-route leak found in EXIT_NODE.md.
- **Phase 3 — DNS rule + exit resolver.** Stand up the resolver on the DNS node's
  overlay IP; `udp/53 → ToExit(dns_node)`; daemon repoints/restores host DNS.
- **Phase 4 — app authorization.** `src_uid` matching (option 1, §7); authorized
  uid sets in the manifest; unauthorized traffic hits `Drop`.
- **Phase 5 — admin console.** A flow-table editor in `gui-admin` (an OpenFlow
  controller UI): rows of match→action, reorder by priority, sign + publish; live
  per-node hit counters from the traffic monitor.

---

## 12. Open questions

- **Rule granularity vs table size:** how many flows before per-packet evaluation
  cost matters? (Cache the decision per 5-tuple, like a real switch's flow cache.)
- **App identity portability:** uid (Linux) vs pf-user (macOS) vs WFP (Windows) —
  one abstraction or per-OS? (§7)
- **Reactive escalation:** ever add `ToController`/PacketIn for dynamic policy, or
  stay strictly proactive?
- **Per-member vs global table:** one network-wide table (simplest) vs
  per-group/per-node sub-tables the admin composes? v1 = one global table, matched
  with `group`/`src` fields.
- **DNS node HA:** single resolver node = a SPOF for name resolution under
  full-tunnel; secondary `dns_node`?

---

This is the natural maturation of [SDN_DHT_ARCHITECTURE.md](SDN_DHT_ARCHITECTURE.md):
that doc gave the *authority + distribution* model; this gives the *programmable
forwarding* model they carry. Together they are the full SDN×DHT control plane.
