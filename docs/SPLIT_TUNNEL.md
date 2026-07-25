# Domain split-tunnel

Use the host's normal internet by default, but send **specific domains** (e.g. `*.pornhub.com`)
out through a chosen mesh **exit** — without routing everything through the mesh. Local to this
node (rules are never gossiped). Built in `crates/meshd/src/dns_split.rs` + `exit.rs`
(route injection) + the `SplitAdd/Del/List/On/Off` IPC; driven by `lattice split`.

**Split-tunnel selects its mesh (since v0.7.11).** Turning split on marks that mesh as the current
selection — shown as a `split` selection (NOT a full tunnel: general traffic stays direct, only
matched domains follow the mesh exit). Switching to the **Default network** (`SetCurrent(None)` /
the GUI "use default network" button) turns split **off** (restores the host DNS + removes the
injected `/32`s). This closes the old trap where split kept hijacking DNS and routing domains
through a mesh even after you thought you were on plain "Default". Internally a `full_tunnel` flag
separates "selected for a full tunnel" from "selected to host split routing", so the network-change
re-route and shutdown restore only fire for a real full tunnel.

## Why it needs DNS

A packet on the wire carries a destination **IP**, not a domain name — the name is gone after
resolution. So "route `pornhub.com` via the exit" can't be done by matching packets alone; we
must first learn which IPs belong to that domain. We do it by proxying DNS:

```
app: "www.pornhub.com?"                     (host resolver → 127.0.0.1:53, our proxy)
  meshd proxy → forwards to the REAL upstream resolver → 66.254.114.41
  name matches a rule (*.pornhub.com)?
     yes → inject 66.254.114.41/32 → mesh tun (utun6), record it       [exit.rs::route_host_via_iface]
     return the answer to the app unchanged
app: connects to 66.254.114.41 → enters utun6 → data plane → mesh exit → egress at the exit
non-matching name → no route injected → app uses the real default route (normal internet)
```

Because only the matched domain's `/32`s point at the tun, and **the default route is never
touched**, everything else keeps using the host's normal internet. Once a matched IP is in the
tun, the existing data plane routes it: `decide()` classifies it Internet-bound and sends it to
the mesh's exit (seeded from the persisted exit at bringup — full-tunnel does **not** need to be
on). The exit NATs it out its own network. Works for HTTPS and any protocol (it's IP-level after
DNS) and adapts to IP rotation (each new answer re-injects).

## Matching

`domain_matches` is **label-bounded suffix match**: a rule for `pornhub.com` matches `pornhub.com`
and every subdomain (`www.`, `ads.cdn.`, …), case-insensitively, but NOT `notpornhub.com` or
`pornhub.com.evil.com`. So one rule = the whole domain tree (the wildcard is implicit).

Manual IP is the secondary path: a static flow-table rule (`lattice flows`) can route a raw
CIDR via the exit for destinations you don't resolve by name.

## Usage

```bash
lattice split add pornhub.com 1     # *.pornhub.com egresses via mesh 1's exit
lattice split list                  # rules + on/off state
lattice split on 1                  # start: point host DNS at the proxy, activate mesh 1's rules
lattice split off                   # stop: remove injected /32s, restore DNS
lattice split rm pornhub.com        # drop a rule
```

Rules persist to `split.json` (0600) in the state dir — **this computer only**, reloaded on
start, never gossiped. Turning split on/off is *not* persisted; re-issue `split on` after a
restart (or when you add a rule while it's already on — the proxy snapshots rules at `on` time).

## What `on` / `off` actually change (🔴 host state)

- **on** — `exit::set_dns([127.0.0.1])` (backs up the prior resolver first, so `detect_upstream`
  can still forward normal names to the REAL resolver) + spawns the DNS proxy on `127.0.0.1:53`.
  No route/pf/default-route change until a matched name is resolved.
- **off** — aborts the proxy, `exit::unroute_host` for every injected `/32`, `exit::restore_dns`.

Requires root (bind :53, edit routes/DNS) — meshd already runs elevated. If the mesh's data
plane isn't up (no tun), `split on` safely bails **before** binding :53 or touching DNS.

## Per-domain exit (the rule carries its own exit)

Each rule specifies WHICH member it exits through, independent of the mesh-wide exit: `lattice
split add pornhub.com <mesh> <exit-member>`. So you never set (or misconfigure) the mesh exit —
normal traffic keeps using your own network, and only the matched domain goes to the rule's exit.
Mechanism: the DNS proxy records `matched-IP → rule.exit` in a shared `SharedSplitRoutes` map; the
data-plane run loop checks it BEFORE the flow table and sends that IP to `rule.exit` (bypassing
the mesh exit). Local, never gossiped. The exit is guarded: it can't be this node itself or an
unknown member (the "set exit to self → can't connect" trap). `exit = 0` falls back to the mesh's
configured exit (back-compat for pre-per-domain `split.json`).

## Limits / not-yet

- **Global DNS hijack while on (single point of failure).** Turning split on points the WHOLE host
  resolver at meshd's `127.0.0.1:53` proxy (no secondary), so ALL DNS — not just the matched
  domains — flows through meshd. The proxy forwards non-matched names to the real upstream, so it's
  transparent in normal operation. Mitigations since v0.7.11: split is no longer a hidden global
  switch (it selects its mesh; the **Default network turns it off**), a clean `shutdown` restores
  the resolver, and `lattice ls`/`status` show a `split-tunnel: ON` line. Still open: a hard CRASH
  (not a clean shutdown) while split is on can leave the resolver pointed at the dead proxy until
  the next start; and even in normal use one split rule means meshd owns your resolver.
- **One active mesh at a time (mutually exclusive).** Rules are per-mesh (each `SplitRule` carries
  its `mesh` + exit member), but activation is a single global session — `state.split` is one
  `Option<SplitActive>` and the host resolver can only point at one `127.0.0.1:53` proxy.
  `split on <mesh>` first tears down any prior session (`split_disable` — removes injected `/32`s,
  restores DNS) and then injects **only that mesh's** rules. So enabling split on a second mesh
  doesn't conflict/corrupt — it cleanly **replaces** the first (last-wins); `split list` shows the
  single active mesh. You cannot split two meshes' domains simultaneously (needed because the same
  domain's `/32` could only point into one mesh's tun, and there's one OS resolver to hijack).
- **A-records / IPv4 only.** The overlay is IPv4 (`100.64.0.0/10`) and only A-records get a `/32`
  injected; AAAA (IPv6) isn't. **Consequence — IPv6 leak on dual-stack networks:** if the client
  has working IPv6 and the matched domain has an AAAA record, the OS prefers IPv6 and the request
  egresses **directly over IPv6, bypassing the mesh exit entirely** (verified on an IPv6 hotspot —
  a `*.ifconfig.me` split rule was skipped and the client's own IPv6 came back). Workaround until
  IPv6 support lands ([`IPV6_PLAN.md`](IPV6_PLAN.md)): force IPv4 (`curl -4`), or use the split on
  an IPv4-only path. The same caveat applies to full-tunnel — IPv6 traffic is not routed through
  the exit and is not kill-switched.
- **DNS is resolved locally** (via the captured upstream), not through the exit. Fine when the
  block is at the connection level (the campus case); a site behind DNS poisoning would need the
  query itself tunnelled — not done.
- **No SNI** — HTTPS domains that share an IP can't be split apart without parsing the TLS
  ClientHello. Out of scope for v1.

## Files

- `crates/meshd/src/dns_split.rs` — `SplitRule`, `domain_matches`, `parse_a_records` (DNS parser,
  unit-tested), `detect_upstream`, `run_proxy`.
- `crates/meshd/src/exit.rs` — `route_host_via_iface` / `unroute_host` (3 OS, `/32`, never touches
  the default route; RISK 🔴).
- `crates/meshd/src/main.rs` — IPC handlers, `split.json` persist, `split_enable` / `split_disable`.
- `crates/mesh/src/ipc.rs` — `SplitAdd/Del/List/On/Off`, `Response::Split`, `SplitView`.
- `scripts/lattice` — `split` subcommand.
