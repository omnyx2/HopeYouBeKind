# Domain split-tunnel

Use the host's normal internet by default, but send **specific domains** (e.g. `*.pornhub.com`)
out through a chosen mesh **exit** — without routing everything through the mesh. Local to this
node (rules are never gossiped). Built in `crates/meshd/src/dns_split.rs` + `exit.rs`
(route injection) + the `SplitAdd/Del/List/On/Off` IPC; driven by `lattice split`.

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

## Limits / not-yet

- **One exit per mesh.** All split rules for a mesh use that mesh's single configured exit
  (`lattice exit`). Per-domain *different* exits need `FlowAction::ToExit(Some(NodeId))` finished
  (roster pubkey→member-id resolution; `dataplane.rs` "phase 2"). See docs/FLOW_TABLE.md.
- **A-records / IPv4 only.** AAAA (IPv6) isn't injected yet.
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
