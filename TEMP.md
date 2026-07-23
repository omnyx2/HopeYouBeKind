# TEMP.md — live working memory

Scratchpad for the task in progress. Charter in `CLAUDE.md` → "Working memory". Only OPEN items
live here; move done items to `COMPLETE.md`; log errors to `docs/ERRORS.md`. Read
`docs/ERRORS.md` before starting.

---

## Current task: domain-based split-tunnel + auto-connect persistence

Two features (user, 2026-07-23):
- **F1 domain split-tunnel** — default = normal internet; specific domains (e.g.
  `www.pornhub.com`) egress via a CHOSEN exit member. Domain-primary + IP/CIDR secondary.
- **F2 auto-connect + persist** — auto-discover which LIVE members are reachable, connect
  automatically, and persist the resulting connection path (key→value) to disk for fast reconnect.

### What exists (explore agent, reuse these)
- Flow table BUILT: `crates/proto/src/flow.rs` FlowRule{priority, match_{scope,dst_cidr,proto,
  dport}, action{ToOverlayOwner|ToExit(Option<NodeId>)|ToPeer|Local|Drop}}; `decide()` in
  dataplane.rs; gossiped via CTRL_FLOWS; CLI `lattice flows`; GUI routing-rules card. **IP-only
  match, no domain field.**
- `ToExit(Some(NodeId))` / `ToPeer` exist in the enum but `decide()` DROPS them ("phase 2":
  NodeId(pubkey)→MemberId via roster not wired). Must finish for per-domain exit override.
- `set_dns` in exit.rs (points host resolver at IPs; used by full-tunnel). No DNS snoop/resolver.
- F2 infra mostly EXISTS: DHT re-discover + endpoint gossip + relay→direct promotion + `Link`
  {endpoint,last_seen}; persisted mesh endpoints re-seeded on load. F2 ≈ surface + persist the
  chosen path, not build discovery from scratch.

### Chosen architecture (F1) — local DNS resolver + dynamic route/flow injection
meshd runs a small DNS proxy on 127.0.0.1:53; host resolver pointed at it (reuse set_dns, in a
NEW "domain-split" mode that does NOT need full-tunnel). Per query: forward upstream, get A/AAAA.
If qname matches a split rule `{domain-pattern → exit member}`: inject `<ip>/32 → mesh tun` host
route + a flow rule `dst=<ip>/32 → ToExit(member)`, refresh on TTL; return answer unchanged.
Non-matching domains: passthrough, no injection → app uses normal internet. Works for HTTPS/any
(IP-level after DNS), adapts to IP rotation. Manual IP/CIDR = static flow+route (the "IP 보조").

### Requirements — status
- ✅ **DNS parser + rule types** (dns_split.rs, 4 unit tests) — commit e12da6f
- ✅ **exit.rs route_host_via_iface/unroute_host** (3 OS, /32 no-default-touch) — d425584
- ✅ **DNS proxy loop + upstream detect** (run_proxy/detect_upstream) — d1a96cc
- ✅ **meshd wiring** (IPC SplitAdd/Del/List/On/Off, split.json persist, split_enable/disable 🔴) — 4d5663f
- ✅ **lattice split CLI** + OFFLINE verified (add/list/rm/persist; on-without-tun safely bails) — 105789f
- Key correctness confirmed: mesh exit_sel is seeded from the persisted exit at bringup
  (main.rs:684) + SetExit (2625) — so split works WITHOUT full-tunnel: a /32-routed pornhub
  packet → decide() exit=Oracle → sealed → Japan NAT. Same path as full-tunnel, one IP.
- ✅ **P5 LIVE VERIFIED (2026-07-23)** — swapped running meshd → build 40eb106; `split add
  pornhub.com 1` + `split on 1`: www.pornhub.com→66.254.114.41 routed to utun6, HTTP 200, Oracle
  tun0 RX +8601 (traffic transited Oracle); google/ifconfig stayed en0/campus with Oracle RX +0;
  `split off` restored DNS (127.0.0.1→10.64.0.3) + removed the /32 cleanly. F1 domain
  split-tunnel WORKS end to end.

### Fleet: ALL on v0.7.5 build 975d26c (done 2026-07-23)
Mac + Oracle + lablinux fresh-installed (GUI+daemon), verified, LIVE, oracle+lablinux direct.
Windows offline (skipped) — reinstall when it's back on a reachable network. SSH: Oracle
`ssh -i ssh-key-2026-06-13.key ubuntu@138.2.14.219`; lablinux `ssh hyunseok@172.28.7.32` (sudo pw
1234, piped `echo 1234|sudo -S`, meshd relaunch `/tmp/lab-start.sh`). Use `command grep` for
remote output (shell has a poisoned grep wrapper).

### Open / deferred (both features shipped; these are polish)
- F1: per-domain DIFFERENT exits (finish ToExit(Some(NodeId))); AAAA/IPv6; SNI.
- F2: persist path-history (so `conns` shows last-good path after a restart, before re-verify);
  GUI `conns` card; live relay-path screenshot.
- Both features' running build = bc0aee3 (swapped into /Applications app). Live VPN fine.

### Deferred / not doing now
SNI extraction (HTTPS same-IP disambiguation), auto-censorship-detection (AUTO_EXIT.md),
app-uid matching. Note them if they block.

---

## Prior task: code documentation pass + process hardening

Goal: make every data-plane/exit function self-explanatory (contract + `///` + edit-risk) so
regressions are easy to localize, and set up the working-memory workflow.

### Requirements (open)

1. **Windows re-join incomplete** — found the box on the home LAN (`192.168.0.6`, host
   `hyunseok`), SSH works as `sshuser`/1234 (expect script in scratchpad; NOT omnyx). meshd.exe
   + Lattice.exe were RUNNING but mesh 1 still showed win #5 idle (stale campus endpoint
   10.32.86.243). Left off at: reading the Windows meshd log failed on PowerShell quoting over
   ssh — use a batch/cmd one-liner or `type %TEMP%\lattice-meshd.log` instead. Next: confirm
   which build it runs (`version v… build <sha>`), and whether it reaches Oracle; then check
   `lattice info 1` shows win live. NOTE: both boxes may have moved networks since (2026-06-26).

### Docs pass status
exit.rs ✅ · meshrun/lib.rs ✅ · meshd/main.rs ✅ — the data-plane/exit/IPC trio is documented
(contract + `///` + edit-risk). Remaining crates (mesh/*, tun, net) not yet given the risk-tag
treatment; do on demand.

### Notes / context to not lose (refreshed 2026-07-22)
- **Mac: CLEAN 0.7.4 install running** — official release dmg installed to /Applications
  (meshd `v0.7.4 build c00836b`), all older installs/bundles/dmgs deleted. Full-tunnel via
  Oracle verified working + stable; state dir preserved (auto-rejoined both meshes).
- Oracle: **updated to `v0.7.4 build 51deceb`** (2026-07-22), systemd active, healthy pinned
  exit; full-tunnel from the Mac re-verified against it (egress OK, no kill-switch). SSH:
  `ssh -i ssh-key-2026-06-13.key -o IdentitiesOnly=yes ubuntu@<oracle>` (key in repo root, gitignored).
- **lablinux (#4) RE-JOINED 2026-07-22**: `v0.7.4 build c00836b` (release meshd-Linux-X64 binary
  scp'd over the old 6/21 install at /usr/lib/lattice/resources/meshd; .bak-0.7.0 kept). LIVE,
  overlay ping 3/3 (~4.9ms), direct path to Mac after starting via Oracle relay. SSH:
  `ssh hyunseok@172.28.7.32` (key auth); sudo pw 1234; launched via `/tmp/lab-start.sh`
  (setsid+disown — plain nohup died on session close). Its public addr (Oracle-reflected) =
  210.107.188.8; LAN addr 172.28.7.32. NOTE: launched manually, NOT persistent across reboot
  (no systemd unit) — GUI app relaunch or a unit would make it durable.
- **v0.7.4 released**: tag + GitHub Release with all installers (run 28096210159 SUCCESS —
  v0.7.3's release run had failed; nothing to fix in release.yml after all).
