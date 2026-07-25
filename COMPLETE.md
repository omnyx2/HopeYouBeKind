# COMPLETE.md — finished work log

Requirements moved here from `TEMP.md` as they complete (newest first). Each: what + date +
commit. The durable record; `TEMP.md` only holds open items.

---

## Mac clean-slate reinstall + macOS-fix verification (2026-07-22)

- **Wiped every stale install** (/Applications 0.7.3 app, 0.7.3 dev bundle, ancient Downloads
  dmgs) and **installed the official `Lattice_0.7.4_aarch64.dmg`** to /Applications. State dir
  kept → both meshes auto-rejoined on launch.
- **VERIFIED the two macOS full-tunnel fixes on a fresh, non-churned daemon**: meshd logs
  `v0.7.4 build c00836b`; pf conf is nat-only (no route-to on a client — fix 5cfa960); exit /32
  pin → en0 (no loop — fix 19465bb); **full-tunnel egress = Oracle on try 1** and stays up past
  the kill-switch window. Closes the "clean verification" TEMP item. — config/deploy, no commit

## Per-mesh `exitable` (opt-in serving as exit) — BUILT + macOS live-verified (2026-07-25)

User security policy: serving as an internet exit for a mesh's members = per-mesh opt-in, default
OFF, decoupled from my own egress. A mesh intruder can't proxy through a node unless it made that
mesh exitable. Expresses the "all meshes / selected only / never" policy as per-mesh flags.
- exit.rs enable_nat(subnet)/disable_nat(subnet): NAT only the mesh's overlay subnet
  (100.80.<id>.0/24), not all 100.64/10 — serving one mesh never proxies another. 3 OS, idempotent,
  cleans legacy all-overlay rule. bringup serves only if exitable||pinned (Oracle stays working).
- MeshState/PersistedMesh exitable (local, persisted, serde-default false); IPC SetExitable +
  ApplyExitable; MeshSummary/MeshDetail.exitable; CLI `lattice exitable <mesh> [on|off]` + info;
  GUI toggle in User>Meshes row. Extension per-mesh scoping (policy #3) already existed.
- Commits 42eadac (core+CLI) + 1ef6032 (GUI+docs+EXIT_SHARING.md). 86 tests, fmt/clippy clean,
  offline on/off/persist verified.
- **LIVE (Mac, build 1ef6032): exitable OFF = no active NAT (stale pf file was old build's, not
  loaded); exitable ON = pf `nat on en0 from 100.80.1.0/24` (mesh-1 subnet ONLY, not 100.64/10);
  OFF removes it.** Per-mesh scoping proven. TODO: full cross-node (lablinux→Mac only when Mac
  exitable) + Oracle/lablinux deploy + fleet reinstall.
- Note: Mac GUI showed a white screen after the meshd swap — webview glitch (frontend unchanged);
  ⌘Q + relaunch fixes it. meshd was fine (CLI worked throughout).

## Current-computer-as-exit — cross-node LIVE-verified on lablinux (2026-07-23)

Verified per-domain split-tunnel where the exit is ANOTHER member (incl. this computer acting as
an exit for someone else): updated lablinux to a07da4d (built on Oracle, scp'd; **gave lablinux a
systemd unit** since setsid launches over ssh didn't persist). On lablinux, rule `ifconfig.me →
member #7 (Mac)`, split on → `curl ifconfig.me` returned **203.247.167.58 (the Mac's egress)**,
not lablinux's own 210.107.188.8 — so lablinux's traffic exited through the Mac (path: lablinux →
Oracle relay → Mac NAT → internet), even though Mac↔lablinux can't reach directly (campus
isolation, relayed). off reverted to 210.107.188.8. Mac forwards+NATs as a client (forwarding=1,
pf nat 100.64/10) so it works as an exit without being a pinned exit node.

## Per-domain split-tunnel exit — BUILT + LIVE-verified (2026-07-23)

The user's model: split-tunnel keeps normal traffic on your OWN network by default; only registered
domains use a designated exit — and the RULE should carry the exit, not a mesh-wide setting (the
recurring "set exit to self #7 → can't connect" bug came from the mesh-exit coupling).
- SplitRule gains `exit: MemberId`; a shared `SharedSplitRoutes` map (matched IP → rule exit) is
  passed meshd↔run loop; the run loop checks it BEFORE the flow table → routes that IP to the
  rule's exit, bypassing the mesh exit. Local, no wire change, exit=0 falls back to mesh exit.
- Guard: exit can't be self or an unknown member (kills the trap at the source).
- CLI `split add <domain> <mesh> <exit>`; GUI exit-member picker.
- **LIVE (build 02a37dc): mesh exit = NONE, rule pornhub→member#1(Oracle); pornhub egressed via
  Oracle (utun6, HTTP 200, Oracle RX+21712) while ifconfig.me stayed campus; off restored clean.**
- Commit 02a37dc (+ docs/GUI/CHANGELOG follow-up). Root-cause note: the exit-drift to #2/#7 was
  the USER setting a bad mesh exit in the GUI; per-domain exit + the self-guard remove the whole class.

## Fleet clean-slate reinstall to v0.7.5 (2026-07-23)

Tagged v0.7.5 @ 975d26c (F1 split-tunnel + F2 conns); CI built all-platform installers.
Fresh-installed on every reachable node, GUI + daemon, all verified `v0.7.5 build 975d26c`:
- **Mac**: removed old /Applications app, installed official 0.7.5 dmg fresh, relaunched — LIVE.
- **Oracle** (ubuntu systemd): swapped meshd-Linux-X64 into ~/myVpn/target/release/meshd, restart — LIVE direct exit.
- **lablinux** (hyunseok): `dpkg -i` the 0.7.5 deb (GUI /usr/bin/lattice + meshd both updated),
  relaunched via /tmp/lab-start.sh — LIVE, now DIRECT to Mac (path re-converged on fresh install).
- **Windows**: offline (192.168.0.6 + 10.32.86.243 down) — skipped.
Connection book confirms oracle+lablinux both `direct`. Gotcha: the poisoned `grep` shell wrapper
masked dpkg success output — use `command grep` when reading remote command output.

## F2 connection book — BUILT + LIVE-verified (2026-07-23)

"Auto-discover reachable live members, auto-connect, persist for fast reconnect + surface as
key→value." Auto-discovery/connect/endpoint-persistence ALREADY existed (DHT + gossip +
relay→direct + to_persisted.peers reloaded on start). New: surface the RESULT as a connection
book. MemberView gained `path` (direct/relay/offline/me) + `last_seen_secs`, derived in detail()
from the Link's last_seen_ms/last_direct_ms. `lattice conns <mesh>` renders per-member key→value.
LIVE (build bc0aee3): oracle shown `direct` 11s-ago at 138.2.14.219, correctly classified. — bc0aee3
Deferred: persist path-history for post-restart view; GUI conns card; F2 relay-case live shot
(same last_direct_ms logic, shown in logs earlier).

## F1 domain split-tunnel — BUILT + LIVE-verified (2026-07-23)

Default internet stays direct; specific domains egress via a chosen mesh exit. Local to this node.
- DNS parser + rule types (dns_split.rs, 4 tests) — e12da6f
- exit.rs route_host_via_iface/unroute_host (3 OS, /32, no default touch) — d425584
- DNS proxy + upstream detect (run_proxy/detect_upstream) — d1a96cc
- meshd wiring (IPC SplitAdd/Del/List/On/Off, split.json persist, split_enable/disable 🔴) — 4d5663f
- lattice split CLI (offline-verified) — 105789f
- **LIVE (build 40eb106): pornhub→Oracle (utun6, HTTP 200, Oracle RX+8601); normal traffic
  en0/campus, Oracle RX+0; on/off restores DNS+/32 cleanly** — 91004d5
- docs/SPLIT_TUNNEL.md + GUI Configs split-tunnel card — 42900ad
Deferred: per-domain different exits (ToExit(Some)), AAAA, SNI.

## Release v0.7.4 pushed + tagged (2026-06-24)

- **Pushed `feat/extensions-meshd` (e069aa7..c00836b) + annotated tag `v0.7.4` at c00836b** → Release workflow triggered (run 28096210159, in_progress). NOTE: v0.7.3 release build had failed.
- **Release build SUCCEEDED** (7m20s) — GitHub Release v0.7.4 published with the full asset set
  (macOS .dmg, Windows .msi/-setup.exe, Linux .AppImage/.deb ×2 arch, standalone meshd Linux
  binaries). The v0.7.3 failure did not recur; release.yml needed no fix. (verified 2026-07-22)

## Code documentation pass + process hardening (2026-06-24)

- **meshd/src/main.rs: module edit-risk map + RISK tags on the dangerous fns + `///` on every
  previously-undocumented fn** (🔴 bringup_dataplane/arm_kill_switch/shutdown_daemon; 🟡 handle/
  serve_conn/scope_gate/peer_allowed/main/accept_loop/join_mesh/create_mesh; 🟢 helpers). — this commit
- **meshrun/src/lib.rs: module edit-risk + wire-compat invariant + RISK tags** (🔴6/🟡5/🟢2 on the
  hot loop, wire encode/decode, CTRL_* tags, route/relay, parsers). — this commit
- **CLAUDE.md: working-memory charter** (TEMP.md / COMPLETE.md / docs/ERRORS.md workflow). — `cab97cd`
- **exit.rs: edit-risk ratings on every fn** (🔴 HIGH 14 / 🟡 MED 18 + legend). — `8851c46`
- **exit.rs: module API contract + `///` on every public fn** (3 OS branches; 0% → full). — `9f69ace`
- **CLAUDE.md: "diff the stable baseline first" diagnostic rule.** — `9f69ace`
- **docs/ERRORS.md: blast-radius regression map** ("edit X → re-test Y") + 2026-06-24 incident. — `e069aa7`

## v0.7.4 + macOS full-tunnel fixes (2026-06-24)

- **v0.7.4 version bump** (4 version files + locks + CHANGELOG). — `e8c0d8c`
- **Fix #2 (loop): macOS exit pin idempotent + divert-only-if-pinned (fail closed).** — `19465bb`
- **Fix #1 (own-IP): isolate pf `route-to` only on real exit nodes.** — `5cfa960`
- **Build tooling: meshd build-identity stamp + `scripts/build-app.sh` + BUILD.md/CLAUDE.md charter + Windows VERSIONINFO.** — `24d617b` / `0457b74`
- **Runtime fix: mesh 1 exit was mis-set to #2 (idle) → set to #1 (Oracle); full-tunnel works.** — `lattice exit 1 1` (config, no commit)
- **Oracle updated cb6c868 → e069aa7, restarted; fleet data-plane version-matched.** — deploy
- **Extensions/connector framework committed (+ 2 pre-commit hardening fixes).** — `d2370c1`
- **GUI version sync to 0.7.3.** — `7e50ea9`

## 2026-07-25 — Per-mesh `exitable` (opt-in exit serving) + legacy-NAT purge
- **Per-mesh `exitable` toggle, default OFF** — members can only use my internet as exit if I made
  that mesh exitable; only the mesh's own subnet `100.80.<id>.0/24` is NAT'd (not 100.64/10);
  pinned exits (`MESHD_ADVERTISE`) stay exitable automatically. — `v0.7.7`
- **fix: `exitable=off` now actually stops serving** — a node upgraded from the old always-on
  build kept leftover `100.64.0.0/10` MASQUERADE rules (14 dups on lablinux) → forwarded for
  everyone. meshd now reconciles NAT at bringup + `disable_nat` purges every legacy all-overlay
  rule. Found by the cross-node test. — `af13e63` / released `v0.7.8` (`40aa1f2`)
- **Cross-node verified (Mac client ↔ lablinux #4 exit, v0.7.8 fresh install):**
  exitable OFF → curl ifconfig.me FAILS (dropped; route→utun6 + overlay healthy, so genuinely
  dropped at exit); exitable ON → NAT scoped to `100.80.1.0/24` only, curl → 210.107.188.8
  (lablinux egress); ON→OFF live (no restart) → NAT purged, curl fails again. — verified

## 2026-07-25 — v0.7.9: pinned-exit isolate/own-IP regression (found by user's "diff the code" call)
- **fix**: v0.7.8's per-subnet isolate rule (`ip rule from 100.80.<id>.0/24 lookup 100`, and macOS
  `route-to … to any`) also matched the exit's OWN overlay IP → member↔member replies leaked out
  the real WAN → pinned exit (Oracle) visible in gossip but overlay data path dead after restart.
  Fix: overlay-dest traffic bypasses isolate (Linux `ip rule to 100.64.0.0/10 lookup main prio
  999`; macOS `to ! 100.64.0.0/10`). Only forwarded INTERNET isolates. — `3a3646e` / `v0.7.9`
- **Oracle deployed v0.7.9 + code-path verified**: cleared rules → restart → bringup AUTO-added
  999 bypass + 1000 isolate; `ip route get 100.80.1.7 from 100.80.1.1` → `dev tun0`; Mac→Oracle
  overlay ssh `TUNNEL_OK`; Oracle-exit egress = 138.2.14.219 (isolate still works); NAT =
  `100.80.1.0/24` only. Diagnosis method: diffed last-working baseline (NOT a guessed rekey/OS
  wedge) — logged in docs/ERRORS.md. — verified
