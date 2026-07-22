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
