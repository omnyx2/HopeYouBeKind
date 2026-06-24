# COMPLETE.md — finished work log

Requirements moved here from `TEMP.md` as they complete (newest first). Each: what + date +
commit. The durable record; `TEMP.md` only holds open items.

---

## Code documentation pass + process hardening (2026-06-24)

- **CLAUDE.md: working-memory charter** (TEMP.md / COMPLETE.md / docs/ERRORS.md workflow). — this commit
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
