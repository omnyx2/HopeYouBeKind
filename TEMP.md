# TEMP.md — live working memory

Scratchpad for the task in progress. Charter in `CLAUDE.md` → "Working memory". Only OPEN items
live here; move done items to `COMPLETE.md`; log errors to `docs/ERRORS.md`. Read
`docs/ERRORS.md` before starting.

---

## Current task: code documentation pass + process hardening

Goal: make every data-plane/exit function self-explanatory (contract + `///` + edit-risk) so
regressions are easy to localize, and set up the working-memory workflow.

### Requirements (open)

1. **meshd/src/main.rs docs** — add the missing module overview (`//!`) + `///` on the
   undocumented functions (~24 of 69) + edit-risk on the dataplane/route/kill-switch ones.
2. **Open verification (separate thread)** — clean-reboot the Mac, launch the fixed bundle
   (≥19465bb / now 0.7.4) once, re-verify full-tunnel egress=Oracle + Ipkts>0 against the
   version-matched Oracle. Confirms the macOS fixes on a non-churned system.
3. **Release decisions (pending user)** — (a) push session commits to `origin`; (b) tag `v0.7.4`
   (triggers the release-installer build).

### Notes / context to not lose
- Fleet right now: Mac = local, running build `19465bb` (0.7.3 code) with full-tunnel ON via
  Oracle (egress 138.2.14.219); Oracle = updated to `e069aa7`, healthy exit, connected. Versions
  data-plane-match. SSH to Oracle: `ssh -i ssh-key-2026-06-13.key -o IdentitiesOnly=yes ubuntu@<oracle>`.
- Source is at `0.7.4` (committed) but the running Mac bundle is still the `19465bb` build — a
  rebuild/redeploy would restart meshd (drops VPN); don't unless asked.
