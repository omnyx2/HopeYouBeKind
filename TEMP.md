# TEMP.md — live working memory

Scratchpad for the task in progress. Charter in `CLAUDE.md` → "Working memory". Only OPEN items
live here; move done items to `COMPLETE.md`; log errors to `docs/ERRORS.md`. Read
`docs/ERRORS.md` before starting.

---

## Current task: code documentation pass + process hardening

Goal: make every data-plane/exit function self-explanatory (contract + `///` + edit-risk) so
regressions are easy to localize, and set up the working-memory workflow.

### Requirements (open)

1. **Open verification (separate thread)** — clean-boot the Mac, launch a ≥0.7.4 bundle once,
   re-verify full-tunnel egress=Oracle + Ipkts>0 against the version-matched Oracle. Confirms
   the macOS fixes on a non-churned system. (meshd is currently NOT running on the Mac.)
2. **Windows re-join incomplete** — found the box on the home LAN (`192.168.0.6`, host
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
- **Mac: meshd NOT running** (socket refused); internet direct via campus (10.32.x / egress
  203.247.167.58). The disk bundle is stale (19465bb-era) vs source 0.7.4 — next launch should
  use a fresh `scripts/build-app.sh` bundle, or install the released `Lattice_0.7.4_aarch64.dmg`.
- Oracle: last known `e069aa7`, systemd, healthy exit. SSH:
  `ssh -i ssh-key-2026-06-13.key -o IdentitiesOnly=yes ubuntu@<oracle>` (key in repo root, gitignored).
- **v0.7.4 released**: tag + GitHub Release with all installers (run 28096210159 SUCCESS —
  v0.7.3's release run had failed; nothing to fix in release.yml after all).
