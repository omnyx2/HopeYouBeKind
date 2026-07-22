# TEMP.md — live working memory

Scratchpad for the task in progress. Charter in `CLAUDE.md` → "Working memory". Only OPEN items
live here; move done items to `COMPLETE.md`; log errors to `docs/ERRORS.md`. Read
`docs/ERRORS.md` before starting.

---

## Current task: code documentation pass + process hardening

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
- Oracle: last known `e069aa7`, systemd, healthy exit. SSH:
  `ssh -i ssh-key-2026-06-13.key -o IdentitiesOnly=yes ubuntu@<oracle>` (key in repo root, gitignored).
- **v0.7.4 released**: tag + GitHub Release with all installers (run 28096210159 SUCCESS —
  v0.7.3's release run had failed; nothing to fix in release.yml after all).
