# CLAUDE.md — working agreement for this repo

Lattice is a serverless mesh VPN (Rust core crates + Tauri GUI). These are binding rules for
any automated change. Keep them; they encode mistakes already made here.

## Working memory — TEMP.md / COMPLETE.md / docs/ERRORS.md (follow this every task)

A disciplined scratchpad so long multi-step work doesn't drift or repeat mistakes. The charter:

0. **Before starting ANY work, READ `docs/ERRORS.md` first** — the blast-radius map + the
   "modify → error → fix" quick-log at the top. Restart from what it tells you; never re-make a
   logged mistake.
1. **At task start, index the work into `TEMP.md`.** Write the feature you're building and its
   detailed implementation requirements as a numbered checklist. `TEMP.md` is the single live
   answer to "what am I doing right now" — keep it current; only OPEN items live here.
2. **When a requirement is done, MOVE it from `TEMP.md` to `COMPLETE.md`** (with the date + the
   commit sha that finished it). `TEMP.md` shrinks as work completes; `COMPLETE.md` is the record.
3. **When an error happens while implementing, append to `docs/ERRORS.md`** in the form
   *"modified `<file:area>` this way → `<the error that occurred>` → fixed by `<what>`"*. Factual
   and granular. This is read in step 0 next time.

How to write entries: concise, numbered/indexed, dated, link the commit. Keep `TEMP.md` short —
it's scratch, not prose. When `TEMP.md` is empty, the task is done.

## Building — ALWAYS follow BUILD.md

**Before any build, bundle, or release action, read [BUILD.md](BUILD.md) and follow it.**
It is the source of truth and exists to stop a build from silently shipping a stale binary.

Non-negotiable build rules (full detail in BUILD.md):

1. **Package name ≠ binary name.** Build the daemon with **`cargo build -p lattice-meshd`**
   (binary is `meshd`). **Never `cargo build -p meshd`** — it does not match any package,
   exits non-zero, and a following `cp` then bundles a stale binary.
2. **Never chain `cargo build …; cp …`** without checking the build exit code. A failed build
   must abort the copy. Don't `| tail` the exit code away.
3. **Toolchains:** core crates build under the pinned **1.79**; the **GUI/Tauri bundle builds
   with `RUSTUP_TOOLCHAIN=stable`** (its deps need edition2024 — by design, not a bug). A
   `getrandom`/`edition2024` error means you ran a GUI build under 1.79; re-run on stable, do
   not downgrade lock deps. `cargo fmt --all` uses plain 1.79 (never a stable override).
4. **Verify, don't assume.** After building anything you'll ship, confirm it's (a) fresh
   (mtime now), (b) the right content/behavior (e.g. the running meshd answers
   `python3 scripts/lattice raw '"ListExtensions"'` without "unknown variant"), and (c) the
   expected version. A green log is not proof. See BUILD.md §4.

## Live VPN safety (macOS)

The running `meshd` serves a live VPN. **Do not casually rebuild-relaunch it** — repeated
restarts wedge the macOS utun and drop the tunnel. Verify daemon changes **offline** (separate
socket + `MESHD_STATE_DIR`, no `DATA_PLANE`) or on a test mesh. Swap the live daemon only when
explicitly agreed, via `lattice off` → `lattice shutdown` → quit app → relaunch once → re-auth.
Diagnose reachability with `curl`/TCP, not `ping` (ICMP is blocked on campus). See BUILD.md §5.

## When something breaks — diff the last stable baseline FIRST

Before hypothesizing a wedge, an OS quirk, infra, or a deep bug, **localize the change**: a
feature that used to work and now doesn't almost always broke in code that changed since the
last version it worked in. So step 1 of any regression is:

```bash
git diff <last-working-tag>..HEAD -- <the relevant area>     # e.g. v0.6.1..HEAD -- crates/meshd/src/exit.rs
git log --oneline <last-working-tag>..HEAD -- <area>
```

The changed lines are the prime suspects — read them before anything else. This is exactly how
the macOS full-tunnel regression (`cb6c868`) was found; a "utun wedge" was wrongly assumed for
hours first. Order of suspicion: **(1) config/state** (`lattice ls/info` — is the exit a LIVE
member? is the running build's `version … build <sha>` == HEAD? are all fleet nodes the same
version?) → **(2) the stable↔current diff** of the area → **(3) only then** OS/kernel/infra.
Don't trust a metric whose semantics you haven't verified (e.g. `netstat -I -b` column order,
`ip route get` needing `iif`); cross-check against a ground-truth signal (the egress IP, not an
interface counter).

## Before editing — check the regression map

`docs/ERRORS.md` opens with a **blast-radius map** ("if you edit X, re-test Y, because…") plus a
running log of real incidents and their root causes. **Before changing the data plane, exit
routing/pf, IPC enums, or the build/packaging, skim that map** — most of those areas have broken
once already and the trap is written down. After fixing a real regression, add an entry (newest
first) so the next person inherits the lesson.

Highest-traffic traps: `exit.rs` route/pf changes are per-OS and independent (test all 3, watch
for route loops + the `100.64/10`-matches-own-IP pitfall); IPC enum changes must be additive
(`"unknown variant"` = version skew); and always confirm you're testing the CURRENT build via the
`meshd: version … build <sha>` log line (a stale binary masks regressions).

## Commits

- This repo is **public**: never commit real infra IPs/hostnames (use placeholders).
- **Do not add `Co-Authored-By` / AI attribution** to commit messages.
- Don't commit a "done" claim you haven't verified per BUILD.md §4.

## Key references

- `BUILD.md` — build/bundle/release procedure + verification gates
- `gui/README.md` — why the GUI builds on stable (edition2024 toolchain note)
- `docs/EXTENSIONS.md` — connector/extension framework spec
- `.github/workflows/release.yml` — canonical CI build recipe (mirrored by BUILD.md)
