# CLAUDE.md — working agreement for this repo

Lattice is a serverless mesh VPN (Rust core crates + Tauri GUI). These are binding rules for
any automated change. Keep them; they encode mistakes already made here.

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

## Commits

- This repo is **public**: never commit real infra IPs/hostnames (use placeholders).
- **Do not add `Co-Authored-By` / AI attribution** to commit messages.
- Don't commit a "done" claim you haven't verified per BUILD.md §4.

## Key references

- `BUILD.md` — build/bundle/release procedure + verification gates
- `gui/README.md` — why the GUI builds on stable (edition2024 toolchain note)
- `docs/EXTENSIONS.md` — connector/extension framework spec
- `.github/workflows/release.yml` — canonical CI build recipe (mirrored by BUILD.md)
