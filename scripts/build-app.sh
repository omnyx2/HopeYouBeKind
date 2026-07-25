#!/usr/bin/env bash
# Build the Lattice desktop app (GUI + meshd sidecar) the ONE correct way, with built-in
# checks that make "an old binary got mixed into the build" impossible to ship silently.
# See BUILD.md. macOS/Linux. Usage: scripts/build-app.sh
set -euo pipefail

ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
cd "$ROOT"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m  ✗ %s\033[0m\n' "$*" >&2; exit 1; }
# Does binary $1 carry the build string for SHA? Uses grep -c (consumes all input) rather than
# grep -q, because under `set -o pipefail` grep -q's early exit SIGPIPEs `strings` and the
# pipeline would falsely report failure.
has_sha() { [ "$(strings "$1" | grep -c "build ${SHA}")" -gt 0 ]; }

SHA="$(git rev-parse --short HEAD)"
[ -z "$(git status --porcelain -- crates/ gui/ 2>/dev/null)" ] || \
  printf '\033[1;33m  ! working tree has uncommitted changes — the embedded SHA (%s) is the\n    last commit, not your edits. Commit first for a truthful stamp.\033[0m\n' "$SHA"

APP="gui/src-tauri/target/release/bundle/macos/Lattice.app"
WMESHD="target/release/meshd"
RMESHD="gui/src-tauri/resources/meshd"
BMESHD="$APP/Contents/Resources/resources/meshd"

# 1) Build the daemon — CORRECT package name (lattice-meshd, NOT meshd), on stable.
#    Touch build.rs so it re-runs and re-stamps the current commit SHA into the binary,
#    regardless of cargo's incremental change detection — the stale-build guard (step 2)
#    then holds unconditionally.
say "Building meshd (lattice-meshd, stable)…"
touch crates/meshd/build.rs
RUSTUP_TOOLCHAIN=stable cargo build --release -p lattice-meshd
[ -f "$WMESHD" ] || die "$WMESHD missing — build did not produce the binary"

# 2) Prove the binary is THIS commit's build, not a stale leftover. The build.rs stamps the
#    git short SHA into the binary; if it doesn't match HEAD, something is stale.
has_sha "$WMESHD" \
  || die "$WMESHD does not carry the current commit ${SHA} — stale build. Run 'cargo clean -p lattice-meshd' and retry."
ok "meshd built from ${SHA}"

# 3) Stage it as the bundle resource.
say "Staging meshd → resources…"
mkdir -p "$(dirname "$RMESHD")"
cp "$WMESHD" "$RMESHD"

# 4) Bundle the app (vite + lattice-gui, on stable). The DMG step can fail on macOS; the .app
#    is what we need, so tolerate a nonzero exit and check the .app explicitly.
say "Bundling app (tauri build, stable)…"
( cd gui && RUSTUP_TOOLCHAIN=stable npm run tauri build ) || true
[ -d "$APP" ] || die "$APP not produced — bundle failed (see log above)"

# 5) Anti-mix gate: the meshd INSIDE the .app must be byte-identical to the one we just
#    built. A hash mismatch means a stale binary slipped into the bundle.
h() { shasum -a 256 "$1" | awk '{print $1}'; }
[ -f "$BMESHD" ] || die "bundle has no meshd at $BMESHD"
[ "$(h "$WMESHD")" = "$(h "$BMESHD")" ] \
  || die "bundled meshd != freshly built meshd (stale binary in bundle!)"
has_sha "$BMESHD" || die "bundled meshd is not commit ${SHA}"
ok "bundled meshd == fresh build (${SHA})"

VER="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist" 2>/dev/null || echo '?')"
ok "app version ${VER}"

# 6) Tell the user what's actually RUNNING — the live daemon is still the old binary until the
#    app is relaunched, which is the usual source of "old vs new" confusion.
say "Done. Built: ${APP} (v${VER}, meshd ${SHA})"
if pgrep -f 'resources/meshd' >/dev/null 2>&1; then
  RUNNING="$( { grep -aE 'version v.* build' /tmp/lattice-meshd.log 2>/dev/null || true; } | tail -1 | sed 's/.*meshd: //')"
  printf '\033[1;33m  ! a meshd is already running'
  [ -n "$RUNNING" ] && printf ' (%s)' "$RUNNING"
  printf ' — it is NOT this build until you\n    relaunch the app. New build is on disk only.\033[0m\n'
fi
