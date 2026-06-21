#!/usr/bin/env bash
# Reinstall the locally-built Lattice.app over the installed one, taking over from the
# old root meshd so the new daemon's features are actually live. Run with sudo:
#   sudo bash scripts/install-mac.sh
set -e

# Repo root = the parent of this script's directory (portable; no hardcoded path).
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO/gui/src-tauri/target/release/bundle/macos/Lattice.app"
DST="/Applications/Lattice.app"

[ -d "$SRC" ] || { echo "build not found at $SRC — run: cd gui && RUSTUP_TOOLCHAIN=stable npm run tauri build"; exit 1; }

echo "1/4  quitting the running Lattice GUI…"
pkill -x Lattice 2>/dev/null || true
sleep 1

echo "2/4  stopping the old root meshd (so the new one can take over)…"
pkill -f "Lattice.app/Contents/Resources/resources/meshd" 2>/dev/null || true
sleep 2
rm -f /tmp/lattice-meshd.sock

echo "3/4  replacing $DST …"
rm -rf "$DST"
cp -R "$SRC" "$DST"
xattr -dr com.apple.quarantine "$DST" 2>/dev/null || true

VER="$(defaults read "$DST/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo '?')"
echo "4/4  done. Installed Lattice $VER."
echo
echo "Now launch it normally (it will prompt for admin to bring up the VPN tunnel):"
echo "    open \"$DST\""
echo "Your meshes are persisted (under the running user's ~/.lattice/meshd) — the node rejoins automatically."
