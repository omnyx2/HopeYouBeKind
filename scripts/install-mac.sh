#!/usr/bin/env bash
# Lattice macOS installer (docs/LIFECYCLE.md §4-§5): install/upgrade the locally-built
# Lattice.app CLEANLY — tear down every legacy remnant (manual daemons, DMG-mounted
# copies, stale sockets), ask about existing mesh state (it's an identity: keep by
# default), and hand ownership back to launchd if boot-start was enabled.
#
#   sudo bash scripts/install-mac.sh [--yes-keep-state | --delete-state]
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO/gui/src-tauri/target/release/bundle/macos/Lattice.app"
DST="/Applications/Lattice.app"
SOCK="/tmp/lattice-meshd.sock"
PLIST="/Library/LaunchDaemons/dev.lattice.meshd.plist"
BACKUP="/tmp/lattice-mesh-backup.json"

[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo bash $0"; exit 1; }
[ -d "$SRC" ] || { echo "build not found at $SRC — run: cd gui && RUSTUP_TOOLCHAIN=stable npm run tauri build"; exit 1; }

# One IPC line to the daemon over its world-writable socket (best-effort).
ipc() { [ -S "$SOCK" ] && printf '%s\n' "$1" | /usr/bin/nc -U -w 3 "$SOCK" 2>/dev/null || true; }

# Mesh state lives under the daemon's HOME — root (launchd/osascript) or the user's.
STATE_DIRS=()
for d in /var/root/.lattice/meshd "/Users/${SUDO_USER:-nobody}/.lattice/meshd"; do
  if ls "$d"/mesh-*.json >/dev/null 2>&1; then STATE_DIRS+=("$d"); fi
done

KEEP=ask
case "${1:-}" in
  --yes-keep-state) KEEP=yes ;;
  --delete-state)   KEEP=no ;;
esac
if [ ${#STATE_DIRS[@]} -gt 0 ] && [ "$KEEP" = ask ]; then
  echo "기존 메쉬 state 발견: ${STATE_DIRS[*]}"
  echo "메쉬 state는 멤버십+identity입니다 — 지우면 모든 메쉬에 재가입해야 합니다."
  read -r -p "보존하고 설치 후 그대로 복귀할까요? [Y/n] " a
  case "$a" in [nN]*) KEEP=no ;; *) KEEP=yes ;; esac
fi

echo "1/6  메쉬 state 처리…"
if [ "$KEEP" = yes ] || [ ${#STATE_DIRS[@]} -eq 0 ]; then
  # Belt-and-braces: also snapshot via ExportState while the daemon is still up —
  # the new daemon re-imports $BACKUP at first start (existing mechanism), and the
  # state dirs are left untouched (the daemon reloads them anyway).
  ipc "{\"ExportState\":{\"path\":\"$BACKUP\"}}" >/dev/null
  [ -f "$BACKUP" ] && echo "     스냅샷: $BACKUP (+ state dir 보존)" || echo "     state dir 보존 (데몬이 꺼져 있어 스냅샷은 생략)"
else
  echo "     ⚠ 완전 삭제를 선택했습니다 — identity가 영구 소실됩니다."
  read -r -p "     정말로요? 'delete'를 입력하면 지웁니다: " c
  [ "$c" = delete ] || { echo "중단."; exit 1; }
  rm -rf "${STATE_DIRS[@]}" "$BACKUP"
fi

echo "2/6  실행 중인 것들 정리 (routes/DNS 복원 포함)…"
pkill -x Lattice 2>/dev/null || true
sleep 1
ipc '"Shutdown"' >/dev/null          # graceful: restores routes + DNS before exiting
sleep 2
pkill -f "Lattice.app/Contents/Resources/resources/meshd" 2>/dev/null || true
pkill -f "resources/meshd $SOCK" 2>/dev/null || true
rm -f "$SOCK"

echo "3/6  레거시 잔재 제거…"
if /sbin/mount | grep -q "/Volumes/Lattice"; then
  hdiutil detach /Volumes/Lattice -force >/dev/null 2>&1 || true   # the 2026-08-22 DMG trap
  echo "     /Volumes/Lattice 언마운트"
fi
rm -rf "$DST.prev"

BOOT=no
if [ -f "$PLIST" ]; then
  BOOT=yes
  launchctl unload -w "$PLIST" 2>/dev/null || true
fi

echo "4/6  $DST 교체…"
rm -rf "$DST"
cp -R "$SRC" "$DST"
xattr -dr com.apple.quarantine "$DST" 2>/dev/null || true

echo "5/6  부팅 자동시작…"
if [ "$BOOT" = yes ]; then
  launchctl load -w "$PLIST" 2>/dev/null || true
  echo "     LaunchDaemon 재가동 — 데몬이 launchd 소유로 시작됩니다."
else
  echo "     미설정 (앱 Settings에서 켤 수 있음)."
fi

VER="$(defaults read "$DST/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo '?')"
echo "6/6  완료 — Lattice $VER 설치됨."
echo
if [ "$BOOT" = yes ]; then
  echo "데몬은 launchd가 이미 띄웠습니다. 앱은 뷰어일 뿐이니 필요할 때 여세요: open \"$DST\""
else
  echo "실행: open \"$DST\"  (데몬이 꺼져 있으면 관리자 권한을 한 번 묻고 띄웁니다)"
fi
[ "$KEEP" = yes ] && echo "메쉬는 보존된 state(+스냅샷)에서 자동 복귀합니다."
# Sanity: the running meshd must be under /Applications, never /Volumes (DMG trap).
sleep 1
BAD="$(ps axo comm | grep -c '^/Volumes/Lattice' || true)"
[ "${BAD:-0}" = 0 ] || echo "⚠ /Volumes 경로의 프로세스가 남아 있습니다 — ps로 확인하세요."
