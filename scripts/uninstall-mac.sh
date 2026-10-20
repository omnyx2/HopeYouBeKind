#!/usr/bin/env bash
# Lattice macOS uninstaller (docs/LIFECYCLE.md §5): remove EVERYTHING the app put on
# this machine — app bundle, LaunchDaemon, LaunchAgent, running daemon (gracefully,
# restoring routes/DNS first), sockets/logs, DMG mounts. Mesh state (membership +
# identity) is KEPT by default so a reinstall rejoins automatically; deleting it is an
# explicit, typed choice.
#
#   sudo bash scripts/uninstall-mac.sh [--delete-state]
set -euo pipefail

DST="/Applications/Lattice.app"
SOCK="/tmp/lattice-meshd.sock"
PLIST="/Library/LaunchDaemons/dev.lattice.meshd.plist"
AGENT="/Users/${SUDO_USER:-nobody}/Library/LaunchAgents/dev.lattice.gui.plist"
BACKUP="/tmp/lattice-mesh-backup.json"

[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo bash $0"; exit 1; }

ipc() { [ -S "$SOCK" ] && printf '%s\n' "$1" | /usr/bin/nc -U -w 3 "$SOCK" 2>/dev/null || true; }

STATE_DIRS=()
for d in /var/root/.lattice/meshd "/Users/${SUDO_USER:-nobody}/.lattice/meshd"; do
  [ -d "$d" ] && STATE_DIRS+=("$d")
done

DELETE_STATE=no
if [ "${1:-}" = --delete-state ]; then
  DELETE_STATE=yes
elif [ ${#STATE_DIRS[@]} -gt 0 ]; then
  echo "메쉬 state 발견: ${STATE_DIRS[*]}"
  echo "보존하면(기본) 나중에 재설치할 때 모든 메쉬에 자동 복귀합니다."
  read -r -p "state도 삭제할까요? identity가 영구 소실됩니다 [y/N] " a
  case "$a" in [yY]*) DELETE_STATE=yes ;; *) DELETE_STATE=no ;; esac
fi

echo "1/4  데몬/앱 정지 (routes/DNS 복원 포함)…"
pkill -x Lattice 2>/dev/null || true
sleep 1
ipc '"Shutdown"' >/dev/null
sleep 2
pkill -f "Lattice.app/Contents/Resources/resources/meshd" 2>/dev/null || true
rm -f "$SOCK" /tmp/lattice-meshd.log

echo "2/4  서비스/자동시작 등록 해제…"
if [ -f "$PLIST" ]; then
  launchctl unload -w "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
fi
rm -f "$AGENT"

echo "3/4  앱/잔재 제거…"
if /sbin/mount | grep -q "/Volumes/Lattice"; then
  hdiutil detach /Volumes/Lattice -force >/dev/null 2>&1 || true
fi
rm -rf "$DST" "$DST.prev"

echo "4/4  메쉬 state…"
if [ "$DELETE_STATE" = yes ] && [ ${#STATE_DIRS[@]} -gt 0 ]; then
  read -r -p "     마지막 확인 — 'delete'를 입력하면 identity까지 지웁니다: " c
  if [ "$c" = delete ]; then
    rm -rf "${STATE_DIRS[@]}" "$BACKUP"
    echo "     삭제됨."
  else
    echo "     보존함 (확인 문구 불일치)."
  fi
else
  [ ${#STATE_DIRS[@]} -gt 0 ] && echo "     보존됨: ${STATE_DIRS[*]} (재설치 시 자동 복귀)" || echo "     없음."
fi

echo "완료 — Lattice가 제거되었습니다."
