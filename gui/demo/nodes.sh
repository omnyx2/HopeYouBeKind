#!/usr/bin/env bash
# Stand up the demo's two daemons on ONE Mac, with a clean capability split:
#
#   GUI  = the MEMBER / user surface. Attaches to /tmp/lattice.sock (the socket
#          the GUI hardcodes, gui/src-tauri/src/main.rs:16). Open mode until it
#          adopts a token. The only membership action a user does in the GUI is
#          JOIN (가입) — a real button click.
#
#   admin = a HEADLESS, ISOLATED tool. Holds the network CA key, on its OWN
#          socket /tmp/lattice-admin.sock. Network create (망생성, automatic on
#          first start with --network_key), issue (발급) and revoke (추방) are
#          admin capabilities driven ONLY via the CLI here — never exposed in the
#          user GUI. (A separate admin GUI can come later; the capability stays
#          isolated from the user surface.)
#
# Membership needs no TUN, so both run --no-tun: no sudo, no password prompt.
# The GUI shows the *effects* of admin actions (role flips to member after join;
# cut off after revoke) without ever holding admin power itself.
#
# Usage:
#   ./nodes.sh build              # cargo build daemon + cli (release)
#   ./nodes.sh up                 # start member (GUI socket) + admin (isolated)
#   ./nodes.sh member-id          # member's 64-hex node id (feed to issue)
#   ./nodes.sh issue [label]      # ADMIN: mint a token for the member -> prints token
#   ./nodes.sh revoke             # ADMIN: evict the member
#   ./nodes.sh members            # ADMIN: list enrolled members
#   ./nodes.sh down               # stop both, clean sockets
#
# Join (가입) is intentionally NOT here — it's the GUI button click the demo
# shows. (If you must do it headless: ./nodes.sh _join <token>.)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$ROOT/target/release"
RUN="/tmp/lattice-demo"
mkdir -p "$RUN"

MEMBER_SOCK="/tmp/lattice.sock"            # GUI attaches here (hardcoded)
ADMIN_SOCK="/tmp/lattice-admin.sock"       # isolated admin tool
DAEMON="$BIN/lattice-daemon"
CLI="$BIN/lattice"
acli() { "$CLI" --ipc-socket "$ADMIN_SOCK" "$@"; }   # talk to the admin daemon

build() { ( cd "$ROOT" && cargo build --release -p lattice-daemon -p lattice-cli ); }

up() {
  [ -x "$DAEMON" ] || { echo "daemon not built — run: ./nodes.sh build"; exit 1; }
  # member: plain open-mode node on the GUI's socket. GUI drives it.
  "$DAEMON" --no-tun \
    --ipc-socket "$MEMBER_SOCK" \
    --identity   "$RUN/member-id.key" \
    --member_cert "$RUN/member.cert" \
    > "$RUN/member.log" 2>&1 &
  echo "member pid $! -> $MEMBER_SOCK  (the GUI attaches here)"
  # admin: isolated tool holding the CA key -> creates the network on first run.
  "$DAEMON" --no-tun \
    --ipc-socket "$ADMIN_SOCK" \
    --identity   "$RUN/admin-id.key" \
    --network_key "$RUN/admin-ca.key" \
    > "$RUN/admin.log" 2>&1 &
  echo "admin  pid $! -> $ADMIN_SOCK  (CLI only — never in the user GUI)"
  sleep 1
  echo "ok. open the Lattice GUI; Mesh tab shows 'open mode' until you Join."
}

member_id() { "$CLI" --ipc-socket "$MEMBER_SOCK" status | awk '/^node-id/{print $2}'; }

issue() {
  local label="${1:-mac-laptop}"
  local id; id="$(member_id)"
  [ -n "$id" ] || { echo "member not up yet"; exit 1; }
  echo "issuing token for member $id (label: $label) ..." >&2
  acli net issue "$id" --label "$label"
}

revoke()  { acli net revoke "$(member_id)"; }
members() { acli net members; }
_join()   { "$CLI" --ipc-socket "$MEMBER_SOCK" net join "${1:?token}"; }

down() {
  pkill -f "lattice-daemon .*$RUN" 2>/dev/null || true
  rm -f "$MEMBER_SOCK" "$ADMIN_SOCK"
  echo "stopped; sockets removed (keys kept in $RUN — rm -rf to fully reset)"
}

case "${1:-}" in
  build) build ;;
  up) up ;;
  member-id) member_id ;;
  issue) shift; issue "$@" ;;
  revoke) revoke ;;
  members) members ;;
  _join) shift; _join "$@" ;;
  down) down ;;
  *) echo "usage: $0 {build|up|member-id|issue [label]|revoke|members|down}"; exit 1 ;;
esac
