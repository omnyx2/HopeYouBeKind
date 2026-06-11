#!/usr/bin/env bash
# Shared helpers for the GUI click-through demo (network create → issue → join →
# revoke). Sourced by the other scripts in this dir. macOS only.
#
# The whole demo is coordinate-driven: we pin the Lattice window to a fixed
# rectangle, then click/capture against that rectangle. So the FIRST thing any
# run does is fit-window — never click before the window is where we think.

set -euo pipefail

APP_NAME="${APP_NAME:-Lattice}"

# Fixed window rectangle (x y w h), in screen points. Clicks below are written
# relative to this origin, so if you change it, re-derive the click coords.
WIN_X="${WIN_X:-120}"
WIN_Y="${WIN_Y:-90}"
WIN_W="${WIN_W:-760}"
WIN_H="${WIN_H:-720}"

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHOTS_DIR="${SHOTS_DIR:-$DEMO_DIR/shots}"
mkdir -p "$SHOTS_DIR"

# --- window placement -------------------------------------------------------
# Move + resize the app's front window to the fixed rectangle via System Events.
# Needs Accessibility permission for whoever runs this (Terminal / Claude Code).
fit_window() {
  osascript <<OSA
tell application "$APP_NAME" to activate
delay 0.4
tell application "System Events" to tell process "$APP_NAME"
  set frontmost to true
  set position of window 1 to {$WIN_X, $WIN_Y}
  set size of window 1 to {$WIN_W, $WIN_H}
end tell
OSA
}

focus() {
  osascript -e "tell application \"$APP_NAME\" to activate" >/dev/null 2>&1 || true
  sleep 0.3
}

# --- screenshot -------------------------------------------------------------
# shot <name>  -> writes shots/NN-<name>.png capturing just the window rect.
# Needs Screen Recording permission. NN auto-increments per run dir.
shot() {
  local name="${1:?usage: shot <name>}"
  local n
  n="$(printf '%02d' "$(( $(ls "$SHOTS_DIR" 2>/dev/null | grep -cE '^[0-9]{2}-') + 1 ))")"
  local out="$SHOTS_DIR/${n}-${name}.png"
  focus
  screencapture -x -R"${WIN_X},${WIN_Y},${WIN_W},${WIN_H}" "$out"
  echo "$out"
}

# --- clicking ---------------------------------------------------------------
# click <x> <y>  where x,y are ABSOLUTE screen points. Use rel_click for coords
# measured from the window's top-left (preferred — survives window moves).
click() { cliclick -e 120 "c:${1},${2}"; }
rel_click() { cliclick -e 120 "c:$(( WIN_X + ${1} )),$(( WIN_Y + ${2} ))"; }

# type_text <string> — types into the focused field. Use after clicking a field.
type_text() { cliclick -e 60 "t:${1}"; }

# clear_field — select-all + delete in the focused field.
clear_field() { cliclick kd:cmd t:a ku:cmd kp:delete; }
