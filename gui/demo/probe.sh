#!/usr/bin/env bash
# Calibration helper. Coordinate clicks need the right targets; nav items and
# buttons are found by reading a fresh screenshot, not guessed. This prints the
# current window rect + a grid-overlay shot so Claude (or you) can read off
# button coordinates relative to the window origin before driving the flow.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

fit_window
echo "current front-window geometry:"
osascript <<OSA
tell application "System Events" to tell process "$APP_NAME"
  set p to position of window 1
  set s to size of window 1
  return "pos " & (item 1 of p) & "," & (item 2 of p) & "  size " & (item 1 of s) & "x" & (item 2 of s)
end tell
OSA
out="$(shot probe)"
echo "probe shot -> $out"
echo
echo "Approx GUI landmarks (relative to window top-left, x y):"
echo "  sidebar nav is the left ~160px column; tabs stack from y~70:"
echo "    Status ~ 80,80   Peers ~ 80,120   Traffic ~ 80,165"
echo "    Mesh   ~ 80,205  Network ~ 80,250"
echo "  (verify against the probe shot before clicking — DPI/theme can shift these)"
