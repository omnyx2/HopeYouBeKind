#!/usr/bin/env bash
# Pin the Lattice window to the fixed demo rectangle and take a baseline shot.
# Run this once at the start of a session (and any time the window gets moved).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

fit_window
out="$(shot baseline)"
echo "window pinned to ${WIN_X},${WIN_Y} ${WIN_W}x${WIN_H}"
echo "baseline -> $out"
