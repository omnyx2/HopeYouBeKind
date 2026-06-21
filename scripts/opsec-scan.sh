#!/usr/bin/env bash
# Opsec guard: fail if any real infrastructure IP / credential / personal path leaks into a
# tracked file. The repo is PUBLIC — use placeholders (<PUBLIC_IP>, RFC5737 203.0.113.x /
# 198.51.100.x / 192.0.2.x) for examples. Private ranges (10.x except the campus /16 below,
# 192.168.x, 172.16-31.x), the overlay 100.64/10, and well-known anchors (8.8.8.8, 1.1.1.1)
# are intentionally allowed.
#
# This is a DENYLIST of strings known to have leaked before — extend it as new infra appears.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Real infra / personal identifiers that must never be committed. (Built from fragments so
# this scanner doesn't trip on its own patterns; it also excludes itself below.)
oct='[0-9]{1,3}'
patterns=(
  "138\.2\.14\.${oct}"     # public cloud exit node
  "203\.247\.${oct}"       # campus public NAT
  "210\.107\.${oct}"       # lab public
  "118\.235\.${oct}"       # cellular public
  "10\.32\.${oct}"         # campus LAN /16
  "hyunseok"               # a node account name
  "/Users/lyuhyeonseog"    # personal home path
  "ssh-key-20[0-9][0-9]-[0-9]" # dated private-key filename
  "omnyx2-2\.local"        # personal hostname
)
PAT=$(IFS='|'; echo "${patterns[*]}")

# Scan every tracked file except this scanner (it literally names the patterns). -I skips
# binaries (e.g. wintun.dll).
hits=$(git ls-files \
  | grep -vxF 'scripts/opsec-scan.sh' \
  | xargs grep -nIE "$PAT" 2>/dev/null || true)

if [ -n "$hits" ]; then
  echo "::error::opsec scan FAILED — real infra IP / credential / personal path in tracked files:"
  echo "$hits"
  echo
  echo "Replace with a placeholder (<PUBLIC_IP>) or an RFC5737 documentation IP (203.0.113.x)."
  exit 1
fi
echo "opsec scan clean — no real infra IPs / credentials / personal paths in tracked files."
