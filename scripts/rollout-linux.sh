#!/bin/bash
# Roll out the current origin/main meshd to THIS Linux node (oracle/lablinux style:
# source build + systemd swap). Run DETACHED and read the log afterwards — never drive
# a daemon restart over a connection the restart can cut (CLAUDE.md, docs/LIFECYCLE.md):
#
#   scp scripts/rollout-linux.sh <node>:/tmp/ && \
#   ssh <node> 'nohup bash /tmp/rollout-linux.sh [repo-dir] >/dev/null 2>&1 & echo detached'
#   ...later...   ssh <node> 'tail -20 /tmp/lattice-rollout.log'
#
# Steps (each logged PASS/FAIL): git → build (lattice-meshd, SHA-stamp gate per
# BUILD.md) → backup → systemctl restart lattice-meshd → socket + version verify.
OUT=/tmp/lattice-rollout.log
log() { echo "$(date +%T) $*" >> "$OUT"; }
: > "$OUT"
set -o pipefail
export PATH="$HOME/.cargo/bin:$PATH"   # nohup runs a non-login shell — no cargo otherwise
REPO="${1:-$HOME/myVpn}"
cd "$REPO" || { log "FAIL no repo at $REPO"; exit 1; }

log '== git =='
git fetch origin >> "$OUT" 2>&1 || { log 'FAIL fetch'; exit 1; }
git checkout -B main origin/main >> "$OUT" 2>&1 || { log 'FAIL checkout main'; exit 1; }
SHA=$(git rev-parse --short HEAD); log "HEAD=$SHA"

log '== backup current binary =='
cp target/release/meshd "$HOME/meshd.pre-$SHA.bak" 2>/dev/null \
  && log "backup: ~/meshd.pre-$SHA.bak" || log 'WARN no previous binary to back up'

log '== build =='
touch crates/meshd/build.rs   # force a fresh SHA stamp (BUILD.md stale-build guard)
if ! cargo build --release -p lattice-meshd >> "$OUT" 2>&1; then log 'FAIL build'; exit 1; fi
if [ "$(strings target/release/meshd | grep -c "build $SHA")" -eq 0 ]; then
  log "FAIL stale binary (no 'build $SHA' stamp)"; exit 1
fi
log "PASS built meshd $SHA"

log '== restart service =='
sudo -n true 2>/dev/null || { log 'FAIL sudo needs a password (run: sudo -v first, or visudo NOPASSWD)'; exit 1; }
sudo systemctl restart lattice-meshd
ok=no; for i in $(seq 1 30); do [ -S /tmp/lattice-meshd.sock ] && ok=yes && break; sleep 1; done
log "socket: $ok"
sleep 3

log '== verify =='
grep -aE 'version v.* build' /tmp/lattice-meshd.log 2>/dev/null | tail -1 >> "$OUT"
python3 "$REPO/scripts/lattice" ls >> "$OUT" 2>&1 || log 'WARN lattice ls failed'
systemctl is-active lattice-meshd >> "$OUT" 2>&1
log '== done =='
