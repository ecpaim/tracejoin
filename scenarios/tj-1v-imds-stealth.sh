#!/usr/bin/env bash
# TJ-1v — T1552.005 stealth variant: IMDS probe from the web-server container with
# argv normalized to be character-identical to the benign IMDS poller (same flags
# -s -m 2, same roll-up path /latest/meta-data/). No shell wrapper — direct exec —
# so the only in-window actor execve is the poller-identical curl itself.
# Purpose: adversary-variation round (method doc Part D predictions, S1v row) —
# tests whether round-1's auditd argv separator survives adversary mimicry.
# Safe: link-local endpoint; the attempt is the observable.
set -euo pipefail
cd "$(dirname "$0")"
./setup-listener.sh >/dev/null

echo "=== TJ-1v begin $(date -u +%FT%TZ)"
docker exec tj-victim curl -s -m 2 http://169.254.169.254/latest/meta-data/ \
  || echo "(timeout/refused on non-AWS rig — expected; the attempt is the observable)"
echo "=== TJ-1v end   $(date -u +%FT%TZ)"