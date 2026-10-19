#!/usr/bin/env bash
# tj-learn-window.sh — the IDS LEARNING window (L): the dedicated, frozen-source
# window the identity-scoped baselines are learned from (method doc Part D,
# "identity-scoped IDS — initial experiment"). NOT a paired round: benign only.
#
# Runs the three benign twins in a loop (LEARN_ITERS iterations, default 8,
# ~4-5 min) with the standing benign background (IMDS poller every 5 s, cron).
# Ends with the symmetric 25 s soak and collects itself as scenario id "learn".
# Run INSIDE THE GUEST, from ~/scenarios, with the probe and capture already live.
set -euo pipefail
cd "$(dirname "$0")"
LEARN_ITERS="${LEARN_ITERS:-8}"
SOAK="${SOAK:-25}"
PROBE_LOG="${PROBE_LOG:-$HOME/probe/tj-probe.ndjson}"

probe_alive() { [ -s "$PROBE_LOG" ] || return 1
  local n0; n0=$(wc -l < "$PROBE_LOG"); sleep 7
  [ "$(wc -l < "$PROBE_LOG")" -gt "$n0" ]; }
probe_alive || { echo "ABORT: probe not running/growing ($PROBE_LOG) — start it before the capture" >&2; exit 1; }

./setup-listener.sh >/dev/null
./setup-imds-poller.sh >/dev/null

t0=$(date -u +%FT%TZ)
echo "=== LEARN window begin $t0 (iters=$LEARN_ITERS)"
for i in $(seq "$LEARN_ITERS"); do
  echo "--- learn iteration $i/$LEARN_ITERS $(date -u +%T)"
  bash tj-1-benign.sh >/dev/null
  bash tj-2-benign.sh >/dev/null
  bash tj-3-benign.sh >/dev/null
done
t1=$(date -u +%FT%TZ)
echo "=== LEARN window end   $t1"
echo "soak ${SOAK}s"; sleep "$SOAK"
bash collect-evidence.sh learn "$t0" "$t1" "learning-window"
