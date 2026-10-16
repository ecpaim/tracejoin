#!/usr/bin/env bash
# tj-pair.sh — run ONE paired round (benign window, then attack window) under the
# 2026-10-16 protocol: symmetric 25 s soak before both collects, probe must be live.
# Run INSIDE THE GUEST from ~/scenarios, after setup-listener/poller + tj-capture-start.
#
# Usage: bash tj-pair.sh <id> <benign-script> <attack-script> <technique>
#   e.g. bash tj-pair.sh 1v tj-1-benign.sh tj-1v-imds-stealth.sh T1552.005
set -euo pipefail
cd "$(dirname "$0")"
ID="${1:?usage: tj-pair.sh <id> <benign-script> <attack-script> <technique>}"
BEN="${2:?benign script}"; ATK="${3:?attack script}"; TECH="${4:?technique}"
SOAK="${SOAK:-25}"
PROBE_LOG="${PROBE_LOG:-$HOME/probe/tj-probe.ndjson}"

probe_alive() { # the probe log must exist and grow (poller connects every 5 s)
  [ -s "$PROBE_LOG" ] || return 1
  local n0; n0=$(wc -l < "$PROBE_LOG"); sleep 7
  [ "$(wc -l < "$PROBE_LOG")" -gt "$n0" ]
}
probe_alive || { echo "ABORT: probe not running/growing ($PROBE_LOG) — start it in terminal 2" >&2; exit 1; }

# Inter-pair quiet period (amendment 2026-10-16b): B's net window starts 60 s before
# t_b0, and on this rig every unanswered IMDS SYN gets a late SLIRP RST ~84 s later
# that Zeek logs as a new conn record. Back-to-back pairs leaked the previous attack
# into the next benign window (replicate 2: 1-benign, p-benign, 3-benign). Wait until
# QUIET seconds have passed since the previous pair's attack ended.
QUIET="${QUIET:-180}"
LAST="$HOME/evidence/.tj-last-attack-end"
if [ -s "$LAST" ]; then
  wait_s=$(( $(cat "$LAST") + QUIET - $(date +%s) ))
  if [ "$wait_s" -gt 0 ]; then echo "quiet period: waiting ${wait_s}s since previous attack"; sleep "$wait_s"; fi
fi

echo "##### pair $ID: benign window ($BEN)"
t_b0=$(date -u +%FT%TZ); bash "$BEN"; t_b1=$(date -u +%FT%TZ)
echo "soak ${SOAK}s"; sleep "$SOAK"
bash collect-evidence.sh "$ID-benign" "$t_b0" "$t_b1" "$TECH"

echo "##### pair $ID: attack window ($ATK)"
t0=$(date -u +%FT%TZ); bash "$ATK"; t1=$(date -u +%FT%TZ)
date +%s > "$LAST"
echo "soak ${SOAK}s"; sleep "$SOAK"
bash collect-evidence.sh "$ID" "$t0" "$t1" "$TECH"

echo "##### pair $ID done: benign $t_b0→$t_b1, attack $t0→$t1"
jq -c '{scenario, window, probe}' "$HOME/evidence/scenario-$ID-benign/meta.json" "$HOME/evidence/scenario-$ID/meta.json"
