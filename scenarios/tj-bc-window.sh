#!/usr/bin/env bash
# tj-bc-window.sh — the benign-change round (D12): a single BENIGN window during
# which a new, legitimate, network-active workload is deployed mid-window. NOT an
# attack round: the measurement is the count of first-ever alerts the deployment
# produces — the false-positive cost of learned baselines, which decides the
# D12 age-out fallback.
#
# Window: benign twin first (~10 s); at +30 s deploy tj-health (nginx image,
# curls the listener every 5 s — same mechanics as the IMDS poller, different
# destination); run to +90 s; symmetric 25 s soak; collects itself as id "bc".
set -euo pipefail
cd "$(dirname "$0")"
SOAK="${SOAK:-25}"
PROBE_LOG="${PROBE_LOG:-$HOME/probe/tj-probe.ndjson}"

probe_alive() { [ -s "$PROBE_LOG" ] || return 1
  local n0; n0=$(wc -l < "$PROBE_LOG"); sleep 7
  [ "$(wc -l < "$PROBE_LOG")" -gt "$n0" ]; }
probe_alive || { echo "ABORT: probe not running/growing ($PROBE_LOG)" >&2; exit 1; }

# Same quiet rule as tj-pair.sh: this window must not contain any residue of a
# previous pair's attack (late SLIRP RST ~84 s later), or its alerts would
# inflate the benign-change FP count.
QUIET="${QUIET:-180}"
LAST="$HOME/evidence/.tj-last-attack-end"
if [ -s "$LAST" ]; then
  wait_s=$(( $(cat "$LAST") + QUIET - $(date +%s) ))
  if [ "$wait_s" -gt 0 ]; then echo "quiet period: waiting ${wait_s}s since previous attack"; sleep "$wait_s"; fi
fi

./setup-listener.sh >/dev/null
./setup-imds-poller.sh >/dev/null
LISTENER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tj-listener)

t0=$(date -u +%FT%TZ)
echo "=== BC window begin $t0"
bash tj-1-benign.sh >/dev/null
echo "--- deploying new legitimate workload tj-health at $(date -u +%T)"
docker run -d --name tj-health nginx \
  sh -c "while true; do curl -s -m 2 http://$LISTENER_IP/ >/dev/null 2>&1 || true; sleep 5; done"
sleep 60
t1=$(date -u +%FT%TZ)
echo "=== BC window end   $t1"
echo "soak ${SOAK}s"; sleep "$SOAK"
bash collect-evidence.sh bc "$t0" "$t1" "benign-change"
echo "tj-health: $(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tj-health)"
