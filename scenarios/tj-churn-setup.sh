#!/usr/bin/env bash
# tj-churn-setup.sh — the IP-churn step of the S-churn round (D18 keying
# ablation): recreate tj-victim and tj-imds-poller in the OPPOSITE order, so
# their IP addresses swap (Docker assigns the lowest free address in creation
# order; tj-listener keeps .3). After this: poller = 172.17.0.2, victim =
# 172.17.0.4 — the static rig-map and any stale IP->workload attribution are
# now wrong; the live map and the probe's cgroup identity are not.
#
# The poller is recreated with the exact same command as setup-imds-poller.sh.
# Run INSIDE THE GUEST, BEFORE the churn pair (tj-pair.sh churn ...), with the
# probe and capture already live.
set -euo pipefail
cd "$(dirname "$0")"

./setup-imds-poller.sh >/dev/null   # idempotent: ensures it exists before the swap
echo "before: victim=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tj-victim) poller=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tj-imds-poller)"
docker rm -f tj-victim tj-imds-poller >/dev/null
INTERVAL="${POLL_INTERVAL:-5}"
docker run -d --name tj-imds-poller nginx \
  sh -c "while true; do curl -s -m 2 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1 || true; sleep $INTERVAL; done"
docker run -d --name tj-victim nginx
VIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tj-victim)
PIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tj-imds-poller)
echo "after : victim=$VIP poller=$PIP"
if [ "$PIP" = "172.17.0.4" ] && [ "$VIP" = "172.17.0.2" ]; then
  echo "CHURN FAILED: addresses did not swap — investigate before running the pair" >&2; exit 1
fi
echo "churn ok: static rig-map (172.17.0.2->tj-victim, 172.17.0.4->tj-imds-poller) is now wrong by construction"
