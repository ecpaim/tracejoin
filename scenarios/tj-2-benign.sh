#!/usr/bin/env bash
# TJ-2 benign twin — mirrors tj-2-t1048.003-bash-tcp-exfil.sh with a legitimate transfer.
#
#   Attack : bash built-ins only — /dev/tcp GET whose URI carries runtime-base64 data
#            (deliberately NO execve of curl/wget)
#   Benign : bash in the same container reads the same local files, then transfers
#            via curl to the local listener
#
# Mechanics matched: same actor (bash inside tj-victim), same file reads, same
# destination host — so a "bash in container did a transfer" host predicate fires
# benign. The attack's candidate distinguishing information is the mechanism
# (socket without any execve of a transfer tool) and the on-wire URI payload.
# Run during the BENIGN window of a scenario-2 round. Safe: local listener only.
set -euo pipefail
cd "$(dirname "$0")"
./setup-listener.sh >/dev/null
./setup-imds-poller.sh >/dev/null
LISTENER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tj-listener)

echo "=== TJ-2 benign begin $(date -u +%FT%TZ)"
docker exec tj-victim bash -c "
  cat /etc/hostname /proc/self/cgroup >/dev/null 2>&1 || true
  curl -s --max-time 3 http://$LISTENER_IP/ >/dev/null || true
" || echo "(benign transfer failed — check tj-listener)"
sleep 6   # poller soak: the benign window must contain the IMDS poller's signature
echo "=== TJ-2 benign end   $(date -u +%FT%TZ)"
