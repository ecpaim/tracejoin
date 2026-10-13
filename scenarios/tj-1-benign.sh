#!/usr/bin/env bash
# TJ-1 benign twin — mirrors tj-1-t1552.005-imds.sh with a legitimate payload.
#
#   Attack : docker exec tj-victim bash -c "curl -s --max-time 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/"
#   Benign : docker exec tj-victim bash -c "curl -s --max-time 3 http://<tj-listener>/"
#
# Mechanics matched exactly (same actor, same bash -c wrapper, same tool, same flags);
# the only differing fields are the destination in argv and in the connect sockaddr —
# that is deliberate: without the poller, "destination" is the expected separating
# literal; with the poller (identical signature from another container) it is not.
# Run during the BENIGN window of a scenario-1 round. Safe: local listener only.
set -euo pipefail
cd "$(dirname "$0")"
./setup-listener.sh >/dev/null
./setup-imds-poller.sh >/dev/null
LISTENER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tj-listener)

echo "=== TJ-1 benign begin $(date -u +%FT%TZ)"
docker exec tj-victim bash -c "curl -s --max-time 3 http://$LISTENER_IP/" >/dev/null \
  || echo "(listener fetch failed — check tj-listener)"
sleep 6   # poller soak: the benign window must contain the IMDS poller's signature
echo "=== TJ-1 benign end   $(date -u +%FT%TZ)"
