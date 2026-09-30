#!/usr/bin/env bash
# Start victim (nginx) + listener containers; print their IPs. Idempotent.
set -euo pipefail

if ! docker info >/dev/null 2>&1; then
  echo "docker not running" >&2
  exit 1
fi

docker inspect tj-victim >/dev/null 2>&1 \
  || docker run -d --name tj-victim nginx
docker inspect tj-listener >/dev/null 2>&1 \
  || docker run -d --name tj-listener python:3-slim python -m http.server 80

echo "victim   : $(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tj-victim)"
echo "listener : $(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tj-listener)"
