#!/usr/bin/env bash
# TJ-1p — T1552.005 poller-compromise attack: the S1v IMDS probe executed FROM
# the legitimate poller container itself, direct exec (no shell wrapper), curl
# argv character-identical to the poller's own loop. Every arm is predicted
# silent (method doc Part D): the edge (poller->IMDS), the process (curl) and
# the image (nginx) are all inside the learned baseline; auditd's argv and the
# net tuple are identical to the standing benign background. This is the
# recorded blind spot of identity-scoped baselines — evading them requires
# compromising the workload whose history already contains the action.
# Safe: link-local endpoint, attempt only.
set -euo pipefail
cd "$(dirname "$0")"
./setup-listener.sh >/dev/null
./setup-imds-poller.sh >/dev/null

echo "=== TJ-1p begin $(date -u +%FT%TZ)"
docker exec tj-imds-poller curl -s -m 2 http://169.254.169.254/latest/meta-data/ \
  || echo "(timeout/refused on non-AWS rig — expected; the attempt is the observable)"
echo "=== TJ-1p end   $(date -u +%FT%TZ)"
