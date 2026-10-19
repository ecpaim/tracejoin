#!/usr/bin/env bash
# TJ-1s — T1552.005 shared-netns sidecar attack: a foothold container sharing the
# legitimate poller's network namespace (--network container:tj-imds-poller —
# exactly how containers share a Kubernetes pod's netns) runs the S1v IMDS probe
# with the poller's exact curl argv. On the wire the flow is indistinguishable
# from the poller's own traffic (same source IP 172.17.0.4, same destination,
# same comm): the net arm, the static IP map and the live IP map (which resolves
# the shared IP to the netns OWNER, as pod-level attribution does) all attribute
# it to the poller. Only the connect-point record separates: the connecting
# cgroup is the attacker's container, not the poller's.
# Prediction (method doc Part D): ids-ipstatic/iplive silent, ids-join fires —
# the measured join-required cell. Safe: link-local endpoint, attempt only.
set -euo pipefail
cd "$(dirname "$0")"
./setup-listener.sh >/dev/null
./setup-imds-poller.sh >/dev/null

echo "=== TJ-1s begin $(date -u +%FT%TZ)"
docker rm -f tj-svictim >/dev/null 2>&1 || true
docker run -d --name tj-svictim --network container:tj-imds-poller nginx >/dev/null
docker exec tj-svictim curl -s -m 2 http://169.254.169.254/latest/meta-data/ \
  || echo "(timeout/refused on non-AWS rig — expected; the attempt is the observable)"
echo "=== TJ-1s end   $(date -u +%FT%TZ)"
