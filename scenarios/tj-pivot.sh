#!/usr/bin/env bash
# TJ-PIVOT — lateral movement / first-ever identity-pair edge (T1021-class).
# The attacker (resident in tj-victim) touches the credential-agent workload
# (tj-imds-poller) — probing a peer container, the precursor to compromising
# the trusted workload ("couldn't the attacker just attack the poller?").
#
# Mechanics are matched to the benign twin (tj-1-benign.sh): same actor
# (docker exec tj-victim bash -c curl), same flags; the ONLY differing field is
# the destination (the poller instead of the listener). The connection is
# refused (the poller runs no listener) — the attempt is the observable, and
# Zeek logs the unanswered flow at attempt-timeout (hence the 25 s soak before
# collection).
#
# Pre-registered prediction (docs/threat-model-method.md, Part D): the benign
# graph is measured at exactly two edges (victim->listener, poller->IMDS; zero
# victim->poller across all four benign windows). This attack creates the
# first-ever victim<->poller edge. Single arms separate only via destination
# literals (attacker-chosen) or the composite tuple — an IP-pair allowlist;
# the identity-pair graph predicate of the IDS fires on the edge.
# Safe: intra-rig traffic only.
set -euo pipefail
cd "$(dirname "$0")"
./setup-listener.sh >/dev/null
./setup-imds-poller.sh >/dev/null
POLLER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tj-imds-poller)

echo "=== TJ-PIVOT begin $(date -u +%FT%TZ)"
docker exec tj-victim bash -c "curl -s --max-time 3 http://$POLLER_IP/" \
  || echo "(connection refused — expected; the attempt is the observable)"
echo "=== TJ-PIVOT end   $(date -u +%FT%TZ)"
