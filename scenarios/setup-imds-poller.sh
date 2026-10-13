#!/usr/bin/env bash
# Start the legitimate IMDS-poller container — standing benign background (negative
# class) for every scenario round. Idempotent.
#
# Rationale: in production, credential agents and SDK providers poll the instance
# metadata service constantly — the reason vendor IMDS rules ship exclusion macros
# (falco's `not ec2_metadata_containers`; allowlists like gke-metadata-server in the
# deployed ruleset). Its signature — comm=curl, subj=docker-default, dst
# 169.254.169.254:80 — is identical to scenario 1's attack on every arm that lacks
# container identity. That indistinguishability is the point.
#
# POLL_INTERVAL defaults to 5 s so the signature lands inside every recorded window
# (a 60 s cadence would miss short windows and fake separation). Production cadence
# is slower — a benign-class design note, see CHECKPOINT.md Phase 1.
set -euo pipefail

if ! docker info >/dev/null 2>&1; then
  echo "docker not running" >&2
  exit 1
fi

INTERVAL="${POLL_INTERVAL:-5}"
docker inspect tj-imds-poller >/dev/null 2>&1 \
  || docker run -d --name tj-imds-poller nginx \
       sh -c "while true; do curl -s -m 2 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1 || true; sleep $INTERVAL; done"

echo "imds-poller: $(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tj-imds-poller) (interval ${INTERVAL}s)"
