#!/usr/bin/env bash
# baseline.sh v2 — identity-scoped learned baselines (D10/D11/D18) and the IDS
# evaluation arms, consumed from the eBPF connect-point record (probe NDJSON).
#
# Usage:
#   tools/baseline.sh learn <learn-window-dir>   # frozen store -> baselines/baselines.json
#   tools/baseline.sh evaluate <evidence-dir>     # prints firing predicates, one per line
#   tools/baseline.sh show
#   BASELINE_OUT=<file> overrides the store path (validation only).
#
# Design (method doc Part D, "identity-scoped IDS — initial experiment"):
#   - Learning source: the DEDICATED learning window only (scenario id "learn"),
#     never the evaluation windows; the store is frozen at learn time.
#     False positives are therefore always out-of-sample.
#   - Scope: container-originated events only (cg starts with "docker-"),
#     matching the monitored estate.
#   - Predicates (first-ever semantics; D12 age-out fallback is decided by the
#     benign-change round, not here):
#       P-edge      (src workload -> dst:port)          — all arms
#       P-procflow  (src workload | comm -> dst:port)   — join arm only
#       P-exec      (image | new binary)                — join arm only
#   - Arms = identity-keying ablation over the SAME probe events (D18):
#       ipstatic  src keyed by baselines/rig-map.json (the vendor allowlist pattern)
#       iplive    src keyed by the window's own raw/identity.ndjson (collect-time
#                 IP->container map; the flow-observability competitor)
#       join      src keyed by the probe's cgroup (connect-point identity)
#     The ip arms carry the information set of flow sensors + an identity map:
#     no per-connection process context — the measured schema gap of the
#     previous chapter. Destination naming is uniform across arms (container
#     name from the window's identity snapshot, else the raw IP).
#   - Honest failure: a window without probe data makes learn/evaluate exit
#     non-zero — an absent probe must never surface as a silent IDS cell.
set -euo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAP="$BASE_DIR/baselines/rig-map.json"
BOUT="${BASELINE_OUT:-$BASE_DIR/baselines/baselines.json}"

# --- event -> predicate-key mapping, per arm ----------------------------------------
arm_keys() { # <dir> <arm>  ->  "P-xxx <key>" lines (caller dedups)
  local d="$1" arm="$2" probe="$1/raw/probe.window.ndjson" ident="$1/raw/identity.ndjson"
  [ -s "$probe" ] || { echo "baseline: no probe window in $d (probe not live) — refusing a silent cell" >&2; return 2; }
  [ -s "$ident" ] || { echo "baseline: no identity snapshot in $d" >&2; return 2; }
  case "$arm" in
    ipstatic)
      jq -r --slurpfile m "$MAP" --slurpfile idn "$ident" '
        def srcn($ip): ($m[0][$ip].name // $ip);
        def dstn($ip): (($idn[]? | select((.ips // []) | index($ip)) | .name) // $ip);
        select(.ev == "connect" and ((.cg // "") | startswith("docker-")))
        | "P-edge " + srcn(.saddr) + ">" + dstn(.daddr) + ":" + (.dport | tostring)' "$probe" ;;
    iplive)
      jq -r --slurpfile idn "$ident" '
        def srcn($ip): (($idn[]? | select((.ips // []) | index($ip)) | .name) // $ip);
        def dstn($ip): (($idn[]? | select((.ips // []) | index($ip)) | .name) // $ip);
        select(.ev == "connect" and ((.cg // "") | startswith("docker-")))
        | "P-edge " + srcn(.saddr) + ">" + dstn(.daddr) + ":" + (.dport | tostring)' "$probe" ;;
    join)
      jq -r --slurpfile idn "$ident" '
        def cg2($cg): ($idn[]? | select(.id | startswith($cg[7:])) | .name);
        def cgi($cg): ($idn[]? | select(.id | startswith($cg[7:])) | .image);
        def srcn($cg): (cg2($cg) // ("unresolved:" + $cg));
        def dstn($ip): (($idn[]? | select((.ips // []) | index($ip)) | .name) // $ip);
        select(((.cg // "") | startswith("docker-")))
        | if .ev == "connect" then
            ("P-edge " + srcn(.cg) + ">" + dstn(.daddr) + ":" + (.dport | tostring)),
            ("P-procflow " + srcn(.cg) + "|" + (.comm // "?") + ">" + dstn(.daddr) + ":" + (.dport | tostring))
          elif .ev == "exec" then
            ("P-exec " + (cgi(.cg) // "?") + "|" + (.file // "?"))
          else empty end' "$probe" ;;
    *) echo "baseline: unknown arm $arm" >&2; return 2 ;;
  esac
}

cmd_learn() {
  local d="${1:?usage: baseline.sh learn <learn-window-dir>}" t arm
  t=$(mktemp -d)
  for arm in ipstatic iplive join; do
    arm_keys "$d" "$arm" | sort -u > "$t/$arm" || return 2
  done
  mkdir -p "$(dirname "$BOUT")"
  jq -n --arg when "$(date -u +%FT%TZ)" --arg from "$d" \
        --argjson ipstatic "$(jq -R -s 'split("\n") | map(select(length > 0))' "$t/ipstatic")" \
        --argjson iplive   "$(jq -R -s 'split("\n") | map(select(length > 0))' "$t/iplive")" \
        --argjson join     "$(jq -R -s 'split("\n") | map(select(length > 0))' "$t/join")" '
    { learned_at: $when,
      learned_from: $from,
      scope: "container-originated probe events (cg ^docker-); first-ever semantics; D12 age-out pending the benign-change round",
      arms: { ipstatic: {keys: $ipstatic},
              iplive:   {keys: $iplive},
              join:     {keys: $join} },
      notes: ["ip arms = flow sensors + identity map: no per-connection process context (schema gap, previous chapter)",
              "destination naming uniform: container name from the window identity snapshot, else raw IP",
              "learn source = the dedicated learning window only; FP are out-of-sample by construction"] }' > "$BOUT"
  rm -rf "$t"
  echo "learned (frozen) $BOUT from $d:"
  for arm in ipstatic iplive join; do
    printf '  %-9s %s keys, e.g. %s\n' "$arm" "$(jq -r --arg a "$arm" '.arms[$a].keys | length' "$BOUT")" \
      "$(jq -r --arg a "$arm" '.arms[$a].keys[0] // "-"' "$BOUT")"
  done
}

cmd_evaluate() {
  local d="${1:?usage: baseline.sh evaluate <dir>}" arm known
  [ -s "$BOUT" ] || { echo "baseline: run 'learn' first" >&2; exit 1; }
  [ -d "$d" ] || { echo "baseline: no such dir: $d" >&2; exit 1; }
  known=$(mktemp)
  for arm in ipstatic iplive join; do
    jq -r --arg a "$arm" '.arms[$a].keys[]' "$BOUT" | sort -u > "$known"
    arm_keys "$d" "$arm" | sort -u | comm -23 - "$known" | sed "s/^/IDS-FIRE $arm /"
  done
  rm -f "$known"
}

case "${1:-}" in
  learn)    shift; cmd_learn "$@" ;;
  evaluate) shift; cmd_evaluate "$@" ;;
  show)     [ -s "$BOUT" ] && jq . "$BOUT" || { echo "no baseline store yet" >&2; exit 1; } ;;
  *) echo "usage: tools/baseline.sh {learn <learn-window-dir> | evaluate <dir> | show}" >&2; exit 1 ;;
esac
