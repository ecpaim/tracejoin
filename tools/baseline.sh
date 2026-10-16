#!/usr/bin/env bash
# baseline.sh — identity-scoped learned baselines (CHECKPOINT D11/D12) and the
# IDS evaluation arm.
#
# Usage:
#   tools/baseline.sh learn [benign-dir ...]   # default: evidence/scenario-*-benign
#   tools/baseline.sh evaluate <evidence-dir>  # prints firing predicates, one per line
#   tools/baseline.sh show                     # print the learned baseline store
#
# Design (D11/D12):
#   - graph baseline: identity-pair edges learned from benign Zeek conn windows;
#     FIRST-EVER semantics (edges never age out; the age-out fallback is D12 and
#     is decided by the benign-change FP round, not by this tool).
#   - destination baseline: per-workload destination sets (identity-scoped).
#   - behavior baseline (per-image argv): DEFERRED — requires identity-attributed
#     argv, i.e. the Phase-4 recorder or Tetragon events; the offline IP join
#     cannot attribute execve events to containers (pids are not stable keys).
#     Recorded honestly rather than approximated by content matching.
#
# Identity resolution: baselines/rig-map.json maps rig IPs to workload names —
# the offline join, exact on the fixed 3-container rig; replaced by cgroup
# resolution when the recorder lands. Consequence for interpretation: S2/S3-style
# attacks whose edges are IN the benign graph (victim->listener) are correctly
# silent under graph/destination predicates — they are the behavior predicate's
# cases (deferred), matching the pre-registered predictions.
set -euo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAP="$BASE_DIR/baselines/rig-map.json"
BOUT="$BASE_DIR/baselines/baselines.json"

ident() { jq -r --arg ip "$1" '.[$ip].name // "unknown"' "$MAP"; }

edges_of() { # dir -> one "orig-name>resp-name:port" per conn row
  local d="$1" ts o op r p rest
  [ -s "$d/raw/zeek-conn.window.txt" ] || return 0
  while IFS=$'\t' read -r ts o op r p rest; do
    [ -n "${o:-}" ] && [ -n "${r:-}" ] && printf '%s>%s:%s\n' "$(ident "$o")" "$(ident "$r")" "$p"
  done < "$d/raw/zeek-conn.window.txt"
}

cmd_learn() {
  local dirs=() d tmp n
  if [ $# -gt 0 ]; then dirs=("$@"); else
    for d in "$BASE_DIR"/evidence/scenario-*-benign; do [ -d "$d" ] && dirs+=("$d"); done
  fi
  [ "${#dirs[@]}" -gt 0 ] || { echo "baseline: no benign dirs found" >&2; exit 1; }
  n=${#dirs[@]}
  tmp=$(mktemp)
  for d in "${dirs[@]}"; do
    edges_of "$d"
  done | sort -u > "$tmp"
  mkdir -p "$BASE_DIR/baselines"
  jq -n --arg when "$(date -u +%FT%TZ)" \
        --arg n "$n" \
        --argjson edges "$(jq -R -s 'split("\n") | map(select(length > 0))' "$tmp")" '
    ($edges | map(capture("^(?<o>[^>]+)>(?<r>[^:]+):(?<p>.+)$"))) as $parsed |
    {
      learned_at: $when,
      learned_from: ($n + " benign windows"),
      edges: $edges,
      destinations: ($parsed | group_by(.o)
                           | map({ key: .[0].o, value: (map("\(.r):\(.p)") | unique) })
                           | from_entries),
      notes: ["first-ever edge semantics (D12 fallback pending benign-change round)",
              "behavior predicate deferred: needs identity-attributed argv (Phase-4 recorder)"]
    }' > "$BOUT"
  rm -f "$tmp"
  echo "learned $BOUT ($n benign windows):"
  jq -r '.edges[] | "  edge: \(.)"' "$BOUT"
  jq -r '.destinations | to_entries[] | "  dest[\(.key)]: \(.value | join(", "))"' "$BOUT"
}

cmd_evaluate() {
  local d="$1" e o rp
  [ -s "$BOUT" ] || { echo "baseline: run 'learn' first" >&2; exit 1; }
  [ -d "$d" ] || { echo "baseline: no such dir: $d" >&2; exit 1; }
  edges_of "$d" | sort -u | while IFS= read -r e; do
    [ -n "$e" ] || continue
    o="${e%%>*}"; rp="${e#*>}"
    if ! jq -e --arg e "$e" '.edges | index($e)' "$BOUT" >/dev/null; then
      echo "IDS-FIRE graph $e"
    fi
    if ! jq -e --arg o "$o" --arg rp "$rp" '(.destinations[$o] // []) | index($rp)' "$BOUT" >/dev/null; then
      echo "IDS-FIRE dest $o -> $rp"
    fi
  done
}

case "${1:-}" in
  learn)    shift; cmd_learn "$@" ;;
  evaluate) shift; cmd_evaluate "${1:?usage: baseline.sh evaluate <dir>}" ;;
  show)     [ -s "$BOUT" ] && jq . "$BOUT" || { echo "no baseline store yet" >&2; exit 1; } ;;
  *) echo "usage: tools/baseline.sh {learn [dirs...] | evaluate <dir> | show}" >&2; exit 1 ;;
esac
