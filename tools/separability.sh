#!/usr/bin/env bash
# separability.sh — apply the Part D separability criterion (docs/threat-model-method.md)
# to one paired observation, print the per-arm report, and persist it as
# <attack-dir>/separability.md (next to curated.md) on every run.
#
# Usage: tools/separability.sh <attack-dir> <benign-dir>
#   e.g. tools/separability.sh evidence/scenario-1 evidence/scenario-1-benign
#
# Arms: auditd (host syscall), Falco (host runtime policy), net (Zeek+Suricata).
# Per arm it extracts (field,value) literals from each window, diffs A−B, and reports
# tier-1 separating literals plus a suggested verdict per the decision matrix.
#
# Scoping decisions (documented, applied to both windows equally):
# - auditd: only events with subj=docker-default (the monitored estate is containers —
#   README threat model; this also deterministically excludes collector-harness noise,
#   which runs subj=unconfined and leaks into windows on second boundaries).
# - net: composite literals (full argv line, conn tuple) capture the common tier-2
#   combinations; ephemeral orig ports and timestamps are never literals.
# - tier-2 (novel combination) beyond these composites remains a manual step.
set -euo pipefail

IDS=0
if [ "${1:-}" = "--ids" ]; then IDS=1; shift; fi
A="${1:?usage: separability.sh [--ids] <attack-dir> <benign-dir>}"
B="${2:?usage: separability.sh [--ids] <attack-dir> <benign-dir>}"
REPORT=""

# every report line goes to stdout AND accumulates for the persisted file
emit() { printf '%s\n' "$*"; REPORT+="$*"$'\n'; }

# --- literal extractors ------------------------------------------------------------
auditd_pairs() { # dir
  local d="$1" filtered
  filtered=$(cat "$d/raw/auditd-execve.txt" "$d/raw/auditd-connect.txt" 2>/dev/null \
  | awk '/^----/ { if (buf ~ /subj=docker-default/) printf "%s", buf; buf=""; next }
         { buf = buf $0 "\n" }
         END { if (buf ~ /subj=docker-default/) printf "%s", buf }' || true)
  [ -n "$filtered" ] || return 0
  {
    # granular tokens (values have no spaces)
    printf '%s\n' "$filtered" | grep -aoE '(comm|exe|subj|syscall|key|laddr|lport|saddr_fam)=[^ ]+'
    # full argv as one composite literal (timestamp stripped; argv may contain spaces)
    printf '%s\n' "$filtered" | grep -a '^type=EXECVE' | sed -E 's/^type=EXECVE msg=audit\([^)]*\) : /execve /'
  } || true
}

falco_pairs() { # dir
  local d="$1"
  grep -a . "$d/raw/falco.txt" 2>/dev/null || true
}

net_pairs() { # dir
  local d="$1"
  if [ -s "$d/raw/zeek-conn.window.txt" ]; then
    awk -F'\t' 'NF>=7 {print "conn=" $2 "->" $4 ":" $5; print "proto=" $6; if ($7!="-") print "service=" $7}' "$d/raw/zeek-conn.window.txt"
  fi
  if [ -s "$d/raw/zeek-http.window.txt" ]; then
    awk -F'\t' 'NF>=7 {print "method=" $4; print "host=" $5; print "uri=" substr($6,1,48); print "ua=" $7}' "$d/raw/zeek-http.window.txt"
  fi
  if [ -s "$d/raw/suricata-eve-window.json" ]; then
    jq -r '"stype=" + (.event_type // "-"),
           "sconn=" + (.src_ip // "-") + "->" + (.dest_ip // "-") + ":" + ((.dest_port // 0)|tostring),
           (if .http.http_method then "smethod=" + .http.http_method else empty end),
           (if .http.hostname   then "shost="   + .http.hostname   else empty end),
           (if .http.url         then "suri="    + .http.url[0:48] else empty end)' \
      "$d/raw/suricata-eve-window.json" 2>/dev/null || true
  fi
}

# --- IDS arm (--ids): firing predicates from the learned baseline store ----------
# Currently keyed by baselines/rig-map.json (static IP -> workload), hence labelled
# "ids-ip": on this rig it carries the same information as the net arm's src
# tuple. It is NOT the join measurement; the cgroup-keyed arm lands with the probe.
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ids_pairs() { # dir -> firing predicates as literals (requires tools/baseline.sh learn)
  "$BASE_DIR/tools/baseline.sh" evaluate "$1"
}
if [ "$IDS" = 1 ]; then
  # fail loudly: a broken evaluator must never surface as a "0 events" cell
  for d in "$A" "$B"; do
    "$BASE_DIR/tools/baseline.sh" evaluate "$d" >/dev/null \
      || { echo "separability: IDS evaluator failed on $d — no IDS cell reported" >&2; exit 2; }
  done
fi

# --- arm evaluation ----------------------------------------------------------------
arm() { # name extractor -> rc 0=separates, 1=no tier-1 separation, 3=no events in A
  local name="$1" extractor="$2" ta tb novel na nb n
  ta=$(mktemp); tb=$(mktemp)
  "$extractor" "$A" | sort -u > "$ta"
  "$extractor" "$B" | sort -u > "$tb"
  na=$(wc -l < "$ta"); nb=$(wc -l < "$tb")
  novel=$(comm -23 "$ta" "$tb" 2>/dev/null || true)
  n=$(printf '%s\n' "$novel" | grep -c . || true)

  if [ "$na" -eq 0 ] && [ "${name#ids}" != "$name" ]; then
    # an IDS emits alerts, not telemetry: no alert on A = does not separate
    emit "$(printf '%-7s | silent on A (no predicate fired) -> does NOT separate' "$name")"
    rm -f "$ta" "$tb"; return 1
  elif [ "$na" -eq 0 ]; then
    emit "$(printf '%-7s | NO EVENTS in A (arm blind this window)' "$name")"
  elif [ "$n" -gt 0 ]; then
    emit "$(printf '%-7s | SEPARATES (tier-1): %s novel of %s literals' "$name" "$n" "$na")"
    while IFS= read -r l; do
      [ -n "$l" ] && emit "          A-only: $l"
    done < <(printf '%s\n' "$novel" | grep . | head -12)
  else
    emit "$(printf '%-7s | does NOT separate (no tier-1 literal; tier-2 combination = manual)' "$name")"
  fi
  rm -f "$ta" "$tb"
  [ "$na" -eq 0 ] && return 3
  [ "$n" -gt 0 ] && return 0
  return 1
}

describe() { case "$1" in 0) echo "sep" ;; 3) echo "0-events" ;; *) echo "no" ;; esac; }

emit "=== separability: A=$(basename "$A") vs B=$(basename "$B") ==="
ra=0; arm auditd auditd_pairs || ra=$?
rf=0; arm falco  falco_pairs  || rf=$?
rn=0; arm net    net_pairs    || rn=$?
ri=3
if [ "$IDS" = 1 ]; then ri=0; arm ids-ip ids_pairs || ri=$?; fi

emit "--- verdict (suggested) ---"
IDSSTAT=""
if [ "$IDS" = 1 ]; then IDSSTAT=" ids-ip=$(describe "$ri")"; fi
if [ "$ra" = 0 ] || [ "$rf" = 0 ] || [ "$rn" = 0 ]; then
  if [ "$ra" = 0 ] && [ "$rn" = 0 ]; then v="covered-both"
  elif [ "$ra" = 0 ]; then v="covered-host-only (auditd)"
  elif [ "$rf" = 0 ]; then v="covered-host-only (eBPF)"
  else v="covered-network-only"; fi
  emit "VERDICT: $v  [auditd=$(describe "$ra") falco=$(describe "$rf") net=$(describe "$rn")$IDSSTAT]"
elif [ "$ri" = 0 ]; then
  emit "VERDICT: no single sensor arm separates; only ids-ip does (IP-keyed: NOT a join measurement)  [auditd=$(describe "$ra") falco=$(describe "$rf") net=$(describe "$rn")$IDSSTAT]"
else
  emit "VERDICT: no tier-1 separator on any arm -> join-required candidate (tier-2 manual) or blind-both$IDSSTAT"
fi

# --- persist the report next to curated.md ------------------------------------------
OUT="$A/separability.md"
{
  echo "# Separability — $(basename "$A") vs $(basename "$B")"
  echo
  echo "- generated: $(date -u +%FT%TZ) by \`tools/separability.sh\`"
  echo "- A (attack window): \`$A\`"
  echo "- B (matched benign window): \`$B\`"
  echo "- criterion: tier-1 novel-literal set difference per arm"
  echo "  (docs/threat-model-method.md Part D); auditd scoped to container-subject"
  echo "  events; composite literals = timestamp-stripped argv lines and conn tuples."
  echo "- raw windows (superset incl. benign background, apparatus, padding) live in"
  echo "  \`raw/\` and \`curated.md\`; this file records the residue only."
  echo
  echo '```'
  printf '%s' "$REPORT"
  echo '```'
} > "$OUT"
echo "residue written: $OUT"
