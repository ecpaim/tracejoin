#!/usr/bin/env bash
# s0-check.sh — evaluate the registered S0 kill criteria (docs/threat-model-method.md
# Part D, "S0") for one evidence window: probe connect tuples vs Zeek conn tuples.
#
# Usage: tools/s0-check.sh <evidence-dir> [...]
#
# K1 as registered: over the comparison interval [net_start+5 s, net_end-5 s], the
#   multiset of container-originated (172.17.0.0/16 minus .1) TCP Zeek conn 4-tuples
#   equals the multiset of probe ev=connect 4-tuples, each tuple once per side.
# K2: every container-originated probe connect's cg id-prefix equals the container id
#   that raw/identity.ndjson assigns to its source IP.
# Both snapshots (raw/zeek-conn.log, raw/probe.window.ndjson) are taken at collect
# time, so the interval's effective right edge is the collect time.
# Mismatches are printed with Zeek history / orig_pkts so their cause is visible;
# the verdict line applies the registered criterion verbatim.
set -euo pipefail

check() {
  local d="$1" n0 n1 z p id zk pk
  [ -s "$d/raw/probe.window.ndjson" ] || { echo "$(basename "$d"): no probe data"; return; }
  n0=$(( $(date -d "$(jq -r .net_window.start "$d/meta.json")" +%s) + 5 ))
  n1=$(( $(date -d "$(jq -r .net_window.end "$d/meta.json")" +%s) - 5 ))
  z=$(mktemp); p=$(mktemp); zk=$(mktemp); pk=$(mktemp)

  # Zeek: key \t ts \t history \t orig_pkts   (key = saddr:sport>daddr:dport)
  awk -F'\t' -v a="$n0" -v b="$n1" '
    /^#fields/ { for (i = 2; i <= NF; i++) f[$i] = i - 1; next }
    /^#/ { next }
    { ts = $f["ts"]; oh = $f["id.orig_h"]
      if ($f["proto"] != "tcp" || ts + 0 < a || ts + 0 > b) next
      if (oh !~ /^172\.17\./ || oh == "172.17.0.1") next
      printf "%s:%s>%s:%s\t%s\t%s\t%s\n", oh, $f["id.orig_p"], $f["id.resp_h"], $f["id.resp_p"], ts, $f["history"], $f["orig_pkts"] }
  ' "$d/raw/zeek-conn.log" | sort > "$z"
  jq -r --argjson a "$n0" --argjson b "$n1" '
    select(.ev == "connect" and .ts >= $a and .ts <= $b
           and (.saddr | startswith("172.17.")) and .saddr != "172.17.0.1")
    | "\(.saddr):\(.sport)>\(.daddr):\(.dport)\t\(.ts)\t\(.comm)\t\(.cg[7:19])"
  ' "$d/raw/probe.window.ndjson" | sort > "$p"
  cut -f1 "$z" | sort > "$zk"; cut -f1 "$p" | sort > "$pk"

  local nz np nm zonly ponly dupz dupp
  nz=$(wc -l < "$zk"); np=$(wc -l < "$pk")
  nm=$(comm -12 "$zk" "$pk" | wc -l)
  zonly=$(comm -23 "$zk" "$pk"); ponly=$(comm -13 "$zk" "$pk")
  dupz=$(uniq -d "$zk" | wc -l); dupp=$(uniq -d "$pk" | wc -l)
  echo "== $(basename "$d")  zeek=$nz probe=$np matched=$nm zeek-only=$(printf '%s' "$zonly" | grep -c . || true) probe-only=$(printf '%s' "$ponly" | grep -c . || true) dup-zeek=$dupz dup-probe=$dupp"
  printf '%s\n' "$zonly" | grep . | while IFS= read -r k; do
    grep -F "$k"$'\t' "$z" | awk -F'\t' '{printf "   zeek-only  %s  ts=%s history=%s orig_pkts=%s\n", $1, strftime("%T", $2, 1), $3, $4}'
  done || true
  printf '%s\n' "$ponly" | grep . | while IFS= read -r k; do
    grep -F "$k"$'\t' "$p" | awk -F'\t' '{printf "   probe-only %s  ts=%s comm=%s cg=%s\n", $1, strftime("%T", $2, 1), $3, $4}'
  done || true
  if [ "$nz" -eq "$np" ] && [ "$nm" -eq "$nz" ] && [ "$dupz" -eq 0 ] && [ "$dupp" -eq 0 ]; then
    echo "   K1 (as registered): PASS"
  else
    echo "   K1 (as registered): FAIL"
  fi

  # K2: probe cg id-prefix == identity snapshot container id for that source IP
  local k2bad
  k2bad=$(jq -r 'select(.ev == "connect" and (.saddr | startswith("172.17.")) and .saddr != "172.17.0.1")
                 | "\(.saddr)\t\(.cg)"' "$d/raw/probe.window.ndjson" | sort -u \
    | while IFS=$'\t' read -r ip cg; do
        id=$(jq -r --arg ip "$ip" 'select(.ips | index($ip)) | .id' "$d/raw/identity.ndjson" | head -1)
        if [ -z "$id" ] || [ "${cg#docker-}" != "${id:0:${#cg}-7}" ]; then echo "   K2 miss: $ip cg=$cg id=${id:-none}"; fi
      done)
  if [ -z "$k2bad" ]; then echo "   K2: PASS (all container-originated connects resolve)"; else echo "$k2bad"; echo "   K2: FAIL"; fi
  rm -f "$z" "$p" "$zk" "$pk"
}

# K1' (registered 2026-10-16b, evaluated prospectively): session-level completeness.
#   Reference = the LAST window's raw/zeek-conn.log (full session log at that
#   snapshot) and the full session probe log. Container-originated TCP only.
#   (a) every Zeek record carrying an originator SYN (uppercase S in history) has
#       exactly one probe connect with the same 4-tuple;
#   (b) every probe connect with capture_start <= ts <= snapshot - 10 s has exactly
#       one SYN-bearing Zeek record (capture_start = ts of the first SYN-bearing Zeek
#       record: connects before tj-capture-start are invisible to Zeek by design);
#   responder-only records (history starting '^', orig_pkts = 0) are excluded from
#   (a) and counted; each must belong to a tuple with an earlier probe connect.
session() {
  local last="$1" plog="$2" cut z p
  cut=$(( $(date -d "$(jq -r .collected_at "$last/meta.json")" +%s) - 10 ))
  z=$(mktemp); p=$(mktemp)
  awk -F'\t' '/^#fields/ { for (i = 2; i <= NF; i++) f[$i] = i - 1; next } /^#/ { next }
    $f["proto"] == "tcp" && $f["id.orig_h"] ~ /^172\.17\./ && $f["id.orig_h"] != "172.17.0.1" {
      h = $f["history"]; c = (h ~ /^\^/ && $f["orig_pkts"] == 0) ? "resp-only" : (h ~ /S/ ? "syn" : "other")
      print $f["id.orig_h"] ":" $f["id.orig_p"] ">" $f["id.resp_h"] ":" $f["id.resp_p"] "\t" c }' \
    "$last/raw/zeek-conn.log" | sort > "$z"
  jq -r 'select(.ev == "connect" and (.saddr | startswith("172.17.")) and .saddr != "172.17.0.1")
         | "\(.saddr):\(.sport)>\(.daddr):\(.dport)\t\(.ts)"' "$plog" | sort > "$p"
  local syn pk a b dz dp ro roorph other start
  start=$(awk -F'\t' '/^#fields/ { for (i = 2; i <= NF; i++) f[$i] = i - 1; next } /^#/ { next }
    $f["history"] ~ /S/ { print int($f["ts"]); exit }' "$last/raw/zeek-conn.log")
  syn=$(awk -F'\t' '$2=="syn"{print $1}' "$z" | sort)
  pk=$(cut -f1 "$p" | sort)
  a=$(comm -23 <(printf '%s\n' "$syn" | grep . | sort -u) <(printf '%s\n' "$pk" | sort -u) | grep -c . || true)
  b=$(awk -F'\t' -v s="$start" -v c="$cut" '$2 + 0 >= s && $2 + 0 <= c { print $1 }' "$p" | sort -u \
      | comm -23 - <(printf '%s\n' "$syn" | sort -u) | grep -c . || true)
  dz=$(printf '%s\n' "$syn" | grep . | uniq -d | grep -c . || true)
  dp=$(printf '%s\n' "$pk" | grep . | uniq -d | grep -c . || true)
  ro=$(awk -F'\t' '$2=="resp-only"' "$z" | wc -l)
  roorph=$(awk -F'\t' '$2=="resp-only"{print $1}' "$z" | sort -u | comm -23 - <(printf '%s\n' "$pk" | sort -u) | grep -c . || true)
  other=$(awk -F'\t' '$2=="other"' "$z" | wc -l)
  echo "== session  zeek-syn=$(printf '%s\n' "$syn" | grep -c . || true) probe=$(printf '%s\n' "$pk" | grep -c . || true) resp-only=$ro (orphans=$roorph) other=$other"
  echo "   (a) SYN records without probe connect: $a   dup-zeek-syn=$dz"
  echo "   (b) probe connects in [capture_start $(date -u -d "@$start" +%T), snapshot-10s $(date -u -d "@$cut" +%T)] without SYN record: $b   dup-probe=$dp"
  if [ "$a" -eq 0 ] && [ "$b" -eq 0 ] && [ "$dz" -eq 0 ] && [ "$dp" -eq 0 ] && [ "$roorph" -eq 0 ]; then
    echo "   K1' : PASS"; else echo "   K1' : FAIL"; fi
  rm -f "$z" "$p"
}

case "${1:-}" in
  --session) session "${2:?last evidence dir}" "${3:?session probe log}" ;;
  "") echo "usage: tools/s0-check.sh <evidence-dir> [...] | --session <last-dir> <probe-log>" >&2; exit 1 ;;
  *) for d in "$@"; do check "$d"; done ;;
esac
