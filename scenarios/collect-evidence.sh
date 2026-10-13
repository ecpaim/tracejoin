#!/usr/bin/env bash
# collect-evidence.sh — TraceJoin v0 evidence collector. Run INSIDE the rig guest.
#
# Usage:
#   t0=$(date -u +%FT%TZ); bash tj-<n>-<tech>.sh; t1=$(date -u +%FT%TZ)
#   bash collect-evidence.sh <scenario-id> "<t0>" "<t1>" "[technique]"
#
# Outputs (in guest):
#   ~/evidence/scenario-<id>/raw/            raw per-sensor output for the window
#   ~/evidence/scenario-<id>/events.ndjson   normalized aggregate (one event per line)
#   ~/evidence/scenario-<id>/curated.md      excerpts + counts (copy to repo docs/evidence/)
#
# Re-running the same <id> replaces that scenario's directory atomically (no stale
# files); other scenarios are left untouched.
set -euo pipefail

ID="${1:?usage: collect-evidence.sh <scenario-id> [t0] [t1] [technique]}"
T0="${2:-$(date -u -d '5 minutes ago' +%FT%TZ)}"
T1="${3:-$(date -u +%FT%TZ)}"
TECHNIQUE="${4:-<fill in>}"

# ausearch (3.0.x) takes date and time as TWO arguments, each parsed with the
# locale's %x / %X. Ubuntu's default C.UTF-8 gives %m/%d/%y and %H:%M:%S, so pin
# the locale and pass the pair explicitly (a single "%m/%d/%Y %H:%M:%S" string
# makes ausearch fail with "Hour, Minute, and Second are required").
AUDIT_LC="C.UTF-8"
AUDIT_LOG="/var/log/audit/audit.log"   # -if: ausearch reads stdin (empty) without it
A0D=$(date -d "$T0" '+%m/%d/%y'); A0T=$(date -d "$T0" '+%H:%M:%S')
A1D=$(date -d "$T1" '+%m/%d/%y'); A1T=$(date -d "$T1" '+%H:%M:%S')
T0E=$(date -d "$T0" +%s); T1E=$(date -d "$T1" +%s)   # epochs: journald + Zeek ts

# Network sensors timestamp a flow at teardown/timeout, not on its first packet, so
# a tight command window misses the flow that matters. Widen the network query
# window (host sensors stay exact).
NET_PAD_BEFORE="${NET_PAD_BEFORE:-60}"; NET_PAD_AFTER="${NET_PAD_AFTER:-180}"
N0E=$((T0E - NET_PAD_BEFORE)); N1E=$((T1E + NET_PAD_AFTER))
NW0=$(date -u -d "@$N0E" '+%FT%TZ'); NW1=$(date -u -d "@$N1E" '+%FT%TZ')
N0S19="${NW0:0:19}"; N1S19="${NW1:0:19}"   # ISO prefix for Suricata compare

# Build into a temp dir, then swap it in, so re-running the same scenario replaces
# its evidence atomically (no stale files) while other scenarios are left alone.
DEST="$HOME/evidence/scenario-$ID"; OUT="$DEST.new"; RAW="$OUT/raw"
trap 'rm -rf "$OUT"' EXIT   # a failed run keeps the previous $DEST intact
rm -rf "$OUT"; mkdir -p "$RAW"

# --- raw capture (each independent; failures leave an empty/logged file) ----------
sudo LC_ALL="$AUDIT_LC" ausearch -if "$AUDIT_LOG" -i -k tj-exec -ts "$A0D" "$A0T" -te "$A1D" "$A1T" > "$RAW/auditd-execve.txt" 2>&1 || true
sudo LC_ALL="$AUDIT_LC" ausearch -if "$AUDIT_LOG" -i -k tj-net  -ts "$A0D" "$A0T" -te "$A1D" "$A1T" > "$RAW/auditd-connect.txt" 2>&1 || true

# Falco's concrete unit is driver-specific (e.g. falco-modern-bpf.service); the
# 'falco' alias is not resolvable by journalctl -u. journald also rejects a trailing
# 'Z', so query by epoch instead of the ISO string.
FALCO_UNIT="$(systemctl show -p Id --value falco 2>/dev/null || true)"
FALCO_UNIT="${FALCO_UNIT:-falco-modern-bpf.service}"
sudo journalctl -u "$FALCO_UNIT" --since "@$T0E" --until "@$T1E" -o json --no-pager > "$RAW/falco.json" 2>&1 || true
jq -r 'select(.MESSAGE) | .MESSAGE' "$RAW/falco.json" > "$RAW/falco.txt" 2>/dev/null || : > "$RAW/falco.txt"

# Zeek logs live root-owned under /root/capture — read as root, write as ubuntu
for f in conn http dns; do
  src="/root/capture/zeek/$f.log"
  if sudo test -f "$src"; then sudo cat "$src" > "$RAW/zeek-$f.log"; fi
done
ZC=/opt/zeek/bin/zeek-cut
if [ -x "$ZC" ] && [ -s "$RAW/zeek-http.log" ]; then
  "$ZC" ts id.orig_h id.resp_h method host uri user_agent < "$RAW/zeek-http.log" \
    | awk -v a="$N0E" -v b="$N1E" '$1+0>=a && $1+0<=b' > "$RAW/zeek-http.window.txt" || true
fi
if [ -x "$ZC" ] && [ -s "$RAW/zeek-conn.log" ]; then
  "$ZC" ts id.orig_h id.orig_p id.resp_h id.resp_p proto service orig_bytes resp_bytes < "$RAW/zeek-conn.log" \
    | awk -v a="$N0E" -v b="$N1E" '$1+0>=a && $1+0<=b' > "$RAW/zeek-conn.window.txt" || true
fi

# Suricata eve.json is root-owned; window by ISO timestamp prefix
if sudo test -f /var/log/suricata/eve.json; then
  sudo cat /var/log/suricata/eve.json > "$RAW/suricata-eve-all.json"
  # Use flow.start when present: a flow record is emitted at teardown, so its
  # .timestamp can sit far outside the command window even though the flow began
  # inside it. Fall back to .timestamp for non-flow events.
  jq -c --arg a "$N0S19" --arg b "$N1S19" \
    'select((((.flow.start // .timestamp // "")[0:19]) >= $a) and (((.flow.start // .timestamp // "")[0:19]) <= $b))' \
    "$RAW/suricata-eve-all.json" > "$RAW/suricata-eve-window.json" 2>/dev/null || : > "$RAW/suricata-eve-window.json"
fi

# --- normalized aggregate ---------------------------------------------------------
: > "$OUT/events.ndjson"
add_lines() { # file source kind
  [ -s "$1" ] || return 0
  jq -Rrc --arg src "$2" --arg kind "$3" 'select(length>0) | {source:$src, kind:$kind, raw:.}' "$1" >> "$OUT/events.ndjson"
}
add_lines "$RAW/auditd-execve.txt"      auditd   execve
add_lines "$RAW/auditd-connect.txt"     auditd   connect
add_lines "$RAW/falco.txt"              falco    alert
add_lines "$RAW/zeek-http.window.txt"   zeek     http
add_lines "$RAW/zeek-conn.window.txt"   zeek     conn
if [ -s "$RAW/suricata-eve-window.json" ]; then
  jq -c '{source:"suricata", kind:(.event_type // "event"), ts:.timestamp, raw:(.|tostring)}' \
    "$RAW/suricata-eve-window.json" >> "$OUT/events.ndjson"
fi

# --- meta + curated ----------------------------------------------------------------
cat > "$OUT/meta.json" <<JSON
{
  "scenario": "$ID",
  "technique": "$TECHNIQUE",
  "collected_at": "$(date -u +%FT%TZ)",
  "window": { "t0": "$T0", "t1": "$T1" },
  "net_window": { "start": "$NW0", "end": "$NW1" },
  "host": "$(hostname)",
  "kernel": "$(uname -r)",
  "rig_manifest": "$(tr '\n' '|' </etc/tracejoin-rig 2>/dev/null | sed 's/"/\\"/g')"
}
JSON

n(){ [ -s "$1" ] && wc -l < "$1" || echo 0; }
{
  echo "# Evidence — scenario $ID ($TECHNIQUE)"
  echo
  echo "- window (UTC): \`$T0\` → \`$T1\`"
  echo "- net window (UTC): \`$NW0\` → \`$NW1\` (flows are end-timestamped)"
  echo "- host: $(hostname), kernel $(uname -r)"
  echo "- raw: \`evidence/scenario-$ID/raw/\`, aggregate: \`events.ndjson\`"
  echo
  echo "## Counts"
  echo
  echo "| sensor | file | lines |"
  echo "|---|---|---|"
  echo "| auditd execve | auditd-execve.txt | $(n "$RAW/auditd-execve.txt") |"
  echo "| auditd connect | auditd-connect.txt | $(n "$RAW/auditd-connect.txt") |"
  echo "| falco alerts | falco.txt | $(n "$RAW/falco.txt") |"
  echo "| zeek http (window) | zeek-http.window.txt | $(n "$RAW/zeek-http.window.txt") |"
  echo "| zeek conn (window) | zeek-conn.window.txt | $(n "$RAW/zeek-conn.window.txt") |"
  echo "| suricata (window) | suricata-eve-window.json | $(n "$RAW/suricata-eve-window.json") |"
  echo
  echo "## Falco (host-only baseline)"
  echo '```'; head -n 15 "$RAW/falco.txt" 2>/dev/null || echo "(none)"; echo '```'
  echo "## auditd execve"
  echo '```'; head -n 20 "$RAW/auditd-execve.txt" 2>/dev/null || echo "(none)"; echo '```'
  echo "## auditd connect"
  echo '```'; head -n 20 "$RAW/auditd-connect.txt" 2>/dev/null || echo "(none)"; echo '```'
  echo "## Zeek http"
  echo '```'; head -n 15 "$RAW/zeek-http.window.txt" 2>/dev/null || echo "(none)"; echo '```'
  echo "## Zeek conn"
  echo '```'; head -n 15 "$RAW/zeek-conn.window.txt" 2>/dev/null || echo "(none)"; echo '```'
  echo "## Suricata"
  echo '```'; head -n 15 "$RAW/suricata-eve-window.json" 2>/dev/null || echo "(none)"; echo '```'
  echo
  echo "## Verdict (fill after review)"
  echo
  echo "- host-only (Falco): "
  echo "- network-only (Zeek/Suricata): "
  echo "- verdict: "
  echo "- gap assertion (conjunction): "
} > "$OUT/curated.md"

# atomic swap: one rename replaces this scenario's previous evidence
rm -rf "$DEST"; mv "$OUT" "$DEST"

echo "evidence written: $DEST"
echo "next (host): rm -rf evidence/scenario-$ID && scp -r -P 2222 ubuntu@127.0.0.1:'~/evidence/scenario-$ID' evidence/"
echo "             scp -P 2222 ubuntu@127.0.0.1:~/evidence/scenario-$ID/curated.md docs/evidence/scenario-$ID.md"
echo "             bash tools/evidence-index.sh   # refresh evidence/README.md"