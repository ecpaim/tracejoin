# Scenarios

Declarative adversary-emulation scenarios derived from documented Linux/K8s LOTL campaigns — SCARLETEEL (Sysdig TRT), Hildegard (Unit 42), Kinsing/WatchDog (Aqua Nautilus / Unit 42) — and **recreated safely**: all attacker endpoints are local stand-in containers. Never point these at third-party services.

## Topology (v0: one VM + Docker inside it)

The rig is a single KVM VM; Docker runs *inside* that VM and provides the containerized
workload the sensors are aimed at. Scenario scripts run in the guest and use `docker exec`
to execute "inside" the victim container — so the attack process is in the container's
namespaces but on the guest kernel, which is what makes host-side and network-side
telemetry joinable.

```
HOST  (your machine)
┌────────────────────────────────────────────────────────────────────┐
│  QEMU/KVM process                                                  │
│    user-mode net (SLIRP): hostfwd tcp:127.0.0.1:2222 → guest:22    │
│    (no host bridge/tap — QEMU acts as a virtual NAT router)        │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ GUEST VM (Ubuntu 22.04) = "the rig"                          │  │
│  │   ens3: 10.0.2.15/24   gw 10.0.2.2 (SLIRP), dns 10.0.2.3     │  │
│  │                                                              │  │
│  │   SENSORS (in the guest)                                     │  │
│  │     auditd   ← syscalls: execve, connect      (host side)    │  │
│  │     Falco    ← eBPF syscalls + container ctx  (host side)    │  │
│  │     Zeek     ─┐                                              │  │
│  │     Suricata ─┘ capture on docker0            (network side) │  │
│  │                                                              │  │
│  │   docker0 bridge  172.17.0.1/16                              │  │
│  │      ┌────────────────┐      ┌────────────────┐              │  │
│  │      │ tj-victim      │      │ tj-listener    │              │  │
│  │      │ nginx          │      │ python http    │              │  │
│  │      │ 172.17.0.2     │      │ 172.17.0.3     │              │  │
│  │      └───────┬────────┘      └───────┬────────┘              │  │
│  │              └──── veth pairs ───────┘                       │  │
│  │      ┌────────────────┐                                      │  │
│  │      │ tj-imds-poller │ ─► 169.254.169.254:80 (link-local;  │  │
│  │      │ nginx + curl   │     no 169.254/16 route: egresses    │  │
│  │      │ 172.17.0.4     │     via default gw → seen on docker0)│  │
│  │      └────────────────┘                                      │  │
│  └──────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
      ssh -p 2222 ubuntu@127.0.0.1   →  into the guest
```

| Where | Interface | Address | Carries |
|---|---|---|---|
| Host | none (no tap/bridge) | — | only the QEMU process, console log, monitor socket |
| Host ↔ Guest | QEMU SLIRP (user net) | host `127.0.0.1:2222` ↔ guest `10.0.2.15`, gw `10.0.2.2` | SSH; the guest's own apt/cron traffic |
| Guest | `ens3` | 10.0.2.15/24 | guest-originated traffic (benign cron, apt) |
| Guest | `docker0` | 172.17.0.1/16 | **container↔container and container↔guest** traffic |
| Guest | `vethXXXX` (one per container) | — | each container's link into `docker0` |
| Container | `eth0` (own netns) | 172.17.0.2 / .3 / .4 | the container's own view |

Sensors: **auditd/Falco** live in the guest kernel (containers share it) → they see the
`execve`/`connect` syscalls and, for Falco, container context (`container.name`).
**Zeek/Suricata** are attached to `docker0` → they see container↔container and
container↔guest flows, but no process identity. Two NAT layers exist — Docker's
(MASQUERADE, guest) and SLIRP's (QEMU, host) — so a container reaching the internet is
visible to the sensors only on its first hop (`docker0`).

Measured deployment state: Falco's stable ruleset (`falco-rules:3`, 25 rules) contains
no IMDS rule — **zero alerts across all eight windows** (four attacks + four matched
benign); the zero column in `docs/threat-model.md` is a ruleset property, not a sensor
failure.


## Scenario files

| File | Technique | Derived from / role |
|---|---|---|
| `setup-listener.sh` | — | starts victim (nginx) + listener containers |
| `setup-imds-poller.sh` | — | benign background: legitimate IMDS poller (credential-agent stand-in; 5 s cadence so its signature lands in every recorded window) |
| `tj-1-t1552.005-imds.sh` | T1552.005 | SCARLETEEL 1.0 — IMDS credential probe |
| `tj-1-benign.sh` | — (benign twin) | same `docker exec` mechanics as tj-1, listener destination |
| `tj-1v-imds-stealth.sh` | T1552.005 (variant) | adversary variation: argv character-identical to the poller, direct exec — erased the auditd separator (round S1v) |
| `tj-pivot.sh` | T1021-class (variant) | lateral movement: victim curls the *poller* (only differing field vs the twin = destination) — first-ever victim↔poller edge; benign window reuses `tj-1-benign.sh` |
| `tj-2-t1048.003-bash-tcp-exfil.sh` | T1048.003 | SCARLETEEL 2.0 — `dload()` base64-GET exfil via shell built-ins |
| `tj-2-benign.sh` | — (benign twin) | bash in victim + legit transfer via curl to the listener |
| `tj-3-t1567.002-paste-upload.sh` | T1567.002 | SCARLETEEL 2.0 — paste-service credential upload |
| `tj-3-benign.sh` | — (benign twin) | file write + curl GET to the same listener (no upload) |

Marker discipline: each script echoes UTC timestamps before/after (GUID markers land with the label harness, v1). Record observations per the method doc (`docs/threat-model-method.md`, Part C) into `evidence/scenario-<n>.md` (gitignored — curated excerpts move to `docs/`).

## Paired-window rounds

Every scenario runs as a **paired observation**: an attack window plus a matched benign
window (benign twin + IMDS poller), collected as `<n>` / `<n>-benign` evidence pairs
(variants append a letter, e.g. `1v`). Benign always precedes attack; windows are
duration-matched; soak 25 s after an attack whose flows may be unanswered. One
replicate per scenario in v0 — verdicts are preliminary. Criterion, decision matrix and
pre-registered predictions: `docs/threat-model-method.md` Parts C–D; full protocol and
record: [`CHECKPOINT.md`](../CHECKPOINT.md).

```
rollback to clean-rig → setup-listener.sh + setup-imds-poller.sh + tj-capture-start docker0
t_b0=$(date -u +%FT%TZ); bash tj-<n>-benign.sh; t_b1=$(date -u +%FT%TZ)
bash collect-evidence.sh <n>-benign "$t_b0" "$t_b1" <technique>
t0=$(date -u +%FT%TZ); bash tj-<n>-<technique>.sh; t1=$(date -u +%FT%TZ); sleep 25
bash collect-evidence.sh <n> "$t0" "$t1" <technique>
sudo tj-capture-stop
```

Per-round analysis (host): `tools/separability.sh evidence/scenario-<n>
evidence/scenario-<n>-benign` — per arm (auditd / Falco / Zeek+Suricata); the report
is persisted to `evidence/scenario-<n>/separability.md` (the A−B residue; the raw
superset — benign background, apparatus, padding — remains in `raw/` and
`curated.md`). Verdicts land in `docs/threat-model.md`.

## Evidence layout

Evidence is keyed by scenario id, so re-running the same scenario replaces it while
other scenarios are kept side by side:

- guest: `collect-evidence.sh <id> …` builds `~/evidence/scenario-<id>/` in a temp dir
  and swaps it in — re-running `<id>` fully replaces it (no stale files).
- host: `rm -rf evidence/scenario-<id>` before the `scp -r` for the same reason, then
  `bash tools/evidence-index.sh` regenerates `evidence/README.md`, an index of every
  pulled scenario (technique, window, per-sensor counts, link to the curated doc).
- curated: `docs/evidence/scenario-<id>.md` (tracked) is overwritten per re-run; the
  raw `evidence/` tree is gitignored.
