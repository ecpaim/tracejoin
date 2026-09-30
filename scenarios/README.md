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
| Container | `eth0` (own netns) | 172.17.0.2 / .3 | the container's own view |

Sensors: **auditd/Falco** live in the guest kernel (containers share it) → they see the
`execve`/`connect` syscalls and, for Falco, container context (`container.name`).
**Zeek/Suricata** are attached to `docker0` → they see container↔container and
container↔guest flows, but no process identity. Two NAT layers exist — Docker's
(MASQUERADE, guest) and SLIRP's (QEMU, host) — so a container reaching the internet is
visible to the sensors only on its first hop (`docker0`).


## Scenario files

| File | Technique | Derived from |
|---|---|---|
| `setup-listener.sh` | — | starts victim (nginx) + listener containers |
| `tj-1-t1552.005-imds.sh` | T1552.005 | SCARLETEEL 1.0 — IMDS credential probe |
| `tj-2-t1048.003-bash-tcp-exfil.sh` | T1048.003 | SCARLETEEL 2.0 — `dload()` base64-GET exfil via shell built-ins |
| `tj-3-t1567.002-paste-upload.sh` | T1567.002 | SCARLETEEL 2.0 — paste-service credential upload |

Marker discipline: each script echoes UTC timestamps before/after (GUID markers land with the label harness, v1). Record observations per the method doc (`docs/threat-model-method.md`, Part C) into `evidence/scenario-<n>.md` (gitignored — curated excerpts move to `docs/`).

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
