# TraceJoin Threat Model (working)

**Adversary model (problem-statement level).** An actor with a foothold inside the monitored estate — a Linux/K8s workload — who uses legitimate tooling and credentials (LOTL) rather than custom malware. Out of scope: physical access, compromised kernel/rootkits (the sensor is in-kernel), supply chain (context citation only — xz-utils/CVE-2024-3094).

## Sensor coverage table

Columns follow the thesis plan §1 + provenance. Verdict ∈ `covered-host-only` | `covered-network-only` | `covered-both` | `join-required` | `blind-both`, assigned by the **separability criterion** over paired attack/benign windows (see [threat-model-method.md](threat-model-method.md), Parts C–D) — never by co-presence of events. **Emitted cells are observability only** (filled from executed runs; each row cites its evidence file); the **separating-predicate cells** record, per arm, the predicate that distinguishes attack from benign and whether it fires on benign. A cell not filled by a run stays unverified.

| # | Technique | Instantiation (corpus) | Host events needed | Network events needed | Falco/Tetragon emitted | Zeek/Suricata emitted | Sep. predicate (auditd / eBPF / net) | Fires on benign? | Verdict | Gap assertion | Evidence | Verified? |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | T1552.005 | `curl` IMDS from shell in web-server container (SCARLETEEL 1.0, Sysdig Feb 2023) | execve(curl) argv, socket() to link-local | flow to 169.254.169.254:80 (verified: traverses docker0) | none — 0 alerts; deployed stable ruleset (`falco-rules:3`) has no IMDS rule | Zeek `conn`: 172.17.0.2:44988→169.254.169.254:80; Suricata: SYN in stats, `flow` at teardown | — | — | — | pending paired run | evidence/scenario-1.md | no |
| 2 | T1048.003 | bash `/dev/tcp` GET, base64 payload in URI — SCARLETEEL 2.0 `send_aws_data()`/`dload()` | bash socket()/connect(), **no execve of curl/wget** | HTTP GET, >100 B base64 URI, raw-IP:80 | — | — | — | — | — | pending run | evidence/scenario-2.md | no |
| 3 | T1567.002 | `curl --upload-file` creds to paste-service stand-in (SCARLETEEL 2.0 temp.sh/termbin variants) | execve(curl) with file operand | upload flow to legitimate-looking endpoint | — | — | — | — | — | pending run | evidence/scenario-3.md | no |
| 4 | T1078 | valid accounts: stolen credential / SSH key reuse | session + auth events | logins from new sources, admin-port flows | — | — | — | — | — | — | — | no |
| 5 | T1059.004 | unix shell spawned by web-server / kubelet (Hildegard) | execve(shell), parent lineage | egress from same PID (join with row 2's pattern) | — | — | — | — | — | — | — | no |
| 6 | T1053.003 | cron persistence (Hildegard, Kinsing) | cron file write, execve of cron child | periodic egress from cron child | — | — | — | — | — | — | — | no |
| 7 | T1105 | `curl \| bash` ingress tool transfer (Kinsing) | execve(curl) piped to execve(bash) | download flow, script-sized body | — | — | — | — | — | — | — | no |
| 8 | T1071.001 / T1102.002 | C2 over legitimate web service (GitHub/CDN) | periodic execve + DNS to legit domain | periodic beaconing to legit domain | — | — | — | — | — | — | — | no |
| 9 | T1573.002 | encrypted channel | process opens TLS socket | TLS flow, SNI/JA3 | — | — | — | — | — | — | — | no |
| 10 | T1609 | `kubectl exec` / kubelet exec into pod (Hildegard analog of WMI remote exec) | kubelet / container-runtime exec events | API-server control traffic + resulting conns | — | — | — | — | — | — | — | no |
| 11 | T1528 | service-account token theft | token file open/read, token use | API calls with stolen token | — | — | — | — | — | — | — | no |

## Notes

- Rows 1–3 are the seed scenarios (`scenarios/`, method doc Part B). Rows 4–11 are stubs — instantiate from the corpus before running.
- The Volt Typhoon → K8s/Linux analog table lives in the planning repo (2026-plan §2.1); copy here when the proposal section stabilizes.
- Corpus report attributions verified and archived in the planning repo `references/` (SCARLETEEL = Sysdig TRT; Hildegard = Unit 42; Kinsing = Aqua Nautilus; WatchDog = Unit 42).
- Row 1 observability cells are from the 2026-09-25 run (pre-paired-protocol); separating predicates, benign-arm results and the verdict await the Phase-1 paired-window rounds — predictions are pre-registered in [threat-model-method.md](threat-model-method.md) Part D; plan in [CHECKPOINT.md](../CHECKPOINT.md).
