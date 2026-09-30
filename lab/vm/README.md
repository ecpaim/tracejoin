# lab/vm — the v0 instrument, provisioned as code

| File | Purpose |
|---|---|
| `user-data.yaml` | cloud-init: the entire rig — sensors, audit rules, benign cron, capture helpers, kernel pin. Consumed by BOTH paths. Pinned versions live in the embedded `versions.env` block inside it — edit there. |
| `UP-CLOUD.md` | **primary path**: OCI Always Free / AWS free tier |
| `up-local.sh` | fallback: **raw QEMU/KVM** (no libvirt, no root) — pristine cloud image + `qemu-img` overlay + cloud-localds seed; SSH forwarded to `127.0.0.1:2222` |

Make targets: `lab-vm-up` (launch) · `lab-vm-reset` (factory reset: stop+wipe+relaunch+wait) ·
`lab-vm-restart` (keep state) · `lab-vm-destroy` (stop + remove all generated artifacts, keeps the
base image) · `lab-vm-clean` (destroy + remove the base image) · `lab-vm-wait` (poll only — it does
not start anything; aborts if the rig isn't running) · `lab-vm-status` · `lab-vm-ssh` ·
`lab-vm-stop` · `lab-vm-snapshot` / `lab-vm-rollback` (offline, via `qemu-img` — stop the VM
first) · `lab-vm-recreate` (cloud: reprovision-is-rollback). Overlay size: `DISK_SIZE` (default 40G).

On the rig: `tj-capture-start [iface]` / `tj-capture-stop` start the Zeek + Suricata
capture; `/etc/tracejoin-rig` records the installed manifest — copy it to
`evidence/versions.txt` after provisioning.

v1 note: the kind testbed (`lab/`) layers onto this same user-data — do not fork it.
