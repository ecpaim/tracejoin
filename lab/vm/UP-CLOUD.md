# Launching the rig on a cloud free tier

Primary path for the instrument VM. Time: ~10 min. Cost: zero **if you follow the shapes
exactly** — verify shape and region before launching, and set a billing alarm (AWS) after.

Shared rules (both providers):

- Image: **Canonical Ubuntu 22.04 LTS**
- Paste `user-data.yaml` (this directory) into the **User data** field at creation —
  its first line must remain `#cloud-config`: that line is the content-type header
  cloud-init keys on. Descriptive comments go below it.
- Ingress: **SSH (TCP/22) only** — the rig runs attacker-lookalike traffic against local
  containers only; it must never be publicly reachable
- Evidence files are pulled to your machine with `scp` after each scenario round —
  nothing on the rig is precious

## Oracle Cloud (OCI) — Always Free

Preferred shape: **VM.Standard.A1.Flex** (Ampere ARM, up to 4 OCPU / 24 GB within
Always Free) — comfortable headroom for Falco + Zeek + Suricata + Docker.
Caveat: verify the Zeek OBS repo has arm64; if not, use the x86 fallback.

x86 fallback: **VM.Standard.E2.1.Micro** (1/8 OCPU, 1 GB) — tight RAM: drop
`build-essential` from the provision script and the compiler-cron line from
`/etc/cron.d/tracejoin-benign`.

1. Region = **your home region** (Always-Free A1 exists only in home regions).
2. Create instance → Edit shape → the shape above → image: Canonical Ubuntu 22.04.
3. Paste `user-data.yaml` contents into **Advanced → Launch options → User data**
   (cloud-init enabled). OCI's SSH-key upload still works: our user-data keeps
   `users: [default]`, so the injected `ubuntu` user keeps the provider key.
4. VCN defaults are fine — restrict ingress 22 to your IP in the security list.
5. Boot ≈ 3–6 min (cloud-init runs the full provisioning). Then:

   ```bash
   ssh ubuntu@<ip>
   cloud-init status --wait   # must print "status: done"
   cat /etc/tracejoin-rig     # manifest of installed versions
   ```

## AWS — Free Tier (12 months)

1. EC2 → Launch instance → name `tracejoin-rig`.
2. AMI: search "Ubuntu Server 22.04 LTS" published by **Canonical** (owner `099720109477`).
3. Type: `t3.micro` (free-tier eligible; 1 GB — same RAM caveat as the OCI fallback).
4. Key pair: create/select — injected to user `ubuntu`.
5. Network: allow SSH from your IP only. Storage: 20 GB gp3 is enough.
6. Advanced details → **User data** → paste `user-data.yaml` contents → Launch.
7. Same verification block as above.
8. CloudWatch → Billing alarm at US$1 (free tier expires after 12 months regardless).

## Rollback = recreate

There is nothing to snapshot in the cloud path — **the user-data is the snapshot**:
terminate the instance, relaunch with the same paste. Identical input, identical rig
(~3 min). `make lab-vm-recreate` prints this reminder.

## Teardown

- OCI: **Terminate** (not Stop — stopped instances can be reclaimed and leave resources
  attached); confirm boot-volume deletion on the termination prompt.
- AWS: Terminate instance; delete any leftover volumes.
