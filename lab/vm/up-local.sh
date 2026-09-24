#!/usr/bin/env bash
# TraceJoin v0 rig — local launcher via raw QEMU/KVM (fallback path; primary is cloud,
# see lab/vm/UP-CLOUD.md).
#
# No libvirt, no daemon, no root: QEMU runs as you and reads images from this directory.
# The guest is reached over a forwarded port (SSH_PORT); snapshots use qemu-img (Makefile).
#
# Prereqs (Ubuntu/Debian host, one-time — ASK before running sudo):
#   sudo apt install qemu-system-x86 qemu-utils cloud-image-utils wget
#
# Usage (from any cwd) — key injection keeps the repo clean and your key out of git:
#   SSH_PUBKEY="$(cat ~/.ssh/id_ed25519.pub)" make lab-vm-up
#   ...or pass the key itself (or a path to it) as the first argument.
#
# Env overrides: RIG_NAME, RIG_VCPUS, RIG_MEM_MB, DISK_SIZE, SSH_PORT, FOREGROUND=1 (attach console).
set -euo pipefail

VM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # absolute path of lab/vm
RIG_NAME="${RIG_NAME:-tracejoin-rig}"
RIG_VCPUS="${RIG_VCPUS:-2}"
RIG_MEM_MB="${RIG_MEM_MB:-4096}"
SSH_PORT="${SSH_PORT:-2222}"
DISK_SIZE="${DISK_SIZE:-40G}"   # virtual size of the overlay; sparse, grown into by cloud-init
IMG="$VM_DIR/jammy-server-cloudimg-amd64.img"
DISK="$VM_DIR/$RIG_NAME-disk.img"                  # qcow2 overlay — the VM writes here, never to $IMG
SEED="$VM_DIR/seed.img"
LOCAL_USER_DATA="$VM_DIR/.user-data.local.yaml"    # gitignored; generated from SSH_PUBKEY
PIDFILE="$VM_DIR/$RIG_NAME.pid"
CONSOLE_LOG="$VM_DIR/$RIG_NAME-console.log"
MONITOR_SOCK="$VM_DIR/$RIG_NAME-monitor.sock"

# --- preflight: host tooling -----------------------------------------------------
missing=()
for c in wget cloud-localds qemu-system-x86_64 qemu-img; do
  command -v "$c" >/dev/null 2>&1 || missing+=("$c")
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "ERROR: missing host tools: ${missing[*]}" >&2
  echo "Ask the user before running: sudo apt install qemu-system-x86 qemu-utils cloud-image-utils wget" >&2
  exit 1
fi
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
  echo "WARNING: /dev/kvm not readable/writable by $USER — falling back to slow emulation." >&2
  echo "         Ask the user before running: sudo usermod -aG kvm \"$USER\" (then log out and back in)." >&2
fi
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "ERROR: $RIG_NAME is already running (pid $(cat "$PIDFILE")). Stop it first: make lab-vm-stop" >&2
  exit 1
fi
if command -v ss >/dev/null 2>&1; then
  if ss -ltn "sport = :$SSH_PORT" 2>/dev/null | grep -q LISTEN; then
    echo "port $SSH_PORT busy — waiting up to 15s for the previous VM to exit..."
    for _ in $(seq 1 15); do
      ss -ltn "sport = :$SSH_PORT" 2>/dev/null | grep -q LISTEN || break
      sleep 1
    done
  fi
  if ss -ltn "sport = :$SSH_PORT" 2>/dev/null | grep -q LISTEN; then
    holder="$(ss -ltnp "sport = :$SSH_PORT" 2>/dev/null | grep -o 'pid=[0-9]*' | head -1)"
    echo "ERROR: SSH port $SSH_PORT is still in use ${holder:+($holder)}." >&2
    echo "       Stop the old VM: make lab-vm-stop   (or: SSH_PORT=2223 make lab-vm-up)" >&2
    exit 1
  fi
fi

# --- SSH key resolution -----------------------------------------------------------
SSH_PUBKEY="${1:-${SSH_PUBKEY:-}}"
if [ -n "$SSH_PUBKEY" ] && [ -f "$SSH_PUBKEY" ]; then
  SSH_PUBKEY="$(cat "$SSH_PUBKEY")"   # argument was a path to the key file
fi

if [ -n "$SSH_PUBKEY" ]; then
  sed "s|REPLACE_WITH_YOUR_PUBLIC_KEY|$SSH_PUBKEY|" \
    "$VM_DIR/user-data.yaml" > "$LOCAL_USER_DATA"
  USER_DATA="$LOCAL_USER_DATA"
elif grep -q 'REPLACE_WITH_YOUR_PUBLIC_KEY' "$VM_DIR/user-data.yaml"; then
  echo "ERROR: no SSH key — the VM would be unreachable without one." >&2
  echo "No key yet? Generate one first: ssh-keygen -t ed25519" >&2
  echo "Then run:" >&2
  echo '  SSH_PUBKEY="$(cat ~/.ssh/id_ed25519.pub)" make lab-vm-up' >&2
  exit 1
else
  USER_DATA="$VM_DIR/user-data.yaml"   # manually edited repo copy
fi

# --- guard: user-data must declare its content type on line 1 ---------------------
# cloud-init identifies the payload by its first line (#cloud-config / #! / MIME);
# anything else is silently treated as empty config.
if [ "$(head -n1 "$USER_DATA")" != "#cloud-config" ]; then
  echo "ERROR: user-data must start with '#cloud-config' on line 1 — that line is the content-type header." >&2
  echo "       Found: $(head -n1 "$USER_DATA")" >&2
  echo "       Fix: in lab/vm/user-data.yaml keep '#cloud-config' as the very first line; comments go below it." >&2
  exit 1
fi

# --- disk: pristine cloud image + copy-on-write overlay ---------------------------
if [ ! -f "$IMG" ]; then
  echo "Downloading Ubuntu 22.04 cloud image (~700 MB, once)..."
  wget -O "$IMG" "https://cloud-images.ubuntu.com/jammy/current/$(basename "$IMG")"
fi
if [ "$(stat -c%s "$IMG")" -lt 100000000 ]; then
  echo "ERROR: $IMG is under 100 MB — truncated download. Delete it and re-run." >&2
  exit 1
fi
if [ ! -f "$DISK" ]; then
  echo "Creating qcow2 overlay: $DISK (${DISK_SIZE} virtual, sparse; base image stays pristine)"
  qemu-img create -f qcow2 -F qcow2 -b "$IMG" "$DISK" "$DISK_SIZE" >/dev/null
fi

# --- seed (cloud-init NoCloud) ------------------------------------------------------
rm -f "$SEED"
cloud-localds "$SEED" "$USER_DATA"

# --- launch: raw QEMU/KVM ------------------------------------------------------------
qemu_args=(
  -name "$RIG_NAME"
  -smp "$RIG_VCPUS"
  -m "$RIG_MEM_MB"
  -drive "file=$DISK,if=virtio,format=qcow2"
  -drive "file=$SEED,if=virtio,format=raw,readonly=on"
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22"
  -device "virtio-net-pci,netdev=net0"
  -display none
)
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  qemu_args+=( -enable-kvm -cpu host )
else
  qemu_args+=( -cpu max )
fi

if [ "${FOREGROUND:-0}" = "1" ]; then
  echo "Foreground mode — serial console on stdio (Ctrl-A X to quit, Ctrl-A C for monitor)."
  exec qemu-system-x86_64 "${qemu_args[@]}" -nographic
fi

echo "Starting $RIG_NAME (QEMU/KVM, headless)..."
qemu-system-x86_64 "${qemu_args[@]}" \
  -serial "file:$CONSOLE_LOG" \
  -monitor "unix:$MONITOR_SOCK,server,nowait" \
  -daemonize -pidfile "$PIDFILE"

cat <<EOF
Boot started — cloud-init provisions the rig (1–5 min of real apt downloads).

  Wait until up:  make lab-vm-wait
  Login:          ssh -p $SSH_PORT ubuntu@127.0.0.1     (key = the one you supplied at launch)
  Boot console:   tail -f $CONSOLE_LOG
  Verify:         cat /etc/tracejoin-rig                  (has content ⇔ provisioning finished)
  Stop:           make lab-vm-stop
  Snapshot:       make lab-vm-snapshot     (once, after clean provisioning; VM must be stopped)
  Rollback:       make lab-vm-rollback     (between scenario rounds; VM must be stopped)
  Factory reset:  make lab-vm-reset      (stop + wipe + relaunch + wait; forgets stale host key)
  Restart:        make lab-vm-restart    (keep state, fast)
  Connect:        make lab-vm-ssh

  Note: "Connection reset by peer" on ssh = sshd not up yet. Wait and retry.
EOF
