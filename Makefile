# TraceJoin — research repo Makefile
# v0: manual lab rig; `lab-up` lands with the kind testbed (see README roadmap).

.PHONY: lab-up scenarios smoke clean lab-vm-up lab-vm-wait lab-vm-ssh lab-vm-stop lab-vm-restart lab-vm-reset lab-vm-destroy lab-vm-clean lab-vm-snapshot lab-vm-rollback lab-vm-recreate

lab-up:
	@echo "v0: manual rig — follow docs/threat-model-method.md (kind testbed lands in v1)."

scenarios:
	bash scenarios/setup-listener.sh

smoke:
	shellcheck scenarios/*.sh

clean:
	@echo "nothing generated in-tree yet"

# --- v0 instrument VM: cloud-first (lab/vm/UP-CLOUD.md); local raw-QEMU fallback -----
# Local VM is driven directly by QEMU (no libvirt). Snapshots are offline: stop the VM first.
#
# Recovery one-liners:
#   make lab-vm-reset     factory reset: stop + wipe overlay + forget stale host key + relaunch + wait
#   make lab-vm-restart   reboot keeping state (fast; no re-provisioning)
#   make lab-vm-destroy   stop + remove all generated artifacts (keeps the base image)
#   make lab-vm-clean     lab-vm-destroy + remove the base image (full wipe)
#   make lab-vm-ssh       connect
RIG          ?= tracejoin-rig
VM_DIR       ?= lab/vm
DISK         ?= $(VM_DIR)/$(RIG)-disk.img
BASE_IMG     ?= $(VM_DIR)/jammy-server-cloudimg-amd64.img
PIDFILE      ?= $(VM_DIR)/$(RIG).pid
CONSOLE      ?= $(VM_DIR)/$(RIG)-console.log
SSH_PORT     ?= 2222
WAIT_TIMEOUT ?= 600

# polling ssh: quiet, no host-key prompt (loopback, disposable VM; never prompts for a password)
SSH_OPTS = -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2

# default to the standard key when present; override any time with SSH_PUBKEY=...
SSH_PUBKEY ?= $(shell cat $(HOME)/.ssh/id_ed25519.pub 2>/dev/null)
export SSH_PUBKEY

lab-vm-up:
	bash $(VM_DIR)/up-local.sh

# wait until the guest has finished provisioning (the manifest file is written last);
# fail fast if cloud-init reports the final stage failed
lab-vm-wait:
	@echo "waiting for $(RIG) provisioning (timeout $(WAIT_TIMEOUT)s; watch: tail -f $(CONSOLE))..."
	@deadline=$$(( $$(date +%s) + $(WAIT_TIMEOUT) )); \
	until ssh $(SSH_OPTS) -p $(SSH_PORT) ubuntu@127.0.0.1 'test -s /etc/tracejoin-rig' 2>/dev/null; do \
	  if ssh $(SSH_OPTS) -p $(SSH_PORT) ubuntu@127.0.0.1 'systemctl is-failed --quiet cloud-final.service' 2>/dev/null; then \
	    echo "FAILED: provisioning did not complete (cloud-final.service failed). Check: tail -f $(CONSOLE)" >&2; exit 1; \
	  fi; \
	  if [ $$(date +%s) -ge $$deadline ]; then \
	    echo "TIMEOUT — provisioning not finished; check: tail -f $(CONSOLE)" >&2; exit 1; \
	  fi; \
	  sleep 5; \
	done
	@echo "== rig ready =="
	@ssh $(SSH_OPTS) -p $(SSH_PORT) ubuntu@127.0.0.1 'cat /etc/tracejoin-rig'
	@echo "connect: make lab-vm-ssh   (or: ssh -p $(SSH_PORT) ubuntu@127.0.0.1)"

lab-vm-ssh:
	ssh -p $(SSH_PORT) ubuntu@127.0.0.1

lab-vm-stop:
	@if [ -f $(PIDFILE) ] && kill -0 "$$(cat $(PIDFILE))" 2>/dev/null; then \
	  pid=$$(cat $(PIDFILE)); \
	  kill "$$pid" 2>/dev/null || true; \
	  for i in $$(seq 1 20); do kill -0 "$$pid" 2>/dev/null || break; sleep 0.5; done; \
	  if kill -0 "$$pid" 2>/dev/null; then echo "force-killing $$pid"; kill -9 "$$pid" 2>/dev/null || true; sleep 1; fi; \
	  rm -f $(PIDFILE); echo "stopped $(RIG)"; \
	else echo "not running"; fi
	@if pgrep -f "[q]emu-system.*$(abspath $(VM_DIR))/$(RIG)-monitor.sock" >/dev/null 2>&1; then \
	  echo "reaping orphan QEMU(s) of $(RIG) under $(VM_DIR)"; pkill -9 -f "[q]emu-system.*$(abspath $(VM_DIR))/$(RIG)-monitor.sock" || true; sleep 1; fi

# reboot keeping all state (fast; cloud-init does not re-run)
lab-vm-restart:
	-@$(MAKE) --no-print-directory lab-vm-stop
	@bash $(VM_DIR)/up-local.sh
	@$(MAKE) --no-print-directory lab-vm-wait

# factory reset: stop + wipe overlay + forget stale host key + relaunch + wait
lab-vm-reset:
	@echo "==> factory reset $(RIG): wiping $(DISK) and rebuilding from the pristine image"
	-@$(MAKE) --no-print-directory lab-vm-stop
	rm -f $(DISK)
	-@ssh-keygen -R "[127.0.0.1]:$(SSH_PORT)" >/dev/null 2>&1
	@bash $(VM_DIR)/up-local.sh
	@$(MAKE) --no-print-directory lab-vm-wait

lab-vm-snapshot:
	@if [ -f $(PIDFILE) ] && kill -0 "$$(cat $(PIDFILE))" 2>/dev/null; then \
		echo "VM is running — stop it first: make lab-vm-stop" >&2; exit 1; fi
	qemu-img snapshot -c clean-rig $(DISK)

lab-vm-rollback:
	@if [ -f $(PIDFILE) ] && kill -0 "$$(cat $(PIDFILE))" 2>/dev/null; then \
		echo "VM is running — stop it first: make lab-vm-stop" >&2; exit 1; fi
	qemu-img snapshot -a clean-rig $(DISK)

lab-vm-recreate:
	@echo "cloud path: terminate the instance, relaunch with lab/vm/user-data.yaml (lab/vm/UP-CLOUD.md)."
	@echo "local path:  make lab-vm-reset    (stop + wipe + relaunch + wait)"

# destroy the local rig: stop the VM and remove all generated artifacts, KEEPING the base image
lab-vm-destroy:
	-@$(MAKE) --no-print-directory lab-vm-stop
	rm -f $(DISK) $(VM_DIR)/seed.img $(VM_DIR)/.user-data.local.yaml $(CONSOLE) $(PIDFILE) $(VM_DIR)/$(RIG)-monitor.sock
	-@ssh-keygen -R "[127.0.0.1]:$(SSH_PORT)" >/dev/null 2>&1
	@echo "destroyed $(RIG): overlay, seed, generated user-data, console log, pid/sock removed."
	@echo "kept base image: $(BASE_IMG)"

# full wipe: destroy + remove the downloaded base image (next 'make lab-vm-up' re-downloads ~700 MB)
lab-vm-clean: lab-vm-destroy
	rm -f $(BASE_IMG)
	@echo "removed base image — 'make lab-vm-up' will re-download it (~700 MB)"
