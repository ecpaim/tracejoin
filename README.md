# TraceJoin

**Joined host–network eBPF telemetry for living-off-the-land (LOTL) detection on Kubernetes.**

# how to run scenarios:


## host

make lab-vm-reset

make lab-vm-stop && make lab-vm-snapshot && make lab-vm-up && make lab-vm-wait

scp -P 2222 scenarios/*.sh ubuntu@127.0.0.1:~/scenarios/

ssh -p 2222 ubuntu@127.0.0.1 'sudo usermod -aG docker ubuntu'

## guest

ssh -p 2222 ubuntu@127.0.0.1 # (reconnect is necessary)

cd ~/scenarios
./setup-listener.sh

docker info >/dev/null 2>&1 && echo "docker ok" || echo "docker needs: sudo usermod -aG docker ubuntu + reconnect"

sudo tj-capture-start docker0

systemctl is-active falco auditd docker

t0=$(date -u +%FT%TZ); bash tj-1-t1552.005-imds.sh; t1=$(date -u +%FT%TZ)

bash collect-evidence.sh 1 "$t0" "$t1" "T1552.005"

sudo tj-capture-stop

## host

# pull one scenario; rm -rf first so this scenario replaces its previous run
# (other scenarios under evidence/ are left untouched)
rm -rf evidence/scenario-1
scp -r -P 2222 ubuntu@127.0.0.1:'~/evidence/scenario-1' evidence/
scp -P 2222 ubuntu@127.0.0.1:~/evidence/scenario-1/curated.md docs/evidence/scenario-1.md

# refresh the index of all pulled scenarios (evidence/README.md)
bash tools/evidence-index.sh