#!/bin/bash
# Arm one playbook A run for the M5 baseline (run on the tools VM):   bash fire_a.sh <run-id>   e.g. A-1, AUTO-A-3
# Picks a blocklist IP never used before (every IP used so far is listed in ~/soc-testdata/used-ips.txt,
# outside git), then replays the SSH brute force after a random 0-120 s delay,
# detached, so neither the analyst nor the person arming it sees the exact moment. Prints only "armed".
# Everything (IP, delay, fire time) goes to ~/soc-testdata/baseline-fire.log for the metrics afterwards.
set -e
RUN=$1
[[ $RUN =~ ^(AUTO-)?A-[0-9]+$ ]] || { echo "usage: $0 A-<n> | AUTO-A-<n>" >&2; exit 2; }
D=~/soc-testdata
LOG=$D/baseline-fire.log
touch $D/used-ips.txt "$LOG"
cat $D/live-test-ips.txt $D/live-test-ips-2.txt 2>/dev/null >> $D/used-ips.txt
IP=$(grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' $D/blocklist-de-ssh-2026-10-09.txt \
     | grep -vxF -f <(sort -u $D/used-ips.txt) \
     | shuf -n 1)
echo "$IP" >> $D/used-ips.txt
DELAY=$((RANDOM % 121))
echo "$(date -u +%FT%T.%3NZ) armed $RUN ip=$IP delay=${DELAY}s" >> "$LOG"
nohup setsid bash -c "sleep $DELAY; echo \"\$(date -u +%FT%T.%3NZ) fired $RUN ip=$IP\" >> $LOG; \
    bash ~/soc-pipeline/tests/replay/ssh_bruteforce.sh $IP > /dev/null" > /dev/null 2>&1 &
echo "armed $RUN: the attack fires within the next 2 minutes"
