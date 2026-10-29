#!/bin/bash
# Replay an SSH brute force into the tools VM's journal so Wazuh raises rule 5712
# ("sshd: brute force trying to get access to the system. Non existent user", 8 hits in 120 s).
# Nothing connects to SSH: these are log lines only, tagged like sshd's own. Simulated test data.
#
#   bash ssh_bruteforce.sh <public IPv4> [count]
#
# Use 203.0.113.0/24 (reserved for documentation) for wiring tests, an IP from a public blocklist for
# the high-score path, and 1.1.1.1 / 8.8.8.8 for the low-score path. Rule 5712 ignores repeats for 60 s.
set -e
IP=$1
COUNT=${2:-8}
[[ $IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "usage: $0 <IPv4> [count]" >&2; exit 2; }
[[ $COUNT =~ ^[0-9]+$ ]] || { echo "count must be a number" >&2; exit 2; }

for i in $(seq 1 "$COUNT"); do
    logger -t "sshd[$((40000 + RANDOM % 20000))]" -p auth.info \
        "Failed password for invalid user test$i from $IP port $((40000 + RANDOM % 20000)) ssh2"
    sleep 0.3
done
echo "$(date -u +%FT%T.%3NZ) replayed $COUNT failed logins from $IP"
