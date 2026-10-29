#!/bin/bash
# Machine timestamps for one baseline run of playbook A (run on the Wazuh server with sudo):
#   sudo bash run_times.sh <IP>
# Prints, from Wazuh's own alerts: T0 = rule 5712 for the IP, T3 = rule 651 (block in place on agent
# tools) and 100701 (verified, automated runs only). Times in UTC. The IP is masked in the output.
IP=$1
[[ $IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "usage: $0 <IPv4>" >&2; exit 2; }
grep -h -F "\"$IP\"" /var/ossec/logs/alerts/alerts.json | python3 -c '
import sys, json
want = {"5712": "T0 alert 5712", "651": "T3 block in place 651", "100701": "verified 100701", "652": "expired 652"}
for l in sys.stdin:
    try:
        a = json.loads(l)
    except ValueError:
        continue
    r = a["rule"]["id"]
    if r in want:
        print(want[r] + ":", a["timestamp"], "agent", a.get("agent", {}).get("name"))
'
