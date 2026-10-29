#!/bin/bash
# Machine timestamps for one baseline run of playbook B (run on the Wazuh server with sudo):
#   sudo bash run_times_b.sh <account>
# T0 = rule 100505 for the actor; T3 = rule 60111 (event 4725, account disabled) for that account;
# 100711 = disabled and verified by the pipeline (automated runs only). Times in UTC.
ACC=$1
[[ $ACC =~ ^test\.rogue[0-9]+$ ]] || { echo "usage: $0 test.rogueN" >&2; exit 2; }
grep -h -F "$ACC" /var/ossec/logs/alerts/alerts.json | python3 -c '
import sys, json
acc = sys.argv[1]
for l in sys.stdin:
    try:
        a = json.loads(l)
    except ValueError:
        continue
    r = a["rule"]["id"]
    e = a.get("data", {}).get("win", {}).get("eventdata", {})
    if r == "100505" and e.get("subjectUserName") == acc:
        print("T0 alert 100505:", a["timestamp"])
    elif r == "60111" and e.get("targetUserName") == acc:
        print("T3 account disabled 60111 (4725):", a["timestamp"], "by", e.get("subjectUserName"))
    elif r == "100711" and a.get("data", {}).get("soc", {}).get("account") == acc:
        print("verified 100711:", a["timestamp"])
' "$ACC"
