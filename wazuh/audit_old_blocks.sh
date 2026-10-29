#!/bin/bash
# Look for blocks left over from the old automatic firewall-drop on rule 100101 (run on the Wazuh server
# with sudo). Read-only.
#   1. Every alert archive since installation: when rule 100101 fired, and every firewall-drop
#      "Host Blocked" (651) / "Host Unblocked" (652) event, per agent and IP
#   2. The manager's own firewall right now (agent 000 runs "local" active responses for its own logs)
# The tools VM's firewall is checked separately (tools-vm side).
set -e
echo "== alert archives searched (compressed and uncompressed daily files)"
find /var/ossec/logs/alerts -name "ossec-alerts-*.json*" ! -name "*.sum" | sort
{
    # alerts.json is the same file as today's ossec-alerts-DD.json, so it is not read separately
    find /var/ossec/logs/alerts -name "ossec-alerts-*.json*" ! -name "*.sum" -print0 | xargs -0 -r zcat -f
} | python3 -c '
import sys, json, collections
fired = collections.Counter()
events = []
for line in sys.stdin:
    if "\"100101\"" not in line and "\"651\"" not in line and "\"652\"" not in line:
        continue
    try:
        a = json.loads(line)
    except ValueError:
        continue
    rid = a["rule"]["id"]
    agent = a.get("agent", {}).get("name", "?")
    data = a.get("data", {})
    ip = data.get("srcip") or data.get("parameters", {}).get("alert", {}).get("data", {}).get("srcip", "?")
    if rid == "100101":
        fired[(agent, ip)] += 1
    elif rid in ("651", "652"):
        events.append((a["timestamp"][:19], rid, agent, ip))
print("rule 100101 fired (agent, source IP: count):")
for (agent, ip), n in sorted(fired.items()):
    print(f"   {agent:12} {ip:18} {n}")
if not fired:
    print("   never")
print("firewall-drop events (651 = blocked, 652 = unblocked):")
for e in sorted(events):
    print("  ", *e)
if not events:
    print("   none")
'
echo "== manager firewall now: DROP rules"
iptables -S | grep -E -- "-j DROP" || echo "   none"
