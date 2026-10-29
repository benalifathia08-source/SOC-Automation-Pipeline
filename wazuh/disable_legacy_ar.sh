#!/bin/bash
# Disable the pre-existing automatic active response on rule 100101 (run on the Wazuh server with sudo).
# Safe to re-run.
#
# Why: that <active-response> block ran firewall-drop by itself, with no approval and no expiry
# (firewall-drop0 = permanent), whenever rule 100101 fired (3 failed SSH logins for a real user from one
# IP within 120 s). That contradicts this project's design (every block is approved by an analyst and
# expires) and would distort the before/after timing. Rule 100101 itself stays: it still detects.
#
# What: backs up ossec.conf, wraps exactly that block in an XML comment with a note, tests the config,
# restarts the manager and checks that firewall-drop0 is gone from the agents' ar.conf.
# Revert: restore the backup printed below (or delete the comment markers), then restart wazuh-manager.
set -e
CONF=/var/ossec/etc/ossec.conf
BACKUP=$CONF.bak-before-100101-ar-off-$(date +%Y%m%d%H%M%S)

cp -a $CONF $BACKUP
echo "backup: $BACKUP"
python3 - "$CONF" <<'EOF'
import re, sys
path = sys.argv[1]
s = open(path).read()
if "DISABLED by Project 3" in s:
    print("already disabled")
    sys.exit(0)
pattern = re.compile(r"( *)<active-response>\s*<disabled>no</disabled>\s*<command>firewall-drop</command>"
                     r"\s*<location>local</location>\s*<rules_id>100101</rules_id>\s*</active-response>")
m = pattern.search(s)
if not m:
    sys.exit("block not found: nothing changed")
indent = m.group(1)
note = (f"{indent}<!-- DISABLED by Project 3 (SOC automation pipeline), 2026-10-09: automatic firewall-drop on rule 100101\n"
        f"{indent}     ran with no approval and no expiry. Blocks now go through the pipeline's Telegram approval and expire\n"
        f"{indent}     after 1 hour. Rule 100101 still detects. To restore, remove this comment wrapper and restart wazuh-manager.\n")
s = s[:m.start()] + note + m.group(0) + "\n" + indent + "-->" + s[m.end():]
open(path, "w").write(s)
print("block commented out")
EOF
grep -n -A9 "DISABLED by Project 3" $CONF
/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager
sleep 15
echo "manager: $(systemctl is-active wazuh-manager)"
echo "== agents' ar.conf (firewall-drop0 should be gone)"
cat /var/ossec/etc/shared/ar.conf
echo "== rule 100101 still loaded"
grep -c 'rule id="100101"' /var/ossec/etc/rules/local_rules.xml
