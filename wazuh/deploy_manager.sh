#!/bin/bash
# Install or update everything Project 3 adds to the Wazuh server (run with sudo). Safe to re-run.
#   1. custom-n8n integration: a copy of Wazuh's own python launcher (the one "slack" uses) + custom-n8n.py
#   2. Shared webhook secret: random, in /var/ossec/etc/n8n_webhook.secret (root:wazuh 0640), never printed.
#      The same value goes into n8n with tools-vm/install_webhook_secret.sh (piped, never displayed).
#   3. Rules for the pipeline's own actions (rules/soc_pipeline_rules.xml, IDs 100700-100799)
#   4. ossec.conf, between "soc-pipeline" markers (replaced on every run, backup first):
#      - integration "alerts": playbook triggers -> n8n intake workflow
#      - integration "results": block verified / missing (100701-100703), block expired (652) and the
#        account results from DC01 (100711-100715) -> n8n
#      - command "soc-block" (the stock firewall-drop) with a BLOCK_TIMEOUT expiry, runnable through the API
#        as "soc-block<timeout>". Its <active-response> block exists only to publish that command to the
#        agents: it is tied to rule 100799, which does not exist, so Wazuh never fires it by itself.
#      - command "soc-disable-account" (soc-disable-account.cmd on DC01), published the same way as
#        "soc-disable-account0" (no timeout: an account stays disabled until an administrator re-enables it)
#   5. ufw: the Wazuh API (55000) reachable from the tools VM only
#   6. Config tests, manager restart, check that the agents' ar.conf lists soc-block<timeout>
set -e
OSSEC=/var/ossec
SRC=$(cd "$(dirname "$0")" && pwd)
N8N=http://192.168.145.20:5678/webhook
TOOLS_VM=192.168.145.20
ALERT_RULES=5712,5720,5763,100505
RESULT_RULES=100701,100702,100703,652,100711,100712,100713,100714,100715
BLOCK_TIMEOUT=${BLOCK_TIMEOUT:-3600}
[[ $BLOCK_TIMEOUT =~ ^[0-9]+$ ]] || { echo "BLOCK_TIMEOUT must be a number of seconds" >&2; exit 2; }

echo "== integration script"
install -m 750 -o root -g wazuh $OSSEC/integrations/slack $OSSEC/integrations/custom-n8n
install -m 750 -o root -g wazuh "$SRC/integrations/custom-n8n.py" $OSSEC/integrations/custom-n8n.py
ls -l $OSSEC/integrations/custom-n8n*

echo "== webhook secret"
if [ ! -s $OSSEC/etc/n8n_webhook.secret ]; then
    (umask 077; openssl rand -hex 32 > $OSSEC/etc/n8n_webhook.secret)
    echo "created (not shown)"
else
    echo "already present (not shown)"
fi
chown root:wazuh $OSSEC/etc/n8n_webhook.secret
chmod 640 $OSSEC/etc/n8n_webhook.secret

echo "== rules"
install -m 660 -o wazuh -g wazuh "$SRC/rules/soc_pipeline_rules.xml" $OSSEC/etc/rules/soc_pipeline_rules.xml
ls -l $OSSEC/etc/rules/soc_pipeline_rules.xml

echo "== ossec.conf"
cp -a $OSSEC/etc/ossec.conf $OSSEC/etc/ossec.conf.bak-$(date +%Y%m%d%H%M%S)
python3 - "$OSSEC/etc/ossec.conf" "$N8N" "$ALERT_RULES" "$RESULT_RULES" "$BLOCK_TIMEOUT" <<'EOF'
import re, sys
path, n8n, alert_rules, result_rules, timeout = sys.argv[1:6]
block = f"""  <!-- BEGIN soc-pipeline (Project 3, managed by deploy_manager.sh) -->
  <integration>
    <name>custom-n8n</name>
    <hook_url>{n8n}/wazuh-alert</hook_url>
    <rule_id>{alert_rules}</rule_id>
    <alert_format>json</alert_format>
  </integration>
  <integration>
    <name>custom-n8n</name>
    <hook_url>{n8n}/wazuh-ar-result</hook_url>
    <rule_id>{result_rules}</rule_id>
    <alert_format>json</alert_format>
  </integration>
  <command>
    <name>soc-block</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>
  <!-- Publishes "soc-block{timeout}" to the agents for API use only. Rule 100799 does not exist: never fires. -->
  <active-response>
    <disabled>no</disabled>
    <command>soc-block</command>
    <location>local</location>
    <rules_id>100799</rules_id>
    <timeout>{timeout}</timeout>
  </active-response>
  <command>
    <name>soc-disable-account</name>
    <executable>soc-disable-account.cmd</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
  <!-- Publishes "soc-disable-account0" (DC01) for API use only, same never-firing rule 100799. -->
  <active-response>
    <disabled>no</disabled>
    <command>soc-disable-account</command>
    <location>local</location>
    <rules_id>100799</rules_id>
  </active-response>
  <!-- END soc-pipeline -->
"""
s = open(path).read()
s = re.sub(r"  <!-- BEGIN soc-pipeline.*?<!-- END soc-pipeline -->\n", "", s, flags=re.S)
i = s.index("</ossec_config>")
s = s[:i] + block + s[i:]
open(path, "w").write(s)
EOF
grep -n "BEGIN soc-pipeline" $OSSEC/etc/ossec.conf
$OSSEC/bin/wazuh-analysisd -t
$OSSEC/bin/wazuh-integratord -t 2>&1 || { echo "integratord config test failed"; exit 1; }

echo "== firewall: Wazuh API from the tools VM only"
ufw allow from $TOOLS_VM to any port 55000 proto tcp comment 'wazuh api from n8n' > /dev/null
ufw status | grep 55000

echo "== restart manager"
systemctl restart wazuh-manager
sleep 15
echo "manager: $(systemctl is-active wazuh-manager)"
$OSSEC/bin/wazuh-control status | grep -E "integratord|analysisd|execd"
grep "^soc-" $OSSEC/etc/shared/ar.conf
grep -q "^soc-block" $OSSEC/etc/shared/ar.conf || { echo "soc-block missing from ar.conf" >&2; exit 1; }
grep -q "^soc-disable-account0" $OSSEC/etc/shared/ar.conf || { echo "soc-disable-account missing from ar.conf" >&2; exit 1; }
