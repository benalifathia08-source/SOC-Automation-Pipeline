#!/bin/bash
# Let the tools VM's Wazuh agent read the pipeline's own log (run on the tools VM with sudo). Safe to re-run.
# n8n's error workflow appends JSON lines to /var/log/soc-pipeline/pipeline.jsonl; the manager's rule 100720
# turns a workflow failure into a level-12 alert.
set -e
CONF=/var/ossec/etc/ossec.conf
LOG=/var/log/soc-pipeline/pipeline.jsonl
[ -f "$LOG" ] || install -o 1000 -g 1000 -m 0640 /dev/null "$LOG"     # create it only if missing
if ! grep -q "$LOG" $CONF; then
    cp -a $CONF $CONF.bak-$(date +%Y%m%d%H%M%S)
    python3 - "$CONF" "$LOG" <<'EOF'
import sys
path, log = sys.argv[1:3]
s = open(path).read()
block = f"""  <!-- SOC pipeline (Project 3): n8n error workflow output -->
  <localfile>
    <log_format>json</log_format>
    <location>{log}</location>
  </localfile>
"""
i = s.rindex("</ossec_config>")
open(path, "w").write(s[:i] + block + s[i:])
EOF
    echo "localfile added"
else
    echo "localfile already present"
fi
systemctl restart wazuh-agent
sleep 5
grep -E "Analyzing file: '$LOG'" /var/ossec/logs/ossec.log | tail -1
ls -l "$LOG"
