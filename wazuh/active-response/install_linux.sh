#!/bin/bash
# Install the pipeline's active-response script on a Linux Wazuh agent (run on the agent with sudo).
# soc-verify-block only reads the firewall; blocking itself uses Wazuh's stock firewall-drop.
set -e
SRC=$(cd "$(dirname "$0")" && pwd)
install -m 750 -o root -g wazuh "$SRC/soc-verify-block.py" /var/ossec/active-response/bin/soc-verify-block
ls -l /var/ossec/active-response/bin/soc-verify-block /var/ossec/active-response/bin/firewall-drop
