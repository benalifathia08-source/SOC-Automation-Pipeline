#!/bin/bash
# Create or replace the n8n credential "Wazuh API responder" (Basic Auth, user soc-pipeline) from a password
# read on stdin. Run on the tools VM with sudo, fed straight from the Wazuh server:
#   ssh wazuh 'sudo cat /var/ossec/etc/soc-pipeline-api.pass' | ssh tools 'sudo bash install_api_credential.sh'
# The password is never printed (printf is a shell builtin); n8n encrypts the credential on import.
set -e
read -r PASS
[ ${#PASS} -ge 16 ] || { echo "password missing or too short" >&2; exit 1; }
[[ $PASS =~ ^[A-Za-z0-9._!-]+$ ]] || { echo "unexpected characters in password" >&2; exit 1; }
TMP=/tmp/cred-$$.json
printf '[{"id":"wzhApiResponder1","name":"Wazuh API responder","type":"httpBasicAuth","data":{"user":"soc-pipeline","password":"%s"}}]' "$PASS" \
    | docker exec -i n8n sh -c "umask 077; cat > $TMP"
unset PASS
docker exec n8n sh -c "n8n import:credentials --input=$TMP > /dev/null 2>&1; rc=\$?; rm -f $TMP; exit \$rc" \
    && echo "credential 'Wazuh API responder' imported" \
    || { echo "import failed" >&2; exit 1; }
