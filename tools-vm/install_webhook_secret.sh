#!/bin/bash
# Create or replace the n8n credential "Wazuh webhook secret" (Header Auth, header X-Wazuh-Secret) from a
# secret read on stdin. Run on the tools VM with sudo, fed straight from the Wazuh server:
#   ssh wazuh 'sudo cat /var/ossec/etc/n8n_webhook.secret' | ssh tools 'sudo bash install_webhook_secret.sh'
# The secret is never printed. printf is a shell builtin (no process command line), and the import file
# exists inside the container only for the import itself. n8n encrypts the credential on import.
set -e
read -r SECRET
[ ${#SECRET} -ge 32 ] || { echo "secret missing or too short" >&2; exit 1; }
TMP=/tmp/cred-$$.json
printf '[{"id":"wzhWebhookSecret","name":"Wazuh webhook secret","type":"httpHeaderAuth","data":{"name":"X-Wazuh-Secret","value":"%s"}}]' "$SECRET" \
    | docker exec -i n8n sh -c "umask 077; cat > $TMP"
unset SECRET
docker exec n8n sh -c "n8n import:credentials --input=$TMP > /dev/null 2>&1; rc=\$?; rm -f $TMP; exit \$rc" \
    && echo "credential 'Wazuh webhook secret' imported" \
    || { echo "import failed" >&2; exit 1; }
