#!/bin/bash
# Replace the Wazuh API's self-signed certificate with one that names the server's lab IP, so n8n can
# verify it instead of ignoring certificate errors (run on the Wazuh server with sudo).
# The installer's certificate only covers "localhost"; n8n connects to 192.168.145.128.
# The dashboard talks to the API on 127.0.0.1 without checking the certificate, so it is unaffected.
# The old files are kept as server.crt.bak-<date> / server.key.bak-<date>. Revert: copy them back and
# restart wazuh-manager. Afterwards, give n8n the new public certificate (tools-vm/deploy_n8n.sh reads
# /opt/soc-pipeline/certs/wazuh-api.crt on the tools VM).
set -e
SSL=/var/ossec/api/configuration/ssl
STAMP=$(date +%Y%m%d%H%M%S)

cp -a $SSL/server.crt $SSL/server.crt.bak-$STAMP
cp -a $SSL/server.key $SSL/server.key.bak-$STAMP
TMP=$(mktemp -d)
openssl req -x509 -newkey rsa:3072 -nodes -days 825 -sha256 \
    -subj "/O=Ftou7 lab/CN=wazuh-api" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:192.168.145.128" \
    -keyout $TMP/server.key -out $TMP/server.crt 2> /dev/null
install -m 400 -o wazuh -g wazuh $TMP/server.key $SSL/server.key
install -m 400 -o wazuh -g wazuh $TMP/server.crt $SSL/server.crt
rm -rf $TMP

systemctl restart wazuh-manager
sleep 15
echo "manager: $(systemctl is-active wazuh-manager)"
openssl x509 -in $SSL/server.crt -noout -subject -enddate -ext subjectAltName
curl -s -o /dev/null -w "API on 127.0.0.1 with the new certificate: HTTP %{http_code}\n" \
    --cacert $SSL/server.crt https://127.0.0.1:55000/
