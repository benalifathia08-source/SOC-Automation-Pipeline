#!/bin/bash
# Check that n8n's stored credential "Wazuh API responder" can log in to the Wazuh API (run on the tools VM
# with sudo). Prints only HTTP codes. The decrypted export exists inside the container for about a second
# (umask 077) and is deleted; the password is never printed.
set -e
docker exec n8n sh -c '
umask 077
n8n export:credentials --id=wzhApiResponder1 --decrypted --output=/tmp/chk.json > /dev/null 2>&1
node -e "
const c = require(\"/tmp/chk.json\")[0];
require(\"fs\").unlinkSync(\"/tmp/chk.json\");
const auth = Buffer.from(c.data.user + \":\" + c.data.password).toString(\"base64\");
fetch(\"https://192.168.145.128:55000/security/user/authenticate\", { method: \"POST\", headers: { Authorization: \"Basic \" + auth } })
  .then(r => console.log(\"n8n credential -> Wazuh API login: HTTP\", r.status, r.status === 200 ? \"(works)\" : \"(FAILS)\"))
  .catch(e => console.log(\"error:\", e.cause ? e.cause.code : e.message));
"
rm -f /tmp/chk.json'
