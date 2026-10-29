#!/usr/bin/env python3
"""Check what the n8n API user "soc-pipeline" can and cannot do (run on the Wazuh server with sudo).

Reads the password from /var/ossec/etc/soc-pipeline-api.pass while it exists (before the handover to n8n)
and prints only HTTP codes and item counts, never the password or any token.
Wazuh's RBAC filters list endpoints instead of refusing them: a list the user may not read comes back
as HTTP 200 with 0 items. Single-object endpoints the user has no permission for return 403.
"""
import base64
import json
import ssl
import time
import urllib.error
import urllib.request

API = 'https://127.0.0.1:55000'
CTX = ssl.create_default_context(cafile='/var/ossec/api/configuration/ssl/server.crt')
USER = 'soc-pipeline'


def call(method, path, headers):
    req = urllib.request.Request(API + path, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=15) as r:
            return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'{}')


password = open('/var/ossec/etc/soc-pipeline-api.pass').read().strip()
basic = {'Authorization': 'Basic ' + base64.b64encode(f'{USER}:{password}'.encode()).decode()}
code, r = call('POST', '/security/user/authenticate', basic)
print(f'login as {USER}: HTTP {code}')
token = {'Authorization': f'Bearer {r["data"]["token"]}'}

checks = [
    ('GET', '/agents', 'list agents (agent:read)'),
    ('GET', '/agents?agents_list=006', 'read agent 006 (agent:read)'),
    ('GET', '/manager/info', 'manager info (manager:read)'),
    ('GET', '/security/users', 'list API users (security:read)'),
    ('GET', '/rules?limit=1', 'read rules (rules:read)'),
    ('GET', '/syscheck/006', 'file-integrity data of agent 006 (syscheck:read)'),
    ('PUT', '/agents/006/restart', 'restart agent 006 (agent:restart)'),
]
for method, path, label in checks:
    time.sleep(0.2)
    code, r = call(method, path, token)
    data = r.get('data') if isinstance(r.get('data'), dict) else {}
    items = data.get('total_affected_items')
    detail = f'{items} items returned' if code == 200 and items is not None else r.get('title', '')
    print(f'{label:52} HTTP {code}  {detail}')
