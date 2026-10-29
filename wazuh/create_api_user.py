#!/usr/bin/env python3
"""Create (or refresh) the least-privilege Wazuh API user that n8n uses to run active responses.

Run by Fathia on the Wazuh server, because it needs the Wazuh API admin password:

    sudo python3 ~/soc-pipeline/wazuh/create_api_user.py                  # agent 006 (tools) only
    sudo python3 ~/soc-pipeline/wazuh/create_api_user.py --agents 006,003   # M4: add DC01

What it does, through the Wazuh API on 127.0.0.1 (certificate verified):
  1. Policy  "soc-pipeline-ar":        allow active-response:command on the listed agents only (default 006);
                                       re-running replaces the list, so access only exists while it is needed
  2. Role    "soc-pipeline-responder": that policy only
  3. User    "soc-pipeline":           that role only, with a new random password (rotated on every run)
  4. Logs in as the new user and proves the limits: allowed to run active responses, refused anything else
  5. Saves the new password to /var/ossec/etc/soc-pipeline-api.pass (owner root:root, mode 0600) for a
     one-time piped install into n8n (tools-vm/install_api_credential.sh). Right after the import the file
     is overwritten and removed with "shred -u", and its absence is checked.
The admin password is read without echo, kept in memory only, and never written or printed.
"""
import base64
import getpass
import json
import os
import secrets
import ssl
import string
import sys
import time
import urllib.error
import urllib.request

API = 'https://127.0.0.1:55000'
CA = '/var/ossec/api/configuration/ssl/server.crt'
PASS_FILE = '/var/ossec/etc/soc-pipeline-api.pass'
USER, ROLE, POLICY = 'soc-pipeline', 'soc-pipeline-responder', 'soc-pipeline-ar'
DEFAULT_AGENTS = '006'                      # tools VM; DC01 (003) is added in M4, when playbook B needs it
CTX = ssl.create_default_context(cafile=CA)


def call(method, path, token=None, basic=None, body=None, ok_codes=(200,)):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    if basic:
        headers['Authorization'] = 'Basic ' + base64.b64encode(basic.encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=15) as r:
            return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        payload = json.loads(e.read() or b'{}')
        if e.code in ok_codes:
            return e.code, payload
        sys.exit(f'{method} {path} failed: HTTP {e.code} {payload.get("title", "")} {payload.get("detail", "")}')


def login(user, password):
    _, r = call('POST', '/security/user/authenticate', basic=f'{user}:{password}')
    return r['data']['token']


def login_after_change(user, password):
    """Log in as a user whose permissions were just changed, and read its effective policies.
    Wazuh revokes every token issued up to the second of a security change, at one-second precision,
    so a token created in that same second is refused ("Invalid token"). Wait first; retry once."""
    for _ in range(2):
        time.sleep(2)
        token = login(user, password)
        code, me = call('GET', '/security/users/me/policies', token, ok_codes=(200, 401))
        if code == 200:
            return token, me
    sys.exit(f'{user} still gets "Invalid token" after two tries; run the script again')


def find(items, key, value):
    return next((x for x in items if x.get(key) == value), None)


def new_password():
    # Wazuh requires upper, lower, digit and symbol; 24 characters from a URL-safe set
    pools = [string.ascii_uppercase, string.ascii_lowercase, string.digits, '-_.!']
    chars = [secrets.choice(p) for p in pools] + [secrets.choice(''.join(pools)) for _ in range(20)]
    secrets.SystemRandom().shuffle(chars)
    return ''.join(chars)


def main():
    if os.geteuid() != 0:
        sys.exit('run with sudo (the API certificate and the password file are root-only)')
    agents = DEFAULT_AGENTS
    if len(sys.argv) == 3 and sys.argv[1] == '--agents':
        agents = sys.argv[2]
    elif len(sys.argv) != 1:
        sys.exit('usage: create_api_user.py [--agents 006,003]')
    ids = agents.split(',')
    if not all(len(i) == 3 and i.isdigit() and i != '000' for i in ids):
        sys.exit('agent IDs must be three digits, e.g. 006,003 (000, the manager, is not allowed)')
    RULES = {'actions': ['active-response:command'],
             'resources': [f'agent:id:{i}' for i in ids],
             'effect': 'allow'}
    admin = input('Wazuh API admin user [wazuh]: ').strip() or 'wazuh'
    token = login(admin, getpass.getpass(f'Password for {admin}: '))

    _, cfg = call('GET', '/security/config', token)
    print(f'RBAC mode: {cfg["data"].get("rbac_mode")} (white = everything not allowed is denied)')

    _, r = call('GET', '/security/policies?limit=500', token)
    pol = find(r['data']['affected_items'], 'name', POLICY)
    if pol and pol.get('policy') != RULES:
        call('PUT', f'/security/policies/{pol["id"]}', token, body={'policy': RULES})
    elif not pol:
        _, r = call('POST', '/security/policies', token, body={'name': POLICY, 'policy': RULES})
        pol = r['data']['affected_items'][0]
    print(f'policy {POLICY} (id {pol["id"]}): {RULES["actions"]} on {RULES["resources"]}')

    _, r = call('GET', '/security/roles?limit=500', token)
    role = find(r['data']['affected_items'], 'name', ROLE)
    if not role:
        _, r = call('POST', '/security/roles', token, body={'name': ROLE})
        role = r['data']['affected_items'][0]
    if pol['id'] not in role.get('policies', []):
        call('POST', f'/security/roles/{role["id"]}/policies?policy_ids={pol["id"]}', token)
    print(f'role {ROLE} (id {role["id"]}) linked to the policy')

    password = new_password()
    _, r = call('GET', '/security/users?limit=500', token)
    user = find(r['data']['affected_items'], 'username', USER)
    if user:
        call('PUT', f'/security/users/{user["id"]}', token, body={'password': password})
        print(f'user {USER} (id {user["id"]}) already existed: password rotated')
    else:
        _, r = call('POST', '/security/users', token, body={'username': USER, 'password': password})
        user = r['data']['affected_items'][0]
        print(f'user {USER} (id {user["id"]}) created')
    if role['id'] not in user.get('roles', []):
        call('POST', f'/security/users/{user["id"]}/roles?role_ids={role["id"]}', token)
    print(f'user {USER} linked to role {ROLE}')

    # Prove the limits with the new user's own token
    t, me = login_after_change(USER, password)
    perms = {k: v for k, v in me['data'].items() if isinstance(v, dict)}
    print(f'{USER} effective permissions: {json.dumps(perms)}')
    # Wazuh filters list endpoints (HTTP 200, 0 items) and refuses single objects (HTTP 403): check both
    code, _ = call('GET', f'/agents?agents_list={ids[0]}', t, ok_codes=(200, 403))
    print(f'{USER} reading agent {ids[0]}: HTTP {code} ({"refused, as intended" if code == 403 else "ALLOWED - check the policy"})')
    code, r = call('GET', '/agents', t, ok_codes=(200, 403))
    seen = r.get('data', {}).get('total_affected_items', 0) if code == 200 else 0
    print(f'{USER} listing agents: {seen} visible ({"none, as intended" if seen == 0 else "VISIBLE - check the policy"})')

    old = os.umask(0o077)
    with open(PASS_FILE, 'w') as f:
        f.write(password + '\n')
    os.umask(old)
    os.chmod(PASS_FILE, 0o600)
    print(f'new password saved to {PASS_FILE} (root only, not shown). Next: tools-vm/install_api_credential.sh pipes it into n8n and deletes the file.')


if __name__ == '__main__':
    main()
