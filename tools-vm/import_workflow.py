#!/usr/bin/env python3
"""Import (or update) an n8n workflow from a template in n8n/workflows/, then publish it.

    sudo python3 import_workflow.py <template.json>

Placeholders in the template:
    {{cred:<credential name>}}  -> that credential's id (looked up by name, so templates hold no ids)
    {{file:<path>}}             -> the text of that file (path from the repo root), e.g. Code node scripts
    {{SETTING}}                 -> SETTING from /opt/soc-pipeline/pipeline.conf (KEY=VALUE lines, not secret)

Only id, name and type are read from the credential export; the export file is deleted at once and the
credential data (encrypted anyway) is never printed. Templates carry a fixed workflow id, so re-importing
updates the same workflow. n8n picks up CLI publishing after a restart, which this script does.
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

CONF = '/opt/soc-pipeline/pipeline.conf'
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # repo root (parent of tools-vm/)
HEALTH = 'http://192.168.145.20:5678/healthz'


def sh(*args, stdin=None):
    r = subprocess.run(args, input=stdin, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f'failed: {" ".join(args[:4])}...\n{r.stderr.strip()[-800:]}')
    return r.stdout


def credentials():
    sh('docker', 'exec', 'n8n', 'n8n', 'export:credentials', '--all', '--output=/tmp/creds.json')
    try:
        raw = sh('docker', 'exec', 'n8n', 'cat', '/tmp/creds.json')
    finally:
        sh('docker', 'exec', 'n8n', 'rm', '-f', '/tmp/creds.json')
    return {c['name']: c['id'] for c in json.loads(raw)}


def settings():
    out = {}
    try:
        for line in open(CONF):
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                out[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return out


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    text = open(sys.argv[1], encoding='utf-8').read()
    creds, conf = credentials(), settings()

    def fill(m):
        key = m.group(1)
        if key.startswith('cred:'):
            name = key[5:]
            if name not in creds:
                sys.exit(f'credential "{name}" not found in n8n')
            return creds[name]
        if key.startswith('file:'):
            path = os.path.realpath(os.path.join(ROOT, key[5:]))
            if not path.startswith(ROOT + os.sep) or not os.path.isfile(path):
                sys.exit(f'file {key[5:]} not found inside the repo')
            return json.dumps(open(path, encoding='utf-8').read())[1:-1]
        if key not in conf:
            sys.exit(f'setting {key} missing from {CONF}')
        return json.dumps(conf[key])[1:-1]          # JSON-escaped, without the quotes

    # Only {{cred:...}}, {{file:...}} and {{UPPER_CASE}}; n8n's own expressions ({{ $json.x }}) are left alone
    text = re.sub(r'\{\{((?:cred|file):[^{}]+|[A-Z][A-Z0-9_]*)\}\}', fill, text)
    wf = json.loads(text)                            # also checks the result is valid JSON
    wid = wf['id']

    sh('docker', 'exec', '-i', 'n8n', 'sh', '-c', 'cat > /tmp/wf.json', stdin=json.dumps(wf))
    try:
        sh('docker', 'exec', 'n8n', 'n8n', 'import:workflow', '--input=/tmp/wf.json')
    finally:
        sh('docker', 'exec', 'n8n', 'rm', '-f', '/tmp/wf.json')
    sh('docker', 'exec', 'n8n', 'n8n', 'publish:workflow', f'--id={wid}')
    print(f'imported and published "{wf["name"]}" ({wid}); restarting n8n')

    sh('docker', 'restart', 'n8n')
    for _ in range(60):
        try:
            urllib.request.urlopen(HEALTH, timeout=2)
            print('n8n is up')
            return
        except OSError:
            time.sleep(2)
    sys.exit('n8n did not come back within 2 minutes')


if __name__ == '__main__':
    main()
