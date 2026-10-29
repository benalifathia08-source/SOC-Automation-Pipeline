#!/usr/bin/env python3
# custom-n8n.py: Wazuh integratord -> n8n webhook (SOC automation pipeline, Project 3).
#
# integratord runs it through the custom-n8n launcher (a copy of Wazuh's own python launcher) with:
#   argv[1] alert file (one alert, JSON)   argv[2] api_key (unused)   argv[3] hook_url
# The shared secret is read from SECRET_FILE (root:wazuh 0640) rather than <api_key>, so it never sits in
# ossec.conf or on a process command line. Standard library only.
import datetime
import json
import sys
import time
import urllib.error
import urllib.request

SECRET_FILE = '/var/ossec/etc/n8n_webhook.secret'
LOG_FILE = '/var/ossec/logs/integrations.log'
HEADER = 'X-Wazuh-Secret'
TIMEOUT = 10
ATTEMPTS = 2


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds')


def log(msg):
    with open(LOG_FILE, 'a') as f:
        f.write(f'{now()} custom-n8n: {msg}\n')


def main(argv):
    if len(argv) < 4:
        log('usage error: expected alert file, api_key, hook_url')
        return 2
    alert_file, hook_url = argv[1], argv[3]
    if not hook_url.startswith(('http://', 'https://')):
        log('refused: hook_url must be http(s)')
        return 2

    with open(alert_file) as f:
        alert = json.load(f)
    with open(SECRET_FILE) as f:
        secret = f.read().strip()

    # sent_at lets the metrics separate Wazuh's own delay (alert -> integratord) from the pipeline's
    body = json.dumps({'alert': alert, 'sent_at': now()}).encode()
    req = urllib.request.Request(hook_url, data=body, method='POST',
                                 headers={'Content-Type': 'application/json', HEADER: secret})
    ref = f"alert {alert.get('id')} rule {alert.get('rule', {}).get('id')}"

    for attempt in range(1, ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                log(f'{ref} -> HTTP {r.status}')
                return 0
        except urllib.error.HTTPError as e:
            log(f'{ref} -> HTTP {e.code}')
            if e.code < 500:            # wrong secret, URL or inactive workflow: retrying will not help
                return 1
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            log(f'{ref} attempt {attempt} failed: {e}')
        if attempt < ATTEMPTS:
            time.sleep(2)
    return 1


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv))
    except Exception as e:  # never let a bad alert crash silently
        log(f'error: {type(e).__name__}: {e}')
        sys.exit(1)
