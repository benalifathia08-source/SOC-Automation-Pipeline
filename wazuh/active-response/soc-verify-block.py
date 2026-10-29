#!/usr/bin/python3
# soc-verify-block: Wazuh active response (Linux agent) that checks whether firewall-drop's rule for an IP
# is really in place, and writes the answer to active-responses.log, where Wazuh turns it into
# alert 100701 (present), 100702 (missing) or 100703 (invalid input). See wazuh/rules/soc_pipeline_rules.xml.
#
# Installed as /var/ossec/active-response/bin/soc-verify-block (root:wazuh 0750) and run through the
# Wazuh API as "!soc-verify-block" with alert.data.srcip set. It only reads the firewall: it never
# changes it. The IP comes from the API call, so it is validated before it reaches iptables, and
# iptables is run without a shell.
import datetime
import ipaddress
import json
import subprocess
import sys

LOG = '/var/ossec/logs/active-responses.log'
NAME = 'active-response/bin/soc-verify-block'


def log(result):
    stamp = datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')
    with open(LOG, 'a') as f:
        f.write(f'{stamp} {NAME}: {json.dumps({"soc": result})}\n')


def rule_present(chain, ip):
    # firewall-drop inserts "-s <ip> -j DROP" into INPUT and FORWARD
    r = subprocess.run(['iptables', '-w', '-C', chain, '-s', ip, '-j', 'DROP'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0


def main():
    checked_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds')
    try:
        msg = json.loads(sys.stdin.readline())
        raw = str(msg['parameters']['alert']['data']['srcip'])
        ip = ipaddress.IPv4Address(raw)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        log({'check': 'block', 'status': 'invalid', 'checked_at': checked_at})
        return 1
    chains = [c for c in ('INPUT', 'FORWARD') if rule_present(c, str(ip))]
    log({'check': 'block', 'ip': str(ip), 'status': 'present' if 'INPUT' in chains else 'missing',
         'chains': chains, 'checked_at': checked_at})
    return 0


if __name__ == '__main__':
    sys.exit(main())
