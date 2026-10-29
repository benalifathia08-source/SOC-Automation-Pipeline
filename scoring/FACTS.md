# Facts available to the scoring rules

`score(f)` receives one object `f` per alert. Values that came from the alert have already passed strict checks in `n8n/code/validate.js`.

| Fact | Type | Meaning |
|---|---|---|
| `f.playbook` | `'A'`, `'B'` or `null` | A = SSH brute force from the internet (rules 5712, 5720, 5763). B = privileged group changed by a non-approved account (Project 1 rule 100505). `null` = not mapped to a playbook: reported only, never acted on |
| `f.alert.rule_id` | string | Wazuh rule ID, e.g. `'5712'` |
| `f.alert.rule_level` | number | Wazuh rule level, 0–16 |
| `f.alert.description` | string | Rule description |
| `f.alert.mitre` | string[] | MITRE ATT&CK IDs, e.g. `['T1110']` |
| `f.agent.name`, `f.agent.id` | string | Wazuh agent that raised the alert (`tools`, `DC01`, …) |
| `f.agent.critical` | boolean | The agent is in `CRITICAL_AGENTS` (`n8n/code/config.js`; DC01 for now) |
| `f.ip` | object or `null` | Source IP, when the alert has one |
| `f.ip.valid` | boolean | A well-formed IPv4 address (IPv6 is not handled yet) |
| `f.ip.public` | boolean | Routable on the internet. Private, documentation and other reserved ranges are `false` and never sent to outside services |
| `f.ip.range` | string | `'public'`, `'private'`, `'documentation'`, `'loopback'`, … |
| `f.ip.allowlisted` | boolean | On `IP_ALLOWLIST`: the pipeline will never block it |
| `f.user` | object or `null` | Playbook B: the account that made the change (the "actor"). Playbook A: the user name from the SSH log, if any |
| `f.user.valid` | boolean | Looks like a real sAMAccountName (≤ 20 safe characters) |
| `f.user.protected` | boolean | On `PROTECTED_ACCOUNTS` (or invalid): the pipeline will never disable it |
| `f.member`, `f.group` | string or `null` | Playbook B: the member added and the group changed |
| `f.intel` | object or `null` | Reputation results; `null` when nothing was asked (playbook B) |
| `f.intel.cached` | boolean | Results reused from the 24-hour cache |

## Reputation results

Each source has a `status`:
- `'ok'`: the numbers below are present.
- `'unavailable'`: the service failed (timeout, quota, bad key). This means **unknown**, not clean. `detail` says why.
- `'skipped'`: not asked (the IP is not public, or there is no IP).

Check with `ok('abuseipdb', f)` before reading a number.

| Fact | Meaning |
|---|---|
| `f.intel.abuseipdb.confidence` | AbuseIPDB abuse confidence, 0–100 (last 90 days) |
| `f.intel.abuseipdb.reports` | Number of reports (90 days) |
| `f.intel.abuseipdb.reporters` | Number of distinct reporters |
| `f.intel.abuseipdb.whitelisted` | AbuseIPDB's own list of known-good services |
| `f.intel.abuseipdb.tor` | Tor exit node |
| `f.intel.abuseipdb.usage` | e.g. `'Data Center/Web Hosting/Transit'`, `'Fixed Line ISP'` |
| `f.intel.virustotal.malicious` | Number of VirusTotal engines flagging the IP as malicious |
| `f.intel.virustotal.suspicious` | Number flagging it as suspicious |
| `f.intel.virustotal.reputation` | VirusTotal community score (negative = bad) |
| `f.intel.otx.pulses` | Number of AlienVault OTX pulses that mention the IP |

## Real values seen in the lab

| IP | AbuseIPDB | VirusTotal | OTX | Date |
|---|---|---|---|---|
| 1.1.1.1 (Cloudflare DNS) | 0% confidence, 107 reports, whitelisted | 0 malicious, 0 suspicious, reputation 115 | 0 pulses | 2026-10-09 |
| 211.253.x.x (blocklist.de SSH, KR) | 100%, 5,457 reports | 12 malicious, 5 suspicious, reputation −5 | 50 pulses | 2026-10-09 |
| 203.128.x.x (blocklist.de SSH, PK) | 100%, 1,237 reports | 9 malicious, 2 suspicious, reputation −2 | 16 pulses | 2026-10-09 |
| 200.73.x.x (blocklist.de SSH, AR) | 100%, 189 reports | 7 malicious, 3 suspicious, reputation −2 | 2 pulses | 2026-10-09 |

A clean service can still have reports (107 here): use confidence and whitelisting, not the raw report count alone. Attacker IPs are masked (first two octets only); the full list stays on the tools VM.

## Things worth deciding in your table

- How much an attack on a critical server (`f.agent.critical`) adds.
- What a failed lookup is worth. "Unavailable" should never make an alert look safer.
- OTX pulses can be noisy: popular hosting and CDN addresses sometimes appear in pulses as collateral. (1.1.1.1 had 0 pulses on 2026-10-09, so OTX filters at least the best-known services.) Compare with the clean fixtures before giving OTX many points.
- Whether AbuseIPDB's `whitelisted` deserves negative points.
- Playbook B has no reputation data. Its score comes from the rule level, the target and the account.
- The thresholds: which totals are medium, high and critical, and from which severity an approval is offered (`APPROVAL_FROM`).
