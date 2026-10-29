# Manual baseline: method and checklist

**Question:** how long does it take an analyst to contain the same attacks **by hand**, with the same tools and the same decision rules, but without the pipeline? The pipeline is switched off for these runs (`tools-vm/pipeline_mode.sh manual`): Wazuh still raises the alert, but nothing reaches Telegram and nothing is proposed.

## Method

| | |
|---|---|
| **Start (T0)** | The Wazuh alert's timestamp: rule **5712** (playbook A) or **100505** (playbook B). Taken from Wazuh, not from a stopwatch. |
| **End (T3)** | Containment **in place**, as logged by Wazuh: rule **651** "Host Blocked" for the IP on agent `tools` (A), rule **60111** / event 4725 "account disabled" for the actor (B). The automated runs use the same two end points, so both sides are measured the same way. |
| **Your notes** | Laptop clock (hh:mm:ss) when you **N**oticed the alert, **D**ecided, and finished **V**erifying. They split the time into stages; T0 and T3 come from Wazuh. |
| **Start of a run** | The run is armed with `tests/baseline/fire_a.sh A-n` (or `Fire-B.ps1` for B-n), which fires the attack at a **random moment within the next 2 minutes**, so you have to watch for it, as you would on shift. The automated runs use the same random start. |
| **Time limit** | 15 minutes, as for the pipeline. Not contained by then = recorded as "not contained". |
| **Runs** | Playbook A: **1 practice + 5 counted**. Playbook B: **1 practice + 5 counted**. Each run uses a new attacker (a new blocklist IP, a new `test.rogueN` account). |
| **Per sitting** | One block of A (6 runs), a short break, one block of B (6 runs): about an hour in all. The automated runs (5 A + 5 B) can be another sitting. |
| **Fairness** | Same decision rule as the pipeline (your scoring table), same block command and expiry, same accounts protected. Lab manual times are **optimistic**: you know an attack is coming within two minutes and you are not working a queue. The write-up says so. |

## Before the first run

- Wazuh dashboard → **Threat Hunting → Events**; search `rule.id:5712` (A) or `rule.id:100505` (B); time range "Last 15 minutes"; refresh **every 5 seconds** (time picker → Refresh every).
- Browser tabs open: abuseipdb.com, virustotal.com, otx.alienvault.com.
- A PowerShell window for the commands below.

## Checklist A: SSH brute force from the internet

1. Alert appears → note **N**. Open it: copy `data.srcip`; agent should be `tools` (006).
2. Look the IP up on AbuseIPDB, VirusTotal and OTX.
3. Score it with your table: level 10+ (+20); AbuseIPDB ≥ 75 % (+40) or 25–74 % (+20); VirusTotal ≥ 3 malicious (+25); AbuseIPDB whitelisted (−40). **60 or more → block.** Allowlisted or private → no block. Note **D**.
4. Block for 1 hour (the same command the pipeline uses):
   `ssh fathia@192.168.145.128 "sudo /var/ossec/bin/agent_control -b <IP> -f soc-block3600 -u 006"`
5. Verify: `ssh fathia@192.168.145.20 "sudo iptables -S | grep <IP>"` → two DROP lines (INPUT and FORWARD). Note **V**.
6. Record the run: N, D, V (or "no action" and why).

## Checklist B: privileged group changed by a non-approved account

1. Alert appears → note **N**. Read the actor (`data.win.eventdata.subjectUserName`), the group and the member added.
2. Protected? Built-in (Administrator, krbtgt, Guest), `fathia`, `svc_*`, `adm.*`, or in a tier-0 group:
   `ssh Administrator@192.168.145.10 "(Get-ADUser <actor> -Properties MemberOf).MemberOf"`
   → any of Domain Admins, Enterprise Admins, Schema Admins, Administrators = protected: **do not disable**, handle by hand.
3. Not protected → playbook B is always critical: **disable**. Note **D**.
4. Disable: `ssh Administrator@192.168.145.10 "Disable-ADAccount -Identity <actor>"`
5. Verify: `ssh Administrator@192.168.145.10 "(Get-ADUser <actor>).Enabled"` → `False`. Note **V**.
6. Record the run: N, D, V.

## Practice run

The first run of each block (A-0, B-0) follows the same steps and is **not counted**. It is there to set up the windows, learn the commands and catch mistakes, so that the counted runs measure the work, not the first-time learning.

## After the runs

T0 and T3 for every run are taken from Wazuh and joined with the N / D / V notes in `metrics/baseline-runs.csv`; `metrics/summarize.py` builds the table (median and range per stage, A and B separately). Then the automated runs, the same table for them, and the before/after comparison in the README.
