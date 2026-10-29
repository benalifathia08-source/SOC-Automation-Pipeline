#!/bin/bash
# Reproduce the 2026-10-13 incident on purpose and check that the failure is reported (run on the tools VM with sudo).
#   1. Telegram's address ranges are rejected for traffic from the containers (DOCKER-USER chain only;
#      the host itself is not affected). Removed again on exit, whatever happens.
#   2. A harmless event: the block check for a reserved test IP -> rule 100702 -> results workflow ->
#      its Telegram step fails after 3 tries -> n8n's error workflow -> one line in pipeline.jsonl.
#   3. Waits up to 90 s for the line. The manager should then raise rule 100720 (level 12).
set -e
LOG=/var/log/soc-pipeline/pipeline.jsonl
RANGES="149.154.160.0/20 91.108.4.0/22 91.108.8.0/22 91.108.56.0/22"
cleanup() { for r in $RANGES; do iptables -D DOCKER-USER -d "$r" -j REJECT 2>/dev/null || true; done; echo "telegram block removed"; }
trap cleanup EXIT
before=$(wc -l < "$LOG")
for r in $RANGES; do iptables -I DOCKER-USER -d "$r" -j REJECT; done
echo "$(date -u +%T.%3NZ) telegram blocked for containers"
echo '{"parameters":{"alert":{"data":{"srcip":"203.0.113.95"}}}}' | /var/ossec/active-response/bin/soc-verify-block
echo "$(date -u +%T.%3NZ) results event triggered (block check, reserved test IP)"
for i in $(seq 1 45); do
    [ "$(wc -l < "$LOG")" -gt "$before" ] && break
    sleep 2
done
echo "$(date -u +%T.%3NZ) new pipeline log lines: $(( $(wc -l < "$LOG") - before ))"
tail -1 "$LOG"
