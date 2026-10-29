#!/bin/bash
# Switch the pipeline between "manual" (intake unpublished: Wazuh still raises alerts, but nothing reaches
# Telegram and nothing is proposed or done) and "auto" (intake published again). Used for the manual
# baseline in M5. Run on the tools VM with sudo:   sudo bash pipeline_mode.sh manual|auto|status
# The results workflow stays on in both modes (it only reports what agents did).
set -e
MODE=${1:-status}
probe() {   # 404 = webhook not registered (manual); 403 = registered, secret missing (auto)
    curl -s -o /dev/null -w '%{http_code}' -X POST http://192.168.145.20:5678/webhook/wazuh-alert
}
wait_up() {
    for i in $(seq 1 60); do curl -fs -o /dev/null http://192.168.145.20:5678/healthz && return 0; sleep 2; done
    echo "n8n did not come back" >&2; exit 1
}
case "$MODE" in
    manual)
        docker exec n8n n8n unpublish:workflow --id=socWazuhIntake01 > /dev/null
        docker restart n8n > /dev/null; wait_up ;;
    auto)
        docker exec n8n n8n publish:workflow --id=socWazuhIntake01 > /dev/null
        docker restart n8n > /dev/null; wait_up ;;
    status) ;;
    *) echo "usage: $0 manual|auto|status" >&2; exit 2 ;;
esac
# n8n reports healthy a few seconds before it has (un)registered its webhooks: wait for the expected state
want=$([ "$MODE" = manual ] && echo 404 || echo 403)
for i in $(seq 1 20); do
    code=$(probe)
    [ "$MODE" = status ] || [ "$code" = "$want" ] && break
    sleep 2
done
case "$code" in
    404) echo "pipeline mode: MANUAL (intake webhook not registered: no Telegram, no proposals)" ;;
    403) echo "pipeline mode: AUTO (intake webhook live)" ;;
    *)   echo "pipeline mode: unknown (webhook answered HTTP $code)" ;;
esac
