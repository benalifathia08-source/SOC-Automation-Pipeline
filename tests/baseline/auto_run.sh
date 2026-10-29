#!/bin/bash
# Timeline of the newest automated run from n8n's own records (run on the tools VM with sudo):
#   sudo bash auto_run.sh
# Prints the newest intake and response executions: T1 (alert message sent), approval request, T2
# (respondedAt), typed confirmation (B), and the action request. Targets are masked.
X="python3 /home/fathia/soc-pipeline/tools-vm/executions.py"
I=$($X 8 | awk '$2=="socWazuhIntake01"{print $1; exit}')
R=$($X 8 | awk '$2=="socResponse00001"{print $1; exit}')
echo "intake $I response $R"
$X 1 --id "$I" | grep -E '^  (Score|Telegram|Start response)'
$X 1 --id "$R" | grep -E '^  (Ask approval|Confirm by typing|Check typed name|Run action)|Approved at|did not match|Rejected|No answer' \
    | sed -E 's/<[^>]+>//g; s/([0-9]+\.[0-9]+)\.[0-9]+\.[0-9]+/\1.x.x/g'
