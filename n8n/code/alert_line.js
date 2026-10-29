// ---- Alert line ----
// Intake: one JSON line per scored alert for /var/log/soc-pipeline/pipeline.jsonl (read by Wazuh, rule 100721).
// Written BEFORE the Telegram message, so the record exists even if Telegram fails.
const f = $('Build message').first().json;
const clip = (v, n) => String(v ?? '').replace(/[\r\n]+/g, ' ').slice(0, n);
const record = {
  soc_pipeline: {
    event: 'alert_scored',
    alert_id: clip(f.alert.id, 40),
    rule_id: clip(f.alert.rule_id, 10),
    playbook: f.playbook ?? 'none',
    agent: clip(f.agent.name, 40),
    target: clip(f.playbook === 'B' ? f.user?.name : f.ip?.value, 64),
    score: f.verdict.points,
    severity: f.verdict.severity,
    reasons: f.verdict.reasons.map((r) => r.id).join(','),
    offered: f.action.offer === true,
    proposed: clip(String(f.action.text).replace(/<[^>]+>/g, ''), 120),
    alert_time: clip(f.alert.timestamp, 40),
    logged_at: new Date().toISOString(),
  },
};
const line = JSON.stringify(record) + '\n';
return [{ json: {}, binary: { data: { data: Buffer.from(line).toString('base64'), mimeType: 'text/plain', fileName: 'pipeline.jsonl' } } }];
