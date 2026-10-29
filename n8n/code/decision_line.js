// ---- Decision line ----
// Response: one JSON line per outcome for /var/log/soc-pipeline/pipeline.jsonl (read by Wazuh, rules
// 100722 / 100723). Written BEFORE the Telegram report, so the record exists even if Telegram fails.
// Used on both branches; it reads whichever outcome message ran.
function latest() {
  try { return $('Check typed name').first().json; } catch (e) { return $('Decision').first().json; }
}
function outcome() {
  try { return $('Action message').first().json; } catch (e) { return $('No-action message').first().json; }
}
const f = latest();
const o = outcome();
const d = f.decision;
const clip = (v, n) => String(v ?? '').replace(/[\r\n]+/g, ' ').slice(0, n);
const record = {
  soc_pipeline: {
    event: 'decision',
    alert_id: clip(f.alert.id, 40),
    playbook: f.playbook,
    agent: clip(f.agent.name, 40),
    target: clip(f.playbook === 'B' ? f.user?.name : f.ip?.value, 64),
    outcome: o.status,                                   // sent / failed / rejected / timed_out / refused / not_confirmed
    approved: d.approved === true,
    responded_at: clip(d.responded_at, 40),
    confirmation: d.confirmation ?? 'not needed',         // playbook B: matched / mismatch / timed_out
    confirmed_at: clip(d.confirmed_at, 40),
    refused_reason: clip(d.refused, 120),
    command: clip(f.request?.command, 40),
    logged_at: new Date().toISOString(),
  },
};
const line = JSON.stringify(record) + '\n';
return [{ json: {}, binary: { data: { data: Buffer.from(line).toString('base64'), mimeType: 'text/plain', fileName: 'pipeline.jsonl' } } }];
