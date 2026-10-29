// ---- Failure line ----
// Runs in the error workflow whenever a pipeline workflow fails. Builds one JSON line for
// /var/log/soc-pipeline/pipeline.jsonl, which the tools VM's Wazuh agent reads (rule 100720, level 12).
// Writing a local file needs no network, so the alert reaches Wazuh even when Telegram or DNS is down
// (the failure seen on 2026-10-13). The Telegram message after it is a best-effort second channel.
const e = $input.first().json;
const clip = (v, n) => String(v ?? '').replace(/[\r\n]+/g, ' ').slice(0, n);
const record = {
  soc_pipeline: {
    event: 'workflow_failure',
    workflow: clip(e.workflow?.name, 80),
    node: clip(e.execution?.lastNodeExecuted ?? e.trigger?.error?.node?.name, 80),
    message: clip(e.execution?.error?.message ?? e.trigger?.error?.message, 200),
    execution_id: clip(e.execution?.id, 20),
    at: new Date().toISOString(),
  },
};
const line = JSON.stringify(record) + '\n';
const esc = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const r = record.soc_pipeline;
return [{
  json: {
    text: `⚠️ <b>SOC pipeline failure</b>: workflow ${esc(r.workflow)} failed at "${esc(r.node)}" (${esc(r.message)}). Execution ${esc(r.execution_id)}. Check n8n; alerts may have been missed.`,
  },
  binary: { data: { data: Buffer.from(line).toString('base64'), mimeType: 'text/plain', fileName: 'pipeline.jsonl' } },
}];
