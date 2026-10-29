// ---- Approval text ----
// The question sent with the Approve / Reject buttons. n8n's Telegram approval uses legacy Markdown,
// so every value is cut short and has Markdown's special characters escaped. The full evidence is in
// the alert message sent just before this one.
const md = (v) => String(v ?? '-').slice(0, 120).replace(/([_*`\[])/g, '\\$1');
const ICON = { low: '🟢', medium: '🟡', high: '🟠', critical: '🔴' };

const f = $input.first().json;
const v = f.verdict;
const action = f.playbook === 'B'
  ? [`Disable domain account ${md(f.user?.name)} (it changed ${md(f.group)} on ${md(f.agent.name)}).`,
     'It stays disabled until an administrator re-enables it (Enable-ADAccount).']
  : [`Block ${md(f.ip?.value)} on ${md(f.agent.name)} for ${BLOCK_HOURS} hour (the agent removes it by itself).`];
const lines = [
  '*Approve containment?*',
  `${ICON[v.severity]} ${md(v.severity.toUpperCase())} | score ${md(v.points)} | playbook ${md(f.playbook)}`,
  '',
  ...action,
  `Alert ${md(f.alert.id)} at ${md(f.alert.timestamp)}`,
  '',
  `No answer within ${APPROVAL_MINUTES} minutes = no action. The buttons open n8n on the lab network: use the laptop.`,
];
return [{ json: { ...f, approval_text: lines.join('\n') } }];
