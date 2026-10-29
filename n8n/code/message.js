// ---- Build message ----
// Telegram message (parse_mode HTML) with the verdict, the reasons and the evidence, plus what the
// pipeline proposes to do. Every value that came from the alert is length-capped and HTML-escaped.
// Low severity is sent silently (no notification sound).

const esc = (v) => String(v ?? '-').slice(0, 200)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const ICON = { low: '🟢', medium: '🟡', high: '🟠', critical: '🔴' };

const f = $input.first().json;
const v = f.verdict;
const lines = [];

lines.push(`${ICON[v.severity]} <b>${v.severity.toUpperCase()}</b> | score ${v.points} | ${f.playbook ? `playbook ${f.playbook}` : 'no playbook'}`);
lines.push(`<b>${esc(f.playbook_name)}</b>`);
lines.push(esc(f.alert.description));
lines.push('');
lines.push(`Target: ${esc(f.agent.name)} (agent ${esc(f.agent.id)})${f.agent.critical ? ' | critical server' : ''}`);
if (f.ip) {
  const tag = !f.ip.valid ? 'invalid' : f.ip.allowlisted ? `${f.ip.range}, allowlisted` : f.ip.range;
  lines.push(`Source IP: <code>${esc(f.ip.value)}</code> (${esc(tag)})`);
}
if (f.user) lines.push(`${f.playbook === 'B' ? 'Actor' : 'User'}: <code>${esc(f.user.name)}</code>${f.user.protected ? ' (protected)' : ''}`);
if (f.member) lines.push(`Member added: ${esc(f.member)}`);
if (f.group) lines.push(`Group: ${esc(f.group)}`);

lines.push('');
lines.push('<b>Why</b>');
if (v.reasons.length === 0) lines.push('• no scoring rule matched');
for (const r of v.reasons) lines.push(`• ${esc(r.reason)} (${r.points > 0 ? '+' : ''}${r.points})`);
for (const e of v.errors) lines.push(`⚠️ scoring rule error: ${esc(e)}`);

const i = f.intel;
if (i && f.ip?.public) {
  const show = (s, text) => (s.status === 'ok' ? text : s.status === 'unavailable' ? `unavailable (${esc(s.detail)})` : 'not asked');
  lines.push('');
  lines.push(`<b>Reputation</b>${i.cached ? ' (cached)' : ''}`);
  lines.push(`• AbuseIPDB: ${show(i.abuseipdb, `${i.abuseipdb.confidence}% confidence, ${i.abuseipdb.reports} reports${i.abuseipdb.tor ? ', Tor exit' : ''}${i.abuseipdb.whitelisted ? ', whitelisted' : ''} | ${esc(i.abuseipdb.isp)} ${esc(i.abuseipdb.country)}`)}`);
  lines.push(`• VirusTotal: ${show(i.virustotal, `${i.virustotal.malicious} malicious, ${i.virustotal.suspicious} suspicious, reputation ${i.virustotal.reputation}`)}`);
  lines.push(`• OTX: ${show(i.otx, `${i.otx.pulses} pulses`)}`);
  const ip = encodeURIComponent(f.ip.value);
  lines.push(`<a href="https://www.abuseipdb.com/check/${ip}">AbuseIPDB</a> | <a href="https://www.virustotal.com/gui/ip-address/${ip}">VirusTotal</a> | <a href="https://otx.alienvault.com/indicator/ip/${ip}">OTX</a>`);
} else if (f.ip && !f.ip.public) {
  lines.push('');
  lines.push('Reputation: not asked (address is not public; it never leaves the lab)');
}

// What the pipeline would do. Buttons and the action itself come in M3 (IP block) and M4 (account).
let action;
if (f.playbook === 'A') {
  if (!f.ip?.valid || !f.ip.public) action = 'none: the source is not a public IPv4 address';
  else if (f.ip.allowlisted) action = 'none: the address is on the allowlist';
  else action = `block <code>${esc(f.ip.value)}</code> on ${esc(f.agent.name)} for 1 hour`;
} else if (f.playbook === 'B') {
  if (!f.user?.valid) action = 'none: the account name failed validation';
  else if (f.user.protected) action = 'none: protected account';
  else action = `disable account <code>${esc(f.user.name)}</code>`;
} else {
  action = 'none: report only';
}
const possible = !action.startsWith('none');
lines.push('');
lines.push(`<b>Proposed action:</b> ${action}${possible && !v.approval ? ' (below the approval threshold: not offered)' : ''}`);
lines.push(`<i>Alert ${esc(f.alert.id)} | rule ${esc(f.alert.rule_id)} level ${esc(f.alert.rule_level)} | ${esc(f.alert.timestamp)}</i>`);

return [{
  json: {
    ...f,
    action: { text: action, possible, offer: possible && v.approval },
    text: lines.join('\n'),
    silent: v.severity === 'low',
  },
}];
