// ---- Result message ----
// The pipeline's own Wazuh alerts, reported back by the agent: block verified in the firewall (100701),
// block missing (100702), verification refused bad input (100703), block expired and removed (652),
// and DC01's account results: disabled and read back from AD (100711), still enabled (100712), refused
// by DC01's own checks (100713), failed (100714), already disabled (100715).
// The agents wrote these log lines themselves, so this is the proof that containment really happened.

const esc = (v) => String(v ?? '-').slice(0, 200)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const body = $input.first().json.body ?? {};
const a = body.alert ?? {};
const d = a.data ?? {};
const rule = String(a.rule?.id ?? '');
const soc = d.soc ?? {};
const rawIp = soc.ip ?? d.srcip ?? d.parameters?.alert?.data?.srcip;
const ip = /^(\d{1,3}\.){3}\d{1,3}$/.test(String(rawIp ?? '')) ? String(rawIp) : null;
const agent = esc(a.agent?.name);
const chains = Array.isArray(soc.chains) ? soc.chains.map(esc).join(' + ') : '';
const account = /^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$/.test(String(soc.account ?? '')) ? String(soc.account) : null;

const TEXT = {
  '100701': `✅ <b>Contained.</b> Block of <code>${esc(ip)}</code> verified in the firewall of ${agent} (${chains}).`,
  '100702': `❌ <b>Block NOT in place</b> for <code>${esc(ip)}</code> on ${agent}. Check the agent's active-responses.log and block by hand if needed.`,
  '100703': `⚠️ Block verification on ${agent} refused an invalid address.`,
  '652': `🔓 Block of <code>${esc(ip)}</code> on ${agent} expired and was removed by the agent.`,
  '100711': `✅ <b>Contained.</b> Account <code>${esc(account)}</code> disabled and verified in Active Directory by ${agent}. Re-enable it only after the investigation (Enable-ADAccount).`,
  '100712': `❌ <b>Account <code>${esc(account)}</code> is still enabled</b> after the disable request on ${agent}. Disable it by hand.`,
  '100713': `🛑 ${agent} <b>refused</b> to disable <code>${esc(account)}</code>: ${esc(soc.reason)}. Handle this account by hand.`,
  '100714': `⚠️ The account action on ${agent} failed (${esc(soc.status)}${soc.reason ? `: ${esc(soc.reason)}` : ''}).`,
  '100715': `ℹ️ Account <code>${esc(account)}</code> was already disabled; nothing changed.`,
};
const text = (TEXT[rule] ?? `ℹ️ Unexpected result rule ${esc(rule)} on ${agent}.`)
  + `\n<i>${esc(a.timestamp)} | rule ${esc(rule)} | alert ${esc(a.id)}</i>`;

return [{ json: { text, rule, ip, account, agent: a.agent?.name ?? null, checked_at: soc.checked_at ?? null, alert_time: a.timestamp ?? null } }];
