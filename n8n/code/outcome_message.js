// ---- Outcome message ----
// One Telegram line saying what happened after the approval request. Used twice in the response
// workflow: on the "no action" branch (rejected, timed out, refused by a guardrail) and after the
// Wazuh calls (action sent or failed). The final word ("verified in the firewall" / "disabled and
// verified in AD") comes separately from the agent itself through the results workflow.

const esc = (v) => String(v ?? '-').slice(0, 200)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
// The latest decision: after the typed confirmation (playbook B) if that step ran, else after the approval
function latest() {
  try { return $('Check typed name').first().json; } catch (e) { return $('Decision').first().json; }
}
const f = latest();
const d = f.decision;
const r = f.request;
const when = esc(d.responded_at);
const target = f.playbook === 'B' ? `account <code>${esc(f.user?.name)}</code>` : `<code>${esc(f.ip?.value)}</code>`;

// Output of an HTTP node, or undefined if it did not run in this execution
function output(node) {
  try { return $(node).first().json; } catch (e) { return undefined; }
}
function apiError(json) {
  if (!json) return 'not run';
  if (json.error && typeof json.error === 'object') return `${json.error.httpCode ?? ''} ${json.error.message ?? ''}`.trim();
  if (json.error && json.error !== 0) return `Wazuh error ${json.error}: ${json.message ?? ''}`;
  return null;
}

let text;
let status;
if (!r) {
  if (d.timed_out) { status = 'timed_out'; text = `⌛ No answer within ${APPROVAL_MINUTES} minutes: <b>no action</b> on ${target}.`; }
  else if (!d.approved) { status = 'rejected'; text = `🚫 Rejected at ${when}: <b>no action</b> on ${target}.`; }
  else if (d.confirmation === 'timed_out') { status = 'not_confirmed'; text = `⌛ Approved at ${when}, but no typed confirmation within ${CONFIRM_MINUTES} minutes: <b>no action</b> on ${target}.`; }
  else if (d.confirmation === 'mismatch') { status = 'not_confirmed'; text = `✋ Approved at ${when}, but the typed name did not match: <b>no action</b> on ${target}. Act by hand if the account must be disabled.`; }
  else { status = 'refused'; text = `🛑 Approved at ${when}, but <b>refused by a guardrail</b>: ${esc(d.refused)}. No action.`; }
} else {
  const login = output('Wazuh login');
  const action = output('Run action');
  const verify = output('Verify block');
  const what = r.kind === 'disable' ? `disable of account <code>${esc(r.target)}</code>` : `block of <code>${esc(r.target)}</code>`;
  const loginErr = apiError(login) ?? (login?.data?.token ? null : 'no token in the answer');
  const actionErr = loginErr ? 'skipped' : apiError(action) ?? (action?.data?.total_affected_items === 1 ? null : `sent to ${action?.data?.total_affected_items ?? 0} agents`);
  if (loginErr) { status = 'failed'; text = `❌ Approved at ${when}, but the Wazuh API login failed (${esc(loginErr)}). <b>Nothing was done.</b>`; }
  else if (actionErr) { status = 'failed'; text = `❌ Approved at ${when}, but the ${what} request failed (${esc(actionErr)}). <b>Nothing was done.</b>`; }
  else if (r.kind === 'disable') {
    status = 'sent';
    const typedAt = d.confirmed_at ? `, name typed at ${esc(d.confirmed_at)}` : '';
    text = `⏳ Approved at ${when}${typedAt}. The ${what} was sent to ${esc(r.agent_name)}. Waiting for the domain controller to confirm it in Active Directory…`;
  } else {
    status = 'sent';
    const verifyErr = apiError(verify);
    text = `⏳ Approved at ${when}. The ${what} was sent to ${esc(r.agent_name)} for ${BLOCK_HOURS} hour. `
      + (verifyErr ? `The verification request failed (${esc(verifyErr)}): check the agent by hand.` : 'Waiting for the agent to confirm it in the firewall…');
  }
}
return [{ json: { text, status, target: r?.target ?? null, alert_id: f.alert.id, decision: d } }];
