// ---- Decision ----
// Reads the analyst's answer, then re-checks every guardrail before anything is sent to Wazuh.
// The intake workflow already checked, but this workflow must be safe on its own (defense in depth):
// an approval can never block an allowlisted, private or invalid address, disable a protected or
// invalid account, or act on an agent that is not listed for the playbook.
// Needs config.js and iplib.js first.

const f = $('From intake').first().json;
const answer = $input.first().json.data ?? null;     // absent when the wait ran out
const decision = {
  approved: answer?.approved === true,
  timed_out: answer === null,
  responded_at: answer?.respondedAt ?? new Date().toISOString(),
  refused: null,
};

let request = null;
if (decision.approved) {
  const agents = RESPONSE_AGENTS[f.playbook] ?? [];
  const agentOk = /^\d{3}$/.test(String(f.agent?.id)) && agents.includes(f.agent.id);
  if (!agentOk) {
    decision.refused = `agent ${f.agent?.id} is not allowed for playbook ${f.playbook}`;
  } else if (f.playbook === 'A') {
    const ip = classifyIp(f.ip?.value);              // recomputed here, not trusted from the input
    if (!ip || !ip.valid) decision.refused = 'the source is not a valid IPv4 address';
    else if (!ip.public) decision.refused = `the source is a ${ip.range} address`;
    else if (ip.allowlisted) decision.refused = 'the address is on the allowlist';
    else request = { kind: 'block', target: ip.value, command: BLOCK_COMMAND, alert: { data: { srcip: ip.value } }, verify_command: VERIFY_BLOCK_COMMAND };
  } else if (f.playbook === 'B') {
    const user = classifyUser(f.user?.name);         // recomputed here, not trusted from the input
    if (!user || !user.valid) decision.refused = 'the account name failed validation';
    else if (user.protected) decision.refused = 'the account is protected';
    // DC01 disables and reads the account back in one step, so there is no separate verify call
    else request = { kind: 'disable', target: user.name, command: DISABLE_COMMAND, alert: { data: { dstuser: user.name } }, verify_command: null };
  } else {
    decision.refused = 'this alert has no automated action';
  }
  if (request) Object.assign(request, { agent_id: f.agent.id, agent_name: f.agent.name });
  // Playbook B asks for a second step: type the account name (Fathia's design: friction where it hurts most)
  if (request?.kind === 'disable') {
    const md = (v) => String(v).replace(/([_*`\[])/g, '\\$1');
    request.confirm_text = [
      '*Step 2 of 2: confirm by typing*',
      `Type the account name ${md(request.target)} in the form to disable it.`,
      `Anything else, or no answer within ${CONFIRM_MINUTES} minutes, means no action.`,
    ].join('\n');
  }
}

return [{ json: { ...f, decision, request } }];
