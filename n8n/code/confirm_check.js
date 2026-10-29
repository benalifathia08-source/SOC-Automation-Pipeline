// ---- Check typed name ----
// Playbook B, step 2: the analyst typed the account name in n8n's form after clicking "Approve disable".
// The typed text only UNLOCKS the action: the account that gets disabled is always the one from the alert,
// already validated in "Decision", and the typed text is never sent anywhere or shown in a message.
// Spaces around it are ignored and case does not matter (AD account names are case-insensitive);
// anything else, or no answer within CONFIRM_MINUTES, means no action. Needs config.js first.

const f = $('Decision').first().json;
const answer = $input.first().json.data ?? null;     // absent when the wait ran out
const typed = answer
  ? String(Object.entries(answer).find(([k, v]) => k !== 'respondedAt' && typeof v === 'string')?.[1] ?? '').trim().slice(0, 64)
  : null;

const decision = { ...f.decision, confirmed_at: answer?.respondedAt ?? null, confirmation: null };
let request = f.request;
if (answer === null) {
  decision.confirmation = 'timed_out';
  decision.refused = `no typed confirmation within ${CONFIRM_MINUTES} minutes`;
  request = null;
} else if (typed.toLowerCase() !== String(f.request.target).toLowerCase()) {
  decision.confirmation = 'mismatch';
  decision.refused = 'the typed name did not match the account';
  request = null;
} else {
  decision.confirmation = 'matched';
}
return [{ json: { ...f, decision, request } }];
