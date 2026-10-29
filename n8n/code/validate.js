// ---- Validate and dedupe ----
// Turns the raw Wazuh alert into "facts". Everything in an alert can be influenced by an attacker
// (usernames and IPs come from log lines), so a value is only used if it passes a strict check.
// Returns no item for a repeat inside the dedupe window, which ends the execution quietly.
// One webhook call = one alert = one item.

// IP and account checks (classifyIp, classifyUser) come from iplib.js, inserted before this file.

const store = $getWorkflowStaticData('global');
store.seen = store.seen || {};
store.cache = store.cache || {};
const now = Date.now();

// Forget old dedupe entries and stale cache entries
for (const [k, v] of Object.entries(store.seen)) {
  if (now - v.first > DEDUPE_MINUTES * 60000) delete store.seen[k];
}
for (const [k, v] of Object.entries(store.cache)) {
  if (now - v.fetched > CACHE_HOURS * 3600000) delete store.cache[k];
}

const body = $input.first().json.body ?? {};
const a = body.alert ?? {};
const d = a.data ?? {};
const win = d.win?.eventdata ?? {};
const ruleId = String(a.rule?.id ?? '');
const playbook = Object.keys(PLAYBOOKS).find((p) => PLAYBOOKS[p].rules.includes(ruleId)) ?? null;
const agentName = String(a.agent?.name ?? '').slice(0, 64);

const ip = classifyIp(d.srcip ?? win.ipAddress);
// Playbook B acts on the account that made the change (the "actor"); the added member is context
const user = classifyUser(playbook === 'B' ? win.subjectUserName : (d.srcuser ?? d.dstuser));

const key = playbook === 'A' ? `A|${ip?.value}` : playbook === 'B' ? `B|${user?.name}` : `-|${ruleId}|${agentName}`;
if (store.seen[key]) {
  store.seen[key].count += 1;
  return [];
}
store.seen[key] = { first: now, count: 1 };

const cached = ip?.valid && ip.public ? store.cache[ip.value] : undefined;
const facts = {
  playbook,
  playbook_name: playbook ? PLAYBOOKS[playbook].name : 'Not mapped to a playbook (report only)',
  alert: {
    id: String(a.id ?? '').slice(0, 40),
    rule_id: ruleId,
    rule_level: Number(a.rule?.level ?? 0),
    description: String(a.rule?.description ?? '').slice(0, 300),
    timestamp: String(a.timestamp ?? '').slice(0, 40),
    mitre: (a.rule?.mitre?.id ?? []).slice(0, 5).map((x) => String(x).slice(0, 20)),
  },
  agent: {
    id: String(a.agent?.id ?? '').slice(0, 8),
    name: agentName,
    critical: CRITICAL_AGENTS.includes(agentName),
  },
  ip,
  user,
  member: playbook === 'B' ? String(win.memberName ?? '').slice(0, 200) : null,
  group: playbook === 'B' ? String(win.targetUserName ?? '').slice(0, 64) : null,
  intel: cached ? { ...cached.intel, cached: true } : null,
  lookup: playbook === 'A' && !!ip?.valid && ip.public && !cached,
  sent_at: String(body.sent_at ?? '').slice(0, 40),
  received_at: new Date(now).toISOString(),
};
return [{ json: facts }];
