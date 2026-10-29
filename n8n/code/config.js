// ---- Pipeline settings shared by the Code nodes (inserted at import time by import_workflow.py) ----
// Not secret. Change here, then re-import the workflow.

// Which Wazuh rules belong to which playbook. Anything else is reported but never acted on.
const PLAYBOOKS = {
  A: { name: 'SSH brute force from the internet', rules: ['5712', '5720', '5763'] },
  B: { name: 'Privileged group changed by a non-approved account', rules: ['100505'] },
};

// Agents whose compromise matters most (raises the score, see scoring/score.js)
const CRITICAL_AGENTS = ['DC01'];

// Addresses the pipeline must never block, whatever the score or the analyst says
// (lab network, VMware gateway/DNS, public DNS resolvers used as "clean" test IPs).
const IP_ALLOWLIST = ['192.168.145.0/24', '1.1.1.1/32', '1.0.0.1/32', '8.8.8.8/32', '8.8.4.4/32'];

// Accounts the pipeline must never disable. Exact names, case-insensitive; prefixes end with '*'.
// DC01 checks again with the same list plus built-in RIDs and tier-0 group membership
// (wazuh/active-response/windows/soc-disable-account.ps1): keep both lists in sync.
const PROTECTED_ACCOUNTS = ['administrator', 'krbtgt', 'guest', 'fathia', 'svc_*', 'adm.*'];

// Response (M3): which agents each playbook may act on, and the Wazuh command used. The Wazuh API user
// "soc-pipeline" is limited to the same agents on the Wazuh side (wazuh/create_api_user.py).
const WAZUH_API = 'https://192.168.145.128:55000';
const RESPONSE_AGENTS = { A: ['006'], B: ['003'] };
const BLOCK_COMMAND = 'soc-block3600';             // firewall-drop with a 1-hour expiry, enforced by the agent
const BLOCK_HOURS = 1;
const VERIFY_BLOCK_COMMAND = '!soc-verify-block';  // read-only firewall check on the agent, 5 s after the block
const DISABLE_COMMAND = 'soc-disable-account0';    // DC01: disables one account and reads it back from AD
const APPROVAL_MINUTES = 15;                       // no answer within this time = no action
const CONFIRM_MINUTES = 5;                         // playbook B: typed confirmation after Approve, or no action

const DEDUPE_MINUTES = 60;   // same playbook + same IP/account within this window: one message only
const CACHE_HOURS = 24;      // reuse reputation results for this long (saves API quota)
const CACHE_MAX = 500;       // cache entries kept at most
