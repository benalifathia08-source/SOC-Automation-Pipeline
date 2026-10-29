// =====================================================================================================
// Alert scoring for the SOC automation pipeline. The table is the analyst's; the engine below applies it.
// =====================================================================================================
// How it works: every rule whose test is true adds its points (negative points are allowed, e.g. for
// a known-good service). The total is mapped to a severity with SEVERITY_THRESHOLDS. Each matching
// rule's "reason" is printed in the Telegram message, so write reasons an analyst understands at a glance.
//
// The facts each rule can read are listed in scoring/FACTS.md. Lookups can be "ok", "unavailable"
// (the service failed: unknown, NOT clean) or "skipped" (never asked: private IP, playbook B, ...).
// Always check ok('virustotal', f) before reading a number from a lookup.
//
// Test your table: scripts/Test-Scoring.ps1 (runs tests/scoring/fixtures.json and shows each score).
// The pipeline picks up a change when the workflow is re-imported (scripts/Deploy-Workflow.ps1).

// Table written by Fathia (2026-10-09). Design choices: README.md (Scoring).

// Total points -> severity. Below 30 = low.
const SEVERITY_THRESHOLDS = { medium: 30, high: 60, critical: 90 };
const APPROVAL_FROM = 'high';   // high and critical get Approve / Reject buttons

const RULES = [
  // ---- Applies to every alert ----
  {
    id: 'R1', points: 20, reason: 'Wazuh rule level 10 or higher',
    when: (f) => f.alert.rule_level >= 10,
  },
  {
    id: 'R2', points: 20, reason: 'The target is a critical server',
    when: (f) => f.agent.critical,
  },

  // ---- Playbook A: reputation of the attacking IP ----
  {
    id: 'R3', points: 40, reason: 'AbuseIPDB confidence 75% or more',
    when: (f) => ok('abuseipdb', f) && f.intel.abuseipdb.confidence >= 75,
  },
  {
    id: 'R4', points: 20, reason: 'AbuseIPDB confidence between 25% and 74%',
    when: (f) => ok('abuseipdb', f)
      && f.intel.abuseipdb.confidence >= 25 && f.intel.abuseipdb.confidence < 75,
  },
  {
    id: 'R5', points: 25, reason: 'At least 3 VirusTotal engines flag the IP as malicious',
    when: (f) => ok('virustotal', f) && f.intel.virustotal.malicious >= 3,
  },
  {
    id: 'R6', points: -40, reason: 'AbuseIPDB lists the IP as a known-good service',
    when: (f) => ok('abuseipdb', f) && f.intel.abuseipdb.whitelisted === true,
  },
  {
    id: 'R7', points: 10, reason: 'A reputation lookup failed: unknown, not clean',
    when: (f) => SOURCES.some((s) => f.intel?.[s]?.status === 'unavailable'),
  },

  // ---- Playbook B: privileged AD group changed (no reputation data exists) ----
  {
    id: 'R8', points: 60, reason: 'Privileged group changed by a non-approved account',
    when: (f) => f.playbook === 'B',
  },
];

// =====================================================================================================
// Engine. No need to edit below this line.
// =====================================================================================================
const SOURCES = ['abuseipdb', 'virustotal', 'otx'];
const SEVERITIES = ['low', 'medium', 'high', 'critical'];

function ok(source, f) {
  return f.intel?.[source]?.status === 'ok';
}

function score(facts) {
  let points = 0;
  const reasons = [];
  const errors = [];
  for (const rule of RULES) {
    let hit = false;
    try {
      hit = rule.when(facts) === true;
    } catch (e) {
      errors.push(`${rule.id}: ${e.message}`);   // a broken rule is reported, never silently ignored
    }
    if (hit) {
      points += rule.points;
      reasons.push({ id: rule.id, points: rule.points, reason: rule.reason });
    }
  }
  let severity = 'low';
  for (const s of ['medium', 'high', 'critical']) {
    if (points >= SEVERITY_THRESHOLDS[s]) severity = s;
  }
  const approval = facts.playbook !== null
    && SEVERITIES.indexOf(severity) >= SEVERITIES.indexOf(APPROVAL_FROM);
  return { points, severity, reasons, approval, errors };
}
