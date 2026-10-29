// ---- Collect intel ----
// Reads the three reputation lookups (when they ran), turns each into a small, uniform result and
// caches it for CACHE_HOURS. A lookup that failed (timeout, quota, bad key) is "unavailable", never
// "clean": the score must not drop because a service was down.
// Reached two ways: after the lookups, or straight from "Needs lookup?" (cached, private IP, playbook B).

const facts = $('Validate and dedupe').first().json;

// Output of a lookup node, or undefined if that node did not run in this execution
function output(node) {
  try {
    return $(node).first().json;
  } catch (e) {
    return undefined;
  }
}

function failure(json) {
  const e = json.error;
  const code = e?.httpCode ?? e?.status ?? '';
  const msg = String(e?.message ?? e ?? 'error').slice(0, 120);
  return { status: 'unavailable', detail: code ? `HTTP ${code}: ${msg}` : msg };
}

function abuseipdb(json) {
  if (!json) return { status: 'skipped' };
  if (json.error || !json.data) return failure(json);
  const x = json.data;
  return {
    status: 'ok',
    confidence: Number(x.abuseConfidenceScore ?? 0),
    reports: Number(x.totalReports ?? 0),
    reporters: Number(x.numDistinctUsers ?? 0),
    whitelisted: x.isWhitelisted === true,
    tor: x.isTor === true,
    usage: String(x.usageType ?? '').slice(0, 60),
    isp: String(x.isp ?? '').slice(0, 60),
    country: String(x.countryCode ?? '').slice(0, 2),
    last_reported: String(x.lastReportedAt ?? '').slice(0, 25),
  };
}

function virustotal(json) {
  if (!json) return { status: 'skipped' };
  if (json.error || !json.data?.attributes) return failure(json);
  const x = json.data.attributes;
  const s = x.last_analysis_stats ?? {};
  return {
    status: 'ok',
    malicious: Number(s.malicious ?? 0),
    suspicious: Number(s.suspicious ?? 0),
    harmless: Number(s.harmless ?? 0),
    reputation: Number(x.reputation ?? 0),
    owner: String(x.as_owner ?? '').slice(0, 60),
  };
}

function otx(json) {
  if (!json) return { status: 'skipped' };
  if (json.error || !json.pulse_info) return failure(json);
  return { status: 'ok', pulses: Number(json.pulse_info.count ?? 0) };
}

let intel = facts.intel;     // from the cache, if Validate found one
if (!intel) {
  intel = {
    abuseipdb: abuseipdb(output('AbuseIPDB')),
    virustotal: virustotal(output('VirusTotal')),
    otx: otx(output('OTX')),
    cached: false,
    fetched_at: new Date().toISOString(),
  };
  // Cache only complete answers, so a service that was down is asked again next time
  const complete = ['abuseipdb', 'virustotal', 'otx'].every((s) => intel[s].status === 'ok');
  if (facts.lookup && complete) {
    const store = $getWorkflowStaticData('global');
    store.cache = store.cache || {};
    store.cache[facts.ip.value] = { fetched: Date.now(), intel };
    const keys = Object.keys(store.cache);
    if (keys.length > CACHE_MAX) {
      keys.sort((a, b) => store.cache[a].fetched - store.cache[b].fetched)
        .slice(0, keys.length - CACHE_MAX)
        .forEach((k) => delete store.cache[k]);
    }
  }
}

return [{ json: { ...facts, intel } }];
