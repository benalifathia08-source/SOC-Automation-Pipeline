// ---- IP and account checks, shared by "Validate and dedupe" (intake) and "Decision" (response) ----
// Needs config.js first (IP_ALLOWLIST, PROTECTED_ACCOUNTS).

// IPv4 only for now; IPv6 sources are reported but not looked up or blocked (documented limitation).
function ipv4ToInt(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function inCidr(ipInt, cidr) {
  const [base, bits] = cidr.split('/');
  const mask = Number(bits) === 0 ? 0 : (~0 << (32 - Number(bits))) >>> 0;
  return ((ipInt & mask) >>> 0) === ((ipv4ToInt(base) & mask) >>> 0);
}

// Ranges that are not routable on the internet: never sent to outside services, never blocked
const NON_PUBLIC = [
  ['0.0.0.0/8', 'this network'], ['10.0.0.0/8', 'private'], ['100.64.0.0/10', 'carrier NAT'],
  ['127.0.0.0/8', 'loopback'], ['169.254.0.0/16', 'link-local'], ['172.16.0.0/12', 'private'],
  ['192.0.0.0/24', 'IETF'], ['192.0.2.0/24', 'documentation'], ['192.168.0.0/16', 'private'],
  ['198.18.0.0/15', 'benchmarking'], ['198.51.100.0/24', 'documentation'],
  ['203.0.113.0/24', 'documentation'], ['224.0.0.0/4', 'multicast'], ['240.0.0.0/4', 'reserved'],
];

function classifyIp(raw) {
  if (raw === undefined || raw === null || raw === '') return null;
  const value = String(raw).trim();
  const n = ipv4ToInt(value);
  if (n === null) {
    return { value: value.slice(0, 64), valid: false, public: false, range: 'not a valid IPv4 address', allowlisted: false };
  }
  const hit = NON_PUBLIC.find(([cidr]) => inCidr(n, cidr));
  return {
    value,
    valid: true,
    public: !hit,
    range: hit ? hit[1] : 'public',
    allowlisted: IP_ALLOWLIST.some((c) => inCidr(n, c)),
  };
}

// sAMAccountName: at most 20 characters, no spaces or special characters we would need to quote
function classifyUser(raw) {
  if (raw === undefined || raw === null || raw === '' || raw === '-') return null;
  const name = String(raw).trim();
  const valid = /^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$/.test(name);
  const lower = name.toLowerCase();
  const isProtected = PROTECTED_ACCOUNTS.some((p) =>
    p.endsWith('*') ? lower.startsWith(p.slice(0, -1)) : lower === p);
  return { name: valid ? name : name.slice(0, 64), valid, protected: valid ? isProtected : true };
}
