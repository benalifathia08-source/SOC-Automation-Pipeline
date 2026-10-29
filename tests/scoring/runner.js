// Scoring test runner. scripts/Test-Scoring.ps1 feeds it to Node (inside the n8n container) after
// scoring/score.js, with the fixtures as the FIXTURES constant. A fixture whose "expect" is null is
// only printed; one with an expected severity must match it.
let failed = 0;
for (const fx of FIXTURES) {
  const r = score(fx.facts);
  const verdict = fx.expect === null ? '  (no expectation)' : r.severity === fx.expect ? '  PASS' : `  FAIL (expected ${fx.expect})`;
  if (fx.expect !== null && r.severity !== fx.expect) failed += 1;
  console.log(`${fx.name}\n  ${r.severity.toUpperCase()} | ${r.points} points | approval ${r.approval ? 'yes' : 'no'}${verdict}`);
  for (const x of r.reasons) console.log(`    ${x.points > 0 ? '+' : ''}${x.points}  ${x.id}  ${x.reason}`);
  for (const e of r.errors) console.log(`    ERROR  ${e}`);
}
console.log(failed === 0 ? '\nall expectations met' : `\n${failed} expectation(s) failed`);
process.exitCode = failed === 0 ? 0 : 1;
