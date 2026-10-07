import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { appendPerformanceStamp, appendCorrectionStamp, canonicalPayload, compareProfiles, createProfile, inspectProfile, normalizeProvenance } from '../src/trackRecord.js';
import { calculateRecordMetrics } from '../src/calculator.js';
import { createSigner, generateProfileKey, sha256Hex } from '../src/signing.js';
import { compareEvidence } from '../scripts/verify-record.mjs';

const csv = (...rows) => `date,nav,external_flow\n${rows.join('\n')}`;
const first = csv('2025-01-01,100,0', '2025-01-02,110,0', '2025-01-03,99,0');
const second = csv('2025-01-03,99,0', '2025-01-04,101,0');
const amended = csv('2025-01-01,100,0', '2025-01-03,105,0');
const text = profile => JSON.stringify(profile);
async function owner() {
  const key = await generateProfileKey();
  const signer = createSigner(key.privateKey, key.publicKey);
  return { signer, profile: await createProfile('Comparison example', signer) };
}
function provenance(scope, currency, format = 'manual-nav-flow', reviewed = true) {
  return { ...normalizeProvenance(), account_scope: scope, currency, format, reviewed };
}
async function comparison(previous, current) {
  const result = await compareProfiles(text(previous), text(current));
  assert.deepEqual(result.changes, compareEvidence(text(previous), text(current)).changes);
  assert.deepEqual(result.changes, (await inspectProfile(text(current), { previousProfile: text(previous) })).checks.previous_copy.changes);
  assert.equal(result.publication_time_established, false);
  return result;
}

test('no earlier copy has no change claim; identical history has a versioned empty change list', async () => {
  const { signer, profile } = await owner();
  const a = await appendPerformanceStamp(profile, first, 252, signer);
  assert.equal((await inspectProfile(text(a))).checks.previous_copy.changes, null);
  assert.deepEqual((await comparison(a, a)).changes, { version: 'n170.verify.comparison.v1', events: [] });
  assert.deepEqual((await comparison(profile, profile)).changes.events, []);
});

test('new periods carry exact checked snapshots without mislabelling normal performance as a correction', async () => {
  const { signer, profile } = await owner();
  const a = await appendPerformanceStamp(profile, first, 252, signer, { provenance: provenance('Taxable account', 'USD') });
  const b = await appendPerformanceStamp(a, second, 365, signer, { provenance: provenance('Selected retirement account', 'EUR', 'owner-entered', false) });
  const initial = (await comparison(profile, a)).changes.events[0];
  assert.equal(initial.before, null);
  const result = await comparison(a, b);
  assert.equal(result.status, 'extended');
  assert.equal(result.changes.events.length, 1);
  const event = result.changes.events[0];
  assert.deepEqual({ kind:event.kind, target:event.target_sequence, reason:event.reason }, { kind:'performance', target:null, reason:null });
  assert.deepEqual(event.period, b.stamps[1].payload.period);
  assert.deepEqual(event.before, {
    sequence:1, period:{start:'2025-01-01',end:'2025-01-03'}, metrics:a.stamps[0].payload.metrics,
    account_scope:'Taxable account', currency:'USD', source_kind:'self_reported', source_format:'manual-nav-flow',
    reviewed:true, periods_per_year:252, calculation_version:'2.0.0', return_observations:2,
  });
  assert.deepEqual(event.after, {
    sequence:2, period:{start:'2025-01-03',end:'2025-01-04'}, metrics:b.stamps[1].payload.metrics,
    account_scope:'Selected retirement account', currency:'EUR', source_kind:'self_reported', source_format:'owner-entered',
    reviewed:false, periods_per_year:365, calculation_version:'2.0.0', return_observations:1,
  });
  assert.equal(text(result.changes).includes('original_sha256'), false);
});

test('successive corrections preserve exact targets, reasons and intermediate signed outcomes', async () => {
  const { signer, profile } = await owner();
  const a = await appendPerformanceStamp(profile, first, 252, signer);
  const b = await appendPerformanceStamp(a, second, 252, signer);
  const c = await appendCorrectionStamp(b, 1, amended, 365, signer, { reason:'Corrected one supplied closing valuation.', provenance:provenance('One selected account', 'USD') });
  const d = await appendCorrectionStamp(c, 3, first, 252, signer, { reason:'Restored the supplied observations after review.', provenance:provenance('Same selected account', 'EUR') });
  const result = await comparison(a, d);
  assert.deepEqual(result.changes.events.map(e => [e.sequence,e.kind,e.target_sequence]), [[2,'performance',null],[3,'correction',1],[4,'correction',3]]);
  const [correction, revisedCorrection] = result.changes.events.slice(1);
  assert.equal(correction.before.sequence, 1);
  assert.equal(correction.before.return_observations, 2);
  assert.equal(correction.after.return_observations, 1);
  assert.deepEqual(correction.before.metrics, a.stamps[0].payload.metrics);
  assert.deepEqual(correction.after.metrics, c.stamps[2].payload.metrics);
  assert.deepEqual(revisedCorrection.before, correction.after);
  assert.equal(revisedCorrection.reason, d.stamps[3].payload.correction.reason);
  assert.deepEqual((await comparison(c, d)).changes.events, [revisedCorrection]);
});

test('the next period compares scope against the latest effective preceding period, not the last correction in history', async () => {
  const { signer, profile } = await owner();
  const a = await appendPerformanceStamp(profile, first, 252, signer);
  const b = await appendPerformanceStamp(a, second, 252, signer, { provenance:provenance('Later account', 'USD') });
  const c = await appendCorrectionStamp(b, 2, csv('2025-01-03,99,0','2025-01-04,102,0'), 252, signer, { reason:'Later period corrected.', provenance:provenance('Corrected later account', 'EUR') });
  const d = await appendCorrectionStamp(c, 1, amended, 252, signer, { reason:'Earlier period corrected.', provenance:provenance('Earlier account', 'GBP') });
  const e = await appendPerformanceStamp(d, csv('2025-01-04,102,0','2025-01-05,104,0'), 252, signer);
  const event = (await comparison(b, e)).changes.events.at(-1);
  assert.equal(event.before.sequence, 3);
  assert.equal(event.before.account_scope, 'Corrected later account');
  assert.equal(event.before.currency, 'EUR');
  assert.deepEqual(event.before.metrics, c.stamps[2].payload.metrics);
});

test('truncated, conflicting and replaced histories never supply an ordinary change summary', async () => {
  const { signer, profile } = await owner();
  const a = await appendPerformanceStamp(profile, first, 252, signer);
  const b = await appendPerformanceStamp(a, second, 252, signer);
  const branch = await appendPerformanceStamp(a, csv('2025-01-03,99,0','2025-01-04,105,0'), 252, signer);
  const other = await owner();
  const replacement = await appendPerformanceStamp(other.profile, first, 252, other.signer);
  for (const [previous,current,status] of [[b,a,'truncated'],[b,branch,'conflicting_history'],[a,replacement,'replacement']]) {
    const result = await comparison(previous,current);
    assert.equal(result.status,status);
    assert.equal(result.changes,null);
  }
});

test('tampering in either file fails before any comparison is returned', async () => {
  const { signer, profile } = await owner();
  const a = await appendPerformanceStamp(profile, first, 252, signer);
  const b = await appendCorrectionStamp(a, 1, amended, 252, signer, { reason:'A reviewed correction.' });
  for (const change of [
    p => { p.stamps[0].signature = 'A'.repeat(86); },
    p => { p.stamps[0].payload.provenance.account_scope = 'Unreviewed replacement scope'; },
    p => { p.stamps[0].payload.metrics.total_return_twr_e8++; },
  ]) {
    const wrongPrevious = structuredClone(a); change(wrongPrevious);
    const wrongCurrent = structuredClone(b); change(wrongCurrent);
    for (const [previous,current] of [[wrongPrevious,b],[a,wrongCurrent]]) {
      await assert.rejects(compareProfiles(text(previous), text(current)));
      assert.throws(() => compareEvidence(text(previous), text(current)));
    }
  }
  const wrongReason = structuredClone(b);
  wrongReason.stamps[1].payload.correction.reason = 'An unsigned replacement reason.';
  await assert.rejects(compareProfiles(text(a),text(wrongReason)));
  assert.throws(() => compareEvidence(text(a),text(wrongReason)));
});

test('legacy records retain exact serialization and calculation semantics in modern comparisons', async () => {
  const fixture = JSON.parse(readFileSync(new URL('../examples/example-profile.json', import.meta.url), 'utf8'));
  assert.deepEqual((await comparison(fixture,fixture)).changes.events, []);
  const { signer, profile } = await owner();
  const modern = await appendPerformanceStamp(profile, first, 252, signer);
  const legacy = structuredClone(modern);
  legacy.schema_version = 'n170.verify.track-record.v3';
  const p = legacy.stamps[0].payload;
  p.schema_version = 'n170.verify.performance-stamp.v3'; p.calculation_version = '1.0.0';
  for (const name of ['serialization_version','event_type','correction','provenance']) delete p[name];
  p.metrics = calculateRecordMetrics(p.relative_returns.map(r=>r.return_e8),252);
  const bytes = new TextEncoder().encode(JSON.stringify(canonicalPayload(p)));
  legacy.stamps[0].sha256 = await sha256Hex(bytes);
  const domain = new TextEncoder().encode('n170.verify.stamp-signature.v3\n');
  const input = new Uint8Array(domain.length+bytes.length);input.set(domain);input.set(bytes,domain.length);
  legacy.stamps[0].signature = await signer.sign(input);
  const preserved = text(legacy.stamps[0]);
  const updated = await appendCorrectionStamp(legacy, 1, amended, 252, signer, { reason:'Reviewed the old period under current calculation rules.' });
  const event = (await comparison(legacy,updated)).changes.events[0];
  assert.equal(text(updated.stamps[0]),preserved);
  assert.equal(event.before.calculation_version,'1.0.0');
  assert.equal(event.after.calculation_version,'2.0.0');
  assert.notEqual(event.before.metrics.annualized_volatility_e8,null);
  assert.equal(event.after.metrics.annualized_volatility_e8,null);
  for(const field of ['account_scope','currency','source_format','reviewed'])assert.equal(event.before[field],null);
});

test('comparison snapshots are detached and cannot mutate verified profile records', async () => {
  const { signer, profile } = await owner();
  const a = await appendPerformanceStamp(profile, first, 252, signer);
  const original = text(a);
  const result = await comparison(profile,a);
  result.changes.events[0].period.start = '2000-01-01';
  result.changes.events[0].after.metrics.total_return_twr_e8 = 42;
  assert.equal(text(a),original);
  assert.deepEqual((await comparison(profile,a)).changes.events[0].after.metrics,a.stamps[0].payload.metrics);
});
