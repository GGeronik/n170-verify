import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { verifyRunReview, RUN_REVIEW_SCHEMA, RUN_REVIEW_MAX_BYTES } from '../src/runReview.js';

const outcomes = ['NO_FINDINGS_REPORTED', 'FINDINGS_REPORTED', 'INSUFFICIENT', 'FAILED', 'TIMED_OUT', 'CANCELLED', 'SKIPPED', 'MISSING_OUTPUT', 'INVALID_OUTPUT', 'INPUT_CHANGED'];
// Original synthetic unit fixture captured from Python's runner boundary with
// its execution seam mocked and 100 original synthetic candles. Docker and
// Freqtrade were never executed. Default tests require only this standalone app.
const fixtures = { NO_FINDINGS_REPORTED: JSON.parse(await readFile(new URL('./fixtures/run-review-unit.json', import.meta.url), 'utf8')) };
const sha = raw => createHash('sha256').update(raw).digest('hex');
const descriptor = (path, raw) => ({ path, size: raw.length, sha256: sha(raw), base64: raw.toString('base64') });
const metadata = d => ({ path: d.path, size: d.size, sha256: d.sha256 });
const rawJson = value => Buffer.from(JSON.stringify(value));
const parse = (value, options) => verifyRunReview(typeof value === 'string' ? value : JSON.stringify(value), options);
const fresh = (outcome = 'NO_FINDINGS_REPORTED') => {
  const packageValue = structuredClone(fixtures[outcome]);
  return { manifest: JSON.parse(Buffer.from(packageValue.manifest.base64, 'base64')),
    buffers: new Map(packageValue.artifacts.map(d => [d.path, Buffer.from(d.base64, 'base64')])) };
};
function repack(state, transport = true) {
  const { manifest, buffers } = state;
  if (transport) for (const attempt of manifest.attempts) {
    const prefix = `attempts/${attempt.id}/`;
    const output = Object.fromEntries([...buffers].filter(([path]) => path.startsWith(prefix + 'output/'))
      .map(([path, raw]) => [path.slice((prefix + 'output/').length), raw.toString('base64')]));
    if (Object.keys(output).length) buffers.set(prefix + 'stdout.log', Buffer.from('Original synthetic unit fixture; engine not executed.\nN170_RESULT_BUNDLE_V1:' + rawJson(output).toString('base64') + '\n'));
  }
  const artifacts = [...buffers].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([path, raw]) => descriptor(path, raw));
  manifest.artifacts = artifacts.map(metadata);
  manifest.inputs = manifest.artifacts.filter(d => d.path.includes('/input/'));
  for (const a of manifest.attempts) a.artifacts = manifest.artifacts.filter(d => d.path.startsWith(`attempts/${a.id}/`));
  return { schema: RUN_REVIEW_SCHEMA, manifest: descriptor('manifest.json', rawJson(manifest)), artifacts };
}
function editWorker(state, callback) {
  const path = 'attempts/000/output/worker-result.json';
  const worker = JSON.parse(state.buffers.get(path)); callback(worker);
  state.buffers.set(path, rawJson(worker));
}
function summary(state, outcome) {
  const a = state.manifest.attempts[0]; a.outcome = outcome; a.reason_codes = [outcome];
  const assessed = ['NO_FINDINGS_REPORTED', 'FINDINGS_REPORTED'].includes(outcome);
  state.manifest.summary = { status: assessed ? outcome : 'NOT_ASSESSABLE', selected_count: 1,
    assessed_count: Number(assessed), findings_count: Number(outcome === 'FINDINGS_REPORTED'),
    outcome_counts: Object.fromEntries([...outcomes].sort().map(k => [k, Number(k === outcome)])) };
}
function rebindInputs(state) {
  const input = 'attempts/000/input/';
  const inventory = [...state.buffers].filter(([p]) => p.startsWith(input) && p !== input + 'request.json')
    .sort(([a], [b]) => a < b ? -1 : 1).map(([p, raw]) => metadata(descriptor(p.slice(input.length), raw)));
  const request = JSON.parse(state.buffers.get(input + 'request.json')); request.input_inventory = inventory;
  const requestRaw = rawJson(request); state.buffers.set(input + 'request.json', requestRaw);
  editWorker(state, worker => { worker.input_inventory = inventory; worker.request_sha256 = sha(requestRaw); });
}
async function invalid(value, options) {
  const report = await parse(value, options);
  assert.equal(report.integrity, 'INVALID', JSON.stringify(report));
  assert.equal(report.status, 'NOT_ASSESSABLE'); assert.equal(report.summary, null);
  assert.deepEqual(report.attempts, []); assert.deepEqual(report.artifacts, []);
  assert.equal(report.reproducibility.status, 'NOT_REPRODUCIBLE');
  assert.match(report.reason_codes[0], /^[A-Z][A-Z0-9_]+$/);
  return report;
}

// Derive unsuccessful and findings cases explicitly in test code. These remain
// attacker-authored, internally consistent unit receipts, not engine evidence.
for (const outcome of outcomes.slice(1)) {
  const state = fresh(); summary(state, outcome);
  if (outcome === 'FINDINGS_REPORTED') {
    editWorker(state, w => { w.analysis.has_bias = true; w.analysis.biased_entry_signals = 1; w.analysis.biased_indicators = ['future_close']; });
    state.buffers.set('attempts/000/output/lookahead.csv', Buffer.from('filename,strategy,has_bias,total_signals,biased_entry_signals,biased_exit_signals,biased_indicators\nClean.py,Clean,True,10,1,0,future_close\n'));
  } else if (outcome === 'FAILED' || outcome === 'INSUFFICIENT') {
    editWorker(state, w => { w.outcome = outcome; });
    if (outcome === 'FAILED') state.manifest.attempts[0].exit_code = 1;
  } else if (outcome === 'MISSING_OUTPUT') state.buffers.delete('attempts/000/output/lookahead.csv');
  else if (outcome === 'INVALID_OUTPUT') state.buffers.set('attempts/000/output/lookahead.csv', Buffer.from('Original malformed output control'));
  else if (outcome === 'INPUT_CHANGED') editWorker(state, w => { w.input_inventory = []; });
  else if (outcome === 'SKIPPED') {
    state.buffers.clear();
    Object.assign(state.manifest.attempts[0], { argv: [], environment: {}, started_at: null, exit_code: null });
    delete state.manifest.attempts[0].container_name; delete state.manifest.attempts[0].cleanup_confirmed;
  } else if (['TIMED_OUT', 'CANCELLED'].includes(outcome)) {
    for (const key of [...state.buffers.keys()]) if (key.includes('/output/')) state.buffers.delete(key);
    state.buffers.set('attempts/000/stdout.log', Buffer.alloc(0));
    state.manifest.attempts[0].exit_code = 137; state.manifest.attempts[0].cleanup_confirmed = true;
    delete state.manifest.attempts[0].environment.observed;
  }
  fixtures[outcome] = repack(state);
}

test('independent browser verifier accepts original synthetic unit receipts and retains every outcome', async () => {
  for (const outcome of outcomes) {
    const report = await parse(fixtures[outcome]);
    assert.equal(report.integrity, 'VALID', `${outcome}: ${report.reason_codes}`);
    assert.equal(report.attempts[0].outcome, outcome);
    assert.equal(report.summary.outcome_counts[outcome], 1);
    assert.equal(report.status, ['NO_FINDINGS_REPORTED', 'FINDINGS_REPORTED'].includes(outcome) ? outcome : 'NOT_ASSESSABLE');
    assert.equal(report.reproducibility.status, outcome === 'SKIPPED' ? 'NOT_REPRODUCIBLE' : 'READY_TO_RERUN');
    assert.match(report.trust.authenticity, /unsigned/);
    assert.match(report.trust.execution, /not witnessed/);
    assert.match(report.trust.completeness, /previous trials.*unknown/);
    assert.match(report.trust.reproduction, /not established/);
  }
});

test('detached manifest pin is checked against exact bytes and never implies authentication', async () => {
  const original = fixtures.NO_FINDINGS_REPORTED;
  const accepted = await parse(original, { manifestSha256: original.manifest.sha256 });
  assert.equal(accepted.integrity, 'VALID'); assert.equal(accepted.manifest_pin, 'matched');
  assert.match(accepted.trust.authenticity, /unsigned/);
  for (const manifestSha256 of ['0'.repeat(64), 'A'.repeat(64), true, '', null]) {
    const rejected = await invalid(original, { manifestSha256 });
    assert.equal(rejected.manifest_pin, 'mismatched_or_invalid');
  }
  const altered = fresh(); altered.manifest.started_at = 'another local untrusted time';
  await invalid(repack(altered), { manifestSha256: original.manifest.sha256 });
});

test('digest and size assertions cannot substitute for recomputed artifact bytes', async () => {
  for (const change of [
    p => { p.artifacts[0].sha256 = '0'.repeat(64); },
    p => { p.artifacts[0].size++; },
    p => { p.manifest.sha256 = '0'.repeat(64); },
    p => { p.artifacts[0].base64 = Buffer.from('changed input').toString('base64'); },
    p => { p.artifacts.pop(); },
    p => { p.artifacts.push(descriptor('extra.txt', Buffer.from('extra'))); },
  ]) { const p = structuredClone(fixtures.NO_FINDINGS_REPORTED); change(p); await invalid(p); }
});

test('canonical paths, order, complete inventory and case collisions are enforced', async () => {
  for (const path of ['../input', '/absolute', 'a//b', 'a/./b', 'a/../b', 'a\\b', 'a%2fb', 'a:b', 'a\u0000b', 'é', 'manifest.json', 'Manifest.json', 'manifest.json/child']) {
    const p = structuredClone(fixtures.NO_FINDINGS_REPORTED); p.artifacts[0].path = path; await invalid(p);
  }
  for (const change of [
    p => p.artifacts.reverse(),
    p => p.artifacts.splice(1, 0, structuredClone(p.artifacts[0])),
    p => p.artifacts.splice(1, 0, { ...p.artifacts[0], path: p.artifacts[0].path.toUpperCase() }),
    p => p.artifacts.push(descriptor('attempts/000/input', Buffer.alloc(0))),
  ]) { const p = structuredClone(fixtures.NO_FINDINGS_REPORTED); change(p); await invalid(p); }
  const state = fresh(); state.buffers.set('attempts/007/stdout.log', Buffer.alloc(0)); await invalid(repack(state));
});

test('base64 must use canonical padded RFC 4648 and respect file bounds', async () => {
  for (const encoded of ['Zg', 'Zg=', 'Zh==', 'Zm9=', 'Zg==\n', 'Zg== ', '-w==', '____', '=AAA', 'AAAA=']) {
    const p = structuredClone(fixtures.NO_FINDINGS_REPORTED); p.artifacts[0].base64 = encoded; await invalid(p);
  }
  for (const size of [true, -1, -0.1, 1.5, 16 * 1024 * 1024 + 1, Number.MAX_SAFE_INTEGER + 1]) {
    const p = structuredClone(fixtures.NO_FINDINGS_REPORTED); p.artifacts[0].size = size; await invalid(p);
  }
  const p = structuredClone(fixtures.NO_FINDINGS_REPORTED); p.artifacts = Array.from({ length: 129 }, () => p.artifacts[0]); await invalid(p);
});

test('valid large opaque logs are handled without regular-expression stack exhaustion', async () => {
  const state = fresh(); state.buffers.set('attempts/000/stderr.log', Buffer.alloc(8 * 1024 * 1024, 65));
  const report = await parse(repack(state));
  assert.equal(report.integrity, 'VALID', report.reason_codes);
  assert.equal(report.artifacts.find(item => item.path.endsWith('/stderr.log')).size, 8 * 1024 * 1024);
});

test('strict JSON rejects duplicates, escaped duplicate keys, unsafe numbers, surrogates and depth', async () => {
  const original = JSON.stringify(fixtures.NO_FINDINGS_REPORTED);
  for (const text of ['', '{}', 'null', '[]', 'true', '\ufeff{}', '{} trailing', '{"x":NaN}', '{"x":1e999}',
    '{"x":9007199254740993}', '{"x":1e100}', '{"x":-0}', '{"x":"\\ud800"}', '{"x":"\\udfff"}',
    '{"x":"\u0000"}', '{"x":"\\q"}', '{"x":01}', '{"x":true,}', '{"x":[true,]}',
    '{"schema":"n170.run-review.v1",' + original.slice(1), '{"\\u0073chema":"n170.run-review.v1",' + original.slice(1),
    '['.repeat(25) + '0' + ']'.repeat(25), '{"x":[' + '0,'.repeat(200000) + '0]}',
    '{"x":"' + 'é'.repeat(2 * 1024 * 1024 + 1) + '"}',
  ]) await invalid(text);
  for (const key of ['__proto__', 'constructor', 'prototype']) await invalid(`{"${key}":{},${original.slice(1)}`);
  assert.equal({}.authenticated, undefined);
  await invalid(' '.repeat(RUN_REVIEW_MAX_BYTES + 1));
});

test('unknown envelope and receipt fields and upgraded trust claims fail closed', async () => {
  for (const change of [
    p => { p.schema = 'n170.run-review.v2'; }, p => { p.signature = 'forged'; },
    p => { p.manifest.authenticated = true; }, p => { p.artifacts[0].command = 'execute'; },
  ]) { const p = structuredClone(fixtures.NO_FINDINGS_REPORTED); change(p); await invalid(p); }
  for (const change of [
    m => { m.authenticated = true; }, m => { m.engine.proof = 'TEE'; },
    m => { m.request.url = 'https://invalid.example'; }, m => { m.attempts[0].certified = true; },
    m => { m.trust.authenticity = 'authenticated'; }, m => { m.schema = 'other'; }, m => { m.state = 'RUNNING'; },
  ]) { const state = fresh(); change(state.manifest); await invalid(repack(state)); }
});

test('attempt selection, complete accounting and failed summaries cannot be silently promoted', async () => {
  for (const change of [
    m => { m.attempts = []; }, m => { m.attempts.push(structuredClone(m.attempts[0])); },
    m => { m.request.strategies.push('Omitted'); }, m => { m.attempts[0].id = '001'; },
    m => { m.attempts[0].strategy = 'Other'; }, m => { m.attempts[0].state = 'RUNNING'; },
    m => { m.attempts[0].exit_code = false; }, m => { m.attempts[0].reason_codes = []; },
    m => { m.summary.assessed_count = true; }, m => { m.summary.selected_count = 0; },
  ]) { const state = fresh(); change(state.manifest); await invalid(repack(state)); }
  for (const outcome of outcomes.filter(o => !['NO_FINDINGS_REPORTED', 'FINDINGS_REPORTED'].includes(o))) {
    const state = fresh(outcome); summary(state, 'NO_FINDINGS_REPORTED'); await invalid(repack(state, false));
  }
});

test('request, staged configuration and selected input bytes must agree independently', async () => {
  for (const change of [
    state => state.buffers.delete('attempts/000/input/request.json'),
    state => state.buffers.delete('attempts/000/input/engine_worker.py'),
    state => state.buffers.set('attempts/000/input/strategies/Clean.py', Buffer.from('# changed source')),
    state => state.buffers.set('attempts/000/input/config.json', Buffer.from('{}')),
    state => state.buffers.set('attempts/000/input/config.json', Buffer.from(state.buffers.get('attempts/000/input/config.json').toString().replace('1.0', '1'))),
    state => { const p = 'attempts/000/input/request.json'; const value = JSON.parse(state.buffers.get(p)); value.timeout_seconds++; state.buffers.set(p, rawJson(value)); },
  ]) { const state = fresh(); change(state); await invalid(repack(state)); }
});

test('fully rebound invalid candle bytes still fail the supported data contract', async () => {
  for (const edit of [rows => rows.splice(0, rows.length - 99), rows => { rows[0][0]++; }, rows => { rows[1][0] = rows[0][0]; },
    rows => { rows[0][1] = -1; }, rows => { rows[0][2] = 0; }, rows => { rows[0][5] = -1; }, rows => { rows[0][0] = true; }]) {
    const state = fresh(); const path = 'attempts/000/input/data/BTC_USDT-5m.json'; const rows = JSON.parse(state.buffers.get(path));
    edit(rows); state.buffers.set(path, rawJson(rows)); rebindInputs(state); await invalid(repack(state));
  }
});

test('exact invocation and isolated runtime declarations are checked as data only', async () => {
  for (const change of [
    a => { a.argv[a.argv.indexOf('--network') + 1] = 'host'; }, a => { a.argv.push('--privileged'); },
    a => { a.argv = ['sh', '-c', 'echo unsafe']; }, a => { a.environment.network = 'host'; },
    a => { a.environment.uid = 0; }, a => { a.cleanup_confirmed = true; }, a => { a.container_name = 'other'; },
  ]) { const state = fresh(); change(state.manifest.attempts[0]); await invalid(repack(state)); }
});

test('present worker engine, method, input, environment and output claims are checked for failures too', async () => {
  for (const outcome of ['NO_FINDINGS_REPORTED', 'INSUFFICIENT', 'FAILED']) for (const change of [
    w => { w.request_sha256 = '0'.repeat(64); }, w => { w.strategy = 'Other'; },
    w => { w.engine.source_files[0].size++; }, w => { w.engine.source_after_sha256 = '0'.repeat(64); },
    w => { w.engine_arguments.minimum_trade_amount++; }, w => { w.environment.uid = 0; },
    w => { w.effective_config_sha256 = '0'.repeat(64); }, w => { w.offline_adapter.market_metadata_sha256 = '0'.repeat(64); },
    w => { w.analysis.has_bias = 1; }, w => { w.analysis.total_signals = true; },
  ]) { const state = fresh(outcome); editWorker(state, change); await invalid(repack(state)); }
});

test('CSV observations are independently recomputed rather than trusting worker counts', async () => {
  for (const csv of [
    'filename,strategy,has_bias,total_signals,biased_entry_signals,biased_exit_signals,biased_indicators\nOther.py,Other,False,10,0,0,\n',
    'filename,strategy,has_bias,total_signals,biased_entry_signals,biased_exit_signals,biased_indicators\nClean.py,Clean,False,0,0,0,\n',
    'filename,strategy,has_bias,total_signals,biased_entry_signals,biased_exit_signals,biased_indicators\nClean.py,Clean,False,5,0,0,\n',
    'filename,strategy,has_bias,total_signals,biased_entry_signals,biased_exit_signals,biased_indicators\nClean.py,Clean,False,11,0,0,\n',
    'filename,strategy,has_bias,total_signals,biased_entry_signals,biased_exit_signals,biased_indicators\nClean.py,Clean,False,10,1,0,\n',
    'filename,strategy,has_bias,total_signals,biased_entry_signals,biased_exit_signals,biased_indicators\nClean.py,Clean,False,10,0,0,"unterminated',
    'filename,strategy,has_bias,total_signals,biased_entry_signals,biased_exit_signals,biased_indicators\nClean.py,Clean,False,10,0,0,\nClean.py,Clean,False,10,0,0,\n',
  ]) { const state = fresh(); state.buffers.set('attempts/000/output/lookahead.csv', Buffer.from(csv)); await invalid(repack(state)); }
});

test('stdout transport and retained outputs must match even after all hashes are recomputed', async () => {
  for (const outcome of ['NO_FINDINGS_REPORTED', 'INSUFFICIENT', 'FAILED']) {
    const state = fresh(outcome); state.buffers.set('attempts/000/output/lookahead.csv', Buffer.from('changed'));
    await invalid(repack(state, false));
  }
  const duplicate = fresh(); const path = 'attempts/000/stdout.log'; duplicate.buffers.set(path, Buffer.concat([duplicate.buffers.get(path), duplicate.buffers.get(path)]));
  await invalid(repack(duplicate, false));
});

test('malformed worker and absent outputs retain their explicit unsuccessful status', async () => {
  const malformed = fresh(); summary(malformed, 'INVALID_OUTPUT'); malformed.buffers.set('attempts/000/output/worker-result.json', Buffer.from('{bad original output'));
  const result = await parse(repack(malformed)); assert.equal(result.integrity, 'VALID', result.reason_codes); assert.equal(result.status, 'NOT_ASSESSABLE');
  assert.equal(result.attempts[0].outcome, 'INVALID_OUTPUT');
  const missing = fresh(); summary(missing, 'MISSING_OUTPUT');
  for (const key of [...missing.buffers.keys()]) if (key.includes('/output/')) missing.buffers.delete(key);
  missing.buffers.set('attempts/000/stdout.log', Buffer.alloc(0));
  assert.equal((await parse(repack(missing))).integrity, 'VALID');
});

test('self-authored byte-consistent source is not executed or promoted into authenticated execution', async () => {
  const state = fresh();
  state.buffers.set('attempts/000/input/strategies/Clean.py', Buffer.from('globalThis.__N170_IMPORTED = true; throw new Error("must never execute");'));
  rebindInputs(state);
  const report = await parse(repack(state));
  assert.equal(report.integrity, 'VALID', report.reason_codes); assert.equal(globalThis.__N170_IMPORTED, undefined);
  assert.match(report.trust.execution, /not witnessed/); assert.match(report.trust.authenticity, /unsigned/);
  assert.match(report.trust.completeness, /selected attempts only/);
});

test('missing selected inputs remain explicit reproduction prerequisites', async () => {
  const report = await parse(fixtures.SKIPPED);
  assert.equal(report.integrity, 'VALID'); assert.equal(report.reproducibility.status, 'NOT_REPRODUCIBLE');
  assert.equal(report.reproducibility.missing.length, 5);
  assert.ok(report.reproducibility.missing.some(path => path.endsWith('/strategies/Clean.py')));
  const missing = fresh(); missing.buffers.delete('attempts/000/input/strategies/Clean.py'); await invalid(repack(missing));
  const partial = fresh('SKIPPED'); partial.buffers.set('attempts/000/input/config.json', fresh().buffers.get('attempts/000/input/config.json'));
  const staged = await parse(repack(partial));
  assert.equal(staged.integrity, 'VALID', staged.reason_codes);
  assert.equal(staged.attempts[0].outcome, 'SKIPPED'); assert.equal(staged.reproducibility.status, 'NOT_REPRODUCIBLE');
  assert.equal(staged.reproducibility.missing.length, 4);
  assert.equal(staged.reproducibility.missing.includes('attempts/000/input/config.json'), false);
});

test('retained original pinned-engine receipts pass the independent browser verifier', { skip: !process.env.N170_RUN_REVIEW_PACKAGE_ROOT }, async () => {
  // Optional integration consumption: these receipts must come from separately
  // recorded actual runs, not the mocked fixtures above. This test executes no code.
  const packages = Object.fromEntries(await Promise.all(['mixed-controls', 'rerun-a', 'rerun-b', 'timeout', 'cancellation']
    .map(async name => [name, await readFile(join(process.env.N170_RUN_REVIEW_PACKAGE_ROOT, name + '.json'), 'utf8')])));
  const reports = Object.fromEntries(await Promise.all(Object.entries(packages).map(async ([name, pkg]) => [name, await parse(pkg)])));
  for (const [name, report] of Object.entries(reports)) assert.equal(report.integrity, 'VALID', `${name}: ${report.reason_codes}`);
  assert.deepEqual(reports['mixed-controls'].attempts.map(a => a.outcome), ['NO_FINDINGS_REPORTED', 'FINDINGS_REPORTED', 'INSUFFICIENT', 'FAILED']);
  assert.equal(reports['mixed-controls'].status, 'NOT_ASSESSABLE');
  assert.equal(reports['rerun-a'].status, 'FINDINGS_REPORTED');
  assert.equal(reports['rerun-b'].status, 'FINDINGS_REPORTED');
  assert.equal(reports.timeout.attempts[0].outcome, 'TIMED_OUT');
  assert.deepEqual(reports.cancellation.attempts.map(a => a.outcome), ['CANCELLED', 'SKIPPED']);
  assert.equal(reports.cancellation.reproducibility.status, 'NOT_REPRODUCIBLE');
});
