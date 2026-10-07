import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync, readdirSync, statSync, existsSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseAgentHandoff } from '../src/agentHandoff.js';
const cli = fileURLToPath(new URL('../scripts/prepare-agent-handoff.mjs', import.meta.url));
const fixture = () => JSON.parse(readFileSync(new URL('../examples/agent-handoff-synthetic.json', import.meta.url), 'utf8'));
const sentinel = 'PRIVATE_SENTINEL_NEVER_PRINT';
function workspace(t) { const folder = mkdtempSync(path.join(tmpdir(), 'n170-handoff-cli-')); t.after(() => rmSync(folder, { recursive: true, force: true })); return folder; }
function run(args = [], text = JSON.stringify(fixture()), options = {}) {
  const result = spawnSync(process.execPath, [cli, ...args], { input: text, encoding: 'utf8', timeout: 10000, ...options });
  assert.equal(result.error, undefined); assert.equal(result.stderr, ''); assert.equal(result.signal, null);
  return { ...result, json: JSON.parse(result.stdout) };
}
function privateFixture() {
  const p = fixture();
  p.source.broker = sentinel; p.source.connector = sentinel; p.source.tools = [sentinel]; p.account_scope = sentinel;
  p.mapping = { date: sentinel, nav: sentinel, external_flow: sentinel };
  p.observations.forEach(row => { row.nav = '123456.789012345678'; row.external_flow = '0'; row.source_ref = sentinel; });
  return p;
}

test('CLI default is bounded review status, not financial or source metadata', () => {
  const result = run([], JSON.stringify(privateFixture()));
  assert.equal(result.status, 0); assert.equal(result.json.status, 'ready_for_owner_review');
  assert.deepEqual(result.json.counts, { observations: 4, missing_periods: 0, unsupported_events: 0 });
  for (const value of [sentinel, '123456.789012345678', '2025-01-02', '2025-01-07', 'normalizedCsv', 'sha256']) assert.equal(result.stdout.includes(value), false);
  for (const key of ['source_authenticated','identity_established','independent_time_established','record_signed','browser_storage_changed','financial_values_included','csv_written']) assert.equal(result.json[key], false);
  assert.equal(result.json.owner_review_required, true);
  assert.deepEqual(result.json.pagination, { sender_claim: 'complete', independently_checked: false });
  assert(result.json.warnings.some(item => item.code === 'agent_claims_unverified'));
});

test('CLI explicit stdin matches piped default input', () => {
  assert.deepEqual(run(['-']).json, run().json);
});

test('CLI reads one file without modifying it or creating other files', t => {
  const dir = workspace(t), input = path.join(dir, 'private.json'), text = JSON.stringify(privateFixture());
  writeFileSync(input, text);
  const result = run([input], '', { cwd: dir }); assert.equal(result.status, 0);
  assert.equal(readFileSync(input, 'utf8'), text); assert.deepEqual(readdirSync(dir), ['private.json']);
});

test('zero observations, no retrieval and unknown evidence stay blocked without fabricated time', () => {
  const p = fixture(); p.observations = []; p.source.tools = []; p.source.retrieved_at = null;
  p.coverage.pagination = 'unknown'; p.flow_timing = 'unknown';
  const result = run([], JSON.stringify(p)); assert.equal(result.status, 2); assert.equal(result.json.status, 'blocked');
  for (const code of ['source_not_retrieved','missing_observations','pagination_unknown','flow_timing_unsupported']) assert(result.json.blockers.some(item => item.code === code), code);
});

test('all acquisition and support blockers remain specific but redact private explanations', () => {
  const cases = [
    ['pagination_incomplete', p => { p.coverage.pagination = 'incomplete'; }],
    ['missing_periods', p => { p.coverage.missing_periods = [{ start: '2025-01-03', end: '2025-01-06', reason: sentinel }]; }],
    ['unsupported_events', p => { p.coverage.unsupported_events = [sentinel]; }],
    ['flow_timing_unsupported', p => { p.flow_timing = 'intraperiod'; }],
    ['requested_period_mismatch', p => { p.observations.pop(); }],
    ['calculation_unsupported', p => { p.observations[1].nav = '0'; }],
  ];
  for (const [code, mutate] of cases) { const p = fixture(); mutate(p); const result = run([], JSON.stringify(p)); assert.equal(result.status, 2, code); assert(result.json.blockers.some(item => item.code === code), code); assert.equal(result.stdout.includes(sentinel), false); }
});

test('explicit CSV export creates only normalized private values with restrictive mode', async t => {
  const dir = workspace(t), output = path.join(dir, 'private.csv'), text = JSON.stringify(privateFixture());
  const result = run(['--csv', output], text); assert.equal(result.status, 0); assert.equal(result.json.csv_written, true);
  const parsed = await parseAgentHandoff(text); assert.equal(readFileSync(output, 'utf8'), parsed.review.normalizedCsv);
  assert.equal(result.stdout.includes(sentinel), false); assert.equal(result.stdout.includes('123456.789012345678'), false);
  if (process.platform !== 'win32') assert.equal(statSync(output).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(dir), ['private.csv']);
});

test('existing output and source files cannot be overwritten', t => {
  const dir = workspace(t), output = path.join(dir, 'private.csv'), original = JSON.stringify(fixture());
  writeFileSync(output, original);
  const existing = run(['--csv', output]); assert.equal(existing.status, 1); assert.deepEqual(existing.json.issue_codes, ['output_exists']); assert.equal(readFileSync(output, 'utf8'), original);
  const source = run([output, '--csv', output], ''); assert.equal(source.status, 1); assert.equal(readFileSync(output, 'utf8'), original);
});

test('blocked or invalid input cannot create the requested CSV', t => {
  const dir = workspace(t), output = path.join(dir, 'private.csv'), p = fixture(); p.coverage.pagination = 'unknown';
  assert.equal(run(['--csv', output], JSON.stringify(p)).status, 2); assert.equal(existsSync(output), false);
  assert.equal(run(['--csv', output], '{broken').status, 1); assert.equal(existsSync(output), false);
});

test('CSV destination failure is sanitized and does not create parent directories', t => {
  const dir = workspace(t), output = path.join(dir, sentinel, 'private.csv');
  const result = run(['--csv', output]); assert.equal(result.status, 1); assert.deepEqual(result.json.issue_codes, ['output_unavailable']);
  assert.equal(result.stdout.includes(sentinel), false); assert.deepEqual(readdirSync(dir), []);
});

test('invalid fields, duplicate keys and money errors print no supplied values or key names', () => {
  const cases = [
    [JSON.stringify({ ...fixture(), [sentinel]: { token: sentinel } }), 'unknown_key'],
    [JSON.stringify(fixture()).replace('"synthetic":true', '"synthetic":true,"synthetic":false'), 'duplicate_key'],
    [JSON.stringify({ ...fixture(), observations: [{ date: '2025-01-02', nav: sentinel, external_flow: '0', source_ref: sentinel }] }), 'invalid_decimal'],
    [`{"${sentinel}":`, 'invalid_json'],
  ];
  for (const [text, code] of cases) { const result = run([], text); assert.equal(result.status, 1); assert(result.json.issue_codes.includes(code), code); assert.equal(result.stdout.includes(sentinel), false); }
});

test('UTF-8 byte limit is stricter than the application character limit', () => {
  const result = run([], 'é'.repeat(500001)); assert.equal(result.status, 1); assert(result.json.issue_codes.includes('size_limit')); assert.equal(result.stdout.includes('é'), false);
});

test('missing file error does not echo a private path', () => {
  const result = run([path.join(tmpdir(), sentinel, 'missing.json')], ''); assert.equal(result.status, 1); assert.equal(result.stdout.includes(sentinel), false);
});

test('invalid options never write or accept remote/implicit output destinations', () => {
  for (const args of [['--csv'], ['--csv','-'], ['--csv','https://example.com/x.csv'], ['--csv','output.json'], ['--csv','a.csv','--csv','b.csv'], ['--unknown'], ['a.json','b.json']]) assert.equal(run(args).status, 1, JSON.stringify(args));
});

test('ready validation succeeds with network, signing and key generation disabled', t => {
  const dir = workspace(t), guard = path.join(dir, 'guard.cjs');
  writeFileSync(guard, `const deny=()=>{throw Error('Forbidden side effect')}; for(const name of ['node:http','node:https']) {const m=require(name); m.request=deny;m.get=deny;}const net=require('node:net');net.connect=deny;net.createConnection=deny;globalThis.fetch=deny;const subtle=require('node:crypto').webcrypto.subtle;subtle.sign=deny;subtle.generateKey=deny;`);
  const result = run([], JSON.stringify(fixture()), { cwd: dir, env: { ...process.env, NODE_OPTIONS: `--require=${guard}` } });
  assert.equal(result.status, 0); assert.deepEqual(readdirSync(dir), ['guard.cjs']);
});

test('copyable prompt contains independently valid complete synthetic JSON', async () => {
  const instructions = readFileSync(new URL('../docs/agent-instructions.txt', import.meta.url), 'utf8');
  const start = instructions.indexOf('\n{\n'); const end = instructions.indexOf('\n}\n', start) + 2;
  assert(start > 0 && end > start); const parsed = await parseAgentHandoff(instructions.slice(start + 1, end));
  assert.equal(parsed.handoff.synthetic, true); assert.equal(parsed.review.canCalculate, true);
  for (const term of ['retrieved_at:null','MCP readOnlyHint','gross','1,000,000','1–240','0–500']) assert(instructions.includes(term), term);
});


test('malformed UTF-8 is rejected rather than silently changing source text', () => {
  const text = JSON.stringify(fixture()).replace('Synthetic example broker', 'ENCODING_SENTINEL');
  const bytes = Buffer.from(text); const offset = bytes.indexOf('ENCODING_SENTINEL'); bytes[offset] = 0xff;
  const result = run([], bytes); assert.equal(result.status, 1); assert.deepEqual(result.json.issue_codes, ['invalid_encoding']);
  assert.equal(result.stdout.includes('ENCODING_SENTINEL'), false);
});

test('CSV output cannot follow an existing symlink to overwrite private data', { skip: process.platform === 'win32' }, t => {
  const dir = workspace(t), original = path.join(dir, 'existing.json'), output = path.join(dir, 'link.csv');
  writeFileSync(original, sentinel); symlinkSync(original, output);
  const result = run(['--csv', output]); assert.equal(result.status, 1); assert.deepEqual(result.json.issue_codes, ['output_exists']);
  assert.equal(readFileSync(original, 'utf8'), sentinel);
});
