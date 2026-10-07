import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readBoundedUtf8, parseStrictJson, validatePrivateArtifact, INPUT_LIMITS } from '../scripts/reconciliation-input.mjs';

const H = '0'.repeat(64);
const issue = () => ({ code: 'structural_test', severity: 'error', message: 'Retained structural diagnostic.', action: 'Review retained input.', row: null });
const source = () => ({ id: null, sha256: null, byte_length: 0, file_name: 'unavailable', format: 'auto', text: null, bytes_base64: null, source_bytes_available: false, digest_scope: null, unconsumed: { byteLength: 9, reason: 'Unavailable.' }, provenance: 'owner_supplied', authenticated: false, uploaded: false, headers: [], rows: [], source_rows: 0, inspection_truncated: false, review: null, issues: [issue()], dates: [], currencies: [], disposition: 'unresolved', reason: '' });
const artifact = () => ({ kind: 'n170.private-account-reconciliation.v1', private: true, disclosure: 'Private structural test.', reconciliation: {
  schema_version: 'n170.account-reconciliation.v1', private: true, source_inventory: [source()], review: null, normalizedCsv: '', normalized_sha256: H,
  scope: { account_alias: '', period: { start: null, end: null }, period_source: 'supplied_boundaries', currency: '', expected_schedule: 'observed_boundaries', flow_activity: 'unknown', flow_timing: 'unknown', periods_per_year: 252, completeness: 'not_established', provenance: 'owner_supplied', authenticated: false, observation_claim: '' },
  intervals: [], blocking_issues: [issue()], canCalculate: false, selected_scope_status: 'blocked', completeness: 'not_established', provenance: 'owner_supplied', authenticated: false, corrections: [], missing_boundaries: [], rejected_source_entries: [],
  privacy: { raw_sources_included: true, account_values_included: true, filenames_included: true, uploaded: false, signing_key_included: false, automatically_included_in_shared_profiles: false }, dependency_sha256: H,
} });
const invalid = (fn, code) => assert.throws(fn, error => error.status === 'INVALID_INPUT' && /^[A-Z][A-Z0-9_]+$/.test(error.code) && error.message === error.code && (!code || error.code === code));

test('strict JSON accepts canonical data and preserves Unicode scalar values', () => {
  assert.deepEqual(parseStrictJson('{"s":"\\ud83d\\ude00","n":-9007199254740991,"a":[true,null,0]}'), { s: '😀', n: -9007199254740991, a: [true, null, 0] });
});

test('strict JSON rejects decoded duplicate keys and all prototype keys at every depth', () => {
  invalid(() => parseStrictJson('{"a":1,"\\u0061":2}'), 'DUPLICATE_JSON_KEY');
  for (const key of ['__proto__', 'constructor', 'prototype']) invalid(() => parseStrictJson(`{"outer":[{"${key}":null}]}`), 'FORBIDDEN_JSON_KEY');
  invalid(() => parseStrictJson('{"\\u005f_proto__":0}'), 'FORBIDDEN_JSON_KEY');
});

test('strict JSON rejects unsafe, noninteger and noncanonical number spellings', () => {
  for (const number of ['-0', '01', '-01', '1.0', '1e0', '1E+0', '+1', 'NaN', 'Infinity', '-Infinity', '9007199254740992', '-9007199254740992']) invalid(() => parseStrictJson(`{"n":${number}}`));
});

test('strict JSON rejects malformed syntax, BOM, lone surrogates and trailing values', () => {
  for (const input of ['{"a":1,}', '[1,]', '{a:1}', '{"a" 1}', 'true false', '', '\ufeff{}', '"\\ud800"', '"\\udfff"', '"\ud800"', '{"\\ud800":0}', '"\\x20"', '"\n"']) invalid(() => parseStrictJson(input));
});

test('JSON depth and node bounds include exactly their supported boundaries', () => {
  assert.equal(parseStrictJson('['.repeat(24) + '0' + ']'.repeat(24))[0][0][0].length, 1);
  invalid(() => parseStrictJson('['.repeat(25) + '0' + ']'.repeat(25)), 'JSON_DEPTH_LIMIT');
  const within = '[' + Array(INPUT_LIMITS.nodes - 1).fill('null').join(',') + ']';
  assert.equal(parseStrictJson(within).length, INPUT_LIMITS.nodes - 1);
  invalid(() => parseStrictJson(within.slice(0, -1) + ',null]'), 'JSON_NODE_LIMIT');
});

test('reader preserves transport bytes/BOM and rejects invalid UTF-8 and size overflow', t => {
  const dir = fs.mkdtempSync(join(tmpdir(), 'n170-input-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'input'); fs.writeFileSync(file, '\ufeff{"a":1}\r\n');
  assert.equal(readBoundedUtf8(file, 100), '\ufeff{"a":1}\r\n');
  invalid(() => parseStrictJson(readBoundedUtf8(file, 100)), 'TRANSPORT_BOM');
  invalid(() => readBoundedUtf8(file, 1), 'INPUT_SIZE_LIMIT');
  fs.writeFileSync(file, Buffer.from([0xc3, 0x28])); invalid(() => readBoundedUtf8(file, 2), 'INVALID_UTF8');
  fs.writeFileSync(file, ''); assert.equal(readBoundedUtf8(file, 0), '');
});

test('reader rejects symlinks, directories and missing paths without echoing paths', t => {
  const dir = fs.mkdtempSync(join(tmpdir(), 'n170-input-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'source'), link = join(dir, 'link'); fs.writeFileSync(file, '{}'); fs.symlinkSync(file, link);
  invalid(() => readBoundedUtf8(link, 10), 'INPUT_NOT_REGULAR_FILE');
  invalid(() => readBoundedUtf8(dir, 10), 'INPUT_NOT_REGULAR_FILE');
  invalid(() => readBoundedUtf8(join(dir, 'PRIVATE-NAME'), 10), 'INPUT_READ_FAILED');
});

test('reader detects in-read growth and replacement with fixed diagnostics', t => {
  const dir = fs.mkdtempSync(join(tmpdir(), 'n170-input-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'input'), originalRead = fs.readSync;
  for (const mutate of [() => fs.appendFileSync(file, 'x'), () => { fs.renameSync(file, file + '.old'); fs.writeFileSync(file, '{}'); }]) {
    fs.writeFileSync(file, '{}'); let changed = false;
    fs.readSync = (...args) => { const count = originalRead(...args); if (!changed) { changed = true; mutate(); } return count; };
    syncBuiltinESMExports();
    try { invalid(() => readBoundedUtf8(file, 100), 'INPUT_CHANGED'); }
    finally { fs.readSync = originalRead; syncBuiltinESMExports(); }
  }
});

test('blocked snapshot, null evidence and all retained dispositions are structurally representable', () => {
  const a = artifact(); const before = JSON.stringify(a);
  assert.equal(validatePrivateArtifact(a), a.reconciliation); assert.equal(JSON.stringify(a), before);
  for (const disposition of ['active', 'unresolved', 'excluded', 'superseded']) { a.reconciliation.source_inventory[0].disposition = disposition; validatePrivateArtifact(a); }
  a.reconciliation.canCalculate = true; // A claim is not evidence; no promotion here.
  validatePrivateArtifact(a);
});

test('documented review, inventory, correction and unresolved dependency shapes pass', () => {
  const a = artifact(), r = a.reconciliation, s = r.source_inventory[0];
  s.id = H; s.sha256 = H; s.text = 'opaque'; s.bytes_base64 = Buffer.from('opaque').toString('base64'); s.byte_length = 6; s.source_bytes_available = true; s.digest_scope = 'exact consumed bytes'; delete s.unconsumed;
  s.rows = [{ source_row: 2, reference: 'csv-record:2', raw_cells: ['retained'], dates: [], currencies: [], status: 'needs_review', normalized_rows: [], physical_line: 2, byte_start: 0, byte_end: 6, raw_text: 'opaque' }]; s.source_rows = 1;
  const review = { version: 'n170.import.v1', format: 'unknown', label: 'Retained review', source: { kind: 'supplied_file', authenticated: false, sha256: H, digest_scope: '', file_name: '', uploaded: false }, normalizedCsv: '', rows: [{ date: 'malformed retained date', nav: 'unparsed', flow: 'unparsed', sourceRow: 2, derived: '' }], mapping: [{ source: 'column', target: 'field', explanation: '' }], exceptions: [issue()], canCalculate: false, currency: '', corrections: [], coverage: { source_rows: 1, observations: 1, start: null, end: null, accounts: '' }, review: { normalized_sha256: H, source_verified: false, flow_timing: 'interval_end_required', reviewed: false } };
  r.review = structuredClone(review); s.review = review;
  const dependency = { role: 'opening', source_sha256: H, source_row: null, source_ref: null, normalized_row: null, date: null, value: null, missing: true, correction_steps: [{ sequence: 1, field: 'nav', previous_sha256: H, replacement_sha256: H }], provenance: 'owner_supplied', authenticated: false };
  r.intervals = [{ start: null, end: null, duration_days: null, opening_nav: null, closing_nav: null, external_flow: null, adjusted_closing_nav: null, economic_change: null, flow_kind: 'unknown', return_e8: null, status: 'unresolved', blocking_reasons: [issue()], dependencies: [dependency], provenance: 'owner_supplied', authenticated: false, dependency_sha256: H }];
  r.corrections = [{ row: 1, field: 'nav', reason: 'retained', before: '', after: '', previous_sha256: H, replacement_sha256: H }];
  r.blocking_issues[0] = { ...issue(), source_sha256: null, dates: [], origin: 'working_observations', details: [{ path: '/', code: 'invalid_handoff', message: 'Retained.', action: 'Review.' }] };
  validatePrivateArtifact(a);
});

test('unknown fields and wrong nested types cannot be consumed as schema extensions', () => {
  for (const mutate of [a => { a.key = 'private'; }, a => { a.reconciliation.scope.extra = true; }, a => { a.reconciliation.source_inventory[0].authenticated = true; }, a => { a.reconciliation.source_inventory[0].review = {}; }, a => { a.reconciliation.blocking_issues[0].message = 1; }, a => { delete a.reconciliation.privacy; }]) { const a = artifact(); mutate(a); invalid(() => validatePrivateArtifact(a)); }
});

test('direct object API rejects accessors, exotic prototypes, cycles and non-JSON values', () => {
  let invoked = false; const a = artifact(); Object.defineProperty(a, 'x', { enumerable: true, get() { invoked = true; return null; } });
  invalid(() => validatePrivateArtifact(a)); assert.equal(invoked, false);
  for (const mutate of [a => { a.reconciliation = new Date(); }, a => { a.loop = a; }, a => { a.x = undefined; }, a => { a.x = -0; }, a => { a.x = '\ud800'; }, a => { a.x = Array(2); }]) { const a = artifact(); mutate(a); invalid(() => validatePrivateArtifact(a)); }
});

test('base64 must be canonical even for unresolved or excluded sources', () => {
  for (const encoding of ['Zg', 'Zg===', 'Zh==', ' Zg==', 'Zg==\n', 'AA-A', '====']) { const a = artifact(); a.reconciliation.source_inventory[0].bytes_base64 = encoding; invalid(() => validatePrivateArtifact(a), 'INVALID_BASE64'); }
  const a = artifact(), s = a.reconciliation.source_inventory[0];
  Object.assign(s, { id: H, sha256: H, bytes_base64: '', digest_scope: '', source_bytes_available: true, unconsumed: null }); validatePrivateArtifact(a);
});

test('availability flags cannot conceal supplied byte evidence or invent a byte identity', () => {
  for (const mutate of [s => { s.bytes_base64 = 'eA=='; }, s => { s.id = H; }, s => { s.sha256 = H; }, s => { s.text = 'hidden'; }, s => { s.digest_scope = 'claimed'; }, s => { s.byte_length = 1; }, s => { s.headers = ['hidden']; }, s => { s.source_rows = 1; }, s => { s.dates = ['retained']; }, s => { s.currencies = ['USD']; }, s => { s.unconsumed = null; }, s => { s.unconsumed.reason = ' '; }, s => { s.source_bytes_available = true; }]) {
    const a = artifact(); mutate(a.reconciliation.source_inventory[0]); invalid(() => validatePrivateArtifact(a), 'INVALID_PRIVATE_SCHEMA');
  }
  const a = artifact(), s = a.reconciliation.source_inventory[0];
  Object.assign(s, { id: H, sha256: H, bytes_base64: 'eA==', digest_scope: 'exact bytes', source_bytes_available: true });
  invalid(() => validatePrivateArtifact(a), 'INVALID_PRIVATE_SCHEMA'); // Contradictory unconsumed claim.
});

test('opaque invalid-UTF8 historical bytes retain null text and their decoding diagnostic', () => {
  for (const disposition of ['unresolved', 'excluded', 'superseded']) {
    const a = artifact(), s = a.reconciliation.source_inventory[0];
    Object.assign(s, { id: H, sha256: H, bytes_base64: '/w==', digest_scope: 'exact bytes', byte_length: 1, source_bytes_available: true, text: null, disposition, reason: 'Retained original.', issues: [{ ...issue(), code: 'invalid_utf8' }] });
    delete s.unconsumed;
    assert.equal(validatePrivateArtifact(a).source_inventory[0].text, null);
    assert.equal(s.issues[0].code, 'invalid_utf8');
  }
});

test('hard source, diagnostic, observation and interval bounds reject rather than truncate', () => {
  for (const mutate of [a => { a.reconciliation.source_inventory = Array.from({ length: 21 }, source); }, a => { a.reconciliation.intervals = Array(5501).fill(null); }, a => { a.reconciliation.corrections = Array(101).fill(null); }, a => { a.reconciliation.source_inventory[0].source_rows = 5001; }, a => { a.reconciliation.blocking_issues = Array.from({ length: 20001 }, issue); }]) { const a = artifact(); mutate(a); invalid(() => validatePrivateArtifact(a)); }
  const a = artifact(), encoded = Buffer.alloc(6 * 1024 * 1024).toString('base64');
  a.reconciliation.source_inventory = [source(), source()]; a.reconciliation.source_inventory.forEach(s => { Object.assign(s, { id: H, sha256: H, bytes_base64: encoded, source_bytes_available: true, digest_scope: '', unconsumed: null }); });
  invalid(() => validatePrivateArtifact(a), 'SOURCE_BYTE_LIMIT');
});
