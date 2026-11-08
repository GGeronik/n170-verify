import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { deriveHeadline as browserHeadline, inspectHeadline, TRACK_RECORD_CLASSIFICATION, CONTINUITY_CLASSIFICATION } from '../src/headline.js';
import * as record from '../src/trackRecord.js';
import { deriveHeadline as cliHeadline } from '../scripts/headline.mjs';
import { verifyHeadline, runCli, MESSAGE_CLASSIFICATION } from '../scripts/verify-headline.mjs';
import { verifyWitnessReceipt as browserReceipt } from '../src/witnessReceipt.js';
import { verifyWitnessReceipt as cliReceipt, runCli as receiptCli } from '../scripts/verify-witness-receipt.mjs';
import { calculateEvidence } from '../src/calculator.js';

const root = new URL('../', import.meta.url);
const read = (name) => readFileSync(new URL(name, root));
const json = (name) => JSON.parse(read(name).toString('utf8'));
const text = (name) => read(name).toString('utf8');
const hash = (b) => createHash('sha256').update(b).digest('hex');
const exhaustive = json('tests/fixtures/headline/facts-exhaustive.json');
const contexts = json('tests/fixtures/headline/facts-context.json');

test('sealed v2 fixture manifests and all 7200 combinations remain intact', () => {
  assert.equal(hash(read('tests/fixtures/headline/MANIFEST.json')), '583c7ef94bd7123d250f8477dafda66d3386f06c7e0aa5f0958273c16f8c4851');
  assert.equal(hash(read('tests/fixtures/witness/MANIFEST.json')), 'f74b25b64600c3cd0215cf2a08eaf86fc3e825de33abca5b3e746ae6413c8d92');
  for (const kind of ['headline', 'witness']) {
    for (const f of json(`tests/fixtures/${kind}/MANIFEST.json`).files) {
      assert.equal(read(f.path).length, f.bytes);
      assert.equal(hash(read(f.path)), f.sha256);
    }
  }
  assert.equal(exhaustive.length, 7200);
});
for (const [name, derive] of [['browser', browserHeadline], ['CLI', cliHeadline]]) {
  test(`${name}: all sealed exhaustive decisions match and have closed headline vocabulary`, () => {
    const allowed = new Set([...exhaustive, ...contexts].map((r) => r.expected.headline));
    assert.equal(allowed.size, 15);
    for (const row of exhaustive) {
      const got = derive(row.facts, row.context);
      for (const key of ['headline', 'code', 'exit']) assert.equal(got[key], row.expected[key], row.id + ': ' + key);
      assert.ok(allowed.has(got.headline));
      assert.ok(!/^verified/i.test(got.headline));
      assert.equal(got.ladder.length, 6);
      assert.ok(Object.isFrozen(got));
    }
  });
  test(`${name}: all 57 sealed display, qualification, completeness and precedence controls match`, () => {
    for (const row of contexts) assert.deepEqual(derive(row.facts, row.context), row.expected, row.id);
  });
}
const receipts = json('tests/fixtures/witness/receipt-cases.json');
for (const row of receipts) test(`receipt ${row.id}: both independent implementations match`, async () => {
  const options = { ...row.options, ...(row.timestamp_input ? { otsProofBytes: read(row.timestamp_input) } : {}) };
  if (row.ots_proof) options.otsProofBytes = read(row.ots_proof);
  const a = await browserReceipt(read(row.input), options), b = cliReceipt(read(row.input), options);
  for (const got of [a, b]) for (const [key, value] of Object.entries(row.expected)) assert.deepEqual(got[key], value, row.id + ': ' + key);
  assert.deepEqual(a, b);
});
for (const row of json('tests/fixtures/headline/record-cases.json')) test(`adapter ${row.id}: supported paths reproduce sealed facts, context and headline`, async () => {
  if (row.preparation_only) {
    assert.throws(() => calculateEvidence(text(row.input)), (e) => e.message === row.expected_refusal.text);
    return;
  }
  const current = text(row.input), previous = row.previous ? text(row.previous) : undefined;
  const inputs = { ...(row.browser_options ?? {}), ...(previous ? { previousProfile: previous } : {}), eventSha256: row.event_sha256 };
  if (row.receipt_input) Object.assign(inputs, { receiptBytes: read(row.receipt_input), ...row.witness_options });
  if (row.browser_expected.supported !== false) {
    const got = await inspectHeadline(current, inputs);
    for (const key of ['facts', 'context', 'headline']) assert.deepEqual(got[key], row.browser_expected[key], 'browser ' + row.id + ': ' + key);
  } else assert.equal(row.browser_supported, false);
  if (row.cli_expected.supported !== false) {
    const got = verifyHeadline(current, { previous, eventSha256: row.event_sha256, ...(row.reconciliation_input ? { reconciliationText: text(row.reconciliation_input) } : {}), ...(row.receipt_input ? { receiptBytes: read(row.receipt_input), ...row.witness_options } : {}) });
    for (const key of ['facts', 'context', 'headline']) assert.deepEqual(got[key], row.cli_expected[key], 'CLI ' + row.id + ': ' + key);
  } else assert.equal(row.cli_supported, false);
});
test('browser classification covers exported messages and every explicit continuity refusal code', () => {
  for (const [name, value] of Object.entries(record)) if (typeof value === 'string' && /\s/.test(value)) assert.ok(Object.hasOwn(TRACK_RECORD_CLASSIFICATION, name), name);
  const source = readFileSync(new URL('../src/keyContinuity.js', import.meta.url), 'utf8');
  for (const m of source.matchAll(/,\s*'([a-z_]+)'\s*\);/g)) assert.ok(Object.hasOwn(CONTINUITY_CLASSIFICATION, m[1]), m[1]);
  assert.equal(CONTINUITY_CLASSIFICATION.new, 'parse');
});
function checkMessages(source) {
  const found = [];
  for (const match of source.matchAll(/\bcheck\(/g)) {
    let i = match.index + match[0].length, depth = 0, quote = null, second = -1;
    for (; i < source.length; i++) {
      const ch = source[i];
      if (quote) { if (ch === '\\') { i++; continue; } if (ch === quote) quote = null; continue; }
      if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
      if ('([{'.includes(ch)) depth++;
      else if (')]}'.includes(ch)) { if (ch === ')' && depth === 0) break; depth--; }
      else if (ch === ',' && depth === 0 && second < 0) second = i + 1;
    }
    if (second >= 0) {
      const arg = source.slice(second, i).trim();
      if (/^['"]/.test(arg)) { const m = /^(['"])(.*?)\1$/.exec(arg); if (m) found.push(m[2]); }
      else if (arg.startsWith('`')) found.push(arg.slice(1, -1));
    }
  }
  return found;
}
test('CLI classification covers every literal in both frozen record and continuity checkers', () => {
  for (const filename of ['verify-record.mjs', 'verify-continuity.mjs']) {
    const source = readFileSync(new URL('../scripts/' + filename, import.meta.url), 'utf8');
    const messages = checkMessages(source);
    assert.ok(messages.length >= 15);
    for (const message of messages) {
      if (message.startsWith('Usage:')) continue;
      if (message === '${role} transition signature mismatch') {
        for (const role of ['old', 'new']) assert.equal(MESSAGE_CLASSIFICATION[role + ' transition signature mismatch'], 'signatures');
        continue;
      }
      if (message === "Invalid ${name || 'object'} fields") {
        assert.equal(MESSAGE_CLASSIFICATION['Invalid object fields'], 'parse');
        for (const m of source.matchAll(/\bexact\([^;]*?,\s*'([^']+)'\s*\);/g)) assert.equal(MESSAGE_CLASSIFICATION['Invalid ' + m[1] + ' fields'], 'parse', m[1]);
        continue;
      }
      assert.ok(Object.hasOwn(MESSAGE_CLASSIFICATION, message), message);
    }
  }
});
test('new CLI help and usage refusals remain fixed and do not echo paths or private text', () => {
  for (const cli of [runCli, receiptCli]) {
    assert.equal(cli(['--help']).exitCode, 0);
    for (const args of [[], ['--bad', 'PRIVATE-5323'], ['PRIVATE-5323', '--event-sha256', 'SECRET']]) {
      const r = cli(args);
      assert.equal(r.exitCode, 3);
      assert.ok(!r.output.includes('PRIVATE-5323'));
      assert.ok(!r.output.includes('SECRET'));
    }
  }
});
test('recipient trust, uppercase codes, unicode hosts and malformed bytes never silently pass', async () => {
  const row = receipts.find((x) => x.id === 'W-OK');
  for (const opts of [undefined, {}, { ...row.options, trustedWitnessKeys: [] }, { ...row.options, trustedWitnessKeys: row.options.trustedWitnessKeys.map((s) => s.toUpperCase()) }, { ...row.options, allowedBrokerHosts: ['ndcdyn.іnteractivebrokers.com'] }, { ...row.options, recordPayloadHash: row.options.recordPayloadHash.toUpperCase() }]) {
    for (const verify of [browserReceipt, cliReceipt]) {
      const got = await verify(read(row.input), opts);
      assert.equal(got.result, 'WITNESS_NOT_ASSESSABLE');
      assert.deepEqual(got.reasons, ['VERIFIER_INPUT_INVALID']);
    }
  }
  for (const verify of [browserReceipt, cliReceipt]) {
    for (const data of [null, 42, new Uint8Array([255]), new Uint8Array(65537)]) assert.equal((await verify(data, row.options)).result, 'WITNESS_RECEIPT_INVALID');
  }
});
test('unsigned edits, pretty-form hashing and inconsistent success reasons refuse before tier promotion', async () => {
  const row = receipts.find((r) => r.id === 'W-OK'), valid = json(row.input);
  const pretty = JSON.parse(JSON.stringify(valid));
  pretty.sha256 = hash(Buffer.from(JSON.stringify(pretty.payload, null, 2)));
  const upper = JSON.parse(JSON.stringify(valid));
  upper.sha256 = upper.sha256.toUpperCase();
  const inconsistent = JSON.parse(JSON.stringify(valid));
  inconsistent.payload.reasons = ['FLOW_MISCLASSIFICATION'];
  for (const [input, reason] of [[pretty, 'RECEIPT_HASH_MISMATCH'], [upper, 'RECEIPT_SCHEMA_INVALID'], [inconsistent, 'RECEIPT_SCHEMA_INVALID']]) {
    for (const verify of [browserReceipt, cliReceipt]) {
      const got = await verify(Buffer.from(JSON.stringify(input)), row.options);
      assert.equal(got.result, 'WITNESS_RECEIPT_INVALID');
      assert.deepEqual(got.reasons, [reason]);
    }
  }
});
test('unknown verifier errors and incomplete facts cannot default to a success tier', async () => {
  const result = await inspectHeadline('{"private":"unclassified"}');
  assert.equal(result.headline.exit, 1);
  for (const derive of [browserHeadline, cliHeadline]) {
    assert.equal(derive({}, contexts[0].context).code, 'FACTS_INCOMPLETE');
    assert.equal(derive({ parse: 'INVALID_INPUT' }, null).code, 'INVALID_INPUT');
  }
});
