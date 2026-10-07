import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createEmptyDraft, validatePrivateDraft, hydratePrivateDraft } from '../src/draftModel.js';
import { importStatement, ibkrSampleInput } from '../src/importer.js';
const envelope = data => ({ kind: 'n170.private-draft.v1', data });
const sha = value => createHash('sha256').update(value).digest('hex');
const before = 'date,nav,external_flow\n2025-01-01,100,0\n2025-01-02,110,0';
const after = before.replace('110,0', '111,0');
const corrected = (first, next) => ({ row: 2, field: 'nav', reason: 'Corrected against original statement', before: first, after: next, previous_sha256: sha(first), replacement_sha256: sha(next) });

test('empty private draft survives, objects are copied and unknown metadata discarded', async () => {
  const original = createEmptyDraft();
  const result = await hydratePrivateDraft(envelope({ ...original, importReview: { canCalculate: true }, unexpected: 'discard' }));
  assert.deepEqual(result, original); assert.notEqual(result, original);
  assert.equal('unexpected' in result, false);
});

test('malformed scope, nested fields and unbounded arrays fail before UI use', () => {
  for (const patch of [{ scope: {} }, { input: [] }, { corrections: new Array(101).fill({}) }, { original: 123 }, { currency: {} }, { synthetic: 'true' }, { format: 'unknown' }]) {
    assert.throws(() => validatePrivateDraft(envelope({ ...createEmptyDraft(), ...patch })), /invalid|unsupported/);
  }
});

test('forged success and mapping cannot bypass IBKR flow review', async () => {
  const review = await importStatement(ibkrSampleInput, { currency: 'USD', flowTimingConfirmed: true });
  const draft = { ...createEmptyDraft(), original: ibkrSampleInput, input: review.normalizedCsv, importReview: { canCalculate: true, mapping: [{ source: 'Forged broker proof' }], source: { authenticated: true } } };
  const result = await hydratePrivateDraft(envelope(draft));
  assert.equal(result.importReview.canCalculate, false);
  assert.equal(result.importReview.source.authenticated, false);
  assert.ok(result.importReview.exceptions.some(e => e.code === 'flow_activity_review'));
  assert.equal(JSON.stringify(result.importReview).includes('Forged broker proof'), false);
  assert.equal(result.original, ibkrSampleInput); assert.equal(result.input, review.normalizedCsv);
});

test('confirmed valid source is rederived and source-to-final correction chain survives', async () => {
  const draft = { ...createEmptyDraft(), original: before, input: after, flowTimingConfirmed: true, corrections: [corrected(before, after)] };
  const result = await hydratePrivateDraft(envelope(draft));
  assert.equal(result.importReview.canCalculate, true);
  assert.equal(result.importReview.normalizedCsv, before);
  assert.equal(result.input, after);
  assert.equal(result.corrections[0].replacement_sha256, sha(after));
  assert.notEqual(result.corrections[0], draft.corrections[0]);
});

test('modified private edit text, disconnected edits and final mismatch are rejected', async () => {
  const valid = { ...createEmptyDraft(), original: before, input: after, corrections: [corrected(before, after)] };
  await assert.rejects(hydratePrivateDraft(envelope({ ...valid, corrections: [{ ...valid.corrections[0], before: before.replace('100,0', '200,0') }] })), /correction history/);
  const unrelated = before.replace('100,0', '99,0');
  await assert.rejects(hydratePrivateDraft(envelope({ ...valid, corrections: [corrected(before, after), corrected(unrelated, after)] })), /correction history/);
  await assert.rejects(hydratePrivateDraft(envelope({ ...valid, input: before })), /correction history/);
  await assert.rejects(hydratePrivateDraft(envelope({ ...valid, corrections: [corrected(unrelated, after)] })), /correction history/);
  await assert.rejects(hydratePrivateDraft(envelope({ ...valid, corrections: [corrected('', after)] })), /correction history/);
});

test('working rows cannot replace a supplied source without a correction', async () => {
  await assert.rejects(hydratePrivateDraft(envelope({ ...createEmptyDraft(), original: before, input: after })), /do not match/);
});

test('malformed original text and unaccepted import restore as blocked without losing raw work', async () => {
  const malformed = 'bad,csv\n"unclosed';
  const result = await hydratePrivateDraft(envelope({ ...createEmptyDraft(), original: malformed, input: before, importReview: { canCalculate: true } }));
  assert.equal(result.original, malformed); assert.equal(result.input, before); assert.equal(result.importReview.canCalculate, false);
  assert.equal(result.importReview.exceptions[0].code, 'invalid_source');
  const notReconciled = await hydratePrivateDraft(envelope({ ...createEmptyDraft(), original: before }));
  assert.equal(notReconciled.input, ''); assert.equal(notReconciled.importReview.canCalculate, false);
  assert.ok(notReconciled.importReview.exceptions.some(e => e.code === 'reconciliation_needed'));
});

test('manual drafts retain bounded working mistakes for repair without forged provenance', async () => {
  const result = await hydratePrivateDraft(envelope({ ...createEmptyDraft(), input: 'incomplete input', importReview: { canCalculate: true, source: { authenticated: true } } }));
  assert.equal(result.input, 'incomplete input'); assert.equal(result.importReview, null);
});


test('each declared data column accepts exactly its own changed cell', async () => {
  for (const [field, first, next] of [['date','2025-01-02','2025-01-03'],['nav','110','111'],['external_flow','110,0','110,1']]) {
    const replacement = before.replace(first, next);
    const correction = { ...corrected(before, replacement), field };
    const result = await hydratePrivateDraft(envelope({ ...createEmptyDraft(), input: replacement, corrections: [correction] }));
    assert.equal(result.corrections[0].field, field); assert.equal(result.input, replacement);
  }
});

test('wrong row, wrong field and concealed changes fail despite correct digests', async () => {
  for (const [replacement, patch] of [
    [after, { row: 1 }], [after, { field: 'external_flow' }],
    [after.replace('100,0', '99,0'), {}],
    [after.replace('111,0', '111,1'), {}],
    [after.replace('2025-01-01,100', '2025-01-01, 100'), {}],
  ]) {
    const correction = { ...corrected(before, replacement), ...patch };
    await assert.rejects(hydratePrivateDraft(envelope({ ...createEmptyDraft(), input: replacement, corrections: [correction] })), /correction history/);
  }
});

test('row zero, missing rows, no-op, column, header and row-count mutations are rejected', async () => {
  const variants = [
    [after, { row: 0 }], [after, { row: 3 }], [before, {}],
    [after.replace('external_flow', 'net_cash'), {}],
    [after + '\n2025-01-03,120,0', {}],
    [after.split('\n').slice(0, 2).join('\n'), {}],
    [after.replace('111,0', '111,0,hidden'), {}],
    [before.replaceAll('\n', '\r\n') + '\n', {}],
  ];
  for (const [replacement, patch] of variants) {
    await assert.rejects(hydratePrivateDraft(envelope({ ...createEmptyDraft(), input: replacement, corrections: [{ ...corrected(before, replacement), ...patch }] })), /correction history/);
  }
});

test('row editor outer trim and newline normalization survives with the single actual edit', async () => {
  const original = ' \r\n' + before.replaceAll('\n', '\r\n') + ' \r\n';
  const correction = corrected(original, after);
  const result = await hydratePrivateDraft(envelope({ ...createEmptyDraft(), input: after, corrections: [correction] }));
  assert.equal(result.corrections[0].before, original); assert.equal(result.corrections[0].previous_sha256, sha(original));
  assert.equal(result.input, after);
});

test('successive legitimate cell edits preserve the complete private chain', async () => {
  const final = after.replace('100,0', '99,0');
  const corrections = [corrected(before, after), { ...corrected(after, final), row: 1 }];
  const result = await hydratePrivateDraft(envelope({ ...createEmptyDraft(), original: before, input: final, flowTimingConfirmed: true, corrections }));
  assert.equal(result.importReview.canCalculate, true); assert.equal(result.corrections.length, 2); assert.equal(result.input, final);
});

test('forged assistant draft cannot conceal two changed NAVs behind a different row claim', async () => {
  const original = readFileSync(new URL('../examples/agent-handoff-synthetic.json', import.meta.url), 'utf8');
  const packet = JSON.parse(original);
  const review = await importStatement(original, { currency: packet.currency, frequency: packet.frequency, flowTimingConfirmed: true });
  const input = review.normalizedCsv.replace(',101,', ',201,').replace(',112.02,', ',212.02,');
  const correction = { ...corrected(review.normalizedCsv, input), row: 1, reason: 'Changed first NAV only' };
  const draft = { ...createEmptyDraft(), format: 'agent-handoff', original, input, currency: packet.currency, frequency: String(packet.frequency), scope: packet.account_scope, flowTimingConfirmed: true, synthetic: true, corrections: [correction] };
  await assert.rejects(hydratePrivateDraft(envelope(draft)), /correction history/);
});
