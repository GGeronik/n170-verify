import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  createEmptyDraft, hydratePrivateDraft, validateReconciliation, retainSource,
  MAX_RETAINED_SOURCES, MAX_SOURCE_BYTES, MAX_TOTAL_SOURCE_BYTES,
} from '../src/reconciliationDraft.js';
import {
  createEmptyDraft as createLegacyEmptyDraft,
  hydratePrivateDraft as hydrateLegacyPrivateDraft,
} from '../src/draftModel.js';

const envelope = data => ({ kind: 'n170.private-draft.v1', data });
const reconciliation = patch => ({ ...createEmptyDraft().reconciliation, ...patch });
const source = patch => ({ text: 'date,nav,external_flow\n2025-03-01,100,0\n2025-03-02,110,0', fileName: 'synthetic.csv', disposition: 'unresolved', reason: '', ...patch });
const draftWith = patch => envelope({ ...createEmptyDraft(), reconciliation: reconciliation(patch) });
const sha = text => createHash('sha256').update(text).digest('hex');

test('legacy drafts hydrate identically with isolated conservative reconciliation defaults', async () => {
  const legacy = createLegacyEmptyDraft();
  const result = await hydratePrivateDraft(envelope(legacy));
  const { reconciliation: inputs, ...fields } = result;
  assert.deepEqual(fields, await hydrateLegacyPrivateDraft(envelope(legacy)));
  assert.deepEqual(inputs, {
    sources: [], period: { start: '', end: '' }, expectedSchedule: 'observed_boundaries',
    flowActivity: 'unknown', flowTiming: 'unknown',
  });
  const another = createEmptyDraft();
  result.reconciliation.sources.push(source());
  result.reconciliation.period.start = '2025-03-01';
  assert.equal(another.reconciliation.sources.length, 0);
  assert.equal(another.reconciliation.period.start, '');
});

test('all supplied legacy fields, original bytes, and valid correction evidence survive the wrapper', async () => {
  const original = source().text;
  const replacement = original.replace('110,0', '109,0');
  const draft = {
    ...createEmptyDraft(), original, input: replacement, fileName: 'original.csv', scope: 'Synthetic complete account',
    handoffText: 'private handoff text', flowTimingConfirmed: true, synthetic: true,
    corrections: [{ row: 2, field: 'nav', reason: 'Original synthetic correction', before: original, after: replacement,
      previous_sha256: sha(original), replacement_sha256: sha(replacement) }],
    reconciliation: reconciliation({ sources: [source({ text: '\ufeffa,b\r\nx,y\r\n', fileName: 'bytes.csv', disposition: 'excluded', reason: 'Different synthetic account' })] }),
  };
  const legacy = await hydrateLegacyPrivateDraft(envelope(draft));
  const actual = await hydratePrivateDraft(envelope(draft));
  assert.deepEqual(actual, { ...legacy, reconciliation: draft.reconciliation });
  assert.notEqual(actual.reconciliation, draft.reconciliation);
  assert.notEqual(actual.reconciliation.sources[0], draft.reconciliation.sources[0]);
  assert.equal(actual.reconciliation.sources[0].text, '\ufeffa,b\r\nx,y\r\n');
});

test('base validation and correction-chain rejection remain enforced', async () => {
  for (const patch of [{ currency: 'BTC' }, { input: [] }, { synthetic: 'true' }, { scope: {} }, { original: 100 }]) {
    await assert.rejects(hydratePrivateDraft(envelope({ ...createEmptyDraft(), ...patch })), /invalid|unsupported/);
  }
  const original = source().text;
  const after = original.replace('100,0', '99,0').replace('110,0', '108,0');
  const correction = { row: 1, field: 'nav', reason: 'False single edit', before: original, after,
    previous_sha256: sha(original), replacement_sha256: sha(after) };
  await assert.rejects(hydratePrivateDraft(envelope({ ...createEmptyDraft(), original, input: after, corrections: [correction] })), /correction history/);
});

test('restore allowlist strips invented inventory, hashes, parsed rows, and authentication', async () => {
  const payload = draftWith({
    sources: [source({
      sha256: 'f'.repeat(64), byteLength: 0, unreadable: false, rows: [{ date: '2025-03-01', nav: '1000000' }],
      authenticated: true, canCalculate: true, review: { authenticated: true }, provenance: 'broker_authenticated',
    })],
    source_inventory: [{ authenticated: true }], canCalculate: true, intervals: [{ return_e8: 900000000 }],
  });
  payload.data.importReview = { canCalculate: true, source: { authenticated: true } };
  const result = await hydratePrivateDraft(payload);
  assert.deepEqual(result.reconciliation, reconciliation({ sources: [source()] }));
  assert.equal(result.importReview, null);
  assert.equal(JSON.stringify(result).includes('broker_authenticated'), false);
});

test('source bytes round trip exactly including BOM, CRLF, non-ASCII and invalid UTF-8', async () => {
  const utf8 = '\ufeffdate,note\r\n2025-03-01,€😀\r\n';
  const broken = Buffer.from([0xef, 0xbb, 0xbf, 0x61, 0x80, 0xff]);
  const sources = [
    source({ text: utf8, rawBytesBase64: Buffer.from(utf8).toString('base64') }),
    source({ text: '', fileName: 'invalid.csv', rawBytesBase64: broken.toString('base64') }),
  ];
  const restored = await hydratePrivateDraft(JSON.parse(JSON.stringify(draftWith({ sources }))));
  assert.deepEqual(restored.reconciliation.sources, sources);
  assert.deepEqual(Buffer.from(restored.reconciliation.sources[1].rawBytesBase64, 'base64'), broken);
});

test('contradictory text and bytes, lossy text and noncanonical base64 are rejected', async () => {
  for (const patch of [
    { text: 'different', rawBytesBase64: Buffer.from('original').toString('base64') },
    { text: 'a', rawBytesBase64: Buffer.from('\ufeffa').toString('base64') },
    { text: '�', rawBytesBase64: '/w==' },
    { text: '\ud800' }, { text: '\udc00' }, { text: '\ud800a' },
    { text: '', rawBytesBase64: '!!!!' }, { text: '', rawBytesBase64: 'YQ' },
    { text: 'a', rawBytesBase64: 'YR==' }, { text: 'a', rawBytesBase64: 'YQ==\n' },
    { text: '', rawBytesBase64: 42 },
  ]) await assert.rejects(hydratePrivateDraft(draftWith({ sources: [source(patch)] })), /reconciliation inputs/);
});

test('all documented source formats, schedules, activity and timing statements round trip', () => {
  for (const format of ['auto', 'n170', 'ibkr-flex', 'agent-handoff', 'trading212', 'portfolio-performance']) {
    assert.equal(validateReconciliation(reconciliation({ sources: [source({ format })] })).sources[0].format, format);
  }
  for (const expectedSchedule of ['observed_boundaries', 'calendar_daily', 'weekdays']) {
    for (const flowActivity of ['reviewed_no_hidden', 'unknown', 'offsetting']) {
      for (const flowTiming of ['interval_end', 'unknown', 'intraperiod']) {
        const value = reconciliation({ expectedSchedule, flowActivity, flowTiming });
        assert.deepEqual(validateReconciliation(value), value);
      }
    }
  }
});

test('invalid nested structures, enum values, dates and source types reject before replacement', async () => {
  const invalidReconciliation = [null, [], 'string',
    reconciliation({ sources: {} }), reconciliation({ sources: new Array(1) }),
    reconciliation({ period: null }), reconciliation({ period: { start: '2025-02-29', end: '' } }),
    reconciliation({ period: { start: '2025-01-32', end: '' } }),
    reconciliation({ period: { start: '2025-1-01', end: '' } }),
    reconciliation({ period: { start: '', end: 0 } }),
    reconciliation({ expectedSchedule: 'every_day_forward_fill' }),
    reconciliation({ flowActivity: 'complete' }), reconciliation({ flowTiming: 'opening' }),
  ];
  const current = createEmptyDraft();
  current.input = 'untouched private work';
  const before = structuredClone(current);
  for (const candidate of invalidReconciliation) {
    await assert.rejects(hydratePrivateDraft(envelope({ ...current, reconciliation: candidate })), /reconciliation inputs/);
    assert.deepEqual(current, before);
  }
  for (const patch of [{ text: {} }, { fileName: [] }, { fileName: 'x'.repeat(256) }, { disposition: 'accepted' },
    { reason: null }, { reason: 'x'.repeat(501) }, { format: 'forged-broker-proof' }]) {
    await assert.rejects(hydratePrivateDraft(draftWith({ sources: [source(patch)] })), /reconciliation inputs/);
  }
});

test('valid dates and unresolved period mistakes remain available for engine review without forward fill', () => {
  for (const period of [{ start: '', end: '' }, { start: '2024-02-29', end: '' }, { start: '2025-03-02', end: '2025-03-01' }]) {
    const restored = validateReconciliation(reconciliation({ period }));
    assert.deepEqual(restored.period, period);
  }
});

test('exclusion and supersession require an explicit bounded owner reason', async () => {
  for (const disposition of ['excluded', 'superseded']) {
    for (const reason of ['', '  ', ' a ', 'x'.repeat(501)]) {
      await assert.rejects(hydratePrivateDraft(draftWith({ sources: [source({ disposition, reason })] })), /reconciliation inputs/);
    }
    const record = source({ disposition, reason: 'Separate account scope' });
    assert.deepEqual(validateReconciliation(reconciliation({ sources: [record] })).sources, [record]);
  }
});

test('source bounds count exact encoded bytes and do not silently truncate input', () => {
  assert.equal(MAX_RETAINED_SOURCES, 20);
  assert.equal(MAX_SOURCE_BYTES, 1_000_000);
  assert.equal(MAX_TOTAL_SOURCE_BYTES, 10 * 1024 * 1024);
  const atLimit = source({ text: 'a'.repeat(MAX_SOURCE_BYTES) });
  assert.equal(validateReconciliation(reconciliation({ sources: [atLimit] })).sources[0].text.length, MAX_SOURCE_BYTES);
  for (const record of [source({ text: 'a'.repeat(MAX_SOURCE_BYTES + 1) }), source({ text: '€'.repeat(333334) }),
    source({ text: '', rawBytesBase64: Buffer.alloc(MAX_SOURCE_BYTES + 1, 0xff).toString('base64') })]) {
    assert.throws(() => validateReconciliation(reconciliation({ sources: [record] })), /reconciliation inputs/);
  }
  assert.throws(() => validateReconciliation(reconciliation({ sources: new Array(21).fill(source()) })), /reconciliation inputs/);
  assert.throws(() => validateReconciliation(reconciliation({ sources: new Array(11).fill(atLimit) })), /10 MiB/);
  assert.equal(validateReconciliation(reconciliation({ sources: new Array(10).fill(atLimit) })).sources.length, 10);
});

test('retaining a new attempt does not mutate existing sources or working data', () => {
  const current = reconciliation({ sources: [source({ disposition: 'excluded', reason: 'Separate account' })] });
  const before = structuredClone(current);
  const result = retainSource(current, { text: 'bad,csv\n"unfinished', fileName: 'rejected.csv', format: 'auto' });
  assert.deepEqual(current, before);
  assert.notEqual(result, current);
  assert.notEqual(result.sources[0], current.sources[0]);
  assert.deepEqual(result.sources[1], { text: 'bad,csv\n"unfinished', fileName: 'rejected.csv', format: 'auto', disposition: 'unresolved', reason: '' });
});

test('deduplication requires equal exact bytes AND name, and preserves the review decision', () => {
  const existing = source({ text: '\ufeffa\r\n', disposition: 'excluded', reason: 'Separate account' });
  const current = reconciliation({ sources: [existing] });
  const duplicate = retainSource(current, { text: existing.text, fileName: existing.fileName, rawBytesBase64: Buffer.from(existing.text).toString('base64') });
  assert.deepEqual(duplicate.sources, [existing]);
  assert.equal(retainSource(current, { text: existing.text, fileName: 'another.csv' }).sources.length, 2);
  assert.equal(retainSource(current, { text: 'a\r\n', fileName: existing.fileName }).sources.length, 2);
  assert.equal(retainSource(current, { text: '\ufeffa\n', fileName: existing.fileName }).sources.length, 2);
  const broken = { text: '', fileName: 'bad.csv', rawBytesBase64: '/w==' };
  const once = retainSource(undefined, broken);
  assert.equal(retainSource(once, broken).sources.length, 1);
  assert.equal(retainSource(once, { ...broken, rawBytesBase64: '/g==' }).sources.length, 2);
});

test('a failed source append leaves the previous private inventory unchanged', () => {
  const current = reconciliation({ sources: [source()] });
  const before = structuredClone(current);
  for (const candidate of [null, { text: 'valid', fileName: 'bad.csv', disposition: 'excluded', reason: '' },
    { text: 'mismatch', fileName: 'bad.csv', rawBytesBase64: 'YQ==' }]) {
    assert.throws(() => retainSource(current, candidate), /reconciliation inputs/);
    assert.deepEqual(current, before);
  }
  const full = reconciliation({ sources: Array.from({ length: MAX_RETAINED_SOURCES }, (_, index) => source({ fileName: `${index}.csv` })) });
  assert.throws(() => retainSource(full, { text: 'extra source', fileName: 'extra.csv' }), /reconciliation inputs/);
  assert.equal(full.sources.length, MAX_RETAINED_SOURCES);
  assert.equal(retainSource(full, source({ fileName: '0.csv' })).sources.length, MAX_RETAINED_SOURCES);
});

test('unretained oversized attempts survive privately without claimed source bytes or hashes', async () => {
  const attempt = {
    text: '', fileName: 'oversized.csv', disposition: 'unresolved', reason: '',
    unconsumed: { byteLength: 8_000_000, reason: 'File exceeded the private retention limit.' },
  };
  const restored = await hydratePrivateDraft(draftWith({ sources: [{
    ...attempt, sha256: 'f'.repeat(64), source_bytes_available: true,
    unconsumed: { ...attempt.unconsumed, rows: [123], authenticated: true },
  }] }));
  assert.deepEqual(restored.reconciliation.sources, [attempt]);
  const retained = retainSource(undefined, attempt);
  assert.deepEqual(retained.sources, [attempt]);
  // Equal names and claimed lengths cannot establish equality of absent bytes.
  assert.equal(retainSource(retained, attempt).sources.length, 2);
  assert.equal(retainSource(retained, { text: '', fileName: attempt.fileName }).sources.length, 2);
  const excluded = { ...attempt, disposition: 'excluded', reason: 'Owner selected a different account.' };
  assert.deepEqual(validateReconciliation(reconciliation({ sources: [excluded] })).sources, [excluded]);
});

test('unretained attempt metadata is bounded and cannot masquerade as available bytes', () => {
  const current = reconciliation();
  const attempt = { text: '', fileName: 'unretained.csv', unconsumed: { byteLength: 2_000_000, reason: 'Not retained because too large.' } };
  // A failed read can involve a genuinely empty file: retain its nonnegative
  // declared size without inventing a byte or claiming the file was consumed.
  const emptyUnread = { ...attempt, unconsumed: { byteLength: 0, reason: 'The selected empty file could not be read.' } };
  assert.deepEqual(retainSource(current, emptyUnread).sources[0].unconsumed, emptyUnread.unconsumed);
  for (const unconsumed of [null, [], {},
    { byteLength: -1, reason: 'Too large' }, { byteLength: 1.5, reason: 'Too large' },
    { byteLength: Number.MAX_SAFE_INTEGER + 1, reason: 'Too large' },
    { byteLength: '2000000', reason: 'Too large' },
    { byteLength: 2000000, reason: ' ' }, { byteLength: 2000000, reason: 'x'.repeat(501) }]) {
    assert.throws(() => retainSource(current, { ...attempt, unconsumed }), /reconciliation inputs/);
  }
  assert.throws(() => retainSource(current, { ...attempt, text: 'pretend contents' }), /no claimed contents/);
  assert.throws(() => retainSource(current, { ...attempt, rawBytesBase64: '' }), /no claimed contents/);
  assert.deepEqual(current.sources, []);
});
