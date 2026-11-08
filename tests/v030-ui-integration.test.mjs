import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { transformWithEsbuild } from 'vite';
import { build } from 'esbuild';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { inspectHeadline } from '../src/headline.js';
import { verifyTlogProofBundle } from '../src/tlogVerifier.js';

const root = new URL('../', import.meta.url);
const read = (p) => readFileSync(new URL(p, root));
const text = (p) => read(p).toString('utf8');
const unhex = (h) => new Uint8Array(Buffer.from(h, 'hex'));

const REC_W = text('tests/fixtures/witness/REC-W.json');
const W_OK_BYTES = read('tests/fixtures/witness/W-OK.receipt.json');
const W_OK_EVENT_SHA = 'b64c266f17152172e7f7ab9d40f2e3ed7732310e062992ba518741362de743de';
const W_OK_RECEIPT_SHA = '4be34ace24c32130722b741092c860a0d5ba9202d454bb1a2c27710273bbaafc';
const WITNESS_TRUST = {
  eventSha256: W_OK_EVENT_SHA,
  trustedWitnessKeys: ['fa06-b0ff-e89f-e266-cfdb'],
  allowedBrokerHosts: ['ndcdyn.interactivebrokers.com'],
};

// OpenTimestamps proof binding W_OK_RECEIPT_SHA via 32-byte sibling prepend + double-SHA256 to Block 358,391
const W_OK_OTS_CONFIRMED = unhex(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108' +
  W_OK_RECEIPT_SHA +
  'f1200be23709859913babd4460bbddf8ed213e7c8773a4b1face30f8acfdf093b7050808000588960d73d7190103f7ef15'
);

const W_OK_OTS_PENDING = unhex(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108' +
  W_OK_RECEIPT_SHA +
  'f1200be23709859913babd4460bbddf8ed213e7c8773a4b1face30f8acfdf093b70508080083dfe30d2ef90c8e2e2d68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267'
);

// Mined 80-byte Bitcoin header (nTime = 1791594000 = 2026-10-10T01:00:00Z, nBits = 0x1d00ffff, nonce = 2760797291)
const VALID_BTC_HEADER_HEX =
  '000000201111111111111111111111111111111111111111111111111111111111111111' +
  'c1b560b7ab4fbe20ec387b1f7ccc47b7ce2d8d0c1830a6f86255f5b941ac2078' +
  '108ec96affff001d6b6c8ea4';

const CORRUPTED_NONCE_HEADER_HEX =
  '000000201111111111111111111111111111111111111111111111111111111111111111' +
  'c1b560b7ab4fbe20ec387b1f7ccc47b7ce2d8d0c1830a6f86255f5b941ac2078' +
  '108ec96affff001d00000000';

const LOW_DIFF_HEADER_HEX =
  '000000201111111111111111111111111111111111111111111111111111111111111111' +
  'c1b560b7ab4fbe20ec387b1f7ccc47b7ce2d8d0c1830a6f86255f5b941ac2078' +
  '108ec96affff001f6b6c8ea4';

const MISMATCHED_MERKLE_HEADER_HEX =
  '000000201111111111111111111111111111111111111111111111111111111111111111' +
  '00b560b7ab4fbe20ec387b1f7ccc47b7ce2d8d0c1830a6f86255f5b941ac2078' +
  '108ec96affff001d6b6c8ea4';

// C2SP tlog-tiles fixtures for browser integration
const B = (x) => (typeof x === 'string' ? Buffer.from(x, 'utf8') : Buffer.from(x));
const H = (...xs) => createHash('sha256').update(Buffer.concat(xs.map(B))).digest();
const node = (l, r) => H([0x01], l, r);
const lh = (e) => H([0x00], e);
const b64 = (b) => b.toString('base64');
const split = (n) => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};
const mth = (L) =>
  L.length === 0 ? H() : L.length === 1 ? L[0] : node(mth(L.slice(0, split(L.length))), mth(L.slice(split(L.length))));
const PATH = (m, L) => {
  if (L.length <= 1) return [];
  const k = split(L.length);
  return m < k ? [...PATH(m, L.slice(0, k)), mth(L.slice(k))] : [...PATH(m - k, L.slice(k)), mth(L.slice(0, k))];
};
const SUB = (m, L, b) => {
  if (m === L.length) return b ? [] : [mth(L)];
  const k = split(L.length);
  return m <= k
    ? [...SUB(m, L.slice(0, k), b), mth(L.slice(k))]
    : [...SUB(m - k, L.slice(k), false), mth(L.slice(0, k))];
};
const PROOF = (m, L) => SUB(m, L, true);

const ZERO = Buffer.alloc(32);
const u64be = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
};
const makeLeaf = (kc, s, e, p) => Buffer.concat([Buffer.from([0x01]), kc, u64be(s), e, p]);
const R = (l) => B('n170-test-record:' + l);
const ev = (l) => H(R(l));
const K = H('n170-test-owner-K');
const Z = H('n170-test-owner-Z');
const LEAVES = [
  makeLeaf(Z, 0, ev('Z0'), ZERO),
  makeLeaf(K, 0, ev('K0'), ZERO),
  makeLeaf(K, 1, ev('K1-A'), ev('K0')),
  makeLeaf(Z, 1, ev('Z1'), ev('Z0')),
  makeLeaf(K, 1, ev('K1-B'), ev('K0')),
  makeLeaf(K, 2, ev('K2-B'), ev('K1-B')),
  makeLeaf(K, 2, ev('K2-A'), ev('K1-A')),
  makeLeaf(Z, 2, ev('Z2'), ev('Z1')),
];
const LH = LEAVES.map(lh);
const treeRoot = (n, L = LH) => mth(L.slice(0, n));

const ed = (l) => {
  const priv = createPrivateKey({
    format: 'der',
    type: 'pkcs8',
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), H('n170-test-key:' + l)]),
  });
  return { priv, pub: createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(12) };
};
const keyId = (name, t, pub) => H(name + '\n', [t], pub).subarray(0, 4);
const vkey = (name, t, pub) => `${name}+${keyId(name, t, pub).toString('hex')}+${b64(Buffer.concat([Buffer.from([t]), pub]))}`;
const ORIGIN = 'log.n170.example/v1';
const TS = 1793491200n;
const LOG = ed('log');
const ATK = ed('attacker');
const WN = ['witness-1.n170.example', 'witness-2.example', 'witness-3.example'];
const W = ['w1', 'w2', 'w3'].map(ed);
const body = (n, r) => `${ORIGIN}\n${n}\n${b64(r)}\n`;
const logLine = (bd, k = LOG) => `\u2014 ${ORIGIN} ${b64(Buffer.concat([keyId(ORIGIN, 1, k.pub), sign(null, B(bd), k.priv)]))}`;
const cos = (bd, i, ts = TS) =>
  `\u2014 ${WN[i]} ${b64(Buffer.concat([keyId(WN[i], 4, W[i].pub), u64be(ts), sign(null, B(`cosignature/v1\ntime ${ts}\n${bd}`), W[i].priv)]))}`;
const note = (bd, ls) => `${bd}\n${ls.join('\n')}\n`;

const b8 = body(8, treeRoot(8));
const CP8 = note(b8, [logLine(b8), cos(b8, 0), cos(b8, 1), cos(b8, 2)]);
const POLICY = {
  origin: ORIGIN,
  log: vkey(ORIGIN, 1, LOG.pub),
  witnesses: [0, 1, 2].map((i) => vkey(WN[i], 4, W[i].pub)),
  quorum: 2,
  key_code: K.toString('hex'),
  now: Number(TS),
};

const makeBundle = (i, rec, cp = CP8, path = PATH(i, LH), extra = {}) => ({
  checkpoint: cp,
  leaf_index: String(i),
  leaf: b64(LEAVES[i]),
  record: b64(rec),
  inclusion_path: path.map(b64),
  ...extra,
});

test('inspectHeadline elevates Time ladder row to CONFIRMED when valid OTS proof and mined 80-byte Bitcoin header are supplied', async () => {
  const res = await inspectHeadline(REC_W, {
    ...WITNESS_TRUST,
    receiptBytes: W_OK_BYTES,
    otsProofBytes: W_OK_OTS_CONFIRMED,
    bitcoinHeader: VALID_BTC_HEADER_HEX,
  });
  assert.equal(res.headline.headline, 'WITNESSED RECORD');
  assert.equal(res.headline.exit, 0);
  assert.equal(res.context.timestamp_proof, 'CONFIRMED');
  assert.equal(res.witness.timestamp_proof.status, 'CONFIRMED');
  assert.equal(res.witness.timestamp_proof.height, 358391);
  assert.equal(res.witness.timestamp_proof.utc, '2026-10-10T01:00:00Z');
  const timeRow = res.headline.ladder.find((r) => r.row === 'Time');
  assert.equal(timeRow.text, 'CONFIRMED · Bitcoin block 358391 (2026-10-10T01:00:00Z)');
  assert.ok(Object.isFrozen(res.headline));
  assert.ok(Object.isFrozen(res.headline.ladder));
});

test('inspectHeadline degrades timestamp_proof to INVALID when Bitcoin header fails PoW, difficulty floor, or Merkle root', async () => {
  for (const [label, badHeader] of [
    ['corrupted nonce', CORRUPTED_NONCE_HEADER_HEX],
    ['low difficulty', LOW_DIFF_HEADER_HEX],
    ['mismatched merkle root', MISMATCHED_MERKLE_HEADER_HEX],
  ]) {
    const res = await inspectHeadline(REC_W, {
      ...WITNESS_TRUST,
      receiptBytes: W_OK_BYTES,
      otsProofBytes: W_OK_OTS_CONFIRMED,
      bitcoinHeader: badHeader,
    });
    assert.equal(res.headline.headline, 'WITNESSED RECORD', label);
    assert.equal(res.context.timestamp_proof, 'INVALID', label);
    assert.equal(res.witness.timestamp_proof.status, 'INVALID', label);
    const timeRow = res.headline.ladder.find((r) => r.row === 'Time');
    assert.equal(timeRow.text, 'Supplied timestamp proof does not bind the receipt', label);
  }
});

test('inspectHeadline keeps calendar-only OTS proof as PENDING even when a Bitcoin header is supplied', async () => {
  const res = await inspectHeadline(REC_W, {
    ...WITNESS_TRUST,
    receiptBytes: W_OK_BYTES,
    otsProofBytes: W_OK_OTS_PENDING,
    bitcoinHeader: VALID_BTC_HEADER_HEX,
  });
  assert.equal(res.headline.headline, 'WITNESSED RECORD');
  assert.equal(res.context.timestamp_proof, 'PENDING');
  assert.equal(res.witness.timestamp_proof.status, 'PENDING');
  const timeRow = res.headline.ladder.find((r) => r.row === 'Time');
  assert.equal(timeRow.text, 'Receipt timestamp proof binds the receipt; confirmation not verified');
});

test('inspectHeadline verifies valid C2SP transparency log proof bundle and populates retention receipt', async () => {
  const validBundle = makeBundle(2, R('K1-A'));
  const res = await inspectHeadline(REC_W, {
    tlogProof: JSON.stringify(validBundle),
    tlogPolicy: JSON.stringify(POLICY),
  });
  assert.equal(res.headline.exit, 0);
  assert.ok(res.tlog);
  assert.equal(res.tlog.ok, true);
  assert.equal(res.tlog.conflict, false);
  assert.equal(res.tlog.origin, ORIGIN);
  assert.equal(res.tlog.treeSize, '8');
  assert.equal(res.tlog.sequence, '1');
  assert.equal(res.tlog.eventSha256Hex, ev('K1-A').toString('hex'));
  assert.equal(res.tlog.retentionReceipt.sequence, '1');
  assert.equal(res.tlog.retentionReceipt.checkpoint_size, '8');
});

test('inspectHeadline maps C2SP EQUIVOCATION, CHAIN BREAK, and LOG FORK to CONFLICT: CONFLICTING_HISTORY (exit 2)', async () => {
  const bundleA = makeBundle(2, R('K1-A'));
  const firstCheck = await verifyTlogProofBundle(bundleA, POLICY);
  assert.equal(firstCheck.ok, true);
  const receiptA = firstCheck.retentionReceipt;

  // Case 1: EQUIVOCATION (same sequence s=1, different event K1-B)
  const bundleEquiv = makeBundle(4, R('K1-B'));
  const resEquiv = await inspectHeadline(REC_W, {
    tlogProof: JSON.stringify(bundleEquiv),
    tlogPolicy: JSON.stringify(POLICY),
    tlogReceipt: JSON.stringify(receiptA),
  });
  assert.equal(resEquiv.tlog.ok, false);
  assert.equal(resEquiv.tlog.conflict, true);
  assert.equal(resEquiv.facts.comparison, 'CONFLICT');
  assert.equal(resEquiv.headline.headline, 'CONFLICT: CONFLICTING_HISTORY');
  assert.equal(resEquiv.headline.exit, 2);

  // Case 2: CHAIN BREAK (sequence s=2 whose predecessor != receiptA.event_sha256)
  const bundleBreak = makeBundle(5, R('K2-B'));
  const resBreak = await inspectHeadline(REC_W, {
    tlogProof: JSON.stringify(bundleBreak),
    tlogPolicy: JSON.stringify(POLICY),
    tlogReceipt: JSON.stringify(receiptA),
  });
  assert.equal(resBreak.tlog.ok, false);
  assert.equal(resBreak.tlog.conflict, true);
  assert.equal(resBreak.facts.comparison, 'CONFLICT');
  assert.equal(resBreak.headline.headline, 'CONFLICT: CONFLICTING_HISTORY');
  assert.equal(resBreak.headline.exit, 2);

  // Case 3: LOG FORK (history rewrite failing consistency proof from size 6 -> 8)
  const LW = LH.slice();
  LW[4] = lh(makeLeaf(Z, 9, ev('cover'), ZERO));
  const bFork = body(8, mth(LW));
  const cpFork = note(bFork, [logLine(bFork), cos(bFork, 0), cos(bFork, 1)]);
  const receiptAt6 = {
    sequence: '1',
    event_sha256: ev('K1-A').toString('hex'),
    checkpoint_size: '6',
    checkpoint_root: b64(treeRoot(6)),
  };
  const bundleFork = makeBundle(6, R('K2-A'), cpFork, PATH(6, LW), {
    consistency: {
      from_size: '6',
      from_root: b64(treeRoot(6)),
      path: PROOF(6, LW).map(b64),
    },
  });
  const resFork = await inspectHeadline(REC_W, {
    tlogProof: JSON.stringify(bundleFork),
    tlogPolicy: JSON.stringify(POLICY),
    tlogReceipt: JSON.stringify(receiptAt6),
  });
  assert.equal(resFork.tlog.ok, false);
  assert.equal(resFork.tlog.conflict, true);
  assert.equal(resFork.facts.comparison, 'CONFLICT');
  assert.equal(resFork.headline.headline, 'CONFLICT: CONFLICTING_HISTORY');
  assert.equal(resFork.headline.exit, 2);
});

test('inspectHeadline maps forged checkpoint, unmet witness quorum, or missing policy to REJECTED: INVALID_INPUT (exit 1)', async () => {
  const bAttacker = note(b8, [logLine(b8, ATK), cos(b8, 0), cos(b8, 1)]);
  const bNoWitnesses = note(b8, [logLine(b8)]);
  const bOneWitness = note(b8, [logLine(b8), cos(b8, 0)]);

  for (const [label, proof, policy] of [
    ['forged log signature', makeBundle(2, R('K1-A'), bAttacker), POLICY],
    ['0/2 witness quorum', makeBundle(2, R('K1-A'), bNoWitnesses), POLICY],
    ['1/2 witness quorum', makeBundle(2, R('K1-A'), bOneWitness), POLICY],
    ['missing policy', makeBundle(2, R('K1-A'), CP8), ''],
  ]) {
    const res = await inspectHeadline(REC_W, {
      tlogProof: JSON.stringify(proof),
      tlogPolicy: typeof policy === 'string' ? policy : JSON.stringify(policy),
    });
    assert.equal(res.tlog.ok, false, label);
    assert.equal(res.tlog.conflict, false, label);
    assert.equal(res.facts.parse, 'INVALID_INPUT', label);
    assert.deepEqual(res.context.record_reasons, ['TLOG_PROOF_INVALID'], label);
    assert.equal(res.headline.headline, 'REJECTED: INVALID_INPUT', label);
    assert.equal(res.headline.exit, 1, label);
  }
});

test('SSR rendering of HeadlineReview, TlogReview, and EmployerReview preserves 6-row ladder and renders tlog verification', async () => {
  const source = readFileSync(new URL('../src/EmployerReview.jsx', import.meta.url), 'utf8');
  const block = source.slice(source.indexOf('export function HeadlineReview'), source.indexOf('const comparisons'));
  const { code } = await transformWithEsbuild('import { download } from "./ui.jsx";\n' + block, 'HeadlineReview.jsx', { jsx: 'automatic' });
  const runtime = pathToFileURL(createRequire(import.meta.url).resolve('react/jsx-runtime')).href;
  const uiUrl = new URL('../src/ui.jsx', import.meta.url).href;
  const { HeadlineReview, TlogReview } = await import(
    'data:text/javascript;base64,' +
      Buffer.from(
        code
          .replace('"react/jsx-runtime"', JSON.stringify(runtime))
          .replace('"./ui.jsx"', JSON.stringify(JSON.stringify({})))
          .replace(`import { download } from ${JSON.stringify(JSON.stringify({}))};`, 'const download = () => {};')
      ).toString('base64')
  );

  const confirmedRes = await inspectHeadline(REC_W, {
    ...WITNESS_TRUST,
    receiptBytes: W_OK_BYTES,
    otsProofBytes: W_OK_OTS_CONFIRMED,
    bitcoinHeader: VALID_BTC_HEADER_HEX,
    tlogProof: JSON.stringify(makeBundle(2, R('K1-A'))),
    tlogPolicy: JSON.stringify(POLICY),
  });

  const headlineHtml = renderToStaticMarkup(createElement(HeadlineReview, { headline: confirmedRes.headline }));
  assert.equal((headlineHtml.match(/<dt>/g) || []).length, 6);
  assert.ok(headlineHtml.includes('CONFIRMED · Bitcoin block 358391 (2026-10-10T01:00:00Z)'));

  const tlogOkHtml = renderToStaticMarkup(createElement(TlogReview, { tlog: confirmedRes.tlog }));
  assert.ok(tlogOkHtml.includes('data-tlog-review'));
  assert.ok(tlogOkHtml.includes('C2SP transparency log proof verified'));
  assert.ok(tlogOkHtml.includes(ORIGIN));
  assert.ok(tlogOkHtml.includes('3 counted'));
  assert.ok(tlogOkHtml.includes('Retain transparency receipt'));

  const conflictRes = await inspectHeadline(REC_W, {
    tlogProof: JSON.stringify(makeBundle(4, R('K1-B'))),
    tlogPolicy: JSON.stringify(POLICY),
    tlogReceipt: JSON.stringify(confirmedRes.tlog.retentionReceipt),
  });
  const tlogConflictHtml = renderToStaticMarkup(createElement(TlogReview, { tlog: conflictRes.tlog }));
  assert.ok(tlogConflictHtml.includes('Transparency log conflict detected'));
  assert.ok(tlogConflictHtml.includes('data-tlog-errors'));
  assert.ok(tlogConflictHtml.includes('EQUIVOCATION:'));

  const bundle = await build({
    entryPoints: [new URL('../src/EmployerReview.jsx', import.meta.url).pathname],
    bundle: true,
    platform: 'node',
    format: 'esm',
    jsx: 'automatic',
    external: ['react', 'react-dom', 'react/jsx-runtime'],
    write: false,
    logLevel: 'silent',
  });
  const reactHref = pathToFileURL(createRequire(import.meta.url).resolve('react')).href;
  const bundledCode = bundle.outputFiles[0].text
    .replaceAll('"react/jsx-runtime"', JSON.stringify(runtime))
    .replaceAll('"react"', JSON.stringify(reactHref));
  const { default: EmployerReview } = await import(
    `data:text/javascript;base64,${Buffer.from(bundledCode).toString('base64')}`
  );
  const fullFormHtml = renderToStaticMarkup(createElement(EmployerReview));
  assert.ok(fullFormHtml.includes('id="bitcoin-header"'));
  assert.ok(fullFormHtml.includes('Transparency log proof (optional)'));
  assert.ok(fullFormHtml.includes('id="tlog-policy"'));
  assert.ok(fullFormHtml.includes('id="tlog-receipt"'));
});
