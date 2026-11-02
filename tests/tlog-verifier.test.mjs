import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import * as browserTlog from '../src/tlogVerifier.js';
import * as cliTlog from '../scripts/verify-tlog.mjs';

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
  L.length === 0
    ? H()
    : L.length === 1
      ? L[0]
      : node(mth(L.slice(0, split(L.length))), mth(L.slice(split(L.length))));
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

// §5.1 Conformance vectors from transparency-dev/merkle (testonly/constants.go)
const CONFORMANCE_LEAVES = [
  ['', '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d'],
  ['00', '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7'],
  ['10', '0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7'],
  ['2021', '07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7'],
  ['3031', 'bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b'],
  ['40414243', '4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658'],
  ['5051525354555657', 'b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f'],
  ['606162636465666768696a6b6c6d6e6f', '46f6ffadd3d06a09ff3c5860d2755c8b9819db7df44251788c7d8e3180de8eb1'],
];

const CONFORMANCE_ROOTS = [
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
  'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
  'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
  'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
  '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
  '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
  'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
  '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
];

// §5.2 Deterministic N170 adversarial split-view vector construction
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
const WN = ['witness-1.n170.example', 'witness-2.example', 'witness-3.example', 'witness-x.example'];
const W = ['w1', 'w2', 'w3', 'wx'].map(ed);
const body = (n, r) => `${ORIGIN}\n${n}\n${b64(r)}\n`;
const logLine = (bd, k = LOG) => `\u2014 ${ORIGIN} ${b64(Buffer.concat([keyId(ORIGIN, 1, k.pub), sign(null, B(bd), k.priv)]))}`;
const cos = (bd, i, ts = TS) =>
  `\u2014 ${WN[i]} ${b64(Buffer.concat([keyId(WN[i], 4, W[i].pub), u64be(ts), sign(null, B(`cosignature/v1\ntime ${ts}\n${bd}`), W[i].priv)]))}`;
const note = (bd, ls) => `${bd}\n${ls.join('\n')}\n`;
const LH = LEAVES.map(lh);
const root = (n, L = LH) => mth(L.slice(0, n));
const b8 = body(8, root(8));
const b7 = body(7, root(7));
const CP8 = note(b8, [logLine(b8), cos(b8, 0), cos(b8, 1), cos(b8, 2)]);
const CP7 = note(b7, [logLine(b7), cos(b7, 0), cos(b7, 1)]);
const bundle = (i, rec, path = PATH(i, LH)) => ({
  leaf_index: String(i),
  leaf: b64(LEAVES[i]),
  record: b64(rec),
  inclusion_path: path.map(b64),
});
const LF = LH.slice();
LF[4] = lh(makeLeaf(K, 1, ev('K1-A'), ev('K0')));
const bF = body(8, mth(LF));
const LW = LH.slice();
LW[4] = lh(makeLeaf(Z, 9, ev('cover'), ZERO));
const p2 = PATH(2, LH);
const flip = p2.map((h, j) => (j === 1 ? Buffer.from(h.map((x, k) => (k === 0 ? x ^ 1 : x))) : h));
const STALE = TS - 400n * 86400n - 1n;

const POLICY = {
  origin: ORIGIN,
  log: vkey(ORIGIN, 1, LOG.pub),
  witnesses: [0, 1, 2].map((i) => vkey(WN[i], 4, W[i].pub)),
  quorum: 2,
  maxSkewSec: 600,
  maxAgeSec: 400 * 86400,
};

for (const [label, mod] of [
  ['Browser', browserTlog],
  ['CLI', cliTlog],
]) {
  test(`${label}: transparency-dev/merkle conformance vectors (8 leaves, 9 roots, 2 inclusion, 3 consistency)`, async () => {
    const { leafHash, hexd, hexe, verifyInclusion, verifyConsistency } = mod;
    const computedLeaves = [];
    for (let i = 0; i < CONFORMANCE_LEAVES.length; i++) {
      const [inputHex, expectedLeafHex] = CONFORMANCE_LEAVES[i];
      const h = await leafHash(hexd(inputHex));
      assert.equal(hexe(h), expectedLeafHex, `leaf ${i}`);
      computedLeaves.push(Buffer.from(h));
    }

    for (let sz = 0; sz <= 8; sz++) {
      const r = mth(computedLeaves.slice(0, sz));
      assert.equal(r.toString('hex'), CONFORMANCE_ROOTS[sz], `tree root size ${sz}`);
    }

    // Inclusion (index 2, size 8)
    const inc2_8 = [
      '07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7',
      'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
      '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4',
    ].map(hexd);
    assert.equal(
      await verifyInclusion(2, 8, hexd(CONFORMANCE_LEAVES[2][1]), inc2_8, hexd(CONFORMANCE_ROOTS[8])),
      true
    );

    // Inclusion (index 5, size 7)
    const inc5_7 = [
      'bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b',
      'b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f',
      'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
    ].map(hexd);
    assert.equal(
      await verifyInclusion(5, 7, hexd(CONFORMANCE_LEAVES[5][1]), inc5_7, hexd(CONFORMANCE_ROOTS[7])),
      true
    );

    // Consistency (6 -> 8)
    const cons6_8 = [
      '0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a',
      'ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0',
      'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
    ].map(hexd);
    assert.equal(
      await verifyConsistency(6, 8, hexd(CONFORMANCE_ROOTS[6]), hexd(CONFORMANCE_ROOTS[8]), cons6_8),
      true
    );

    // Consistency (3 -> 7)
    const cons3_7 = [
      '0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7',
      '07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7',
      'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
      '837dbb152e9b079010717e84e865da4ebc0fa198a806d59d31bf15accef22d0e',
    ].map(hexd);
    assert.equal(
      await verifyConsistency(3, 7, hexd(CONFORMANCE_ROOTS[3]), hexd(CONFORMANCE_ROOTS[7]), cons3_7),
      true
    );

    // Consistency (1 -> 8)
    const cons1_8 = [
      '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7',
      '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
      '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4',
    ].map(hexd);
    assert.equal(
      await verifyConsistency(1, 8, hexd(CONFORMANCE_ROOTS[1]), hexd(CONFORMANCE_ROOTS[8]), cons1_8),
      true
    );
  });

  test(`${label}: Case (i) same key, same sequence, two events -> both pass inclusion, receipt comparison reports EQUIVOCATION`, async () => {
    const cp8 = await mod.verifyCheckpoint(CP8, POLICY, Number(TS));
    const bA = bundle(2, R('K1-A'));
    const bB = bundle(4, R('K1-B'));
    const resA = await mod.verifyN170Merkle(bA, cp8, new Uint8Array(K), null);
    const resB = await mod.verifyN170Merkle(bB, cp8, new Uint8Array(K), null);
    assert.equal(resA.ok, true);
    assert.equal(resB.ok, true);

    const receiptFromA = {
      sequence: resA.leaf.sequence,
      event_sha256: resA.leaf.event_sha256,
      checkpoint_size: cp8.size,
      checkpoint_root: cp8.root,
    };
    const equivRes = await mod.verifyN170Merkle(bB, cp8, new Uint8Array(K), receiptFromA);
    assert.equal(equivRes.ok, false);
    assert.ok(equivRes.errors.some((e) => e.startsWith('EQUIVOCATION:')));
  });

  test(`${label}: Case (ii) chain break (sequence s=2 whose predecessor != receipt's event_sha256 at s=1)`, async () => {
    const cp8 = await mod.verifyCheckpoint(CP8, POLICY, Number(TS));
    const resA = await mod.verifyN170Merkle(bundle(2, R('K1-A')), cp8, new Uint8Array(K), null);
    const receiptA = {
      sequence: resA.leaf.sequence,
      event_sha256: resA.leaf.event_sha256,
      checkpoint_size: cp8.size,
      checkpoint_root: cp8.root,
    };
    const resBreak = await mod.verifyN170Merkle(bundle(5, R('K2-B')), cp8, new Uint8Array(K), receiptA);
    assert.equal(resBreak.ok, false);
    assert.ok(resBreak.errors.some((e) => e.startsWith('CHAIN BREAK:')));
  });

  test(`${label}: Cases (iii-a, iii-b, iii-c) forged checkpoints rejected`, async () => {
    const noteIiiA = note(bF, [logLine(bF, ATK)]);
    await assert.rejects(
      () => mod.verifyCheckpoint(noteIiiA, POLICY, Number(TS)),
      /no valid signature from the pinned log key/
    );

    const noteIiiB = note(bF, [logLine(bF), ...CP8.split('\n\n')[1].trim().split('\n').slice(1)]);
    await assert.rejects(
      () => mod.verifyCheckpoint(noteIiiB, POLICY, Number(TS)),
      /cosignature INVALID/
    );

    const noteIiiC = note(bF, [logLine(bF)]);
    await assert.rejects(
      () => mod.verifyCheckpoint(noteIiiC, POLICY, Number(TS)),
      /witness quorum not met: 0\/2/
    );
  });

  test(`${label}: Case (iv) right proof checked against wrong checkpoint CP7 fails inclusion`, async () => {
    const cp7 = await mod.verifyCheckpoint(CP7, POLICY, Number(TS));
    const res = await mod.verifyN170Merkle(bundle(2, R('K1-A')), cp7, new Uint8Array(K), null);
    assert.equal(res.ok, false);
    assert.ok(res.errors.includes('inclusion proof does not verify against the checkpoint root'));
  });

  test(`${label}: Case (v) one hash altered in inclusion path fails verification`, async () => {
    const cp8 = await mod.verifyCheckpoint(CP8, POLICY, Number(TS));
    const res = await mod.verifyN170Merkle(bundle(2, R('K1-A'), flip), cp8, new Uint8Array(K), null);
    assert.equal(res.ok, false);
    assert.ok(res.errors.includes('inclusion proof does not verify against the checkpoint root'));
  });

  test(`${label}: Case (vi) truncated and over-long inclusion paths both fail`, async () => {
    const cp8 = await mod.verifyCheckpoint(CP8, POLICY, Number(TS));
    const resShort = await mod.verifyN170Merkle(bundle(2, R('K1-A'), p2.slice(0, -1)), cp8, new Uint8Array(K), null);
    assert.equal(resShort.ok, false);
    const resLong = await mod.verifyN170Merkle(bundle(2, R('K1-A'), [...p2, root(8)]), cp8, new Uint8Array(K), null);
    assert.equal(resLong.ok, false);
  });

  test(`${label}: Case (vii) index out of range (leaf_index "8", size 8) fails`, async () => {
    const cp8 = await mod.verifyCheckpoint(CP8, POLICY, Number(TS));
    const bOut = { ...bundle(2, R('K1-A')), leaf_index: '8' };
    const res = await mod.verifyN170Merkle(bOut, cp8, new Uint8Array(K), null);
    assert.equal(res.ok, false);
  });

  test(`${label}: Case (viii) history rewrite fails consistency with LOG FORK while honest proof passes`, async () => {
    const cp8Honest = await mod.verifyCheckpoint(CP8, POLICY, Number(TS));
    const b6Root = b64(root(6));
    const receiptAt6 = {
      sequence: 1n,
      event_sha256: new Uint8Array(ev('K1-A')),
      checkpoint_size: 6n,
      checkpoint_root: new Uint8Array(root(6)),
    };
    const honestBundle = {
      ...bundle(6, R('K2-A')),
      consistency: {
        from_size: '6',
        from_root: b6Root,
        path: PROOF(6, LH).map(b64),
      },
    };
    const honestRes = await mod.verifyN170Merkle(honestBundle, cp8Honest, new Uint8Array(K), receiptAt6);
    assert.equal(honestRes.ok, true);

    const cp8Forked = { size: 8n, root: new Uint8Array(mth(LW)) };
    const forkedBundle = {
      ...bundle(6, R('K2-A'), PATH(6, LW)),
      consistency: {
        from_size: '6',
        from_root: b6Root,
        path: PROOF(6, LW).map(b64),
      },
    };
    const forkedRes = await mod.verifyN170Merkle(forkedBundle, cp8Forked, new Uint8Array(K), receiptAt6);
    assert.equal(forkedRes.ok, false);
    assert.ok(forkedRes.errors.some((e) => e.startsWith('LOG FORK:')));
  });

  test(`${label}: Case (ix) stale or unknown cosigner rejected with quorum 1/2`, async () => {
    const noteIx = note(b8, [logLine(b8), cos(b8, 0), cos(b8, 1, STALE), cos(b8, 3)]);
    await assert.rejects(
      () => mod.verifyCheckpoint(noteIx, POLICY, Number(TS)),
      /witness quorum not met: 1\/2/
    );
  });

  test(`${label}: Case (x) clean substitute record fails event_sha256 binding`, async () => {
    const cp8 = await mod.verifyCheckpoint(CP8, POLICY, Number(TS));
    const res = await mod.verifyN170Merkle(bundle(2, R('K1-clean')), cp8, new Uint8Array(K), null);
    assert.equal(res.ok, false);
    assert.ok(res.errors.includes('event_sha256 != SHA-256(bundled record)'));
  });
}

test('tlog tile coordinate example (leaf 69,999 in tree of size 70,000) and CLI --help', async () => {
  assert.deepEqual(browserTlog.entryLocation(69999n, 70000n), {
    tile: 'tile/0/273.p/112',
    bundle: 'tile/entries/273.p/112',
    offset: 111n,
  });
  const help = await cliTlog.runCli(['--help']);
  assert.equal(help.exitCode, 0);
  assert.ok(help.output.startsWith('Usage: node scripts/verify-tlog.mjs '));
});
