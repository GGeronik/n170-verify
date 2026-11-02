import test from 'node:test';
import assert from 'node:assert/strict';
import {
  verifyOtsProof as verifyOtsCli,
  verifyBitcoinHeader as verifyHeaderCli,
  ripemd160 as ripemd160Cli,
  keccak256 as keccak256Cli,
  runCli,
} from '../scripts/ots-verifier.mjs';
import {
  verifyOtsProof as verifyOtsBrowser,
  verifyBitcoinHeader as verifyHeaderBrowser,
  ripemd160 as ripemd160Browser,
  keccak256 as keccak256Browser,
} from '../src/otsVerifier.js';

const unhex = (h) => new Uint8Array(Buffer.from(h, 'hex'));

const TARGET_SHA256 = unhex('3f10376d0aebb4647ff550b60d69ba5ad6b6809d51af6a6476e0312a9433a3bf');
const HDR_358391 = unhex(
  '02000000b96394585a281b7e5f438fd1c9ed492645a1fd61cb3802040000000000000000' +
  '007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a' +
  '1e376755f58616186272def6'
);

const VEC_1A = unhex(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108' +
  '3f10376d0aebb4647ff550b60d69ba5ad6b6809d51af6a6476e0312a9433a3bf' +
  'fff004deadbeef080083dfe30d2ef90c8e2e2d68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267' +
  'fff2670006869a0d73d71b4503c0843d' +
  'f1200be23709859913babd4460bbddf8ed213e7c8773a4b1face30f8acfdf093b7050808000588960d73d7190103f7ef15'
);

const VEC_1B = unhex(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108' +
  '3f10376d0aebb4647ff550b60d69ba5ad6b6809d51af6a6476e0312a9433a3bf' +
  'ffff08000588960d73d7190103f7ef15'
);

const VEC_2A = unhex(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108' +
  '3f10376d0aebb4647ff550b60d69ba5ad6b6809d51af6a6476e0312a9433a3bf' +
  'f080'
);

const VEC_2B = unhex(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108' +
  '3f10376d0aebb4647ff550b60d69ba5ad6b6809d51af6a6476e0312a9433a3bf' +
  '000588960d73d7190106808080808001'
);

const VEC_2C = unhex(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108' +
  '3f10376d0aebb4647ff550b60d69ba5ad6b6809d51af6a6476e0312a9433a3bf' +
  'f040deadbeef'
);

const VEC_3 = unhex(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108' +
  '3f10376d0aebb4647ff550b60d69ba5ad6b6809d51af6a6476e0312a9433a3bf' +
  'f1200be23709859913babd4460bbddf8ed213e7c8773a4b1face30f8acfdf093b7040808000588960d73d7190103f7ef15'
);

const VEC_4_OTS = unhex(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108' +
  '3f10376d0aebb4647ff550b60d69ba5ad6b6809d51af6a6476e0312a9433a3bf' +
  'f1200be23709859913babd4460bbddf8ed213e7c8773a4b1face30f8acfdf093b7050808000588960d73d7190103f7ef15'
);

const VEC_4A_HDR = unhex(
  '02000000b96394585a281b7e5f438fd1c9ed492645a1fd61cb3802040000000000000000' +
  '007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a' +
  '1e376755f58616186272de00'
);

const VEC_4B_HDR = unhex(
  '02000000b96394585a281b7e5f438fd1c9ed492645a1fd61cb3802040000000000000000' +
  '007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a' +
  '00f15365ffff001f6d730200'
);

const VEC_5A = unhex(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108' +
  '3f10376d0aebb4647ff550b60d69ba5ad6b6809d51af6a6476e0312a9433a3bf' +
  'f1200be23709859913babd4460bbddf8ed213e7c8773a4b1face30f8acfdf093b70508080083dfe30d2ef90c8e2e2d68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267'
);

const VEC_5B = unhex(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108' +
  '3f10376d0aebb4647ff550b60d69ba5ad6b6809d51af6a6476e0312a9433a3bf' +
  'f1200be23709859913babd4460bbddf8ed213e7c8773a4b1face30f8acfdf093b70508080083dfe30d2ef90c8e353468747470733a2f2f63616c656e6461722e6578616d706c652e6f72672f303538383936306437336437313930313f6576696c3d31'
);

const HELLO_WORLD_SHA256 = unhex('03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340');
const HELLO_WORLD_OTS = unhex(
  '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108' +
  '03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340' +
  '03f1c8010100000001e482f9d32ecc3ba657b69d898010857b54457a90497982ff56f97c4ec58e6f9801000000' +
  '6b483045022100b253add1d1cf90844338a475a04ff13fc9e7bd242b07762dea07f5608b2de367022000b268ca' +
  '9c3342b3769cdd062891317cdcef87aac310b6855e9d93898ebbe8ec0121020d8e4d107d2b339b0050efdd4b4a' +
  '09245aa056048f125396374ea6a2ab0709c6ffffffff026533e605000000001976a9140bf057d40fbba6744862' +
  '515f5b55a2310de5772f88aca0860100000000001976a914f00688ac000000000808' +
  'f120a987f716c533913c314c78e35d35884cac943fa42cac49d2b2c69f4003f85f880808' +
  'f120dec55b3487e1e3f722a49b55a7783215862785f4a3acb392846019f71dc64a9d0808' +
  'f120b2ca18f485e080478e025dab3d464b416c0e1ecb6629c9aefce8c8214d0424320808' +
  'f02011b0e90661196ff4b0813c3eda141bab5e91604837bdf7a0c9df37db0e3a11980808' +
  'f020c34bc1a4a1093ffd148c016b1e664742914e939efabe4d3d356515914b26d9e20808' +
  'f020c3e6e7c38c69f6af24c2be34ebac48257ede61ec0a21b9535e4443277be306460808' +
  'f1200798bf8606e00024e5d5d54bf0c960f629dfb9dad69157455b6f2652c0e8de810808' +
  'f0203f9ada6d60baa244006bb0aad51448ad2fafb9d4b6487a0999cff26b91f0f5360808' +
  'f120c703019e959a8dd3faef7489bb328ba485574758e7091f01464eb65872c975c80808' +
  'f020cbfefff513ff84b915e3fed6f9d799676630f8364ea2a6c7557fad94a5b5d7880808' +
  'f1200be23709859913babd4460bbddf8ed213e7c8773a4b1face30f8acfdf093b7050808' +
  '000588960d73d7190103f7ef15'
);

for (const [label, verifyOtsProof, verifyBitcoinHeader, ripemd160, keccak256] of [
  ['CLI', verifyOtsCli, verifyHeaderCli, ripemd160Cli, keccak256Cli],
  ['Browser', verifyOtsBrowser, verifyHeaderBrowser, ripemd160Browser, keccak256Browser],
]) {
  test(`${label}: pure-JS ripemd160 and pre-NIST keccak256 match standard digests`, () => {
    assert.equal(
      Buffer.from(ripemd160(HELLO_WORLD_SHA256)).toString('hex'),
      '1df8859e60bc679503d16dcb870e6ce91a57e9df'
    );
    assert.equal(
      Buffer.from(keccak256(new Uint8Array(0))).toString('hex'),
      'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    );
  });

  test(`${label}: Vec 1A multi-branch fork (Pending + Litecoin/Unknown + Bitcoin) confirms Block 358,391`, async () => {
    assert.equal(VEC_1A.length, 194);
    const res = await verifyOtsProof(VEC_1A, TARGET_SHA256, { headers: { 358391: HDR_358391 } });
    assert.equal(res.status, 'CONFIRMED');
    assert.equal(res.height, 358391);
    assert.equal(res.nTime, 1432827678);
    assert.equal(res.merkleRoot, '007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a');
    assert.deepEqual(res.attestations.map((a) => a.type), ['pending', 'unknown', 'bitcoin']);
  });

  test(`${label}: Vec 1B malformed empty fork (0xff 0xff) rejects with ERR_INVALID_FORK`, async () => {
    assert.equal(VEC_1B.length, 81);
    await assert.rejects(
      () => verifyOtsProof(VEC_1B, TARGET_SHA256, { headers: { 358391: HDR_358391 } }),
      (err) => err.code === 'ERR_INVALID_FORK'
    );
  });

  test(`${label}: Vec 2A truncated non-terminating LEB128 varint at EOF rejects with ERR_TRUNCATED`, async () => {
    assert.equal(VEC_2A.length, 67);
    await assert.rejects(
      () => verifyOtsProof(VEC_2A, TARGET_SHA256),
      (err) => err.code === 'ERR_TRUNCATED'
    );
  });

  test(`${label}: Vec 2B 6-byte 32-bit shift-overflowing LEB128 varint rejects with ERR_VARINT_OVERFLOW`, async () => {
    assert.equal(VEC_2B.length, 81);
    await assert.rejects(
      () => verifyOtsProof(VEC_2B, TARGET_SHA256),
      (err) => err.code === 'ERR_VARINT_OVERFLOW'
    );
  });

  test(`${label}: Vec 2C out-of-bounds varbytes slice length rejects with ERR_TRUNCATED`, async () => {
    assert.equal(VEC_2C.length, 71);
    await assert.rejects(
      () => verifyOtsProof(VEC_2C, TARGET_SHA256),
      (err) => err.code === 'ERR_TRUNCATED'
    );
  });

  test(`${label}: Vec 3 1-bit corruption in prepended Merkle sibling rejects with ERR_MERKLE_MISMATCH`, async () => {
    assert.equal(VEC_3.length, 114);
    await assert.rejects(
      () => verifyOtsProof(VEC_3, TARGET_SHA256, { headers: { 358391: HDR_358391 } }),
      (err) => err.code === 'ERR_MERKLE_MISMATCH'
    );
  });

  test(`${label}: Vec 4A corrupted nonce failing nBits PoW inequality rejects with ERR_POW_INVALID`, async () => {
    assert.equal(VEC_4_OTS.length, 114);
    assert.equal(VEC_4A_HDR.length, 80);
    await assert.rejects(
      () => verifyOtsProof(VEC_4_OTS, TARGET_SHA256, { headers: { 358391: VEC_4A_HDR } }),
      (err) => err.code === 'ERR_POW_INVALID'
    );
  });

  test(`${label}: Vec 4B spoofed low-difficulty header with mined nonce rejects with ERR_DIFFICULTY_TOO_LOW`, async () => {
    assert.equal(VEC_4B_HDR.length, 80);
    await assert.rejects(
      () => verifyOtsProof(VEC_4_OTS, TARGET_SHA256, { headers: { 358391: VEC_4B_HDR } }),
      (err) => err.code === 'ERR_DIFFICULTY_TOO_LOW'
    );
  });

  test(`${label}: Vec 5A calendar-only proof reaching authentic Merkle root returns PENDING (never CONFIRMED)`, async () => {
    assert.equal(VEC_5A.length, 157);
    const res = await verifyOtsProof(VEC_5A, TARGET_SHA256, { headers: { 358391: HDR_358391 } });
    assert.equal(res.status, 'PENDING');
    assert.equal(res.attestations.length, 1);
    assert.equal(res.attestations[0].type, 'pending');
  });

  test(`${label}: Vec 5B pending URI with embedded Bitcoin tag & ? injection rejects with ERR_INVALID_URI`, async () => {
    assert.equal(VEC_5B.length, 164);
    await assert.rejects(
      () => verifyOtsProof(VEC_5B, TARGET_SHA256, { headers: { 358391: HDR_358391 } }),
      (err) => err.code === 'ERR_INVALID_URI'
    );
  });

  test(`${label}: complete 688-byte canonical hello-world.txt.ots proof confirms against Bitcoin Mainnet Block 358,391`, async () => {
    assert.equal(HELLO_WORLD_OTS.length, 688);
    const res = await verifyOtsProof(HELLO_WORLD_OTS, HELLO_WORLD_SHA256, {
      headers: { 358391: HDR_358391 },
    });
    assert.equal(res.status, 'CONFIRMED');
    assert.equal(res.height, 358391);
    assert.equal(res.nTime, 1432827678);
    assert.equal(res.merkleRoot, '007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a');
    assert.equal(res.blockHash, '000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319');
    assert.equal(res.fileDigest, '03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340');
    const hdrInfo = await verifyBitcoinHeader(HDR_358391, unhex(res.merkleRoot));
    assert.equal(hdrInfo.nTime, 1432827678);
  });
}

test('CLI --help outputs usage cleanly', async () => {
  const res = await runCli(['--help']);
  assert.equal(res.exitCode, 0);
  assert.ok(res.output.startsWith('Usage: node scripts/ots-verifier.mjs '));
});
