// Fixture integrity tests; no headline or witness product implementation.
// This test does not read or import the private headline oracle.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify } from 'node:crypto';
const root=new URL('../',import.meta.url);
const read=path=>readFileSync(new URL(path,root));
const json=path=>JSON.parse(read(path));
const hash=data=>createHash('sha256').update(data).digest('hex');
test('headline and witness manifest members retain their sealed lengths and digests',()=>{
 const receipts=json('tests/fixtures/witness/receipt-cases.json');
 for(const id of ['W-DUP','W-ESC-DUP','W-UTF8']){const row=receipts.find(r=>r.id===id);assert.equal(row.input,`tests/fixtures/witness/${id}.receipt.raw`);assert.equal(row.expected.result,'WITNESS_RECEIPT_INVALID');}
 for(const kind of ['headline','witness']) {
  const manifest=json(`tests/fixtures/${kind}/MANIFEST.json`);
  assert.equal(manifest.schema,'n170.verify.fixture-manifest.v1');
  assert.deepEqual(manifest.files.map(f=>f.path),manifest.files.map(f=>f.path).toSorted());
  for(const file of manifest.files){const data=read(file.path);assert.equal(data.length,file.bytes,file.path);assert.equal(hash(data),file.sha256,file.path);}
 }
});
test('exhaustive enum vectors and context controls cover the fifteen closed headlines',()=>{
 const exhaustive=json('tests/fixtures/headline/facts-exhaustive.json'), contexts=json('tests/fixtures/headline/facts-context.json');
 assert.equal(exhaustive.length,7200);
 assert.equal(new Set(exhaustive.map(x=>JSON.stringify(x.facts))).size,7200);
 const allowed=new Set(['REJECTED: INVALID_INPUT','REJECTED: PAYLOAD_HASH_MISMATCH','REJECTED: SIGNATURE_INVALID','REJECTED: CHAIN_BROKEN','REJECTED: FACTS_INCOMPLETE','REJECTED: PRIVATE_SOURCE_MISMATCH','REJECTED: WITNESS_MISMATCH','REJECTED: WITNESS_RECEIPT_INVALID','CONFLICT: TRUNCATION','CONFLICT: REPLACEMENT','CONFLICT: CONFLICTING_HISTORY','CONFLICT: CONTINUITY_CONFLICT','WITNESSED RECORD','SOURCE-RECONCILED RECORD · under owner assertions','SELF-REPORTED RECORD · arithmetic and signatures verified']);
 const seen=new Set();for(const row of [...exhaustive,...contexts]){assert.ok(allowed.has(row.expected.headline));assert.ok(!/^verified/i.test(row.expected.headline));seen.add(row.expected.headline);}
 assert.deepEqual(seen,allowed);
 for(const row of contexts){assert.equal(row.expected.ladder.length,6);if(row.expected.exit)assert.deepEqual(row.expected.qualifications,[]);}
});
function publicKey(text){const b=Buffer.from(text,'base64url');return createPublicKey({key:{kty:'EC',crv:'P-256',x:b.subarray(1,33).toString('base64url'),y:b.subarray(33).toString('base64url')},format:'jwk'});}
function signature(receipt){return verify('sha256',Buffer.concat([Buffer.from('n170.verify.witness-receipt-signature.v1\n'),Buffer.from(JSON.stringify(receipt.payload))]),{key:publicKey(receipt.payload.witness_public_key),dsaEncoding:'ieee-p1363'},Buffer.from(receipt.signature,'base64url'));}
test('public receipt controls establish valid signatures, both forgeries and high-s identity',()=>{
 const ok=json('tests/fixtures/witness/W-OK.receipt.json'),high=json('tests/fixtures/witness/W-HIGHS.receipt.json'),own=json('tests/fixtures/witness/F13a.receipt.json'),transplanted=json('tests/fixtures/witness/F13b.receipt.json');
 assert.ok(signature(ok));assert.ok(signature(high));assert.equal(ok.sha256,high.sha256);assert.ok(signature(own));assert.ok(!signature(transplanted));
 const raw=Buffer.from(own.payload.witness_public_key,'base64url');assert.notEqual(hash(Buffer.concat([Buffer.from('n170.verify.witness-key.v1\n'),raw])),own.payload.witness_key_id);
 assert.equal(transplanted.payload.witness_public_key,ok.payload.witness_public_key);
 const n=BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');assert.ok(BigInt('0x'+Buffer.from(high.signature,'base64url').subarray(32).toString('hex'))>n/2n);
});
