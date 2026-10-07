import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import test from 'node:test';
import { appendCorrectionStamp, appendPerformanceStamp, canonicalPayload, compareProfiles, createProfile, effectiveStamps, inspectProfile, normalizeProvenance, provenanceFromImport, publishedFingerprint } from '../src/trackRecord.js';
import { appendStoredRecord } from '../src/keyStore.js';
import { buildReviewPackage, extractReviewEvidence, inspectReviewPackage } from '../src/reviewPackage.js';
import { createSigner, generateProfileKey, sha256Hex } from '../src/signing.js';
import { calculateRecordMetrics } from '../src/calculator.js';
import { importStatement } from '../src/importer.js';
import { verifyEvidence, compareEvidence } from '../scripts/verify-record.mjs';
const csv=(...rows)=>`date,nav,external_flow\n${rows.join('\n')}`;
const first=csv('2025-01-01,100,0','2025-01-02,110,0','2025-01-03,99,0');
const second=csv('2025-01-03,99,0','2025-01-04,101,0');
async function owner(){const key=await generateProfileKey();const signer=createSigner(key.privateKey,key.publicKey);return {signer,profile:await createProfile('Review example',signer)};}
const inspect=p=>inspectProfile(JSON.stringify(p));

test('corrections append exact targets and retain originals without double-counting coverage',async()=>{
  const {signer,profile}=await owner();
  const a=await appendPerformanceStamp(profile,first,252,signer);
  const b=await appendPerformanceStamp(a,second,252,signer);
  const corrected=csv('2025-01-01,100,0','2025-01-02,105,0','2025-01-03,99,0');
  const c=await appendCorrectionStamp(b,1,corrected,252,signer,{reason:'Corrected an opening-period valuation transcription.'});
  assert.deepEqual(c.stamps.slice(0,2),b.stamps);
  assert.equal(c.stamps[2].payload.previous_sha256,b.stamps[1].sha256);
  assert.equal(c.stamps[2].payload.correction.target_sha256,a.stamps[0].sha256);
  assert.deepEqual(effectiveStamps(c).map(s=>s.payload.sequence),[3,2]);
  assert.deepEqual((await inspect(c)).summary.effective_sequences,[3,2]);
  assert.equal((await inspect(c)).summary.return_observations,3);
  assert.equal((await inspect(c)).summary.last_date,'2025-01-04');
  assert.equal(verifyEvidence(JSON.stringify(c)).records,3);
  await assert.rejects(appendCorrectionStamp(c,1,first,252,signer,{reason:'Second correction of superseded original.'}),/already been corrected/);
  const d=await appendCorrectionStamp(c,3,first,252,signer,{reason:'Reinstated original values after reviewing the source.'});
  assert.deepEqual(effectiveStamps(d).map(s=>s.payload.sequence),[4,2]);
  await assert.rejects(appendCorrectionStamp(c,3,second,252,signer,{reason:'Wrong period boundary'}),/retain the original period/);
  await assert.rejects(appendCorrectionStamp(c,3,first,252,signer,{reason:''}),/Explain/);
});

test('previous-copy checks distinguish extension, truncation, key replacement and conflicting signed histories',async()=>{
  const {signer,profile}=await owner();const a=await appendPerformanceStamp(profile,first,252,signer);const b=await appendPerformanceStamp(a,second,252,signer);
  const fork=await appendPerformanceStamp(a,csv('2025-01-03,99,0','2025-01-04,110,0'),252,signer);
  const other=await owner();const replacement=await appendPerformanceStamp(other.profile,first,252,other.signer);
  for(const [previous,current,status]of[[a,b,'extended'],[b,a,'truncated'],[b,fork,'conflicting_history'],[a,a,'identical'],[a,replacement,'replacement']]){
    const p=JSON.stringify(previous),c=JSON.stringify(current);
    assert.equal((await compareProfiles(p,c)).status,status);assert.equal(compareEvidence(p,c).status,status);
    assert.equal((await inspectProfile(c,{previousProfile:p})).checks.previous_copy.status,status);
  }
  const corrupted=structuredClone(b);corrupted.stamps[0].signature='A'.repeat(86);
  await assert.rejects(compareProfiles(JSON.stringify(corrupted),JSON.stringify(a)),/signature/);
});

test('checkpoint reports exact supplied event and no publication time',async()=>{
  const {signer,profile}=await owner();const a=await appendPerformanceStamp(profile,first,252,signer);const b=await appendPerformanceStamp(a,second,252,signer);
  assert.equal((await inspect(b)).checks.checkpoint.checked,false);
  const checked=await inspectProfile(JSON.stringify(b),{publishedFingerprints:publishedFingerprint(a)});
  assert.deepEqual(checked.checks.checkpoint,{checked:true,sequence:1,end:'2025-01-03',sha256:a.stamps[0].sha256,source:'supplied_fingerprint',publication_time_established:false});
  assert.equal(checked.checks.independent_timestamp,false);assert.equal(checked.checks.identity_established,false);
});

test('v3 fixtures preserve old semantics; same key can append v4 without rewriting v3 bytes',async()=>{
  const fixture=readFileSync(new URL('../examples/example-profile.json',import.meta.url),'utf8');
  assert.equal((await inspectProfile(fixture)).profile.stamps[0].payload.metrics.annualized_volatility_e8,18375843);
  assert.equal(verifyEvidence(fixture).records,2);
  const {signer,profile}=await owner();const modern=await appendPerformanceStamp(profile,first,252,signer);
  const legacy=structuredClone(modern);legacy.schema_version='n170.verify.track-record.v3';
  const p=legacy.stamps[0].payload;p.schema_version='n170.verify.performance-stamp.v3';p.calculation_version='1.0.0';
  for(const k of ['serialization_version','event_type','correction','provenance'])delete p[k];
  p.metrics=calculateRecordMetrics(p.relative_returns.map(r=>r.return_e8),252);
  const bytes=new TextEncoder().encode(JSON.stringify(canonicalPayload(p)));legacy.stamps[0].sha256=await sha256Hex(bytes);
  const domain=new TextEncoder().encode('n170.verify.stamp-signature.v3\n');const message=new Uint8Array(domain.length+bytes.length);message.set(domain);message.set(bytes,domain.length);
  legacy.stamps[0].signature=await signer.sign(message);
  await inspect(legacy);assert.equal(verifyEvidence(JSON.stringify(legacy)).records,1);
  const extended=await appendPerformanceStamp(legacy,second,252,signer);
  assert.deepEqual(extended.stamps[0],legacy.stamps[0]);assert.equal(extended.schema_version,'n170.verify.track-record.v4');
  assert.equal((await inspect(extended)).checks.signatures_valid,true);assert.equal(verifyEvidence(JSON.stringify(extended)).records,2);
});

test('signed import provenance binds reviewed observations and rejects silent input changes',async()=>{
  const imported=await importStatement(first,{currency:'USD'});const provenance=await provenanceFromImport(imported,{accountScope:'One selected taxable account',reviewed:true});
  const {signer,profile}=await owner();const signed=await appendPerformanceStamp(profile,imported.normalizedCsv,252,signer,{provenance});
  assert.equal(signed.stamps[0].payload.provenance.original_sha256,imported.source.sha256);assert.equal(signed.stamps[0].payload.provider_authenticated,false);
  assert.equal(verifyEvidence(JSON.stringify(signed)).signatures_valid,true);
  await assert.rejects(appendPerformanceStamp(profile,second,252,signer,{provenance}),/no longer matches/);
  const altered=structuredClone(signed);altered.stamps[0].payload.provenance.account_scope='Every account';
  await assert.rejects(inspect(altered),/integrity/);
  assert.throws(()=>normalizeProvenance({...provenance,completeness:'complete'}));
});

test('review packages safely embed evidence, preserve privacy, and accept a previous HTML copy',async()=>{
  const {signer}=await owner();const profile=await createProfile('A </script><img src=x onerror=alert(1)>',signer);
  const a=await appendPerformanceStamp(profile,first,252,signer);const b=await appendPerformanceStamp(a,second,252,signer);
  const html=await buildReviewPackage(a),later=await buildReviewPackage(b);
  assert.equal(html.includes('<img src=x'),false);assert.equal(html.includes('\\u003c/script'),true);
  assert.deepEqual(JSON.parse(extractReviewEvidence(html)),a);
  assert.equal((await inspectReviewPackage(later,{previousProfile:html})).checks.previous_copy.status,'extended');
  assert.equal(verifyEvidence(html).records,1);
  assert.match(html,/identity verification/);assert.match(html,/Earlier publication has not been checked/);assert.match(html,/presentation is not signed/);
  assert.equal(html.includes('"nav":'),false);assert.equal(html.includes('"external_flow":'),false);
  assert.throws(()=>extractReviewEvidence('<h1>No attachment</h1>'),/no unique/);
  assert.throws(()=>extractReviewEvidence(html+html),/no unique/);
  await assert.rejects(inspectReviewPackage(html.replace('"return_e8":10000000','"return_e8":90000000')));
  assert.throws(()=>verifyEvidence(html.replace('"sequence":1','"sequence":1,"sequence":1')),/Duplicate/);
});

test('independent v2 verifier reproduces eligible volatility and rejects changed fields',async()=>{
  const rows=[];for(let i=0;i<=25;i++)rows.push(`${new Date(Date.UTC(2025,0,1+i)).toISOString().slice(0,10)},${100+i*(i%3+1)},0`);
  const {signer,profile}=await owner();const signed=await appendPerformanceStamp(profile,csv(...rows),365,signer);
  assert.ok(signed.stamps[0].payload.metrics.annualized_volatility_e8>0);assert.equal(verifyEvidence(JSON.stringify(signed)).records,1);
  for(const change of [p=>p.stamps[0].payload.metrics.total_return_twr_e8++,p=>p.stamps[0].payload.provider_authenticated=true,p=>p.stamps[0].payload.provenance.unchecked='extra',p=>p.public_key='A'.repeat(87)]){
    const changed=structuredClone(signed);change(changed);assert.throws(()=>verifyEvidence(JSON.stringify(changed)));
  }
});


test('published v4 fixture and command-line exit codes are reproducible',async()=>{
  const path=new URL('../examples/review-profile-v4.html',import.meta.url);
  const html=readFileSync(path,'utf8');assert.equal(verifyEvidence(html).records,2);
  const app=await inspectReviewPackage(html);assert.equal(app.summary.correction_count,1);
  const script=new URL('../scripts/verify-record.mjs',import.meta.url);
  const output=JSON.parse(execFileSync(process.execPath,[script.pathname,path.pathname],{encoding:'utf8'}));
  assert.equal(output.arithmetic_valid,true);assert.equal(output.earlier_publication_checked,false);
  const legacy=new URL('../examples/example-profile.json',import.meta.url);
  const replaced=spawnSync(process.execPath,[script.pathname,path.pathname,legacy.pathname],{encoding:'utf8'});
  assert.equal(replaced.status,2);assert.equal(JSON.parse(replaced.stdout).previous_copy.status,'replacement');
});


test('stored append rejects tampered preserved records before opening IndexedDB',async()=>{
  const {signer,profile}=await owner();const a=await appendPerformanceStamp(profile,first,252,signer);const b=await appendPerformanceStamp(a,second,252,signer);
  b.stamps[0].payload.coverage.external_cash_flow_count=1;
  await assert.rejects(appendStoredRecord(b),/integrity/);
});

test('explicit synthetic provenance remains synthetic for an imported demonstration series',async()=>{
  const {signer,profile}=await owner();const p=await appendPerformanceStamp(profile,first,252,signer,{synthetic:true});
  assert.equal(p.stamps[0].payload.source_kind,'synthetic_demo');await inspect(p);assert.equal(verifyEvidence(JSON.stringify(p)).source_authenticated,false);
});
