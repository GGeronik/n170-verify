import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { importStatement } from '../src/importer.js';
import { parseAgentHandoff } from '../src/agentHandoff.js';
import { createEmptyDraft, hydratePrivateDraft } from '../src/draftModel.js';
import { createProfile, appendPerformanceStamp, provenanceFromImport, inspectProfile } from '../src/trackRecord.js';
import { createSigner, generateProfileKey } from '../src/signing.js';
import { buildReviewPackage } from '../src/reviewPackage.js';
const packet = () => JSON.parse(readFileSync(new URL('../examples/agent-handoff-synthetic.json', import.meta.url), 'utf8'));
const options = p => ({currency:p.currency,frequency:p.frequency,flowTimingConfirmed:true});
const envelope = data => ({kind:'n170.private-draft.v1',data});
const sha = text => createHash('sha256').update(text).digest('hex');

test('assistant handoff requires owner review and cannot grant it through JSON', async () => {
 const p=packet(); const text=JSON.stringify(p);
 const pending=await importStatement(text,{currency:p.currency,frequency:p.frequency});
 assert.equal(pending.canCalculate,false);assert(pending.exceptions.some(e=>e.code==='owner_review_required'));
 const ready=await importStatement(text,options(p)); assert.equal(ready.canCalculate,true);assert.equal(ready.source.authenticated,false);
 assert.equal(ready.format,'agent-handoff');assert.equal(ready.source.sha256,sha(text));
 await assert.rejects(parseAgentHandoff(JSON.stringify({...p,owner_reviewed:true})));
});

test('owner review cannot override unknown acquisition coverage or missing requested dates',async()=>{
 const p=packet();p.coverage.pagination='unknown';
 const blocked=await importStatement(JSON.stringify(p),options(p));assert.equal(blocked.canCalculate,false);
 const q=packet();q.observations.pop();
 const incomplete=await importStatement(JSON.stringify(q),options(q));assert.equal(incomplete.canCalculate,false);
});

test('handoff currency and frequency cannot silently diverge from draft settings',async()=>{
 const p=packet(),text=JSON.stringify(p);
 await assert.rejects(importStatement(text,{...options(p),currency:p.currency==='USD'?'EUR':'USD'}),/currency/);
 await assert.rejects(importStatement(text,{...options(p),frequency:p.frequency===252?365:252}),/frequency/);
});

test('handoff private draft is revalidated, retains paste text and cannot erase synthetic label',async()=>{
 const p=packet();p.synthetic=true;const text=JSON.stringify(p);
 const ready=await importStatement(text,options(p));
 const data={...createEmptyDraft(),format:'agent-handoff',original:text,input:ready.normalizedCsv,currency:p.currency,frequency:String(p.frequency),scope:p.account_scope,synthetic:false,flowTimingConfirmed:true,handoffText:'Unfinished next handoff',importReview:{canCalculate:true,source:{authenticated:true}}};
 const result=await hydratePrivateDraft(envelope(data));assert.equal(result.importReview.canCalculate,true);assert.equal(result.synthetic,true);assert.equal(result.handoffText,'Unfinished next handoff');assert.equal(result.importReview.source.authenticated,false);
 const blocked=await hydratePrivateDraft(envelope({...data,flowTimingConfirmed:false}));assert.equal(blocked.importReview.canCalculate,false);
 const noRows=await hydratePrivateDraft(envelope({...data,input:''}));assert.equal(noRows.importReview.canCalculate,false);
});

test('agent metadata stays private while complete handoff digest and canonical returns are signed',async()=>{
 const p=packet();p.source.connector='PrivateConnectorSentinel';p.mapping.nav='privateToolResponse.accountEquity';p.observations[0].source_ref='PrivateSourceRefSentinel';
 const text=JSON.stringify(p),review=await importStatement(text,options(p));
 const key=await generateProfileKey();const signer=createSigner(key.privateKey,key.publicKey);const profile=await createProfile('Synthetic agent handoff',signer);
 const signed=await appendPerformanceStamp(profile,review.normalizedCsv,p.frequency,signer,{provenance:provenanceFromImport(review,{accountScope:p.account_scope,reviewed:true}),synthetic:p.synthetic});
 const checked=await inspectProfile(JSON.stringify(signed));assert.equal(checked.checks.arithmetic_valid,true);assert.equal(checked.checks.signatures_valid,true);
 assert.equal(signed.stamps[0].payload.provenance.original_sha256,sha(text));
 const exported=JSON.stringify(signed);for(const sensitive of ['PrivateConnectorSentinel','privateToolResponse.accountEquity','PrivateSourceRefSentinel'])assert.equal(exported.includes(sensitive),false);
 const html=await buildReviewPackage(signed);assert.match(html,/Assistant-prepared handoff/);assert.match(html,/authenticity not established/);
});
