import test from 'node:test';
import assert from 'node:assert/strict';
import {generateProfileKey,createSigner} from '../src/signing.js';
import {createProfile,appendPerformanceStamp,publishedFingerprint,profileKeyCode} from '../src/trackRecord.js';
import {createTransitionRequest,approveTransitionRequest} from '../src/keyContinuity.js';
import {extractReviewEvidence,inspectReviewPackage,buildEvidenceReviewPackage,buildContinuityReviewPackage,buildReviewPackage} from '../src/reviewPackage.js';
const json=JSON.stringify;
async function fixture(){
 const make=async()=>{const k=await generateProfileKey(),signer=createSigner(k.privateKey,k.publicKey);return {profile:await createProfile('Synthetic <chain> & owner',signer),signer};};
 const old=await make(),next=await make(),last=await make();
 old.profile=await appendPerformanceStamp(old.profile,'date,nav,external_flow\n2026-01-01,100,0\n2026-01-02,90,0',252,old.signer,{synthetic:true});
 const first=(await approveTransitionRequest(await createTransitionRequest(old.profile,next.profile,next.signer),old.signer)).package;
 first.profiles[1]=await appendPerformanceStamp(first.profiles[1],'date,nav,external_flow\n2026-01-02,100,0\n2026-01-03,101,0',252,next.signer,{synthetic:true});
 const second=(await approveTransitionRequest(await createTransitionRequest(first,last.profile,last.signer),next.signer)).package;
 return {old,next,last,first,second};
}
const f=await fixture();
test('legacy builder and review retain exact profile semantics and limits',async()=>{
 const html=await buildEvidenceReviewPackage(f.old.profile);
 assert.equal(html,await buildReviewPackage(json(f.old.profile)));
 assert.deepEqual((await inspectReviewPackage(html)).profile,f.old.profile);
 assert.throws(()=>extractReviewEvidence(json(f.old.profile)+' '.repeat(500001)),/500,000/);
});
test('continuity HTML round trips the entire unchanged chain with inert escaped data',async()=>{
 const html=await buildEvidenceReviewPackage(f.second);
 assert.deepEqual(JSON.parse(extractReviewEvidence(html)),f.second);
 assert.match(html,/Synthetic &lt;chain&gt; &amp; owner/);
 assert.equal((html.match(/<script/g)||[]).length,1);
 assert.match(html,/No financial metric or return chart is combined/);
 assert.match(html,/No independently retained anchor was supplied/);
 assert.equal((await inspectReviewPackage(html)).anchor_status,'not_supplied');
 assert.equal((await inspectReviewPackage(html)).profiles.length,3);
});
test('first-edge profile/checkpoint and later retained chain route to separate anchoring semantics',async()=>{
 assert.equal((await inspectReviewPackage(json(f.first),{previousProfile:await buildReviewPackage(json(f.old.profile))})).anchor_status,'matched');
 assert.equal((await inspectReviewPackage(json(f.first),{publishedFingerprints:publishedFingerprint(f.old.profile)})).anchor_status,'matched');
 assert.equal((await inspectReviewPackage(json(f.second),{previousProfile:json(f.old.profile)})).anchor_status,'partial');
 assert.equal((await inspectReviewPackage(json(f.second),{previousProfile:await buildContinuityReviewPackage(json(f.first))})).anchor_status,'matched');
});
test('expected key remains root; destination code cannot anchor the chain',async()=>{
 assert.equal((await inspectReviewPackage(json(f.first),{expectedKeyCode:profileKeyCode(f.old.profile)})).root_key_anchor_status,'matched');
 assert.equal((await inspectReviewPackage(json(f.first),{expectedKeyCode:profileKeyCode(f.next.profile)})).anchor_status,'conflict');
});
test('single-profile downgrade refuses a previously retained full chain',async()=>{
 await assert.rejects(inspectReviewPackage(json(f.first.profiles[1]),{previousProfile:json(f.first)}),/omits.*continuity chain/);
});
test('extraction rejects duplicate escaped fields, ambiguous attachment and HTML overlimit',async()=>{
 const text=json(f.first),html=await buildContinuityReviewPackage(text);
 assert.throws(()=>extractReviewEvidence(text.replace('"schema_version":','"schema\\u005fversion":"unexpected","schema_version":')),/repeat|duplicate/i);
 assert.throws(()=>extractReviewEvidence(html+html),/unique/);
 assert.throws(()=>extractReviewEvidence(html+' '.repeat(2000000)),/2 MB/);
 assert.throws(()=>extractReviewEvidence(text+' '.repeat(2600000)),/limit|large|characters/i);
});
test('request is never accepted as completion or recipient trust evidence',async()=>{
 const request=await createTransitionRequest(f.old.profile,f.next.profile,f.next.signer);
 await assert.rejects(inspectReviewPackage(json(request)));
 const ownerClaims=structuredClone(f.first);ownerClaims.recipient_accepted=true;
 await assert.rejects(inspectReviewPackage(json(ownerClaims)));
});
