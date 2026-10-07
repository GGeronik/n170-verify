import test from 'node:test';
import assert from 'node:assert/strict';
import { importStatement, importDisclosure, correctImport, ibkrSampleInput } from '../src/importer.js';
const secret = 'PRIVATE_SENTINEL_987654';
const options = {currency:'USD',flowTimingConfirmed:true};
const good = () => importStatement(ibkrSampleInput,options);

test('raw-value error reproduction remains private while its public issue stays useful', async () => {
  const review = await importStatement(`date,nav,external_flow\n2025-01-01,100,0\n${secret},110,0`);
  assert(JSON.stringify(review.exceptions).includes(secret));
  const result = importDisclosure(review);
  assert.equal(JSON.stringify(result).includes(secret),false); assert.equal(result.raw_values_included,false); assert.equal(result.free_text_included,false);
  assert.equal(result.status,'blocked'); assert(result.exceptions.some(item=>item.code==='invalid_observation'));
});

test('unknown source column names cannot escape through public exception messages', async () => {
  const source = ibkrSampleInput.split('\n').map((line,index)=>line + ',' + (index===0 ? secret : '0')).join('\n');
  const review = await importStatement(source,options);
  assert(review.exceptions.some(item=>item.code==='unknown_columns'&&item.message.includes(secret)));
  assert.equal(JSON.stringify(importDisclosure(review)).includes(secret),false);
});

test('legitimate summary keeps validated digests, counts and review status without private scope or dates', async () => {
  const review = await good(); const result = importDisclosure(review);
  assert.equal(result.disclosure_version,'n170.import-disclosure.v2'); assert.equal(result.importer_version,'n170.import.v1');
  assert.equal(result.source_sha256,review.source.sha256); assert.equal(result.original_source_sha256,review.source.sha256); assert.equal(result.normalized_sha256,review.review.normalized_sha256);
  assert.equal(result.status,'ready_for_owner_review'); assert.equal(result.owner_review_required,true); assert.equal(result.source_authenticated,false);
  assert.deepEqual(result.coverage,{source_rows:3,observations:4,completeness:'not_established'});
  assert.equal(result.currency,'USD'); assert.equal(result.format,'ibkr-flex'); assert.equal(result.correction_count,0);
  for (const value of ['SYNTHETIC','10200','2025-01-02','source_ref','file_name','mapping']) assert.equal(JSON.stringify(result).includes(value),false);
});

test('arbitrary metadata never passes through format, coverage, corrections or source fields', async () => {
  const review = await good();
  review.version=secret;review.format=secret;review.currency=secret;review.mapping=[{source:secret,target:secret}];
  review.coverage={source_rows:secret,observations:secret,start:secret,end:secret,accounts:secret,extra:secret};
  review.source={sha256:secret,file_name:secret,authenticated:true};review.original_source_sha256=secret;
  review.review={normalized_sha256:secret,flow_timing:secret};
  review.corrections=[{sequence:secret,reason:secret,changed_at:secret,time_evidence:secret,previous_source_sha256:secret,replacement_source_sha256:secret,previous_normalized_sha256:secret,replacement_normalized_sha256:secret,raw:secret}];
  review.exceptions=[{code:secret,severity:secret,message:secret,action:secret,path:secret}];
  const result=importDisclosure(review);
  assert.equal(JSON.stringify(result).includes(secret),false);assert.equal(result.format,'unknown');assert.equal(result.importer_version,'unknown');assert.equal(result.currency,'unspecified');
  assert.equal(result.source_sha256,null);assert.equal(result.original_source_sha256,null);assert.equal(result.normalized_sha256,null);
  assert.deepEqual(result.coverage,{source_rows:null,observations:null,completeness:'not_established'});assert.equal(result.status,'blocked');
});

test('real source correction retains only digest continuity and count, never the owner explanation', async () => {
  const original=await good();
  const corrected=await correctImport(original,ibkrSampleInput.replace('10000,10100','10000,10101'),secret,options);
  const result=importDisclosure(corrected);
  assert.equal(result.correction_count,1);assert.equal(result.corrections[0].sequence,1);
  assert.equal(result.corrections[0].previous_source_sha256,original.source.sha256);
  assert.equal(result.corrections[0].replacement_source_sha256,corrected.source.sha256);
  assert.equal(result.original_source_sha256,original.source.sha256);assert.equal(JSON.stringify(result).includes(secret),false);
  assert.deepEqual(Object.keys(result.corrections[0]),['sequence','previous_source_sha256','replacement_source_sha256','previous_normalized_sha256','replacement_normalized_sha256']);
});

test('counts and digests are bounded primitive values, never coercions or arbitrary serializable objects', async () => {
  const review=await good();let called=false;
  const hostile={toJSON(){called=true;return secret;}};
  review.source.sha256=hostile;review.review.normalized_sha256='A'.repeat(64);
  review.coverage={source_rows:Infinity,observations:501};
  const result=importDisclosure(review);JSON.stringify(result);
  assert.equal(called,false);assert.equal(result.source_sha256,null);assert.equal(result.normalized_sha256,null);assert.equal(result.coverage.source_rows,null);assert.equal(result.coverage.observations,null);
  review.coverage={source_rows:'3',observations:-1};const next=importDisclosure(review);assert.equal(next.coverage.source_rows,null);assert.equal(next.coverage.observations,null);
});

test('malformed input and excessive correction arrays cannot become a successful public review', async () => {
  for(const input of [null,undefined,{},secret]) {const result=importDisclosure(input);assert.equal(result.status,'blocked');assert(result.exceptions.some(item=>item.code==='needs_review'));assert.equal(JSON.stringify(result).includes(secret),false);}
  const review=await good();review.corrections=new Array(101).fill({reason:secret});
  const result=importDisclosure(review);assert.equal(result.status,'blocked');assert.equal(result.correction_count,null);assert.deepEqual(result.corrections,[]);
  assert(result.exceptions.some(item=>item.code==='needs_review'));assert.equal(JSON.stringify(result).includes(secret),false);
});

test('private detailed review is untouched when a public summary is generated', async () => {
  const review=await good();const before=JSON.stringify(review);const result=importDisclosure(review);
  result.coverage.source_rows=0;result.exceptions[0].message=secret;
  assert.equal(JSON.stringify(review),before);
});
