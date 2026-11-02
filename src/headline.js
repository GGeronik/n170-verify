// Display decisions consume verifier facts only. This module never reads claims.
import * as recordMessages from './trackRecord.js';
import { inspectReviewPackage } from './reviewPackage.js';
import { verifyWitnessReceipt } from './witnessReceipt.js';
import { verifyOtsProof } from './otsVerifier.js';
import { verifyTlogProofBundle } from './tlogVerifier.js';

const enums = {
  parse:['OK','INVALID_INPUT'], payload_hash:['MATCH','MISMATCH'], signatures:['VALID','INVALID'], chain:['VALID','BROKEN'],
  continuity:['NONE','VALID','CONFLICT'], comparison:['NONE','IDENTICAL','EXTENDED','TRUNCATION','REPLACEMENT','CONFLICT'],
  reconciliation:['NONE','VERIFIED_UNDER_OWNER_ASSERTIONS','MISMATCH','NOT_ASSESSABLE','INVALID_INPUT'],
  witness:['NONE','WITNESSED','WITNESS_MISMATCH','WITNESS_NOT_ASSESSABLE','WITNESS_RECEIPT_INVALID'],
};
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value, names) => object(value) && Object.keys(value).length === names.length && names.every(k=>Object.hasOwn(value,k));
const date = s => typeof s==='string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && Number.isFinite(Date.parse(s)) && new Date(s).toISOString().slice(0,10)===s;
const range = (v,a,b) => keys(v,[a,b]) && date(v[a]) && date(v[b]) && v[a]<v[b];
const identifiers = a => Array.isArray(a) && a.every(s=>typeof s==='string' && /^[A-Z][A-Z0-9_]{0,79}$/.test(s));
export function emptyHeadlineContext() {
  return {record_reasons:[], selected_event:null, witness_host:null, witness_key_code:null, other_effective_slots:0, selected_event_superseded:false,
    continuity_anchor:null, reconciliation_reasons:[], witness_reasons:[], timestamp_proof:'NONE', expected_key:'not_supplied', checkpoint_checked:false, gaps:[]};
}
function validContext(c) {
  return keys(c,Object.keys(emptyHeadlineContext())) && identifiers(c.record_reasons) && identifiers(c.reconciliation_reasons) && identifiers(c.witness_reasons)
    && (c.selected_event===null || (keys(c.selected_event,['sequence','start','end']) && Number.isSafeInteger(c.selected_event.sequence) && c.selected_event.sequence>0 && date(c.selected_event.start) && date(c.selected_event.end) && c.selected_event.start<c.selected_event.end))
    && (c.witness_host===null || typeof c.witness_host==='string') && (c.witness_key_code===null || typeof c.witness_key_code==='string')
    && Number.isSafeInteger(c.other_effective_slots) && c.other_effective_slots>=0 && typeof c.selected_event_superseded==='boolean'
    && [null,'matched','partial','not_supplied'].includes(c.continuity_anchor) && ['NONE','PENDING','CONFIRMED','INVALID'].includes(c.timestamp_proof)
    && ['matched','not_supplied'].includes(c.expected_key) && typeof c.checkpoint_checked==='boolean' && Array.isArray(c.gaps) && c.gaps.every(g=>range(g,'start','end'));
}
function freeze(value) { if(object(value)||Array.isArray(value)){Object.values(value).forEach(freeze);Object.freeze(value);}return value; }
export function deriveHeadline(facts, context) {
  const f=object(facts)?facts:{}, c=validContext(context)?structuredClone(context):emptyHeadlineContext();
  const early=[['parse','INVALID_INPUT','INVALID_INPUT'],['payload_hash','MISMATCH','PAYLOAD_HASH_MISMATCH'],['signatures','INVALID','SIGNATURE_INVALID'],['chain','BROKEN','CHAIN_BROKEN']].find(([k,v])=>f[k]===v);
  let code=early?.[2]??null, exit=code?1:0, headline=null, sublabel=null;
  if(!code && (!keys(f,Object.keys(enums)) || Object.entries(enums).some(([k,allowed])=>!allowed.includes(f[k])) || !validContext(context))){code='FACTS_INCOMPLETE';exit=1;}
  if(!code){
    code={TRUNCATION:'TRUNCATION',REPLACEMENT:'REPLACEMENT',CONFLICT:'CONFLICTING_HISTORY'}[f.comparison]??(f.continuity==='CONFLICT'?'CONTINUITY_CONFLICT':null);
    if(code)exit=2;
  }
  if(!code){
    code=f.reconciliation==='MISMATCH'?'PRIVATE_SOURCE_MISMATCH':f.witness==='WITNESS_MISMATCH'?'WITNESS_MISMATCH':f.witness==='WITNESS_RECEIPT_INVALID'?'WITNESS_RECEIPT_INVALID':null;
    if(code)exit=1;
  }
  if(code)headline=`${exit===2?'CONFLICT':'REJECTED'}: ${code}`;
  else if(f.witness==='WITNESSED'){
    headline='WITNESSED RECORD';const e=c.selected_event;
    sublabel=`Record ${e?.sequence??'?'} (${e?.start??'?'} – ${e?.end??'?'}) fetched from ${c.witness_host}; witness key ${c.witness_key_code}.`;
  }else if(f.reconciliation==='VERIFIED_UNDER_OWNER_ASSERTIONS'){
    headline='SOURCE-RECONCILED RECORD · under owner assertions';sublabel='owner-supplied source bytes matched the signed event; the source is not authenticated';
  }else headline='SELF-REPORTED RECORD · arithmetic and signatures verified';
  const qualifications=[];
  const qualify=(id,text,reasons=[])=>qualifications.push({code:id,reasons:[...reasons],text:`${id}: ${text}`});
  if(!exit){
    if(f.witness==='WITNESSED' && c.other_effective_slots>0)qualify('OTHER_PERIODS_NOT_WITNESSED',`${c.other_effective_slots} other effective periods in this record are not witnessed.`);
    if(f.witness!=='WITNESSED' && f.reconciliation==='VERIFIED_UNDER_OWNER_ASSERTIONS' && c.other_effective_slots>0)qualify('OTHER_PERIODS_NOT_RECONCILED',`${c.other_effective_slots} other effective periods in this record are not source-reconciled.`);
    if(f.witness==='WITNESS_NOT_ASSESSABLE')qualify('WITNESS_NOT_ASSESSABLE','The supplied witness receipt could not establish the source.',c.witness_reasons);
    if(f.reconciliation==='NOT_ASSESSABLE')qualify('PRIVATE_SOURCE_NOT_ASSESSABLE','The supplied private-source check could not assess the selected event.',c.reconciliation_reasons);
    if(f.reconciliation==='INVALID_INPUT')qualify('PRIVATE_SOURCE_INPUT_INVALID','The supplied private-source input was invalid and was not used.',c.reconciliation_reasons);
    if(c.continuity_anchor==='partial')qualify('CONTINUITY_ANCHOR_PARTIAL','Key linkage is valid; retained history anchors only part of the chain.');
    if(c.continuity_anchor==='not_supplied')qualify('CONTINUITY_ANCHOR_NOT_SUPPLIED','Key linkage is valid; no retained history anchor was supplied.');
  }
  const history=early?'Not established':`${f.continuity==='NONE'?'Valid for this key':'Valid across the supplied key chain'} · ${exit===2?'conflicts with your retained copy':f.comparison==='IDENTICAL'?'same as your retained copy':f.comparison==='EXTENDED'?'extends your retained copy':f.comparison==='NONE'?'no retained copy checked':''}`.replace(/ · $/,'');
  const ladder=[
    {row:'Calculations',text:early?(c.record_reasons.includes('ARITHMETIC_NOT_REPRODUCED')?'Not reproduced':'Not established'):'Reproduced from disclosed returns'},
    {row:'Signatures and history',text:history},
    {row:'Source',text:headline==='WITNESSED RECORD'?`Fetched by the witness from ${c.witness_host}; broker responses are not signed`:headline.startsWith('SOURCE-RECONCILED')?'Owner-supplied source bytes matched the signed event; the source is not authenticated':'Self-reported · not authenticated'},
    {row:'Key',text:c.expected_key==='matched'?'Expected key matches; identity unchecked':'Not established'},
    {row:'Time',text:c.timestamp_proof==='PENDING'?'Receipt timestamp proof binds the receipt; confirmation not verified':c.timestamp_proof==='INVALID'?'Supplied timestamp proof does not bind the receipt':'No independent evidence'},
    {row:'Coverage',text:'Supplied observations for the declared account only; lifetime inception unverified'+(c.gaps.length?` · ${c.gaps.length} gap(s) between disclosed periods`:'')},
  ];
  return freeze({version:'n170.verify.headline.v1',headline,code,exit,sublabel,qualifications,ladder});
}

const comparisonMap={not_supplied:'NONE',identical:'IDENTICAL',extended:'EXTENDED',truncated:'TRUNCATION',replacement:'REPLACEMENT',conflicting_history:'CONFLICT'};
export const TRACK_RECORD_CLASSIFICATION=Object.freeze({INVALID:'parse',REPEATED_FIELD:'parse',SIZE:'parse',OPTIONS:'parse',KEY_CODE_FORMAT:'parse',COMMITMENT_SIZE:'parse',METRICS:'parse',ORDER:'chain',HASH:'payload_hash',KEY:'signatures',SIGNATURE:'signatures',KEY_CODE_MISMATCH:'comparison',NO_KEY:'parse'});
export const CONTINUITY_CLASSIFICATION=Object.freeze({transition_signature:'signatures',transition_hash:'payload_hash',transition_history:'chain',transition_checkpoint:'chain',transition_overlap:'chain',same_key_transition:'chain',continuity_loop:'chain',continuity_schema:'parse',continuity_count:'parse',continuity_size:'parse',continuity_depth:'parse',invalid_number:'parse',duplicate_field:'parse',new:'parse',invalid_continuity:'parse'});
const failFact={parse:'INVALID_INPUT',payload_hash:'MISMATCH',signatures:'INVALID',chain:'BROKEN'};
const extractionMessages=new Set(['Choose a supported signed JSON or review HTML file.','Use a profile of at most 500,000 characters.','Use a review package smaller than 2 MB. Export a large continuity chain as JSON.','This file has no unique N170 evidence attachment. Choose an exported review HTML or profile JSON file.','The evidence attachment is incomplete. Ask for another copy.','The attached profile exceeds the supported size.']);
export function factsFromInspection(outcome, inputs={}) {
  const context=emptyHeadlineContext();
  const facts={continuity:'NONE',comparison:'NONE',reconciliation:'NONE',witness:'NONE'};
  if(outcome instanceof Error){
    const entry=Object.entries(TRACK_RECORD_CLASSIFICATION).find(([name])=>recordMessages[name]===outcome.message);
    const reference=entry?.[0]==='KEY_CODE_MISMATCH'?'REPLACEMENT':/^The published fingerprint on line [1-9][0-9]* belongs to a different key\.$/.test(outcome.message)?'REPLACEMENT':/^This profile has fewer records than a published fingerprint \(record [1-9][0-9]*\): later records were removed\.$/.test(outcome.message)?'TRUNCATION':/^Record [1-9][0-9]* does not match the supplied fingerprint\. Its publication date has not been established\.$/.test(outcome.message)?'CONFLICT':null;
    if(reference)Object.assign(facts,{parse:'OK',payload_hash:'MATCH',signatures:'VALID',chain:'VALID',comparison:reference});
    else {
      const field=entry?.[1]??CONTINUITY_CLASSIFICATION[outcome.code]??'parse';
      if(entry || CONTINUITY_CLASSIFICATION[outcome.code] || extractionMessages.has(outcome.message))Object.assign(facts,{parse:'OK',payload_hash:'MATCH',signatures:'VALID',chain:'VALID'});
      facts[field]=failFact[field];
      if(entry?.[0]==='METRICS')context.record_reasons=['ARITHMETIC_NOT_REPRODUCED'];
      else if(!entry && !CONTINUITY_CLASSIFICATION[outcome.code] && !extractionMessages.has(outcome.message))context.record_reasons=['UNCLASSIFIED_VERIFIER_FAILURE'];
    }
  }else if(object(outcome)){
    Object.assign(facts,{parse:'OK',payload_hash:'MATCH',signatures:'VALID',chain:'VALID'});
    if(outcome.package){facts.continuity=outcome.anchor_status==='conflict'?'CONFLICT':'VALID';context.continuity_anchor=outcome.anchor_status==='conflict'?null:outcome.anchor_status;context.gaps=(outcome.gaps??[]).map(({start,end})=>({start,end}));}
    else{facts.comparison=comparisonMap[outcome.checks?.previous_copy?.status];context.gaps=(outcome.summary?.gaps??[]).map(({start,end})=>({start,end}));}
    context.expected_key=outcome.checks?.key_code==='matched'?'matched':'not_supplied';context.checkpoint_checked=outcome.checks?.checkpoint?.checked===true;
    if(inputs.witness){facts.witness=inputs.witness.result;context.witness_reasons=[...inputs.witness.reasons];context.timestamp_proof=inputs.witness.timestamp_proof.status;}
    if(inputs.selectedEvent){
      const stamp=inputs.selectedEvent,p=stamp.payload;context.selected_event={sequence:p.sequence,start:p.period.start,end:p.period.end};
      const inspection=outcome.package?outcome.profileInspections.find(i=>i.profile.stamps.some(s=>s.sha256===stamp.sha256)):outcome;
      context.selected_event_superseded=!inspection.summary.effective_sequences.includes(p.sequence);
      context.other_effective_slots=(outcome.package?outcome.profileInspections.reduce((sum,i)=>sum+i.summary.effective_sequences.length,0):inspection.summary.effective_sequences.length)-1;
      if(context.selected_event_superseded && facts.witness==='WITNESSED'){facts.witness='WITNESS_NOT_ASSESSABLE';context.witness_reasons.push('SELECTED_EVENT_SUPERSEDED');}
    }
    if(facts.witness==='WITNESSED'){context.witness_host=inputs.witness.endpoint_host;context.witness_key_code=inputs.witness.witness_key_code;}
  }else {facts.parse='INVALID_INPUT';context.record_reasons=['UNCLASSIFIED_VERIFIER_FAILURE'];}
  return {facts,context};
}
export async function inspectHeadline(text, inputs={}) {
  let outcome;
  const recordOptions={expectedKeyCode:inputs.expectedKeyCode??'',publishedFingerprints:inputs.publishedFingerprints??'',previousProfile:inputs.previousProfile??''};
  try {outcome=await inspectReviewPackage(text,recordOptions);}catch(error){
    if(error.message==='The received single profile omits the previously retained continuity chain. Ask for the complete continuity package and retain both copies.'){
      try{outcome=await inspectReviewPackage(text,{...recordOptions,previousProfile:''});const mapped=factsFromInspection(outcome);mapped.facts.comparison='TRUNCATION';return {...mapped,headline:deriveHeadline(mapped.facts,mapped.context),inspection:outcome,error};}catch(cause){outcome=cause;}
    }else outcome=error;
  }
  let witness,selectedEvent,tlog;
  if(!(outcome instanceof Error) && inputs.receiptBytes!==undefined){
    const profiles=outcome.package?outcome.package.profiles:[outcome.profile];
    selectedEvent=profiles.flatMap(p=>p.stamps).find(s=>s.sha256===inputs.eventSha256);
    witness=await verifyWitnessReceipt(inputs.receiptBytes,{recordPayloadHash:selectedEvent?.sha256,trustedWitnessKeys:inputs.trustedWitnessKeys,allowedBrokerHosts:inputs.allowedBrokerHosts,...(inputs.otsProofBytes===undefined?{}:{otsProofBytes:inputs.otsProofBytes})});
    if(!selectedEvent)witness={...witness,result:'WITNESS_RECEIPT_INVALID',reasons:['EVENT_HASH_UNBOUND']};
    if(inputs.otsProofBytes!==undefined && inputs.bitcoinHeader!==undefined && inputs.bitcoinHeader!=='' && witness.receipt_sha256){
      try {
        const ots=await verifyOtsProof(inputs.otsProofBytes,witness.receipt_sha256,{header:inputs.bitcoinHeader});
        if(ots.status==='CONFIRMED'){
          const utc=new Date(ots.nTime*1000).toISOString().replace('.000Z','Z');
          witness={...witness,timestamp_proof:{status:'CONFIRMED',reasons:[],height:ots.height,nTime:ots.nTime,utc,merkleRoot:ots.merkleRoot,blockHash:ots.blockHash}};
        }else{
          witness={...witness,timestamp_proof:{status:'PENDING',reasons:['TIMESTAMP_CONFIRMATION_NOT_VERIFIED']}};
        }
      }catch(otsErr){
        witness={...witness,timestamp_proof:{status:'INVALID',reasons:[otsErr.code||'TIMESTAMP_PROOF_MALFORMED']}};
      }
    }
  }
  const mapped=factsFromInspection(outcome,{witness,selectedEvent});
  if(!(outcome instanceof Error) && inputs.tlogProof!==undefined && inputs.tlogProof!==''){
    tlog=await verifyTlogProofBundle(inputs.tlogProof,inputs.tlogPolicy,inputs.tlogReceipt||null);
    if(tlog.ok && inputs.requireRecordEventMatch){
      const stamps=outcome.package?outcome.package.profiles.flatMap(p=>p.stamps):(outcome.profile?.stamps??[]);
      if(!stamps.some(s=>s.sha256===tlog.eventSha256Hex)){
        tlog={ok:false,conflict:false,errors:['tlog event_sha256 does not match any stamp in the inspected record'],warnings:tlog.warnings};
      }
    }
    if(!tlog.ok){
      if(tlog.conflict){
        mapped.facts.comparison='CONFLICT';
      }else{
        mapped.facts.parse='INVALID_INPUT';
        mapped.context.record_reasons=['TLOG_PROOF_INVALID'];
      }
    }
  }
  let headline=deriveHeadline(mapped.facts,mapped.context);
  if(witness?.timestamp_proof?.status==='CONFIRMED' && witness.timestamp_proof.height!==undefined){
    headline=freeze({
      ...headline,
      ladder:headline.ladder.map(r=>r.row==='Time'?{row:'Time',text:`CONFIRMED · Bitcoin block ${witness.timestamp_proof.height} (${witness.timestamp_proof.utc})`}:{...r}),
    });
  }
  return {...mapped,headline,inspection:outcome instanceof Error?null:outcome,error:outcome instanceof Error?outcome:null,witness,...(tlog?{tlog}:{})};
}
