#!/usr/bin/env node
// Standalone adapters keep the original verifier output and status vocabularies.
import { lstatSync, readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { verifyEvidence, compareEvidence } from './verify-record.mjs';
import { verifyContinuity } from './verify-continuity.mjs';
import { verifyReconciliation } from './verify-reconciliation.mjs';
import { verifyWitnessReceipt } from './verify-witness-receipt.mjs';
import { deriveHeadline, emptyHeadlineContext } from './headline.mjs';

const recordValid=()=>({parse:'OK',payload_hash:'MATCH',signatures:'VALID',chain:'VALID',continuity:'NONE',comparison:'NONE',reconciliation:'NONE',witness:'NONE'});
const statusMap={identical:'IDENTICAL',extended:'EXTENDED',truncated:'TRUNCATION',replacement:'REPLACEMENT',conflicting_history:'CONFLICT'};
export const MESSAGE_CLASSIFICATION=Object.freeze({
 'Payload hash mismatch':'payload_hash','Transition payload hash mismatch':'payload_hash',
 'Signature mismatch':'signatures','Key ID mismatch':'signatures','old transition signature mismatch':'signatures','new transition signature mismatch':'signatures',
 'Record chain mismatch':'chain','Invalid correction':'chain','Overlapping periods':'chain','Transition must commit to the complete supplied old head':'chain','Previous transition digest mismatch':'chain','New performance overlaps the effective old performance period':'chain','Same-key transition is unsupported':'chain','Invalid old checkpoint':'chain',
 'Metric mismatch':'arithmetic',
 'Invalid or unsupported evidence':'parse','File exceeds 2 MB':'parse','Missing or ambiguous evidence attachment':'parse','Incomplete evidence attachment':'parse','Evidence exceeds 500,000 characters':'parse','Excessive nesting':'parse','Duplicate object field':'parse','Noncanonical or unsafe number':'parse','Unsupported source/time claim':'parse','Synthetic label mismatch':'parse','Gross factor out of range':'parse','Wealth out of range':'parse','Drawdown rounds to total loss':'parse','Metric out of range':'parse',
 'Invalid continuity evidence':'parse','Invalid base64url encoding':'parse','Noncanonical base64url encoding or wrong byte length':'parse','JSON exceeds its character limit':'parse','Excessive JSON nesting':'parse','Supply JSON or an inert HTML review package as text':'parse','HTML exceeds 2,000,000 characters; use JSON':'parse','Public key must be an uncompressed P-256 point':'parse','Unsupported package schema; a request is not completed continuity':'parse','A package needs two to five profiles':'parse','A package needs one to four ordered transitions':'parse','An embedded profile exceeds 500,000 characters':'parse','Every destination profile must use v4':'parse','Duplicate profile identity or key loop':'chain','Duplicate public key or key loop':'chain','Aliases must match across the chain':'parse','Certificate exceeds 8,192 characters':'parse','Unsupported transition version or purpose':'parse','Every outgoing profile needs a complete nonempty history':'parse','Certificate identity does not match its adjacent profile':'parse','A previous reference must be a supported profile or complete continuity package':'parse','Supply a checkpoint of at most 20,000 characters':'parse','Invalid anchor checkpoint':'parse','Invalid legacy checkpoint fingerprint':'parse','Invalid verifier options':'parse','Profile and checkpoint anchors are mutually exclusive':'parse','Expected key code must be text':'parse','Expected key code needs five groups of four hexadecimal characters':'parse',
 'Input file exceeds the bounded UTF-8 file size':'parse','Input file must contain valid UTF-8; no replacement decoding is allowed':'parse','Repeated option or missing option value':'parse','Unknown option':'parse',
 'Invalid continuity package fields':'parse','Invalid certificate fields':'parse','Invalid anchor checkpoint fields':'parse',
 'Invalid object fields':'parse','Invalid package fields':'parse','Invalid transition fields':'parse','Invalid transition payload fields':'parse','Invalid old checkpoint fields':'parse','Invalid checkpoint fields':'parse',
});
export function classifyFailure(error){
 const context=emptyHeadlineContext(),category=MESSAGE_CLASSIFICATION[error?.message];
 if(!category)return {facts:{parse:'INVALID_INPUT',continuity:'NONE',comparison:'NONE',reconciliation:'NONE',witness:'NONE'},context:{...context,record_reasons:['UNCLASSIFIED_VERIFIER_FAILURE']}};
 // Recognized refusals are terminal: neutral values in the remaining record
 // fields cannot promote them, because record failure has first precedence.
 const facts=recordValid();
 if(category==='arithmetic'){facts.parse='INVALID_INPUT';context.record_reasons=['ARITHMETIC_NOT_REPRODUCED'];}
 else facts[category]={parse:'INVALID_INPUT',payload_hash:'MISMATCH',signatures:'INVALID',chain:'BROKEN'}[category];
 return {facts,context};
}
function effective(profile){const removed=new Set(profile.stamps.filter(s=>s.payload.event_type==='correction').map(s=>s.payload.correction.target_sequence));return profile.stamps.filter(s=>!removed.has(s.payload.sequence));}
function gaps(profiles){const periods=profiles.flatMap(p=>effective(p).map(s=>s.payload.period));return periods.slice(1).flatMap((p,i)=>periods[i].end<p.start?[{start:periods[i].end,end:p.start}]:[]);}
const safeSummary=(value,key)=>Object.fromEntries(Object.entries(value).filter(([name])=>name!==key));
export function verifyHeadline(current,inputs={}){
 let record,profile,profiles,isContinuity=false,facts,context;
 try{
  const raw=current.trimStart().startsWith('{')?current:current.split('<script id="n170-evidence" type="application/json">')[1]?.split('</script>')[0];
  isContinuity=JSON.parse(raw)?.schema_version==='n170.verify.continuity-package.v1';
  if(isContinuity){record=verifyContinuity(current,inputs.previous===undefined?{}:{previous:inputs.previous});profiles=record.package.profiles;}
  else{record=verifyEvidence(current);profile=record.profile;profiles=[profile];}
  facts=recordValid();context=emptyHeadlineContext();
  if(isContinuity){facts.continuity=record.anchor_status==='conflict'?'CONFLICT':'VALID';context.continuity_anchor=record.anchor_status==='conflict'?null:record.anchor_status;}
  context.gaps=gaps(profiles);
 }catch(error){const mapped=classifyFailure(error);return {schema:'n170.verify.headline-check.v1',...mapped,headline:deriveHeadline(mapped.facts,mapped.context)};}
 const out={schema:'n170.verify.headline-check.v1',facts,context,record:safeSummary(record,isContinuity?'package':'profile')};
 if(!isContinuity&&inputs.previous!==undefined){
  try{out.previous_copy=compareEvidence(inputs.previous,current);facts.comparison=statusMap[out.previous_copy.status];}
  catch{facts.parse='INVALID_INPUT';context.record_reasons=['PREVIOUS_COPY_INVALID'];out.headline=deriveHeadline(facts,context);return out;}
 }
 if(inputs.reconciliationText!==undefined&&isContinuity)return {schema:'n170.verify.headline-check.v1',status:'INVALID_INPUT',reasons:['VERIFIER_INPUT_INVALID']};
 let selected;
 if(inputs.reconciliationText!==undefined||inputs.receiptBytes!==undefined){
  if(typeof inputs.eventSha256!=='string'||!/^[a-f0-9]{64}$/.test(inputs.eventSha256))return {schema:out.schema,status:'INVALID_INPUT',reasons:['VERIFIER_INPUT_INVALID']};
  const owner=profiles.find(p=>p.stamps.some(s=>s.sha256===inputs.eventSha256));selected=owner?.stamps.find(s=>s.sha256===inputs.eventSha256);
  if(!selected)return {schema:out.schema,status:'INVALID_INPUT',reasons:['EVENT_NOT_FOUND']};
  const p=selected.payload;context.selected_event={sequence:p.sequence,start:p.period.start,end:p.period.end};
  context.selected_event_superseded=!effective(owner).some(s=>s.sha256===selected.sha256);
  context.other_effective_slots=profiles.reduce((sum,p)=>sum+effective(p).length,0)-1;
 }
 if(inputs.reconciliationText!==undefined){
  out.reconciliation=verifyReconciliation(current,inputs.reconciliationText,inputs.eventSha256);facts.reconciliation=out.reconciliation.status;context.reconciliation_reasons=[...out.reconciliation.reasons];
  if(context.selected_event_superseded&&facts.reconciliation==='VERIFIED_UNDER_OWNER_ASSERTIONS'){facts.reconciliation='NOT_ASSESSABLE';context.reconciliation_reasons.push('SELECTED_EVENT_SUPERSEDED');}
 }
 if(inputs.receiptBytes!==undefined){
  out.witness=verifyWitnessReceipt(inputs.receiptBytes,{recordPayloadHash:selected.sha256,trustedWitnessKeys:inputs.trustedWitnessKeys,allowedBrokerHosts:inputs.allowedBrokerHosts,...(inputs.otsProofBytes===undefined?{}:{otsProofBytes:inputs.otsProofBytes})});
  facts.witness=out.witness.result;context.witness_reasons=[...out.witness.reasons];context.timestamp_proof=out.witness.timestamp_proof.status;
  if(context.selected_event_superseded&&facts.witness==='WITNESSED'){facts.witness='WITNESS_NOT_ASSESSABLE';context.witness_reasons.push('SELECTED_EVENT_SUPERSEDED');}
  if(facts.witness==='WITNESSED'){context.witness_host=out.witness.endpoint_host;context.witness_key_code=out.witness.witness_key_code;}
 }
 out.headline=deriveHeadline(facts,context);return out;
}
export function runCli(args){
 const schema='n170.verify.headline-check.v1';
 const refusal=reason=>({exitCode:3,output:JSON.stringify({schema,status:'INVALID_INPUT',reasons:[reason]})+'\n'});
 if(args.length===1&&args[0]==='--help')return {exitCode:0,output:'Usage: node scripts/verify-headline.mjs CURRENT [PREVIOUS] [--event-sha256 HEX] [--reconciliation FILE] [--witness-receipt FILE --trusted-witness-key CODE ... --allowed-broker-host HOST ... [--timestamp-proof FILE]]\nHeadline exits: 0 accepted local facts, 1 rejected, 2 conflict, 3 usage/read error. Original record, private-source and continuity command statuses and exits are unchanged.\n'};
 try{
  const positional=[],opts={},trustedWitnessKeys=[],allowedBrokerHosts=[];
  for(let i=0;i<args.length;i++){
   const flag=args[i];if(!flag.startsWith('--')){positional.push(flag);continue;}
   if(!['--event-sha256','--reconciliation','--witness-receipt','--trusted-witness-key','--allowed-broker-host','--timestamp-proof'].includes(flag)||i+1>=args.length||args[i+1].startsWith('--'))return refusal('VERIFIER_INPUT_INVALID');
   const v=args[++i];if(flag==='--trusted-witness-key')trustedWitnessKeys.push(v);else if(flag==='--allowed-broker-host')allowedBrokerHosts.push(v);else{if(Object.hasOwn(opts,flag))return refusal('VERIFIER_INPUT_INVALID');opts[flag]=v;}
  }
  if(positional.length<1||positional.length>2)return refusal('VERIFIER_INPUT_INVALID');
  const receipt=opts['--witness-receipt'],reconciliation=opts['--reconciliation'];
  if((receipt||reconciliation)&&!/^[a-f0-9]{64}$/.test(opts['--event-sha256']??''))return refusal('VERIFIER_INPUT_INVALID');
  if(receipt?(!trustedWitnessKeys.length||!allowedBrokerHosts.length):trustedWitnessKeys.length||allowedBrokerHosts.length||opts['--timestamp-proof'])return refusal('VERIFIER_INPUT_INVALID');
  if(opts['--event-sha256']&&!/^[a-f0-9]{64}$/.test(opts['--event-sha256']))return refusal('VERIFIER_INPUT_INVALID');
  const read=(path,max,text)=>{const stat=lstatSync(path);if(!stat.isFile()||stat.size>max)throw 0;const b=readFileSync(path);if(b.length>max)throw 0;return text?new TextDecoder('utf-8',{fatal:true}).decode(b):b;};
  let current,previous,reconciliationText,receiptBytes,otsProofBytes;
  try{current=read(positional[0],12000000,true);if(positional[1])previous=read(positional[1],12000000,true);if(reconciliation)reconciliationText=read(reconciliation,16000000,true);if(receipt)receiptBytes=read(receipt,65536,false);if(opts['--timestamp-proof'])otsProofBytes=read(opts['--timestamp-proof'],65536,false);}catch{return refusal('VERIFIER_INPUT_INVALID');}
  const result=verifyHeadline(current,{previous,reconciliationText,receiptBytes,otsProofBytes,eventSha256:opts['--event-sha256'],trustedWitnessKeys,allowedBrokerHosts});
  return {exitCode:result.headline?.exit??3,output:JSON.stringify(result,null,2)+'\n'};
 }catch{return refusal('VERIFIER_INPUT_INVALID');}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){const response=runCli(process.argv.slice(2));process.stdout.write(response.output);process.exitCode=response.exitCode;}
