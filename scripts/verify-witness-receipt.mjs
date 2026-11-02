#!/usr/bin/env node
// Standalone, offline receipt verifier; no browser or package dependencies.
import { createHash, createPublicKey, ECDH, verify } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const digest=b=>createHash('sha256').update(b).digest('hex');
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const hostname=v=>typeof v==='string'&&v.length>0&&v.length<=253&&v.split('.').every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
const code=v=>typeof v==='string'&&/^[a-f0-9]{4}(?:-[a-f0-9]{4}){4}$/.test(v);
function exact(v,fields){return v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===fields.length&&fields.every(k=>Object.hasOwn(v,k));}
function binary(v){return v instanceof Uint8Array||v instanceof ArrayBuffer;}
function toBuffer(v){return v instanceof ArrayBuffer?Buffer.from(v):Buffer.from(v.buffer,v.byteOffset,v.byteLength);}
function b64(v,n){if(typeof v!=='string'||!/^[A-Za-z0-9_-]+$/.test(v))return null;const b=Buffer.from(v,'base64url');return b.length===n&&b.toString('base64url')===v?b:null;}
function date(v){if(typeof v!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(v))return false;const d=new Date(v);return Number.isFinite(d.valueOf())&&d.toISOString().substring(0,10)===v;}
function period(v,a,b){return exact(v,[a,b])&&date(v[a])&&date(v[b])&&v[a]<v[b];}
const payloadFields=['schema_version','serialization_version','witness_public_key','witness_key_id','broker','endpoint_host','tls_chain_sha256','query_id','token_sha256','requested_range','fetched_at_witness_clock','response_sha256','canonicalization_version','canonical_statement_sha256','sections_present','accounts_seen','coverage','record_event_sha256','reconciliation','reasons','first_difference'];
function sorted(values,low,high,accept){if(!Array.isArray(values)||values.length<low||values.length>high)return false;for(let i=0;i<values.length;i++)if(!accept(values[i])||i>0&&values[i-1]>=values[i])return false;return true;}
function receiptJson(input){
 const raw=typeof input==='string'?Buffer.from(input,'utf8'):binary(input)?toBuffer(input):null;
 if(raw===null||raw.length>65536||raw.subarray(0,3).equals(Buffer.from([239,187,191])))throw 0;
 const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);if(text.length>16384)throw 0;
 // JSON.parse checks the grammar. A separate scan rejects duplicate decoded
 // names, all number tokens, and excessive depth before any shape is trusted.
 const obj=JSON.parse(text);let i=0;const stack=[];
 while(i<text.length){
  const ch=text[i];
  if(ch==='"'){let j=i+1;while(j<text.length&&text[j]!=='"')j+=text[j]==='\\'?2:1;const token=text.slice(i,j+1);i=j+1;let next=i;while(/[\t\r\n ]/.test(text[next]??'!'))next++;if(text[next]===':'){const name=JSON.parse(token),names=stack.at(-1);if(!names||names.has(name))throw 0;names.add(name);}continue;}
  if(ch==='{'||ch==='['){stack.push(ch==='{'?new Set():null);if(stack.length>4)throw 0;}
  else if(ch==='}'||ch===']')stack.pop();
  else if(ch==='-'||ch>='0'&&ch<='9')throw 0;
  i++;
 }
 return obj;
}
function validFields(p){
 if(!exact(p,payloadFields))return false;
 const pending=[p];while(pending.length){const v=pending.pop();if(v===null)continue;if(typeof v==='string'){if(!/^[\x00-\x7f]*$/.test(v))return false;}else if(Array.isArray(v))pending.push(...v);else if(typeof v==='object'){for(const [k,x] of Object.entries(v)){if(!/^[\x00-\x7f]*$/.test(k))return false;pending.push(x);}}else return false;}
 if(!b64(p.witness_public_key,65)||!hex(p.witness_key_id)||p.broker!=='IBKR'||!hostname(p.endpoint_host))return false;
 if(!Array.isArray(p.tls_chain_sha256)||p.tls_chain_sha256.length<1||p.tls_chain_sha256.length>10||!p.tls_chain_sha256.every(hex))return false;
 if(!/^\d{1,32}$/.test(p.query_id)||!hex(p.token_sha256)||!period(p.requested_range,'from','to'))return false;
 const clock=p.fetched_at_witness_clock;if(typeof clock!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(clock)||!Number.isFinite(Date.parse(clock))||new Date(clock).toISOString()!==clock.replace('Z','.000Z'))return false;
 for(const name of ['response_sha256','canonical_statement_sha256','record_event_sha256'])if(!hex(p[name]))return false;
 if(!sorted(p.sections_present,1,4,x=>['AccountInformation','CashReport','CashTransactions','ChangeInNAV'].includes(x)))return false;
 if(!sorted(p.accounts_seen,0,20,x=>typeof x==='string'&&/^[A-Z]{1,3}\*{3,8}[0-9]{4}$/.test(x)))return false;
 if(p.coverage!==null&&!period(p.coverage,'available_from','available_to'))return false;
 if(!['VERIFIED_UNDER_WITNESS','MISMATCH','NOT_ASSESSABLE'].includes(p.reconciliation)||!sorted(p.reasons,0,20,x=>typeof x==='string'&&/^[A-Z][A-Z0-9_]{0,79}$/.test(x)))return false;
 if(p.reconciliation==='VERIFIED_UNDER_WITNESS'?(p.reasons.length!==0||p.first_difference!==null):p.reasons.length===0)return false;
 return p.first_difference===null||exact(p.first_difference,['date','field'])&&date(p.first_difference.date)&&['nav','external_flow','return','coverage','section'].includes(p.first_difference.field);
}
function canonicalBytes(p){
 const values={};for(const k of payloadFields)values[k]=p[k];
 values.requested_range={from:p.requested_range.from,to:p.requested_range.to};
 if(p.coverage!==null)values.coverage={available_from:p.coverage.available_from,available_to:p.coverage.available_to};
 if(p.first_difference!==null)values.first_difference={date:p.first_difference.date,field:p.first_difference.field};
 return Buffer.from(JSON.stringify(values),'utf8');
}
function checkTimestamp(input,sha){
 if(input===undefined)return {status:'NONE',reasons:[]};
 const b=toBuffer(input),bad=reason=>({status:'INVALID',reasons:[reason]});
 const magic=Buffer.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294','hex');
 if(b.length<65||!b.subarray(0,31).equals(magic))return bad('TIMESTAMP_PROOF_MALFORMED');
 let position=31,multiplier=1,version=0;
 for(let count=0;;count++){if(count>4||position>=b.length)return bad('TIMESTAMP_PROOF_MALFORMED');const octet=b[position++];version+=(octet&127)*multiplier;if(octet<128)break;multiplier*=128;}
 if(version!==1||b[position++]!==8||position+32>b.length)return bad('TIMESTAMP_PROOF_MALFORMED');
 if(b.subarray(position,position+32).toString('hex')!==sha)return bad('TIMESTAMP_PROOF_UNBOUND');
 return {status:'PENDING',reasons:['TIMESTAMP_CONFIRMATION_NOT_VERIFIED']};
}
export function verifyWitnessReceipt(receiptBytes,options){
 const state={result:'WITNESS_RECEIPT_INVALID',reasons:[],receipt_sha256:null,witness_key_code:null,endpoint_host:null,record_event_sha256:null,sections_present:null,accounts_seen:null,timestamp_proof:{status:'NONE',reasons:[]}};
 const refuse=(reason,result='WITNESS_RECEIPT_INVALID')=>({...state,result,reasons:[reason]});
 try{
  if(!options||!hex(options.recordPayloadHash)||!Array.isArray(options.trustedWitnessKeys)||options.trustedWitnessKeys.length===0||options.trustedWitnessKeys.length>50||!options.trustedWitnessKeys.every(code)||!Array.isArray(options.allowedBrokerHosts)||options.allowedBrokerHosts.length===0||options.allowedBrokerHosts.length>20||!options.allowedBrokerHosts.every(hostname)||options.otsProofBytes!==undefined&&(!binary(options.otsProofBytes)||toBuffer(options.otsProofBytes).length>65536))return refuse('VERIFIER_INPUT_INVALID','WITNESS_NOT_ASSESSABLE');
  let receipt;try{receipt=receiptJson(receiptBytes);}catch{return refuse('RECEIPT_SCHEMA_INVALID');}
  if(!exact(receipt,['payload','sha256','signature'])||!hex(receipt.sha256)||!b64(receipt.signature,64)||!receipt.payload||typeof receipt.payload!=='object'||Array.isArray(receipt.payload))return refuse('RECEIPT_SCHEMA_INVALID');
  const p=receipt.payload;
  if(p.schema_version!=='n170.verify.witness-receipt.v1'||p.serialization_version!=='1.0.0'||p.canonicalization_version!=='1.0.0')return refuse('RECEIPT_VERSION_UNSUPPORTED');
  if(!validFields(p))return refuse('RECEIPT_SCHEMA_INVALID');
  const raw=b64(p.witness_public_key,65);let key;
  try{if(raw[0]!==4)throw 0;ECDH.convertKey(raw,'prime256v1',undefined,undefined,'uncompressed');key=createPublicKey({format:'jwk',key:{kty:'EC',crv:'P-256',x:raw.subarray(1,33).toString('base64url'),y:raw.subarray(33).toString('base64url')}});}catch{return refuse('WITNESS_KEY_INVALID');}
  const id=digest(Buffer.concat([Buffer.from('n170.verify.witness-key.v1\n'),raw]));
  if(id!==p.witness_key_id)return refuse('WITNESS_KEY_ID_MISMATCH');state.witness_key_code=id.substring(0,20).match(/.{4}/g).join('-');
  if(!options.trustedWitnessKeys.includes(state.witness_key_code))return refuse('WITNESS_KEY_NOT_TRUSTED');
  const payload=canonicalBytes(p),sha=digest(payload);if(sha!==receipt.sha256)return refuse('RECEIPT_HASH_MISMATCH');state.receipt_sha256=sha;
  let signature;try{signature=verify('sha256',Buffer.concat([Buffer.from('n170.verify.witness-receipt-signature.v1\n'),payload]),{key,dsaEncoding:'ieee-p1363'},b64(receipt.signature,64));}catch{signature=false;}
  if(!signature)return refuse('WITNESS_SIGNATURE_INVALID');state.sections_present=p.sections_present.slice();state.accounts_seen=p.accounts_seen.slice();
  if(p.record_event_sha256!==options.recordPayloadHash)return refuse('EVENT_HASH_UNBOUND');state.record_event_sha256=p.record_event_sha256;
  state.endpoint_host=p.endpoint_host;if(!options.allowedBrokerHosts.includes(p.endpoint_host))return refuse('BROKER_HOST_NOT_ALLOWED','WITNESS_NOT_ASSESSABLE');
  state.timestamp_proof=checkTimestamp(options.otsProofBytes,sha);
  if(p.reconciliation==='VERIFIED_UNDER_WITNESS')return {...state,result:'WITNESSED',reasons:[]};
  const mismatch=p.reconciliation==='MISMATCH';return {...state,result:mismatch?'WITNESS_MISMATCH':'WITNESS_NOT_ASSESSABLE',reasons:[mismatch?'RECEIPT_RECONCILIATION_MISMATCH':'RECEIPT_RECONCILIATION_NOT_ASSESSABLE',...p.reasons]};
 }catch{return refuse('RECEIPT_SCHEMA_INVALID');}
}
export function runCli(args){
 const help='Usage: node scripts/verify-witness-receipt.mjs RECEIPT --event-sha256 HEX --trusted-witness-key CODE ... --allowed-broker-host HOST ... [--timestamp-proof FILE]\nOffline P-256 receipt verification; trust lists are required. Results: WITNESSED, WITNESS_MISMATCH, WITNESS_NOT_ASSESSABLE, WITNESS_RECEIPT_INVALID.\n';
 if(args.length===1&&args[0]==='--help')return {exitCode:0,output:help};
 const invalid=reason=>({exitCode:3,output:JSON.stringify({schema:'n170.verify.witness-receipt-check.v1',status:'INVALID_INPUT',reasons:[reason]})+'\n'});
 try{
  const opts={},trustedWitnessKeys=[],allowedBrokerHosts=[];let file;
  for(let i=0;i<args.length;i++){
   const a=args[i];if(!a.startsWith('--')){if(file) return invalid('VERIFIER_INPUT_INVALID');file=a;continue;}
   if(!['--event-sha256','--trusted-witness-key','--allowed-broker-host','--timestamp-proof'].includes(a)||i+1>=args.length||args[i+1].startsWith('--'))return invalid('VERIFIER_INPUT_INVALID');
   const value=args[++i];if(a==='--trusted-witness-key')trustedWitnessKeys.push(value);else if(a==='--allowed-broker-host')allowedBrokerHosts.push(value);else{if(Object.hasOwn(opts,a))return invalid('VERIFIER_INPUT_INVALID');opts[a]=value;}
  }
  if(!file||!hex(opts['--event-sha256'])||!trustedWitnessKeys.length||!allowedBrokerHosts.length)return invalid('VERIFIER_INPUT_INVALID');
  const read=path=>{const stat=lstatSync(path);if(!stat.isFile()||stat.size>65536)throw 0;const b=readFileSync(path);if(b.length>65536)throw 0;return b;};
  let data,proof;try{data=read(file);if(opts['--timestamp-proof'])proof=read(opts['--timestamp-proof']);}catch{return invalid('VERIFIER_INPUT_INVALID');}
  const result=verifyWitnessReceipt(data,{recordPayloadHash:opts['--event-sha256'],trustedWitnessKeys,allowedBrokerHosts,...(proof===undefined?{}:{otsProofBytes:proof})});
  return {exitCode:result.result==='WITNESSED'?0:result.result==='WITNESS_NOT_ASSESSABLE'?2:1,output:JSON.stringify({schema:'n170.verify.witness-receipt-check.v1',...result},null,2)+'\n'};
 }catch{return invalid('VERIFIER_INPUT_INVALID');}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){const result=runCli(process.argv.slice(2));process.stdout.write(result.output);process.exitCode=result.exitCode;}
