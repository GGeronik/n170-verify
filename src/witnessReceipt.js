// Offline receipt checking. Trust is supplied by the recipient on every call.
const encoder=new TextEncoder();
const fields=['schema_version','serialization_version','witness_public_key','witness_key_id','broker','endpoint_host','tls_chain_sha256','query_id','token_sha256','requested_range','fetched_at_witness_clock','response_sha256','canonicalization_version','canonical_statement_sha256','sections_present','accounts_seen','coverage','record_event_sha256','reconciliation','reasons','first_difference'];
const hashPattern=/^[a-f0-9]{64}$/, codePattern=/^[a-f0-9]{4}(?:-[a-f0-9]{4}){4}$/;
const hex=s=>typeof s==='string'&&hashPattern.test(s);
const host=s=>typeof s==='string'&&s.length>=1&&s.length<=253&&s.split('.').every(x=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x));
const exact=(o,ks)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===ks.length&&ks.every(k=>Object.hasOwn(o,k));
const bytes=value=>value instanceof Uint8Array || value instanceof ArrayBuffer;
const arrayBytes=v=>v instanceof Uint8Array?v:new Uint8Array(v);
const day=s=>typeof s==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(s)&&Number.isFinite(Date.parse(s))&&new Date(s).toISOString().slice(0,10)===s;
function range(o,a,b){return exact(o,[a,b])&&day(o[a])&&day(o[b])&&o[a]<o[b];}
function ordered(a,min,max,predicate){return Array.isArray(a)&&a.length>=min&&a.length<=max&&a.every((v,i)=>predicate(v)&&(i===0||a[i-1]<v));}
function decode64(s,size){
 if(typeof s!=='string'||!/^[A-Za-z0-9_-]+$/.test(s))return null;
 try{const data=Uint8Array.from(atob(s.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));const back=btoa(String.fromCharCode(...data)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');return data.length===size&&back===s?data:null;}catch{return null;}
}
async function hash(data){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',data)),n=>n.toString(16).padStart(2,'0')).join('');}
function concatenate(a,b){const out=new Uint8Array(a.length+b.length);out.set(a);out.set(b,a.length);return out;}
function parse(data){
 const b=typeof data==='string'?encoder.encode(data):bytes(data)?arrayBytes(data):null;
 if(!b||b.length>65536||b[0]===0xef&&b[1]===0xbb&&b[2]===0xbf)throw 0;
 const text=new TextDecoder('utf-8',{fatal:true}).decode(b);if(text.length>16384)throw 0;
 const value=JSON.parse(text), scopes=[];
 const tokens=text.match(/"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null|[{}\[\]:,]/g)||[];
 for(let i=0;i<tokens.length;i++){
  const t=tokens[i];if(t==='{'||t==='['){scopes.push(t==='{'?new Set():null);if(scopes.length>4)throw 0;}
  else if(t==='}'||t===']')scopes.pop();
  else if(t[0]==='"'&&tokens[i+1]===':'){const name=JSON.parse(t),scope=scopes.at(-1);if(!scope||scope.has(name))throw 0;scope.add(name);}
  else if(/^[0-9-]/.test(t))throw 0;
 }
 return value;
}
function validPayload(p){
 if(!exact(p,fields))return false;
 // JSON strings, including identifiers, must decode to ASCII.
 const ascii=v=>v===null||typeof v==='string'&&/^[\x00-\x7f]*$/.test(v)||Array.isArray(v)&&v.every(ascii)||v&&typeof v==='object'&&Object.keys(v).every(k=>/^[\x00-\x7f]*$/.test(k)&&ascii(v[k]));
 if(!ascii(p))return false;
 if(!decode64(p.witness_public_key,65)||!hex(p.witness_key_id)||p.broker!=='IBKR'||!host(p.endpoint_host))return false;
 if(!Array.isArray(p.tls_chain_sha256)||p.tls_chain_sha256.length<1||p.tls_chain_sha256.length>10||!p.tls_chain_sha256.every(hex))return false;
 if(typeof p.query_id!=='string'||!/^\d{1,32}$/.test(p.query_id)||!hex(p.token_sha256)||!range(p.requested_range,'from','to'))return false;
 if(typeof p.fetched_at_witness_clock!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(p.fetched_at_witness_clock)||!Number.isFinite(Date.parse(p.fetched_at_witness_clock))||new Date(p.fetched_at_witness_clock).toISOString().replace('.000','')!==p.fetched_at_witness_clock)return false;
 if(!hex(p.response_sha256)||!hex(p.canonical_statement_sha256)||!hex(p.record_event_sha256))return false;
 if(!ordered(p.sections_present,1,4,s=>['AccountInformation','CashReport','CashTransactions','ChangeInNAV'].includes(s)))return false;
 if(!ordered(p.accounts_seen,0,20,s=>typeof s==='string'&&/^[A-Z]{1,3}\*{3,8}[0-9]{4}$/.test(s)))return false;
 if(p.coverage!==null&&!range(p.coverage,'available_from','available_to'))return false;
 if(!['VERIFIED_UNDER_WITNESS','MISMATCH','NOT_ASSESSABLE'].includes(p.reconciliation)||!ordered(p.reasons,0,20,s=>typeof s==='string'&&/^[A-Z][A-Z0-9_]{0,79}$/.test(s)))return false;
 if((p.reconciliation==='VERIFIED_UNDER_WITNESS')!==(p.reasons.length===0))return false;
 if(p.first_difference!==null&&(!exact(p.first_difference,['date','field'])||!day(p.first_difference.date)||!['nav','external_flow','return','coverage','section'].includes(p.first_difference.field)))return false;
 return p.reconciliation!=='VERIFIED_UNDER_WITNESS'||p.first_difference===null;
}
function canonical(p){const out=Object.fromEntries(fields.map(k=>[k,p[k]]));out.requested_range={from:p.requested_range.from,to:p.requested_range.to};out.coverage=p.coverage===null?null:{available_from:p.coverage.available_from,available_to:p.coverage.available_to};out.first_difference=p.first_difference===null?null:{date:p.first_difference.date,field:p.first_difference.field};return encoder.encode(JSON.stringify(out));}
function timestamp(proof,digest){
 if(proof===undefined)return {status:'NONE',reasons:[]};
 const b=arrayBytes(proof),magic=Uint8Array.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294'.match(/../g),s=>parseInt(s,16));
 const invalid=reason=>({status:'INVALID',reasons:[reason]});
 if(b.length<65||!magic.every((v,i)=>b[i]===v))return invalid('TIMESTAMP_PROOF_MALFORMED');
 let pos=31,version=0,shift=0;
 do{if(pos>=b.length||shift>28)return invalid('TIMESTAMP_PROOF_MALFORMED');const v=b[pos++];version+=(v&127)*2**shift;if(!(v&128))break;shift+=7;}while(true);
 if(version!==1||b[pos++]!==8||pos+32>b.length)return invalid('TIMESTAMP_PROOF_MALFORMED');
 const bound=Array.from(b.slice(pos,pos+32),v=>v.toString(16).padStart(2,'0')).join('');
 return bound===digest?{status:'PENDING',reasons:['TIMESTAMP_CONFIRMATION_NOT_VERIFIED']}:invalid('TIMESTAMP_PROOF_UNBOUND');
}
export async function verifyWitnessReceipt(receiptBytes, options){
 const out={result:'WITNESS_RECEIPT_INVALID',reasons:[],receipt_sha256:null,witness_key_code:null,endpoint_host:null,record_event_sha256:null,sections_present:null,accounts_seen:null,timestamp_proof:{status:'NONE',reasons:[]}};
 const fail=(reason,result='WITNESS_RECEIPT_INVALID')=>({...out,result,reasons:[reason]});
 try{
  if(!options||!hex(options.recordPayloadHash)||!Array.isArray(options.trustedWitnessKeys)||options.trustedWitnessKeys.length<1||options.trustedWitnessKeys.length>50||!options.trustedWitnessKeys.every(c=>typeof c==='string'&&codePattern.test(c))||!Array.isArray(options.allowedBrokerHosts)||options.allowedBrokerHosts.length<1||options.allowedBrokerHosts.length>20||!options.allowedBrokerHosts.every(host)||options.otsProofBytes!==undefined&&(!bytes(options.otsProofBytes)||arrayBytes(options.otsProofBytes).length>65536))return fail('VERIFIER_INPUT_INVALID','WITNESS_NOT_ASSESSABLE');
  let r;try{r=parse(receiptBytes);}catch{return fail('RECEIPT_SCHEMA_INVALID');}
  if(!exact(r,['payload','sha256','signature'])||!hex(r.sha256)||!decode64(r.signature,64)||!r.payload||typeof r.payload!=='object'||Array.isArray(r.payload))return fail('RECEIPT_SCHEMA_INVALID');
  const p=r.payload;
  if(p.schema_version!=='n170.verify.witness-receipt.v1'||p.serialization_version!=='1.0.0'||p.canonicalization_version!=='1.0.0')return fail('RECEIPT_VERSION_UNSUPPORTED');
  if(!validPayload(p))return fail('RECEIPT_SCHEMA_INVALID');
  const raw=decode64(p.witness_public_key,65);let key;
  try{if(raw[0]!==4)throw 0;key=await crypto.subtle.importKey('raw',raw,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);}catch{return fail('WITNESS_KEY_INVALID');}
  const id=await hash(concatenate(encoder.encode('n170.verify.witness-key.v1\n'),raw));
  if(id!==p.witness_key_id)return fail('WITNESS_KEY_ID_MISMATCH');
  out.witness_key_code=id.slice(0,20).match(/.{4}/g).join('-');
  if(!options.trustedWitnessKeys.includes(out.witness_key_code))return fail('WITNESS_KEY_NOT_TRUSTED');
  const data=canonical(p),digest=await hash(data);if(digest!==r.sha256)return fail('RECEIPT_HASH_MISMATCH');out.receipt_sha256=digest;
  let valid;try{valid=await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,decode64(r.signature,64),concatenate(encoder.encode('n170.verify.witness-receipt-signature.v1\n'),data));}catch{valid=false;}
  if(!valid)return fail('WITNESS_SIGNATURE_INVALID');
  out.sections_present=[...p.sections_present];out.accounts_seen=[...p.accounts_seen];
  if(p.record_event_sha256!==options.recordPayloadHash)return fail('EVENT_HASH_UNBOUND');out.record_event_sha256=p.record_event_sha256;
  out.endpoint_host=p.endpoint_host;if(!options.allowedBrokerHosts.includes(p.endpoint_host))return fail('BROKER_HOST_NOT_ALLOWED','WITNESS_NOT_ASSESSABLE');
  out.timestamp_proof=timestamp(options.otsProofBytes,digest);
  if(p.reconciliation==='MISMATCH')return {...out,result:'WITNESS_MISMATCH',reasons:['RECEIPT_RECONCILIATION_MISMATCH',...p.reasons]};
  if(p.reconciliation==='NOT_ASSESSABLE')return {...out,result:'WITNESS_NOT_ASSESSABLE',reasons:['RECEIPT_RECONCILIATION_NOT_ASSESSABLE',...p.reasons]};
  return {...out,result:'WITNESSED',reasons:[]};
 }catch{return fail('RECEIPT_SCHEMA_INVALID');}
}
