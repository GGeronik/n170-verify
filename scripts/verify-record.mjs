#!/usr/bin/env node
// Independent implementation of FORMAT.md. No imports from src/, third-party
// packages, browser WebCrypto, network, or code contained in an input package.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const hash = x => createHash('sha256').update(x).digest('hex');
const check = (condition, message = 'Invalid or unsupported evidence') => { if (!condition) throw new Error(message); };
const exact = (o, keys) => check(o && !Array.isArray(o) && typeof o === 'object' && Object.keys(o).length === keys.length && keys.every(k => Object.hasOwn(o,k)));
const hex = s => typeof s === 'string' && /^[a-f0-9]{64}$/.test(s);
const visible = (s, max) => typeof s === 'string' && s.length <= max && (s === '' || /^[\p{L}\p{M}\p{N}\p{P}\p{S} ]+$/u.test(s));
const date = s => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && Number.isFinite(Date.parse(s)) && new Date(s).toISOString().slice(0,10) === s;
const base64 = (s,n) => { check(typeof s === 'string' && /^[A-Za-z0-9_-]+$/.test(s)); const b=Buffer.from(s,'base64url'); check(b.length===n && b.toString('base64url')===s); return b; };
const payloadFields = ['schema_version','calculation_version','sequence','profile_id','display_name','previous_sha256','source_kind','provider_authenticated','independent_timestamp','period','periods_per_year','relative_returns','coverage','metrics'];
const modernFields = ['serialization_version','event_type','correction','provenance'];
const provenanceFields = ['kind','format','original_sha256','source_sha256','normalized_sha256','mapping','account_scope','currency','completeness','corrections','reviewed'];
const metricFields = ['total_return_twr_e8','annualized_volatility_e8','max_drawdown_e8'];
const pick = (o, fields) => Object.fromEntries(fields.map(k=>[k,o[k]]));

export function extractEvidence(text) {
  check(typeof text === 'string' && text.length <= 2000000, 'File exceeds 2 MB');
  if (!text.trimStart().startsWith('{')) {
    const marker='<script id="n170-evidence" type="application/json">';
    const parts=text.split(marker); check(parts.length===2,'Missing or ambiguous evidence attachment');
    const end=parts[1].indexOf('</script>'); check(end>=0,'Incomplete evidence attachment'); text=parts[1].slice(0,end);
  }
  check(text.length<=500000,'Evidence exceeds 500,000 characters');
  return text;
}

// Token-level duplicate-field and integer checking before JSON.parse. Decodes
// escaped object keys before comparing; nesting is bounded without recursion.
function strictJson(text) {
  const tokens=text.match(/"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null|[{}\[\]:,]/g) || [];
  const scopes=[];
  for(let i=0;i<tokens.length;i++) {
    const token=tokens[i];
    if(token==='{' || token==='[') {scopes.push(token==='{'?new Set():null);check(scopes.length<=12,'Excessive nesting');}
    else if(token==='}' || token===']') scopes.pop();
    else if(token[0]==='"' && tokens[i+1]===':') {const key=JSON.parse(token); const scope=scopes.at(-1);check(scope && !scope.has(key),'Duplicate object field');scope.add(key);}
    else if(/^[-0-9]/.test(token)) check(/^(0|-?[1-9][0-9]*)$/.test(token) && Number.isSafeInteger(Number(token)), 'Noncanonical or unsafe number');
  }
  return JSON.parse(text);
}

function canonical(p,modern) {
  const out=pick(p,payloadFields);
  out.period=pick(p.period,['start','end']);
  out.relative_returns=p.relative_returns.map(r=>pick(r,['start','end','return_e8']));
  out.coverage=pick(p.coverage,['nav_observations','return_observations','external_cash_flow_count']);
  out.metrics=pick(p.metrics,metricFields);
  if(modern) {
    Object.assign(out,pick(p,modernFields));
    out.correction=p.correction===null?null:pick(p.correction,['target_sequence','target_sha256','reason']);
    out.provenance=pick(p.provenance,provenanceFields);
    out.provenance.mapping=p.provenance.mapping.map(m=>pick(m,['field','column']));
    out.provenance.corrections=p.provenance.corrections.map(c=>pick(c,['row','field','reason','previous_sha256','replacement_sha256']));
  }
  return JSON.stringify(out);
}

function units(value) {const n=value*100000000;const f=Math.floor(n);const result=(n-f>=.5?f+1:f)||0;check(Number.isSafeInteger(result),'Metric out of range');return result;}
function v1Metrics(p) {
  const values=p.relative_returns.map(r=>r.return_e8/100000000);
  let wealth=1, peak=1, dd=0, sum=0, squares=0;
  for(const r of values) {wealth=wealth*(1+r);check(Number.isFinite(wealth)&&wealth>0);peak=Math.max(peak,wealth);dd=Math.min(dd,wealth/peak-1);sum=sum+r;}
  const mean=sum/values.length;
  for(const r of values) squares=squares+(r-mean)*(r-mean);
  const vol=values.length>1?Math.sqrt(squares/(values.length-1))*Math.sqrt(p.periods_per_year):null;
  return [units(wealth-1),vol===null?null:units(vol),units(dd)];
}

// Independent rational implementation reduces fractions after each step.
const U=100000000n;
function gcd(a,b) {a=a<0n?-a:a;while(b){const r=a%b;a=b;b=r;}return a;}
function ratio(n,d) {const g=gcd(n,d);return [n/g,d/g];}
function rounded(n,d) {let f=n/d;if(n<0n && n%d!==0n)f--;return Number(f+(2n*(n-f*d)>=d?1n:0n));}
function rootRounded(n,d) {let lo=0n,hi=n/d+1n;while(hi-lo>1n){const m=(lo+hi)/2n;if(m*m*d<=n)lo=m;else hi=m;}return Number(lo+(4n*n>=d*(2n*lo+1n)*(2n*lo+1n)?1n:0n));}
function annualizationAllowed(p) {
  const frequency=p.periods_per_year;
  if(![1,4,12,52,252,365,366].includes(frequency) || p.relative_returns.length<20)return false;
  let missing=0;
  for(const r of p.relative_returns) {
    const start=new Date(r.start),end=new Date(r.end),days=(end-start)/86400000;
    const months=(end.getUTCFullYear()-start.getUTCFullYear())*12+end.getUTCMonth()-start.getUTCMonth();
    if(frequency===252) {
      if(days>5 || [0,6].includes(start.getUTCDay()) || [0,6].includes(end.getUTCDay()))return false;
      let weekdays=0;for(let day=1;day<=days;day++){if(![0,6].includes((start.getUTCDay()+day)%7))weekdays++;}
      missing+=Math.max(0,weekdays-1);
    } else if(frequency>=365 && days!==1)return false;
    else if(frequency===52 && (days<5 || days>9))return false;
    else if(frequency===12 && (months!==1 || days<26 || days>35))return false;
    else if(frequency===4 && (months!==3 || days<80 || days>100))return false;
    else if(frequency===1 && (months!==12 || days<360 || days>370))return false;
  }
  return frequency!==252 || missing<=Math.max(2,Math.floor(p.relative_returns.length*.06));
}
function v2Metrics(p) {
  let [n,d]=[1n,1n], [pn,pd]=[1n,1n], [dn,dd]=[0n,1n];let sum=0n,squares=0n;
  for(const r of p.relative_returns) {
    check(r.return_e8<=(10000-1)*100000000,'Gross factor out of range');
    const v=BigInt(r.return_e8);
    [n,d]=ratio(n*(U+v),d*U);check(n*1000000n>=d && n<=d*1000000n,'Wealth out of range');
    if(n*pd>pn*d){pn=n;pd=d;}
    const [cn,cd]=ratio(n*pd-d*pn,d*pn);if(cn*dd<dn*cd){dn=cn;dd=cd;}
    sum+=v;squares+=v*v;
  }
  const count=BigInt(p.relative_returns.length);
  const drawdown=rounded(dn*U,dd);check(drawdown>-100000000,'Drawdown rounds to total loss');
  return [rounded((n-d)*U,d),annualizationAllowed(p)?rootRounded((count*squares-sum*sum)*BigInt(p.periods_per_year),count*(count-1n)):null,drawdown];
}

export function verifyEvidence(input) {
  const profile=strictJson(extractEvidence(input));
  exact(profile,['schema_version','profile_id','display_name','public_key','stamps']);
  check(['n170.verify.track-record.v3','n170.verify.track-record.v4'].includes(profile.schema_version));
  check(visible(profile.display_name,80)&&profile.display_name.length>0&&profile.display_name.trim()===profile.display_name);
  const raw=base64(profile.public_key,65);check(raw[0]===4);
  check(profile.profile_id===hash(Buffer.concat([Buffer.from('n170.verify.profile-key.v3\n'),raw])),'Key ID mismatch');
  const key=createPublicKey({format:'jwk',key:{kty:'EC',crv:'P-256',x:raw.subarray(1,33).toString('base64url'),y:raw.subarray(33).toString('base64url')}});
  check(Array.isArray(profile.stamps)&&profile.stamps.length<=120);
  let lastEnd=null,sawV4=false;const superseded=new Set();
  profile.stamps.forEach((stamp,index)=>{
    exact(stamp,['payload','sha256','signature']);check(hex(stamp.sha256));const sig=base64(stamp.signature,64);
    const p=stamp.payload,modern=p.schema_version==='n170.verify.performance-stamp.v4';
    exact(p,modern?[...payloadFields,...modernFields]:payloadFields);
    check(modern?profile.schema_version==='n170.verify.track-record.v4'&&p.calculation_version==='2.0.0'&&p.serialization_version==='1.0.0':!sawV4&&p.schema_version==='n170.verify.performance-stamp.v3'&&p.calculation_version==='1.0.0');sawV4 ||=modern;
    check(p.profile_id===profile.profile_id && p.display_name===profile.display_name && p.sequence===index+1 && p.previous_sha256===(index?profile.stamps[index-1].sha256:null),'Record chain mismatch');
    check(p.provider_authenticated===false && p.independent_timestamp===false && ['self_reported','synthetic_demo'].includes(p.source_kind),'Unsupported source/time claim');
    exact(p.period,['start','end']);check(date(p.period.start)&&date(p.period.end)&&p.period.start<p.period.end);
    if(modern){
      check(['performance','correction'].includes(p.event_type));
      if(p.event_type==='correction'){
        exact(p.correction,['target_sequence','target_sha256','reason']);const c=p.correction;
        check(Number.isInteger(c.target_sequence)&&c.target_sequence>=1&&c.target_sequence<=index&&!superseded.has(c.target_sequence));
        const target=profile.stamps[c.target_sequence-1];check(c.target_sha256===target.sha256&&visible(c.reason,500)&&c.reason.trim().length>=3&&p.period.start===target.payload.period.start&&p.period.end===target.payload.period.end,'Invalid correction');superseded.add(c.target_sequence);
      }else check(p.correction===null);
      const v=p.provenance;exact(v,provenanceFields);
      check(['manual','supplied_file'].includes(v.kind)&&visible(v.format,80)&&v.format.length>0&&visible(v.account_scope,160)&&v.account_scope.length>0&&typeof v.currency==='string'&&(v.currency==='unspecified'||/^[A-Z]{3}$/.test(v.currency))&&v.completeness==='not_established'&&typeof v.reviewed==='boolean');
      for(const field of ['original_sha256','source_sha256','normalized_sha256'])check(v.kind==='manual'?v[field]===null:hex(v[field]));
      check(Array.isArray(v.mapping)&&v.mapping.length<=20&&Array.isArray(v.corrections)&&v.corrections.length<=100);
      for(const m of v.mapping){exact(m,['field','column']);check(visible(m.field,80)&&visible(m.column,120));}
      for(const c of v.corrections){exact(c,['row','field','reason','previous_sha256','replacement_sha256']);check(Number.isInteger(c.row)&&c.row>=0&&c.row<=10000&&visible(c.field,80)&&visible(c.reason,500)&&c.reason.trim().length>=3&&hex(c.previous_sha256)&&hex(c.replacement_sha256));}
    }
    if(!modern||p.event_type==='performance'){check(lastEnd===null||p.period.start>=lastEnd,'Overlapping periods');lastEnd=p.period.end;}
    check(Number.isInteger(p.periods_per_year)&&p.periods_per_year>=1&&p.periods_per_year<=366);
    check(Array.isArray(p.relative_returns)&&p.relative_returns.length>=1&&p.relative_returns.length<=499);let end=p.period.start;
    for(const r of p.relative_returns){exact(r,['start','end','return_e8']);check(date(r.start)&&date(r.end)&&r.start===end&&r.start<r.end&&Number.isSafeInteger(r.return_e8)&&r.return_e8>-100000000);end=r.end;}
    check(end===p.period.end);
    exact(p.coverage,['nav_observations','return_observations','external_cash_flow_count']);check(p.coverage.return_observations===p.relative_returns.length&&p.coverage.nav_observations===p.relative_returns.length+1&&Number.isInteger(p.coverage.external_cash_flow_count)&&p.coverage.external_cash_flow_count>=0&&p.coverage.external_cash_flow_count<=p.relative_returns.length);
    if(!modern && p.source_kind==='synthetic_demo')check(JSON.stringify(p.relative_returns.map(r=>pick(r,['start','end','return_e8'])))===JSON.stringify([{start:'2025-01-02',end:'2025-01-03',return_e8:1000000},{start:'2025-01-03',end:'2025-01-06',return_e8:1009901},{start:'2025-01-06',end:'2025-01-07',return_e8:-1000000}])&&p.coverage.external_cash_flow_count===1,'Synthetic label mismatch');
    exact(p.metrics,metricFields);const calculated=modern?v2Metrics(p):v1Metrics(p);
    metricFields.forEach((field,i)=>check(p.metrics[field]===calculated[i]&&(calculated[i]===null||Number.isSafeInteger(calculated[i])),'Metric mismatch'));
    const bytes=Buffer.from(canonical(p,modern));check(stamp.sha256===hash(bytes),'Payload hash mismatch');
    check(verify('sha256',Buffer.concat([Buffer.from(`n170.verify.stamp-signature.${modern?'v4':'v3'}\n`),bytes]),{key,dsaEncoding:'ieee-p1363'},sig),'Signature mismatch');
  });
  return {profile,records:profile.stamps.length,key_code:profile.profile_id.slice(0,20).match(/.{4}/g).join('-'),arithmetic_valid:true,signatures_valid:true,source_authenticated:false,identity_established:false,independent_timestamp:false,earlier_publication_checked:false};
}

// Comparison output is a checked presentation, not another signed record.
// Rebuild the effective period slots independently of the application code.
function describeChanges(prior, next) {
  const snapshot = p => p ? {
    sequence:p.sequence, period:pick(p.period,['start','end']), metrics:pick(p.metrics,metricFields),
    account_scope:p.provenance?.account_scope??null, currency:p.provenance?.currency??null,
    source_kind:p.source_kind, source_format:p.provenance?.format??null,
    reviewed:p.provenance?.reviewed??null, periods_per_year:p.periods_per_year,
    calculation_version:p.calculation_version, return_observations:p.coverage.return_observations,
  } : null;
  const slots=[], slotForEvent=new Map(), events=[];
  for(const {payload:p} of next.stamps) {
    const isCorrection=p.event_type==='correction';
    const target=isCorrection?p.correction.target_sequence:null;
    const before=isCorrection?next.stamps[target-1].payload:slots.at(-1);
    if(p.sequence>prior.stamps.length)events.push({
      sequence:p.sequence,kind:isCorrection?'correction':'performance',period:pick(p.period,['start','end']),
      target_sequence:target,before:snapshot(before),after:snapshot(p),reason:isCorrection?p.correction.reason:null,
    });
    const slot=isCorrection?slotForEvent.get(target):slots.length;
    slots[slot]=p;slotForEvent.set(p.sequence,slot);
  }
  return {version:'n170.verify.comparison.v1',events};
}

export function compareEvidence(previous,current){
  const a=verifyEvidence(previous).profile,b=verifyEvidence(current).profile;let shared=0;
  if(a.profile_id===b.profile_id&&a.display_name===b.display_name)while(shared<Math.min(a.stamps.length,b.stamps.length)&&a.stamps[shared].sha256===b.stamps[shared].sha256)shared++;
  const status=a.profile_id!==b.profile_id||a.display_name!==b.display_name?'replacement':shared<Math.min(a.stamps.length,b.stamps.length)?'conflicting_history':b.stamps.length<a.stamps.length?'truncated':b.stamps.length===a.stamps.length?'identical':'extended';
  return {status,shared_records:shared,previous_records:a.stamps.length,current_records:b.stamps.length,
    changes:['identical','extended'].includes(status)?describeChanges(a,b):null};
}

if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href){
  try{
    check(process.argv.length>=3&&process.argv.length<=4,'Usage: node scripts/verify-record.mjs CURRENT.html-or-json [PREVIOUS.html-or-json]');
    const current=readFileSync(process.argv[2],'utf8');const {profile,...result}=verifyEvidence(current);
    if(process.argv[3])result.previous_copy=compareEvidence(readFileSync(process.argv[3],'utf8'),current);
    console.log(JSON.stringify(result,null,2));
    if(['replacement','conflicting_history','truncated'].includes(result.previous_copy?.status))process.exitCode=2;
  }catch(error){console.error(`Evidence check failed: ${error.message}`);process.exitCode=1;}
}
