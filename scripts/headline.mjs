// Independent CLI implementation of SPEC-04. No browser-module imports.
const sets=[['parse','OK','INVALID_INPUT'],['payload_hash','MATCH','MISMATCH'],['signatures','VALID','INVALID'],['chain','VALID','BROKEN'],['continuity','NONE','VALID','CONFLICT'],['comparison','NONE','IDENTICAL','EXTENDED','TRUNCATION','REPLACEMENT','CONFLICT'],['reconciliation','NONE','VERIFIED_UNDER_OWNER_ASSERTIONS','MISMATCH','NOT_ASSESSABLE','INVALID_INPUT'],['witness','NONE','WITNESSED','WITNESS_MISMATCH','WITNESS_NOT_ASSESSABLE','WITNESS_RECEIPT_INVALID']];
export const emptyHeadlineContext=()=>({record_reasons:[],selected_event:null,witness_host:null,witness_key_code:null,other_effective_slots:0,selected_event_superseded:false,continuity_anchor:null,reconciliation_reasons:[],witness_reasons:[],timestamp_proof:'NONE',expected_key:'not_supplied',checkpoint_checked:false,gaps:[]});
function shape(value,fields){return value!==null && typeof value==='object' && !Array.isArray(value) && Object.keys(value).length===fields.length && fields.every(k=>Object.hasOwn(value,k));}
function day(value){if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(value))return false;const d=new Date(value);return Number.isFinite(d.getTime()) && d.toISOString().slice(0,10)===value;}
function reasons(value){return Array.isArray(value)&&value.every(x=>typeof x==='string' && /^[A-Z][A-Z0-9_]{0,79}$/.test(x));}
function display(c){
 if(!shape(c,Object.keys(emptyHeadlineContext())))return false;
 for(const key of ['record_reasons','reconciliation_reasons','witness_reasons'])if(!reasons(c[key]))return false;
 for(const key of ['witness_host','witness_key_code'])if(c[key]!==null&&typeof c[key]!=='string')return false;
 if(c.selected_event!==null){const e=c.selected_event;if(!shape(e,['sequence','start','end'])||!Number.isSafeInteger(e.sequence)||e.sequence<1||!day(e.start)||!day(e.end)||e.start>=e.end)return false;}
 return Number.isSafeInteger(c.other_effective_slots)&&c.other_effective_slots>=0&&typeof c.selected_event_superseded==='boolean'&&[null,'matched','partial','not_supplied'].includes(c.continuity_anchor)&&['NONE','PENDING','CONFIRMED','INVALID'].includes(c.timestamp_proof)&&['matched','not_supplied'].includes(c.expected_key)&&typeof c.checkpoint_checked==='boolean'&&Array.isArray(c.gaps)&&c.gaps.every(g=>shape(g,['start','end'])&&day(g.start)&&day(g.end)&&g.start<g.end);
}
export function deriveHeadline(facts,context){
 const f=facts&&typeof facts==='object'&&!Array.isArray(facts)?facts:{};
 const c=display(context)?JSON.parse(JSON.stringify(context)):emptyHeadlineContext();
 let code=null,exit=0,recordFailed=false;
 if(f.parse==='INVALID_INPUT')code='INVALID_INPUT';
 else if(f.payload_hash==='MISMATCH')code='PAYLOAD_HASH_MISMATCH';
 else if(f.signatures==='INVALID')code='SIGNATURE_INVALID';
 else if(f.chain==='BROKEN')code='CHAIN_BROKEN';
 if(code){exit=1;recordFailed=true;}
 else if(!shape(f,sets.map(x=>x[0]))||sets.some(([key,...values])=>!values.includes(f[key]))||!display(context)){code='FACTS_INCOMPLETE';exit=1;}
 else if(['TRUNCATION','REPLACEMENT','CONFLICT'].includes(f.comparison)){code=f.comparison==='CONFLICT'?'CONFLICTING_HISTORY':f.comparison;exit=2;}
 else if(f.continuity==='CONFLICT'){code='CONTINUITY_CONFLICT';exit=2;}
 else if(f.reconciliation==='MISMATCH'){code='PRIVATE_SOURCE_MISMATCH';exit=1;}
 else if(f.witness==='WITNESS_MISMATCH'){code='WITNESS_MISMATCH';exit=1;}
 else if(f.witness==='WITNESS_RECEIPT_INVALID'){code='WITNESS_RECEIPT_INVALID';exit=1;}
 let headline=code?`${exit===2?'CONFLICT':'REJECTED'}: ${code}`:f.witness==='WITNESSED'?'WITNESSED RECORD':f.reconciliation==='VERIFIED_UNDER_OWNER_ASSERTIONS'?'SOURCE-RECONCILED RECORD · under owner assertions':'SELF-REPORTED RECORD · arithmetic and signatures verified';
 let sublabel=null;
 if(!exit&&f.witness==='WITNESSED'){const e=c.selected_event;sublabel=`Record ${e?e.sequence:'?'} (${e?e.start:'?'} – ${e?e.end:'?'}) fetched from ${c.witness_host}; witness key ${c.witness_key_code}.`;}
 else if(!exit&&f.reconciliation==='VERIFIED_UNDER_OWNER_ASSERTIONS')sublabel='owner-supplied source bytes matched the signed event; the source is not authenticated';
 const qualifications=[];
 if(!exit){
  const add=(code,sentence,why)=>qualifications.push({code,reasons:why?[...why]:[],text:code+': '+sentence});
  if(c.other_effective_slots>0){if(f.witness==='WITNESSED')add('OTHER_PERIODS_NOT_WITNESSED',`${c.other_effective_slots} other effective periods in this record are not witnessed.`);else if(f.reconciliation==='VERIFIED_UNDER_OWNER_ASSERTIONS')add('OTHER_PERIODS_NOT_RECONCILED',`${c.other_effective_slots} other effective periods in this record are not source-reconciled.`);}
  if(f.witness==='WITNESS_NOT_ASSESSABLE')add('WITNESS_NOT_ASSESSABLE','The supplied witness receipt could not establish the source.',c.witness_reasons);
  switch(f.reconciliation){case 'NOT_ASSESSABLE':add('PRIVATE_SOURCE_NOT_ASSESSABLE','The supplied private-source check could not assess the selected event.',c.reconciliation_reasons);break;case 'INVALID_INPUT':add('PRIVATE_SOURCE_INPUT_INVALID','The supplied private-source input was invalid and was not used.',c.reconciliation_reasons);break;}
  if(c.continuity_anchor==='partial')add('CONTINUITY_ANCHOR_PARTIAL','Key linkage is valid; retained history anchors only part of the chain.');
  if(c.continuity_anchor==='not_supplied')add('CONTINUITY_ANCHOR_NOT_SUPPLIED','Key linkage is valid; no retained history anchor was supplied.');
 }
 let history='Not established';
 if(!recordFailed){history=f.continuity==='NONE'?'Valid for this key':'Valid across the supplied key chain';history+=' · '+(exit===2?'conflicts with your retained copy':f.comparison==='IDENTICAL'?'same as your retained copy':f.comparison==='EXTENDED'?'extends your retained copy':f.comparison==='NONE'?'no retained copy checked':'');history=history.replace(/ · $/,'');}
 const texts=[recordFailed?(c.record_reasons.includes('ARITHMETIC_NOT_REPRODUCED')?'Not reproduced':'Not established'):'Reproduced from disclosed returns',history,
 headline==='WITNESSED RECORD'?`Fetched by the witness from ${c.witness_host}; broker responses are not signed`:headline.startsWith('SOURCE-RECONCILED')?'Owner-supplied source bytes matched the signed event; the source is not authenticated':'Self-reported · not authenticated',
 c.expected_key==='matched'?'Expected key matches; identity unchecked':'Not established',
 c.timestamp_proof==='PENDING'?'Receipt timestamp proof binds the receipt; confirmation not verified':c.timestamp_proof==='INVALID'?'Supplied timestamp proof does not bind the receipt':'No independent evidence',
 'Supplied observations for the declared account only; lifetime inception unverified'+(c.gaps.length?` · ${c.gaps.length} gap(s) between disclosed periods`:'')];
 const ladder=['Calculations','Signatures and history','Source','Key','Time','Coverage'].map((row,i)=>Object.freeze({row,text:texts[i]}));
 qualifications.forEach(q=>{Object.freeze(q.reasons);Object.freeze(q);});
 return Object.freeze({version:'n170.verify.headline.v1',headline,code,exit,sublabel,qualifications:Object.freeze(qualifications),ladder:Object.freeze(ladder)});
}
