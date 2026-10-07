import { useEffect, useRef, useState } from 'react';
import { calculateEvidence, buildStampObservationEvidence, sampleInput } from './calculator.js';
import { createStoredProfile, listStoredProfiles, appendStoredRecord, deleteStoredProfile, getStoredEvidence } from './keyStore.js';
import { appendPerformanceStamp, appendCorrectionStamp, inspectProfile, profileKeyCode, publishedFingerprint, provenanceFromImport, normalizeProvenance } from './trackRecord.js';
import { buildEvidenceReviewPackage } from './reviewPackage.js';
import IndependentContinuityHelp from './IndependentContinuityHelp.jsx';
import DeviceContinuityPanel from './DeviceContinuityPanel.jsx';
import { importStatement, ibkrSampleInput } from './importer.js';
import { parseAgentHandoff } from './agentHandoff.js';
import AgentHandoffPanel from './AgentHandoffPanel.jsx';
import AccountPreparationHelp from './AccountPreparationHelp.jsx';
import IndependentVerifierHelp from './IndependentVerifierHelp.jsx';
import { extractAssistantReply, makeRepairPrompt, RECIPIENT_INSTRUCTIONS } from './assistantPrompt.js';
import instructions from '../docs/agent-instructions.txt?raw';
import CopyableText from './CopyableText.jsx';
import AccountReconciliationPanel from './AccountReconciliationPanel.jsx';
import { captureSource, reconcileAccount, makeReconciliationArtifact } from './reconciliation.js';
import { sha256Hex } from './signing.js';
import { readDraft, saveDraft } from './draftStore.js';
import { Dialog, EvidenceRail, Metrics, Notice, ReturnChart, download } from './ui.jsx';

import { createEmptyDraft as empty, hydratePrivateDraft, retainSource } from './reconciliationDraft.js';
const serialize = value => JSON.stringify(value);
export default function OwnerWorkspace({ registerGuard, onReview }) {
  const [draft, setDraft] = useState(empty);
  const [saved, setSaved] = useState(serialize(empty()));
  const [draftRevision, setDraftRevision] = useState(0);
  const [draftReady, setDraftReady] = useState(false);
  const [stored, setStored] = useState([]), [active, setActive] = useState(null);
  const [name, setName] = useState(''), [step, setStep] = useState(1);
  const [imported, setImported] = useState(null), [report, setReport] = useState(null);
  const [message, setMessage] = useState(''), [error, setError] = useState(''), [busy, setBusy] = useState(false);
  const [consent, setConsent] = useState(false), [pending, setPending] = useState(null), [deleting, setDeleting] = useState(false);
  const [edit, setEdit] = useState(null), [correctionTarget, setCorrectionTarget] = useState(''), [correctionReason, setCorrectionReason] = useState('');
  const [copied, setCopied] = useState(false);
  const [repairIssues, setRepairIssues] = useState(null);
  const [entryMode, setEntryMode] = useState(null), [reviewRequest, setReviewRequest] = useState(0);
  const [accountReview, setAccountReview] = useState(null), [checkingAccount, setCheckingAccount] = useState(false);
  const reviewHeading = useRef(null);
  const generation = useRef(0), heading = useRef(null);
  const dirty = serialize(draft) !== saved;
  const profile = active?.profile;
  const canSignHere = !!active && (!active.lifecycle || active.lifecycle==='active');
  const isAgentHandoff = draft.format === 'agent-handoff';
  const startMode = entryMode || ((draft.original || draft.input) && !isAgentHandoff ? 'file' : 'ai');
  const hasData = !!(draft.original || draft.input || draft.reconciliation.sources.length);
  const rows = draft.input ? draft.input.trim().split(/\r?\n/).slice(1).map(line => line.split(',')) : isAgentHandoff ? (imported?.rows || []).map(row=>[row.date,row.nav,row.flow]) : [];
  function resetResult() { setRepairIssues(null); setReport(null); setConsent(false); setError(''); setStep(1); }
  function change(patch) { generation.current++; setAccountReview(null); setDraft(d => ({ ...d, ...patch })); resetResult(); }
  function restoreSavedState() { const data=JSON.parse(saved);generation.current++;setDraft(data);setImported(data.importReview || null);setReport(null);setConsent(false);setCorrectionTarget('');setCorrectionReason('');setStep(1); }
  function guard(action) { if (dirty) setPending(() => action); else action(); }
  useEffect(() => { registerGuard(guard); return () => registerGuard(null); });
  useEffect(() => { const before = event => { if (dirty) { event.preventDefault(); event.returnValue = ''; } }; window.addEventListener('beforeunload', before); return () => window.removeEventListener('beforeunload', before); }, [dirty]);
  useEffect(() => {
    let alive = true; const restoreGeneration = generation.current;
    readDraft().then(async value => { if (!alive || generation.current !== restoreGeneration) return; if (value) { const checked = await hydratePrivateDraft({kind:'n170.private-draft.v1',data:value.data}); if (!alive || generation.current !== restoreGeneration) return; setDraft(checked); setImported(checked.importReview); setSaved(serialize(checked)); setDraftRevision(value.revision); setMessage('Saved private draft restored in this browser.'); } }).catch(cause => alive && setError(cause.message)).finally(() => alive && setDraftReady(true));
    listStoredProfiles().then(value => alive && setStored(value), cause => alive && setError(cause.message));
    return () => { alive = false; generation.current++; };
  }, []);
  useEffect(() => { if(step !== 1) heading.current?.focus(); }, [step]);
  useEffect(() => { if(reviewRequest) reviewHeading.current?.focus(); }, [reviewRequest]);
  useEffect(() => {
    let alive = true;
    setAccountReview(null);
    if (!draft.original && !draft.input && !draft.reconciliation.sources.length) { setCheckingAccount(false); return; }
    setCheckingAccount(true);
    reconcileAccount({ ...draft, ...draft.reconciliation, accountScope:draft.scope, frequency:Number(draft.frequency) })
      .then(value=>{if(alive)setAccountReview(value);})
      .catch(cause=>{if(alive)setError(`Private reconciliation could not finish: ${cause.message}`);})
      .finally(()=>{if(alive)setCheckingAccount(false);});
    return ()=>{alive=false;};
  }, [draft]);
  async function refresh() { const entries = await listStoredProfiles(); setStored(entries); return entries; }
  async function continuityChanged(entry = null) {
    generation.current++; setConsent(false); setReport(null); setStep(1);
    const entries = await refresh();
    if(entry) setActive(entries.find(value=>value.profile.profile_id===entry.profile.profile_id) || entry);
    else if(active) setActive(entries.find(value=>value.profile.profile_id===active.profile.profile_id) || null);
  }
  async function currentEvidence() {
    if(!profile) throw new Error('Open a saved profile first.');
    return getStoredEvidence(profile.profile_id);
  }
  async function refreshAfterSuccess() { try { await refresh(); } catch { setError('The change was saved, but the profile list could not be refreshed. Reopen the saved profile when storage is available.'); } }
  async function run(action) { if (busy) return; setBusy(true); setError(''); setMessage(''); try { await action(); } catch (cause) { setError(cause.message); } finally { setBusy(false); } }
  async function save() { const checked = await hydratePrivateDraft({kind:'n170.private-draft.v1',data:draft}); const value = await saveDraft(checked, draftRevision); setDraft(checked);setImported(checked.importReview);setDraftRevision(value.revision); setSaved(serialize(checked)); setMessage('Private draft saved in this browser. Raw data is stored locally and is not encrypted by this app.'); }
  function exportDraft() { download(serialize({kind:'n170.private-draft.v1',data:draft}), 'n170-private-draft.json'); setMessage('Private draft downloaded. It includes original financial data; keep it private. It contains no signing key.'); }
  async function reopen() { const value = await readDraft(); const data=value ? await hydratePrivateDraft({kind:'n170.private-draft.v1',data:value.data}) : empty(); setDraft(data); setSaved(serialize(data)); setDraftRevision(value?.revision || 0); setImported(data.importReview); resetResult(); }
  function sourceHistoryForReplacement() {
    let settings = draft.reconciliation;
    if (draft.original || draft.input) settings = retainSource(settings, {text:draft.original || draft.input,fileName:draft.fileName || 'Previous manual observations',format:draft.format,disposition:'unresolved',reason:''});
    return settings;
  }
  function keepRejectedSource(source, message) {
    let reconciliation;
    try { reconciliation = retainSource(draft.reconciliation, {...source,disposition:'unresolved',reason:''}); }
    catch (cause) {
      if(draft.reconciliation.sources.length>=20) { setError(`${message} Source inventory capacity has been reached; this scope stays blocked. Export the current reconciliation and retain the attempted file separately.`); return; }
      reconciliation = retainSource(draft.reconciliation, {text:'',fileName:source.fileName,unconsumed:{byteLength:source.byteLength ?? source.unconsumed?.byteLength ?? new TextEncoder().encode(source.text || '').length,reason:`Bytes could not be retained: ${cause.message}`.slice(0,500)}});
    }
    change({reconciliation});
    setError(`${message} Your current observations are unchanged. The attempted source is retained as an unresolved scope item.`);
  }
  async function prepareHandoff(text, fileName) {
    const { handoff, review } = await parseAgentHandoff(text);
    if((draft.original || draft.input) && !review.canCalculate) throw new Error(review.exceptions.filter(item=>item.severity==='error').map(item=>item.message).join(' ') || 'The replacement handoff has unresolved source evidence.');
    const result = await importStatement(text, {format:'agent-handoff', currency:handoff.currency, frequency:handoff.frequency, flowTimingConfirmed:false, fileName});
    return {data:{...empty(),original:text,fileName,format:'agent-handoff',currency:handoff.currency,frequency:String(handoff.frequency),scope:handoff.account_scope,synthetic:handoff.synthetic},result};
  }
  function acceptPreparedSource(prepared) {
    const history = sourceHistoryForReplacement();
    const incoming = prepared.data.reconciliation;
    let settings = {...incoming,sources:history.sources};
    for (const source of incoming.sources) settings = retainSource(settings, source);
    const apply = () => {
      change({...prepared.data,reconciliation:settings});
      setImported(prepared.result || prepared.data.importReview); setEntryMode(prepared.data.format==='agent-handoff'?'ai':'file'); setReviewRequest(value=>value+1);
      setMessage(prepared.message || 'File opened locally. Review its scope, currency and cash activity, then reconcile. Nothing has been signed.');
    };
    if(draft.original || draft.input) guard(apply); else apply();
  }
  function openPastedHandoff() {
    const text = draft.handoffText, token = generation.current;
    return run(async () => {
      let prepared;
      try { prepared = await prepareHandoff(extractAssistantReply(text), 'assistant-handoff.json'); }
      catch (cause) { if(token!==generation.current)return; keepRejectedSource({text,fileName:'Rejected assistant reply',format:'agent-handoff'},cause.message); setRepairIssues(cause.errors || [{code:'invalid_json'}]); return; }
      if(token!==generation.current)return;
      try { acceptPreparedSource(prepared); }
      catch(cause) { keepRejectedSource({text,fileName:'Rejected assistant reply',format:'agent-handoff'},cause.message); }
    });
  }
  async function chooseFile(event) {
    const file = event.target.files?.[0]; event.target.value = ''; if (!file) return;
    const token = generation.current;
    await run(async () => {
      if (file.size > (/\.json$/i.test(file.name) ? 16000000 : 1000000)) { keepRejectedSource({text:'',fileName:file.name,unconsumed:{byteLength:file.size,reason:'File exceeds the intake limit; its bytes were not consumed.'}}, 'Choose CSV or assistant JSON up to 1 MB, or a private draft up to 16 MB.'); return; }
      let bytes;
      try { bytes = new Uint8Array(await file.arrayBuffer()); }
      catch (cause) { if(token===generation.current)keepRejectedSource({text:'',fileName:file.name,unconsumed:{byteLength:file.size,reason:'The browser could not read this selected file; its bytes are unavailable.'}}, `The selected file could not be read: ${cause.message}`); return; }
      if(token!==generation.current)return;
      let text;
      try { text = new TextDecoder('utf-8', {fatal:true,ignoreBOM:true}).decode(bytes); }
      catch {
        const captured = await captureSource({bytes,fileName:file.name,currency:draft.currency,frequency:Number(draft.frequency)});
        if(token!==generation.current)return;
        keepRejectedSource({text:'',rawBytesBase64:captured.bytes_base64,fileName:file.name,byteLength:bytes.length},'This file is not valid UTF-8 text. Export it as UTF-8 and choose it again.'); return;
      }
      let prepared;
      try {
        if (/\.json$/i.test(file.name)) {
          const parsed = JSON.parse(text.replace(/^\uFEFF/,''));
          if (parsed?.schema_version === 'n170.agent-handoff.v1') prepared = await prepareHandoff(text, file.name);
          else {
            const restored = await hydratePrivateDraft(parsed);
            const data = await hydratePrivateDraft({kind:'n170.private-draft.v1',data:{...restored,flowTimingConfirmed:false,reconciliation:{...restored.reconciliation,flowActivity:'unknown',flowTiming:'unknown'}}});
            prepared = {data,result:data.importReview,message:'Private draft opened. Source review must be confirmed again before signing.'};
          }
        } else {
          // Validate the candidate before the replacement decision. Owner review
          // remains false; unsupported rows stay attached to the attempted source.
          const result = await importStatement(text,{currency:draft.currency,frequency:draft.frequency,flowTimingConfirmed:true,fileName:file.name});
          if(!result.canCalculate && (draft.original || draft.input)) throw new Error(result.exceptions.filter(item=>item.severity==='error').map(item=>item.message).join(' ') || 'The replacement source cannot be reconciled.');
          prepared = {data:{...empty(),original:text,fileName:file.name,currency:draft.currency,frequency:draft.frequency},result:null};
        }
      } catch(cause) {
        if(token!==generation.current)return;
        if(bytes.length>1000000) { keepRejectedSource({text:'',fileName:file.name,unconsumed:{byteLength:bytes.length,reason:'Rejected private draft exceeds the source-retention limit; its bytes were not retained.'}},cause.message); return; }
        keepRejectedSource({text,fileName:file.name,format:'auto'},cause.message); setRepairIssues(cause.errors || [{code:'invalid_source'}]); return;
      }
      if(token!==generation.current)return;
      try { acceptPreparedSource(prepared); }
      catch(cause) {
        keepRejectedSource(bytes.length>1000000 ? {text:'',fileName:file.name,unconsumed:{byteLength:bytes.length,reason:'The replacement inventory exceeds workspace capacity; its original bytes were not retained.'}} : {text,fileName:file.name},cause.message);
      }
    });
  }
  async function reconcile() {
    const token = generation.current;
    await run(async () => {
      if(draft.original && imported && draft.corrections.length) throw new Error('This workspace has corrected observations. Clear the workspace explicitly to reimport; your corrections have been kept.');
      const result = await importStatement(draft.original || draft.input, { format: draft.format, currency: draft.currency, frequency: draft.frequency, flowTimingConfirmed: draft.flowTimingConfirmed, fileName: draft.fileName });
      if (token !== generation.current) return;
      setImported(result); setReport(null); setConsent(false);
      if (result.canCalculate && draft.corrections.length) { const first=draft.corrections[0],last=draft.corrections.at(-1); if(first.previous_sha256 !== result.review.normalized_sha256 || last.replacement_sha256 !== await sha256Hex(new TextEncoder().encode(draft.input))) throw new Error('The private correction history does not match this source. Review the original and corrected observations.'); result.normalizedCsv=draft.input; }
      if (result.canCalculate) { setDraft(d => ({ ...d, input: result.normalizedCsv, importReview: result, corrections: [...d.corrections, ...(result.corrections || []).map(c => ({row:c.row || 0,field:c.field || 'row',reason:c.reason || c.message || 'Reviewed import normalization',previous_sha256:c.previous_source_sha256,replacement_sha256:c.replacement_source_sha256}))] })); setMessage('Reconciliation complete. Review the observations and exceptions before continuing.'); }
    });
  }
  async function openProfile(id) { const entries = await refresh(); const entry = entries.find(item => item.profile.profile_id === id); if (!entry) throw new Error('This profile is no longer stored here. Choose another profile.'); await inspectProfile(serialize(entry.profile)); setActive(entry); setConsent(false); setCorrectionTarget(''); setMessage(`Opened ${entry.profile.display_name}. Its saved records passed their checks.`); }
  function create() { return run(async () => { const entry = await createStoredProfile(name.trim()); setActive(entry); setName(''); await refreshAfterSuccess(); setMessage('Profile created and saved. Its signing key stays in this browser; a profile export is not a key backup.'); }); }
  function calculate() {
    const token = generation.current;
    return run(async () => {
      if (draft.original && !imported?.canCalculate) throw new Error('Reconcile this supplied file before calculating.');
      if (!draft.scope.trim()) throw new Error('Describe which accounts this period covers, using an alias rather than an account number.');
      const checked = await reconcileAccount({...draft,...draft.reconciliation,accountScope:draft.scope,frequency:Number(draft.frequency)});
      if(token!==generation.current)return;
      setAccountReview(checked);
      if(!checked.canCalculate) throw new Error('This selected scope has unresolved evidence. Review the retained source attempts and interval reasons before calculating.');
      const next = calculateEvidence(draft.input, Number(draft.frequency)); setReport(next); setConsent(false); setStep(2); setError('');
    });
  }
  async function provenance() {
    const base = imported ? provenanceFromImport(imported, { accountScope: draft.scope.trim(), reviewed: true }) : { ...normalizeProvenance(), account_scope: draft.scope.trim(), currency: draft.currency, reviewed: true };
    if (imported) base.normalized_sha256 = await sha256Hex(new TextEncoder().encode(draft.input));
    base.corrections = draft.corrections.map(c => ({row:c.row,field:c.field,reason:c.reason,previous_sha256:c.previous_sha256,replacement_sha256:c.replacement_sha256}));
    return base;
  }
  async function sign() {
    if (!active || !consent || !report) return;
    if(!canSignHere) {setError('This local key is pending, cancelled or retired and cannot sign new records.');return;}
    const token = generation.current;
    await run(async () => {
      const checked = await reconcileAccount({...draft,...draft.reconciliation,accountScope:draft.scope,frequency:Number(draft.frequency)});
      if(!checked.canCalculate) throw new Error('Source reconciliation is blocked. Return to observations and retain the unresolved intervals. Nothing was signed.');
      const options = {provenance:await provenance(),reason:correctionReason,synthetic:draft.synthetic};
      const next = correctionTarget ? await appendCorrectionStamp(profile, Number(correctionTarget), draft.input, Number(draft.frequency), active.signer, options) : await appendPerformanceStamp(profile, draft.input, Number(draft.frequency), active.signer, options);
      if (token !== generation.current) throw new Error('The input changed while signing. Review the new calculation and try again.');
      const signed=next.stamps.at(-1).payload.metrics; if(signed.total_return_twr_e8/1e8 !== report.metrics.total_return_twr || signed.max_drawdown_e8/1e8 !== report.metrics.max_drawdown || (signed.annualized_volatility_e8===null?null:signed.annualized_volatility_e8/1e8) !== report.metrics.annualized_volatility) throw new Error('The displayed calculation changed. Recalculate and review it before signing. Nothing was saved.');
      await appendStoredRecord(next); setActive({...active,profile:next}); setConsent(false); setStep(3); await refreshAfterSuccess();
      setMessage('Signed record saved atomically in this browser. Download a review package to share or retain a copy.');
    });
  }
  async function applyEdit() {
    if (!edit.reason.trim() || edit.reason.trim().length < 3) { setError('Explain the correction in at least three characters.'); return; }
    const lines = draft.input.trim().split(/\r?\n/); const cells = lines[edit.index + 1].split(','); const before = draft.input; if(cells[edit.column] === edit.value.trim()) { setEdit(null); setMessage('No value changed; no correction was added.'); return; } cells[edit.column] = edit.value.trim(); lines[edit.index + 1] = cells.join(',');
    change({ input: lines.join('\n'), corrections: [...draft.corrections, {row:edit.index + 1,field:['date','nav','external_flow'][edit.column],reason:edit.reason.trim(),before,after:lines.join('\n'),previous_sha256:await sha256Hex(new TextEncoder().encode(before)),replacement_sha256:await sha256Hex(new TextEncoder().encode(lines.join('\n')))}] }); setEdit(null);
  }
  const sourceCanCalculate = (!draft.original || imported?.canCalculate) && accountReview?.canCalculate && !checkingAccount && draft.reconciliation.sources.length<20;
  const blockedIssues = repairIssues || imported?.exceptions?.filter(item=>item.severity === 'error') || [];
  const repairHelp = blockedIssues.length > 0 && <section className="repair-help" aria-labelledby="repair-heading"><h3 id="repair-heading">A clear next step</h3><p>Send your AI the checks that need attention. This prompt includes issue categories and instructions; it excludes your source values, dates, account labels and tool metadata. Missing evidence stays blocked.</p><CopyableText key={JSON.stringify(blockedIssues.map(item=>item.code))} id="repair-prompt" title="Repair prompt for your AI" text={makeRepairPrompt(blockedIssues,instructions)} action="Copy what needs fixing" fileName="n170-verify-repair-prompt.txt" busy={busy}/></section>;
  return <div>
    <div className="page-intro"><h1>Your performance,<br className="mobile-break"/> clearly explained.</h1><p>Prepare a private, reproducible record. Give the reader the evidence and the limits.</p></div>
    <ol className="steps" aria-label="Preparation progress">{['Import & reconcile','Review & sign','Share'].map((label,index) => <li key={label} aria-current={step === index + 1 ? 'step' : undefined}><span>{index+1}</span>{label}</li>)}</ol>
    <div className="workspace-layout"><div>
      <div className="draft-bar"><span role="status">{!draftReady ? 'Checking local storage…' : dirty ? 'Unsaved private draft' : 'Private draft up to date'}</span><div><button className="text-button" disabled={busy || !draftReady} onClick={() => run(save)}>Save draft</button><button className="text-button" disabled={busy} onClick={exportDraft}>Export private draft</button><button className="text-button" disabled={busy} onClick={() => guard(() => run(reopen))}>Reopen saved draft</button></div></div>
      <Notice error>{error}</Notice><Notice>{message}</Notice>
      {step === 1 && <section className="paper"><h2 ref={heading} tabIndex={-1}>Start with your data</h2><p>Your file stays in this browser. You decide what to share.</p>
        <div className="entry-choice" role="group" aria-label="Choose how to start"><button aria-label="Ask your AI" aria-pressed={startMode === 'ai'} onClick={()=>setEntryMode('ai')}>Ask your AI<span>Use your existing broker connection</span></button><button aria-label="Import a file" aria-pressed={startMode === 'file'} onClick={()=>setEntryMode('file')}>Import a file<span>Use an export or enter observations</span></button></div>
        {startMode === 'ai' && <AgentHandoffPanel value={draft.handoffText} onChange={value=>change({handoffText:value})} onOpen={openPastedHandoff} onFile={chooseFile} prepared={isAgentHandoff && hasData} busy={busy}/>}
        {startMode === 'file' && <><div className="upload-zone"><svg width="30" height="36" viewBox="0 0 30 36" fill="none" aria-hidden="true"><path d="M5 1h13l7 7v26H5zM18 1v8h7" stroke="currentColor" strokeWidth="1.5"/></svg><label className="button primary file-label">Choose export file<input type="file" accept=".csv,.txt,.json" onChange={chooseFile} disabled={busy}/></label><p>CSV / assistant JSON up to 1 MB · private draft up to 16 MB</p><button className="text-button" disabled={busy} onClick={() => run(()=>acceptPreparedSource({data:{...empty(),input:sampleInput,scope:'Synthetic example portfolio',synthetic:true,flowTimingConfirmed:true,reconciliation:{...empty().reconciliation,flowActivity:'reviewed_no_hidden',flowTiming:'interval_end'}}}))}>Try a synthetic example</button><button className="text-button" disabled={busy} onClick={() => run(()=>acceptPreparedSource({data:{...empty(),original:ibkrSampleInput,fileName:'ibkr-flex-synthetic.csv',scope:'Synthetic example portfolio',synthetic:true}}))}>Try an IBKR export example</button></div>
        <details open={!draft.original && !!draft.input}><summary>Or enter observations manually</summary><label htmlFor="observations">Date, net asset value, external flow</label><p id="input-help">2–500 observations. One currency. Deposits positive; withdrawals negative. A valuation is required at each flow. Opening flow must be zero.</p><textarea id="observations" aria-describedby="input-help" spellCheck="false" maxLength={50000} value={draft.input} disabled={!!draft.original || draft.corrections.length > 0 || busy} onChange={event => change({input:event.target.value,synthetic:false})} placeholder={'date,nav,external_flow\n2026-01-01,100,0\n2026-01-02,101,0'}/>{draft.corrections.length>0&&<p>Use row corrections to keep the edit history intact, or explicitly clear the workspace to begin a new input.</p>}</details></>}
        {repairIssues && repairHelp}
        {hasData && draft.fileName && <p className="file-caption">Selected locally: <strong>{draft.fileName}</strong></p>}
        {(hasData || startMode === 'file') && <><div className="form-grid"><div><label htmlFor="currency">Reporting currency</label><select id="currency" value={draft.currency} disabled={busy || isAgentHandoff} onChange={event => {change({currency:event.target.value,importReview:null});setImported(null);}}>{['USD','EUR','GBP','CHF','CAD','AUD','JPY'].map(c => <option key={c}>{c}</option>)}</select></div><div><label htmlFor="frequency">Observation frequency</label><select id="frequency" value={draft.frequency} disabled={busy || isAgentHandoff} onChange={event => change({frequency:event.target.value})}><option value="252">Trading daily · 252/year</option><option value="365">Calendar daily · 365/year</option><option value="52">Weekly · 52/year</option><option value="12">Monthly · 12/year</option><option value="4">Quarterly · 4/year</option><option value="1">Yearly · 1/year</option></select></div></div>
        {isAgentHandoff && <p>Currency and frequency come from the handoff. Correct those in the source and load a new handoff if they are wrong.</p>}
        <label htmlFor="scope">Accounts covered, using public aliases</label><input id="scope" maxLength={160} value={draft.scope} disabled={busy} onChange={event => change({scope:event.target.value})} placeholder="e.g. My long-term investment account"/><p>Only this declared scope is shared. Do not enter account numbers. Undisclosed accounts remain unknown.</p><AccountPreparationHelp/>
        {draft.original && <><label className="check-row"><input type="checkbox" checked={draft.flowTimingConfirmed && draft.reconciliation.flowActivity==='reviewed_no_hidden' && draft.reconciliation.flowTiming==='interval_end'} disabled={busy} onChange={event => {change({flowTimingConfirmed:event.target.checked,reconciliation:{...draft.reconciliation,flowActivity:event.target.checked?'reviewed_no_hidden':'unknown',flowTiming:event.target.checked?'interval_end':'unknown'},importReview:null});setImported(null);}}/><span>{isAgentHandoff ? 'I reviewed the assistant’s field mappings, valuation dates, account scope and complete cash activity against the source. No offsetting flows are hidden; external flows occur at interval end.' : 'I checked cash activity: no offsetting flows are hidden, and any external flows occur at interval end. Otherwise I need valuations at each flow.'}</span></label><button className="button secondary" disabled={busy} onClick={reconcile}>{busy ? 'Reconciling…' : 'Reconcile file'}</button></>}
        <section className="reconciliation"><h3 ref={reviewHeading} tabIndex={-1}>Reconciliation</h3>{draft.synthetic && <p className="synthetic">Synthetic example · no real account</p>}{!draft.input && !imported && <p className="empty-state">Choose an export to see its mappings, supported observations and anything that needs attention.</p>}
          {imported && <><p>{imported.label || imported.format} · supplied-file evidence</p>{imported.coverage && <dl className="coverage"><div><dt>Source file coverage</dt><dd>{imported.coverage.source_rows} source rows · {imported.coverage.observations} parsed observations</dd></div><div><dt>Source observation dates</dt><dd>{imported.coverage.start || 'Not available'} — {imported.coverage.end || 'Not available'}</dd></div></dl>}<p>{imported.canCalculate ? 'Input checks permit a calculation under the stated assumptions.' : 'Calculation blocked: resolve the missing or unsupported evidence below.'} Counts describe this supplied file; they do not establish complete coverage. Current reviewed values, including any corrections, appear below.</p><ul className="exceptions">{(imported.exceptions || []).map((item,i) => <li key={i} className={item.severity === 'error' ? 'blocking' : ''}><strong>{item.severity === 'error' ? 'Needs attention: ' : ''}</strong>{item.message} {item.action}</li>)}</ul>{!repairIssues && repairHelp}{imported.agentContext && <details open><summary>Assistant-reported source · review privately</summary><dl className="record-facts"><div><dt>Broker / connector claim</dt><dd>{imported.agentContext.source.broker} / {imported.agentContext.source.connector}</dd></div><div><dt>Tools reported</dt><dd>{imported.agentContext.source.tools.join(', ') || 'No tools reported'}</dd></div><div><dt>Retrieval time claim</dt><dd>{imported.agentContext.source.retrieved_at || 'No retrieval reported'} · not independently witnessed</dd></div><div><dt>Requested dates</dt><dd>{imported.agentContext.requested_period.start} — {imported.agentContext.requested_period.end}</dd></div><div><dt>Pagination claim</dt><dd>{imported.agentContext.coverage.pagination} · not independently established</dd></div></dl><h4>Fields mapped by your assistant</h4><ul>{Object.entries(imported.agentContext.mapping).map(([field,path])=><li key={field}><code>{path}</code> → {field}</li>)}</ul>{(imported.agentContext.coverage.missing_periods.length>0 || imported.agentContext.coverage.unsupported_events.length>0) && <div className="notice error"><h4>Missing or unsupported evidence</h4><ul>{imported.agentContext.coverage.missing_periods.map((period,i)=><li key={`gap-${i}`}>{period.start} — {period.end}: {period.reason}</li>)}{imported.agentContext.coverage.unsupported_events.map((event,i)=><li key={`event-${i}`}>{event}</li>)}</ul></div>}<details><summary>Observation references · private</summary><ol>{(imported.rows || []).map((row,i)=><li key={i}>{row.date}: <code>{row.sourceRef}</code></li>)}</ol></details><p>Check the source valuation time, total account equity and external cash activity. Live versus paper account status is not established by this handoff. These source paths, tool names and retrieval claims stay in the private handoff; the shared record includes its digest and the fixed handoff column names.</p></details>}<details><summary>Column mapping & source evidence</summary><ul>{(imported.mapping || []).map((item,i)=><li key={i}><code>{item.source}</code> → {item.target}{item.explanation ? `: ${item.explanation}` : ''}</li>)}</ul><p>No currency conversion. Hashes identify the selected UTF-8 source text; they do not establish who created them.</p><code className="hash">{imported.source?.sha256 || imported.source?.original_sha256}</code></details></>}
          {rows.length > 0 && <><div className="table-scroll"><table><caption>Review observations · account values stay private</caption><thead><tr><th>Date</th><th>NAV</th><th>External flow</th><th>Review</th></tr></thead><tbody>{rows.slice(0,500).map((row,i)=><tr key={i}>{row.map((cell,j)=><td key={j}>{cell}</td>)}<td><button className="text-button" disabled={busy || !draft.input} aria-label={`Correct row ${i+1}`} onClick={() => setEdit({index:i,column:1,value:row[1],reason:''})}>Correct</button></td></tr>)}</tbody></table></div><p>Transfers are flows, not gains. Fees and taxes affect returns only when already reflected in NAV. Original amounts and edits remain private unless you export the private draft.</p></>}
          {draft.corrections.length > 0 && <details open><summary>{draft.corrections.length} reviewed input correction(s)</summary><ul>{draft.corrections.map((c,i)=><li key={i}>Row {c.row}, {c.field}: {c.reason}</li>)}</ul></details>}
        </section>
        <AccountReconciliationPanel draft={draft} result={accountReview} checking={checkingAccount} busy={busy} onChange={settings=>change({reconciliation:settings,flowTimingConfirmed:settings.flowActivity==='reviewed_no_hidden' && settings.flowTiming==='interval_end'})} onResolve={({index,disposition,reason})=>change({reconciliation:{...draft.reconciliation,sources:draft.reconciliation.sources.map((source,i)=>i===index?{...source,disposition,reason:reason.trim()}:source)}})} onExport={()=>{download(serialize(makeReconciliationArtifact(accountReview)),'n170-private-reconciliation.json');setMessage('Private reconciliation downloaded. It includes original financial data and retained unresolved sources; it is not encrypted.');}}/>
        <div className="actions"><button className="button primary" disabled={!draft.input || !sourceCanCalculate || busy} onClick={calculate}>Review calculation</button><button className="text-button" disabled={busy} onClick={() => guard(() => {change(empty());setImported(null);})}>Clear workspace</button></div></>}
      </section>}
      {step === 2 && report && <section className="paper"><h2 ref={heading} tabIndex={-1}>Review before you sign</h2><p>{report.calculation_version} calculation rules · {draft.currency} · {draft.scope}</p><p>The signed record covers the selected observation boundaries only. Private rejected-source decisions and source rows are not added to the shared profile. Whole-account completeness and broker authenticity remain unestablished.</p><Metrics metrics={report.metrics}/>{draft.synthetic && <p className="synthetic">Synthetic example · no real account</p>}<dl className="coverage"><div><dt>Reviewed observations</dt><dd>{report.coverage.nav_observations} NAV observations · {report.coverage.return_observations} return intervals</dd></div><div><dt>Disclosed external flows</dt><dd>{report.coverage.external_cash_flow_count} observations with a nonzero net external flow</dd></div></dl><p>{report.metrics.total_return_twr < 0 ? 'This disclosed period has a loss. Keep it in the record.' : 'Keep losing intervals and periods in the record, including when the total return is positive.'} These counts cannot reveal hidden offsetting flows or missing accounts. Drawdown covers sampled observations only.</p><Notice>{report.annualization?.reason}</Notice><ReturnChart returns={buildStampObservationEvidence(draft.input,Number(draft.frequency)).relative_returns}/><details><summary>Method and limitations</summary><ul>{report.warnings.map(text=><li key={text}>{text}</li>)}</ul><p>Public evidence reproduces rounded returns → metrics. It cannot reproduce private NAV → returns without the original draft. An aggregate summary alone is not a reproducible record.</p><button className="text-button" onClick={() => download(serialize(report),'n170-aggregate-summary-not-reproducible.json')}>Download aggregate summary only</button></details>
        <div className="profile-section"><h3>{profile ? profile.display_name : 'Choose a signing profile'}</h3>{!profile ? <><p>Create a public alias. No account or cryptographic setup is needed.</p>{stored.length>0 && <ul className="profile-list">{stored.filter(entry=>!entry.lifecycle || entry.lifecycle==='active').map(({profile:p})=><li key={p.profile_id}><span>{p.display_name}<small>{p.stamps.length} saved records</small></span><button className="button secondary" disabled={busy} onClick={() => run(()=>openProfile(p.profile_id))}>Open</button></li>)}</ul>}<form onSubmit={e=>{e.preventDefault();create();}}><label htmlFor="profile-name">Public profile alias</label><input id="profile-name" required maxLength={80} value={name} disabled={busy} onChange={e=>setName(e.target.value)} placeholder="e.g. Alex · long-term portfolio"/><button className="button secondary" disabled={busy || !name.trim()}>Create profile</button></form></> : <><p className="key-line">Key <code>{profileKeyCode(profile)}</code> · {profile.stamps.length} saved records</p><div className="actions"><button className="text-button" disabled={busy} onClick={()=>guard(()=>{setActive(null);setConsent(false);})}>Close / switch profile</button><button className="text-button danger" disabled={busy} onClick={()=>setDeleting(true)}>Delete local key & records</button></div>{profile.stamps.length>0 && <><label htmlFor="record-kind">Record purpose</label><select id="record-kind" value={correctionTarget} onChange={e=>{setCorrectionTarget(e.target.value);setConsent(false);}} disabled={busy}><option value="">Add a new period</option>{profile.stamps.filter(s=>!profile.stamps.some(x=>x.payload.correction?.target_sequence===s.payload.sequence)).map(s=><option key={s.payload.sequence} value={s.payload.sequence}>Correct record {s.payload.sequence} · {s.payload.period.start} to {s.payload.period.end}</option>)}</select>{correctionTarget && <><label htmlFor="correction-reason">Public reason for correction</label><textarea id="correction-reason" maxLength={500} value={correctionReason} onChange={e=>{setCorrectionReason(e.target.value);setConsent(false);}}/><p>The original remains in history. The corrected record must keep the same period boundaries.</p></>}</>}</>}
        <p className="boundary">A review package backs up evidence, not your signing key. Change devices while the old key still exists using the device-change panel below. A lost old key cannot recover continuity. Local retirement is not cryptographic revocation.</p>{active?.lifecycle && active.lifecycle!=='active' && <Notice error>This key is {active.lifecycle} locally. It cannot sign new records.</Notice>}{active?.continuity?.boundary && <p>New-key performance must begin on or after {active.continuity.boundary}. Corrections can only address records within this key segment.</p>}</div>
        <label className="check-row"><input type="checkbox" checked={consent} onChange={e=>setConsent(e.target.checked)} disabled={!canSignHere || busy}/><span>I reviewed the calculation, flow treatment and account scope. Share my alias, dates, rounded interval returns, field mappings, input correction reasons, source digest and signatures. Keep balances and original file private.</span></label><div className="actions"><button className="button primary" disabled={!canSignHere||!consent||busy||(correctionTarget&&correctionReason.trim().length<3)} onClick={sign}>{busy?'Signing & saving…':correctionTarget?'Sign correction & save':'Sign record & save'}</button><button className="text-button" disabled={busy} onClick={()=>{setStep(1);setConsent(false);}}>Back to observations</button></div>
      </section>}
      {step === 3 && profile && <section className="paper"><h2 ref={heading} tabIndex={-1}>Ready for a thoughtful review.</h2><p>Your signed record is saved here. Share a readable package with embedded evidence for independent checking.</p><Metrics metrics={profile.stamps.at(-1).payload.metrics} units/><div className="actions"><button className="button primary" disabled={busy} onClick={()=>run(async()=>download(await buildEvidenceReviewPackage(await currentEvidence()),`n170-review-${profileKeyCode(profile)}.html`,'text/html'))}>Download review package</button><button className="button secondary" onClick={()=>run(async()=>onReview(serialize(await currentEvidence())))}>Open employer review</button></div><p>Download and inspect the package before sending it yourself. No public page is created.</p><details className="recipient-help"><summary>Include a short note for your reviewer</summary><p>Help the recipient open, check and retain the evidence. No account or command line is needed.</p><CopyableText id="recipient-instructions" title="Note for your reviewer" text={RECIPIENT_INSTRUCTIONS} action="Copy review instructions" fileName="n170-review-instructions.txt"/></details>{active.continuity?.transitionCount ? <IndependentContinuityHelp/> : <IndependentVerifierHelp/>}<details><summary>Machine-readable record & retained checkpoint</summary><button className="text-button" onClick={()=>run(async()=>download(serialize(await currentEvidence()),`n170-profile-${profileKeyCode(profile)}.json`))}>Download signed JSON</button><code className="hash">{publishedFingerprint(profile)}</code><button className="text-button" onClick={()=>run(async()=>{await navigator.clipboard.writeText(publishedFingerprint(profile));setCopied(true);})}>{copied?'Checkpoint copied':'Copy checkpoint'}</button><p>Ask the recipient to keep this file and compare the next one with it. A copied checkpoint does not establish when it was published.</p></details><div className="actions"><button className="text-button" onClick={()=>{if(report)setStep(2);else{setStep(1);setMessage('Open the private draft for the period you want to correct, review its inputs, then select the original record.');}}}>Review / correct this period</button><button className="text-button" onClick={()=>setStep(1)}>Prepare another period</button><button className="text-button" onClick={()=>guard(()=>{setActive(null);setConsent(false);setStep(1);})}>Close / switch profile</button></div></section>}
      {step === 1 && stored.length>0 && <section className="saved-records"><h2>Saved profiles</h2><p>Saved signatures and records can reopen even when no draft was saved.</p><ul className="profile-list">{stored.map(({profile:p,lifecycle})=><li key={p.profile_id}><span>{p.display_name}<small>{p.stamps.length} record(s) · key {profileKeyCode(p)} · {lifecycle || 'active'}</small></span><button className="text-button" disabled={busy || (lifecycle && !['active','retired'].includes(lifecycle))} onClick={()=>guard(()=>run(async()=>{await openProfile(p.profile_id);if(p.stamps.length){setStep(3);}else{setMessage('Profile opened. Prepare observations to add its first record.');}}))}>Open saved profile</button></li>)}</ul></section>}
      <DeviceContinuityPanel profiles={stored} onChanged={continuityChanged} disabled={busy}/>
    </div><EvidenceRail/></div>
    {pending && <Dialog busy={busy} title="Keep your unsaved work?" onCancel={()=>setPending(null)}><p>This action would replace or leave your private draft. Signed records are already saved separately.</p><Notice error>{error}</Notice><div className="dialog-actions"><button className="button primary" disabled={busy} onClick={()=>run(async()=>{await save();const next=pending;setPending(null);await next();})}>Save draft & continue</button><button className="button secondary" onClick={()=>{exportDraft();const next=pending;setPending(null);restoreSavedState();next();}}>Export draft & continue</button><button className="text-button danger" onClick={()=>{const next=pending;setPending(null);restoreSavedState();next();}}>Discard draft changes</button><button className="text-button" onClick={()=>setPending(null)}>Keep editing</button></div></Dialog>}
    {edit && <Dialog busy={busy} title={`Correct observation ${edit.index+1}`} onCancel={()=>setEdit(null)}><label htmlFor="edit-field">Field</label><select id="edit-field" value={edit.column} onChange={e=>{const column=Number(e.target.value);setEdit({...edit,column,value:rows[edit.index][column]});}}>{['Date','NAV','External flow'].map((field,i)=><option key={field} value={i}>{field}</option>)}</select><label htmlFor="edit-value">Corrected value</label><input id="edit-value" value={edit.value} onChange={e=>setEdit({...edit,value:e.target.value})}/><label htmlFor="edit-reason">Reason (included in shared evidence)</label><textarea id="edit-reason" maxLength={500} value={edit.reason} onChange={e=>setEdit({...edit,reason:e.target.value})}/><p>Original and corrected amounts remain in your private draft. Do not put private details in the reason.</p><div className="actions"><button className="button primary" disabled={busy} onClick={() => run(applyEdit)}>Apply correction</button><button className="text-button" onClick={()=>setEdit(null)}>Cancel</button></div></Dialog>}
    {deleting && <Dialog busy={busy} title="Delete this local signing key?" onCancel={()=>setDeleting(false)}><p>This removes {profile.display_name} and its signing key from this browser. Exported records remain checkable. Deletion does not revoke past records or cryptographically invalidate signing handles already loaded elsewhere. There is no recovery. Committed public transition evidence remains retained locally if available; deleting a key does not revoke exported approvals.</p><div className="actions"><button className="button secondary" onClick={()=>run(async()=>{await deleteStoredProfile(profile.profile_id);setActive(null);setDeleting(false);await refreshAfterSuccess();setMessage('Local key and records deleted. Previously exported evidence remains valid.');})}>Delete local key & records</button><button className="button primary" onClick={()=>setDeleting(false)}>Keep profile</button></div></Dialog>}
  </div>;
}
