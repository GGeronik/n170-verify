import { useEffect, useRef, useState } from 'react';
import { parseToolEvidence, makeToolEvidenceExport, TOOL_EVIDENCE_MAX_BYTES, TOOL_EVIDENCE_LABELS } from './toolEvidence.js';
import syntheticExample from '../examples/tool-evidence-findings.json?raw';
import { download, Notice } from './ui.jsx';
import RunReviewPanel from './RunReviewPanel.jsx';
import './runReview.css';

const reason = code => code.toLowerCase().replaceAll('_', ' ');

// A separate memory-only workflow. It has no access to account data, signing,
// key storage or draft storage. A newer selection always invalidates old reads.
export default function ToolEvidencePanel() {
  const [view, setView] = useState('observations');
  return <div className="evidence-workspace">
    <div className="actions evidence-switch" role="group" aria-label="Evidence format">
      <button className={`button ${view === 'observations' ? 'primary' : 'secondary'}`} aria-pressed={view === 'observations'} onClick={() => setView('observations')}>Observation JSON</button>
      <button className={`button ${view === 'run' ? 'primary' : 'secondary'}`} aria-pressed={view === 'run'} onClick={() => setView('run')}>Run package</button>
    </div>
    {view === 'run' ? <RunReviewPanel/> : <ObservationPanel/>}
  </div>;
}

function ObservationPanel() {
  const [report, setReport] = useState(null), [error, setError] = useState('');
  const [busy, setBusy] = useState(false), [includeLabels, setIncludeLabels] = useState(false);
  const [shared, setShared] = useState('');
  const generation = useRef(0), resultHeading = useRef(null);
  useEffect(() => () => { generation.current += 1; }, []);
  useEffect(() => { if (report) resultHeading.current?.focus(); }, [report]);
  function reset() {
    generation.current += 1;
    setReport(null); setError(''); setBusy(false); setIncludeLabels(false); setShared('');
    return generation.current;
  }
  async function openFile(event) {
    const file = event.target.files?.[0]; event.target.value = '';
    if (!file) return;
    const request = reset();
    if (file.size > TOOL_EVIDENCE_MAX_BYTES) { setError('Observation JSON exceeds the 4 MiB limit. Export a smaller supported report.'); return; }
    setBusy(true);
    try {
      const buffer = await file.arrayBuffer();
      if (generation.current !== request) return;
      if (buffer.byteLength > TOOL_EVIDENCE_MAX_BYTES) throw new Error('size');
      const text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
      setReport(parseToolEvidence(text));
    } catch {
      if (generation.current === request) setError('This file could not be read as supported observation JSON. Check UTF-8, the v1 schema, versions, counts and declared scope. No previous result is retained.');
    } finally { if (generation.current === request) setBusy(false); }
  }
  function example() { reset(); setReport(parseToolEvidence(syntheticExample)); }
  function exportReport() {
    const exported = makeToolEvidenceExport(report, { includeLabels });
    download(JSON.stringify(exported, null, 2) + '\n', 'n170-tool-observations.json');
    setShared(`Downloaded a separate unsigned observation file. ${includeLabels ? 'Available strategy, file and indicator labels are included.' : 'Strategy, file and indicator labels are omitted.'} Share it only with your intended recipient.`);
  }
  return <div className="tool-evidence page-intro">
    <h1>Inspect tool observations.</h1>
    <p>Read an exported Freqtrade lookahead observation locally. Findings describe supplied output; they do not verify account performance or a strategy.</p>
    <section className="paper" aria-labelledby="tool-import-heading">
      <h2 id="tool-import-heading">Open an observation file</h2>
      <p>Use JSON produced by the open toolkit’s <code>freqtrade-lookahead</code> command. Supported contract: <code>n170.tool-evidence.freqtrade-lookahead.v1</code>, format reference 2026.8. Maximum 4 MiB.</p>
      <div className="actions">
        <label className="button primary file-label">Choose observation JSON<input type="file" accept=".json,application/json" onChange={openFile} aria-describedby="tool-privacy"/></label>
        <button className="button secondary" onClick={example}>Try synthetic observations</button>
        <button className="text-button" onClick={reset} disabled={!report && !busy && !error}>Clear observations</button>
      </div>
      <p id="tool-privacy" className="tool-privacy">No upload or automatic storage. Opening another file clears the previous result immediately. Leaving this view clears its observations. Export is a separate deliberate action.</p>
      <Notice>{busy ? 'Reading observation file… You can choose a replacement or clear this read.' : ''}</Notice>
      <Notice error>{error}</Notice>
    </section>
    {report && <section className="paper tool-result" aria-labelledby="tool-result-heading">
      <p className="record-overline">Unsigned supplied tool output · separate from account records</p>
      <h2 ref={resultHeading} tabIndex={-1} id="tool-result-heading">{TOOL_EVIDENCE_LABELS[report.status]}</h2>
      <p className={report.example_declaration === 'synthetic' ? 'boundary' : 'notice'}>{report.example_declaration === 'synthetic' ? <><strong>Synthetic demonstration.</strong> Invented observations exercise the interface. No actual strategy or investment result is represented.</> : 'Synthetic status was not declared. This does not establish that the observations are real.'}</p>
      <div className="tool-scope" aria-label="Observation evidence limits">
        <p><strong>Source authenticity</strong><br/>Unknown · unverified</p>
        <p><strong>Run freshness</strong><br/>Unknown · not established</p>
        <p><strong>Complete attempts</strong><br/>Unknown · not established</p>
        <p><strong>Execution by this app</strong><br/>Not performed</p>
      </div>
      <p><strong>{report.tested_strategy_count}</strong> usable supplied strategy rows; <strong>{report.rows.length}</strong> rows in this report. These are reported counts, not independently observed tests.</p>
      <p>Declared run status: <strong>{report.scope.declared_context.run_status || 'Not supplied'}</strong>. Expected strategy count: <strong>{report.scope.declared_context.expected_strategy_count ?? 'Not supplied'}</strong>. Declared tool version: <strong>{report.scope.declared_context.freqtrade_version || 'Not supplied'}</strong>.</p>
      <p className="tool-privacy">Scroll the table horizontally on narrow screens, or focus it and use the arrow keys. A finding can concern indicators even when biased entry and exit counts are zero.</p>
      <div className="table-scroll" role="region" aria-label="Reported strategy observations" tabIndex={0}>
        <table><caption>Signals reported as checked; untriggered and omitted signals remain unknown.</caption><thead><tr><th>Supplied row</th><th>Tested signals</th><th>Biased entries</th><th>Biased exits</th><th>Observation</th></tr></thead><tbody>
          {report.rows.map(row => <tr key={row.row_number}><th scope="row">{row.display_label || row.strategy || `Strategy ${row.row_number}`}</th><td>{row.total_signals ?? 'Unknown'}</td><td>{row.biased_entry_signals ?? 'Unknown'}</td><td>{row.biased_exit_signals ?? 'Unknown'}</td><td>{TOOL_EVIDENCE_LABELS[row.status]}<br/><small>{row.reason_codes.map(reason).join('; ')}</small>{row.has_bias && <><br/><small>{row.biased_indicators ? `Indicator findings: ${row.biased_indicators.length}` : 'Indicator details omitted in supplied report'}</small></>}</td></tr>)}
          {!report.rows.length && <tr><td colSpan={5}>No strategy rows supplied. This is not a clean check.</td></tr>}
        </tbody></table>
      </div>
      <h3>Reasons and limitations</h3>
      <ul>{report.reason_codes.map(code => <li key={code}>{reason(code)}.</li>)}</ul>
      <ul>{report.limitations.map((limit, index) => <li key={index}>{limit}</li>)}</ul>
      <p className="boundary">These observations never change signed account calculations, source authenticity or account coverage. This is a single tool-output contract, not a completed eight-dimension research assessment.</p>
      <details><summary>Inspect supplied scope and labels</summary><p>The supplied digest identifies claimed source bytes. This app has not checked it against the original CSV and it does not authenticate the source. Private labels may be present below.</p><pre>{JSON.stringify(report, null, 2)}</pre></details>
      <section aria-labelledby="tool-export-heading">
        <h3 id="tool-export-heading">Export observations separately</h3>
        <p>Review before sharing. Counts, declared scope and source/configuration/data digests can disclose research information even when labels are omitted. No raw CSV or account record is included.</p>
        <label className="check-row"><input type="checkbox" checked={includeLabels} onChange={event => { setIncludeLabels(event.target.checked); setShared(''); }}/><span>Include any available strategy, file and indicator labels. Omitted labels cannot be recovered.</span></label>
        <button className="button secondary" onClick={exportReport}>Download observation JSON</button>
        <Notice>{shared}</Notice>
      </section>
      <section className="recipient-help" aria-labelledby="tool-rerun-heading">
        <h3 id="tool-rerun-heading">How a recipient checks the observations</h3>
        <p>Open this JSON in the Tool observations view to inspect its structure. To independently reproduce the interpretation, obtain the separate open toolkit, the exact retained CSV and declared context from the sender, and run:</p>
        <pre><code>python -m verify_toolkit freqtrade-lookahead export.csv --context context.json</code></pre>
        <p>Omit the context option when none was supplied. Compare the source digest, counts, findings and limits. Agreement establishes repeatable interpretation only. Missing CSV or context prevents that rerun; JSON alone does not prove tool execution. Retain the synthetic declaration when applicable.</p>
      </section>
    </section>}
    <p><a href="/tool-evidence.md" target="_blank" rel="noreferrer">Observation format, sharing and limitations</a></p>
  </div>;
}
