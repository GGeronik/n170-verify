import { useEffect, useRef, useState } from 'react';
import { verifyRunReviewPackage } from './runReviewV2.js';
import AccountingReviewPanel from './AccountingReviewPanel.jsx';
import { download, Notice } from './ui.jsx';

const MAX_BYTES = 96 * 1024 * 1024;
const labels = {
  NO_FINDINGS_REPORTED: 'No findings in exercised signals', FINDINGS_REPORTED: 'Findings reported',
  NOT_ASSESSABLE: 'Run is not assessable', INSUFFICIENT: 'Insufficient signals', FAILED: 'Failed',
  TIMED_OUT: 'Timed out', CANCELLED: 'Cancelled', SKIPPED: 'Skipped', MISSING_OUTPUT: 'Missing output',
  INVALID_OUTPUT: 'Invalid output', INPUT_CHANGED: 'Input changed',
};
const words = code => String(code).toLowerCase().replaceAll('_', ' ');

// Separate memory-only review. A file selection, clear, changed pin, or unmount
// invalidates both pending reads and digest work before any result is displayed.
export default function RunReviewPanel() {
  const [report, setReport] = useState(null), [busy, setBusy] = useState(false);
  const [error, setError] = useState(''), [pin, setPin] = useState(''), [shared, setShared] = useState('');
  const generation = useRef(0), heading = useRef(null);
  useEffect(() => () => { generation.current += 1; }, []);
  useEffect(() => { if (report) heading.current?.focus(); }, [report]);
  function clear() {
    generation.current += 1;
    setReport(null); setError(''); setShared(''); setBusy(false);
    return generation.current;
  }
  async function openFile(event) {
    const file = event.target.files?.[0]; event.target.value = '';
    if (!file) return;
    const current = clear(), expected = pin.trim();
    if (expected && !/^[a-f0-9]{64}$/.test(expected)) { setError('Use a 64-character lowercase SHA-256 manifest digest, or leave the optional digest empty.'); return; }
    if (file.size > MAX_BYTES) { setError('This package exceeds the 96 MiB limit. Ask for a supported complete package; omitted artifacts cannot be checked.'); return; }
    setBusy(true);
    try {
      const bytes = await file.arrayBuffer();
      if (generation.current !== current) return;
      if (bytes.byteLength > MAX_BYTES) throw new Error('size');
      const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
      const checked = await verifyRunReviewPackage(text, { manifestSha256: expected || undefined });
      if (generation.current !== current) return;
      setReport(checked);
    } catch {
      if (generation.current === current) setError('This package could not be read as supported UTF-8 run-review JSON. No previous result is retained. Ask the sender to export the complete run again.');
    } finally { if (generation.current === current) setBusy(false); }
  }
  function exportSummary() {
    const summary = {
      schema: report.accounting ? 'n170.run-review-reading-summary.v2' : 'n170.run-review-reading-summary.v1', integrity: report.integrity,
      status: report.status, manifest_sha256: report.manifest_sha256 || null,
      manifest_pin: report.manifest_pin, summary: report.summary,
      attempts: (report.attempts || []).map(({ id, outcome }) => ({ id, outcome })),
      reproducibility: { status: report.reproducibility?.status, missing_count: report.reproducibility?.missing?.length || 0 },
      reason_codes: report.reason_codes, trust: report.trust,
      boundary: 'Unsigned reading summary only. Obtain the full original package for independent byte verification. Strategy names, raw artifacts and source code are omitted.',
    };
    if (report.accounting) summary.accounting = { status: report.accounting.status, attempts: report.accounting.attempts.map(item => ({ id: item.id,
      capture_status: item.capture?.status, exact_model_status: item.exact_model?.status || 'NOT_ASSESSED',
      native_compatibility_status: item.native_compatibility?.status || 'NOT_ASSESSED', oracle_status: item.oracle?.status || 'NOT_RUN',
      native_metric_statuses: Object.fromEntries(Object.entries(item.native_metrics || {}).map(([key, value]) => [key, value.status])) })) };
    download(JSON.stringify(summary, null, 2) + '\n', 'n170-run-reading-summary.json');
    setShared('Downloaded an unsigned reading summary. It includes the manifest digest, selected outcome counts and reasons. It cannot replace the full package for independent verification.');
  }
  const valid = report?.integrity === 'VALID';
  const accountingVersion = report?.schema === 'n170.run-review-verification.v2';
  return <div className="run-review page-intro">
    <h1>Review a captured run.</h1>
    <p>Check a portable package’s exact bytes and selected attempt receipts in your browser. Imported strategies and commands are never executed.</p>
    <section className="paper" aria-labelledby="run-import-heading">
      <p className="record-overline">Local recipient review · data-only package</p>
      <h2 id="run-import-heading">Open a run package</h2>
      <p>Ask the sender for the JSON exported by <code>export-run</code>. It includes source code, settings, data, logs and outputs. Treat all supplied text as untrusted and review its privacy before sharing.</p>
      <label htmlFor="run-manifest-pin">Expected manifest SHA-256 <span className="optional">(optional)</span></label>
      <input id="run-manifest-pin" value={pin} autoComplete="off" spellCheck={false} maxLength={64} aria-describedby="run-pin-help" onChange={event => { clear(); setPin(event.target.value); }}/>
      <p id="run-pin-help">Use a digest retained separately or received through a trusted channel. A match identifies those bytes; it does not authenticate the sender or execution. Changing it clears the result; choose the file again.</p>
      <div className="actions">
        <label className="button primary file-label">Choose run package<input type="file" accept=".json,application/json" onChange={openFile} aria-describedby="run-local-privacy"/></label>
        <button className="text-button" disabled={!report && !error && !busy} onClick={clear}>Clear run package</button>
      </div>
      <p id="run-local-privacy" className="tool-privacy">No upload or automatic storage. Maximum 96 MiB JSON, 64 MiB decoded bytes and 128 artifacts. A new selection immediately clears the old result. Leaving this view clears the package.</p>
      <Notice>{busy ? 'Checking package bytes and receipt relationships… You can replace or clear this read.' : ''}</Notice>
      <Notice error>{error}</Notice>
    </section>
    {report && <section className="paper run-result" aria-labelledby="run-result-heading">
      <p className="record-overline">Unsigned supplied receipt · execution not witnessed by this app</p>
      <h2 id="run-result-heading" ref={heading} tabIndex={-1}>{valid ? 'Supplied package is internally consistent' : 'Package could not be verified'}</h2>
      <p className={valid ? 'notice' : 'notice error'}>{valid ? 'Artifact digests and supported receipt relationships match the supplied manifest. This is a check of the selected supplied evidence.' : 'Missing, altered, unsupported or inconsistent evidence prevents a valid package result. No clean run or successful reproduction is inferred.'}</p>
      {valid && <h3>{labels[report.status] || 'Run is not assessable'}</h3>}
      <div className="tool-scope" aria-label="Run evidence limits">
        <p><strong>Producer identity</strong><br/>Not authenticated</p>
        <p><strong>Actual execution</strong><br/>Not witnessed here</p>
        <p><strong>Broker / data provenance</strong><br/>Not established</p>
        <p><strong>Other attempts</strong><br/>Omissions remain unknown</p>
      </div>
      <p className="boundary">An attacker can author an internally consistent unsigned package. Valid hashes do not prove that its engine ran, that its producer is genuine, or that failed trials outside this package were disclosed.</p>
      {report.manifest_sha256 && <><h3>Manifest identity</h3><code className="hash">{report.manifest_sha256}</code><p>{report.manifest_pin === 'matched' ? 'Matches the separately supplied expected digest.' : report.manifest_pin === 'mismatched_or_invalid' ? 'The expected digest does not match.' : 'No independent expected digest was supplied.'}</p></>}
      {valid && <>
        <h3>Every selected attempt</h3>
        <p>{report.summary?.selected_count ?? report.attempts?.length ?? 0} selected; {report.summary?.assessed_count ?? 0} assessable; {report.summary?.findings_count ?? 0} with findings. Failure and insufficient results remain visible. These counts cannot establish all historical trials.</p>
        <p id="run-attempts-help">Each selected attempt is checked against its captured artifacts. Scroll horizontally to read all outcomes and reasons on narrow screens.</p>
        <div className="table-scroll" role="region" aria-label="Selected run attempts" aria-describedby="run-attempts-help" tabIndex={0}>
          <table><caption>Selected attempts and outcomes</caption><thead><tr><th>Attempt</th><th>Supplied strategy</th><th>Outcome</th><th>Reasons</th></tr></thead><tbody>
            {(report.attempts || []).map(attempt => <tr key={attempt.id}><th scope="row">{attempt.id}</th><td>{attempt.strategy}</td><td>{labels[attempt.outcome] || words(attempt.outcome)}</td><td>{(attempt.reason_codes || []).map(words).join('; ') || 'No additional reason supplied'}</td></tr>)}
          </tbody></table>
        </div>
        <AccountingReviewPanel accounting={report.accounting}/>
      </>}
      <h3>Reproduction prerequisites</h3>
      <p><strong>Independent reproduction has not been performed by this review.</strong> {valid && report.reproducibility?.status === 'READY_TO_RERUN' ? 'Captured inputs are present. A deliberate local rerun still requires source review and installation of the exact supported engine.' : 'Required evidence is missing or invalid. Resolve the items below before attempting reproduction.'}</p>
      {(report.reproducibility?.missing || []).length > 0 && <ul>{report.reproducibility.missing.map((item, index) => <li key={index}>{typeof item === 'string' ? words(item) : JSON.stringify(item)}</li>)}</ul>}
      <details><summary>Check reasons and artifact inventory</summary><ul>{(report.reason_codes || []).map(code => <li key={code}>{words(code)}.</li>)}</ul><p>Private paths and digests may identify research inputs. Content is treated as data.</p><div className="table-scroll" role="region" aria-label="Run artifact inventory" tabIndex={0}><table><thead><tr><th>Path</th><th>Bytes</th><th>SHA-256</th></tr></thead><tbody>{(report.artifacts || []).map(item => <tr key={item.path}><th scope="row">{item.path}</th><td>{item.size}</td><td><code>{item.sha256}</code></td></tr>)}</tbody></table></div></details>
      <section aria-labelledby="run-summary-heading"><h3 id="run-summary-heading">Keep a reading summary</h3><p>The summary omits raw artifacts and strategy labels, but includes the manifest digest, selected counts and reasons. It is unsigned and is not a portable run package.</p><button className="button secondary" onClick={exportSummary}>Download reading summary</button><Notice>{shared}</Notice></section>
    </section>}
    {accountingVersion ? <section className="paper recipient-help" aria-labelledby="run-recipient-heading">
      <h2 id="run-recipient-heading">Check this v2 receipt with the combined offline toolkit</h2>
      <p>Use Python 3.10 or later and the combined download below, containing both <code>verify_toolkit</code> and <code>verify_accounting</code>. Offline package review uses only Python’s standard library; no engine, optional oracle or account connection is required. The toolkit’s older <code>package-source</code> command produces a v1-only archive; use this combined download for v2 receipts.</p>
      <p className="actions"><a className="button secondary" href="/n170-verify-toolkit.zip" download>Download combined offline toolkit</a><a href="/n170-verify-toolkit.zip.sha256" download>Download toolkit checksum</a><a href="/verify_release.py" download>Download archive verifier</a></p>
      <p>Obtain the expected ZIP SHA-256 and a trusted copy of the verifier separately. A checksum and verifier from the same untrusted page do not authenticate it. From the directory containing both downloads, replace this placeholder with your retained archive digest before extracting:</p>
      <pre><code>python3 verify_release.py n170-verify-toolkit.zip --sha256 EXPECTED_ARCHIVE_SHA256</code></pre>
      <p>After verification, extract into a new folder and keep the original ZIP and checksum. Keep the complete receipt as <code>run-review-v2.json</code>. Run from the extraction root containing both Python source directories, not inside either module. For a full source or combined release archive, first use <code>cd app</code>. Run the offline, data-only review:</p>
      <pre><code>python3 -m verify_toolkit.accounting verify run-review-v2.json</code></pre>
      <p>If you hold the receipt’s detached manifest SHA-256 through a separate trusted channel, replace the placeholder with its 64 lowercase hexadecimal characters. This receipt digest is distinct from the downloaded toolkit ZIP digest:</p>
      <pre><code>python3 -m verify_toolkit.accounting verify run-review-v2.json --manifest-sha256 RECORDED_64_HEX_DIGEST</code></pre>
      <p>Read package integrity, detector outcome, capture support, exact model, native compatibility and supplied oracle evidence separately. Native evidence supplies only cash, quantity and accumulated net PnL; six metrics remain <code>NOT_SUPPLIED</code>, so overall accounting remains <code>NOT_ASSESSABLE</code> and review returns exit <code>2</code> even when supported calculations match. Preserve reasons and failures. Verification never executes received source code, strategies, commands or oracle workers. Matching evidence does not authenticate its producer, establish omitted history or demonstrate financial realism.</p>
      <p>Read the <a href="/accounting-release.md">combined download guide</a>, <a href="/accounting-v2.md">v2 accounting instructions</a> and <a href="/capture-v2.md">capture contract</a> for supported scope and the separately installed pinned optional oracle.</p>
      <details><summary>For the sender: export a captured v2 run</summary>
        <p>Use the accounting-enabled source and preserve every selected attempt. Review all source, data, settings and logs for private information before explicitly sharing an export:</p>
        <pre><code>python3 -m verify_toolkit.accounting export run-001 --output run-review-v2.json</code></pre>
      </details>
      <p>A reading summary lacks the bytes needed for independent review. A supplied oracle result is evidence of a claimed local calculation; this browser has not executed or authenticated that calculation.</p>
    </section> : <section className="paper recipient-help" aria-labelledby="run-recipient-heading">
      <h2 id="run-recipient-heading">Check a received package with the offline toolkit</h2>
      <p>Use Python 3.10 or later. Package verification uses only Python’s standard library; it needs no Docker, Freqtrade installation, account connection or network access after downloading the toolkit.</p>
      <p className="actions"><a className="button secondary" href="/n170-verify-toolkit.zip" download>Download offline toolkit</a><a href="/n170-verify-toolkit.zip.sha256" download>Download toolkit checksum</a><a href="/verify_release.py" download>Download archive verifier</a></p>
      <p>Keep the expected ZIP SHA-256 through a separate trusted channel and obtain or review the verifier through a trusted source. A checksum and verifier downloaded from the same untrusted page do not authenticate its publisher.</p>
      <p>Before extracting, open a terminal in the folder containing the downloaded ZIP and <code>verify_release.py</code>. Replace <code>EXPECTED_ARCHIVE_SHA256</code> with your separately held ZIP digest:</p>
      <pre><code>{'python3 --version\npython3 verify_release.py n170-verify-toolkit.zip --sha256 EXPECTED_ARCHIVE_SHA256'}</code></pre>
      <ol>
        <li>After the archive check passes, extract the unchanged ZIP into a new folder. It contains the <code>verify_toolkit</code> source directory, its instructions and a source inventory. Preserve the ZIP and checksum.</li>
        <li>Place the complete received run package in that folder as <code>run-review.json</code>. Keep the original. A reading summary alone does not contain the artifacts needed for verification.</li>
        <li>Open a terminal and use <code>cd</code> to enter the extracted folder that contains <code>verify_toolkit</code>, then run the commands below. Stay in its parent folder; do not enter the <code>verify_toolkit</code> directory itself.</li>
      </ol>
      <pre><code>python3 -m verify_toolkit verify-review run-review.json</code></pre>
      <p>If you hold a manifest digest from a separate trusted channel, replace the placeholder below with those 64 lowercase hexadecimal characters:</p>
      <pre><code>python3 -m verify_toolkit verify-review run-review.json --manifest-sha256 RECORDED_64_HEX_DIGEST</code></pre>
      <p>Read both <code>integrity</code> and <code>status</code>. Exit code 0 means an intact selected receipt reports no findings; 1 means intact findings; 2 means invalid or unassessable evidence, including failed or insufficient runs. None authenticates execution. The verification command never executes the received strategy or embedded commands.</p>
      <details><summary>For the sender: export a captured run</summary><p>Use the same toolkit to run reviewed local synthetic controls with explicit local-code opt-in, following <code>verify_toolkit/RUNNER.md</code>. Retain every selected attempt, then export the complete run directory:</p><pre><code>python3 -m verify_toolkit export-run run-001 --output run-review.json</code></pre><p>Review the included source code, settings, data, logs and outputs for private information before sharing. This deliberate export is not a redacted public report.</p></details>
      <h3>Compare a deliberate rerun</h3>
      <p>Install the pinned engine separately, review the captured strategy source, and use the toolkit runner with explicit local-code opt-in. Obtain an independently exported second package, then compare:</p>
      <pre><code>python3 -m verify_toolkit compare-runs run-review.json rerun-review.json</code></pre>
      <p>The comparator keeps changed input bytes, settings, engine identity, method and outcomes visible. Missing prerequisites prevent a reproducibility result. Matching supplied receipts alone does not establish that another person ran the engine.</p>
      <p className="boundary">Current execution scope: a single synthetic BTC/USDT spot pair, five-minute candles, pinned Freqtrade 2026.8 lookahead controls. Findings concern exercised signals only. Real-market fills, profitability, broker authenticity, TEE attestation and an external audit are not established.</p>
    </section>}
  </div>;
}
