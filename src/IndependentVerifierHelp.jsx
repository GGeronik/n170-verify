export default function IndependentVerifierHelp() {
  return <details className="independent-verifier-help"><summary>Rerun the independent verifier</summary>
    <ol>
      <li>Obtain the N170 Verify source through a channel you trust. Use Node.js 20.19+ within 20.x, or 22.12+ supported by that source. The separate verifier uses Node’s built-in libraries; this check needs no package install or broker access.</li>
      <li>Keep the received HTML or signed JSON unchanged. In a terminal, open the app subfolder of the extracted release (the folder containing package.json), then run the command below, replacing the quoted example path with your file’s path.</li>
    </ol>
    <pre className="hash"><code>{'node scripts/verify-record.mjs "/path/to/current-record.json"'}</code></pre>
    <p>To compare with your own earlier copy, put the current file first and the earlier file second. HTML review packages are accepted too.</p>
    <pre className="hash"><code>{'node scripts/verify-record.mjs "/path/to/current-record.json" "/path/to/previous-record.json"'}</code></pre>
    <ul>
      <li><strong>Exit 0:</strong> implemented structure, calculation and signature checks pass. If a previous copy was supplied, its history is identical or preserved with new events appended.</li>
      <li><strong>Exit 1:</strong> evidence or input failed validation. Resolve the reported error; do not rely on the displayed HTML.</li>
      <li><strong>Exit 2:</strong> both files check individually, but comparison finds a replaced key/alias, shortened history or conflicting earlier records. Ask for an explanation and retain both copies.</li>
    </ul>
    <p>Check the JSON result, including source authenticity, identity and independent time: those remain unverified. No comparison establishes complete accounts, source freshness or missing observations. This verifier does not check separate research/tool observations or AuditZK attestation.</p>
    <p>Retain the exact checked file for the next review. Keeping it does not independently timestamp it. Original balances and flow amounts are excluded. If the owner deliberately supplies <code>n170-private-reconciliation.json</code>, the <a href="/verify-reconciliation.md" target="_blank" rel="noreferrer">private source-check guide</a> explains how to compare supported source evidence with one explicitly selected signed v4 event. That unencrypted export is separate from a private draft and contains financial data; it is never attached automatically. The check remains conditional on owner assertions and does not authenticate a broker or complete accounts.</p>
  </details>;
}
