export default function ChallengeKitHelp() {
  return <>
  <section className="paper recipient-help" aria-labelledby="private-source-challenge-heading">
    <h2 id="private-source-challenge-heading">Reproduce the 68-case private-source challenge</h2>
    <p>Check how the private-source checker handles deliberately supplied synthetic evidence. This separate pack includes the accepted checker and everything needed to repeat the cases without an app build, npm installation or financial engine.</p>
    <p>The accepted local run matched <strong>all 68 expected statuses and exit codes</strong>, including <strong>31 conditional positive cases</strong>. Its original result remains <strong>51 raw passes and 17 flags</strong>. Each flag has a recorded explanation and acceptance decision; none was removed or relabelled as a pass.</p>
    <p>A match means the checker behaved as expected for these cases and their stated assumptions. It does not establish source authenticity, complete accounts or investment performance. Outside human review and outside-user reproduction have not been established.</p>
    <p className="actions">
      <a className="button secondary" href="/private-source-challenge/n170-private-source-challenge-v1.zip" download>Download 68-case challenge</a>
      <a href="/private-source-challenge/accepted-offline-toolkit.zip" download>Download accepted checker</a>
      <a href="/private-source-challenge/README.md" download>Download reproduction instructions</a>
      <a href="/private-source-challenge/verify_pack.py" download>Download pack verifier</a>
      <a href="/private-source-challenge/SHA256SUMS" download>Download pack checksums</a>
      <a href="/private-source-challenge/RELEASE.json" download>Download acceptance summary</a>
    </p>
    <p>Save all six files together and follow the <a href="/private-source-challenge/README.md">unchanged reproduction instructions</a>. Use Linux or macOS with Python 3.9+ and Node 20.19+ in the 20 series, or Node 22.12+. Start each run in new output directories and retain unsuccessful attempts. Read the synthetic JSON and HTML fixtures as data; do not render the test HTML.</p>
    <details>
      <summary>Check the pack identity and expected outcome</summary>
      <p>Retain these expected identities through a trusted channel and inspect the verifier before running it. Matching files identify the accepted bytes; files downloaded together cannot authenticate their publisher.</p>
      <p>Challenge ZIP SHA-256:</p>
      <code className="hash">e7471919bdf7f5b42ab233d6c89c834a2a3f1952fd0aa268a5931a4b53b35f57</code>
      <p>Accepted checker ZIP SHA-256:</p>
      <code className="hash">24ad3cc8f88c3b01b076d99b33017f9b090259dffa18e0cb500130d87bf37863</code>
      <p>Pack verifier SHA-256:</p>
      <code className="hash">2eda69531c3c079f71e1bbfb9e6dc3a6683deddd3bdab7e3ca0b2bcf45e75d72</code>
      <p>Challenge manifest SHA-256:</p>
      <code className="hash">5abe3172731422206ac4418f8c0b8f056b2e8b93d85d6d3624c7747549da2c83</code>
      <p>The reproduction runner is expected to exit 0 with <code>status_and_exit_matches: 68</code>, <code>raw_passed: 51</code>, <code>raw_flagged: 17</code> and <code>unresolved_cases: 0</code>. The original 60-case harness still exits 1 because its 17 flags remain. Acceptance requires exact matches for each case’s saved output and receipt, with those flags explicitly adjudicated.</p>
      <p>This pack retains its own accepted checker and evidence identities. It is separate from the earlier 175-case kit below and does not certify every part of the combined application.</p>
    </details>
  </section>
  <section className="paper recipient-help" aria-labelledby="challenge-kit-heading">
    <h2 id="challenge-kit-heading">Run the frozen challenge kit</h2>
    <p>Download a portable set of checks for the earlier wave2 compatibility-v4 app and toolkit. It preserves all 175 original expected cases and its fixed tested source. <strong>It excludes continuity and accounting</strong> and does not validate the combined source in this preview.</p>
    <p className="actions">
      <a className="button secondary" href="/challenge-kit/public-challenge-kit.zip" download>Download challenge kit</a>
      <a href="/challenge-kit/README.md" download>Download kit instructions</a>
      <a href="/challenge-kit/SHA256SUMS" download>Download kit checksums</a>
      <a href="/challenge-kit/verify_archive.py" download>Download kit verifier</a>
    </p>
    <p>Retain the expected ZIP digest through a trusted channel and obtain or review the verifier through a trusted source. Files downloaded together cannot authenticate their own publisher. Use Python 3.11+ and Node 22.12+; the documented workflow does not fetch dependencies or run an engine.</p>
    <details>
      <summary>Verify the download and run the documented checks</summary>
      <p>Start in the directory containing the four downloaded files. Each output directory must be new. These commands use the kit’s frozen source and separately pinned synthetic receipt inputs:</p>
      <pre><code>{'python3 -B verify_archive.py public-challenge-kit.zip \\\n  --expected-sha256 5802a438f08afdad9e1d74d7ee9f1ab03b86a059e9d77bb30ea977148c9a0a22 \\\n  --extract challenge-kit\ncd challenge-kit\npython3 -B prepare_source.py --output ../accepted-source\npython3 -B run_challenges.py --source ../accepted-source \\\n  --receipts receipts \\\n  --receipt-freeze-sha256 f510104c165d61705472197ad5b21a765d180071410b4392a1ca430b81707ec7 \\\n  --output ../challenge-results'}</code></pre>
      <p>Read <code>../challenge-results/report.json</code> from that working directory and retain the actual outcome, including any failed run. The documented no-scored-failure outcome is <code>INCOMPLETE</code>, exit <code>2</code>; the kit’s frozen report leaves separate engine and public-build challenges unrun. Unsupported and partial results stay separate.</p>
      <p>Fixed tested-source SHA-256:</p>
      <code className="hash">efa705edb9782568aba7561cea448f4e824f1a58cb745930471fb6cee39fe3e5</code>
    </details>
    <p>The eight recorded engine executions cover four synthetic controls; they are not the five separate engine challenge cases. The 77 wrapper self-tests and six calculation probes also have separate counts. The 175-case total is not an accuracy percentage or an external audit.</p>
    <p>For the current combined toolkit and v2 accounting receipt workflow, read the <a href="/accounting-release.md">accounting release guide</a>. Keep package integrity, supported calculations and evidence limits separate.</p>
  </section>
  </>;
}
