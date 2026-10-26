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
  <section className="paper recipient-help" aria-labelledby="earlier-kit-heading">
    <h2 id="earlier-kit-heading">Earlier challenge kit</h2>
    <p>An earlier 175-case kit tested the wave2 compatibility-v4 app and toolkit. Its documented no-scored-failure result is <code>INCOMPLETE</code>, exit <code>2</code>, because its frozen report leaves separate engine and public-build challenges unrun. It excludes continuity and accounting and is not validation of the current source. The kit is not served here; it is retained with its original identity outside this distribution.</p>
    <p>For the current combined toolkit and v2 accounting receipt workflow, read the <a href="/accounting-release.md">accounting release guide</a>. Keep package integrity, supported calculations and evidence limits separate.</p>
  </section>
  </>;
}
