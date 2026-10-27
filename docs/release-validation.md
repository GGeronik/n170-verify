# Validation scope and reproduction

This public guide describes checks to run; it is not a result report. Apart from the separately pinned synthetic challenge pack, historical
internal logs, screenshots and handoffs are outside the public inventory. Keep
results tied to the exact received source ZIP hash or the distinct hash of a
modified build. Automated checks are not an external audit or an
outside-user study.

## Receipt and clean build

Use the [release guide](release-readiness.md) to verify original archive bytes
before extraction. From the extracted `app/` folder containing `package.json`:

```sh
npm ci --ignore-scripts
npm run build
npm test
python3 scripts/numerical-controls.py
node scripts/verify-record.mjs examples/example-profile.json
node scripts/verify-record.mjs examples/review-profile-v4.html
```

The financial verifier uses Node standard cryptography and separately implemented
arithmetic; it requires no npm packages. Numerical controls use Python Decimal
without importing the JavaScript calculations. Tests preserve v3/v4 signatures,
arithmetic, correction history, import limits, private-data boundaries and public
build checks. A test's existence does not demonstrate that it passed in your
source/environment; retain the command and complete output.

Some tests need retained evidence or separately installed software that is not part of this source, and are skipped without it. At this revision, `npm test` runs 567 tests: 563 pass and 4 are skipped unless `N170_ACCOUNTING_V2_PACKAGE_ROOT` (2 tests), `N170_RUN_REVIEW_PACKAGE_ROOT` (1) or `N170_WALLET_SCOPE_PACKAGE` (1) names a retained package. `python3 -S -m unittest discover -s toolkit-tests` runs 150 tests: 125 pass and 25 are skipped unless `N170_ACCOUNTING_EVIDENCE` names a directory of retained accounting captures. `python3 -m unittest discover -s accounting-tests` runs 51 tests: 48 pass and 3 are skipped unless `N170_BEANCOUNT_PYTHON` names a separately installed pinned oracle interpreter. A skipped test is not a pass; record skips with their conditions.

For reproducibility, independently extract the same verified ZIP into two clean
directories, install the same locked dependencies with the same Node/npm/Python
versions and platform, and run the ordinary build in each. Compare all generated
file bytes, including the embedded source ZIP. Record environmental differences
before attributing a mismatch to source. Cached installation is not a claim that
an empty-cache offline install works; dependencies are not vendored. Matching
build hashes establish byte consistency, not program correctness.

To exercise maintainer use, edit a reviewed source file in a separate extraction,
run `npm run build` and verify the resulting new archive with its new digest. The
modified source should not match the original immutable manifest. Preserve the
original receipt instead of altering it to conceal the change.

## Browser journeys

The [README](../README.md) and [reviewer journey](reviewer-journey.md) list the
production preview and optional browser commands. Use an existing Playwright
runtime and browser binaries; record their exact versions. Preserve output outside
the source tree. Check desktop and mobile rendering, owner import/reconciliation,
losses and flows, signing, downloaded evidence, recipient checking and previous-copy
comparison. Include invalid replacement files, delayed reads, privacy boundaries
and stale-result clearing. Inspect the screenshots as well as the exit code.

Browser checks against a built package and downloaded files are distinct from
unit tests, static HTML checks and fixture generation. Chromium or Playwright
WebKit is not native Safari. Narrow reflow is not actual browser zoom or a WCAG
certification. No full assistive-technology or outside-user result follows from
automated harnesses.

## Reproduce the separate private-source challenge

Open **Methods → Reproduce the 68-case private-source challenge** and save its
six downloads together. The
[unchanged instructions](../release-assets/private-source-challenge/README.md)
provide the verifier and runner commands, required runtimes and fixed identities.
This workflow uses the included accepted checker without rebuilding the app,
installing npm dependencies or running a financial engine. It is separate from
the earlier 175-case kit, which is not distributed here, and from tests of a newly rebuilt combined application.

Keep the accepted challenge ZIP SHA-256
`e7471919bdf7f5b42ab233d6c89c834a2a3f1952fd0aa268a5931a4b53b35f57`
and manifest SHA-256
`5abe3172731422206ac4418f8c0b8f056b2e8b93d85d6d3624c7747549da2c83`
through a trusted channel. Start in new output directories, keep failed attempts
and read the synthetic JSON and HTML fixtures as data without rendering the HTML.

Compare all 68 expected status/exit pairs and all 204 recorded case output and
receipt files. Preserve **51 raw passes and 17 flags**, their explicit
adjudications and the separate count of **31 conditional positive cases**. The
expected reproduction runner exits 0 with no unresolved cases; the original
60-case harness still exits 1 because the flags remain. Matching this finite
synthetic pack does not establish source authenticity, complete accounts,
investment performance, outside human review or outside-user reproduction.
A changed app/source archive has a new identity; the six delivered pack files
must remain byte-for-byte identical to their separate receipts.

## Report outcomes without hiding limits

Report exact supported-case counts, failures, false accepts, false rejects and
unsupported dimensions separately. Retain failed and inconclusive attempts. A
failed test must not be silently converted to a skipped check or omitted from an
aggregate. For new producer contracts, fix independent expected adversarial cases
before running their frozen candidates and identify the source/build hashes.

Relevant adversarial cases include altered, missing and extra artifact bytes;
mismatched identities/settings; duplicate paths; supplied failed attempts;
irrelevant-run comparisons; private source leakage; gaps, cash-flow timing,
currency disagreement, valid losses and legacy-record regression. A producer can
rebuild a different internally consistent unsigned bundle and can omit an entire
unknown attempt. Such cases limit authenticity and completeness claims; they are
not detectable solely by internal hashes or schema checks. A recipient's retained
reference can support a narrower comparison.

Complete source and combined releases include the original toolkit and its tests
inside `app/`. From a fresh terminal at the extracted release root, the offline
Python 3.10+ standard-library checks are:

```sh
cd app
PYTHONDONTWRITEBYTECODE=1 python3 -S -m verify_toolkit self-test
PYTHONDONTWRITEBYTECODE=1 python3 -S -m unittest discover -s toolkit-tests
```

For the separate `n170-verify-toolkit.zip`, verify its exact archive hash before
extracting. Run those Python commands at its root containing `verify_toolkit/`
and `toolkit-tests/`, omitting `cd app`. The ZIP includes original editable source,
independent archive verification and metadata, with a separate detached checksum.
Use the [run-review contract](../verify_toolkit/RUN_REVIEW_V1.md) and
[account-reconciliation contract](account-reconciliation-contract.md) for exact
supported relationships, retained failures, private-data boundaries and unresolved
coverage. Do not modify the producer contract to turn an unsupported case into a pass.

Toolkit parser conformance, real-engine detector checks and realistic financial
execution validity are separate results. The optional engine remains separately
installed. Missing data, untriggered signals, stale exports and infeasible
execution do not become passes because a file parsed. Refer to the exact supplied
toolkit contract when evaluating newer run bundles.

No local check establishes real investment performance, broker authenticity,
complete accounts, independent time, external human review or competitive
superiority. See [methods](methods.md), [import formats](import-formats.md),
[evidence decisions](research-decisions.md) and [release status](release-readiness.md).
