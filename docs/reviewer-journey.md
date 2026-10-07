# Account preparation and independent reviewer journey

The account-report workflow makes checks and limitations visible at the point where the owner or recipient needs them. It does not change financial calculations, signed payloads, import formats, key handling, or the independent verifier.

## Reviewable evidence

- The importer already returned source-row counts, observation counts and source dates, but the owner screen only showed rows, mappings and exceptions. Reconciliation now displays these counts and dates, labels them as supplied-file coverage, and distinguishes calculation readiness from missing evidence. Source dates describe the original file; the observation table shows current values after any explicit corrections.
- Flow assumptions and loss limits were scattered across warnings and documentation. A keyboard-operable disclosure beside account scope now explains deposits/withdrawals, transfers across or within declared scope, retained income, fees/taxes, offsetting flows, required valuations, unsupported events, missing dates/accounts, and corrections. The sign review displays counts from the existing calculator output and explicitly acknowledges a losing period. Synthetic drafts remain visibly synthetic on this screen.
- The reviewer could see returns but did not have a concise count of losing intervals or flow-bearing observations. Each signed event now displays those counts from its already-validated payload. Superseded records keep their own counts. Counts do not authenticate cash activity or prove complete coverage; no combined currency or account return is introduced.
- The reviewer was told to use an independent CLI without a runnable command. Owner sharing and reviewer results now include identical commands, current-versus-previous argument order, quoted example paths, runtime prerequisites, exit 0/1/2 interpretation and source/identity/time/privacy limits. Separate tool observations and AuditZK attestation are explicitly outside this verifier's scope.

## Owner walkthrough

1. Choose **Import a file**, bring an existing supported export or N170 observations, or use the existing assistant handoff path. Synthetic examples are for practice; do not present them as real accounts.
2. Review currency and declared public account aliases. Open **What to reconcile: losses, flows and coverage**. Check all available NAV and cash activity, including losing periods and offsetting flows. Missing evidence stays missing; do not delete inconvenient rows or insert guessed amounts.
3. Reconcile the file. In **Input-to-return reconciliation**, check requested dates and expected valuation coverage, review gross cash activity and confirm actual flow timing. Check retained source attempts, interval dependencies, source counts, dates, exceptions and current observations. Source count equality is not proof of completeness. Fix supported row errors using **Correct**, with a shareable reason. Importer-reported unsupported events require source review rather than a forced passing result.
4. Choose **Review calculation**. Check the disclosed counts, period loss, withheld metrics and synthetic label before selecting a profile and signing. One consistent currency is used; there is no currency conversion.
5. Download and inspect the review package or signed JSON. Share only by a separate deliberate action outside the app. Keep original financial files/private drafts private unless choosing to disclose them separately. A signed record is not a signing-key backup.
6. For a later correction, reopen the private observations, correct the row, review again, select the original under **Record purpose**, and sign a correction with the same period boundaries. The earlier signed event stays in history.

The [private account-reconciliation contract](account-reconciliation-contract.md)
adds explicit requested boundaries, valuation schedules, retained source attempts
and input dependencies. In **Input-to-return reconciliation**, unresolved sources
or intervals block the selected draft; an exclusion needs an owner's reason.
A missing value is not filled with zero, and source counts or an owner's decision
do not prove complete accounts. Private reconciliation exports contain raw source
bytes and financial rows and are never automatically attached to signed records.
Existing shared records retain their original observation-boundary semantics.

## Recipient walkthrough

1. Open **Review a record** in a copy of the app from a source you trust. Import the received HTML review package or signed JSON as data, then choose **Check record**.
2. Read the result, dates, source/account/currency claims, losing intervals, flow counts, missing coverage and corrections. Valid signatures and arithmetic do not prove source authenticity, account ownership, independent time, freshness or complete accounts.
3. Supply your own retained previous file under **Add earlier evidence for comparison**. A file received from the same sender now is not an independently retained historical reference. Keep both files if history is replaced, shortened or conflicts.
4. For a separate implementation, obtain the source through a trusted channel. Verify the source archive as described in the [release guide](release-readiness.md), extract it, and open a terminal at the extracted root. The commands enter its `app` subfolder containing `package.json`. With supported Node.js:

   ```sh
   cd app
   node scripts/verify-record.mjs "/path/to/current-record.json"
   node scripts/verify-record.mjs "/path/to/current-record.json" "/path/to/previous-record.json"
   ```

   HTML packages are also accepted. No package installation or broker access is required for this verifier. Exit 0 means implemented evidence checks pass, with an identical/extended comparison if supplied. Exit 1 rejects evidence/input. Exit 2 means both files pass individually but comparison detects replacement, truncation or conflicting history. Inspect the output as well as the exit code. This does not verify the installed verifier's own provenance.
5. Retain the exact checked file and any checkpoint. Retention alone is not an independent timestamp. The public verifier reproduces disclosed relative returns to metrics. If the owner deliberately supplies a matching private reconciliation export, the additive [source-to-signed-event checker](verify-reconciliation.md) can independently check supported source observations against one explicitly selected existing v4 event. Its passing status is conditional on owner assertions; unsupported inputs and missing evidence remain unassessable. The private export contains unencrypted financial data and is never attached automatically.

## Reproduction and scope

App test and browser commands below run in the folder containing `package.json`
(`cd app` from the complete source or combined release root). Install the locked dependencies and
build the public app:

```sh
npm ci --ignore-scripts
npm run build
```

See the [release guide](release-readiness.md) for archive verification, runtime
requirements and the separate maintainer workflow. The browser harness also
requires an existing Playwright runtime; set `PLAYWRIGHT_MODULE` when it is outside
the app package.

Focused non-browser validation:

```sh
node --test tests/reviewer-journey.test.mjs tests/calculator.test.mjs tests/importer.test.mjs tests/signing.test.mjs tests/record-reliability.test.mjs tests/draft-model.test.mjs
```

The new tests render the actual help components, extract the two actual displayed commands, and execute the separate verifier with original synthetic signed fixtures and file paths containing spaces. They exercise passing checks, invalid input and shortened history. They are not browser/accessibility tests.

For production browser acceptance, start the built app in one terminal whose
working directory is the `app` subfolder, and leave that server running:

```sh
npm run preview -- --host 127.0.0.1 --port 4174 --strictPort
```

Then open a second terminal in the same `app` subfolder containing `package.json`
(`cd app` from the complete source or combined release root) and run the harness against that server.
Replace the output placeholder with the chosen evidence directory:

```sh
N170_PREVIEW_URL=http://127.0.0.1:4174/ N170_EVIDENCE_DIR=/absolute/output/directory node scripts/browser-reviewer-journey.mjs
```

This harness checks desktop 1440×1000 and mobile 390×844, native-disclosure keyboard behavior, source counts, an original synthetic loss/deposit/withdrawal/zero-flow fixture, signing and retained correction history, independent verification of downloaded records, error-free rendering, page overflow, no external requests and checking after the already loaded application is taken offline. It writes result JSON and screenshots for visual inspection. A passing exit alone does not establish that screenshots were reviewed.

No real account input, live broker, outside human recipient, screen reader or full WCAG audit was available for this increment. Fresh installation while offline, native Safari and Firefox are not covered by this harness. The standalone HTML package format and its presentation remain unchanged; the clearer instructions appear in the app’s owner and reviewer views.

## Public validation scope

The commands above generate current synthetic results for the exact source being
checked. Historical task-local logs and screenshots are outside the public
inventory. The [validation guide](release-validation.md) explains what to record,
including all failures and unsupported dimensions. Automated synthetic checks do
not establish real-account validation, outside human review or an external audit.
