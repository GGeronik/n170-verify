# N170 Verify

Prepare a performance record privately, explain its limitations, and give another person a copy they can check and retain.

N170 Verify is a free, open-source browser application. Its useful core is a complete **import → reconcile → review → sign → share → compare** workflow. It checks supplied evidence; it does not authenticate a broker, identify an applicant, measure investment skill or decide suitability for employment.

## Release status

This file describes the source at its tagged revision. It does not itself assert publication, deployment or a release identity; those are stated in the notes of a published release, not in this file. Supported signed v3/v4 records keep their versioned arithmetic and signature semantics. Current source includes retained-copy comparison, consistent-currency checks and protection against stale replacement-file results. See [release readiness](docs/release-readiness.md) and [validation scope](docs/release-validation.md) for the checks and remaining evidence gaps.

The [captured-run viewer](docs/tool-evidence.md) checks portable package bytes and selected-attempt relationships under the [run-review contract](verify_toolkit/RUN_REVIEW_V1.md). Separate CSV observation reports remain supplied unsigned research evidence. [Private account reconciliation](docs/account-reconciliation-contract.md) retains source attempts, unresolved intervals and input dependencies under owner-stated scope; it does not prove complete accounts. Neither workflow changes signed v3/v4 records or authenticates a producer. The original [AuditZK interface](docs/auditzk-adapter.md) is disabled or explicitly synthetic mock-only; no upstream implementation or authentic TEE verification is included.

The additive [accounting release guide](docs/accounting-release.md) describes v2 captured-run receipts, offline review and an optional separately installed accounting oracle. The browser keeps capture support, exact-decimal calculations, native compatibility and supplied oracle evidence separate. Only cash, quantity and accumulated net PnL have supplied native comparisons; the other six metrics remain `NOT_SUPPLIED`, so overall accounting remains `NOT_ASSESSABLE`. These receipts do not authenticate execution or establish financial realism. The Methods page offers a separate [68-case private-source challenge](release-assets/private-source-challenge/README.md) with its accepted checker and fixed evidence. An earlier 175-case kit for an older baseline is retained outside this distribution with its documented `INCOMPLETE` / exit `2` result; it excludes continuity and accounting.

## Use it

The standalone application opens directly at `/`. Choose **Prepare a record** for the owner workflow, **Review a record** for an employer or collaborator, or **Methods** for the trust boundaries. Synthetic examples are explicitly labeled and require the same preparation and signing actions as other data.

1. Start with **Ask your AI** to copy a complete prompt to your already connected broker assistant and bring back its file/reply, or choose the peer **Import a file** entry to import an export or enter dated portfolio NAV and external flows. The initial supported real format is **IBKR Activity Flex / Change in NAV CSV**, with explicit reconciliation and flow-timing restrictions. The N170 three-column format is also supported. Trading 212 transaction exports and Portfolio Performance asset-chart exports are recognized and explain the missing evidence; they are not converted into invented portfolio returns. See [supported formats and fixtures](docs/import-formats.md).
2. Review column mapping, currency, account scope, duplicate/missing observations, cash flows and unsupported events. In **Input-to-return reconciliation**, check requested dates, the expected valuation schedule, gross cash activity and flow timing. Retained unresolved sources require review; exclusion or supersession needs an explicit reason. Make supported corrections with reasons. Original values and source text stay in memory unless you choose to save or export a private draft.
3. Review actual calculated results and a chart from the disclosed returns. Annualized volatility is withheld when the sample or schedule does not support it. Choose a public profile alias, then explicitly sign and save.
4. Download one **readable HTML review package** with embedded signed JSON. It omits raw NAV and flow values while retaining dated returns, scope declarations, hashes and correction reasons. Send the file yourself; the app does not publish it or contact recipients.
5. The recipient opens the package in an independently obtained copy of Verify; see the [recipient guide](docs/recipient-guide.md). They can compare a trusted key code, a retained checkpoint and their previous file. Keep the checked copy for the next review.

The HTML is a static, unsigned presentation for reading. Imported HTML is never executed by the checker: it extracts the bounded evidence attachment and verifies that data. A file can be visually edited, so recipients should run the independent check before relying on its presentation. An aggregate summary export omits the relative-return series and **cannot reproduce itself**.

## Ask your AI

The preparation screen opens with **Ask your AI**, beside **Import a file**. The full prompt is visible in a read-only textbox with **Copy prompt**, **Select prompt** and **Download prompt**; all three use exactly the same text. Its friendly introduction asks your existing broker assistant for the selected account scope and dates when needed. The complete safeguards, JSON contract and example are included. There is no new assistant setup or broker connection in Verify.

Under **Bring its answer back here**, use **Choose AI file** or **Or paste your AI’s reply**, then **Review my record**. Pasting accepts plain JSON or one complete JSON/unlabelled code block and preserves the exact inner text. Surrounding prose, multiple blocks and incomplete wrappers produce an actionable error; the strict financial/schema checks remain. Switching entry modes keeps the draft. Loading a source collapses the prompt and moves focus to reconciliation.

Source metadata and actual values are visible before mandatory owner review. Missing retrieval, pages, observations or supported flow timing stay blocked even after acknowledgement. Clipboard failure selects the full prompt for ordinary copying, with download available as another route.

The [handoff guide](docs/agent-handoff.md), [JSON schema](schemas/agent-handoff-v1.schema.json), [synthetic example](examples/agent-handoff-synthetic.json) and [llms.txt](llms.txt) make this discoverable to assistants. The local command `node scripts/prepare-agent-handoff.mjs HANDOFF.json` reports safe status/counts without printing raw financial values. It does not connect accounts, sign or publish. An optional explicit `--csv PRIVATE.csv` creates a private file without overwriting existing data.

This reuses your assistant's already authorized source access. It is broker-agnostic where tools can supply actual matching NAV and cash activity, not a guarantee of every broker MCP's compatibility. A connection asserted in a file does not authenticate its source. Live/paper status remains unchecked. Your assistant's own privacy settings apply before the data reaches Verify. See the [handoff boundaries](docs/agent-handoff.md) and [validation scope](docs/release-validation.md).

## Six separate questions

| Question | What the application establishes | What remains unchecked |
| --- | --- | --- |
| Do the calculations reproduce? | Metrics match the disclosed dated returns under their versioned calculation rules | Whether private source amounts and flow classification produced those returns correctly |
| Are signatures and history valid? | Every supplied event hash, signature and predecessor link is checked | Other valid branches, omitted newer records, or any prior publication unless the reviewer supplies a reference |
| Where did the data come from? | The owner's manual/supplied-file declaration, mapping, reviewed corrections and source text digests are signed | Broker authenticity, execution, live/paper status and complete source acquisition |
| Who holds the key? | Signatures identify a signing key; an expected code can be matched | The person's legal identity, exclusive key control, account ownership or qualifications |
| What independent time exists? | The checker explicitly reports none | Creation/publication time; observation dates and pasted checkpoints are not timestamps |
| What coverage exists? | Supplied dates, observations, declared scope, corrections and gaps between periods are shown | Undisclosed accounts, missing observations within selected intervals, omitted strategies or unseen drawdowns |

A valid signature can cover fabricated numbers. A retained checkpoint binds the exact supplied prefix through one event; it does not stop the owner signing another history. Comparing an earlier copy identifies **extension, identical history, truncation, key/alias replacement or conflicting history**. The result names the checked checkpoint and says when no prior publication was checked.

## Calculations and corrections

New records use **format v4, calculation 2.0.0, serialization 1.0.0**. Existing v3 records retain their original calculation 1.0.0 and signature semantics. A v4 profile can append to an unchanged v3 prefix using the same key. See [FORMAT.md](FORMAT.md), [the frozen v3 specification](FORMAT-v3.md), and [financial methods](docs/methods.md).

The new pipeline subtracts decimal amounts exactly using scaled integers, rounds each relative return to 10⁻⁸, and calculates displayed and signed metrics from that same series using exact rational arithmetic. Supported input is 2-500 dated observations, ≤50,000 characters, plain decimal amounts of magnitude ≤10¹⁵ and ≤18 fractional places. Gross interval factors above 10,000, wealth outside 10⁻⁶-10⁶ times opening wealth, excessive relative rounding error, total loss, negative equity and unsupported recapitalization are rejected with a next action. End-of-interval external flows are required; intraperiod flows need additional valuations.

Annualized volatility requires at least 20 return intervals and a compatible supported schedule. This conservative product threshold is not a statistical reliability guarantee or a check against an exchange holiday calendar. Sampled drawdown cannot reveal losses between supplied observations. Fees and taxes affect results only to the extent they are already represented in source values.

A correction appends a signed event identifying the exact target hash and reason while retaining the original. Current performance uses the latest correction for each period; history shows every event. Corrected period boundaries must remain unchanged. Changes to account coverage or financial treatment remain owner declarations, never provider authentication.

## Privacy and key continuity

- There is no financial upload, broker connector, application account, analytics or telemetry in the current app. App assets and external links still use the network. Production CSP blocks fetch/XHR/WebSocket/beacon connection APIs; it is not a promise of zero network activity.
- Original source text and financial observations are working data in memory by default. **Save draft** explicitly stores them locally; **Export private draft** downloads them. Drafts are not encrypted by this app and are separate from public signed records.
- Review packages include aliases, covered dates, rounded returns, selected metadata, correction reasons, public keys and signatures. Financial amounts are not automatically attached. Owner-entered text can itself contain sensitive information; review it before sharing. Source hashes commit to UTF-8 text processed by the importer, not necessarily the original encoding's byte sequence. Hashes are commitments, not encryption.
- Creating a profile saves a nonextractable WebCrypto P-256 signing key in the site's IndexedDB. Raw private key material cannot be exported through WebCrypto. A loaded signing capability may be cloned or retained elsewhere; this does not establish hardware protection or exclusive possession.
- Signed records are validated and appended with a transactional comparison against the current stored history. Concurrent stale appends are rejected. Draft saves also compare revisions to avoid overwriting another tab's newer work. Navigation/reopen/close actions offer draft save, export or discard choices.
- Closing or switching a profile is separate from deleting its stored key. Storage deletion does not revoke existing signatures or cryptographically invalidate every already-loaded signing handle.
- **A profile export is not a key backup.** Clearing storage, browser eviction or private-session termination may permanently prevent further signing under that key. Exported records remain checkable. The additive continuity source candidate supports one to four dual-signed device changes while both keys for each transition remain available. Signed profile segments stay separate; inherited key authority does not establish independently retained history. See the [continuity contract](docs/key-continuity-contract.md) and [format decision](FORMAT.md#key-continuity-decision). Lost-key recovery, passkeys, external timestamps and revocation publishing remain unimplemented. This implementation scope is not evidence of a completed security audit or public release.

## Independently verify a file

For the verifier-derived evidence headline, run `node scripts/verify-headline.mjs CURRENT [PREVIOUS]`. Optional receipt checking requires an explicitly selected event digest and recipient-supplied trusted witness keys and allowed broker hosts; see [witness receipts](docs/witness-receipt.md). Headline exits are 0 for a supported tier, 1 for rejection, 2 for conflict and 3 for usage/read failure. The original record, private-source and continuity commands retain their own output status names and exit codes.

First verify the received source archive as described below. Run these commands in the folder containing `package.json` (`app/` after extracting a source archive). Node's standard cryptography and a separate arithmetic/serialization implementation are sufficient; the verifier does not import application code or require npm installation:

```sh
node scripts/verify-record.mjs examples/example-profile.json
node scripts/verify-record.mjs examples/review-profile-v4.html
node scripts/verify-record.mjs CURRENT.html PREVIOUS.html
```

Exit 0: implemented structural/arithmetic/signature checks passed and any comparison is identical or extended. Exit 1: invalid evidence/input. Exit 2: both files check individually, but comparison found truncation, replacement or conflicting histories. Every result keeps source authenticity, identity and independent time false. The verifier does not establish the provenance of its own installed code; obtain it through a channel you trust.

## Check deliberately supplied private source

The additive [private-source checker](docs/verify-reconciliation.md) compares an
explicitly selected existing signed v4 event with the owner's matching
`n170-private-reconciliation.json` export. That file contains unencrypted source
bytes, financial rows and source decisions; it is separate from a private draft
and is never automatically attached to a public review package. Share it only by
a deliberate choice. This check creates no key or signature and authenticates
neither a broker nor complete accounts.

First verify the downloaded complete source ZIP or combined offline toolkit ZIP
against a separately retained archive SHA-256, as described below. Both include
the fifteen standalone CLI modules in `scripts/`, their guides and schemas in
`docs/` and `schemas/`, and the root license/notice. In the complete source or combined
release, these paths are under `app/`; from its extracted root use `cd app`.
The separate `n170-verify-toolkit.zip` puts `scripts/` at the extraction root;
stay there and omit `cd app`. The Node CLI needs no npm install, browser build,
Python package, engine or broker access. Use Node satisfying the source's
`^20.19.0 || >=22.12.0` requirement.

From the appropriate folder containing `scripts/`, replace both quoted paths
and the explicit event-digest placeholder:

```sh
node scripts/verify-reconciliation.mjs --record "/absolute/path/to/signed-record.json" --event-sha256 EVENT_SHA256 --reconciliation "/absolute/path/to/n170-private-reconciliation.json"
```

`EVENT_SHA256` must be the selected event's 64 lowercase hexadecimal payload
digest, not a source/file checksum. The placeholder is invalid until replaced;
there is no automatic latest-event choice. A whole device-continuity envelope
is outside this command's accepted input; see the guide's single-profile boundary.
Read the JSON status and reasons: exit 0 is `VERIFIED_UNDER_OWNER_ASSERTIONS`,
1 is `MISMATCH`, 2 is `NOT_ASSESSABLE`, and 3 is `INVALID_INPUT`. Counts and selected
event metadata can still reveal workflow information. Keep both original inputs;
a compact result does not replace them.

## Check an additive continuity package

A continuity package contains two to five unchanged v3/v4 profile segments and
one to four dual-signed transitions. The existing single-profile verifier rejects
these envelopes; use the separate [continuity verifier](scripts/verify-continuity.mjs).
After verifying and extracting the source archive as described below, run from
the app folder containing `package.json` (`cd app` from the extracted full source
or combined release root). Replace the quoted paths with your retained files:

```sh
node scripts/verify-continuity.mjs "/absolute/current.json" --anchor-profile "/absolute/retained-root.json"
node scripts/verify-continuity.mjs "/absolute/current.json" "/absolute/previous-chain.json"
```

The Node standard-library command needs no npm installation. Exit 0 means the
implemented checks pass and every outgoing segment's final history head matches
caller-supplied retained evidence. Exit 2 means valid cryptographic linkage with
unanchored or partially anchored history, or a detected continuity conflict.
Exit 1 means malformed or cryptographically invalid evidence. Read the result,
including each edge's separate key and history anchors, before deciding whether
to accept the new key.

Retaining only the root profile can anchor that key while later keys inherit its
authority; it does not independently anchor later outgoing history heads. Such a
repeated chain remains `partial`. An earlier retained prefix also remains partial,
even for a single transition. A supplied reference cannot prove when or how it
was retained, and hidden competing transitions cannot be discovered offline.
Recipient acceptance is a separate decision. No metric is combined across key
segments, and no identity, broker, recovery or independent-time claim follows.
See the [exact continuity contract](docs/key-continuity-contract.md).

## Verify received source, then build

Keep the received archive unchanged and retain its expected SHA-256 through a channel you trust. Obtain the independent `verify_release.py` verifier through a trusted channel too. Before extraction or editing, use Python 3's standard library:

```sh
python3 verify_release.py source.zip --sha256 EXPECTED_ARCHIVE_SHA256
```

Replace both placeholders with the archive's actual filename and separately retained digest. The verifier checks the exact archive bytes, its file inventory and per-file hashes without extracting. A matching hash identifies bytes; it does not authenticate the publisher. The same verifier is included as `scripts/verify-release.py` for later use, but a file obtained only from an untrusted archive is not an independent trust anchor.

After verification, extract to a new directory. The source archive contains the application and editable Python sources in `app/`: `verify_toolkit/`, `verify_accounting/`, `toolkit-tests/` and `accounting-tests/`. A combined release adds root documentation and a `build.py` convenience wrapper; it does not duplicate the toolkit at the root. App and Python toolkit commands run in `app/`, the folder containing `package.json`. Use Node satisfying `^20.19.0 || >=22.12.0`, npm, and Python 3 available as `python3`. Building and offline package verification require no third-party Python packages; deliberate engine and optional oracle execution have separate installation requirements.

```sh
cd app
npm ci --ignore-scripts
npm run build
npm test
npm run preview -- --host 127.0.0.1 --port 4174 --strictPort
```

`npm run preflight` checks source inventory, local links, runtime and installed dependencies without writing a build; `npm run build` performs the same preflight automatically. If dependencies are missing, run `npm ci --ignore-scripts` first.

`npm ci` installs the locked dependencies. The included `.npmrc` disables install scripts and checks the Node engine requirement. A first installation needs registry access unless a complete matching npm cache is already available; dependencies are not included in the source ZIP. The preview serves the built app and its configured security headers. Use `npm run dev` separately for development; development mode does not have the production security boundary. `npm run check` additionally runs registry checks and therefore needs network access.

Some tests need retained evidence or separately installed software that is not part of this source, and are skipped without it. At this revision, `npm test` runs 792 tests: 788 pass and 4 are skipped unless `N170_ACCOUNTING_V2_PACKAGE_ROOT` (2 tests), `N170_RUN_REVIEW_PACKAGE_ROOT` (1) or `N170_WALLET_SCOPE_PACKAGE` (1) names a retained package. `python3 -S -m unittest discover -s toolkit-tests` runs 150 tests: 125 pass and 25 are skipped unless `N170_ACCOUNTING_EVIDENCE` names a directory of retained accounting captures. `python3 -m unittest discover -s accounting-tests` runs 51 tests: 48 pass and 3 are skipped unless `N170_BEANCOUNT_PYTHON` names a separately installed pinned oracle interpreter. A skipped test is not a pass; record skips with their conditions.

The conventional `npm run build` invokes the explicit public build. It produces the browser app in `dist/client`, the host worker in `dist/server`, selected public documentation and two downloads: `dist/client/n170-verify-source.zip` contains complete editable app and toolkit source under `app/`; `dist/client/n170-verify-toolkit.zip` contains `verify_toolkit/`, `verify_accounting/` and their two test directories at the archive root, plus the fifteen standalone CLI modules in `scripts/`, their guides and schemas in `docs/` and `schemas/`, and root `LICENSE`/`NOTICE`. Each ZIP has a detached `.sha256` file and includes an independent archive verifier and metadata. The build also serves `verify_release.py` and the six unchanged private-source challenge files described below. The challenge pack retains its own identity; delivering it creates a new app/source archive identity without changing the pack. [The exact public source inventory](scripts/public-source-inventory.json) determines which files may enter these ZIPs. Apart from the explicitly pinned synthetic challenge pack, historical internal reports, screenshots, private handoffs and the obsolete prototype are outside the public inventory. No dependency upgrade or account access is part of building.

### Offline toolkit review

In a fresh terminal at the extracted full source or combined release root:

```sh
cd app
PYTHONDONTWRITEBYTECODE=1 python3 -S -m verify_toolkit self-test
PYTHONDONTWRITEBYTECODE=1 python3 -S -m unittest discover -s toolkit-tests
PYTHONDONTWRITEBYTECODE=1 python3 -S -m verify_toolkit verify-review "/absolute/review.json"
```

Use Python 3.10+ for toolkit commands. The first two commands need no engine or
network; the third checks an existing captured run package without executing its
code. See [toolkit usage](verify_toolkit/README.md) and the
[run-review contract](verify_toolkit/RUN_REVIEW_V1.md) for status and comparison
semantics. Findings and unassessable evidence have distinct nonzero exit codes;
read the output and retain failures.

For the separate `n170-verify-toolkit.zip` download, first verify that exact ZIP
against its separately retained expected digest, then extract it into a new
directory. Run the Python commands above from that directory containing
`verify_toolkit/`, `verify_accounting/` and their test directories, omitting
`cd app`. The Freqtrade execution engine is installed separately; no strategy
runs during package verification.

For a v2 accounting receipt, retain the complete JSON and, when available, its
manifest SHA-256 from a separate trusted channel. From the extracted full source
or combined release root:

```sh
cd app
python3 -B -S -m verify_toolkit.accounting verify "/absolute/run-review-v2.json" --manifest-sha256 RECORDED_64_HEX_DIGEST
```

Use the same command without `cd app` from the separate toolkit extraction root.
Replace the digest placeholder with 64 lowercase hexadecimal characters; omit
the `--manifest-sha256` option if no independent digest is available and retain
that limitation. A ZIP digest identifies the downloaded software archive; the
receipt's manifest digest identifies the supplied run evidence. Neither
authenticates the producer. V2 overall accounting is currently `NOT_ASSESSABLE`
and the review returns exit `2`, even when supported calculations match. Read
the separate dimensions and reason codes, and preserve failures. See the
[combined download workflow](docs/accounting-release.md),
[v2 accounting instructions](verify_toolkit/ACCOUNTING_V2.md) and
[capture contract](verify_toolkit/CAPTURE_V2.md).

### Reproduce the 68-case private-source challenge

Choose **Methods → Reproduce the 68-case private-source challenge**. Save all six
files together: [instructions](release-assets/private-source-challenge/README.md),
[challenge ZIP](release-assets/private-source-challenge/n170-private-source-challenge-v1.zip),
[accepted checker](release-assets/private-source-challenge/accepted-offline-toolkit.zip),
[pack verifier](release-assets/private-source-challenge/verify_pack.py),
[checksums](release-assets/private-source-challenge/SHA256SUMS) and
[acceptance summary](release-assets/private-source-challenge/RELEASE.json).
These exact files are also served under `/private-source-challenge/`.

Follow the unchanged README to verify and reproduce the synthetic cases on Linux
or macOS with Python 3.9+ and Node `^20.19.0 || >=22.12.0`; no npm installation,
app build or financial engine is needed. The challenge ZIP SHA-256 is
`e7471919bdf7f5b42ab233d6c89c834a2a3f1952fd0aa268a5931a4b53b35f57`;
its manifest SHA-256 is
`5abe3172731422206ac4418f8c0b8f056b2e8b93d85d6d3624c7747549da2c83`.
Retain expected identities through a trusted channel and inspect the verifier.

The accepted local run matched all 68 expected status/exit pairs, including 31
conditional positive cases. The original result remains **51 raw passes and 17
flags**, with explicit case-by-case adjudication. The reproduction runner's
expected exit is 0 with no unresolved cases; the original 60-case harness still
exits 1 because the flags remain. Keep unsuccessful runs and read each result.
This finite synthetic challenge does not establish source authenticity, complete
accounts, investment performance, outside human review or outside-user
reproduction. It retains its own accepted checker, separate from the current
rebuilt toolkit.

### Earlier challenge kit

An earlier 175-case challenge kit preserved the wave2 compatibility-v4 tested
source. Its documented no-scored-failure result is `INCOMPLETE` / exit `2`,
because its frozen report leaves separate engine and public-build challenges
unrun. It excludes continuity and accounting and is not validation of this
source. The kit is not part of this distribution. Its four delivery files keep
their original identities in private records.

### Maintainer changes are new source

Retain the original ZIP and its receipt before editing. Modify the extracted code, run `npm run build` and `npm test`, and retain the newly generated source ZIP and its new manifest as a distinct artifact. The build hashes the current explicitly inventoried files; it does **not** require edited sources to match the received archive's immutable `MANIFEST.json`. Updating code changes the artifact identity. Never replace the old receipt or describe a modified tree as the original received bytes.

When adding a public file, review its contents and update `scripts/public-source-inventory.json` explicitly. A new file does not become public merely because it exists in the working tree. Local source links, regular-file/path checks and the selected public documentation are checked during the build. The combined release's root `python3 build.py` is a convenience entry point for the same app build, not a separate historical packaging path. [Contribution guidance](CONTRIBUTING.md) describes this workflow.

The optional real-browser harnesses require an available Playwright installation and its browser binaries; Playwright is not a production dependency and these commands do not install anything. Point `PLAYWRIGHT_MODULE` to its module entry if it is outside normal Node module resolution. For example:

```sh
# In one terminal, serve the completed production build:
npm run preview -- --host 127.0.0.1 --port 4174 --strictPort

# In another terminal, in the same app folder; replace both absolute paths:
export PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs
export N170_EVIDENCE_DIR=/absolute/output/directory
mkdir -p "$N170_EVIDENCE_DIR"
npm run test:browser
npm run test:storage
npm run test:agent-handoff
npm run test:lifecycle
npm run test:accessibility
```

`N170_PREVIEW_URL` can select a different loopback production-preview URL for `test:agent-handoff`, `test:browser`, `test:lifecycle` and `test:accessibility`. The lifecycle suite covers file/draft navigation, reload protection and local profile close/deletion. The accessibility harness checks rendered text contrast, dialog keyboard focus/Escape and narrow reflow; it is not a full assistive-technology or WCAG conformance audit. The storage harness starts its own isolated loopback fixture origin and tests the current modules; it does not test production CSP or the full interface. Keep these scopes separate when interpreting results. Playwright WebKit is not the Safari application.

The browser harnesses generate original synthetic evidence. Keep `N170_EVIDENCE_DIR` outside the extracted public source directory and record the exact archive hash, runtime/browser versions, command, exit status and failures. `npm run test:comparison` exercises received/retained-copy review; `node scripts/browser-comparison.mjs --fixtures-only` only checks generated fixtures and is not browser acceptance. Automated checks are not an external audit or an outside-user study. [Validation scope](docs/release-validation.md) separates test coverage from unsupported dimensions.

Security headers are implemented in [worker/index.js](worker/index.js) and reused for production preview. The build embeds the CSP subset supported by a meta element. The included [`wrangler.jsonc`](wrangler.jsonc) runs `dist/server/index.js` before every request, with an `ASSETS` binding to `dist/client`, so the worker's headers apply to every response; another static host needs an index fallback and the actual response headers. A local build does not demonstrate that a public host enforces them.

Exact dependencies, lockfile integrity and disabled install scripts are configured. Repository CI configuration is included; its presence is not evidence of successful remote runs, required reviews or branch protection. This file asserts no status badge, repository availability or private reporting service; check the repository itself.

## Full-stack Wave-4 verification platform (`core/`, `api/`, `mcp/`, `web/`)

Alongside the standalone browser record workflow and offline toolkit above, this repository includes the modular **N170 Verify v3** verification stack (`VerifyProofBundle`, schema `n170-verify/v3`) for salted Merkle selective disclosure, calibrated brokerage reconciliation, counterfactual and behavioural coaching analytics, subprocess-isolated HTTP verification, zero-secret stdio MCP verification, and an optional Next.js tear-sheet and WebCrypto verification studio.

### Six orthogonal assurance axes

Rather than collapsing provenance into a single opaque badge, `VerifyProofBundle` verification evaluates six separate axes dynamically at check time:

1. **Origin assurance (`OriginAssurance`)** - Re-derived by the verifier (`broker_signed`, `independently_witnessed_tls`, `operator_retrieved`, `self_reported`) from cryptographic evidence; self-asserted origin headers are never trusted.
2. **Account scope (`AccountScope`)** - Separates enumerated multi-subaccount coverage (`all_enumerated_subaccounts`) from single-account survivorship uncertainty (`single_account_survivorship_uncertain`) and offline exports (`unknown_offline_scope`).
3. **Provider approval state (`ProviderApprovalState`)** - Distinguishes live approved integrations (`approved_live`) from user-key self-attested APIs (`user_key_self_attested`), pending vendor reviews (`pending_provider_approval`), and offline exports (`offline_export_only`).
4. **Environment tier (`EnvironmentTier`)** - Rejects paper, demo, and sandbox scopes (`DU*`, `PA*`, `paper-api.alpaca.markets`, `sandbox.tradier.com`, Trading 212 demo/CFD) from `live_production`.
5. **Signer trust status (`SignerTrustStatus`)** - Checks Ed25519 publisher keys against a C2SP-checkpointed registry (`official_n170_hosted`, `retired_historical_valid`, `revoked_key`, `unrecognized_self_hosted_signer`).
6. **Chain continuity mode (`ChainContinuityMode`)** - Evaluates prospective hash-linked sequence invariants (`prospective_continuous`, `retrospective_backfill`, `unenrolled_single_snapshot`, `continuity_broken`).

As with v3/v4 browser profiles, cryptographic signatures identify a signing key and committed bytes; they do not establish a person's legal identity, undisclosed accounts, or future investment skill.

### Platform layout

| Path | Role |
| --- | --- |
| [core/](core/) (`n170_verify`) | Unified verification pipeline (`verify_portfolio`), CLI (`n170-verify`), RFC 8785 JCS + domain-separated salted SHA-256 Merkle + Ed25519 cryptography, C2SP checkpoints, dynamic `k >= 2` TLS witness quorum checks, TWR/XIRR + Getmansky-Lo-Makarov MA(2) PSR/MinTRL econometrics (`T >= 30`), calibrated multi-section reconciliation, SEC EDGAR / FRED ALFRED / GDELT catalyst alignment, FIFO behavioural coaching, and read-only/offline broker connectors. |
| [api/](api/) (`app`) | Subprocess-isolated (`spawn` + `RLIMIT_CORE=0` + `PR_SET_DUMPABLE=0`) HTTP/FastAPI service (`POST /api/v1/verify` with zero default retention), opt-in AES-256-GCM envelope-encrypted sync vault, `/.well-known/n170-verify-keys.json`, SVG assurance badges, and multi-axis filtered leaderboard. |
| [mcp/](mcp/) ([mcp/README.md](mcp/README.md)) | Zero-dependency Node.js stdio MCP verifier (`mcp/server.js`) guarded by `McpAllowlistFirewall` so broker credentials, cookies, local file paths, and arbitrary URLs never enter tool arguments. |
| [web/](web/) ([web/README.md](web/README.md)) | Next.js 15 + React 19 + TypeScript tear-sheet studio (`/p/[proofId]`), offline WebCrypto verifier and selective leaf redaction studio (`/verify`), connector onboarding (`/connect`), and assurance-filtered leaderboard (`/leaderboard`). |
| [tests_e2e/](tests_e2e/) | End-to-end adversarial, privacy-redaction, subprocess-isolation, and three-language (Python, Node.js MCP, WebCrypto) parity suites. |
| [docker-compose.yml](docker-compose.yml) | Hardened container stack (`read_only: true`, `cap_drop: ALL`, `no-new-privileges`, `ulimits.core: 0`) with optional local `ollama` narration profile and [.env.example](.env.example). |

### Salted Merkle selective disclosure

Every `VerifyProofBundle` commits to seven domain-separated (`0x00` leaf / `0x01` internal node), 256-bit salted SHA-256 leaves (`core_metrics`, `indexed_curve`, `reconciliation`, `coaching_and_context`, `capital_bracket`, `benchmark_alpha`, `delayed_closed_trades`) and a one-way `HMAC-SHA256` `blinded_account_tag`. Holders can redact any subset of leaves before sharing (`--disclose`, `redact_proof_bundle_leaves`, or `/verify`) while preserving root signature verification across Python (`n170_verify`), Node.js (`mcp/server.js`), and browser WebCrypto (`web/src/lib/browserVerify.ts`).

### CLI, API, MCP, Web, and Docker quickstart

```sh
# 1. Inspect capabilities and generate an Ed25519 keypair outside the repo tree
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=core python3 -B -m n170_verify.cli capabilities
mkdir -p /var/tmp/n170-verify-keys
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=core python3 -B -m n170_verify.cli keygen \
  --seed-out /var/tmp/n170-verify-keys/publisher_seed.hex

# 2. Verify an offline statement with selective leaf disclosure and check the bundle offline
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=core python3 -B -m n170_verify.cli verify-csv \
  --broker degiro /path/to/export.csv \
  --signing-seed-file /var/tmp/n170-verify-keys/publisher_seed.hex \
  --disclose core_metrics,indexed_curve,reconciliation \
  --output /tmp/sample.verify.json
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=core python3 -B -m n170_verify.cli check-bundle /tmp/sample.verify.json

# 3. Run the subprocess-isolated verification API and zero-secret MCP server
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=core:api python3 -B -m app.main --host 127.0.0.1 --port 8080
N170_VERIFY_API_URL=http://127.0.0.1:8080 node mcp/server.js

# 4. Run core, API, end-to-end, MCP, release-boundary, and web studio checks
python3 scripts/public_release_audit.py --root . --tracked --require-license
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=core:api:api/tests python3 -B -m pytest core/tests api/tests tests_e2e tests/test_public_release_audit.py -q
node --check mcp/server.js && node --test mcp/server.test.js
cd web && npm ci --ignore-scripts && npm run lint && npx tsc --noEmit && npm test && NEXT_TELEMETRY_DISABLED=1 npm run build
```

For containerized deployment (`api` on `127.0.0.1:8080` and `web` on `127.0.0.1:3000`, plus optional self-hosted `--profile ollama`), copy `.env.example` to `.env` outside public source builds and run `docker compose -f docker-compose.yml config --quiet`.

## Product status and contribution

This is a local pilot candidate. The useful workflow is private reconciliation, transparent corrections and a portable review that preserves prior evidence. Signatures and analytics are established techniques; no competitive superiority claim follows from the local checks. The [evidence decisions](docs/research-decisions.md) describe the product boundaries.

The standalone application is `src/main.jsx → src/App.jsx → OwnerWorkspace / EmployerReview`. Its public build contains the explicit current source inventory. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution and maintainer guidance and [SECURITY.md](SECURITY.md) for responsible reporting.

Copyright 2026 Geronik LLC. Licensed under [Apache-2.0](LICENSE), with [NOTICE](NOTICE). The license does not grant rights to N170 names or logos. This is research and record-review software, not investment advice.
