# Private account reconciliation contract

Version: `n170.account-reconciliation.v1`. This is a local preparation artifact, not a signed-record schema or an authentication result. Existing signed records and calculation version 2.0.0 retain their existing semantics.

## API and data authority

`captureSource({ text?, bytes?, fileName, format = 'auto', currency, frequency, flowTimingConfirmed })` returns a JSON source entry. `bytes` may be an ArrayBuffer, Uint8Array or byte array. SHA-256 identifies the exact consumed bytes, including BOM and line endings. Strict UTF-8 decoding preserves BOM in `text`; invalid UTF-8 retains `bytes_base64` and a blocking issue. `id`, `sha256`, `byte_length`, `file_name`, `text`, `bytes_base64`, `rows`, `issues` and importer `review` describe the source. CSV row numbers are logical records, not physical lines; `raw_cells` are parsed strings and are not substitutes for the raw bytes. JSON observations use JSON pointer references. Malformed sources are retained with errors.

`reconcileAccount({ input, original = '', fileName = '', format = 'auto', currency, frequency, accountScope, flowTimingConfirmed, corrections = [], sources = [], period, expectedSchedule = 'observed_boundaries', flowActivity = 'unknown', flowTiming = 'unknown' })` rebuilds every derived result from raw source text/bytes and existing importer/calculator rules. The active source is `original || input`. Historical `sources` accept `{ text, fileName, format?, disposition, reason, rawBytesBase64? }` or captured source entries. Recognized dispositions are `unresolved`, `excluded`, `superseded`; exclusion or supersession needs an explicit reason. An unresolved attempted source blocks the draft. Caller-supplied hashes, rows, reviews and success flags have no authority. A private correction chain must pass the existing draft-model validation and connect the original normalization to the current input.

The result exposes `schema_version`, `source_inventory`, `review`, `normalizedCsv`, `normalized_sha256`, `scope`, `intervals`, `blocking_issues`, `canCalculate`, `selected_scope_status`, `corrections`, and `dependency_sha256`. All source and interval provenance is `owner_supplied`, with `authenticated: false`. A digest proves consistency with the enclosed bytes; it does not identify their author, authenticate a broker, or prove undisclosed accounts do not exist.

## Scope and missingness

Scope includes the owner's account alias, requested start/end, reporting currency, expected observation schedule, flow-activity statement and timing statement. Empty period dates derive bounds from available observations. Explicit boundaries require observations at those boundaries; a requested period that drops supplied observations blocks until separately reconciled. `observed_boundaries` evaluates only supplied boundaries and makes no daily-completeness claim. `calendar_daily` requires every calendar date. `weekdays` requires every Monday–Friday date and does not infer exchange holidays. Missing boundaries remain represented as null observations and unresolved intervals. No value or zero flow is forward-filled.

Duplicate/conflicting dates, overlapping statements, rejected rows, source errors, currency conflicts and unsupported activity remain visible and block the selected draft. An exclusion/supersession records an owner's selection decision; it never establishes whole-account completeness. `selected_scope_status` is `blocked` or `calculable_under_owner_assumptions`. Whole-account completeness is always `not_established`.

## Interval method and dependencies

Every interval contains `start`, `end`, `duration_days`, `opening_nav`, `closing_nav`, `external_flow`, `adjusted_closing_nav`, `economic_change`, `flow_kind`, nullable `return_e8`, `status`, `blocking_reasons`, `dependencies` and `dependency_sha256`. `status` is `calculable` or `unresolved`. Unavailable returns remain null, never zero. Decimal amounts are exact decimal strings computed with BigInt at 18 decimal places. The existing calculator supplies the supported rounded return:

`return = (closing NAV − end-of-interval external flow) / opening NAV − 1`

`economic_change = closing NAV − external flow − opening NAV`.

Deposits are positive, withdrawals negative and zero is explicitly a net zero. `flowActivity = reviewed_no_hidden` and `flowTiming = interval_end` are owner statements required to calculate, even for zero net flow. `offsetting` cannot be resolved by a net-flow series: separate gross cash activity and valuations at actual flow times are required. `intraperiod` and `unknown` timing are unsupported. Zero/negative opening NAV, nonpositive adjusted wealth, total loss, extreme precision/range cases and unsupported currency conversion stay unresolved. Supported currencies are USD, EUR, GBP, CHF, CAD, AUD and JPY, with no conversion.

Dependencies include both opening and closing observation references and the closing-flow reference. Corrected observations identify their normalized row and the original source row plus applicable correction steps. Dependency hashes bind the active source digest, current normalized digest, interval values, dates, scope, corrections and all dependencies. Changing an opening observation changes the interval digest. A stronger claim about a closing value never upgrades the interval's provenance.

## Private artifact, limits and recovery

`makeReconciliationArtifact(result)` produces a clearly marked private JSON artifact containing source filenames, exact raw bytes (base64), decoded source text, parsed cells, dates, currencies, account aliases, NAV values, flows, corrections, selection/exclusion reasons, issues, interval dependencies and hashes. It contains no signing key. It is not encrypted. Explicitly exporting it reveals private financial data to anyone receiving the file. It is never automatically included in shared profiles, signed JSON or review packages.

The separate [source-to-signed-event checker](verify-reconciliation.md) accepts a deliberately supplied artifact and an explicitly selected existing v4 event. It independently reconstructs its supported source formats and compares commitments, scope, interval facts and signed returns. A passing check remains conditional on owner assertions; the artifact schema, signed projection and completeness limits are unchanged. Private dependency digests are not promoted to signed proof, and preparation corrections are outside the checker's v1 support.

Inputs are bounded to 10 MiB total source bytes, 20 sources including the active source, 5,000 total logical source rows and 500 working observations. Expected schedules are limited to 5,000 calendar boundaries before expansion. Existing importer/parser bounds can be stricter. Out-of-bound requests block rather than silently truncating into a successful calculation. Raw excess historical entries remain in `rejected_source_entries` for recovery. The workspace must preserve its current valid draft when a replacement cannot be decoded/validated, while recording the attempted source for review. This module does not delete or replace stored work, manipulate keys, perform network requests, or publish artifacts.

When a file is too large to consume or cannot be read, the workspace may retain an attempted-source sentinel `{ text: '', fileName, disposition, reason, unconsumed: { byteLength, reason } }`. Its `byteLength` must be a nonnegative safe integer and is an owner/device claim about unread bytes, not a consumed-byte measurement. The inventory explicitly reports `source_bytes_available: false`, null source identity/digest, and `source_bytes_unavailable`; it never hashes an empty string and pretends to identify the unavailable file. The unresolved attempt blocks. An explicit reasoned exclusion remains an owner selection decision. A private artifact with this sentinel does not contain the original unread file, and that missing evidence remains disclosed.

## Required independent challenges

Test gains, valid losses, cashflow-dominated unsupported losses, positive deposits, negative withdrawals, net-zero offsetting flows, unknown/intraperiod timing, missing leading/middle/trailing dates, duplicate/conflicting overlaps, rejected rows/files, currency conflicts, BOM and CRLF identity, correction tampering and changes to each dependency. Expected arithmetic should be computed independently using exact rational numbers. Agent validation is not an external audit.

## Workspace recovery behavior

A replacement is parsed and its combined private inventory is bounded before the owner is asked to replace unsaved work. Intrinsically blocked or malformed replacements preserve the current working observations and enter the source inventory as unresolved attempts. Browser read failures retain an explicit bytes-unavailable entry. A successfully replaced source also remains unresolved until the owner records its exclusion or supersession reason; choosing a synthetic example preserves this history. Clear workspace is an explicit reset. Stale reads cannot replace a newly mounted workspace, and source-decision editors reset when their underlying inventory changes. External private-draft imports are fully validated before prior review confirmations are cleared.

The new owner flow does not change the signed projection. The private requested-schedule decision, rejected-source ledger and reconciliation artifact are not signed into existing records or silently attached to shared profiles. The shared record still declares only its observation boundaries and existing provenance. Source authenticity, account completeness and omitted accounts remain unestablished. A maintainer must not present this private workflow gate as a new recipient-verifiable completeness proof.
