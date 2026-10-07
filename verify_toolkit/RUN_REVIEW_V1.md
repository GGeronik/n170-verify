# N170 portable run review, version 1

Contract identifier: `n170.run-review.v1`. This is a bounded data-only JSON
transport for an existing `n170.freqtrade-run.v1` receipt. It is not a signature,
proof of execution, external audit, or authenticated producer statement. Nothing
in the package is extracted or executed by verification or comparison.

## Envelope

Exactly three keys are permitted: `schema`, `manifest`, `artifacts`.
`schema` is exactly `n170.run-review.v1`. `manifest` is one descriptor for
`manifest.json`. `artifacts` is an array of descriptors sorted by ASCII path.
Each descriptor has exactly `path`, `size`, `sha256`, `base64`. `size` is a
nonnegative safe JSON integer, `sha256` is 64 lowercase hexadecimal characters,
and `base64` is canonical RFC 4648 padded base64 of the exact file bytes.
Every digest and size is recomputed. The manifest descriptor is never counted
as an artifact; it is optionally checked against a separately supplied SHA-256.

Paths are 1–240 ASCII characters from `[A-Za-z0-9_./-]`, relative, and contain
no empty, `.` or `..` segments. Paths must be unique, including case-insensitive
comparison; no file may also be an ancestor directory of another file. The
manifest may not occur in `artifacts`. Manifest artifact entries have exactly
`path`, `size`, `sha256`, in the same sorted order and equal the envelope inventory.
Uninventoried, missing, duplicate, ambiguous, and mismatched bytes are invalid.

## Resource limits and JSON

Envelope: 96 MiB UTF-8; decoded total (including manifest): 64 MiB; each artifact:
16 MiB; manifest: 4 MiB; at most 128 artifacts. Each parsed JSON document has at
most 24 nesting levels (root at depth 0), 200,000 nodes (values plus object keys),
and 4 MiB per string. Duplicate object keys, the object keys `__proto__`, `prototype`, `constructor`,
negative-zero numbers, non-finite numbers, integer-valued
numbers outside ±(2^53−1), lone UTF-16 surrogates, BOMs, invalid UTF-8, trailing
JSON, and unsupported JSON types are rejected. The envelope's base64 strings
are exempt from the 4 MiB string limit and remain subject to file/total bounds.
Integral numeric spellings such as `120.0` and `1.2e2` are interpreted as the safe
integer 120 consistently in Python and JavaScript; booleans are never numbers.
The limits apply before recursive receipt processing. Input source files remain
opaque bytes and are never imported. JSON inputs and retained JSON outputs are
strictly parsed within their applicable file limits.

## Receipt relationships

The original complete run manifest is carried byte-for-byte. Verification applies
the existing `verify_run` accounting checks and additionally checks every selected
attempt and all supplied outputs, including unsuccessful outcomes. Manifest,
request, strategy, staged config, selected input inventory, worker request digest,
worker input inventory, pinned engine revision/source inventory, engine arguments,
observed environment, output digests, CSV assessment, stdout transport, and selected
attempt summary must agree when applicable. Supplied worker stdout bundles must
exactly match all retained output files for every outcome. Nonzero exits may remain
`FAILED`; timeouts, cancellations and skipped attempts remain explicit. A skipped
attempt without staged inputs has valid accounting but is `NOT_REPRODUCIBLE`.
A package missing a manifest-inventoried file is `INVALID` and `NOT_REPRODUCIBLE`.
An invalid/missing output outcome is preserved when the receipt consistently records
that failure; it never becomes a clean result.

The supported runner scope is original synthetic BTC/USDT spot metadata, one pair,
five-minute JSON candles, a separately installed immutable Freqtrade 2026.8 engine,
and explicit selected strategies. Unsupported or absent prerequisites remain visible.
No claim establishes broker provenance, producer identity, trusted execution,
global attempt completeness, realistic fills, profitability, or absence of bias.

## APIs and report

Python: `export_run_review(directory) -> dict`,
`verify_run_review(raw, manifest_sha256=None) -> dict`,
`compare_run_reviews(left_raw, right_raw) -> dict`.
`raw` is UTF-8 bytes or text, never an already parsed object.
The verifier returns `schema: n170.run-review-verification.v1`,
`integrity: VALID|INVALID`, receipt `status`, `manifest_sha256`, `manifest_pin`,
`summary`, `attempts`, `reproducibility: {status: READY_TO_RERUN|NOT_REPRODUCIBLE,
missing: [...]}`, `trust`, and `reason_codes`. READY_TO_RERUN only describes retained
input prerequisites; a separately obtained matching engine and explicit review of
executable strategy/worker code are still required. A matched digest pin binds
bytes only; its producer and delivery channel require independent authentication.
Invalid packages retain no trusted summaries. Export packages all inventoried bytes
and rejects unsafe paths or extra local files; consistently recorded unsuccessful
runs are exportable. It does not overwrite an existing CLI output.

## Semantic comparison

Comparison first independently verifies both packages. Any invalid package yields
`NOT_COMPARABLE`. Complete comparisons return `SAME` or `DIFFERENT`, with changed
semantic sections and evidence-only byte differences surfaced separately. Missing
staged inputs yield `NOT_COMPARABLE`. Matching comparisons do not establish
independent rerun, authenticity, deterministic execution, or completeness.

Only these incidental receipt fields may be ignored: manifest `run_id`,
`execution_root`, `started_at`, `finished_at`; attempt `started_at`, `finished_at`,
and `container_name`; validated invocation host executable and the host mount/name
positions implied by that manifest. Artifact inventory digests are derived fields,
not independent semantics. All input bytes (including request/config/source/data),
engine identity, selection/order, budgets, arguments, outcome, reason codes, environment,
worker result fields, outputs, summary and unknown fields are retained. Log bytes
remain significant except the exact validated stdout result-transport line, whose
contents are compared through retained output bytes. The only log timestamp normalization is an anchored line prefix matching
`YYYY-MM-DD HH:MM:SS,mmm` immediately followed by either
` - freqtrade[.logger]* - LEVEL - ` or ` LEVEL freqtrade[.logger]* `.
Logger segments are ASCII identifiers and LEVEL is DEBUG, INFO, WARNING, ERROR,
or CRITICAL. Only that leading timestamp is replaced. Logger, severity, message,
unrecognized lines, strategy messages, date literals and UUIDs remain significant.
A changed diagnostic message is conservatively DIFFERENT. `evidence_differences`
still identifies exact log-byte changes. SAME failed/insufficient outcomes compare
the same failure; they do not establish successful reproduction.
Manifest formatting-only differences are surfaced as evidence-only differences.

## Recipient CLI

`python -m verify_toolkit export-run RUN_DIRECTORY --output review.json`

`python -m verify_toolkit verify-review review.json [--manifest-sha256 DIGEST]`

`python -m verify_toolkit compare-runs original.json rerun.json`

Verification exits 0 for an intact no-findings receipt, 1 for intact findings, and
2 for invalid or unassessable evidence. Export exits 0 after an intact package is
written (unsuccessful outcomes remain inside it). Comparison exits 0 for SAME,
1 for DIFFERENT and 2 for NOT_COMPARABLE. Retain the original run directory and
share the manifest digest separately when the recipient can authenticate that channel.
