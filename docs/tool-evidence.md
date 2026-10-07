# Tool evidence and captured run review

The app imports the existing `n170.tool-evidence.freqtrade-lookahead.v1` JSON contract into a separate local observation review. These observations are unsigned supplied-output claims. They do not change account calculations, signed performance records, identity, or source authentication. This is one narrow lookahead CSV interpretation contract, not a completed eight-dimension research assessment.

The app accepts the raw result of `verify_toolkit.freqtrade.assess_lookahead` and the sharing/CLI result of `verify_toolkit.reporting.report_for_sharing`. The latter may contain a `disclosure` object, generic or private display labels, and `example_declaration: "synthetic"` or `"not_declared"`. Missing example declarations remain missing; they never imply a real or authenticated source. CLI error envelopes (`n170.tool-evidence.error.v1`) are not observation reports and are rejected.

## Captured run packages

The separate **Review a captured run** view accepts the bounded JSON exported by
`verify_toolkit export-run`, using the [portable run-review contract](../verify_toolkit/RUN_REVIEW_V1.md).
It recomputes artifact sizes/digests and checks relationships among the supplied
manifest, captured inputs, selected attempts and outputs. It retains unsuccessful
outcomes and missing rerun prerequisites. Imported code and commands are treated
as data and are never executed by this viewer. An optional separately retained
manifest digest identifies expected bytes; it does not authenticate a producer.

Packages include source code, settings, data, logs and outputs and can disclose
private research. Review their contents before sharing. The app's deliberate
reading-summary download omits raw artifacts and source code; that unsigned
summary cannot replace the full package for independent verification. A producer
can rebuild internally consistent unsigned evidence or omit an entire unknown
attempt. Selected-attempt accounting cannot prove global attempt completeness.

From a new terminal at the complete source or combined release root:

```sh
cd app
PYTHONDONTWRITEBYTECODE=1 python3 -S -m verify_toolkit verify-review "/absolute/review.json"
PYTHONDONTWRITEBYTECODE=1 python3 -S -m verify_toolkit compare-runs "/absolute/original.json" "/absolute/rerun.json"
```

Use Python 3.10+. For a separately downloaded toolkit ZIP, verify and extract it,
then run these commands from the directory containing `verify_toolkit/`, omitting
`cd app`. See the contract for exact exit codes: intact findings, unassessable
receipts and noncomparable packages are not ordinary no-findings success.
Comparison checks both packages first; it does not itself perform an independent
rerun. The original supplied CSV observation format below remains supported.

## Inspect and deliberately share

Import a JSON report in the app's observation review. Read the overall status, usable strategy-row count, each row's reported signal counts, failed rows, declared run status and scope, reasons, and limitations. A report with `NOT_ASSESSABLE` is a valid import when its failure details satisfy the contract; it is not hidden as a parsing failure. For example, a failed declared run can still contain a row reporting findings. Those findings stay visible alongside the overall failure.

The three statuses describe the supplied report only:

- `FINDINGS_REPORTED`: supplied rows identify possible bias requiring review.
- `NO_FINDINGS_REPORTED`: the supplied rows contain no reported findings. Untested or omitted cases remain unknown.
- `NOT_ASSESSABLE`: invalid/insufficient rows, invalid declarations, failed or incomplete runs, or declared coverage mismatches prevent a clean assessment.

`tested_strategy_count` counts usable supplied rows with positive signals. The app does not observe execution. Signals in the rows are reported counts, not authenticated test results. Source authenticity and context authenticity remain `unverified`; freshness and whole-run completeness remain `not_established`; tool execution remains `not_performed`.

Export JSON only after reviewing what it discloses. The default export removes `filename`, `strategy`, `biased_indicators`, and any imported custom `display_label`; rows receive `Strategy 1`, `Strategy 2`, and so on. Counts, reasons, source digest, declared hashes and run configuration remain. They may still disclose research information. Explicit label inclusion preserves available upstream labels; it cannot recover labels absent from an imported redacted report. The export retains a synthetic declaration. An indicator-only finding stays `has_bias: true` even when removing its indicator names leaves both biased-signal counts at zero.

Nothing here authenticates the source digest. The digest identifies retained source bytes for comparison, and is itself only a supplied claim until a recipient compares it with those bytes. Editing a structurally valid unsigned report can change its claims; schema validation cannot detect all such edits or authenticate any report.

## Recipient reproduction

Obtain the original CSV bytes and the exact declared context separately, if the owner chooses to provide them. Keep private strategy code and account data out of that exchange unless separately needed and authorized. Obtain an independent copy of the original open toolkit. Complete source and combined releases include it inside `app/`. Open a new terminal at that extracted root; the command below enters `app/`. For a separately verified/extracted toolkit ZIP, start at its root containing `verify_toolkit/` and omit `cd app`. Replace the example input, context and output paths with the chosen local paths:

```sh
cd app
PYTHONDONTWRITEBYTECODE=1 python3 -S -m verify_toolkit freqtrade-lookahead "/absolute/export.csv" --context "/absolute/context.json" --output "/absolute/outside-release/recipient-observations.json"
```

Keep input, context and output files outside the source tree. The no-bytecode
prefix avoids leaving Python caches there; it does not replace archive verification.
Omit `--context` if no context was supplied. Use a new output path; the toolkit does not overwrite existing files. Use `--include-labels` only when you deliberately intend to include private file, strategy, and indicator names. For an invented demonstration, retain `--synthetic-example`. Compare the assessment, counts, reason codes, declared scope, and source SHA-256 with the received report. Reading or importing the JSON alone does not rerun CSV interpretation. Matching output demonstrates repeatable interpretation; it does not establish source authenticity, completeness, freshness, or absence of bias. The independent account-performance verifier is a separate workflow and does not verify these observations.

## Validation boundary

`src/toolEvidence.js` exports:

```js
parseToolEvidence(text) // supported validated report; throws one fixed safe error
makeToolEvidenceExport(report, { includeLabels: false }) // fresh sharing copy
TOOL_EVIDENCE_MAX_BYTES // 4 * 1024 * 1024 UTF-8 bytes
TOOL_EVIDENCE_LABELS // user-readable overall status labels
```

Imports enforce the exact v1 schema, supported format reference `2026.8` at revision `9f10e357a93c1dcf10c2a2b367659214d89c073e`, exact limitations and trust fields, strict allowed keys at every level, declaration syntax, and reason/status/count consistency. The format reference describes the frozen adapter's supported upstream export format; it is not a claim that the declared run used that revision. The imported declaration of the actual `freqtrade_version` remains unverified.

The parser rejects duplicate object members, including equivalent escaped keys; prototype-related members; unknown schema versions; invalid or non-finite JSON; invalid Unicode scalar sequences; trailing input; oversized strings; excessive nesting; and contradictory disclosure or trust claims. It allows at most 4 MiB UTF-8 JSON, 12 container nesting levels, 160,000 parsed values, 8,192 UTF-16 code units per JSON string, 1,000 strategy rows, 128 indicator names per row, and upstream counts from 0 through 1,000,000,000 (positive total signals for usable rows). These are app import limits. The original CSV adapter separately limits CSV source bytes to 1 MiB. App errors are fixed text and never echo rejected input, private labels, or paths.

Unknown keys and future revisions deliberately fail closed. This is not a generic research-report parser. The module has no network, storage, financial-calculation, or signing dependencies. A bounded custom `display_label` remains untrusted display text; render it through text nodes/React interpolation, never executable markup. It is removed from default exports. The module does not sanitize HTML for use with `innerHTML`.

## Original synthetic fixtures and tests

All four `examples/tool-evidence-*.json` fixtures are invented demonstrations generated with the verified frozen original toolkit, not runs of Freqtrade or real strategies:

| Fixture | Overall result | Usable rows | Purpose |
| --- | --- | ---: | --- |
| `tool-evidence-clean.json` | `NO_FINDINGS_REPORTED` | 2 | Positive reported signal counts, no supplied findings |
| `tool-evidence-findings.json` | `FINDINGS_REPORTED` | 2 | Indicator-only finding must survive private-label removal |
| `tool-evidence-failed.json` | `NOT_ASSESSABLE` | 2 | Declared run failed; a supplied finding remains visible |
| `tool-evidence-insufficient.json` | `NOT_ASSESSABLE` | 1 | Zero tested signals in one row plus declared coverage mismatch |

They use the following original synthetic source CSVs. The failed fixture uses the findings CSV and changes the declaration's `run_status` to `FAILED`.

```csv
filename,strategy,has_bias,total_signals,biased_entry_signals,biased_exit_signals,biased_indicators
synthetic_alpha.py,SyntheticAlpha,False,40,0,0,
synthetic_beta.py,SyntheticBeta,False,25,0,0,
```

```csv
filename,strategy,has_bias,total_signals,biased_entry_signals,biased_exit_signals,biased_indicators
synthetic_alpha.py,SyntheticAlpha,True,40,0,0,"future_window,forward_close"
synthetic_beta.py,SyntheticBeta,False,25,0,0,
```

```csv
filename,strategy,has_bias,total_signals,biased_entry_signals,biased_exit_signals,biased_indicators
synthetic_alpha.py,SyntheticAlpha,False,0,0,0,
synthetic_beta.py,SyntheticBeta,False,25,0,0,
```

Each source includes a final LF newline. The context is:

```json
{
  "freqtrade_version": "2026.8",
  "run_status": "COMPLETED",
  "expected_strategy_count": 2,
  "run_config": {
    "timerange": "20250101-20250401",
    "timeframe": "1h",
    "minimum_trade_amount": 10,
    "targeted_trade_amount": 100,
    "lookahead_allow_limit_orders": false
  }
}
```

Generate with `assess_lookahead(csv, context=context)`, then `report_for_sharing(result, include_labels=True)`, then set `example_declaration` to `synthetic`; equivalently invoke the CLI with `--include-labels --synthetic-example`. These fixture files contain no actual strategy or investment results.

The original received archive's `MANIFEST.json` records its exact per-file hashes;
`COMPONENTS.json` identifies its packaged components. Verify that archive against a
separately retained SHA-256 with `verify_release.py` before extraction or editing.
Complete source and combined releases place app fixtures under `app/examples/`
and toolkit source under `app/verify_toolkit/`. The separate toolkit archive puts
`verify_toolkit/` at its root. A maintainer rebuild creates a new artifact with
new hashes. These fixtures remain synthetic CSV-interpretation controls, not
evidence of a Freqtrade engine run or actual investment performance.

For JavaScript tests, use the folder containing `package.json` (`cd app` from the complete source or combined release root), then run `node --test tests/tool-evidence.test.mjs`. Tests cover all four fixtures; raw and sharing forms; both explicit disclosure choices; retained failures and insufficient evidence; counts, scope, and reason consistency; malicious JSON; Unicode and size limits; duplicate and unknown keys; private-label removal; 1,000-row bounds; and data-only rendering expectations. They establish contract behavior with synthetic inputs. They do not establish a real-account result, tool execution, attestation, outside-user usability, or external human review.
