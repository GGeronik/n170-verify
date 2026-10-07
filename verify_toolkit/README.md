# N170 Open Evidence Toolkit — experimental 0.2

Source layout: complete source and combined releases put `verify_toolkit/` and
`toolkit-tests/` inside `app/`. From that extracted release root, run `cd app` once
before the Python commands below. The separate `n170-verify-toolkit.zip` instead
puts both directories at its extraction root; run the commands there without
`cd app`. Verify the original received ZIP against its separately retained digest
with `verify_release.py` before extraction. Keep generated inputs and outputs
outside the source tree and use fresh output paths. The documented
`PYTHONDONTWRITEBYTECODE=1` prefix avoids creating source-tree bytecode.

Free, original, Apache-2.0 software for inspecting supplied tool evidence locally.
No account, service, network access, broker credentials or trading is involved.
The first adapter reads Freqtrade lookahead-analysis CSV exports and distinguishes
reported findings, rows reporting no findings, and unassessable evidence.

This is an integration foundation, not a combined trading engine or an issued
research report. The CSV importer cannot authenticate an export or establish a
strategy's validity. A separate [opt-in offline runner](RUNNER.md) now executes
explicitly selected local strategies in a separately installed pinned engine. Its reports are separate from N170 Verify's
signed account-performance records.

## Try it

From the directory containing `verify_toolkit/`, with Python 3.10+ on macOS/Linux:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m verify_toolkit self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m verify_toolkit freqtrade-lookahead verify_toolkit/examples/freqtrade-lookahead-findings.csv --synthetic-example --html /tmp/freqtrade-review.html --output /tmp/freqtrade-review.json
```

The examples are synthetic. The findings example exits **1** deliberately.
Exit **0** means only that supplied rows report no findings; **2** means input,
output or assessment was incomplete. Read the evidence limits regardless of code.
Existing output files are never overwritten. Choose fresh paths when repeating.

For a real export, replace the example path with an explicitly supplied CSV.
The adapter accepts the documented seven-column format pinned to Freqtrade
2026.8, with an optional leading pandas index. Other versions are not presumed
compatible. See [FREQTRADE.md](FREQTRADE.md) for exact sources and limits.

Optional `--context context.json` supplies declarations, for example:

```json
{
  "freqtrade_version": "2026.8",
  "run_status": "COMPLETED",
  "expected_strategy_count": 1,
  "run_config": {
    "timeframe": "1h",
    "timerange": "20240101-20240201",
    "minimum_trade_amount": 10,
    "targeted_trade_amount": 20,
    "lookahead_allow_limit_orders": false
  }
}
```

These declarations are not independently checked. Inconsistent counts or a
declared failed/skipped run prevent an ordinary no-findings result. Even matching
declarations cannot establish freshness or completeness: upstream exports can
omit failed analyses and retain old rows. The separate [execution receipt](RUN_MANIFEST_V1.md) binds all selected attempts
to captured configuration, strategy, data, environment, logs and outcomes.

## Private by default; independently repeatable

The CSV inspection CLI omits filenames, strategy names and indicator names in its output by
default. `--include-labels` includes them explicitly. Counts, timing/configuration
declarations and hashes may still reveal research details. Inspect before sharing.
Source CSV text is never embedded, and reports are written with owner-only file
permissions. The library API retains labels in memory for local inspection.

The HTML is a static, unsigned, editable reading copy. It escapes supplied text,
has no scripts or external resources, and does not execute imported HTML. A
recipient should independently obtain the toolkit and rerun it on the same CSV
and context. The recorded source digest binds the exact UTF-8 source bytes,
including a BOM if supplied. Agreement is repeatable interpretation, not proof
of the data's origin. No global grade or research/performance credential is issued.

## Captured run packages

The [portable run-review contract](RUN_REVIEW_V1.md) describes `export-run`,
`verify-review` and `compare-runs`. Verification is data-only: it recomputes bytes
and selected-attempt relationships, retains failed outcomes, and does not execute
embedded strategies or commands. A separately retained manifest digest can pin
bytes; it cannot authenticate the producer or reveal an entire unknown omitted
attempt. Packages include private source/configuration/data/logs, so review their
contents before deliberate sharing. Browser reading summaries do not contain
those artifacts and cannot replace the full package.

## Reusable source package

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m verify_toolkit package --output /tmp/n170-open-evidence-toolkit.zip
```

An explicit allowlist includes only this original package, documentation and
synthetic examples, with an unsigned SHA-256 inventory. It excludes proprietary
N170 engines, private research bundles, personal account files and keys. Extract
into a new directory and run the commands above. Python's standard library is
sufficient. Preparing the archive does not publish it or expand another release's
allowlist.

## What is and is not demonstrated

The included self-test is a synthetic parser and claim-boundary corpus. It
contains positive controls as well as malformed, contradictory and incomplete
inputs; it is not a Freqtrade detector benchmark or evidence of superiority over
another product. It does not assess financial arithmetic or personal performance.

The runner has been exercised against original synthetic clean, biased,
insufficient and failed controls using the real pinned engine. See RUNNER.md for
the supported narrow boundary and reproduction. Next: licensed LEAN and portfolio
accounting adapters, broader independent challenge cases and reviewer testing. Real
source authority, independent time and observed execution require separate
evidence. None is replaced by a signature or successful parsing.

## Licensing and attribution

Original adapter, CLI and report code: Apache-2.0; see [LICENSE](LICENSE) and
[NOTICE](NOTICE). Freqtrade is a separate GPLv3 project; its engine is neither
bundled. Only the isolated interoperability worker imports the separately
installed engine during an explicitly opted-in run; the CSV adapter/verifier
have no engine dependency. No AuditZK code is included. Use of upstream names identifies
interoperability, not endorsement. Helping people freely is the mission; the
license does not impose a noncommercial restriction.
