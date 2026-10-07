# Supplied Freqtrade lookahead observations

Source layout: complete source and combined releases put `verify_toolkit/` and
`toolkit-tests/` inside `app/`. From that extracted release root, run `cd app` once
before the Python commands below. The separate `n170-verify-toolkit.zip` instead
puts both directories at its extraction root; run the commands there without
`cd app`. Verify the original received ZIP against its separately retained digest
with `verify_release.py` before extraction. Keep generated inputs and outputs
outside the source tree and use fresh output paths. The documented
`PYTHONDONTWRITEBYTECODE=1` prefix avoids creating source-tree bytecode.

This original, standard-library adapter reads a bounded CSV string. It does not
install, import, execute or embed Freqtrade; run a strategy; retrieve prices; or
contact a broker. Its output records what supplied rows say, with explicit limits.
The example CSVs are invented fixtures, not outputs from executed Freqtrade tests.

## Source and format reference

Checked 18 September 2026 against Freqtrade release **2026.8**, commit
[`9f10e357a93c1dcf10c2a2b367659214d89c073e`](https://github.com/freqtrade/freqtrade/commit/9f10e357a93c1dcf10c2a2b367659214d89c073e).
The current [release page](https://github.com/freqtrade/freqtrade/releases/tag/2026.8)
identifies that revision. These links describe the format inspected, not the
version that produced any supplied file:

- [Official lookahead-analysis documentation](https://www.freqtrade.io/en/stable/lookahead-analysis/).
- [Pinned CSV exporter and table formatter](https://github.com/freqtrade/freqtrade/blob/9f10e357a93c1dcf10c2a2b367659214d89c073e/freqtrade/optimize/analysis/lookahead_helpers.py).
- [Pinned result semantics](https://github.com/freqtrade/freqtrade/blob/9f10e357a93c1dcf10c2a2b367659214d89c073e/freqtrade/optimize/analysis/lookahead.py).

The CSV uses the seven columns shown in the examples. Its boolean values are
`True`/`False`; the terminal table displays `Yes`/`No`. The adapter accepts both
spellings, case-insensitively. The exporter writes without an index; a single
leading empty or `Unnamed: 0` integer index is additionally supported for files
resaved through dataframe tooling. Header order may vary. Unknown columns are
rejected, not silently discarded.

The exporter admits successful analyses only when their signal total exceeds its
configured minimum. It can update an existing export. Consequently a CSV can
omit unsuccessful strategies or retain earlier rows; it is not a complete,
fresh execution receipt. Indicator-only findings are valid, and entry/exit
counts may each reach the signal total. The two counts are not disjoint.

The documented analysis covers signals actually exercised. Untriggered signals
can escape detection; order assumptions and FreqAI target columns can also
produce findings needing interpretation. This adapter preserves supplied
findings rather than attempting to adjudicate them.

## API and interpretation

```python
from verify_toolkit.freqtrade import assess_lookahead

result = assess_lookahead(csv_text, context={
    "freqtrade_version": "2026.8",
    "run_status": "COMPLETED",
    "expected_strategy_count": 1,
    "run_config": {
        "minimum_trade_amount": 10,
        "targeted_trade_amount": 20,
        "timeframe": "5m",
        "timerange": "20260101-20260201",
        "lookahead_allow_limit_orders": False,
    },
})
```

The schema is `n170.tool-evidence.freqtrade-lookahead.v1`. `evidence_class` is
always `supplied_tool_output`. The top-level status is one of:

| Status | Meaning |
| --- | --- |
| `FINDINGS_REPORTED` | All rows are interpretable and at least one reports findings. This is not independent confirmation of bias. |
| `NO_FINDINGS_REPORTED` | All rows are interpretable and none reports findings. This is not a finding of no bias. |
| `NOT_ASSESSABLE` | At least one required value is missing, invalid, unsupported, inconsistent or insufficient, or the supplied context reports an unsuccessful/incomplete run. |

`tested_strategy_count` counts valid supplied strategy rows with positive signal
totals. It is not a count of runs observed by N170. Mixed valid/invalid input
keeps valid row observations, including findings, while making the top-level
status unassessable. `reason_codes` contains fixed codes, never raw parser errors
or rejected values. No code path returns a statistical or source-authenticity pass.

The scope includes a digest of the exact UTF-8 input, the adapter's reference
revision, and explicit unverified source/context and unestablished completeness
and freshness. A digest binds only these supplied bytes; it does not authenticate
their producer. Context assertions cannot strengthen those trust labels.

Context is optional and strictly allowlisted. Its keys may be `freqtrade_version`,
`run_status`, `expected_strategy_count`, `config_sha256`, `strategy_sha256`,
`data_sha256`, and `run_config`. The only configuration keys are the five shown
above. Status accepts `COMPLETED`, `FAILED`, `SKIPPED`, `NOT_RUN`, or `CANCELLED`
case-insensitively. Digests must be 64 hexadecimal characters. Empty context means
no declaration, not an implicit successful run. Arbitrary/full configurations,
exchange credentials, file paths and commands are rejected without being echoed.
Invalid context makes the entire assessment unassessable; valid CSV observations
may still be retained.

## Bounds and unsupported cases

Input is limited to 1 MiB UTF-8 and 1,000 data rows. Counts are decimal integers
from zero through one billion; signal totals must be positive. No floating-point,
scientific-notation, nonfinite, signed or missing counts are coerced. Each bias
count must be no greater than the signal total, and the boolean must agree with
the presence of count/indicator findings. If declared, minimum/target constraints
are checked using the inspected export semantics.

Fields are capped at 8,192 characters, identifiers at 128, and indicator lists at
128 entries. The ASCII identifier grammar deliberately rejects unusual custom
names rather than guessing their meaning. All controls except CSV line endings
are rejected. Duplicate columns, strategy/file identities, indices and indicator
names are rejected. Only an empty indicator cell means an empty indicator list;
empty members in a nonempty list are invalid. Empty exports, header-only files,
error/skip text and zero-signal rows cannot produce a no-findings status.

The parser does not read paths, execute uploaded code or import archived modules.
It receives a string already loaded by the caller; any caller accepting files
must separately enforce safe bounded file loading. Its fixed limits are local
interoperability controls, not a claim of a hardened multi-tenant service.

Reports retain validated strategy filenames, class names and indicator labels.
These can disclose research details. They are inert text, not markup or commands;
downstream renderers must still escape them and users should review disclosure.

## Tests and reuse boundary

In an extracted toolkit package, run its synthetic conformance controls with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m verify_toolkit self-test
```

From the same directory containing `verify_toolkit/`, the included regression tests are:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s toolkit-tests -p test_verify_toolkit_freqtrade.py -v
```

The tests cover clean and positive observations, indicator-only findings,
unsupported and adversarial CSVs, failed/skipped declarations, mixed records,
bounded context, duplicates, inconsistent counts and resource limits. They do not
claim an executed Freqtrade integration or investment experiment.

Only the observable format and documented result semantics informed this original
implementation. No upstream source or algorithms were copied. Freqtrade remains
a separate GPL project; this adapter has no engine dependency and does not change
upstream licensing or claim upstream endorsement. Do not bundle an engine or
restricted third-party implementation under this adapter's licence by inference.
