# Local accounting integration v2

This original, versioned extension observes the full pinned Freqtrade baseline,
derives an exact decimal ledger, checks a separate native binary64 policy, and
optionally retains an actual independently installed Beancount calculation.
All v1 commands, files and schemas retain their existing behavior.

The initial bridge supports naturally closed BTC/USDT spot trades: leverage one,
zero opening asset, one full market entry and exit, and modeled quote fees at
0.001. Open holdings, forced exits, partial/base-fee trades, adjustments, unknown
runtime behavior and incomplete captures remain unsupported. The ledger alone
can diagnose FIFO and open holdings; that does not expand engine bridge support.

## Run, retain and review

Use Python 3.10 or later from the source directory containing both
`verify_toolkit` and `verify_accounting`. Review the local strategy and use the
separately installed pinned container documented in RUNNER.md. The runner never
pulls an image and its container has no network. Select trusted local source
explicitly; received portable packages never authorize its execution.

```sh
python3 -m verify_toolkit.accounting run run-v2 \
  --strategy Example=Example.py --data BTC_USDT-5m.json \
  --acknowledge-local-code
python3 -m verify_toolkit.accounting export run-v2 --output run-review-v2.json
python3 -m verify_toolkit.accounting verify run-review-v2.json
```

The OHLCV input contains 100–10,000 original synthetic five-minute candles.
`--timerange`, `--minimum-trade-amount`, `--targeted-trade-amount`, and
`--timeout-seconds` have the same bounded meaning as runner v1. Preserve failed,
insufficient, timed-out and cancelled attempts alongside successful attempts.

Review a received package entirely offline, optionally supplying a separately
retained manifest commitment:

```sh
python3 -m verify_toolkit.accounting verify run-review-v2.json \
  --manifest-sha256 RECORDED_64_HEX_DIGEST --report reading.json
```

Verification parses data and recomputes relationships; it never executes embedded
strategies, commands, ledger files or workers. Use this accounting-enabled source
distribution. The earlier public v1 toolkit does not understand v2 packages.
Before extracting any distribution, independently verify its archive hash and
source inventory using a trusted verifier. Distribution packaging remains a
separate release step for this integration candidate.

## Optional separate oracle

Install the pinned Beancount environment independently as documented in
`verify_accounting/README.md`. The v2 oracle also requires the reviewed installed
code inventory; another platform/build may correctly return unavailable until
separately validated. Supply the trusted interpreter explicitly:

```sh
python3 -m verify_toolkit.accounting oracle run-v2 \
  --python /path/to/trusted-beancount-env/bin/python --output run-v2-with-oracle
python3 -m verify_toolkit.accounting export run-v2-with-oracle \
  --output run-review-v2-with-oracle.json
```

The original run is preserved. The new receipt contains the exact generated
events, fixed ledger, original worker, stdout, stderr and oracle report under
each supported attempt's `accounting/` directory. The oracle determines FIFO
cost and realized gain independently; N170 does not supply its calculated gain.
Native rounded balances are not inserted into zero-tolerance ledger assertions.
Reviewers regenerate ledger bytes and check all retained bindings and nine
computed metrics. `SUPPLIED_MATCHED` means that supplied oracle evidence agrees;
the recipient did not witness or authenticate that execution. The explicit
oracle command is a trusted local process, not an OS network sandbox.

## Interpret the separate results

- **Package integrity:** exact supplied bytes and receipt relationships. Hashes
  neither authenticate the producer nor prove an engine executed.
- **Detector:** only the lookahead findings exercised by the selected attempts.
- **Capture:** observation completeness, bindings, full-order bijection and
  supported accounting scope. Completion sequence is never sorted or deduplicated.
- **Exact model:** quantity/price retain eight decimal places; modeled fees and
  results admit nineteen. Calculations trap inexact arithmetic at precision 80.
  Inputs are never rounded to enter the domain. Fees retain operand references.
- **Native arithmetic:** `freqtrade-2026.8-cpython3147-serial-round8.v1` independently
  constructs exact decimal legs, converts each to binary64, subtracts, rounds the
  actual binary rational to eight decimal places with ties to even, and accumulates
  in captured close order. Every compared native bit pattern must match; there is
  no epsilon. Exact binary-minus-model and printed-decimal-minus-model differences
  remain separate. See CAPTURE_V2.md for source/runtime commitments.
- **External oracle:** not run, incomplete, unavailable, invalid, supplied match,
  or supplied discrepancy. A native match never substitutes for an oracle run.

Only cash, quantity and accumulated net P&L are supplied as native metrics.
The other six metrics remain `NOT_SUPPLIED`. Overall financial reconciliation
therefore remains `NOT_ASSESSABLE`, even when exact calculations, native replay
and the oracle agree. Export exits 0 when bytes are exported; run, review, oracle
and comparison commands exit 2 because no fully assessable financial result is
established. Read each status rather than treating that exit code as an exception.

The portable v2 envelope retains v1's 96 MiB JSON, 64 MiB decoded, 128-artifact
limits. Capture is bounded at 2 MiB; worker transport at 6 MiB encoded/3 MiB
decoded. Missing, oversized and interrupted evidence cannot become a successful
prefix. Review in the browser is memory-only and does not upload or store inputs.
Changing the file or digest, clearing, or leaving the view invalidates pending work.

Source completeness outside the selected receipt, broker authenticity, real fills,
returns, profitability and independently witnessed execution remain unestablished.
