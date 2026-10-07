# N170 accounting reconciliation — standalone core and bounded integration

This original, dependency-free Python checker recalculates cash, position quantity,
FIFO cost basis, fees, realized and unrealized P&L, external flows and closing NAV
from a selected event document. The optional independent check actually runs a
separately installed Beancount process. This guide describes the standalone
events-v1 commands and contract. The separately versioned v2 bridge connects
captured Freqtrade runs to exact accounting and offline browser review; see
[Accounting integration v2](../verify_toolkit/ACCOUNTING_V2.md) for its narrower
trade scope, commands, native arithmetic policy and distinct result statuses.

This is engineering evidence about supplied bookkeeping. No report authenticates
a broker account, establishes that all events were supplied, validates a fill or
closing price, measures investment skill, or claims a return. In particular, a
consistently omitted event and its balance effect can still reconcile.

## Run locally

From the application source directory containing `verify_accounting` and
`accounting-tests`, using Python 3.12 or newer:

```sh
python -B -m verify_accounting check verify_accounting/fixtures/gain.json
python -B -m verify_accounting check verify_accounting/fixtures/gain.json --output /private/tmp/new-accounting-report.json
```

Output files and oracle evidence directories must be new, created with modes 0600
and 0700 respectively, and have no symlink parents. The input reader refuses
symlinks, special files and files over 2 MiB. It reads the selected file once; the
hash binds those bytes. It does not establish their origin. CLI exit codes are
0 for reconciliation, 1 for discrepancies, and 2 for missing/unsupported inputs or
an unavailable oracle. A local Python API is also available:

```python
from verify_accounting import assess_bytes, assess_document
report = assess_bytes(raw_json_bytes)
```

`assess_document` binds its canonical JSON encoding; `assess_bytes` binds the exact
selected bytes. A report inventories each event with a canonical hash and sequence
number, records event cash/quantity checkpoints and gives a signed difference for
each supplied closing claim. It does not silently fill in absent reported metrics.

## Admitted contract

Use `fixtures/gain.json` as a complete schema example. Schema
`n170.accounting.events.v1` requires an evidence class (`synthetic_fixture` or
`supplied_events`), one distinct asset/cash-currency pair, opening cash and time,
chronological events, closing time, closing mark and reported metrics.

The declared policies are one asset, cash-funded long positions, immediate spot
settlement, zero opening position, FIFO acquisition order and quote-currency fees
expensed immediately. Events are BUY, SELL, DEPOSIT and WITHDRAWAL. Each trade must
declare a fee, including an explicit zero, and its currency. Fee-inclusive cash and
gross realized/unrealized gains are separate; net P&L subtracts the fees once.

Every event has a unique bounded ID and timezone-aware timestamp. Equal timestamps
retain supplied sequence order. No more than 10,000 events are admitted. Opening
cash and the closing mark may be zero; the mark must still be present. Quantities,
trade prices and deposit/withdrawal amounts must be positive. Cash and holdings may
never become negative. A zero-value holding and a fully depleted NAV are valid
bookkeeping outcomes. This module makes no time-weighted-return claim.

Numbers are decimal strings, without exponent notation or thousands separators.
Event operands and opening cash/mark have magnitude at most `1e12` and at most
8 fractional places. Reported results separately admit magnitude at most `1e30`
and 16 fractional places, covering exact products and bounded event sums. Arithmetic
uses precision 80; no rounding or tolerance is applied. The admitted operations
use addition, subtraction and multiplication only. Explicit signed zero normalizes
to `0`. Reported claims outside this numeric contract are unsupported.

Unknown fields, event types, duplicate JSON keys or event IDs, missing fields,
nonfinite values, malformed decimals, oversells, borrowing and chronology errors
produce `NOT_ASSESSABLE`. FX, asset-denominated fees, asset transfers, taxes,
interest, dividends, splits, delayed settlement, short positions, derivatives,
starting holdings and intraperiod valuation/return metrics require future schemas.

Reports use `RECONCILED_UNDER_ASSUMPTIONS`, `DISCREPANCIES_FOUND` and
`NOT_ASSESSABLE`. Missing reported metrics cannot yield reconciliation; a known
discrepancy remains visible even when another metric is absent. Every report keeps
`source_authenticity=not_established` and `selected_source_completeness=unknown`.

## Real independent oracle

Beancount is an optional external GPL-2.0-only program. It is not bundled, imported
by the original checker, installed automatically, or required by normal operation.
`_oracle_worker.py` is original integration code executed only by an explicitly
selected trusted interpreter containing that separately installed program. See
`REFERENCES.md` for the source/installation identity and licensing boundary.

An isolated installation can be created explicitly:

```sh
python3.12 -m venv /private/tmp/n170-beancount-env
/private/tmp/n170-beancount-env/bin/python -m pip install -r verify_accounting/oracle-requirements.txt
python -B -m verify_accounting oracle verify_accounting/fixtures/gain.json \
  --python /private/tmp/n170-beancount-env/bin/python \
  --output-dir /private/tmp/new-n170-beancount-evidence
```

The source archive and runtime dependencies are pinned. Building the archive still
uses external build tooling; this is not a fully hermetic or bit-reproducible build.
The worker requires version 3.2.3 and the exact commit archive URL in installation
metadata, and records that metadata and installed Python/native-code hashes.
Metadata and the local interpreter are trusted observations, not attestation.

The generator reads raw event quantities, execution prices and fees. It never
supplies N170-computed cost bases, gains or selected sale lots. Each acquisition
receives a fixed sequence label so equal-price purchases on one date cannot merge
across an intervening lot. Sales request Beancount's FIFO booking with `{}`; its
ordinary omitted `Income:Trading` amount is independently interpolated by Beancount
from booked cost, raw proceeds and raw fee postings. No pad or balancing adjustment
is inserted. Supplied balance claims become strict zero-tolerance assertions, not
transactions that change inventory. Assertions occur the day after closing because
Beancount balance assertions apply at the start of their date.

Only generated, fixed-format ledgers are accepted by this interface. It emits no
plugins, includes, user descriptions, executable code, raw path directives or pad
entries; arbitrary uploaded `.bean` ledgers are never parsed. The process uses
Python `-I -B`, disables Beancount's pickle load cache and has a 45-second deadline.
It requests no networking, but does not claim OS network isolation. The explicitly
selected interpreter and installed packages must be trusted; this is not a hostile
process sandbox. The output-size limit is checked after process collection.

Oracle status is separately `NOT_RUN`, `UNAVAILABLE`, `DISCREPANCIES_FOUND` or
`MATCHED`. A missing interpreter, different installation, process failure or parse
failure never becomes an oracle success. `MATCHED` means the external program
executed and its nine calculated metrics agreed; it does not upgrade source trust.
Each run retains input, generated ledger, original worker, stdout/stderr, hashes,
version/installation identity and report.

## Validation and integration boundary

`fixtures/EXPECTED.json` was hand-calculated and frozen before implementation:
SHA-256 `f593cca4075eca132a97b4831676e1106b65c1259fff4cc19ff9883624053f79`.
This local sequence is not an externally timestamped commitment. Supplementary
fixtures cover zero funding, total depletion, 16-place products and same-day FIFO.
Execution evidence is retained separately from this source distribution.

```sh
python -B -m unittest discover -s accounting-tests -p 'test_*.py' -v
N170_BEANCOUNT_PYTHON=/private/tmp/n170-beancount-env/bin/python \
  python -B -m unittest discover -s accounting-tests -p 'test_*.py' -v
```

Without the explicit environment path, actual external-engine tests are skipped,
not simulated. Positive controls include gain, loss, external contribution,
multi-lot FIFO, depletion, funding from zero, exact fractional arithmetic and
same-day FIFO. Negative controls include a `1e-16` cash discrepancy, unsupported
currencies/types, missing mark, missing claims, duplicates, source-byte changes,
overselling, negative cash, unsafe file types and unavailable external execution.

The v2 bridge requires a bound full-baseline capture and supports naturally closed
BTC/USDT spot trades with one full entry and exit, zero opening asset, modeled
quote fees at 0.001, and no external flows or residual holdings. A closed-trade
export alone is insufficient. Open positions, partial/base-fee trades, forced
exits and incomplete captures remain unsupported. Six absent native metrics stay
`NOT_SUPPLIED`, so overall financial reconciliation remains `NOT_ASSESSABLE` even
when exact model, native arithmetic and supplied oracle results agree. A clean
lookahead result or hash match cannot establish financial reconciliation.
