# Accounting receipts and the combined offline toolkit

This local source candidate adds v2 captured-run accounting review while keeping
the signed v3/v4 records, bounded continuity envelopes and v1 run-review interface
separate. It has not been published or deployed. This guide describes packaging
and interpretation; it does not claim completed release acceptance, an external
audit or real-market validation.

## Get and verify the toolkit

The browser's captured-run recipient help links the combined
`n170-verify-toolkit.zip`, its detached `.sha256` file and `verify_release.py`.
Obtain the expected archive SHA-256 and the verifier through a trusted channel.
A checksum and verifier from the same untrusted page do not authenticate it.
Before extracting, run from the directory containing those downloaded files:

```sh
python3 verify_release.py n170-verify-toolkit.zip --sha256 EXPECTED_ARCHIVE_SHA256
```

Replace the placeholder with the separately retained archive digest. Preserve
the unchanged ZIP and receipt. Extract into a new directory; it contains both
`verify_toolkit/` and `verify_accounting/`, their instructions, `toolkit-tests/`
and `accounting-tests/`, plus archive metadata. Run commands from that extraction
root, not from inside either Python module directory. The complete application
source ZIP contains the same sources under `app/`; use `cd app` from its extracted
root instead. See [source verification and rebuilding](../README.md#verify-received-source-then-build).

Ordinary package review uses Python 3.10+ and its standard library. It needs no
Freqtrade, Docker, optional oracle, account connection or network after download.
The original versioned producer documents are retained: the standalone
[`verify_accounting` README](../verify_accounting/README.md) describes its v1
event interface, while [ACCOUNTING_V2.md](../verify_toolkit/ACCOUNTING_V2.md)
describes this v2 bridge. Historical distribution-stage wording in those source
documents does not mean the combined download omits either module.

The original `python3 -m verify_toolkit package-source` command remains a
historical v1-only packaging interface. Use the combined website download or
the complete application source archive for v2; that command's output is not
the combined toolkit described here.

## Review a complete v2 receipt

Keep the complete received JSON as `run-review-v2.json`. A reading summary does
not contain the artifacts needed for verification. For the separate toolkit
download, from the extraction root containing both Python modules:

```sh
python3 -B -S -m verify_toolkit.accounting verify run-review-v2.json
```

If you separately retained the receipt's manifest SHA-256 or received it through
a trusted channel, supply those 64 lowercase hexadecimal characters. From the
extracted full source or combined release root:

```sh
cd app
python3 -B -S -m verify_toolkit.accounting verify "/absolute/run-review-v2.json" --manifest-sha256 RECORDED_64_HEX_DIGEST
```

For the separate toolkit extraction, use that verification command without
`cd app`. The archive digest pins the downloaded software; the receipt manifest
digest pins the selected run evidence. If no independent manifest digest is
available, omit the option and retain that limitation. Neither digest establishes
sender identity, execution or when the evidence existed.

Read package integrity, detector outcome, capture support, exact model, native
compatibility and supplied oracle evidence separately. The native comparison
supplies cash, quantity and accumulated net PnL only. Its six other metrics remain
`NOT_SUPPLIED`, so overall accounting remains `NOT_ASSESSABLE` even when the
supported native checks and supplied oracle calculations match. The v2 review
returns exit `2` at this boundary. Inspect reasons and keep invalid, failed,
timed-out, cancelled and insufficient results; exit `2` is not a clean financial
assessment. A successful export's exit `0` only means a package was written.

Verification treats the receipt as data. It does not execute embedded strategies,
commands or oracle workers. Browser review stays in memory, uploads nothing and
clears the package when leaving that view. The complete export can include source
code, input data, settings, paths, logs and outputs; review privacy before sharing.
An internally consistent unsigned receipt can be authored without the claimed
engine execution. It cannot authenticate a broker, reveal omitted trials or
establish profitability.

## Execution and optional oracle scope

The v2 bridge supports naturally closed synthetic BTC/USDT spot positions with
leverage one, zero opening asset, a single full market entry and exit per trade,
modeled quote fees of 0.001, no external flows and no residual holdings. Forced
exits, open holdings, partial fills, unsupported fee treatment and unknown runtime
details remain explicit limits. The broader standalone accounting event interface
does not silently widen this engine bridge. Consult the exact
[capture contract](../verify_toolkit/CAPTURE_V2.md).

The exact-decimal model and pinned native binary64 replay use different declared
policies. Preserve reported model differences. An optional Beancount 3.2.3 oracle
requires a separately installed pinned environment and a trusted interpreter;
the toolkit does not install or vendor it. Use the versioned
[local execution and oracle instructions](../verify_toolkit/ACCOUNTING_V2.md)
for required code inventory checks and explicit local-code opt-in. This is trusted
local execution, not an operating-system network sandbox. Package review never
starts that process. `SUPPLIED_MATCHED` records agreement in supplied oracle
evidence, not witnessed or authenticated execution, and does not fill the six
missing native metrics.

## Earlier challenge baseline

An earlier 175-case challenge kit for the wave2 compatibility-v4 baseline is
retained outside this distribution with its original identity. Its documented
result is `INCOMPLETE`, exit `2`; it excludes continuity and accounting, and it
is not validation of this toolkit or of the accounting additions.
