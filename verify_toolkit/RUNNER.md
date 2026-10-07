# Offline Freqtrade runner — bounded milestone 0.2

Source layout: complete source and combined releases put `verify_toolkit/` and
`toolkit-tests/` inside `app/`. From that extracted release root, run `cd app` once
before the Python commands below. The separate `n170-verify-toolkit.zip` instead
puts both directories at its extraction root; run the commands there without
`cd app`. Verify the original received ZIP against its separately retained digest
with `verify_release.py` before extraction. Keep generated inputs and outputs
outside the source tree and use fresh output paths. The documented
`PYTHONDONTWRITEBYTECODE=1` prefix avoids creating source-tree bytecode.

This opt-in local runner executes explicitly selected, reviewed local strategies
in a separately installed Freqtrade Docker image. It retains a fresh execution
receipt for every selected strategy. The CSV-only adapter and its conservative
`n170.tool-evidence.freqtrade-lookahead.v1` schema are unchanged.

## Supported scope and trust

Supported now: Python 3.10+ host on macOS/Linux with a trusted local Docker daemon;
Linux ARM64 Freqtrade 2026.8; one spot `BTC/USDT` pair; five-minute JSON OHLCV;
1–8 selected local strategy files; market-order lookahead analysis. There is no
browser upload endpoint. Do not route uploaded or unreviewed code into this CLI.
The engine executes Python code, including that strategy's imports and callbacks.

The worker uses the real unmodified Freqtrade lookahead detector and backtester.
It supplies original synthetic spot market metadata through CCXT `set_markets`
and the pinned Freqtrade `Exchange._markets` cache, avoiding live exchange
initialization. It calls `LookaheadAnalysis` directly, one selected strategy per
container; it never searches a directory of arbitrary strategies. This narrow
fixture adapter is not a standard live exchange setup or validation of realistic
execution, broker provenance, authentic market data, or profitability.

The trusted boundary includes the host, Docker daemon, image installation and
selected local strategy. A malicious host/root or daemon can forge receipts or
transiently replace mounted host files. Checksums and unsigned manifests do not
prove remote execution. No attestation, external human audit or real-account
validation is claimed. Retaining a manifest hash separately lets a recipient
detect later changes to that exact bundle, not establish its original truth.

## Install the engine separately

Original toolkit code is Apache-2.0. Freqtrade remains separately installed GPLv3
software; no Freqtrade source or dependencies are bundled in the toolkit archive.
Pulling the image downloads third-party software under its own licenses. Inspect
its source and notices when preparing any separate engine distribution.

Pinned upstream revision:
[`9f10e357a93c1dcf10c2a2b367659214d89c073e`](https://github.com/freqtrade/freqtrade/commit/9f10e357a93c1dcf10c2a2b367659214d89c073e),
release 2026.8. The checked ARM64 image is:

```sh
docker pull freqtradeorg/freqtrade@sha256:289f403917e170ecced1f3c537a2580435a581f2b21311c488c4efcb1694f666
```

The runner never pulls automatically and always launches the inspected image ID,
not a mutable tag. The worker inventories all 332 installed `freqtrade/**/*.py`
files. SHA-256 of compact sorted-key JSON of the sorted `{path,size,sha256}` list
must equal `a96f980268301b69f8fb6e423d27606ede3f174449f63ff672aebb48f97ac6de`.
[engine-source.json](engine-source.json) contains the reference filenames and
hashes, not upstream source. This digest was computed from the actual pinned Git
revision and independently matched against the installed image. Dependency names,
versions, Python/platform, image ID and Docker client/server identity are retained.
Other architectures/images have not been validated; an explicitly supplied
immutable image still must pass the source checks and cannot declare writable
Dockerfile volumes.

## Reproduce the original controls

From the directory containing `verify_toolkit/` (enter `app/` for a complete source or combined release), replace the `/absolute/new-*` placeholders below with fresh absolute paths outside the source tree:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m verify_toolkit synthetic-fixture --output /absolute/new-synthetic-inputs
PYTHONDONTWRITEBYTECODE=1 python3 -m verify_toolkit run-freqtrade \
  --output /absolute/new-run-001 \
  --data /absolute/new-synthetic-inputs/data/BTC_USDT-5m.json \
  --strategy N170Clean=/absolute/new-synthetic-inputs/strategies/N170Clean.py \
  --strategy N170Biased=/absolute/new-synthetic-inputs/strategies/N170Biased.py \
  --acknowledge-local-code \
  --timerange 20260101-20260103 \
  --minimum-trade-amount 5 --targeted-trade-amount 10 \
  --timeout-seconds 120
PYTHONDONTWRITEBYTECODE=1 python3 -m verify_toolkit verify-run /absolute/new-run-001
```

Expected: clean attempt `NO_FINDINGS_REPORTED`; biased attempt
`FINDINGS_REPORTED` with `future_close`; 10 analyzed signals each. Aggregate
`FINDINGS_REPORTED` exits **1** deliberately. Each uses original generated candles;
these are engineering controls, not financial strategies or real-market evidence.

Use `N170Never=/absolute/new-synthetic-inputs/strategies/N170Never.py` for no-trade insufficient
analysis and `N170Failure=/absolute/new-synthetic-inputs/strategies/N170Failure.py` for a deliberate
runtime exception. Both must produce `NOT_ASSESSABLE` (exit **2**). A mixed run
retains its valid findings while keeping the aggregate unassessable. Exit **0**
means only all selected attempts completed and their exercised signals reported
no findings. It does not mean absence of bias throughout the strategy.

For an independent rerun of a retained bundle, use its captured files directly:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m verify_toolkit run-freqtrade --output /absolute/new-independent-run \
  --data /absolute/new-run-001/attempts/000/input/data/BTC_USDT-5m.json \
  --strategy N170Clean=/absolute/new-run-001/attempts/000/input/strategies/N170Clean.py \
  --strategy N170Biased=/absolute/new-run-001/attempts/001/input/strategies/N170Biased.py \
  --acknowledge-local-code --timerange 20260101-20260103 \
  --minimum-trade-amount 5 --targeted-trade-amount 10 --timeout-seconds 120
```

Compare input hashes, engine source/image identity, analysis counts/findings and
raw CSVs. UUIDs, host paths, timestamps, durations and logs can legitimately differ;
byte-identical full manifests are not expected. No network is needed after the
engine image and toolkit are locally installed. The standard-library verifier
requires neither Docker nor Freqtrade.

## Receipt and failure semantics

See [RUN_MANIFEST_V1.md](RUN_MANIFEST_V1.md). Each exclusive run directory contains
`manifest.json` and ordered `attempts/000`, `001`, etc. Each attempted container
has `input/` (captured config, selected source, data, worker and request),
`stdout.log`, `stderr.log`, and any emitted `output/` artifacts. Output includes
worker outcome/analysis/environment, effective configuration, synthetic market
metadata and the official CSV when available. The effective configuration snapshot
is explicitly post-lookahead overrides and **before** per-strategy default
resolution; selected source and engine logs retain the later strategy settings.
Do not treat it as an introspection dump of arbitrary Python runtime state.

Inputs are read once using bounded regular-file reads through no-follow parent
descriptors, then staged from those exact buffers. The original paths are never
reopened for engine consumption. Only that attempt's input directory is mounted,
read-only. Worker input hashes are checked before and after analysis; the host
also compares retained input bytes after the process ends. A supplied digest
cannot replace this capture. Symlink inputs and parent components, FIFOs,
duplicate strategy names, unsupported configuration and stale destinations fail.
Use canonical paths on systems where `/tmp` or `/var` are symlink aliases.

Engine output exists only in a fresh bounded in-container tmpfs. The worker emits
a fixed data-only bundle through captured stdout; the host exclusively creates
its output files after execution. It never reads a prior export as current
output. The verifier checks exact retained files, the output/log transport,
engine/config/input identities, command arguments, outcomes, complete selected
attempt accounting and recomputed summary. Missing logs, omitted/duplicate
attempts, failed exits, insufficient/no results and altered artifacts cannot
become a clean result. A manifest still marked RUNNING after abrupt host/process
loss remains unassessable. SIGTERM/interrupt handling attempts container removal;
a machine or daemon failure may prevent finalization or removal.

Limits: no network; unprivileged UID 1000; read-only root; capability drop;
no-new-privileges; 1 CPU; 1 GiB memory with no extra swap; 64 PIDs; 256 descriptors;
16 MiB per-file limit; 128 MiB temporary tmpfs; 16 MiB output tmpfs; 8 MiB combined
retained logs per attempt; wall time 1–600 seconds; 100–10,000 candles within 8 MiB;
source files at most 256 KiB; target signals at most 100. Docker images declaring
implicit writable volumes are refused. Limit exhaustion is a failed/incomplete
attempt. No shell interpolation or inherited FREQTRADE configuration is used.
On timeout/cancellation, the runner force-removes the named container, records
whether Docker confirmed cleanup, and skips subsequent attempts if cleanup is
unconfirmed. Check a reported container name with your trusted Docker daemon if
cleanup could not be confirmed; host/daemon outages cannot provide a kill guarantee.

To pin retained bytes, record the returned manifest SHA-256 separately and run:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m verify_toolkit verify-run /absolute/new-run-001 --manifest-sha256 RECORDED_64_HEX_DIGEST
```

Run directories contain code, configuration, data and full logs. They are private
by default but deliberately complete; review all contents before sharing.
Runtime receipts are unsigned and may contain strategy-authored text. CLI errors
and verifier reason codes do not echo parser/strategy exception values.

## Source and tests

Pinned primary references: [lookahead helper/exporter](https://github.com/freqtrade/freqtrade/blob/9f10e357a93c1dcf10c2a2b367659214d89c073e/freqtrade/optimize/analysis/lookahead_helpers.py),
[lookahead analysis](https://github.com/freqtrade/freqtrade/blob/9f10e357a93c1dcf10c2a2b367659214d89c073e/freqtrade/optimize/analysis/lookahead.py),
[exchange implementation](https://github.com/freqtrade/freqtrade/blob/9f10e357a93c1dcf10c2a2b367659214d89c073e/freqtrade/exchange/exchange.py),
[upstream license](https://github.com/freqtrade/freqtrade/blob/9f10e357a93c1dcf10c2a2b367659214d89c073e/LICENSE).

From the directory containing `verify_toolkit/` (enter `app/` for a complete source or combined release):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s toolkit-tests -p 'test_verify_toolkit*.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 -m verify_toolkit self-test
```

Unit tests use labeled synthetic transports to challenge orchestration; they are
not real-engine integration evidence. Historical engine receipts and their exact
inventories are development evidence excluded from this public source archive.
The reproduction instructions support new local runs; this guide does not supply
the excluded execution records. Untested strategy branches,
recursive analysis, FreqAI, multi-pair/futures trading, real execution realism,
statistical validity, independently authenticated data and universal detector
coverage remain outside this milestone.
