# Offline execution receipt v1 (implementation contract)

Schema: `n170.freqtrade-run.v1`. This is separate from the unchanged
`n170.tool-evidence.freqtrade-lookahead.v1` CSV observation. Consumers must not
promote either into authenticated financial evidence.

The runner exclusively creates a new private directory for each invocation.
`manifest.json` is written before engine launch and atomically replaced after
each attempt. A missing final manifest or `state != "FINALIZED"` is incomplete,
never clean. No existing export is admitted as fresh execution output.

Required final fields:

- `schema`, `run_id`, `state`, `started_at`, `finished_at` (local untrusted clock).
- `engine`: pinned version `2026.8`, upstream revision
  `9f10e357a93c1dcf10c2a2b367659214d89c073e`, image ID and runtime identity.
- `request`: exact selected strategies and bounded execution settings.
- `inputs`: relative path, byte count and SHA-256 for every staged file. Source
  files are read once with bounded no-follow regular-file reads. Captured bytes
  are written into fresh per-attempt read-only input mounts. Input receipts bind
  the worker's checked bytes; user-provided digest claims are not accepted.
- `attempts`: exactly one ordered entry per selected strategy, containing ID,
  strategy, state, outcome, reason codes, exact argv (no shell), environment,
  start/end times, exit status, and all retained output/log identities.
- `artifacts`: relative path, bytes and SHA-256 for the complete retained file set
  other than the manifest itself. A detached manifest digest may be retained by
  the caller; unsigned self-consistency does not authenticate a remote producer.
- `summary`: `status` is `NO_FINDINGS_REPORTED`, `FINDINGS_REPORTED`, or
  `NOT_ASSESSABLE`; attempt counts and findings remain visible when another
  attempt fails. All selected attempts must complete with adequate usable output
  for either assessable aggregate status.
- `trust`: separate execution, authenticity, completeness, reproduction and
  detector-coverage statements. Never an aggregate certification or performance
  claim. Reproduction requires an independent rerun, not matching hashes alone.

Attempt outcomes: `NO_FINDINGS_REPORTED`, `FINDINGS_REPORTED`, `INSUFFICIENT`,
`FAILED`, `TIMED_OUT`, `CANCELLED`, `SKIPPED`, `MISSING_OUTPUT`, `INVALID_OUTPUT`,
`INPUT_CHANGED`. Only the first two are assessable. Pending/running attempts and
missing/extra/duplicate attempt entries invalidate completeness. Findings are
reported observations on exercised signals; the engine does not prove absence
of leakage in unexercised branches, realistic fills, data authenticity, or
profitability.

Supported boundary: an explicitly opted-in local strategy, separately installed
pinned Docker image, no network, read-only root and input mounts, capability drop,
no privilege escalation, unprivileged UID, bounded CPU/memory/process count,
bounded temporary storage, wall time and retained logs/output. The host, Docker
daemon and selected local engine installation must be trusted. This is not an
arbitrary upload execution service. Do not send browser uploads to this runner.
Config is generated from a narrow data-only request, with no secrets, live mode,
plugins, arbitrary argv, imported config paths or credentials. A fixture exchange
shim, if needed for offline market metadata, is identified as such and its bytes
are bound; it cannot strengthen real-market claims.

`python -m verify_toolkit verify-run DIRECTORY [--manifest-sha256 HEX]` checks
inventory and attempt accounting without running an engine. `run-freqtrade`
requires explicit local-code opt-in. Full command examples and the tested runtime
will be recorded in RUNNER.md once implementation is validated.
