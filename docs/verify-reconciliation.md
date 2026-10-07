# Check private source against a signed event

This additive checker compares a deliberately exported private reconciliation with one explicitly selected event in an existing signed v4 record. It independently reconstructs supported source observations and their returns, then compares them with the signed event. The existing independent record verifier first checks the complete signature chain and disclosed-return metrics. Existing signing and calculation rules are unchanged.

This is conditional verification of supplied material. It does not authenticate a broker, establish account ownership or completeness, identify hidden accounts, or prove when a record was published.

## Keep the inputs private

The private reconciliation JSON contains original source bytes and text, filenames, account aliases, dates, NAV values, cash flows, raw rows, correction histories, source decisions and unresolved evidence. It is unencrypted. Anyone receiving it can read that data. It contains no signing key and is never automatically included in a shared profile or review package. Share it only deliberately with an intended reviewer; running this checker does not upload it.

Keep both input files unchanged. The compact check result does not replace the original evidence.

## Obtain and verify the checker

Both the complete editable source download (`n170-verify-source.zip`) and the
combined offline toolkit (`n170-verify-toolkit.zip`) include this Node checker.
Keep the received archive unchanged. Obtain its expected SHA-256 and an
independent `verify_release.py` through a channel you trust. A verifier and digest
from the same untrusted download do not authenticate their publisher. Before
extraction, use Python 3's standard library to check the exact archive bytes,
manifest and file inventory:

```sh
python3 verify_release.py ARCHIVE.zip --sha256 EXPECTED_ARCHIVE_SHA256
```

Replace `ARCHIVE.zip` with the actual downloaded filename and the digest with
your separately retained value. Extract into a new directory only after the check
passes. Retain the original archive and its expected digest.

- Complete source or combined release: the application and CLI are under `app/`.
  From the extracted root, use `cd app`; this folder contains `package.json` and
  `scripts/`.
- Standalone toolkit: `scripts/` is directly under the extraction root, alongside
  `verify_toolkit/`, `verify_accounting/`, `docs/`, `LICENSE` and `NOTICE`. Run there;
  omit `cd app`. The Node CLI does not require a `package.json` in this archive.

The four included CLI modules are `scripts/verify-reconciliation.mjs`,
`scripts/reconciliation-input.mjs`, `scripts/reconciliation-source.mjs` and the
unchanged independent `scripts/verify-record.mjs`. Use Node.js 20.19+ within 20.x
or Node.js 22.12+ supported by the source. They use Node's built-in libraries and
need no npm install, browser build, Python package, network, engine or broker
access. Python is used for archive verification above, not by the Node checker.

## Run the check

1. In the owner app's **Input-to-return reconciliation**, open **Export this reconciliation privately** and choose **Export private reconciliation**. Retain `n170-private-reconciliation.json`, not `n170-private-draft.json`. A blocked export remains useful evidence; exporting it does not resolve its blockers.
2. Retain the existing single-profile signed JSON or self-contained review HTML. Choose the exact signed v4 event you intend to check. In a profile JSON, its payload digest is the selected entry's `sha256` in `stamps`, alongside its `payload` and `signature`. With HTML, open the file as data in a trusted app, check the record, then open that event's **Independent checking details** and use **Record SHA-256**. Do not use the nearby original supplied-file digest. Use all 64 lowercase hexadecimal characters. This is an event digest, not the profile ID, a source digest or a file checksum. No new signing is required.
3. Open a terminal in the appropriate folder containing `scripts/`, as described above. Replace both quoted paths below with your retained files and `EVENT_SHA256` with the selected event digest. Keep the quotes around paths containing spaces.

```sh
node scripts/verify-reconciliation.mjs --record "/absolute/path/to/signed-record.json" --event-sha256 EVENT_SHA256 --reconciliation "/absolute/path/to/n170-private-reconciliation.json"
```

`EVENT_SHA256` is an invalid placeholder until replaced. There is no implicit
latest-event selection. For fixed help, run
`node scripts/verify-reconciliation.mjs --help` from the same folder.

Only the two explicit input paths are opened. Paths, URLs, code and commands
contained in either input are not followed. The checker creates no key, accesses
no private key and signs nothing. Choose ordinary UTF-8 files; symbolic links,
pipes and device files are rejected.

### Single-profile boundary

This checker accepts one existing signed profile, including its complete event
history, directly as JSON or embedded in the existing self-contained review HTML.
It does not accept a whole device-continuity envelope, combine key segments or
replace the separate continuity check. After a device change, the owner's normal
signed JSON and review HTML exports can contain a continuity envelope. Keep that
original unchanged. Use a separately retained single-profile export containing
the selected event if available; this guide does not provide a segment-extraction
workflow. If only the envelope is available, this checker cannot assess that
export directly. Envelope rejection does not mean its continuity signatures are
invalid. Continuity instructions are in `app/docs/key-continuity-contract.md` and
`app/scripts/verify-continuity.mjs` in the **complete source only**; those are not
included in the standalone toolkit's four-module checker bundle.

## Read the result

The checker writes one bounded JSON result. Inspect its status, fixed reason codes, binding checks, selected event sequence/type and superseded state, counts and source-decision inventory as well as the exit code.

| Exit | Status | Meaning |
| --- | --- | --- |
| 0 | `VERIFIED_UNDER_OWNER_ASSERTIONS` | The implemented source, private-interval and selected signed-event checks agree within the supported scope. Owner assertions and the stated limitations still apply. |
| 1 | `MISMATCH` | A verifiable contradiction exists, such as a source/normalization commitment, scope, interval or signed-return disagreement. Retain both inputs and investigate. |
| 2 | `NOT_ASSESSABLE` | Evidence, assumptions or numerical support are missing or unsupported. This is not a passing financial result. |
| 3 | `INVALID_INPUT` | Input encoding, structure, signature, event selection, command flags or resource limits fail validation. |

A historical event superseded by a later valid correction stays explicitly identified as superseded; the checker does not silently select its replacement. A signed correction event can be selected itself if its source meets the supported preparation rules. This check cannot establish that another signed history does not exist.

The output omits filenames, paths, account aliases/IDs, source hashes, dates, raw values, raw rows and free-text reasons. Source decisions are reported by ordinal, disposition, bytes availability, byte-binding status, text-decoding status and whether a reason is present. The interval count covers independently calculated adjacent source/signed intervals (at most 499), not the private schedule expansion, which may retain up to 5,500 intervals including missing boundaries. Counts and event metadata may still reveal workflow information. There is no verbose or raw-output option. The [result JSON schema](verify-reconciliation-result.schema.json) is beside this guide: `docs/verify-reconciliation-result.schema.json` from the standalone toolkit root, or `app/docs/verify-reconciliation-result.schema.json` from the complete source root.

## Supported scope and refusals

Version 1 supports one active N170 `date,nav,external_flow` CSV or the documented IBKR Activity Flex **Change in NAV** CSV. The detailed import-format instructions are in `app/docs/import-formats.md` in the **complete source only**. Transaction history, arbitrary broker formats, assistant handoffs and manual/v3 signed records are outside this checker's supported source path. The signed provenance must declare the matching `supplied_file` format and commitments. Preparation correction arrays are unsupported in v1, even when their hashes are consistent.

The checker independently binds retained bytes, decoded text, source hashes, normalization, the exact working CSV, scope, interval dependencies and signed returns. Every observation participates. A producer's success flag cannot authorize verification, and private dependency digests do not become signed proof.

Account aliases, absent source currency, interval-end flow timing, review for hidden offsetting flows, valuation schedules and source exclusions remain owner assertions. Explicit source currencies must agree. No currency conversion, missing-value filling, row sorting or silent deduplication occurs. Unknown/intraperiod timing, offsetting cash activity, missing required boundaries, unresolved source attempts, rejected excess entries, unresolved intervals and blockers prevent verification.

The signed account alias must equal the exact `.trim()` result of the raw private `scope.account_alias`, matching the existing signing rule. The checker does not otherwise rewrite the alias or infer that it belongs to a broker Account ID.

Retained excluded or superseded sources require a recorded reason. Supplied bytes are checked even for those sources. Missing active bytes prevent verification. Missing bytes for an explicitly excluded or superseded attempt remain disclosed and may coexist with a conditional result; unavailable originals are not authenticated or given a byte identity.

An explicitly excluded or superseded source with a recorded reason may retain bytes that cannot be decoded as UTF-8. Their byte length and identity must still bind, their decoded text stays null, and the source-decision result reports `text_decoding: "invalid_utf8"`. Those bytes are never parsed as a financial source, and the limitation remains disclosed. Invalid UTF-8 in the active source prevents assessment; any unresolved attempt also prevents assessment. A successful byte binding alone does not make either case assessable.

Amounts must be supported plain decimals, with at most 18 fractional places and magnitude 10^15. The checker uses exact integer/rational arithmetic. Depletion, recapitalization, unsupported rounding precision and interval or cumulative-wealth limits remain unassessable. It never drops an unsupported period to produce a passing prefix.

Transport and structural limits include a 2,000,000-byte signed input, 32 MiB private JSON, 10 MiB aggregate decoded source bytes, 20 retained sources, 5,000 source rows, 500 observations, 5,500 private intervals, 20,000 diagnostics, 100 corrections, JSON depth 24 and 500,000 nodes. Enumerated schedules are bounded to 5,000 days. Duplicate JSON keys, unsafe numeric encodings, malformed UTF-8 in either outer input, malformed base64, unknown schema fields and other ambiguous input are rejected. Retained source bytes have the separate decoding treatment described above. These bounds do not guarantee that every otherwise well-formed auxiliary payload is supported.

## Relationship to public verification

`scripts/verify-record.mjs` remains the separate public-record checker for signed relative returns and metrics. `scripts/verify-reconciliation.mjs` adds a conditional source-to-return check only when the owner deliberately supplies the matching private artifact and an explicit event digest. Neither result establishes broker authenticity, all accounts, independent publication time or an external financial audit. The private artifact contract (`app/docs/account-reconciliation-contract.md`) and signed format (`app/FORMAT.md`) remain unchanged; these additional references are in the **complete source only** and are not bundled with the standalone toolkit guide.
