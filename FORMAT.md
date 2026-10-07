# N170 Verify portable evidence, version 4

Normative record format, 14 September 2026. New records use calculation `2.0.0` and serialization `1.0.0`. Version 3 files and record prefixes remain checked using their original [frozen v3 specification](FORMAT-v3.md); v1/v2 experimental formats remain unsupported. The independent command-line implementation in [`scripts/verify-record.mjs`](scripts/verify-record.mjs) uses Node's standard crypto and separate arithmetic/serialization code, without importing application modules.

Run these commands in the folder containing `package.json` (`cd app` from either
source archive root). Use actual paths to the retained record files. Verify the
source archive before extraction as described in [README.md](README.md).

```sh
node scripts/verify-record.mjs examples/example-profile.json
node scripts/verify-record.mjs examples/review-profile-v4.html
node scripts/verify-record.mjs CURRENT.html PREVIOUS.html
```

Exit 0 means the implemented structural, arithmetic and signature checks passed, and any compared previous copy is identical or extended. Exit 1 means invalid evidence/input. Exit 2 means both copies check individually but comparison found truncation, replacement or conflicting history. No result authenticates a broker, establishes personal identity, proves account completeness, establishes independent time, demonstrates investment skill or determines employment suitability.

## Strict parsing and bounds

Profiles are UTF-8 JSON of at most 500,000 UTF-16 code units, with 0–120 events and 1–499 intervals per event. Reject duplicate object fields, including equivalent escaped names; missing or extra fields; unsafe integers; fractions/exponents; negative zero. Numbers use plain integer syntax, magnitude at most 2⁵³−1. Use the v3 visible Unicode alias rules for `display_name` (1–80 UTF-16 units, no outer spaces); other text fields allow those same categories, with bounds below. Strings are not interpreted as URLs, HTML or code. Calendar dates use valid `YYYY-MM-DD` dates.

The review HTML envelope is at most 2,000,000 code units and contains one exact opening marker `<script id="n170-evidence" type="application/json">`, followed by the JSON attachment and `</script>`. Angle brackets and ampersands in JSON strings are escaped as `\u003c`, `\u003e`, `\u0026`. Importers extract this inert text without rendering or executing any supplied HTML, and then apply the strict JSON rules. Static HTML is an unsigned convenience presentation; recipients independently check the signed attachment using software they trust. It must never be treated as a self-authenticating certificate.

## Profile and signatures

The exact profile fields remain, in order: `schema_version`, `profile_id`, `display_name`, `public_key`, `stamps`. The new schema is `n170.verify.track-record.v4`. V4 containers may hold an unchanged contiguous v3 prefix followed by v4 events; v3 after the first v4 event is rejected. A v3 container accepts only v3 events. Appending upgrades the container label without altering earlier events. The unsigned container label alone does not change record identity.

Keys and key codes retain the v3 definition: uncompressed P-256 point, canonical unpadded base64url, profile ID SHA-256 of `n170.verify.profile-key.v3` + LF + raw key. Keeping this key-domain label preserves the same signing identity across record-format upgrades. The private key is not included. WebCrypto nonextractability prevents raw export through that API; it does not prove hardware protection, exclusive possession or inability to clone a signing capability.

Each stamp has exactly `payload`, `sha256`, `signature`. Payload hash is SHA-256 of canonical payload bytes. Signature is ECDSA P-256/SHA-256, canonical unpadded base64url of 64-byte IEEE P1363 r||s. Both high-s and low-s verify; chain identity uses the payload hash, never signature bytes. For v4, sign `n170.verify.stamp-signature.v4` + LF + canonical payload. V3 keeps its original signature domain.

## Canonical v4 payload

These fields appear in this exact order; nested fields appear in the listed order. Canonicalization uses compact JSON, plain integer decimal digits and standard JSON string escaping; all other permitted Unicode characters are emitted directly as UTF-8. Input object field order and whitespace are irrelevant. Hash only this fixed-depth constructed representation.

| Field | Rule |
| --- | --- |
| `schema_version` | `n170.verify.performance-stamp.v4` |
| `calculation_version` | `2.0.0` |
| `sequence` | Position in the complete event list, starting at 1 |
| `profile_id` | Equal to profile ID |
| `display_name` | Equal to profile alias |
| `previous_sha256` | Null at sequence 1; immediately prior event hash otherwise |
| `source_kind` | `self_reported`, or owner-designated `synthetic_demo` (demonstration data only); v3 retains its original exact-sample restriction |
| `provider_authenticated` | Always `false` |
| `independent_timestamp` | Always `false` |
| `period` | `{start,end}` with start before end |
| `periods_per_year` | Integer 1–366; unsupported annualization choices withhold volatility |
| `relative_returns` | `[{start,end,return_e8}]`; contiguous ascending intervals spanning the entire period |
| `coverage` | `{nav_observations,return_observations,external_cash_flow_count}`; first two equal interval count+1 and count; flow count integer 0–interval count |
| `metrics` | `{total_return_twr_e8,annualized_volatility_e8,max_drawdown_e8}`; exactly reproduced using calculation 2.0.0; volatility may be null |
| `serialization_version` | `1.0.0` |
| `event_type` | `performance` or `correction` |
| `correction` | Null for performance; correction object below otherwise |
| `provenance` | Source/preparation object below |

`return_e8` must be greater than −100,000,000 and at most 999,900,000,000. Amount-to-return normalization accepts plain decimals of magnitude ≤10¹⁵ and ≤18 fractional places, subtracts cash flows exactly before division, and rounds the exact return to integer e8 units, ties toward positive infinity. It rejects intervals where rounding changes the gross factor by more than 10⁻⁷ relative. The attached returns cannot prove that the owner applied the original amounts or flow interpretation correctly.

## Calculation 2.0.0

Use exact rational/integer arithmetic. Let U=100,000,000. For each interval i, exact wealth `W[i] = product((U + return_e8[j])/U)` for j≤i. The opening wealth and running peak start at 1. Every wealth must lie in [10⁻⁶,10⁶]. Total return is W[last]−1; drawdown is the minimum W[i]/max(1,W[1]…W[i])−1. Round final metrics to e8 once, ties toward positive infinity. Reject unsafe resulting integers and sampled drawdown rounding to −100,000,000.

Annualization is an explicit conservative product support policy, not a claim that 20 intervals are statistically reliable. Volatility is null unless at least 20 intervals have a supported schedule:

- 252: interval ≤5 calendar days, both ends weekdays. Count weekdays strictly after start through end; summed `max(0,weekdays−1)` may not exceed `max(2,floor(interval_count×0.06))`. This tolerates occasional holidays but checks no exchange calendar.
- 365 or 366: exactly one calendar day each.
- 52: each interval 5–9 days.
- 12: each interval crosses exactly one calendar month and spans 26–35 days.
- 4: exactly three calendar months, 80–100 days.
- 1: exactly twelve calendar months, 360–370 days.
- Every other frequency withholds volatility.

For eligible volatility, let n be interval count, s=sum(return_e8), q=sum(return_e8²). The volatility e8 is the integer nearest to `sqrt((n×q−s²)×periods_per_year/(n×(n−1)))`, ties upward. An integer square-root and midpoint comparison can implement this without floating-point rounding ambiguity. [`docs/methods.md`](docs/methods.md) documents the financial interpretation, limits and independent controls. Displayed results use these same rounded values. V3 uses its original binary64 arithmetic and annualization, even when the new rules would withhold a metric.

## Corrections and effective performance

A `performance` event starts on or after the end of the latest original performance period. Later starts expose a gap. A `correction` event appends:

```json
{"target_sequence":1,"target_sha256":"<64 lowercase hex>","reason":"Visible explanation of what changed"}
```

The target must be a prior event that has not already been superseded. Its hash must match exactly; period start/end must remain identical; reason must contain 3–500 visible characters after trimming. A correction may itself be corrected. It always links to the immediately preceding event hash, preserving the full event history. Correcting period boundaries is deliberately unsupported: preserve the record and explain the coverage limitation rather than creating overlapping or silently shortened histories.

For effective performance, start one ordered slot for each original performance event. A correction replaces the effective event in its target's original slot. All historical events remain independently checked and displayed; summaries count only the currently effective intervals. Do not concatenate originals and replacements, or double-count corrected periods. Event numbers express signing history order, not publication dates.

## Signed source and preparation declarations

Exact provenance field order:

```text
kind, format, original_sha256, source_sha256, normalized_sha256,
mapping, account_scope, currency, completeness, corrections, reviewed
```

- `kind`: `manual` or `supplied_file`.
- `format`: nonempty visible text ≤80 units. A format name is a parser selection, not source authority.
- `original_sha256`, `source_sha256`, `normalized_sha256`: null for manual input; lowercase SHA-256 hex for supplied files. Import hashing commits to UTF-8 text as supplied, current source text, and normalized observation CSV respectively. No source amounts are attached. Before signing, the app requires the normalized digest to match the calculation input.
- `mapping`: ≤20 objects `{field,column}`, visible text ≤80/120 units.
- `account_scope`: nonempty owner-declared visible text ≤160 units. Avoid including account numbers; nothing verifies this claim.
- `currency`: three uppercase ASCII letters or `unspecified`; no FX conversion/authentication occurs.
- `completeness`: always `not_established`.
- `corrections`: ≤100 objects `{row,field,reason,previous_sha256,replacement_sha256}`. Row integer 0–10,000 (0 means whole-source revision); field ≤80 visible units; reason 3–500 trimmed visible units; both digests lowercase hex. Each describes a reviewed preparation revision; it does not turn revised data into authenticated source data. Financial values remain private.
- `reviewed`: boolean owner acknowledgement, never a third-party review.

Source digests allow comparison if the owner separately discloses original files. They can reveal whether guessed candidate input matches and must not be described as encryption or zero-knowledge privacy. Selecting a file, a subset of accounts or a period leaves selection/completeness unproved. Returns may reveal sensitive performance even without balances.

## Prior copies and checkpoints

Fingerprint syntax is unchanged from v3 and addresses an exact event sequence, period end and payload hash. A matching event N fixes the supplied prefix 1…N. The checker reports the exact supplied checkpoint and explicitly reports `checked:false` when none was supplied. A line's period end is not a publication date; pasted text has no independent time authority. Fingerprints on the owner's current package are useful future retained checkpoints but do not constitute independent prior evidence.

Compare two independently validated copies by full profile identity and the longest shared prefix of payload hashes:

- `identical`: same identity, all events shared, same length.
- `extended`: same identity, full previous prefix preserved, current longer.
- `truncated`: same identity, current is a shorter exact prefix.
- `conflicting_history`: same identity, differing hash at a shared position.
- `replacement`: different key/profile identity or alias.

Report the number of shared events and exact previous final checkpoint. An invalid previous file is an error, never a trusted comparison. Comparison is relative only to files supplied by the reviewer. No network publication, other account, hidden branch or globally complete history is discovered.

### Derived comparison output, version 1

The application and independent CLI can return `previous_copy.changes` with `version: "n170.verify.comparison.v1"` and an ordered `events` list. This is unsigned, computed output, never accepted input authority and never added to a signed payload. It is returned only after both copies fully verify and the history is identical or extended; identical histories have no new events. Missing previous evidence, conflicts, truncation and replacement have no ordinary change summary.

Each event identifies its sequence, performance/correction kind, period, exact correction target/reason (or null) and before/after snapshots. A correction's before snapshot is its exact signed target, including a correction of a correction. A performance event's optional before snapshot is the then-current effective preceding period, used for declaration context, never as a performance correction. Snapshots contain signed metrics, scope/currency, source declaration/format, review claim, calculation version, frequency and interval count. Legacy absent fields remain null. This summary does not compare every source digest/mapping or establish their author. The full signed records remain available.

No financial formula, record canonicalization, hash, signature domain or old-record compatibility changed for this presentation. A v3 documentation erratum corrects the prose lengths of the domain labels to 26/30 bytes before LF; the literal byte strings and fixtures are unchanged.

## Key continuity decision

Normal local save/reopen/close behavior and portable public history are supported.
The additive source candidate implements a separately versioned
[continuity envelope](docs/key-continuity-contract.md): two to five unchanged
v3/v4 profiles joined by one to four dual-signed transitions. No transition event
or field is added to the profile format specified above. Existing single-profile
checkers reject continuity envelopes; the separate continuity checker dispatches
them explicitly. These implementation rules do not establish a completed security
audit, publication or release acceptance.

Each transition binds both profile identities, the outgoing final event checkpoint,
a random challenge and the preceding transition digest. Both available keys sign
distinct role domains. The outgoing checkpoint includes its complete supplied
event history, including corrections. The destination's first performance period
must start on or after the outgoing segment's effective performance end; a later
correction's checkpoint date is not that boundary. Gaps remain visible, corrections
stay within their original segment, and metrics are never merged across keys.

The recipient checks each outgoing head against retained evidence. Per-edge
`key_anchor` (`direct`, `inherited`, `unanchored`) is distinct from `history_anchor`
(`exact`, `prefix_only`, `not_retained`). Overall `anchor_status: matched` requires
independently retained exact history through every outgoing segment's final head.
Root-only retention in a repeated chain remains `partial`, even if subsequent key
authority is inherited. A retained prefix remains partial even for one transition.
An expected key code identifies the root key and does not establish retained
history or silently identify the newest key. Detected competing transitions remain
conflicts; hidden forks and the actual time of retention cannot be discovered
offline. Recipient acceptance remains a separate decision.

A profile export is not a private-key backup. Losing origin storage may permanently
prevent further signing under that key. Local retirement or key deletion is not
cryptographic revocation and cannot erase loaded signing capabilities elsewhere.
Lost-key recovery, passkeys, recovery authorities, revocation publishing and
external time remain unimplemented. After old-key loss, continuity cannot be
established by creating another key.

## Captured accounting evidence (v2)

V2 captured-run packages are a separate, unsigned evidence format. They do not
add fields to signed v3/v4 profiles, change their calculations, merge continuity
segments or establish broker provenance. The [accounting release guide](docs/accounting-release.md)
describes the combined download and recipient workflow. The versioned
[accounting instructions](verify_toolkit/ACCOUNTING_V2.md) and
[capture contract](verify_toolkit/CAPTURE_V2.md) define the supplied artifacts
and supported bridge.

Read package integrity, detector outcome, capture support, exact-decimal model,
native compatibility and supplied oracle evidence as separate dimensions. The
v2 exact model and the pinned native binary64 calculation are distinct policies;
model differences are not silently converted into matches. Native evidence
currently supplies only cash, quantity and accumulated net PnL. Its other six
metrics remain `NOT_SUPPLIED`, so overall accounting remains `NOT_ASSESSABLE`,
including when supplied optional oracle evidence agrees. These statuses do not
establish actual execution, complete history, real-market fills or profitability.

Verification recomputes supported relationships from received bytes without
executing strategies, embedded commands or an oracle worker. A separately held
manifest SHA-256 pins the exact supplied evidence; it does not authenticate its
producer. A reading summary omits the raw artifacts and cannot replace a complete
package for independent verification. Unlike the signed profile export, a full
run package deliberately includes source code, settings, input data and logs;
review those bytes for sensitive information before sharing.
