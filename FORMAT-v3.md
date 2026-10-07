# Record format, version 3

This page specifies N170 Verify profile files closely enough to write an independent checker in any language. The reference implementation is [`src/trackRecord.js`](src/trackRecord.js) with [`src/calculator.js`](src/calculator.js). [`examples/`](examples) holds a signed two-record profile and its published fingerprints to test against, and [`tests/examples.test.mjs`](tests/examples.test.mjs) is a second checker written from this page alone.

A checker rejects a file if any rule here fails.

## File

A profile file is UTF-8 JSON of at most 500,000 characters (UTF-16 code units). Whitespace between tokens is allowed. Reject the file if:

- any object repeats a field name, at any depth, including names spelled with different escapes;
- any object has a missing or additional field;
- any number isn't written as a plain integer: an optional minus sign and digits, with no leading zero, fraction, exponent or `-0`, and a magnitude of at most 2⁵³ − 1.

## Profile

| Field | Type | Rule |
|---|---|---|
| `schema_version` | string | `"n170.verify.track-record.v3"` |
| `profile_id` | string | 64 lowercase hex characters, derived from `public_key` ([Keys](#keys)) |
| `display_name` | string | the profile's alias ([Aliases](#aliases)) |
| `public_key` | string | the profile's public key ([Keys](#keys)) |
| `stamps` | array | 0 to 120 records |

Each record in `stamps` has exactly three fields: `payload` (an object, below), `sha256` (64 lowercase hex characters) and `signature` ([Signatures](#signatures)).

## Record payload

Fields in canonical order:

| Field | Type | Rule |
|---|---|---|
| `schema_version` | string | `"n170.verify.performance-stamp.v3"` |
| `calculation_version` | string | `"1.0.0"` |
| `sequence` | integer | the record's position in `stamps`, starting at 1 |
| `profile_id` | string | equal to the profile's `profile_id` |
| `display_name` | string | equal to the profile's `display_name` |
| `previous_sha256` | string or null | `null` for record 1, otherwise the previous record's `sha256` |
| `source_kind` | string | `"self_reported"`, or `"synthetic_demo"` for the bundled example series only |
| `provider_authenticated` | boolean | `false` |
| `independent_timestamp` | boolean | `false` |
| `period` | object | `start`, `end` |
| `periods_per_year` | integer | 1 to 366 |
| `relative_returns` | array | 1 to 499 intervals, each with `start`, `end`, `return_e8` |
| `coverage` | object | `nav_observations`, `return_observations`, `external_cash_flow_count` |
| `metrics` | object | `total_return_twr_e8`, `annualized_volatility_e8`, `max_drawdown_e8` |

Rules:

- **Dates** are valid calendar dates written `YYYY-MM-DD`, compared as strings.
- **Period.** `period.start` is before `period.end`, and on or after the previous record's `period.end`. A later start leaves a gap, which checkers report but don't reject.
- **Intervals** are contiguous. The first starts at `period.start`, each one starts where the previous one ended, the last ends at `period.end`, and each `start` is before its `end`.
- **Returns.** `return_e8` is the interval's relative return in units of 10⁻⁸, greater than −100,000,000. A loss of 100% or more isn't representable.
- **Coverage.** `return_observations` is the number of intervals, `nav_observations` is one more, and `external_cash_flow_count` is from 0 to the number of intervals.
- **Metrics** must equal the values recomputed in [Metrics](#metrics), with `annualized_volatility_e8` null exactly when there's one interval.
- **Synthetic example.** A `synthetic_demo` record must have exactly these intervals and an `external_cash_flow_count` of 1:

  | `start` | `end` | `return_e8` |
  |---|---|---|
  | 2025-01-02 | 2025-01-03 | 1000000 |
  | 2025-01-03 | 2025-01-06 | 1009901 |
  | 2025-01-06 | 2025-01-07 | -1000000 |

## Canonical bytes and record hash

`canonical(payload)` is the payload written as JSON:

- fields in the order of the table above; nested fields in the order `start`, `end` for `period`; `start`, `end`, `return_e8` for each interval; and the orders listed above for `coverage` and `metrics`;
- no whitespace;
- integers as plain decimal digits;
- in strings, `"` written as `\"` and `\` as `\\`, and every other character as itself in UTF-8. Aliases can't contain control characters and every other string is ASCII, so no other escapes occur.

A record's `sha256` is the lowercase hex SHA-256 of `canonical(payload)`.

Record 1 of the example profile has these canonical bytes:

```json
{"schema_version":"n170.verify.performance-stamp.v3","calculation_version":"1.0.0","sequence":1,"profile_id":"71dc2b628045f792681bd1ee3431723112f24308cf4a303809dd8ad8d263a32f","display_name":"Example profile","previous_sha256":null,"source_kind":"synthetic_demo","provider_authenticated":false,"independent_timestamp":false,"period":{"start":"2025-01-02","end":"2025-01-07"},"periods_per_year":252,"relative_returns":[{"start":"2025-01-02","end":"2025-01-03","return_e8":1000000},{"start":"2025-01-03","end":"2025-01-06","return_e8":1009901},{"start":"2025-01-06","end":"2025-01-07","return_e8":-1000000}],"coverage":{"nav_observations":4,"return_observations":3,"external_cash_flow_count":1},"metrics":{"total_return_twr_e8":999800,"annualized_volatility_e8":18375843,"max_drawdown_e8":-1000000}}
```

Their SHA-256 is `ef8581ab4870834ffede0a185ec56f6b00703e2b9f5db33389a7c2ce20cee4ef`.

## Keys

- **`public_key`** is the 65-byte uncompressed P-256 point (`0x04`, then X, then Y) in base64url without padding: 87 characters, with the unused low bits of the last character set to zero. The point must be on the curve.
- **`profile_id`** is the lowercase hex SHA-256 of the 26 ASCII bytes `n170.verify.profile-key.v3` plus a line feed (27 bytes including the line feed), followed by the 65 public key bytes.
- **The key code** is the first 20 hex characters of `profile_id` in five groups of four, joined by hyphens. For the example profile it's `71dc-2b62-8045-f792-681b`.

## Signatures

- **`signature`** is the 64-byte IEEE P1363 encoding (r, then s) in base64url without padding: 86 characters, with the unused low bits of the last character set to zero.
- **Algorithm.** It's an ECDSA P-256 signature with SHA-256.
- **Signed message.** The signature covers the 30 ASCII bytes `n170.verify.stamp-signature.v3` plus a line feed (31 bytes including the line feed), followed by `canonical(payload)`.
- **Low-s.** Both (r, s) and (r, n − s) verify, so don't require low-s. A record's identity is its `sha256`, never its signature.

## Aliases

`display_name` rules:

- **Length.** 1 to 80 UTF-16 code units.
- **Spaces.** No space at either end.
- **Characters.** Only characters in the Unicode general categories Letter (L), Mark (M), Number (N), Punctuation (P) and Symbol (S), plus U+0020 SPACE.

That rules out control, formatting (zero-width, joiner and bidi override), private-use, unassigned and other space characters, which can hide or reorder text. Checkers built on different Unicode versions can disagree about recently assigned characters. When they do, the older checker rejects the file rather than accepting something unexpected.

## Metrics

Compute with IEEE 754 double-precision arithmetic, one operation at a time in exactly this order. Don't use `pow`, extended precision, fused multiply-add, or a compensated sum such as Python 3.12's built-in `sum()` or `math.fsum`.

```text
n = number of intervals
r[i] = return_e8[i] / 100000000

wealth = 1, peak = 1, drawdown = 0
for i = 0 .. n-1:
    wealth = wealth * (1 + r[i])
    peak = max(peak, wealth)
    drawdown = min(drawdown, wealth / peak - 1)

sum = 0;     for i = 0 .. n-1: sum = sum + r[i]
mean = sum / n
squares = 0; for i = 0 .. n-1: squares = squares + (r[i] - mean) * (r[i] - mean)
volatility = sqrt(squares / (n - 1)) * sqrt(periods_per_year)   if n > 1, else null

total_return_twr_e8      = units(wealth - 1)
annualized_volatility_e8 = units(volatility), or null
max_drawdown_e8          = units(drawdown)
```

`units(x)` is the integer nearest to `x * 100000000` (one multiplication), taking the larger integer when exactly halfway, with negative zero written as `0`. This is JavaScript's `Math.round`. Elsewhere, compute `y = x * 100000000`, `f = floor(y)`, and take `f + 1` if `y - f >= 0.5`, otherwise `f`. `floor(y + 0.5)` is wrong for some inputs.

The record is invalid if `wealth` stops being finite and positive, `volatility` isn't finite, or a result isn't a safe integer.

## Published fingerprints

A fingerprint is one line:

```text
n170-verify key=<key code> record=<sequence> end=<period end> sha256=<record sha256>
```

- **Parsing.** Trim each line and lowercase it, and skip blank lines. Identical lines count once.
- **Limits.** At most 120 non-blank lines and 20,000 characters.
- **Fields.** `record` is from 1 to 120 with no leading zero, and `end` is a valid date.

A fingerprint matches when its key code equals the profile's, the profile has at least `record` records, and that record's `sha256` and `period.end` equal the line's. Each payload includes the previous record's `sha256`, so matching record N fixes records 1 to N exactly as they were.

## Reported without rejecting

The reference checker also reports:

- **Gaps:** where a record starts after the previous one ended.
- **Frequency warnings:** for records with at least two intervals, where `periods_per_year` is more than twice, or less than half, of 365.25 divided by the median interval length in days. The frequency only scales annualized volatility.

## Versions

Any change to the canonical bytes, the metric arithmetic or the field rules gets a new version number in both schema strings and both domain labels. Checkers reject versions they don't implement.
