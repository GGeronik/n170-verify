# Witness receipt v1

A witness receipt records an independent fetcher's comparison with one signed event. Verification is offline. It does not fetch from a broker, authenticate broker responses, establish account ownership, confirm a timestamp, discover omitted accounts or establish lifetime coverage. The broker responses are not signed. The witness's clock is a claim by that witness.

## Recipient inputs

Trust comes from the recipient. Supply a nonempty list of trusted witness key codes and a nonempty list of allowed lowercase broker hosts. The review page starts with both fields empty. A receipt cannot add itself to either list. Obtain key codes through a channel you trust; a code has 80 bits, so compare the full witness key ID separately when needed.

Select the exact signed event using its verifier-computed SHA-256. A receipt for a superseded event cannot promote the current record: successful reconciliation becomes not assessable with `SELECTED_EVENT_SUPERSEDED`. Mismatches remain rejections. Other effective periods remain qualified as unwitnessed or unreconciled.

```text
node scripts/verify-headline.mjs CURRENT [PREVIOUS]
  --event-sha256 HEX --witness-receipt RECEIPT
  --trusted-witness-key CODE --allowed-broker-host HOST
  [--timestamp-proof PROOF]

node scripts/verify-witness-receipt.mjs RECEIPT --event-sha256 HEX
  --trusted-witness-key CODE --allowed-broker-host HOST
  [--timestamp-proof PROOF]
```

Key and host options are repeatable and have no defaults. IBKR Flex Web Service uses `ndcdyn.interactivebrokers.com`; its name is guidance, never an implicit allowlist. The headline command exits 0 for a supported tier, 1 for rejection, 2 for conflict, and 3 for usage or file-read failure. The receipt command exits 0 for `WITNESSED`, 1 for mismatch/invalid receipt, 2 for not assessable, and 3 for usage/read failure. The existing record, private-source and continuity commands keep their original output names and exit codes.

## Wire format and identity

The [structural schema](../schemas/witness-receipt-v1.schema.json) describes exactly three top-level fields: `payload`, `sha256`, `signature`. The schema alone cannot perform cryptographic, duplicate-name, byte-bound, sorted-array or date-order checks.

Canonical payload JSON contains exactly these fields, in order:

1. `schema_version`: `n170.verify.witness-receipt.v1`.
2. `serialization_version`: `1.0.0`.
3. `witness_public_key`: canonical unpadded base64url of a 65-byte uncompressed P-256 point.
4. `witness_key_id`: SHA-256 of UTF-8 `n170.verify.witness-key.v1`, LF, then the raw point.
5. `broker`: `IBKR`.
6. `endpoint_host`: 1–253 characters, lowercase ASCII hostname labels, no trailing dot.
7. `tls_chain_sha256`: 1–10 lowercase certificate digests, leaf first.
8. `query_id`: 1–32 ASCII digits as a string.
9. `token_sha256`: the token fingerprint only. Never include the token.
10. `requested_range`: `from`, then `to`, valid dates, first earlier than second.
11. `fetched_at_witness_clock`: `YYYY-MM-DDTHH:MM:SSZ`.
12. `response_sha256`: digest of raw response bytes.
13. `canonicalization_version`: `1.0.0`.
14. `canonical_statement_sha256`: digest of canonical statement bytes.
15. `sections_present`: sorted, unique, 1–4 of `AccountInformation`, `CashReport`, `CashTransactions`, `ChangeInNAV`.
16. `accounts_seen`: sorted, unique, 0–20 masked identifiers matching `[A-Z]{1,3}\*{3,8}[0-9]{4}`.
17. `coverage`: null, or `available_from`, then `available_to`, valid dates in ascending order.
18. `record_event_sha256`: the selected event's digest.
19. `reconciliation`: `VERIFIED_UNDER_WITNESS`, `MISMATCH`, or `NOT_ASSESSABLE`.
20. `reasons`: sorted, unique, at most 20 fixed uppercase identifiers; empty exactly for `VERIFIED_UNDER_WITNESS`.
21. `first_difference`: null, or `date`, then `field` (`nav`, `external_flow`, `return`, `coverage`, `section`). It contains no value or amount and is null for successful reconciliation.

Dates are `YYYY-MM-DD`. Digests are 64 lowercase hexadecimal characters. All payload strings are ASCII; no JSON number appears. Reject missing/extra fields, duplicate decoded names (including escaped spellings), a byte-order mark, malformed UTF-8, more than 65,536 bytes, more than 16,384 characters, or nesting deeper than four levels. Arrays retain their stored order; checks do not sort them.

Canonical bytes are compact JSON in the field order above with standard JSON string escaping and UTF-8. `sha256` hashes these payload bytes and is the receipt identity. The signature is ECDSA P-256/SHA-256 over UTF-8 `n170.verify.witness-receipt-signature.v1`, LF, then canonical bytes. It is IEEE P1363 `r‖s` (64 bytes), canonical unpadded base64url. Both high-s and low-s verify. DER signatures are rejected. The witness key code is the first 20 hex characters of the derived key ID, grouped four at a time with hyphens. Profile keys and signatures use different domains; a profile code or stamp signature cannot substitute for a witness receipt.

## Verification and results

Browser and standalone Node implementations check options, byte/JSON bounds, versions, all field rules, curve point, derived key ID, recipient trust, payload digest, signature, selected event binding, allowed host, reconciliation, then detached timestamp header. The first failure controls the result; invalid or forged receipts cannot fall through to a lower source tier. The implementations return statuses rather than throwing. Returned metadata is populated only after its establishing check succeeds.

- `WITNESSED`: all required checks pass and reconciliation succeeds.
- `WITNESS_MISMATCH`: a valid, bound, allowed receipt reports `MISMATCH`; includes `RECEIPT_RECONCILIATION_MISMATCH` and its fixed reasons.
- `WITNESS_NOT_ASSESSABLE`: invalid recipient options, a disallowed host, or a valid receipt reporting `NOT_ASSESSABLE`.
- `WITNESS_RECEIPT_INVALID`: schema/version, key, trust, hash, signature or event-binding failure.

The result also includes `reasons`, `receipt_sha256`, `witness_key_code`, `endpoint_host`, `record_event_sha256`, `sections_present`, `accounts_seen`, and `timestamp_proof`.

## Detached timestamp header

No proof gives `NONE`. A supplied proof must begin with the 31-byte OpenTimestamps magic `004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294`, major version 1, SHA-256 operation tag `08`, and the 32-byte canonical payload digest. A malformed header gives `INVALID` / `TIMESTAMP_PROOF_MALFORMED`; a different digest gives `INVALID` / `TIMESTAMP_PROOF_UNBOUND`; a matching header gives `PENDING` / `TIMESTAMP_CONFIRMATION_NOT_VERIFIED`.

This checks header binding only, not the commitment path or blockchain confirmation. Iteration 1 never emits `CONFIRMED`; it remains reserved. Timestamp outcomes do not change the receipt result or tier.

## Headline and ladder

The headline consumes verifier-computed enums only. Record failure precedes comparison/continuity conflict, which precedes source/receipt mismatch or invalid receipt. Successful witness checking promotes only the selected event; owner-supplied source comparison remains explicitly under owner assertions. Missing facts or malformed display context reject with `FACTS_INCOMPLETE`. Statistics never choose a headline or enter its sublabel.

Six rows always accompany a check outcome: Calculations, Signatures and history, Source, Key, Time, Coverage. A not-assessable check is a qualification with fixed reasons, never a pass. The page and CLI preserve existing record, comparison, continuity and private-source status vocabularies.
