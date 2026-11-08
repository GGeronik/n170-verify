# Recipient Guide

## 1. What you received

You received a review HTML package or a signed JSON record (single profile or key-continuity package), and optionally a witness receipt, its detached timestamp proof, or an owner-shared private-source file.

## 2. Checking in the browser

Open the hosted page or your own local build, choose **Review a record**, and select the file. You may add your retained copy, an expected key code, or a checkpoint fingerprint. For a witness receipt, select the covered event and enter your trusted witness key codes, allowed broker hosts, and optional timestamp proof. Everything stays on your device; the content security policy blocks script network connections.

Below the headline and any qualification rows, the page renders:

- **Six-row ladder:** `Calculations`, `Signatures and history`, `Source`, `Key`, `Time`, and `Coverage`, stating what was checked and what remains unestablished.
- **Derived statistics (unsigned):** one panel per effective period showing interval count and frequency, mean, standard deviation, skewness and excess kurtosis with standard errors, lag-1 autocorrelation with band, nominal and autocorrelation-adjusted annualised Sharpe ratios over zero, probabilistic Sharpe ratio against zero, and minimum track record length at observed moments (or refusal codes when withheld).

## 3. Checking on the command line

First verify the release archive with a separately obtained digest:

- `python3 verify_release.py n170-verify-source.zip --sha256 <digest>`

Then run:

- `node scripts/verify-record.mjs FILE [PREVIOUS]`: `0` means valid and identical or extended; `1` means invalid; `2` means truncated, replaced, or conflicting.
- `node scripts/verify-headline.mjs CURRENT [PREVIOUS]`: derives the headline, qualifications, and six-row ladder (accepting `--event-sha256`, `--reconciliation`, or `--witness-receipt`, `--trusted-witness-key`, `--allowed-broker-host`, and `--timestamp-proof`; exits `0`, `1`, `2`, or `3` for usage errors).
- `node scripts/verify-reconciliation.mjs`: run only when the owner deliberately shares the private-source file.

## 4. What each headline means

- `REJECTED: INVALID_INPUT`: Strict parsing failed or disclosed returns did not reproduce the signed metrics.
- `REJECTED: PAYLOAD_HASH_MISMATCH`: A signed payload's SHA-256 digest differed from its recorded digest.
- `REJECTED: SIGNATURE_INVALID`: A signature or key identifier failed verification against the public key.
- `REJECTED: CHAIN_BROKEN`: The record, correction, or key-transition sequence has a broken link, bad order, or overlap.
- `REJECTED: FACTS_INCOMPLETE`: Verification inputs were incomplete or malformed, so the verifier failed closed.
- `REJECTED: PRIVATE_SOURCE_MISMATCH`: The owner-supplied private-source file disagreed with the signed event.
- `REJECTED: WITNESS_MISMATCH`: A valid witness receipt reported that the broker statement disagreed with the signed event.
- `REJECTED: WITNESS_RECEIPT_INVALID`: The witness receipt failed schema, signature, key-trust, or event-hash checks.
- `CONFLICT: TRUNCATION`: The record is valid alone but omits earlier history from your retained copy or checkpoint.
- `CONFLICT: REPLACEMENT`: The record uses a different key or replaces the root history of your retained reference.
- `CONFLICT: CONFLICTING_HISTORY`: The record shares a key with your retained reference but diverges at a signed entry.
- `CONFLICT: CONTINUITY_CONFLICT`: The key-continuity package conflicts with the transition chain in your retained package.
- `WITNESSED RECORD`: Arithmetic and signatures are valid, and a trusted witness receipt matched the selected period from an allowed broker host.
- `SOURCE-RECONCILED RECORD · under owner assertions`: Arithmetic and signatures are valid, and the owner-supplied file matched the selected event under unauthenticated owner assertions.
- `SELF-REPORTED RECORD · arithmetic and signatures verified`: Arithmetic, hashes, signatures, and chain links are valid for self-reported figures.

## 5. What is not established

- **Broker authenticity:** unestablished except for periods covered by a witness receipt you trust.
- **Identity and account completeness:** key continuity does not prove legal identity or that all accounts were disclosed.
- **Independent time:** timestamps are self-reported or witness-clock values unless a supported timestamp proof is confirmed.
- **Investment skill and employment suitability:** verification checks data integrity only.
- **Statistics:** all statistics are derived, unsigned, and change with future returns.

## 6. Keep your evidence

Retain the checked copy, any witness receipt, and the checkpoint for the next review; compare every later copy against what you kept.
