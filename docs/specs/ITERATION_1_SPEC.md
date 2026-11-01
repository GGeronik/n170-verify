# N170 Verify — Iteration 1 specification

Derived statistics view · headline derivation · witness-receipt verification interface · frozen fixtures

Status: proposal for freeze, 1 October 2026. Nothing here is implemented. No number in this document is an expectation until the oracle has produced it and the fixture manifest has been sealed. Publication of the current 229-file baseline precedes every step below.

## 0. Invariants this iteration must not break

- Language and layout: vanilla JavaScript ES modules under `src/` and `scripts/`; every new file is added to `scripts/public-source-inventory.json`; the Vite inventory plugin stays as the gate.
- Format v4 is unchanged. No new signed field. `relative_returns[].return_e8` are JSON integers within JavaScript safe-integer bounds; amounts never appear in the public record.
- Statistics are a derived, unsigned, versioned view (`n170.verify.statistics.v1`) recomputed by every verifier from the signed e8 series of currently effective intervals. They are never written into a payload, never hashed into identity, never shown in a headline.
- The browser stays offline (`connect-src 'none'`). Receipt and record verification need no network. Acquisition lives in the CLI toolkit.
- Existing status vocabularies keep their meanings: `verify-record.mjs` exits 0/1/2; `verify-reconciliation.mjs` returns `VERIFIED_UNDER_OWNER_ASSERTIONS`, `MISMATCH`, `NOT_ASSESSABLE`, `INVALID_INPUT`. New labels are added; none are reused with a new meaning.
- Frozen packs (68-case, 175-case) keep their identities and expectations.

## 1. Inputs to the statistics view

1. `returns`: the ordered `return_e8` integers of the currently effective intervals of one profile, as the existing verifier already derives them; converted to doubles by division by 10⁸ for this view only.
2. `periods_per_year` (`q`): the record's declared frequency, one of 1, 4, 12, 52, 252, 365, 366.
3. `schedule`: the result of the existing `analyzeObservationSchedule`. If it reports an incompatible schedule, every annualised figure in this view is withheld with `SCHEDULE_ANNUALIZATION_REFUSED`; per-interval figures (moments, ρ̂₁, PSR, MinTRL in intervals) are still computed.
4. `rf_per_interval`: scalar, default 0, always displayed in the label ("excess over 0").

No benchmark Sharpe in this version. PSR is against 0 only. A later version may accept a recipient-supplied benchmark series bound by digest.

## 2. Method (frozen on acceptance of this document)

Notation: T intervals, mean r̄ = (1/T)Σr, central moments m_k = (1/T)Σ(r−r̄)^k, sample variance s² = T·m₂/(T−1).

Refusals, evaluated in this order and returned as statuses, never thrown:
- `STATS_SAMPLE_INSUFFICIENT` if T < 20 (coincides with the existing volatility floor).
- `STATS_ZERO_VARIANCE` if m₂ = 0.
- `STATS_NON_FINITE` if any intermediate value is not finite.

Moments reported with asymptotic standard errors: skewness γ̂₃ = m₃/m₂^{3/2}, SE √(6/T); excess kurtosis γ̂₄ = m₄/m₂² − 3, SE √(24/T). These are the biased sample estimators; the choice is part of the freeze.

Lag-1 autocorrelation ρ̂₁ = Σ_{t≥2}(r_t−r̄)(r_{t−1}−r̄) / Σ(r_t−r̄)², SE 1/√T, band ±1.96/√T, flag `autocorr_significant = |ρ̂₁| > 1.96/√T`.

Sharpe per interval SR_d = (r̄ − r_f)/s. Nominal annualised Sharpe SR_d·√q. Lo (2002) finite-q lag-1 factor η = 1 + 2·((q−1)/q)·ρ̂₁ for ρ̂₁ > 0, else 1; adjusted annualised Sharpe = SR_d·√q/√η. Both figures are always reported together with ρ̂₁ and its band. There is no threshold switch; the flag is informational.

Inference. V = 1 + ½SR_d² − γ̂₃·SR_d + (γ̂₄/4)·SR_d². By Pearson's inequality (γ̂₄ ≥ γ̂₃² − 2 for any sample) V ≥ (1 − γ̂₃·SR_d/2)² ≥ 0, and V = 0 is not attainable by a finite series with non-zero variance; a V ≤ 0 or non-finite result therefore indicates a defect or corrupted input and returns `STATS_NON_FINITE`. There is no clamp. σ̂_SR = √(V/(T−1)); Z = SR_d/σ̂_SR; PSR(0) = Φ(Z). MinTRL at α = 0.05: T_min = ⌈1 + V·(1.6448536269514722/SR_d)²⌉ when SR_d > 0, else `null` with `MINTRL_UNDEFINED_NONPOSITIVE_EXCESS`. Both are labelled "at observed moments" and the view states that future returns change them.

When `autocorr_significant` is true, PSR and MinTRL are still reported but carry `STATS_INFERENCE_ASSUMES_IID` and are excluded from any summary line. This version does not implement Lo's non-i.i.d. standard error; that is an explicit limitation of v1.

Φ is computed through erfc to avoid cancellation: Φ(z) = ½·erfc(−z/√2) for z < 0 and 1 − ½·erfc(z/√2) otherwise. The JavaScript erfc is a full three-region Cody rational approximation with the split-exponential evaluation in regions 2 and 3; its coefficient tables are transcribed from SPECFUN `CALERF` and are not accepted until they pass the vectors in §5. The reference values below are from Python `math.erfc`:

Φ(−8.2) = 1.2019351542735896e−16 · Φ(−5.7) = 5.9903714010635321e−09 · Φ(−3) = 0.0013498980316300957 · Φ(−2.0526) = 0.020055693779797306 · Φ(−1) = 0.15865525393145705 · Φ(0) = 0.5 · Φ(1) = 0.84134474606854293 · Φ(1.7238) = 0.9576280226859315 · Φ(2.0526) = 0.97994430622020268 · Φ(3) = 0.9986501019683699 · Φ(5.7) = 0.99999999400962858

## 3. Oracle

`tests/stats_oracle.py`, Python 3.10+ standard library only (`math`, including `math.fsum` for every sum, and `statistics.NormalDist` as a second Φ). It implements §2 from this text, by an author other than the engine's author, and emits one JSON result per fixture. Its outputs become the sealed expectations. A third opinion is recorded once for the record, not used as oracle: QuantStats `probabilistic_sharpe_ratio` on the same series, with its convention differences noted.

Tolerances for the JavaScript engine against the oracle: moments, ρ̂₁, Sharpe figures and V relative 10⁻¹²; Φ absolute 10⁻¹⁵ for |Z| ≤ 8 and relative 10⁻¹² beyond; MinTRL exact integer equality; status codes exact string equality; erfc continuity at 0.46875 and 4.0 within 4 ULP.

## 4. Headline derivation

The headline is a function of verifier-computed facts only. It takes no field from the record or from any receipt as truth. Every input is an enum or boolean produced by the verifier; a missing input is a failure, never a default pass.

Inputs: `parse` (OK | INVALID_INPUT), `payload_hash` (MATCH | MISMATCH), `signatures` (VALID | INVALID), `chain` (VALID | BROKEN, covering predecessor links and correction bindings), `continuity` (NONE | VALID | CONFLICT, from the continuity verifier when an envelope is supplied), `comparison` (NONE | IDENTICAL | EXTENDED | TRUNCATION | REPLACEMENT | CONFLICT, from a retained copy when supplied), `reconciliation` (NONE | VERIFIED_UNDER_OWNER_ASSERTIONS | MISMATCH | NOT_ASSESSABLE | INVALID_INPUT), `witness` (NONE | WITNESSED | WITNESS_MISMATCH | WITNESS_NOT_ASSESSABLE | WITNESS_RECEIPT_INVALID).

Order:
1. `parse` INVALID, `payload_hash` MISMATCH, `signatures` INVALID, `chain` BROKEN → `REJECTED: <code>`, exit 1.
2. `comparison` TRUNCATION, REPLACEMENT or CONFLICT, or `continuity` CONFLICT → `CONFLICT: <code>`, exit 2.
3. `reconciliation` MISMATCH → `REJECTED: PRIVATE_SOURCE_MISMATCH`, exit 1. `witness` WITNESS_MISMATCH → `REJECTED: WITNESS_MISMATCH`, exit 1. `witness` WITNESS_RECEIPT_INVALID → `REJECTED: WITNESS_RECEIPT_INVALID`, exit 1. A failed or forged receipt never falls through to a lower tier.
4. `witness` WITNESSED → headline `WITNESSED RECORD`, sublabel naming broker host and witness key code.
5. `reconciliation` VERIFIED_UNDER_OWNER_ASSERTIONS → headline `SOURCE-RECONCILED RECORD · under owner assertions`, sublabel "owner-supplied source bytes matched the signed event; the source is not authenticated".
6. Otherwise → headline `SELF-REPORTED RECORD · arithmetic and signatures verified`.
7. `witness` WITNESS_NOT_ASSESSABLE or `reconciliation` NOT_ASSESSABLE is shown as a qualification row with its reason, never as a pass.

The six-row ladder (calculations, signatures and history, source, key, time, coverage) is always rendered beneath the headline. The word "verified" never leads a headline. Statistics never appear in the headline or sublabel.

## 5. Witness receipt verification interface

Defined here so the headline has a real input; the IBKR fetch itself is Iteration 2.

`verifyWitnessReceipt(receiptBytes, { recordPayloadHash, trustedWitnessKeys, allowedBrokerHosts, otsProofBytes? })` returns one of WITNESSED, WITNESS_MISMATCH, WITNESS_NOT_ASSESSABLE, WITNESS_RECEIPT_INVALID with reason codes.

Checks, all required for WITNESSED: receipt parses under its schema with strict fields; the receipt's canonical bytes verify under a key whose code is in `trustedWitnessKeys`, supplied by the recipient, never read from the receipt; `receipt.record_event_sha256 === recordPayloadHash` where the right-hand side is computed by the verifier from the record; `receipt.endpoint_host` is in `allowedBrokerHosts`; `receipt.reconciliation === "VERIFIED_UNDER_WITNESS"`; if an OpenTimestamps proof is supplied it binds the receipt hash and is reported as PENDING or CONFIRMED, never as a condition of WITNESSED. A receipt whose reconciliation says MISMATCH yields WITNESS_MISMATCH. A receipt with an unknown key or a bad signature yields WITNESS_RECEIPT_INVALID. The receipt contains a token fingerprint only, never a token.

## 6. Fixtures and freeze protocol

Every fixture is a literal file: an e8 integer array or a complete signed record, plus construction notes. Expected results are the oracle's JSON output or the verifier's status, written by the fixture author before any engine code exists, and sealed in a manifest with SHA-256 digests. Target moments in the notes are design intents; the sealed expectation is whatever the oracle computed on the stored bytes.

- F01 split-run inception: series starting 18 months into an account's life. Headline SELF-REPORTED RECORD; coverage row "declared account only, lifetime inception unverified".
- F02 inflow equal to or exceeding equity without a valuation at the flow: existing intraperiod-flow refusal with the existing reason code; no new code, no Dietz.
- F03 stored 295-interval series generated as AR(1) with ρ = 0.4 and recorded seed; expectations are the oracle's ρ̂₁, both Sharpe figures, `autocorr_significant` true, `STATS_INFERENCE_ASSUMES_IID` present.
- F04 14-day gap: REJECTED `SEQUENCE_GAP` only when the declared coverage is daily or weekday; QUALIFIED with the gap visible otherwise.
- F05 deposit relabelled as dividend in a Change-in-NAV bridge: file tier "not detectable; remains self-reported" recorded as a known limitation; witness tier REJECTED `FLOW_MISCLASSIFICATION`, with the dependency that the owner's Flex query includes the Cash Report section, else WITNESS_NOT_ASSESSABLE.
- F06 one key, two histories at the same index: each record valid alone; comparison CONFLICT, exit 2.
- F07 DER-encoded signature: existing rejection; regression fixture.
- F08 stored 180-interval series constructed toward skew −2.1, excess kurtosis 8.4, annual Sharpe 2.4; expectations from the oracle (design target PSR ≈ 0.958, MinTRL ≈ 164).
- F09 guard: (a) unit test injecting non-finite moments → `STATS_NON_FINITE`; (b) the lowest-V stress series found by search (V ≈ 0.06) → correct PSR with no clamp.
- F10 record carrying `provenance_tier: "WITNESSED"` and no receipt → SELF-REPORTED RECORD.
- F11 Φ at Z = ±5.7 and ±8.2 against the values in §2.
- F12 14-interval monthly record → `STATS_SAMPLE_INSUFFICIENT`.
- F13 receipt with a trusted key code copied in but an invalid signature → `REJECTED: WITNESS_RECEIPT_INVALID`.
- F14 valid receipt whose reconciliation is MISMATCH → `REJECTED: WITNESS_MISMATCH`; no fall-through.
- F15 valid receipt bound to a different event hash → WITNESS_RECEIPT_INVALID with `EVENT_HASH_UNBOUND`.
- F16 erfc continuity at the region boundaries and the Cody tables against 10,000 uniformly random Z in [−10, 10] from the oracle.

Sequence: oracle written → fixtures authored and sealed → engine implemented → engine evaluated against the sealed manifest → integration with inventory update → tests added to `npm test`. A failure is retained and fixed in a successor; the expectations are not edited.

## 7. Presentation

A statistics panel below the ladder: sample size and frequency, mean and standard deviation per interval, skewness and kurtosis each with SE, ρ̂₁ with band and flag, nominal and adjusted annualised Sharpe side by side with r_f stated, PSR(0) and MinTRL "at observed moments" with their status codes. Plain declarative sentences; no progress bars, no runway, no encouragement. Where a status withholds a figure, the row shows the code and one sentence of reason.

## 8. Out of scope for this iteration

Format changes (`declared_assumptions`, `record_type`, receipt references inside the payload) are bundled into one later version bump that updates FORMAT.md, the browser verifier, the independent CLI and the Python toolkit together. The IBKR Flex fetch, OpenTimestamps stamping, the transparency log, zkTLS, and the transaction-level engine port (gated on a measured, semantics-preserving performance fix under the research freeze protocol) follow.
