# Calculation methods and support limits

Reviewed and implemented 14 September 2026. Applies to calculation **2.0.0**, used by new records. This is a calculation specification and a bounded test result, not financial-source authentication, GIPS compliance or an assessment of the owner.

## What the numbers describe

N170 Verify calculates a return series from supplied dated net asset values (NAV) and external flows, or reviews supported supplied return observations. External deposits are positive and withdrawals negative. For the NAV input route every external flow must occur at the **end of its observation interval**:

`gross_factor[i] = (NAV[i] − external_flow[i]) / NAV[i−1]`

Trades within the account, retained dividends and interest are not external flows. Fees and taxes affect the result only when the supplied values already include them. A withdrawal for spending is different from a fee expense; classification must be reviewed. Foreign currency values must already use one consistent reporting currency; the calculator does not perform FX conversion. Unknown intraperiod flows require the relevant additional valuations or another accounting method, rather than inventing valuations or treating a transfer as investment profit.

A linked return describes the supplied account and dates under this convention. It cannot establish that the data was complete, that another account was not omitted, or that the signer is a particular person. Signatures bind the supplied record, not these economic claims.

[Portfolio Performance's official method](https://help.portfolio-performance.info/en/concepts/performance/time-weighted/) explains why cash-flow timing changes the formula. Portfolio Performance normally assumes inflows at the start of the day and outflows at the end. Its native daily TTWROR should be used as disclosed return observations where supported; its raw flows must not be silently fed to N170's end-flow formula as though the conventions were equivalent. Agreement is expected for identical no-flow inputs and identical conventions, not for differently timed deposits.

## One canonical numerical pipeline

1. Parse plain decimal NAV and flow text into integers at scale `10^18`. No amount is converted to binary floating point. Subtract cash flow exactly.
2. Calculate `return_e8 = round(((NAV − flow − prior_NAV) × 100000000) / prior_NAV)` with integer division of an exact rational. Round to nearest integer; exact half ties go toward positive infinity, including negative values. Zero is always serialized as `0`.
3. Calculate every displayed, charted and newly signed result from these **same disclosed integer return units**. One unit is `10^−8` as a decimal return, or a millionth of a percentage point. Rounding reduces numerical detail; it is not a formal guarantee that source balances cannot be inferred.
4. Preserve exact rational products until the final metric is rounded to return units. Browser display divides the signed integer result by `100000000`. There is no separate full-precision display path.

Consequently, a recipient can reproduce the metrics from the disclosed return series. A recipient who has only that series cannot check how the original NAVs and flows became returns. A private source file and reconciliation details are needed for that additional check. The small aggregate JSON intentionally omits dates and return observations and **cannot reproduce itself**; the record/review package is the reproducible artifact.

### Time-weighted linked return

For integer units `u[i]` and `U = 100000000`, keep rational wealth `W = product((U + u[i]) / U)` without intermediate rounding. Output `round((W − 1) × U)`.

The output is the total for the supplied period. The app does not compute CAGR or annualize short-period returns. It does not compute Sharpe, Sortino, XIRR or an investment-skill score.

### Sampled maximum drawdown

Start wealth and peak at 1. At each supplied interval end update wealth, update the peak, and take the minimum of `wealth / peak − 1`. Keep exact rational comparisons and round only the final result. A chart uses this same rational wealth series. Drawdown is **sampled**: a larger loss between observations is unknowable from this record. Sparse observations are not equivalent to a daily loss history.

### Annualized sample volatility

Let `n` be the return count, `S = sum(u[i])`, `Q = sum(u[i]^2)` and `F` be selected periods per year. The exact square of annualized volatility in integer return units is:

`A = ((n × Q − S²) × F) / (n × (n − 1))`

Take the nearest integer square root of this rational without binary floating-point arithmetic: `k = floor(sqrt(floor(numerator / denominator)))`; round upward iff `4 × numerator >= denominator × (2k + 1)²`. This is sample standard deviation (`n−1`), scaled by the square root of frequency. Scaling is an assumption, not a forecast. Serial dependence or changing distributions can make it misleading even when dates pass the screen.

Volatility is `null`, with a reviewable reason derived from signed dates, unless **both** conditions hold:

- At least 20 return intervals. This is a conservative product threshold, not a statistical assurance or a GIPS requirement.
- Frequency is supported and dates pass the following conservative spacing screen.

| Frequency | Screen |
| --- | --- |
| 252 trading observations/year | Endpoints are weekdays; no gap over five calendar days. At most `max(2, floor(n × 0.06))` unobserved weekdays are tolerated for possible holidays. |
| 365 or 366 calendar observations/year | Every interval is exactly one calendar day. |
| 52 weekly observations/year | Every interval is five to nine days. |
| 12 monthly observations/year | Consecutive calendar months and intervals of 26–35 days. |
| 4 quarterly observations/year | Three-month increments and intervals of 80–100 days. |
| 1 yearly observation/year | Twelve-month increments and intervals of 360–370 days. |
| Any other integer from 1–366 | TWR/drawdown may be calculated; volatility is withheld. |

The app uses no external exchange holiday calendar. A missing weekday may be a holiday or an omitted valuation; date screening cannot decide. Candidate gaps are visible, and account/source completeness remains unchecked. Long or mixed-duration gaps withhold volatility. Do not fill such gaps with invented observations. The screen is a guardrail, not validation of a market calendar.

[GIPS's official handbook](https://www.gipsstandards.org/standards/gips-standards-for-firms/gips-standards-handbook-for-firms/) defines a different reporting context, including three-year standard deviation from 36 monthly returns. N170's descriptive measure and minimum-sample policy must not be presented as GIPS compliance or an equivalent institutional track record.

## Numerical and economic support boundaries

| Boundary | Supported rule and failure behavior |
| --- | --- |
| Input | 2–500 observations, 50,000 characters; exact three-column input. |
| Amounts | Plain decimals only, at most 18 decimal places and absolute magnitude `10^15`. At most 50 characters per amount; no exponent notation, currency symbols or grouping separators. |
| Dates | Valid ISO calendar dates, unique and strictly ascending. Signed intervals must be contiguous within a record. |
| NAV and adjusted NAV | Strictly positive. Zero/negative equity, total loss and recapitalization are explicitly unsupported. The error tells the owner to retain the loss and obtain separate accounting review. |
| Interval returns | Rounded gross factor must be positive and at most 10,000. A return rounding to −100% is rejected. |
| Quantization error | Source-to-rounded gross-factor relative error may not exceed `10^−7` for any interval. Check uses exact integers: `abs((U+u)×prior_NAV − adjusted_NAV×U) × 10000000 <= adjusted_NAV×U`. |
| Cumulative wealth | Must remain between `10^−6` and `10^6` times opening wealth at every observation. |
| Drawdown precision | A drawdown rounding to −100% is rejected rather than describing a positive remnant as an actual total loss. |
| Serialization | All signed numbers are safe integers or the permitted `null` volatility. No NaN, infinity or negative zero. |

The per-interval quantization bound implies that over at most 499 intervals, the rounded cumulative **gross wealth ratio** differs from the exact supplied-factor product by less than approximately `0.005%` relative (the bound is `(1 + 10^−7)^499 − 1`). Typical cases are much closer. This is a worst-case bound on gross wealth, not a fixed bound in percentage points on total return, and does not cover errors in source data or cash-flow classification. Final metric rounding adds at most half a return unit. If an interval fails support, changing currency units cannot repair that relative precision problem. Do not omit extreme losses to get a supported number.

## Compatibility and independent reproduction

Existing `performance-stamp.v3` records use calculation `1.0.0` and retain their original binary64 operation order and rounding in `src/calculatorLegacy.js`. Their recorded volatility is not silently rewritten under the new sample policy. The checker may separately explain that an old result uses legacy rules. New v4 records use calculation `2.0.0`; format canonicalization/versioning is specified in [FORMAT.md](../FORMAT.md). Unknown versions must fail closed. Recomputed equality is exact at the integer boundary; verification is not weakened with a tolerance.

Regression controls retain two decimal cancellation cases that must return 0% in both display and record construction. Near-total-loss and inappropriate annualization cases fail or withhold under the support rules above. These checks do not change legacy record arithmetic.

Run the numerical verification in the folder containing `package.json`
(`cd app` from the complete source or combined release root):

```sh
node --test tests/calculator.test.mjs
python3 scripts/numerical-controls.py
```

The Python program independently derives returns and metrics with 200-digit Decimal arithmetic and a deterministic synthetic-data seed. It imports no JavaScript implementation. Its 105 cases cover the two exact cancellation regressions, the ordinary path-divergence case, cash-flow timing controls, the bundled sample and 100 varied source series. Tests also cover scale invariance, exact tie rounding, support failures, calendar/sample withholding, chart consistency and the retained v3 fixture. Run these commands to obtain results for the exact source you are checking. The [public validation scope and reproduction guide](release-validation.md) explains the scope and limitations; it does not contain historical per-case result files. Browser-engine interoperability is a separate release check; running JavaScriptCore or Bun alone is not Safari testing.
