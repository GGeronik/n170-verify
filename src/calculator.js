// Calculation 2.0.0. Decimal input and all signed metric rounding use BigInt.
// Legacy exports are deliberately frozen so existing v3 records keep their rules.
export { calculateRecordMetrics, calculateRelativeReturnMetrics } from "./calculatorLegacy.js";
export const CALCULATION_VERSION = "2.0.0";
export const RETURN_UNITS = 100000000;
export const sampleInput = "date,nav,external_flow\n2025-01-02,100,0\n2025-01-03,101,0\n2025-01-06,112.02,10\n2025-01-07,110.8998,0";
export const NUMERICAL_LIMITS = Object.freeze({ observations: 500, input_characters: 50000, amount_magnitude: "1000000000000000", decimal_places: 18, return_scale: RETURN_UNITS, maximum_factor: 10000, minimum_wealth: "0.000001", maximum_wealth: "1000000", maximum_interval_factor_relative_rounding_error: "0.0000001", minimum_volatility_intervals: 20 });
const U = BigInt(RETURN_UNITS);
const AMOUNT_SCALE = 10n ** 18n;
const DAY_MS = 86400000;
const MAX_FACTOR = 10000n;
const RANGE = "This series exceeds the supported wealth range (0.000001 to 1,000,000 times opening wealth). Review extreme losses or leveraged intervals separately; do not omit them to obtain a result.";
const decimal = /^-?(?:\d+(?:\.\d*)?|\.\d+)$/;
const abs = (n) => n < 0n ? -n : n;

// Round an exact rational to the nearest integer, ties toward positive infinity.
// BigInt division truncates toward zero, so negative values need floor correction.
function roundRatio(numerator, denominator) {
  let quotient = numerator / denominator;
  let remainder = numerator % denominator;
  if (remainder < 0n) { quotient -= 1n; remainder += denominator; }
  return quotient + (2n * remainder >= denominator ? 1n : 0n);
}
function safeNumber(value) {
  const result = Number(value);
  if (!Number.isSafeInteger(result)) throw new Error(RANGE);
  return result === 0 ? 0 : result;
}
function readAmount(value, row) {
  if (value.length > 50 || !decimal.test(value)) throw new Error(`Row ${row}: use plain decimal amounts without currency symbols, grouping separators or exponents.`);
  const negative = value.startsWith("-");
  const [whole, fraction = ""] = (negative ? value.slice(1) : value).split(".");
  if (fraction.length > 18) throw new Error(`Row ${row}: at most 18 decimal places are supported. Review and explicitly round the source value before importing.`);
  const amount = BigInt(whole || "0") * AMOUNT_SCALE + BigInt(fraction.padEnd(18, "0") || "0");
  if (amount > 1000000000000000n * AMOUNT_SCALE) throw new Error(`Row ${row}: amount magnitude exceeds 10^15. Review the source units and currency.`);
  return negative ? -amount : amount;
}
function validDate(value) {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value;
}
function validateFrequency(value) {
  if (!Number.isInteger(value) || value < 1 || value > 366) throw new Error("Periods per year must be an integer from 1 to 366.");
}
function readObservations(input, periodsPerYear) {
  if (typeof input !== "string" || input.length > 50000) throw new Error("Use at most 50,000 characters and 500 observations.");
  validateFrequency(periodsPerYear);
  const lines = input.trim().split(/\r?\n/);
  if (lines.shift()?.trim() !== "date,nav,external_flow") throw new Error("Use the header date,nav,external_flow and exactly three columns.");
  if (lines.length < 2 || lines.length > 500) throw new Error("Supply 2 to 500 dated observations.");
  const rows = lines.map((line, index) => {
    const cells = line.split(",").map((cell) => cell.trim());
    const [date, nav, flow] = cells;
    if (cells.length !== 3 || !validDate(date)) throw new Error(`Row ${index + 1}: use a valid ISO date and exactly three columns.`);
    const amount = readAmount(nav, index + 1);
    if (amount <= 0n) throw new Error(`Row ${index + 1}: zero or negative NAV, total loss and recapitalization are unsupported. Keep the original history and review the loss separately; do not remove the row.`);
    return { date, nav: amount, flow: readAmount(flow, index + 1) };
  });
  if (rows[0].flow !== 0n) throw new Error("The opening observation must have zero external flow; it establishes the starting NAV.");
  return rows;
}
function validateIntervals(relativeReturns, periodsPerYear) {
  validateFrequency(periodsPerYear);
  if (!Array.isArray(relativeReturns) || relativeReturns.length < 1 || relativeReturns.length > 499) throw new Error("Supply 1 to 499 contiguous relative-return intervals.");
  let previousEnd = null;
  for (const interval of relativeReturns) {
    if (!interval || !validDate(interval.start) || !validDate(interval.end) || interval.start >= interval.end || (previousEnd !== null && interval.start !== previousEnd)) throw new Error("Return intervals must have valid, contiguous ascending dates.");
    if (!Number.isSafeInteger(interval.return_e8) || interval.return_e8 <= -RETURN_UNITS || interval.return_e8 > (Number(MAX_FACTOR) - 1) * RETURN_UNITS) throw new Error("The relative return is outside the supported range. Total loss and gross factors above 10,000 are unsupported.");
    previousEnd = interval.end;
  }
}
function weekdaysBetween(start, days) {
  const startDay = new Date(start).getUTCDay();
  let count = Math.floor(days / 7) * 5;
  for (let day = 1; day <= days % 7; day += 1) {
    const weekday = (startDay + day) % 7;
    if (weekday !== 0 && weekday !== 6) count += 1;
  }
  return count;
}

// A conservative support policy, not a holiday-calendar or completeness audit.
// Reasons are reproducible from disclosed dates; no claim of missing-data discovery.
export function analyzeObservationSchedule(relativeReturns, periodsPerYear) {
  validateIntervals(relativeReturns, periodsPerYear);
  const supported = [1, 4, 12, 52, 252, 365, 366].includes(periodsPerYear);
  const gaps = [];
  let mismatch = false;
  let possibleMissingWeekdays = 0;
  for (const [index, { start, end }] of relativeReturns.entries()) {
    const days = (Date.parse(end) - Date.parse(start)) / DAY_MS;
    const startDate = new Date(start), endDate = new Date(end);
    const months = (endDate.getUTCFullYear() - startDate.getUTCFullYear()) * 12 + endDate.getUTCMonth() - startDate.getUTCMonth();
    let compatible = false;
    if (periodsPerYear === 252) {
      const weekdays = weekdaysBetween(start, days);
      possibleMissingWeekdays += Math.max(0, weekdays - 1);
      compatible = days <= 5 && ![0, 6].includes(startDate.getUTCDay()) && ![0, 6].includes(endDate.getUTCDay());
      if (weekdays > 1) gaps.push({ interval: index + 1, days, possible_missing_weekdays: weekdays - 1 });
    } else if (periodsPerYear === 365 || periodsPerYear === 366) compatible = days === 1;
    else if (periodsPerYear === 52) compatible = days >= 5 && days <= 9;
    else if (periodsPerYear === 12) compatible = months === 1 && days >= 26 && days <= 35;
    else if (periodsPerYear === 4) compatible = months === 3 && days >= 80 && days <= 100;
    else if (periodsPerYear === 1) compatible = months === 12 && days >= 360 && days <= 370;
    if (supported && !compatible) { mismatch = true; gaps.push({ interval: index + 1, days }); }
  }
  // Allows occasional exchange holidays without treating long gaps as daily returns.
  if (periodsPerYear === 252 && possibleMissingWeekdays > Math.max(2, Math.floor(relativeReturns.length * 0.06))) mismatch = true;
  let status = "eligible", reason = "Sample volatility annualized using the selected frequency. This is descriptive, not a forecast or evidence of investment skill.";
  if (!supported) { status = "unsupported_frequency"; reason = "Annualized volatility is withheld for this frequency. Select daily (252, 365 or 366), weekly (52), monthly (12), quarterly (4) or yearly (1) observations with matching dates."; }
  else if (mismatch) { status = "incompatible_spacing"; reason = "Annualized volatility is withheld because the observation dates do not support the selected frequency. Supply the missing valuations or select the actual observation frequency; do not fill gaps with invented values."; }
  else if (relativeReturns.length < 20) { status = "insufficient_observations"; reason = `Annualized volatility is withheld: ${relativeReturns.length} return interval${relativeReturns.length === 1 ? "" : "s"} supplied; at least 20 are required by this product's conservative policy. Add actual observations. This threshold is not a reliability guarantee.`; }
  return { eligible: status === "eligible", status, reason, interval_count: relativeReturns.length, frequency: periodsPerYear, coverage_note: "Dates are screened for spacing. No exchange holiday calendar, account universe or external source was checked; missing observations may remain undiscovered.", gaps };
}
function integerSqrt(value) {
  if (value < 2n) return value;
  let estimate = 1n << BigInt(Math.ceil(value.toString(2).length / 2));
  for (;;) {
    const next = (estimate + value / estimate) / 2n;
    if (next >= estimate) return estimate;
    estimate = next;
  }
}
function roundedSqrtRatio(numerator, denominator) {
  const root = integerSqrt(numerator / denominator);
  return root + (4n * numerator >= denominator * (2n * root + 1n) ** 2n ? 1n : 0n);
}
function rationalMetrics(relativeReturns, periodsPerYear, makeSeries = false) {
  const annualization = analyzeObservationSchedule(relativeReturns, periodsPerYear);
  let numerator = 1n, denominator = 1n, peakNumerator = 1n, peakDenominator = 1n;
  let drawdownNumerator = 0n, drawdownDenominator = 1n;
  let sum = 0n, sumSquares = 0n;
  const series = [];
  for (const { end, return_e8 } of relativeReturns) {
    const value = BigInt(return_e8);
    numerator *= U + value; denominator *= U;
    if (numerator * 1000000n < denominator || numerator > denominator * 1000000n) throw new Error(RANGE);
    if (numerator * peakDenominator > peakNumerator * denominator) { peakNumerator = numerator; peakDenominator = denominator; }
    const ddDenominator = denominator * peakNumerator;
    const ddNumerator = numerator * peakDenominator - ddDenominator;
    if (ddNumerator * drawdownDenominator < drawdownNumerator * ddDenominator) { drawdownNumerator = ddNumerator; drawdownDenominator = ddDenominator; }
    sum += value; sumSquares += value * value;
    if (makeSeries) series.push({ date: end, wealth_e8: safeNumber(roundRatio(numerator * U, denominator)), drawdown_e8: safeNumber(roundRatio(ddNumerator * U, ddDenominator)) });
  }
  const n = BigInt(relativeReturns.length);
  const drawdown = safeNumber(roundRatio(drawdownNumerator * U, drawdownDenominator));
  if (drawdown <= -RETURN_UNITS) throw new Error("The sampled drawdown rounds to total loss at the supported precision. Review the extreme loss separately; do not remove it.");
  return { metrics: {
    total_return_twr_e8: safeNumber(roundRatio((numerator - denominator) * U, denominator)),
    annualized_volatility_e8: annualization.eligible ? safeNumber(roundedSqrtRatio((n * sumSquares - sum * sum) * BigInt(periodsPerYear), n * (n - 1n))) : null,
    max_drawdown_e8: drawdown,
  }, annualization, series };
}
export function calculateRecordMetricsV2(relativeReturns, periodsPerYear) {
  return rationalMetrics(relativeReturns, periodsPerYear).metrics;
}
export function calculateRecordSeriesV2(relativeReturns, periodsPerYear) {
  const { series } = rationalMetrics(relativeReturns, periodsPerYear, true);
  return [{ date: relativeReturns[0].start, wealth_e8: RETURN_UNITS, drawdown_e8: 0 }, ...series];
}
export function buildStampObservationEvidence(input, periodsPerYear = 252) {
  const rows = readObservations(input, periodsPerYear);
  const relativeReturns = [];
  for (let i = 1; i < rows.length; i += 1) {
    const previous = rows[i - 1], current = rows[i];
    if (current.date <= previous.date) throw new Error("Dates must be unique and in ascending order.");
    const adjusted = current.nav - current.flow;
    if (adjusted <= 0n) throw new Error(`Row ${i + 1}: cash-flow-adjusted wealth is zero or negative. Total loss and recapitalization are unsupported; keep this observation and obtain a separate accounting review.`);
    const units = roundRatio((adjusted - previous.nav) * U, previous.nav);
    if (units <= -U) throw new Error(`Row ${i + 1}: the interval rounds to total loss. This loss cannot be represented at the supported precision; do not omit it.`);
    const factorError = abs((U + units) * previous.nav - adjusted * U);
    if (factorError * 10000000n > adjusted * U) throw new Error(`Row ${i + 1}: rounding this extreme interval would exceed the supported precision (0.00001% of its gross factor). Review it separately; changing currency units will not fix this limitation.`);
    relativeReturns.push({ start: previous.date, end: current.date, return_e8: safeNumber(units) });
  }
  const { metrics, annualization } = rationalMetrics(relativeReturns, periodsPerYear);
  return { calculation_version: CALCULATION_VERSION, source_kind: input === sampleInput ? "synthetic_demo" : "self_reported", period: { start: rows[0].date, end: rows.at(-1).date }, periods_per_year: periodsPerYear, relative_returns: relativeReturns, coverage: { nav_observations: rows.length, return_observations: relativeReturns.length, external_cash_flow_count: rows.filter((row) => row.flow !== 0n).length }, metrics, annualization };
}
export function calculateEvidence(input, periodsPerYear = 252) {
  const evidence = buildStampObservationEvidence(input, periodsPerYear);
  return {
    schema_version: "n170.verify.browser.v2", calculation_version: CALCULATION_VERSION,
    source_kind: evidence.source_kind === "synthetic_demo" ? "synthetic_demo" : "user_entered", provider_authenticated: false,
    quality_status: evidence.annualization.eligible ? "calculable_under_assumptions" : "partial_metrics",
    coverage: evidence.coverage,
    metrics: { total_return_twr: evidence.metrics.total_return_twr_e8 / RETURN_UNITS, annualized_volatility: evidence.metrics.annualized_volatility_e8 === null ? null : evidence.metrics.annualized_volatility_e8 / RETURN_UNITS, max_drawdown: evidence.metrics.max_drawdown_e8 / RETURN_UNITS },
    annualization: evidence.annualization,
    methodology: {
      subperiod_return: "Exact decimal (NAV[i] - external_flow[i]) / NAV[i-1] - 1, rounded to integer units of 10^-8; ties toward positive infinity",
      total_return: "Exact rational product of disclosed (1 + return_e8 / 10^8) minus 1; result rounded once to 10^-8",
      volatility: "Sample standard deviation of disclosed interval returns * sqrt(periods_per_year); exact integer square-root rounding; withheld unless frequency and sample policy pass",
      drawdown: "Minimum disclosed wealth / running peak - 1, including opening wealth 1; sampled observations only",
      cash_flow_timing: "end_of_each_observation_interval", periods_per_year: periodsPerYear, currency: "one consistent currency supplied by the user; no conversion",
    },
    numerical_support: NUMERICAL_LIMITS,
    privacy: { raw_values_included: false, dates_included: false, source_digest_included: false, source_uploaded: false },
    warnings: [
      "Inputs, account coverage and cash-flow completeness are unverified. This is supplied-data evidence, not broker authentication.",
      "All external flows must occur at interval end; contributions are positive and withdrawals negative. Intraperiod flows require additional valuations. Internal trades and retained dividends are not external flows.",
      evidence.annualization.reason,
      "Return units are rounded to 10^-8 before all displayed and signed metrics. Drawdown is sampled; losses between observations remain unknown. Fees and taxes count only if present in the source values.",
      "This aggregate summary omits dates, return observations and amounts; it cannot reproduce itself. Share a review package for reproducible relative-return evidence. Keep the source privately to check the amount-to-return transformation.",
    ],
  };
}
