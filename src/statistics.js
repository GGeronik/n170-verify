import { normalCdf } from './erfc.js';

export const STATISTICS_VERSION = 'n170.verify.statistics.v1';
const FREQUENCIES = new Set([1, 4, 12, 52, 252, 365, 366]);
const FIGURES = [
  'mean', 'sd', 'variance', 'm2', 'm3', 'm4', 'skewness', 'skewness_se',
  'excess_kurtosis', 'excess_kurtosis_se', 'rho1', 'rho1_se', 'rho1_band',
  'autocorr_significant', 'sharpe_per_interval', 'sharpe_annualized_nominal',
  'lo_eta', 'sharpe_annualized_adjusted', 'annualization_code', 'V', 'sigma_sr',
  'z', 'psr0', 'mintrl', 'mintrl_code', 'inference_code',
];
const INFERENCE_FIELDS = ['V', 'sigma_sr', 'z', 'psr0', 'mintrl', 'mintrl_code', 'inference_code'];
const LABELS = Object.freeze({ rf: 'excess over 0', inference: 'at observed moments' });

// Non-overlapping exact partials, with the final half-even correction used by
// math.fsum. The correction matters when the two largest partials tie and a
// smaller partial establishes the rounding direction.
export function fsum(values) {
  const partials = [];
  for (let x of values) {
    if (!Number.isFinite(x)) return NaN;
    let used = 0;
    for (let y of partials) {
      if (Math.abs(x) < Math.abs(y)) [x, y] = [y, x];
      const high = x + y;
      if (!Number.isFinite(high)) return NaN;
      const low = y - (high - x);
      if (low !== 0) partials[used++] = low;
      x = high;
    }
    partials.length = used;
    if (x !== 0) partials.push(x);
  }
  let remaining = partials.length;
  if (remaining === 0) return 0;
  let high = partials[--remaining];
  let low = 0;
  while (remaining > 0) {
    const x = high;
    const y = partials[--remaining];
    high = x + y;
    low = y - (high - x);
    if (low !== 0) break;
  }
  if (remaining > 0 && ((low < 0 && partials[remaining - 1] < 0)
    || (low > 0 && partials[remaining - 1] > 0))) {
    const twiceLow = low * 2;
    const rounded = high + twiceLow;
    if (rounded - high === twiceLow) high = rounded;
  }
  return high;
}

function finite(...values) {
  if (!values.every(Number.isFinite)) throw new RangeError('Non-finite statistics intermediate');
  return values[0];
}

function emptyInference() {
  return Object.freeze({ status: 'STATS_NON_FINITE', ...Object.fromEntries(INFERENCE_FIELDS.map(key => [key, null])) });
}

export function inferenceFromMoments(input) {
  try {
    const { T, sharpePerInterval: S, skewness, excessKurtosis, autocorrSignificant } = input;
    if (!Number.isSafeInteger(T) || T < 20 || typeof autocorrSignificant !== 'boolean') return emptyInference();
    finite(S, skewness, excessKurtosis);
    // Preserve the frozen binary64 parenthesization; V is never clamped.
    const halfSquare = finite(finite(0.5 * S) * S);
    const skewTerm = finite(skewness * S);
    const kurtosisTerm = finite(finite(finite(excessKurtosis / 4) * S) * S);
    const V = finite(finite(finite(1 + halfSquare) - skewTerm) + kurtosisTerm);
    if (V <= 0) return emptyInference();
    const sigma_sr = finite(Math.sqrt(finite(V / (T - 1))));
    const z = finite(S / sigma_sr);
    const psr0 = finite(normalCdf(z));
    let mintrl = null;
    if (S > 0) {
      const k = finite(1.6448536269514722 / S);
      mintrl = finite(Math.ceil(finite(1 + finite(V * finite(k * k)))));
    }
    return Object.freeze({
      status: 'OK', V, sigma_sr, z, psr0, mintrl,
      mintrl_code: S > 0 ? null : 'MINTRL_UNDEFINED_NONPOSITIVE_EXCESS',
      inference_code: autocorrSignificant ? 'STATS_INFERENCE_ASSUMES_IID' : null,
    });
  } catch {
    return emptyInference();
  }
}

export function computeStatistics(returnsE8, options) {
  let T = null, periods_per_year = null, schedule_compatible = null, rf_per_interval = null;
  const refuse = status => Object.freeze({
    version: STATISTICS_VERSION, status, T, periods_per_year, schedule_compatible, rf_per_interval,
    ...Object.fromEntries(FIGURES.map(key => [key, null])),
    labels: LABELS,
  });
  try {
    const isArray = Array.isArray(returnsE8);
    T = isArray ? returnsE8.length : null;
    const { periodsPerYear, scheduleCompatible, rfPerInterval = 0 } = options ?? {};
    if (Number.isSafeInteger(periodsPerYear)) periods_per_year = periodsPerYear;
    if (typeof scheduleCompatible === 'boolean') schedule_compatible = scheduleCompatible;
    if (Number.isFinite(rfPerInterval)) rf_per_interval = rfPerInterval;
    if (!isArray || !Number.isSafeInteger(periodsPerYear) || periodsPerYear <= 0
      || typeof scheduleCompatible !== 'boolean' || !Number.isFinite(rfPerInterval)) return refuse('STATS_NON_FINITE');
    // An indexed copy also rejects sparse arrays and insulates computation
    // from later mutations of the supplied array.
    const integers = [];
    for (let i = 0; i < T; i += 1) {
      const value = returnsE8[i];
      if (!Number.isSafeInteger(value)) return refuse('STATS_NON_FINITE');
      integers.push(value);
    }
    if (T < 20) return refuse('STATS_SAMPLE_INSUFFICIENT');
    // Q5: test signed integers before any conversion or risk-free arithmetic.
    if (integers.every(value => value === integers[0])) return refuse('STATS_ZERO_VARIANCE');
    // Early refusals echo the caller's schedule flag. A computed result uses
    // the effective schedule, including Q5's unsupported-frequency refusal.
    schedule_compatible = schedule_compatible && FREQUENCIES.has(periods_per_year);
    const returns = integers.map(value => value / 100000000);
    const mean = finite(fsum(returns) / T);
    const deviations = returns.map(value => finite(value - mean));
    const squares = deviations.map(value => finite(value * value));
    const m2 = finite(fsum(squares) / T);
    const m3 = finite(fsum(deviations.map((value, i) => finite(squares[i] * value))) / T);
    const m4 = finite(fsum(squares.map(value => finite(value * value))) / T);
    const variance = finite(finite(T * m2) / (T - 1));
    const sd = finite(Math.sqrt(variance));
    const skewness = finite(m3 / finite(m2 * finite(Math.sqrt(m2))));
    const excess_kurtosis = finite(finite(m4 / finite(m2 * m2)) - 3);
    const skewness_se = finite(Math.sqrt(6 / T));
    const excess_kurtosis_se = finite(Math.sqrt(24 / T));
    const rootT = finite(Math.sqrt(T));
    const rho1_se = finite(1 / rootT);
    const rho1_band = finite(1.96 / rootT);
    const lagProducts = [];
    for (let i = 1; i < T; i += 1) lagProducts.push(finite(deviations[i] * deviations[i - 1]));
    const rho1 = finite(fsum(lagProducts) / fsum(squares));
    const autocorr_significant = Math.abs(rho1) > rho1_band;
    const sharpe_per_interval = finite(finite(mean - rf_per_interval) / sd);
    let sharpe_annualized_nominal = null, lo_eta = null, sharpe_annualized_adjusted = null;
    if (schedule_compatible) {
      const rootQ = finite(Math.sqrt(periods_per_year));
      sharpe_annualized_nominal = finite(sharpe_per_interval * rootQ);
      lo_eta = rho1 > 0 ? finite(1 + finite(finite(2 * ((periods_per_year - 1) / periods_per_year)) * rho1)) : 1;
      sharpe_annualized_adjusted = finite(sharpe_annualized_nominal / finite(Math.sqrt(lo_eta)));
    }
    const inference = inferenceFromMoments({ T, sharpePerInterval: sharpe_per_interval, skewness,
      excessKurtosis: excess_kurtosis, autocorrSignificant: autocorr_significant });
    if (inference.status !== 'OK') return refuse('STATS_NON_FINITE');
    const inferenceFields = Object.fromEntries(INFERENCE_FIELDS.map(key => [key, inference[key]]));
    return Object.freeze({
      version: STATISTICS_VERSION, status: 'OK', T, periods_per_year, schedule_compatible, rf_per_interval,
      mean, sd, variance, m2, m3, m4, skewness, skewness_se, excess_kurtosis, excess_kurtosis_se,
      rho1, rho1_se, rho1_band, autocorr_significant, sharpe_per_interval,
      sharpe_annualized_nominal, lo_eta, sharpe_annualized_adjusted,
      annualization_code: schedule_compatible ? null : 'SCHEDULE_ANNUALIZATION_REFUSED',
      ...inferenceFields,
      labels: LABELS,
    });
  } catch {
    return refuse('STATS_NON_FINITE');
  }
}
