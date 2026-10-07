// Frozen calculation 1.0.0 semantics for performance-stamp.v3 files.
// Do not modernize operation order or rounding: old signatures bind these values.
export function calculateRelativeReturnMetrics(values, periodsPerYear) {
  if (!Array.isArray(values) || values.length < 1 || values.length > 499 || !Number.isInteger(periodsPerYear) || periodsPerYear < 1 || periodsPerYear > 366) throw new Error("The relative return series is unsupported.");
  let wealth = 1;
  let peak = 1;
  let drawdown = 0;
  for (const value of values) {
    if (typeof value !== "number" || !Number.isFinite(value) || value <= -1) throw new Error("The relative return series is unsupported.");
    wealth *= 1 + value;
    if (!Number.isFinite(wealth) || wealth <= 0) throw new Error("The input exceeds the supported numerical range.");
    peak = Math.max(peak, wealth);
    drawdown = Math.min(drawdown, wealth / peak - 1);
  }
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const volatility = values.length > 1 ? Math.sqrt(values.reduce((sum, value) => sum + (value - mean) * (value - mean), 0) / (values.length - 1)) * Math.sqrt(periodsPerYear) : null;
  if (volatility !== null && !Number.isFinite(volatility)) throw new Error("The input exceeds the supported numerical range.");
  return { total_return_twr: wealth - 1, annualized_volatility: volatility, max_drawdown: drawdown };
}

// Signed records store returns and metrics as integers in units of 10^-8 (a
// millionth of a percent). Full-precision ratios can pin down the exact amounts
// behind them; rounded integers carry far less of that detail, and integers
// serialize identically in every programming language.
export const RETURN_UNITS = 100000000;

function toUnits(value) {
  if (!Number.isFinite(value)) throw new Error("The input exceeds the supported numerical range.");
  const units = Math.round(value * RETURN_UNITS) || 0;
  if (!Number.isSafeInteger(units)) throw new Error("A relative return is outside the supported range.");
  return units;
}

export function calculateRecordMetrics(returnUnits, periodsPerYear) {
  if (!Array.isArray(returnUnits) || !returnUnits.every((units) => Number.isSafeInteger(units) && units > -RETURN_UNITS)) throw new Error("The relative return series is unsupported.");
  const metrics = calculateRelativeReturnMetrics(returnUnits.map((units) => units / RETURN_UNITS), periodsPerYear);
  return {
    total_return_twr_e8: toUnits(metrics.total_return_twr),
    annualized_volatility_e8: metrics.annualized_volatility === null ? null : toUnits(metrics.annualized_volatility),
    max_drawdown_e8: toUnits(metrics.max_drawdown),
  };
}

