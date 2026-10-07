import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { analyzeObservationSchedule, buildStampObservationEvidence, calculateEvidence, calculateRecordMetrics, calculateRecordMetricsV2, calculateRecordSeriesV2, RETURN_UNITS, sampleInput } from "../src/calculator.js";

const csv = (...rows) => `date,nav,external_flow\n${rows.join("\n")}`;
const date = (day) => new Date(Date.UTC(2025, 0, day)).toISOString().slice(0, 10);
const daily = (values) => values.map((return_e8, i) => ({ start: date(i + 1), end: date(i + 2), return_e8 }));
const units = (metrics) => ({ total_return_twr: metrics.total_return_twr_e8 / RETURN_UNITS, annualized_volatility: metrics.annualized_volatility_e8 === null ? null : metrics.annualized_volatility_e8 / RETURN_UNITS, max_drawdown: metrics.max_drawdown_e8 / RETURN_UNITS });

test("sample uses the exact disclosed series and withholds annualization for sparse observations", () => {
  const report = calculateEvidence(sampleInput);
  assert.deepEqual(report.metrics, { total_return_twr: 0.009998, annualized_volatility: null, max_drawdown: -0.01 });
  assert.equal(report.annualization.status, "insufficient_observations");
  assert.equal(report.coverage.return_observations, 3);
  assert.equal(report.calculation_version, "2.0.0");
});

test("audited decimal cancellation defects return zero in both display and signing paths", () => {
  for (const input of [
    csv("2025-01-01,0.1,0", "2025-01-02,999999999999999.9,999999999999999.8"),
    csv("2025-01-01,0.01,0", "2025-01-02,100000000000000.01,100000000000000"),
  ]) {
    const shown = calculateEvidence(input), signed = buildStampObservationEvidence(input);
    assert.deepEqual(shown.metrics, { total_return_twr: 0, annualized_volatility: null, max_drawdown: 0 });
    assert.deepEqual(shown.metrics, units(signed.metrics));
    assert.equal(signed.relative_returns[0].return_e8, 0);
  }
});

test("pure deposits and withdrawals do not create performance", () => {
  const report = calculateEvidence(csv("2025-01-01,100,0", "2025-01-02,150,50", "2025-01-03,80,-70"));
  assert.deepEqual(report.metrics, { total_return_twr: 0, annualized_volatility: null, max_drawdown: 0 });
});

test("drawdown includes opening wealth and is based on the running peak", () => {
  assert.deepEqual(calculateEvidence(csv("2025-01-01,100,0", "2025-01-02,90,0")).metrics, { total_return_twr: -0.1, annualized_volatility: null, max_drawdown: -0.1 });
  const report = calculateEvidence(csv("2025-01-01,100,0", "2025-01-02,120,0", "2025-01-03,90,0", "2025-01-04,130,0"));
  // Quantized relative returns, rather than hidden full-precision ratios, are normative.
  assert.equal(report.metrics.total_return_twr, 0.3);
  assert.equal(report.metrics.max_drawdown, -0.25);
});

test("ordinary audited path divergence now has one exact canonical result", () => {
  const input = csv("2025-01-01,100,0", "2025-01-02,10,0", "2025-01-03,100,0");
  assert.deepEqual(calculateEvidence(input).metrics, units(buildStampObservationEvidence(input).metrics));
  assert.equal(calculateEvidence(input).metrics.total_return_twr, 0);
});

test("display, record, independently recomputed series and final chart point agree", () => {
  const record = buildStampObservationEvidence(sampleInput);
  assert.deepEqual(record.metrics, calculateRecordMetricsV2(record.relative_returns, 252));
  assert.deepEqual(calculateEvidence(sampleInput).metrics, units(record.metrics));
  const series = calculateRecordSeriesV2(record.relative_returns, 252);
  assert.equal(series.length, record.relative_returns.length + 1);
  assert.deepEqual(series[0], { date: "2025-01-02", wealth_e8: RETURN_UNITS, drawdown_e8: 0 });
  assert.equal(series.at(-1).wealth_e8 - RETURN_UNITS, record.metrics.total_return_twr_e8);
  assert.equal(Math.min(...series.map((point) => point.drawdown_e8)), record.metrics.max_drawdown_e8);
});

test("decimal tie rounding is exact and ties go toward positive infinity", () => {
  const positive = buildStampObservationEvidence(csv("2025-01-01,100,0", "2025-01-02,100.0000005,0"));
  const negative = buildStampObservationEvidence(csv("2025-01-01,100,0", "2025-01-02,99.9999995,0"));
  assert.equal(positive.relative_returns[0].return_e8, 1);
  assert.equal(negative.relative_returns[0].return_e8, 0);
  assert.equal(Object.is(negative.metrics.total_return_twr_e8, -0), false);
});

test("scale and external-flow invariants hold without cancellation", () => {
  const a = csv("2025-01-01,100,0", "2025-01-02,160,50", "2025-01-03,144,0");
  const b = csv("2025-01-01,1000000000000,0", "2025-01-02,1600000000000,500000000000", "2025-01-03,1440000000000,0");
  const c = csv("2025-01-01,0.0001,0", "2025-01-02,0.00016,0.00005", "2025-01-03,0.000144,0");
  assert.deepEqual(calculateEvidence(a).metrics, calculateEvidence(b).metrics);
  assert.deepEqual(calculateEvidence(a).metrics, calculateEvidence(c).metrics);
});

test("twenty compatible intervals support volatility and use independent expected units", () => {
  const intervals = daily(Array.from({ length: 20 }, (_, i) => i % 2 ? -1000000 : 1000000));
  assert.equal(analyzeObservationSchedule(intervals, 365).status, "eligible");
  assert.deepEqual(calculateRecordMetricsV2(intervals, 365), { total_return_twr_e8: -99955, annualized_volatility_e8: 19601289, max_drawdown_e8: -1089064 });
});

test("mixed-duration audit case withholds annualization and explains the next action", () => {
  const report = calculateEvidence(csv("2025-01-01,100,0", "2025-01-02,110,0", "2026-01-02,99,0"));
  assert.equal(report.metrics.annualized_volatility, null);
  assert.equal(report.annualization.status, "incompatible_spacing");
  assert.match(report.annualization.reason, /missing valuations/);
  assert.equal(report.annualization.gaps.at(-1).days, 365);
});

test("trading-day schedule allows weekends and a holiday without claiming completeness", () => {
  const dates = Array.from({ length: 40 }, (_, i) => date(i + 1)).filter((value) => ![0, 6].includes(new Date(value).getUTCDay())).filter((value) => value !== "2025-01-20");
  const intervals = dates.slice(1).map((end, i) => ({ start: dates[i], end, return_e8: 0 }));
  const schedule = analyzeObservationSchedule(intervals, 252);
  assert.equal(schedule.eligible, true);
  assert.ok(schedule.gaps.some(({ possible_missing_weekdays }) => possible_missing_weekdays === 1));
  assert.match(schedule.coverage_note, /No exchange holiday calendar/);
  assert.equal(calculateRecordMetricsV2(intervals, 252).annualized_volatility_e8, 0);
});

test("frequency mismatch, unsupported frequency and sparse data are distinct states", () => {
  assert.equal(analyzeObservationSchedule(daily(Array(20).fill(0)), 12).status, "incompatible_spacing");
  assert.equal(analyzeObservationSchedule(daily(Array(20).fill(0)), 250).status, "unsupported_frequency");
  assert.equal(analyzeObservationSchedule(daily(Array(19).fill(0)), 365).status, "insufficient_observations");
  const monthly = Array.from({ length: 20 }, (_, i) => ({ start: new Date(Date.UTC(2023, i, 1)).toISOString().slice(0, 10), end: new Date(Date.UTC(2023, i + 1, 1)).toISOString().slice(0, 10), return_e8: 1000000 }));
  assert.equal(analyzeObservationSchedule(monthly, 12).eligible, true);
  assert.equal(calculateRecordMetricsV2(monthly, 12).annualized_volatility_e8, 0);
});

test("all supported calendar frequencies pass only matching intervals", () => {
  for (const [frequency, monthStep] of [[12, 1], [4, 3], [1, 12]]) {
    const intervals = Array.from({ length: 20 }, (_, i) => ({ start: new Date(Date.UTC(2000, i * monthStep, 1)).toISOString().slice(0, 10), end: new Date(Date.UTC(2000, (i + 1) * monthStep, 1)).toISOString().slice(0, 10), return_e8: 0 }));
    assert.equal(analyzeObservationSchedule(intervals, frequency).eligible, true);
    assert.equal(calculateRecordMetricsV2(intervals, frequency).annualized_volatility_e8, 0);
  }
  const weekly = Array.from({ length: 20 }, (_, i) => ({ start: date(i * 7 + 1), end: date((i + 1) * 7 + 1), return_e8: 0 }));
  assert.equal(analyzeObservationSchedule(weekly, 52).eligible, true);
  assert.equal(analyzeObservationSchedule(daily(Array(20).fill(0)), 366).eligible, true);
  const monthlyGap = weekly.map((interval) => ({ ...interval }));
  monthlyGap.at(-1).end = date(200);
  assert.equal(analyzeObservationSchedule(monthlyGap, 52).status, "incompatible_spacing");
});

test("invalid dates, inputs, ambiguous flows and unsupported equity fail in both paths", () => {
  for (const rows of [
    ["2025-01-01,100,0"], ["2025-02-30,100,0", "2025-03-01,101,0"],
    ["2025-01-01,100,0", "2025-01-01,101,0"], ["2025-01-02,100,0", "2025-01-01,101,0"],
    ["2025-01-01,100,1", "2025-01-02,101,0"], ["2025-01-01,0,0", "2025-01-02,101,0"],
    ["2025-01-01,100,0", "2025-01-02,10,10"], ["2025-01-01,100,0", "2025-01-02,Infinity,0"],
    ["2025-01-01,100,0", "2025-01-02,1e3,0"], ["2025-01-01,100,0", "2025-01-02,,0"],
    ["2025-01-01,100,0", "2025-01-02,101,0,account"], ["2025-01-01,100,0", "2025-01-02,0,0"],
    ["2025-01-01,100,0", "2025-01-02,-1,0"], ["2025-01-01,100,0", "2025-01-02,0.0000000000000001,0"],
    ["2025-01-01,100,0", "2025-01-02,0.0001000049,0"],
    ["2025-01-01,1,0", "2025-01-02,10001,0"],
    ["2025-01-01,100,0", "2025-01-02,1000000000000000.01,0"],
    ["2025-01-01,100,0", "2025-01-02,0.0000000000000000001,0"],
  ]) for (const calculate of [calculateEvidence, buildStampObservationEvidence]) assert.throws(() => calculate(csv(...rows)));
  for (const frequency of [0, 252.5, Infinity]) assert.throws(() => calculateEvidence(sampleInput, frequency));
  assert.throws(() => calculateEvidence("x".repeat(50001)));
});

test("numerical support limits reject unsafe cumulative wealth and rounded total drawdown", () => {
  assert.throws(() => calculateRecordMetricsV2(daily([9999 * RETURN_UNITS, 9999 * RETURN_UNITS]), 365), /wealth range/);
  assert.throws(() => calculateRecordMetricsV2(daily([-99999900, -1]), 365), /wealth range/);
  assert.throws(() => calculateRecordMetricsV2(daily([9999 * RETURN_UNITS, 99 * RETURN_UNITS, -99999900, -99999900]), 365), /drawdown rounds to total loss/);
});

test("aggregate omits raw dates and amounts and plainly says it cannot reproduce itself", () => {
  const report = calculateEvidence(csv("2025-03-11,12345.67,0", "2025-03-12,12400,13.37"));
  const json = JSON.stringify(report);
  for (const raw of ["2025-03-11", "2025-03-12", "12345.67", "12400", "13.37"]) assert.equal(json.includes(raw), false);
  assert.equal(report.provider_authenticated, false);
  assert.equal(report.source_kind, "user_entered");
  assert.equal(report.methodology.cash_flow_timing, "end_of_each_observation_interval");
  assert.match(report.warnings.at(-1), /cannot reproduce itself/);
});

test("v3 fixture remains reproducible under frozen legacy calculation semantics", () => {
  const profile = JSON.parse(readFileSync(new URL("../examples/example-profile.json", import.meta.url), "utf8"));
  for (const { payload } of profile.stamps) assert.deepEqual(calculateRecordMetrics(payload.relative_returns.map(({ return_e8 }) => return_e8), payload.periods_per_year), payload.metrics);
  assert.equal(profile.stamps[0].payload.metrics.annualized_volatility_e8, 18375843);
});

test("independent Python Decimal controls agree with source conversion and rounded metrics", () => {
  const run = spawnSync("python3", [new URL("../scripts/numerical-controls.py", import.meta.url).pathname], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  const control = JSON.parse(run.stdout);
  assert.equal(control.cases.length, 105);
  for (const item of control.cases) {
    const evidence = buildStampObservationEvidence(item.input, item.periods_per_year);
    assert.deepEqual(evidence.relative_returns.map(({ return_e8 }) => return_e8), item.return_units, item.name);
    assert.deepEqual(evidence.metrics, item.expected_metrics, item.name);
    assert.deepEqual(calculateEvidence(item.input, item.periods_per_year).metrics, units(evidence.metrics), item.name);
  }
});
