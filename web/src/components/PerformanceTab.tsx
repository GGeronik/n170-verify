"use client";

import { useMemo, useState } from "react";
import { SessionExpectancyMatrix } from "@/components/SessionExpectancyMatrix.tsx";
import {
  CAPITAL_BRACKET_LABELS,
  type BootstrapRiskSummary,
  type DailyCalendarCell,
  type ExtractedBundleLeaves,
  type IndexedCurvePoint,
  type VerifyProofBundle,
} from "@/lib/contracts.ts";
import {
  fmtNum,
  fmtPct,
  groupCalendarCellsByMonth,
  resolveBootstrapSummary,
  resolveDailyCalendarCells,
  resolveSessionExpectancyCells,
  type MonthCalendarGroup,
} from "@/lib/wave4Analytics.ts";

const WEEKDAY_HEADERS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] as const;

export function PerformanceTab({
  bundle,
  leaves,
}: {
  bundle: VerifyProofBundle;
  leaves: ExtractedBundleLeaves;
}) {
  const perf = leaves.coreMetrics;
  const curve = leaves.indexedCurve;
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const [glmMode, setGlmMode] = useState<"glm" | "raw" | "compare">("compare");
  const [selectedMonthIdx, setSelectedMonthIdx] = useState<number | null>(null);
  const [hoveredDay, setHoveredDay] = useState<DailyCalendarCell | null>(null);
  const [hoverConeIdx, setHoverConeIdx] = useState<number | null>(null);

  const dailyCells = useMemo(
    () => resolveDailyCalendarCells(bundle, leaves),
    [bundle, leaves],
  );
  const monthGroups = useMemo(
    () => groupCalendarCellsByMonth(dailyCells),
    [dailyCells],
  );
  const bootstrapSummary = useMemo(
    () => resolveBootstrapSummary(bundle, leaves, dailyCells),
    [bundle, leaves, dailyCells],
  );
  const sessionCells = useMemo(
    () => resolveSessionExpectancyCells(bundle, leaves),
    [bundle, leaves],
  );

  if (!perf) {
    return (
      <div className="inst-panel rounded-md p-6 text-sm text-ink-muted">
        Core performance metrics leaf is not disclosed in this bundle.
      </div>
    );
  }

  const activeIdx = hoverIdx != null ? hoverIdx : Math.max(curve.length - 1, 0);
  const activePoint: IndexedCurvePoint | null = curve[activeIdx] ?? null;
  const prevPoint: IndexedCurvePoint | null =
    activeIdx > 0 ? (curve[activeIdx - 1] ?? null) : null;
  const intervalPct =
    activePoint && prevPoint && prevPoint.index_value > 0
      ? ((activePoint.index_value - prevPoint.index_value) / prevPoint.index_value) * 100
      : 0;

  const activeMonth: MonthCalendarGroup | null =
    monthGroups.length > 0
      ? (monthGroups[
          selectedMonthIdx != null && selectedMonthIdx < monthGroups.length
            ? selectedMonthIdx
            : monthGroups.length - 1
        ] ?? null)
      : null;

  const undisclosed = bundle.undisclosed_leaf_hashes ?? {};
  const benchSymbol =
    perf.benchmark_symbol ?? leaves.benchmarkAlpha?.benchmark_symbol ?? "BENCH";

  const rawVolPct = (perf.annualized_volatility ?? 0) * 100;
  const glmVolPct = (perf.unsmoothed_volatility ?? perf.annualized_volatility ?? 0) * 100;
  const maxVolScale = Math.max(rawVolPct, glmVolPct, 1);

  const rawSr = perf.sharpe_ratio ?? 0;
  const glmSr = perf.unsmoothed_sharpe_ratio ?? rawSr;
  const maxSrScale = Math.max(Math.abs(rawSr), Math.abs(glmSr), 1);

  return (
    <div className="space-y-6">
      {/* Sample-Size Gate Warning when T < 30 */}
      {!perf.psr_sample_eligible && (
        <div className="rounded border border-signal-ochre-border bg-signal-ochre-bg p-4 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2 font-mono font-semibold text-signal-ochre">
            <span>
              PSR &amp; PSR_GLM Sample-Horizon Gate Active (T = {perf.observation_count}{" "}
              &lt; 30 Required Observations)
            </span>
            <span className="badge-ochre rounded px-2 py-0.5 text-[10px]">
              GATED (BAILEY &amp; LÓPEZ DE PRADO 2012)
            </span>
          </div>
          <p className="mt-1.5 text-ink-secondary">
            Probabilistic Sharpe Ratio depends on higher return moments (skewness and
            excess kurtosis) whose estimator variance diverges below 30 observations.
            Small-sample PSR figures are suppressed until{" "}
            <code className="text-ink">observation_count &gt;= 30</code>.
          </p>
        </div>
      )}

      {/* 6-Column Primary Econometric Telemetry Strip */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6 print-avoid-break">
        <MetricCard
          label="Cumulative TWR"
          value={fmtPct(perf.twr_decimal)}
          sub={`Index 100.00 → ${(100 * (1 + perf.twr_decimal)).toFixed(2)}`}
          accent="emerald"
        />
        <MetricCard
          label="CAGR / XIRR"
          value={fmtPct(perf.cagr_decimal, 1)}
          sub={`ACT/365 XIRR ${fmtPct(perf.xirr_decimal, 1)}`}
        />
        <MetricCard
          label="Max Drawdown"
          value={
            perf.max_drawdown_pct != null
              ? `${perf.max_drawdown_pct.toFixed(2)}%`
              : fmtPct(perf.max_drawdown_decimal)
          }
          sub="Peak-to-trough TWR"
          accent="vermilion"
        />
        <MetricCard
          label="GLM Unsmoothed Vol"
          value={
            perf.unsmoothed_volatility != null
              ? `${(perf.unsmoothed_volatility * 100).toFixed(1)}%`
              : perf.annualized_volatility != null
                ? `${(perf.annualized_volatility * 100).toFixed(1)}%`
                : "-"
          }
          sub={`Raw ${
            perf.annualized_volatility != null
              ? `${(perf.annualized_volatility * 100).toFixed(1)}%`
              : "-"
          } • ξ̂=${fmtNum(perf.smoothing_index_xi)}`}
        />
        <MetricCard
          label="GLM Sharpe / Sortino"
          value={fmtNum(perf.unsmoothed_sharpe_ratio ?? perf.sharpe_ratio)}
          sub={`Raw SR ${fmtNum(perf.sharpe_ratio)} • Sortino ${fmtNum(perf.sortino_ratio)}`}
          accent="champagne"
        />
        <MetricCard
          label="PSR (GLM Unsmoothed)"
          value={
            perf.psr_sample_eligible && perf.psr_glm_unsmoothed != null
              ? `${(perf.psr_glm_unsmoothed * 100).toFixed(1)}%`
              : "GATED (T<30)"
          }
          sub={
            perf.psr_sample_eligible && perf.probabilistic_sharpe_ratio != null
              ? `Raw ${(perf.probabilistic_sharpe_ratio * 100).toFixed(1)}% • MinTRL ${fmtNum(
                  perf.min_track_record_length_periods,
                  1,
                )}p`
              : `T=${perf.observation_count}/30 • MinTRL ${fmtNum(
                  perf.min_track_record_length_periods,
                  1,
                )}p`
          }
          accent={perf.psr_sample_eligible ? "emerald" : "ochre"}
        />
      </div>

      {/* Synchronized Indexed-100 Wealth + Underwater Drawdown Chart */}
      {curve.length >= 2 && (
        <div className="inst-panel rounded-md p-5 print-avoid-break">
          <div className="flex flex-col justify-between gap-3 border-b border-hairline pb-4 lg:flex-row lg:items-center">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-[10px] font-semibold uppercase tracking-widest text-signal-champagne">
                  Synchronized Telemetry Curve
                </span>
                <span className="rounded border border-hairline-strong bg-elevated px-2 py-0.5 font-mono text-[10px] text-ink-secondary">
                  Base = 100.00 • Zero Dollar-NAV Leakage
                </span>
              </div>
              <h3 className="editorial-serif mt-1 text-xl text-ink sm:text-2xl">
                Flow-Adjusted Indexed-100 Wealth &amp; Underwater Drawdown
              </h3>
            </div>

            {/* Live Tabular-Mono Readout Bar */}
            {activePoint && (
              <div className="flex flex-wrap items-center gap-3 rounded border border-hairline-strong bg-elevated px-3 py-2 font-mono text-xs tabular-nums">
                <span className="text-ink-muted">
                  {activePoint.timestamp_utc.slice(0, 10)}
                </span>
                <span className="font-semibold text-signal-emerald">
                  Index {activePoint.index_value.toFixed(2)}
                </span>
                <span
                  className={
                    intervalPct >= 0 ? "text-signal-emerald" : "text-signal-vermilion"
                  }
                >
                  ({intervalPct >= 0 ? "+" : ""}
                  {intervalPct.toFixed(2)}%)
                </span>
                {activePoint.benchmark_index_value != null && (
                  <span className="text-ink-secondary">
                    {benchSymbol} {activePoint.benchmark_index_value.toFixed(2)}
                  </span>
                )}
                <span className="font-semibold text-signal-vermilion">
                  DD {activePoint.drawdown_pct.toFixed(2)}%
                </span>
              </div>
            )}
          </div>

          <SynchronizedWealthDrawdownSvg
            points={curve}
            benchSymbol={benchSymbol}
            hoverIdx={hoverIdx}
            onHover={setHoverIdx}
          />
        </div>
      )}

      {/* 1,000-Path Stationary Block-Bootstrap & Risk-of-Ruin Fan Chart */}
      <BootstrapFanChartPanel
        summary={bootstrapSummary}
        hoverConeIdx={hoverConeIdx}
        onHoverCone={setHoverConeIdx}
      />

      {/* GLM Unsmoothed Volatility Comparison + Privacy-Safe Monthly % of NAV Calendar Heatmap */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12 print-avoid-break">
        {/* Left: Interactive GLM Unsmoothing Comparison */}
        <div className="inst-panel flex flex-col justify-between space-y-4 rounded-md p-5 lg:col-span-5">
          <div className="space-y-4">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div>
                <p className="font-mono text-[10px] font-semibold uppercase tracking-widest text-signal-champagne">
                  Getmansky-Lo-Makarov (2004)
                </p>
                <h3 className="mt-0.5 text-sm font-semibold tracking-telemetry text-ink">
                  Autocorrelation-Adjusted Volatility &amp; Sharpe
                </h3>
              </div>

              <div className="no-print inline-flex rounded border border-hairline-strong bg-elevated p-0.5 font-mono text-[10px]">
                {(["compare", "glm", "raw"] as const).map((m) => (
                  <button
                    key={m}
                    type="button"
                    onClick={() => setGlmMode(m)}
                    className={`rounded-sm px-2 py-1 uppercase transition ${
                      glmMode === m
                        ? "bg-panel text-ink shadow-[inset_0_0_0_1px_var(--border-strong)]"
                        : "text-ink-muted hover:text-ink"
                    }`}
                  >
                    {m === "compare" ? "Dual" : m}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-3 font-mono text-xs tabular-nums">
              {/* Volatility Bar Comparison */}
              <div className="space-y-2 rounded border border-hairline bg-elevated p-3">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-ink-secondary">Annualized Volatility (σ)</span>
                  <span className="text-ink">
                    Raw {rawVolPct.toFixed(2)}% →{" "}
                    <strong className="text-signal-champagne">
                      GLM {glmVolPct.toFixed(2)}%
                    </strong>
                  </span>
                </div>
                {(glmMode === "compare" || glmMode === "raw") && (
                  <div className="space-y-1">
                    <div className="flex justify-between text-[10px] text-ink-muted">
                      <span>Reported Raw σ</span>
                      <span>{rawVolPct.toFixed(2)}%</span>
                    </div>
                    <div className="h-2 w-full overflow-hidden rounded-sm bg-subtle">
                      <div
                        className="h-full bg-ink-muted transition-all duration-500 ease-out"
                        style={{ width: `${Math.min((rawVolPct / maxVolScale) * 100, 100)}%` }}
                      />
                    </div>
                  </div>
                )}
                {(glmMode === "compare" || glmMode === "glm") && (
                  <div className="space-y-1">
                    <div className="flex justify-between text-[10px] text-signal-champagne">
                      <span>GLM Unsmoothed σ_GLM</span>
                      <span>{glmVolPct.toFixed(2)}%</span>
                    </div>
                    <div className="h-2 w-full overflow-hidden rounded-sm bg-subtle">
                      <div
                        className="h-full bg-signal-champagne transition-all duration-500 ease-out"
                        style={{ width: `${Math.min((glmVolPct / maxVolScale) * 100, 100)}%` }}
                      />
                    </div>
                  </div>
                )}
              </div>

              {/* Sharpe Bar Comparison */}
              <div className="space-y-2 rounded border border-hairline bg-elevated p-3">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-ink-secondary">Annualized Sharpe Ratio</span>
                  <span className="text-ink">
                    Raw {fmtNum(perf.sharpe_ratio)} →{" "}
                    <strong className="text-signal-emerald">
                      GLM {fmtNum(perf.unsmoothed_sharpe_ratio)}
                    </strong>
                  </span>
                </div>
                {(glmMode === "compare" || glmMode === "raw") && (
                  <div className="h-2 w-full overflow-hidden rounded-sm bg-subtle">
                    <div
                      className="h-full bg-ink-muted transition-all duration-500 ease-out"
                      style={{
                        width: `${Math.min((Math.max(rawSr, 0) / maxSrScale) * 100, 100)}%`,
                      }}
                    />
                  </div>
                )}
                {(glmMode === "compare" || glmMode === "glm") && (
                  <div className="h-2 w-full overflow-hidden rounded-sm bg-subtle">
                    <div
                      className="h-full bg-signal-emerald transition-all duration-500 ease-out"
                      style={{
                        width: `${Math.min((Math.max(glmSr, 0) / maxSrScale) * 100, 100)}%`,
                      }}
                    />
                  </div>
                )}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <MiniStat
                label="Smoothing ξ̂"
                value={fmtNum(perf.smoothing_index_xi)}
                note={(perf.smoothing_index_xi ?? 1) < 0.8 ? "Illiquid adj" : "Clean"}
              />
              <MiniStat
                label="Lag-1 ρ̂₁"
                value={fmtNum(perf.lag1_autocorrelation)}
                note="AR(1)"
              />
              <MiniStat
                label="Skewness"
                value={fmtNum(perf.skewness)}
                note="3rd mom."
              />
              <MiniStat
                label="Ex. Kurtosis"
                value={fmtNum(perf.excess_kurtosis)}
                note="4th mom."
              />
            </div>
          </div>

          <p className="rounded border border-hairline bg-elevated p-3 text-[11px] leading-relaxed text-ink-secondary">
            <strong className="text-ink">Econometric Governance:</strong>{" "}
            {perf.non_iid_caveat} Survivorship and backfill selection are enforced
            cryptographically via <code className="text-ink">account_scope</code> and{" "}
            <code className="text-ink">prospective_chain_link</code>.
          </p>
        </div>

        {/* Right: Privacy-Safe Monthly % of NAV Calendar Heatmap + Trade Count Pills */}
        <div className="inst-panel flex flex-col justify-between space-y-4 rounded-md p-5 lg:col-span-7">
          <div>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[10px] font-semibold uppercase tracking-widest text-signal-emerald">
                    Privacy-Safe Monthly % of NAV Calendar
                  </span>
                  <span className="rounded border border-hairline-strong bg-elevated px-2 py-0.5 font-mono text-[10px] text-ink-secondary">
                    Zero Raw Dollar Leak • Daily % + Trade Count
                  </span>
                </div>
                <h3 className="mt-0.5 text-sm font-semibold tracking-telemetry text-ink sm:text-base">
                  Monthly Flow-Adjusted Return &amp; Activity Cadence
                </h3>
              </div>

              {hoveredDay ? (
                <span className="rounded border border-hairline-strong bg-elevated px-2.5 py-1 font-mono text-[11px] text-ink tabular-nums">
                  {hoveredDay.date}:{" "}
                  <strong
                    className={
                      hoveredDay.return_pct >= 0
                        ? "text-signal-emerald"
                        : "text-signal-vermilion"
                    }
                  >
                    {hoveredDay.return_pct >= 0 ? "+" : ""}
                    {hoveredDay.return_pct.toFixed(2)}%
                  </strong>{" "}
                  • {hoveredDay.trade_count} trades
                </span>
              ) : activeMonth ? (
                <span className="font-mono text-[11px] text-ink-secondary tabular-nums">
                  {activeMonth.winDays}W / {activeMonth.lossDays}L days •{" "}
                  {activeMonth.totalTrades} trades
                </span>
              ) : null}
            </div>

            {/* Month Selector Pills */}
            {monthGroups.length > 0 && activeMonth && (
              <div className="mt-3 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="no-print flex flex-wrap gap-1.5">
                    {monthGroups.map((mg, idx) => {
                      const isSel = mg.monthKey === activeMonth.monthKey;
                      return (
                        <button
                          key={mg.monthKey}
                          type="button"
                          onClick={() => setSelectedMonthIdx(idx)}
                          className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-1 font-mono text-[11px] transition tabular-nums ${
                            isSel
                              ? "border-signal-emerald bg-signal-emerald-bg font-semibold text-ink"
                              : "border-hairline bg-elevated text-ink-secondary hover:border-ink-muted hover:text-ink"
                          }`}
                        >
                          <span>{mg.monthLabel}</span>
                          <span
                            className={
                              mg.compoundedReturnPct >= 0
                                ? "text-signal-emerald"
                                : "text-signal-vermilion"
                            }
                          >
                            {mg.compoundedReturnPct >= 0 ? "+" : ""}
                            {mg.compoundedReturnPct.toFixed(2)}%
                          </span>
                        </button>
                      );
                    })}
                  </div>

                  <div className="flex items-center gap-2 font-mono text-[10.5px] text-ink-muted tabular-nums">
                    <span>
                      Best:{" "}
                      <strong className="text-signal-emerald">
                        +{ Math.max(0, activeMonth.bestDayPct).toFixed(2) }%
                      </strong>
                    </span>
                    <span>•</span>
                    <span>
                      Worst:{" "}
                      <strong className="text-signal-vermilion">
                        {activeMonth.worstDayPct.toFixed(2)}%
                      </strong>
                    </span>
                  </div>
                </div>

                {/* 7-Column Calendar Grid (Mon .. Sun) */}
                <div onMouseLeave={() => setHoveredDay(null)}>
                  <div className="grid grid-cols-7 gap-1.5 font-mono text-[9.5px] uppercase tracking-wider text-ink-muted">
                    {WEEKDAY_HEADERS.map((wd) => (
                      <div key={wd} className="px-1 py-0.5 text-center">
                        {wd}
                      </div>
                    ))}
                  </div>

                  <div className="mt-1 grid grid-cols-7 gap-1.5">
                    {Array.from({ length: activeMonth.leadingEmptySlots }).map((_, i) => (
                      <div
                        key={`empty-${activeMonth.monthKey}-${i}`}
                        className="h-14 rounded border border-transparent bg-transparent"
                      />
                    ))}

                    {Array.from({ length: activeMonth.daysInMonth }, (_, idx) => idx + 1).map(
                      (dayNum) => {
                        const cell = activeMonth.byDayOfMonth.get(dayNum);
                        if (!cell) {
                          return (
                            <div
                              key={`${activeMonth.monthKey}-${dayNum}`}
                              className="flex h-14 flex-col justify-between rounded border border-hairline bg-elevated/30 p-1.5 font-mono text-[9.5px] text-ink-muted/60 tabular-nums"
                            >
                              <span>{String(dayNum).padStart(2, "0")}</span>
                              <span className="text-[9px]">-</span>
                            </div>
                          );
                        }

                        const isPos = cell.return_pct >= 0;
                        const mag = Math.min(Math.abs(cell.return_pct) / 2.6, 1);
                        const mixPct = Math.round(11 + mag * 38);
                        const bgStyle = isPos
                          ? {
                              backgroundColor: `color-mix(in srgb, var(--signal-emerald) ${mixPct}%, var(--bg-elevated))`,
                            }
                          : {
                              backgroundColor: `color-mix(in srgb, var(--signal-vermilion) ${mixPct}%, var(--bg-elevated))`,
                            };

                        return (
                          <button
                            key={cell.date}
                            type="button"
                            style={bgStyle}
                            onMouseEnter={() => setHoveredDay(cell)}
                            onFocus={() => setHoveredDay(cell)}
                            className="flex h-14 flex-col justify-between rounded border border-hairline p-1.5 text-left font-mono transition hover:border-ink tabular-nums"
                          >
                            <div className="flex w-full items-center justify-between gap-1">
                              <span className="text-[9.5px] text-ink-muted">
                                {String(dayNum).padStart(2, "0")}
                              </span>
                              {cell.trade_count > 0 && (
                                <span className="rounded bg-canvas/70 px-1 py-0.2 text-[8.5px] text-ink-secondary">
                                  {cell.trade_count}t
                                </span>
                              )}
                            </div>
                            <span
                              className={`text-[10.5px] font-semibold leading-none ${
                                isPos ? "text-signal-emerald" : "text-signal-vermilion"
                              }`}
                            >
                              {isPos ? "+" : ""}
                              {cell.return_pct.toFixed(2)}%
                            </span>
                          </button>
                        );
                      },
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 rounded border border-hairline bg-elevated px-3 py-2 font-mono text-[10.5px] text-ink-secondary tabular-nums">
            <span>
              Month Compounded:{" "}
              <strong
                className={
                  (activeMonth?.compoundedReturnPct ?? 0) >= 0
                    ? "text-signal-emerald"
                    : "text-signal-vermilion"
                }
              >
                {(activeMonth?.compoundedReturnPct ?? 0) >= 0 ? "+" : ""}
                {(activeMonth?.compoundedReturnPct ?? 0).toFixed(2)}%
              </strong>
            </span>
            <span>
              Total Active Observations: <strong className="text-ink">{dailyCells.length}</strong>{" "}
              days
            </span>
          </div>
        </div>
      </div>

      {/* Hour x Weekday Session Expectancy Matrix */}
      <SessionExpectancyMatrix cells={sessionCells} />

      {/* Selective Disclosure Leaves Status Strip */}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3 print-avoid-break">
        <DisclosureCard
          leafName="capital_bracket"
          disclosedValue={
            leaves.capitalBracket ? CAPITAL_BRACKET_LABELS[leaves.capitalBracket] : null
          }
          subText={
            undisclosed.capital_bracket
              ? `salted sha256: ${undisclosed.capital_bracket.slice(0, 22)}…`
              : "Logarithmic USD tier without raw dollar balance"
          }
        />
        <DisclosureCard
          leafName="benchmark_alpha"
          disclosedValue={
            leaves.benchmarkAlpha
              ? `${fmtPct(leaves.benchmarkAlpha.alpha_decimal)} vs ${leaves.benchmarkAlpha.benchmark_symbol}`
              : null
          }
          subText={
            leaves.benchmarkAlpha
              ? `IR ${fmtNum(leaves.benchmarkAlpha.information_ratio)} • Beta ${fmtNum(
                  leaves.benchmarkAlpha.beta,
                )}`
              : undisclosed.benchmark_alpha
                ? `salted sha256: ${undisclosed.benchmark_alpha.slice(0, 22)}…`
                : "Relative benchmark excess return"
          }
        />
        <DisclosureCard
          leafName="delayed_closed_trades"
          disclosedValue={
            leaves.delayedClosedTrades
              ? `${leaves.delayedClosedTrades.trades.length} round-trips (${leaves.delayedClosedTrades.embargo_days}d guard)`
              : null
          }
          subText={
            undisclosed.delayed_closed_trades
              ? `salted sha256: ${undisclosed.delayed_closed_trades.slice(0, 22)}…`
              : "Front-running guard strips share & dollar quantities"
          }
        />
      </div>

      {/* 7-Day Delayed Closed Round-Trip Executions Table */}
      {leaves.delayedClosedTrades && leaves.delayedClosedTrades.trades.length > 0 && (
        <div className="inst-panel rounded-md p-5 print-avoid-break">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-hairline pb-3">
            <div>
              <h3 className="text-sm font-semibold tracking-telemetry text-ink">
                7-Day Delayed Closed Round-Trips (Percentage-Only • Zero Notional Leak)
              </h3>
              <p className="text-xs text-ink-muted">
                Verified via salted leaf <code className="text-ink">delayed_closed_trades</code>{" "}
                after {leaves.delayedClosedTrades.embargo_days}-day front-run embargo.
              </p>
            </div>
          </div>

          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-hairline font-mono text-[10.5px] uppercase tracking-wider text-ink-muted">
                <tr>
                  <th className="py-2 pr-4">Symbol</th>
                  <th className="py-2 pr-4">Asset</th>
                  <th className="py-2 pr-4">Side</th>
                  <th className="py-2 pr-4">Entry (UTC)</th>
                  <th className="py-2 pr-4">Exit (UTC)</th>
                  <th className="py-2 pr-4 text-right">Hold</th>
                  <th className="py-2 text-right">Realized %</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hairline font-mono tabular-nums">
                {leaves.delayedClosedTrades.trades.map((tr, i) => (
                  <tr
                    key={`${tr.symbol}-${tr.entry_timestamp_utc}-${i}`}
                    className="transition hover:bg-elevated/50"
                  >
                    <td className="py-2.5 pr-4 font-semibold text-ink">{tr.symbol}</td>
                    <td className="py-2.5 pr-4 text-ink-muted">{tr.asset_class}</td>
                    <td className="py-2.5 pr-4 uppercase text-ink-secondary">{tr.side}</td>
                    <td className="py-2.5 pr-4 text-ink-muted">
                      {tr.entry_timestamp_utc.slice(0, 16).replace("T", " ")}
                    </td>
                    <td className="py-2.5 pr-4 text-ink-muted">
                      {tr.exit_timestamp_utc.slice(0, 16).replace("T", " ")}
                    </td>
                    <td className="py-2.5 pr-4 text-right text-ink-secondary">
                      {tr.holding_hours.toFixed(1)}h
                    </td>
                    <td
                      className={`py-2.5 text-right font-semibold ${
                        tr.return_pct >= 0
                          ? "text-signal-emerald"
                          : "text-signal-vermilion"
                      }`}
                    >
                      {tr.return_pct >= 0 ? "+" : ""}
                      {tr.return_pct.toFixed(2)}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function BootstrapFanChartPanel({
  summary,
  hoverConeIdx,
  onHoverCone,
}: {
  summary: BootstrapRiskSummary;
  hoverConeIdx: number | null;
  onHoverCone: (idx: number | null) => void;
}) {
  const cone = summary.cone;
  if (cone.length < 2) return null;

  const width = 940;
  const height = 225;
  const padL = 54;
  const padR = 24;
  const padTop = 18;
  const padBot = 28;
  const plotW = width - padL - padR;
  const plotH = height - padTop - padBot;

  let minVal = 96;
  let maxVal = 104;
  for (const pt of cone) {
    if (pt.p05 < minVal) minVal = pt.p05;
    if (pt.p95 > maxVal) maxVal = pt.p95;
  }
  const span = Math.max(maxVal - minVal, 2);

  const xAt = (i: number) => padL + (i / Math.max(cone.length - 1, 1)) * plotW;
  const yAt = (v: number) => padTop + (1 - (v - minVal) / span) * plotH;

  const outerBandPath = `${cone
    .map((p, i) => `${i === 0 ? "M" : "L"}${xAt(i).toFixed(1)},${yAt(p.p95).toFixed(1)}`)
    .join(" ")} ${[...cone]
    .reverse()
    .map((p, revI) => {
      const origI = cone.length - 1 - revI;
      return `L${xAt(origI).toFixed(1)},${yAt(p.p05).toFixed(1)}`;
    })
    .join(" ")} Z`;

  const innerBandPath = `${cone
    .map((p, i) => `${i === 0 ? "M" : "L"}${xAt(i).toFixed(1)},${yAt(p.p75).toFixed(1)}`)
    .join(" ")} ${[...cone]
    .reverse()
    .map((p, revI) => {
      const origI = cone.length - 1 - revI;
      return `L${xAt(origI).toFixed(1)},${yAt(p.p25).toFixed(1)}`;
    })
    .join(" ")} Z`;

  const medianPath = cone
    .map((p, i) => `${i === 0 ? "M" : "L"}${xAt(i).toFixed(1)},${yAt(p.p50).toFixed(1)}`)
    .join(" ");
  const p95Line = cone
    .map((p, i) => `${i === 0 ? "M" : "L"}${xAt(i).toFixed(1)},${yAt(p.p95).toFixed(1)}`)
    .join(" ");
  const p05Line = cone
    .map((p, i) => `${i === 0 ? "M" : "L"}${xAt(i).toFixed(1)},${yAt(p.p05).toFixed(1)}`)
    .join(" ");

  const activeIdx = hoverConeIdx != null ? hoverConeIdx : cone.length - 1;
  const activeCone = cone[activeIdx]!;
  const activeX = xAt(activeIdx);

  return (
    <div className="inst-panel rounded-md p-5 print-avoid-break">
      <div className="flex flex-col justify-between gap-3 border-b border-hairline pb-4 lg:flex-row lg:items-center">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[10px] font-semibold uppercase tracking-widest text-signal-emerald">
              Stationary Block-Bootstrap Risk-of-Ruin Engine
            </span>
            <span className="rounded border border-hairline-strong bg-elevated px-2 py-0.5 font-mono text-[10px] text-ink-secondary tabular-nums">
              {summary.num_simulations.toLocaleString()} Paths • Block b={summary.block_length} •{" "}
              {summary.horizon_periods}-Period Forward Cone
            </span>
          </div>
          <h3 className="editorial-serif mt-1 text-xl text-ink sm:text-2xl">
            1,000-Path Forward Confidence Fan (p05 / p25 / p50 / p75 / p95)
          </h3>
        </div>

        {/* Risk-of-Ruin Telemetry Badges */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] tabular-nums">
          <span className="badge-emerald rounded px-2.5 py-1 font-semibold">
            P(Terminal &gt; 1.0x): {(summary.prob_positive_terminal * 100).toFixed(1)}%
          </span>
          <span
            className={`rounded px-2.5 py-1 font-semibold ${
              summary.prob_drawdown_10pct > 0.25 ? "badge-ochre" : "badge-champagne"
            }`}
          >
            P(10% DD): {(summary.prob_drawdown_10pct * 100).toFixed(1)}%
          </span>
          <span
            className={`rounded px-2.5 py-1 font-semibold ${
              summary.prob_drawdown_20pct > 0.1 ? "badge-vermilion" : "badge-neutral"
            }`}
          >
            P(20% DD): {(summary.prob_drawdown_20pct * 100).toFixed(1)}%
          </span>
        </div>
      </div>

      {/* Live Step Readout */}
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 font-mono text-xs tabular-nums">
        <div className="flex flex-wrap items-center gap-3 text-[11px]">
          <span className="text-ink-muted">Step +{activeCone.step}d:</span>
          <span className="text-signal-vermilion">p05 {activeCone.p05.toFixed(2)}</span>
          <span className="text-ink-secondary">p25 {activeCone.p25.toFixed(2)}</span>
          <span className="font-semibold text-signal-emerald">
            p50 Median {activeCone.p50.toFixed(2)}
          </span>
          <span className="text-ink-secondary">p75 {activeCone.p75.toFixed(2)}</span>
          <span className="text-signal-champagne">p95 {activeCone.p95.toFixed(2)}</span>
        </div>
        <span className="text-[10.5px] text-ink-muted">
          Preserves volatility clustering &amp; serial return dependence
        </span>
      </div>

      <div className="relative mt-2">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="h-auto w-full select-none overflow-visible"
          onMouseLeave={() => onHoverCone(null)}
        >
          <defs>
            <linearGradient id="bootstrapOuterGrad" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="var(--signal-emerald)" stopOpacity="0.06" />
              <stop offset="100%" stopColor="var(--signal-champagne)" stopOpacity="0.16" />
            </linearGradient>
            <linearGradient id="bootstrapInnerGrad" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="var(--signal-emerald)" stopOpacity="0.18" />
              <stop offset="100%" stopColor="var(--signal-emerald)" stopOpacity="0.34" />
            </linearGradient>
          </defs>

          {/* Horizontal Reference Hairlines */}
          {[maxVal, 100, minVal].map((lvl, idx) => (
            <g key={`bgrid-${idx}`}>
              <line
                x1={padL}
                x2={width - padR}
                y1={yAt(lvl)}
                y2={yAt(lvl)}
                stroke="var(--chart-axis)"
                strokeWidth="1"
              />
              <text
                x={padL - 8}
                y={yAt(lvl) + 3.5}
                textAnchor="end"
                fill="var(--text-muted)"
                fontSize="10"
                className="mono-num"
              >
                {lvl.toFixed(1)}
              </text>
            </g>
          ))}

          {/* p05..p95 Outer Band & p25..p75 Inner Band */}
          <path d={outerBandPath} fill="url(#bootstrapOuterGrad)" />
          <path d={innerBandPath} fill="url(#bootstrapInnerGrad)" />

          {/* Quantile Boundary Hairlines */}
          <path
            d={p95Line}
            fill="none"
            stroke="var(--signal-champagne)"
            strokeWidth="1.2"
            strokeDasharray="4 3"
            strokeOpacity="0.85"
          />
          <path
            d={p05Line}
            fill="none"
            stroke="var(--signal-vermilion)"
            strokeWidth="1.2"
            strokeDasharray="4 3"
            strokeOpacity="0.8"
          />

          {/* p50 Median Trajectory */}
          <path
            d={medianPath}
            fill="none"
            stroke="var(--chart-wealth-stroke)"
            strokeWidth="2.5"
            strokeLinecap="round"
            
          />

          {/* Active Step Crosshair */}
          <line
            x1={activeX}
            x2={activeX}
            y1={padTop}
            y2={height - padBot}
            stroke="var(--chart-crosshair)"
            strokeWidth="1"
          />
          <circle
            cx={activeX}
            cy={yAt(activeCone.p50)}
            r="4.5"
            fill="var(--chart-wealth-stroke)"
            stroke="var(--bg-panel)"
            strokeWidth="2"
          />

          {/* X-Axis Labels */}
          <text
            x={padL}
            y={height - 6}
            fill="var(--text-muted)"
            fontSize="10"
            className="mono-num"
          >
            t + 0 (Rebased 100.0)
          </text>
          <text
            x={padL + plotW / 2}
            y={height - 6}
            textAnchor="middle"
            fill="var(--text-muted)"
            fontSize="10"
            className="mono-num"
          >
            t + {Math.round(summary.horizon_periods / 2)} periods
          </text>
          <text
            x={width - padR}
            y={height - 6}
            textAnchor="end"
            fill="var(--text-muted)"
            fontSize="10"
            className="mono-num"
          >
            t + {summary.horizon_periods} periods
          </text>

          {/* Interactive Step Scrubbers */}
          {cone.map((pt, idx) => {
            const colW = plotW / cone.length;
            return (
              <rect
                key={`bstep-${pt.step}`}
                x={xAt(idx) - colW / 2}
                y={0}
                width={Math.max(colW, 12)}
                height={height}
                fill="transparent"
                className="cursor-crosshair"
                onMouseEnter={() => onHoverCone(idx)}
              />
            );
          })}
        </svg>
      </div>
    </div>
  );
}

function SynchronizedWealthDrawdownSvg({
  points,
  benchSymbol,
  hoverIdx,
  onHover,
}: {
  points: IndexedCurvePoint[];
  benchSymbol: string;
  hoverIdx: number | null;
  onHover: (idx: number | null) => void;
}) {
  const width = 940;
  const wealthTop = 18;
  const wealthBottom = 196;
  const ddTop = 220;
  const ddBottom = 286;
  const totalHeight = 310;
  const padLeft = 54;
  const padRight = 20;

  const allVals: number[] = [100];
  for (const pt of points) {
    allVals.push(pt.index_value);
    if (pt.benchmark_index_value != null) {
      allVals.push(pt.benchmark_index_value);
    }
  }
  const minVal = Math.min(...allVals, 98.5);
  const maxVal = Math.max(...allVals, 102);
  const valSpan = Math.max(maxVal - minVal, 1);

  const minDd = Math.min(...points.map((p) => p.drawdown_pct), -1.0);

  const plotW = width - padLeft - padRight;
  const xAt = (idx: number) =>
    padLeft + (idx / Math.max(points.length - 1, 1)) * plotW;
  const yWealth = (v: number) =>
    wealthTop + (1 - (v - minVal) / valSpan) * (wealthBottom - wealthTop);
  const yDd = (dd: number) =>
    ddTop + (Math.abs(dd) / Math.abs(minDd)) * (ddBottom - ddTop);

  const portfolioPath = points
    .map(
      (p, i) =>
        `${i === 0 ? "M" : "L"}${xAt(i).toFixed(1)},${yWealth(p.index_value).toFixed(1)}`,
    )
    .join(" ");

  const portfolioArea = `${portfolioPath} L${xAt(points.length - 1).toFixed(
    1,
  )},${wealthBottom} L${xAt(0).toFixed(1)},${wealthBottom} Z`;

  const hasBenchmark = points.every((p) => p.benchmark_index_value != null);
  const benchPath = hasBenchmark
    ? points
        .map(
          (p, i) =>
            `${i === 0 ? "M" : "L"}${xAt(i).toFixed(1)},${yWealth(
              p.benchmark_index_value!,
            ).toFixed(1)}`,
        )
        .join(" ")
    : null;

  const ddPath = points
    .map((p, i) => `${i === 0 ? "M" : "L"}${xAt(i).toFixed(1)},${yDd(p.drawdown_pct).toFixed(1)}`)
    .join(" ");
  const ddArea = `M${xAt(0).toFixed(1)},${ddTop} ${points
    .map((p, i) => `L${xAt(i).toFixed(1)},${yDd(p.drawdown_pct).toFixed(1)}`)
    .join(" ")} L${xAt(points.length - 1).toFixed(1)},${ddTop} Z`;

  const activeIdx = hoverIdx != null ? hoverIdx : points.length - 1;
  const activePt = points[activeIdx]!;
  const activeX = xAt(activeIdx);
  const hudFlipLeft = activeX > width * 0.64;

  const midVal = (minVal + maxVal) / 2;

  return (
    <div className="relative mt-4">
      <svg
        viewBox={`0 0 ${width} ${totalHeight}`}
        className="h-auto w-full select-none overflow-visible"
        onMouseLeave={() => onHover(null)}
      >
        <defs>
          <linearGradient id="instWealthFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--chart-wealth-top)" />
            <stop offset="100%" stopColor="var(--chart-wealth-bottom)" />
          </linearGradient>
          <linearGradient id="instDrawdownFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="transparent" />
            <stop offset="100%" stopColor="var(--chart-dd-top)" />
          </linearGradient>
        </defs>

        {/* Fine 1px Horizontal Hairlines (Zero Heavy Dashed Gridlines) */}
        {[maxVal, midVal, 100].map((lvl, idx) => (
          <g key={`grid-${idx}`}>
            <line
              x1={padLeft}
              x2={width - padRight}
              y1={yWealth(lvl)}
              y2={yWealth(lvl)}
              stroke="var(--chart-axis)"
              strokeWidth="1"
            />
            <text
              x={padLeft - 8}
              y={yWealth(lvl) + 3.5}
              textAnchor="end"
              fill="var(--text-muted)"
              fontSize="10"
              className="mono-num"
            >
              {lvl.toFixed(1)}
            </text>
          </g>
        ))}

        {/* Wealth Area & Splines */}
        <path d={portfolioArea} fill="url(#instWealthFill)" />
        {benchPath && (
          <path
            d={benchPath}
            fill="none"
            stroke="var(--chart-bench-stroke)"
            strokeWidth="1.4"
            strokeOpacity="0.7"
          />
        )}
        <path
          d={portfolioPath}
          fill="none"
          stroke="var(--chart-wealth-stroke)"
          strokeWidth="2.35"
          strokeLinecap="round"
          strokeLinejoin="round"
          
        />

        {/* Synchronized Underwater Drawdown Pane */}
        <line
          x1={padLeft}
          x2={width - padRight}
          y1={ddTop}
          y2={ddTop}
          stroke="var(--chart-axis)"
          strokeWidth="1"
        />
        <line
          x1={padLeft}
          x2={width - padRight}
          y1={ddBottom}
          y2={ddBottom}
          stroke="var(--chart-axis)"
          strokeWidth="1"
        />
        <path d={ddArea} fill="url(#instDrawdownFill)" />
        <path
          d={ddPath}
          fill="none"
          stroke="var(--chart-dd-stroke)"
          strokeWidth="1.55"
          strokeLinejoin="round"
        />

        <text
          x={padLeft - 8}
          y={ddTop + 9}
          textAnchor="end"
          fill="var(--text-muted)"
          fontSize="9.5"
          className="mono-num"
        >
          0.0%
        </text>
        <text
          x={padLeft - 8}
          y={ddBottom - 2}
          textAnchor="end"
          fill="var(--signal-vermilion)"
          fontSize="9.5"
          className="mono-num"
        >
          {minDd.toFixed(1)}%
        </text>

        {/* Synchronized Crosshair Spanning Wealth + Drawdown Panes */}
        <line
          x1={activeX}
          x2={activeX}
          y1={wealthTop - 4}
          y2={ddBottom}
          stroke="var(--chart-crosshair)"
          strokeWidth="1"
        />

        {/* Synchronized Active Point Markers */}
        {activePt.benchmark_index_value != null && (
          <circle
            cx={activeX}
            cy={yWealth(activePt.benchmark_index_value)}
            r="3"
            fill="var(--chart-bench-stroke)"
          />
        )}
        <circle
          cx={activeX}
          cy={yWealth(activePt.index_value)}
          r="4.5"
          fill="var(--chart-wealth-stroke)"
          stroke="var(--bg-panel)"
          strokeWidth="2"
        />
        <circle
          cx={activeX}
          cy={yDd(activePt.drawdown_pct)}
          r="3.5"
          fill="var(--chart-dd-stroke)"
          stroke="var(--bg-panel)"
          strokeWidth="1.5"
        />

        {/* Floating Tabular-Mono HUD Tooltip */}
        {hoverIdx != null && (
          <g
            transform={`translate(${
              hudFlipLeft ? Math.max(activeX - 198, padLeft + 4) : activeX + 12
            }, ${wealthTop + 4})`}
          >
            <rect
              width="186"
              height={activePt.benchmark_index_value != null ? "72" : "56"}
              rx="4"
              fill="var(--bg-elevated)"
              stroke="var(--border-strong)"
              strokeWidth="1"
            />
            <text
              x="10"
              y="16"
              fill="var(--text-muted)"
              fontSize="10"
              className="mono-num"
            >
              {activePt.timestamp_utc.slice(0, 10)}
            </text>
            <text
              x="10"
              y="32"
              fill="var(--signal-emerald)"
              fontSize="11"
              fontWeight="600"
              className="mono-num"
            >
              Portfolio: {activePt.index_value.toFixed(2)}
            </text>
            {activePt.benchmark_index_value != null && (
              <text
                x="10"
                y="47"
                fill="var(--text-secondary)"
                fontSize="10.5"
                className="mono-num"
              >
                {benchSymbol}: {activePt.benchmark_index_value.toFixed(2)}
              </text>
            )}
            <text
              x="10"
              y={activePt.benchmark_index_value != null ? "62" : "47"}
              fill="var(--signal-vermilion)"
              fontSize="10.5"
              className="mono-num"
            >
              Underwater DD: {activePt.drawdown_pct.toFixed(2)}%
            </text>
          </g>
        )}

        {/* X-Axis Timestamps */}
        <text
          x={padLeft}
          y={totalHeight - 4}
          fill="var(--text-muted)"
          fontSize="10"
          className="mono-num"
        >
          {points[0]!.timestamp_utc.slice(0, 10)}
        </text>
        <text
          x={padLeft + plotW / 2}
          y={totalHeight - 4}
          textAnchor="middle"
          fill="var(--text-muted)"
          fontSize="10"
          className="mono-num"
        >
          {points[Math.floor(points.length / 2)]!.timestamp_utc.slice(0, 10)}
        </text>
        <text
          x={width - padRight}
          y={totalHeight - 4}
          textAnchor="end"
          fill="var(--text-muted)"
          fontSize="10"
          className="mono-num"
        >
          {points[points.length - 1]!.timestamp_utc.slice(0, 10)}
        </text>

        {/* Full-Height Interactive Scrubbing Hit Targets */}
        {points.map((pt, idx) => {
          const colW = plotW / points.length;
          return (
            <rect
              key={pt.timestamp_utc}
              x={xAt(idx) - colW / 2}
              y={0}
              width={Math.max(colW, 10)}
              height={totalHeight}
              fill="transparent"
              className="cursor-crosshair"
              onMouseEnter={() => onHover(idx)}
            />
          );
        })}
      </svg>
    </div>
  );
}

function MetricCard({
  label,
  value,
  sub,
  accent = "ink",
}: {
  label: string;
  value: string;
  sub: string;
  accent?: "emerald" | "champagne" | "ochre" | "vermilion" | "ink";
}) {
  const valueColor =
    accent === "emerald"
      ? "text-signal-emerald"
      : accent === "champagne"
        ? "text-signal-champagne"
        : accent === "ochre"
          ? "text-signal-ochre"
          : accent === "vermilion"
            ? "text-signal-vermilion"
            : "text-ink";

  return (
    <div className="inst-panel rounded-md p-3.5">
      <p className="font-mono text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
        {label}
      </p>
      <p className={`mt-1.5 font-mono text-lg font-bold tabular-nums ${valueColor}`}>
        {value}
      </p>
      <p className="mt-1 font-mono text-[10.5px] text-ink-secondary tabular-nums">{sub}</p>
    </div>
  );
}

function MiniStat({
  label,
  value,
  note,
}: {
  label: string;
  value: string;
  note: string;
}) {
  return (
    <div className="rounded border border-hairline bg-elevated p-2.5">
      <p className="font-mono text-[10px] text-ink-muted">{label}</p>
      <p className="mt-0.5 font-mono text-sm font-semibold text-ink tabular-nums">
        {value}
      </p>
      <p className="font-mono text-[9.5px] text-ink-muted">{note}</p>
    </div>
  );
}

function DisclosureCard({
  leafName,
  disclosedValue,
  subText,
}: {
  leafName: string;
  disclosedValue: string | null;
  subText: string;
}) {
  return (
    <div className="inst-panel rounded-md p-3.5">
      <div className="flex items-center justify-between gap-2 font-mono text-xs">
        <span className="text-ink-muted">{leafName}</span>
        {disclosedValue ? (
          <span className="font-semibold text-signal-emerald tabular-nums">
            {disclosedValue}
          </span>
        ) : (
          <span className="badge-ochre rounded px-1.5 py-0.5 text-[10px]">
            Salted-Redacted
          </span>
        )}
      </div>
      <p className="mt-1.5 truncate font-mono text-[10.5px] text-ink-muted tabular-nums">
        {subText}
      </p>
    </div>
  );
}
