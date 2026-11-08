"use client";

import { AlertTriangle, Sparkles } from "lucide-react";
import { useMemo, useState } from "react";
import { SessionExpectancyMatrix } from "@/components/SessionExpectancyMatrix.tsx";
import {
  CatalystAlignmentClass,
  DEFAULT_COUNTERFACTUAL_DISCLAIMER,
  type EventWindowObservation,
  type ExtractedBundleLeaves,
  type QuantDnaProfile,
  type VerifyProofBundle,
} from "@/lib/contracts.ts";
import {
  resolveCounterfactualTwin,
  resolveQuantDnaProfile,
  resolveSessionExpectancyCells,
} from "@/lib/wave4Analytics.ts";

const ALIGNMENT_META: Record<
  CatalystAlignmentClass,
  { label: string; style: string; markerPosPct: number; markerColor: string }
> = {
  post_confirmed_catalyst: {
    label: "Post-Confirmed Public Catalyst",
    style: "badge-emerald",
    markerPosPct: 80,
    markerColor: "bg-signal-emerald",
  },
  ambiguous_public_window: {
    label: "Inside Catalyst Window I_e",
    style: "badge-ochre",
    markerPosPct: 50,
    markerColor: "bg-signal-ochre",
  },
  prior_to_earliest_recorded_catalyst: {
    label: "Prior to Earliest Indexed Wire",
    style: "badge-champagne",
    markerPosPct: 18,
    markerColor: "bg-signal-champagne",
  },
  quiet_non_catalyst_regime: {
    label: "Quiet Non-Catalyst Regime",
    style: "badge-neutral",
    markerPosPct: 50,
    markerColor: "bg-ink-muted",
  },
};

const SYNTHETIC_FALLBACK_BUNDLE_STUB = {
  proof_id: "coaching-preview",
  broker_id: "ibkr_flex",
  merkle_root: "0".repeat(64),
} as unknown as VerifyProofBundle;

export function CoachingStudioTab({
  bundle,
  leaves,
}: {
  bundle?: VerifyProofBundle;
  leaves: ExtractedBundleLeaves;
}) {
  const coaching = leaves.coaching;
  const effectiveBundle = bundle ?? SYNTHETIC_FALLBACK_BUNDLE_STUB;

  // Interactive Counterfactual Twin Lever Toggles
  const [removeFeeFxDrag, setRemoveFeeFxDrag] = useState(true);
  const [fixPostDdSizing, setFixPostDdSizing] = useState(true);
  const [capTailLosers, setCapTailLosers] = useState(false);
  const [hoverStepIdx, setHoverStepIdx] = useState<number | null>(null);

  const counterfactualReport = useMemo(
    () => resolveCounterfactualTwin(effectiveBundle, leaves),
    [effectiveBundle, leaves],
  );
  const quantDna = useMemo(
    () => resolveQuantDnaProfile(effectiveBundle, leaves),
    [effectiveBundle, leaves],
  );
  const sessionCells = useMemo(
    () => resolveSessionExpectancyCells(effectiveBundle, leaves),
    [effectiveBundle, leaves],
  );

  // Compose combined hypothetical twin curve from the active toggle pills
  const replaySeries = useMemo(() => {
    if (!counterfactualReport || counterfactualReport.curve_points.length < 2) {
      return null;
    }
    const pts = counterfactualReport.curve_points.map((pt) => {
      const feeDelta = removeFeeFxDrag
        ? Math.max(0, pt.zero_friction - pt.actual)
        : 0;
      const ddDelta = fixPostDdSizing
        ? Math.max(0, pt.disciplined_sizing - pt.actual)
        : 0;
      const tailDelta = capTailLosers
        ? Math.max(0, pt.capped_tail_loss - pt.actual)
        : 0;
      // Combine orthogonally with mild overlap damping when multiple levers are active
      const activeCount =
        Number(removeFeeFxDrag) + Number(fixPostDdSizing) + Number(capTailLosers);
      const damping = activeCount >= 3 ? 0.86 : activeCount === 2 ? 0.92 : 1.0;
      const simulated =
        Math.round((pt.actual + (feeDelta + ddDelta + tailDelta) * damping) * 100) /
        100;

      return {
        step: pt.step,
        label: pt.date ?? pt.timestamp_utc?.slice(0, 10) ?? `t+${pt.step}`,
        actual: pt.actual,
        simulated,
        gapPts: Math.round((simulated - pt.actual) * 100) / 100,
      };
    });

    const last = pts[pts.length - 1]!;
    return {
      points: pts,
      actualTerminal: last.actual,
      simulatedTerminal: last.simulated,
      deltaTerminalPts: Math.round((last.simulated - last.actual) * 100) / 100,
      disclaimer:
        counterfactualReport.compliance_disclaimer ||
        DEFAULT_COUNTERFACTUAL_DISCLAIMER,
    };
  }, [counterfactualReport, removeFeeFxDrag, fixPostDdSizing, capTailLosers]);

  if (!coaching) {
    return (
      <div className="inst-panel rounded-md p-6 text-sm text-ink-muted">
        Coaching &amp; catalyst context leaf is not disclosed in this bundle.
      </div>
    );
  }

  const { cost_drag: drag, behaviour: beh } = coaching;
  const totalBps = Math.max(drag.total_friction_drag_bps, 0.1);

  const waterfallSteps = [
    {
      code: "COMM",
      name: "1. Commissions & Exchange Fees",
      bps: drag.commission_and_fee_drag_bps,
      startBps: 0,
      tone: "var(--signal-champagne)",
    },
    {
      code: "MARG",
      name: "2. Margin Borrow & Funding Carry",
      bps: drag.margin_and_funding_drag_bps,
      startBps: drag.commission_and_fee_drag_bps,
      tone: "var(--signal-ochre)",
    },
    {
      code: "FX",
      name: "3. Multi-Currency FX Spread",
      bps: drag.fx_conversion_drag_bps,
      startBps: drag.commission_and_fee_drag_bps + drag.margin_and_funding_drag_bps,
      tone: "var(--text-secondary)",
    },
    {
      code: "WHT",
      name: "4. Dividend Withholding Tax",
      bps: drag.withholding_tax_drag_bps,
      startBps:
        drag.commission_and_fee_drag_bps +
        drag.margin_and_funding_drag_bps +
        drag.fx_conversion_drag_bps,
      tone: "var(--text-muted)",
    },
  ];

  const odeanSpread = beh.odean_pgr_plr_spread ?? 0;
  const sdiAtr = beh.post_drawdown_sizing_discipline_atr ?? 1.0;
  const importedTags = coaching.imported_journal_tags ?? [];

  return (
    <div className="space-y-6">
      {/* Studio Telemetry Banner + 6-Axis Quant DNA Radar ("Wrapped for Traders") */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
        <div className="inst-panel flex flex-col justify-between space-y-4 rounded-md p-5 lg:col-span-7">
          <div>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="badge-emerald rounded px-2.5 py-0.5 font-mono text-[10.5px] font-semibold uppercase tracking-wider">
                Open-Source Execution &amp; Behavioural Studio
              </span>
              <span className="font-mono text-xs text-ink-muted tabular-nums">
                Sample Gate: {beh.observed_trades}/{beh.min_trades_gate} closed trades (
                {beh.sample_eligible ? "ELIGIBLE" : "GATED"}) • {beh.observed_days} active days
              </span>
            </div>

            {quantDna && (
              <div className="mt-3 inline-flex flex-wrap items-center gap-2 rounded border border-signal-champagne-border bg-signal-champagne-bg px-3 py-1.5 font-mono text-xs">
                <Sparkles className="h-3.5 w-3.5 text-signal-champagne" />
                <span className="text-[10.5px] uppercase tracking-wider text-ink-secondary">
                  Trader Archetype:
                </span>
                <strong className="text-signal-champagne">
                  {quantDna.archetype_label}
                </strong>
              </div>
            )}

            <p className="mt-3 text-sm font-medium leading-relaxed text-ink">
              {coaching.style_summary}
            </p>

            {importedTags.length > 0 && (
              <div className="mt-3 flex flex-wrap items-center gap-1.5 font-mono text-[10.5px]">
                <span className="text-ink-muted">Preserved Journal Tags:</span>
                {importedTags.map((tag) => (
                  <span
                    key={tag}
                    className="rounded border border-hairline-strong bg-elevated px-2 py-0.5 text-ink-secondary"
                  >
                    #{tag}
                  </span>
                ))}
              </div>
            )}
          </div>

          {quantDna && (
            <div className="grid grid-cols-2 gap-2 pt-1 sm:grid-cols-3">
              <DnaScoreChip label="Consistency" score={quantDna.consistency_score} />
              <DnaScoreChip
                label="DD Resilience"
                score={quantDna.drawdown_resilience_score}
              />
              <DnaScoreChip
                label="Cost Efficiency"
                score={quantDna.cost_efficiency_score}
              />
              <DnaScoreChip
                label="Sizing Discipline"
                score={quantDna.sizing_discipline_score}
              />
              <DnaScoreChip
                label="Exit Symmetry"
                score={quantDna.exit_symmetry_score}
              />
              <DnaScoreChip
                label="Catalyst Align"
                score={quantDna.catalyst_alignment_score}
              />
            </div>
          )}
        </div>

        {/* Right: 6-Axis Hexagonal Quant DNA Radar */}
        {quantDna && (
          <div className="inst-panel flex flex-col items-center justify-between rounded-md p-5 lg:col-span-5">
            <div className="flex w-full items-center justify-between">
              <div>
                <p className="font-mono text-[10px] font-semibold uppercase tracking-widest text-signal-champagne">
                  Wrapped for Traders • 6-Axis Telemetry
                </p>
                <h3 className="mt-0.5 text-sm font-semibold tracking-telemetry text-ink">
                  Quant DNA Radar Profile
                </h3>
              </div>
              <span className="rounded border border-hairline-strong bg-elevated px-2 py-0.5 font-mono text-[10px] text-signal-emerald tabular-nums">
                0–100 Scale
              </span>
            </div>

            <QuantDnaRadarSvg profile={quantDna} />
          </div>
        )}
      </div>

      {/* "Actual vs. Disciplined Twin" Counterfactual Equity Replay */}
      {replaySeries && counterfactualReport && (
        <div className="rounded-md border border-signal-champagne-border bg-panel p-5">
          <div className="flex flex-col justify-between gap-4 border-b border-hairline pb-4 xl:flex-row xl:items-center">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="badge-ochre inline-flex items-center gap-1.5 rounded px-2.5 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider">
                  <AlertTriangle className="h-3 w-3" />
                  Hypothetical Coaching Simulation — Separate from Verified Realized Record
                </span>
              </div>
              <h3 className="editorial-serif mt-1.5 text-xl text-ink sm:text-2xl">
                Actual vs. Disciplined Twin Counterfactual Equity Replay
              </h3>
              <p className="mt-0.5 text-xs text-ink-secondary">
                Toggle execution &amp; risk-budget levers below to quantify recoverable alpha
                without altering the cryptographically verified TWR / XIRR header.
              </p>
            </div>

            {/* 3 Interactive Counterfactual Toggle Pills */}
            <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] tabular-nums">
              <button
                type="button"
                onClick={() => setRemoveFeeFxDrag((v) => !v)}
                className={`rounded border px-3 py-1.5 font-medium transition ${
                  removeFeeFxDrag
                    ? "border-signal-champagne bg-signal-champagne-bg text-signal-champagne shadow-[0_0_14px_rgba(214,179,106,0.16)]"
                    : "border-hairline-strong bg-elevated text-ink-muted hover:text-ink"
                }`}
              >
                [Remove Fee/FX Drag] (
                +
                {(
                  counterfactualReport.zero_friction_ending_index -
                  counterfactualReport.actual_ending_index
                ).toFixed(2)}{" "}
                pts)
              </button>
              <button
                type="button"
                onClick={() => setFixPostDdSizing((v) => !v)}
                className={`rounded border px-3 py-1.5 font-medium transition ${
                  fixPostDdSizing
                    ? "border-signal-emerald bg-signal-emerald-bg text-signal-emerald shadow-[0_0_14px_rgba(16,185,129,0.16)]"
                    : "border-hairline-strong bg-elevated text-ink-muted hover:text-ink"
                }`}
              >
                [Fix Post-DD Oversizing] (
                +
                {(
                  counterfactualReport.disciplined_post_dd_sizing_ending_index -
                  counterfactualReport.actual_ending_index
                ).toFixed(2)}{" "}
                pts)
              </button>
              <button
                type="button"
                onClick={() => setCapTailLosers((v) => !v)}
                className={`rounded border px-3 py-1.5 font-medium transition ${
                  capTailLosers
                    ? "border-signal-ochre bg-signal-ochre-bg text-signal-ochre shadow-[0_0_14px_rgba(245,158,11,0.16)]"
                    : "border-hairline-strong bg-elevated text-ink-muted hover:text-ink"
                }`}
              >
                [Cap p95 Tail Losers] (
                +
                {(
                  counterfactualReport.capped_tail_loss_ending_index -
                  counterfactualReport.actual_ending_index
                ).toFixed(2)}{" "}
                pts)
              </button>
            </div>
          </div>

          <CounterfactualReplaySvg
            points={replaySeries.points}
            hoverStepIdx={hoverStepIdx}
            onHoverStep={setHoverStepIdx}
          />

          {/* Realized vs Simulated Readout Strip */}
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2 font-mono text-xs tabular-nums">
            <span>
              Verified Realized Ending Index:{" "}
              <strong className="text-signal-emerald">
                {replaySeries.actualTerminal.toFixed(2)}
              </strong>
            </span>
            <span>
              Simulated Disciplined Twin:{" "}
              <strong className="text-signal-champagne">
                {replaySeries.simulatedTerminal.toFixed(2)} (+
                {replaySeries.deltaTerminalPts.toFixed(2)} idx pts hypothetical recovery)
              </strong>
            </span>
          </div>

          {/* Unmissable SEC / FINRA / GIPS Hypothetical Simulation Compliance Banner */}
          <div
            role="note"
            aria-label="SEC FINRA GIPS Hypothetical Simulation Disclaimer"
            className="mt-3.5 rounded border border-signal-ochre-border bg-signal-ochre-bg p-3.5 text-xs leading-relaxed"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[10.5px] font-bold uppercase tracking-wider text-signal-ochre">
              <span>
                SEC Rule 206(4)-1 / FINRA 2210 / GIPS Hypothetical Coaching Simulation
                Notice
              </span>
              <span>NOT VERIFIED REALIZED PERFORMANCE</span>
            </div>
            <p className="mt-1 text-[11.5px] text-ink-secondary">
              {replaySeries.disclaimer}
            </p>
          </div>
        </div>
      )}

      {/* Top 2-Column Analytics: Stepped 5-Part Friction Waterfall + Odean & ATR Discipline */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        {/* Stepped 5-Part Friction-Drag Waterfall */}
        <div className="inst-panel flex flex-col justify-between rounded-md p-5">
          <div>
            <div className="flex items-start justify-between gap-2">
              <div>
                <p className="font-mono text-[10px] font-semibold uppercase tracking-widest text-signal-champagne">
                  Cost Decomposition
                </p>
                <h3 className="mt-0.5 text-sm font-semibold tracking-telemetry text-ink">
                  Stepped 5-Part Friction-Drag Waterfall
                </h3>
              </div>
              <span className="badge-vermilion rounded px-2.5 py-1 font-mono text-xs font-semibold tabular-nums">
                -{drag.annualized_total_drag_bps.toFixed(1)} bps / yr
              </span>
            </div>

            <div className="mt-4 space-y-3 font-mono text-xs tabular-nums">
              {waterfallSteps.map((step) => {
                const offsetPct = Math.min((step.startBps / totalBps) * 100, 96);
                const widthPct = Math.max(
                  (step.bps / totalBps) * 100,
                  step.bps > 0 ? 3 : 0,
                );
                return (
                  <div key={step.code} className="space-y-1">
                    <div className="flex items-center justify-between text-[11.5px]">
                      <span className="font-sans text-ink-secondary">{step.name}</span>
                      <span className="font-semibold text-ink">
                        -{step.bps.toFixed(1)} bps
                      </span>
                    </div>
                    <div className="relative h-2.5 w-full overflow-hidden rounded-sm bg-elevated">
                      <div
                        className="absolute top-0 bottom-0 rounded-sm transition-all duration-500 ease-out"
                        style={{
                          left: `${offsetPct}%`,
                          width: `${Math.min(widthPct, 100 - offsetPct)}%`,
                          backgroundColor: step.tone,
                        }}
                      />
                    </div>
                  </div>
                );
              })}

              {/* Step 5: Cumulative Total Bar */}
              <div className="mt-2 rounded border border-hairline-strong bg-elevated p-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-sans font-semibold text-ink">
                    5. Cumulative Period Friction Drag
                  </span>
                  <span className="font-bold text-signal-vermilion">
                    -{drag.total_friction_drag_bps.toFixed(1)} bps
                  </span>
                </div>
                <div className="mt-1.5 h-2.5 w-full overflow-hidden rounded-sm bg-subtle">
                  <div className="h-full w-full bg-signal-vermilion" />
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Odean PGR/PLR Disposition + ATR Post-Drawdown Discipline */}
        <div className="inst-panel space-y-4 rounded-md p-5">
          <div>
            <p className="font-mono text-[10px] font-semibold uppercase tracking-widest text-signal-emerald">
              Microstructure &amp; Sizing Discipline
            </p>
            <h3 className="mt-0.5 text-sm font-semibold tracking-telemetry text-ink">
              Odean (1998) Disposition Spread &amp; ATR Drawdown Risk
            </h3>
          </div>

          <div className="rounded border border-hairline bg-elevated p-3.5">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-semibold text-ink">
                Odean Disposition Spread (PGR − PLR)
              </span>
              <span
                className={`rounded px-2 py-0.5 font-mono text-xs font-semibold tabular-nums ${
                  odeanSpread > 0.1 ? "badge-ochre" : "badge-emerald"
                }`}
              >
                {odeanSpread >= 0 ? "+" : ""}
                {odeanSpread.toFixed(3)}
              </span>
            </div>
            <p className="mt-1.5 text-[11.5px] text-ink-secondary tabular-nums">
              {odeanSpread > 0.1
                ? `Positive spread indicates early winner cutting (winners held ${
                    beh.winner_vs_loser_hold_ratio?.toFixed(2) ?? "—"
                  }x relative to stopped losers).`
                : `Disciplined negative/neutral spread: winners held ${
                    beh.winner_vs_loser_hold_ratio?.toFixed(2) ?? "—"
                  }x longer than losers.`}
            </p>
          </div>

          <div className="rounded border border-hairline bg-elevated p-3.5">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-semibold text-ink">
                ATR Post-Drawdown Sizing (SDI_DD^ATR)
              </span>
              <span
                className={`rounded px-2 py-0.5 font-mono text-xs font-semibold tabular-nums ${
                  sdiAtr > 1.15 ? "badge-ochre" : "badge-emerald"
                }`}
              >
                {sdiAtr.toFixed(2)}x Baseline ATR
              </span>
            </div>
            <div className="relative mt-2.5 h-2.5 w-full rounded-sm bg-subtle">
              <div
                className="absolute top-0 bottom-0 z-10 w-0.5 bg-ink"
                style={{ left: "45.5%" }}
                title="1.00x Baseline ATR Risk"
              />
              <div
                className={`h-full rounded-sm transition-all duration-500 ${
                  sdiAtr > 1.15 ? "bg-signal-ochre" : "bg-signal-emerald"
                }`}
                style={{
                  width: `${Math.min(Math.max(((sdiAtr - 0.5) / 1.1) * 100, 6), 100)}%`,
                }}
              />
            </div>
            <p className="mt-1.5 text-[11.5px] text-ink-secondary">
              {sdiAtr > 1.15
                ? "Post-drawdown entries expanded volatility risk >15% above baseline ATR."
                : "Volatility-normalized position sizing stayed within <=1.15x baseline ATR."}
            </p>
          </div>

          <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
            <SmallKpi
              label="Win Rate"
              value={beh.win_rate != null ? `${(beh.win_rate * 100).toFixed(1)}%` : "—"}
            />
            <SmallKpi
              label="Profit Factor"
              value={beh.profit_factor != null ? beh.profit_factor.toFixed(2) : "—"}
            />
            <SmallKpi
              label="Median Hold"
              value={
                beh.median_holding_hours != null
                  ? `${beh.median_holding_hours.toFixed(1)}h`
                  : "—"
              }
            />
            <SmallKpi
              label="Top-5 Conc."
              value={
                beh.return_concentration_top5_pct != null
                  ? `${beh.return_concentration_top5_pct.toFixed(1)}%`
                  : "—"
              }
            />
          </div>
        </div>
      </div>

      {/* Hour x Weekday Session Expectancy Matrix */}
      <SessionExpectancyMatrix cells={sessionCells} compact />

      {/* Actionable Coaching Playbook */}
      {beh.actionable_improvements.length > 0 && (
        <div className="inst-panel rounded-md p-5">
          <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-signal-emerald">
            Quantified Edge-Recovery Playbook
          </h3>
          <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-3">
            {beh.actionable_improvements.map((item, idx) => (
              <div
                key={item}
                className="rounded border border-hairline bg-elevated p-3.5 text-xs leading-relaxed text-ink-secondary"
              >
                <span className="badge-champagne mb-1.5 inline-block rounded px-2 py-0.5 font-mono text-[10px] font-semibold">
                  ACTION #{idx + 1}
                </span>
                <p className="text-ink">{item}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Catalyst Availability Interval I_e = [t_earliest, t_confirmed] Timeline */}
      <div className="inst-panel rounded-md p-5">
        <div className="flex flex-col justify-between gap-2 sm:flex-row sm:items-center">
          <div>
            <p className="font-mono text-[10px] font-semibold uppercase tracking-widest text-signal-ochre">
              Public Dissemination Uncertainty Window
            </p>
            <h3 className="mt-0.5 text-sm font-semibold tracking-telemetry text-ink">
              Catalyst Availability Interval{" "}
              <span className="font-mono text-xs text-signal-champagne">
                Ie = [t_earliest, t_confirmed]
              </span>
            </h3>
            <p className="mt-0.5 text-xs text-ink-muted">
              Alignment between execution fills and public EDGAR/newswire timestamps (
              <span className="font-mono tabular-nums">
                {coaching.event_window_share_pct.toFixed(1)}%
              </span>{" "}
              catalyst-regime share).
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 font-mono text-xs tabular-nums">
            {coaching.catalyst_regime_win_rate != null && (
              <span className="badge-emerald rounded px-2.5 py-1">
                Catalyst Win: {(coaching.catalyst_regime_win_rate * 100).toFixed(1)}%
              </span>
            )}
            {coaching.quiet_regime_win_rate != null && (
              <span className="badge-neutral rounded px-2.5 py-1">
                Quiet Win: {(coaching.quiet_regime_win_rate * 100).toFixed(1)}%
              </span>
            )}
          </div>
        </div>

        <div className="mt-4 space-y-3">
          {coaching.event_observations.map((obs, idx) => (
            <CatalystIntervalRow
              key={`${obs.symbol}-${obs.trade_timestamp_utc}-${idx}`}
              obs={obs}
            />
          ))}
        </div>

        {coaching.uncertainty_disclosures.length > 0 && (
          <div className="mt-4 rounded border border-hairline bg-elevated p-3 text-[11px] text-ink-muted">
            {coaching.uncertainty_disclosures.map((note) => (
              <p key={note}>{note}</p>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function QuantDnaRadarSvg({ profile }: { profile: QuantDnaProfile }) {
  const axes: { label: string; value: number }[] = [
    { label: "Consistency", value: profile.consistency_score },
    { label: "DD Resilience", value: profile.drawdown_resilience_score },
    { label: "Cost Efficiency", value: profile.cost_efficiency_score },
    { label: "Sizing Discipline", value: profile.sizing_discipline_score },
    { label: "Exit Symmetry", value: profile.exit_symmetry_score },
    { label: "Catalyst Align", value: profile.catalyst_alignment_score },
  ];

  const cx = 175;
  const cy = 132;
  const maxR = 86;

  const vertexAt = (idx: number, radiusFraction: number) => {
    const angle = -Math.PI / 2 + (idx * 2 * Math.PI) / 6;
    return {
      x: cx + Math.cos(angle) * maxR * radiusFraction,
      y: cy + Math.sin(angle) * maxR * radiusFraction,
    };
  };

  const ringPolygons = [0.25, 0.5, 0.75, 1.0].map((frac) =>
    axes
      .map((_, idx) => {
        const pt = vertexAt(idx, frac);
        return `${pt.x.toFixed(1)},${pt.y.toFixed(1)}`;
      })
      .join(" "),
  );

  const dataPts = axes.map((ax, idx) =>
    vertexAt(idx, Math.max(0.08, Math.min(1, ax.value / 100))),
  );
  const dataPolygon = dataPts
    .map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`)
    .join(" ");

  return (
    <svg
      viewBox="0 0 350 264"
      className="mt-2 h-auto w-full max-w-[340px] select-none overflow-visible"
      role="img"
      aria-label={`Quant DNA Radar: ${profile.archetype_label}`}
    >
      <defs>
        <radialGradient id="quantDnaFillGrad" cx="50%" cy="50%" r="55%">
          <stop offset="0%" stopColor="var(--signal-champagne)" stopOpacity="0.34" />
          <stop offset="100%" stopColor="var(--signal-emerald)" stopOpacity="0.22" />
        </radialGradient>
      </defs>

      {/* Concentric Hexagonal Rings */}
      {ringPolygons.map((pts, idx) => (
        <polygon
          key={`ring-${idx}`}
          points={pts}
          fill="none"
          stroke="var(--border-strong)"
          strokeWidth={idx === 3 ? "1.2" : "0.9"}
          strokeDasharray={idx < 3 ? "2 2" : undefined}
        />
      ))}

      {/* Radial Spokes */}
      {axes.map((ax, idx) => {
        const outer = vertexAt(idx, 1.0);
        const labelPt = vertexAt(idx, 1.24);
        const anchor =
          Math.abs(labelPt.x - cx) < 10
            ? "middle"
            : labelPt.x > cx
              ? "start"
              : "end";
        return (
          <g key={ax.label}>
            <line
              x1={cx}
              y1={cy}
              x2={outer.x}
              y2={outer.y}
              stroke="var(--chart-axis)"
              strokeWidth="1"
            />
            <text
              x={labelPt.x}
              y={labelPt.y}
              textAnchor={anchor}
              dominantBaseline="middle"
              fill="var(--text-secondary)"
              fontSize="10"
              className="mono-num"
            >
              {ax.label}
            </text>
            <text
              x={labelPt.x}
              y={labelPt.y + 11}
              textAnchor={anchor}
              dominantBaseline="middle"
              fill="var(--signal-emerald)"
              fontSize="9.5"
              fontWeight="700"
              className="mono-num"
            >
              {ax.value.toFixed(0)}
            </text>
          </g>
        );
      })}

      {/* Filled Quant DNA Polygon */}
      <polygon
        points={dataPolygon}
        fill="url(#quantDnaFillGrad)"
        stroke="var(--signal-emerald)"
        strokeWidth="2"
        strokeLinejoin="round"
        className="transition-all duration-500 ease-out"
      />

      {/* Vertex Nodes */}
      {dataPts.map((pt, idx) => (
        <circle
          key={`v-${idx}`}
          cx={pt.x}
          cy={pt.y}
          r="3.8"
          fill="var(--signal-champagne)"
          stroke="var(--bg-panel)"
          strokeWidth="1.5"
        />
      ))}
    </svg>
  );
}

function CounterfactualReplaySvg({
  points,
  hoverStepIdx,
  onHoverStep,
}: {
  points: {
    step: number;
    label: string;
    actual: number;
    simulated: number;
    gapPts: number;
  }[];
  hoverStepIdx: number | null;
  onHoverStep: (idx: number | null) => void;
}) {
  const width = 920;
  const height = 195;
  const padL = 52;
  const padR = 20;
  const padTop = 16;
  const padBot = 26;
  const plotW = width - padL - padR;
  const plotH = height - padTop - padBot;

  const vals: number[] = [100];
  for (const p of points) {
    vals.push(p.actual, p.simulated);
  }
  const minV = Math.min(...vals, 98.5);
  const maxV = Math.max(...vals, 102);
  const span = Math.max(maxV - minV, 1);

  const xAt = (i: number) => padL + (i / Math.max(points.length - 1, 1)) * plotW;
  const yAt = (v: number) => padTop + (1 - (v - minV) / span) * plotH;

  const actualPath = points
    .map((p, i) => `${i === 0 ? "M" : "L"}${xAt(i).toFixed(1)},${yAt(p.actual).toFixed(1)}`)
    .join(" ");
  const simPath = points
    .map(
      (p, i) => `${i === 0 ? "M" : "L"}${xAt(i).toFixed(1)},${yAt(p.simulated).toFixed(1)}`,
    )
    .join(" ");

  const gapRibbonPath = `${points
    .map(
      (p, i) => `${i === 0 ? "M" : "L"}${xAt(i).toFixed(1)},${yAt(p.simulated).toFixed(1)}`,
    )
    .join(" ")} ${[...points]
    .reverse()
    .map((p, revI) => {
      const origI = points.length - 1 - revI;
      return `L${xAt(origI).toFixed(1)},${yAt(p.actual).toFixed(1)}`;
    })
    .join(" ")} Z`;

  const activeIdx = hoverStepIdx != null ? hoverStepIdx : points.length - 1;
  const activePt = points[activeIdx]!;
  const activeX = xAt(activeIdx);

  return (
    <div className="mt-4">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-auto w-full select-none overflow-visible"
        onMouseLeave={() => onHoverStep(null)}
      >
        <defs>
          <linearGradient id="twinGapFill" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="var(--signal-champagne)" stopOpacity="0.1" />
            <stop offset="100%" stopColor="var(--signal-champagne)" stopOpacity="0.28" />
          </linearGradient>
        </defs>

        {[maxV, 100, minV].map((lvl, idx) => (
          <g key={`cf-grid-${idx}`}>
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
              fontSize="10"
              fill="var(--text-muted)"
              className="mono-num"
            >
              {lvl.toFixed(1)}
            </text>
          </g>
        ))}

        {/* Highlighted Recoverable Alpha Gap Ribbon */}
        <path
          d={gapRibbonPath}
          fill="url(#twinGapFill)"
          className="transition-all duration-300"
        />

        {/* Verified Realized Solid Emerald */}
        <path
          d={actualPath}
          fill="none"
          stroke="var(--chart-wealth-stroke)"
          strokeWidth="2.3"
          strokeLinecap="round"
        />

        {/* Hypothetical Disciplined Twin Dashed Champagne */}
        <path
          d={simPath}
          fill="none"
          stroke="var(--chart-twin-stroke)"
          strokeWidth="2.2"
          strokeDasharray="6 4"
          className="transition-all duration-300"
        />

        {/* Active Step Crosshair & Gap Callout */}
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
          cy={yAt(activePt.actual)}
          r="4"
          fill="var(--chart-wealth-stroke)"
          stroke="var(--bg-panel)"
          strokeWidth="1.5"
        />
        <circle
          cx={activeX}
          cy={yAt(activePt.simulated)}
          r="4"
          fill="var(--chart-twin-stroke)"
          stroke="var(--bg-panel)"
          strokeWidth="1.5"
        />

        <text
          x={padL}
          y={height - 6}
          fontSize="10"
          fill="var(--text-muted)"
          className="mono-num"
        >
          {points[0]!.label}
        </text>
        <text
          x={padL + plotW / 2}
          y={height - 6}
          textAnchor="middle"
          fontSize="10"
          fill="var(--signal-champagne)"
          className="mono-num"
        >
          {activePt.label}: Actual {activePt.actual.toFixed(2)} vs Twin{" "}
          {activePt.simulated.toFixed(2)} (+{activePt.gapPts.toFixed(2)} pts)
        </text>
        <text
          x={width - padR}
          y={height - 6}
          textAnchor="end"
          fontSize="10"
          fill="var(--text-muted)"
          className="mono-num"
        >
          {points[points.length - 1]!.label}
        </text>

        {points.map((pt, idx) => {
          const colW = plotW / points.length;
          return (
            <rect
              key={`cf-hit-${pt.step}`}
              x={xAt(idx) - colW / 2}
              y={0}
              width={Math.max(colW, 12)}
              height={height}
              fill="transparent"
              className="cursor-crosshair"
              onMouseEnter={() => onHoverStep(idx)}
            />
          );
        })}
      </svg>
    </div>
  );
}

function DnaScoreChip({ label, score }: { label: string; score: number }) {
  const tone =
    score >= 82
      ? "text-signal-emerald"
      : score >= 65
        ? "text-signal-champagne"
        : "text-signal-ochre";
  return (
    <div className="rounded border border-hairline bg-elevated px-2.5 py-2 font-mono tabular-nums">
      <div className="flex items-center justify-between text-[10px]">
        <span className="text-ink-muted">{label}</span>
        <span className={`font-bold ${tone}`}>{score.toFixed(0)}/100</span>
      </div>
      <div className="mt-1 h-1.5 w-full overflow-hidden rounded-sm bg-subtle">
        <div
          className="h-full bg-signal-emerald transition-all duration-500"
          style={{ width: `${Math.min(Math.max(score, 4), 100)}%` }}
        />
      </div>
    </div>
  );
}

function CatalystIntervalRow({ obs }: { obs: EventWindowObservation }) {
  const meta = ALIGNMENT_META[obs.alignment_class];
  const hasInterval = obs.earliest_public_utc != null && obs.confirmed_public_utc != null;

  return (
    <div className="rounded border border-hairline bg-elevated p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded border border-hairline-strong bg-panel px-2 py-0.5 font-mono text-xs font-bold text-ink">
            {obs.symbol}
          </span>
          <span className="text-xs font-semibold text-ink">{obs.headline_or_event}</span>
        </div>
        <span className={`rounded px-2 py-0.5 font-mono text-[10px] font-semibold ${meta.style}`}>
          {meta.label}
        </span>
      </div>

      {hasInterval && (
        <div className="mt-3">
          <div className="flex justify-between font-mono text-[10px] text-ink-muted tabular-nums">
            <span>Pre-Wire</span>
            <span className="text-signal-ochre">
              t_earliest: {obs.earliest_public_utc!.slice(11, 19)}Z
            </span>
            <span className="text-signal-ochre">
              t_confirmed: {obs.confirmed_public_utc!.slice(11, 19)}Z
            </span>
            <span>Post-Confirmed</span>
          </div>
          <div className="relative mt-1.5 h-3 w-full rounded-sm border border-hairline bg-panel">
            {/* Warm Ochre Uncertainty Interval Band Ie */}
            <div
              className="absolute top-0 bottom-0 border-x border-signal-ochre bg-signal-ochre-bg"
              style={{ left: "32%", width: "36%" }}
            />
            {/* Fill Timestamp Marker */}
            <div
              className={`absolute -top-1 h-5 w-2 -translate-x-1/2 rounded-sm ${meta.markerColor}`}
              style={{ left: `${meta.markerPosPct}%` }}
              title={`Fill UTC: ${obs.trade_timestamp_utc}`}
            />
          </div>
        </div>
      )}

      <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2 text-[11px] text-ink-secondary">
        <span>{obs.timestamp_uncertainty_note}</span>
        <span className="font-mono text-[10px] text-ink-muted tabular-nums">
          fill={obs.trade_timestamp_utc} • wires: {obs.event_sources.join(", ")}
        </span>
      </div>
    </div>
  );
}

function SmallKpi({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-hairline bg-elevated p-2.5">
      <p className="font-mono text-[10px] text-ink-muted">{label}</p>
      <p className="mt-0.5 font-mono text-sm font-semibold text-ink tabular-nums">
        {value}
      </p>
    </div>
  );
}
