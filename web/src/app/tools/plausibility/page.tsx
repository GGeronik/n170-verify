"use client";

import {
  ArrowRight,
  Calculator,
  Check,
  Copy,
  Share2,
  ShieldCheck,
  Sliders,
} from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useState } from "react";
import {
  ASSET_TAIL_PRESETS,
  MIN_MOMENT_SAMPLE_GATE,
  SufficiencyTier,
  buildPlausibilityQueryString,
  computeClaimPlausibility,
  parsePlausibilityQueryParams,
  type AssetTailPresetId,
} from "@/lib/plausibilityMath.ts";

const VIRAL_SCENARIOS = [
  {
    id: "fintwit_0dte",
    badge: "VIRAL CLAIM #1",
    label: "Sharpe 4.2 in 28 Days (Short-Vol / Options)",
    sharpe: 4.2,
    days: 28,
    preset: "short_vol_options" as AssetTailPresetId,
    skew: -1.5,
    kurt: 6.0,
    bench: 0.5,
    ann: 252,
  },
  {
    id: "crypto_perp_60d",
    badge: "VIRAL CLAIM #2",
    label: "Sharpe 3.4 in 60 Days (Crypto / Futures)",
    sharpe: 3.4,
    days: 60,
    preset: "crypto_futures" as AssetTailPresetId,
    skew: -0.45,
    kurt: 4.5,
    bench: 0.5,
    ann: 365,
  },
  {
    id: "inst_equity_2y",
    badge: "INSTITUTIONAL BENCH",
    label: "Sharpe 2.35 over 380 Days (Equities)",
    sharpe: 2.35,
    days: 380,
    preset: "equities" as AssetTailPresetId,
    skew: -0.25,
    kurt: 1.5,
    bench: 0.5,
    ann: 252,
  },
] as const;

const TIER_META: Record<
  string,
  { badgeClass: string; shortLabel: string; explanation: string }
> = {
  [SufficiencyTier.INSUFFICIENT_TRACK_RECORD_NOISE_DOMINATED]: {
    badgeClass: "badge-vermilion",
    shortLabel: "INSUFFICIENT_TRACK_RECORD_NOISE_DOMINATED",
    explanation:
      "Finite-sample estimation variance dominates at this sample horizon or tail kurtosis.",
  },
  [SufficiencyTier.BORDERLINE_SAMPLE]: {
    badgeClass: "badge-ochre",
    shortLabel: "BORDERLINE_SAMPLE",
    explanation:
      "Promising excess Sharpe, but track record has not yet cleared the 95% non-normal MinTRL threshold.",
  },
  [SufficiencyTier.STATISTICALLY_SUFFICIENT_IF_UNSMOOTHED]: {
    badgeClass: "badge-emerald",
    shortLabel: "STATISTICALLY_SUFFICIENT_IF_UNSMOOTHED",
    explanation:
      "Clears 95% non-normal PSR & MinTRL assuming returns are GLM-unsmoothed and sub-accounts are enumerated.",
  },
};

export default function PlausibilityToolPage() {
  return (
    <Suspense
      fallback={
        <div className="mx-auto max-w-7xl px-4 py-16 font-mono text-xs text-ink-muted">
          Initializing Bailey &amp; López de Prado (2012) Non-Normal PSR &amp; MinTRL Engine…
        </div>
      }
    >
      <PlausibilityCalculatorContent />
    </Suspense>
  );
}

function PlausibilityCalculatorContent() {
  const searchParams = useSearchParams();

  const initial = useMemo(
    () => parsePlausibilityQueryParams(searchParams),
    [searchParams],
  );

  const [claimedSharpe, setClaimedSharpe] = useState(initial.claimedSharpe);
  const [observedPeriods, setObservedPeriods] = useState(initial.observedPeriods);
  const [skewness, setSkewness] = useState(initial.skewness);
  const [excessKurtosis, setExcessKurtosis] = useState(initial.excessKurtosis);
  const [benchmarkSharpe, setBenchmarkSharpe] = useState(initial.benchmarkSharpe);
  const [annualizationFactor, setAnnualizationFactor] = useState(
    initial.annualizationFactor,
  );
  const [activePreset, setActivePreset] =
    useState<AssetTailPresetId>("short_vol_options");
  const [copiedShareUrl, setCopiedShareUrl] = useState(false);

  // Sync state if URL query params change externally
  useEffect(() => {
    setClaimedSharpe(initial.claimedSharpe);
    setObservedPeriods(initial.observedPeriods);
    setSkewness(initial.skewness);
    setExcessKurtosis(initial.excessKurtosis);
    setBenchmarkSharpe(initial.benchmarkSharpe);
    setAnnualizationFactor(initial.annualizationFactor);

    const matched = ASSET_TAIL_PRESETS.find(
      (p) =>
        p.id !== "custom" &&
        Math.abs(p.skewness - initial.skewness) < 0.01 &&
        Math.abs(p.excessKurtosis - initial.excessKurtosis) < 0.01,
    );
    setActivePreset(matched ? matched.id : "custom");
  }, [initial]);

  const analysis = useMemo(
    () =>
      computeClaimPlausibility({
        claimedSharpe,
        observedPeriods,
        skewness,
        excessKurtosis,
        benchmarkSharpe,
        annualizationFactor,
      }),
    [
      claimedSharpe,
      observedPeriods,
      skewness,
      excessKurtosis,
      benchmarkSharpe,
      annualizationFactor,
    ],
  );

  const queryStr = useMemo(
    () =>
      buildPlausibilityQueryString({
        claimedSharpe,
        observedPeriods,
        skewness,
        excessKurtosis,
        benchmarkSharpe,
        annualizationFactor,
      }),
    [
      claimedSharpe,
      observedPeriods,
      skewness,
      excessKurtosis,
      benchmarkSharpe,
      annualizationFactor,
    ],
  );

  const applyPreset = (presetId: AssetTailPresetId) => {
    setActivePreset(presetId);
    const found = ASSET_TAIL_PRESETS.find((p) => p.id === presetId);
    if (found && presetId !== "custom") {
      setSkewness(found.skewness);
      setExcessKurtosis(found.excessKurtosis);
      setAnnualizationFactor(found.annualizationFactor);
    }
  };

  const handleCopyShareLink = async () => {
    const origin =
      typeof window !== "undefined" && window.location?.origin
        ? window.location.origin
        : "https://verify.n170.io";
    const fullUrl = `${origin}/tools/plausibility${queryStr}`;
    try {
      if (typeof window !== "undefined" && window.history?.replaceState) {
        window.history.replaceState(null, "", `/tools/plausibility${queryStr}`);
      }
      await navigator.clipboard.writeText(fullUrl);
      setCopiedShareUrl(true);
      setTimeout(() => setCopiedShareUrl(false), 1800);
    } catch {
      // Ignore clipboard failures in headless browsers
    }
  };

  const tierInfo =
    TIER_META[analysis.sufficiency_tier] ??
    TIER_META[SufficiencyTier.INSUFFICIENT_TRACK_RECORD_NOISE_DOMINATED]!;

  const minTrl = analysis.required_min_trl_periods_95pct;
  const effectiveTargetPeriods =
    minTrl != null ? Math.max(minTrl, MIN_MOMENT_SAMPLE_GATE) : null;
  const minTrlProgressPct =
    effectiveTargetPeriods != null && effectiveTargetPeriods > 0
      ? Math.min(100, (observedPeriods / effectiveTargetPeriods) * 100)
      : 0;

  return (
    <div className="bg-institutional-grid">
      <div className="mx-auto max-w-7xl space-y-6 px-4 py-10 sm:px-6 lg:px-8">
        {/* Masthead */}
        <div className="flex flex-col justify-between gap-4 border-b border-hairline pb-6 lg:flex-row lg:items-end">
          <div className="max-w-3xl space-y-2">
            <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
              <span className="badge-champagne rounded px-2 py-0.5 font-semibold uppercase tracking-wider">
                Zero Login • Instant Econometric Reality Check
              </span>
              <span className="text-ink-muted">•</span>
              <span className="text-signal-emerald">
                Bailey &amp; López de Prado (2012) Non-Normal PSR &amp; MinTRL (95%)
              </span>
            </div>
            <h1 className="editorial-serif text-3xl text-ink sm:text-5xl">
              Track-Record Claim Plausibility &amp; MinTRL Buster
            </h1>
            <p className="text-sm leading-relaxed text-ink-secondary">
              Evaluate whether a claimed annualized Sharpe Ratio is statistically
              distinguishable from benchmark skill{" "}
              <code className="text-ink">SR*</code> given track-record length{" "}
              <code className="text-ink">T</code>, return skewness{" "}
              <code className="text-ink">γ₃</code>, and excess tail kurtosis{" "}
              <code className="text-ink">γ₄ − 3</code>.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              onClick={() => void handleCopyShareLink()}
              className="inline-flex items-center gap-1.5 rounded border border-signal-emerald bg-signal-emerald px-4 py-2.5 font-mono text-xs font-semibold text-canvas transition hover:opacity-90"
            >
              {copiedShareUrl ? (
                <>
                  <Check className="h-3.5 w-3.5" />
                  <span>Copied Shareable Debate URL</span>
                </>
              ) : (
                <>
                  <Share2 className="h-3.5 w-3.5" />
                  <span>1-Click Share Debate Link</span>
                </>
              )}
            </button>
            <Link
              href={`/challenge?claim=${encodeURIComponent(
                `Sharpe ${claimedSharpe.toFixed(2)} (${observedPeriods}d)`,
              )}`}
              className="inline-flex items-center gap-1.5 rounded border border-hairline-strong bg-panel px-3.5 py-2.5 font-mono text-xs text-ink transition hover:border-signal-champagne"
            >
              <span>Generate Polite Invite</span>
              <ArrowRight className="h-3.5 w-3.5 text-signal-champagne" />
            </Link>
          </div>
        </div>

        {/* 1-Click Viral Fintwit / Reddit Scenario Presets */}
        <div className="inst-panel flex flex-wrap items-center justify-between gap-2 rounded-md p-3.5">
          <span className="inline-flex items-center gap-1.5 font-mono text-[11px] font-semibold uppercase tracking-wider text-signal-champagne">
            <Calculator className="h-3.5 w-3.5" />
            <span>1-Click Debate Scenarios:</span>
          </span>
          <div className="flex flex-wrap gap-2">
            {VIRAL_SCENARIOS.map((sc) => (
              <button
                key={sc.id}
                type="button"
                onClick={() => {
                  setClaimedSharpe(sc.sharpe);
                  setObservedPeriods(sc.days);
                  setActivePreset(sc.preset);
                  setSkewness(sc.skew);
                  setExcessKurtosis(sc.kurt);
                  setBenchmarkSharpe(sc.bench);
                  setAnnualizationFactor(sc.ann);
                }}
                className="rounded border border-hairline-strong bg-elevated px-3 py-1.5 font-mono text-[11px] text-ink-secondary transition hover:border-signal-emerald hover:text-ink tabular-nums"
              >
                <span className="mr-1.5 text-[10px] font-semibold text-signal-champagne">
                  [{sc.badge}]
                </span>
                {sc.label}
              </button>
            ))}
          </div>
        </div>

        {/* Main 12-Column Interactive Split */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          {/* Left 5 Columns: Sliders & Asset-Class Tail Presets */}
          <div className="inst-panel space-y-5 rounded-md p-5 lg:col-span-5">
            <div className="flex items-center justify-between border-b border-hairline pb-3">
              <div className="flex items-center gap-2">
                <Sliders className="h-4 w-4 text-signal-champagne" />
                <h2 className="text-sm font-semibold tracking-telemetry text-ink">
                  Claim &amp; Tail-Risk Parameters
                </h2>
              </div>
              <span className="font-mono text-[10.5px] text-ink-muted tabular-nums">
                N_ann = {annualizationFactor}/yr
              </span>
            </div>

            {/* Slider 1: Claimed Annualized Sharpe */}
            <SliderField
              label="Claimed Annualized Sharpe (SR̂)"
              valueLabel={claimedSharpe.toFixed(2)}
              accent="emerald"
              min={-1.0}
              max={8.0}
              step={0.05}
              value={claimedSharpe}
              onChange={setClaimedSharpe}
              sub="Reported annualized Sharpe ratio before higher-moment variance penalty"
            />

            {/* Slider 2: Track-Record Days (T) */}
            <SliderField
              label="Track-Record Observations (T Days)"
              valueLabel={`T = ${observedPeriods} days`}
              accent={observedPeriods < MIN_MOMENT_SAMPLE_GATE ? "ochre" : "emerald"}
              min={5}
              max={1000}
              step={1}
              value={observedPeriods}
              onChange={setObservedPeriods}
              sub="Minimum T >= 30 required for stable 3rd/4th return moment estimation"
            />

            {/* Asset-Class Tail Presets */}
            <div className="space-y-2 border-t border-hairline pt-4">
              <span className="block font-mono text-[10.5px] font-semibold uppercase tracking-wider text-signal-champagne">
                Asset-Class Higher-Moment Tail Presets
              </span>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {ASSET_TAIL_PRESETS.map((preset) => {
                  const isSel = activePreset === preset.id;
                  return (
                    <button
                      key={preset.id}
                      type="button"
                      onClick={() => applyPreset(preset.id)}
                      className={`rounded border p-2.5 text-left font-mono transition ${
                        isSel
                          ? "border-signal-champagne bg-signal-champagne-bg text-ink"
                          : "border-hairline bg-elevated text-ink-secondary hover:border-ink-muted"
                      }`}
                    >
                      <span className="block text-[11px] font-semibold text-ink">
                        {preset.label}
                      </span>
                      {preset.id !== "custom" && (
                        <span className="mt-0.5 block text-[10px] text-ink-muted tabular-nums">
                          skew {preset.skewness.toFixed(2)} • kurt{" "}
                          {preset.excessKurtosis.toFixed(1)} • N={preset.annualizationFactor}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
              <p className="text-[11px] leading-relaxed text-ink-muted">
                {ASSET_TAIL_PRESETS.find((p) => p.id === activePreset)?.note}
              </p>
            </div>

            {/* Custom Skewness & Excess Kurtosis Sliders */}
            <div className="grid grid-cols-1 gap-4 border-t border-hairline pt-4 sm:grid-cols-2">
              <SliderField
                label="Return Skewness (γ₃)"
                valueLabel={skewness.toFixed(2)}
                accent={skewness < -0.5 ? "vermilion" : "ink"}
                min={-4.0}
                max={3.0}
                step={0.05}
                value={skewness}
                onChange={(val) => {
                  setActivePreset("custom");
                  setSkewness(val);
                }}
              />
              <SliderField
                label="Excess Kurtosis (γ₄ − 3)"
                valueLabel={excessKurtosis.toFixed(2)}
                accent={excessKurtosis > 3.0 ? "ochre" : "ink"}
                min={-1.5}
                max={16.0}
                step={0.1}
                value={excessKurtosis}
                onChange={(val) => {
                  setActivePreset("custom");
                  setExcessKurtosis(val);
                }}
              />
            </div>

            {/* Slider 5: Benchmark Sharpe SR* */}
            <div className="border-t border-hairline pt-4">
              <SliderField
                label="Skill Hurdle Benchmark Sharpe (SR*)"
                valueLabel={`SR* = ${benchmarkSharpe.toFixed(2)}`}
                accent="champagne"
                min={0.0}
                max={2.5}
                step={0.05}
                value={benchmarkSharpe}
                onChange={setBenchmarkSharpe}
                sub="Null-hypothesis Sharpe hurdle (0.00 = zero-skill, 0.50 = passive equity risk premium)"
              />
            </div>
          </div>

          {/* Right 7 Columns: Animated PSR Gauge + MinTRL Countdown + Bell Curve SVG */}
          <div className="space-y-5 lg:col-span-7">
            {/* Sufficiency Tier Banner */}
            <div className="inst-panel space-y-3 rounded-md p-5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono text-[10.5px] font-semibold uppercase tracking-widest text-ink-muted">
                  Neutral Statistical Sufficiency Verdict
                </span>
                <span
                  className={`rounded px-2.5 py-1 font-mono text-[11px] font-bold tracking-wider ${tierInfo.badgeClass}`}
                >
                  {tierInfo.shortLabel}
                </span>
              </div>
              <p className="text-sm leading-relaxed text-ink">
                {analysis.plain_english_summary}
              </p>
              <p className="text-[11.5px] text-ink-muted">{tierInfo.explanation}</p>
            </div>

            {/* Gauge + MinTRL Countdown Grid */}
            <div className="grid grid-cols-1 gap-5 md:grid-cols-12">
              {/* Animated Semicircular PSR Confidence Gauge */}
              <div className="inst-panel flex flex-col items-center justify-between rounded-md p-5 md:col-span-5">
                <div className="w-full text-left">
                  <p className="font-mono text-[10px] font-semibold uppercase tracking-widest text-signal-emerald">
                    Implied Non-Normal PSR
                  </p>
                  <h3 className="mt-0.5 text-xs font-semibold text-ink">
                    P(True SR &gt; SR* = {benchmarkSharpe.toFixed(2)})
                  </h3>
                </div>

                <PsrConfidenceGaugeSvg psr={analysis.implied_psr} />

                <div className="w-full rounded border border-hairline bg-elevated px-3 py-2 text-center font-mono text-[10.5px] text-ink-secondary tabular-nums">
                  95.0% Institutional Threshold:{" "}
                  <strong
                    className={
                      analysis.implied_psr >= 0.95 &&
                      observedPeriods >= MIN_MOMENT_SAMPLE_GATE
                        ? "text-signal-emerald"
                        : "text-signal-ochre"
                    }
                  >
                    {analysis.implied_psr >= 0.95 &&
                    observedPeriods >= MIN_MOMENT_SAMPLE_GATE
                      ? "CLEARED"
                      : "NOT YET CLEARED"}
                  </strong>
                </div>
              </div>

              {/* MinTRL (95%) Countdown Progress Card */}
              <div className="inst-panel flex flex-col justify-between space-y-4 rounded-md p-5 md:col-span-7">
                <div>
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <p className="font-mono text-[10px] font-semibold uppercase tracking-widest text-signal-champagne">
                        Minimum Track Record Length
                      </p>
                      <h3 className="mt-0.5 text-sm font-semibold text-ink">
                        Required 95% MinTRL Countdown
                      </h3>
                    </div>
                    <span className="font-mono text-lg font-bold text-signal-champagne tabular-nums">
                      {minTrl != null ? `${Math.ceil(minTrl)} periods` : "∞ (SR ≤ SR*)"}
                    </span>
                  </div>

                  {/* Animated Progress Bar */}
                  <div className="mt-4 space-y-1.5 font-mono text-xs tabular-nums">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-ink-secondary">
                        Observed: <strong className="text-ink">T = {observedPeriods}</strong>
                      </span>
                      <span className="text-ink-secondary">
                        Target (max of MinTRL, T&ge;30):{" "}
                        <strong className="text-signal-champagne">
                          {effectiveTargetPeriods != null
                            ? `${Math.ceil(effectiveTargetPeriods)}p`
                            : "Unreachable"}
                        </strong>
                      </span>
                    </div>

                    <div className="relative h-3.5 w-full overflow-hidden rounded-sm border border-hairline bg-elevated">
                      <div
                        className={`h-full transition-all duration-500 ease-out ${
                          minTrlProgressPct >= 100
                            ? "bg-signal-emerald"
                            : minTrlProgressPct >= 60
                              ? "bg-signal-champagne"
                              : "bg-signal-vermilion"
                        }`}
                        style={{ width: `${minTrlProgressPct}%` }}
                      />
                    </div>

                    <div className="flex justify-between text-[10.5px] text-ink-muted">
                      <span>{minTrlProgressPct.toFixed(1)}% of required horizon</span>
                      {effectiveTargetPeriods != null &&
                      observedPeriods < effectiveTargetPeriods ? (
                        <span className="text-signal-ochre">
                          {Math.ceil(effectiveTargetPeriods - observedPeriods)} more periods
                          needed
                        </span>
                      ) : effectiveTargetPeriods != null ? (
                        <span className="text-signal-emerald">Horizon satisfied</span>
                      ) : null}
                    </div>
                  </div>
                </div>

                <div className="rounded border border-hairline bg-elevated p-3 font-mono text-[10.5px] leading-relaxed text-ink-secondary tabular-nums">
                  Formula:{" "}
                  <code className="text-ink">
                    MinTRL = 1 + [1 − γ₃·SR_p + ((γ₄−1)/4)·SR_p²] · (Z_0.95 / (SR_p −
                    SR*_p))²
                  </code>
                  . Negative skewness and fat tails directly stretch required track-record
                  length.
                </div>
              </div>
            </div>

            {/* Sampling Distribution Bell Curve vs SR* */}
            <div className="inst-panel space-y-3 rounded-md p-5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <p className="font-mono text-[10px] font-semibold uppercase tracking-widest text-signal-emerald">
                    Finite-Sample Sharpe Estimator Density
                  </p>
                  <h3 className="mt-0.5 text-sm font-semibold text-ink">
                    Sampling Distribution of SR̂ vs. Benchmark Hurdle SR* (
                    {benchmarkSharpe.toFixed(2)})
                  </h3>
                </div>
                <span className="font-mono text-[11px] text-ink-muted tabular-nums">
                  Emerald Area = PSR ({(analysis.implied_psr * 100).toFixed(1)}%)
                </span>
              </div>

              <SamplingBellCurveSvg
                points={analysis.bell_curve_points}
                claimedSharpe={claimedSharpe}
                benchmarkSharpe={benchmarkSharpe}
              />

              {/* Shareable URL Box + Governance Note */}
              <div className="flex flex-col justify-between gap-3 border-t border-hairline pt-3 sm:flex-row sm:items-center">
                <div className="min-w-0 font-mono text-[11px] text-ink-muted">
                  Shareable Query:{" "}
                  <code className="text-signal-emerald">
                    /tools/plausibility{queryStr}
                  </code>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <button
                    type="button"
                    onClick={() => void handleCopyShareLink()}
                    className="inline-flex items-center gap-1 rounded border border-hairline-strong bg-elevated px-2.5 py-1.5 font-mono text-[11px] text-ink transition hover:border-signal-emerald"
                  >
                    {copiedShareUrl ? (
                      <Check className="h-3 w-3 text-signal-emerald" />
                    ) : (
                      <Copy className="h-3 w-3" />
                    )}
                    <span>{copiedShareUrl ? "Copied" : "Copy Permalink"}</span>
                  </button>
                  <Link
                    href="/connect"
                    className="inline-flex items-center gap-1 rounded border border-signal-emerald-border bg-signal-emerald-bg px-2.5 py-1.5 font-mono text-[11px] font-semibold text-signal-emerald transition hover:border-signal-emerald"
                  >
                    <ShieldCheck className="h-3.5 w-3.5" />
                    <span>Verify Real Ledger →</span>
                  </Link>
                </div>
              </div>
            </div>

            <p className="rounded border border-hairline bg-panel p-3.5 text-[11px] leading-relaxed text-ink-muted">
              <strong className="text-ink-secondary">Econometric Scope Note:</strong> This
              calculator evaluates single-series non-normal{" "}
              <code className="text-ink">PSR</code> and{" "}
              <code className="text-ink">MinTRL (95%)</code> per Bailey &amp; López de Prado
              (2012). N170 Verify never fabricates a single-account Deflated Sharpe Ratio
              from an unobserved multi-trial count; selection &amp; survivorship bias are
              addressed structurally via sub-account enumeration and prospective hash-chain
              continuity.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function SliderField({
  label,
  valueLabel,
  min,
  max,
  step,
  value,
  onChange,
  accent = "ink",
  sub,
}: {
  label: string;
  valueLabel: string;
  min: number;
  max: number;
  step: number;
  value: number;
  onChange: (next: number) => void;
  accent?: "emerald" | "champagne" | "ochre" | "vermilion" | "ink";
  sub?: string;
}) {
  const valTone =
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
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2 font-mono text-xs tabular-nums">
        <span className="text-ink-secondary">{label}</span>
        <span className={`font-bold ${valTone}`}>{valueLabel}</span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="inst-slider"
      />
      {sub && <p className="text-[10.5px] text-ink-muted">{sub}</p>}
    </div>
  );
}

function PsrConfidenceGaugeSvg({ psr }: { psr: number }) {
  const clamped = Math.max(0, Math.min(1, psr));
  const cx = 120;
  const cy = 112;
  const r = 84;

  const arcPoint = (fraction: number) => {
    const angle = Math.PI - fraction * Math.PI;
    return {
      x: cx + r * Math.cos(angle),
      y: cy - r * Math.sin(angle),
    };
  };

  const start = arcPoint(0);
  const end = arcPoint(1);
  const current = arcPoint(clamped);
  const tick95 = arcPoint(0.95);
  const tick95Outer = {
    x: cx + (r + 9) * Math.cos(Math.PI - 0.95 * Math.PI),
    y: cy - (r + 9) * Math.sin(Math.PI - 0.95 * Math.PI),
  };

  const bgArc = `M ${start.x.toFixed(1)},${start.y.toFixed(1)} A ${r},${r} 0 0 1 ${end.x.toFixed(
    1,
  )},${end.y.toFixed(1)}`;
  const valArc =
    clamped > 0.002
      ? `M ${start.x.toFixed(1)},${start.y.toFixed(1)} A ${r},${r} 0 0 1 ${current.x.toFixed(
          1,
        )},${current.y.toFixed(1)}`
      : "";

  const strokeColor =
    clamped >= 0.95
      ? "var(--signal-emerald)"
      : clamped >= 0.8
        ? "var(--signal-champagne)"
        : "var(--signal-vermilion)";

  return (
    <svg
      viewBox="0 0 240 136"
      className="my-1 h-auto w-full max-w-[230px] select-none overflow-visible"
      role="img"
      aria-label={`Implied PSR ${(clamped * 100).toFixed(1)}%`}
    >
      <path
        d={bgArc}
        fill="none"
        stroke="var(--bg-subtle)"
        strokeWidth="12"
        strokeLinecap="round"
      />
      {valArc && (
        <path
          d={valArc}
          fill="none"
          stroke={strokeColor}
          strokeWidth="12"
          strokeLinecap="round"
          className="transition-all duration-300 ease-out"
        />
      )}

      {/* 95% Institutional Threshold Marker */}
      <line
        x1={tick95.x}
        y1={tick95.y}
        x2={tick95Outer.x}
        y2={tick95Outer.y}
        stroke="var(--signal-champagne)"
        strokeWidth="2"
      />
      <text
        x={tick95Outer.x + 3}
        y={tick95Outer.y - 2}
        fontSize="9"
        fill="var(--signal-champagne)"
        className="mono-num"
      >
        95%
      </text>

      <text
        x={cx}
        y={cy - 16}
        textAnchor="middle"
        fontSize="28"
        fontWeight="700"
        fill={strokeColor}
        className="mono-num"
      >
        {(clamped * 100).toFixed(1)}%
      </text>
      <text
        x={cx}
        y={cy + 4}
        textAnchor="middle"
        fontSize="10"
        fill="var(--text-muted)"
        className="mono-num"
      >
        IMPLIED PSR
      </text>
    </svg>
  );
}

function SamplingBellCurveSvg({
  points,
  claimedSharpe,
  benchmarkSharpe,
}: {
  points: { sharpe: number; density: number }[];
  claimedSharpe: number;
  benchmarkSharpe: number;
}) {
  if (points.length < 3) return null;

  const width = 680;
  const height = 185;
  const padL = 36;
  const padR = 24;
  const padTop = 18;
  const padBot = 28;
  const plotW = width - padL - padR;
  const plotH = height - padTop - padBot;

  const minSr = points[0]!.sharpe;
  const maxSr = points[points.length - 1]!.sharpe;
  const srSpan = Math.max(maxSr - minSr, 0.2);
  const maxDensity = Math.max(...points.map((p) => p.density), 0.01);

  const xAt = (sr: number) =>
    padL + ((Math.max(minSr, Math.min(maxSr, sr)) - minSr) / srSpan) * plotW;
  const yAt = (d: number) => padTop + (1 - d / maxDensity) * plotH;
  const baseLineY = padTop + plotH;

  const curvePath = points
    .map(
      (p, i) => `${i === 0 ? "M" : "L"}${xAt(p.sharpe).toFixed(1)},${yAt(p.density).toFixed(1)}`,
    )
    .join(" ");

  const abovePts = points.filter((p) => p.sharpe >= benchmarkSharpe);
  const belowPts = points.filter((p) => p.sharpe <= benchmarkSharpe);

  const benchX = xAt(benchmarkSharpe);
  const claimedX = xAt(claimedSharpe);

  const aboveArea =
    abovePts.length >= 2
      ? `M${benchX.toFixed(1)},${baseLineY} ${abovePts
          .map((p) => `L${xAt(p.sharpe).toFixed(1)},${yAt(p.density).toFixed(1)}`)
          .join(" ")} L${xAt(abovePts[abovePts.length - 1]!.sharpe).toFixed(
          1,
        )},${baseLineY} Z`
      : null;

  const belowArea =
    belowPts.length >= 2
      ? `M${xAt(belowPts[0]!.sharpe).toFixed(1)},${baseLineY} ${belowPts
          .map((p) => `L${xAt(p.sharpe).toFixed(1)},${yAt(p.density).toFixed(1)}`)
          .join(" ")} L${benchX.toFixed(1)},${baseLineY} Z`
      : null;

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      className="h-auto w-full select-none overflow-visible"
      role="img"
      aria-label="Sharpe Ratio Sampling Distribution vs Benchmark SR*"
    >
      <defs>
        <linearGradient id="psrPassArea" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--signal-emerald)" stopOpacity="0.34" />
          <stop offset="100%" stopColor="var(--signal-emerald)" stopOpacity="0.04" />
        </linearGradient>
        <linearGradient id="psrNoiseArea" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--signal-vermilion)" stopOpacity="0.28" />
          <stop offset="100%" stopColor="var(--signal-vermilion)" stopOpacity="0.04" />
        </linearGradient>
      </defs>

      <line
        x1={padL}
        x2={width - padR}
        y1={baseLineY}
        y2={baseLineY}
        stroke="var(--chart-axis)"
        strokeWidth="1"
      />

      {belowArea && <path d={belowArea} fill="url(#psrNoiseArea)" />}
      {aboveArea && <path d={aboveArea} fill="url(#psrPassArea)" />}

      <path
        d={curvePath}
        fill="none"
        stroke="var(--text-primary)"
        strokeWidth="2"
        strokeLinecap="round"
      />

      {/* Benchmark Hurdle SR* Vertical Hairline */}
      <line
        x1={benchX}
        x2={benchX}
        y1={padTop - 4}
        y2={baseLineY}
        stroke="var(--signal-champagne)"
        strokeWidth="1.6"
        strokeDasharray="4 3"
      />
      <text
        x={benchX}
        y={padTop - 7}
        textAnchor="middle"
        fontSize="10"
        fontWeight="700"
        fill="var(--signal-champagne)"
        className="mono-num"
      >
        SR* = {benchmarkSharpe.toFixed(2)}
      </text>

      {/* Claimed Sharpe Mean Vertical Hairline */}
      <line
        x1={claimedX}
        x2={claimedX}
        y1={padTop + 6}
        y2={baseLineY}
        stroke="var(--signal-emerald)"
        strokeWidth="1.6"
      />
      <text
        x={claimedX}
        y={baseLineY + 16}
        textAnchor="middle"
        fontSize="10"
        fontWeight="700"
        fill="var(--signal-emerald)"
        className="mono-num"
      >
        SR̂ = {claimedSharpe.toFixed(2)}
      </text>

      <text
        x={padL}
        y={baseLineY + 16}
        fontSize="9.5"
        fill="var(--text-muted)"
        className="mono-num"
      >
        {minSr.toFixed(1)}
      </text>
      <text
        x={width - padR}
        y={baseLineY + 16}
        textAnchor="end"
        fontSize="9.5"
        fill="var(--text-muted)"
        className="mono-num"
      >
        {maxSr.toFixed(1)}
      </text>
    </svg>
  );
}
