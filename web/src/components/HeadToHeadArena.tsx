"use client";

import {
  AlertTriangle,
  ArrowLeftRight,
  Check,
  Copy,
  ShieldCheck,
  Swords,
} from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { verifyProofBundle } from "@/lib/browserVerify.ts";
import {
  ACCOUNT_SCOPE_META,
  CHAIN_CONTINUITY_META,
  ORIGIN_ASSURANCE_META,
  RECONCILIATION_STATUS_META,
  extractTypedLeaves,
  type BundleVerificationResult,
  type ContinuityLogLeaf,
  type IndexedCurvePoint,
  type PublisherKeyRegistryDocument,
  type VerifyProofBundle,
} from "@/lib/contracts.ts";
import { ARENA_PRESET_MATCHUPS } from "@/lib/demoFixtures.ts";
import { extractVerifiedCardSummary } from "@/lib/viralShareBuilders.ts";
import { fmtNum, fmtPct } from "@/lib/wave4Analytics.ts";

export interface ArenaContenderSpec {
  routeSlug: string;
  handle: string;
  strategyTitle: string;
  brokerDisplay: string;
  bundle: VerifyProofBundle;
  chainHistory: readonly VerifyProofBundle[];
  continuityLogLeaves?: readonly ContinuityLogLeaf[];
}

export interface HeadToHeadArenaProps {
  contenderA: ArenaContenderSpec;
  contenderB: ArenaContenderSpec;
  registryDoc: PublisherKeyRegistryDocument;
}

function sampleCurveAtProgress(
  curve: readonly IndexedCurvePoint[],
  progress: number,
): IndexedCurvePoint | null {
  if (curve.length === 0) return null;
  if (curve.length === 1) return curve[0]!;
  const pos = Math.max(0, Math.min(1, progress)) * (curve.length - 1);
  const idx = Math.round(pos);
  return curve[idx] ?? curve[curve.length - 1]!;
}

export function HeadToHeadArena({
  contenderA,
  contenderB,
  registryDoc,
}: HeadToHeadArenaProps) {
  const [verA, setVerA] = useState<BundleVerificationResult | null>(null);
  const [verB, setVerB] = useState<BundleVerificationResult | null>(null);
  const [hoverStep, setHoverStep] = useState<number | null>(null);
  const [copiedUrl, setCopiedUrl] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const runBoth = async () => {
      const [resA, resB] = await Promise.all([
        verifyProofBundle(contenderA.bundle, {
          registryDoc,
          chainHistory: contenderA.chainHistory,
          continuityLogLeaves: contenderA.continuityLogLeaves ?? null,
        }),
        verifyProofBundle(contenderB.bundle, {
          registryDoc,
          chainHistory: contenderB.chainHistory,
          continuityLogLeaves: contenderB.continuityLogLeaves ?? null,
        }),
      ]);
      if (!cancelled) {
        setVerA(resA);
        setVerB(resB);
      }
    };
    void runBoth();
    return () => {
      cancelled = true;
    };
  }, [contenderA, contenderB, registryDoc]);

  const leavesA = useMemo(
    () => extractTypedLeaves(contenderA.bundle),
    [contenderA.bundle],
  );
  const leavesB = useMemo(
    () => extractTypedLeaves(contenderB.bundle),
    [contenderB.bundle],
  );

  const summaryA = useMemo(
    () => extractVerifiedCardSummary(contenderA.bundle, verA),
    [contenderA.bundle, verA],
  );
  const summaryB = useMemo(
    () => extractVerifiedCardSummary(contenderB.bundle, verB),
    [contenderB.bundle, verB],
  );

  const comparabilityNotices = useMemo(() => {
    const notes: string[] = [];
    if (verA && verB) {
      if (verA.effective_origin_assurance !== verB.effective_origin_assurance) {
        notes.push(
          `Asymmetric Origin Assurance: ${contenderA.handle} is ${
            ORIGIN_ASSURANCE_META[verA.effective_origin_assurance].shortLabel
          } whereas ${contenderB.handle} is ${
            ORIGIN_ASSURANCE_META[verB.effective_origin_assurance].shortLabel
          }.`,
        );
      }
      if (
        verA.assurance_profile.account_scope !==
        verB.assurance_profile.account_scope
      ) {
        notes.push(
          `Sub-Account Survivorship Scope Mismatch: ${
            ACCOUNT_SCOPE_META[verA.assurance_profile.account_scope].shortLabel
          } vs ${
            ACCOUNT_SCOPE_META[verB.assurance_profile.account_scope].shortLabel
          }.`,
        );
      }
      if (
        verA.effective_chain_continuity_mode !==
        verB.effective_chain_continuity_mode
      ) {
        notes.push(
          `Continuity Mode Difference: ${
            CHAIN_CONTINUITY_META[verA.effective_chain_continuity_mode].shortLabel
          } vs ${
            CHAIN_CONTINUITY_META[verB.effective_chain_continuity_mode].shortLabel
          }.`,
        );
      }
    }
    const startA = contenderA.bundle.period_start_utc.slice(0, 10);
    const endA = contenderA.bundle.period_end_utc.slice(0, 10);
    const startB = contenderB.bundle.period_start_utc.slice(0, 10);
    const endB = contenderB.bundle.period_end_utc.slice(0, 10);
    if (startA !== startB || endA !== endB) {
      notes.push(
        `Non-Identical Measurement Windows: ${startA}→${endA} vs ${startB}→${endB} (curves normalized along period progress 0%→100%).`,
      );
    }
    if (
      leavesA.reconciliation?.status === "unexplained_residual" ||
      leavesB.reconciliation?.status === "unexplained_residual"
    ) {
      notes.push(
        "Accounting Reconciliation Warning: at least one contender carries an unexplained NAV residual in its custody ledger.",
      );
    }
    return notes;
  }, [verA, verB, contenderA, contenderB, leavesA, leavesB]);

  const copyArenaPermalink = async () => {
    const origin =
      typeof window !== "undefined" && window.location?.origin
        ? window.location.origin
        : "https://verify.n170.org";
    const url = `${origin}/vs/${encodeURIComponent(contenderA.routeSlug)}/${encodeURIComponent(
      contenderB.routeSlug,
    )}`;
    try {
      await navigator.clipboard.writeText(url);
      setCopiedUrl(true);
      setTimeout(() => setCopiedUrl(false), 1800);
    } catch {
      // Clipboard fallback
    }
  };

  const perfA = leavesA.coreMetrics;
  const perfB = leavesB.coreMetrics;

  const comparisonRows = [
    {
      metric: "Flow-Adjusted Cumulative TWR",
      valA: fmtPct(perfA?.twr_decimal),
      valB: fmtPct(perfB?.twr_decimal),
      winner:
        perfA && perfB
          ? perfA.twr_decimal > perfB.twr_decimal
            ? "A"
            : perfB.twr_decimal > perfA.twr_decimal
              ? "B"
              : null
          : null,
    },
    {
      metric: "Annualized CAGR / ACT-365 XIRR",
      valA: `${fmtPct(perfA?.cagr_decimal, 1)} / ${fmtPct(perfA?.xirr_decimal, 1)}`,
      valB: `${fmtPct(perfB?.cagr_decimal, 1)} / ${fmtPct(perfB?.xirr_decimal, 1)}`,
      winner: null,
    },
    {
      metric: "Peak-to-Trough Max Drawdown",
      valA: perfA ? `-${Math.abs(perfA.max_drawdown_decimal * 100).toFixed(2)}%` : "-",
      valB: perfB ? `-${Math.abs(perfB.max_drawdown_decimal * 100).toFixed(2)}%` : "-",
      winner:
        perfA && perfB
          ? Math.abs(perfA.max_drawdown_decimal) < Math.abs(perfB.max_drawdown_decimal)
            ? "A"
            : Math.abs(perfB.max_drawdown_decimal) < Math.abs(perfA.max_drawdown_decimal)
              ? "B"
              : null
          : null,
    },
    {
      metric: "GLM Unsmoothed Sharpe Ratio",
      valA: fmtNum(perfA?.unsmoothed_sharpe_ratio ?? perfA?.sharpe_ratio),
      valB: fmtNum(perfB?.unsmoothed_sharpe_ratio ?? perfB?.sharpe_ratio),
      winner:
        perfA && perfB
          ? (perfA.unsmoothed_sharpe_ratio ?? 0) >
            (perfB.unsmoothed_sharpe_ratio ?? 0)
            ? "A"
            : (perfB.unsmoothed_sharpe_ratio ?? 0) >
                (perfA.unsmoothed_sharpe_ratio ?? 0)
              ? "B"
              : null
          : null,
    },
    {
      metric: "PSR (GLM Unsmoothed, T>=30 Gate)",
      valA: summaryA.psrLabel,
      valB: summaryB.psrLabel,
      winner:
        perfA?.psr_sample_eligible && !perfB?.psr_sample_eligible
          ? "A"
          : !perfA?.psr_sample_eligible && perfB?.psr_sample_eligible
            ? "B"
            : null,
    },
    {
      metric: "Annualized Friction Drag (bps/yr)",
      valA: leavesA.coaching
        ? `-${leavesA.coaching.cost_drag.annualized_total_drag_bps.toFixed(1)} bps`
        : "-",
      valB: leavesB.coaching
        ? `-${leavesB.coaching.cost_drag.annualized_total_drag_bps.toFixed(1)} bps`
        : "-",
      winner:
        leavesA.coaching && leavesB.coaching
          ? leavesA.coaching.cost_drag.annualized_total_drag_bps <
            leavesB.coaching.cost_drag.annualized_total_drag_bps
            ? "A"
            : "B"
          : null,
    },
    {
      metric: "01 Verified Origin Assurance",
      valA: summaryA.chips[0].value,
      valB: summaryB.chips[0].value,
      winner: null,
    },
    {
      metric: "03 Accounting Reconciliation",
      valA: leavesA.reconciliation
        ? RECONCILIATION_STATUS_META[leavesA.reconciliation.status].shortLabel
        : "Redacted",
      valB: leavesB.reconciliation
        ? RECONCILIATION_STATUS_META[leavesB.reconciliation.status].shortLabel
        : "Redacted",
      winner: null,
    },
    {
      metric: "04 Sub-Account Scope & Chain",
      valA: summaryA.chips[3].value,
      valB: summaryB.chips[3].value,
      winner: null,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Arena Masthead & Matchup Preset Bar */}
      <div className="flex flex-col justify-between gap-4 border-b border-hairline pb-5 lg:flex-row lg:items-end">
        <div>
          <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
            <span className="badge-emerald inline-flex items-center gap-1 rounded px-2 py-0.5 font-semibold uppercase tracking-wider">
              <Swords className="h-3 w-3" />
              Head-to-Head Verified Arena
            </span>
            <span className="text-ink-muted">•</span>
            <span className="text-signal-champagne">
              Dual Browser WebCrypto Ed25519 + Salted Merkle Audit
            </span>
          </div>
          <h1 className="editorial-serif mt-1.5 text-3xl text-ink sm:text-4xl">
            {contenderA.handle} <span className="text-ink-muted">vs.</span>{" "}
            {contenderB.handle}
          </h1>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Link
            href={`/vs/${encodeURIComponent(contenderB.routeSlug)}/${encodeURIComponent(
              contenderA.routeSlug,
            )}`}
            className="inline-flex items-center gap-1.5 rounded border border-hairline-strong bg-panel px-3 py-2 font-mono text-xs text-ink-secondary transition hover:border-signal-champagne hover:text-ink"
          >
            <ArrowLeftRight className="h-3.5 w-3.5 text-signal-champagne" />
            <span>Swap Sides</span>
          </Link>
          <button
            type="button"
            onClick={() => void copyArenaPermalink()}
            className="inline-flex items-center gap-1.5 rounded border border-signal-emerald bg-signal-emerald px-3.5 py-2 font-mono text-xs font-semibold text-canvas transition hover:opacity-90"
          >
            {copiedUrl ? (
              <>
                <Check className="h-3.5 w-3.5" />
                <span>Copied /vs Link</span>
              </>
            ) : (
              <>
                <Copy className="h-3.5 w-3.5" />
                <span>Share Arena Duel</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Preset Matchup Switcher */}
      <div className="inst-panel flex flex-wrap items-center justify-between gap-2 rounded-md p-3 text-xs">
        <span className="font-mono text-[10.5px] font-semibold uppercase tracking-wider text-ink-muted">
          Featured Verified Matchups:
        </span>
        <div className="flex flex-wrap gap-1.5">
          {ARENA_PRESET_MATCHUPS.map((m) => (
            <Link
              key={`${m.slugA}-${m.slugB}`}
              href={`/vs/${m.slugA}/${m.slugB}`}
              className="rounded border border-hairline bg-elevated px-2.5 py-1 font-mono text-[11px] text-ink-secondary transition hover:border-signal-champagne hover:text-ink"
            >
              {m.label}
            </Link>
          ))}
        </div>
      </div>

      {/* Scope / Origin Comparability Governance Banner */}
      {comparabilityNotices.length > 0 && (
        <div className="rounded-md border border-signal-ochre-border bg-signal-ochre-bg p-4 text-xs">
          <div className="flex items-center gap-2 font-mono text-[11px] font-bold uppercase tracking-wider text-signal-ochre">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
            <span>Provenance &amp; Scope Comparability Notice</span>
          </div>
          <ul className="mt-1.5 list-disc space-y-1 pl-5 text-ink-secondary">
            {comparabilityNotices.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Side-by-Side WebCrypto Contender Cards */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <ContenderHeaderCard
          sideLabel="CONTENDER A • EMERALD LINE"
          accent="emerald"
          contender={contenderA}
          summary={summaryA}
        />
        <ContenderHeaderCard
          sideLabel="CONTENDER B • CHAMPAGNE LINE"
          accent="champagne"
          contender={contenderB}
          summary={summaryB}
        />
      </div>

      {/* Split-Screen Synchronized Wealth & Underwater Drawdown Duel SVG */}
      <div className="inst-panel rounded-md p-5">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-hairline pb-3.5">
          <div>
            <p className="font-mono text-[10px] font-semibold uppercase tracking-widest text-signal-emerald">
              Synchronized Indexed-100 Wealth &amp; Underwater Drawdown Duel
            </p>
            <h2 className="editorial-serif mt-0.5 text-xl text-ink sm:text-2xl">
              Rebased Trajectory Comparison (Base = 100.00 • Zero Dollar-NAV Leakage)
            </h2>
          </div>

          <div className="flex items-center gap-4 font-mono text-xs">
            <span className="inline-flex items-center gap-1.5 text-signal-emerald">
              <span className="h-2.5 w-2.5 rounded-full bg-signal-emerald" />
              {contenderA.handle} ({summaryA.twrLabel})
            </span>
            <span className="inline-flex items-center gap-1.5 text-signal-champagne">
              <span className="h-2.5 w-2.5 rounded-full bg-signal-champagne" />
              {contenderB.handle} ({summaryB.twrLabel})
            </span>
          </div>
        </div>

        <DuelWealthDrawdownSvg
          curveA={leavesA.indexedCurve}
          curveB={leavesB.indexedCurve}
          handleA={contenderA.handle}
          handleB={contenderB.handle}
          hoverStep={hoverStep}
          onHoverStep={setHoverStep}
        />
      </div>

      {/* Head-to-Head Metric & Cryptographic Assurance Comparison Table */}
      <div className="inst-panel overflow-hidden rounded-md">
        <div className="border-b border-hairline bg-elevated px-5 py-3.5">
          <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-ink">
            Side-by-Side Econometric &amp; 4-Axis Trust Comparison
          </h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-hairline font-mono text-[10.5px] uppercase tracking-wider text-ink-muted">
              <tr>
                <th className="px-5 py-3">Dimension / Metric</th>
                <th className="px-5 py-3 text-signal-emerald">
                  {contenderA.handle} ({contenderA.bundle.proof_id})
                </th>
                <th className="px-5 py-3 text-signal-champagne">
                  {contenderB.handle} ({contenderB.bundle.proof_id})
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline font-mono tabular-nums">
              {comparisonRows.map((row) => (
                <tr key={row.metric} className="transition hover:bg-elevated/40">
                  <td className="px-5 py-3 font-sans font-medium text-ink-secondary">
                    {row.metric}
                  </td>
                  <td
                    className={`px-5 py-3 ${
                      row.winner === "A"
                        ? "font-bold text-signal-emerald"
                        : "text-ink"
                    }`}
                  >
                    {row.valA}
                  </td>
                  <td
                    className={`px-5 py-3 ${
                      row.winner === "B"
                        ? "font-bold text-signal-champagne"
                        : "text-ink"
                    }`}
                  >
                    {row.valB}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function ContenderHeaderCard({
  sideLabel,
  accent,
  contender,
  summary,
}: {
  sideLabel: string;
  accent: "emerald" | "champagne";
  contender: ArenaContenderSpec;
  summary: ReturnType<typeof extractVerifiedCardSummary>;
}) {
  const topBar =
    accent === "emerald" ? "bg-signal-emerald" : "bg-signal-champagne";
  const accentText =
    accent === "emerald" ? "text-signal-emerald" : "text-signal-champagne";

  return (
    <div className="inst-panel relative overflow-hidden rounded-md p-5">
      <div className={`absolute inset-x-0 top-0 h-[3px] ${topBar}`} />
      <div className="flex items-start justify-between gap-2">
        <div>
          <span className={`font-mono text-[10px] font-semibold uppercase tracking-widest ${accentText}`}>
            {sideLabel}
          </span>
          <h2 className="editorial-serif mt-1 text-2xl text-ink">
            {contender.strategyTitle}
          </h2>
          <p className="font-mono text-xs text-ink-muted tabular-nums">
            {contender.handle} • {contender.brokerDisplay} •{" "}
            {contender.bundle.period_start_utc.slice(0, 10)} →{" "}
            {contender.bundle.period_end_utc.slice(0, 10)}
          </p>
        </div>

        <Link
          href={`/p/${encodeURIComponent(contender.bundle.proof_id)}`}
          className="inline-flex shrink-0 items-center gap-1 rounded border border-hairline-strong bg-elevated px-2.5 py-1.5 font-mono text-[11px] text-ink transition hover:border-signal-emerald"
        >
          <ShieldCheck className="h-3.5 w-3.5 text-signal-emerald" />
          <span>Full Tear Sheet</span>
        </Link>
      </div>

      <div className="mt-4 grid grid-cols-3 gap-2 font-mono tabular-nums">
        <div className="rounded border border-hairline bg-elevated p-2.5">
          <span className="block text-[9.5px] uppercase text-ink-muted">Indexed TWR</span>
          <span className={`mt-0.5 block text-lg font-bold ${accentText}`}>
            {summary.twrLabel}
          </span>
        </div>
        <div className="rounded border border-hairline bg-elevated p-2.5">
          <span className="block text-[9.5px] uppercase text-ink-muted">PSR (GLM)</span>
          <span className="mt-0.5 block text-sm font-semibold text-ink">
            {summary.psrLabel}
          </span>
        </div>
        <div className="rounded border border-hairline bg-elevated p-2.5">
          <span className="block text-[9.5px] uppercase text-ink-muted">Max DD</span>
          <span className="mt-0.5 block text-sm font-semibold text-signal-vermilion">
            {summary.maxDdLabel}
          </span>
        </div>
      </div>

      <div className="mt-3 grid grid-cols-2 gap-1.5 font-mono text-[10px]">
        {summary.chips.map((chip) => (
          <div
            key={chip.axis}
            className="flex items-center justify-between gap-2 rounded border border-hairline bg-elevated/60 px-2.5 py-1.5"
          >
            <span className="text-ink-muted">{chip.indexLabel}</span>
            <span
              className={`truncate font-semibold ${
                chip.tone === "emerald"
                  ? "text-signal-emerald"
                  : chip.tone === "champagne"
                    ? "text-signal-champagne"
                    : chip.tone === "ochre"
                      ? "text-signal-ochre"
                      : chip.tone === "vermilion"
                        ? "text-signal-vermilion"
                        : "text-ink-secondary"
              }`}
            >
              {chip.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function DuelWealthDrawdownSvg({
  curveA,
  curveB,
  handleA,
  handleB,
  hoverStep,
  onHoverStep,
}: {
  curveA: readonly IndexedCurvePoint[];
  curveB: readonly IndexedCurvePoint[];
  handleA: string;
  handleB: string;
  hoverStep: number | null;
  onHoverStep: (idx: number | null) => void;
}) {
  const numSteps = 32;
  const steps = Array.from({ length: numSteps }, (_, idx) => {
    const progress = idx / (numSteps - 1);
    const ptA = sampleCurveAtProgress(curveA, progress);
    const ptB = sampleCurveAtProgress(curveB, progress);
    return {
      idx,
      progressPct: Math.round(progress * 100),
      valA: ptA?.index_value ?? 100,
      ddA: ptA?.drawdown_pct ?? 0,
      valB: ptB?.index_value ?? 100,
      ddB: ptB?.drawdown_pct ?? 0,
    };
  });

  const width = 940;
  const wealthTop = 18;
  const wealthBottom = 186;
  const ddTop = 212;
  const ddBottom = 276;
  const totalHeight = 300;
  const padL = 54;
  const padR = 22;
  const plotW = width - padL - padR;

  const allVals = steps.flatMap((s) => [s.valA, s.valB, 100]);
  const minVal = Math.min(...allVals, 98.5);
  const maxVal = Math.max(...allVals, 102);
  const valSpan = Math.max(maxVal - minVal, 1);

  const minDd = Math.min(...steps.flatMap((s) => [s.ddA, s.ddB]), -1.5);

  const xAt = (i: number) => padL + (i / (numSteps - 1)) * plotW;
  const yWealth = (v: number) =>
    wealthTop + (1 - (v - minVal) / valSpan) * (wealthBottom - wealthTop);
  const yDd = (dd: number) =>
    ddTop + (Math.abs(dd) / Math.abs(minDd)) * (ddBottom - ddTop);

  const pathWealthA = steps
    .map((s, i) => `${i === 0 ? "M" : "L"}${xAt(i).toFixed(1)},${yWealth(s.valA).toFixed(1)}`)
    .join(" ");
  const pathWealthB = steps
    .map((s, i) => `${i === 0 ? "M" : "L"}${xAt(i).toFixed(1)},${yWealth(s.valB).toFixed(1)}`)
    .join(" ");

  const pathDdA = steps
    .map((s, i) => `${i === 0 ? "M" : "L"}${xAt(i).toFixed(1)},${yDd(s.ddA).toFixed(1)}`)
    .join(" ");
  const pathDdB = steps
    .map((s, i) => `${i === 0 ? "M" : "L"}${xAt(i).toFixed(1)},${yDd(s.ddB).toFixed(1)}`)
    .join(" ");

  const activeIdx = hoverStep != null ? hoverStep : numSteps - 1;
  const activeStep = steps[activeIdx]!;
  const activeX = xAt(activeIdx);
  const deltaPts = activeStep.valA - activeStep.valB;

  return (
    <div className="mt-4">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2 font-mono text-xs tabular-nums">
        <span className="text-ink-muted">
          Normalized Horizon Progress: <strong className="text-ink">{activeStep.progressPct}%</strong>
        </span>
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-signal-emerald">
            {handleA}: {activeStep.valA.toFixed(2)} (DD {activeStep.ddA.toFixed(2)}%)
          </span>
          <span className="text-signal-champagne">
            {handleB}: {activeStep.valB.toFixed(2)} (DD {activeStep.ddB.toFixed(2)}%)
          </span>
          <span className="rounded border border-hairline-strong bg-elevated px-2 py-0.5 text-[11px] text-ink">
            Spread: {deltaPts >= 0 ? "+" : ""}
            {deltaPts.toFixed(2)} idx pts
          </span>
        </div>
      </div>

      <svg
        viewBox={`0 0 ${width} ${totalHeight}`}
        className="h-auto w-full select-none overflow-visible"
        onMouseLeave={() => onHoverStep(null)}
      >
        {[maxVal, 100, minVal].map((lvl, idx) => (
          <g key={`vs-grid-${idx}`}>
            <line
              x1={padL}
              x2={width - padR}
              y1={yWealth(lvl)}
              y2={yWealth(lvl)}
              stroke="var(--chart-axis)"
              strokeWidth="1"
            />
            <text
              x={padL - 8}
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

        {/* Contender B & Contender A Wealth Curves */}
        <path
          d={pathWealthB}
          fill="none"
          stroke="var(--signal-champagne)"
          strokeWidth="2.3"
          strokeLinecap="round"
        />
        <path
          d={pathWealthA}
          fill="none"
          stroke="var(--signal-emerald)"
          strokeWidth="2.5"
          strokeLinecap="round"
        />

        {/* Underwater Drawdown Duel Pane */}
        <line
          x1={padL}
          x2={width - padR}
          y1={ddTop}
          y2={ddTop}
          stroke="var(--chart-axis)"
          strokeWidth="1"
        />
        <line
          x1={padL}
          x2={width - padR}
          y1={ddBottom}
          y2={ddBottom}
          stroke="var(--chart-axis)"
          strokeWidth="1"
        />
        <path
          d={pathDdB}
          fill="none"
          stroke="var(--signal-champagne)"
          strokeWidth="1.5"
          strokeDasharray="4 3"
        />
        <path
          d={pathDdA}
          fill="none"
          stroke="var(--signal-emerald)"
          strokeWidth="1.6"
        />

        <text
          x={padL - 8}
          y={ddTop + 8}
          textAnchor="end"
          fontSize="9.5"
          fill="var(--text-muted)"
          className="mono-num"
        >
          0.0%
        </text>
        <text
          x={padL - 8}
          y={ddBottom - 2}
          textAnchor="end"
          fontSize="9.5"
          fill="var(--signal-vermilion)"
          className="mono-num"
        >
          {minDd.toFixed(1)}%
        </text>

        {/* Synchronized Scrubber */}
        <line
          x1={activeX}
          x2={activeX}
          y1={wealthTop}
          y2={ddBottom}
          stroke="var(--chart-crosshair)"
          strokeWidth="1"
        />
        <circle
          cx={activeX}
          cy={yWealth(activeStep.valA)}
          r="4.2"
          fill="var(--signal-emerald)"
          stroke="var(--bg-panel)"
          strokeWidth="1.5"
        />
        <circle
          cx={activeX}
          cy={yWealth(activeStep.valB)}
          r="4.2"
          fill="var(--signal-champagne)"
          stroke="var(--bg-panel)"
          strokeWidth="1.5"
        />

        <text x={padL} y={totalHeight - 5} fontSize="10" fill="var(--text-muted)" className="mono-num">
          0% Period Start (Index 100.0)
        </text>
        <text
          x={padL + plotW / 2}
          y={totalHeight - 5}
          textAnchor="middle"
          fontSize="10"
          fill="var(--text-muted)"
          className="mono-num"
        >
          50% Midpoint
        </text>
        <text
          x={width - padR}
          y={totalHeight - 5}
          textAnchor="end"
          fontSize="10"
          fill="var(--text-muted)"
          className="mono-num"
        >
          100% Period Close
        </text>

        {steps.map((s) => {
          const colW = plotW / numSteps;
          return (
            <rect
              key={`vs-hit-${s.idx}`}
              x={xAt(s.idx) - colW / 2}
              y={0}
              width={Math.max(colW, 10)}
              height={totalHeight}
              fill="transparent"
              className="cursor-crosshair"
              onMouseEnter={() => onHoverStep(s.idx)}
            />
          );
        })}
      </svg>
    </div>
  );
}
