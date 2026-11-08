import Link from "next/link";
import {
  fetchActiveRegistryDocument,
  resolveShowcaseOrLiveProfile,
  safeDecodeURIComponent,
} from "@/lib/apiClient.ts";
import { verifyProofBundle } from "@/lib/browserVerify.ts";
import { extractTypedLeaves } from "@/lib/contracts.ts";
import { DEMO_CONTINUITY_LOG_LEAVES } from "@/lib/demoFixtures.ts";
import { sanitizePlainInput } from "@/lib/plausibilityMath.ts";
import { generateQrCode } from "@/lib/qrSvg.ts";
import {
  buildCurveSparklinePaths,
  extractVerifiedCardSummary,
  sanitizeProofIdSegment,
} from "@/lib/viralShareBuilders.ts";

export default async function EmbedProofCardPage({
  params,
  searchParams,
}: {
  params: Promise<{ proofId: string }>;
  searchParams?: Promise<{ theme?: string }>;
}) {
  const { proofId } = await params;
  const resolvedSearch = searchParams ? await searchParams : {};
  const decodedId = safeDecodeURIComponent(proofId);
  const safeDisplayId = sanitizePlainInput(decodedId, 64);
  const [{ registryDoc }, profile] = await Promise.all([
    fetchActiveRegistryDocument(),
    resolveShowcaseOrLiveProfile(decodedId),
  ]);

  if (!profile) {
    return (
      <div className="flex min-h-[240px] items-center justify-center bg-canvas p-4">
        <div className="inst-panel rounded-md p-5 text-center font-mono text-xs text-ink-secondary">
          Proof bundle <strong className="text-ink">{safeDisplayId}</strong> not hosted on
          server (zero-retention default).
        </div>
      </div>
    );
  }

  const bundle = profile.bundle;
  const verified = await verifyProofBundle(bundle, {
    registryDoc,
    chainHistory: profile.chainHistory,
    continuityLogLeaves:
      bundle.proof_id === "prf-inst-alpha-012" ? DEMO_CONTINUITY_LOG_LEAVES : null,
  });

  const summary = extractVerifiedCardSummary(bundle, verified);
  const leaves = extractTypedLeaves(bundle);
  const curve = leaves.indexedCurve;

  const safeId = sanitizeProofIdSegment(bundle.proof_id);
  const safeHandle = sanitizePlainInput(profile.handle, 32);
  const safeTitle = sanitizePlainInput(profile.strategyTitle, 72);
  const forcePaper = resolvedSearch.theme === "paper";

  const qr = generateQrCode(
    `https://verify.n170.io/p/${encodeURIComponent(safeId)}`,
  );

  const { line: sparkLine, area: sparkArea } = buildCurveSparklinePaths(
    summary.valid ? curve : [],
    240,
    68,
    6,
    14,
  );

  return (
    <div
      data-theme={forcePaper ? "paper" : undefined}
      className="bg-canvas p-2.5 sm:p-3.5"
    >
      <div className="inst-panel relative mx-auto max-w-[680px] overflow-hidden rounded-md p-4">
        <div
          className={`absolute inset-x-0 top-0 h-[3px] ${
            summary.valid ? "bg-signal-emerald" : "bg-signal-vermilion"
          }`}
        />

        {/* Header Row */}
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 font-mono text-[10px]">
              <span
                className={`rounded px-1.5 py-0.5 font-semibold uppercase tracking-wider ${
                  summary.valid ? "badge-champagne" : "badge-vermilion"
                }`}
              >
                {summary.headlineStatus}
              </span>
              <span className="font-semibold text-signal-emerald">{safeHandle}</span>
              <span className="text-ink-muted tabular-nums">
                {bundle.period_start_utc.slice(0, 10)} →{" "}
                {bundle.period_end_utc.slice(0, 10)}
              </span>
            </div>
            <h1 className="editorial-serif mt-1 truncate text-xl text-ink sm:text-2xl">
              {safeTitle}
            </h1>
          </div>

          <div className="shrink-0 rounded border border-hairline-strong bg-elevated p-1.5">
            <svg
              viewBox={`-1 -1 ${qr.size + 2} ${qr.size + 2}`}
              className="h-12 w-12 text-ink"
              aria-label="Scan to verify proof bundle"
            >
              <path d={qr.svgPath} fill="currentColor" shapeRendering="crispEdges" />
            </svg>
          </div>
        </div>

        {/* Metrics + Curve Row */}
        <div className="mt-3 grid grid-cols-1 items-end gap-3 sm:grid-cols-12">
          <div className="grid grid-cols-3 gap-2 sm:col-span-7">
            <div className="rounded border border-hairline bg-elevated px-2.5 py-1.5">
              <span className="block font-mono text-[9px] uppercase text-ink-muted">
                Indexed TWR
              </span>
              <span className="mt-0.5 block font-mono text-base font-bold text-signal-emerald tabular-nums">
                {summary.twrLabel}
              </span>
            </div>
            <div className="rounded border border-hairline bg-elevated px-2.5 py-1.5">
              <span className="block font-mono text-[9px] uppercase text-ink-muted">
                PSR (GLM)
              </span>
              <span className="mt-0.5 block font-mono text-xs font-semibold text-ink tabular-nums">
                {summary.psrLabel}
              </span>
            </div>
            <div className="rounded border border-hairline bg-elevated px-2.5 py-1.5">
              <span className="block font-mono text-[9px] uppercase text-ink-muted">
                Max DD
              </span>
              <span className="mt-0.5 block font-mono text-xs font-semibold text-signal-vermilion tabular-nums">
                {summary.maxDdLabel}
              </span>
            </div>
          </div>

          <div className="rounded border border-hairline bg-elevated p-1.5 sm:col-span-5">
            <svg viewBox="0 0 240 68" className="h-11 w-full">
              <defs>
                <linearGradient id="embedWealthFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--chart-wealth-top)" />
                  <stop offset="100%" stopColor="var(--chart-wealth-bottom)" />
                </linearGradient>
              </defs>
              <path d={sparkArea} fill="url(#embedWealthFill)" />
              <path
                d={sparkLine}
                fill="none"
                stroke="var(--chart-wealth-stroke)"
                strokeWidth="2"
              />
            </svg>
          </div>
        </div>

        {/* Footer 4 Orthogonal Verified Trust Chips + Link */}
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-hairline pt-2 font-mono text-[9.5px] text-ink-secondary tabular-nums">
          <div className="flex flex-wrap items-center gap-1.5">
            {summary.chips.map((chip, idx) => (
              <span key={chip.axis} className="inline-flex items-center gap-1.5">
                {idx > 0 && <span className="text-ink-muted">•</span>}
                <span
                  className={
                    chip.tone === "emerald"
                      ? "font-semibold text-signal-emerald"
                      : chip.tone === "champagne"
                        ? "font-semibold text-signal-champagne"
                        : chip.tone === "ochre"
                          ? "font-semibold text-signal-ochre"
                          : chip.tone === "vermilion"
                            ? "font-semibold text-signal-vermilion"
                            : "text-ink-secondary"
                  }
                >
                  {chip.value}
                </span>
              </span>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <span className="text-ink-muted">SHA256 {summary.shortProofHash}</span>
            <Link
              href={`/p/${encodeURIComponent(safeId)}`}
              target="_blank"
              rel="noopener noreferrer"
              className="font-semibold text-signal-emerald underline-offset-4 hover:underline"
            >
              Verify in Browser →
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
