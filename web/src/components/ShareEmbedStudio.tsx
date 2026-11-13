"use client";

import {
  Check,
  Code2,
  Copy,
  Download,
  ExternalLink,
  MessageSquare,
  QrCode,
  Smartphone,
  Swords,
  Tv,
} from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { useTheme } from "@/components/ThemeProvider.tsx";
import { renderArchivalBadgeSvg } from "@/lib/badgeSvg.ts";
import {
  extractTypedLeaves,
  type BundleVerificationResult,
  type VerifyProofBundle,
} from "@/lib/contracts.ts";
import { generateQrCode } from "@/lib/qrSvg.ts";
import {
  buildCurveSparklinePaths,
  buildDiscordVerifyEmbedJson,
  buildMarkdownBadgeSnippet,
  buildSubstackNotionIframeSnippet,
  extractVerifiedCardSummary,
  renderShareCard16x9Svg,
  renderShareCard9x16Svg,
  sanitizeOriginUrl,
  sanitizeProofIdSegment,
} from "@/lib/viralShareBuilders.ts";

export interface ShareEmbedStudioProps {
  bundle: VerifyProofBundle;
  verification: BundleVerificationResult | null;
  title?: string;
  handle?: string;
}

type AspectMode = "16:9" | "9:16";

export function ShareEmbedStudio({
  bundle,
  verification,
  title,
  handle,
}: ShareEmbedStudioProps) {
  const { theme } = useTheme();
  const [aspect, setAspect] = useState<AspectMode>("16:9");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const leaves = useMemo(() => extractTypedLeaves(bundle), [bundle]);
  const curve = leaves.indexedCurve;

  const originStr =
    typeof window !== "undefined" && window.location?.origin
      ? sanitizeOriginUrl(window.location.origin)
      : "https://verify.n170.org";
  const safeProofId = sanitizeProofIdSegment(bundle.proof_id);
  const permalinkUrl = `${originStr}/p/${encodeURIComponent(safeProofId)}`;

  // Strictly bound to WebCrypto verification: never echoes unverified bundle claims
  const cardSummary = useMemo(
    () => extractVerifiedCardSummary(bundle, verification),
    [bundle, verification],
  );

  const qr = useMemo(() => generateQrCode(permalinkUrl), [permalinkUrl]);

  const badgeSvgRaw = useMemo(() => {
    if (!verification) return "";
    return renderArchivalBadgeSvg(bundle, verification, theme);
  }, [bundle, verification, theme]);

  const activeCardSvgRaw = useMemo(() => {
    const opts = { theme, title, handle, originUrl: originStr };
    return aspect === "16:9"
      ? renderShareCard16x9Svg(bundle, verification, opts)
      : renderShareCard9x16Svg(bundle, verification, opts);
  }, [aspect, bundle, verification, theme, title, handle, originStr]);

  const markdownSnippet = useMemo(
    () => buildMarkdownBadgeSnippet(bundle.proof_id, originStr, theme),
    [bundle.proof_id, originStr, theme],
  );

  const discordEmbedJson = useMemo(
    () =>
      buildDiscordVerifyEmbedJson(bundle, verification, {
        theme,
        title,
        handle,
        originUrl: originStr,
      }),
    [bundle, verification, theme, title, handle, originStr],
  );

  const { iframeHtml: iframeSnippet } = useMemo(
    () => buildSubstackNotionIframeSnippet(bundle.proof_id, originStr, theme),
    [bundle.proof_id, originStr, theme],
  );

  const copyText = async (id: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedId(id);
      setTimeout(() => {
        setCopiedId((prev) => (prev === id ? null : prev));
      }, 1800);
    } catch {
      // Clipboard fallback
    }
  };

  const downloadActiveCardSvg = () => {
    if (!activeCardSvgRaw) return;
    const blob = new Blob([activeCardSvgRaw], {
      type: "image/svg+xml;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${safeProofId}-${aspect === "16:9" ? "16x9" : "9x16"}-card.svg`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  // Build crisp SVG sparkline path from Indexed-100 points
  const sparkPath = useMemo(
    () => buildCurveSparklinePaths(cardSummary.valid ? curve : [], 260, 76, 6, 14),
    [cardSummary.valid, curve],
  );

  const chipColorClass = (
    tone: "emerald" | "champagne" | "ochre" | "vermilion" | "neutral",
  ) =>
    tone === "emerald"
      ? "text-signal-emerald"
      : tone === "champagne"
        ? "text-signal-champagne"
        : tone === "ochre"
          ? "text-signal-ochre"
          : tone === "vermilion"
            ? "text-signal-vermilion"
            : "text-ink-secondary";

  const opponentId =
    safeProofId === "prf-xray-residual-004"
      ? "demo-tls-alpha"
      : "demo-ibkr-flex";

  return (
    <div className="space-y-6">
      {/* Studio Header & Aspect Selector */}
      <div className="inst-panel flex flex-col justify-between gap-4 rounded-md p-5 sm:flex-row sm:items-center">
        <div>
          <p className="font-mono text-[10px] font-semibold uppercase tracking-widest text-signal-champagne">
            Share &amp; Viral Export Studio
          </p>
          <h3 className="editorial-serif mt-0.5 text-2xl text-ink">
            16:9 &amp; 9:16 Cryptographic Tear Cards, Discord /verify JSON &amp; Embeds
          </h3>
          <p className="mt-1 text-xs text-ink-secondary">
            All 4 orthogonal trust chips bind strictly to browser{" "}
            <code className="text-ink">window.crypto.subtle</code> verification: zero
            unverified bundle claims, zero exact dollar balances.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="inline-flex rounded border border-hairline-strong bg-elevated p-0.5 font-mono text-xs">
            <button
              type="button"
              onClick={() => setAspect("16:9")}
              className={`inline-flex items-center gap-1.5 rounded-sm px-3 py-1.5 transition ${
                aspect === "16:9"
                  ? "bg-panel text-ink shadow-[inset_0_0_0_1px_var(--border-strong)]"
                  : "text-ink-muted hover:text-ink"
              }`}
            >
              <Tv className="h-3.5 w-3.5 text-signal-champagne" />
              <span>16:9 X / LinkedIn</span>
            </button>
            <button
              type="button"
              onClick={() => setAspect("9:16")}
              className={`inline-flex items-center gap-1.5 rounded-sm px-3 py-1.5 transition ${
                aspect === "9:16"
                  ? "bg-panel text-ink shadow-[inset_0_0_0_1px_var(--border-strong)]"
                  : "text-ink-muted hover:text-ink"
              }`}
            >
              <Smartphone className="h-3.5 w-3.5 text-signal-champagne" />
              <span>9:16 Stories / Reels</span>
            </button>
          </div>

          <Link
            href={`/embed/${encodeURIComponent(safeProofId)}`}
            target="_blank"
            className="inline-flex items-center gap-1.5 rounded border border-hairline-strong bg-panel px-3 py-1.5 font-mono text-xs text-ink-secondary transition hover:border-signal-champagne hover:text-ink"
          >
            <ExternalLink className="h-3.5 w-3.5" />
            <span>Preview /embed</span>
          </Link>

          <Link
            href={`/vs/${encodeURIComponent(safeProofId)}/${opponentId}`}
            className="inline-flex items-center gap-1.5 rounded border border-signal-emerald-border bg-signal-emerald-bg px-3 py-1.5 font-mono text-xs font-semibold text-signal-emerald transition hover:border-signal-emerald"
          >
            <Swords className="h-3.5 w-3.5" />
            <span>Head-to-Head /vs</span>
          </Link>
        </div>
      </div>

      {/* Main Split: Camera-Ready Card Canvas + 1-Click Copy Matrix */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left: Pixel-Perfect 16:9 or 9:16 Card Preview + Export Actions */}
        <div className="inst-panel flex flex-col justify-between gap-4 rounded-md bg-telemetry-grid p-4 sm:p-6 lg:col-span-7">
          <div className="flex flex-1 items-center justify-center py-2">
            {aspect === "16:9" ? (
              <div className="relative flex aspect-[16/9] w-full max-w-[650px] flex-col justify-between overflow-hidden rounded-md border border-hairline-strong bg-canvas p-5 shadow-2xl">
                <div
                  className={`absolute inset-x-0 top-0 h-[3px] ${
                    cardSummary.valid ? "bg-signal-emerald" : "bg-signal-vermilion"
                  }`}
                />

                {/* Top Row */}
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2 font-mono text-[10px]">
                      <span
                        className={`rounded px-1.5 py-0.5 font-semibold uppercase tracking-wider ${
                          cardSummary.valid ? "badge-champagne" : "badge-vermilion"
                        }`}
                      >
                        {cardSummary.headlineStatus}
                      </span>
                      {handle && (
                        <span className="font-semibold text-signal-emerald">{handle}</span>
                      )}
                      <span className="text-ink-muted tabular-nums">
                        {bundle.period_start_utc.slice(0, 10)} →{" "}
                        {bundle.period_end_utc.slice(0, 10)}
                      </span>
                    </div>
                    <h4 className="editorial-serif mt-1 truncate text-xl text-ink sm:text-2xl">
                      {title ?? `${bundle.broker_id.toUpperCase()} Verified Tear Sheet`}
                    </h4>
                    <p className="font-mono text-[10px] text-ink-muted tabular-nums">
                      Tier: {cardSummary.capitalTierLabel} • Zero Dollar-NAV Leakage
                    </p>
                  </div>

                  {/* Inline Scannable SVG QR */}
                  <div className="shrink-0 rounded border border-hairline-strong bg-panel p-1.5 text-center">
                    <svg
                      viewBox={`-1 -1 ${qr.size + 2} ${qr.size + 2}`}
                      className="h-14 w-14 text-ink"
                      aria-label="Verification QR Code"
                    >
                      <path d={qr.svgPath} fill="currentColor" shapeRendering="crispEdges" />
                    </svg>
                  </div>
                </div>

                {/* Middle Telemetry + Sparkline */}
                <div className="grid grid-cols-12 items-end gap-3">
                  <div className="col-span-7 grid grid-cols-3 gap-2">
                    <div className="rounded border border-hairline bg-panel px-2.5 py-2">
                      <span className="block font-mono text-[9px] uppercase text-ink-muted">
                        Indexed TWR
                      </span>
                      <span className="mt-0.5 block font-mono text-base font-bold text-signal-emerald sm:text-lg tabular-nums">
                        {cardSummary.twrLabel}
                      </span>
                    </div>
                    <div className="rounded border border-hairline bg-panel px-2.5 py-2">
                      <span className="block font-mono text-[9px] uppercase text-ink-muted">
                        PSR (GLM)
                      </span>
                      <span className="mt-0.5 block font-mono text-xs font-semibold text-ink sm:text-sm tabular-nums">
                        {cardSummary.psrLabel}
                      </span>
                    </div>
                    <div className="rounded border border-hairline bg-panel px-2.5 py-2">
                      <span className="block font-mono text-[9px] uppercase text-ink-muted">
                        Max DD
                      </span>
                      <span className="mt-0.5 block font-mono text-xs font-semibold text-signal-vermilion sm:text-sm tabular-nums">
                        {cardSummary.maxDdLabel}
                      </span>
                    </div>
                  </div>

                  <div className="col-span-5 rounded border border-hairline bg-panel p-2">
                    <svg viewBox="0 0 260 76" className="h-12 w-full overflow-visible">
                      <defs>
                        <linearGradient id="share-spark-169" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="var(--chart-wealth-top)" />
                          <stop offset="100%" stopColor="var(--chart-wealth-bottom)" />
                        </linearGradient>
                      </defs>
                      <path d={sparkPath.area} fill="url(#share-spark-169)" />
                      <path
                        d={sparkPath.line}
                        fill="none"
                        stroke="var(--chart-wealth-stroke)"
                        strokeWidth="2.1"
                      />
                    </svg>
                  </div>
                </div>

                {/* 4 Orthogonal WebCrypto-Verified Trust Chips */}
                <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-4">
                  {cardSummary.chips.map((chip) => (
                    <div
                      key={chip.axis}
                      className="rounded border border-hairline bg-panel px-2 py-1.5 font-mono"
                    >
                      <span className="block text-[8.5px] font-semibold uppercase tracking-wider text-ink-muted">
                        {chip.indexLabel}
                      </span>
                      <span
                        className={`mt-0.5 block truncate text-[10px] font-semibold ${chipColorClass(
                          chip.tone,
                        )}`}
                      >
                        {chip.value}
                      </span>
                    </div>
                  ))}
                </div>

                {/* Merkle / Ed25519 / SHA-256 Fingerprint Footer */}
                <div className="flex flex-wrap items-center justify-between gap-2 border-t border-hairline pt-1.5 font-mono text-[9.5px] text-ink-muted tabular-nums">
                  <span>
                    merkle: <strong className="text-ink-secondary">{cardSummary.shortMerkleRoot}</strong> • ed25519:{" "}
                    <strong className="text-ink-secondary">{cardSummary.shortEd25519Sig}</strong>
                  </span>
                  <span className="text-signal-emerald">
                    SHA-256 {cardSummary.shortProofHash}
                  </span>
                </div>
              </div>
            ) : (
              <div className="relative flex aspect-[9/16] w-full max-w-[320px] flex-col justify-between overflow-hidden rounded-md border border-hairline-strong bg-canvas p-5 shadow-2xl">
                <div
                  className={`absolute inset-x-0 top-0 h-[3px] ${
                    cardSummary.valid ? "bg-signal-emerald" : "bg-signal-vermilion"
                  }`}
                />

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between font-mono text-[9.5px]">
                    <span
                      className={`rounded px-1.5 py-0.5 font-semibold ${
                        cardSummary.valid ? "badge-champagne" : "badge-vermilion"
                      }`}
                    >
                      {cardSummary.headlineStatus}
                    </span>
                    <span className="text-ink-muted tabular-nums">{safeProofId}</span>
                  </div>
                  {handle && (
                    <p className="font-mono text-xs font-medium text-signal-emerald">
                      {handle}
                    </p>
                  )}
                  <h4 className="editorial-serif text-2xl leading-snug text-ink">
                    {title ?? `${bundle.broker_id.toUpperCase()} Verified Record`}
                  </h4>
                  <p className="font-mono text-[10px] text-ink-muted tabular-nums">
                    {bundle.period_start_utc.slice(0, 10)} →{" "}
                    {bundle.period_end_utc.slice(0, 10)} • {cardSummary.capitalTierLabel}
                  </p>
                </div>

                {/* Vertical Telemetry Stack */}
                <div className="space-y-2 my-1">
                  <div className="rounded border border-hairline bg-panel p-2.5">
                    <span className="font-mono text-[9.5px] uppercase text-ink-muted">
                      Flow-Adjusted Indexed-100 TWR
                    </span>
                    <p className="mt-0.5 font-mono text-2xl font-bold text-signal-emerald tabular-nums">
                      {cardSummary.twrLabel}
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <div className="rounded border border-hairline bg-panel p-2">
                      <span className="font-mono text-[9px] uppercase text-ink-muted">
                        PSR (GLM)
                      </span>
                      <p className="mt-0.5 font-mono text-xs font-semibold text-ink tabular-nums">
                        {cardSummary.psrLabel}
                      </p>
                    </div>
                    <div className="rounded border border-hairline bg-panel p-2">
                      <span className="font-mono text-[9px] uppercase text-ink-muted">
                        Max Drawdown
                      </span>
                      <p className="mt-0.5 font-mono text-xs font-semibold text-signal-vermilion tabular-nums">
                        {cardSummary.maxDdLabel}
                      </p>
                    </div>
                  </div>

                  <div className="rounded border border-hairline bg-panel p-2">
                    <svg viewBox="0 0 260 76" className="h-12 w-full overflow-visible">
                      <path
                        d={sparkPath.area}
                        fill="var(--chart-wealth-top)"
                        fillOpacity="0.4"
                      />
                      <path
                        d={sparkPath.line}
                        fill="none"
                        stroke="var(--chart-wealth-stroke)"
                        strokeWidth="2.2"
                      />
                    </svg>
                  </div>

                  {/* 4 Orthogonal Chips Stacked for 9:16 */}
                  <div className="space-y-1">
                    {cardSummary.chips.map((chip) => (
                      <div
                        key={chip.axis}
                        className="flex items-center justify-between rounded border border-hairline bg-panel px-2.5 py-1 font-mono text-[9.5px]"
                      >
                        <span className="text-ink-muted">{chip.indexLabel}</span>
                        <span
                          className={`truncate font-semibold ${chipColorClass(chip.tone)}`}
                        >
                          {chip.value}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Bottom QR + Merkle/Ed25519 Seal */}
                <div className="flex items-center justify-between gap-2.5 border-t border-hairline pt-2.5">
                  <div className="min-w-0 space-y-0.5 font-mono text-[9px] text-ink-muted tabular-nums">
                    <p className="font-semibold text-signal-champagne">
                      SCAN TO VERIFY ED25519
                    </p>
                    <p className="truncate text-ink-secondary">
                      SHA256 {cardSummary.shortProofHash}
                    </p>
                    <p className="truncate">merkle {cardSummary.shortMerkleRoot}</p>
                    <p className="truncate">ed25519 {cardSummary.shortEd25519Sig}</p>
                  </div>
                  <div className="shrink-0 rounded border border-hairline-strong bg-panel p-1.5">
                    <svg
                      viewBox={`-1 -1 ${qr.size + 2} ${qr.size + 2}`}
                      className="h-14 w-14 text-ink"
                      aria-label="Scan to verify in browser"
                    >
                      <path d={qr.svgPath} fill="currentColor" shapeRendering="crispEdges" />
                    </svg>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Card Vector Download & Copy Bar */}
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-hairline pt-3 font-mono text-xs">
            <span className="text-[11px] text-ink-muted">
              Active Canvas:{" "}
              <strong className="text-ink">
                {aspect === "16:9" ? "1280 × 720 Landscape" : "720 × 1280 Story/Reel"}
              </strong>
            </span>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => void copyText("card-svg", activeCardSvgRaw)}
                className="inline-flex items-center gap-1.5 rounded border border-hairline-strong bg-panel px-3 py-1.5 text-[11px] text-ink transition hover:border-signal-champagne"
              >
                {copiedId === "card-svg" ? (
                  <Check className="h-3.5 w-3.5 text-signal-emerald" />
                ) : (
                  <Copy className="h-3.5 w-3.5 text-signal-champagne" />
                )}
                <span>
                  {copiedId === "card-svg"
                    ? `Copied ${aspect} .svg`
                    : `Copy ${aspect} Card .svg`}
                </span>
              </button>
              <button
                type="button"
                onClick={downloadActiveCardSvg}
                className="inline-flex items-center gap-1.5 rounded border border-signal-emerald-border bg-signal-emerald-bg px-3 py-1.5 text-[11px] font-semibold text-signal-emerald transition hover:border-signal-emerald"
              >
                <Download className="h-3.5 w-3.5" />
                <span>Download {aspect} .svg</span>
              </button>
            </div>
          </div>
        </div>

        {/* Right: Standalone SVG Badge + 1-Click Copy Controls (Markdown, Discord /verify JSON, Substack/Notion iframe) */}
        <div className="space-y-4 lg:col-span-5">
          <div className="inst-panel space-y-3 rounded-md p-4">
            <div className="flex items-center justify-between">
              <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-ink">
                Standalone Cryptographic .svg Badge
              </span>
              <span className="font-mono text-[10px] text-ink-muted">660 × 88 vector</span>
            </div>

            {badgeSvgRaw ? (
              <div
                className="overflow-x-auto rounded border border-hairline bg-elevated p-2"
                dangerouslySetInnerHTML={{ __html: badgeSvgRaw }}
              />
            ) : (
              <div className="rounded border border-hairline bg-elevated p-4 font-mono text-xs text-ink-muted">
                Computing WebCrypto badge signature…
              </div>
            )}

            <button
              type="button"
              onClick={() => void copyText("svg", badgeSvgRaw)}
              disabled={!badgeSvgRaw}
              className="inline-flex w-full items-center justify-center gap-2 rounded border border-signal-champagne-border bg-signal-champagne-bg px-3 py-2 font-mono text-xs font-semibold text-signal-champagne transition hover:border-signal-champagne"
            >
              {copiedId === "svg" ? (
                <>
                  <Check className="h-3.5 w-3.5" />
                  <span>Copied Standalone .svg Vector</span>
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" />
                  <span>Copy Raw .svg Vector Markup</span>
                </>
              )}
            </button>
          </div>

          {/* 1. Markdown Badge Snippet */}
          <CopyBlock
            id="md"
            label="Markdown Badge (GitHub / Substack / Pitch Deck)"
            code={markdownSnippet}
            copied={copiedId === "md"}
            onCopy={() => void copyText("md", markdownSnippet)}
          />

          {/* 2. Discord /verify Rich Embed JSON */}
          <CopyBlock
            id="discord"
            icon="discord"
            label="Discord /verify Rich Embed JSON (Webhook / Bot)"
            code={discordEmbedJson}
            copied={copiedId === "discord"}
            onCopy={() => void copyText("discord", discordEmbedJson)}
          />

          {/* 3. Substack / Notion Iframe Embed Snippet */}
          <CopyBlock
            id="embed"
            label="Substack / Notion Iframe (<iframe src=.../embed/[proofId]>)"
            code={iframeSnippet}
            copied={copiedId === "embed"}
            onCopy={() => void copyText("embed", iframeSnippet)}
          />

          {/* Permalink + Fingerprint */}
          <div className="inst-panel flex items-center justify-between gap-2 rounded-md p-3.5 font-mono text-xs">
            <div className="min-w-0">
              <div className="flex items-center gap-1.5 text-[10px] uppercase text-ink-muted">
                <QrCode className="h-3 w-3 text-signal-emerald" />
                <span>Canonical Verification URL</span>
              </div>
              <p className="mt-0.5 truncate text-ink">{permalinkUrl}</p>
            </div>
            <button
              type="button"
              onClick={() => void copyText("url", permalinkUrl)}
              className="shrink-0 rounded border border-hairline-strong bg-elevated px-2.5 py-1.5 text-[11px] text-ink transition hover:border-signal-emerald"
            >
              {copiedId === "url" ? "Copied" : "Copy URL"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function CopyBlock({
  label,
  code,
  copied,
  onCopy,
  icon = "code",
}: {
  id: string;
  label: string;
  code: string;
  copied: boolean;
  onCopy: () => void;
  icon?: "code" | "discord";
}) {
  return (
    <div className="inst-panel space-y-2 rounded-md p-4">
      <div className="flex items-center justify-between gap-2">
        <span className="inline-flex items-center gap-1.5 font-mono text-[11px] font-semibold text-ink">
          {icon === "discord" ? (
            <MessageSquare className="h-3.5 w-3.5 text-signal-emerald" />
          ) : (
            <Code2 className="h-3.5 w-3.5 text-signal-champagne" />
          )}
          {label}
        </span>
        <button
          type="button"
          onClick={onCopy}
          className="inline-flex items-center gap-1 rounded border border-hairline-strong bg-elevated px-2.5 py-1 font-mono text-[11px] text-ink transition hover:border-signal-emerald"
        >
          {copied ? (
            <Check className="h-3 w-3 text-signal-emerald" />
          ) : (
            <Copy className="h-3 w-3" />
          )}
          <span>{copied ? "Copied" : "1-Click Copy"}</span>
        </button>
      </div>
      <pre className="max-h-36 overflow-auto rounded border border-hairline bg-elevated p-2.5 font-mono text-[10.5px] text-ink-secondary">
        {code}
      </pre>
    </div>
  );
}
