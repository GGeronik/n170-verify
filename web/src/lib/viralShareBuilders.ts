/**
 * N170 Verify: Verifier-Bound 16:9 & 9:16 Share Card SVG Builders,
 * Discord `/verify` Rich Embed JSON Builder, and XSS-Safe Embed Snippets.
 *
 * SECURITY INVARIANT: Every trust chip, badge label, and Discord embed field is
 * derived strictly from the browser WebCrypto `BundleVerificationResult` (never
 * from unverified `bundle.claimed_origin_assurance` or raw unverified strings).
 */

import { xmlEscape } from "./badgeSvg.ts";
import {
  ACCOUNT_SCOPE_META,
  CAPITAL_BRACKET_LABELS,
  CHAIN_CONTINUITY_META,
  ORIGIN_ASSURANCE_META,
  RECONCILIATION_STATUS_META,
  SIGNER_TRUST_META,
  extractTypedLeaves,
  type BundleVerificationResult,
  type IndexedCurvePoint,
  type VerifyProofBundle,
} from "./contracts.ts";
import { sanitizeHandleInput, sanitizePlainInput } from "./plausibilityMath.ts";
import { generateQrCode } from "./qrSvg.ts";

export { xmlEscape };

export function sanitizeOriginUrl(rawOrigin?: string | null): string {
  const candidate = (rawOrigin ?? "").trim().replace(/\/+$/, "");
  if (!candidate) return "https://verify.example.org";
  try {
    const parsed = new URL(candidate);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return "https://verify.example.org";
    }
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return "https://verify.example.org";
  }
}

export function sanitizeProofIdSegment(proofId: string): string {
  return proofId.replace(/[^A-Za-z0-9_.\-]/g, "").slice(0, 96) || "unknown-proof";
}

export interface OrthogonalVerifiedChip {
  axis: "origin" | "signer" | "reconciliation" | "continuity";
  indexLabel: string;
  value: string;
  tone: "emerald" | "champagne" | "ochre" | "vermilion" | "neutral";
}

export interface VerifiedCardSummary {
  ready: boolean;
  valid: boolean;
  downgraded: boolean;
  headlineStatus: string;
  twrLabel: string;
  psrLabel: string;
  maxDdLabel: string;
  capitalTierLabel: string;
  shortProofHash: string;
  shortMerkleRoot: string;
  shortEd25519Sig: string;
  chips: [
    OrthogonalVerifiedChip,
    OrthogonalVerifiedChip,
    OrthogonalVerifiedChip,
    OrthogonalVerifiedChip,
  ];
}

/**
 * Extracts the 4 Orthogonal Trust Chips strictly from `BundleVerificationResult`.
 * When `verification` is null or invalid, unverified bundle claims are NEVER echoed.
 */
export function extractVerifiedCardSummary(
  bundle: VerifyProofBundle,
  verification: BundleVerificationResult | null,
): VerifiedCardSummary {
  const shortMerkleRoot = `${bundle.merkle_root.slice(0, 10)}·${bundle.merkle_root.slice(-8)}`;
  const shortEd25519Sig = `${bundle.signature_hex.slice(0, 10)}·${bundle.signature_hex.slice(-8)}`;

  if (!verification) {
    return {
      ready: false,
      valid: false,
      downgraded: false,
      headlineStatus: "VERIFYING IN WEBCRYPTO…",
      twrLabel: "VERIFYING…",
      psrLabel: "VERIFYING…",
      maxDdLabel: "-",
      capitalTierLabel: "Verifying…",
      shortProofHash: "computing…",
      shortMerkleRoot,
      shortEd25519Sig,
      chips: [
        {
          axis: "origin",
          indexLabel: "01 ORIGIN",
          value: "Pending WebCrypto",
          tone: "neutral",
        },
        {
          axis: "signer",
          indexLabel: "02 SIGNER",
          value: "Pending WebCrypto",
          tone: "neutral",
        },
        {
          axis: "reconciliation",
          indexLabel: "03 LEDGER",
          value: "Pending WebCrypto",
          tone: "neutral",
        },
        {
          axis: "continuity",
          indexLabel: "04 SCOPE & CHAIN",
          value: "Pending WebCrypto",
          tone: "neutral",
        },
      ],
    };
  }

  const shortProofHash = `${verification.proof_hash.slice(0, 10)}·${verification.proof_hash.slice(-8)}`;

  if (!verification.valid || !verification.merkle_valid || !verification.signature_valid) {
    const signerLabel = SIGNER_TRUST_META[verification.signer_trust_status].shortLabel;
    return {
      ready: true,
      valid: false,
      downgraded: false,
      headlineStatus: "VERIFICATION REJECTED",
      twrLabel: "REJECTED",
      psrLabel: "INVALID",
      maxDdLabel: "-",
      capitalTierLabel: "Unverified",
      shortProofHash,
      shortMerkleRoot,
      shortEd25519Sig,
      chips: [
        {
          axis: "origin",
          indexLabel: "01 ORIGIN",
          value: "Unverified (Rejected)",
          tone: "vermilion",
        },
        {
          axis: "signer",
          indexLabel: "02 SIGNER",
          value: signerLabel,
          tone: "vermilion",
        },
        {
          axis: "reconciliation",
          indexLabel: "03 LEDGER",
          value: verification.merkle_valid ? "Sig Invalid" : "Merkle Tampered",
          tone: "vermilion",
        },
        {
          axis: "continuity",
          indexLabel: "04 SCOPE & CHAIN",
          value: CHAIN_CONTINUITY_META[verification.effective_chain_continuity_mode].shortLabel,
          tone: "vermilion",
        },
      ],
    };
  }

  const leaves = extractTypedLeaves(bundle);
  const perf = leaves.coreMetrics;
  const downgraded =
    verification.effective_origin_assurance !== bundle.claimed_origin_assurance;

  const originShort =
    ORIGIN_ASSURANCE_META[verification.effective_origin_assurance].shortLabel;
  const signerShort = SIGNER_TRUST_META[verification.signer_trust_status].shortLabel;
  const reconShort = leaves.reconciliation
    ? RECONCILIATION_STATUS_META[leaves.reconciliation.status].shortLabel
    : "Leaf Redacted";
  const scopeShort =
    ACCOUNT_SCOPE_META[verification.assurance_profile.account_scope].shortLabel;
  const chainShort =
    CHAIN_CONTINUITY_META[verification.effective_chain_continuity_mode].shortLabel;

  const twrLabel =
    perf != null
      ? `${perf.twr_decimal >= 0 ? "+" : ""}${(perf.twr_decimal * 100).toFixed(2)}%`
      : "REDACTED";
  const psrLabel =
    perf?.psr_sample_eligible && perf.psr_glm_unsmoothed != null
      ? `${(perf.psr_glm_unsmoothed * 100).toFixed(1)}%`
      : perf?.psr_sample_eligible && perf.probabilistic_sharpe_ratio != null
        ? `${(perf.probabilistic_sharpe_ratio * 100).toFixed(1)}%`
        : `GATED (T=${perf?.observation_count ?? 0})`;
  const maxDdLabel =
    perf != null ? `-${Math.abs(perf.max_drawdown_decimal * 100).toFixed(2)}%` : "-";
  const capitalTierLabel = leaves.capitalBracket
    ? CAPITAL_BRACKET_LABELS[leaves.capitalBracket]
    : "Salted-Redacted";

  const originTone: OrthogonalVerifiedChip["tone"] = downgraded
    ? "ochre"
    : verification.effective_origin_assurance === "broker_signed" ||
        verification.effective_origin_assurance === "independently_witnessed_tls"
      ? "emerald"
      : verification.effective_origin_assurance === "operator_retrieved"
        ? "champagne"
        : "ochre";

  const signerTone: OrthogonalVerifiedChip["tone"] =
    verification.signer_trust_status === "official_n170_hosted"
      ? "emerald"
      : verification.signer_trust_status === "retired_historical_valid"
        ? "champagne"
        : "ochre";

  const reconTone: OrthogonalVerifiedChip["tone"] =
    leaves.reconciliation?.status === "reconciled_within_tolerance"
      ? "emerald"
      : leaves.reconciliation?.status === "unexplained_residual" ||
          leaves.reconciliation?.status === "insufficient_sections"
        ? "ochre"
        : "neutral";

  const chainTone: OrthogonalVerifiedChip["tone"] =
    verification.effective_chain_continuity_mode === "prospective_continuous" &&
    verification.assurance_profile.account_scope === "all_enumerated_subaccounts"
      ? "emerald"
      : verification.effective_chain_continuity_mode === "continuity_broken"
        ? "vermilion"
        : "champagne";

  return {
    ready: true,
    valid: true,
    downgraded,
    headlineStatus: "N170 WEBCRYPTO VERIFIED",
    twrLabel,
    psrLabel,
    maxDdLabel,
    capitalTierLabel,
    shortProofHash,
    shortMerkleRoot,
    shortEd25519Sig,
    chips: [
      {
        axis: "origin",
        indexLabel: "01 ORIGIN",
        value: downgraded ? `${originShort} (Downgraded)` : originShort,
        tone: originTone,
      },
      {
        axis: "signer",
        indexLabel: "02 SIGNER",
        value: signerShort,
        tone: signerTone,
      },
      {
        axis: "reconciliation",
        indexLabel: "03 LEDGER",
        value: reconShort,
        tone: reconTone,
      },
      {
        axis: "continuity",
        indexLabel: "04 SCOPE & CHAIN",
        value: `${scopeShort} • ${chainShort}`,
        tone: chainTone,
      },
    ],
  };
}

export function buildCurveSparklinePaths(
  curve: readonly IndexedCurvePoint[],
  width: number,
  height: number,
  padBottom = 10,
  padSpan = 22,
): { line: string; area: string } {
  const finitePts = curve.filter((p) => Number.isFinite(p.index_value));
  if (finitePts.length < 2) {
    const midY = (height * 0.55).toFixed(1);
    return {
      line: `M 0,${midY} L ${width},${midY}`,
      area: `M 0,${midY} L ${width},${midY} L ${width},${height} L 0,${height} Z`,
    };
  }
  const vals = finitePts.map((p) => p.index_value);
  const minV = Math.min(...vals, 99);
  const maxV = Math.max(...vals, 101);
  const span = Math.max(maxV - minV, 0.5);
  const pts = finitePts.map((pt, idx) => {
    const x = (idx / (finitePts.length - 1)) * width;
    const y = height - padBottom - ((pt.index_value - minV) / span) * (height - padSpan);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const line = `M ${pts.join(" L ")}`;
  return { line, area: `${line} L ${width},${height} L 0,${height} Z` };
}

export interface ShareCardSvgOptions {
  theme?: "obsidian" | "paper";
  title?: string;
  handle?: string;
  originUrl?: string;
}

function resolveShareCardContext(
  bundle: VerifyProofBundle,
  verification: BundleVerificationResult | null,
  options: ShareCardSvgOptions,
  titleSuffix: string,
  titleMaxLen: number,
) {
  const summary = extractVerifiedCardSummary(bundle, verification);
  const isDark = (options.theme ?? "obsidian") === "obsidian";
  const safeOrigin = sanitizeOriginUrl(options.originUrl);
  const safeProofId = sanitizeProofIdSegment(bundle.proof_id);
  const permalink = `${safeOrigin}/p/${encodeURIComponent(safeProofId)}`;
  const qr = generateQrCode(permalink);
  const safeTitle = sanitizePlainInput(
    options.title ?? `${bundle.broker_id.toUpperCase()} ${titleSuffix}`,
    titleMaxLen,
  );
  const safeHandle = options.handle ? sanitizePlainInput(options.handle, 32) : "";
  const periodStr = `${bundle.period_start_utc.slice(0, 10)} -> ${bundle.period_end_utc.slice(0, 10)}`;
  const palette = {
    bg: isDark ? "#06080D" : "#F7F6F2",
    panel: isDark ? "#0E1117" : "#FFFFFF",
    elevated: isDark ? "#141822" : "#F1EFE9",
    stroke: isDark ? "rgba(255,255,255,0.12)" : "rgba(17,18,20,0.14)",
    primary: isDark ? "#F3F4F6" : "#111214",
    secondary: isDark ? "#B9C0CE" : "#383D47",
    muted: isDark ? "#8A92A1" : "#5C6370",
    emerald: summary.valid ? (isDark ? "#10B981" : "#047857") : "#EF4444",
    champagne: isDark ? "#D6B36A" : "#8A6421",
    vermilion: isDark ? "#EF4444" : "#B91C1C",
  };
  const chipColor = (tone: OrthogonalVerifiedChip["tone"]) =>
    tone === "emerald"
      ? palette.emerald
      : tone === "champagne"
        ? palette.champagne
        : tone === "vermilion"
          ? palette.vermilion
          : palette.secondary;
  const curve = summary.valid ? extractTypedLeaves(bundle).indexedCurve : [];
  return {
    summary,
    safeProofId,
    permalink,
    qr,
    safeTitle,
    safeHandle,
    periodStr,
    palette,
    chipColor,
    curve,
  };
}

/**
 * Generates a standalone 16:9 Landscape SVG Tear Card (1280x720) for X / LinkedIn / Substack.
 */
export function renderShareCard16x9Svg(
  bundle: VerifyProofBundle,
  verification: BundleVerificationResult | null,
  options: ShareCardSvgOptions = {},
): string {
  const {
    summary,
    safeProofId,
    permalink,
    qr,
    safeTitle,
    safeHandle,
    periodStr,
    palette: p,
    chipColor,
    curve,
  } = resolveShareCardContext(bundle, verification, options, "Verified Tear Sheet", 64);
  const spark = buildCurveSparklinePaths(curve, 430, 150);
  const qrScale = (108 / (qr.size + 2)).toFixed(4);

  const chipBoxes = summary.chips
    .map(
      (chip, idx) =>
        `<g transform="translate(${48 + idx * 298}, 536)">` +
        `<rect width="282" height="84" rx="6" fill="${p.elevated}" stroke="${p.stroke}" />` +
        `<text x="16" y="28" font-size="11" font-weight="700" fill="${p.muted}" letter-spacing="0.06em">${xmlEscape(chip.indexLabel)}</text>` +
        `<text x="16" y="58" font-size="14" font-weight="700" fill="${chipColor(chip.tone)}">${xmlEscape(chip.value.slice(0, 36))}</text>` +
        `</g>`,
    )
    .join("");

  return [
    `<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="720" viewBox="0 0 1280 720" role="img" aria-label="${xmlEscape(summary.headlineStatus)}">`,
    `<defs>`,
    `<linearGradient id="spark169Fill" x1="0" y1="0" x2="0" y2="1">`,
    `<stop offset="0%" stop-color="${p.emerald}" stop-opacity="0.28" />`,
    `<stop offset="100%" stop-color="${p.emerald}" stop-opacity="0.0" />`,
    `</linearGradient>`,
    `</defs>`,
    `<rect width="1280" height="720" fill="${p.bg}" />`,
    `<rect x="24" y="24" width="1232" height="672" rx="12" fill="${p.panel}" stroke="${p.stroke}" />`,
    `<rect x="24" y="24" width="1232" height="5" rx="2.5" fill="${p.emerald}" />`,
    `<g font-family="Geist Mono, JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace" style="font-variant-numeric: tabular-nums slashed-zero;">`,
    `<text x="48" y="76" font-size="14" font-weight="700" fill="${p.champagne}" letter-spacing="0.08em">${xmlEscape(summary.headlineStatus)}</text>`,
    safeHandle
      ? `<text x="340" y="76" font-size="14" font-weight="600" fill="${p.emerald}">${xmlEscape(safeHandle)}</text>`
      : "",
    `<text x="1080" y="76" text-anchor="end" font-size="13" fill="${p.muted}">${xmlEscape(periodStr)}</text>`,
    `</g>`,
    `<text x="48" y="132" font-family="Instrument Serif, Georgia, serif" font-size="44" fill="${p.primary}">${xmlEscape(safeTitle)}</text>`,
    `<text x="48" y="164" font-family="Geist, system-ui, sans-serif" font-size="16" fill="${p.secondary}">Indexed-100 Flow-Adjusted Performance • Zero Dollar-NAV Leakage • Salted 7-Leaf JCS Merkle Proof</text>`,
    `<g transform="translate(1116, 52)">`,
    `<rect width="116" height="116" rx="8" fill="${p.elevated}" stroke="${p.stroke}" />`,
    `<g transform="translate(4, 4) scale(${qrScale})">`,
    `<path d="${qr.svgPath}" fill="${p.primary}" shape-rendering="crispEdges" transform="translate(1, 1)" />`,
    `</g>`,
    `</g>`,
    `<g font-family="Geist Mono, JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace" style="font-variant-numeric: tabular-nums slashed-zero;">`,
    `<rect x="48" y="210" width="230" height="150" rx="8" fill="${p.elevated}" stroke="${p.stroke}" />`,
    `<text x="68" y="248" font-size="13" fill="${p.muted}">INDEXED-100 TWR</text>`,
    `<text x="68" y="314" font-size="42" font-weight="700" fill="${p.emerald}">${xmlEscape(summary.twrLabel)}</text>`,
    `<text x="68" y="342" font-size="12" fill="${p.secondary}">Tier: ${xmlEscape(summary.capitalTierLabel)}</text>`,
    `<rect x="296" y="210" width="220" height="150" rx="8" fill="${p.elevated}" stroke="${p.stroke}" />`,
    `<text x="316" y="248" font-size="13" fill="${p.muted}">PSR (GLM UNSMOOTHED)</text>`,
    `<text x="316" y="312" font-size="34" font-weight="700" fill="${p.primary}">${xmlEscape(summary.psrLabel)}</text>`,
    `<text x="316" y="342" font-size="12" fill="${p.muted}">Bailey &amp; Lopez de Prado</text>`,
    `<rect x="534" y="210" width="210" height="150" rx="8" fill="${p.elevated}" stroke="${p.stroke}" />`,
    `<text x="554" y="248" font-size="13" fill="${p.muted}">MAX DRAWDOWN</text>`,
    `<text x="554" y="312" font-size="34" font-weight="700" fill="${p.vermilion}">${xmlEscape(summary.maxDdLabel)}</text>`,
    `<text x="554" y="342" font-size="12" fill="${p.muted}">Peak-to-Trough TWR</text>`,
    `<rect x="762" y="210" width="470" height="296" rx="8" fill="${p.elevated}" stroke="${p.stroke}" />`,
    `<text x="784" y="244" font-size="12" fill="${p.champagne}">REBASED WEALTH TRAJECTORY (BASE = 100.00)</text>`,
    `<g transform="translate(782, 272)">`,
    `<path d="${spark.area}" fill="url(#spark169Fill)" />`,
    `<path d="${spark.line}" fill="none" stroke="${p.emerald}" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" />`,
    `</g>`,
    `<text x="784" y="484" font-size="12" fill="${p.muted}">merkle_root: ${xmlEscape(summary.shortMerkleRoot)} • ed25519: ${xmlEscape(summary.shortEd25519Sig)}</text>`,
    `<rect x="48" y="380" width="696" height="126" rx="8" fill="${p.elevated}" stroke="${p.stroke}" />`,
    `<text x="68" y="414" font-size="12" font-weight="700" fill="${p.champagne}">CRYPTOGRAPHIC FINGERPRINT &amp; ZERO-RETENTION VERIFICATION</text>`,
    `<text x="68" y="446" font-size="14" fill="${p.primary}">proof_id: ${xmlEscape(safeProofId)} • proof_hash: ${xmlEscape(summary.shortProofHash)}</text>`,
    `<text x="68" y="478" font-size="13" fill="${p.secondary}">Scan QR or open ${xmlEscape(permalink)} to verify in window.crypto.subtle</text>`,
    chipBoxes,
    `<text x="48" y="664" font-size="13" fill="${p.muted}">APACHE-2.0 OPEN STANDARD • N170 VERIFY • ZERO RAW DOLLAR BALANCES DISCLOSED</text>`,
    `<text x="1232" y="664" text-anchor="end" font-size="13" fill="${p.emerald}">SHA-256 ${xmlEscape(summary.shortProofHash)}</text>`,
    `</g>`,
    `</svg>`,
  ].join("");
}

/**
 * Generates a standalone 9:16 Vertical Story/Reel SVG Card (720x1280) for Instagram / TikTok / Shorts.
 */
export function renderShareCard9x16Svg(
  bundle: VerifyProofBundle,
  verification: BundleVerificationResult | null,
  options: ShareCardSvgOptions = {},
): string {
  const {
    summary,
    safeProofId,
    qr,
    safeTitle,
    safeHandle,
    periodStr,
    palette: p,
    chipColor,
    curve,
  } = resolveShareCardContext(bundle, verification, options, "Verified Record", 48);
  const spark = buildCurveSparklinePaths(curve, 576, 190);
  const qrScale = (144 / (qr.size + 2)).toFixed(4);

  const chipRows = summary.chips
    .map(
      (chip, idx) =>
        `<g transform="translate(48, ${742 + idx * 74})">` +
        `<rect width="624" height="62" rx="6" fill="${p.elevated}" stroke="${p.stroke}" />` +
        `<text x="20" y="37" font-size="13" font-weight="700" fill="${p.muted}" letter-spacing="0.06em">${xmlEscape(chip.indexLabel)}</text>` +
        `<text x="604" y="37" text-anchor="end" font-size="15" font-weight="700" fill="${chipColor(chip.tone)}">${xmlEscape(chip.value.slice(0, 38))}</text>` +
        `</g>`,
    )
    .join("");

  return [
    `<svg xmlns="http://www.w3.org/2000/svg" width="720" height="1280" viewBox="0 0 720 1280" role="img" aria-label="${xmlEscape(summary.headlineStatus)}">`,
    `<defs>`,
    `<linearGradient id="spark916Fill" x1="0" y1="0" x2="0" y2="1">`,
    `<stop offset="0%" stop-color="${p.emerald}" stop-opacity="0.28" />`,
    `<stop offset="100%" stop-color="${p.emerald}" stop-opacity="0.0" />`,
    `</linearGradient>`,
    `</defs>`,
    `<rect width="720" height="1280" fill="${p.bg}" />`,
    `<rect x="24" y="24" width="672" height="1232" rx="16" fill="${p.panel}" stroke="${p.stroke}" />`,
    `<rect x="24" y="24" width="672" height="6" rx="3" fill="${p.emerald}" />`,
    `<g font-family="Geist Mono, JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace" style="font-variant-numeric: tabular-nums slashed-zero;">`,
    `<text x="48" y="80" font-size="14" font-weight="700" fill="${p.champagne}" letter-spacing="0.08em">${xmlEscape(summary.headlineStatus)}</text>`,
    `<text x="672" y="80" text-anchor="end" font-size="13" fill="${p.muted}">${xmlEscape(safeProofId)}</text>`,
    safeHandle
      ? `<text x="48" y="114" font-size="16" font-weight="600" fill="${p.emerald}">${xmlEscape(safeHandle)}</text>`
      : "",
    `</g>`,
    `<text x="48" y="166" font-family="Instrument Serif, Georgia, serif" font-size="40" fill="${p.primary}">${xmlEscape(safeTitle)}</text>`,
    `<text x="48" y="198" font-family="Geist Mono, ui-monospace, monospace" font-size="14" fill="${p.muted}">${xmlEscape(periodStr)} • Tier: ${xmlEscape(summary.capitalTierLabel)}</text>`,
    `<g font-family="Geist Mono, JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace" style="font-variant-numeric: tabular-nums slashed-zero;">`,
    `<rect x="48" y="228" width="624" height="132" rx="10" fill="${p.elevated}" stroke="${p.stroke}" />`,
    `<text x="72" y="266" font-size="14" fill="${p.muted}">FLOW-ADJUSTED INDEXED-100 TWR</text>`,
    `<text x="72" y="332" font-size="52" font-weight="700" fill="${p.emerald}">${xmlEscape(summary.twrLabel)}</text>`,
    `<rect x="48" y="376" width="304" height="108" rx="8" fill="${p.elevated}" stroke="${p.stroke}" />`,
    `<text x="68" y="410" font-size="13" fill="${p.muted}">PSR (GLM)</text>`,
    `<text x="68" y="458" font-size="30" font-weight="700" fill="${p.primary}">${xmlEscape(summary.psrLabel)}</text>`,
    `<rect x="368" y="376" width="304" height="108" rx="8" fill="${p.elevated}" stroke="${p.stroke}" />`,
    `<text x="388" y="410" font-size="13" fill="${p.muted}">MAX DRAWDOWN</text>`,
    `<text x="388" y="458" font-size="30" font-weight="700" fill="${p.vermilion}">${xmlEscape(summary.maxDdLabel)}</text>`,
    `<rect x="48" y="500" width="624" height="224" rx="10" fill="${p.elevated}" stroke="${p.stroke}" />`,
    `<g transform="translate(72, 520)">`,
    `<path d="${spark.area}" fill="url(#spark916Fill)" />`,
    `<path d="${spark.line}" fill="none" stroke="${p.emerald}" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round" />`,
    `</g>`,
    chipRows,
    `<g transform="translate(48, 1054)">`,
    `<rect width="624" height="172" rx="10" fill="${p.elevated}" stroke="${p.stroke}" />`,
    `<text x="24" y="42" font-size="13" font-weight="700" fill="${p.champagne}">SCAN TO VERIFY ED25519 + SALTED MERKLE IN BROWSER</text>`,
    `<text x="24" y="76" font-size="14" fill="${p.primary}">SHA-256: ${xmlEscape(summary.shortProofHash)}</text>`,
    `<text x="24" y="106" font-size="13" fill="${p.secondary}">merkle: ${xmlEscape(summary.shortMerkleRoot)}</text>`,
    `<text x="24" y="136" font-size="12" fill="${p.muted}">ed25519: ${xmlEscape(summary.shortEd25519Sig)} • Zero $ NAV Leak</text>`,
    `<g transform="translate(460, 12)">`,
    `<rect width="148" height="148" rx="8" fill="${p.panel}" stroke="${p.stroke}" />`,
    `<g transform="translate(2, 2) scale(${qrScale})">`,
    `<path d="${qr.svgPath}" fill="${p.primary}" shape-rendering="crispEdges" transform="translate(1, 1)" />`,
    `</g>`,
    `</g>`,
    `</g>`,
    `</g>`,
    `</svg>`,
  ].join("");
}

export interface DiscordVerifyEmbedPayload {
  content: string;
  allowed_mentions: { parse: never[] };
  embeds: [
    {
      title: string;
      url: string;
      color: number;
      description: string;
      fields: { name: string; value: string; inline: boolean }[];
      footer: { text: string };
      timestamp: string;
    },
  ];
}

/**
 * Builds an XSS-sanitized Discord `/verify` Rich Embed JSON payload strictly from
 * WebCrypto `BundleVerificationResult`.
 */
export function buildDiscordVerifyEmbedPayload(
  bundle: VerifyProofBundle,
  verification: BundleVerificationResult | null,
  options: ShareCardSvgOptions = {},
): DiscordVerifyEmbedPayload {
  const summary = extractVerifiedCardSummary(bundle, verification);
  const safeOrigin = sanitizeOriginUrl(options.originUrl);
  const safeProofId = sanitizeProofIdSegment(bundle.proof_id);
  const permalink = `${safeOrigin}/p/${encodeURIComponent(safeProofId)}`;
  const safeTitle = sanitizePlainInput(
    options.title ?? `${bundle.broker_id.toUpperCase()} Verified Tear Sheet`,
    80,
  );
  const cleanedHandle = options.handle ? sanitizeHandleInput(options.handle) : "";
  const safeHandle = cleanedHandle || null;

  const color = !summary.ready
    ? 0x8a92a1
    : summary.valid
      ? summary.downgraded
        ? 0xf59e0b
        : 0x10b981
      : 0xef4444;

  const titlePrefix = summary.valid ? "N170 Verified Proof" : "N170 Proof Inspection";

  return {
    content: safeHandle
      ? `Cryptographic Track-Record Proof for **${safeHandle}** (\`${safeProofId}\`)`
      : `Cryptographic Track-Record Proof (\`${safeProofId}\`)`,
    allowed_mentions: { parse: [] },
    embeds: [
      {
        title: `${titlePrefix}: ${safeTitle}`,
        url: permalink,
        color,
        description:
          "Verified client-side via `window.crypto.subtle` (RFC 8785 JCS + Salted 7-Leaf Merkle + Ed25519). Zero exact dollar balances or live open positions disclosed.",
        fields: [
          {
            name: "Indexed-100 TWR",
            value: `\`${summary.twrLabel}\``,
            inline: true,
          },
          {
            name: "PSR (GLM)",
            value: `\`${summary.psrLabel}\``,
            inline: true,
          },
          {
            name: "Max Drawdown",
            value: `\`${summary.maxDdLabel}\``,
            inline: true,
          },
          {
            name: summary.chips[0].indexLabel,
            value: summary.chips[0].value,
            inline: true,
          },
          {
            name: summary.chips[1].indexLabel,
            value: summary.chips[1].value,
            inline: true,
          },
          {
            name: summary.chips[2].indexLabel,
            value: summary.chips[2].value,
            inline: true,
          },
          {
            name: summary.chips[3].indexLabel,
            value: summary.chips[3].value,
            inline: false,
          },
        ],
        footer: {
          text: `SHA-256 ${summary.shortProofHash} • Merkle ${summary.shortMerkleRoot} • Tier: ${summary.capitalTierLabel}`,
        },
        timestamp: bundle.issued_at_utc,
      },
    ],
  };
}

export function buildDiscordVerifyEmbedJson(
  bundle: VerifyProofBundle,
  verification: BundleVerificationResult | null,
  options: ShareCardSvgOptions = {},
): string {
  return JSON.stringify(
    buildDiscordVerifyEmbedPayload(bundle, verification, options),
    null,
    2,
  );
}

export function buildMarkdownBadgeSnippet(
  proofId: string,
  originUrl?: string | null,
  theme: "obsidian" | "paper" = "obsidian",
): string {
  const safeOrigin = sanitizeOriginUrl(originUrl);
  const safeId = sanitizeProofIdSegment(proofId);
  const safeTheme = theme === "paper" ? "paper" : "obsidian";
  const badgeUrl = `${safeOrigin}/api/v1/badges/${encodeURIComponent(safeId)}.svg?theme=${safeTheme}`;
  const permalinkUrl = `${safeOrigin}/p/${encodeURIComponent(safeId)}`;
  return `[![N170 Verified Performance (${safeId})](${badgeUrl})](${permalinkUrl})`;
}

export function buildSubstackNotionIframeSnippet(
  proofId: string,
  originUrl?: string | null,
  theme: "obsidian" | "paper" = "obsidian",
): { embedUrl: string; iframeHtml: string } {
  const safeOrigin = sanitizeOriginUrl(originUrl);
  const safeId = sanitizeProofIdSegment(proofId);
  const safeTheme = theme === "paper" ? "paper" : "obsidian";
  const embedUrl = `${safeOrigin}/embed/${encodeURIComponent(safeId)}?theme=${safeTheme}`;
  const iframeHtml = `<iframe src="${xmlEscape(embedUrl)}" width="680" height="270" sandbox="allow-scripts allow-popups" style="border:0;border-radius:8px;overflow:hidden;max-width:100%;" loading="lazy" referrerpolicy="strict-origin-when-cross-origin" title="N170 Verified Proof ${xmlEscape(safeId)}"></iframe>`;
  return { embedUrl, iframeHtml };
}
