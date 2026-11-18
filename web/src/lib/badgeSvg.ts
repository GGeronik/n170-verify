/**
 * Obsidian & Brushed Champagne standalone SVG assurance badge renderer.
 *
 * Strictly renders verifier-computed `BundleVerificationResult` fields (never
 * self-asserted claims) with XML entity escaping.
 */

import {
  CHAIN_CONTINUITY_META,
  ORIGIN_ASSURANCE_META,
  RECONCILIATION_STATUS_META,
  ReconciliationStatus,
  extractTypedLeaves,
  type BundleVerificationResult,
  type VerifyProofBundle,
} from "./contracts.ts";
import { sanitizePlainInput } from "./plausibilityMath.ts";

export function xmlEscape(raw: string): string {
  return String(raw)
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\uFFFE\uFFFF]/g, "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function renderArchivalBadgeSvg(
  bundle: VerifyProofBundle,
  verification: BundleVerificationResult,
  theme: "obsidian" | "paper" = "obsidian",
  customLabel?: string | null,
): string {
  const verifiedIntact =
    verification.valid && verification.merkle_valid && verification.signature_valid;
  const leaves = verifiedIntact ? extractTypedLeaves(bundle) : null;
  const perf = leaves?.coreMetrics ?? null;
  const reconStatus =
    leaves?.reconciliation?.status ?? ReconciliationStatus.REFERENCE_DATA_UNAVAILABLE;

  const twrLabel = !verifiedIntact
    ? "UNVERIFIED"
    : perf != null && Number.isFinite(perf.twr_decimal)
      ? `${perf.twr_decimal >= 0 ? "+" : ""}${(perf.twr_decimal * 100).toFixed(2)}%`
      : "REDACTED";
  const psrLabel = !verifiedIntact
    ? "UNVERIFIED"
    : perf?.psr_sample_eligible &&
        perf.psr_glm_unsmoothed != null &&
        Number.isFinite(perf.psr_glm_unsmoothed)
      ? `${(perf.psr_glm_unsmoothed * 100).toFixed(1)}%`
      : `GATED (T=${perf?.observation_count ?? 0}<30)`;

  const originLabel = verifiedIntact
    ? ORIGIN_ASSURANCE_META[verification.effective_origin_assurance].shortLabel
    : verification.signer_trust_status.toUpperCase();
  const reconLabel = verifiedIntact
    ? RECONCILIATION_STATUS_META[reconStatus].shortLabel
    : "UNVERIFIED";
  const chainLabel =
    CHAIN_CONTINUITY_META[verification.effective_chain_continuity_mode].shortLabel;
  const shortHash = `${verification.proof_hash.slice(0, 8)}·${verification.proof_hash.slice(-6)}`;

  const isDark = theme === "obsidian";
  const bg = isDark ? "#090A0D" : "#F7F6F2";
  const panel = isDark ? "#101217" : "#FFFFFF";
  const stroke = isDark ? "rgba(255,255,255,0.12)" : "rgba(17,18,20,0.14)";
  const primary = isDark ? "#F3F4F6" : "#111214";
  const muted = isDark ? "#8A919E" : "#5A606B";
  const emerald = verification.valid
    ? isDark
      ? "#10B981"
      : "#047857"
    : "#EF4444";
  const champagne = isDark ? "#D6B36A" : "#8A6421";

  const sanitizedCustom = customLabel ? sanitizePlainInput(customLabel, 28) : "";
  const headline = !verification.valid
    ? "VERIFICATION REJECTED"
    : sanitizedCustom
      ? `N170 VERIFIED · ${sanitizedCustom.toUpperCase()}`
      : "N170 VERIFIED PROOF";

  return [
    `<svg xmlns="http://www.w3.org/2000/svg" width="660" height="88" viewBox="0 0 660 88" role="img" aria-label="${xmlEscape(headline)}">`,
    `<rect width="660" height="88" rx="6" fill="${bg}" />`,
    `<rect x="0.5" y="0.5" width="659" height="87" rx="5.5" fill="${panel}" stroke="${stroke}" />`,
    `<rect x="0" y="0" width="4" height="88" rx="2" fill="${emerald}" />`,
    `<g font-family="JetBrains Mono, Geist Mono, ui-monospace, SFMono-Regular, Menlo, monospace" style="font-variant-numeric: tabular-nums slashed-zero;">`,
    `<circle cx="20" cy="21" r="3.5" fill="${emerald}" />`,
    `<text x="31" y="25" font-size="11" font-weight="700" letter-spacing="0.06em" fill="${primary}">${xmlEscape(headline)}</text>`,
    `<text x="205" y="25" font-size="10.5" fill="${champagne}">${xmlEscape(originLabel.toUpperCase())}</text>`,
    `<text x="644" y="25" text-anchor="end" font-size="10" fill="${muted}">SHA256 ${xmlEscape(shortHash)}</text>`,
    `<line x1="16" y1="36" x2="644" y2="36" stroke="${stroke}" />`,
    `<text x="16" y="56" font-size="10" fill="${muted}">INDEXED-100 TWR</text>`,
    `<text x="16" y="73" font-size="14" font-weight="700" fill="${emerald}">${xmlEscape(twrLabel)}</text>`,
    `<text x="162" y="56" font-size="10" fill="${muted}">PSR (GLM)</text>`,
    `<text x="162" y="73" font-size="13" font-weight="600" fill="${primary}">${xmlEscape(psrLabel)}</text>`,
    `<text x="308" y="56" font-size="10" fill="${muted}">RECONCILIATION</text>`,
    `<text x="308" y="73" font-size="12" font-weight="600" fill="${primary}">${xmlEscape(reconLabel)}</text>`,
    `<text x="480" y="56" font-size="10" fill="${muted}">CONTINUITY</text>`,
    `<text x="480" y="73" font-size="12" font-weight="600" fill="${primary}">${xmlEscape(chainLabel)}</text>`,
    `</g>`,
    `</svg>`,
  ].join("");
}

export const renderInstitutionalBadgeSvg = renderArchivalBadgeSvg;
