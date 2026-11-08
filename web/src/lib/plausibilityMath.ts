/**
 * N170 Verify v3 — Client-Side Bailey & Lopez de Prado (2012) Non-Normal PSR & MinTRL Engine
 * plus Diplomatic Proof-Challenge Sanitizers.
 *
 * Matches `n170_verify.performance.econometrics` 1:1 with zero external dependencies,
 * zero defamatory phrasing, and zero single-account multiple-testing Sharpe deflation.
 */

import type { ClaimPlausibilityAnalysis } from "./contracts.ts";

export const MIN_MOMENT_SAMPLE_GATE = 30 as const;

/** Inverse standard normal CDF at 95% one-sided confidence: Phi^-1(0.95). */
export const Z_ALPHA_95 = 1.6448536269514722 as const;

export const SufficiencyTier = {
  INSUFFICIENT_TRACK_RECORD_NOISE_DOMINATED:
    "INSUFFICIENT_TRACK_RECORD_NOISE_DOMINATED",
  BORDERLINE_SAMPLE: "BORDERLINE_SAMPLE",
  STATISTICALLY_SUFFICIENT_IF_UNSMOOTHED:
    "STATISTICALLY_SUFFICIENT_IF_UNSMOOTHED",
} as const;

export type SufficiencyTierCode =
  (typeof SufficiencyTier)[keyof typeof SufficiencyTier];

export type AssetTailPresetId =
  | "equities"
  | "short_vol_options"
  | "crypto_futures"
  | "custom";

export interface AssetTailPreset {
  id: AssetTailPresetId;
  label: string;
  shortLabel: string;
  skewness: number;
  excessKurtosis: number;
  annualizationFactor: number;
  note: string;
}

export const ASSET_TAIL_PRESETS: readonly AssetTailPreset[] = [
  {
    id: "equities",
    label: "Equities",
    shortLabel: "Equities (N=252)",
    skewness: -0.25,
    excessKurtosis: 1.5,
    annualizationFactor: 252,
    note: "Liquid cash equities / ETFs with moderate left-tail gap risk (skew -0.25, ex. kurt 1.5).",
  },
  {
    id: "short_vol_options",
    label: "Short-Vol / Options (skew -1.5, kurt 6.0)",
    shortLabel: "Short-Vol / Options",
    skewness: -1.5,
    excessKurtosis: 6.0,
    annualizationFactor: 252,
    note: "Premium-selling & convex short-gamma structures carry severe negative skew (-1.5) and fat tails (ex. kurt 6.0), inflating required MinTRL.",
  },
  {
    id: "crypto_futures",
    label: "Crypto / Futures",
    shortLabel: "Crypto / Futures",
    skewness: -0.45,
    excessKurtosis: 4.5,
    annualizationFactor: 365,
    note: "24/7 perpetuals, spot crypto, and leveraged futures with liquidation-cascade kurtosis (skew -0.45, ex. kurt 4.5).",
  },
  {
    id: "custom",
    label: "Custom Skew & Excess Kurtosis",
    shortLabel: "Custom Moments",
    skewness: 0.0,
    excessKurtosis: 0.0,
    annualizationFactor: 252,
    note: "User-specified higher return moments (skewness gamma_3 and excess kurtosis gamma_4 - 3).",
  },
] as const;

export interface PlausibilityInputs {
  claimedSharpe: number;
  observedPeriods: number;
  skewness: number;
  excessKurtosis: number;
  benchmarkSharpe: number;
  annualizationFactor: number;
}

/**
 * High-precision standard normal CDF Phi(z) (Abramowitz & Stegun 7.1.26, max error < 1.5e-7).
 */
export function standardNormalCdf(z: number): number {
  if (!Number.isFinite(z)) {
    return z > 0 ? 1.0 : 0.0;
  }
  if (z < -10) return 0.0;
  if (z > 10) return 1.0;

  const sign = z < 0 ? -1 : 1;
  const x = Math.abs(z) / Math.SQRT2;
  const t = 1.0 / (1.0 + 0.3275911 * x);
  const a1 = 0.254829592;
  const a2 = -0.284496736;
  const a3 = 1.421413741;
  const a4 = -1.453152027;
  const a5 = 1.061405429;
  const erfApprox =
    1.0 -
    ((((a5 * t + a4) * t + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);
  const cdf = 0.5 * (1.0 + sign * erfApprox);
  return Math.max(0.0, Math.min(1.0, cdf));
}

export function standardNormalPdf(z: number): number {
  if (!Number.isFinite(z)) return 0.0;
  return Math.exp(-0.5 * z * z) / Math.sqrt(2.0 * Math.PI);
}

/**
 * Bailey & Lopez de Prado (2012) non-normal Sharpe estimator variance factor:
 * `V = 1 - gamma_3 * SR_period + ((excess_kurtosis + 2) / 4) * SR_period^2`
 * (since kurtosis gamma_4 = excess_kurtosis + 3, gamma_4 - 1 = excess_kurtosis + 2).
 */
export function computePsrVarianceFactor(
  periodSharpe: number,
  skewness: number,
  excessKurtosis: number,
): number {
  const raw =
    1.0 -
    skewness * periodSharpe +
    ((excessKurtosis + 2.0) / 4.0) * (periodSharpe * periodSharpe);
  return Math.max(raw, 1e-12);
}

export function clampFinite(
  value: number,
  min: number,
  max: number,
  fallback: number,
): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  return Math.max(min, Math.min(max, value));
}

/**
 * Computes exact client-side `ClaimPlausibilityAnalysis` matching `n170_verify.performance.econometrics`.
 */
export function computeClaimPlausibility(
  rawInputs: Partial<PlausibilityInputs>,
): ClaimPlausibilityAnalysis {
  const annualizationFactor = Math.round(
    clampFinite(rawInputs.annualizationFactor ?? 252, 1, 3650, 252),
  );
  const observedPeriods = Math.round(
    clampFinite(rawInputs.observedPeriods ?? 45, 1, 25200, 45),
  );
  const claimedSharpe = clampFinite(
    rawInputs.claimedSharpe ?? 3.2,
    -5.0,
    15.0,
    3.2,
  );
  const benchmarkSharpe = clampFinite(
    rawInputs.benchmarkSharpe ?? 0.5,
    -2.0,
    10.0,
    0.5,
  );
  const skewness = clampFinite(rawInputs.skewness ?? -0.25, -6.0, 6.0, -0.25);
  const excessKurtosis = clampFinite(
    rawInputs.excessKurtosis ?? 1.5,
    -1.95,
    30.0,
    1.5,
  );

  const rootAnn = Math.sqrt(annualizationFactor);
  const srPerPeriod = claimedSharpe / rootAnn;
  const periodBenchSr = benchmarkSharpe / rootAnn;
  const varFactor = computePsrVarianceFactor(srPerPeriod, skewness, excessKurtosis);

  let impliedPsr = 0.5;
  if (observedPeriods >= 2) {
    const zScore =
      ((srPerPeriod - periodBenchSr) * Math.sqrt(observedPeriods - 1.0)) /
      Math.sqrt(varFactor);
    impliedPsr = standardNormalCdf(zScore);
  } else {
    impliedPsr = srPerPeriod > periodBenchSr ? 0.5 : srPerPeriod < periodBenchSr ? 0.25 : 0.5;
  }

  let requiredMinTrl95: number | null = null;
  if (srPerPeriod > periodBenchSr) {
    const diff = srPerPeriod - periodBenchSr;
    const rawMinTrl = 1.0 + varFactor * ((Z_ALPHA_95 / diff) ** 2);
    requiredMinTrl95 = Number.isFinite(rawMinTrl)
      ? Math.round(rawMinTrl * 100) / 100
      : null;
  }

  // Annualized standard error of the Sharpe estimator for sampling bell curve visualization
  const effSample = Math.max(observedPeriods - 1, 1);
  const annualizedStdErr = rootAnn * Math.sqrt(varFactor / effSample);
  const clampedSe = Math.max(annualizedStdErr, 0.05);

  const lowerBound = Math.min(
    claimedSharpe - 3.5 * clampedSe,
    benchmarkSharpe - 1.2 * clampedSe,
  );
  const upperBound = Math.max(
    claimedSharpe + 3.5 * clampedSe,
    benchmarkSharpe + 1.2 * clampedSe,
  );
  const numCurvePts = 65;
  const bellCurvePoints: { sharpe: number; density: number }[] = [];
  for (let i = 0; i < numCurvePts; i += 1) {
    const srX =
      lowerBound + (i / (numCurvePts - 1)) * (upperBound - lowerBound);
    const z = (srX - claimedSharpe) / clampedSe;
    const density = standardNormalPdf(z) / clampedSe;
    bellCurvePoints.push({
      sharpe: Math.round(srX * 1000) / 1000,
      density: Math.round(density * 100000) / 100000,
    });
  }

  let sufficiencyTier: SufficiencyTierCode;
  if (
    observedPeriods < MIN_MOMENT_SAMPLE_GATE ||
    claimedSharpe <= benchmarkSharpe ||
    impliedPsr < 0.8
  ) {
    sufficiencyTier = SufficiencyTier.INSUFFICIENT_TRACK_RECORD_NOISE_DOMINATED;
  } else if (
    impliedPsr < 0.95 ||
    (requiredMinTrl95 !== null && observedPeriods < requiredMinTrl95)
  ) {
    sufficiencyTier = SufficiencyTier.BORDERLINE_SAMPLE;
  } else {
    sufficiencyTier = SufficiencyTier.STATISTICALLY_SUFFICIENT_IF_UNSMOOTHED;
  }

  const psrPctStr = `${(impliedPsr * 100).toFixed(1)}%`;
  let plainEnglishSummary: string;

  if (claimedSharpe <= benchmarkSharpe) {
    plainEnglishSummary = `Claimed annualized Sharpe (${claimedSharpe.toFixed(2)}) does not exceed the selected benchmark SR* (${benchmarkSharpe.toFixed(2)}); implied PSR is ${psrPctStr} and 95% MinTRL is unreachable unless excess Sharpe turns positive.`;
  } else if (observedPeriods < MIN_MOMENT_SAMPLE_GATE) {
    const needed =
      requiredMinTrl95 != null
        ? Math.max(Math.ceil(requiredMinTrl95), MIN_MOMENT_SAMPLE_GATE)
        : MIN_MOMENT_SAMPLE_GATE;
    plainEnglishSummary = `Sample of T=${observedPeriods} periods falls below the T>=30 higher-moment estimator gate (implied PSR ${psrPctStr} vs SR*=${benchmarkSharpe.toFixed(2)}). Under skew=${skewness.toFixed(2)} and excess kurtosis=${excessKurtosis.toFixed(2)}, at least ${needed} unsmoothed observations are needed to separate skill from finite-sample variance at 95% confidence.`;
  } else if (
    sufficiencyTier === SufficiencyTier.STATISTICALLY_SUFFICIENT_IF_UNSMOOTHED
  ) {
    plainEnglishSummary = `Across T=${observedPeriods} observations (skew=${skewness.toFixed(2)}, excess kurtosis=${excessKurtosis.toFixed(2)}), a ${claimedSharpe.toFixed(2)} Sharpe exceeds SR*=${benchmarkSharpe.toFixed(2)} with PSR=${psrPctStr} (95% MinTRL=${requiredMinTrl95?.toFixed(1) ?? "—"} periods), provided returns are GLM-unsmoothed and all sub-accounts are enumerated.`;
  } else {
    const shortfall =
      requiredMinTrl95 != null
        ? Math.max(0, Math.ceil(requiredMinTrl95 - observedPeriods))
        : 0;
    plainEnglishSummary = `Across T=${observedPeriods} observations with skew=${skewness.toFixed(2)} and excess kurtosis=${excessKurtosis.toFixed(2)}, implied PSR is ${psrPctStr} against SR*=${benchmarkSharpe.toFixed(2)} — below the 95% institutional threshold (MinTRL=${requiredMinTrl95?.toFixed(1) ?? "—"} periods; ${shortfall} additional periods needed).`;
  }

  return {
    claimed_sharpe: claimedSharpe,
    annualization_factor: annualizationFactor,
    observed_periods: observedPeriods,
    skewness,
    excess_kurtosis: excessKurtosis,
    benchmark_sharpe: benchmarkSharpe,
    implied_psr: Math.round(impliedPsr * 1e6) / 1e6,
    required_min_trl_periods_95pct: requiredMinTrl95,
    sufficiency_tier: sufficiencyTier,
    bell_curve_points: bellCurvePoints,
    plain_english_summary: plainEnglishSummary,
  };
}

export function buildPlausibilityQueryString(inputs: PlausibilityInputs): string {
  const params = new URLSearchParams();
  params.set("sharpe", inputs.claimedSharpe.toFixed(2));
  params.set("days", String(Math.round(inputs.observedPeriods)));
  params.set("skew", inputs.skewness.toFixed(2));
  params.set("kurt", inputs.excessKurtosis.toFixed(2));
  params.set("bench", inputs.benchmarkSharpe.toFixed(2));
  params.set("ann", String(Math.round(inputs.annualizationFactor)));
  return `?${params.toString()}`;
}

export function parsePlausibilityQueryParams(
  searchParams: URLSearchParams | Record<string, string | undefined>,
): PlausibilityInputs {
  const readNum = (key: string, fallback: number): number => {
    const raw =
      searchParams instanceof URLSearchParams
        ? searchParams.get(key)
        : searchParams[key];
    if (raw == null || raw.trim() === "") return fallback;
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : fallback;
  };

  return {
    claimedSharpe: clampFinite(readNum("sharpe", 3.2), -5.0, 15.0, 3.2),
    observedPeriods: Math.round(clampFinite(readNum("days", 42), 1, 25200, 42)),
    skewness: clampFinite(readNum("skew", -1.5), -6.0, 6.0, -1.5),
    excessKurtosis: clampFinite(readNum("kurt", 6.0), -1.95, 30.0, 6.0),
    benchmarkSharpe: clampFinite(readNum("bench", 0.5), -2.0, 10.0, 0.5),
    annualizationFactor: Math.round(
      clampFinite(readNum("ann", 252), 1, 3650, 252),
    ),
  };
}

/**
 * Strictly strips HTML/XML brackets, control characters, bidi overrides, and unsafe URI
 * schemes so user-supplied handles/claims can never inject markup or script payloads.
 */
export function sanitizePlainInput(raw: string, maxLen = 80): string {
  const cleaned = String(raw ?? "")
    .replace(/[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069\uFFFE\uFFFF]/g, " ")
    .replace(/<@[!&]?\d+>|<!?[a-z]+>/gi, " ")
    .replace(/<[^>]*>/g, " ")
    .replace(/[<>`"']/g, "")
    .replace(/\b(?:javascript|data|vbscript)\s*:/gi, "")
    .replace(/\bon[a-z0-9_]+\s*=/gi, "")
    .replace(/@+(everyone|here)\b/gi, "$1")
    .replace(/\s+/g, " ")
    .trim();
  return cleaned.slice(0, maxLen);
}

export function sanitizeHandleInput(raw: string): string {
  const base = sanitizePlainInput(raw, 36).replace(/[^A-Za-z0-9_.\-@]/g, "");
  const stripped = base.replace(/^@+/, "").replace(/@+/g, "");
  if (!stripped) return "";
  if (/^(?:everyone|here)/i.test(stripped)) return "";
  return `@${stripped}`;
}

export type ChallengeTone = "institutional" | "peer_quant" | "concise_reply";

export function buildPoliteChallengeReply(options: {
  handle: string;
  claimText: string;
  assetContext?: string;
  tone?: ChallengeTone;
  originUrl?: string;
}): {
  sanitizedHandle: string;
  sanitizedClaim: string;
  sanitizedContext: string;
  replyText: string;
  challengeUrl: string;
} {
  const sanitizedHandle = sanitizeHandleInput(options.handle);
  const sanitizedClaim = sanitizePlainInput(options.claimText, 72);
  const sanitizedContext = sanitizePlainInput(options.assetContext ?? "", 48);
  const baseOrigin = (options.originUrl ?? "https://verify.n170.io").replace(
    /\/+$/,
    "",
  );

  const params = new URLSearchParams();
  if (sanitizedHandle) params.set("handle", sanitizedHandle);
  if (sanitizedClaim) params.set("claim", sanitizedClaim);
  if (sanitizedContext) params.set("context", sanitizedContext);
  const qs = params.toString();
  const challengeUrl = `${baseOrigin}/challenge${qs ? `?${qs}` : ""}`;
  const connectUrl = `${baseOrigin}/connect`;

  const greeting = sanitizedHandle ? `Impressive numbers ${sanitizedHandle}` : "Impressive numbers";
  const claimClause = sanitizedClaim ? ` on the ${sanitizedClaim} run` : "";

  let replyText: string;
  if (options.tone === "institutional") {
    replyText = `${greeting}${claimClause}. If you ever want to share a cryptographic percentage tear sheet for LP/peer review without revealing dollar NAV, account ID, or live positions (7-day embargo on closed trades), N170 Verify (Apache-2.0) generates a client-verifiable Indexed-100 proof in ~60s: ${connectUrl}`;
  } else if (options.tone === "concise_reply") {
    replyText = `${greeting}${claimClause} — would love to see an Indexed-100 cryptographic tear sheet on N170 Verify (60s read-only setup; $ NAV, account ID, and live open positions stay 100% private): ${challengeUrl}`;
  } else {
    replyText = `${greeting}${claimClause}! If you're open to sharing a privacy-preserving proof, you can verify pure % returns in 60s on N170 Verify while keeping $ balance, raw account ID, and live open positions (7-day guard) 100% private: ${challengeUrl}`;
  }

  return {
    sanitizedHandle,
    sanitizedClaim,
    sanitizedContext,
    replyText,
    challengeUrl,
  };
}
