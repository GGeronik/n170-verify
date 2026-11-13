/**
 * N170 Verify: Typed Client & Server API Adapter (`NEXT_PUBLIC_N170_VERIFY_API_URL`).
 *
 * Connects `/connect`, `/p/[proofId]`, `/verify`, `/leaderboard`, and
 * `/.well-known/n170-verify-keys.json` to `./api` when configured,
 * with automatic offline fallback to cryptographically signed showcase bundles
 * when running offline or statically hosted.
 */

import {
  type BundleVerificationResult,
  type CanonicalLeafName,
  type NotaryNodeInfo,
  type PublisherKeyRecord,
  type PublisherKeyRegistryDocument,
  type VerifyProofBundle,
} from "./contracts.ts";
import {
  DEMO_REGISTRY_DOCUMENT,
  findShowcaseProfile,
  type ShowcaseProfileMeta,
} from "./demoFixtures.ts";

export interface ApiProofLookupResponse {
  proof_bundle: VerifyProofBundle;
  proof_hash: string;
  opt_in_leaderboard?: boolean;
  stored_at_utc?: string;
  verification?: BundleVerificationResult;
}

export interface ApiOneShotVerifyRequest {
  broker_id: string;
  raw_statement?: string;
  csv_format?: "degiro" | "robinhood" | "schwab";
  base_currency?: string;
  benchmark_symbol?: string;
  disclose_leaf_names?: CanonicalLeafName[];
  publish_proof?: boolean;
  opt_in_leaderboard?: boolean;
  persist_sync?: boolean;
  sync_credentials?: Record<string, string>;
}

export interface ApiOneShotVerifyResponse {
  proof_bundle: VerifyProofBundle;
  verification: BundleVerificationResult;
  isolation_receipt: {
    worker_pid: number;
    parent_pid: number;
    rlimit_core_soft: number;
    rlimit_core_hard: number;
    pr_dumpable: number | null;
    retention_mode: string;
    persistent_rows_written: number;
  };
  stripped_recent_closed_trades_count: number;
}

export interface ApiLeaderboardEntrySummary {
  proof_id: string;
  proof_hash: string;
  broker_id: string;
  blinded_account_tag: string;
  period_start_utc: string;
  period_end_utc: string;
  issued_at_utc: string;
  effective_origin_assurance: string;
  account_scope: string;
  effective_chain_continuity_mode: string;
  signer_trust_status: string;
  reconciliation_status: string | null;
  capital_bracket: string;
  twr_decimal: number | null;
  twr_pct: number | null;
  probabilistic_sharpe_ratio: number | null;
  max_drawdown_decimal: number | null;
  badge_url: string;
}

export interface ApiLeaderboardResponse {
  filters: Record<string, unknown>;
  count: number;
  entries: ApiLeaderboardEntrySummary[];
}

function normalizeBaseUrl(raw: string | undefined | null): string | null {
  const cleaned = (raw ?? "").trim().replace(/\/+$/, "");
  return cleaned.length > 0 ? cleaned : null;
}

/**
 * Returns the configured N170 Verify API base URL (or `null` when running in
 * pure client-side / offline mode).
 */
export function getConfiguredApiBaseUrl(): string | null {
  if (typeof window === "undefined") {
    return normalizeBaseUrl(
      process.env.N170_VERIFY_INTERNAL_API_URL ??
        process.env.NEXT_PUBLIC_N170_VERIFY_API_URL,
    );
  }
  return normalizeBaseUrl(process.env.NEXT_PUBLIC_N170_VERIFY_API_URL);
}

/**
 * Returns the public browser-reachable API URL for SVG badge embeds and links.
 */
export function getPublicApiBaseUrl(): string | null {
  return normalizeBaseUrl(process.env.NEXT_PUBLIC_N170_VERIFY_API_URL);
}

export function getBadgeSvgUrl(
  proofId: string,
  baseUrlOverride?: string | null,
): string | null {
  const base =
    normalizeBaseUrl(baseUrlOverride) ??
    getPublicApiBaseUrl() ??
    getConfiguredApiBaseUrl();
  if (!base) {
    return null;
  }
  return `${base}/api/v1/badges/${encodeURIComponent(proofId)}.svg`;
}

export async function fetchLiveRegistryDocument(
  fetchImpl: typeof fetch = fetch,
): Promise<PublisherKeyRegistryDocument | null> {
  const base = getConfiguredApiBaseUrl();
  if (!base) {
    return null;
  }
  try {
    const resp = await fetchImpl(`${base}/.well-known/n170-verify-keys.json`, {
      method: "GET",
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    if (!resp.ok) {
      return null;
    }
    const doc = (await resp.json()) as PublisherKeyRegistryDocument;
    if (!doc || !Array.isArray(doc.keys)) {
      return null;
    }
    return doc;
  } catch {
    return null;
  }
}


export function combineRegistryDocuments(
  liveDoc: PublisherKeyRegistryDocument | null,
): PublisherKeyRegistryDocument {
  if (!liveDoc) {
    return DEMO_REGISTRY_DOCUMENT;
  }
  const seenKids = new Set<string>(liveDoc.keys.map((k) => k.publisher_kid));
  const mergedKeys: PublisherKeyRecord[] = [...liveDoc.keys];
  for (const dk of DEMO_REGISTRY_DOCUMENT.keys) {
    if (!seenKids.has(dk.publisher_kid)) {
      mergedKeys.push(dk);
    }
  }

  const seenNotaries = new Set<string>(liveDoc.notaries.map((n) => n.notary_id));
  const mergedNotaries: NotaryNodeInfo[] = [...liveDoc.notaries];
  for (const dn of DEMO_REGISTRY_DOCUMENT.notaries) {
    if (!seenNotaries.has(dn.notary_id)) {
      mergedNotaries.push(dn);
    }
  }

  return {
    ...liveDoc,
    keys: mergedKeys,
    notaries: mergedNotaries,
  };
}

export async function fetchActiveRegistryDocument(
  fetchImpl: typeof fetch = fetch,
): Promise<{
  registryDoc: PublisherKeyRegistryDocument;
  liveConnected: boolean;
}> {
  const liveDoc = await fetchLiveRegistryDocument(fetchImpl);
  return {
    registryDoc: combineRegistryDocuments(liveDoc),
    liveConnected: liveDoc !== null,
  };
}

export async function fetchPublicProofFromApi(
  proofId: string,
  fetchImpl: typeof fetch = fetch,
): Promise<ApiProofLookupResponse | null> {
  const base = getConfiguredApiBaseUrl();
  if (!base) {
    return null;
  }
  try {
    const resp = await fetchImpl(
      `${base}/api/v1/proofs/${encodeURIComponent(proofId)}`,
      {
        method: "GET",
        headers: { Accept: "application/json" },
        cache: "no-store",
      },
    );
    if (!resp.ok) {
      return null;
    }
    const parsed = (await resp.json()) as ApiProofLookupResponse;
    if (!parsed || typeof parsed.proof_bundle !== "object") {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export async function submitOneShotVerification(
  request: ApiOneShotVerifyRequest,
  fetchImpl: typeof fetch = fetch,
): Promise<ApiOneShotVerifyResponse> {
  const base = getConfiguredApiBaseUrl();
  if (!base) {
    throw new Error(
      "NEXT_PUBLIC_N170_VERIFY_API_URL is not configured; start ./api or use the local CLI.",
    );
  }
  const resp = await fetchImpl(`${base}/api/v1/verify`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(request),
  });
  const body = (await resp.json()) as Record<string, unknown>;
  if (!resp.ok) {
    const detail =
      typeof body.detail === "string"
        ? body.detail
        : Array.isArray(body.errors)
          ? body.errors.join("; ")
          : typeof body.error === "string"
            ? body.error
            : `HTTP ${resp.status}`;
    throw new Error(detail);
  }
  return body as unknown as ApiOneShotVerifyResponse;
}

export function safeDecodeURIComponent(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

export function buildLiveProfileMeta(
  b: VerifyProofBundle,
  subtitleLabel = "",
): ShowcaseProfileMeta {
  return {
    proofId: b.proof_id,
    handle: `@acct-${b.blinded_account_tag.slice(0, 8)}`,
    strategyTitle: `Verified ${b.broker_id.toUpperCase()} Portfolio (${b.base_currency})`,
    subtitle: subtitleLabel
      ? `Period ${b.period_start_utc.slice(0, 10)} → ${b.period_end_utc.slice(0, 10)} • ${subtitleLabel}`
      : "",
    assetFocus: "Multi-Asset Live",
    brokerDisplay: b.broker_id.toUpperCase(),
    bundle: b,
    chainHistory: [],
    previewMode: "full_studio",
  };
}

export async function resolveShowcaseOrLiveProfile(
  rawProofId: string,
  options?: { subtitleLabel?: string; fetchImpl?: typeof fetch },
): Promise<ShowcaseProfileMeta | undefined> {
  const cleaned = safeDecodeURIComponent(rawProofId).trim();
  const showcase = findShowcaseProfile(cleaned);
  if (showcase) {
    return showcase;
  }
  const liveResp = await fetchPublicProofFromApi(cleaned, options?.fetchImpl);
  if (liveResp?.proof_bundle) {
    return buildLiveProfileMeta(liveResp.proof_bundle, options?.subtitleLabel ?? "");
  }
  return undefined;
}

export async function fetchLeaderboardProfilesFromApi(
  minCapitalBracket = "under_1k",
  fetchImpl: typeof fetch = fetch,
): Promise<ShowcaseProfileMeta[] | null> {
  const base = getConfiguredApiBaseUrl();
  if (!base) {
    return null;
  }
  try {
    const url = `${base}/api/v1/leaderboard?min_capital_bracket=${encodeURIComponent(minCapitalBracket)}&limit=50`;
    const resp = await fetchImpl(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    if (!resp.ok) {
      return null;
    }
    const leaderboard = (await resp.json()) as ApiLeaderboardResponse;
    if (!leaderboard || !Array.isArray(leaderboard.entries)) {
      return null;
    }
    const profiles: ShowcaseProfileMeta[] = [];
    for (const entry of leaderboard.entries) {
      const proofResp = await fetchPublicProofFromApi(entry.proof_id, fetchImpl);
      if (!proofResp?.proof_bundle) {
        continue;
      }
      profiles.push(buildLiveProfileMeta(proofResp.proof_bundle, "Live API Record"));
    }
    return profiles;
  } catch {
    return null;
  }
}
