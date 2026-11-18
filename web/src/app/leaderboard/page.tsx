"use client";

import { ArrowUpRight } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import {
  fetchActiveRegistryDocument,
  fetchLeaderboardProfilesFromApi,
} from "@/lib/apiClient.ts";
import { verifyProofBundle } from "@/lib/browserVerify.ts";
import {
  ACCOUNT_SCOPE_META,
  CAPITAL_BRACKET_LABELS,
  CHAIN_CONTINUITY_META,
  ORIGIN_ASSURANCE_META,
  RECONCILIATION_STATUS_META,
  extractTypedLeaves,
  type BundleVerificationResult,
} from "@/lib/contracts.ts";
import {
  DEMO_CONTINUITY_LOG_LEAVES,
  SHOWCASE_PROFILES,
  type ShowcaseProfileMeta,
} from "@/lib/demoFixtures.ts";

type OriginFilter = "high_assurance_only" | "include_operator" | "all";

interface VerifiedRow {
  profile: ShowcaseProfileMeta;
  result: BundleVerificationResult;
}

export default function LeaderboardPage() {
  const [originFilter, setOriginFilter] =
    useState<OriginFilter>("include_operator");
  const [enumeratedScopeOnly, setEnumeratedScopeOnly] = useState(false);
  const [prospectiveOnly, setProspectiveOnly] = useState(false);
  const [reconciledOnly, setReconciledOnly] = useState(false);
  const [assetFilter, setAssetFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<"psr_glm" | "twr" | "sharpe">("psr_glm");
  const [rows, setRows] = useState<VerifiedRow[]>([]);
  const [liveDirectoryConnected, setLiveDirectoryConnected] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const verifyAll = async () => {
      const [{ registryDoc, liveConnected }, liveProfiles] = await Promise.all([
        fetchActiveRegistryDocument(),
        fetchLeaderboardProfilesFromApi("under_1k"),
      ]);
      const combinedProfiles: ShowcaseProfileMeta[] = [];
      const seenIds = new Set<string>();
      for (const prof of liveProfiles ?? []) {
        if (!seenIds.has(prof.proofId)) {
          seenIds.add(prof.proofId);
          combinedProfiles.push(prof);
        }
      }
      for (const sp of SHOWCASE_PROFILES) {
        if (!seenIds.has(sp.proofId)) {
          seenIds.add(sp.proofId);
          combinedProfiles.push(sp);
        }
      }

      const evaluated: VerifiedRow[] = [];
      for (const profile of combinedProfiles) {
        const res = await verifyProofBundle(profile.bundle, {
          registryDoc,
          chainHistory: profile.chainHistory,
          continuityLogLeaves:
            profile.proofId === "prf-inst-alpha-012"
              ? DEMO_CONTINUITY_LOG_LEAVES
              : null,
        });
        evaluated.push({ profile, result: res });
      }
      if (!cancelled) {
        setLiveDirectoryConnected(liveConnected && liveProfiles !== null);
        setRows(evaluated);
      }
    };
    void verifyAll();
    return () => {
      cancelled = true;
    };
  }, []);

  const distinctAssets = Array.from(
    new Set(rows.map((r) => r.profile.assetFocus)),
  );

  const filtered = rows
    .filter(({ profile, result }) => {
      if (!result.valid) {
        return false;
      }
      const eff = result.effective_origin_assurance;
      if (originFilter === "high_assurance_only") {
        if (eff !== "broker_signed" && eff !== "independently_witnessed_tls") {
          return false;
        }
      } else if (originFilter === "include_operator") {
        if (eff === "self_reported") {
          return false;
        }
      }
      if (
        enumeratedScopeOnly &&
        profile.bundle.account_scope !== "all_enumerated_subaccounts"
      ) {
        return false;
      }
      if (
        prospectiveOnly &&
        result.effective_chain_continuity_mode !== "prospective_continuous"
      ) {
        return false;
      }
      const leaves = extractTypedLeaves(profile.bundle);
      if (
        reconciledOnly &&
        leaves.reconciliation?.status !== "reconciled_within_tolerance"
      ) {
        return false;
      }
      if (assetFilter !== "all" && profile.assetFocus !== assetFilter) {
        return false;
      }
      return true;
    })
    .sort((a, b) => {
      const la = extractTypedLeaves(a.profile.bundle).coreMetrics;
      const lb = extractTypedLeaves(b.profile.bundle).coreMetrics;
      if (sortBy === "twr") {
        return (lb?.twr_decimal ?? -999) - (la?.twr_decimal ?? -999);
      }
      if (sortBy === "sharpe") {
        return (
          (lb?.unsmoothed_sharpe_ratio ?? lb?.sharpe_ratio ?? -999) -
          (la?.unsmoothed_sharpe_ratio ?? la?.sharpe_ratio ?? -999)
        );
      }
      return (lb?.psr_glm_unsmoothed ?? -1) - (la?.psr_glm_unsmoothed ?? -1);
    });

  return (
    <div className="bg-telemetry-grid">
      <div className="mx-auto max-w-7xl space-y-6 px-4 py-10 sm:px-6 lg:px-8">
        <div className="flex flex-col justify-between gap-4 border-b border-hairline pb-6 lg:flex-row lg:items-end">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
              <span className="badge-emerald rounded px-2 py-0.5 font-semibold uppercase tracking-wider">
                Client-Side WebCrypto Verified Registry
              </span>
              <span className="rounded border border-hairline-strong bg-panel px-2 py-0.5 text-ink-secondary">
                {liveDirectoryConnected
                  ? "Source: Live API + Signed Archive"
                  : "Source: Signed Public Specimens"}
              </span>
            </div>
            <h1 className="editorial-serif text-3xl text-ink sm:text-4xl">
              Multi-Axis Track-Record Registry
            </h1>
            <p className="max-w-3xl text-sm text-ink-secondary">
              Every record below is verified in real time inside your browser via{" "}
              <code className="text-ink">verifyProofBundle</code>. Self-reported exports
              are excluded by default, and single-notary claims are dynamically downgraded
              prior to ranking.
            </p>
          </div>

          <Link
            href="/connect"
            className="inline-flex items-center justify-center rounded border border-signal-emerald bg-signal-emerald px-4 py-2.5 font-mono text-xs font-semibold text-canvas transition hover:opacity-90"
          >
            Publish Verified Record →
          </Link>
        </div>

        {/* Multi-Axis Orthogonal Filter Bar */}
        <div className="inst-panel rounded-md p-4">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3 lg:grid-cols-5">
            <div>
              <label className="block font-mono text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
                Verified Origin Floor
              </label>
              <select
                value={originFilter}
                onChange={(e) => setOriginFilter(e.target.value as OriginFilter)}
                className="mt-1 w-full rounded border border-hairline-strong bg-canvas px-2.5 py-2 font-mono text-xs text-ink"
              >
                <option value="high_assurance_only">
                  Broker-Signed or Witnessed TLS (k&gt;=2)
                </option>
                <option value="include_operator">
                  Include Operator-Retrieved (Default)
                </option>
                <option value="all">Include Self-Reported</option>
              </select>
            </div>

            <div>
              <label className="block font-mono text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
                Asset Class Focus
              </label>
              <select
                value={assetFilter}
                onChange={(e) => setAssetFilter(e.target.value)}
                className="mt-1 w-full rounded border border-hairline-strong bg-canvas px-2.5 py-2 font-mono text-xs text-ink"
              >
                <option value="all">All Asset Classes</option>
                {distinctAssets.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block font-mono text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
                Primary Rank Metric
              </label>
              <select
                value={sortBy}
                onChange={(e) =>
                  setSortBy(e.target.value as "psr_glm" | "twr" | "sharpe")
                }
                className="mt-1 w-full rounded border border-hairline-strong bg-canvas px-2.5 py-2 font-mono text-xs text-ink"
              >
                <option value="psr_glm">PSR_GLM (Unsmoothed Probabilistic SR)</option>
                <option value="sharpe">GLM Unsmoothed Sharpe Ratio</option>
                <option value="twr">Cumulative Flow-Adjusted TWR</option>
              </select>
            </div>

            <div className="flex flex-col justify-end gap-2 lg:col-span-2">
              <div className="flex flex-wrap gap-2">
                <FilterCheck
                  checked={enumeratedScopeOnly}
                  onChange={() => setEnumeratedScopeOnly((v) => !v)}
                  label="All Sub-Accounts"
                />
                <FilterCheck
                  checked={prospectiveOnly}
                  onChange={() => setProspectiveOnly((v) => !v)}
                  label="Prospective Chain"
                />
                <FilterCheck
                  checked={reconciledOnly}
                  onChange={() => setReconciledOnly((v) => !v)}
                  label="Reconciled"
                />
              </div>
            </div>
          </div>
        </div>

        {/* Registry Table */}
        <div className="inst-panel overflow-x-auto rounded-md">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-hairline bg-elevated font-mono text-[10px] uppercase tracking-wider text-ink-muted">
              <tr>
                <th className="px-4 py-3.5">Strategy / Handle</th>
                <th className="px-4 py-3.5">Verified Origin</th>
                <th className="px-4 py-3.5">Scope &amp; Chain</th>
                <th className="px-4 py-3.5">Reconciliation</th>
                <th className="px-4 py-3.5">Capital Tier</th>
                <th className="px-4 py-3.5 text-right">Indexed TWR</th>
                <th className="px-4 py-3.5 text-right">Max DD</th>
                <th className="px-4 py-3.5 text-right">GLM Sharpe</th>
                <th className="px-4 py-3.5 text-right">PSR_GLM</th>
                <th className="px-4 py-3.5 text-right">Tear Sheet</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline">
              {filtered.map(({ profile, result }) => {
                const leaves = extractTypedLeaves(profile.bundle);
                const perf = leaves.coreMetrics;
                const reconStatus =
                  leaves.reconciliation?.status ?? "reference_data_unavailable";
                const downgraded =
                  result.effective_origin_assurance !==
                  profile.bundle.claimed_origin_assurance;

                return (
                  <tr
                    key={profile.proofId}
                    className="transition hover:bg-elevated/60"
                  >
                    <td className="px-4 py-4">
                      <div className="font-semibold tracking-telemetry text-ink">
                        {profile.strategyTitle}
                      </div>
                      <div className="mt-0.5 font-mono text-[11px] text-ink-muted">
                        {profile.handle} • {profile.assetFocus}
                      </div>
                    </td>

                    <td className="px-4 py-4">
                      <span
                        className={`inline-block rounded px-2 py-0.5 font-mono text-[10px] font-semibold ${
                          downgraded ? "badge-ochre" : "badge-champagne"
                        }`}
                      >
                        {
                          ORIGIN_ASSURANCE_META[result.effective_origin_assurance]
                            .shortLabel
                        }
                        {downgraded ? " (Downgraded)" : ""}
                      </span>
                      <div className="mt-1 font-mono text-[10px] text-ink-muted">
                        {profile.brokerDisplay}
                      </div>
                    </td>

                    <td className="px-4 py-4 font-mono text-[11px]">
                      <div className="text-ink">
                        {ACCOUNT_SCOPE_META[profile.bundle.account_scope].shortLabel}
                      </div>
                      <div className="text-[10px] text-signal-emerald">
                        {
                          CHAIN_CONTINUITY_META[
                            result.effective_chain_continuity_mode
                          ].shortLabel
                        }
                      </div>
                    </td>

                    <td className="px-4 py-4">
                      <span
                        className={`inline-block rounded px-2 py-0.5 font-mono text-[10px] font-semibold ${
                          reconStatus === "reconciled_within_tolerance"
                            ? "badge-emerald"
                            : "badge-ochre"
                        }`}
                      >
                        {RECONCILIATION_STATUS_META[reconStatus].shortLabel}
                      </span>
                    </td>

                    <td className="px-4 py-4 font-mono text-[11px] text-ink-secondary tabular-nums">
                      {leaves.capitalBracket
                        ? CAPITAL_BRACKET_LABELS[leaves.capitalBracket]
                        : "Salted-Redacted"}
                    </td>

                    <td className="px-4 py-4 text-right font-mono font-semibold text-signal-emerald tabular-nums">
                      {perf
                        ? `${perf.twr_decimal >= 0 ? "+" : ""}${(
                            perf.twr_decimal * 100
                          ).toFixed(2)}%`
                        : "-"}
                    </td>

                    <td className="px-4 py-4 text-right font-mono text-signal-vermilion tabular-nums">
                      {perf
                        ? `-${Math.abs(perf.max_drawdown_decimal * 100).toFixed(2)}%`
                        : "-"}
                    </td>

                    <td className="px-4 py-4 text-right font-mono text-ink tabular-nums">
                      {perf?.unsmoothed_sharpe_ratio != null
                        ? perf.unsmoothed_sharpe_ratio.toFixed(2)
                        : "-"}
                    </td>

                    <td className="px-4 py-4 text-right font-mono font-semibold text-ink tabular-nums">
                      {perf?.psr_sample_eligible && perf.psr_glm_unsmoothed != null
                        ? `${(perf.psr_glm_unsmoothed * 100).toFixed(1)}%`
                        : "Gated (T<30)"}
                    </td>

                    <td className="px-4 py-4 text-right">
                      <Link
                        href={`/p/${profile.proofId}`}
                        className="inline-flex items-center gap-1 rounded border border-hairline-strong bg-canvas px-2.5 py-1.5 font-mono text-[11px] font-medium text-signal-champagne transition hover:border-signal-champagne"
                      >
                        <span>Inspect</span>
                        <ArrowUpRight className="h-3 w-3" />
                      </Link>
                    </td>
                  </tr>
                );
              })}

              {filtered.length === 0 && (
                <tr>
                  <td
                    colSpan={10}
                    className="px-4 py-10 text-center text-sm text-ink-muted"
                  >
                    No verified bundles match all selected assurance filters. Relax a
                    filter above to view additional records.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function FilterCheck({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: () => void;
  label: string;
}) {
  return (
    <label
      className={`inline-flex cursor-pointer items-center gap-2 rounded border px-3 py-2 font-mono text-[11px] transition ${
        checked
          ? "border-signal-emerald bg-signal-emerald-bg text-signal-emerald"
          : "border-hairline-strong bg-canvas text-ink-secondary"
      }`}
    >
      <input
        type="checkbox"
        checked={checked}
        onChange={onChange}
        className="accent-emerald-500"
      />
      <span>{label}</span>
    </label>
  );
}
