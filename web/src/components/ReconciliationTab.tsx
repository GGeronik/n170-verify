"use client";

import {
  CheckOutcome,
  RECONCILIATION_STATUS_META,
  type ExtractedBundleLeaves,
} from "@/lib/contracts.ts";

const CANONICAL_LEDGER_SECTIONS = [
  "PriorPeriodPositions",
  "Trades",
  "Transfers",
  "CorporateActions",
  "OptionEAE",
] as const;

const OUTCOME_BADGE: Record<
  CheckOutcome,
  { label: string; style: string }
> = {
  pass: {
    label: "PASS",
    style: "badge-emerald",
  },
  explained_convention: {
    label: "EXPLAINED CONVENTION",
    style: "badge-champagne",
  },
  discrepancy: {
    label: "UNEXPLAINED RESIDUAL",
    style: "badge-ochre",
  },
  not_evaluated: {
    label: "NOT EVALUATED",
    style: "badge-neutral",
  },
};

export function ReconciliationTab({ leaves }: { leaves: ExtractedBundleLeaves }) {
  const recon = leaves.reconciliation;

  if (!recon) {
    return (
      <div className="inst-panel rounded-md p-6 text-sm text-ink-muted">
        Reconciliation leaf is not disclosed in this proof bundle.
      </div>
    );
  }

  const statusMeta = RECONCILIATION_STATUS_META[recon.status];
  const missingSet = new Set(
    (recon.missing_sections ?? []).map((s) => s.trim().toLowerCase()),
  );

  return (
    <div className="space-y-6">
      {/* Summary & 5-Section Completeness Gate */}
      <div className="inst-panel rounded-md p-5 print-avoid-break">
        <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-[10px] font-semibold uppercase tracking-widest text-signal-champagne">
                Accounting Identity Engine
              </span>
              <span className="rounded border border-hairline-strong bg-elevated px-2 py-0.5 font-mono text-[10px] text-ink-secondary">
                Market Reference: {recon.reference_provider.toUpperCase()}
              </span>
            </div>
            <h3 className="editorial-serif mt-1 text-xl text-ink sm:text-2xl">
              5-Section Ledger Completeness &amp; Fill Envelope Audit
            </h3>
            <p className="mt-1 text-xs text-ink-secondary">{recon.summary_text}</p>
          </div>

          <div className="flex items-center gap-2.5 font-mono text-xs tabular-nums">
            <span className="rounded border border-hairline-strong bg-elevated px-2.5 py-1 text-ink-secondary">
              {recon.checks_evaluated} checks
            </span>
            <span
              className={`rounded px-2.5 py-1 font-semibold ${
                recon.discrepancy_count > 0 ? "badge-ochre" : "badge-emerald"
              }`}
            >
              {statusMeta.shortLabel}
            </span>
          </div>
        </div>

        {/* 5 Mandatory Non-Cash & Cash Ledger Sections */}
        <div className="mt-4 grid grid-cols-2 gap-2.5 sm:grid-cols-5">
          {CANONICAL_LEDGER_SECTIONS.map((sec) => {
            const isMissing = missingSet.has(sec.toLowerCase());
            return (
              <div
                key={sec}
                className={`rounded px-3 py-2 font-mono text-xs ${
                  isMissing ? "badge-ochre" : "badge-emerald"
                }`}
              >
                <div className="flex items-center justify-between gap-1">
                  <span className="truncate text-[11px] font-semibold">&lt;{sec}&gt;</span>
                  <span className="text-[9.5px] font-bold">
                    {isMissing ? "MISSING" : "OK"}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Period-by-Period Accounting Identity & 2-Stage Fill Envelope Findings */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-ink">
            Period-by-Period NAV Identities &amp; 2-Stage Fill Envelope Checks
          </h3>
          <span className="font-mono text-[11px] text-ink-muted">
            Neutral mathematical residuals — zero arbitrary heuristic cutoffs
          </span>
        </div>

        {recon.findings.map((finding, idx) => {
          const badge = OUTCOME_BADGE[finding.outcome] ?? OUTCOME_BADGE.not_evaluated;
          return (
            <div
              key={`${finding.category}-${finding.date_or_timestamp}-${idx}`}
              className="inst-panel rounded-md p-4 print-avoid-break"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`rounded px-2 py-0.5 font-mono text-[10px] font-semibold ${badge.style}`}>
                    {badge.label}
                  </span>
                  <span className="font-mono text-xs font-semibold text-ink">
                    {finding.category}
                  </span>
                  {finding.symbol && (
                    <span className="rounded border border-hairline-strong bg-elevated px-2 py-0.5 font-mono text-[11px] font-semibold text-signal-emerald">
                      {finding.symbol}
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-3 font-mono text-xs text-ink-muted tabular-nums">
                  <span>{finding.date_or_timestamp}</span>
                  {finding.residual_bps != null && (
                    <span
                      className={
                        finding.outcome === CheckOutcome.DISCREPANCY
                          ? "font-semibold text-signal-ochre"
                          : "text-ink-secondary"
                      }
                    >
                      residual: {finding.residual_bps >= 0 ? "+" : ""}
                      {finding.residual_bps.toFixed(2)} bps
                    </span>
                  )}
                </div>
              </div>

              {finding.math_identity && (
                <div className="mt-2.5 overflow-x-auto rounded border border-hairline bg-elevated px-3 py-2 font-mono text-xs text-signal-champagne tabular-nums">
                  {finding.math_identity}
                  {finding.expected_value != null && finding.observed_value != null && (
                    <span className="ml-3 text-ink-muted">
                      (expected={finding.expected_value.toFixed(2)}, observed=
                      {finding.observed_value.toFixed(2)})
                    </span>
                  )}
                </div>
              )}

              <p className="mt-2.5 text-xs leading-relaxed text-ink-secondary">
                {finding.technical_explanation}
              </p>

              {finding.benign_causes_considered.length > 0 && (
                <div className="mt-3 flex flex-wrap items-center gap-1.5">
                  <span className="font-mono text-[10px] uppercase tracking-wider text-ink-muted">
                    Benign Conventions Evaluated:
                  </span>
                  {finding.benign_causes_considered.map((cause) => (
                    <span
                      key={cause}
                      className="rounded border border-hairline bg-elevated px-2 py-0.5 font-mono text-[10.5px] text-ink-secondary"
                    >
                      {cause}
                    </span>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Separated Contextual Statistical Diagnostics */}
      {recon.statistical_diagnostics.length > 0 && (
        <div className="space-y-3 border-t border-hairline pt-5 print-avoid-break">
          <div>
            <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-ink">
              Contextual Return &amp; Microstructure Diagnostics (Separated from Ledger Proof)
            </h3>
            <p className="mt-0.5 text-xs text-ink-muted">
              Descriptive return-distribution metrics reported with explicit sample caveats.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {recon.statistical_diagnostics.map((diag) => (
              <div key={diag.metric_name} className="inst-panel rounded-md p-4">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-semibold text-ink">
                    {diag.metric_name}
                  </span>
                  {diag.observed_value != null && (
                    <span className="badge-emerald rounded px-2 py-0.5 font-mono text-xs font-semibold tabular-nums">
                      {diag.observed_value}
                    </span>
                  )}
                </div>
                <p className="mt-2 text-xs leading-relaxed text-ink-secondary">
                  {diag.interpretation}
                </p>
                {diag.caveats.length > 0 && (
                  <ul className="mt-2 list-disc space-y-0.5 pl-4 text-[11px] text-ink-muted">
                    {diag.caveats.map((cav) => (
                      <li key={cav}>{cav}</li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
