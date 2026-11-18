"use client";

import { ArrowRight, CheckCircle2, FileText, Layers, ShieldCheck, Upload } from "lucide-react";
import { useEffect, useState } from "react";
import { verifyProofBundle } from "@/lib/browserVerify.ts";
import {
  CHAIN_CONTINUITY_META,
  ORIGIN_ASSURANCE_META,
  RECONCILIATION_STATUS_META,
  extractTypedLeaves,
  type BundleVerificationResult,
  type VerifyProofBundle,
} from "@/lib/contracts.ts";
import {
  BUNDLE_INSTITUTIONAL_SEQ0,
  BUNDLE_INSTITUTIONAL_SEQ1,
  DEMO_REGISTRY_DOCUMENT,
} from "@/lib/demoFixtures.ts";
import { fmtNum, fmtPct } from "@/lib/wave4Analytics.ts";

export default function RetainedCopyDiffPage() {
  const [retainedRaw, setRetainedRaw] = useState<string>(() =>
    JSON.stringify(BUNDLE_INSTITUTIONAL_SEQ0, null, 2),
  );
  const [candidateRaw, setCandidateRaw] = useState<string>(() =>
    JSON.stringify(BUNDLE_INSTITUTIONAL_SEQ1, null, 2),
  );

  const [retainedBundle, setRetainedBundle] = useState<VerifyProofBundle | null>(
    BUNDLE_INSTITUTIONAL_SEQ0,
  );
  const [candidateBundle, setCandidateBundle] = useState<VerifyProofBundle | null>(
    BUNDLE_INSTITUTIONAL_SEQ1,
  );

  const [retainedResult, setRetainedResult] = useState<BundleVerificationResult | null>(null);
  const [candidateResult, setCandidateResult] = useState<BundleVerificationResult | null>(null);
  const [verifying, setVerifying] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const runVerification = async () => {
      if (!retainedBundle || !candidateBundle) return;
      setVerifying(true);
      try {
        const [resRetained, resCandidate] = await Promise.all([
          verifyProofBundle(retainedBundle, { registryDoc: DEMO_REGISTRY_DOCUMENT }),
          verifyProofBundle(candidateBundle, { registryDoc: DEMO_REGISTRY_DOCUMENT }),
        ]);
        if (!cancelled) {
          setRetainedResult(resRetained);
          setCandidateResult(resCandidate);
        }
      } finally {
        if (!cancelled) setVerifying(false);
      }
    };
    void runVerification();
    return () => {
      cancelled = true;
    };
  }, [retainedBundle, candidateBundle]);

  const handleRetainedChange = (text: string) => {
    setRetainedRaw(text);
    try {
      const parsed = JSON.parse(text) as VerifyProofBundle;
      if (parsed && typeof parsed.proof_id === "string") {
        setRetainedBundle(parsed);
      }
    } catch {
      // Keep existing bundle on parse error
    }
  };

  const handleCandidateChange = (text: string) => {
    setCandidateRaw(text);
    try {
      const parsed = JSON.parse(text) as VerifyProofBundle;
      if (parsed && typeof parsed.proof_id === "string") {
        setCandidateBundle(parsed);
      }
    } catch {
      // Keep existing bundle on parse error
    }
  };

  // Analyze sequence continuity
  const retainedSeq = retainedBundle?.prospective_chain_link?.sequence_number ?? 0;
  const candidateSeq = candidateBundle?.prospective_chain_link?.sequence_number ?? 0;
  const prevHashMatches =
    candidateBundle?.prospective_chain_link?.prev_proof_hash === retainedResult?.proof_hash;
  const accountTagMatches =
    retainedBundle?.blinded_account_tag === candidateBundle?.blinded_account_tag;

  let continuityVerdict = "EVALUATING";
  let verdictTone = "neutral";
  if (retainedResult && candidateResult) {
    if (!retainedResult.valid || !candidateResult.valid) {
      continuityVerdict = "REJECTED: INVALID SIGNATURE OR MERKLE ROOT";
      verdictTone = "vermilion";
    } else if (candidateSeq === retainedSeq + 1 && prevHashMatches && accountTagMatches) {
      continuityVerdict = "VALID CONTINUATION: SEQUENCE MONOTONIC & HASH LINKED";
      verdictTone = "emerald";
    } else if (candidateSeq <= retainedSeq) {
      continuityVerdict = "CONFLICT: TRUNCATION OR STALE SEQUENCE DETECTED";
      verdictTone = "vermilion";
    } else if (!accountTagMatches) {
      continuityVerdict = "CONFLICT: REPLACEMENT (DIFFERENT BLINDED ACCOUNT)";
      verdictTone = "vermilion";
    } else {
      continuityVerdict = "CONFLICT: BROKEN HASH LINKAGE ACROSS PERIODS";
      verdictTone = "ochre";
    }
  }

  const retLeaves = retainedBundle ? extractTypedLeaves(retainedBundle) : null;
  const candLeaves = candidateBundle ? extractTypedLeaves(candidateBundle) : null;

  return (
    <div className="min-h-screen bg-canvas font-sans text-ink antialiased">
      <div className="bg-telemetry-grid">
        <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
          {/* Header */}
          <div className="mb-8 space-y-3">
            <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] tracking-wide text-ink-secondary">
              <span className="rounded border border-hairline-strong bg-elevated px-2 py-0.5 uppercase">
                DIFF / COMPARISON
              </span>
              <span>•</span>
              <span>Retained-Copy Verification Studio</span>
            </div>
            <h1 className="text-2xl font-bold tracking-telemetry sm:text-3xl">
              Retained-Copy Comparison & Continuity Verifier
            </h1>
            <p className="max-w-3xl text-sm leading-relaxed text-ink-secondary">
              Compare an existing retained proof against an updated candidate record. WebCrypto checks
              monotonic sequence progression, cryptographic parent-hash linkage, and metric variances
              entirely client-side with zero data transmission.
            </p>
          </div>

          {/* Continuity Verdict Banner */}
          <div
            className={`mb-8 rounded-lg border p-4 transition-all ${
              verdictTone === "emerald"
                ? "border-signal-emerald-border bg-signal-emerald-bg/30 text-signal-emerald"
                : verdictTone === "vermilion"
                  ? "border-signal-vermilion-border bg-signal-vermilion-bg/30 text-signal-vermilion"
                  : "border-hairline-strong bg-elevated text-ink"
            }`}
          >
            <div className="flex items-center gap-3">
              <ShieldCheck className="h-5 w-5 shrink-0" />
              <div>
                <p className="font-mono text-xs font-semibold uppercase tracking-wider">
                  Continuity Status
                </p>
                <p className="text-sm font-bold tracking-tight">
                  {verifying ? "Computing WebCrypto Invariants..." : continuityVerdict}
                </p>
              </div>
            </div>
          </div>

          {/* Split Dropzones */}
          <div className="mb-8 grid gap-6 lg:grid-cols-2">
            {/* Retained Panel */}
            <div className="space-y-3 rounded-lg border border-hairline bg-surface p-5">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-semibold uppercase text-ink-secondary">
                  Reference Copy (Sequence {retainedSeq})
                </span>
                <span className="font-mono text-[11px] text-ink-muted">
                  {retainedResult?.valid ? "Signature Valid" : "Unchecked"}
                </span>
              </div>
              <textarea
                value={retainedRaw}
                onChange={(e) => handleRetainedChange(e.target.value)}
                rows={8}
                className="w-full rounded border border-hairline bg-canvas p-3 font-mono text-xs text-ink focus:border-signal-emerald focus:outline-none"
                placeholder="Paste reference VerifyProofBundle JSON..."
              />
              <div className="font-mono text-xs text-ink-secondary">
                Proof ID: <span className="text-ink">{retainedBundle?.proof_id ?? "None"}</span>
              </div>
            </div>

            {/* Candidate Panel */}
            <div className="space-y-3 rounded-lg border border-hairline bg-surface p-5">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-semibold uppercase text-ink-secondary">
                  Candidate Copy (Sequence {candidateSeq})
                </span>
                <span className="font-mono text-[11px] text-ink-muted">
                  {candidateResult?.valid ? "Signature Valid" : "Unchecked"}
                </span>
              </div>
              <textarea
                value={candidateRaw}
                onChange={(e) => handleCandidateChange(e.target.value)}
                rows={8}
                className="w-full rounded border border-hairline bg-canvas p-3 font-mono text-xs text-ink focus:border-signal-emerald focus:outline-none"
                placeholder="Paste candidate VerifyProofBundle JSON..."
              />
              <div className="font-mono text-xs text-ink-secondary">
                Proof ID: <span className="text-ink">{candidateBundle?.proof_id ?? "None"}</span>
              </div>
            </div>
          </div>

          {/* Comparative Metrics Table */}
          <div className="overflow-hidden rounded-lg border border-hairline bg-surface">
            <div className="border-b border-hairline px-6 py-4">
              <h2 className="text-sm font-semibold tracking-telemetry text-ink">
                Verified Metric Deltas & Leaf Evolution
              </h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-hairline bg-elevated/40 font-mono text-ink-secondary">
                    <th className="px-6 py-3 font-medium">Dimension</th>
                    <th className="px-6 py-3 font-medium">Reference Value</th>
                    <th className="px-6 py-3 font-medium">Candidate Value</th>
                    <th className="px-6 py-3 font-medium">Observed Delta</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-hairline">
                  <tr>
                    <td className="px-6 py-3.5 font-medium text-ink">Sequence Number</td>
                    <td className="px-6 py-3.5 font-mono text-ink-secondary">{retainedSeq}</td>
                    <td className="px-6 py-3.5 font-mono text-ink">{candidateSeq}</td>
                    <td className="px-6 py-3.5 font-mono font-semibold text-signal-emerald">
                      +{candidateSeq - retainedSeq}
                    </td>
                  </tr>
                  <tr>
                    <td className="px-6 py-3.5 font-medium text-ink">Period Horizon</td>
                    <td className="px-6 py-3.5 font-mono text-ink-secondary">
                      {retainedBundle?.period_start_utc.slice(0, 10)} to{" "}
                      {retainedBundle?.period_end_utc.slice(0, 10)}
                    </td>
                    <td className="px-6 py-3.5 font-mono text-ink">
                      {candidateBundle?.period_start_utc.slice(0, 10)} to{" "}
                      {candidateBundle?.period_end_utc.slice(0, 10)}
                    </td>
                    <td className="px-6 py-3.5 font-mono text-ink-secondary">Extended</td>
                  </tr>
                  <tr>
                    <td className="px-6 py-3.5 font-medium text-ink">Indexed TWR</td>
                    <td className="px-6 py-3.5 font-mono text-ink-secondary">
                      {fmtPct(retLeaves?.coreMetrics?.twr_decimal)}
                    </td>
                    <td className="px-6 py-3.5 font-mono text-ink">
                      {fmtPct(candLeaves?.coreMetrics?.twr_decimal)}
                    </td>
                    <td className="px-6 py-3.5 font-mono text-signal-emerald">
                      {retLeaves?.coreMetrics?.twr_decimal != null &&
                      candLeaves?.coreMetrics?.twr_decimal != null
                        ? fmtPct(
                            candLeaves.coreMetrics.twr_decimal -
                              retLeaves.coreMetrics.twr_decimal,
                          )
                        : "-"}
                    </td>
                  </tr>
                  <tr>
                    <td className="px-6 py-3.5 font-medium text-ink">Max Drawdown</td>
                    <td className="px-6 py-3.5 font-mono text-ink-secondary">
                      {fmtPct(retLeaves?.coreMetrics?.max_drawdown_decimal)}
                    </td>
                    <td className="px-6 py-3.5 font-mono text-ink">
                      {fmtPct(candLeaves?.coreMetrics?.max_drawdown_decimal)}
                    </td>
                    <td className="px-6 py-3.5 font-mono text-ink-secondary">
                      {retLeaves?.coreMetrics?.max_drawdown_decimal != null &&
                      candLeaves?.coreMetrics?.max_drawdown_decimal != null
                        ? fmtPct(
                            candLeaves.coreMetrics.max_drawdown_decimal -
                              retLeaves.coreMetrics.max_drawdown_decimal,
                          )
                        : "-"}
                    </td>
                  </tr>
                  <tr>
                    <td className="px-6 py-3.5 font-medium text-ink">Disclosed Merkle Leaves</td>
                    <td className="px-6 py-3.5 font-mono text-ink-secondary">
                      {retainedBundle?.disclosed_leaves.length ?? 0} leaves
                    </td>
                    <td className="px-6 py-3.5 font-mono text-ink">
                      {candidateBundle?.disclosed_leaves.length ?? 0} leaves
                    </td>
                    <td className="px-6 py-3.5 font-mono text-ink-secondary">
                      {(candidateBundle?.disclosed_leaves.length ?? 0) -
                        (retainedBundle?.disclosed_leaves.length ?? 0)}{" "}
                      delta
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
