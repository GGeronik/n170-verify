"use client";

import { Swords } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { CoachingStudioTab } from "@/components/CoachingStudioTab.tsx";
import { PerformanceTab } from "@/components/PerformanceTab.tsx";
import { ReconciliationTab } from "@/components/ReconciliationTab.tsx";
import { ShareEmbedStudio } from "@/components/ShareEmbedStudio.tsx";
import { TrustHeader } from "@/components/TrustHeader.tsx";
import { VerifierModal } from "@/components/VerifierModal.tsx";
import { verifyProofBundle } from "@/lib/browserVerify.ts";
import {
  extractTypedLeaves,
  type BundleVerificationResult,
  type ContinuityLogLeaf,
  type PublisherKeyRegistryDocument,
  type VerifyProofBundle,
} from "@/lib/contracts.ts";

export type StudioTabId = "performance" | "reconciliation" | "coaching" | "share";

export interface TearSheetViewProps {
  bundle: VerifyProofBundle;
  registryDoc: PublisherKeyRegistryDocument;
  chainHistory?: readonly VerifyProofBundle[];
  continuityLogLeaves?: readonly ContinuityLogLeaf[];
  title?: string;
  subtitle?: string;
  handle?: string;
  defaultTab?: StudioTabId;
}

export function TearSheetView({
  bundle,
  registryDoc,
  chainHistory = [],
  continuityLogLeaves,
  title,
  subtitle,
  handle,
  defaultTab = "performance",
}: TearSheetViewProps) {
  const [activeTab, setActiveTab] = useState<StudioTabId>(defaultTab);
  const [verification, setVerification] = useState<BundleVerificationResult | null>(
    null,
  );
  const [verifyLatencyMs, setVerifyLatencyMs] = useState<number | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  useEffect(() => {
    setActiveTab(defaultTab);
  }, [defaultTab, bundle.proof_id]);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      const t0 = performance.now();
      const res = await verifyProofBundle(bundle, {
        registryDoc,
        chainHistory,
        continuityLogLeaves:
          continuityLogLeaves && continuityLogLeaves.length > 0
            ? continuityLogLeaves
            : null,
      });
      const elapsed = performance.now() - t0;
      if (!cancelled) {
        setVerification(res);
        setVerifyLatencyMs(elapsed);
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [bundle, registryDoc, chainHistory, continuityLogLeaves]);

  const leaves = extractTypedLeaves(bundle);

  const handleDownloadJson = () => {
    const blob = new Blob([JSON.stringify(bundle, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${bundle.proof_id}.verify.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const allChainBundles =
    bundle.prospective_chain_link != null ? [...chainHistory, bundle] : [];

  return (
    <div className="space-y-6">
      <TrustHeader
        bundle={bundle}
        verification={verification}
        registryDoc={registryDoc}
        verifyLatencyMs={verifyLatencyMs}
        title={title}
        subtitle={subtitle}
        handle={handle}
        onOpenVerifier={() => setModalOpen(true)}
        onOpenShareStudio={() => setActiveTab("share")}
        onDownloadBundle={handleDownloadJson}
      />

      {/* Prospective Hash-Linked Chain Strip */}
      {allChainBundles.length > 0 && (
        <div className="inst-panel rounded-md p-4 print-avoid-break">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="font-mono text-xs font-semibold text-signal-champagne">
                PROSPECTIVE HASH-LINKED CHAIN ({bundle.prospective_chain_link?.chain_id})
              </span>
              <span className="text-xs text-ink-muted">
                &le;24h genesis window • contiguous flow-adjusted index linkage
              </span>
            </div>
            <span className="font-mono text-[11px] text-ink-secondary tabular-nums">
              {allChainBundles.length} committed link{allChainBundles.length === 1 ? "" : "s"}
            </span>
          </div>

          <div className="mt-3 grid grid-cols-1 gap-2.5 sm:grid-cols-3">
            {allChainBundles.map((item) => {
              const link = item.prospective_chain_link!;
              const isCurrent = item.proof_id === bundle.proof_id;
              return (
                <div
                  key={item.proof_id}
                  className={`rounded border p-3 font-mono text-xs tabular-nums ${
                    isCurrent
                      ? "border-signal-emerald-border bg-signal-emerald-bg"
                      : "border-hairline bg-elevated"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-ink">
                      Seq #{link.sequence_number} ({item.proof_id})
                    </span>
                    <span className="text-[11px] font-semibold text-signal-emerald">
                      {link.beginning_index_value.toFixed(2)} →{" "}
                      {link.ending_index_value.toFixed(2)}
                    </span>
                  </div>
                  <p className="mt-1 text-[10.5px] text-ink-secondary">
                    {link.period_start_utc.slice(0, 10)} → {link.period_end_utc.slice(0, 10)}
                  </p>
                  <p className="mt-0.5 truncate text-[10px] text-ink-muted">
                    prev:{" "}
                    {link.prev_proof_hash
                      ? `${link.prev_proof_hash.slice(0, 18)}…`
                      : "GENESIS (null)"}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Interactive Studio Tabs (Screen Only) */}
      <div className="no-print space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-hairline">
          <div
            className="flex flex-wrap gap-1 sm:gap-2"
            role="tablist"
            aria-label="Tear Sheet Studio Tabs"
          >
            <TabButton
              active={activeTab === "performance"}
              onClick={() => setActiveTab("performance")}
              badge="GLM + Bootstrap"
              label="Performance & Curves"
            />
            <TabButton
              active={activeTab === "reconciliation"}
              onClick={() => setActiveTab("reconciliation")}
              badge={
                leaves.reconciliation?.discrepancy_count
                  ? `${leaves.reconciliation.discrepancy_count} Residual`
                  : "0 Residuals"
              }
              warn={Boolean(leaves.reconciliation?.discrepancy_count)}
              label="Accounting Reconciliation"
            />
            <TabButton
              active={activeTab === "coaching"}
              onClick={() => setActiveTab("coaching")}
              badge="DNA + Twin + Ie"
              label="Execution Coaching & Catalysts"
            />
            <TabButton
              active={activeTab === "share"}
              onClick={() => setActiveTab("share")}
              badge="16:9 • 9:16 • Discord"
              label="Share & Embed Studio"
            />
          </div>

          <Link
            href={`/vs/${encodeURIComponent(bundle.proof_id)}/${
              bundle.proof_id === "prf-xray-residual-004"
                ? "demo-tls-alpha"
                : "demo-ibkr-flex"
            }`}
            className="mb-1.5 inline-flex items-center gap-1.5 rounded border border-hairline-strong bg-elevated px-2.5 py-1.5 font-mono text-[11px] font-medium text-ink-secondary transition hover:border-signal-champagne hover:text-ink"
          >
            <Swords className="h-3.5 w-3.5 text-signal-champagne" />
            <span>Compare in /vs Arena</span>
          </Link>
        </div>

        {activeTab === "performance" && (
          <PerformanceTab bundle={bundle} leaves={leaves} />
        )}
        {activeTab === "reconciliation" && <ReconciliationTab leaves={leaves} />}
        {activeTab === "coaching" && (
          <CoachingStudioTab bundle={bundle} leaves={leaves} />
        )}
        {activeTab === "share" && (
          <ShareEmbedStudio
            bundle={bundle}
            verification={verification}
            title={title}
            handle={handle}
          />
        )}
      </div>

      {/* ====================================================================
          2-Page Institutional Archival Print Layout (Active ONLY on Cmd+P)
          ==================================================================== */}
      <div className="print-only hidden space-y-5">
        <PerformanceTab bundle={bundle} leaves={leaves} />

        <div className="print-page-break pt-2 space-y-5">
          <div className="flex items-center justify-between border-b border-hairline-strong pb-2 font-mono text-[10px]">
            <span className="font-bold uppercase tracking-wider text-ink">
              N170 ARCHIVAL TEAR SHEET • PAGE 2 OF 2 ({bundle.proof_id})
            </span>
            <span className="text-ink-muted tabular-nums">
              merkle_root: {bundle.merkle_root.slice(0, 24)}…
            </span>
          </div>
          <ReconciliationTab leaves={leaves} />
        </div>
      </div>

      <VerifierModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        bundle={bundle}
        registryDoc={registryDoc}
        chainHistory={chainHistory}
        continuityLogLeaves={continuityLogLeaves}
      />
    </div>
  );
}

function TabButton({
  active,
  onClick,
  label,
  badge,
  warn = false,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  badge: string;
  warn?: boolean;
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={`inline-flex items-center gap-2 border-b-2 px-3 py-3 text-xs font-semibold tracking-telemetry transition sm:px-4 sm:text-[13px] ${
        active
          ? "border-signal-emerald text-ink"
          : "border-transparent text-ink-muted hover:border-hairline-strong hover:text-ink-secondary"
      }`}
    >
      <span>{label}</span>
      <span
        className={`rounded px-1.5 py-0.5 font-mono text-[10px] tabular-nums ${
          warn ? "badge-ochre" : active ? "badge-emerald" : "badge-neutral"
        }`}
      >
        {badge}
      </span>
    </button>
  );
}
