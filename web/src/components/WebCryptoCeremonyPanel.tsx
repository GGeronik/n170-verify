"use client";

import {
  CheckCircle2,
  Cpu,
  Lock,
  Play,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { redactProofBundleLeaves } from "@/lib/browserVerify.ts";
import {
  runCeremonyTelemetry,
  type CeremonyStepTrace,
  type CeremonyTelemetryReport,
} from "@/lib/ceremonyTelemetry.ts";
import {
  CANONICAL_LEAF_NAMES,
  LEAF_DISPLAY_META,
  type CanonicalLeafName,
  type ContinuityLogLeaf,
  type PublisherKeyRegistryDocument,
  type VerifyProofBundle,
} from "@/lib/contracts.ts";

export interface WebCryptoCeremonyPanelProps {
  bundle: VerifyProofBundle;
  registryDoc: PublisherKeyRegistryDocument;
  chainHistory?: readonly VerifyProofBundle[];
  continuityLogLeaves?: readonly ContinuityLogLeaf[];
  enableRedactionSimulator?: boolean;
  autoPlayOnMount?: boolean;
  compact?: boolean;
}

export function WebCryptoCeremonyPanel({
  bundle,
  registryDoc,
  chainHistory = [],
  continuityLogLeaves,
  enableRedactionSimulator = true,
  autoPlayOnMount = true,
  compact = false,
}: WebCryptoCeremonyPanelProps) {
  const [hiddenOptional, setHiddenOptional] = useState<string[]>([]);
  const [report, setReport] = useState<CeremonyTelemetryReport | null>(null);
  const [revealedCount, setRevealedCount] = useState<number>(0);
  const [isCeremonyRunning, setIsCeremonyRunning] = useState<boolean>(false);
  const [runNonce, setRunNonce] = useState<number>(0);

  useEffect(() => {
    setHiddenOptional([]);
  }, [bundle.proof_id]);

  const executeCeremony = useCallback(
    async (animateSteps: boolean) => {
      setIsCeremonyRunning(true);
      if (animateSteps) {
        setRevealedCount(0);
      }

      const workingBundle =
        hiddenOptional.length > 0
          ? redactProofBundleLeaves(bundle, hiddenOptional)
          : bundle;

      const telemetry = await runCeremonyTelemetry(workingBundle, {
        registryDoc,
        chainHistory,
        continuityLogLeaves:
          continuityLogLeaves && continuityLogLeaves.length > 0
            ? continuityLogLeaves
            : null,
      });

      setReport(telemetry);

      if (!animateSteps) {
        setRevealedCount(telemetry.steps.length);
        setIsCeremonyRunning(false);
        return;
      }

      for (let i = 1; i <= telemetry.steps.length; i += 1) {
        await new Promise((resolve) => setTimeout(resolve, 85));
        setRevealedCount(i);
      }
      setIsCeremonyRunning(false);
    },
    [bundle, hiddenOptional, registryDoc, chainHistory, continuityLogLeaves],
  );

  useEffect(() => {
    if (!autoPlayOnMount && runNonce === 0) {
      return;
    }
    let active = true;
    const run = async () => {
      if (!active) return;
      await executeCeremony(true);
    };
    void run();
    return () => {
      active = false;
    };
  }, [autoPlayOnMount, executeCeremony, runNonce]);

  const alreadyUndisclosed = new Set(Object.keys(bundle.undisclosed_leaf_hashes ?? {}));

  const toggleOptionalRedaction = (leafName: CanonicalLeafName) => {
    if (alreadyUndisclosed.has(leafName)) {
      return;
    }
    setHiddenOptional((prev) =>
      prev.includes(leafName)
        ? prev.filter((item) => item !== leafName)
        : [...prev, leafName],
    );
  };

  const workingBundle =
    hiddenOptional.length > 0
      ? redactProofBundleLeaves(bundle, hiddenOptional)
      : bundle;

  return (
    <div className="space-y-4">
      {/* Telemetry Command Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded border border-hairline-strong bg-elevated px-3.5 py-2.5">
        <div className="flex flex-wrap items-center gap-2.5 font-mono text-[11px]">
          <span className="inline-flex items-center gap-1.5 rounded border border-signal-emerald-border bg-signal-emerald-bg px-2 py-0.5 font-semibold text-signal-emerald">
            <Cpu className="h-3.5 w-3.5" />
            window.crypto.subtle
          </span>
          <span className="inline-flex items-center gap-1 rounded border border-signal-champagne-border bg-signal-champagne-bg px-2 py-0.5 text-signal-champagne">
            <Lock className="h-3 w-3" />0 bytes sent to server
          </span>
          {report && (
            <span className="text-ink-secondary tabular-nums">
              Local execution:{" "}
              <strong className="text-ink">{report.totalComputeMs.toFixed(2)} ms</strong> •{" "}
              {report.canonicalBytesLength.toLocaleString()} JCS bytes
            </span>
          )}
        </div>

        <button
          type="button"
          onClick={() => setRunNonce((n) => n + 1)}
          disabled={isCeremonyRunning}
          className="inline-flex items-center gap-1.5 rounded border border-hairline-strong bg-panel px-3 py-1 font-mono text-[11px] font-medium text-ink transition hover:border-signal-emerald hover:text-signal-emerald disabled:opacity-60"
        >
          <Play className="h-3 w-3" />
          {isCeremonyRunning ? "Verifying Locally…" : "Re-Run Ceremony"}
        </button>
      </div>

      {/* Overall Cryptographic Verdict Banner */}
      {report && revealedCount >= report.steps.length && (
        <div
          className={`rounded border px-4 py-3 ${
            report.result.valid
              ? "border-signal-emerald-border bg-signal-emerald-bg"
              : "border-signal-vermilion-border bg-signal-vermilion-bg"
          }`}
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              {report.result.valid ? (
                <ShieldCheck className="h-4 w-4 text-signal-emerald" />
              ) : (
                <XCircle className="h-4 w-4 text-signal-vermilion" />
              )}
              <span className="font-mono text-xs font-semibold tracking-wide text-ink">
                {report.result.valid
                  ? "CRYPTOGRAPHIC PROOF VERIFIED: ALL INVARIANTS SATISFIED"
                  : "CRYPTOGRAPHIC VERIFICATION REJECTED: INVARIANT VIOLATION"}
              </span>
            </div>
            <span className="font-mono text-[11px] text-ink-secondary tabular-nums">
              effective_origin: <strong>{report.result.effective_origin_assurance}</strong>
            </span>
          </div>
          {!compact && (
            <div className="mt-2 grid grid-cols-1 gap-1.5 border-t border-hairline pt-2 font-mono text-[11px] text-ink-secondary md:grid-cols-2">
              <div className="truncate tabular-nums">
                <span className="text-ink-muted">proof_hash: </span>
                {report.result.proof_hash}
              </div>
              <div className="truncate tabular-nums">
                <span className="text-ink-muted">merkle_root: </span>
                {workingBundle.merkle_root}
              </div>
            </div>
          )}
        </div>
      )}

      {/* 5-Step Choreographed Telemetry Trace */}
      <div className="divide-y divide-hairline rounded border border-hairline bg-panel">
        {(report?.steps ?? PLACEHOLDER_STEPS).map((step, idx) => {
          const isVisible = report != null && idx < revealedCount;
          return (
            <div
              key={step.id}
              className={`px-4 py-3 transition-all duration-200 ${
                isVisible ? "animate-ceremony-step opacity-100" : "opacity-40"
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <StepStatusIcon status={isVisible ? step.status : "pending"} />
                  <span className="font-mono text-xs font-semibold text-ink">
                    {step.label}
                  </span>
                  <span className="hidden rounded border border-hairline bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-ink-muted sm:inline-block">
                    {step.protocolSpec}
                  </span>
                </div>

                <div className="flex items-center gap-2.5 font-mono text-[11px] tabular-nums">
                  <span
                    className={
                      !isVisible
                        ? "text-ink-muted"
                        : step.status === "pass"
                          ? "text-signal-emerald"
                          : step.status === "warn"
                            ? "text-signal-ochre"
                            : "text-signal-vermilion"
                    }
                  >
                    {isVisible ? step.metricSummary : "queued…"}
                  </span>
                  <span className="rounded bg-elevated px-1.5 py-0.5 text-[10px] text-ink-muted">
                    {isVisible ? `${step.durationMs.toFixed(2)} ms` : "- ms"}
                  </span>
                </div>
              </div>

              {!compact && isVisible && (
                <div className="mt-1.5 flex flex-col justify-between gap-1 pl-6 text-[11.5px] text-ink-secondary lg:flex-row lg:items-center">
                  <p>{step.technicalDetail}</p>
                  <span className="shrink-0 font-mono text-[10.5px] text-ink-muted tabular-nums">
                    {step.digestPreview}
                  </span>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Live Salted Merkle Selective Redaction Simulator */}
      {enableRedactionSimulator && (
        <div className="rounded border border-hairline bg-elevated/60 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="font-mono text-[11px] font-semibold uppercase tracking-wider text-signal-champagne">
                Salted Merkle Selective-Disclosure Simulator
              </p>
              <p className="mt-0.5 text-xs text-ink-secondary">
                Strip optional leaves in-browser to verify that{" "}
                <code className="text-ink">merkle_root</code>,{" "}
                <code className="text-ink">proof_hash</code>, and the publisher Ed25519
                signature remain cryptographically valid without re-signing.
              </p>
            </div>
          </div>

          <div className="mt-3 grid grid-cols-1 gap-2.5 sm:grid-cols-3">
            {CANONICAL_LEAF_NAMES.filter((name) => LEAF_DISPLAY_META[name].optional).map(
              (leafName) => {
                const preRedacted = alreadyUndisclosed.has(leafName);
                const simulatedRedacted = hiddenOptional.includes(leafName);
                const isHidden = preRedacted || simulatedRedacted;
                return (
                  <button
                    key={leafName}
                    type="button"
                    disabled={preRedacted}
                    onClick={() => toggleOptionalRedaction(leafName)}
                    className={`rounded border p-2.5 text-left transition ${
                      isHidden
                        ? "border-signal-ochre-border bg-signal-ochre-bg"
                        : "border-hairline-strong bg-panel hover:border-signal-emerald"
                    } ${preRedacted ? "cursor-not-allowed opacity-75" : ""}`}
                  >
                    <div className="flex items-center justify-between gap-2 font-mono text-[11px]">
                      <span className="font-semibold text-ink">{leafName}</span>
                      <span
                        className={`rounded px-1.5 py-0.5 text-[10px] ${
                          isHidden ? "badge-ochre" : "badge-emerald"
                        }`}
                      >
                        {preRedacted
                          ? "Holder Redacted"
                          : simulatedRedacted
                            ? "Redacted"
                            : "Disclosed"}
                      </span>
                    </div>
                    <p className="mt-1 text-[11px] text-ink-muted">
                      {LEAF_DISPLAY_META[leafName].title}
                    </p>
                  </button>
                );
              },
            )}
          </div>
        </div>
      )}

      {/* Warnings & Errors Log */}
      {report && (report.result.errors.length > 0 || report.result.warnings.length > 0) && (
        <div className="space-y-1.5 rounded border border-hairline bg-panel p-3.5 font-mono text-[11px]">
          {report.result.errors.map((err) => (
            <p key={err} className="text-signal-vermilion">
              [ERR] {err}
            </p>
          ))}
          {report.result.warnings.map((warn) => (
            <p key={warn} className="text-signal-ochre">
              [NOTE] {warn}
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

function StepStatusIcon({ status }: { status: "pass" | "warn" | "fail" | "pending" }) {
  if (status === "pass") {
    return <CheckCircle2 className="h-4 w-4 shrink-0 text-signal-emerald" />;
  }
  if (status === "warn") {
    return <ShieldAlert className="h-4 w-4 shrink-0 text-signal-ochre" />;
  }
  if (status === "fail") {
    return <XCircle className="h-4 w-4 shrink-0 text-signal-vermilion" />;
  }
  return <span className="h-3.5 w-3.5 shrink-0 rounded-full border border-hairline-strong" />;
}

const PLACEHOLDER_STEPS: CeremonyStepTrace[] = [
  {
    id: "jcs_canonical",
    index: 1,
    label: "1. JCS Canonicalization",
    protocolSpec: "RFC 8785 • UTF-16 Key Sort",
    status: "pass",
    durationMs: 0,
    metricSummary: "",
    technicalDetail: "",
    digestPreview: "",
  },
  {
    id: "salted_merkle",
    index: 2,
    label: "2. Salted Leaf & 0x01 Merkle Root",
    protocolSpec: "SHA-256 • 0x00 Leaf / 0x01 Node",
    status: "pass",
    durationMs: 0,
    metricSummary: "",
    technicalDetail: "",
    digestPreview: "",
  },
  {
    id: "ed25519_sig",
    index: 3,
    label: "3. Ed25519 Signature",
    protocolSpec: "WebCrypto • n170.verify.bundle",
    status: "pass",
    durationMs: 0,
    metricSummary: "",
    technicalDetail: "",
    digestPreview: "",
  },
  {
    id: "c2sp_checkpoint",
    index: 4,
    label: "4. C2SP Key Checkpoint",
    protocolSpec: "tlog-checkpoint • Base L2 #8453",
    status: "pass",
    durationMs: 0,
    metricSummary: "",
    technicalDetail: "",
    digestPreview: "",
  },
  {
    id: "origin_verdict",
    index: 5,
    label: "5. Dynamic Origin-Assurance Verdict",
    protocolSpec: "k>=2 Org/ASN Clique • 5 Chain Rules",
    status: "pass",
    durationMs: 0,
    metricSummary: "",
    technicalDetail: "",
    digestPreview: "",
  },
];
