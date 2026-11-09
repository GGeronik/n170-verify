"use client";

import { ShieldCheck, Upload } from "lucide-react";
import { type DragEvent, useEffect, useState } from "react";
import { TearSheetView } from "@/components/TearSheetView.tsx";
import { WebCryptoCeremonyPanel } from "@/components/WebCryptoCeremonyPanel.tsx";
import { fetchActiveRegistryDocument } from "@/lib/apiClient.ts";
import { redactProofBundleLeaves } from "@/lib/browserVerify.ts";
import {
  CANONICAL_LEAF_NAMES,
  LEAF_DISPLAY_META,
  type PublisherKeyRegistryDocument,
  type VerifyProofBundle,
} from "@/lib/contracts.ts";
import {
  BUNDLE_COACHING_STUDIO,
  BUNDLE_CUSTODY_SIGNED,
  BUNDLE_DISCREPANCY_XRAY,
  BUNDLE_INSTITUTIONAL_FUND,
  BUNDLE_INSTITUTIONAL_SEQ0,
  BUNDLE_INSTITUTIONAL_SEQ1,
  DEMO_CONTINUITY_LOG_LEAVES,
  DEMO_REGISTRY_DOCUMENT,
} from "@/lib/demoFixtures.ts";

export default function OfflineVerifyPage() {
  const [rawJson, setRawJson] = useState<string>(() =>
    JSON.stringify(BUNDLE_INSTITUTIONAL_FUND, null, 2),
  );
  const [parsedBundle, setParsedBundle] = useState<VerifyProofBundle | null>(
    BUNDLE_INSTITUTIONAL_FUND,
  );
  const [parseError, setParseError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [ceremonyKey, setCeremonyKey] = useState(0);
  const [activeRegistryDoc, setActiveRegistryDoc] =
    useState<PublisherKeyRegistryDocument>(DEMO_REGISTRY_DOCUMENT);
  const [liveRegistryConnected, setLiveRegistryConnected] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void fetchActiveRegistryDocument().then(({ registryDoc, liveConnected }) => {
      if (!cancelled) {
        setActiveRegistryDoc(registryDoc);
        setLiveRegistryConnected(liveConnected);
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const parseAndTriggerCeremony = (text: string) => {
    setRawJson(text);
    setParseError(null);
    try {
      const obj = JSON.parse(text) as VerifyProofBundle;
      if (!obj || typeof obj !== "object" || typeof obj.proof_id !== "string") {
        throw new Error("JSON root must be a VerifyProofBundle object with proof_id");
      }
      setParsedBundle(obj);
      setCeremonyKey((k) => k + 1);
    } catch (err) {
      setParsedBundle(null);
      setParseError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleDrop = async (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (!file) {
      return;
    }
    parseAndTriggerCeremony(await file.text());
  };

  const loadPreset = (
    preset: "inst" | "redacted" | "downgraded" | "custody" | "tampered_leaf",
  ) => {
    if (preset === "inst") {
      parseAndTriggerCeremony(JSON.stringify(BUNDLE_INSTITUTIONAL_FUND, null, 2));
    } else if (preset === "redacted") {
      parseAndTriggerCeremony(JSON.stringify(BUNDLE_COACHING_STUDIO, null, 2));
    } else if (preset === "downgraded") {
      parseAndTriggerCeremony(JSON.stringify(BUNDLE_DISCREPANCY_XRAY, null, 2));
    } else if (preset === "custody") {
      parseAndTriggerCeremony(JSON.stringify(BUNDLE_CUSTODY_SIGNED, null, 2));
    } else {
      const tampered: VerifyProofBundle = {
        ...BUNDLE_INSTITUTIONAL_FUND,
        disclosed_leaves: BUNDLE_INSTITUTIONAL_FUND.disclosed_leaves.map((leaf) =>
          leaf.leaf_name === "core_metrics"
            ? {
                ...leaf,
                payload: {
                  ...(leaf.payload as Record<string, unknown>),
                  twr_decimal: 8.88,
                },
              }
            : leaf,
        ),
      };
      parseAndTriggerCeremony(JSON.stringify(tampered, null, 2));
    }
  };

  const applyClientSideRedaction = (leafName: string) => {
    if (!parsedBundle) {
      return;
    }
    const next = redactProofBundleLeaves(parsedBundle, [leafName]);
    parseAndTriggerCeremony(JSON.stringify(next, null, 2));
  };

  const isInstitutionalChain =
    parsedBundle?.proof_id === BUNDLE_INSTITUTIONAL_FUND.proof_id;

  return (
    <div className="bg-institutional-grid">
      <div className="mx-auto max-w-7xl space-y-8 px-4 py-10 sm:px-6 lg:px-8">
        {/* Masthead */}
        <div className="flex flex-col justify-between gap-4 border-b border-hairline pb-6 lg:flex-row lg:items-end">
          <div className="max-w-3xl space-y-2">
            <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
              <span className="badge-emerald rounded px-2 py-0.5 font-semibold uppercase tracking-wider">
                Air-Gapped Browser WebCrypto • 0 Bytes Sent to Server
              </span>
              <span className="rounded border border-hairline-strong bg-panel px-2 py-0.5 text-ink-secondary">
                {liveRegistryConnected
                  ? "Registry: Live /.well-known + Pinned"
                  : "Registry: Pinned Offline Keyring"}
              </span>
            </div>
            <h1 className="editorial-serif text-3xl text-ink sm:text-4xl">
              Client-Side Cryptographic Ceremony &amp; Bundle Redactor
            </h1>
            <p className="text-sm text-ink-secondary">
              Drop any <code className="text-ink">.verify.json</code> proof bundle below.
              Every RFC 8785 JCS sort, salted <code className="text-ink">0x00</code>/
              <code className="text-ink">0x01</code> Merkle path, Ed25519 signature, C2SP
              checkpoint, and dynamic k&ge;2 org/ASN-disjoint notary check executes in{" "}
              <code className="text-ink">window.crypto.subtle</code>.
            </p>
          </div>

          <button
            type="button"
            onClick={() => parseAndTriggerCeremony(rawJson)}
            className="inline-flex items-center gap-2 rounded border border-signal-emerald bg-signal-emerald px-4 py-2.5 font-mono text-xs font-semibold text-canvas transition hover:opacity-90"
          >
            <ShieldCheck className="h-4 w-4" />
            <span>Verify Cryptographically in Browser</span>
          </button>
        </div>

        {/* Cryptographic Test Vectors */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-xs text-ink-muted">Test Vectors:</span>
          <PresetBtn onClick={() => loadPreset("inst")}>
            1. Valid k=3 Disjoint + Chain #2
          </PresetBtn>
          <PresetBtn onClick={() => loadPreset("redacted")}>
            2. Salted-Redacted CapitalBracket
          </PresetBtn>
          <PresetBtn onClick={() => loadPreset("downgraded")}>
            3. Single-Notary Dynamic Downgrade
          </PresetBtn>
          <PresetBtn onClick={() => loadPreset("custody")}>
            4. Pinned Broker Ed25519 Custody
          </PresetBtn>
          <PresetBtn danger onClick={() => loadPreset("tampered_leaf")}>
            5. Adversarial Tampered TWR (Must Reject)
          </PresetBtn>
        </div>

        {/* Dropzone + Raw JSON Inspector */}
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => void handleDrop(e)}
            className={`flex flex-col justify-between rounded-md border border-dashed p-5 transition lg:col-span-5 ${
              dragging
                ? "border-signal-emerald bg-signal-emerald-bg"
                : "border-hairline-strong bg-panel"
            }`}
          >
            <div className="space-y-3">
              <div className="flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-wider text-signal-champagne">
                <Upload className="h-4 w-4" />
                <span>Air-Gapped .verify.json Dropzone</span>
              </div>
              <p className="text-xs text-ink-secondary">
                Drag and drop a signed bundle from disk or select a local file. Bytes
                never leave your browser tab.
              </p>

              <label className="inline-flex cursor-pointer items-center gap-2 rounded border border-hairline-strong bg-elevated px-3.5 py-2 font-mono text-xs font-semibold text-ink transition hover:border-signal-emerald">
                <span>Choose .verify.json File</span>
                <input
                  type="file"
                  accept=".json,application/json"
                  className="hidden"
                  onChange={async (e) => {
                    const file = e.target.files?.[0];
                    if (file) {
                      parseAndTriggerCeremony(await file.text());
                    }
                  }}
                />
              </label>
            </div>

            {parsedBundle && (
              <div className="mt-5 rounded border border-hairline bg-canvas p-3.5">
                <p className="font-mono text-[10.5px] font-semibold uppercase tracking-wider text-signal-emerald">
                  Holder JSON Redaction Tool (Preserves Signature)
                </p>
                <p className="mt-1 text-[11px] text-ink-secondary">
                  Strip optional leaves directly from the JSON above without invalidating
                  the publisher signature:
                </p>
                <div className="mt-2.5 flex flex-wrap gap-1.5">
                  {CANONICAL_LEAF_NAMES.filter((n) => LEAF_DISPLAY_META[n].optional).map(
                    (leafName) => {
                      const isDisclosed = parsedBundle.disclosed_leaves.some(
                        (l) => l.leaf_name === leafName,
                      );
                      return (
                        <button
                          key={leafName}
                          type="button"
                          disabled={!isDisclosed}
                          onClick={() => applyClientSideRedaction(leafName)}
                          className={`rounded border px-2.5 py-1 font-mono text-[10.5px] transition ${
                            isDisclosed
                              ? "border-signal-emerald-border bg-signal-emerald-bg text-signal-emerald hover:border-signal-emerald"
                              : "cursor-not-allowed border-hairline bg-elevated text-ink-muted"
                          }`}
                        >
                          {isDisclosed ? `Redact ${leafName}` : `${leafName} (Sealed)`}
                        </button>
                      );
                    },
                  )}
                </div>
              </div>
            )}
          </div>

          <div className="inst-panel flex flex-col rounded-md p-4 lg:col-span-7">
            <div className="flex items-center justify-between pb-2.5">
              <span className="font-mono text-xs font-semibold text-ink">
                Raw VerifyProofBundle JSON Payload
              </span>
              <button
                type="button"
                onClick={() => parseAndTriggerCeremony(rawJson)}
                className="rounded border border-signal-champagne-border bg-signal-champagne-bg px-3 py-1 font-mono text-[11px] font-semibold text-signal-champagne transition hover:border-signal-champagne"
              >
                Verify JSON Payload
              </button>
            </div>
            <textarea
              value={rawJson}
              onChange={(e) => setRawJson(e.target.value)}
              spellCheck={false}
              className="h-60 w-full flex-1 rounded border border-hairline bg-canvas p-3 font-mono text-[11px] leading-relaxed text-ink focus:border-signal-emerald focus:outline-none"
            />
          </div>
        </div>

        {parseError && (
          <div className="rounded border border-signal-vermilion-border bg-signal-vermilion-bg p-4 font-mono text-xs text-signal-vermilion">
            JSON Schema / Parse Error: {parseError}
          </div>
        )}

        {/* Choreographed 5-Step WebCrypto Verification Ceremony */}
        {parsedBundle && (
          <section className="inst-panel rounded-md p-5 sm:p-6">
            <div className="mb-4 border-b border-hairline pb-3">
              <p className="font-mono text-[10.5px] font-semibold uppercase tracking-widest text-signal-champagne">
                5-Step Telemetry Trace
              </p>
              <h2 className="editorial-serif mt-0.5 text-2xl text-ink">
                Choreographed Browser WebCrypto Verification ({parsedBundle.proof_id})
              </h2>
            </div>

            <WebCryptoCeremonyPanel
              key={`${parsedBundle.proof_id}-${ceremonyKey}`}
              bundle={parsedBundle}
              registryDoc={activeRegistryDoc}
              chainHistory={
                isInstitutionalChain
                  ? [BUNDLE_INSTITUTIONAL_SEQ0, BUNDLE_INSTITUTIONAL_SEQ1]
                  : []
              }
              continuityLogLeaves={
                isInstitutionalChain ? DEMO_CONTINUITY_LOG_LEAVES : undefined
              }
              enableRedactionSimulator={false}
              autoPlayOnMount
            />
          </section>
        )}

        {/* Full Studio Tear Sheet Render for Inspected Bundle */}
        {parsedBundle && (
          <TearSheetView
            bundle={parsedBundle}
            registryDoc={activeRegistryDoc}
            chainHistory={
              isInstitutionalChain
                ? [BUNDLE_INSTITUTIONAL_SEQ0, BUNDLE_INSTITUTIONAL_SEQ1]
                : []
            }
            continuityLogLeaves={
              isInstitutionalChain ? DEMO_CONTINUITY_LOG_LEAVES : undefined
            }
            title={`Inspected Proof Bundle • ${parsedBundle.proof_id}`}
          />
        )}
      </div>
    </div>
  );
}

function PresetBtn({
  children,
  onClick,
  danger = false,
}: {
  children: string;
  onClick: () => void;
  danger?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded border px-3 py-1.5 font-mono text-[11px] font-medium transition ${
        danger
          ? "border-signal-vermilion-border bg-signal-vermilion-bg text-signal-vermilion hover:border-signal-vermilion"
          : "border-hairline-strong bg-panel text-ink-secondary hover:border-signal-champagne hover:text-ink"
      }`}
    >
      {children}
    </button>
  );
}
