"use client";

import { CheckCircle2, Download, KeyRound, Lock, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { jcsSha256Hex } from "@/lib/browserVerify.ts";

export default function ProspectiveCommitPage() {
  const [chainId, setChainId] = useState<string>("chain-2026-alpha");
  const [sequenceNumber, setSequenceNumber] = useState<number>(0);
  const [accountSecret, setAccountSecret] = useState<string>("account-secret-seed");
  const [cadenceSeconds, setCadenceSeconds] = useState<number>(86400);
  const [graceSeconds, setGraceSeconds] = useState<number>(7200);
  const [prevProofHash, setPrevProofHash] = useState<string>("");
  const [commitmentDigest, setCommitmentDigest] = useState<string | null>(null);
  const [generating, setGenerating] = useState<boolean>(false);

  const handleGenerateCommitment = async () => {
    setGenerating(true);
    try {
      const encoder = new TextEncoder();
      const accountTagBuffer = await window.crypto.subtle.digest(
        "SHA-256",
        encoder.encode(accountSecret),
      );
      const blindedAccountTag = Array.from(new Uint8Array(accountTagBuffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      const commitmentPayload = {
        schema_version: "n170-commitment-v1",
        chain_id: chainId,
        sequence_number: sequenceNumber,
        prev_proof_hash: sequenceNumber === 0 ? null : prevProofHash || null,
        blinded_account_tag: blindedAccountTag,
        cadence_policy: {
          expected_interval_seconds: cadenceSeconds,
          grace_window_seconds: graceSeconds,
        },
        committed_at_utc: new Date().toISOString(),
      };

      const digest = await jcsSha256Hex(commitmentPayload);
      setCommitmentDigest(digest);
    } finally {
      setGenerating(false);
    }
  };

  const downloadJson = () => {
    if (!commitmentDigest) return;
    const data = {
      schema_version: "n170-commitment-v1",
      chain_id: chainId,
      sequence_number: sequenceNumber,
      prev_proof_hash: sequenceNumber === 0 ? null : prevProofHash || null,
      commitment_hash: commitmentDigest,
      cadence_policy: {
        expected_interval_seconds: cadenceSeconds,
        grace_window_seconds: graceSeconds,
      },
      committed_at_utc: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `prospective-commitment-${chainId}-seq${sequenceNumber}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-canvas font-sans text-ink antialiased">
      <div className="bg-telemetry-grid">
        <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
          {/* Header */}
          <div className="mb-8 space-y-3">
            <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] tracking-wide text-ink-secondary">
              <span className="rounded border border-hairline-strong bg-elevated px-2 py-0.5 uppercase">
                PROSPECTIVE COMMITMENT
              </span>
              <span>•</span>
              <span>Genesis & Sequence Enrollment</span>
            </div>
            <h1 className="text-2xl font-bold tracking-telemetry sm:text-3xl">
              Prospective Chain Commitment Ceremony
            </h1>
            <p className="max-w-3xl text-sm leading-relaxed text-ink-secondary">
              Pre-commit to a cryptographic track-record schedule prior to observing market returns.
              Prospective continuity locks reporting cadence and parent-hash linkage, preventing
              selection bias or retroactive curve resets.
            </p>
          </div>

          <div className="grid gap-8 lg:grid-cols-12">
            {/* Parameters Form */}
            <div className="space-y-6 rounded-lg border border-hairline bg-surface p-6 lg:col-span-7">
              <h2 className="text-base font-semibold tracking-telemetry text-ink">
                Commitment Invariant Parameters
              </h2>

              <div className="space-y-4 text-xs">
                <div>
                  <label className="mb-1 block font-mono font-medium text-ink-secondary">
                    Chain Identifier
                  </label>
                  <input
                    type="text"
                    value={chainId}
                    onChange={(e) => setChainId(e.target.value)}
                    className="w-full rounded border border-hairline bg-canvas px-3 py-2 font-mono text-ink focus:border-signal-emerald focus:outline-none"
                    placeholder="e.g. chain-2026-alpha"
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="mb-1 block font-mono font-medium text-ink-secondary">
                      Sequence Number
                    </label>
                    <input
                      type="number"
                      min={0}
                      value={sequenceNumber}
                      onChange={(e) => setSequenceNumber(Number(e.target.value))}
                      className="w-full rounded border border-hairline bg-canvas px-3 py-2 font-mono text-ink focus:border-signal-emerald focus:outline-none"
                    />
                    <p className="mt-1 text-[11px] text-ink-muted">
                      0 for genesis enrollment
                    </p>
                  </div>

                  <div>
                    <label className="mb-1 block font-mono font-medium text-ink-secondary">
                      Cadence Interval
                    </label>
                    <select
                      value={cadenceSeconds}
                      onChange={(e) => setCadenceSeconds(Number(e.target.value))}
                      className="w-full rounded border border-hairline bg-canvas px-3 py-2 font-mono text-ink focus:border-signal-emerald focus:outline-none"
                    >
                      <option value={86400}>Daily (86,400s)</option>
                      <option value={604800}>Weekly (604,800s)</option>
                      <option value={2592000}>Monthly (2,592,000s)</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="mb-1 block font-mono font-medium text-ink-secondary">
                    Account Seed (Hashed to Blinded Tag)
                  </label>
                  <input
                    type="text"
                    value={accountSecret}
                    onChange={(e) => setAccountSecret(e.target.value)}
                    className="w-full rounded border border-hairline bg-canvas px-3 py-2 font-mono text-ink focus:border-signal-emerald focus:outline-none"
                    placeholder="Private seed or account identifier"
                  />
                  <p className="mt-1 text-[11px] text-ink-muted">
                    Hashed client-side via SHA-256; raw string is never transmitted.
                  </p>
                </div>

                {sequenceNumber > 0 && (
                  <div>
                    <label className="mb-1 block font-mono font-medium text-ink-secondary">
                      Previous Proof Hash
                    </label>
                    <input
                      type="text"
                      value={prevProofHash}
                      onChange={(e) => setPrevProofHash(e.target.value)}
                      className="w-full rounded border border-hairline bg-canvas px-3 py-2 font-mono text-ink focus:border-signal-emerald focus:outline-none"
                      placeholder="64-character hex digest of prior sequence link"
                    />
                  </div>
                )}
              </div>

              <div className="pt-2">
                <button
                  type="button"
                  onClick={() => void handleGenerateCommitment()}
                  disabled={generating}
                  className="flex items-center gap-2 rounded bg-signal-champagne px-4 py-2 font-mono text-xs font-semibold text-canvas transition hover:opacity-90"
                >
                  <ShieldCheck className="h-4 w-4" />
                  <span>{generating ? "Computing Hash..." : "Generate Cryptographic Commitment"}</span>
                </button>
              </div>
            </div>

            {/* Output Panel */}
            <div className="space-y-6 rounded-lg border border-hairline bg-surface p-6 lg:col-span-5">
              <h2 className="text-base font-semibold tracking-telemetry text-ink">
                Commitment Output & Invariants
              </h2>

              {commitmentDigest ? (
                <div className="space-y-4">
                  <div className="rounded border border-signal-emerald-border bg-signal-emerald-bg/20 p-4">
                    <div className="flex items-center gap-2 text-signal-emerald">
                      <CheckCircle2 className="h-4 w-4 shrink-0" />
                      <span className="font-mono text-xs font-semibold uppercase">
                        Commitment Hash Computed
                      </span>
                    </div>
                    <p className="mt-2 break-all font-mono text-xs text-ink">
                      {commitmentDigest}
                    </p>
                  </div>

                  <button
                    type="button"
                    onClick={downloadJson}
                    className="flex w-full items-center justify-center gap-2 rounded border border-hairline-strong bg-elevated px-4 py-2 font-mono text-xs font-medium text-ink transition hover:bg-surface"
                  >
                    <Download className="h-4 w-4" />
                    <span>Download Commitment JSON</span>
                  </button>
                </div>
              ) : (
                <div className="rounded border border-hairline bg-canvas p-6 text-center">
                  <KeyRound className="mx-auto mb-2 h-6 w-6 text-ink-muted" />
                  <p className="text-xs text-ink-secondary">
                    Configure parameters and click generate to compute the RFC 8785 canonical hash.
                  </p>
                </div>
              )}

              {/* Invariants Checklist */}
              <div className="space-y-2 border-t border-hairline pt-4 text-xs text-ink-secondary">
                <p className="font-mono font-semibold uppercase text-ink">
                  Five Enforced Invariants
                </p>
                <ul className="space-y-1.5 pl-4 list-disc text-ink-muted">
                  <li>Genesis enrollment window boundary (86,400s)</li>
                  <li>Monotonic sequence progression (N+1 strictly follows N)</li>
                  <li>Parent hash continuity linkage</li>
                  <li>Cadence policy immutability across chain links</li>
                  <li>Blinded account continuity across transitions</li>
                </ul>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
