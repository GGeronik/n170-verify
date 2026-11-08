"use client";

import { X } from "lucide-react";
import { useEffect } from "react";
import { WebCryptoCeremonyPanel } from "@/components/WebCryptoCeremonyPanel.tsx";
import type {
  ContinuityLogLeaf,
  PublisherKeyRegistryDocument,
  VerifyProofBundle,
} from "@/lib/contracts.ts";

export interface VerifierModalProps {
  open: boolean;
  onClose: () => void;
  bundle: VerifyProofBundle;
  registryDoc: PublisherKeyRegistryDocument;
  chainHistory?: readonly VerifyProofBundle[];
  continuityLogLeaves?: readonly ContinuityLogLeaf[];
}

export function VerifierModal({
  open,
  onClose,
  bundle,
  registryDoc,
  chainHistory = [],
  continuityLogLeaves,
}: VerifierModalProps) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) {
    return null;
  }

  return (
    <div
      className="no-print fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-3 backdrop-blur-sm sm:p-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby="verifier-modal-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) {
          onClose();
        }
      }}
    >
      <div className="max-h-[92vh] w-full max-w-4xl overflow-y-auto rounded-md border border-hairline-strong bg-canvas p-5 shadow-2xl sm:p-6">
        <div className="flex items-start justify-between gap-4 border-b border-hairline pb-4">
          <div>
            <p className="font-mono text-[10px] font-semibold uppercase tracking-widest text-signal-champagne">
              Client-Side Cryptographic Ceremony • RFC 8785 + Ed25519 + Salted SHA-256
            </p>
            <h2
              id="verifier-modal-title"
              className="editorial-serif mt-1 text-2xl text-ink"
            >
              Browser WebCrypto Verification Trace ({bundle.proof_id})
            </h2>
            <p className="mt-1 text-xs text-ink-secondary">
              Every cryptographic commitment is recomputed locally via{" "}
              <code className="text-ink">window.crypto.subtle</code> with zero server round-trips.
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="Close cryptographic verifier modal"
            className="inline-flex items-center gap-1 rounded border border-hairline-strong bg-panel px-2.5 py-1.5 font-mono text-xs text-ink-secondary transition hover:border-ink hover:text-ink"
          >
            <X className="h-3.5 w-3.5" />
            <span>ESC</span>
          </button>
        </div>

        <div className="mt-4">
          <WebCryptoCeremonyPanel
            bundle={bundle}
            registryDoc={registryDoc}
            chainHistory={chainHistory}
            continuityLogLeaves={continuityLogLeaves}
            enableRedactionSimulator
            autoPlayOnMount
          />
        </div>
      </div>
    </div>
  );
}
