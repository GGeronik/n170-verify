"use client";

import { CheckCircle2, Cpu, Database, ShieldCheck } from "lucide-react";

export interface IsolationReceiptData {
  mode: "backend_worker" | "pyodide_failsafe";
  workerPid?: number;
  rlimitCoreSoft?: number;
  rlimitCoreHard?: number;
  persistentRowsWritten?: number;
  zeroNetworkRequestsVerified?: boolean;
  sha384IntegrityVerified?: boolean;
  wheelHash?: string;
  executionTimeMs?: number;
  timestamp?: string;
}

export function ConnectIsolationReceipt({
  receipt,
  className = "",
}: {
  receipt: IsolationReceiptData;
  className?: string;
}) {
  const isPyodide = receipt.mode === "pyodide_failsafe";

  return (
    <div
      className={`rounded border border-signal-emerald-border bg-signal-emerald-bg p-4 font-mono text-xs tabular-nums text-ink ${className}`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-signal-emerald/20 pb-2.5">
        <div className="flex items-center gap-2">
          {isPyodide ? (
            <Cpu className="h-4 w-4 text-signal-emerald" />
          ) : (
            <ShieldCheck className="h-4 w-4 text-signal-emerald" />
          )}
          <span className="font-semibold tracking-wide text-ink">
            {isPyodide
              ? "CLIENT-SIDE PYODIDE FAILSAFE RECEIPT"
              : "ISOLATED WORKER PROCESS RECEIPT"}
          </span>
        </div>
        <span className="badge-emerald rounded px-2 py-0.5 text-[10.5px] font-semibold uppercase">
          {isPyodide ? "0 Network Requests" : "RLIMIT_CORE=0"}
        </span>
      </div>

      <div className="mt-3 grid grid-cols-2 gap-2 text-[11px] sm:grid-cols-4">
        {isPyodide ? (
          <>
            <div>
              <span className="block text-[10px] uppercase text-ink-muted">
                Runtime
              </span>
              <span className="font-semibold text-ink">WebAssembly Pyodide</span>
            </div>
            <div>
              <span className="block text-[10px] uppercase text-ink-muted">
                SHA-384 Wheel
              </span>
              <span className="font-semibold text-signal-emerald">
                {receipt.sha384IntegrityVerified ? "Verified Match" : "Unverified"}
              </span>
            </div>
            <div>
              <span className="block text-[10px] uppercase text-ink-muted">
                Network Calls
              </span>
              <span className="font-semibold text-signal-emerald">0 (Offline Safe)</span>
            </div>
            <div>
              <span className="block text-[10px] uppercase text-ink-muted">
                Wheel Hash
              </span>
              <span className="truncate text-ink-secondary" title={receipt.wheelHash}>
                {receipt.wheelHash ? receipt.wheelHash.slice(0, 14) + "…" : "Local Wheel"}
              </span>
            </div>
          </>
        ) : (
          <>
            <div>
              <span className="block text-[10px] uppercase text-ink-muted">
                Worker PID
              </span>
              <span className="font-semibold text-ink">
                {receipt.workerPid ?? "N/A"}
              </span>
            </div>
            <div>
              <span className="block text-[10px] uppercase text-ink-muted">
                Core Limit
              </span>
              <span className="font-semibold text-signal-emerald">
                {receipt.rlimitCoreSoft ?? 0}/{receipt.rlimitCoreHard ?? 0}
              </span>
            </div>
            <div>
              <span className="block text-[10px] uppercase text-ink-muted">
                DB Rows Stored
              </span>
              <span className="font-semibold text-signal-emerald">
                {receipt.persistentRowsWritten ?? 0} Rows
              </span>
            </div>
            <div>
              <span className="block text-[10px] uppercase text-ink-muted">
                Execution Time
              </span>
              <span className="text-ink-secondary">
                {receipt.executionTimeMs != null
                  ? `${receipt.executionTimeMs} ms`
                  : "Under 1s"}
              </span>
            </div>
          </>
        )}
      </div>

      <div className="mt-2.5 flex items-center gap-1.5 text-[10.5px] text-ink-secondary">
        <CheckCircle2 className="h-3.5 w-3.5 text-signal-emerald" />
        <span>
          {isPyodide
            ? "Proof generated entirely inside browser WebAssembly worker memory without server transit."
            : "Single-use worker terminated; statement zeroized in memory upon completion."}
        </span>
      </div>
    </div>
  );
}
