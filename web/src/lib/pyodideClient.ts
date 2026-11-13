/**
 * N170 Verify - Client Controller for In-Browser Offline Pyodide Failsafe.
 *
 * Coordinates offline statement verification with 0 network requests, verified
 * SHA-384 pure-Python wheel integrity, and local cryptographic bundle issuance.
 * Completely free of Node built-ins for clean Next.js client bundling.
 */

import type { CanonicalLeafName, VerifyProofBundle } from "./contracts.ts";
import {
  executeOfflineVerification,
  type PyodideJobPayload,
  type PyodideVerifyResult,
  type PyodideWorkerResponse,
} from "./pyodideFailsafeWorker.ts";

export interface PyodideVerifyOptions {
  broker_id: string;
  raw_statement: string;
  csv_format?: "degiro" | "robinhood" | "schwab";
  disclose_leaf_names?: readonly CanonicalLeafName[] | readonly string[];
  publish_proof?: boolean;
  account_blinding_salt_hex?: string;
  expectedSha384?: string;
  wheelBytes?: Uint8Array;
}

export type { PyodideVerifyResult };

/**
 * Checks whether WebCrypto and offline failsafe runtime are available.
 */
export function isPyodideFailsafeSupported(): boolean {
  return (
    typeof globalThis !== "undefined" &&
    typeof globalThis.crypto?.subtle !== "undefined"
  );
}

/**
 * Executes zero-network-call verification via offline Pyodide failsafe engine.
 */
export async function verifyWithPyodideFailsafe(
  options: PyodideVerifyOptions,
): Promise<PyodideVerifyResult> {
  const payload: PyodideJobPayload = {
    broker_id: options.broker_id,
    raw_statement: options.raw_statement,
    csv_format: options.csv_format,
    disclose_leaf_names: options.disclose_leaf_names,
    publish_proof: options.publish_proof,
    account_blinding_salt_hex: options.account_blinding_salt_hex,
  };

  // 1. In browser environment with active Web Worker support:
  if (typeof window !== "undefined" && typeof Worker !== "undefined") {
    return new Promise<PyodideVerifyResult>((resolve, reject) => {
      let worker: Worker;
      try {
        worker = new Worker(
          new URL("./pyodideFailsafeWorker.ts", import.meta.url),
          { type: "module" },
        );
      } catch {
        // Fallback to in-thread execution if worker URL is restricted
        executeOfflineVerification(payload, {
          expectedSha384: options.expectedSha384,
          wheelBytes: options.wheelBytes,
        }).then(resolve, reject);
        return;
      }

      worker.onmessage = (event: MessageEvent<PyodideWorkerResponse>) => {
        worker.terminate();
        if (
          event.data.type === "VERIFY_SUCCESS" &&
          event.data.proof_bundle &&
          event.data.isolation_receipt
        ) {
          resolve({
            proof_bundle: event.data.proof_bundle,
            isolation_receipt: event.data.isolation_receipt,
          });
        } else {
          reject(
            new Error(
              event.data.error ?? "Pyodide failsafe worker verification failed",
            ),
          );
        }
      };

      worker.onerror = () => {
        worker.terminate();
        executeOfflineVerification(payload, {
          expectedSha384: options.expectedSha384,
          wheelBytes: options.wheelBytes,
        }).then(resolve, reject);
      };

      worker.postMessage({
        type: "VERIFY",
        payload,
        expectedSha384: options.expectedSha384,
        wheelBytes: options.wheelBytes,
      });
    });
  }

  // 2. In Node test environment or environments without Web Worker:
  return executeOfflineVerification(payload, {
    expectedSha384: options.expectedSha384,
    wheelBytes: options.wheelBytes,
  });
}
