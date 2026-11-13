/**
 * N170 Verify: Zero-Dependency Browser & Node WebCrypto Verifier.
 *
 * Byte-for-byte compatible with Wave-1 Python:
 *   - `n170_verify.crypto.canonical` (RFC 8785 JCS UTF-16 code-unit sorting)
 *   - `n170_verify.crypto.merkle_disclosure` (0x00 leaf / 0x01 node salted SHA-256)
 *   - `n170_verify.crypto.signing` (domain-separated Ed25519 via `crypto.subtle`)
 *   - `n170_verify.crypto.publisher_registry` (key lifecycle + C2SP tlog-checkpoint)
 *   - `n170_verify.crypto.witness_quorum` (dynamic k>=2 org/ASN-disjoint TLSN quorum)
 *   - `n170_verify.crypto.chain_invariants` (all 5 prospective chain invariants)
 *   - `n170_verify.contracts.proof.verify_proof_bundle`
 */

import {
  ALLOWED_RETENTION_MODES,
  CANONICAL_LEAF_NAMES,
  ChainContinuityMode,
  ChainInvariantViolationCode,
  DEFAULT_MAX_WITNESS_SKEW_SECONDS,
  EnvironmentTier,
  GENESIS_ENROLLMENT_WINDOW_SECONDS,
  INDEX_CONTINUITY_TOLERANCE,
  LEAF_DOMAIN_PREFIX,
  NODE_DOMAIN_PREFIX,
  OriginAssurance,
  ProviderApprovalState,
  REQUIRED_TLS_VERSION,
  REQUIRED_TLSN_PROTOCOL,
  SIGNING_DOMAIN_BROKER,
  SIGNING_DOMAIN_BUNDLE,
  SIGNING_DOMAIN_CHECKPOINT,
  SIGNING_DOMAIN_WITNESS,
  SignerTrustStatus,
  TranscriptCommitmentKind,
  VERIFY_SCHEMA_VERSION,
  type AssuranceProfile,
  type BrokerNativeSignature,
  type BundleVerificationResult,
  type C2SPCheckpoint,
  type ChainVerificationResult,
  type ContinuityLogLeaf,
  type DisclosedLeaf,
  type MerkleAuditStep,
  type NotaryNodeInfo,
  type ProspectiveChainLink,
  type PublisherKeyRegistryDocument,
  type VerifyProofBundle,
  type WitnessAttestation,
  type WitnessQuorumEvaluation,
} from "./contracts.ts";

const UTF8_ENCODER = new TextEncoder();

const CONTROL_ESCAPES: Readonly<Record<number, string>> = {
  0x08: "\\b",
  0x09: "\\t",
  0x0a: "\\n",
  0x0c: "\\f",
  0x0d: "\\r",
  0x22: '\\"',
  0x5c: "\\\\",
};

const IBKR_WITNESS_SNIS: ReadonlySet<string> = new Set<string>([
  "api.ibkr.com",
  "ndcdyn.interactivebrokers.com",
  "gdcdyn.interactivebrokers.com",
  "www.interactivebrokers.com",
]);

const SCHWAB_WITNESS_SNIS: ReadonlySet<string> = new Set<string>([
  "api.schwabapi.com",
]);

const CTRADER_WITNESS_SNIS: ReadonlySet<string> = new Set<string>([
  "openapi.ctrader.com",
  "live.ctraderapi.com",
]);

const COINBASE_WITNESS_SNIS: ReadonlySet<string> = new Set<string>([
  "api.coinbase.com",
  "api.exchange.coinbase.com",
]);

export const BROKER_WITNESS_SNI_ALLOWLIST: Readonly<
  Record<string, ReadonlySet<string>>
> = {
  ibkr: IBKR_WITNESS_SNIS,
  ibkr_flex: IBKR_WITNESS_SNIS,
  ibkr_flex_offline: IBKR_WITNESS_SNIS,
  ibkr_flex_web: IBKR_WITNESS_SNIS,
  ibkr_oauth: IBKR_WITNESS_SNIS,
  interactive_brokers: IBKR_WITNESS_SNIS,
  schwab: SCHWAB_WITNESS_SNIS,
  schwab_csv: SCHWAB_WITNESS_SNIS,
  alpaca: new Set<string>(["api.alpaca.markets"]),
  tradier: new Set<string>(["api.tradier.com"]),
  trading212: new Set<string>(["live.trading212.com"]),
  ctrader: CTRADER_WITNESS_SNIS,
  ctrader_oauth: CTRADER_WITNESS_SNIS,
  coinbase: COINBASE_WITNESS_SNIS,
  coinbaseadvanced: COINBASE_WITNESS_SNIS,
  coinbase_advanced: COINBASE_WITNESS_SNIS,
  binance: new Set<string>(["api.binance.com"]),
  kraken: new Set<string>(["api.kraken.com"]),
  bybit: new Set<string>(["api.bybit.com"]),
};

const REDACTED_PLACEHOLDERS = new Set<string>([
  "[redacted]",
  "<redacted>",
  "redacted",
  "***",
  "*",
]);

const ALLOWED_STATIC_ACCOUNT_SEGMENTS = new Set<string>([
  ...REDACTED_PLACEHOLDERS,
  "accountnumbers",
  "subaccounts",
  "summary",
]);

const SENSITIVE_HEADER_NAMES = new Set<string>([
  "authorization",
  "proxy-authorization",
  "apca-api-key-id",
  "apca-api-secret-key",
  "cookie",
  "set-cookie",
  "x-api-key",
  "cb-access-key",
  "cb-access-sign",
  "cb-access-passphrase",
  "api-key",
  "api-sign",
]);

const SENSITIVE_QUERY_PARAM_RE =
  /(?:^|[?&])(t|q|token|access_token|refresh_token|api_key|apikey|secret|signature)=([^&#\s]*)/gi;
const ACCOUNT_PATH_RE = /(?:\/*v\d+)?\/accounts\/([^/?#\s]+)/gi;
const EMBEDDED_HEADER_LEAK_RE =
  /\b(authorization|apca-api-key-id|apca-api-secret-key|cookie|set-cookie|cb-access-key|x-api-key|api-key|api-sign)\s*:/i;
const AUTH_SCHEME_LEAK_RE = /\b(bearer|basic)\s+([^\s,;]+)/gi;

// ---------------------------------------------------------------------------
// Low-Level Byte, Hex, Base64 & Timestamp Helpers
// ---------------------------------------------------------------------------

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}

export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const chunk of chunks) {
    total += chunk.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function validateHexDigest(
  value: string,
  fieldName: string,
  numBytes = 32,
): string {
  if (typeof value !== "string") {
    throw new Error(`${fieldName} must be a hex string`);
  }
  const normalized = value.trim().toLowerCase();
  const expectedLen = numBytes * 2;
  if (normalized.length !== expectedLen) {
    throw new Error(
      `${fieldName} must be ${expectedLen} hex characters (${numBytes} bytes)`,
    );
  }
  if (!/^[0-9a-f]+$/.test(normalized)) {
    throw new Error(`${fieldName} contains non-hexadecimal characters`);
  }
  return normalized;
}

export function hexToBytes(hex: string, fieldName = "hex"): Uint8Array {
  if (typeof hex !== "string") {
    throw new Error(`${fieldName} must be a string`);
  }
  const clean = hex.trim().toLowerCase();
  if (clean.length % 2 !== 0 || (clean.length > 0 && !/^[0-9a-f]+$/.test(clean))) {
    throw new Error(`Invalid hexadecimal string for ${fieldName}`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i += 1) {
    hex += bytes[i]!.toString(16).padStart(2, "0");
  }
  return hex;
}

export function decodeBase64Strict(b64: string, fieldName = "base64"): Uint8Array {
  if (typeof b64 !== "string") {
    throw new Error(`${fieldName} must be a base64 string`);
  }
  const trimmed = b64.trim();
  if (
    !trimmed ||
    trimmed.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)
  ) {
    throw new Error(`${fieldName} must be valid base64`);
  }
  let binary: string;
  try {
    binary = atob(trimmed);
  } catch {
    throw new Error(`${fieldName} must be valid base64`);
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  // Canonical round-trip check matching Python `base64.b64decode(..., validate=True)`.
  let checkBin = "";
  for (let i = 0; i < bytes.length; i += 1) {
    checkBin += String.fromCharCode(bytes[i]!);
  }
  if (btoa(checkBin) !== trimmed) {
    throw new Error(`${fieldName} has non-canonical base64 padding bits`);
  }
  return bytes;
}

const ISO_8601_RE =
  /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|z|[+-]\d{2}:\d{2})?$/;

export function parseUtcTimestampMs(
  value: string | Date,
  fieldName = "timestamp",
): number {
  if (value instanceof Date) {
    const ms = value.getTime();
    if (!Number.isFinite(ms)) {
      throw new Error(`${fieldName} is an invalid Date`);
    }
    return ms;
  }
  if (typeof value !== "string") {
    throw new Error(`${fieldName} must be an ISO-8601 string or Date`);
  }
  const cleaned = value.trim();
  if (!cleaned) {
    throw new Error(`${fieldName} must not be empty`);
  }
  const match = ISO_8601_RE.exec(cleaned);
  if (!match) {
    throw new Error(`${fieldName} must be a valid ISO-8601 timestamp: ${value}`);
  }
  const [, y, mo, d, h, mi, s, frac, tz] = match;
  const msFrac = frac ? frac.padEnd(3, "0").slice(0, 3) : "000";
  const tzSuffix = !tz || tz === "z" || tz === "Z" ? "Z" : tz;
  const normalizedIso = `${y}-${mo}-${d}T${h}:${mi}:${s}.${msFrac}${tzSuffix}`;
  const parsed = Date.parse(normalizedIso);
  if (!Number.isFinite(parsed)) {
    throw new Error(`${fieldName} must be a valid ISO-8601 timestamp: ${value}`);
  }
  return parsed;
}

export function normalizeAsn(asn: string): string {
  if (typeof asn !== "string") {
    throw new Error("NotaryNodeInfo.asn must be a string");
  }
  let cleaned = asn.trim().toUpperCase();
  if (cleaned.startsWith("AS")) {
    cleaned = cleaned.slice(2).trim();
  }
  if (!cleaned) {
    throw new Error("NotaryNodeInfo.asn must not be empty");
  }
  return `AS${cleaned}`;
}

// ---------------------------------------------------------------------------
// RFC 8785 JSON Canonicalization Scheme (JCS)
// ---------------------------------------------------------------------------

function assertNoLoneSurrogates(value: string, context: string): void {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        i += 1;
        continue;
      }
      throw new Error(
        `RFC 8785 JCS forbids lone UTF-16 surrogate U+${code.toString(16).toUpperCase().padStart(4, "0")} in ${context}`,
      );
    }
    if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error(
        `RFC 8785 JCS forbids lone UTF-16 surrogate U+${code.toString(16).toUpperCase().padStart(4, "0")} in ${context}`,
      );
    }
  }
}

export function compareUtf16CodeUnits(a: string, b: string): number {
  const minLen = Math.min(a.length, b.length);
  for (let i = 0; i < minLen; i += 1) {
    const diff = a.charCodeAt(i) - b.charCodeAt(i);
    if (diff !== 0) {
      return diff;
    }
  }
  return a.length - b.length;
}

function escapeJcsString(value: string): string {
  assertNoLoneSurrogates(value, "string value");
  let out = '"';
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    const mapped = CONTROL_ESCAPES[code];
    if (mapped !== undefined) {
      out += mapped;
    } else if (code < 0x20) {
      out += `\\u${code.toString(16).padStart(4, "0")}`;
    } else {
      out += value[i]!;
    }
  }
  out += '"';
  return out;
}

function serializeJcsValue(obj: unknown): string {
  if (obj === null) {
    return "null";
  }
  if (typeof obj === "boolean") {
    return obj ? "true" : "false";
  }
  if (typeof obj === "number") {
    if (!Number.isFinite(obj)) {
      throw new Error(`RFC 8785 JCS forbids non-finite numbers: ${String(obj)}`);
    }
    return obj === 0 ? "0" : obj.toString();
  }
  if (typeof obj === "string") {
    return escapeJcsString(obj);
  }
  if (Array.isArray(obj)) {
    return `[${obj.map((item) => serializeJcsValue(item)).join(",")}]`;
  }
  if (typeof obj === "object") {
    const record = obj as Record<string, unknown>;
    const keys = Object.keys(record);
    for (const k of keys) {
      assertNoLoneSurrogates(k, "object key");
    }
    keys.sort(compareUtf16CodeUnits);
    const members: string[] = [];
    for (const k of keys) {
      const val = record[k];
      if (val === undefined) {
        throw new TypeError(
          `RFC 8785 JCS forbids undefined object property: ${JSON.stringify(k)}`,
        );
      }
      members.push(`${escapeJcsString(k)}:${serializeJcsValue(val)}`);
    }
    return `{${members.join(",")}}`;
  }
  throw new TypeError(
    `Unsupported type for RFC 8785 JCS canonicalization: ${typeof obj}`,
  );
}

export function jcsCanonicalizeStr(obj: unknown): string {
  return serializeJcsValue(obj);
}

export function jcsCanonicalize(obj: unknown): Uint8Array {
  return UTF8_ENCODER.encode(serializeJcsValue(obj));
}

// ---------------------------------------------------------------------------
// SHA-256 & Domain-Separated Ed25519 via WebCrypto (`crypto.subtle`)
// ---------------------------------------------------------------------------

export async function sha256Bytes(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(data));
  return new Uint8Array(digest);
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  return bytesToHex(await sha256Bytes(data));
}

export async function jcsSha256Hex(obj: unknown): Promise<string> {
  return sha256Hex(jcsCanonicalize(obj));
}

const ED25519_P = (1n << 255n) - 19n;
const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;
const ED25519_SMALL_ORDER_Y = new Set<bigint>([
  0n,
  1n,
  ED25519_P - 1n,
  0x05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826n,
  0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7n,
]);

function bytesToLittleEndianBigInt(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    acc = (acc << 8n) | BigInt(bytes[i]!);
  }
  return acc;
}

function isCanonicalNonTorsionEd25519Point(point32b: Uint8Array): boolean {
  if (point32b.length !== 32) {
    return false;
  }
  const y = bytesToLittleEndianBigInt(point32b) & ((1n << 255n) - 1n);
  if (y >= ED25519_P || ED25519_SMALL_ORDER_Y.has(y)) {
    return false;
  }
  return true;
}

function isCanonicalEd25519Scalar(scalar32b: Uint8Array): boolean {
  if (scalar32b.length !== 32) {
    return false;
  }
  const s = bytesToLittleEndianBigInt(scalar32b);
  return s > 0n && s < ED25519_L;
}

export async function ed25519Verify(
  publicKeyHex: string,
  message: Uint8Array,
  signatureHex: string,
): Promise<boolean> {
  if (typeof publicKeyHex !== "string" || typeof signatureHex !== "string") {
    return false;
  }
  let pubNorm: string;
  let sigNorm: string;
  try {
    pubNorm = validateHexDigest(publicKeyHex, "public_key_hex", 32);
    sigNorm = validateHexDigest(signatureHex, "signature_hex", 64);
  } catch {
    return false;
  }

  try {
    const pubBytes = hexToBytes(pubNorm);
    const sigBytes = hexToBytes(sigNorm);
    if (
      !isCanonicalNonTorsionEd25519Point(pubBytes) ||
      !isCanonicalNonTorsionEd25519Point(sigBytes.subarray(0, 32)) ||
      !isCanonicalEd25519Scalar(sigBytes.subarray(32, 64))
    ) {
      return false;
    }
    const key = await crypto.subtle.importKey(
      "raw",
      toArrayBuffer(pubBytes),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      toArrayBuffer(sigBytes),
      toArrayBuffer(message),
    );
  } catch {
    return false;
  }
}

export async function ed25519VerifyDomain(
  publicKeyHex: string,
  domain: string | Uint8Array,
  payload: Uint8Array,
  signatureHex: string,
): Promise<boolean> {
  const domainBytes =
    typeof domain === "string" ? UTF8_ENCODER.encode(domain) : domain;
  if (domainBytes.length === 0) {
    return false;
  }
  const message = concatBytes(domainBytes, new Uint8Array([0x00]), payload);
  return ed25519Verify(publicKeyHex, message, signatureHex);
}

// ---------------------------------------------------------------------------
// Salted Merkle Selective Disclosure (`0x00` Leaf / `0x01` Internal Node)
// ---------------------------------------------------------------------------

export async function computeSaltedLeafHash(
  leafName: string,
  salt32bHex: string,
  payload: unknown,
): Promise<string> {
  if (
    typeof leafName !== "string" ||
    !leafName.trim() ||
    leafName.includes("\x00")
  ) {
    throw new Error("leaf_name must be a non-empty string without NUL bytes");
  }
  const normSalt = validateHexDigest(salt32bHex, "salt_32b_hex", 32);
  const saltBytes = hexToBytes(normSalt);
  const jcsBytes = jcsCanonicalize(payload);
  const nul = new Uint8Array([0x00]);
  const preimage = concatBytes(
    LEAF_DOMAIN_PREFIX,
    UTF8_ENCODER.encode(leafName),
    nul,
    saltBytes,
    nul,
    jcsBytes,
  );
  return sha256Hex(preimage);
}

export async function computeInternalNodeHash(
  leftHashHex: string,
  rightHashHex: string,
): Promise<string> {
  const leftNorm = validateHexDigest(leftHashHex, "left_hash_hex", 32);
  const rightNorm = validateHexDigest(rightHashHex, "right_hash_hex", 32);
  const preimage = concatBytes(
    NODE_DOMAIN_PREFIX,
    hexToBytes(leftNorm),
    hexToBytes(rightNorm),
  );
  return sha256Hex(preimage);
}

export async function computeMerkleRootFromLeafHashes(
  orderedLeafHashes: readonly string[],
): Promise<string> {
  if (orderedLeafHashes.length === 0) {
    throw new Error("Cannot construct Merkle tree from empty leaf sequence");
  }
  let current = orderedLeafHashes.map((h, idx) =>
    validateHexDigest(h, `leaf_hash[${idx}]`, 32),
  );
  while (current.length > 1) {
    const nextLayer: string[] = [];
    let idx = 0;
    while (idx < current.length) {
      if (idx + 1 < current.length) {
        nextLayer.push(
          await computeInternalNodeHash(current[idx]!, current[idx + 1]!),
        );
        idx += 2;
      } else {
        // Odd trailing node promotes directly without duplication (matching Python).
        nextLayer.push(current[idx]!);
        idx += 1;
      }
    }
    current = nextLayer;
  }
  return current[0]!;
}

export async function verifyMerkleAuditPath(
  leafHashHex: string,
  auditPath: readonly MerkleAuditStep[],
  expectedRootHex: string,
): Promise<boolean> {
  let current: string;
  let target: string;
  try {
    current = validateHexDigest(leafHashHex, "leaf_hash_hex", 32);
    target = validateHexDigest(expectedRootHex, "expected_root_hex", 32);
  } catch {
    return false;
  }

  for (const rawStep of auditPath) {
    if (!rawStep || typeof rawStep !== "object") {
      return false;
    }
    const side =
      typeof rawStep.side === "string" ? rawStep.side.trim().toLowerCase() : "";
    let siblingNorm: string;
    try {
      siblingNorm = validateHexDigest(
        rawStep.sibling_hash_hex,
        "sibling_hash_hex",
        32,
      );
    } catch {
      return false;
    }

    if (side === "left") {
      current = await computeInternalNodeHash(siblingNorm, current);
    } else if (side === "right") {
      current = await computeInternalNodeHash(current, siblingNorm);
    } else {
      return false;
    }
  }
  return current === target;
}

export async function verifyDisclosedLeaf(
  leaf: DisclosedLeaf,
  expectedRootHex: string,
): Promise<boolean> {
  let recomputed: string;
  let expectedLeafHash: string;
  try {
    expectedLeafHash = validateHexDigest(
      leaf.leaf_hash_hex,
      "DisclosedLeaf.leaf_hash_hex",
      32,
    );
    recomputed = await computeSaltedLeafHash(
      leaf.leaf_name,
      leaf.salt_hex,
      leaf.payload,
    );
  } catch {
    return false;
  }
  if (recomputed !== expectedLeafHash) {
    return false;
  }
  return verifyMerkleAuditPath(recomputed, leaf.audit_path ?? [], expectedRootHex);
}

export async function verifySelectiveDisclosure(
  merkleRootHex: string,
  disclosedLeaves: readonly DisclosedLeaf[],
  undisclosedLeafHashes: Readonly<Record<string, string>>,
  expectedLeafOrder: readonly string[] = CANONICAL_LEAF_NAMES,
): Promise<{ valid: boolean; errors: string[] }> {
  const errors: string[] = [];
  let normRoot: string;
  try {
    normRoot = validateHexDigest(merkleRootHex, "merkle_root_hex", 32);
  } catch (err) {
    return {
      valid: false,
      errors: [err instanceof Error ? err.message : String(err)],
    };
  }

  const seenDisclosed = new Map<string, string>();
  for (const leaf of disclosedLeaves) {
    if (seenDisclosed.has(leaf.leaf_name)) {
      errors.push(`Duplicate disclosed leaf: ${JSON.stringify(leaf.leaf_name)}`);
      continue;
    }
    const ok = await verifyDisclosedLeaf(leaf, normRoot);
    if (!ok) {
      errors.push(
        `Merkle disclosure verification failed for leaf ${JSON.stringify(leaf.leaf_name)}`,
      );
    }
    let normLeafHash = leaf.leaf_hash_hex;
    try {
      normLeafHash = validateHexDigest(
        leaf.leaf_hash_hex,
        `disclosed[${leaf.leaf_name}]`,
        32,
      );
    } catch {
      // Already captured by verifyDisclosedLeaf failure.
    }
    seenDisclosed.set(leaf.leaf_name, normLeafHash);
  }

  const undisclosedKeys = Object.keys(undisclosedLeafHashes ?? {});
  const overlap = undisclosedKeys.filter((k) => seenDisclosed.has(k)).sort();
  if (overlap.length > 0) {
    errors.push(
      `Leaves present in both disclosed and undisclosed sets: [${overlap.join(", ")}]`,
    );
  }

  const combinedHashes = new Map<string, string>(seenDisclosed);
  for (const [name, digest] of Object.entries(undisclosedLeafHashes ?? {})) {
    try {
      combinedHashes.set(
        name,
        validateHexDigest(digest, `undisclosed_leaf_hashes[${name}]`, 32),
      );
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }
  }

  const expectedSet = new Set(expectedLeafOrder);
  const combinedSet = new Set(combinedHashes.keys());
  const missing = [...expectedSet].filter((k) => !combinedSet.has(k)).sort();
  const extra = [...combinedSet].filter((k) => !expectedSet.has(k)).sort();
  if (missing.length > 0 || extra.length > 0) {
    errors.push(
      `Canonical leaf partition mismatch (missing=[${missing.join(", ")}], extra=[${extra.join(", ")}])`,
    );
  } else if (errors.length === 0) {
    const orderedHashes = expectedLeafOrder.map(
      (name) => combinedHashes.get(name)!,
    );
    const rebuiltRoot = await computeMerkleRootFromLeafHashes(orderedHashes);
    if (rebuiltRoot !== normRoot) {
      errors.push(
        "Reconstructed canonical 7-leaf Merkle root does not match bundle merkle_root",
      );
    }
  }

  return { valid: errors.length === 0, errors };
}

// ---------------------------------------------------------------------------
// C2SP Checkpoint & Publisher Registry Evaluation
// ---------------------------------------------------------------------------

export function formatC2spCheckpointBody(
  origin: string,
  size: number,
  hashB64: string,
): Uint8Array {
  if (
    typeof origin !== "string" ||
    !origin.trim() ||
    origin.includes("\n") ||
    origin.includes("\r")
  ) {
    throw new Error(
      "C2SP checkpoint origin must be a non-empty single-line string",
    );
  }
  if (typeof size !== "number" || !Number.isInteger(size) || size < 0) {
    throw new Error("C2SP checkpoint size must be a non-negative integer");
  }
  if (
    typeof hashB64 !== "string" ||
    !hashB64.trim() ||
    hashB64.includes("\n")
  ) {
    throw new Error("C2SP checkpoint hash_b64 must be a non-empty base64 string");
  }
  const rawHash = decodeBase64Strict(hashB64, "C2SP checkpoint hash_b64");
  if (rawHash.length !== 32) {
    throw new Error(
      "C2SP checkpoint hash_b64 must decode to 32 bytes (SHA-256)",
    );
  }
  return UTF8_ENCODER.encode(`${origin.trim()}\n${size}\n${hashB64.trim()}\n`);
}

export function formatC2spCosignaturePayload(
  checkpointBody: Uint8Array,
  timestampUtc: string,
): Uint8Array {
  const ms = parseUtcTimestampMs(timestampUtc, "cosignature.timestamp_utc");
  const unixSeconds = Math.trunc(ms / 1000);
  const prefix = UTF8_ENCODER.encode(`cosignature/v1\ntime ${unixSeconds}\n`);
  return concatBytes(prefix, checkpointBody);
}

export async function verifyC2spCheckpoint(
  checkpoint: C2SPCheckpoint,
  options: {
    publisherPublicKeyHex: string;
    trustedWitnessKeys?: Readonly<Record<string, string>> | null;
    minWitnessCosignatures?: number;
  },
): Promise<{
  valid: boolean;
  validWitnessIds: string[];
  errors: string[];
}> {
  const errors: string[] = [];
  let body: Uint8Array;
  try {
    body = formatC2spCheckpointBody(
      checkpoint.origin,
      checkpoint.size,
      checkpoint.hash_b64,
    );
  } catch (err) {
    return {
      valid: false,
      validWitnessIds: [],
      errors: [err instanceof Error ? err.message : String(err)],
    };
  }

  const pubSigOk = await ed25519VerifyDomain(
    options.publisherPublicKeyHex,
    SIGNING_DOMAIN_CHECKPOINT,
    body,
    checkpoint.publisher_signature_hex,
  );
  if (!pubSigOk) {
    errors.push("C2SP checkpoint publisher signature verification failed");
  }

  const validWitnesses = new Set<string>();
  for (const cosig of checkpoint.witness_cosignatures ?? []) {
    let expectedPub = cosig.public_key_hex;
    if (options.trustedWitnessKeys != null) {
      const pinnedPub = options.trustedWitnessKeys[cosig.witness_id];
      if (
        !pinnedPub ||
        pinnedPub.trim().toLowerCase() !== cosig.public_key_hex.trim().toLowerCase()
      ) {
        errors.push(
          `Untrusted or mismatched checkpoint witness ${JSON.stringify(cosig.witness_id)}`,
        );
        continue;
      }
      expectedPub = pinnedPub;
    }
    let cosigMsg: Uint8Array;
    try {
      cosigMsg = formatC2spCosignaturePayload(body, cosig.timestamp_utc);
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
      continue;
    }
    const cosigOk = await ed25519VerifyDomain(
      expectedPub,
      SIGNING_DOMAIN_CHECKPOINT,
      cosigMsg,
      cosig.signature_hex,
    );
    if (cosigOk) {
      validWitnesses.add(cosig.witness_id);
    } else {
      errors.push(
        `Invalid checkpoint witness cosignature from ${JSON.stringify(cosig.witness_id)}`,
      );
    }
  }

  const minRequired = options.minWitnessCosignatures ?? 0;
  if (validWitnesses.size < minRequired) {
    errors.push(
      `Checkpoint has ${validWitnesses.size} valid witness cosignatures; required >= ${minRequired}`,
    );
  }

  return {
    valid: errors.length === 0,
    validWitnessIds: [...validWitnesses],
    errors,
  };
}

// ---------------------------------------------------------------------------
// Bundle Header Canonicalization & Signature Verification
// ---------------------------------------------------------------------------

function normalizeWitnessAttestationDict(
  att: WitnessAttestation,
): Record<string, unknown> {
  return {
    protocol: att.protocol,
    tls_version: att.tls_version,
    defer_decryption_from_start: Boolean(att.defer_decryption_from_start),
    notary_id: att.notary_id,
    server_sni: att.server_sni,
    sanitized_request_target: att.sanitized_request_target,
    redacted_headers: [...(att.redacted_headers ?? [])],
    commitment_kind: att.commitment_kind,
    response_body_sha256: validateHexDigest(
      att.response_body_sha256,
      "WitnessAttestation.response_body_sha256",
      32,
    ),
    session_timestamp_utc: att.session_timestamp_utc,
    signature_hex: validateHexDigest(
      att.signature_hex,
      "WitnessAttestation.signature_hex",
      64,
    ),
  };
}

function witnessAttestationSignableBytes(att: WitnessAttestation): Uint8Array {
  return jcsCanonicalize({
    commitment_kind: att.commitment_kind,
    defer_decryption_from_start: Boolean(att.defer_decryption_from_start),
    notary_id: att.notary_id,
    protocol: att.protocol,
    redacted_headers: [...(att.redacted_headers ?? [])],
    response_body_sha256: validateHexDigest(
      att.response_body_sha256,
      "WitnessAttestation.response_body_sha256",
      32,
    ),
    sanitized_request_target: att.sanitized_request_target,
    server_sni: att.server_sni,
    session_timestamp_utc: att.session_timestamp_utc,
    tls_version: att.tls_version,
  });
}

function normalizeBrokerSignatureDict(
  sig: BrokerNativeSignature,
): Record<string, unknown> {
  return {
    broker_id: sig.broker_id.trim().toLowerCase(),
    key_id: sig.key_id,
    algorithm: sig.algorithm,
    signed_payload_sha256: validateHexDigest(
      sig.signed_payload_sha256,
      "BrokerNativeSignature.signed_payload_sha256",
      32,
    ),
    signature_hex: validateHexDigest(
      sig.signature_hex,
      "BrokerNativeSignature.signature_hex",
      64,
    ),
  };
}

function normalizeProspectiveChainLinkDict(
  link: ProspectiveChainLink,
): Record<string, unknown> {
  return {
    chain_id: link.chain_id,
    sequence_number: link.sequence_number,
    prev_proof_hash:
      link.prev_proof_hash != null
        ? validateHexDigest(
            link.prev_proof_hash,
            "ProspectiveChainLink.prev_proof_hash",
            32,
          )
        : null,
    blinded_account_tag: validateHexDigest(
      link.blinded_account_tag,
      "ProspectiveChainLink.blinded_account_tag",
      32,
    ),
    enrolled_at_utc: link.enrolled_at_utc,
    period_start_utc: link.period_start_utc,
    period_end_utc: link.period_end_utc,
    issued_at_utc: link.issued_at_utc,
    cadence_policy: {
      expected_interval_seconds: link.cadence_policy.expected_interval_seconds,
      grace_window_seconds: link.cadence_policy.grace_window_seconds,
    },
    beginning_index_value:
      link.beginning_index_value === 0 ? 0 : link.beginning_index_value,
    ending_index_value:
      link.ending_index_value === 0 ? 0 : link.ending_index_value,
    period_twr_decimal:
      link.period_twr_decimal === 0 ? 0 : link.period_twr_decimal,
  };
}

export function buildSignableHeader(
  bundle: VerifyProofBundle,
): Record<string, unknown> {
  return {
    account_scope: bundle.account_scope,
    base_currency: bundle.base_currency.trim().toUpperCase(),
    blinded_account_tag: validateHexDigest(
      bundle.blinded_account_tag,
      "VerifyProofBundle.blinded_account_tag",
      32,
    ),
    broker_id: bundle.broker_id.trim().toLowerCase(),
    broker_native_signature:
      bundle.broker_native_signature != null
        ? normalizeBrokerSignatureDict(bundle.broker_native_signature)
        : null,
    claimed_origin_assurance: bundle.claimed_origin_assurance,
    environment_tier: bundle.environment_tier,
    issued_at_utc: bundle.issued_at_utc,
    merkle_root: validateHexDigest(
      bundle.merkle_root,
      "VerifyProofBundle.merkle_root",
      32,
    ),
    period_end_utc: bundle.period_end_utc,
    period_start_utc: bundle.period_start_utc,
    proof_id: bundle.proof_id,
    prospective_chain_link:
      bundle.prospective_chain_link != null
        ? normalizeProspectiveChainLinkDict(bundle.prospective_chain_link)
        : null,
    provider_approval_state: bundle.provider_approval_state,
    publisher_kid: bundle.publisher_kid,
    publisher_public_key_hex: validateHexDigest(
      bundle.publisher_public_key_hex,
      "VerifyProofBundle.publisher_public_key_hex",
      32,
    ),
    retention_mode: (bundle.retention_mode ?? "no_persistent_storage")
      .trim()
      .toLowerCase(),
    schema_version: bundle.schema_version ?? VERIFY_SCHEMA_VERSION,
    source_body_sha256: validateHexDigest(
      bundle.source_body_sha256,
      "VerifyProofBundle.source_body_sha256",
      32,
    ),
    witness_attestations: (bundle.witness_attestations ?? []).map(
      normalizeWitnessAttestationDict,
    ),
  };
}

export async function computeProofHash(
  bundle: VerifyProofBundle,
): Promise<string> {
  return jcsSha256Hex(buildSignableHeader(bundle));
}

export async function verifyPublisherSignature(
  bundle: VerifyProofBundle,
): Promise<boolean> {
  try {
    const signableBytes = jcsCanonicalize(buildSignableHeader(bundle));
    return await ed25519VerifyDomain(
      bundle.publisher_public_key_hex,
      SIGNING_DOMAIN_BUNDLE,
      signableBytes,
      bundle.signature_hex,
    );
  } catch {
    return false;
  }
}

export function redactProofBundleLeaves(
  bundle: VerifyProofBundle,
  leafNamesToHide: Iterable<string>,
): VerifyProofBundle {
  const hideSet = new Set(leafNamesToHide);
  const canonicalSet = new Set<string>(CANONICAL_LEAF_NAMES);
  const unknown = [...hideSet].filter((name) => !canonicalSet.has(name)).sort();
  if (unknown.length > 0) {
    throw new Error(
      `Cannot redact unknown canonical leaf name(s): [${unknown.join(", ")}]`,
    );
  }

  const keptDisclosed: DisclosedLeaf[] = [];
  const updatedUndisclosed: Record<string, string> = {
    ...(bundle.undisclosed_leaf_hashes ?? {}),
  };

  for (const leaf of bundle.disclosed_leaves ?? []) {
    if (hideSet.has(leaf.leaf_name)) {
      updatedUndisclosed[leaf.leaf_name] = leaf.leaf_hash_hex.trim().toLowerCase();
    } else {
      keptDisclosed.push(leaf);
    }
  }

  return {
    ...bundle,
    disclosed_leaves: keptDisclosed,
    undisclosed_leaf_hashes: updatedUndisclosed,
  };
}

export async function evaluateSignerTrust(
  bundle: VerifyProofBundle,
  registryDoc: PublisherKeyRegistryDocument | null | undefined,
  precomputedSigValid?: boolean,
): Promise<{
  status: SignerTrustStatus;
  checkpointVerified: boolean;
  checkpointWitnessCount: number;
}> {
  const sigOk =
    precomputedSigValid !== undefined
      ? precomputedSigValid
      : await verifyPublisherSignature(bundle);
  if (!sigOk) {
    return {
      status: SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER,
      checkpointVerified: false,
      checkpointWitnessCount: 0,
    };
  }
  if (!registryDoc) {
    return {
      status: SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER,
      checkpointVerified: false,
      checkpointWitnessCount: 0,
    };
  }

  const keyMap = new Map(
    (registryDoc.keys ?? []).map((rec) => [rec.publisher_kid, rec]),
  );

  let checkpointVerified = false;
  let checkpointWitnessCount = 0;

  if (registryDoc.checkpoint != null) {
    const ckptKey = keyMap.get(registryDoc.checkpoint.publisher_kid);
    if (!ckptKey || ckptKey.status.trim().toLowerCase() === "revoked") {
      return {
        status: SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER,
        checkpointVerified: false,
        checkpointWitnessCount: 0,
      };
    }
    const ckptRes = await verifyC2spCheckpoint(registryDoc.checkpoint, {
      publisherPublicKeyHex: ckptKey.public_key_hex,
    });
    if (!ckptRes.valid) {
      return {
        status: SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER,
        checkpointVerified: false,
        checkpointWitnessCount: 0,
      };
    }
    checkpointVerified = true;
    checkpointWitnessCount = ckptRes.validWitnessIds.length;
  }

  const keyRecord = keyMap.get(bundle.publisher_kid);
  const bundlePubNorm = bundle.publisher_public_key_hex.trim().toLowerCase();
  if (
    !keyRecord ||
    keyRecord.public_key_hex.trim().toLowerCase() !== bundlePubNorm
  ) {
    return {
      status: SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER,
      checkpointVerified,
      checkpointWitnessCount,
    };
  }

  const recordStatus = keyRecord.status.trim().toLowerCase();
  if (recordStatus === "revoked") {
    return {
      status: SignerTrustStatus.REVOKED_KEY,
      checkpointVerified,
      checkpointWitnessCount,
    };
  }

  const issuedMs = parseUtcTimestampMs(
    bundle.issued_at_utc,
    "proof_bundle.issued_at_utc",
  );
  const notBeforeMs = parseUtcTimestampMs(
    keyRecord.not_before_utc,
    "key_record.not_before_utc",
  );
  if (issuedMs < notBeforeMs) {
    return {
      status: SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER,
      checkpointVerified,
      checkpointWitnessCount,
    };
  }

  if (keyRecord.revoked_after_utc != null) {
    const revokedMs = parseUtcTimestampMs(
      keyRecord.revoked_after_utc,
      "key_record.revoked_after_utc",
    );
    if (issuedMs >= revokedMs) {
      return {
        status: SignerTrustStatus.REVOKED_KEY,
        checkpointVerified,
        checkpointWitnessCount,
      };
    }
  }

  if (keyRecord.not_after_utc != null) {
    const notAfterMs = parseUtcTimestampMs(
      keyRecord.not_after_utc,
      "key_record.not_after_utc",
    );
    if (issuedMs > notAfterMs) {
      return {
        status: SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER,
        checkpointVerified,
        checkpointWitnessCount,
      };
    }
  }

  if (recordStatus === "retired") {
    return {
      status: SignerTrustStatus.RETIRED_HISTORICAL_VALID,
      checkpointVerified,
      checkpointWitnessCount,
    };
  }

  return {
    status: SignerTrustStatus.OFFICIAL_N170_HOSTED,
    checkpointVerified,
    checkpointWitnessCount,
  };
}

// ---------------------------------------------------------------------------
// Dynamic Witness Quorum & Transcript Safety Evaluation
// ---------------------------------------------------------------------------

export function inspectTranscriptSafety(
  attestation: WitnessAttestation,
): { safe: boolean; violations: string[] } {
  const violations: string[] = [];

  if (attestation.protocol !== REQUIRED_TLSN_PROTOCOL) {
    violations.push(
      `Unsupported TLSNotary protocol ${JSON.stringify(attestation.protocol)}; expected ${JSON.stringify(REQUIRED_TLSN_PROTOCOL)}`,
    );
  }
  if (attestation.tls_version !== REQUIRED_TLS_VERSION) {
    violations.push(
      `Unsupported witnessed TLS version ${JSON.stringify(attestation.tls_version)}; expected ${JSON.stringify(REQUIRED_TLS_VERSION)}`,
    );
  }
  if (!attestation.defer_decryption_from_start) {
    violations.push(
      "defer_decryption_from_start must be True to prevent selective forgery",
    );
  }
  if (
    attestation.commitment_kind ===
    TranscriptCommitmentKind.UNPADDED_VARIABLE_SPAN_REJECTED
  ) {
    violations.push(
      "Variable-span transcript commitments leak NAV digit counts; require whole_body_sha256 or fixed_64b_padded_window",
    );
  }

  const target = attestation.sanitized_request_target ?? "";
  for (const match of target.matchAll(SENSITIVE_QUERY_PARAM_RE)) {
    const paramName = match[1]!;
    const paramVal = (match[2] ?? "").trim().toLowerCase();
    if (!REDACTED_PLACEHOLDERS.has(paramVal)) {
      violations.push(
        `Unredacted sensitive query parameter ${JSON.stringify(paramName)} in sanitized_request_target`,
      );
    }
  }

  for (const match of target.matchAll(ACCOUNT_PATH_RE)) {
    const acctSeg = (match[1] ?? "").trim().toLowerCase();
    if (!ALLOWED_STATIC_ACCOUNT_SEGMENTS.has(acctSeg)) {
      violations.push(
        "Unredacted raw account identifier in /accounts/<id> path of sanitized_request_target",
      );
    }
  }

  if (EMBEDDED_HEADER_LEAK_RE.test(target)) {
    violations.push(
      "Sensitive HTTP header leaked inside sanitized_request_target",
    );
  }

  for (const match of target.matchAll(AUTH_SCHEME_LEAK_RE)) {
    const scheme = match[1]!;
    const token = (match[2] ?? "").trim().toLowerCase();
    if (!REDACTED_PLACEHOLDERS.has(token)) {
      violations.push(
        `Unredacted ${scheme} credential leaked in sanitized_request_target`,
      );
    }
  }

  if (!attestation.redacted_headers || attestation.redacted_headers.length === 0) {
    violations.push(
      "redacted_headers must list at least one redacted credential header",
    );
  } else {
    for (const entry of attestation.redacted_headers) {
      const stripped = entry.trim();
      const colonIdx = stripped.indexOf(":");
      if (colonIdx !== -1) {
        const hdrName = stripped.slice(0, colonIdx).trim();
        const hdrVal = stripped.slice(colonIdx + 1).trim().toLowerCase();
        if (
          SENSITIVE_HEADER_NAMES.has(hdrName.toLowerCase()) &&
          !REDACTED_PLACEHOLDERS.has(hdrVal)
        ) {
          violations.push(
            `Unredacted sensitive header value for ${JSON.stringify(hdrName)} in redacted_headers`,
          );
        }
      }
      for (const match of stripped.matchAll(AUTH_SCHEME_LEAK_RE)) {
        const scheme = match[1]!;
        const token = (match[2] ?? "").trim().toLowerCase();
        if (!REDACTED_PLACEHOLDERS.has(token)) {
          violations.push(`Unredacted ${scheme} token in redacted_headers`);
        }
      }
    }
  }

  return { safe: violations.length === 0, violations };
}

export async function verifyBrokerNativeSignature(
  brokerSig: BrokerNativeSignature | null | undefined,
  expectedSourceBodySha256: string,
  pinnedBrokerKeys: Readonly<Record<string, Readonly<Record<string, string>>>> | null | undefined,
): Promise<boolean> {
  if (!brokerSig || !pinnedBrokerKeys) {
    return false;
  }
  let normExpected: string;
  let normSignedPayload: string;
  try {
    normExpected = validateHexDigest(
      expectedSourceBodySha256,
      "expected_source_body_sha256",
      32,
    );
    normSignedPayload = validateHexDigest(
      brokerSig.signed_payload_sha256,
      "signed_payload_sha256",
      32,
    );
  } catch {
    return false;
  }
  if (normSignedPayload !== normExpected) {
    return false;
  }
  const brokerKeys = pinnedBrokerKeys[brokerSig.broker_id.trim().toLowerCase()];
  if (!brokerKeys) {
    return false;
  }
  const pubHex = brokerKeys[brokerSig.key_id];
  if (!pubHex) {
    return false;
  }
  if (brokerSig.algorithm.trim().toLowerCase() !== "ed25519") {
    return false;
  }
  const signableBytes = jcsCanonicalize({
    algorithm: brokerSig.algorithm,
    broker_id: brokerSig.broker_id.trim().toLowerCase(),
    key_id: brokerSig.key_id,
    signed_payload_sha256: normSignedPayload,
  });
  return ed25519VerifyDomain(
    pubHex,
    SIGNING_DOMAIN_BROKER,
    signableBytes,
    brokerSig.signature_hex,
  );
}

function maxMutuallyDisjointQuorum(
  candidates: ReadonlyArray<{ node: NotaryNodeInfo; tsMs: number }>,
  maxSkewSeconds: number,
): [number, number, number] {
  if (candidates.length === 0) {
    return [0, 0, 0];
  }
  const sorted = [...candidates].sort((a, b) => a.tsMs - b.tsMs);
  let bestCliqueSize = 0;

  for (let startIdx = 0; startIdx < sorted.length; startIdx += 1) {
    const t0 = sorted[startIdx]!.tsMs;
    const windowNodes = sorted
      .slice(startIdx)
      .filter((item) => (item.tsMs - t0) / 1000 <= maxSkewSeconds)
      .map((item) => item.node);

    const usedIds = new Set<string>();
    const usedPubs = new Set<string>();
    const usedOrgs = new Set<string>();
    const usedAsns = new Set<string>();

    const search = (idx: number, chosenLen: number): void => {
      if (chosenLen > bestCliqueSize) {
        bestCliqueSize = chosenLen;
      }
      if (chosenLen + (windowNodes.length - idx) <= bestCliqueSize) {
        return;
      }
      for (let pos = idx; pos < windowNodes.length; pos += 1) {
        const cand = windowNodes[pos]!;
        const nid = cand.notary_id.trim().toLowerCase();
        const pub = cand.public_key_hex.trim().toLowerCase();
        const org = cand.operator_org.trim().toLowerCase();
        const asn = normalizeAsn(cand.asn);
        if (
          !usedIds.has(nid) &&
          !usedPubs.has(pub) &&
          !usedOrgs.has(org) &&
          !usedAsns.has(asn)
        ) {
          usedIds.add(nid);
          usedPubs.add(pub);
          usedOrgs.add(org);
          usedAsns.add(asn);
          search(pos + 1, chosenLen + 1);
          usedAsns.delete(asn);
          usedOrgs.delete(org);
          usedPubs.delete(pub);
          usedIds.delete(nid);
        }
      }
    };

    search(0, 0);
  }

  const allOrgs = new Set(
    sorted.map((c) => c.node.operator_org.trim().toLowerCase()),
  ).size;
  const allAsns = new Set(sorted.map((c) => normalizeAsn(c.node.asn))).size;
  return [bestCliqueSize, allOrgs, allAsns];
}

export async function evaluateOriginAssurance(options: {
  sourceBodySha256: string;
  signerTrust?: SignerTrustStatus;
  publisherKid?: string;
  publisherPublicKeyHex?: string;
  publisherOrg?: string;
  environmentTier?: EnvironmentTier;
  providerApprovalState?: ProviderApprovalState;
  claimedOriginAssurance?: OriginAssurance | null;
  witnessAttestations?: readonly WitnessAttestation[];
  notaryRegistry?: readonly NotaryNodeInfo[];
  brokerNativeSignature?: BrokerNativeSignature | null;
  pinnedBrokerKeys?: Readonly<Record<string, Readonly<Record<string, string>>>> | null;
  maxWitnessSkewSeconds?: number;
  brokerId?: string | null;
}): Promise<WitnessQuorumEvaluation> {
  const reasons: string[] = [];
  const normSourceSha = validateHexDigest(
    options.sourceBodySha256,
    "source_body_sha256",
    32,
  );
  const signerTrust = options.signerTrust ?? SignerTrustStatus.OFFICIAL_N170_HOSTED;
  const environmentTier = options.environmentTier ?? EnvironmentTier.LIVE_PRODUCTION;
  const providerApprovalState =
    options.providerApprovalState ?? ProviderApprovalState.OFFLINE_EXPORT_ONLY;
  const claimedOriginAssurance = options.claimedOriginAssurance ?? null;
  const maxSkew =
    options.maxWitnessSkewSeconds ?? DEFAULT_MAX_WITNESS_SKEW_SECONDS;

  if (environmentTier === EnvironmentTier.PAPER_OR_SANDBOX_REJECTED) {
    reasons.push(
      "Paper or sandbox environment tier rejected; downgraded to self_reported",
    );
    return {
      effective_origin_assurance: OriginAssurance.SELF_REPORTED,
      valid_witness_count: 0,
      disjoint_quorum_size: 0,
      distinct_org_count: 0,
      distinct_asn_count: 0,
      broker_signature_valid: false,
      downgrade_reasons: reasons,
    };
  }

  if (
    signerTrust === SignerTrustStatus.REVOKED_KEY ||
    signerTrust === SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER
  ) {
    reasons.push(
      `Publisher signer trust is ${signerTrust}; downgraded to self_reported`,
    );
    return {
      effective_origin_assurance: OriginAssurance.SELF_REPORTED,
      valid_witness_count: 0,
      disjoint_quorum_size: 0,
      distinct_org_count: 0,
      distinct_asn_count: 0,
      broker_signature_valid: false,
      downgrade_reasons: reasons,
    };
  }

  const brokerIdNorm =
    options.brokerId != null ? options.brokerId.trim().toLowerCase() : null;
  if (
    options.brokerNativeSignature != null &&
    brokerIdNorm != null &&
    options.brokerNativeSignature.broker_id.trim().toLowerCase() !== brokerIdNorm
  ) {
    reasons.push(
      `BrokerNativeSignature broker_id ${JSON.stringify(options.brokerNativeSignature.broker_id)} mismatches bundle broker_id ${JSON.stringify(options.brokerId)}`,
    );
  } else {
    const brokerSigOk = await verifyBrokerNativeSignature(
      options.brokerNativeSignature,
      normSourceSha,
      options.pinnedBrokerKeys,
    );
    if (brokerSigOk) {
      return {
        effective_origin_assurance: OriginAssurance.BROKER_SIGNED,
        valid_witness_count: 0,
        disjoint_quorum_size: 0,
        distinct_org_count: 0,
        distinct_asn_count: 0,
        broker_signature_valid: true,
        downgrade_reasons: [],
      };
    }
    if (options.brokerNativeSignature != null) {
      reasons.push(
        "BrokerNativeSignature failed verification against pinned broker keys",
      );
    }
  }

  const notaryMap = new Map(
    (options.notaryRegistry ?? []).map((n) => [n.notary_id, n]),
  );
  const pubKeyNorm = (options.publisherPublicKeyHex ?? "").trim().toLowerCase();
  const pubKidNorm = (options.publisherKid ?? "").trim().toLowerCase();
  const pubOrgNorm = (options.publisherOrg ?? "N170").trim().toLowerCase();

  const validBySni = new Map<
    string,
    Array<{ node: NotaryNodeInfo; tsMs: number }>
  >();
  let totalValidWitnesses = 0;

  for (const att of options.witnessAttestations ?? []) {
    const notary = notaryMap.get(att.notary_id);
    if (!notary) {
      reasons.push(
        `Notary ${JSON.stringify(att.notary_id)} is not present in trusted notary registry`,
      );
      continue;
    }
    if (
      Boolean(notary.is_debug_build) ||
      (notary.attestation_type ?? "production").trim().toLowerCase() === "debug"
    ) {
      reasons.push(
        `Notary ${JSON.stringify(att.notary_id)} uses a debug build/attestation`,
      );
      continue;
    }
    if (pubKidNorm && notary.notary_id.trim().toLowerCase() === pubKidNorm) {
      reasons.push(
        `Notary ${JSON.stringify(att.notary_id)} shares key ID with bundle publisher`,
      );
      continue;
    }
    if (
      pubKeyNorm &&
      notary.public_key_hex.trim().toLowerCase() === pubKeyNorm
    ) {
      reasons.push(
        `Notary ${JSON.stringify(att.notary_id)} shares public key with bundle publisher`,
      );
      continue;
    }
    if (
      pubOrgNorm &&
      notary.operator_org.trim().toLowerCase() === pubOrgNorm
    ) {
      reasons.push(
        `Notary ${JSON.stringify(att.notary_id)} is operated by publisher org (${JSON.stringify(notary.operator_org)})`,
      );
      continue;
    }
    const attRespSha = att.response_body_sha256.trim().toLowerCase();
    if (attRespSha !== normSourceSha) {
      reasons.push(
        `Notary ${JSON.stringify(att.notary_id)} response_body_sha256 does not match source_body_sha256`,
      );
      continue;
    }
    const safety = inspectTranscriptSafety(att);
    if (!safety.safe) {
      reasons.push(...safety.violations);
      continue;
    }
    const sigOk = await ed25519VerifyDomain(
      notary.public_key_hex,
      SIGNING_DOMAIN_WITNESS,
      witnessAttestationSignableBytes(att),
      att.signature_hex,
    );
    if (!sigOk) {
      reasons.push(
        `Notary ${JSON.stringify(att.notary_id)} Ed25519 signature verification failed`,
      );
      continue;
    }

    const sniKey = att.server_sni.trim().toLowerCase().replace(/\.+$/, "");
    const targetTrimmed = att.sanitized_request_target.trim();
    const targetLower = targetTrimmed.toLowerCase();
    if (
      targetLower.startsWith("http://") ||
      targetLower.startsWith("https://") ||
      targetTrimmed.startsWith("//")
    ) {
      let parsedHost = "";
      try {
        const candidateUrl = targetTrimmed.startsWith("//")
          ? `https:${targetTrimmed}`
          : targetTrimmed;
        parsedHost = new URL(candidateUrl).hostname
          .trim()
          .toLowerCase()
          .replace(/\.+$/, "");
      } catch {
        parsedHost = "";
      }
      if (parsedHost !== sniKey) {
        reasons.push(
          `Notary ${JSON.stringify(att.notary_id)} sanitized_request_target host mismatches server_sni ${JSON.stringify(sniKey)}`,
        );
        continue;
      }
    }
    if (brokerIdNorm != null) {
      const allowedSnis = BROKER_WITNESS_SNI_ALLOWLIST[brokerIdNorm];
      if (!allowedSnis || !allowedSnis.has(sniKey)) {
        reasons.push(
          `Notary ${JSON.stringify(att.notary_id)} server_sni ${JSON.stringify(sniKey)} is not an official TLS endpoint for broker_id=${JSON.stringify(options.brokerId)}`,
        );
        continue;
      }
    }

    const tsMs = parseUtcTimestampMs(
      att.session_timestamp_utc,
      "WitnessAttestation.session_timestamp_utc",
    );
    const bucket = validBySni.get(sniKey) ?? [];
    bucket.push({ node: notary, tsMs });
    validBySni.set(sniKey, bucket);
    totalValidWitnesses += 1;
  }

  let bestQuorum = 0;
  let bestOrgs = 0;
  let bestAsns = 0;
  for (const sniCandidates of validBySni.values()) {
    const [qSize, orgCnt, asnCnt] = maxMutuallyDisjointQuorum(
      sniCandidates,
      maxSkew,
    );
    if (
      qSize > bestQuorum ||
      (qSize === bestQuorum && orgCnt > bestOrgs) ||
      (qSize === bestQuorum && orgCnt === bestOrgs && asnCnt > bestAsns)
    ) {
      bestQuorum = qSize;
      bestOrgs = orgCnt;
      bestAsns = asnCnt;
    }
  }

  if (bestQuorum >= 2) {
    return {
      effective_origin_assurance: OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
      valid_witness_count: totalValidWitnesses,
      disjoint_quorum_size: bestQuorum,
      distinct_org_count: bestOrgs,
      distinct_asn_count: bestAsns,
      broker_signature_valid: false,
      downgrade_reasons: reasons,
    };
  }

  if (totalValidWitnesses >= 1) {
    reasons.push(
      `Insufficient org/ASN-disjoint notary quorum (disjoint_quorum_size=${bestQuorum} < 2); downgraded to operator_retrieved`,
    );
    return {
      effective_origin_assurance: OriginAssurance.OPERATOR_RETRIEVED,
      valid_witness_count: totalValidWitnesses,
      disjoint_quorum_size: bestQuorum,
      distinct_org_count: bestOrgs,
      distinct_asn_count: bestAsns,
      broker_signature_valid: false,
      downgrade_reasons: reasons,
    };
  }

  if (
    providerApprovalState !== ProviderApprovalState.OFFLINE_EXPORT_ONLY &&
    claimedOriginAssurance !== OriginAssurance.SELF_REPORTED
  ) {
    if (
      claimedOriginAssurance === OriginAssurance.INDEPENDENTLY_WITNESSED_TLS ||
      claimedOriginAssurance === OriginAssurance.BROKER_SIGNED
    ) {
      reasons.push(
        `Claimed ${claimedOriginAssurance} without valid quorum/broker signature; downgraded to operator_retrieved`,
      );
    }
    return {
      effective_origin_assurance: OriginAssurance.OPERATOR_RETRIEVED,
      valid_witness_count: 0,
      disjoint_quorum_size: 0,
      distinct_org_count: 0,
      distinct_asn_count: 0,
      broker_signature_valid: false,
      downgrade_reasons: reasons,
    };
  }

  if (
    claimedOriginAssurance != null &&
    claimedOriginAssurance !== OriginAssurance.SELF_REPORTED
  ) {
    reasons.push(
      `Offline export without valid witness quorum or broker signature; downgraded from ${claimedOriginAssurance} to self_reported`,
    );
  }
  return {
    effective_origin_assurance: OriginAssurance.SELF_REPORTED,
    valid_witness_count: 0,
    disjoint_quorum_size: 0,
    distinct_org_count: 0,
    distinct_asn_count: 0,
    broker_signature_valid: false,
    downgrade_reasons: reasons,
  };
}

// ---------------------------------------------------------------------------
// Five Prospective Chain Invariants
// ---------------------------------------------------------------------------

export async function verifyProspectiveChain(
  proofs: ReadonlyArray<VerifyProofBundle | ProspectiveChainLink>,
  options?: {
    continuityLogLeaves?: readonly ContinuityLogLeaf[] | null;
    nowUtc?: string | Date | null;
  },
): Promise<ChainVerificationResult> {
  if (proofs.length === 0) {
    return {
      valid: true,
      continuity_mode: ChainContinuityMode.UNENROLLED_SINGLE_SNAPSHOT,
      verified_length: 0,
      violation_codes: [],
      details: ["No prospective chain elements provided; single unenrolled snapshot."],
    };
  }

  const extracted: Array<{
    link: ProspectiveChainLink | null;
    digest: string;
    outerTag: string | null;
  }> = [];

  for (const item of proofs) {
    if ("schema_version" in item || "merkle_root" in item || "signature_hex" in item) {
      const bundle = item as VerifyProofBundle;
      const digest = await computeProofHash(bundle);
      extracted.push({
        link: bundle.prospective_chain_link ?? null,
        digest,
        outerTag: bundle.blinded_account_tag.trim().toLowerCase(),
      });
    } else {
      const link = item as ProspectiveChainLink;
      const digest = await jcsSha256Hex(normalizeProspectiveChainLinkDict(link));
      extracted.push({
        link,
        digest,
        outerTag: null,
      });
    }
  }

  if (extracted.length === 1 && extracted[0]!.link === null) {
    return {
      valid: true,
      continuity_mode: ChainContinuityMode.UNENROLLED_SINGLE_SNAPSHOT,
      verified_length: 0,
      violation_codes: [],
      details: ["Proof bundle is an unenrolled single snapshot."],
    };
  }

  const violations: ChainInvariantViolationCode[] = [];
  const details: string[] = [];

  const record = (code: ChainInvariantViolationCode, msg: string): void => {
    if (!violations.includes(code)) {
      violations.push(code);
    }
    details.push(msg);
  };

  const links: ProspectiveChainLink[] = [];
  const elemHashes: string[] = [];

  for (let idx = 0; idx < extracted.length; idx += 1) {
    const { link, digest, outerTag } = extracted[idx]!;
    if (link === null) {
      record(
        ChainInvariantViolationCode.NON_MONOTONIC_SEQUENCE,
        `Element ${idx} in multi-element chain is missing prospective_chain_link`,
      );
      return {
        valid: false,
        continuity_mode: ChainContinuityMode.CONTINUITY_BROKEN,
        verified_length: idx,
        violation_codes: violations,
        details,
      };
    }
    if (
      !Number.isInteger(link.sequence_number) ||
      link.sequence_number < 0
    ) {
      record(
        ChainInvariantViolationCode.NON_MONOTONIC_SEQUENCE,
        `Element ${idx} sequence_number must be an integer >= 0`,
      );
    }
    if (
      !Number.isFinite(link.beginning_index_value) ||
      !Number.isFinite(link.ending_index_value) ||
      !Number.isFinite(link.period_twr_decimal) ||
      link.beginning_index_value <= 0 ||
      link.ending_index_value <= 0
    ) {
      record(
        ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
        `Element ${idx} has non-finite or non-positive index/TWR values`,
      );
    }
    if (
      !Number.isInteger(link.cadence_policy?.expected_interval_seconds) ||
      link.cadence_policy.expected_interval_seconds <= 0 ||
      !Number.isInteger(link.cadence_policy?.grace_window_seconds) ||
      link.cadence_policy.grace_window_seconds < 0
    ) {
      record(
        ChainInvariantViolationCode.CADENCE_POLICY_MUTATED,
        `Element ${idx} has invalid cadence_policy bounds`,
      );
    }
    if (
      outerTag !== null &&
      outerTag !== link.blinded_account_tag.trim().toLowerCase()
    ) {
      record(
        ChainInvariantViolationCode.ACCOUNT_CONTINUITY_VIOLATION,
        `Element ${idx} bundle blinded_account_tag mismatches chain link blinded_account_tag`,
      );
    }
    links.push(link);
    elemHashes.push(digest);
  }

  const genesis = links[0]!;
  const genesisTag = genesis.blinded_account_tag.trim().toLowerCase();

  // Invariant 1: 24h Genesis Enrollment Window & Genesis Boundary
  if (genesis.sequence_number !== 0) {
    record(
      ChainInvariantViolationCode.NON_MONOTONIC_SEQUENCE,
      `Genesis link sequence_number must be 0 (got ${genesis.sequence_number})`,
    );
  }
  if (genesis.prev_proof_hash != null) {
    record(
      ChainInvariantViolationCode.PREV_HASH_MISMATCH,
      "Genesis link prev_proof_hash must be None",
    );
  }

  const gEnrolledMs = parseUtcTimestampMs(genesis.enrolled_at_utc);
  const gStartMs = parseUtcTimestampMs(genesis.period_start_utc);
  const gEndMs = parseUtcTimestampMs(genesis.period_end_utc);
  const gIssuedMs = parseUtcTimestampMs(genesis.issued_at_utc);

  if (gEndMs <= gStartMs) {
    record(
      ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
      "Genesis period_end_utc must be strictly after period_start_utc",
    );
  }
  if (gIssuedMs < gEndMs) {
    record(
      ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
      "Genesis issued_at_utc cannot precede period_end_utc",
    );
  }

  const enrollmentDeltaSec = Math.abs(gEnrolledMs - gStartMs) / 1000;
  const genesisIssueLagSec = (gIssuedMs - gEndMs) / 1000;
  if (
    enrollmentDeltaSec > GENESIS_ENROLLMENT_WINDOW_SECONDS ||
    genesisIssueLagSec > genesis.cadence_policy.grace_window_seconds
  ) {
    record(
      ChainInvariantViolationCode.GENESIS_BACKFILL_WINDOW_EXCEEDED,
      `Genesis enrollment delta (${Math.round(enrollmentDeltaSec)}s) or issuance lag (${Math.round(genesisIssueLagSec)}s) exceeds prospective window; classified as retrospective backfill`,
    );
  }

  let intactPrefix = 0;
  let structuralBroken = violations.some(
    (c) => c !== ChainInvariantViolationCode.GENESIS_BACKFILL_WINDOW_EXCEEDED,
  );

  const expectedEnd0 =
    genesis.beginning_index_value * (1.0 + genesis.period_twr_decimal);
  if (
    Math.abs(genesis.ending_index_value - expectedEnd0) >
    INDEX_CONTINUITY_TOLERANCE
  ) {
    record(
      ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
      "Genesis ending_index_value does not match beginning_index_value * (1 + period_twr_decimal)",
    );
    structuralBroken = true;
  }

  if (!structuralBroken) {
    intactPrefix = 1;
  }

  for (let idx = 1; idx < links.length; idx += 1) {
    const prevLink = links[idx - 1]!;
    const currLink = links[idx]!;
    let linkOk = true;

    // Invariant 2: Monotonic sequence_number, prev_proof_hash, immutable cadence_policy
    if (currLink.sequence_number !== prevLink.sequence_number + 1) {
      record(
        ChainInvariantViolationCode.NON_MONOTONIC_SEQUENCE,
        `Link ${idx} sequence_number=${currLink.sequence_number} expected ${prevLink.sequence_number + 1}`,
      );
      linkOk = false;
    }

    const currPrevHash =
      currLink.prev_proof_hash != null
        ? currLink.prev_proof_hash.trim().toLowerCase()
        : null;
    if (
      currPrevHash !== elemHashes[idx - 1] ||
      currLink.chain_id !== genesis.chain_id
    ) {
      record(
        ChainInvariantViolationCode.PREV_HASH_MISMATCH,
        `Link ${idx} prev_proof_hash or chain_id does not match previous proof digest`,
      );
      linkOk = false;
    }

    if (
      currLink.cadence_policy.expected_interval_seconds !==
        genesis.cadence_policy.expected_interval_seconds ||
      currLink.cadence_policy.grace_window_seconds !==
        genesis.cadence_policy.grace_window_seconds
    ) {
      record(
        ChainInvariantViolationCode.CADENCE_POLICY_MUTATED,
        `Link ${idx} mutated cadence_policy from genesis commitment`,
      );
      linkOk = false;
    }

    // Invariant 3: blinded_account_tag pinning
    if (currLink.blinded_account_tag.trim().toLowerCase() !== genesisTag) {
      record(
        ChainInvariantViolationCode.ACCOUNT_CONTINUITY_VIOLATION,
        `Link ${idx} blinded_account_tag switched mid-chain`,
      );
      linkOk = false;
    }

    // Invariant 4: Contiguous period boundaries + timely issuance + index continuity
    const prevEndMs = parseUtcTimestampMs(prevLink.period_end_utc);
    const currStartMs = parseUtcTimestampMs(currLink.period_start_utc);
    const currEndMs = parseUtcTimestampMs(currLink.period_end_utc);
    const currIssuedMs = parseUtcTimestampMs(currLink.issued_at_utc);

    if (currStartMs !== prevEndMs) {
      record(
        ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
        `Link ${idx} period_start_utc (${currLink.period_start_utc}) != prev.period_end_utc (${prevLink.period_end_utc})`,
      );
      linkOk = false;
    }

    if (currEndMs <= currStartMs) {
      record(
        ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
        `Link ${idx} period_end_utc must be strictly after period_start_utc`,
      );
      linkOk = false;
    }

    const issueLagSec = (currIssuedMs - currEndMs) / 1000;
    if (
      issueLagSec < 0 ||
      issueLagSec > genesis.cadence_policy.grace_window_seconds
    ) {
      record(
        ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
        `Link ${idx} issued_at_utc violates [period_end_utc, period_end_utc + grace_window_seconds]`,
      );
      linkOk = false;
    }

    if (
      Math.abs(currLink.beginning_index_value - prevLink.ending_index_value) >
      INDEX_CONTINUITY_TOLERANCE
    ) {
      record(
        ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
        `Link ${idx} beginning_index_value (${currLink.beginning_index_value}) discontinuous with prev.ending_index_value (${prevLink.ending_index_value})`,
      );
      linkOk = false;
    }

    const expectedCurrEnd =
      currLink.beginning_index_value * (1.0 + currLink.period_twr_decimal);
    if (
      Math.abs(currLink.ending_index_value - expectedCurrEnd) >
      INDEX_CONTINUITY_TOLERANCE
    ) {
      record(
        ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
        `Link ${idx} ending_index_value inconsistent with period_twr_decimal`,
      );
      linkOk = false;
    }

    if (!linkOk) {
      structuralBroken = true;
    } else if (!structuralBroken) {
      intactPrefix += 1;
    }
  }

  // Invariant 5: Transparency Log Monotonicity & Tail Freshness
  if (options?.continuityLogLeaves != null) {
    const acctLeaves = options.continuityLogLeaves.filter(
      (leaf) => leaf.blinded_account_tag.trim().toLowerCase() === genesisTag,
    );
    const genesisLeaves = acctLeaves.filter((leaf) => leaf.sequence_number === 0);
    if (genesisLeaves.length > 1) {
      record(
        ChainInvariantViolationCode.PARALLEL_CHAIN_RESET_DETECTED,
        "Continuity log contains multiple sequence_number == 0 entries for blinded_account_tag",
      );
      structuralBroken = true;
    }

    const distinctChains = new Set(acctLeaves.map((leaf) => leaf.chain_id));
    if (
      distinctChains.size > 0 &&
      (distinctChains.size > 1 || !distinctChains.has(genesis.chain_id))
    ) {
      record(
        ChainInvariantViolationCode.PARALLEL_CHAIN_RESET_DETECTED,
        "Continuity log records a conflicting chain_id for blinded_account_tag",
      );
      structuralBroken = true;
    }

    const loggedBySeq = new Map<number, string>();
    for (const leaf of acctLeaves) {
      const normProofHash = leaf.proof_hash.trim().toLowerCase();
      const existing = loggedBySeq.get(leaf.sequence_number);
      if (existing !== undefined && existing !== normProofHash) {
        record(
          ChainInvariantViolationCode.PARALLEL_CHAIN_RESET_DETECTED,
          `Continuity log contains conflicting proof_hash entries at sequence ${leaf.sequence_number}`,
        );
        structuralBroken = true;
      }
      loggedBySeq.set(leaf.sequence_number, normProofHash);
    }

    for (let idx = 0; idx < links.length; idx += 1) {
      const link = links[idx]!;
      const digest = elemHashes[idx]!;
      const loggedHash = loggedBySeq.get(link.sequence_number);
      if (loggedHash !== undefined && loggedHash !== digest) {
        record(
          ChainInvariantViolationCode.PARALLEL_CHAIN_RESET_DETECTED,
          `Presented proof hash at sequence ${link.sequence_number} conflicts with transparency log`,
        );
        structuralBroken = true;
      }
    }

    const maxPresentedSeq = links[links.length - 1]!.sequence_number;
    if (acctLeaves.some((leaf) => leaf.sequence_number > maxPresentedSeq)) {
      record(
        ChainInvariantViolationCode.STALE_OR_TRUNCATED_TAIL,
        "Continuity log contains newer sequence_number(s) omitted from presented chain tail",
      );
      structuralBroken = true;
    }
  }

  if (options?.nowUtc != null) {
    const nowMs = parseUtcTimestampMs(options.nowUtc, "now_utc");
    const lastLink = links[links.length - 1]!;
    const lastEndMs = parseUtcTimestampMs(lastLink.period_end_utc);
    const freshnessDeadlineMs =
      lastEndMs +
      (lastLink.cadence_policy.expected_interval_seconds +
        lastLink.cadence_policy.grace_window_seconds) *
        1000;
    if (nowMs > freshnessDeadlineMs) {
      record(
        ChainInvariantViolationCode.STALE_OR_TRUNCATED_TAIL,
        `Chain tail period_end_utc (${lastLink.period_end_utc}) is stale at ${new Date(nowMs).toISOString()}`,
      );
      structuralBroken = true;
    }
  }

  let mode: ChainContinuityMode;
  if (structuralBroken) {
    mode = ChainContinuityMode.CONTINUITY_BROKEN;
  } else if (
    violations.includes(ChainInvariantViolationCode.GENESIS_BACKFILL_WINDOW_EXCEEDED)
  ) {
    mode = ChainContinuityMode.RETROSPECTIVE_BACKFILL;
  } else {
    mode = ChainContinuityMode.PROSPECTIVE_CONTINUOUS;
  }

  return {
    valid: violations.length === 0,
    continuity_mode: mode,
    verified_length: intactPrefix,
    violation_codes: violations,
    details,
  };
}

// ---------------------------------------------------------------------------
// End-to-End `verifyProofBundle`
// ---------------------------------------------------------------------------

export async function verifyProofBundle(
  bundle: VerifyProofBundle,
  options?: {
    registryDoc?: PublisherKeyRegistryDocument | null;
    chainHistory?: readonly VerifyProofBundle[] | null;
    continuityLogLeaves?: readonly ContinuityLogLeaf[] | null;
    nowUtc?: string | Date | null;
  },
): Promise<BundleVerificationResult> {
  const errors: string[] = [];
  const warnings: string[] = [];

  const retentionNorm = (bundle.retention_mode ?? "no_persistent_storage")
    .trim()
    .toLowerCase();
  if (
    !ALLOWED_RETENTION_MODES.includes(
      retentionNorm as (typeof ALLOWED_RETENTION_MODES)[number],
    )
  ) {
    throw new Error(
      `VerifyProofBundle.retention_mode must be one of ${JSON.stringify(ALLOWED_RETENTION_MODES)}`,
    );
  }

  const schemaOk = bundle.schema_version === VERIFY_SCHEMA_VERSION;
  if (!schemaOk) {
    errors.push(
      `Unsupported schema_version ${JSON.stringify(bundle.schema_version)}; expected ${JSON.stringify(VERIFY_SCHEMA_VERSION)}`,
    );
  }

  const envOk = bundle.environment_tier === EnvironmentTier.LIVE_PRODUCTION;
  if (!envOk) {
    errors.push("Bundle environment_tier is paper_or_sandbox_rejected");
  }

  const proofHash = await computeProofHash(bundle);
  const signatureValid = await verifyPublisherSignature(bundle);
  if (!signatureValid) {
    errors.push("Publisher Ed25519 signature verification failed");
  }

  const merkleRes = await verifySelectiveDisclosure(
    bundle.merkle_root,
    bundle.disclosed_leaves ?? [],
    bundle.undisclosed_leaf_hashes ?? {},
  );
  const merkleValid = merkleRes.valid;
  if (!merkleValid) {
    errors.push(...merkleRes.errors);
  }

  let transcriptSafetyOk = true;
  for (const att of bundle.witness_attestations ?? []) {
    const safety = inspectTranscriptSafety(att);
    if (!safety.safe) {
      transcriptSafetyOk = false;
      errors.push(...safety.violations);
    }
  }

  const registryDoc = options?.registryDoc ?? null;
  const signerEval = await evaluateSignerTrust(bundle, registryDoc, signatureValid);
  const signerTrust = signerEval.status;
  if (signerTrust === SignerTrustStatus.REVOKED_KEY) {
    errors.push(
      `Publisher signing key ${JSON.stringify(bundle.publisher_kid)} is revoked`,
    );
  }

  let publisherOrg = "N170";
  let notaries: readonly NotaryNodeInfo[] = [];
  let pinnedBrokerKeys:
    | Readonly<Record<string, Readonly<Record<string, string>>>>
    | null = null;
  if (registryDoc != null) {
    notaries = registryDoc.notaries ?? [];
    pinnedBrokerKeys = registryDoc.pinned_broker_keys ?? null;
    for (const rec of registryDoc.keys ?? []) {
      if (rec.publisher_kid === bundle.publisher_kid) {
        publisherOrg = rec.issuer_org ?? "N170";
        break;
      }
    }
  }

  const witnessEval = await evaluateOriginAssurance({
    sourceBodySha256: bundle.source_body_sha256,
    signerTrust,
    brokerId: bundle.broker_id,
    publisherKid: bundle.publisher_kid,
    publisherPublicKeyHex: bundle.publisher_public_key_hex,
    publisherOrg,
    environmentTier: bundle.environment_tier,
    providerApprovalState: bundle.provider_approval_state,
    claimedOriginAssurance: bundle.claimed_origin_assurance,
    witnessAttestations: bundle.witness_attestations ?? [],
    notaryRegistry: notaries,
    brokerNativeSignature: bundle.broker_native_signature ?? null,
    pinnedBrokerKeys,
  });

  const effectiveOrigin = witnessEval.effective_origin_assurance;
  if (effectiveOrigin !== bundle.claimed_origin_assurance) {
    warnings.push(
      `Origin assurance dynamically evaluated as ${effectiveOrigin} (bundle claimed ${bundle.claimed_origin_assurance})`,
    );
    warnings.push(...witnessEval.downgrade_reasons);
  }

  let chainResult: ChainVerificationResult | null = null;
  let continuityMode: ChainContinuityMode;
  const chainHistory = options?.chainHistory ?? null;
  const continuityLogLeaves = options?.continuityLogLeaves ?? null;

  if (
    bundle.prospective_chain_link == null &&
    (!chainHistory || chainHistory.length === 0)
  ) {
    continuityMode = ChainContinuityMode.UNENROLLED_SINGLE_SNAPSHOT;
    if (continuityLogLeaves && continuityLogLeaves.length > 0) {
      const normBundleTag = bundle.blinded_account_tag.trim().toLowerCase();
      const enrolledEntries = continuityLogLeaves.filter(
        (leaf) => leaf.blinded_account_tag.trim().toLowerCase() === normBundleTag,
      );
      if (enrolledEntries.length > 0) {
        continuityMode = ChainContinuityMode.CONTINUITY_BROKEN;
        errors.push(
          "Account has enrolled continuity log entries but presented an unenrolled snapshot",
        );
      }
    }
  } else {
    const chainElements = [...(chainHistory ?? [])];
    if (
      chainElements.length === 0 ||
      chainElements[chainElements.length - 1]!.proof_id !== bundle.proof_id
    ) {
      chainElements.push(bundle);
    }
    chainResult = await verifyProspectiveChain(chainElements, {
      continuityLogLeaves,
      nowUtc: options?.nowUtc ?? null,
    });
    continuityMode = chainResult.continuity_mode;
    if (continuityMode === ChainContinuityMode.CONTINUITY_BROKEN) {
      errors.push(...chainResult.details);
    } else if (continuityMode === ChainContinuityMode.RETROSPECTIVE_BACKFILL) {
      warnings.push(...chainResult.details);
    }
  }

  const overallValid =
    schemaOk &&
    envOk &&
    signatureValid &&
    merkleValid &&
    transcriptSafetyOk &&
    signerTrust !== SignerTrustStatus.REVOKED_KEY &&
    continuityMode !== ChainContinuityMode.CONTINUITY_BROKEN;

  const profile: AssuranceProfile = {
    effective_origin_assurance: effectiveOrigin,
    account_scope: bundle.account_scope,
    provider_approval_state: bundle.provider_approval_state,
    environment_tier: bundle.environment_tier,
    signer_trust_status: signerTrust,
    chain_continuity_mode: continuityMode,
  };

  return {
    valid: overallValid,
    proof_id: bundle.proof_id,
    proof_hash: proofHash,
    signature_valid: signatureValid,
    merkle_valid: merkleValid,
    transcript_safety_ok: transcriptSafetyOk,
    signer_trust_status: signerTrust,
    effective_origin_assurance: effectiveOrigin,
    effective_chain_continuity_mode: continuityMode,
    assurance_profile: profile,
    disclosed_leaf_names: (bundle.disclosed_leaves ?? []).map(
      (leaf) => leaf.leaf_name,
    ),
    undisclosed_leaf_names: Object.keys(
      bundle.undisclosed_leaf_hashes ?? {},
    ).sort(),
    witness_quorum: witnessEval,
    chain_verification: chainResult,
    checkpoint_verified: signerEval.checkpointVerified,
    checkpoint_witness_count: signerEval.checkpointWitnessCount,
    errors: Array.from(new Set(errors)),
    warnings: Array.from(new Set(warnings)),
  };
}
