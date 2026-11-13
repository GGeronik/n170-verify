"use strict";

/**
 * Outbound `n170-verify-mcp` JSON-RPC 2.0 server (pure Node.js >= 20 stdlib).
 *
 * Zero external npm dependencies (`node:crypto`, `node:readline`).
 * Implements byte-for-byte parity with Python `n170_verify.contracts.verify_proof_bundle`:
 *   - RFC 8785 JSON Canonicalization Scheme (JCS)
 *   - Domain-separated WebCrypto Ed25519 signature verification
 *   - Salted 7-leaf Merkle tree selective disclosure (`0x00` leaf / `0x01` node)
 *   - C2SP `tlog-checkpoint` & publisher key registry trust evaluation
 *   - Dynamic k >= 2 org- & ASN-disjoint TLSNotary witness quorum verification
 *   - Five formal prospective chain invariants
 *
 * Security invariants:
 *   - `additionalProperties: false` on every tool schema
 *   - Zero credentials, zero filesystem paths, and zero arbitrary URLs accepted
 *   - Explicit LLM transcript-privacy notice on all capabilities and tool outputs
 */

const crypto = require("node:crypto");
const readline = require("node:readline");

const SERVER_NAME = "n170-verify-mcp";
const SERVER_VERSION = "0.3.0";
const VERIFY_SCHEMA_VERSION = "n170-verify-v3";
const MCP_PROTOCOL_VERSION = "2025-11-25";
const SUPPORTED_MCP_VERSIONS = new Set([
  "2025-11-25",
  "2025-06-18",
  "2025-03-26",
  "2024-11-05",
]);

const SIGNING_DOMAIN_BUNDLE = Buffer.from("n170.verify.bundle.v3", "utf8");
const SIGNING_DOMAIN_CHECKPOINT = Buffer.from("n170.verify.checkpoint.v3", "utf8");
const SIGNING_DOMAIN_WITNESS = Buffer.from("n170.verify.witness.v3", "utf8");
const SIGNING_DOMAIN_BROKER = Buffer.from("n170.verify.broker.v3", "utf8");

const LEAF_DOMAIN_PREFIX = Buffer.from("n170.verify.leaf.v3\x00", "utf8");
const NODE_DOMAIN_PREFIX = Buffer.from("n170.verify.node.v3\x01", "utf8");

const CANONICAL_LEAF_NAMES = Object.freeze([
  "core_metrics",
  "indexed_curve",
  "reconciliation",
  "coaching_and_context",
  "capital_bracket",
  "benchmark_alpha",
  "delayed_closed_trades",
]);

const REQUIRED_TLSN_PROTOCOL = "tlsn-v0.1.0-alpha.15";
const REQUIRED_TLS_VERSION = "1.2";
const DEFAULT_MAX_WITNESS_SKEW_SECONDS = 600;
const GENESIS_ENROLLMENT_WINDOW_SECONDS = 86400;
const INDEX_CONTINUITY_TOLERANCE = 1e-4;

const TRANSCRIPT_PRIVACY_NOTICE =
  "LLM TRANSCRIPT PRIVACY NOTICE: All MCP tool arguments and responses are visible to " +
  "your host LLM provider's conversation transcript. Pass ONLY selectively redacted " +
  "public VerifyProofBundle JSON objects or public proof_id identifiers; NEVER pass " +
  "raw brokerage statements, unredacted account numbers, API keys, or session tokens.";

const FORBIDDEN_TOP_OR_NESTED_CREDENTIAL_KEYS = new Set([
  "api_key",
  "apikey",
  "api_secret",
  "secret",
  "secret_key",
  "password",
  "passphrase",
  "access_token",
  "refresh_token",
  "flex_token",
  "live_session_token",
  "session_cookie",
  "cookie",
  "cookies",
  "totp",
  "mfa_code",
  "private_key",
  "private_key_hex",
  "file",
  "filepath",
  "file_path",
  "path",
  "cache_dir",
  "raw_xml",
  "raw_csv",
  "endpoint_url",
  "url",
]);

const PATH_OR_URL_VALUE_RE =
  /(?:^file:\/\/|^\.\.\/|\/\.\.\/|^[A-Za-z]:\\|^~[/\\]|^\/(?:etc|var|tmp|opt|private|proc|sys|root|Users|home)(?:\/|$)|^https?:\/\/)/i;

const REDACTED_PLACEHOLDERS = new Set(["[redacted]", "<redacted>", "redacted", "***", "*"]);
const ALLOWED_STATIC_ACCOUNT_SEGMENTS = new Set([
  ...REDACTED_PLACEHOLDERS,
  "accountnumbers",
  "subaccounts",
  "summary",
]);
const SENSITIVE_HEADER_NAMES = new Set([
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

class VerifyMcpError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "VerifyMcpError";
    this.code = code;
  }
}

/* -------------------------------------------------------------------------- */
/* RFC 8785 JSON Canonicalization Scheme (JCS)                                */
/* -------------------------------------------------------------------------- */

const CONTROL_ESCAPES = Object.freeze({
  0x08: "\\b",
  0x09: "\\t",
  0x0a: "\\n",
  0x0c: "\\f",
  0x0d: "\\r",
  0x22: '\\"',
  0x5c: "\\\\",
});

function escapeJcsString(str) {
  if (typeof str !== "string") {
    throw new TypeError("JCS string serializer expected a string");
  }
  const out = ['"'];
  for (let i = 0; i < str.length; i += 1) {
    const code = str.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (i + 1 >= str.length) {
        throw new RangeError("RFC 8785 JCS forbids lone high UTF-16 surrogate");
      }
      const next = str.charCodeAt(i + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        throw new RangeError("RFC 8785 JCS forbids unpaired high UTF-16 surrogate");
      }
      out.push(str.slice(i, i + 2));
      i += 1;
      continue;
    }
    if (code >= 0xdc00 && code <= 0xdfff) {
      throw new RangeError("RFC 8785 JCS forbids lone low UTF-16 surrogate");
    }
    if (Object.prototype.hasOwnProperty.call(CONTROL_ESCAPES, code)) {
      out.push(CONTROL_ESCAPES[code]);
    } else if (code < 0x20) {
      out.push(`\\u${code.toString(16).padStart(4, "0")}`);
    } else {
      out.push(str[i]);
    }
  }
  out.push('"');
  return out.join("");
}

function compareUtf16CodeUnits(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function jcsCanonicalizeStr(value) {
  if (value === null) {
    return "null";
  }
  const t = typeof value;
  if (t === "boolean") {
    return value ? "true" : "false";
  }
  if (t === "number") {
    if (!Number.isFinite(value)) {
      throw new RangeError("RFC 8785 JCS forbids non-finite numbers");
    }
    return Object.is(value, -0) ? "0" : JSON.stringify(value);
  }
  if (t === "string") {
    return escapeJcsString(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => jcsCanonicalizeStr(item)).join(",")}]`;
  }
  if (t === "object") {
    const keys = Object.keys(value);
    for (const k of keys) {
      if (value[k] === undefined) {
        throw new TypeError(`RFC 8785 JCS forbids undefined object property: ${JSON.stringify(k)}`);
      }
    }
    keys.sort(compareUtf16CodeUnits);
    const members = keys.map((k) => `${escapeJcsString(k)}:${jcsCanonicalizeStr(value[k])}`);
    return `{${members.join(",")}}`;
  }
  throw new TypeError(`Unsupported type in JCS canonicalization: ${t}`);
}

function jcsCanonicalize(value) {
  return Buffer.from(jcsCanonicalizeStr(value), "utf8");
}

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function jcsSha256Hex(value) {
  return sha256Hex(jcsCanonicalize(value));
}

/* -------------------------------------------------------------------------- */
/* Validation & WebCrypto Ed25519 Helpers                                     */
/* -------------------------------------------------------------------------- */

function validateHexDigest(value, fieldName, numBytes = 32) {
  if (typeof value !== "string") {
    throw new VerifyMcpError("invalid_bundle", `${fieldName} must be a hex string`);
  }
  const norm = value.trim().toLowerCase();
  const expectedLen = numBytes * 2;
  if (norm.length !== expectedLen || !/^[0-9a-f]+$/.test(norm)) {
    throw new VerifyMcpError(
      "invalid_bundle",
      `${fieldName} must be ${expectedLen} hexadecimal characters`
    );
  }
  return norm;
}

function parseUtcTimestampMs(value, fieldName = "timestamp") {
  if (typeof value !== "string" || !value.trim()) {
    throw new VerifyMcpError("invalid_bundle", `${fieldName} must be a non-empty ISO-8601 string`);
  }
  let cleaned = value.trim();
  if (!cleaned.endsWith("Z") && !cleaned.endsWith("z") && !/[+-]\d{2}:\d{2}$/.test(cleaned)) {
    cleaned += "Z";
  }
  const ms = Date.parse(cleaned);
  if (Number.isNaN(ms)) {
    throw new VerifyMcpError("invalid_bundle", `${fieldName} is not a valid ISO-8601 timestamp`);
  }
  return ms;
}

function normalizeFiniteNumber(val, fieldName) {
  if (typeof val !== "number" || !Number.isFinite(val)) {
    throw new VerifyMcpError("invalid_bundle", `${fieldName} must be a finite number`);
  }
  return Object.is(val, -0) ? 0 : val;
}

const ED25519_P = (1n << 255n) - 19n;
const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;
const ED25519_SMALL_ORDER_Y = new Set([
  0n,
  1n,
  ED25519_P - 1n,
  0x05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826n,
  0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7n,
]);

function bytesToLittleEndianBigInt(bytes) {
  let acc = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    acc = (acc << 8n) | BigInt(bytes[i]);
  }
  return acc;
}

function isCanonicalNonTorsionEd25519Point(point32b) {
  if (!point32b || point32b.length !== 32) {
    return false;
  }
  const y = bytesToLittleEndianBigInt(point32b) & ((1n << 255n) - 1n);
  if (y >= ED25519_P || ED25519_SMALL_ORDER_Y.has(y)) {
    return false;
  }
  return true;
}

function isCanonicalEd25519Scalar(scalar32b) {
  if (!scalar32b || scalar32b.length !== 32) {
    return false;
  }
  const s = bytesToLittleEndianBigInt(scalar32b);
  return s > 0n && s < ED25519_L;
}

async function ed25519VerifyDomain(publicKeyHex, domainBuf, payloadBuf, signatureHex) {
  try {
    const normPub = validateHexDigest(publicKeyHex, "public_key_hex", 32);
    const normSig = validateHexDigest(signatureHex, "signature_hex", 64);
    const pubBytes = Buffer.from(normPub, "hex");
    const sigBytes = Buffer.from(normSig, "hex");
    if (
      !isCanonicalNonTorsionEd25519Point(pubBytes) ||
      !isCanonicalNonTorsionEd25519Point(sigBytes.subarray(0, 32)) ||
      !isCanonicalEd25519Scalar(sigBytes.subarray(32, 64))
    ) {
      return false;
    }
    const message = Buffer.concat([domainBuf, Buffer.from([0x00]), payloadBuf]);
    const key = await crypto.webcrypto.subtle.importKey(
      "raw",
      pubBytes,
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    return await crypto.webcrypto.subtle.verify("Ed25519", key, sigBytes, message);
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* Salted Merkle Selective Disclosure (`0x00` leaf / `0x01` node)             */
/* -------------------------------------------------------------------------- */

function computeSaltedLeafHash(leafName, saltHex, payload) {
  if (typeof leafName !== "string" || !leafName.trim() || leafName.includes("\x00")) {
    throw new VerifyMcpError("invalid_bundle", "Invalid Merkle leaf_name");
  }
  const normSalt = validateHexDigest(saltHex, "salt_hex", 32);
  const jcsBytes = jcsCanonicalize(payload);
  const preimage = Buffer.concat([
    LEAF_DOMAIN_PREFIX,
    Buffer.from(leafName, "utf8"),
    Buffer.from([0x00]),
    Buffer.from(normSalt, "hex"),
    Buffer.from([0x00]),
    jcsBytes,
  ]);
  return sha256Hex(preimage);
}

function computeInternalNodeHash(leftHex, rightHex) {
  const lNorm = validateHexDigest(leftHex, "left_hash_hex", 32);
  const rNorm = validateHexDigest(rightHex, "right_hash_hex", 32);
  return sha256Hex(
    Buffer.concat([NODE_DOMAIN_PREFIX, Buffer.from(lNorm, "hex"), Buffer.from(rNorm, "hex")])
  );
}

function computeMerkleRootFromLeafHashes(orderedHashes) {
  let current = orderedHashes.map((h, i) => validateHexDigest(h, `leaf_hash[${i}]`, 32));
  while (current.length > 1) {
    const next = [];
    for (let i = 0; i < current.length; ) {
      if (i + 1 < current.length) {
        next.push(computeInternalNodeHash(current[i], current[i + 1]));
        i += 2;
      } else {
        next.push(current[i]);
        i += 1;
      }
    }
    current = next;
  }
  return current[0];
}

function verifyDisclosedLeaf(leaf, expectedRootHex) {
  try {
    const recomputed = computeSaltedLeafHash(leaf.leaf_name, leaf.salt_hex, leaf.payload);
    const claimedLeafHash = validateHexDigest(leaf.leaf_hash_hex, "leaf_hash_hex", 32);
    if (recomputed !== claimedLeafHash) {
      return false;
    }
    let current = recomputed;
    const steps = Array.isArray(leaf.audit_path) ? leaf.audit_path : [];
    for (const step of steps) {
      const side = String(step.side || "").trim().toLowerCase();
      const sib = validateHexDigest(step.sibling_hash_hex, "sibling_hash_hex", 32);
      if (side === "left") {
        current = computeInternalNodeHash(sib, current);
      } else if (side === "right") {
        current = computeInternalNodeHash(current, sib);
      } else {
        return false;
      }
    }
    return current === expectedRootHex;
  } catch {
    return false;
  }
}

function verifySelectiveDisclosure(merkleRootHex, disclosedLeaves, undisclosedLeafHashes) {
  const errors = [];
  let normRoot;
  try {
    normRoot = validateHexDigest(merkleRootHex, "merkle_root", 32);
  } catch (err) {
    return { valid: false, errors: [err.message] };
  }

  const seenDisclosed = new Map();
  for (const leaf of disclosedLeaves || []) {
    if (seenDisclosed.has(leaf.leaf_name)) {
      errors.push(`Duplicate disclosed leaf: '${leaf.leaf_name}'`);
      continue;
    }
    if (!verifyDisclosedLeaf(leaf, normRoot)) {
      errors.push(`Merkle disclosure verification failed for leaf '${leaf.leaf_name}'`);
    }
    try {
      seenDisclosed.set(
        leaf.leaf_name,
        validateHexDigest(leaf.leaf_hash_hex, "leaf_hash_hex", 32)
      );
    } catch (err) {
      errors.push(err.message);
      seenDisclosed.set(leaf.leaf_name, "0".repeat(64));
    }
  }

  const undisclosedObj = undisclosedLeafHashes || {};
  const overlap = Object.keys(undisclosedObj).filter((k) => seenDisclosed.has(k));
  if (overlap.length > 0) {
    errors.push(`Leaves present in both disclosed and undisclosed sets: ${overlap.sort().join(", ")}`);
  }

  const combined = new Map(seenDisclosed);
  for (const [name, digest] of Object.entries(undisclosedObj)) {
    try {
      combined.set(name, validateHexDigest(digest, `undisclosed_leaf_hashes[${name}]`, 32));
    } catch (err) {
      errors.push(err.message);
    }
  }

  const expectedSet = new Set(CANONICAL_LEAF_NAMES);
  const missing = CANONICAL_LEAF_NAMES.filter((n) => !combined.has(n));
  const extra = [...combined.keys()].filter((n) => !expectedSet.has(n));
  if (missing.length > 0 || extra.length > 0) {
    errors.push(
      `Canonical leaf partition mismatch (missing=[${missing.join(", ")}], extra=[${extra.join(", ")}])`
    );
  } else if (errors.length === 0) {
    const rebuiltRoot = computeMerkleRootFromLeafHashes(
      CANONICAL_LEAF_NAMES.map((n) => combined.get(n))
    );
    if (rebuiltRoot !== normRoot) {
      errors.push("Reconstructed canonical 7-leaf Merkle root does not match bundle merkle_root");
    }
  }

  return { valid: errors.length === 0, errors };
}

/* -------------------------------------------------------------------------- */
/* Transcript Safety, Witness Quorum (k >= 2 Disjoint), & C2SP Registry       */
/* -------------------------------------------------------------------------- */

const IBKR_WITNESS_SNIS = Object.freeze(
  new Set([
    "api.ibkr.com",
    "ndcdyn.interactivebrokers.com",
    "gdcdyn.interactivebrokers.com",
    "www.interactivebrokers.com",
  ])
);

const BROKER_WITNESS_SNI_ALLOWLIST = Object.freeze({
  ibkr: IBKR_WITNESS_SNIS,
  ibkr_flex: IBKR_WITNESS_SNIS,
  ibkr_flex_offline: IBKR_WITNESS_SNIS,
  ibkr_flex_web: IBKR_WITNESS_SNIS,
  ibkr_oauth: IBKR_WITNESS_SNIS,
  interactive_brokers: IBKR_WITNESS_SNIS,
  schwab: Object.freeze(new Set(["api.schwabapi.com"])),
  schwab_csv: Object.freeze(new Set(["api.schwabapi.com"])),
  alpaca: Object.freeze(new Set(["api.alpaca.markets"])),
  tradier: Object.freeze(new Set(["api.tradier.com"])),
  trading212: Object.freeze(new Set(["live.trading212.com"])),
  ctrader: Object.freeze(new Set(["openapi.ctrader.com", "live.ctraderapi.com"])),
  ctrader_oauth: Object.freeze(new Set(["openapi.ctrader.com", "live.ctraderapi.com"])),
  coinbase: Object.freeze(new Set(["api.coinbase.com", "api.exchange.coinbase.com"])),
  coinbaseadvanced: Object.freeze(new Set(["api.coinbase.com", "api.exchange.coinbase.com"])),
  coinbase_advanced: Object.freeze(new Set(["api.coinbase.com", "api.exchange.coinbase.com"])),
  binance: Object.freeze(new Set(["api.binance.com"])),
  kraken: Object.freeze(new Set(["api.kraken.com"])),
  bybit: Object.freeze(new Set(["api.bybit.com"])),
});

function inspectTranscriptSafety(att) {
  const violations = [];
  if (att.protocol !== REQUIRED_TLSN_PROTOCOL) {
    violations.push(
      `Unsupported TLSNotary protocol '${att.protocol}'; expected '${REQUIRED_TLSN_PROTOCOL}'`
    );
  }
  if (att.tls_version !== REQUIRED_TLS_VERSION) {
    violations.push(
      `Unsupported witnessed TLS version '${att.tls_version}'; expected '${REQUIRED_TLS_VERSION}'`
    );
  }
  if (att.defer_decryption_from_start !== true) {
    violations.push("defer_decryption_from_start must be True to prevent selective forgery");
  }
  if (att.commitment_kind === "unpadded_variable_span_rejected") {
    violations.push(
      "Variable-span transcript commitments leak NAV digit counts; require whole_body_sha256 or fixed_64b_padded_window"
    );
  }

  const target = String(att.sanitized_request_target || "");
  const queryRe = /(?:^|[?&])(t|q|token|access_token|refresh_token|api_key|apikey|secret|signature)=([^&#\s]*)/gi;
  let m;
  while ((m = queryRe.exec(target)) !== null) {
    if (!REDACTED_PLACEHOLDERS.has(m[2].trim().toLowerCase())) {
      violations.push(`Unredacted sensitive query parameter '${m[1]}' in sanitized_request_target`);
    }
  }

  const acctPathRe = /(?:\/v\d+)?\/accounts\/([^/?#\s]+)/gi;
  while ((m = acctPathRe.exec(target)) !== null) {
    if (!ALLOWED_STATIC_ACCOUNT_SEGMENTS.has(m[1].trim().toLowerCase())) {
      violations.push("Unredacted raw account identifier in /accounts/<id> path of sanitized_request_target");
    }
  }

  if (
    /\b(authorization|apca-api-key-id|apca-api-secret-key|cookie|set-cookie|cb-access-key|x-api-key|api-key|api-sign)\s*:/i.test(
      target
    )
  ) {
    violations.push("Sensitive HTTP header leaked inside sanitized_request_target");
  }

  const authSchemeRe = /\b(bearer|basic)\s+([^\s,;]+)/gi;
  while ((m = authSchemeRe.exec(target)) !== null) {
    if (!REDACTED_PLACEHOLDERS.has(m[2].trim().toLowerCase())) {
      violations.push(`Unredacted ${m[1]} credential leaked in sanitized_request_target`);
    }
  }

  const redactedHeaders = Array.isArray(att.redacted_headers) ? att.redacted_headers : [];
  if (redactedHeaders.length === 0) {
    violations.push("redacted_headers must list at least one redacted credential header");
  }
  for (const entry of redactedHeaders) {
    const stripped = String(entry).trim();
    const colonIdx = stripped.indexOf(":");
    if (colonIdx !== -1) {
      const hName = stripped.slice(0, colonIdx).trim().toLowerCase();
      const hVal = stripped.slice(colonIdx + 1).trim().toLowerCase();
      if (SENSITIVE_HEADER_NAMES.has(hName) && !REDACTED_PLACEHOLDERS.has(hVal)) {
        violations.push(`Unredacted sensitive header value for '${hName}' in redacted_headers`);
      }
    }
    authSchemeRe.lastIndex = 0;
    while ((m = authSchemeRe.exec(stripped)) !== null) {
      if (!REDACTED_PLACEHOLDERS.has(m[2].trim().toLowerCase())) {
        violations.push(`Unredacted ${m[1]} token in redacted_headers`);
      }
    }
  }

  return { ok: violations.length === 0, violations };
}

function normalizeAsn(asn) {
  let cleaned = String(asn || "").trim().toUpperCase();
  if (cleaned.startsWith("AS")) {
    cleaned = cleaned.slice(2).trim();
  }
  if (!cleaned) {
    throw new VerifyMcpError("invalid_bundle", "NotaryNodeInfo.asn must not be empty");
  }
  return `AS${cleaned}`;
}

function maxMutuallyDisjointQuorum(candidates, maxSkewSeconds) {
  if (candidates.length === 0) {
    return { bestQuorum: 0, distinctOrgs: 0, distinctAsns: 0 };
  }
  const sorted = [...candidates].sort((a, b) => a.tsMs - b.tsMs);
  let bestClique = [];

  for (let startIdx = 0; startIdx < sorted.length; startIdx += 1) {
    const t0 = sorted[startIdx].tsMs;
    const windowNodes = sorted
      .slice(startIdx)
      .filter((item) => (item.tsMs - t0) / 1000 <= maxSkewSeconds)
      .map((item) => item.node);

    const usedIds = new Set();
    const usedPubs = new Set();
    const usedOrgs = new Set();
    const usedAsns = new Set();
    const chosen = [];

    const search = (idx) => {
      if (chosen.length > bestClique.length) {
        bestClique = [...chosen];
      }
      if (chosen.length + (windowNodes.length - idx) <= bestClique.length) {
        return;
      }
      for (let pos = idx; pos < windowNodes.length; pos += 1) {
        const cand = windowNodes[pos];
        const nid = cand.notary_id.trim().toLowerCase();
        const pub = cand.public_key_hex.toLowerCase();
        const org = cand.operator_org.trim().toLowerCase();
        const asn = normalizeAsn(cand.asn);
        if (!usedIds.has(nid) && !usedPubs.has(pub) && !usedOrgs.has(org) && !usedAsns.has(asn)) {
          usedIds.add(nid);
          usedPubs.add(pub);
          usedOrgs.add(org);
          usedAsns.add(asn);
          chosen.push(cand);
          search(pos + 1);
          chosen.pop();
          usedAsns.delete(asn);
          usedOrgs.delete(org);
          usedPubs.delete(pub);
          usedIds.delete(nid);
        }
      }
    };
    search(0);
  }

  const allOrgs = new Set(sorted.map((c) => c.node.operator_org.trim().toLowerCase()));
  const allAsns = new Set(sorted.map((c) => normalizeAsn(c.node.asn)));
  return {
    bestQuorum: bestClique.length,
    distinctOrgs: allOrgs.size,
    distinctAsns: allAsns.size,
  };
}

async function verifyC2spCheckpoint(checkpoint, publisherPubHex) {
  const origin = String(checkpoint.origin || "").trim();
  const size = Number(checkpoint.size);
  const hashB64 = String(checkpoint.hash_b64 || "").trim();
  if (
    !origin ||
    !Number.isInteger(size) ||
    size < 0 ||
    !hashB64 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(hashB64) ||
    hashB64.length % 4 !== 0
  ) {
    return false;
  }
  const rawHash = Buffer.from(hashB64, "base64");
  if (rawHash.length !== 32 || rawHash.toString("base64") !== hashB64) {
    return false;
  }
  const body = Buffer.from(`${origin}\n${size}\n${hashB64}\n`, "utf8");
  const pubOk = await ed25519VerifyDomain(
    publisherPubHex,
    SIGNING_DOMAIN_CHECKPOINT,
    body,
    checkpoint.publisher_signature_hex
  );
  if (!pubOk) {
    return false;
  }
  for (const cosig of checkpoint.witness_cosignatures || []) {
    const tsSec = Math.floor(parseUtcTimestampMs(cosig.timestamp_utc, "cosignature.timestamp_utc") / 1000);
    const prefix = Buffer.from(`cosignature/v1\ntime ${tsSec}\n`, "utf8");
    const msg = Buffer.concat([prefix, body]);
    const wOk = await ed25519VerifyDomain(
      cosig.public_key_hex,
      SIGNING_DOMAIN_CHECKPOINT,
      msg,
      cosig.signature_hex
    );
    if (!wOk) {
      return false;
    }
  }
  return true;
}

async function evaluateSignerTrust(bundle, signatureValid, registryDoc, registryTrusted = true) {
  if (!signatureValid || !registryDoc || typeof registryDoc !== "object") {
    return "unrecognized_self_hosted_signer";
  }
  const keys = Array.isArray(registryDoc.keys) ? registryDoc.keys : [];
  const keyMap = new Map(keys.map((k) => [k.publisher_kid, k]));

  if (!registryTrusted) {
    const untrustedKeyRec = keyMap.get(bundle.publisher_kid);
    if (
      untrustedKeyRec &&
      String(untrustedKeyRec.public_key_hex || "").trim().toLowerCase() ===
        bundle.publisher_public_key_hex
    ) {
      const untrustedStatus = String(untrustedKeyRec.status || "").trim().toLowerCase();
      if (untrustedStatus === "revoked") {
        return "revoked_key";
      }
      if (untrustedKeyRec.revoked_after_utc) {
        const issuedMs = parseUtcTimestampMs(bundle.issued_at_utc, "issued_at_utc");
        const revMs = parseUtcTimestampMs(
          untrustedKeyRec.revoked_after_utc,
          "revoked_after_utc"
        );
        if (issuedMs >= revMs) {
          return "revoked_key";
        }
      }
    }
    return "unrecognized_self_hosted_signer";
  }

  if (registryDoc.checkpoint) {
    const ckptKey = keyMap.get(registryDoc.checkpoint.publisher_kid);
    if (!ckptKey || String(ckptKey.status).toLowerCase() === "revoked") {
      return "unrecognized_self_hosted_signer";
    }
    const ckptOk = await verifyC2spCheckpoint(registryDoc.checkpoint, ckptKey.public_key_hex);
    if (!ckptOk) {
      return "unrecognized_self_hosted_signer";
    }
  }

  const keyRec = keyMap.get(bundle.publisher_kid);
  if (
    !keyRec ||
    String(keyRec.public_key_hex || "").trim().toLowerCase() !== bundle.publisher_public_key_hex
  ) {
    return "unrecognized_self_hosted_signer";
  }

  const status = String(keyRec.status || "").trim().toLowerCase();
  if (status === "revoked") {
    return "revoked_key";
  }

  const issuedMs = parseUtcTimestampMs(bundle.issued_at_utc, "issued_at_utc");
  const notBeforeMs = parseUtcTimestampMs(keyRec.not_before_utc, "not_before_utc");
  if (issuedMs < notBeforeMs) {
    return "unrecognized_self_hosted_signer";
  }
  if (keyRec.revoked_after_utc) {
    const revMs = parseUtcTimestampMs(keyRec.revoked_after_utc, "revoked_after_utc");
    if (issuedMs >= revMs) {
      return "revoked_key";
    }
  }
  if (keyRec.not_after_utc) {
    const naMs = parseUtcTimestampMs(keyRec.not_after_utc, "not_after_utc");
    if (issuedMs > naMs) {
      return "unrecognized_self_hosted_signer";
    }
  }
  return status === "retired" ? "retired_historical_valid" : "official_n170_hosted";
}

async function evaluateOriginAssurance({
  bundle,
  signerTrust,
  publisherOrg,
  notaries,
  pinnedBrokerKeys,
}) {
  const reasons = [];
  const normSourceSha = bundle.source_body_sha256;

  if (bundle.environment_tier === "paper_or_sandbox_rejected") {
    reasons.push("Paper or sandbox environment tier rejected; downgraded to self_reported");
    return {
      effective_origin_assurance: "self_reported",
      valid_witness_count: 0,
      disjoint_quorum_size: 0,
      distinct_org_count: 0,
      distinct_asn_count: 0,
      broker_signature_valid: false,
      downgrade_reasons: reasons,
    };
  }

  if (signerTrust === "revoked_key" || signerTrust === "unrecognized_self_hosted_signer") {
    reasons.push(`Publisher signer trust is ${signerTrust}; downgraded to self_reported`);
    return {
      effective_origin_assurance: "self_reported",
      valid_witness_count: 0,
      disjoint_quorum_size: 0,
      distinct_org_count: 0,
      distinct_asn_count: 0,
      broker_signature_valid: false,
      downgrade_reasons: reasons,
    };
  }

  const bundleBrokerNorm = String(bundle.broker_id || "").trim().toLowerCase();

  // 1. First-party BrokerNativeSignature check
  if (bundle.broker_native_signature) {
    const bSig = bundle.broker_native_signature;
    const sigBrokerNorm = String(bSig.broker_id || "").trim().toLowerCase();
    const brokerIdMatches = !bundleBrokerNorm || sigBrokerNorm === bundleBrokerNorm;
    const brokerKeys =
      pinnedBrokerKeys && typeof pinnedBrokerKeys === "object"
        ? pinnedBrokerKeys[sigBrokerNorm]
        : null;
    const pinnedPub = brokerKeys ? brokerKeys[bSig.key_id] : null;
    let brokerOk = false;
    if (!brokerIdMatches) {
      reasons.push(
        `BrokerNativeSignature broker_id '${bSig.broker_id}' does not match bundle broker_id '${bundle.broker_id}'`
      );
    } else if (
      pinnedPub &&
      bSig.signed_payload_sha256 === normSourceSha &&
      bSig.algorithm.trim().toLowerCase() === "ed25519"
    ) {
      const signable = jcsCanonicalize({
        algorithm: bSig.algorithm,
        broker_id: bSig.broker_id,
        key_id: bSig.key_id,
        signed_payload_sha256: bSig.signed_payload_sha256,
      });
      brokerOk = await ed25519VerifyDomain(
        pinnedPub,
        SIGNING_DOMAIN_BROKER,
        signable,
        bSig.signature_hex
      );
    }
    if (brokerOk) {
      return {
        effective_origin_assurance: "broker_signed",
        valid_witness_count: 0,
        disjoint_quorum_size: 0,
        distinct_org_count: 0,
        distinct_asn_count: 0,
        broker_signature_valid: true,
        downgrade_reasons: [],
      };
    }
    if (brokerIdMatches) {
      reasons.push("BrokerNativeSignature failed verification against pinned broker keys");
    }
  }

  // 2. Dynamic k >= 2 org/ASN-disjoint TLSNotary witness quorum check
  const notaryMap = new Map((notaries || []).map((n) => [n.notary_id, n]));
  const pubKidNorm = bundle.publisher_kid.trim().toLowerCase();
  const pubKeyNorm = bundle.publisher_public_key_hex.toLowerCase();
  const pubOrgNorm = String(publisherOrg || "N170").trim().toLowerCase();

  const validBySni = new Map();
  let totalValid = 0;

  for (const att of bundle.witness_attestations) {
    const notary = notaryMap.get(att.notary_id);
    if (!notary) {
      reasons.push(`Notary '${att.notary_id}' is not present in trusted notary registry`);
      continue;
    }
    if (notary.is_debug_build || String(notary.attestation_type || "").trim().toLowerCase() === "debug") {
      reasons.push(`Notary '${att.notary_id}' uses a debug build/attestation`);
      continue;
    }
    if (pubKidNorm && notary.notary_id.trim().toLowerCase() === pubKidNorm) {
      reasons.push(`Notary '${att.notary_id}' shares key ID with bundle publisher`);
      continue;
    }
    if (pubKeyNorm && String(notary.public_key_hex).toLowerCase() === pubKeyNorm) {
      reasons.push(`Notary '${att.notary_id}' shares public key with bundle publisher`);
      continue;
    }
    if (pubOrgNorm && notary.operator_org.trim().toLowerCase() === pubOrgNorm) {
      reasons.push(`Notary '${att.notary_id}' is operated by publisher org ('${notary.operator_org}')`);
      continue;
    }
    if (att.response_body_sha256 !== normSourceSha) {
      reasons.push(`Notary '${att.notary_id}' response_body_sha256 does not match source_body_sha256`);
      continue;
    }
    const safety = inspectTranscriptSafety(att);
    if (!safety.ok) {
      reasons.push(...safety.violations);
      continue;
    }
    const attSignable = jcsCanonicalize({
      commitment_kind: att.commitment_kind,
      defer_decryption_from_start: att.defer_decryption_from_start,
      notary_id: att.notary_id,
      protocol: att.protocol,
      redacted_headers: att.redacted_headers,
      response_body_sha256: att.response_body_sha256,
      sanitized_request_target: att.sanitized_request_target,
      server_sni: att.server_sni,
      session_timestamp_utc: att.session_timestamp_utc,
      tls_version: att.tls_version,
    });
    const sigOk = await ed25519VerifyDomain(
      notary.public_key_hex,
      SIGNING_DOMAIN_WITNESS,
      attSignable,
      att.signature_hex
    );
    if (!sigOk) {
      reasons.push(`Notary '${att.notary_id}' Ed25519 signature verification failed`);
      continue;
    }

    const sniKey = String(att.server_sni || "")
      .trim()
      .toLowerCase()
      .replace(/\.+$/, "");
    const targetTrimmed = String(att.sanitized_request_target || "").trim();
    const targetLower = targetTrimmed.toLowerCase();
    if (targetLower.startsWith("http://") || targetLower.startsWith("https://")) {
      let parsedHost = "";
      try {
        parsedHost = new URL(targetTrimmed).hostname.trim().toLowerCase().replace(/\.+$/, "");
      } catch {
        parsedHost = "";
      }
      if (parsedHost !== sniKey) {
        reasons.push(
          `Notary '${att.notary_id}' sanitized_request_target host mismatches server_sni '${sniKey}'`
        );
        continue;
      }
    }
    if (bundleBrokerNorm) {
      const allowedSnis = BROKER_WITNESS_SNI_ALLOWLIST[bundleBrokerNorm];
      if (!allowedSnis || !allowedSnis.has(sniKey)) {
        reasons.push(
          `Notary '${att.notary_id}' server_sni '${sniKey}' is not an official TLS endpoint for broker_id='${bundle.broker_id}'`
        );
        continue;
      }
    }

    const tsMs = parseUtcTimestampMs(att.session_timestamp_utc, "session_timestamp_utc");
    if (!validBySni.has(sniKey)) {
      validBySni.set(sniKey, []);
    }
    validBySni.get(sniKey).push({ node: notary, tsMs });
    totalValid += 1;
  }

  let bestQuorum = 0;
  let bestOrgs = 0;
  let bestAsns = 0;
  for (const sniCands of validBySni.values()) {
    const q = maxMutuallyDisjointQuorum(sniCands, DEFAULT_MAX_WITNESS_SKEW_SECONDS);
    if (
      q.bestQuorum > bestQuorum ||
      (q.bestQuorum === bestQuorum && q.distinctOrgs > bestOrgs) ||
      (q.bestQuorum === bestQuorum && q.distinctOrgs === bestOrgs && q.distinctAsns > bestAsns)
    ) {
      bestQuorum = q.bestQuorum;
      bestOrgs = q.distinctOrgs;
      bestAsns = q.distinctAsns;
    }
  }

  if (bestQuorum >= 2) {
    return {
      effective_origin_assurance: "independently_witnessed_tls",
      valid_witness_count: totalValid,
      disjoint_quorum_size: bestQuorum,
      distinct_org_count: bestOrgs,
      distinct_asn_count: bestAsns,
      broker_signature_valid: false,
      downgrade_reasons: reasons,
    };
  }

  if (totalValid >= 1) {
    reasons.push(
      `Insufficient org/ASN-disjoint notary quorum (disjoint_quorum_size=${bestQuorum} < 2); downgraded to operator_retrieved`
    );
    return {
      effective_origin_assurance: "operator_retrieved",
      valid_witness_count: totalValid,
      disjoint_quorum_size: bestQuorum,
      distinct_org_count: bestOrgs,
      distinct_asn_count: bestAsns,
      broker_signature_valid: false,
      downgrade_reasons: reasons,
    };
  }

  if (
    bundle.provider_approval_state !== "offline_export_only" &&
    bundle.claimed_origin_assurance !== "self_reported"
  ) {
    if (
      bundle.claimed_origin_assurance === "independently_witnessed_tls" ||
      bundle.claimed_origin_assurance === "broker_signed"
    ) {
      reasons.push(
        `Claimed ${bundle.claimed_origin_assurance} without valid quorum/broker signature; downgraded to operator_retrieved`
      );
    }
    return {
      effective_origin_assurance: "operator_retrieved",
      valid_witness_count: 0,
      disjoint_quorum_size: 0,
      distinct_org_count: 0,
      distinct_asn_count: 0,
      broker_signature_valid: false,
      downgrade_reasons: reasons,
    };
  }

  if (bundle.claimed_origin_assurance && bundle.claimed_origin_assurance !== "self_reported") {
    reasons.push(
      `Offline export without valid witness quorum or broker signature; downgraded from ${bundle.claimed_origin_assurance} to self_reported`
    );
  }
  return {
    effective_origin_assurance: "self_reported",
    valid_witness_count: 0,
    disjoint_quorum_size: 0,
    distinct_org_count: 0,
    distinct_asn_count: 0,
    broker_signature_valid: false,
    downgrade_reasons: reasons,
  };
}

/* -------------------------------------------------------------------------- */
/* Bundle Normalization, Signable Header, & Prospective Chain Invariants      */
/* -------------------------------------------------------------------------- */

function normalizeWitnessAttestation(att) {
  return {
    protocol: String(att.protocol),
    tls_version: String(att.tls_version),
    defer_decryption_from_start: Boolean(att.defer_decryption_from_start),
    notary_id: String(att.notary_id),
    server_sni: String(att.server_sni),
    sanitized_request_target: String(att.sanitized_request_target),
    redacted_headers: Array.from(att.redacted_headers || [], String),
    commitment_kind: String(att.commitment_kind),
    response_body_sha256: validateHexDigest(att.response_body_sha256, "response_body_sha256", 32),
    session_timestamp_utc: String(att.session_timestamp_utc),
    signature_hex: validateHexDigest(att.signature_hex, "witness.signature_hex", 64),
  };
}

function normalizeBrokerSignature(sig) {
  if (sig === null || sig === undefined) {
    return null;
  }
  return {
    broker_id: String(sig.broker_id).trim().toLowerCase(),
    key_id: String(sig.key_id),
    algorithm: String(sig.algorithm),
    signed_payload_sha256: validateHexDigest(sig.signed_payload_sha256, "signed_payload_sha256", 32),
    signature_hex: validateHexDigest(sig.signature_hex, "broker_signature.signature_hex", 64),
  };
}

function normalizeChainLink(link) {
  if (link === null || link === undefined) {
    return null;
  }
  const seqNum = Number(link.sequence_number);
  if (!Number.isInteger(seqNum) || seqNum < 0) {
    throw new VerifyMcpError("invalid_bundle", "link.sequence_number must be an integer >= 0");
  }
  const expectedInterval = Number(link.cadence_policy?.expected_interval_seconds);
  const graceWindow = Number(link.cadence_policy?.grace_window_seconds);
  if (!Number.isInteger(expectedInterval) || expectedInterval <= 0) {
    throw new VerifyMcpError("invalid_bundle", "cadence_policy.expected_interval_seconds must be > 0");
  }
  if (!Number.isInteger(graceWindow) || graceWindow < 0) {
    throw new VerifyMcpError("invalid_bundle", "cadence_policy.grace_window_seconds must be >= 0");
  }
  const begIdx = normalizeFiniteNumber(link.beginning_index_value, "beginning_index_value");
  const endIdx = normalizeFiniteNumber(link.ending_index_value, "ending_index_value");
  if (begIdx <= 0 || endIdx <= 0) {
    throw new VerifyMcpError("invalid_bundle", "ProspectiveChainLink index values must be > 0");
  }
  return {
    chain_id: String(link.chain_id),
    sequence_number: seqNum,
    prev_proof_hash:
      link.prev_proof_hash === null || link.prev_proof_hash === undefined
        ? null
        : validateHexDigest(link.prev_proof_hash, "prev_proof_hash", 32),
    blinded_account_tag: validateHexDigest(link.blinded_account_tag, "link.blinded_account_tag", 32),
    enrolled_at_utc: String(link.enrolled_at_utc),
    period_start_utc: String(link.period_start_utc),
    period_end_utc: String(link.period_end_utc),
    issued_at_utc: String(link.issued_at_utc),
    cadence_policy: {
      expected_interval_seconds: expectedInterval,
      grace_window_seconds: graceWindow,
    },
    beginning_index_value: begIdx,
    ending_index_value: endIdx,
    period_twr_decimal: normalizeFiniteNumber(link.period_twr_decimal, "period_twr_decimal"),
  };
}

function normalizeBundle(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new VerifyMcpError("invalid_bundle", "bundle must be a JSON object");
  }
  const undisclosed = {};
  for (const [k, v] of Object.entries(raw.undisclosed_leaf_hashes || {})) {
    undisclosed[k] = validateHexDigest(v, `undisclosed_leaf_hashes[${k}]`, 32);
  }
  return {
    proof_id: String(raw.proof_id || "").trim(),
    schema_version: String(raw.schema_version || VERIFY_SCHEMA_VERSION).trim(),
    issued_at_utc: String(raw.issued_at_utc || "").trim(),
    publisher_kid: String(raw.publisher_kid || "").trim(),
    publisher_public_key_hex: validateHexDigest(
      raw.publisher_public_key_hex,
      "publisher_public_key_hex",
      32
    ),
    broker_id: String(raw.broker_id || "").trim().toLowerCase(),
    blinded_account_tag: validateHexDigest(raw.blinded_account_tag, "blinded_account_tag", 32),
    account_scope: String(raw.account_scope || ""),
    provider_approval_state: String(raw.provider_approval_state || ""),
    environment_tier: String(raw.environment_tier || ""),
    claimed_origin_assurance: String(raw.claimed_origin_assurance || ""),
    source_body_sha256: validateHexDigest(raw.source_body_sha256, "source_body_sha256", 32),
    period_start_utc: String(raw.period_start_utc || "").trim(),
    period_end_utc: String(raw.period_end_utc || "").trim(),
    base_currency: String(raw.base_currency || "").trim().toUpperCase(),
    merkle_root: validateHexDigest(raw.merkle_root, "merkle_root", 32),
    disclosed_leaves: Array.isArray(raw.disclosed_leaves) ? raw.disclosed_leaves : [],
    undisclosed_leaf_hashes: undisclosed,
    witness_attestations: Array.from(raw.witness_attestations || [], normalizeWitnessAttestation),
    broker_native_signature: normalizeBrokerSignature(raw.broker_native_signature),
    prospective_chain_link: normalizeChainLink(raw.prospective_chain_link),
    retention_mode: (() => {
      const mode = String(
        raw.retention_mode === undefined || raw.retention_mode === null
          ? "no_persistent_storage"
          : raw.retention_mode
      )
        .trim()
        .toLowerCase();
      if (mode !== "no_persistent_storage" && mode !== "opt_in_encrypted_sync") {
        throw new Error(`Unsupported retention_mode: ${String(raw.retention_mode)}`);
      }
      return mode;
    })(),
    signature_hex: validateHexDigest(raw.signature_hex, "signature_hex", 64),
  };
}

function buildSignableHeader(bundle) {
  return {
    account_scope: bundle.account_scope,
    base_currency: bundle.base_currency,
    blinded_account_tag: bundle.blinded_account_tag,
    broker_id: bundle.broker_id,
    broker_native_signature: bundle.broker_native_signature,
    claimed_origin_assurance: bundle.claimed_origin_assurance,
    environment_tier: bundle.environment_tier,
    issued_at_utc: bundle.issued_at_utc,
    merkle_root: bundle.merkle_root,
    period_end_utc: bundle.period_end_utc,
    period_start_utc: bundle.period_start_utc,
    proof_id: bundle.proof_id,
    prospective_chain_link: bundle.prospective_chain_link,
    provider_approval_state: bundle.provider_approval_state,
    publisher_kid: bundle.publisher_kid,
    publisher_public_key_hex: bundle.publisher_public_key_hex,
    retention_mode: bundle.retention_mode,
    schema_version: bundle.schema_version,
    source_body_sha256: bundle.source_body_sha256,
    witness_attestations: bundle.witness_attestations,
  };
}

function verifyProspectiveChain(bundles, continuityLogLeaves, nowUtc) {
  const violations = [];
  const details = [];
  const record = (code, msg) => {
    if (!violations.includes(code)) {
      violations.push(code);
    }
    details.push(msg);
  };

  const links = [];
  const elemHashes = [];
  for (let i = 0; i < bundles.length; i += 1) {
    const b = bundles[i];
    const link = b.prospective_chain_link;
    if (!link) {
      record("non_monotonic_sequence", `Element ${i} in multi-element chain is missing prospective_chain_link`);
      return {
        valid: false,
        continuity_mode: "continuity_broken",
        verified_length: i,
        violation_codes: violations,
        details,
      };
    }
    if (b.blinded_account_tag !== link.blinded_account_tag) {
      record(
        "account_continuity_violation",
        `Element ${i} bundle blinded_account_tag mismatches chain link blinded_account_tag`
      );
    }
    links.push(link);
    elemHashes.push(jcsSha256Hex(buildSignableHeader(b)));
  }

  const genesis = links[0];
  if (genesis.sequence_number !== 0) {
    record("non_monotonic_sequence", `Genesis link sequence_number must be 0 (got ${genesis.sequence_number})`);
  }
  if (genesis.prev_proof_hash !== null) {
    record("prev_hash_mismatch", "Genesis link prev_proof_hash must be None");
  }

  const gEnrolled = parseUtcTimestampMs(genesis.enrolled_at_utc);
  const gStart = parseUtcTimestampMs(genesis.period_start_utc);
  const gEnd = parseUtcTimestampMs(genesis.period_end_utc);
  const gIssued = parseUtcTimestampMs(genesis.issued_at_utc);

  if (gEnd <= gStart) {
    record("missed_interval_detected", "Genesis period_end_utc must be strictly after period_start_utc");
  }
  if (gIssued < gEnd) {
    record("missed_interval_detected", "Genesis issued_at_utc cannot precede period_end_utc");
  }

  const enrollDeltaSec = Math.abs(gEnrolled - gStart) / 1000;
  const issueLagSec = (gIssued - gEnd) / 1000;
  if (
    enrollDeltaSec > GENESIS_ENROLLMENT_WINDOW_SECONDS ||
    issueLagSec > genesis.cadence_policy.grace_window_seconds
  ) {
    record(
      "genesis_backfill_window_exceeded",
      "Genesis enrollment delta or issuance lag exceeds prospective window; classified as retrospective backfill"
    );
  }

  let structuralBroken = violations.some((c) => c !== "genesis_backfill_window_exceeded");
  const expectedEnd0 = genesis.beginning_index_value * (1 + genesis.period_twr_decimal);
  if (Math.abs(genesis.ending_index_value - expectedEnd0) > INDEX_CONTINUITY_TOLERANCE) {
    record("missed_interval_detected", "Genesis ending_index_value inconsistent with period_twr_decimal");
    structuralBroken = true;
  }

  let intactPrefix = structuralBroken ? 0 : 1;

  for (let i = 1; i < links.length; i += 1) {
    const prev = links[i - 1];
    const curr = links[i];
    let linkOk = true;

    if (curr.sequence_number !== prev.sequence_number + 1) {
      record("non_monotonic_sequence", `Link ${i} non-monotonic sequence_number`);
      linkOk = false;
    }
    if (curr.prev_proof_hash !== elemHashes[i - 1] || curr.chain_id !== genesis.chain_id) {
      record("prev_hash_mismatch", `Link ${i} prev_proof_hash or chain_id mismatch`);
      linkOk = false;
    }
    if (
      curr.cadence_policy.expected_interval_seconds !== genesis.cadence_policy.expected_interval_seconds ||
      curr.cadence_policy.grace_window_seconds !== genesis.cadence_policy.grace_window_seconds
    ) {
      record("cadence_policy_mutated", `Link ${i} mutated cadence_policy`);
      linkOk = false;
    }
    if (curr.blinded_account_tag !== genesis.blinded_account_tag) {
      record("account_continuity_violation", `Link ${i} blinded_account_tag switched mid-chain`);
      linkOk = false;
    }

    const prevEnd = parseUtcTimestampMs(prev.period_end_utc);
    const currStart = parseUtcTimestampMs(curr.period_start_utc);
    const currEnd = parseUtcTimestampMs(curr.period_end_utc);
    const currIssued = parseUtcTimestampMs(curr.issued_at_utc);
    const currLagSec = (currIssued - currEnd) / 1000;

    if (currStart !== prevEnd || currEnd <= currStart) {
      record("missed_interval_detected", `Link ${i} period boundary gap or overlap`);
      linkOk = false;
    }
    if (currLagSec < 0 || currLagSec > genesis.cadence_policy.grace_window_seconds) {
      record("missed_interval_detected", `Link ${i} issued_at_utc outside grace window`);
      linkOk = false;
    }
    if (Math.abs(curr.beginning_index_value - prev.ending_index_value) > INDEX_CONTINUITY_TOLERANCE) {
      record("missed_interval_detected", `Link ${i} beginning_index_value discontinuous`);
      linkOk = false;
    }
    const expEnd = curr.beginning_index_value * (1 + curr.period_twr_decimal);
    if (Math.abs(curr.ending_index_value - expEnd) > INDEX_CONTINUITY_TOLERANCE) {
      record("missed_interval_detected", `Link ${i} ending_index_value inconsistent with period_twr_decimal`);
      linkOk = false;
    }

    if (!linkOk) {
      structuralBroken = true;
    } else if (!structuralBroken) {
      intactPrefix += 1;
    }
  }

  if (Array.isArray(continuityLogLeaves)) {
    const acctLeaves = continuityLogLeaves.filter(
      (l) => String(l.blinded_account_tag || "").toLowerCase() === genesis.blinded_account_tag
    );
    if (acctLeaves.filter((l) => l.sequence_number === 0).length > 1) {
      record("parallel_chain_reset_detected", "Multiple sequence_number == 0 entries in continuity log");
      structuralBroken = true;
    }
    const distinctChains = new Set(acctLeaves.map((l) => l.chain_id));
    if (distinctChains.size > 0 && (distinctChains.size > 1 || !distinctChains.has(genesis.chain_id))) {
      record("parallel_chain_reset_detected", "Conflicting chain_id in continuity log");
      structuralBroken = true;
    }
    const loggedBySeq = new Map();
    for (const l of acctLeaves) {
      const pHash = String(l.proof_hash || "").toLowerCase();
      if (loggedBySeq.has(l.sequence_number) && loggedBySeq.get(l.sequence_number) !== pHash) {
        record("parallel_chain_reset_detected", "Conflicting proof_hash in continuity log");
        structuralBroken = true;
      }
      loggedBySeq.set(l.sequence_number, pHash);
    }
    for (let i = 0; i < links.length; i += 1) {
      const logged = loggedBySeq.get(links[i].sequence_number);
      if (logged && logged !== elemHashes[i]) {
        record("parallel_chain_reset_detected", "Presented proof hash conflicts with continuity log");
        structuralBroken = true;
      }
    }
    const maxSeq = links[links.length - 1].sequence_number;
    if (acctLeaves.some((l) => l.sequence_number > maxSeq)) {
      record("stale_or_truncated_tail", "Continuity log contains newer sequence_number omitted from tail");
      structuralBroken = true;
    }
  }

  if (nowUtc) {
    const nowMs = parseUtcTimestampMs(nowUtc, "now_utc");
    const last = links[links.length - 1];
    const lastEndMs = parseUtcTimestampMs(last.period_end_utc);
    const deadlineMs =
      lastEndMs +
      (last.cadence_policy.expected_interval_seconds + last.cadence_policy.grace_window_seconds) * 1000;
    if (nowMs > deadlineMs) {
      record("stale_or_truncated_tail", "Chain tail is stale at now_utc");
      structuralBroken = true;
    }
  }

  const mode = structuralBroken
    ? "continuity_broken"
    : violations.includes("genesis_backfill_window_exceeded")
      ? "retrospective_backfill"
      : "prospective_continuous";

  return {
    valid: violations.length === 0,
    continuity_mode: mode,
    verified_length: intactPrefix,
    violation_codes: violations,
    details,
  };
}

async function verifyProofBundle(
  rawBundle,
  {
    registryDoc = null,
    registryTrusted = true,
    chainHistory = null,
    continuityLogLeaves = null,
    nowUtc = null,
  } = {}
) {
  const bundle = normalizeBundle(rawBundle);
  const errors = [];
  const warnings = [];

  const schemaOk = bundle.schema_version === VERIFY_SCHEMA_VERSION;
  if (!schemaOk) {
    errors.push(
      `Unsupported schema_version '${bundle.schema_version}'; expected '${VERIFY_SCHEMA_VERSION}'`
    );
  }

  const envOk = bundle.environment_tier === "live_production";
  if (!envOk) {
    errors.push("Bundle environment_tier is paper_or_sandbox_rejected");
  }

  const signableHeader = buildSignableHeader(bundle);
  const signableBytes = jcsCanonicalize(signableHeader);
  const proofHash = sha256Hex(signableBytes);

  const signatureValid = await ed25519VerifyDomain(
    bundle.publisher_public_key_hex,
    SIGNING_DOMAIN_BUNDLE,
    signableBytes,
    bundle.signature_hex
  );
  if (!signatureValid) {
    errors.push("Publisher Ed25519 signature verification failed");
  }

  const merkleCheck = verifySelectiveDisclosure(
    bundle.merkle_root,
    bundle.disclosed_leaves,
    bundle.undisclosed_leaf_hashes
  );
  if (!merkleCheck.valid) {
    errors.push(...merkleCheck.errors);
  }

  let transcriptSafetyOk = true;
  for (const att of bundle.witness_attestations) {
    const safe = inspectTranscriptSafety(att);
    if (!safe.ok) {
      transcriptSafetyOk = false;
      errors.push(...safe.violations);
    }
  }

  const signerTrust = await evaluateSignerTrust(
    bundle,
    signatureValid,
    registryDoc,
    registryTrusted
  );
  if (signerTrust === "revoked_key") {
    errors.push(`Publisher signing key '${bundle.publisher_kid}' is revoked`);
  }

  let publisherOrg = "N170";
  let notaries = [];
  let pinnedBrokerKeys = null;
  if (!registryTrusted) {
    notaries = [];
    pinnedBrokerKeys = null;
    if (registryDoc && typeof registryDoc === "object") {
      warnings.push(
        "Caller-supplied registry_doc is untrusted; configure N170_VERIFY_API_URL or host defaultRegistryDoc for official signer/notary trust"
      );
    }
  } else if (registryDoc && typeof registryDoc === "object") {
    notaries = Array.isArray(registryDoc.notaries) ? registryDoc.notaries : [];
    pinnedBrokerKeys = registryDoc.pinned_broker_keys || null;
    for (const rec of registryDoc.keys || []) {
      if (rec.publisher_kid === bundle.publisher_kid && rec.issuer_org) {
        publisherOrg = rec.issuer_org;
        break;
      }
    }
  }

  const witnessQuorum = await evaluateOriginAssurance({
    bundle,
    signerTrust,
    publisherOrg,
    notaries,
    pinnedBrokerKeys,
  });
  const effectiveOrigin = witnessQuorum.effective_origin_assurance;
  if (effectiveOrigin !== bundle.claimed_origin_assurance) {
    warnings.push(
      `Origin assurance dynamically evaluated as ${effectiveOrigin} (bundle claimed ${bundle.claimed_origin_assurance})`
    );
    warnings.push(...witnessQuorum.downgrade_reasons);
  }

  let chainVerification = null;
  let continuityMode = "unenrolled_single_snapshot";
  if (!bundle.prospective_chain_link && (!chainHistory || chainHistory.length === 0)) {
    if (Array.isArray(continuityLogLeaves) && continuityLogLeaves.length > 0) {
      const enrolled = continuityLogLeaves.some(
        (l) => String(l.blinded_account_tag || "").toLowerCase() === bundle.blinded_account_tag
      );
      if (enrolled) {
        continuityMode = "continuity_broken";
        errors.push(
          "Account has enrolled continuity log entries but presented an unenrolled snapshot"
        );
      }
    }
  } else {
    const historyBundles = Array.from(chainHistory || [], normalizeBundle);
    if (historyBundles.length === 0 || historyBundles[historyBundles.length - 1].proof_id !== bundle.proof_id) {
      historyBundles.push(bundle);
    }
    chainVerification = verifyProspectiveChain(historyBundles, continuityLogLeaves, nowUtc);
    continuityMode = chainVerification.continuity_mode;
    if (continuityMode === "continuity_broken") {
      errors.push(...chainVerification.details);
    } else if (continuityMode === "retrospective_backfill") {
      warnings.push(...chainVerification.details);
    }
  }

  const valid =
    schemaOk &&
    envOk &&
    signatureValid &&
    merkleCheck.valid &&
    transcriptSafetyOk &&
    signerTrust !== "revoked_key" &&
    continuityMode !== "continuity_broken";

  const assuranceProfile = {
    effective_origin_assurance: effectiveOrigin,
    account_scope: bundle.account_scope,
    provider_approval_state: bundle.provider_approval_state,
    environment_tier: bundle.environment_tier,
    signer_trust_status: signerTrust,
    chain_continuity_mode: continuityMode,
  };

  return {
    valid,
    proof_id: bundle.proof_id,
    proof_hash: proofHash,
    signature_valid: signatureValid,
    merkle_valid: merkleCheck.valid,
    transcript_safety_ok: transcriptSafetyOk,
    signer_trust_status: signerTrust,
    effective_origin_assurance: effectiveOrigin,
    effective_chain_continuity_mode: continuityMode,
    assurance_profile: assuranceProfile,
    disclosed_leaf_names: bundle.disclosed_leaves.map((l) => l.leaf_name),
    undisclosed_leaf_names: Object.keys(bundle.undisclosed_leaf_hashes).sort(),
    witness_quorum: witnessQuorum,
    chain_verification: chainVerification,
    errors: [...new Set(errors)],
    warnings: [...new Set(warnings)],
  };
}

/* -------------------------------------------------------------------------- */
/* MCP Tool Definitions, Argument Guardrails, & JSON-RPC 2.0 Server           */
/* -------------------------------------------------------------------------- */

const READ_ONLY_ANNOTATIONS = Object.freeze({
  readOnlyHint: true,
  destructiveHint: false,
  openWorldHint: false,
});

const TOOLS = Object.freeze([
  Object.freeze({
    name: "n170_verify_capabilities",
    description:
      "Return N170 Verify v3 cryptographic verification capabilities, supported leaf names, hard-disabled mutating/credential actions, and the LLM transcript-privacy notice.",
    inputSchema: Object.freeze({
      type: "object",
      additionalProperties: false,
      properties: Object.freeze({}),
    }),
    annotations: READ_ONLY_ANNOTATIONS,
  }),
  Object.freeze({
    name: "n170_verify_check_bundle",
    description:
      "Cryptographically verify a selectively disclosed VerifyProofBundle v3 offline using WebCrypto Ed25519, RFC 8785 JCS, salted 7-leaf Merkle audit paths, C2SP registry trust, and dynamic k>=2 org/ASN-disjoint TLS witness quorum.",
    inputSchema: Object.freeze({
      type: "object",
      additionalProperties: false,
      required: Object.freeze(["bundle"]),
      properties: Object.freeze({
        bundle: Object.freeze({ type: "object" }),
        registry_doc: Object.freeze({ type: "object" }),
        chain_history: Object.freeze({ type: "array", items: Object.freeze({ type: "object" }) }),
        continuity_log_leaves: Object.freeze({
          type: "array",
          items: Object.freeze({ type: "object" }),
        }),
        now_utc: Object.freeze({ type: "string" }),
      }),
    }),
    annotations: READ_ONLY_ANNOTATIONS,
  }),
  Object.freeze({
    name: "n170_verify_inspect_public_proof",
    description:
      "Verify and extract selectively disclosed leaf payloads and six-axis assurance metadata from a public VerifyProofBundle or resolved public proof_id without accepting credentials or filesystem paths.",
    inputSchema: Object.freeze({
      type: "object",
      additionalProperties: false,
      properties: Object.freeze({
        bundle: Object.freeze({ type: "object" }),
        proof_id: Object.freeze({
          type: "string",
          pattern: "^[A-Za-z0-9._:-]{1,128}$",
        }),
        registry_doc: Object.freeze({ type: "object" }),
        leaf_names: Object.freeze({
          type: "array",
          items: Object.freeze({
            type: "string",
            enum: CANONICAL_LEAF_NAMES,
          }),
        }),
      }),
    }),
    annotations: READ_ONLY_ANNOTATIONS,
  }),
]);

function assertNoCredentialsOrPaths(val, pathLabel = "arguments", depth = 0) {
  if (depth > 24 || val === null || val === undefined || typeof val !== "object") {
    if (typeof val === "string" && pathLabel === "arguments.proof_id") {
      if (PATH_OR_URL_VALUE_RE.test(val.trim())) {
        throw new VerifyMcpError(
          "forbidden_argument",
          `Filesystem path or URL rejected in ${pathLabel}`
        );
      }
    }
    return;
  }
  if (Array.isArray(val)) {
    for (let i = 0; i < val.length; i += 1) {
      assertNoCredentialsOrPaths(val[i], `${pathLabel}[${i}]`, depth + 1);
    }
    return;
  }
  for (const [k, v] of Object.entries(val)) {
    const normK = k.trim().toLowerCase().replace(/[^a-z0-9]+/g, "_");
    if (FORBIDDEN_TOP_OR_NESTED_CREDENTIAL_KEYS.has(normK)) {
      throw new VerifyMcpError(
        "forbidden_argument",
        `Credential or filesystem path field '${k}' is strictly prohibited in n170-verify-mcp`
      );
    }
    if (depth === 0 && typeof v === "string" && PATH_OR_URL_VALUE_RE.test(v.trim())) {
      throw new VerifyMcpError(
        "forbidden_argument",
        `Filesystem path or URL rejected in ${pathLabel}.${k}`
      );
    }
    assertNoCredentialsOrPaths(v, `${pathLabel}.${k}`, depth + 1);
  }
}

function assertAllowedTopKeys(args, allowedKeys) {
  if (args === undefined || args === null) {
    return {};
  }
  if (typeof args !== "object" || Array.isArray(args)) {
    throw new VerifyMcpError("invalid_arguments", "Tool arguments must be a JSON object");
  }
  assertNoCredentialsOrPaths(args);
  const allowed = new Set(allowedKeys);
  const unknown = Object.keys(args).filter((k) => !allowed.has(k));
  if (unknown.length > 0) {
    throw new VerifyMcpError(
      "invalid_arguments",
      `Unexpected argument(s) rejected by additionalProperties=false: ${unknown.join(", ")}`
    );
  }
  return args;
}

async function fetchJsonFromPinnedApi(url, fetchImpl, resourceLabel) {
  if (typeof fetchImpl !== "function") {
    throw new VerifyMcpError(
      "offline_resolver_unavailable",
      `No fetch implementation available to resolve ${resourceLabel}`
    );
  }
  let response;
  try {
    response = await fetchImpl(url, {
      method: "GET",
      headers: { Accept: "application/json" },
    });
  } catch (err) {
    throw new VerifyMcpError(
      "upstream_api_unreachable",
      `Failed to fetch ${resourceLabel} from pinned N170 Verify API: ${
        err instanceof Error ? err.message : String(err)
      }`
    );
  }
  if (!response || !response.ok) {
    const status = response ? response.status : "unknown";
    throw new VerifyMcpError(
      status === 404 ? "proof_not_found" : "upstream_api_error",
      `Pinned N170 Verify API returned HTTP ${status} for ${resourceLabel}`
    );
  }
  const parsed = await response.json();
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new VerifyMcpError(
      "upstream_api_error",
      `Pinned N170 Verify API returned invalid JSON object for ${resourceLabel}`
    );
  }
  return parsed;
}

function trimTrailingSlashes(value) {
  const trimmed = String(value || "").trim();
  let end = trimmed.length;
  while (end > 0 && trimmed.charCodeAt(end - 1) === 47) {
    end -= 1;
  }
  return trimmed.slice(0, end);
}

async function resolveMcpToolRegistry(callerRegistryDoc, options = {}) {
  const pinnedDoc = options.trustedRegistryDoc || options.defaultRegistryDoc || null;
  const apiBaseUrl = trimTrailingSlashes(
    options.apiBaseUrl || process.env.N170_VERIFY_API_URL || ""
  );

  if (pinnedDoc || apiBaseUrl) {
    const extraWarnings = callerRegistryDoc
      ? ["Ignored caller-supplied registry_doc because a pinned N170 Verify registry is configured"]
      : [];
    if (pinnedDoc) {
      return { registryDoc: pinnedDoc, registryTrusted: true, extraWarnings };
    }
    const fetchImpl = options.fetchImpl || globalThis.fetch;
    const fetchedDoc = await fetchJsonFromPinnedApi(
      `${apiBaseUrl}/.well-known/n170-verify-keys.json`,
      fetchImpl,
      "/.well-known/n170-verify-keys.json"
    );
    return { registryDoc: fetchedDoc, registryTrusted: true, extraWarnings };
  }

  if (callerRegistryDoc) {
    return { registryDoc: callerRegistryDoc, registryTrusted: false, extraWarnings: [] };
  }
  return { registryDoc: null, registryTrusted: true, extraWarnings: [] };
}

async function executeVerifyTool(name, rawArgs, options = {}) {
  if (name === "n170_verify_capabilities") {
    assertAllowedTopKeys(rawArgs, []);
    return {
      server: SERVER_NAME,
      version: SERVER_VERSION,
      schema_version: VERIFY_SCHEMA_VERSION,
      canonical_leaf_names: CANONICAL_LEAF_NAMES,
      cryptography: {
        canonicalization: "RFC 8785 JCS",
        signatures: "WebCrypto Ed25519 (domain-separated)",
        merkle_disclosure: "Salted 256-bit 7-leaf Merkle tree (0x00 leaf / 0x01 node)",
        witness_quorum: "Dynamic k >= 2 org- and ASN-disjoint TLSNotary v0.1.0-alpha.15",
      },
      hard_disabled_actions: {
        broker_credentials_accepted: false,
        filesystem_paths_accepted: false,
        arbitrary_urls_accepted: false,
        order_execution: false,
        fund_transfers_or_withdrawals: false,
      },
      transcript_privacy_notice: TRANSCRIPT_PRIVACY_NOTICE,
    };
  }

  if (name === "n170_verify_check_bundle") {
    const args = assertAllowedTopKeys(rawArgs, [
      "bundle",
      "registry_doc",
      "chain_history",
      "continuity_log_leaves",
      "now_utc",
    ]);
    if (!args.bundle || typeof args.bundle !== "object" || Array.isArray(args.bundle)) {
      throw new VerifyMcpError("invalid_arguments", "n170_verify_check_bundle requires bundle object");
    }
    const { registryDoc: resolvedRegistry, registryTrusted, extraWarnings } =
      await resolveMcpToolRegistry(args.registry_doc, options);
    const result = await verifyProofBundle(args.bundle, {
      registryDoc: resolvedRegistry,
      registryTrusted,
      chainHistory: args.chain_history || null,
      continuityLogLeaves: args.continuity_log_leaves || null,
      nowUtc: args.now_utc || null,
    });
    const mergedWarnings = [...new Set([...extraWarnings, ...result.warnings])];
    return {
      ...result,
      warnings: mergedWarnings,
      transcript_privacy_notice: TRANSCRIPT_PRIVACY_NOTICE,
    };
  }

  if (name === "n170_verify_inspect_public_proof") {
    const args = assertAllowedTopKeys(rawArgs, [
      "bundle",
      "proof_id",
      "registry_doc",
      "leaf_names",
    ]);
    let targetBundle = args.bundle || null;
    if (!targetBundle) {
      if (!args.proof_id || typeof args.proof_id !== "string") {
        throw new VerifyMcpError(
          "invalid_arguments",
          "Provide either 'bundle' or a valid alphanumeric 'proof_id'"
        );
      }
      if (!/^[A-Za-z0-9._:-]{1,128}$/.test(args.proof_id)) {
        throw new VerifyMcpError("invalid_arguments", "proof_id violates allowed identifier pattern");
      }
      const apiBaseUrl = trimTrailingSlashes(
        options.apiBaseUrl || process.env.N170_VERIFY_API_URL || ""
      );
      if (typeof options.publicProofResolver === "function") {
        targetBundle = await options.publicProofResolver(args.proof_id);
      } else if (apiBaseUrl) {
        const fetchImpl = options.fetchImpl || globalThis.fetch;
        const apiPayload = await fetchJsonFromPinnedApi(
          `${apiBaseUrl}/api/v1/proofs/${encodeURIComponent(args.proof_id)}`,
          fetchImpl,
          `/api/v1/proofs/${args.proof_id}`
        );
        targetBundle =
          apiPayload.proof_bundle && typeof apiPayload.proof_bundle === "object"
            ? apiPayload.proof_bundle
            : apiPayload;
      } else {
        throw new VerifyMcpError(
          "offline_resolver_unavailable",
          "Offline mode active: pass a VerifyProofBundle object directly in 'bundle', configure N170_VERIFY_API_URL, or provide a pinned publicProofResolver"
        );
      }
    }

    let requestedLeaves = null;
    if (args.leaf_names !== undefined) {
      if (!Array.isArray(args.leaf_names)) {
        throw new VerifyMcpError("invalid_arguments", "leaf_names must be an array");
      }
      const allowedSet = new Set(CANONICAL_LEAF_NAMES);
      for (const ln of args.leaf_names) {
        if (!allowedSet.has(ln)) {
          throw new VerifyMcpError("invalid_arguments", `Unknown canonical leaf name: '${ln}'`);
        }
      }
      requestedLeaves = new Set(args.leaf_names);
    }

    const { registryDoc: resolvedRegistry, registryTrusted, extraWarnings } =
      await resolveMcpToolRegistry(args.registry_doc, options);
    const verification = await verifyProofBundle(targetBundle, {
      registryDoc: resolvedRegistry,
      registryTrusted,
    });
    verification.warnings = [...new Set([...extraWarnings, ...verification.warnings])];
    const normalized = normalizeBundle(targetBundle);
    const disclosedPayloads = {};
    for (const leaf of normalized.disclosed_leaves) {
      if (!requestedLeaves || requestedLeaves.has(leaf.leaf_name)) {
        disclosedPayloads[leaf.leaf_name] = leaf.payload;
      }
    }

    return {
      valid: verification.valid,
      proof_id: verification.proof_id,
      proof_hash: verification.proof_hash,
      broker_id: normalized.broker_id,
      period_start_utc: normalized.period_start_utc,
      period_end_utc: normalized.period_end_utc,
      base_currency: normalized.base_currency,
      assurance_profile: verification.assurance_profile,
      disclosed_payloads: disclosedPayloads,
      undisclosed_leaf_names: verification.undisclosed_leaf_names,
      errors: verification.errors,
      warnings: verification.warnings,
      transcript_privacy_notice: TRANSCRIPT_PRIVACY_NOTICE,
    };
  }

  throw new VerifyMcpError("unknown_tool", `Unknown MCP tool '${name}'`);
}

async function handleJsonRpcMessage(message, options = {}) {
  if (!message || typeof message !== "object" || Array.isArray(message) || message.jsonrpc !== "2.0") {
    return {
      jsonrpc: "2.0",
      id: message && message.id !== undefined ? message.id : null,
      error: { code: -32600, message: "Invalid JSON-RPC 2.0 request object" },
    };
  }

  const { id, method, params } = message;
  const isNotification = id === undefined;

  if (method === "notifications/initialized") {
    return null;
  }
  if (method === "ping") {
    return isNotification ? null : { jsonrpc: "2.0", id, result: {} };
  }
  if (method === "initialize") {
    const reqProto =
      params && typeof params.protocolVersion === "string" && SUPPORTED_MCP_VERSIONS.has(params.protocolVersion)
        ? params.protocolVersion
        : MCP_PROTOCOL_VERSION;
    return {
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: reqProto,
        capabilities: { tools: {} },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
        instructions: TRANSCRIPT_PRIVACY_NOTICE,
      },
    };
  }
  if (method === "tools/list") {
    return {
      jsonrpc: "2.0",
      id,
      result: { tools: TOOLS },
    };
  }
  if (method === "tools/call") {
    if (!params || typeof params !== "object" || typeof params.name !== "string") {
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32602, message: "tools/call requires params.name" },
      };
    }
    try {
      const payload = await executeVerifyTool(params.name, params.arguments, options);
      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: JSON.stringify(payload) }],
          isError: false,
        },
      };
    } catch (err) {
      const errBody = {
        ok: false,
        error: {
          code: err instanceof VerifyMcpError ? err.code : "verification_error",
          message: err instanceof Error ? err.message : "Unexpected verification failure",
        },
        transcript_privacy_notice: TRANSCRIPT_PRIVACY_NOTICE,
      };
      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: JSON.stringify(errBody) }],
          isError: true,
        },
      };
    }
  }

  if (isNotification) {
    return null;
  }
  return {
    jsonrpc: "2.0",
    id,
    error: { code: -32601, message: `Method '${method}' is not supported by ${SERVER_NAME}` },
  };
}

function startStdioServer(options = {}) {
  const input = options.input || process.stdin;
  const output = options.output || process.stdout;
  const rl = readline.createInterface({ input, crlfDelay: Infinity });

  rl.on("line", async (line) => {
    const trimmed = line.trim();
    if (!trimmed) {
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      output.write(
        `${JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Parse error" },
        })}\n`
      );
      return;
    }
    const response = await handleJsonRpcMessage(parsed, options);
    if (response !== null) {
      output.write(`${JSON.stringify(response)}\n`);
    }
  });

  return rl;
}

if (require.main === module) {
  startStdioServer();
}

module.exports = {
  BROKER_WITNESS_SNI_ALLOWLIST,
  CANONICAL_LEAF_NAMES,
  LEAF_DOMAIN_PREFIX,
  MCP_PROTOCOL_VERSION,
  NODE_DOMAIN_PREFIX,
  SERVER_NAME,
  SERVER_VERSION,
  SIGNING_DOMAIN_BROKER,
  SIGNING_DOMAIN_BUNDLE,
  SIGNING_DOMAIN_CHECKPOINT,
  SIGNING_DOMAIN_WITNESS,
  TOOLS,
  TRANSCRIPT_PRIVACY_NOTICE,
  VERIFY_SCHEMA_VERSION,
  VerifyMcpError,
  buildSignableHeader,
  computeInternalNodeHash,
  computeMerkleRootFromLeafHashes,
  computeSaltedLeafHash,
  ed25519VerifyDomain,
  executeVerifyTool,
  handleJsonRpcMessage,
  inspectTranscriptSafety,
  jcsCanonicalize,
  jcsCanonicalizeStr,
  jcsSha256Hex,
  startStdioServer,
  verifyProofBundle,
  verifySelectiveDisclosure,
};
