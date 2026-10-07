import { buildStampObservationEvidence, calculateRecordMetrics, calculateRecordMetricsV2, RETURN_UNITS, sampleInput } from "./calculator.js";
import { formatKeyCode, importVerificationKey, isPublicKeyText, isSignatureText, keyIdFromPublicKey, sha256Hex, verifySignature } from "./signing.js";

export const PROFILE_SCHEMA = "n170.verify.track-record.v4";
export const LEGACY_PROFILE_SCHEMA = "n170.verify.track-record.v3";
export const STAMP_SCHEMA = "n170.verify.performance-stamp.v4";
const LEGACY_STAMP_SCHEMA = "n170.verify.performance-stamp.v3";
export const MAX_PROFILE_CHARACTERS = 500000;
export const MAX_PROFILE_STAMPS = 120;
export const MAX_COMMITMENT_LINES = 120;
export const MAX_COMMITMENT_CHARACTERS = 20000;

const signatureDomain = (payload) => new TextEncoder().encode(`n170.verify.stamp-signature.${payload.schema_version === STAMP_SCHEMA ? "v4" : "v3"}\n`);
const BACKSLASH = String.fromCharCode(92);
const JSON_WHITESPACE = new Set([9, 10, 13, 32]);
const NUMBER_CHARACTERS = "0123456789+-.eE";
const DAY_MS = 86400000;

const INVALID = "Profile format is invalid or unsupported.";
const REPEATED_FIELD = "Profile file repeats a field name, so different programs could read different values from it.";
const SIZE = "Use a profile of at most 500,000 characters and 120 records.";
const ORDER = "Track-record sequence or period order is invalid.";
const METRICS = "Stored performance does not match the disclosed return series.";
const HASH = "Record integrity check failed.";
const KEY = "The profile ID does not match its public key.";
const SIGNATURE = "A record signature is invalid: the record was changed after signing, or signed with a different key.";
const NO_KEY = "This browser doesn't hold the signing key for this profile.";
const OPTIONS = "Inspection options are invalid.";
const KEY_CODE_FORMAT = "Enter the key code as five groups of four letters or digits (for example 1a2b-3c4d-5e6f-7a8b-9c0d), or leave it blank.";
const KEY_CODE_MISMATCH = "This profile was signed with a different key than the expected key code.";
const COMMITMENT_SIZE = "Paste at most 120 fingerprint lines (20,000 characters).";
const hex = /^[a-f0-9]{64}$/;
const plainInteger = /^(?:0|-?[1-9][0-9]*)$/;
const keyCodePattern = /^[a-f0-9]{4}(?:-[a-f0-9]{4}){4}$/;
const commitmentPattern = /^n170-verify key=([a-f0-9]{4}(?:-[a-f0-9]{4}){4}) record=([1-9][0-9]{0,2}) end=([0-9]{4}-[0-9]{2}-[0-9]{2}) sha256=([a-f0-9]{64})$/;
// Aliases use visible characters only: letters, marks, numbers, punctuation,
// symbols and the ordinary space. Control, formatting (zero-width, joiner, bidi
// override), private-use, unassigned and other space characters can hide or
// reorder text, so they're rejected.
const aliasPattern = /^[\p{L}\p{M}\p{N}\p{P}\p{S} ]+$/u;
const metricKeys = ["total_return_twr_e8", "annualized_volatility_e8", "max_drawdown_e8"];
const payloadKeys = ["schema_version", "calculation_version", "sequence", "profile_id", "display_name", "previous_sha256", "source_kind", "provider_authenticated", "independent_timestamp", "period", "periods_per_year", "relative_returns", "coverage", "metrics"];

function requireValue(condition, message = INVALID) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, keys) {
  requireValue(value !== null && typeof value === "object" && !Array.isArray(value));
  const ownKeys = Object.keys(value);
  requireValue(ownKeys.length === keys.length && keys.every((key) => Object.hasOwn(value, key)));
}

export function isValidDisplayName(name) {
  return typeof name === "string" && name.length >= 1 && name.length <= 80 && name.trim() === name && aliasPattern.test(name);
}

function validDate(value) {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value;
}

// Checks the raw text of a file JSON.parse already accepted, so every JSON
// reader gets the same values from it. JSON.parse keeps the last copy of a
// repeated field while other parsers keep the first or reject the file, and
// numbers such as 1.0 or 1e2 are integers to some parsers but not others.
// Field names are decoded before comparing, so escaped spellings still match.
function jsonTextProblem(text) {
  const scopes = [];
  let index = 0;
  while (index < text.length) {
    const character = text[index];
    if (character === '"') {
      let end = index + 1;
      while (end < text.length && text[end] !== '"') end += text[end] === BACKSLASH ? 2 : 1;
      const token = text.slice(index, end + 1);
      index = end + 1;
      let next = index;
      while (next < text.length && JSON_WHITESPACE.has(text.charCodeAt(next))) next += 1;
      const scope = scopes.at(-1);
      if (scope && text[next] === ":") {
        let name;
        try {
          name = JSON.parse(token);
        } catch {
          return INVALID;
        }
        if (scope.has(name)) return REPEATED_FIELD;
        scope.add(name);
      }
      continue;
    }
    if (character === "-" || (character >= "0" && character <= "9")) {
      let end = index + 1;
      while (end < text.length && NUMBER_CHARACTERS.includes(text[end])) end += 1;
      if (!plainInteger.test(text.slice(index, end))) return INVALID;
      index = end;
      continue;
    }
    if (character === "{") scopes.push(new Set());
    else if (character === "[") scopes.push(null);
    else if (character === "}" || character === "]") scopes.pop();
    index += 1;
  }
  return null;
}

// Fixed-depth canonicalization: known keys in the order below; integers,
// strings, booleans and null only; no whitespace. Imported keys are never traversed.
export function canonicalPayload(payload) {
  const common = {
    schema_version: payload.schema_version,
    calculation_version: payload.calculation_version,
    sequence: payload.sequence,
    profile_id: payload.profile_id,
    display_name: payload.display_name,
    previous_sha256: payload.previous_sha256,
    source_kind: payload.source_kind,
    provider_authenticated: payload.provider_authenticated,
    independent_timestamp: payload.independent_timestamp,
    period: { start: payload.period.start, end: payload.period.end },
    periods_per_year: payload.periods_per_year,
    relative_returns: payload.relative_returns.map((interval) => ({ start: interval.start, end: interval.end, return_e8: interval.return_e8 })),
    coverage: {
      nav_observations: payload.coverage.nav_observations,
      return_observations: payload.coverage.return_observations,
      external_cash_flow_count: payload.coverage.external_cash_flow_count,
    },
    metrics: {
      total_return_twr_e8: payload.metrics.total_return_twr_e8,
      annualized_volatility_e8: payload.metrics.annualized_volatility_e8,
      max_drawdown_e8: payload.metrics.max_drawdown_e8,
    },
  };
  if (payload.schema_version === LEGACY_STAMP_SCHEMA) return common;
  return {
    ...common,
    serialization_version: payload.serialization_version,
    event_type: payload.event_type,
    correction: payload.correction === null ? null : { target_sequence: payload.correction.target_sequence, target_sha256: payload.correction.target_sha256, reason: payload.correction.reason },
    provenance: canonicalProvenance(payload.provenance),
  };
}

function canonicalProfile(profile) {
  return {
    schema_version: profile.schema_version,
    profile_id: profile.profile_id,
    display_name: profile.display_name,
    public_key: profile.public_key,
    stamps: profile.stamps.map((stamp) => ({ payload: canonicalPayload(stamp.payload), sha256: stamp.sha256, signature: stamp.signature })),
  };
}

function canonicalBytes(payload) {
  return new TextEncoder().encode(JSON.stringify(canonicalPayload(payload)));
}

// Signatures cover a domain label plus the exact canonical payload bytes, so a
// record signature can't be replayed as a signature over anything else.
function signatureInput(payloadBytes, payload) {
  const domain = signatureDomain(payload);
  const input = new Uint8Array(domain.length + payloadBytes.length);
  input.set(domain);
  input.set(payloadBytes, domain.length);
  return input;
}

function validateStructure(profile) {
  exactKeys(profile, ["schema_version", "profile_id", "display_name", "public_key", "stamps"]);
  requireValue([PROFILE_SCHEMA, LEGACY_PROFILE_SCHEMA].includes(profile.schema_version) && typeof profile.profile_id === "string" && hex.test(profile.profile_id) && isValidDisplayName(profile.display_name) && isPublicKeyText(profile.public_key));
  requireValue(Array.isArray(profile.stamps));
  requireValue(profile.stamps.length <= MAX_PROFILE_STAMPS, SIZE);
  let lastPerformanceEnd = null;
  let sawV4 = false;
  const superseded = new Set();
  for (const [index, stamp] of profile.stamps.entries()) {
    exactKeys(stamp, ["payload", "sha256", "signature"]);
    requireValue(typeof stamp.sha256 === "string" && hex.test(stamp.sha256) && isSignatureText(stamp.signature));
    const payload = stamp.payload;
    requireValue(payload !== null && typeof payload === "object" && !Array.isArray(payload));
    const modern = payload.schema_version === STAMP_SCHEMA;
    exactKeys(payload, modern ? [...payloadKeys, "serialization_version", "event_type", "correction", "provenance"] : payloadKeys);
    requireValue(modern ? profile.schema_version === PROFILE_SCHEMA && payload.calculation_version === "2.0.0" && payload.serialization_version === "1.0.0" : payload.schema_version === LEGACY_STAMP_SCHEMA && payload.calculation_version === "1.0.0" && !sawV4);
    sawV4 ||= modern;
    exactKeys(payload.period, ["start", "end"]);
    if (modern) {
      requireValue(["performance", "correction"].includes(payload.event_type));
      validateProvenance(payload.provenance);
      if (payload.event_type === "performance") requireValue(payload.correction === null);
      else {
        exactKeys(payload.correction, ["target_sequence", "target_sha256", "reason"]);
        const correction = payload.correction;
        requireValue(Number.isInteger(correction.target_sequence) && correction.target_sequence >= 1 && correction.target_sequence <= index && !superseded.has(correction.target_sequence), "A correction must reference an earlier record that has not already been corrected.");
        const target = profile.stamps[correction.target_sequence - 1];
        requireValue(correction.target_sha256 === target.sha256 && validText(correction.reason, 500) && correction.reason.trim().length >= 3, "A correction needs the exact original record and a reviewable reason.");
        requireValue(payload.period.start === target.payload.period.start && payload.period.end === target.payload.period.end, "A correction must retain the original period boundaries. Explain missing observations in the source review.");
        superseded.add(correction.target_sequence);
      }
    }
    requireValue(payload.profile_id === profile.profile_id && payload.display_name === profile.display_name);
    requireValue(payload.provider_authenticated === false && payload.independent_timestamp === false && ["synthetic_demo", "self_reported"].includes(payload.source_kind));
    requireValue(payload.sequence === index + 1 && payload.previous_sha256 === (index === 0 ? null : profile.stamps[index - 1].sha256), ORDER);
    exactKeys(payload.period, ["start", "end"]);
    requireValue(validDate(payload.period.start) && validDate(payload.period.end) && payload.period.start < payload.period.end);
    if (!modern || payload.event_type === "performance") {
      requireValue(lastPerformanceEnd === null || payload.period.start >= lastPerformanceEnd, ORDER);
      lastPerformanceEnd = payload.period.end;
    }
    requireValue(Number.isInteger(payload.periods_per_year) && payload.periods_per_year >= 1 && payload.periods_per_year <= 366);
    requireValue(Array.isArray(payload.relative_returns) && payload.relative_returns.length >= 1 && payload.relative_returns.length <= 499);
    let previousEnd = payload.period.start;
    for (const interval of payload.relative_returns) {
      exactKeys(interval, ["start", "end", "return_e8"]);
      requireValue(validDate(interval.start) && validDate(interval.end) && interval.start === previousEnd && interval.start < interval.end);
      requireValue(Number.isSafeInteger(interval.return_e8) && interval.return_e8 > -RETURN_UNITS);
      previousEnd = interval.end;
    }
    requireValue(previousEnd === payload.period.end);
    exactKeys(payload.coverage, ["nav_observations", "return_observations", "external_cash_flow_count"]);
    requireValue(payload.coverage.nav_observations === payload.relative_returns.length + 1 && payload.coverage.return_observations === payload.relative_returns.length);
    requireValue(Number.isInteger(payload.coverage.external_cash_flow_count) && payload.coverage.external_cash_flow_count >= 0 && payload.coverage.external_cash_flow_count <= payload.relative_returns.length);
    exactKeys(payload.metrics, metricKeys);
    for (const key of metricKeys) requireValue((key === "annualized_volatility_e8" && payload.metrics[key] === null) || Number.isSafeInteger(payload.metrics[key]));
    // A bundled-example label can only describe the actual bundled series.
    if (!modern && payload.source_kind === "synthetic_demo") {
      const example = { relative_returns: [{start:"2025-01-02",end:"2025-01-03",return_e8:1000000},{start:"2025-01-03",end:"2025-01-06",return_e8:1009901},{start:"2025-01-06",end:"2025-01-07",return_e8:-1000000}], coverage:{external_cash_flow_count:1} };
      requireValue(JSON.stringify(payload.relative_returns.map(({ start, end, return_e8 }) => ({ start, end, return_e8 }))) === JSON.stringify(example.relative_returns));
      requireValue(payload.coverage.external_cash_flow_count === example.coverage.external_cash_flow_count);
    }
  }
}

function parseExpectedKeyCode(value) {
  requireValue(typeof value === "string", OPTIONS);
  const code = value.trim().toLowerCase();
  if (code === "") return "";
  requireValue(code.length <= 24 && keyCodePattern.test(code), KEY_CODE_FORMAT);
  return code;
}

// Published fingerprint lines, one per record the owner posted publicly:
// n170-verify key=<key code> record=<sequence> end=<YYYY-MM-DD> sha256=<record hash>
// Repeated lines count once. Error messages cite line numbers, never pasted text.
function parseCommitments(value) {
  requireValue(typeof value === "string", OPTIONS);
  requireValue(value.length <= MAX_COMMITMENT_CHARACTERS, COMMITMENT_SIZE);
  const commitments = new Map();
  let lineCount = 0;
  for (const [index, rawLine] of value.split(/\r?\n/).entries()) {
    const line = rawLine.trim().toLowerCase();
    if (!line) continue;
    lineCount += 1;
    requireValue(lineCount <= MAX_COMMITMENT_LINES, COMMITMENT_SIZE);
    const match = commitmentPattern.exec(line);
    const record = match ? Number(match[2]) : 0;
    requireValue(match !== null && record <= MAX_PROFILE_STAMPS && validDate(match[3]), `Published fingerprint line ${index + 1} isn't in the expected format.`);
    if (!commitments.has(line)) commitments.set(line, { line: index + 1, keyCode: match[1], record, end: match[3], sha256: match[4] });
  }
  return [...commitments.values()];
}

// Periods per year implied by the median spacing of a record's interval dates.
function impliedPeriodsPerYear(relativeReturns) {
  const days = relativeReturns.map(({ start, end }) => (Date.parse(end) - Date.parse(start)) / DAY_MS).sort((a, b) => a - b);
  const middle = Math.floor(days.length / 2);
  const medianDays = days.length % 2 === 1 ? days[middle] : (days[middle - 1] + days[middle]) / 2;
  return 365.25 / medianDays;
}

async function inspectObject(value, options = {}) {
  requireValue(options !== null && typeof options === "object" && !Array.isArray(options), OPTIONS);
  const expectedKeyCode = parseExpectedKeyCode(options.expectedKeyCode ?? "");
  const commitments = parseCommitments(options.publishedFingerprints ?? "");
  validateStructure(value);
  const profile = canonicalProfile(value);
  requireValue(JSON.stringify(profile).length <= MAX_PROFILE_CHARACTERS, SIZE);
  requireValue(await keyIdFromPublicKey(profile.public_key) === profile.profile_id, KEY);
  const verificationKey = await importVerificationKey(profile.public_key);
  requireValue(verificationKey !== null, KEY);
  for (const stamp of profile.stamps) {
    let metrics;
    try {
      metrics = stamp.payload.schema_version === STAMP_SCHEMA
        ? calculateRecordMetricsV2(stamp.payload.relative_returns, stamp.payload.periods_per_year)
        : calculateRecordMetrics(stamp.payload.relative_returns.map(({ return_e8 }) => return_e8), stamp.payload.periods_per_year);
    } catch {
      throw new Error(METRICS);
    }
    requireValue(metricKeys.every((key) => metrics[key] === stamp.payload.metrics[key]), METRICS);
    const bytes = canonicalBytes(stamp.payload);
    requireValue(await sha256Hex(bytes) === stamp.sha256, HASH);
    requireValue(await verifySignature(verificationKey, stamp.signature, signatureInput(bytes, stamp.payload)), SIGNATURE);
  }
  const keyCode = formatKeyCode(profile.profile_id);
  requireValue(expectedKeyCode === "" || expectedKeyCode === keyCode, KEY_CODE_MISMATCH);
  // Each record's hash covers its predecessor's hash, so matching a published
  // fingerprint for record N fixes records 1..N exactly as they were posted.
  for (const commitment of commitments) {
    requireValue(commitment.keyCode === keyCode, `The published fingerprint on line ${commitment.line} belongs to a different key.`);
    requireValue(commitment.record <= profile.stamps.length, `This profile has fewer records than a published fingerprint (record ${commitment.record}): later records were removed.`);
    const stamp = profile.stamps[commitment.record - 1];
    requireValue(stamp.sha256 === commitment.sha256 && stamp.payload.period.end === commitment.end, `Record ${commitment.record} does not match the supplied fingerprint. Its publication date has not been established.`);
  }
  const effective = effectiveStamps(profile);
  const gaps = [];
  for (let i = 1; i < effective.length; i += 1) {
    const start = effective[i - 1].payload.period.end;
    const end = effective[i].payload.period.start;
    if (start < end) gaps.push({ start, end });
  }
  // Periods per year only scales volatility, which needs at least two returns.
  const frequencyWarnings = profile.stamps.flatMap(({ payload }) => {
    if (payload.relative_returns.length < 2) return [];
    const implied = impliedPeriodsPerYear(payload.relative_returns);
    const declared = payload.periods_per_year;
    return declared > implied * 2 || declared < implied / 2 ? [{ sequence: payload.sequence, declared, implied: Math.round(implied) }] : [];
  });
  let previousCopy = { status: "not_supplied", shared_records: 0, previous_records: 0, current_records: profile.stamps.length, changes: null };
  if (options.previousProfile !== undefined && options.previousProfile !== null && options.previousProfile !== "") {
    const previous = typeof options.previousProfile === "string" ? await inspectProfile(options.previousProfile) : await inspectObject(options.previousProfile);
    previousCopy = compareValidProfiles(previous.profile, profile);
  }
  const latestCommitment = commitments.reduce((latest, item) => !latest || item.record > latest.record ? item : latest, null);
  return {
    profile,
    key_code: keyCode,
    checks: {
      schema_valid: true,
      arithmetic_valid: true,
      chain_valid: true,
      signatures_valid: true,
      key_code: expectedKeyCode === "" ? "not_supplied" : "matched",
      published_fingerprints: { supplied: commitments.length, matched: commitments.length, latest_record: commitments.reduce((latest, { record }) => Math.max(latest, record), 0) },
      provider_authenticated: false,
      independent_timestamp: false,
      identity_established: false,
      checkpoint: latestCommitment ? { checked: true, sequence: latestCommitment.record, end: latestCommitment.end, sha256: latestCommitment.sha256, source: "supplied_fingerprint", publication_time_established: false } : { checked: false, sequence: null, end: null, sha256: null, source: null, publication_time_established: false },
      previous_copy: previousCopy,
    },
    summary: {
      stamp_count: profile.stamps.length,
      latest_sha256: profile.stamps.at(-1)?.sha256 ?? null,
      first_date: effective[0]?.payload.period.start ?? null,
      last_date: effective.at(-1)?.payload.period.end ?? null,
      effective_sequences: effective.map(({payload}) => payload.sequence),
      correction_count: profile.stamps.filter(({payload}) => payload.event_type === "correction").length,
      gaps,
      frequency_warnings: frequencyWarnings,
      source_kinds: [...new Set(profile.stamps.map(({ payload }) => payload.source_kind))],
      return_observations: effective.reduce((count, { payload }) => count + payload.relative_returns.length, 0),
    },
  };
}

function isSigner(signer) {
  return signer !== null && typeof signer === "object" && typeof signer.sign === "function" && isPublicKeyText(signer.publicKey);
}

export async function createProfile(displayName, signer) {
  requireValue(isValidDisplayName(displayName), "Use a display name of 1 to 80 letters, numbers, punctuation marks, symbols or spaces, with no space at either end.");
  requireValue(isSigner(signer), "A signing key is required to create a profile.");
  return { schema_version: PROFILE_SCHEMA, profile_id: await keyIdFromPublicKey(signer.publicKey), display_name: displayName, public_key: signer.publicKey, stamps: [] };
}

export async function appendPerformanceStamp(value, input, periodsPerYear = 252, signer = null, options = {}) {
  return appendRecord(value, input, periodsPerYear, signer, options);
}

export async function appendCorrectionStamp(value, targetSequence, input, periodsPerYear = 252, signer = null, options = {}) {
  requireValue(Number.isInteger(targetSequence), "Choose the record being corrected.");
  requireValue(validText(options.reason, 500) && options.reason.trim().length >= 3, "Explain the correction in 3 to 500 visible characters. Do not include private account details.");
  return appendRecord(value, input, periodsPerYear, signer, { ...options, targetSequence });
}

async function appendRecord(value, input, periodsPerYear, signer, options) {
  const { profile } = await inspectObject(value);
  requireValue(isSigner(signer) && signer.publicKey === profile.public_key, NO_KEY);
  requireValue(profile.stamps.length < MAX_PROFILE_STAMPS, SIZE);
  const evidence = buildStampObservationEvidence(input, periodsPerYear);
  const target = options.targetSequence === undefined ? null : profile.stamps[options.targetSequence - 1];
  if (options.targetSequence !== undefined) requireValue(target, "Choose an existing record to correct.");
  if (!target) {
    const last = effectiveStamps(profile).at(-1);
    requireValue(!last || evidence.period.start >= last.payload.period.end, "A new record must start on or after the previous record's end date. Use a correction to replace an earlier period.");
  }
  const payload = canonicalPayload({
    schema_version: STAMP_SCHEMA,
    calculation_version: "2.0.0",
    sequence: profile.stamps.length + 1,
    profile_id: profile.profile_id,
    display_name: profile.display_name,
    previous_sha256: profile.stamps.at(-1)?.sha256 ?? null,
    provider_authenticated: false,
    independent_timestamp: false,
    ...evidence,
    source_kind: options.synthetic === true ? "synthetic_demo" : evidence.source_kind,
    serialization_version: "1.0.0",
    event_type: target ? "correction" : "performance",
    correction: target ? { target_sequence: options.targetSequence, target_sha256: target.sha256, reason: options.reason.trim() } : null,
    provenance: normalizeProvenance(options.provenance),
  });
  profile.schema_version = PROFILE_SCHEMA;
  // Check all newly supplied metadata and correction references before signing.
  validateStructure({ ...profile, stamps: [...profile.stamps, { payload, sha256: "0".repeat(64), signature: "A".repeat(86) }] });
  if (payload.provenance.kind === "supplied_file") requireValue(payload.provenance.normalized_sha256 === await sha256Hex(new TextEncoder().encode(input)), "The reviewed import no longer matches the observations. Reconcile and review the edited source before signing.");
  const bytes = canonicalBytes(payload);
  const signature = await signer.sign(signatureInput(bytes, payload));
  const verificationKey = await importVerificationKey(profile.public_key);
  requireValue(isSignatureText(signature) && await verifySignature(verificationKey, signature, signatureInput(bytes, payload)), "Signing failed: the stored key doesn't match this profile.");
  profile.stamps.push({ payload, sha256: await sha256Hex(bytes), signature });
  requireValue(JSON.stringify(profile).length <= MAX_PROFILE_CHARACTERS, SIZE);
  return profile;
}

// Local storage can use this compare-and-append predicate atomically. It only
// protects the stored copy; a key holder can create forks elsewhere.
export function extendsByOneRecord(stored, next) {
  return Array.isArray(stored?.stamps) && Array.isArray(next?.stamps)
    && next.profile_id === stored.profile_id && next.public_key === stored.public_key && next.display_name === stored.display_name
    && next.stamps.length === stored.stamps.length + 1 && stored.stamps.every((stamp, index) => stamp.sha256 === next.stamps[index].sha256);
}

export async function inspectProfile(jsonText, options = {}) {
  requireValue(typeof jsonText === "string", INVALID);
  requireValue(jsonText.length <= MAX_PROFILE_CHARACTERS, SIZE);
  let value;
  try {
    value = JSON.parse(jsonText);
  } catch {
    throw new Error(INVALID);
  }
  const problem = jsonTextProblem(jsonText);
  requireValue(problem === null, problem);
  return inspectObject(value, options);
}

export function profileKeyCode(profile) {
  return formatKeyCode(profile?.profile_id);
}

export function publishedFingerprint(profile, index = (profile?.stamps?.length ?? 0) - 1) {
  const stamp = profile?.stamps?.[index];
  requireValue(stamp !== undefined, "Add a record before publishing a fingerprint.");
  return `n170-verify key=${formatKeyCode(profile.profile_id)} record=${stamp.payload.sequence} end=${stamp.payload.period.end} sha256=${stamp.sha256}`;
}


function validText(value, max) {
  return typeof value === "string" && value.length <= max && (value === "" || aliasPattern.test(value));
}

function canonicalProvenance(p) {
  return { kind: p.kind, format: p.format, original_sha256: p.original_sha256, source_sha256: p.source_sha256, normalized_sha256: p.normalized_sha256,
    mapping: p.mapping.map(({ field, column }) => ({ field, column })),
    account_scope: p.account_scope, currency: p.currency, completeness: p.completeness,
    corrections: p.corrections.map(({ row, field, reason, previous_sha256, replacement_sha256 }) => ({ row, field, reason, previous_sha256, replacement_sha256 })), reviewed: p.reviewed };
}

export function normalizeProvenance(value) {
  const p = value ?? { kind: "manual", format: "manual-nav-flow", original_sha256: null, source_sha256: null, normalized_sha256: null, mapping: [], account_scope: "Not specified by owner", currency: "unspecified", completeness: "not_established", corrections: [], reviewed: false };
  validateProvenance(p);
  return canonicalProvenance(p);
}

function validateProvenance(p) {
  exactKeys(p, ["kind", "format", "original_sha256", "source_sha256", "normalized_sha256", "mapping", "account_scope", "currency", "completeness", "corrections", "reviewed"]);
  requireValue(["manual", "supplied_file"].includes(p.kind) && validText(p.format, 80) && p.format.length > 0);
  for (const key of ["original_sha256", "source_sha256", "normalized_sha256"]) requireValue(p.kind === "manual" ? p[key] === null : typeof p[key] === "string" && hex.test(p[key]));
  requireValue(validText(p.account_scope, 160) && p.account_scope.length > 0 && typeof p.currency === "string" && (p.currency === "unspecified" || /^[A-Z]{3}$/.test(p.currency)));
  requireValue(p.completeness === "not_established" && typeof p.reviewed === "boolean");
  requireValue(Array.isArray(p.mapping) && p.mapping.length <= 20 && Array.isArray(p.corrections) && p.corrections.length <= 100);
  for (const m of p.mapping) { exactKeys(m, ["field", "column"]); requireValue(validText(m.field, 80) && validText(m.column, 120)); }
  for (const c of p.corrections) { exactKeys(c, ["row", "field", "reason", "previous_sha256", "replacement_sha256"]); requireValue(typeof c.previous_sha256 === "string" && hex.test(c.previous_sha256) && typeof c.replacement_sha256 === "string" && hex.test(c.replacement_sha256)); requireValue(Number.isInteger(c.row) && c.row >= 0 && c.row <= 10000 && validText(c.field, 80) && validText(c.reason, 500) && c.reason.trim().length >= 3); }
}

// Latest replacement for each original performance period. The original signed
// events remain available in profile.stamps, and all are always verified.
export function effectiveStamps(profile) {
  const active = new Map();
  const roots = new Map();
  for (const stamp of profile.stamps) {
    const p = stamp.payload;
    if (p.event_type === "correction") {
      const root = roots.get(p.correction.target_sequence);
      active.set(root, stamp);
      roots.set(p.sequence, root);
    } else { active.set(p.sequence, stamp); roots.set(p.sequence, p.sequence); }
  }
  return [...active.values()];
}

// Unsigned presentation data derived only from two fully checked profiles.
// A correction compares the exact event it replaces. A new period instead
// carries the latest effective earlier period for scope/currency context;
// its performance is not a correction of that earlier period.
function comparisonSnapshot(stamp) {
  if (!stamp) return null;
  const p = stamp.payload;
  return {
    sequence: p.sequence,
    period: { ...p.period },
    metrics: { ...p.metrics },
    account_scope: p.provenance?.account_scope ?? null,
    currency: p.provenance?.currency ?? null,
    source_kind: p.source_kind,
    source_format: p.provenance?.format ?? null,
    reviewed: p.provenance?.reviewed ?? null,
    periods_per_year: p.periods_per_year,
    calculation_version: p.calculation_version,
    return_observations: p.coverage.return_observations,
  };
}

function comparisonChanges(previous, current) {
  const events = [];
  const active = new Map();
  const roots = new Map();
  for (const [index, stamp] of current.stamps.entries()) {
    const p = stamp.payload;
    const correction = p.event_type === "correction";
    const before = correction ? current.stamps[p.correction.target_sequence - 1] : [...active.values()].at(-1);
    if (index >= previous.stamps.length) events.push({
      sequence: p.sequence,
      kind: correction ? "correction" : "performance",
      period: { ...p.period },
      target_sequence: correction ? p.correction.target_sequence : null,
      before: comparisonSnapshot(before),
      after: comparisonSnapshot(stamp),
      reason: correction ? p.correction.reason : null,
    });
    const root = correction ? roots.get(p.correction.target_sequence) : p.sequence;
    roots.set(p.sequence, root);
    active.set(root, stamp);
  }
  return { version: "n170.verify.comparison.v1", events };
}

function compareValidProfiles(previous, current) {
  let shared = 0;
  if (previous.profile_id === current.profile_id && previous.display_name === current.display_name) {
    while (shared < Math.min(previous.stamps.length, current.stamps.length) && previous.stamps[shared].sha256 === current.stamps[shared].sha256) shared += 1;
  }
  let status;
  if (previous.profile_id !== current.profile_id || previous.display_name !== current.display_name) status = "replacement";
  else if (shared < Math.min(previous.stamps.length, current.stamps.length)) status = "conflicting_history";
  else if (current.stamps.length < previous.stamps.length) status = "truncated";
  else if (current.stamps.length === previous.stamps.length) status = "identical";
  else status = "extended";
  return { status, shared_records: shared, previous_records: previous.stamps.length, current_records: current.stamps.length,
    first_difference: ["replacement", "conflicting_history", "truncated"].includes(status) ? shared + 1 : null,
    previous_checkpoint: previous.stamps.length ? { sequence: previous.stamps.length, end: previous.stamps.at(-1).payload.period.end, sha256: previous.stamps.at(-1).sha256 } : null,
    publication_time_established: false,
    changes: ["identical", "extended"].includes(status) ? comparisonChanges(previous, current) : null };
}

export async function compareProfiles(previousText, currentText) {
  const [previous, current] = await Promise.all([inspectProfile(previousText), inspectProfile(currentText)]);
  return compareValidProfiles(previous.profile, current.profile);
}


export function provenanceFromImport(review, { accountScope, reviewed = false } = {}) {
  requireValue(review?.canCalculate === true && review?.source?.authenticated === false, "Resolve import exceptions before preparing signed source metadata.");
  return normalizeProvenance({
    kind: "supplied_file", format: review.format,
    original_sha256: review.original_source_sha256 || review.source.sha256,
    source_sha256: review.source.sha256, normalized_sha256: review.review.normalized_sha256,
    mapping: review.mapping.map(m => ({ field: m.target, column: m.source })),
    account_scope: accountScope || review.coverage.accounts, currency: review.currency,
    completeness: "not_established",
    corrections: review.corrections.map(c => ({ row: 0, field: "Source revision", reason: c.reason, previous_sha256: c.previous_source_sha256, replacement_sha256: c.replacement_source_sha256 })),
    reviewed,
  });
}
