// Input transport and structural checks only. No producer imports or execution.
import { constants, openSync, closeSync, readSync, fstatSync, lstatSync } from 'node:fs';

export const INPUT_LIMITS = Object.freeze({ privateBytes: 32 * 1024 * 1024, sourceBytes: 10 * 1024 * 1024, sources: 20, sourceRows: 5000, observations: 500, intervals: 5500, diagnostics: 20000, corrections: 100, depth: 24, nodes: 500000 });
const forbidden = new Set(['__proto__', 'prototype', 'constructor']);
function fail(code = 'INVALID_PRIVATE_SCHEMA') { const error = new Error(code); error.status = 'INVALID_INPUT'; error.code = code; throw error; }
const check = (condition, code) => { if (!condition) fail(code); };
const sameFile = (a, b) => ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every(key => a[key] === b[key]);

// O_NONBLOCK prevents a path changed into a FIFO from blocking during open.
// O_NOFOLLOW and lstat reject final-component links; both descriptor and path
// identities/timestamps are checked after the bounded read.
export function readBoundedUtf8(path, maxBytes) {
  check(typeof path === 'string' && path.length > 0 && path.length <= 4096 && !path.includes('\0'), 'INVALID_INPUT_PATH');
  check(Number.isSafeInteger(maxBytes) && maxBytes >= 0 && maxBytes <= INPUT_LIMITS.privateBytes, 'INVALID_INPUT_LIMIT');
  let fd;
  try {
    const beforePath = lstatSync(path, { bigint: true });
    check(beforePath.isFile() && !beforePath.isSymbolicLink(), 'INPUT_NOT_REGULAR_FILE');
    check(beforePath.size <= BigInt(maxBytes), 'INPUT_SIZE_LIMIT');
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const before = fstatSync(fd, { bigint: true });
    check(before.isFile() && sameFile(beforePath, before), 'INPUT_CHANGED');
    const buffer = Buffer.alloc(Number(before.size) + 1);
    let size = 0;
    while (size < buffer.length) {
      const count = readSync(fd, buffer, size, Math.min(65536, buffer.length - size), null);
      if (!count) break;
      size += count;
    }
    const after = fstatSync(fd, { bigint: true });
    const afterPath = lstatSync(path, { bigint: true });
    check(size === Number(before.size) && afterPath.isFile() && !afterPath.isSymbolicLink() && sameFile(before, after) && sameFile(before, afterPath), 'INPUT_CHANGED');
    try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buffer.subarray(0, size)); }
    catch { fail('INVALID_UTF8'); }
  } catch (error) {
    if (error?.status === 'INVALID_INPUT') throw error;
    fail('INPUT_READ_FAILED');
  } finally { if (fd !== undefined) { try { closeSync(fd); } catch { /* No input-derived diagnostics. */ } } }
}

function unicode(value) {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) { const d = value.charCodeAt(++i); check(d >= 0xdc00 && d <= 0xdfff, 'INVALID_UNICODE'); }
    else check(c < 0xdc00 || c > 0xdfff, 'INVALID_UNICODE');
  }
}

// A bounded grammar parser: escaped-equivalent keys are compared after decode.
// JSON.parse is used only for a single, already delimited string token.
export function parseStrictJson(text) {
  check(typeof text === 'string', 'INVALID_JSON');
  check(text.length <= INPUT_LIMITS.privateBytes && Buffer.byteLength(text, 'utf8') <= INPUT_LIMITS.privateBytes, 'INPUT_SIZE_LIMIT');
  check(text.charCodeAt(0) !== 0xfeff, 'TRANSPORT_BOM');
  let at = 0, nodes = 0;
  const space = () => { while (at < text.length && [' ', '\t', '\r', '\n'].includes(text[at])) at++; };
  function string() {
    const start = at++;
    while (at < text.length) {
      const c = text.charCodeAt(at++);
      if (c === 34) {
        let value; try { value = JSON.parse(text.slice(start, at)); } catch { fail('INVALID_JSON'); }
        unicode(value); return value;
      }
      check(c >= 32, 'INVALID_JSON');
      if (c === 92) { check(at < text.length, 'INVALID_JSON'); at++; }
    }
    fail('INVALID_JSON');
  }
  function value(depth) {
    check(++nodes <= INPUT_LIMITS.nodes, 'JSON_NODE_LIMIT'); space();
    const c = text[at];
    if (c === '"') return string();
    if (c === '{' || c === '[') {
      check(depth < INPUT_LIMITS.depth, 'JSON_DEPTH_LIMIT'); at++; space();
      const object = c === '{', end = object ? '}' : ']', out = object ? {} : [], keys = new Set();
      if (text[at] === end) { at++; return out; }
      while (true) {
        if (object) {
          check(text[at] === '"', 'INVALID_JSON'); const key = string();
          check(!forbidden.has(key), 'FORBIDDEN_JSON_KEY'); check(!keys.has(key), 'DUPLICATE_JSON_KEY'); keys.add(key);
          space(); check(text[at++] === ':', 'INVALID_JSON'); out[key] = value(depth + 1);
        } else out.push(value(depth + 1));
        space(); if (text[at] === end) { at++; return out; }
        check(text[at++] === ',', 'INVALID_JSON'); space();
      }
    }
    for (const [word, parsed] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(word, at)) { at += word.length; return parsed; }
    }
    const start = at;
    if (text[at] === '-') at++;
    while (at < text.length && text.charCodeAt(at) >= 48 && text.charCodeAt(at) <= 57) at++;
    const token = text.slice(start, at);
    check(/^(?:0|-?[1-9][0-9]*)$/.test(token) && token.length <= 17 && Number.isSafeInteger(Number(token)), 'INVALID_JSON_NUMBER');
    return Number(token);
  }
  const out = value(0); space(); check(at === text.length, 'INVALID_JSON'); return out;
}

// Validate direct API objects too; do not invoke supplied getters or permit
// cycles/non-JSON values that cannot have come from parseStrictJson.
function jsonTree(root) {
  let nodes = 0; const active = new Set();
  function visit(value, depth) {
    check(++nodes <= INPUT_LIMITS.nodes, 'JSON_NODE_LIMIT');
    if (value === null || typeof value === 'boolean') return;
    if (typeof value === 'string') { check(value.length <= INPUT_LIMITS.privateBytes, 'INPUT_SIZE_LIMIT'); unicode(value); return; }
    if (typeof value === 'number') { check(Number.isSafeInteger(value) && !Object.is(value, -0), 'INVALID_JSON_NUMBER'); return; }
    check(typeof value === 'object' && depth < INPUT_LIMITS.depth && !active.has(value), 'INVALID_PRIVATE_SCHEMA');
    const array = Array.isArray(value), prototype = Object.getPrototypeOf(value);
    check(array ? prototype === Array.prototype : prototype === Object.prototype || prototype === null);
    check(Object.getOwnPropertySymbols(value).length === 0);
    active.add(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (array) check(Object.keys(descriptors).length === value.length + 1);
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (array && key === 'length') continue;
      check(!forbidden.has(key), 'FORBIDDEN_JSON_KEY'); unicode(key);
      check(Object.hasOwn(descriptor, 'value') && descriptor.enumerable);
      if (array) check(/^(?:0|[1-9][0-9]*)$/.test(key) && Number(key) < value.length);
      visit(descriptor.value, depth + 1);
    }
    active.delete(value);
  }
  visit(root, 0);
  check(Buffer.byteLength(JSON.stringify(root), 'utf8') <= INPUT_LIMITS.privateBytes, 'INPUT_SIZE_LIMIT');
}

const text = max => value => check(typeof value === 'string' && value.length <= max);
const bool = value => check(typeof value === 'boolean');
const integer = (min = 0, max = Number.MAX_SAFE_INTEGER) => value => check(Number.isSafeInteger(value) && value >= min && value <= max);
const nullable = validate => value => { if (value !== null) validate(value); };
const enumeration = (...values) => value => check(values.includes(value));
const hash = value => check(typeof value === 'string' && /^[a-f0-9]{64}$/.test(value));
const array = (validate, max) => value => { check(Array.isArray(value) && value.length <= max); value.forEach(validate); };
const record = (required, optional = {}) => value => {
  check(value !== null && typeof value === 'object' && !Array.isArray(value));
  check(Object.keys(required).every(key => Object.hasOwn(value, key)));
  for (const key of Object.keys(value)) { check(Object.hasOwn(required, key) || Object.hasOwn(optional, key)); (required[key] || optional[key])(value[key]); }
};
const dateText = text(1000); // Malformed retained dates are claims, not repaired.
const amountText = text(100000); // Preserve bounded malformed source claims.
const period = record({ start: nullable(dateText), end: nullable(dateText) });
const owner = enumeration('owner_supplied');
const no = enumeration(false);
const unconsumed = record({ byteLength: integer(), reason: text(500) });
const correctionStep = record({ sequence: integer(1, 100), field: text(80), previous_sha256: hash, replacement_sha256: hash });
const preparationCorrection = record({ row: integer(0, 500), field: text(80), reason: text(500), before: text(50000), after: text(50000), previous_sha256: hash, replacement_sha256: hash });
const importCorrection = record({ sequence: integer(1, 100), previous_source_sha256: hash, replacement_source_sha256: hash, previous_normalized_sha256: hash, replacement_normalized_sha256: hash, reason: text(500), changed_at: text(100), time_evidence: enumeration('device_clock_only') });

export function validatePrivateArtifact(value) {
  jsonTree(value);
  let diagnostics = 0, decodedBytes = 0, sourceRows = 0;
  const issueDetails = record({ path: text(1000), code: text(160), message: text(20000), action: text(20000) });
  const issue = item => {
    check(++diagnostics <= INPUT_LIMITS.diagnostics, 'DIAGNOSTIC_LIMIT');
    record({ code: text(160), severity: enumeration('error', 'warning', 'info'), message: text(20000), action: text(20000) }, {
      row: nullable(integer(0, 5001)), date: nullable(dateText), dates: array(dateText, 5500), source_sha256: nullable(hash), start: nullable(dateText), end: nullable(dateText), origin: text(100), details: array(detail => { check(++diagnostics <= INPUT_LIMITS.diagnostics, 'DIAGNOSTIC_LIMIT'); issueDetails(detail); }, 20000),
    })(item);
  };
  const issues = array(issue, INPUT_LIMITS.diagnostics);
  const review = record({
    version: enumeration('n170.import.v1'), format: text(80), label: text(500),
    source: record({ kind: enumeration('supplied_file'), authenticated: no, sha256: hash, digest_scope: text(500), file_name: text(255), uploaded: no }),
    normalizedCsv: text(50000), rows: array(record({ date: dateText, nav: amountText, flow: amountText, sourceRow: integer(0, 5001) }, { derived: text(1000), sourceRef: text(1000) }), 500),
    mapping: array(record({ source: text(120), target: text(80), explanation: text(2000) }), 20), exceptions: issues, canCalculate: bool, currency: text(100), corrections: array(importCorrection, 100),
    coverage: record({ source_rows: integer(0, 5000), observations: integer(0, 500), start: nullable(dateText), end: nullable(dateText), accounts: text(1000) }),
    review: record({ normalized_sha256: hash, source_verified: no, flow_timing: enumeration('owner_confirmed_interval_end', 'interval_end_required'), reviewed: bool }),
  }, { original_source_sha256: hash });
  const row = record({
    source_row: integer(0, 5001), reference: text(1000), raw_cells: array(text(INPUT_LIMITS.sourceBytes), 5000),
    dates: array(record({ field: text(100000), date: dateText }), 5000), currencies: array(record({ field: text(100000), value: text(100000) }), 5000),
    status: enumeration('needs_review', 'parsed'), normalized_rows: array(integer(1, 500), 500),
  }, { physical_line: integer(1), byte_start: integer(), byte_end: integer(), raw_text: text(INPUT_LIMITS.sourceBytes), source_ref: nullable(text(1000)) });
  function base64(value) {
    check(typeof value === 'string' && value.length <= 4 * Math.ceil(INPUT_LIMITS.sourceBytes / 3), 'INVALID_BASE64');
    check(value.length % 4 === 0 && !/[^A-Za-z0-9+/=]/.test(value), 'INVALID_BASE64');
    const bytes = Buffer.from(value, 'base64');
    check(bytes.toString('base64') === value, 'INVALID_BASE64');
    decodedBytes += bytes.length; check(decodedBytes <= INPUT_LIMITS.sourceBytes, 'SOURCE_BYTE_LIMIT');
  }
  const source = item => {
    record({
      id: nullable(hash), sha256: nullable(hash), byte_length: integer(0, INPUT_LIMITS.sourceBytes), file_name: text(255), format: text(80), text: nullable(text(INPUT_LIMITS.sourceBytes)), bytes_base64: nullable(base64), source_bytes_available: bool, digest_scope: nullable(text(500)), provenance: owner, authenticated: no, uploaded: no,
      headers: array(text(100000), 5000), rows: array(row, 5000), source_rows: integer(0, 5000), inspection_truncated: bool, review: nullable(review), issues,
      dates: array(dateText, 5000), currencies: array(text(100000), 5000), disposition: enumeration('active', 'unresolved', 'excluded', 'superseded'), reason: text(500),
    }, { unconsumed: nullable(unconsumed), overlap_with_active: nullable(record({ dates: array(dateText, 5000), relation: enumeration('identical_source_bytes', 'overlapping_source_dates'), active_source_sha256: hash, conflicting_observation_dates: array(dateText, 5000) })) })(item);
    if (item.source_bytes_available) {
      check(item.id !== null && item.sha256 !== null && item.bytes_base64 !== null && item.digest_scope !== null && (item.unconsumed === undefined || item.unconsumed === null));
    } else {
      check(['id', 'sha256', 'text', 'bytes_base64', 'digest_scope'].every(key => item[key] === null)
        && item.byte_length === 0 && item.unconsumed !== undefined && item.unconsumed !== null && item.unconsumed.reason.trim().length >= 3
        && item.review === null && item.source_rows === 0 && ['rows', 'headers', 'dates', 'currencies'].every(key => item[key].length === 0));
    }
    sourceRows += Math.max(item.rows.length, item.source_rows); check(sourceRows <= INPUT_LIMITS.sourceRows, 'SOURCE_ROW_LIMIT');
  };
  const dependency = record({ role: enumeration('opening', 'closing', 'flow'), source_sha256: nullable(hash), source_row: nullable(integer(0, 5001)), source_ref: nullable(text(1000)), normalized_row: nullable(integer(1, 500)), date: nullable(dateText), value: nullable(amountText), missing: bool, correction_steps: array(correctionStep, 100), provenance: owner, authenticated: no });
  const interval = record({
    start: nullable(dateText), end: nullable(dateText), duration_days: nullable(integer(-3660000, 3660000)), opening_nav: nullable(amountText), closing_nav: nullable(amountText), external_flow: nullable(amountText), adjusted_closing_nav: nullable(amountText), economic_change: nullable(amountText), flow_kind: enumeration('unknown', 'deposit', 'withdrawal', 'net_zero'), return_e8: nullable(integer(Number.MIN_SAFE_INTEGER)), status: enumeration('unresolved', 'calculable'), blocking_reasons: issues, dependencies: array(dependency, 3), provenance: owner, authenticated: no, dependency_sha256: hash,
  });
  // Only documented retained-source draft entries are accepted in this recovery
  // field. They never become active sources or authorize a successful result.
  const rejected = record({ text: text(INPUT_LIMITS.sourceBytes), fileName: text(255), disposition: enumeration('unresolved', 'excluded', 'superseded'), reason: text(500) }, { format: text(80), rawBytesBase64: base64, bytes_base64: base64, unconsumed });
  const reconciliation = record({
    schema_version: enumeration('n170.account-reconciliation.v1'), private: enumeration(true), source_inventory: array(source, 20), review: nullable(review), normalizedCsv: text(50000), normalized_sha256: hash,
    scope: record({ account_alias: text(160), period, period_source: enumeration('owner_selected', 'supplied_boundaries'), currency: text(100), expected_schedule: text(100), flow_activity: text(100), flow_timing: text(100), periods_per_year: integer(Number.MIN_SAFE_INTEGER), completeness: enumeration('not_established'), provenance: owner, authenticated: no, observation_claim: text(1000) }),
    intervals: array(interval, 5500), blocking_issues: issues, canCalculate: bool, selected_scope_status: enumeration('calculable_under_owner_assumptions', 'blocked'), completeness: enumeration('not_established'), provenance: owner, authenticated: no, corrections: array(preparationCorrection, 100), missing_boundaries: array(dateText, 5500), rejected_source_entries: array(rejected, 20),
    privacy: record({ raw_sources_included: enumeration(true), account_values_included: enumeration(true), filenames_included: enumeration(true), uploaded: no, signing_key_included: no, automatically_included_in_shared_profiles: no }), dependency_sha256: hash,
  });
  record({ kind: enumeration('n170.private-account-reconciliation.v1'), private: enumeration(true), disclosure: text(2000), reconciliation })(value);
  return value.reconciliation;
}
