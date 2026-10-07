// Private, owner-supplied reconciliation inputs only. Derived source inventories,
// hashes, parsing results and provenance are rebuilt by the reconciliation engine.
import {
  createEmptyDraft as createLegacyEmptyDraft,
  hydratePrivateDraft as hydrateLegacyPrivateDraft,
} from './draftModel.js';

export const MAX_RETAINED_SOURCES = 20;
export const MAX_SOURCE_BYTES = 1_000_000;
export const MAX_TOTAL_SOURCE_BYTES = 10 * 1024 * 1024;

const invalid = 'This private draft has invalid or unsupported reconciliation inputs. Your current work is unchanged.';
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const text = (value, max) => typeof value === 'string' && value.length <= max;
const schedules = ['observed_boundaries', 'calendar_daily', 'weekdays'];
const activities = ['reviewed_no_hidden', 'unknown', 'offsetting'];
const timings = ['interval_end', 'unknown', 'intraperiod'];
const formats = ['auto', 'n170', 'ibkr-flex', 'agent-handoff', 'trading212', 'portfolio-performance'];
const dispositions = ['unresolved', 'excluded', 'superseded'];
const encoder = new TextEncoder();

function reject(detail = '') {
  throw new Error(detail ? `${invalid} ${detail}` : invalid);
}

function emptyReconciliation() {
  return {
    sources: [],
    period: { start: '', end: '' },
    expectedSchedule: 'observed_boundaries',
    flowActivity: 'unknown',
    flowTiming: 'unknown',
  };
}

function validDate(value) {
  if (value === '') return true;
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

function hasUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return true;
  }
  return false;
}

// There is no replacement decoding: text and retained bytes must describe the
// same input. Unreadable UTF-8 is retained as bytes with an empty text field.
function sourceBytes(source) {
  if (!text(source.text, MAX_SOURCE_BYTES) || hasUnpairedSurrogate(source.text)) reject('Source text must be exact UTF-8 text.');
  if (source.rawBytesBase64 === undefined) {
    const bytes = encoder.encode(source.text);
    if (bytes.byteLength > MAX_SOURCE_BYTES) reject('Each retained source is limited to 1,000,000 bytes.');
    return bytes;
  }
  const encoded = source.rawBytesBase64;
  if (!text(encoded, 4 * Math.ceil(MAX_SOURCE_BYTES / 3))
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) reject('Retained source bytes must use canonical base64.');
  let binary;
  try { binary = atob(encoded); } catch { reject('Retained source bytes must use canonical base64.'); }
  if (binary.length > MAX_SOURCE_BYTES) reject('Each retained source is limited to 1,000,000 bytes.');
  if (btoa(binary) !== encoded) reject('Retained source bytes must use canonical base64.');
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
  let decoded;
  try { decoded = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } catch {
    if (source.text !== '') reject('Unreadable source bytes require an empty text field.');
    return bytes;
  }
  if (decoded !== source.text) reject('Retained source text does not match its exact bytes.');
  return bytes;
}

function validateSource(source) {
  if (!object(source) || !text(source.fileName, 255)
    || !dispositions.includes(source.disposition) || !text(source.reason, 500)
    || (source.disposition !== 'unresolved' && source.reason.trim().length < 3)
    || (source.format !== undefined && !formats.includes(source.format))) reject();
  let unconsumed;
  if (source.unconsumed !== undefined) {
    const value = source.unconsumed;
    if (!object(value) || !Number.isSafeInteger(value.byteLength) || value.byteLength < 0
      || !text(value.reason, 500) || value.reason.trim().length < 3
      || source.text !== '' || source.rawBytesBase64 !== undefined) reject('An unretained source needs a byte count and explanation, with no claimed contents.');
    unconsumed = { byteLength: value.byteLength, reason: value.reason };
  }
  const bytes = unconsumed ? null : sourceBytes(source);
  const result = {
    text: source.text,
    fileName: source.fileName,
    disposition: source.disposition,
    reason: source.reason,
  };
  if (source.format !== undefined) result.format = source.format;
  if (source.rawBytesBase64 !== undefined) result.rawBytesBase64 = source.rawBytesBase64;
  if (unconsumed) result.unconsumed = unconsumed;
  return { result, bytes };
}

// This is intentionally an allowlist. In particular, source SHA-256, row lists,
// unreadable flags and authenticity/success claims cannot be restored as facts.
export function validateReconciliation(value) {
  if (value === undefined) return emptyReconciliation();
  if (!object(value) || !Array.isArray(value.sources) || value.sources.length > MAX_RETAINED_SOURCES
    || !object(value.period) || !validDate(value.period.start) || !validDate(value.period.end)
    || !schedules.includes(value.expectedSchedule) || !activities.includes(value.flowActivity)
    || !timings.includes(value.flowTiming)) reject();
  let totalBytes = 0;
  const sources = Array.from(value.sources, source => {
    const checked = validateSource(source);
    totalBytes += checked.bytes?.byteLength || 0;
    if (totalBytes > MAX_TOTAL_SOURCE_BYTES) reject('Retained sources are limited to 10 MiB combined bytes.');
    return checked.result;
  });
  return {
    sources,
    period: { start: value.period.start, end: value.period.end },
    expectedSchedule: value.expectedSchedule,
    flowActivity: value.flowActivity,
    flowTiming: value.flowTiming,
  };
}

export function createEmptyDraft() {
  return { ...createLegacyEmptyDraft(), reconciliation: emptyReconciliation() };
}

// Validation happens before the baseline hydration is awaited, and this helper
// never mutates its argument. The caller can replace its state only on success.
export async function hydratePrivateDraft(value) {
  const reconciliation = validateReconciliation(value?.data?.reconciliation);
  const draft = await hydrateLegacyPrivateDraft(value);
  return { ...draft, reconciliation };
}

function sameBytes(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

// Append an attempted source without changing accepted working observations.
// Repeating the same name and bytes does not erase an existing review decision.
// All errors leave the caller's original reconciliation object untouched.
export function retainSource(reconciliation, source) {
  const current = validateReconciliation(reconciliation);
  if (!object(source)) reject();
  const candidate = validateSource({ disposition: 'unresolved', reason: '', ...source });
  const duplicate = !candidate.result.unconsumed && current.sources.some(existing => !existing.unconsumed && existing.fileName === candidate.result.fileName
    && sameBytes(sourceBytes(existing), candidate.bytes));
  if (duplicate) return current;
  return validateReconciliation({ ...current, sources: [...current.sources, candidate.result] });
}
