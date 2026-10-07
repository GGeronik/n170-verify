// Private draft validation. Stored/imported derived metadata has no authority.
import { importStatement, IMPORT_VERSION } from './importer.js';
import { sha256Hex } from './signing.js';

export const PRIVATE_DRAFT_KIND = 'n170.private-draft.v1';
const invalid = 'This private draft is invalid or unsupported. Your current work is unchanged.';
const invalidCorrections = 'The private draft correction history is inconsistent. Keep the original export and review the saved draft before replacing your current work.';
const text = (value, max) => typeof value === 'string' && value.length <= max;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const hashText = value => sha256Hex(new TextEncoder().encode(value));

// Mirror the row editor's outer trim and CRLF -> LF normalization only. Cell
// text is deliberately not trimmed: a hidden change in any other cell would
// otherwise disappear from the signed correction description.
function matchesDeclaredCell(correction) {
  const before = correction.before.trim().split(/\r?\n/);
  const after = correction.after.trim().split(/\r?\n/);
  if (before.length !== after.length || before.length < 2
    || correction.row >= before.length || before[0] !== after[0]) return false;
  const column = ['date', 'nav', 'external_flow'].indexOf(correction.field);
  let changed = false;
  for (let row = 1; row < before.length; row++) {
    const oldCells = before[row].split(',');
    const newCells = after[row].split(',');
    if (oldCells.length !== 3 || newCells.length !== 3) return false;
    for (let cell = 0; cell < 3; cell++) {
      if (oldCells[cell] === newCells[cell]) continue;
      if (changed || row !== correction.row || cell !== column) return false;
      changed = true;
    }
  }
  return changed;
}

export function createEmptyDraft() {
  return { input: '', original: '', fileName: '', format: 'auto', currency: 'USD', frequency: '252', scope: '', handoffText: '', corrections: [], flowTimingConfirmed: false, synthetic: false, importReview: null };
}

// Validate only user-owned fields and return new objects. Never retain derived
// importReview, canCalculate, mapping or arbitrary metadata from a saved file.
export function validatePrivateDraft(value) {
  const d = value?.data;
  if (!object(value) || value.kind !== PRIVATE_DRAFT_KIND || !object(d)
    || (d.handoffText !== undefined && !text(d.handoffText, 1000000))
    || !text(d.input, 50000) || !text(d.original, 1000000) || !text(d.fileName, 255) || !text(d.scope, 160)
    || !['USD', 'EUR', 'GBP', 'CHF', 'CAD', 'AUD', 'JPY'].includes(d.currency)
    || !['252', '365', '52', '12', '4', '1'].includes(d.frequency)
    || !['auto', 'n170', 'ibkr-flex', 'agent-handoff'].includes(d.format)
    || typeof d.flowTimingConfirmed !== 'boolean' || typeof d.synthetic !== 'boolean'
    || !Array.isArray(d.corrections) || d.corrections.length > 100) throw new Error(invalid);
  const corrections = d.corrections.map(c => {
    if (!object(c) || !Number.isInteger(c.row) || c.row < 1 || c.row > 500
      || !['date', 'nav', 'external_flow'].includes(c.field)
      || !text(c.reason, 500) || c.reason.trim().length < 3 || !text(c.before, 50000) || !text(c.after, 50000)
      || !hash(c.previous_sha256) || !hash(c.replacement_sha256)) throw new Error(invalidCorrections);
    return { row: c.row, field: c.field, reason: c.reason, before: c.before, after: c.after, previous_sha256: c.previous_sha256, replacement_sha256: c.replacement_sha256 };
  });
  return { input: d.input, original: d.original, fileName: d.fileName, format: d.format, currency: d.currency, frequency: d.frequency, scope: d.scope, handoffText: d.handoffText || '', corrections, flowTimingConfirmed: d.flowTimingConfirmed, synthetic: d.synthetic, importReview: null };
}

async function unavailableSourceReview(draft, cause) {
  return {
    version: IMPORT_VERSION, format: draft.format, label: 'Supplied source needs attention', normalizedCsv: '', rows: [], mapping: [], canCalculate: false,
    source: { kind: 'supplied_file', authenticated: false, sha256: await hashText(draft.original), digest_scope: 'UTF-8 text exactly as supplied before parsing', file_name: draft.fileName || 'Pasted CSV', uploaded: false },
    exceptions: [{ code: 'invalid_source', severity: 'error', message: cause.message, action: 'The original source and working observations are retained. Correct or replace the source and reconcile it before calculating.', row: null }],
    currency: draft.currency, corrections: [], coverage: { source_rows: 0, observations: 0, start: null, end: null, accounts: 'Scope supplied by owner' },
    review: { normalized_sha256: await hashText(''), source_verified: false, flow_timing: draft.flowTimingConfirmed ? 'owner_confirmed_interval_end' : 'interval_end_required', reviewed: false },
  };
}

// Rehydrate from immutable source text and verify each private edit. A blocked
// source can still be restored for repair; it never becomes calculable because
// imported metadata asserted success. Broken correction evidence rejects before
// a caller replaces its existing workspace state.
export async function hydratePrivateDraft(value) {
  const draft = validatePrivateDraft(value);
  let prior = null;
  for (const correction of draft.corrections) {
    if (!matchesDeclaredCell(correction) || (prior !== null && correction.before !== prior)
      || await hashText(correction.before) !== correction.previous_sha256
      || await hashText(correction.after) !== correction.replacement_sha256) throw new Error(invalidCorrections);
    prior = correction.after;
  }
  if (prior !== null && prior !== draft.input) throw new Error(invalidCorrections);
  if (!draft.original) return draft;

  let result;
  try {
    result = await importStatement(draft.original, { format: draft.format, currency: draft.currency, frequency: draft.frequency, flowTimingConfirmed: draft.flowTimingConfirmed, fileName: draft.fileName });
  } catch (cause) {
    result = await unavailableSourceReview(draft, cause);
  }
  if (result.normalizedCsv) {
    const sourceEnd = draft.corrections.length ? draft.corrections[0].before : draft.input;
    // An imported-but-not-reconciled draft legitimately has no working rows.
    if ((draft.corrections.length || sourceEnd) && sourceEnd !== result.normalizedCsv) throw new Error('The working observations do not match the saved source and correction history. Your current work is unchanged. Reconcile the original source before using this draft.');
    if (!draft.input) {
      result.canCalculate = false;
      result.exceptions.push({ code: 'reconciliation_needed', severity: 'error', message: 'The source is retained but its observations have not been accepted into this draft.', action: 'Reconcile the file and review the observations before continuing.', row: null });
    }
  }
  if (result.format === 'agent-handoff' && result.synthetic) draft.synthetic = true;
  draft.importReview = result;
  return draft;
}
