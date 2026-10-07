// Private preparation evidence. No source supplied to this module authenticates
// a broker, account owner, machine, or execution environment.
import { importStatement } from './importer.js';
import { buildStampObservationEvidence } from './calculator.js';
import { hydratePrivateDraft, PRIVATE_DRAFT_KIND } from './draftModel.js';
import { sha256Hex } from './signing.js';

export const RECONCILIATION_SCHEMA = 'n170.account-reconciliation.v1';
export const RECONCILIATION_LIMITS = Object.freeze({ source_bytes: 10 * 1024 * 1024, total_source_bytes: 10 * 1024 * 1024, sources: 20, source_rows: 5000, observations: 500, boundaries: 5000 });
const currencies = ['USD', 'EUR', 'GBP', 'CHF', 'CAD', 'AUD', 'JPY'];
const formats = ['auto', 'n170', 'ibkr-flex', 'agent-handoff', 'trading212', 'portfolio-performance'];
const encoder = new TextEncoder();
const SCALE = 10n ** 18n;
const DAY = 86400000;
const hashText = text => sha256Hex(encoder.encode(text));
const clone = value => JSON.parse(JSON.stringify(value));
const issue = (code, message, action, extra = {}) => ({ code, severity: 'error', message, action, ...extra });
const key = value => String(value).toLowerCase().replace(/[^a-z0-9]/g, '');
const isDate = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value;
const dateOf = value => { const s = typeof value === 'string' ? value.trim() : ''; const d = /^\d{8}$/.test(s) ? `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6)}` : s; return isDate(d) ? d : null; };
const nextDay = date => new Date(Date.parse(date) + DAY).toISOString().slice(0, 10);
const byteArray = bytes => {
  if (bytes instanceof Uint8Array) return new Uint8Array(bytes);
  if (bytes instanceof ArrayBuffer) return new Uint8Array(bytes.slice(0));
  if (Array.isArray(bytes) && bytes.every(b => Number.isInteger(b) && b >= 0 && b <= 255)) return Uint8Array.from(bytes);
  throw new Error('Source bytes must be an ArrayBuffer, Uint8Array or array of bytes.');
};
function toBase64(bytes) {
  let text = '';
  for (let i = 0; i < bytes.length; i += 8192) text += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(text);
}
function fromBase64(text) {
  if (typeof text !== 'string' || text.length > Math.ceil(RECONCILIATION_LIMITS.source_bytes / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) throw new Error('The retained source byte encoding is invalid or too large.');
  const bytes = Uint8Array.from(atob(text), c => c.charCodeAt(0));
  if (toBase64(bytes) !== text) throw new Error('The retained source byte encoding is not canonical base64.');
  return bytes;
}
function amount(value) {
  if (typeof value !== 'string' || value.length > 50 || !/^-?(?:\d+(?:\.\d{0,18})?|\.\d{1,18})$/.test(value)) throw new Error('Use an explicit plain decimal amount with at most 18 decimal places.');
  const negative = value.startsWith('-'); const [whole, fraction = ''] = (negative ? value.slice(1) : value).split('.');
  const n = BigInt(whole || '0') * SCALE + BigInt(fraction.padEnd(18, '0'));
  if (n > 1000000000000000n * SCALE) throw new Error('Amount magnitude exceeds the supported 10^15 limit.');
  return negative ? -n : n;
}
function decimal(n) {
  const sign = n < 0n ? '-' : ''; const unsigned = n < 0n ? -n : n;
  const fraction = String(unsigned % SCALE).padStart(18, '0').replace(/0+$/, '');
  return `${sign}${unsigned / SCALE}${fraction ? `.${fraction}` : ''}`;
}

// Tolerant inventory only: this never authorizes a calculation. It retains a
// malformed final record and raw cells even when the authoritative importer
// rejects the table. Byte spans refer to original UTF-8, not normalized CSV.
function inventoryCsv(text) {
  const first = text.replace(/^\uFEFF/, '').split(/\r?\n/, 1)[0];
  const delimiter = first.includes(';') && !first.includes(',') ? ';' : ',';
  const records = []; let cells = []; let cell = ''; let quoted = false;
  let start = 0; let byteStart = 0; let physical = 1; let recordLine = 1; let count = 0;
  const add = end => {
    cells.push(cell); const raw = text.slice(start, end); const byteEnd = byteStart + encoder.encode(raw).length;
    if (cells.some(c => c.trim())) {
      count += 1;
      if (records.length <= RECONCILIATION_LIMITS.source_rows) records.push({ source_row: count, physical_line: recordLine, byte_start: byteStart, byte_end: byteEnd, raw_text: raw, raw_cells: cells });
    }
    start = end; byteStart = byteEnd; cells = []; cell = ''; recordLine = physical;
  };
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (c === '"') { if (quoted && text[i + 1] === '"') { cell += '"'; i += 1; } else quoted = !quoted; }
    else if (!quoted && c === delimiter) { cells.push(cell); cell = ''; }
    else if (!quoted && (c === '\n' || c === '\r')) {
      if (c === '\r' && text[i + 1] === '\n') i += 1;
      physical += 1; add(i + 1);
    } else { cell += c; if (c === '\n') physical += 1; }
  }
  if (start < text.length || cells.length || cell) add(text.length);
  const header = records.shift(); const headers = (header?.raw_cells || []).map(c => c.replace(/^\uFEFF/, '').trim());
  const keys = headers.map(key);
  return {
    headers, source_rows: Math.max(0, count - 1), inspection_truncated: count > RECONCILIATION_LIMITS.source_rows + 1,
    rows: records.map(record => {
      const dates = [], currencyFields = [];
      record.raw_cells.forEach((value, i) => {
        if (['date', 'fromdate', 'todate', 'time'].includes(keys[i])) { const d = dateOf(value); if (d) dates.push({ field: headers[i], date: d }); }
        if (['currency', 'basecurrency', 'currencytotal'].includes(keys[i])) currencyFields.push({ field: headers[i], value: value.trim() });
      });
      return { ...record, reference: `csv-record:${record.source_row}`, dates, currencies: currencyFields };
    }),
  };
}
function inventoryJson(text) {
  let object;
  try { object = JSON.parse(text); } catch { return { headers: [], rows: [], source_rows: 0, inspection_truncated: false }; }
  const observations = Array.isArray(object?.observations) ? object.observations : [];
  return {
    headers: ['observations[].date', 'observations[].nav', 'observations[].external_flow'], source_rows: observations.length, inspection_truncated: observations.length > RECONCILIATION_LIMITS.source_rows,
    rows: observations.slice(0, RECONCILIATION_LIMITS.source_rows).map((row, i) => ({ source_row: i + 1, reference: `/observations/${i}`, raw_cells: clone(row), dates: dateOf(row?.date) ? [{ field: 'date', date: dateOf(row.date) }] : [], currencies: typeof object.currency === 'string' ? [{ field: '/currency', value: object.currency }] : [], source_ref: typeof row?.source_ref === 'string' ? row.source_ref : null })),
  };
}

export async function captureSource({ text, bytes, fileName = '', format = 'auto', currency, frequency, flowTimingConfirmed = false } = {}) {
  const issues = []; let consumed;
  try { consumed = bytes === undefined ? encoder.encode(typeof text === 'string' ? text : '') : byteArray(bytes); }
  catch (error) { consumed = new Uint8Array(); issues.push(issue('invalid_source_bytes', error.message, 'Keep the original file and select it again.')); }
  if (bytes === undefined && typeof text !== 'string') issues.push(issue('missing_source_text', 'No source text or bytes were supplied.', 'Choose an export or enter observations.'));
  const identity = await sha256Hex(consumed);
  let decoded = null;
  try { decoded = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(consumed); }
  catch { issues.push(issue('invalid_utf8', 'The original bytes are not valid UTF-8. They have been retained without replacement-character decoding.', 'Export the source as UTF-8 and explicitly resolve this attempted file.')); }
  if (bytes !== undefined && typeof text === 'string' && decoded !== null && text !== decoded) issues.push(issue('source_text_bytes_mismatch', 'Source text does not match the exact supplied bytes.', 'Restore matching original text and bytes; neither version may silently override the other.'));
  if (consumed.length > RECONCILIATION_LIMITS.source_bytes) issues.push(issue('source_size_limit', 'The source exceeds the 10 MiB byte limit.', 'Retain it separately and prepare a bounded, explicitly scoped source.'));
  if (!formats.includes(format)) issues.push(issue('unsupported_source_format', 'The requested source format is unsupported.', 'Choose a documented import format.'));
  let inventory = { headers: [], rows: [], source_rows: 0, inspection_truncated: false }; let review = null;
  if (decoded !== null && consumed.length <= RECONCILIATION_LIMITS.source_bytes) {
    inventory = decoded.trimStart().startsWith('{') ? inventoryJson(decoded) : inventoryCsv(decoded);
    if (inventory.source_rows > RECONCILIATION_LIMITS.source_rows) issues.push(issue('source_row_limit', 'The source exceeds 5,000 logical data rows. Full raw bytes remain retained.', 'Prepare a bounded source without silently excluding financial periods.'));
    try { review = await importStatement(decoded, { fileName, format, currency, frequency, flowTimingConfirmed }); }
    catch (error) { issues.push(issue('invalid_source', error.message, 'Correct or replace the original source and retain a reason for the replacement.', { details: Array.isArray(error.errors) ? clone(error.errors) : [] })); }
  }
  if (review) issues.push(...review.exceptions.filter(item => item.severity === 'error').map(clone));
  const source = {
    id: identity, sha256: identity, byte_length: consumed.length, file_name: String(fileName || 'Pasted observations').slice(0, 255), format: review?.format || format,
    text: decoded, bytes_base64: toBase64(consumed), source_bytes_available: true, digest_scope: 'exact consumed bytes; BOM and line endings included', provenance: 'owner_supplied', authenticated: false, uploaded: false,
    ...inventory, review, issues,
  };
  source.rows = source.rows.map(row => ({ ...row, status: !review || issues.some(i => i.row === row.source_row || i.row == null) ? 'needs_review' : 'parsed', normalized_rows: (review?.rows || []).flatMap((r, index) => r.sourceRow === row.source_row ? [index + 1] : []) }));
  source.dates = [...new Set(source.rows.flatMap(row => row.dates.map(d => d.date)))].sort();
  source.currencies = [...new Set(source.rows.flatMap(row => row.currencies.map(c => c.value)))];
  return source;
}

function sourceOptions(source, defaults) {
  const options = { ...defaults, fileName: source.fileName ?? source.file_name ?? '', format: source.format ?? 'auto' };
  const base64 = source.rawBytesBase64 ?? source.bytes_base64;
  if (base64 !== undefined) { options.bytes = fromBase64(base64); if (typeof source.text === 'string' && source.text !== '') options.text = source.text; }
  else options.text = source.text;
  return options;
}
function salvageObservations(source) {
  const keys = source.headers.map(key);
  if (keys.length !== 3 || !['date', 'nav', 'externalflow'].every(k => keys.includes(k))) return [];
  return source.rows.map(row => ({ date: String(row.raw_cells[keys.indexOf('date')] || '').trim(), nav: String(row.raw_cells[keys.indexOf('nav')] || '').trim(), flow: String(row.raw_cells[keys.indexOf('externalflow')] || '').trim(), sourceRow: row.source_row }));
}

export async function reconcileAccount(options = {}) {
  const { input = '', original = '', fileName = '', format = 'auto', currency = '', frequency = 252, accountScope = '', flowTimingConfirmed = false, corrections = [], sources = [], expectedSchedule = 'observed_boundaries', flowActivity = 'unknown', flowTiming = 'unknown' } = options;
  const blocking = []; const policy = [];
  const defaults = { currency, frequency, flowTimingConfirmed };
  const active = await captureSource({ text: original || input, fileName, format, ...defaults });
  active.disposition = 'active'; active.reason = '';
  const inventory = [active];
  if (!Array.isArray(sources)) blocking.push(issue('invalid_source_inventory', 'The historical source inventory must be an array.', 'Restore a valid private draft.'));
  else {
    if (sources.length + 1 > RECONCILIATION_LIMITS.sources) blocking.push(issue('source_count_limit', 'The draft exceeds 20 sources including the active source.', 'Resolve the attempted files and prepare a bounded selected scope.'));
    // No successful result is possible when a limit is exceeded. Raw excess
    // entries remain in rejected_source_entries for explicit recovery/export.
    for (const raw of sources.slice(0, RECONCILIATION_LIMITS.sources)) {
      let source;
      if (raw?.unconsumed) {
        const valid = Number.isSafeInteger(raw.unconsumed.byteLength) && raw.unconsumed.byteLength >= 0 && typeof raw.unconsumed.reason === 'string' && raw.unconsumed.reason.trim().length >= 3 && raw.unconsumed.reason.length <= 500 && !raw.text && raw.rawBytesBase64 === undefined && raw.bytes_base64 === undefined;
        source = { id: null, sha256: null, byte_length: 0, file_name: String(raw.fileName || 'Unread source').slice(0, 255), format: raw.format || 'auto', text: null, bytes_base64: null, digest_scope: null, source_bytes_available: false, unconsumed: valid ? clone(raw.unconsumed) : null, provenance: 'owner_supplied', authenticated: false, uploaded: false, headers: [], rows: [], source_rows: 0, inspection_truncated: false, dates: [], currencies: [], review: null, issues: [issue(valid ? 'source_bytes_unavailable' : 'invalid_unconsumed_source', valid ? 'This attempted source was not consumed or retained. Its declared byte count is an owner claim, not a byte identity.' : 'The unread-source entry is inconsistent.', 'Keep the original separately and retry, or explicitly exclude the attempt with a reason.')] };
        if (!valid) blocking.push(...source.issues);
      } else {
        try { source = await captureSource(sourceOptions(raw || {}, defaults)); }
        catch (error) { source = await captureSource({ text: typeof raw?.text === 'string' ? raw.text : '', fileName: raw?.fileName }); source.issues.push(issue('invalid_retained_bytes', error.message, 'Restore the exact source bytes before excluding or superseding this attempt.')); }
      }
      source.disposition = ['unresolved', 'excluded', 'superseded'].includes(raw?.disposition) ? raw.disposition : 'unresolved';
      source.reason = typeof raw?.reason === 'string' ? raw.reason.slice(0, 500) : '';
      inventory.push(source);
      if (source.disposition === 'unresolved') blocking.push(issue('unresolved_source', `An attempted source (${source.file_name}) remains unresolved.`, 'Review it, or explicitly exclude/supersede it with a reason and retain the attempt.', { source_sha256: source.sha256 }));
      else if (source.reason.trim().length < 3) blocking.push(issue('source_disposition_reason_required', 'An excluded or superseded source has no meaningful recorded reason.', 'Record why this file is outside the selected scope or how its replacement resolves it.', { source_sha256: source.sha256 }));
      if (source.issues.some(i => ['invalid_retained_bytes', 'source_text_bytes_mismatch'].includes(i.code))) blocking.push(...source.issues.filter(i => ['invalid_retained_bytes', 'source_text_bytes_mismatch'].includes(i.code)));
    }
  }
  if (inventory.reduce((sum, source) => sum + source.byte_length, 0) > RECONCILIATION_LIMITS.total_source_bytes) blocking.push(issue('source_bytes_limit', 'The complete inventory exceeds 10 MiB of source bytes.', 'Prepare a bounded selected scope and retain other original files separately.'));
  if (inventory.reduce((sum, source) => sum + source.source_rows, 0) > RECONCILIATION_LIMITS.source_rows) blocking.push(issue('inventory_row_limit', 'The complete inventory exceeds 5,000 source rows.', 'Prepare a bounded selected scope without silently removing rejected rows.'));
  for (const source of inventory.slice(1)) {
    const commonDates = source.dates.filter(date => active.dates.includes(date));
    source.overlap_with_active = commonDates.length ? { dates: commonDates, relation: source.sha256 === active.sha256 ? 'identical_source_bytes' : 'overlapping_source_dates', active_source_sha256: active.sha256 } : null;
    const activeRows = active.review?.rows || []; const historicalRows = source.review?.rows || [];
    const conflictDates = [...new Set(historicalRows.filter(row => activeRows.some(other => other.date === row.date && (other.nav !== row.nav || other.flow !== row.flow))).map(row => row.date))];
    if (source.overlap_with_active) source.overlap_with_active.conflicting_observation_dates = conflictDates;
    if (source.disposition === 'unresolved' && conflictDates.length) blocking.push(issue('conflicting_source_overlap', 'An unresolved source supplies different NAV or flow values on active observation dates.', 'Compare both original sources and explicitly resolve the conflicting observations; neither source is chosen automatically.', { dates: conflictDates, source_sha256: source.sha256 }));
  }
  blocking.push(...active.issues.map(item => ({ ...item, source_sha256: active.sha256 })));

  if (!currencies.includes(currency)) policy.push(issue('unsupported_currency', 'Choose one supported reporting currency.', 'Use USD, EUR, GBP, CHF, CAD, AUD or JPY; conversion is not performed.'));
  if (active.currencies.some(c => c !== currency)) policy.push(issue('currency_conflict', 'An explicit source currency is blank or differs from the selected reporting currency.', 'Resolve the currency evidence in the source. Foreign-exchange conversion is unsupported.'));
  if (typeof accountScope !== 'string' || !accountScope.trim() || accountScope.length > 160) policy.push(issue('account_scope_required', 'Describe the selected account scope with a public alias.', 'Use 1–160 characters; do not claim completeness beyond the supplied evidence.'));
  if (flowActivity !== 'reviewed_no_hidden') policy.push(issue(flowActivity === 'offsetting' ? 'offsetting_flows_unsupported' : 'flow_activity_unknown', flowActivity === 'offsetting' ? 'Net flows do not evidence separate offsetting deposits and withdrawals.' : 'Cash activity has not been reviewed for hidden or missing external flows.', 'Obtain gross cash activity and valuations at each actual flow; confirm completeness of cash activity for this selected scope.'));
  if (flowTiming !== 'interval_end') policy.push(issue(flowTiming === 'intraperiod' ? 'intraperiod_flow_unsupported' : 'flow_timing_unknown', flowTiming === 'intraperiod' ? 'Intraperiod external flows require additional valuations.' : 'The timing of every external flow is unknown.', 'Supply valuations at each flow and only use this method when every flow occurs at interval end.'));
  if (!['observed_boundaries', 'calendar_daily', 'weekdays'].includes(expectedSchedule)) policy.push(issue('unsupported_schedule', 'The expected observation schedule is unsupported.', 'Choose observed boundaries, calendar daily, or weekdays.'));
  if (!Number.isInteger(Number(frequency)) || Number(frequency) < 1 || Number(frequency) > 366) policy.push(issue('unsupported_frequency', 'Observation frequency is outside the calculator support.', 'Use an integer from 1 to 366 periods per year.'));

  let working = input || active.review?.normalizedCsv || '';
  let correctionValid = true;
  if (original || (Array.isArray(corrections) && corrections.length)) {
    try {
      await hydratePrivateDraft({ kind: PRIVATE_DRAFT_KIND, data: { input: working, original, fileName, format, currency, frequency: String(frequency), scope: accountScope, handoffText: '', corrections, flowTimingConfirmed, synthetic: false } });
    } catch (error) { correctionValid = false; blocking.push(issue('invalid_correction_chain', error.message, 'Restore the original normalization and a verified one-cell correction history.')); }
  } else if (!Array.isArray(corrections)) { correctionValid = false; blocking.push(issue('invalid_correction_chain', 'Correction history must be an array.', 'Restore the private draft correction history.')); }
  const normalizedHash = await hashText(working);
  let currentReview = null;
  if (working) {
    try { currentReview = await importStatement(working, { format: 'n170', ...defaults }); }
    catch (error) { blocking.push(issue('invalid_working_observations', error.message, 'Repair the observations while retaining source and correction history.')); }
  }
  if (currentReview) blocking.push(...currentReview.exceptions.filter(i => i.severity === 'error').map(item => ({ ...item, origin: 'working_observations' })));
  let observations = currentReview?.rows || active.review?.rows || salvageObservations(active);
  if (observations.length > RECONCILIATION_LIMITS.observations) blocking.push(issue('observation_limit', 'More than 500 observations are outside supported calculation bounds.', 'Prepare a bounded record and preserve unsupported periods separately.'));
  const rawRows = active.review?.rows || salvageObservations(active);
  const safeCorrections = correctionValid && Array.isArray(corrections) ? corrections.map(clone) : [];
  observations = observations.map((row, index) => ({ ...row, normalized_row: index + 1, original_source_row: rawRows[index]?.sourceRow ?? null, source_ref: rawRows[index]?.sourceRef ?? null, correction_steps: safeCorrections.flatMap((c, step) => c.row === index + 1 ? [{ sequence: step + 1, field: c.field, previous_sha256: c.previous_sha256, replacement_sha256: c.replacement_sha256 }] : []) }));
  const availableDates = observations.map(row => dateOf(row.date)).filter(Boolean);
  const requested = options.period || {};
  const start = requested.start || availableDates[0] || null; const end = requested.end || availableDates.at(-1) || null;
  const scope = {
    account_alias: typeof accountScope === 'string' ? accountScope : '', period: { start, end }, period_source: requested.start || requested.end ? 'owner_selected' : 'supplied_boundaries', currency,
    expected_schedule: expectedSchedule, flow_activity: flowActivity, flow_timing: flowTiming, periods_per_year: Number(frequency),
    completeness: 'not_established', provenance: 'owner_supplied', authenticated: false,
    observation_claim: expectedSchedule === 'observed_boundaries' ? 'Only supplied observation boundaries; missing intraperiod observations remain unknown.' : expectedSchedule === 'weekdays' ? 'Every weekday required; no exchange-holiday calendar is assumed.' : 'Every calendar date required.',
  };
  if (!isDate(start) || !isDate(end) || start >= end) policy.push(issue('invalid_selected_period', 'The selected period needs valid, ascending opening and closing dates.', 'Supply a real opening and closing valuation.'));
  if (availableDates.some(date => (start && date < start) || (end && date > end))) policy.push(issue('observations_outside_selected_period', 'The selected period would omit supplied observations.', 'Retain the full supplied history or prepare an explicitly separate source; this module does not filter away periods.'));
  blocking.push(...policy);
  const missingDates = [];
  if (isDate(start) && isDate(end) && start < end) {
    const dateSet = new Set(availableDates);
    if (!dateSet.has(start)) missingDates.push(start);
    if (!dateSet.has(end)) missingDates.push(end);
    if (['calendar_daily', 'weekdays'].includes(expectedSchedule)) {
      if ((Date.parse(end) - Date.parse(start)) / DAY > RECONCILIATION_LIMITS.boundaries) blocking.push(issue('schedule_range_limit', 'The selected schedule exceeds 5,000 calendar boundaries.', 'Prepare a shorter explicitly scoped record.'));
      else for (let date = start; date < end; date = nextDay(date)) {
        const day = new Date(date).getUTCDay();
        if ((expectedSchedule === 'calendar_daily' || (day !== 0 && day !== 6)) && !dateSet.has(date) && !missingDates.includes(date)) missingDates.push(date);
      }
    }
  }
  const ascending = observations.every((row, index) => isDate(row.date) && (!index || row.date > observations[index - 1].date));
  let timeline = observations;
  if (ascending) timeline = [...observations, ...missingDates.map(date => ({ date, nav: null, flow: null, missing: true, normalized_row: null, original_source_row: null, correction_steps: [] }))].sort((a, b) => a.date.localeCompare(b.date));
  else if (missingDates.length) blocking.push(issue('missing_requested_boundaries', 'Missing selected boundaries cannot be sequenced alongside invalid or conflicting dates.', 'Resolve all date conflicts and supply every required valuation.', { dates: missingDates }));
  const missing = missingDates.map(date => issue('missing_valuation', `No valuation is supplied for required boundary ${date}.`, 'Obtain the missing valuation. Do not forward-fill NAV or assume a zero external flow.', { date }));
  blocking.push(...missing);

  const intervals = [];
  // The calculator's wealth limits apply cumulatively to the supplied series.
  // Re-running a supported interval in isolation can wrongly reject it (e.g.
  // a 1e-7 interval factor after a preceding 10x gain). Reuse the full result.
  let fullEvidence = null; let fullCalculationError = null;
  try { fullEvidence = buildStampObservationEvidence(working, Number(frequency)); }
  catch (error) { fullCalculationError = error; }
  const fullReturns = new Map((fullEvidence?.relative_returns || []).map(interval => [`${interval.start}/${interval.end}`, interval.return_e8]));
  const dateCounts = observations.reduce((counts, row) => counts.set(row.date, (counts.get(row.date) || 0) + 1), new Map());
  for (let index = 1; index < timeline.length; index += 1) {
    const opening = timeline[index - 1], closing = timeline[index]; const reasons = policy.map(clone);
    reasons.push(...active.issues.filter(item => item.row == null).map(clone));
    const duration = isDate(opening.date) && isDate(closing.date) ? (Date.parse(closing.date) - Date.parse(opening.date)) / DAY : null;
    if (duration === null || duration <= 0) reasons.push(issue('conflicting_observation_dates', 'Interval boundaries are invalid, duplicate or out of order.', 'Resolve every conflicting observation explicitly; no duplicate is automatically removed.'));
    for (const row of [opening, closing]) {
      if (row.missing) reasons.push(issue('missing_valuation', `No valuation is supplied for ${row.date}.`, 'Obtain this valuation and its external-flow evidence.', { date: row.date }));
      if (dateCounts.get(row.date) > 1) reasons.push(issue('conflicting_observation_dates', `More than one observation supplies boundary ${row.date}.`, 'Explicitly resolve every duplicate/conflicting observation before this boundary is used.', { date: row.date }));
      const sourceErrors = active.issues.filter(item => item.row != null && item.row === row.original_source_row);
      reasons.push(...sourceErrors.map(clone));
      reasons.push(...(currentReview?.exceptions || []).filter(item => item.severity === 'error' && item.row != null && item.row === row.normalized_row + 1).map(clone));
      if (!correctionValid) reasons.push(issue('invalid_correction_chain', 'The working observation cannot be connected to a valid correction history.', 'Restore consistent source and corrections.'));
    }
    let adjusted = null, change = null, flowKind = closing.flow === null ? 'unknown' : null, returnE8 = null;
    try {
      if (!opening.missing && !closing.missing) {
        const a = amount(opening.nav), b = amount(closing.nav), flow = amount(closing.flow);
        adjusted = decimal(b - flow); change = decimal(b - flow - a); flowKind = flow > 0n ? 'deposit' : flow < 0n ? 'withdrawal' : 'net_zero';
        if (a <= 0n || b <= 0n || b - flow <= 0n) reasons.push(issue('total_loss_or_recapitalization_unsupported', 'Zero/negative NAV or cash-flow-adjusted wealth is unsupported; this interval is not a zero return.', 'Keep the interval and obtain valuations and an accounting review before applying a supported method.'));
        if (!reasons.length) {
          const csv = `date,nav,external_flow\n${opening.date},${opening.nav},0\n${closing.date},${closing.nav},${closing.flow}`;
          try { returnE8 = fullReturns.has(`${opening.date}/${closing.date}`) ? fullReturns.get(`${opening.date}/${closing.date}`) : buildStampObservationEvidence(csv, Number(frequency)).relative_returns[0].return_e8; }
          catch (error) { reasons.push(issue('numerical_support_exceeded', error.message, 'Keep this interval and review the unsupported range or precision separately.')); }
        }
      }
    } catch (error) { reasons.push(issue('invalid_interval_amount', error.message, 'Supply exact supported decimal valuations and flow amounts; missing amounts are never zero.')); }
    const dependency = (role, row) => ({ role, source_sha256: active.sha256, source_row: row.original_source_row, source_ref: row.source_ref || null, normalized_row: row.normalized_row, date: row.date, value: role === 'flow' ? row.flow : row.nav, missing: !!row.missing, correction_steps: row.correction_steps, provenance: 'owner_supplied', authenticated: false });
    const dependencies = [dependency('opening', opening), dependency('closing', closing), dependency('flow', closing)];
    const interval = { start: opening.date, end: closing.date, duration_days: duration, opening_nav: opening.nav, closing_nav: closing.nav, external_flow: closing.flow, adjusted_closing_nav: adjusted, economic_change: change, flow_kind: flowKind || 'unknown', return_e8: reasons.length ? null : returnE8, status: reasons.length || returnE8 === null ? 'unresolved' : 'calculable', blocking_reasons: reasons, dependencies, provenance: 'owner_supplied', authenticated: false };
    interval.dependency_sha256 = await hashText(JSON.stringify({ schema: RECONCILIATION_SCHEMA, source_sha256: active.sha256, normalized_sha256: normalizedHash, scope, corrections: safeCorrections, interval }));
    intervals.push(interval);
  }
  if (!intervals.length) blocking.push(issue('intervals_required', 'No complete interval can be constructed from the supplied observations.', 'Supply opening and closing valuations and retain rejected source evidence.'));
  for (const interval of intervals) if (interval.status === 'unresolved') blocking.push(...interval.blocking_reasons.map(reason => ({ ...reason, start: interval.start, end: interval.end })));
  if (fullCalculationError && working) blocking.push(issue('series_calculation_unsupported', fullCalculationError.message, 'Retain the full series and review the unsupported calculation; do not omit difficult periods.'));
  const blockingIssues = [...new Map(blocking.map(item => [JSON.stringify(item), item])).values()];
  const canCalculate = blockingIssues.length === 0 && intervals.length > 0 && intervals.every(i => i.status === 'calculable') && active.review?.canCalculate === true && currentReview?.canCalculate === true;
  const result = {
    schema_version: RECONCILIATION_SCHEMA, private: true, source_inventory: inventory, review: active.review, normalizedCsv: working, normalized_sha256: normalizedHash,
    scope, intervals, blocking_issues: blockingIssues, canCalculate, selected_scope_status: canCalculate ? 'calculable_under_owner_assumptions' : 'blocked', completeness: 'not_established',
    provenance: 'owner_supplied', authenticated: false, corrections: Array.isArray(corrections) ? clone(corrections) : [], missing_boundaries: missingDates,
    rejected_source_entries: Array.isArray(sources) && sources.length >= RECONCILIATION_LIMITS.sources ? clone(sources.slice(RECONCILIATION_LIMITS.sources)) : [],
    privacy: { raw_sources_included: true, account_values_included: true, filenames_included: true, uploaded: false, signing_key_included: false, automatically_included_in_shared_profiles: false },
  };
  result.dependency_sha256 = await hashText(JSON.stringify({ schema: RECONCILIATION_SCHEMA, source_inventory: inventory.map(source => ({ sha256: source.sha256, file_name: source.file_name, byte_length: source.byte_length, unconsumed: source.unconsumed || null, disposition: source.disposition, reason: source.reason })), normalized_sha256: normalizedHash, scope, corrections: result.corrections, intervals: intervals.map(i => i.dependency_sha256), blocking_issues: blockingIssues }));
  return result;
}

export function makeReconciliationArtifact(result) {
  if (!result || result.schema_version !== RECONCILIATION_SCHEMA) throw new Error('A current private reconciliation result is required.');
  return { kind: 'n170.private-account-reconciliation.v1', private: true, disclosure: 'PRIVATE, UNENCRYPTED: includes exact source bytes/text, filenames, account aliases, dates, currencies, balances, flows, corrections, exclusion reasons and dependency hashes. No signing key. Share only intentionally.', reconciliation: clone(result) };
}
