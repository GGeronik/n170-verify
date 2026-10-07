// A bounded local handoff from another assistant. All source metadata is a
// sender claim; MCP connection/permission hints are not source attestations.
import { buildStampObservationEvidence } from './calculator.js';
import { sha256Hex } from './signing.js';

export const AGENT_HANDOFF_SCHEMA = 'n170.agent-handoff.v1';
export const MAX_AGENT_HANDOFF_CHARACTERS = 1000000;
export const HANDOFF_BLOCK_CODES = Object.freeze(['source_not_retrieved', 'pagination_incomplete', 'pagination_unknown', 'missing_periods', 'unsupported_events', 'flow_timing_unsupported', 'missing_observations', 'requested_period_mismatch', 'calculation_unsupported']);
const currencies = ['USD', 'EUR', 'GBP', 'CHF', 'CAD', 'AUD', 'JPY'];
const frequencies = [252, 365, 52, 12, 4, 1];
const plainDecimal = /^-?(?:\d+(?:\.\d{0,18})?|\.\d{1,18})$/;
const control = /[\u0000-\u001f\u007f-\u009f]/;
const at = (path, key) => `${path}/${String(key).replaceAll('~', '~0').replaceAll('/', '~1')}`;
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const validDate = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value;
function validTimestamp(value) {
  if (typeof value !== 'string') return false;
  const match = /^(\d{4}-\d{2}-\d{2})T([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(?:\.\d{1,3})?(Z|[+-](?:0\d|1[0-4]):[0-5]\d)$/.exec(value);
  return !!match && validDate(match[1]) && Number.isFinite(Date.parse(value)) && (!/[+-]14:/.test(match[5]) || /14:00$/.test(match[5]));
}
function amountInRange(value) {
  const unsigned = value.startsWith('-') ? value.slice(1) : value;
  const [whole, fractional = ''] = unsigned.split('.');
  const amount = BigInt(whole || '0') * 10n ** 18n + BigInt(fractional.padEnd(18, '0') || '0');
  return amount <= 1000000000000000n * 10n ** 18n;
}

// JSON.parse accepts duplicate keys; reject them to keep independent readers
// from choosing different evidence. Also bound nested objects before traversing.
function lexicalProblem(text) {
  const stack = []; let index = 0;
  while (index < text.length) {
    const char = text[index];
    if (char === '"') {
      let end = index + 1;
      while (end < text.length && text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
      const token = text.slice(index, end + 1); index = end + 1;
      let next = index; while (/\s/.test(text[next] || '') && next < text.length) next += 1;
      const scope = stack.at(-1);
      if (scope && text[next] === ':') {
        const key = JSON.parse(token);
        if (scope.has(key)) return { code: 'duplicate_key', message: 'JSON contains a repeated field. Emit each field exactly once.' };
        scope.add(key);
      }
      continue;
    }
    if (char === '{') stack.push(new Set()); else if (char === '[') stack.push(null);
    else if (char === '}' || char === ']') stack.pop();
    if (stack.length > 20) return { code: 'invalid_value', message: 'JSON nesting exceeds the supported handoff structure.' };
    index += 1;
  }
  return null;
}

export class AgentHandoffError extends Error {
  constructor(errors) {
    super(`Handoff needs correction: ${errors[0]?.path || '/'}: ${errors[0]?.message || 'Invalid handoff.'}`);
    this.name = 'AgentHandoffError'; this.code = 'invalid_handoff'; this.errors = errors;
  }
}

// Synchronous structural validation for CLIs. Errors use JSON-pointer paths and
// stable codes; only parseAgentHandoff additionally checks calculation readiness.
export function validateAgentHandoff(text) {
  const errors = [];
  const fail = (path, code, message, action = 'Correct this field using the documented handoff schema; do not guess missing evidence.') => { if (errors.length < 50) errors.push({ path: path || '/', code, message, action }); };
  if (typeof text !== 'string') { fail('', 'invalid_type', 'Supply JSON text.'); return { valid: false, errors }; }
  if (text.length > MAX_AGENT_HANDOFF_CHARACTERS) { fail('', 'size_limit', 'Use at most 1,000,000 characters.'); return { valid: false, errors }; }
  let h;
  try { h = JSON.parse(text); const problem = lexicalProblem(text); if (problem) { fail('', problem.code, problem.message); return { valid: false, errors }; } }
  catch { fail('', 'invalid_json', 'The handoff is not valid JSON.', 'Return one JSON object without markdown fences or surrounding explanation.'); return { valid: false, errors }; }
  const fields = (value, keys, path) => {
    if (!isObject(value)) { fail(path, 'invalid_type', 'Expected an object.'); return false; }
    for (const key of Object.keys(value)) if (!keys.includes(key)) fail(at(path, '[unknown-field]'), 'unknown_key', 'This field is not part of the handoff schema. Credentials, account IDs and verification claims must not be added.');
    for (const key of keys) if (!Object.hasOwn(value, key)) fail(at(path, key), 'missing_key', 'This required field is missing.');
    return true;
  };
  const label = (value, path, max) => { if (typeof value !== 'string') fail(path, 'invalid_type', 'Expected text.'); else if (!value.trim() || value.length > max || control.test(value)) fail(path, 'invalid_value', `Use 1–${max} visible characters without control characters.`); };
  const enumValue = (value, allowed, path) => { if (!allowed.includes(value)) fail(path, 'invalid_value', `Use one of: ${allowed.join(', ')}.`); };
  const list = (value, path, max) => { if (!Array.isArray(value)) { fail(path, 'invalid_type', 'Expected an array.'); return false; } if (value.length > max) { fail(path, 'invalid_value', `Use at most ${max} items.`); return false; } return true; };
  const date = (value, path) => { if (!validDate(value)) fail(path, 'invalid_date', 'Use a real calendar date as YYYY-MM-DD.'); };
  const period = (value, path, keys = ['start', 'end']) => {
    if (!fields(value, keys, path)) return;
    date(value.start, at(path, 'start')); date(value.end, at(path, 'end'));
    if (validDate(value.start) && validDate(value.end) && value.start > value.end) fail(path, 'invalid_range', 'Start must be on or before end.');
  };
  if (!fields(h, ['schema_version', 'synthetic', 'source', 'account_scope', 'currency', 'frequency', 'requested_period', 'coverage', 'flow_timing', 'observations', 'mapping'], '')) return { valid: false, errors };
  enumValue(h.schema_version, [AGENT_HANDOFF_SCHEMA], '/schema_version');
  if (typeof h.synthetic !== 'boolean') fail('/synthetic', 'invalid_type', 'State whether this packet contains synthetic example data.');
  if (fields(h.source, ['broker', 'connector', 'tools', 'retrieved_at'], '/source')) {
    label(h.source.broker, '/source/broker', 80); label(h.source.connector, '/source/connector', 80);
    if (list(h.source.tools, '/source/tools', 40)) {
      h.source.tools.forEach((tool, i) => label(tool, `/source/tools/${i}`, 80));
      if (new Set(h.source.tools).size !== h.source.tools.length) fail('/source/tools', 'invalid_value', 'Tool names must be unique.');
    }
    if (h.source.retrieved_at !== null && !validTimestamp(h.source.retrieved_at)) fail('/source/retrieved_at', 'invalid_timestamp', 'Use an ISO timestamp with time zone, or null when no retrieval occurred.');
  }
  label(h.account_scope, '/account_scope', 160); enumValue(h.currency, currencies, '/currency'); enumValue(h.frequency, frequencies, '/frequency');
  period(h.requested_period, '/requested_period');
  if (fields(h.coverage, ['pagination', 'missing_periods', 'unsupported_events'], '/coverage')) {
    enumValue(h.coverage.pagination, ['complete', 'incomplete', 'unknown'], '/coverage/pagination');
    if (list(h.coverage.missing_periods, '/coverage/missing_periods', 100)) h.coverage.missing_periods.forEach((p, i) => { const path = `/coverage/missing_periods/${i}`; period(p, path, ['start', 'end', 'reason']); if (isObject(p)) label(p.reason, `${path}/reason`, 300); });
    if (list(h.coverage.unsupported_events, '/coverage/unsupported_events', 100)) h.coverage.unsupported_events.forEach((event, i) => label(event, `/coverage/unsupported_events/${i}`, 300));
  }
  enumValue(h.flow_timing, ['interval_end', 'intraperiod', 'unknown'], '/flow_timing');
  if (list(h.observations, '/observations', 500)) h.observations.forEach((row, i) => {
    const path = `/observations/${i}`;
    if (!fields(row, ['date', 'nav', 'external_flow', 'source_ref'], path)) return;
    date(row.date, `${path}/date`); label(row.source_ref, `${path}/source_ref`, 240);
    for (const field of ['nav', 'external_flow']) {
      const value = row[field];
      if (typeof value !== 'string' || value.length > 50 || !plainDecimal.test(value)) fail(`${path}/${field}`, 'invalid_decimal', 'Supply an explicit plain decimal string with at most 18 decimal places; missing amounts, numbers, exponents and null are not accepted.');
      else if (!amountInRange(value)) fail(`${path}/${field}`, 'decimal_range', 'Amount magnitude must not exceed 10^15.');
    }
    if (i && validDate(row.date) && validDate(h.observations[i - 1]?.date) && row.date <= h.observations[i - 1].date) fail(`${path}/date`, 'date_order', 'Observation dates must be unique and ascending; review duplicates rather than dropping them.');
  });
  if (fields(h.mapping, ['date', 'nav', 'external_flow'], '/mapping')) for (const key of ['date', 'nav', 'external_flow']) label(h.mapping[key], `/mapping/${key}`, 120);
  return errors.length ? { valid: false, errors } : { valid: true, handoff: h, errors: [] };
}

export async function parseAgentHandoff(text) {
  const validation = validateAgentHandoff(text);
  if (!validation.valid) throw new AgentHandoffError(validation.errors);
  const handoff = validation.handoff;
  const exceptions = [];
  const add = (code, severity, message, action) => exceptions.push({ code, severity, message, action, row: null });
  if (handoff.source.retrieved_at === null || handoff.source.tools.length === 0) add('source_not_retrieved', 'error', 'No completed source retrieval is reported.', 'Keep the packet blocked until an authorized read-only source provides the required observations. Do not invent a retrieval time or tool call.');
  if (handoff.coverage.pagination !== 'complete') add(`pagination_${handoff.coverage.pagination}`, 'error', `The sender reports ${handoff.coverage.pagination} pagination.`, 'Read every relevant page within the authorized scope or leave the handoff blocked.');
  if (handoff.coverage.missing_periods.length) add('missing_periods', 'error', 'The sender reports missing periods.', 'Obtain the missing observations or keep the affected requested period blocked; do not fill gaps.');
  if (handoff.coverage.unsupported_events.length) add('unsupported_events', 'error', 'The sender reports unsupported events.', 'Resolve their deterministic treatment and obtain necessary valuations before calculating.');
  if (handoff.flow_timing !== 'interval_end') add('flow_timing_unsupported', 'error', 'The source does not establish supported interval-end cash-flow timing.', 'Obtain valuations around every external flow. Do not treat intraperiod flows as interval-end flows.');
  if (handoff.observations.length < 2) add('missing_observations', 'error', 'At least two complete dated NAV observations are required.', 'Return only observations actually available, or an empty array; never invent NAV or missing zero flows.');
  else if (handoff.observations[0].date !== handoff.requested_period.start || handoff.observations.at(-1).date !== handoff.requested_period.end) add('requested_period_mismatch', 'error', 'The supplied observation boundaries do not match the requested period.', 'Obtain the requested opening and closing valuations or ask the owner to explicitly change the requested scope.');
  const rows = handoff.observations.map((row, i) => ({ date: row.date, nav: row.nav, flow: row.external_flow, sourceRow: i + 1, sourceRef: row.source_ref }));
  const normalizedCsv = 'date,nav,external_flow\n' + rows.map(row => `${row.date},${row.nav},${row.flow}`).join('\n');
  if (rows.length >= 2) {
    try { buildStampObservationEvidence(normalizedCsv, handoff.frequency); }
    catch (error) { add('calculation_unsupported', 'error', error.message, 'Review the unsupported values or intervals; do not remove losses or invent data to obtain a result.'); }
  }
  add('agent_claims_unverified', 'warning', 'Broker, connector, tool names, pagination and retrieval time are sender claims. This file does not prove a tool ran or authenticate its response.', 'Review the original tool outputs privately. A connection or read-only hint is not a source attestation, identity check or independent timestamp.');
  add('flow_activity_review', 'warning', 'Interval-end timing refers to every actual external flow, including offsetting flows hidden by a zero net total.', 'The owner must review cash activity and confirm flow classification, timing and scope before signing. Trades, dividends and fees must not silently become external flows.');
  if (handoff.synthetic) add('synthetic_example', 'warning', 'This packet explicitly contains synthetic example data.', 'Keep the example label when reviewing or sharing. It is not personal performance evidence.');
  const sourceHash = await sha256Hex(new TextEncoder().encode(text));
  const normalizedHash = await sha256Hex(new TextEncoder().encode(normalizedCsv));
  const review = {
    version: AGENT_HANDOFF_SCHEMA, format: 'agent-handoff', label: 'Connected-agent handoff · sender claims', synthetic: handoff.synthetic,
    source: { kind: 'supplied_file', authenticated: false, sha256: sourceHash, digest_scope: 'UTF-8 JSON text exactly as supplied before parsing', file_name: 'Agent handoff JSON', uploaded: false },
    normalizedCsv, rows,
    mapping: [
      { source: 'observations[].date', target: 'Observation date', explanation: 'The sender supplies the valuation date explicitly; no timestamp relabeling is inferred.' },
      { source: 'observations[].nav', target: 'Portfolio NAV', explanation: 'Exact supplied decimal value. No reconstruction from positions, prices, trade proceeds or cash alone.' },
      { source: 'observations[].external_flow', target: 'External flows', explanation: 'Explicit supplied net external flow; missing values are never replaced with zero.' },
    ],
    exceptions, canCalculate: !exceptions.some(item => item.severity === 'error'), currency: handoff.currency, frequency: handoff.frequency, corrections: [],
    coverage: { source_rows: rows.length, observations: rows.length, start: rows[0]?.date || null, end: rows.at(-1)?.date || null, accounts: handoff.account_scope },
    review: { normalized_sha256: normalizedHash, source_verified: false, flow_timing: 'interval_end_required', reviewed: false },
    agentContext: { source: handoff.source, mapping: handoff.mapping, requested_period: handoff.requested_period, coverage: handoff.coverage },
  };
  return { handoff, review };
}
