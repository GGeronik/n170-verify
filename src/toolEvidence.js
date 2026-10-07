// Original Apache-2.0 interoperability code for a supplied-output contract.
// This module has no account, calculator, signing, storage or network dependency.
export const TOOL_EVIDENCE_MAX_BYTES = 4 * 1024 * 1024;
export const TOOL_EVIDENCE_LABELS = Object.freeze({
  FINDINGS_REPORTED: 'The supplied export reports findings',
  NO_FINDINGS_REPORTED: 'The supplied export reports no findings',
  NOT_ASSESSABLE: 'The supplied export cannot be assessed',
});

const ERROR = 'Observation import rejected. Use a supported n170.tool-evidence.freqtrade-lookahead.v1 JSON report within 4 MiB. No report was authenticated.';
const SCHEMA = 'n170.tool-evidence.freqtrade-lookahead.v1';
const MAX_COUNT = 1_000_000_000;
const MAX_ROWS = 1000;
const DISCLOSURE_NOTE = 'Counts and declared scope may still disclose research information. Review before sharing.';
const LIMITATIONS = [
  'This is supplied tool output. N170 did not execute Freqtrade or authenticate its source.',
  'No findings reported describes these CSV rows only; it does not establish absence of lookahead bias.',
  'Untested signals, omitted strategies and earlier trials are not evidenced by this export.',
  'Freqtrade exports can omit unsuccessful analyses and retain rows from earlier runs; run completeness and freshness are not established.',
  'Reported indicators can include FreqAI targets, and order assumptions can cause false positives; findings require review.',
  'This report does not assess data authenticity, point-in-time validity, statistical robustness, execution realism or investment performance.',
  'Filenames, strategy names and indicator names are retained locally; review them before sharing this report.',
];
const CONTEXT_REASONS = new Set(['UNSUPPORTED_CONTEXT', 'INVALID_CONTEXT', 'UNSUPPORTED_RUN_CONFIG', 'INVALID_RUN_CONFIG', 'CONTRADICTORY_RUN_CONFIG']);
const OUTER_REASONS = new Set(['INVALID_CSV_TYPE', 'CSV_LIMIT_EXCEEDED', 'INVALID_CSV_CONTROL', 'EMPTY_EXPORT', 'DUPLICATE_COLUMNS', 'UNSUPPORTED_COLUMNS', 'ROW_LIMIT_EXCEEDED', 'MALFORMED_CSV']);
const ROW_REASONS = new Set([
  'INVALID_COUNT', 'NO_TESTED_SIGNALS', 'COUNT_LIMIT_EXCEEDED', 'INVALID_FILENAME', 'INVALID_STRATEGY',
  'UNRECOGNIZED_OR_UNSUCCESSFUL_RESULT', 'CONTRADICTORY_COUNTS', 'INDICATOR_LIMIT_EXCEEDED',
  'INVALID_INDICATORS', 'DUPLICATE_INDICATORS', 'CONTRADICTORY_BIAS_RESULT',
  'BELOW_DECLARED_EXPORT_MINIMUM', 'EXCEEDS_DECLARED_TARGET', 'MALFORMED_ROW',
  'FIELD_LIMIT_EXCEEDED', 'DUPLICATE_INDEX', 'DUPLICATE_STRATEGY',
]);
const reject = () => { throw new Error(ERROR); };
const check = condition => { if (!condition) reject(); };
const own = (value, key) => Object.hasOwn(value, key);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

function shape(value, required, optional = []) {
  check(object(value));
  check(required.every(key => own(value, key)));
  const allowed = new Set([...required, ...optional]);
  check(Object.keys(value).every(key => allowed.has(key)));
}

function count(value, min = 0, max = MAX_COUNT) {
  check(Number.isSafeInteger(value) && !Object.is(value, -0) && value >= min && value <= max);
}

function validUnicode(value) {
  for (let i = 0; i < value.length; i++) {
    const point = value.charCodeAt(i);
    if (point >= 0xd800 && point <= 0xdbff) {
      const next = value.charCodeAt(++i);
      check(next >= 0xdc00 && next <= 0xdfff);
    } else check(point < 0xdc00 || point > 0xdfff);
  }
}

// JSON.parse silently accepts duplicate members. Scan the original tokens first,
// comparing decoded keys (including escaped spellings), and bound work/depth.
function strictJson(text) {
  check(typeof text === 'string' && text.length > 0 && text.length <= TOOL_EVIDENCE_MAX_BYTES);
  validUnicode(text);
  check(new TextEncoder().encode(text).byteLength <= TOOL_EVIDENCE_MAX_BYTES);
  let offset = 0;
  let nodes = 0;
  const whitespace = () => { while (/[\x20\t\r\n]/.test(text[offset] || '') && offset < text.length) offset++; };
  const stringToken = () => {
    check(text[offset] === '"');
    const start = offset++;
    while (offset < text.length) {
      const char = text[offset++];
      if (char === '\\') { offset++; continue; }
      if (char === '"') {
        const value = JSON.parse(text.slice(start, offset));
        check(value.length <= 8192);
        validUnicode(value);
        return value;
      }
    }
    reject();
  };
  function value(depth) {
    check(depth <= 12 && ++nodes <= 160_000);
    whitespace();
    const first = text[offset];
    if (first === '"') { stringToken(); return; }
    if (first === '{' || first === '[') {
      const isObject = first === '{';
      const end = isObject ? '}' : ']';
      const keys = new Set();
      offset++;
      whitespace();
      if (text[offset] === end) { offset++; return; }
      while (true) {
        if (isObject) {
          whitespace();
          const key = stringToken();
          check(!keys.has(key) && !['__proto__', 'prototype', 'constructor'].includes(key));
          keys.add(key);
          whitespace();
          check(text[offset++] === ':');
        }
        value(depth + 1);
        whitespace();
        if (text[offset] === end) { offset++; return; }
        check(text[offset++] === ',');
      }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(offset));
    check(Boolean(token));
    offset += token[0].length;
    if (!['true', 'false', 'null'].includes(token[0])) check(Number.isFinite(Number(token[0])));
  }
  value(0);
  whitespace();
  check(offset === text.length);
  return JSON.parse(text);
}

function validateContext(context) {
  shape(context, [], ['freqtrade_version', 'run_status', 'config_sha256', 'strategy_sha256', 'data_sha256', 'expected_strategy_count', 'run_config']);
  for (const [key, value] of Object.entries(context)) {
    if (key.endsWith('_sha256')) check(typeof value === 'string' && /^[a-f0-9]{64}$/.test(value));
    else if (key === 'freqtrade_version') check(typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/.test(value));
    else if (key === 'run_status') check(['COMPLETED', 'FAILED', 'SKIPPED', 'NOT_RUN', 'CANCELLED'].includes(value));
    else if (key === 'expected_strategy_count') count(value, 1, MAX_ROWS);
    else {
      shape(value, [], ['timerange', 'timeframe', 'minimum_trade_amount', 'targeted_trade_amount', 'lookahead_allow_limit_orders']);
      for (const [setting, supplied] of Object.entries(value)) {
        if (['minimum_trade_amount', 'targeted_trade_amount'].includes(setting)) count(supplied, 1);
        else if (setting === 'lookahead_allow_limit_orders') check(typeof supplied === 'boolean');
        else if (setting === 'timeframe') check(typeof supplied === 'string' && /^[1-9][0-9]{0,5}[smhdwM]$/.test(supplied));
        else check(typeof supplied === 'string' && /^[0-9T:-]{1,64}$/.test(supplied));
      }
      if (own(value, 'minimum_trade_amount') && own(value, 'targeted_trade_amount')) check(value.minimum_trade_amount <= value.targeted_trade_amount);
    }
  }
}

function validateReport(report) {
  shape(report, ['schema', 'tool', 'evidence_class', 'status', 'tested_strategy_count', 'rows', 'reason_codes', 'limitations', 'scope'], ['disclosure', 'example_declaration']);
  check(report.schema === SCHEMA && report.tool === 'freqtrade' && report.evidence_class === 'supplied_tool_output');
  check(own(TOOL_EVIDENCE_LABELS, report.status));
  if (own(report, 'example_declaration')) check(['synthetic', 'not_declared'].includes(report.example_declaration));
  check(same(report.limitations, LIMITATIONS));
  const scope = report.scope;
  shape(scope, ['analysis', 'source_sha256', 'adapter_format_reference', 'tool_execution', 'source_authenticity', 'run_completeness', 'run_freshness', 'context_authenticity', 'declared_context', 'tested_strategy_count_basis']);
  check(scope.analysis === 'lookahead-analysis' && scope.tool_execution === 'not_performed');
  check(scope.source_authenticity === 'unverified' && scope.context_authenticity === 'unverified');
  check(scope.run_completeness === 'not_established' && scope.run_freshness === 'not_established');
  check(scope.tested_strategy_count_basis === 'valid supplied rows with positive signal counts; not independently observed tests');
  check(scope.source_sha256 === null || (typeof scope.source_sha256 === 'string' && /^[a-f0-9]{64}$/.test(scope.source_sha256)));
  shape(scope.adapter_format_reference, ['version', 'revision']);
  check(scope.adapter_format_reference.version === '2026.8' && scope.adapter_format_reference.revision === '9f10e357a93c1dcf10c2a2b367659214d89c073e');
  validateContext(scope.declared_context);

  let labelsIncluded = true;
  if (own(report, 'disclosure')) {
    shape(report.disclosure, ['source_text_included', 'strategy_labels_included', 'note']);
    check(report.disclosure.source_text_included === false && typeof report.disclosure.strategy_labels_included === 'boolean');
    check(report.disclosure.note === DISCLOSURE_NOTE);
    labelsIncluded = report.disclosure.strategy_labels_included;
  }
  check(Array.isArray(report.rows) && report.rows.length <= MAX_ROWS);
  const rowErrors = new Set();
  const identities = new Set();
  let validRows = 0;
  let findings = false;
  const config = scope.declared_context.run_config || {};
  for (const [index, row] of report.rows.entries()) {
    const invalid = row?.status === 'NOT_ASSESSABLE';
    const base = ['row_number', 'status', 'reason_codes'];
    const labels = ['filename', 'strategy', 'biased_indicators'];
    shape(row, invalid ? base : [...base, 'has_bias', 'total_signals', 'biased_entry_signals', 'biased_exit_signals', ...(labelsIncluded ? labels : [])], ['display_label']);
    check(row.row_number === index + 1);
    if (own(row, 'display_label')) {
      check(typeof row.display_label === 'string' && row.display_label.length >= 1 && row.display_label.length <= 128);
      check(!/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/.test(row.display_label));
    }
    check(Array.isArray(row.reason_codes) && row.reason_codes.length === 1);
    if (invalid) {
      check(ROW_REASONS.has(row.reason_codes[0]));
      rowErrors.add(row.reason_codes[0]);
      continue;
    }
    check(typeof row.has_bias === 'boolean');
    check(row.status === (row.has_bias ? 'FINDINGS_REPORTED' : 'NO_FINDINGS_REPORTED'));
    check(row.reason_codes[0] === (row.has_bias ? 'UPSTREAM_FINDINGS_REPORTED' : 'NO_FINDINGS_IN_SUPPLIED_ROW'));
    count(row.total_signals, 1);
    count(row.biased_entry_signals, 0, row.total_signals);
    count(row.biased_exit_signals, 0, row.total_signals);
    if (own(config, 'minimum_trade_amount')) check(row.total_signals > config.minimum_trade_amount);
    if (own(config, 'targeted_trade_amount')) check(row.total_signals <= config.targeted_trade_amount);
    if (labelsIncluded) {
      check(typeof row.filename === 'string' && /^[A-Za-z0-9_][A-Za-z0-9_. -]{0,127}$/.test(row.filename));
      check(typeof row.strategy === 'string' && /^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(row.strategy));
      const identity = `${row.filename}\n${row.strategy}`;
      check(!identities.has(identity));
      identities.add(identity);
      check(Array.isArray(row.biased_indicators) && row.biased_indicators.length <= 128);
      check(row.biased_indicators.every(item => typeof item === 'string' && /^[A-Za-z0-9_&%][A-Za-z0-9_.:&% +/()=-]{0,127}$/.test(item)));
      check(new Set(row.biased_indicators).size === row.biased_indicators.length && row.biased_indicators.join(',').length <= 8192);
      check(row.has_bias === Boolean(row.biased_entry_signals || row.biased_exit_signals || row.biased_indicators.length));
    } else if (!row.has_bias) check(row.biased_entry_signals === 0 && row.biased_exit_signals === 0);
    validRows++;
    findings ||= row.has_bias;
  }
  count(report.tested_strategy_count, 0, MAX_ROWS);
  check(report.tested_strategy_count === validRows);
  check(Array.isArray(report.reason_codes) && report.reason_codes.length >= 1 && report.reason_codes.length <= 32);
  check(report.reason_codes.every(reason => typeof reason === 'string') && new Set(report.reason_codes).size === report.reason_codes.length);
  const reasons = new Set(report.reason_codes);
  const contextErrors = [...reasons].filter(reason => CONTEXT_REASONS.has(reason));
  const outerErrors = [...reasons].filter(reason => OUTER_REASONS.has(reason));
  check(contextErrors.length <= 1 && outerErrors.length <= 1);
  if (contextErrors.length) check(Object.keys(scope.declared_context).length === 0);
  const expectedErrors = new Set([...rowErrors, ...contextErrors, ...outerErrors]);
  if (own(scope.declared_context, 'run_status') && scope.declared_context.run_status !== 'COMPLETED') expectedErrors.add('DECLARED_RUN_NOT_COMPLETED');
  if (own(scope.declared_context, 'expected_strategy_count') && scope.declared_context.expected_strategy_count !== validRows) expectedErrors.add('DECLARED_STRATEGY_COUNT_MISMATCH');
  for (const reason of outerErrors) {
    if (reason === 'ROW_LIMIT_EXCEEDED') check(report.rows.length === MAX_ROWS);
    else if (reason !== 'MALFORMED_CSV') check(report.rows.length === 0);
    if (['INVALID_CSV_TYPE', 'CSV_LIMIT_EXCEEDED'].includes(reason)) check(scope.source_sha256 === null);
    else if (reason !== 'MALFORMED_CSV') check(scope.source_sha256 !== null);
  }
  if (scope.source_sha256 === null) check(report.rows.length === 0 && outerErrors.some(reason => ['INVALID_CSV_TYPE', 'CSV_LIMIT_EXCEEDED', 'MALFORMED_CSV'].includes(reason)));
  if (!report.rows.length) check(outerErrors.length === 1);
  if (expectedErrors.size) {
    check(report.status === 'NOT_ASSESSABLE' && reasons.size === expectedErrors.size && [...reasons].every(reason => expectedErrors.has(reason)));
  } else {
    check(report.rows.length > 0 && report.status === (findings ? 'FINDINGS_REPORTED' : 'NO_FINDINGS_REPORTED'));
    check(same(report.reason_codes, [findings ? 'UPSTREAM_FINDINGS_REPORTED' : 'NO_FINDINGS_IN_SUPPLIED_ROWS']));
  }
  return report;
}

/** Validate this exact supplied-output v1 contract. Never authenticate its claims. */
export function parseToolEvidence(text) {
  try { return validateReport(strictJson(text)); }
  catch { throw new Error(ERROR); }
}

/** Explicit sharing copy. Even indicator-only findings survive label removal. */
export function makeToolEvidenceExport(report, { includeLabels = false } = {}) {
  check(typeof includeLabels === 'boolean');
  let copy;
  try { copy = parseToolEvidence(JSON.stringify(report)); }
  catch { reject(); }
  // Missing labels cannot be recovered by opting in after a redacted import.
  const available = !copy.disclosure || copy.disclosure.strategy_labels_included;
  const retainLabels = includeLabels && available;
  copy.rows.forEach((row, index) => {
    if (!retainLabels) {
      delete row.filename;
      delete row.strategy;
      delete row.biased_indicators;
    }
    row.display_label = retainLabels ? (row.strategy || `Strategy ${index + 1}`) : `Strategy ${index + 1}`;
  });
  copy.disclosure = { source_text_included: false, strategy_labels_included: retainLabels, note: DISCLOSURE_NOTE };
  return parseToolEvidence(JSON.stringify(copy));
}
