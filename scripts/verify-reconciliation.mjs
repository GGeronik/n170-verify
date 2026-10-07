#!/usr/bin/env node
// Independent, offline private-source checker. Never import the producer in src/.
// Output is deliberately a fixed vocabulary: no input-derived diagnostic text.
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { extractEvidence, verifyEvidence } from './verify-record.mjs';
import { readBoundedUtf8, parseStrictJson, validatePrivateArtifact } from './reconciliation-input.mjs';
import { reconstructSource, calculateIntervals } from './reconciliation-source.mjs';

const EXIT = Object.freeze({ VERIFIED_UNDER_OWNER_ASSERTIONS: 0, MISMATCH: 1, NOT_ASSESSABLE: 2, INVALID_INPUT: 3 });
const HASH = /^[a-f0-9]{64}$/;
const hash = value => createHash('sha256').update(value).digest('hex');
const equal = isDeepStrictEqual;
const day = 86400000;
const date = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value;
const currencies = ['USD', 'EUR', 'GBP', 'CHF', 'CAD', 'AUD', 'JPY'];
const error = (status, code) => Object.assign(new Error(code), { status, code });
const assertions = Object.freeze([
  'ACCOUNT_ALIAS_AND_ACCOUNT_ID_LINK_NOT_ESTABLISHED', 'FLOW_TIMING_IS_OWNER_ASSERTION',
  'HIDDEN_FLOW_REVIEW_IS_OWNER_ASSERTION', 'SCHEDULE_IS_OWNER_ASSERTION',
  'EXCLUSIONS_AND_SUPERSESSION_ARE_OWNER_ASSERTIONS', 'SOURCE_AUTHENTICITY_NOT_ESTABLISHED',
  'ACCOUNT_COMPLETENESS_NOT_ESTABLISHED', 'IDENTITY_NOT_ESTABLISHED', 'INDEPENDENT_PUBLICATION_NOT_ESTABLISHED',
]);

function summary() {
  return {
    schema: 'n170.private-source-check.v1', checker_version: '1.0.0', status: 'NOT_ASSESSABLE', reasons: [],
    selected_event: null,
    checks: { signed_profile: false, source_bytes: false, source_normalization: false, signed_source_commitments: false, signed_scope: false, signed_returns: false, private_intervals: false },
    counts: { retained_sources: 0, observations: 0, intervals: 0 },
    source_decisions: [], currency_evidence: 'unassessed', limitations: [...assertions],
  };
}

function runCheck(recordText, privateText, eventSha256, result) {
  if (typeof eventSha256 !== 'string' || !HASH.test(eventSha256)) throw error('INVALID_INPUT', 'INVALID_EVENT_SELECTION');
  if (typeof recordText !== 'string' || Buffer.byteLength(recordText) > 2000000 || recordText.startsWith('\uFEFF')) throw error('INVALID_INPUT', 'INVALID_RECORD_TRANSPORT');
  const reconciliation = validatePrivateArtifact(parseStrictJson(privateText));
  let verified;
  try {
    // Apply the stronger input policy to JSON even when it was carried by HTML.
    parseStrictJson(extractEvidence(recordText));
    verified = verifyEvidence(recordText);
  } catch { throw error('INVALID_INPUT', 'INVALID_SIGNED_RECORD'); }
  const stamps = verified.profile.stamps;
  const matches = stamps.filter(stamp => stamp.sha256 === eventSha256);
  if (matches.length !== 1) throw error('INVALID_INPUT', 'EVENT_NOT_FOUND');
  const stamp = matches[0], payload = stamp.payload;
  result.checks.signed_profile = true;
  result.selected_event = {
    sequence: payload.sequence,
    event_type: payload.schema_version === 'n170.verify.performance-stamp.v4' ? payload.event_type : 'legacy',
    superseded: stamps.some(s => s.payload.correction?.target_sha256 === stamp.sha256),
  };
  const issues = [];
  const add = (status, code) => { if (!issues.some(i => i.status === status && i.code === code)) issues.push({ status, code }); };
  const mismatch = code => add('MISMATCH', code);
  const unsupported = code => add('NOT_ASSESSABLE', code);
  const sources = reconciliation.source_inventory;
  result.counts.retained_sources = sources.length;
  const activeSources = sources.filter(source => source.disposition === 'active');
  if (activeSources.length !== 1) throw error('INVALID_INPUT', 'INVALID_ACTIVE_SOURCE');
  let totalBytes = 0, allBytesBound = true, decodedActiveText = null;
  for (let index = 0; index < sources.length; index++) {
    const source = sources[index];
    const decision = {
      ordinal: index + 1, disposition: source.disposition, bytes_available: source.source_bytes_available,
      byte_binding: 'unavailable', text_decoding: 'unavailable', reason_present: source.reason.trim().length >= 3,
    };
    result.source_decisions.push(decision);
    if (source.disposition === 'unresolved') unsupported('UNRESOLVED_SOURCE');
    if (['excluded', 'superseded'].includes(source.disposition) && !decision.reason_present) unsupported('SOURCE_DECISION_REASON_REQUIRED');
    if (!source.source_bytes_available) {
      allBytesBound = false;
      if (source.disposition === 'active') unsupported('SOURCE_BYTES_UNAVAILABLE');
      else if (!result.limitations.includes('RETAINED_SOURCE_BYTES_UNAVAILABLE')) result.limitations.push('RETAINED_SOURCE_BYTES_UNAVAILABLE');
      continue;
    }
    const bytes = Buffer.from(source.bytes_base64, 'base64');
    if (bytes.toString('base64') !== source.bytes_base64) throw error('INVALID_INPUT', 'INVALID_SOURCE_BASE64');
    totalBytes += bytes.length;
    if (totalBytes > 10 * 1024 * 1024) throw error('INVALID_INPUT', 'SOURCE_BYTE_LIMIT');
    let text = null;
    try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); decision.text_decoding = 'valid_utf8'; }
    catch {
      decision.text_decoding = 'invalid_utf8';
      if (source.disposition === 'active') unsupported('ACTIVE_SOURCE_INVALID_UTF8');
      else if (!result.limitations.includes('RETAINED_SOURCE_UTF8_UNDECODABLE')) result.limitations.push('RETAINED_SOURCE_UTF8_UNDECODABLE');
    }
    if (source.disposition === 'active') decodedActiveText = text;
    const digest = hash(bytes);
    const bound = bytes.length === source.byte_length && digest === source.sha256 && digest === source.id && text === source.text;
    decision.byte_binding = bound ? 'matched' : 'mismatch';
    if (!bound) { mismatch('SOURCE_COMMITMENT_MISMATCH'); allBytesBound = false; }
  }
  result.checks.source_bytes = allBytesBound;
  if (reconciliation.rejected_source_entries.length) unsupported('REJECTED_SOURCE_ENTRIES');
  if (reconciliation.missing_boundaries.length) unsupported('MISSING_BOUNDARIES');
  if (reconciliation.blocking_issues.length) unsupported('PRIVATE_RECONCILIATION_BLOCKED');
  if (reconciliation.intervals.some(interval => interval.status !== 'calculable' || interval.blocking_reasons.length)) unsupported('PRIVATE_INTERVAL_UNRESOLVED');
  const source = activeSources[0], scope = reconciliation.scope;
  if (hash(reconciliation.normalizedCsv) !== reconciliation.normalized_sha256) mismatch('NORMALIZED_COMMITMENT_MISMATCH');
  if (!reconciliation.canCalculate || reconciliation.selected_scope_status === 'blocked') unsupported('PRIVATE_RECONCILIATION_BLOCKED');
  if (!reconciliation.intervals.length) unsupported('PRIVATE_INTERVALS_UNAVAILABLE');
  if (sources.some(item => item.inspection_truncated)) unsupported('SOURCE_INSPECTION_TRUNCATED');
  if (source.issues.some(item => item.severity === 'error')) unsupported('ACTIVE_SOURCE_REVIEW_BLOCKED');
  const modern = payload.schema_version === 'n170.verify.performance-stamp.v4';
  if (!modern) unsupported('UNSUPPORTED_SIGNED_VERSION');
  const provenance = modern ? payload.provenance : null;
  if (modern && provenance.kind !== 'supplied_file') unsupported('SOURCE_NOT_COMMITTED');
  const preparationCorrections = reconciliation.corrections.length || reconciliation.review?.corrections?.length || sources.some(s => s.review?.corrections?.length) || provenance?.corrections?.length;
  if (preparationCorrections) unsupported('UNSUPPORTED_PREPARATION_CORRECTIONS');
  // These commitments are assessable even when CSV economics are unsupported.
  // Never let an unsupported source condition hide an established contradiction.
  if (!preparationCorrections && source.source_bytes_available) {
    const sourceDigest = hash(Buffer.from(source.bytes_base64, 'base64'));
    if (provenance?.kind === 'supplied_file' && (provenance.original_sha256 !== sourceDigest || provenance.source_sha256 !== sourceDigest || provenance.normalized_sha256 !== hash(reconciliation.normalizedCsv) || provenance.format !== source.format)) mismatch('SIGNED_SOURCE_COMMITMENT_MISMATCH');
    for (const review of [reconciliation.review, source.review]) {
      if (!review) continue;
      if (review.source.sha256 !== sourceDigest || review.format !== source.format || (review.original_source_sha256 && review.original_source_sha256 !== sourceDigest)) mismatch('SOURCE_COMMITMENT_MISMATCH');
      if (review.review.normalized_sha256 !== hash(review.normalizedCsv)) mismatch('NORMALIZED_COMMITMENT_MISMATCH');
    }
  }
  if (!['n170', 'ibkr-flex'].includes(source.format)) unsupported('UNSUPPORTED_FORMAT');
  if (!currencies.includes(scope.currency)) unsupported('UNSUPPORTED_CURRENCY');
  if (scope.flow_activity !== 'reviewed_no_hidden') unsupported(scope.flow_activity === 'offsetting' ? 'OFFSETTING_FLOWS_UNSUPPORTED' : 'FLOW_ACTIVITY_UNKNOWN');
  if (scope.flow_timing !== 'interval_end') unsupported(scope.flow_timing === 'intraperiod' ? 'INTRAPERIOD_FLOW_UNSUPPORTED' : 'FLOW_TIMING_UNKNOWN');
  if (!Number.isInteger(scope.periods_per_year) || scope.periods_per_year < 1 || scope.periods_per_year > 366) unsupported('UNSUPPORTED_FREQUENCY');
  if (!['observed_boundaries', 'calendar_daily', 'weekdays'].includes(scope.expected_schedule)) unsupported('UNSUPPORTED_SCHEDULE');
  if (!date(scope.period.start) || !date(scope.period.end) || scope.period.start >= scope.period.end) unsupported('INVALID_SELECTED_PERIOD');
  if (!scope.account_alias.trim()) unsupported('ACCOUNT_SCOPE_REQUIRED');

  let reconstructed = null, calculated = null;
  if (source.source_bytes_available && decodedActiveText !== null && ['n170', 'ibkr-flex'].includes(source.format)) {
    try { reconstructed = reconstructSource(decodedActiveText, { format: source.format, currency: scope.currency }); }
    catch (failure) {
      if (!['MISMATCH', 'NOT_ASSESSABLE', 'INVALID_INPUT'].includes(failure.status)) throw error('INVALID_INPUT', 'SOURCE_RECONSTRUCTION_FAILED');
      if (failure.status === 'INVALID_INPUT') throw failure;
      add(failure.status, failure.code);
    }
  }
  if (reconstructed) {
    const { rows, normalizedCsv, mapping } = reconstructed;
    result.counts.observations = rows.length;
    result.currency_evidence = reconstructed.currencyEvidence;
    if (reconstructed.currencyEvidence === 'owner_assertion') result.limitations.push('CURRENCY_IS_OWNER_ASSERTION');
    if (source.source_rows !== reconstructed.sourceRows) mismatch('PRIVATE_SOURCE_ROW_COUNT_MISMATCH');
    // Preparation edits need an independent edit-chain contract, not a guessed repair.
    if (!preparationCorrections) {
      const digest = hash(normalizedCsv), sourceDigest = hash(Buffer.from(source.bytes_base64, 'base64'));
      const normalizationMatches = reconciliation.normalizedCsv === normalizedCsv && reconciliation.normalized_sha256 === digest;
      if (!normalizationMatches) mismatch('NORMALIZED_COMMITMENT_MISMATCH');
      result.checks.source_normalization = normalizationMatches;
      for (const review of [reconciliation.review, source.review]) {
        if (!review) { unsupported('SOURCE_IMPORT_REVIEW_UNAVAILABLE'); continue; }
        if (!review.canCalculate || review.exceptions.some(item => item.severity === 'error')) unsupported('SOURCE_IMPORT_REVIEW_BLOCKED');
        if (review.source.sha256 !== sourceDigest || review.format !== source.format || (review.original_source_sha256 && review.original_source_sha256 !== sourceDigest)) mismatch('SOURCE_COMMITMENT_MISMATCH');
        if (review.normalizedCsv !== normalizedCsv || review.review.normalized_sha256 !== digest) mismatch('NORMALIZED_COMMITMENT_MISMATCH');
        if (review.currency !== scope.currency || !equal(review.mapping.map(m => ({ field: m.target, column: m.source })), mapping)) mismatch('PRIVATE_IMPORT_MAPPING_MISMATCH');
        if (!equal(review.rows.map(row => ({ date: row.date, nav: row.nav, flow: row.flow, sourceRow: row.sourceRow })), rows.map(row => ({ date: row.date, nav: row.nav, flow: row.flow, sourceRow: row.sourceRow })))) mismatch('PRIVATE_IMPORT_ROWS_MISMATCH');
        if (review.coverage.source_rows !== reconstructed.sourceRows || review.coverage.observations !== rows.length || review.coverage.start !== rows[0].date || review.coverage.end !== rows.at(-1).date) mismatch('PRIVATE_IMPORT_COVERAGE_MISMATCH');
      }
      if (provenance?.kind === 'supplied_file') {
        const bound = provenance.original_sha256 === sourceDigest && provenance.source_sha256 === sourceDigest && provenance.normalized_sha256 === digest && provenance.format === source.format && equal(provenance.mapping, mapping);
        result.checks.signed_source_commitments = bound;
        if (!bound) mismatch('SIGNED_SOURCE_COMMITMENT_MISMATCH');
      }
      try { calculated = calculateIntervals(rows); }
      catch (failure) {
        if (!['MISMATCH', 'NOT_ASSESSABLE', 'INVALID_INPUT'].includes(failure.status)) throw error('INVALID_INPUT', 'CALCULATION_FAILED');
        if (failure.status === 'INVALID_INPUT') throw failure;
        add(failure.status, failure.code);
      }
    }
    const first = rows[0]?.date, last = rows.at(-1)?.date;
    if (first !== scope.period.start || last !== scope.period.end) mismatch('PRIVATE_SCOPE_MISMATCH');
    if (date(scope.period.start) && date(scope.period.end) && scope.period.start < scope.period.end && ['calendar_daily', 'weekdays'].includes(scope.expected_schedule)) {
      const start = Date.parse(scope.period.start), end = Date.parse(scope.period.end);
      if ((end - start) / day > 5000) unsupported('SCHEDULE_RANGE_EXCEEDED');
      else {
        const dates = new Set(rows.map(row => row.date));
        for (let cursor = start; cursor <= end; cursor += day) {
          const d = new Date(cursor), weekday = d.getUTCDay();
          if ((cursor === start || cursor === end || scope.expected_schedule === 'calendar_daily' || (weekday !== 0 && weekday !== 6)) && !dates.has(d.toISOString().slice(0, 10))) unsupported('MISSING_BOUNDARIES');
        }
      }
    }
  }
  if (provenance) {
    const bound = provenance.currency === scope.currency && provenance.account_scope === scope.account_alias.trim() && payload.periods_per_year === scope.periods_per_year && equal(payload.period, scope.period);
    result.checks.signed_scope = bound;
    if (!bound) mismatch('SIGNED_SCOPE_MISMATCH');
  }
  if (calculated) {
    result.counts.intervals = calculated.intervals.length;
    const returnsMatch = equal(payload.period, calculated.period) && equal(payload.relative_returns, calculated.relative_returns) && equal(payload.coverage, calculated.coverage);
    result.checks.signed_returns = returnsMatch;
    if (!returnsMatch) mismatch('SIGNED_RETURNS_MISMATCH');
    const privateIntervals = reconciliation.intervals;
    const missing = reconciliation.missing_boundaries.length > 0;
    let privateMatch = !missing && privateIntervals.length === calculated.intervals.length;
    if (!privateMatch && !missing) mismatch('PRIVATE_INTERVAL_MISMATCH');
    if (!missing && privateIntervals.length === calculated.intervals.length) {
      for (let index = 0; index < calculated.intervals.length; index++) {
        const expected = calculated.intervals[index], supplied = privateIntervals[index];
        for (const key of Object.keys(expected)) {
          // Unknown computed values remain unresolved, never rewritten to zero.
          if (supplied[key] === null && supplied.status === 'unresolved') { privateMatch = false; continue; }
          if (supplied[key] !== expected[key]) { privateMatch = false; mismatch('PRIVATE_INTERVAL_MISMATCH'); }
        }
        const opening = reconstructed.rows[index], closing = reconstructed.rows[index + 1];
        const dependencies = [
          { role: 'opening', row: opening, normalized: index + 1 },
          { role: 'closing', row: closing, normalized: index + 2 },
          { role: 'flow', row: closing, normalized: index + 2 },
        ];
        if (supplied.dependencies.length !== 3) { privateMatch = false; mismatch('PRIVATE_DEPENDENCY_MISMATCH'); }
        else for (let j = 0; j < 3; j++) {
          const given = supplied.dependencies[j], expectedDependency = dependencies[j];
          if (given.role !== expectedDependency.role || given.source_sha256 !== source.sha256 || given.source_row !== expectedDependency.row.sourceRow || given.source_ref !== null || given.normalized_row !== expectedDependency.normalized || given.date !== expectedDependency.row.date || given.value !== (given.role === 'flow' ? expectedDependency.row.flow : expectedDependency.row.nav) || given.missing !== false || given.correction_steps.length !== 0) {
            privateMatch = false; mismatch('PRIVATE_DEPENDENCY_MISMATCH');
          }
        }
      }
    }
    result.checks.private_intervals = privateMatch;
  }
  // Required positive findings cannot be supplied by flags in the artifact.
  if (!calculated && !issues.length) unsupported('CALCULATION_UNAVAILABLE');
  const priority = ['INVALID_INPUT', 'MISMATCH', 'NOT_ASSESSABLE'];
  result.status = priority.find(status => issues.some(issue => issue.status === status)) || 'VERIFIED_UNDER_OWNER_ASSERTIONS';
  result.reasons = issues.map(issue => issue.code).sort();
  return result;
}

export function verifyReconciliation(recordText, privateText, eventSha256) {
  const result = summary();
  try { return runCheck(recordText, privateText, eventSha256, result); }
  catch (failure) {
    // Only internally assigned fixed identifiers can cross the privacy boundary.
    result.status = 'INVALID_INPUT';
    result.reasons = [failure?.status === 'INVALID_INPUT' && /^[A-Z][A-Z0-9_]{0,79}$/.test(failure.code) ? failure.code : 'INVALID_INPUT'];
    return result;
  }
}

export function runCli(args) {
  if (args.length === 1 && args[0] === '--help') return { exitCode: 0, output: 'Usage: node scripts/verify-reconciliation.mjs --record signed-record.json --event-sha256 EVENT_SHA256 --reconciliation n170-private-reconciliation.json\nOffline check of one existing signed v4 event against private source bytes. EVENT_SHA256 must be its lowercase 64-hex payload digest.\nExits: 0 VERIFIED_UNDER_OWNER_ASSERTIONS; 1 MISMATCH; 2 NOT_ASSESSABLE; 3 INVALID_INPUT. No paths or private financial values are printed.\n' };
  const options = new Map();
  try {
    if (args.length !== 6) throw error('INVALID_INPUT', 'INVALID_ARGUMENTS');
    for (let i = 0; i < args.length; i += 2) {
      const flag = args[i], value = args[i + 1];
      if (!['--record', '--event-sha256', '--reconciliation'].includes(flag) || options.has(flag) || typeof value !== 'string' || !value || value.startsWith('--')) throw error('INVALID_INPUT', 'INVALID_ARGUMENTS');
      options.set(flag, value);
    }
    if (!HASH.test(options.get('--event-sha256'))) throw error('INVALID_INPUT', 'INVALID_EVENT_SELECTION');
    const record = readBoundedUtf8(options.get('--record'), 2000000);
    const artifact = readBoundedUtf8(options.get('--reconciliation'), 32 * 1024 * 1024);
    const result = verifyReconciliation(record, artifact, options.get('--event-sha256'));
    return { exitCode: EXIT[result.status], output: `${JSON.stringify(result)}\n` };
  } catch (failure) {
    const result = summary(); result.status = 'INVALID_INPUT';
    result.reasons = [failure?.status === 'INVALID_INPUT' && /^[A-Z][A-Z0-9_]{0,79}$/.test(failure.code) ? failure.code : 'INPUT_READ_FAILED'];
    return { exitCode: 3, output: `${JSON.stringify(result)}\n` };
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = runCli(process.argv.slice(2)); process.stdout.write(result.output); process.exitCode = result.exitCode;
}
