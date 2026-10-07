import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseToolEvidence, makeToolEvidenceExport, TOOL_EVIDENCE_MAX_BYTES, TOOL_EVIDENCE_LABELS } from '../src/toolEvidence.js';

const fixtures = Object.fromEntries(await Promise.all(['clean', 'findings', 'failed', 'insufficient'].map(async name => [name, JSON.parse(await readFile(new URL(`../examples/tool-evidence-${name}.json`, import.meta.url), 'utf8'))])));
const clone = value => structuredClone(value);
const parse = value => parseToolEvidence(JSON.stringify(value));
const mutate = (edit, original = fixtures.findings) => { const value = clone(original); edit(value); return value; };
const error = (() => { try { parseToolEvidence('{}'); } catch (error) { return error.message; } })();
const rejected = value => assert.throws(() => typeof value === 'string' ? parseToolEvidence(value) : parse(value), caught => caught instanceof Error && caught.message === error);
const raw = fixture => mutate(value => {
  delete value.disclosure;
  delete value.example_declaration;
  value.rows.forEach(row => { delete row.display_label; });
}, fixture);

test('frozen-toolkit synthetic outputs preserve each supported conclusion and usable count', () => {
  for (const [name, status, count, reasons] of [
    ['clean', 'NO_FINDINGS_REPORTED', 2, ['NO_FINDINGS_IN_SUPPLIED_ROWS']],
    ['findings', 'FINDINGS_REPORTED', 2, ['UPSTREAM_FINDINGS_REPORTED']],
    ['failed', 'NOT_ASSESSABLE', 2, ['DECLARED_RUN_NOT_COMPLETED']],
    ['insufficient', 'NOT_ASSESSABLE', 1, ['NO_TESTED_SIGNALS', 'DECLARED_STRATEGY_COUNT_MISMATCH']],
  ]) {
    const report = parse(fixtures[name]);
    assert.equal(report.status, status, name);
    assert.equal(report.tested_strategy_count, count, name);
    assert.deepEqual(report.reason_codes, reasons, name);
    assert.equal(report.example_declaration, 'synthetic');
    assert.equal(report.scope.source_authenticity, 'unverified');
    assert.equal(report.scope.run_completeness, 'not_established');
    assert.equal(report.scope.run_freshness, 'not_established');
    assert.ok(TOOL_EVIDENCE_LABELS[status]);
  }
  assert.equal(parse(fixtures.failed).rows[0].status, 'FINDINGS_REPORTED');
  assert.equal(parse(fixtures.insufficient).rows[0].status, 'NOT_ASSESSABLE');
  assert.equal(parse(fixtures.insufficient).rows[1].status, 'NO_FINDINGS_REPORTED');
});

test('raw assess_lookahead output is accepted without inventing synthetic or sharing declarations', () => {
  const report = parse(raw(fixtures.clean));
  assert.equal(Object.hasOwn(report, 'disclosure'), false);
  assert.equal(Object.hasOwn(report, 'example_declaration'), false);
  assert.equal(report.rows[0].strategy, 'SyntheticAlpha');
});

test('default sharing removes private labels and preserves indicator-only findings and source limitations', () => {
  const input = mutate(report => { report.rows[0].display_label = 'Private research name'; });
  const before = clone(input);
  const shared = makeToolEvidenceExport(input);
  assert.deepEqual(input, before, 'caller data must not be modified');
  assert.equal(shared.example_declaration, 'synthetic');
  assert.equal(shared.status, 'FINDINGS_REPORTED');
  assert.equal(shared.rows[0].has_bias, true);
  assert.equal(shared.rows[0].biased_entry_signals, 0);
  assert.equal(shared.rows[0].biased_exit_signals, 0);
  assert.deepEqual(shared.rows.map(row => row.display_label), ['Strategy 1', 'Strategy 2']);
  for (const row of shared.rows) for (const key of ['filename', 'strategy', 'biased_indicators']) assert.equal(Object.hasOwn(row, key), false);
  for (const privateLabel of ['synthetic_alpha.py', 'SyntheticAlpha', 'future_window', 'forward_close', 'Private research name']) assert.equal(JSON.stringify(shared).includes(privateLabel), false);
  assert.equal(shared.disclosure.strategy_labels_included, false);
  assert.equal(shared.disclosure.source_text_included, false);
  assert.deepEqual(shared.scope, input.scope);
  assert.deepEqual(shared.limitations, input.limitations);
  assert.deepEqual(parse(shared), shared, 'redacted findings remain a supported import');
});

test('explicit label inclusion retains available labels without claiming to recover missing ones', () => {
  const included = makeToolEvidenceExport(fixtures.findings, { includeLabels: true });
  assert.equal(included.disclosure.strategy_labels_included, true);
  assert.deepEqual(included.rows[0].biased_indicators, ['future_window', 'forward_close']);
  assert.equal(included.rows[0].display_label, 'SyntheticAlpha');
  const redacted = makeToolEvidenceExport(included);
  const stillRedacted = makeToolEvidenceExport(redacted, { includeLabels: true });
  assert.equal(stillRedacted.disclosure.strategy_labels_included, false);
  assert.equal(stillRedacted.rows[0].has_bias, true);
  assert.equal(Object.hasOwn(stillRedacted.rows[0], 'strategy'), false);
});

test('all fixtures survive both deliberate export choices without changing assessment', () => {
  for (const input of Object.values(fixtures)) for (const includeLabels of [false, true]) {
    const result = makeToolEvidenceExport(input, { includeLabels });
    assert.equal(result.status, input.status);
    assert.equal(result.tested_strategy_count, input.tested_strategy_count);
    assert.deepEqual(result.reason_codes, input.reason_codes);
    assert.equal(result.example_declaration, 'synthetic');
  }
});

test('unsupported schemas, versions, evidence classes and forged trust flags fail closed', () => {
  const edits = [
    report => { report.schema = 'n170.tool-evidence.freqtrade-lookahead.v2'; },
    report => { report.schema = 'n170.tool-evidence.error.v1'; },
    report => { report.schema = 'n170.research-eight-dimensions.v1'; },
    report => { report.tool = 'auditzk'; },
    report => { report.evidence_class = 'authenticated_execution'; },
    report => { report.example_declaration = 'real'; },
    report => { report.scope.adapter_format_reference.version = '2026.9'; },
    report => { report.scope.adapter_format_reference.revision = '0'.repeat(40); },
    report => { report.scope.analysis = 'complete-research'; },
    report => { report.scope.source_authenticity = 'verified'; },
    report => { report.scope.context_authenticity = 'verified'; },
    report => { report.scope.tool_execution = 'performed'; },
    report => { report.scope.run_completeness = 'established'; },
    report => { report.scope.run_freshness = 'established'; },
    report => { report.scope.tested_strategy_count_basis = 'independently observed'; },
    report => { report.limitations.pop(); },
    report => { report.limitations[0] = 'Authenticated'; },
    report => { report.disclosure.source_text_included = true; },
    report => { report.disclosure.note = ''; },
  ];
  for (const edit of edits) rejected(mutate(edit));
});

test('unknown fields and prototype-shaped members are rejected at every nesting level', () => {
  for (const edit of [
    report => { report.signature = 'forged'; },
    report => { report.scope.authenticated = true; },
    report => { report.scope.adapter_format_reference.verified = true; },
    report => { report.scope.declared_context.command = 'upload'; },
    report => { report.scope.declared_context.run_config.url = 'https://example.invalid'; },
    report => { report.rows[0].authenticated = true; },
    report => { report.disclosure.authenticated = true; },
  ]) rejected(mutate(edit));
  const source = JSON.stringify(fixtures.findings);
  for (const name of ['__proto__', 'constructor', 'prototype']) rejected(`{"${name}":{},${source.slice(1)}`);
  assert.equal({}.authenticated, undefined);
});

test('duplicate keys are rejected including escaped names and nested declarations', () => {
  const source = JSON.stringify(fixtures.findings);
  rejected(`{"schema":"${fixtures.findings.schema}",${source.slice(1)}`);
  rejected(`{"\\u0073chema":"${fixtures.findings.schema}",${source.slice(1)}`);
  rejected(source.replace('"source_authenticity":"unverified"', '"source_authenticity":"verified","source_authenticity":"unverified"'));
  rejected(source.replace('"timeframe":"1h"', '"timeframe":"1h","\\u0074imeframe":"1h"'));
});

test('malformed JSON and parser limits produce one safe error without echoing input', () => {
  for (const input of ['', 'null', '[]', 'true', '{', '{"PRIVATE_SECRET":', '\ufeff{}', '{} trailing', '{"x":NaN}', '{"x":1e999}', '{"x":01}', '{"x":true,}', '{"x":[true,]}', '{"x":"\\ud800"}', '{"x":"\\udfff"}', '{"x":"\u0000"}', '{"x":"\\q"}', ' '.repeat(TOOL_EVIDENCE_MAX_BYTES + 1), '['.repeat(50) + '0' + ']'.repeat(50), '{"x":"' + 'x'.repeat(8193) + '"}']) rejected(input);
  assert.equal(error.includes('PRIVATE_SECRET'), false);
  assert.throws(() => parseToolEvidence({}), { message: error });
  const manyUtf8Bytes = ' '.repeat(TOOL_EVIDENCE_MAX_BYTES - 3) + '🧪';
  assert.ok(manyUtf8Bytes.length < TOOL_EVIDENCE_MAX_BYTES);
  rejected(manyUtf8Bytes);
});

test('disclosure and labels cannot contradict one another', () => {
  rejected(mutate(report => { report.disclosure.strategy_labels_included = false; }));
  rejected(mutate(report => { delete report.rows[0].strategy; }));
  const redacted = makeToolEvidenceExport(fixtures.findings);
  rejected(mutate(report => { report.disclosure.strategy_labels_included = true; }, redacted));
  rejected(mutate(report => { delete report.disclosure; }, redacted));
  rejected(mutate(report => { report.rows[0].biased_indicators = []; }));
});

test('counts, row positions and status summaries must agree', () => {
  const edits = [
    report => { report.tested_strategy_count = 1; },
    report => { report.tested_strategy_count = true; },
    report => { report.rows[0].row_number = 2; },
    report => { report.rows[0].total_signals = 0; },
    report => { report.rows[0].total_signals = -1; },
    report => { report.rows[0].total_signals = '40'; },
    report => { report.rows[0].total_signals = 40.1; },
    report => { report.rows[0].total_signals = 1_000_000_001; },
    report => { report.rows[0].biased_entry_signals = 41; },
    report => { report.rows[0].biased_exit_signals = false; },
    report => { report.rows[0].has_bias = 'true'; },
    report => { report.rows[0].status = 'NO_FINDINGS_REPORTED'; },
    report => { report.status = 'NO_FINDINGS_REPORTED'; },
    report => { report.reason_codes = ['NO_FINDINGS_IN_SUPPLIED_ROWS']; },
    report => { report.rows[0].reason_codes = ['NO_FINDINGS_IN_SUPPLIED_ROW']; },
    report => { report.rows[1].biased_entry_signals = 1; },
    report => { report.rows[1].biased_indicators = ['future']; },
  ];
  for (const edit of edits) rejected(mutate(edit));
  rejected(JSON.stringify(fixtures.findings).replace('"biased_entry_signals":0', '"biased_entry_signals":-0'));
});

test('failed and insufficient inputs cannot be silently promoted or stripped of reasons', () => {
  for (const name of ['failed', 'insufficient']) {
    rejected(mutate(report => { report.status = 'NO_FINDINGS_REPORTED'; report.reason_codes = ['NO_FINDINGS_IN_SUPPLIED_ROWS']; }, fixtures[name]));
    rejected(mutate(report => { report.reason_codes = []; }, fixtures[name]));
  }
  rejected(mutate(report => { report.reason_codes = ['DECLARED_STRATEGY_COUNT_MISMATCH']; }, fixtures.insufficient));
  rejected(mutate(report => { report.rows[0].total_signals = 0; }, fixtures.insufficient));
  rejected(mutate(report => { report.reason_codes.push('UNVERIFIED_SOURCE'); }));
  rejected(mutate(report => { report.reason_codes.push(report.reason_codes[0]); }));
  rejected(mutate(report => { report.reason_codes = ['UPSTREAM_FINDINGS_REPORTED']; report.status = 'FINDINGS_REPORTED'; }, fixtures.failed));
});

test('run context remains strictly data-only, bounded and consistent with usable rows', () => {
  const edits = [
    report => { report.scope.declared_context.config_sha256 = 'x'.repeat(64); },
    report => { report.scope.declared_context.strategy_sha256 = 'a'.repeat(63); },
    report => { report.scope.declared_context.freqtrade_version = 'bad version'; },
    report => { report.scope.declared_context.freqtrade_version = 'x'.repeat(65); },
    report => { report.scope.declared_context.run_status = 'completed'; },
    report => { report.scope.declared_context.expected_strategy_count = 3; },
    report => { report.scope.declared_context.expected_strategy_count = 0; },
    report => { report.scope.declared_context.run_config.minimum_trade_amount = 40; },
    report => { report.scope.declared_context.run_config.targeted_trade_amount = 39; },
    report => { report.scope.declared_context.run_config.minimum_trade_amount = 101; },
    report => { report.scope.declared_context.run_config.lookahead_allow_limit_orders = 'false'; },
    report => { report.scope.declared_context.run_config.timerange = 'https://example.invalid'; },
    report => { report.scope.declared_context.run_config.timeframe = '0h'; },
    report => { report.scope.declared_context.run_config.targeted_trade_amount = true; },
  ];
  for (const edit of edits) rejected(mutate(edit));
  const valid = mutate(report => { for (const key of ['config_sha256', 'strategy_sha256', 'data_sha256']) report.scope.declared_context[key] = 'a'.repeat(64); });
  assert.equal(parse(valid).scope.context_authenticity, 'unverified');
});

test('private upstream label syntax, indicator limits and repeated identities are checked', () => {
  const edits = [
    report => { report.rows[0].filename = '../../private.py'; },
    report => { report.rows[0].strategy = '<img src=x>'; },
    report => { report.rows[0].biased_indicators = ['future', 'future']; },
    report => { report.rows[0].biased_indicators = ['<script>alert(1)</script>']; },
    report => { report.rows[0].biased_indicators = Array.from({ length: 129 }, (_, i) => `indicator_${i}`); },
    report => { report.rows[0].biased_indicators = ['a'.repeat(129)]; },
    report => { report.rows[0].biased_indicators = Array.from({ length: 100 }, (_, i) => `${i}_${'a'.repeat(100)}`); },
    report => { report.rows[1].strategy = report.rows[0].strategy; report.rows[1].filename = report.rows[0].filename; },
    report => { report.rows[0].display_label = 'x'.repeat(129); },
    report => { report.rows[0].display_label = 'danger\u202etext'; },
  ];
  for (const edit of edits) rejected(mutate(edit));
});

test('bounded display labels are data-only and always removed from the default sharing copy', () => {
  const label = '<img src=x onerror=alert(1)> 🧪';
  const report = parse(mutate(report => { report.rows[0].display_label = label; }));
  assert.equal(report.rows[0].display_label, label, 'renderers must use text nodes, never innerHTML');
  assert.equal(makeToolEvidenceExport(report).rows[0].display_label, 'Strategy 1');
});

test('legitimate empty/error outputs and incomplete CSV parsing remain inspectable', () => {
  for (const reason of ['INVALID_CSV_TYPE', 'CSV_LIMIT_EXCEEDED', 'INVALID_CSV_CONTROL', 'EMPTY_EXPORT', 'DUPLICATE_COLUMNS', 'UNSUPPORTED_COLUMNS', 'MALFORMED_CSV']) {
    const report = mutate(report => {
      report.status = 'NOT_ASSESSABLE'; report.rows = []; report.tested_strategy_count = 0;
      report.reason_codes = [reason]; report.scope.declared_context = {};
      if (['INVALID_CSV_TYPE', 'CSV_LIMIT_EXCEEDED'].includes(reason)) report.scope.source_sha256 = null;
    });
    assert.equal(parse(report).status, 'NOT_ASSESSABLE', reason);
  }
  const partial = mutate(report => {
    report.rows.pop(); report.tested_strategy_count = 1; report.status = 'NOT_ASSESSABLE';
    report.scope.declared_context = {}; report.reason_codes = ['MALFORMED_CSV'];
  });
  assert.equal(parse(partial).rows[0].has_bias, true);
  rejected(mutate(report => { report.scope.source_sha256 = null; }, partial));
  rejected(mutate(report => { report.reason_codes = ['EMPTY_EXPORT']; }, partial));
});

test('invalid context is retained as an assessment failure without allowing arbitrary context claims', () => {
  for (const reason of ['UNSUPPORTED_CONTEXT', 'INVALID_CONTEXT', 'UNSUPPORTED_RUN_CONFIG', 'INVALID_RUN_CONFIG', 'CONTRADICTORY_RUN_CONFIG']) {
    const report = mutate(report => { report.status = 'NOT_ASSESSABLE'; report.reason_codes = [reason]; report.scope.declared_context = {}; });
    assert.equal(parse(report).tested_strategy_count, 2);
    rejected(mutate(report => { report.scope.declared_context.run_status = 'COMPLETED'; }, report));
  }
});

test('all frozen-toolkit per-row failure codes retain zero usable rows for their failed observations', () => {
  for (const code of ['INVALID_COUNT', 'NO_TESTED_SIGNALS', 'COUNT_LIMIT_EXCEEDED', 'INVALID_FILENAME', 'INVALID_STRATEGY', 'UNRECOGNIZED_OR_UNSUCCESSFUL_RESULT', 'CONTRADICTORY_COUNTS', 'INDICATOR_LIMIT_EXCEEDED', 'INVALID_INDICATORS', 'DUPLICATE_INDICATORS', 'CONTRADICTORY_BIAS_RESULT', 'BELOW_DECLARED_EXPORT_MINIMUM', 'EXCEEDS_DECLARED_TARGET', 'MALFORMED_ROW', 'FIELD_LIMIT_EXCEEDED', 'DUPLICATE_INDEX', 'DUPLICATE_STRATEGY']) {
    const report = mutate(report => {
      report.scope.declared_context = {}; report.rows = [{ row_number: 1, status: 'NOT_ASSESSABLE', reason_codes: [code] }];
      report.tested_strategy_count = 0; report.status = 'NOT_ASSESSABLE'; report.reason_codes = [code];
    });
    assert.equal(parse(report).tested_strategy_count, 0, code);
  }
});

test('1000 supported rows are accepted and an asserted upstream row-limit failure is consistent', () => {
  const report = mutate(report => {
    report.rows = Array.from({ length: 1000 }, (_, index) => ({ ...clone(report.rows[0]), row_number: index + 1, filename: `synthetic_${index}.py`, strategy: `Synthetic_${index}` }));
    report.tested_strategy_count = 1000; report.scope.declared_context.expected_strategy_count = 1000;
  });
  assert.equal(parse(report).rows.length, 1000);
  const limited = mutate(report => { report.reason_codes = ['ROW_LIMIT_EXCEEDED']; report.status = 'NOT_ASSESSABLE'; }, report);
  assert.equal(parse(limited).tested_strategy_count, 1000);
  rejected(mutate(report => { report.rows.push({ ...report.rows[0], row_number: 1001 }); report.tested_strategy_count++; }, report));
  rejected(mutate(report => { report.reason_codes = ['ROW_LIMIT_EXCEEDED']; report.status = 'NOT_ASSESSABLE'; }));
});

test('empty and malformed source hashes cannot support usable observations', () => {
  for (const hash of [null, '', 'g'.repeat(64), 'a'.repeat(63), true, 'A'.repeat(64)]) rejected(mutate(report => { report.scope.source_sha256 = hash; }));
});

test('export validates input anew and rejects wrong option types with a safe fixed error', () => {
  assert.throws(() => makeToolEvidenceExport({ schema: 'fake' }), { message: error });
  assert.throws(() => makeToolEvidenceExport(fixtures.findings, { includeLabels: 'false' }), { message: error });
  const cyclic = {}; cyclic.self = cyclic;
  assert.throws(() => makeToolEvidenceExport(cyclic), { message: error });
});
