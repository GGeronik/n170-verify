// Structural interface checks only. Independent financial witnesses live elsewhere.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { reconstructSource, calculateIntervals } from '../scripts/reconciliation-source.mjs';

const options = { format: 'n170', currency: 'USD' };
const table = 'date,nav,external_flow\n2026-01-01,01.00,-0\n2026-01-02,1.,0';
const refusal = (status, code) => error => error instanceof Error && error.status === status
  && error.code === code && error.message === code;

test('independent module imports no producer or external dependency', () => {
  const source = readFileSync(new URL('../scripts/reconciliation-source.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /^\s*import\b|\brequire\s*\(|\bimport\s*\(/m);
  assert.doesNotMatch(source, /\b(?:fetch|eval)\s*\(/);
});

test('normalization preserves decimal spelling while normalizing CSV syntax and dates', () => {
  const result = reconstructSource('\ufeff"External flow";"NAV";"Date"\r\n -0 ; 01.00 ;20260101\r\n\r\n0;1.;2026-01-02\r\n', options);
  assert.equal(result.normalizedCsv, table);
  assert.deepEqual(result.rows.map(row => row.sourceRow), [2, 3]);
  assert.equal(result.sourceRows, 2);
  assert.equal(result.currencyEvidence, 'owner_assertion');
  assert.deepEqual(Object.keys(result).sort(), ['currencyEvidence', 'mapping', 'normalizedCsv', 'rows', 'sourceRows']);
  assert.deepEqual(result.mapping.map(row => Object.keys(row).sort()), Array(3).fill(['column', 'field']));
});

test('mapping objects are detached between reconstructions', () => {
  const first = reconstructSource(table, options);
  first.mapping[0].field = 'changed locally';
  assert.equal(reconstructSource(table, options).mapping[0].field, 'Observation date');
});

test('IBKR structural metadata allows quoting without exposing account labels', () => {
  const headers = ['Account ID', 'From Date', 'To Date', 'Starting Value', 'Ending Value',
    'Deposits/Withdrawals', 'Internal Cash Transfers', 'Asset Transfers', 'Linking Adjustments',
    'Other', 'Account Alias', 'Currency', 'TWR'];
  const cells = ['PRIVATE-STRUCTURAL-LABEL', '20260102', '20260102', '1', '1', '0', '0', '0', '0', '0',
    '"quoted, alias\ncontinued"', 'USD', 'not used as a return'];
  const result = reconstructSource(headers.join(',') + '\n' + cells.join(','), { format: 'ibkr-flex', currency: 'USD' });
  assert.equal(result.currencyEvidence, 'source');
  assert.equal(result.sourceRows, 1);
  assert.deepEqual(result.rows.map(row => row.sourceRow), [2, 2]);
  assert.equal(result.mapping.length, 4);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE-STRUCTURAL-LABEL|quoted, alias|not used as a return/);
});

test('malformed CSV and normalized-header ambiguity are structural failures', () => {
  for (const source of [table + '\n"unclosed', 'date,nav,external_flow\n2026-01-01,1,"0"unexpected', 'date,nav,external_flow\n2026-01-01,1,0"']) {
    assert.throws(() => reconstructSource(source, options), refusal('INVALID_INPUT', 'MALFORMED_CSV_QUOTING'));
  }
  assert.throws(() => reconstructSource('Date,Da-te,external_flow\n2026-01-01,1,0', options), refusal('INVALID_INPUT', 'INVALID_CSV_HEADERS'));
  assert.throws(() => reconstructSource(table + '\n2026-01-03,1', options), refusal('INVALID_INPUT', 'CSV_COLUMN_COUNT_MISMATCH'));
});

test('unsupported delimiter and format have fixed refusal codes', () => {
  assert.throws(() => reconstructSource('date\tnav\texternal_flow\n2026-01-01\t1\t0', options), refusal('NOT_ASSESSABLE', 'UNSUPPORTED_DELIMITER'));
  assert.throws(() => reconstructSource(table, { ...options, format: 'private arbitrary name' }), refusal('NOT_ASSESSABLE', 'UNSUPPORTED_FORMAT'));
});

test('unpaired Unicode and invalid caller structures never echo source text', () => {
  assert.throws(() => reconstructSource(table + '\ud800', options), refusal('INVALID_INPUT', 'INVALID_SOURCE_ENCODING'));
  assert.throws(() => reconstructSource({}, options), refusal('INVALID_INPUT', 'INVALID_SOURCE_TEXT'));
  assert.throws(() => reconstructSource(table, { ...options, injected: 'private string' }), refusal('INVALID_INPUT', 'INVALID_SOURCE_OPTIONS'));
  assert.throws(() => calculateIntervals(null), refusal('INVALID_INPUT', 'INVALID_OBSERVATION_STRUCTURE'));
  assert.throws(() => calculateIntervals([{ date: '2026-01-01', nav: '1', flow: '0', sourceRow: 1 }]), refusal('INVALID_INPUT', 'INVALID_OBSERVATION_STRUCTURE'));
});

test('hard record and observation resource bounds are structural failures', () => {
  const repeated = count => 'date,nav,external_flow\n' + Array(count).fill('2026-01-01,1,0').join('\n');
  assert.throws(() => reconstructSource(repeated(5001), options), refusal('INVALID_INPUT', 'SOURCE_ROW_LIMIT'));
  assert.throws(() => reconstructSource(repeated(501), options), refusal('INVALID_INPUT', 'OBSERVATION_LIMIT'));
});

test('interval API emits only documented fields and leaves input objects unchanged', () => {
  const rows = reconstructSource(table, options).rows;
  const before = JSON.stringify(rows);
  const result = calculateIntervals(rows);
  assert.equal(JSON.stringify(rows), before);
  assert.deepEqual(Object.keys(result).sort(), ['coverage', 'intervals', 'period', 'relative_returns']);
  assert.deepEqual(Object.keys(result.intervals[0]).sort(), ['adjusted_closing_nav', 'closing_nav', 'duration_days', 'economic_change', 'end', 'external_flow', 'flow_kind', 'opening_nav', 'return_e8', 'start']);
  assert.deepEqual(Object.keys(result.coverage).sort(), ['external_cash_flow_count', 'nav_observations', 'return_observations']);
  assert.deepEqual(Object.keys(result.relative_returns[0]).sort(), ['end', 'return_e8', 'start']);
  assert.ok(Number.isSafeInteger(result.relative_returns[0].return_e8));
});
