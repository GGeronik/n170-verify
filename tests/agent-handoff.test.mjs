import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { parseAgentHandoff, validateAgentHandoff, AgentHandoffError, HANDOFF_BLOCK_CODES } from '../src/agentHandoff.js';
import { buildStampObservationEvidence, sampleInput } from '../src/calculator.js';
const fixtureText = await readFile(new URL('../examples/agent-handoff-synthetic.json', import.meta.url), 'utf8');
const packet = () => JSON.parse(fixtureText);
const parse = value => parseAgentHandoff(JSON.stringify(value));
const contains = (review, code) => review.exceptions.some(item => item.code === code);
const codeFor = value => validateAgentHandoff(JSON.stringify(value)).errors.map(item => item.code);

test('synthetic agent packet preserves exact financial strings and matches canonical sample', async () => {
  const { handoff, review } = await parseAgentHandoff(fixtureText);
  assert.equal(review.canCalculate, true);
  assert.equal(review.synthetic, true);
  assert.equal(review.normalizedCsv, sampleInput);
  assert.equal(review.source.sha256, createHash('sha256').update(fixtureText).digest('hex'));
  assert.deepEqual(buildStampObservationEvidence(review.normalizedCsv, review.frequency).metrics, buildStampObservationEvidence(sampleInput, 252).metrics);
  assert.equal(review.source.authenticated, false); assert.equal(review.review.source_verified, false);
  assert.deepEqual(review.rows.map(row => row.sourceRow), [1, 2, 3, 4]);
  assert.equal(review.agentContext.source.retrieved_at, handoff.source.retrieved_at);
});

test('unknown fields including forged proof, account IDs and credentials are rejected at every level', async () => {
  for (const mutate of [p => { p.verified = true; }, p => { p.source.authenticated = true; }, p => { p.source.account_id = 'PRIVATE_ACCOUNT'; }, p => { p.source.api_key = 'PRIVATE_SECRET'; }, p => { p.observations[0].identity_verified = true; }, p => { p.mapping.extra = 'unexpected'; }, p => { p.requested_period.complete = true; }]) {
    const p = packet(); mutate(p); assert.ok(codeFor(p).includes('unknown_key'));
    await assert.rejects(parse(p), error => error instanceof AgentHandoffError && error.code === 'invalid_handoff');
  }
});

test('duplicate JSON keys, including escaped equivalent names, never choose a winning value', () => {
  const duplicate = fixtureText.replace('"synthetic": true,', '"synthetic": true, "synthetic": false,');
  assert.equal(validateAgentHandoff(duplicate).errors[0].code, 'duplicate_key');
  const escaped = fixtureText.replace('"synthetic": true,', '"synthetic": true, "synth\\u0065tic": false,');
  assert.equal(validateAgentHandoff(escaped).errors[0].code, 'duplicate_key');
});

test('unknown-key errors redact arbitrary key text and stay bounded', async () => {
  const p = packet(); p.source['PRIVATE_TOKEN_' + 'x'.repeat(20000)] = 'secret';
  const validation = validateAgentHandoff(JSON.stringify(p));
  assert.equal(validation.errors[0].path, '/source/[unknown-field]');
  assert.equal(JSON.stringify(validation.errors).includes('PRIVATE_TOKEN'), false);
  await assert.rejects(parse(p), error => error.message.length < 500 && !error.message.includes('PRIVATE_TOKEN'));
});

test('missing decimal values cannot become zero or rounded JavaScript numbers', () => {
  for (const value of [null, 0, 1.1, '1e3', '1,000', '£10', '.0000000000000000001', '', ' ']) {
    const p = packet(); p.observations[1].external_flow = value; assert.ok(codeFor(p).includes('invalid_decimal'));
  }
  const absent = packet(); delete absent.observations[0].external_flow;
  assert.ok(codeFor(absent).includes('missing_key'));
  const exceeded = packet(); exceeded.observations[1].nav = '1000000000000000.000000000000000001';
  assert.ok(codeFor(exceeded).includes('decimal_range'));
});

test('large exact decimal cancellation survives input-to-canonical calculation', async () => {
  const p = packet(); p.observations = [
    { date: '2025-01-02', nav: '0.1', external_flow: '0', source_ref: 'private.nav[0]' },
    { date: '2025-01-07', nav: '999999999999999.9', external_flow: '999999999999999.8', source_ref: 'private.nav[1]' },
  ];
  const { review } = await parse(p); assert.equal(review.canCalculate, true);
  assert.equal(review.rows[1].flow, '999999999999999.8');
  assert.equal(buildStampObservationEvidence(review.normalizedCsv, 252).metrics.total_return_twr_e8, 0);
});

test('pagination, gaps, unsupported events and flow timing block rather than fabricate', async () => {
  const mutations = [
    ['pagination_incomplete', p => { p.coverage.pagination = 'incomplete'; }],
    ['pagination_unknown', p => { p.coverage.pagination = 'unknown'; }],
    ['missing_periods', p => { p.coverage.missing_periods = [{ start: '2025-01-04', end: '2025-01-05', reason: 'Requested history unavailable' }]; }],
    ['unsupported_events', p => { p.coverage.unsupported_events = ['Asset transfer timing unresolved']; }],
    ['flow_timing_unsupported', p => { p.flow_timing = 'intraperiod'; }],
    ['flow_timing_unsupported', p => { p.flow_timing = 'unknown'; }],
  ];
  for (const [code, mutate] of mutations) { const p = packet(); mutate(p); const { review } = await parse(p); assert.equal(review.canCalculate, false); assert.ok(contains(review, code)); assert.ok(HANDOFF_BLOCK_CODES.includes(code)); }
});

test('honest empty/no-retrieval packet is valid but blocked', async () => {
  const p = packet(); p.synthetic = false; p.observations = []; p.source.retrieved_at = null; p.source.tools = [];
  p.source.broker = 'Unavailable'; p.source.connector = 'Unavailable'; p.coverage.pagination = 'unknown'; p.flow_timing = 'unknown';
  p.coverage.missing_periods = [{ ...p.requested_period, reason: 'No authorized source retrieval available' }];
  assert.equal(validateAgentHandoff(JSON.stringify(p)).valid, true);
  const { review } = await parse(p); assert.equal(review.canCalculate, false);
  assert.ok(contains(review, 'source_not_retrieved')); assert.ok(contains(review, 'missing_observations'));
  assert.equal(review.rows.length, 0); assert.equal(review.normalizedCsv, 'date,nav,external_flow\n');
  const one = packet(); one.observations = one.observations.slice(0, 1); assert.ok(contains((await parse(one)).review, 'missing_observations'));
});

test('invalid dates/order are structural errors; incomplete requested bounds remain explicit blockers', async () => {
  for (const mutate of [p => { p.observations[1].date = '2025-02-30'; }, p => { p.observations[1].date = p.observations[0].date; }, p => { p.requested_period.start = '2025-02-01'; }, p => { p.source.retrieved_at = '2025-02-30T10:00:00Z'; }, p => { p.source.retrieved_at = '2025-01-01T12:00:00'; }, p => { p.source.retrieved_at = '2025-01-01T12:00:00+14:30'; }]) {
    const p = packet(); mutate(p); assert.equal(validateAgentHandoff(JSON.stringify(p)).valid, false);
  }
  const mismatch = packet(); mismatch.requested_period.start = '2025-01-01'; const { review } = await parse(mismatch);
  assert.equal(review.canCalculate, false); assert.ok(contains(review, 'requested_period_mismatch'));
});

test('numerical limitations cannot produce ready packets', async () => {
  for (const mutate of [p => { p.observations[1].nav = '0'; }, p => { p.observations[0].external_flow = '1'; }, p => { p.observations[1].nav = '100000000'; }]) {
    const p = packet(); mutate(p); const { review } = await parse(p); assert.equal(review.canCalculate, false); assert.ok(contains(review, 'calculation_unsupported'));
  }
});

test('public mapping excludes private provider field paths/tool names/row source refs', async () => {
  const p = packet(); p.mapping.nav = 'PRIVATE_PROVIDER_PATH'; p.source.tools = ['PRIVATE_TOOL_NAME']; p.observations[0].source_ref = 'PRIVATE_RESPONSE_REFERENCE';
  const { review } = await parse(p);
  assert.equal(JSON.stringify(review.mapping).includes('PRIVATE_'), false);
  assert.equal(review.rows[0].sourceRef, 'PRIVATE_RESPONSE_REFERENCE');
  assert.equal(review.agentContext.mapping.nav, 'PRIVATE_PROVIDER_PATH');
  assert.ok(review.mapping.every(m => m.source.length <= 120 && m.target.length <= 80));
});

test('schema field structure and decimal grammar agree for boundary strings', async () => {
  const schema = JSON.parse(await readFile(new URL('../schemas/agent-handoff-v1.schema.json', import.meta.url), 'utf8'));
  assert.equal(schema.additionalProperties, false); assert.equal(schema.properties.observations.maxItems, 500);
  assert.deepEqual(schema.required.sort(), Object.keys(packet()).sort());
  const expression = new RegExp(schema.$defs.decimal.pattern);
  const values = ['0', '-0', '.1', '-.1', '1.', '000001.100', '1000000000000000', '-1000000000000000.000000000000000000', '1000000000000000.000000000000000001', '1000000000000001', '999999999999999.999999999999999999', '1e3', '1,000', '0.0000000000000000001'];
  for (const value of values) { const p = packet(); p.observations[1].external_flow = value; const structural = validateAgentHandoff(JSON.stringify(p)).valid; assert.equal(expression.test(value), structural, value); }
});
