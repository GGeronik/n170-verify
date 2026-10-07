import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { computeExactLedger, decodeBinary64, roundBinary64ToDecimal8, numberHex, canonicalNativeRepr, compareNativeMetric, expandNativeDecimal, exactDecimal, replayNativeClosedTrades } from '../src/accountingExact.js';

const fixtureBytes = await readFile(new URL('./fixtures/accounting-v2-acceptance.json', import.meta.url));
assert.equal(createHash('sha256').update(fixtureBytes).digest('hex'), '7174e250f0f4955c4943d1fa84087615ada39d31f9c416eb6fcf8b6931358986');
const frozen = JSON.parse(fixtureBytes);
const numeric = Object.fromEntries(frozen.numeric_cases.map(item => [item.id, item]));
const native = (repr, hex) => ({ encoding: 'binary64', repr, hex });
const runtime = { image_id: 'sha256:' + 'a'.repeat(64), image_reference: 'freqtradeorg/freqtrade@sha256:289f403917e170ecced1f3c537a2580435a581f2b21311c488c4efcb1694f666',
  engine_revision: '9f10e357a93c1dcf10c2a2b367659214d89c073e', engine_source_sha256: 'a96f980268301b69f8fb6e423d27606ede3f174449f63ff672aebb48f97ac6de',
  python: '3.14.7', ccxt: '4.5.76', numpy: '2.4.6', precise_sha256: '445721221b65f37cc198adaeec26f68b214926e82ea2bfc0195a346ec94773ed' };
const doc = (item, reported = item.expected_decimal) => ({ schema: 'n170.accounting.events.v2', evidence_class: 'synthetic_fixture', asset: 'BTC', cash_currency: 'USDT',
  opening: { timestamp: '2026-02-01T00:00:00Z', cash: item.opening_cash }, closing: { timestamp: '2026-02-01T23:59:59Z', mark_price: item.closing_mark, reported },
  events: item.completion_events.map(event => ({ event_id: event.event_id, timestamp: event.timestamp, type: event.side, quantity: event.quantity, price: event.price,
    fee: event.exact_modeled_fee, fee_currency: 'USDT', fee_model: { kind: 'modeled_fee', quantity: event.quantity, price: event.price, rate: '0.001', sources: ['original-independent-fixture:' + item.id] } })) });

test('all frozen exact ledgers and intermediate FIFO checkpoints are reproduced independently with BigInt', () => {
  for (const item of frozen.ledger_cases) {
    const report = computeExactLedger(doc(item));
    assert.deepEqual(report.computed, item.expected_decimal, `${item.id}: ${report.reason_codes}`);
    assert.equal(report.status, 'RECONCILED_UNDER_ASSUMPTIONS');
    for (const expected of item.expected_event_checkpoints) assert.deepEqual(report.event_checkpoints.find(p => p.event_id === expected.event_id), expected);
  }
});
test('no reported native or decimal metrics are invented from exact computation', () => {
  const report = computeExactLedger(doc(frozen.ledger_cases[0], {}));
  assert.equal(report.status, 'NOT_ASSESSABLE'); assert.ok(report.computed);
  assert.ok(Object.values(report.checks).every(row => row.status === 'NOT_SUPPLIED'));
  assert.equal(report.oracle.status, 'NOT_RUN');
});
test('nineteen-place fee boundaries and discrepancies remain exact without truncation', () => {
  const item = frozen.ledger_cases.find(item => item.id === 'nineteen_place_fees');
  const broken = doc(item); broken.events[0].fee = '0.001';
  assert.deepEqual(computeExactLedger(broken).reason_codes, ['MODELED_FEE_MISMATCH']);
  const falseClaim = doc(item); falseClaim.closing.reported = { ...item.expected_decimal, cash: '9.9980000199400001997' };
  assert.equal(computeExactLedger(falseClaim).checks.cash.difference_reported_minus_computed, '0.0000000000000000001');
  assert.equal(exactDecimal('1000000000000000000000', 'fee'), '1000000000000000000000');
  for (const [input, kind] of [['0.00000000000000000001', 'fee'], ['1.000000001', 'operand'], ['1000000000000000000000.0000000000000000001', 'fee'], ['1000000000000000000000000000000.0000000000000000001', 'result']]) assert.throws(() => exactDecimal(input, kind));
  assert.equal(expandNativeDecimal('1e-19'), '0.0000000000000000001');
});
test('event identity, order, borrowing, oversells and fee operands are independently checked', () => {
  for (const edit of [d => d.events.reverse(), d => { d.events[1].event_id = d.events[0].event_id; },
    d => { d.events[0].fee_model.quantity = '999'; }, d => { d.events[0].fee_model.rate = '0.002'; },
    d => { d.events[1].quantity = '3'; d.events[1].fee_model.quantity = '3'; d.events[1].fee = '0.33'; },
    d => { d.opening.cash = '1'; }, d => { d.events[0].fee_currency = 'BTC'; },
    d => { d.events[0].timestamp = '2026-02-31T00:05:00Z'; }]) {
    const value = doc(frozen.ledger_cases[0]); edit(value); assert.equal(computeExactLedger(value).status, 'NOT_ASSESSABLE');
  }
});
test('exact binary64 decoding distinguishes a decimal spelling from the true value', () => {
  const item = numeric.decimal_spelling_is_not_binary_value;
  const result = decodeBinary64(native(item.decimal_spelling, item.captured_hex));
  assert.deepEqual(result.exact, item.expected_exact_binary.exact);
  assert.equal(result.exact_decimal, item.expected_exact_binary.exact_decimal);
  const comparison = compareNativeMetric(native(item.decimal_spelling, item.captured_hex), item.decimal_spelling);
  assert.deepEqual(comparison.exact_binary_difference, item.expected_binary_minus_decimal);
  assert.equal(comparison.display_decimal_difference, '0'); assert.equal(comparison.exact_decimal_equal, false);
});
test('frozen signed ties and one-ULP neighbors satisfy rational ties-even round8', () => {
  for (const item of frozen.numeric_cases.filter(item => item.id.startsWith('eight_place_'))) {
    const value = roundBinary64ToDecimal8(item.input_binary64.hex);
    assert.equal(value.decimal, item.expected_decimal_quantized, item.id);
    assert.equal(value.hex, item.expected_output_binary64.hex, item.id);
    assert.deepEqual(decodeBinary64(value.hex).exact, item.expected_output_binary64.exact);
  }
  assert.equal(roundBinary64ToDecimal8(5e-9).decimal, '0.00000001');
  assert.equal(roundBinary64ToDecimal8(1.5e-8).decimal, '0.00000001');
});
test('native capture rejects expression wrappers, nonfinite values and repr/hex mismatches', () => {
  const bad = numeric.repr_hex_disagree;
  assert.throws(() => decodeBinary64(native(bad.decimal_spelling, bad.captured_hex)));
  const item = numeric.numpy_float64_normalized_at_capture;
  assert.equal(expandNativeDecimal(item.required_capture_repr), item.expanded_decimal_spelling);
  assert.deepEqual(decodeBinary64(native(item.required_capture_repr, item.required_capture_hex)).exact, item.exact_binary_value);
  for (const value of [item.observed_source_repr, 'NaN', 'Infinity', '-Infinity', '1 + 1']) assert.throws(() => decodeBinary64(native(value, item.required_capture_hex)));
  assert.throws(() => decodeBinary64(native('0', '-0x0.0p+0')));
  assert.equal(decodeBinary64(native('-0.0', '-0x0.0p+0')).negative_zero, true);
  assert.equal(roundBinary64ToDecimal8(-1e-12).hex, '-0x0.0p+0');
  assert.equal(numberHex(0 + roundBinary64ToDecimal8(-1e-12).number), '0x0.0p+0');
});
test('Python repr formatting preserves signed zero and fixed/scientific threshold boundaries', () => {
  for (const [value, repr] of [[1e15, '1000000000000000.0'], [1e16, '1e+16'], [1e-4, '0.0001'], [1e-5, '1e-05'],
    [100, '100.0'], [-0, '-0.0'], [0, '0.0'], [-1e-8, '-1e-08'], [1.234e16, '1.234e+16']]) {
    assert.equal(canonicalNativeRepr(value), repr); assert.equal(decodeBinary64(native(repr, numberHex(value))).hex, numberHex(value));
  }
  for (const [value, repr] of [[100, '100'], [100, '100.00'], [1e-8, '1e-8'], [1e-8, '1.0e-08'], [1e16, '10000000000000000.0'], [-0, '-0']]) {
    assert.throws(() => decodeBinary64(native(repr, numberHex(value))), /NONCANONICAL_NATIVE_REPR/);
  }
  assert.throws(() => decodeBinary64(native('100.000000000000001', numberHex(100))), /UNSUPPORTED_NATIVE_SPELLING/);
});
test('round-per-trade, decimal-leg conversion and serial accumulation retain operation order', () => {
  const loss = numeric.conversion_loses_difference_before_subtraction;
  assert.equal(numberHex(Number(loss.close_leg_decimal) - Number(loss.open_leg_decimal)), loss.expected_native_difference.hex);
  for (const item of [numeric.close_order_absorbed, numeric.close_order_retained]) {
    let sum = 0; const trace = item.ordered_profit_integers.map(value => numberHex(sum += Number(value)));
    assert.deepEqual(trace, item.expected_trace.map(item => item.hex));
  }
  const rounding = numeric.round_each_trade_before_accumulation;
  assert.equal(numberHex(rounding.unrounded_trade_binary64.reduce((sum, item) => sum + roundBinary64ToDecimal8(item.hex).number, 0)), rounding.expected_sum.hex);
  for (const item of [numeric.large_opening_absorbs_gain, numeric.large_opening_absorbs_loss]) {
    assert.equal(numberHex(Number(item.opening_cash) + decodeBinary64(item.trade_profit_binary64.hex).number), item.expected_native_cash.hex);
    assert.deepEqual(compareNativeMetric(native(canonicalNativeRepr(Number(item.opening_cash)), item.expected_native_cash.hex), item.exact_model_cash).exact_binary_difference, item.expected_native_cash_minus_exact_model);
  }
});
test('retained smooth control preserves true-binary and printed-decimal differences separately', () => {
  const item = frozen.retained_controls.find(item => item.id === 'retained_smooth');
  const result = compareNativeMetric(native(item.observed_native_cash.repr, item.observed_native_cash.hex), item.expected_decimal.cash);
  assert.deepEqual(result.exact_binary_difference, item.expected_exact_binary_minus_model);
  assert.equal(result.exact_binary_difference_decimal, item.expected_exact_binary_minus_model_decimal);
  assert.equal(result.display_decimal_difference, item.expected_display_decimal_minus_model);
});
test('native replay checks each supplied bit pattern and refuses unbound runtime or missing results', () => {
  const value = { opening_cash: '1000', runtime, trades: [{ trade_id: 'T1', entry_quantity: '2', entry_price: '100', exit_quantity: '2', exit_price: '110', fee_rate: '0.001', native_profit: native('19.58', numberHex(19.58)) }],
    native_total_profit: native('19.58', numberHex(19.58)), native_cash: native('1019.58', numberHex(1019.58)) };
  assert.equal(replayNativeClosedTrades(value).status, 'MATCHES_ENGINE_NUMERIC_POLICY');
  assert.equal(replayNativeClosedTrades({ ...value, native_cash: native('1019.5800000000002', numberHex(1019.5800000000002)) }).status, 'MISMATCH');
  assert.equal(replayNativeClosedTrades({ ...value, native_cash: null }).status, 'NOT_ASSESSABLE');
  assert.equal(replayNativeClosedTrades({ ...value, runtime: { ...runtime, python: '3.12.0' } }).status, 'NOT_ASSESSABLE');
  assert.equal(replayNativeClosedTrades({ ...value, trades: [] }).status, 'NOT_ASSESSABLE');
});
test('direct native replay requires a bounded canonical trade identifier', () => {
  const trade = { trade_id: 'T1', entry_quantity: '2', entry_price: '100', exit_quantity: '2', exit_price: '110', fee_rate: '0.001', native_profit: native('19.58', numberHex(19.58)) };
  const input = { opening_cash: '1000', runtime, native_total_profit: native('19.58', numberHex(19.58)), native_cash: native('1019.58', numberHex(1019.58)) };
  for (const trade_id of ['', '.', '-id', '_id', 'trade/id', 'trade id', '!', 'A'.repeat(65), 1, null, {}, []]) {
    const report = replayNativeClosedTrades({ ...input, trades: [{ ...trade, trade_id }] });
    assert.equal(report.status, 'NOT_ASSESSABLE'); assert.deepEqual(report.reason_codes, ['INVALID_NATIVE_CLOSE_ORDER']);
  }
  for (const trade_id of ['A', '0', 'Trade_1.2-3', 'A'.repeat(64)]) {
    assert.equal(replayNativeClosedTrades({ ...input, trades: [{ ...trade, trade_id }] }).status, 'MATCHES_ENGINE_NUMERIC_POLICY');
  }
});
