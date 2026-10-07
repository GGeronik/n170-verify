import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { verifyRunReviewV2 } from '../src/runReviewV2.js';
import { numberHex, canonicalNativeRepr } from '../src/accountingExact.js';

// Original mocked unit capture, never executed; copied locally to preserve all prior tests.
// Every wallet mutation is rebound through capture, worker transport, attempt and manifest.
// Optional retained real receipt checks launch no engine or oracle.
const legacy = JSON.parse(await readFile(new URL('./fixtures/run-review-unit.json', import.meta.url), 'utf8'));
const sha = raw => createHash('sha256').update(raw).digest('hex');
const bytes = value => Buffer.from(JSON.stringify(value));
const descriptor = (path, raw) => ({ path, size: raw.length, sha256: sha(raw), base64: raw.toString('base64') });
const entry = d => ({ path: d.path, size: d.size, sha256: d.sha256 });
const n = value => ({ encoding: 'binary64', repr: canonicalNativeRepr(value), hex: numberHex(value) });
const prefix = 'attempts/000/', inp = prefix + 'input/', out = prefix + 'output/';
const wallet = cash => ({ balances: [{ currency: 'USDT', free: n(cash), used: 0, total: n(cash) }], cash: n(cash), asset: 0 });
const priceOrder = (side, id, date, price) => ({ id: null, order_id: id, pair: 'BTC/USDT', side, type: 'market', status: 'closed', is_open: false,
  amount: n(2), filled: n(2), remaining: n(0), price: n(price), average: n(price), safe_price: n(price), cost: n(2 * price * 1.001), fee_base: 0,
  created_at: date, filled_at: date, tag: side === 'sell' ? 'exit_signal' : null });
function fixture() {
  const manifest = JSON.parse(Buffer.from(legacy.manifest.base64, 'base64'));
  const files = new Map(legacy.artifacts.map(d => [d.path, Buffer.from(d.base64, 'base64')]));
  manifest.schema = 'n170.freqtrade-run.v2';
  manifest.engine.reference = 'freqtradeorg/freqtrade@sha256:289f403917e170ecced1f3c537a2580435a581f2b21311c488c4efcb1694f666';
  files.set(inp + 'engine_worker_v1.py', files.get(inp + 'engine_worker.py'));
  files.set(inp + 'engine_worker.py', Buffer.from('# Original unit transport. Never executed.\n'));
  files.set(inp + 'accounting_collector.py', Buffer.from('# Original unit observer placeholder. Never executed.\n'));
  const worker = JSON.parse(files.get(out + 'worker-result.json')); worker.schema = 'n170.freqtrade-worker.v2';
  const source = JSON.parse(files.get(inp + 'data/BTC_USDT-5m.json'));
  const iso = ms => new Date(ms).toISOString().replace('.000Z', 'Z');
  const last = source.at(-1); const ohlcv = { date: iso(last[0]), ...Object.fromEntries(['open', 'high', 'low', 'close', 'volume'].map((k, i) => [k, n(last[i + 1])])) };
  const backtest = { ...ohlcv }; delete backtest.volume;
  const buy = priceOrder('buy', 'order-1', '2026-01-01T00:05:00Z', 100), sell = priceOrder('sell', 'order-2', '2026-01-01T00:10:00Z', 110);
  const trade = { trade_id: 1, pair: 'BTC/USDT', is_open: false, is_short: false, trading_mode: 'spot', leverage: n(1), amount: n(2), stake_amount: n(200),
    open_rate: n(100), close_rate: n(110), fee_open: n(0.001), fee_close: n(0.001), fee_open_cost: n(0.2), fee_close_cost: n(0.22),
    fee_open_currency: '', fee_close_currency: '', open_date: buy.filled_at, close_date: sell.filled_at, exit_reason: 'exit_signal', entry_count: 1, exit_count: 1,
    close_profit_abs: n(19.58), realized_profit: n(19.58), funding_fees: n(0), has_open_orders: false, orders: [buy, sell] };
  const columns = ['pair', 'stake_amount', 'amount', 'open_date', 'close_date', 'open_rate', 'close_rate', 'fee_open', 'fee_close', 'profit_abs', 'exit_reason', 'is_open', 'is_short', 'leverage', 'funding_fees', 'orders', 'open_timestamp', 'close_timestamp'];
  const rowOrders = [buy, sell].map(o => ({amount:o.amount,cost:o.cost,ft_is_entry:o.side==='buy',ft_order_side:o.side,ft_order_tag:o.tag,order_filled_timestamp:Date.parse(o.filled_at),safe_price:o.safe_price}));
  const config = JSON.parse(files.get(out + 'effective-config.json'));
  const nativeConfig = value => typeof value === 'number' ? Number.isSafeInteger(value) ? value : n(value) : Array.isArray(value) ? value.map(nativeConfig) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([k,v])=>[k,nativeConfig(v)])) : value;
  const capture = { schema: 'n170.freqtrade-baseline-capture.v1', capture_policy: 'freqtrade-2026.8-full-baseline-observer.v1', binding: {},
    capture: { status: 'COMPLETE', reason_codes: [], hook_counts: { baseline: 1, backtest: 1, opening: 1, pre_force_exit: 1, final: 1 }, completion_count: 2, closed_trade_count: 1, terminal_order_count: 2, truncated: false },
    runtime: { implementation: 'CPython', python_version: '3.14.7', float_info: { radix: 2, mant_dig: 53, max_exp: 1024, min_exp: -1021, rounds: 1 }, numpy_version: '2.4.6', ccxt_version: '4.5.76',
      ccxt_precise_sha256: '445721221b65f37cc198adaeec26f68b214926e82ea2bfc0195a346ec94773ed', ccxt_precise_after_sha256: '445721221b65f37cc198adaeec26f68b214926e82ea2bfc0195a346ec94773ed' },
    scope: { pair: 'BTC/USDT', timeframe: '5m', trading_mode: 'spot', fee_model: 'quote-filled-price-rate.v1' },
    window: { requested_timerange: manifest.request.timerange, backtest_start: '2026-01-01T00:00:00Z', backtest_end: iso(last[0]), processed_bounds: { 'BTC/USDT': { first: iso(source[0][0]), last: iso(last[0]), count: source.length } }, candle_count: source.length },
    resolved: { config: { ...nativeConfig(config), strategy: manifest.attempts[0].strategy, pairs: ['BTC/USDT'] }, strategy_settings: { timeframe: '5m', startup_candle_count: 3, minimal_roi: { 0: n(100) }, stoploss: n(-0.99), can_short: false, position_adjustment_enable: false, order_types: { entry: 'market', exit: 'market' } } },
    opening: { wallets: wallet(1000000000), starting_balance: n(1000000000), open_trades: [], closed_trade_count: 0, total_closed_profit: n(0) },
    completions: [buy, sell].map((order, i) => ({ sequence: i + 1, phase: 'baseline', trade_id: 1, order, trade_fee_rates: { open: n(0.001), close: n(0.001) }, trade_fee_costs: { open: n(0.2), close: n(0.22) }, trade_fee_currencies: { open: '', close: '' } })),
    closes: [{ sequence: 1, trade_id: 1, close_profit_abs: n(19.58), total_profit_before: n(0), total_profit_after: n(19.58) }],
    pre_force_exit: { wallets: wallet(1000000019.58), open_trades: [], terminal_candles: { 'BTC/USDT': { ohlcv, backtest_row: backtest } } },
    final: { wallets: wallet(1000000019.58), open_trades: [], closed_trades: [trade], trade_rows: { columns, rows: [columns.map(k => k === 'profit_abs' ? trade.close_profit_abs : k === 'orders' ? rowOrders : k === 'open_timestamp' ? Date.parse(trade.open_date) : k === 'close_timestamp' ? Date.parse(trade.close_date) : trade[k])] }, native_final_balance: n(1000000019.58), native_total_closed_profit: n(19.58), close_order: [1],
      engine_counters: Object.fromEntries('rejected_trades timedout_entry_orders timedout_exit_orders canceled_trade_entries canceled_entry_orders replaced_entry_orders canceled_exit_orders replaced_exit_orders'.split(' ').map(k => [k, 0])), wallet_summary: { columns: [], rows: [] } },
    trust: { execution: 'Original mocked unit capture, never executed', authenticity: 'unsigned', completeness: 'selected only', fees: 'modeled only', observer: 'mocked only' } };
  return { manifest, files, worker, capture };
}
function pack(state, { binding = true, descriptorBinding = true } = {}) {
  const { manifest, files, worker, capture } = state;
  const inventory = [...files].filter(([p]) => p.startsWith(inp) && p !== inp + 'request.json').sort(([a], [b]) => a < b ? -1 : 1).map(([p, raw]) => entry(descriptor(p.slice(inp.length), raw)));
  const request = { ...manifest.request, schema: 'n170.freqtrade-request.v2', run_id: manifest.run_id, attempt_id: '000', strategy: manifest.attempts[0].strategy, input_inventory: inventory }; delete request.strategies;
  const requestRaw = bytes(request); files.set(inp + 'request.json', requestRaw);
  worker.input_inventory = inventory; worker.request_sha256 = sha(requestRaw);
  if (binding) {
    const byName = Object.fromEntries(inventory.map(i => [i.path, i.sha256]));
    capture.binding = { run_id: request.run_id, attempt_id: '000', strategy: request.strategy, request_sha256: sha(requestRaw), input_inventory: inventory,
      collector_sha256: byName['accounting_collector.py'], worker_sha256: byName['engine_worker.py'], helper_sha256: byName['engine_worker_v1.py'], market_metadata_sha256: worker.offline_adapter.market_metadata_sha256,
      engine_revision: worker.engine.revision, engine_source_sha256: worker.engine.source_sha256, engine_source_after_sha256: worker.engine.source_after_sha256 };
  }
  const captureRaw = bytes(capture); files.set(out + 'baseline-capture.json', captureRaw);
  if (descriptorBinding) worker.capture = { schema: capture.schema, path: 'baseline-capture.json', size: captureRaw.length, sha256: sha(captureRaw), status: capture.capture.status, reason_codes: capture.capture.reason_codes };
  manifest.attempts[0].capture = structuredClone(worker.capture); files.set(out + 'worker-result.json', bytes(worker));
  const output = Object.fromEntries([...files].filter(([p]) => p.startsWith(out)).map(([p, raw]) => [p.slice(out.length), raw.toString('base64')]));
  files.set(prefix + 'stdout.log', Buffer.from('Original self-authored unit capture, not execution evidence.\nN170_RESULT_BUNDLE_V2:' + bytes(output).toString('base64') + '\n'));
  const artifacts = [...files].sort(([a], [b]) => a < b ? -1 : 1).map(([p, raw]) => descriptor(p, raw));
  manifest.artifacts = artifacts.map(entry); manifest.inputs = manifest.artifacts.filter(i => i.path.startsWith(inp)); manifest.attempts[0].artifacts = manifest.artifacts;
  return { schema: 'n170.run-review.v2', manifest: descriptor('manifest.json', bytes(manifest)), artifacts };
}
const verify = (state, options) => verifyRunReviewV2(JSON.stringify(pack(state, options)));

const stages = ['opening', 'pre_force_exit', 'final'];
const row = (currency, free = 0, used = 0, total = free) => ({ currency, free, used, total });
const add = (wallet, entry) => { wallet.balances.push(entry); wallet.balances.sort((a, b) => a.currency < b.currency ? -1 : 1); };
const USDT = wallet => wallet.balances.find(entry => entry.currency === 'USDT');
const rejects = [
  ['positive foreign asset', w => add(w, row('ETH', 1)), 'UNSUPPORTED', 'OTHER_ASSET_BALANCE_UNSUPPORTED'],
  ['negative foreign asset', w => add(w, row('ETH', -1)), 'UNSUPPORTED', 'NEGATIVE_NATIVE_WALLET'],
  ['punctuation currency', w => add(w, row('!')), 'INVALID', 'INVALID_WALLET'],
  ['lowercase currency', w => add(w, row('eth')), 'INVALID', 'INVALID_WALLET'],
  ['one-character currency', w => add(w, row('A')), 'INVALID', 'INVALID_WALLET'],
  ['overlength currency', w => add(w, row('A'.repeat(13))), 'INVALID', 'INVALID_WALLET'],
  ['negative free', w => add(w, row('ETH', -1, 0, 0)), 'UNSUPPORTED', 'NEGATIVE_NATIVE_WALLET'],
  ['negative used', w => add(w, row('ETH', 0, -1, 0)), 'UNSUPPORTED', 'NEGATIVE_NATIVE_WALLET'],
  ['negative total', w => add(w, row('ETH', 0, 0, -1)), 'UNSUPPORTED', 'NEGATIVE_NATIVE_WALLET'],
  ['residual used', w => { USDT(w).used = 1; }, 'UNSUPPORTED', 'RESIDUAL_OR_INCONSISTENT_WALLET'],
  ['inconsistent free total', w => { USDT(w).free = 0; }, 'UNSUPPORTED', 'RESIDUAL_OR_INCONSISTENT_WALLET'],
  ['duplicate currency', w => add(w, structuredClone(USDT(w))), 'INVALID', 'INVALID_WALLET'],
  ['unsorted currencies', w => { w.balances.push(row('ETH')); }, 'INVALID', 'INVALID_WALLET'],
  ['cash query differs', w => { w.cash = 123; }, 'INVALID', 'WALLET_QUERY_MISMATCH'],
  ['asset query differs', w => { add(w, row('BTC')); w.asset = 1; }, 'INVALID', 'WALLET_QUERY_MISMATCH'],
  ['missing positive cash currency', w => { w.balances = []; }, 'INVALID', 'MISSING_WALLET_CURRENCY'],
  ['missing positive asset currency', w => { w.balances = w.balances.filter(r => r.currency !== 'BTC'); w.asset = 1; }, 'INVALID', 'MISSING_WALLET_CURRENCY'],
  ['33-entry wallet', w => { for (let i = 0; i < 32; i++) add(w, row('ZZ' + String(i).padStart(2, '0'))); }, 'INVALID', 'INVALID_WALLET'],
  ['row rejection precedes sorted uniqueness', w => { add(w, structuredClone(USDT(w))); add(w, row('ZZ', -1)); }, 'UNSUPPORTED', 'NEGATIVE_NATIVE_WALLET'],
];
function expectedRejection(stage, name, status, reason) {
  // Python rejects a nonzero pre-force asset query before inspecting any wallet row.
  return stage === 'pre_force_exit' && ['asset query differs', 'missing positive asset currency'].includes(name)
    ? ['UNSUPPORTED', 'FORCED_LIQUIDATION_UNSUPPORTED'] : [status, reason];
}
function rejected(report, status, reason) {
  assert.equal(report.integrity, 'VALID', report.reason_codes); const result = report.accounting.attempts[0];
  assert.equal(result.capture.status, status); assert.deepEqual(result.capture.reason_codes, [reason]);
  assert.equal(result.status, 'NOT_ASSESSABLE'); assert.equal(report.accounting.status, 'NOT_ASSESSABLE');
  assert.equal(result.events, null); assert.equal(result.exact_model, null); assert.equal(result.native_compatibility, null);
  assert.equal(Object.keys(result.native_metrics).length, 9);
  assert.equal(Object.values(result.native_metrics).every(v => v.status === 'NOT_SUPPLIED'), true); assert.notEqual(result.oracle.status, 'SUPPLIED_MATCHED');
}
function supported(report) {
  assert.equal(report.integrity, 'VALID', report.reason_codes); const result = report.accounting.attempts[0]; assert.equal(result.capture.status, 'SUPPORTED', result.capture.reason_codes);
  assert.equal(result.native_compatibility.status, 'MATCHES_ENGINE_NUMERIC_POLICY'); assert.ok(result.exact_model.computed);
  assert.equal(Object.values(result.native_metrics).filter(v => v.status === 'NOT_SUPPLIED').length, 6);
  assert.equal(result.status, 'NOT_ASSESSABLE'); assert.equal(report.accounting.status, 'NOT_ASSESSABLE');
}
test('valid original mocked baseline retains its separate financial states', async () => supported(await verify(fixture())));
for (const stage of stages) {
  for (const [name, edit, status, reason] of rejects) test(`${stage}: ${name} cannot promote any financial assessment`, async () => {
    const state = fixture(); edit(state.capture[stage].wallets); rejected(await verify(state), ...expectedRejection(stage, name, status, reason));
  });
  for (const [name, edit] of [
    ['zero foreign asset', w => add(w, row('ETH'))],
    ['maximum currency length', w => add(w, row('A' + '9'.repeat(11)))],
    ['32-entry wallet', w => { for (let i = 0; i < 31; i++) add(w, row('ZZ' + String(i).padStart(2, '0'))); }],
    ['ordinary zero equality accepts signed zero', w => { add(w, row('ETH', n(-0), 0, n(0))); w.asset = n(-0); }],
  ]) test(`${stage}: ${name} remains supported`, async () => { const state = fixture(); edit(state.capture[stage].wallets); supported(await verify(state)); });
}
// Explicit opt-in retained evidence only. Default tests need no Python or sibling toolkit.
test('retained oracle receipt loses financial promotion for each independently rebound wallet stage', { skip: !process.env.N170_WALLET_SCOPE_PACKAGE }, async () => {
  const original = JSON.parse(await readFile(process.env.N170_WALLET_SCOPE_PACKAGE, 'utf8'));
  const baseline = await verifyRunReviewV2(JSON.stringify(original)); supported(baseline); assert.equal(baseline.accounting.attempts[0].oracle.status, 'SUPPLIED_MATCHED');
  function rebound(stage, edit) {
    const envelope = structuredClone(original), manifest = JSON.parse(Buffer.from(envelope.manifest.base64, 'base64'));
    const files = new Map(envelope.artifacts.map(d => [d.path, Buffer.from(d.base64, 'base64')]));
    const capture = JSON.parse(files.get(out + 'baseline-capture.json')); edit(capture[stage].wallets); const raw = bytes(capture); files.set(out + 'baseline-capture.json', raw);
    const worker = JSON.parse(files.get(out + 'worker-result.json')); worker.capture.size = raw.length; worker.capture.sha256 = sha(raw); files.set(out + 'worker-result.json', bytes(worker)); manifest.attempts[0].capture = structuredClone(worker.capture);
    const outputs = Object.fromEntries([...files].filter(([p]) => p.startsWith(out)).map(([p, raw]) => [p.slice(out.length), raw.toString('base64')]));
    const log = files.get(prefix + 'stdout.log').toString('utf8').split('\n').filter(line => !line.startsWith('N170_RESULT_BUNDLE_V2:')).join('\n');
    files.set(prefix + 'stdout.log', Buffer.from(log + '\nN170_RESULT_BUNDLE_V2:' + bytes(outputs).toString('base64') + '\n'));
    envelope.artifacts = [...files].sort(([a], [b]) => a < b ? -1 : 1).map(([p, raw]) => descriptor(p, raw)); manifest.artifacts = envelope.artifacts.map(entry);
    for (const attempt of manifest.attempts) attempt.artifacts = manifest.artifacts.filter(item => item.path.startsWith(`attempts/${attempt.id}/`));
    envelope.manifest = descriptor('manifest.json', bytes(manifest)); return JSON.stringify(envelope);
  }
  for (const stage of stages) {
    for (const [name, edit, status, reason] of rejects) {
      const report = await verifyRunReviewV2(rebound(stage, edit)); rejected(report, ...expectedRejection(stage, name, status, reason));
      assert.equal(report.accounting.attempts[0].oracle.status, 'UNAVAILABLE'); assert.deepEqual(report.accounting.attempts[0].oracle.reason_codes, ['SUPPORTED_CAPTURE_REQUIRED']);
    }
    const allowed = await verifyRunReviewV2(rebound(stage, w => add(w, row('ETH')))); supported(allowed); assert.equal(allowed.accounting.attempts[0].oracle.status, 'SUPPLIED_MATCHED');
  }
});
