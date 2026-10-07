import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { verifyRunReview } from '../src/runReview.js';
import { verifyRunReviewV2, verifyRunReviewPackage } from '../src/runReviewV2.js';
import { numberHex, canonicalNativeRepr, generateOracleLedger } from '../src/accountingExact.js';

// Explicitly attacker-authored original unit capture, never an engine run.
// Mathematical answers come from the separately frozen closed_gain challenge.
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

test('v2 performs its own exact/native calculations and retains six absent metrics without a financial pass', async () => {
  const report = await verify(fixture()); assert.equal(report.integrity, 'VALID', report.reason_codes);
  const accounting = report.accounting.attempts[0];
  assert.equal(accounting.capture.status, 'SUPPORTED', accounting.reason_codes);
  assert.equal(accounting.exact_model.computed.cash, '1000000019.58'); assert.equal(accounting.exact_model.computed.fees, '0.42');
  assert.equal(accounting.exact_model.computed.realized_pnl, '20'); assert.equal(accounting.exact_model.status, 'NOT_ASSESSABLE');
  assert.equal(accounting.native_compatibility.status, 'MATCHES_ENGINE_NUMERIC_POLICY'); assert.equal(accounting.status, 'NOT_ASSESSABLE');
  assert.equal(Object.values(accounting.native_metrics).filter(v => v.status === 'NOT_SUPPLIED').length, 6);
  assert.equal(accounting.oracle.status, 'NOT_RUN'); assert.match(report.trust.authenticity, /unsigned/);
});
test('version dispatch preserves v1 report behavior byte-for-byte and v2 cannot be imported as v1', async () => {
  assert.deepEqual(await verifyRunReviewPackage(JSON.stringify(legacy)), await verifyRunReview(JSON.stringify(legacy)));
  assert.equal((await verifyRunReview(JSON.stringify(pack(fixture())))).integrity, 'INVALID');
  assert.equal((await verifyRunReviewPackage(JSON.stringify(pack(fixture())))).integrity, 'VALID');
});
test('capture byte descriptors, input identities, runtime and observed source hashes are independently bound', async () => {
  for (const field of ['run_id', 'attempt_id', 'strategy', 'request_sha256', 'collector_sha256', 'helper_sha256', 'engine_source_sha256']) {
    const state = fixture(); pack(state); state.capture.binding[field] = 'tampered';
    assert.equal((await verify(state, { binding: false })).integrity, 'INVALID', field);
  }
  const state = fixture(); pack(state); state.worker.capture.sha256 = '0'.repeat(64);
  assert.equal((await verify(state, { descriptorBinding: false })).integrity, 'INVALID');
  for (const field of ['python_version', 'ccxt_version', 'numpy_version', 'ccxt_precise_after_sha256']) {
    const state = fixture(); state.capture.runtime[field] = 'unsupported'; const report = await verify(state);
    assert.notEqual(report.accounting.attempts[0].capture.status, 'SUPPORTED');
  }
});
test('duplicate, omitted, reordered, changed and chronologically invalid completion records cannot pass', async () => {
  for (const edit of [c => c.completions.reverse(), c => c.completions.pop(), c => c.completions.push(structuredClone(c.completions[0])),
    c => { c.completions[0].sequence = 2; }, c => { c.completions[1].order = { ...c.completions[1].order, filled: n(1) }; },
    c => { c.final.close_order = [2]; }, c => { c.completions[1].order = { ...c.completions[1].order, filled_at: '2025-12-31T00:00:00Z' }; }]) {
    const state = fixture(); edit(state.capture); const report = await verify(state); assert.equal(report.integrity, 'VALID');
    assert.equal(report.accounting.attempts[0].capture.status, 'INVALID', report.accounting.attempts[0].reason_codes);
  }
});
test('partial fills, forced liquidation and base fees stay outside scope despite refreshed matching hashes', async () => {
  for (const edit of [c => { c.completions[1].order.remaining = n(1); }, c => { c.completions[1].phase = 'forced_liquidation'; },
    c => { c.completions[0].order.fee_base = n(0.002); }, c => { c.final.closed_trades[0].exit_reason = 'force_exit'; c.final.trade_rows.rows[0][c.final.trade_rows.columns.indexOf('exit_reason')] = 'force_exit'; },
    c => { c.completions[0].trade_fee_currencies.open = 'BTC'; }]) {
    const state = fixture(); edit(state.capture); const report = await verify(state); assert.equal(report.integrity, 'VALID');
    assert.equal(report.accounting.attempts[0].capture.status, 'UNSUPPORTED', report.accounting.attempts[0].reason_codes);
    assert.equal(report.accounting.attempts[0].native_compatibility, null);
  }
});
test('missing hooks, failed/truncated capture and unknown fields do not produce an accounting success', async () => {
  for (const edit of [c => { c.capture.truncated = true; }, c => { c.capture.status = 'FAILED'; }, c => { c.capture.hook_counts.final = 0; },
    c => { c.capture.reason_codes = ['INCOMPLETE']; }, c => { c.authenticated = true; }]) {
    const state = fixture(); edit(state.capture); const report = await verify(state);
    assert.notEqual(report.accounting.attempts[0].capture.status, 'SUPPORTED'); assert.equal(report.accounting.status, 'NOT_ASSESSABLE');
  }
});
test('native source bit identities, close accumulation and final wallet corroboration reject contradictions', async () => {
  for (const edit of [c => { c.final.native_final_balance = n(1019.59); }, c => { c.closes[0].total_profit_after = n(19.59); },
    c => { c.closes[0].close_profit_abs = n(19.59); }, c => { c.final.wallets.cash = { ...c.final.wallets.cash, repr: '1' }; },
    c => { c.completions[0].order.filled = { encoding: 'binary64', repr: 'np.float64(2.0)', hex: numberHex(2) }; }]) {
    const state = fixture(); edit(state.capture); const report = await verify(state);
    assert.equal(report.accounting.attempts[0].capture.status, 'INVALID');
  }
});
test('self-consistent wrong native arithmetic remains a replay mismatch instead of widening a tolerance', async () => {
  const state = fixture(); const c = state.capture; const profit = 19.58000001, cash = 1000000000 + profit;
  c.closes[0].close_profit_abs = n(profit); c.closes[0].total_profit_after = n(profit); c.final.closed_trades[0].close_profit_abs = n(profit);
  c.final.trade_rows.rows[0][c.final.trade_rows.columns.indexOf('profit_abs')] = n(profit);
  c.final.native_total_closed_profit = n(profit); c.final.native_final_balance = n(cash); c.final.wallets = wallet(cash); c.pre_force_exit.wallets = wallet(cash);
  const report = await verify(state); assert.equal(report.accounting.attempts[0].native_compatibility.status, 'MISMATCH');
  assert.equal(report.accounting.attempts[0].exact_model.computed.cash, '1000000019.58');
});
test('source candle values and bounded windows cannot be substituted with unrelated claims', async () => {
  for (const edit of [c => { c.window.candle_count++; }, c => { c.window.processed_bounds['BTC/USDT'].count--; },
    c => { c.pre_force_exit.terminal_candles['BTC/USDT'].ohlcv.close = n(999); }, c => { c.window.requested_timerange = '20270101-20270103'; }]) {
    const state = fixture(); edit(state.capture); const report = await verify(state); assert.equal(report.accounting.attempts[0].capture.status, 'INVALID');
  }
});
test('corroborating dataframe cells, wallet queries and resolved knobs cannot contradict the financial source', async () => {
  for (const edit of [c => { c.final.trade_rows.rows[0][c.final.trade_rows.columns.indexOf('stake_amount')] = n(999); },
    c => { c.final.trade_rows.rows[0][c.final.trade_rows.columns.indexOf('orders')][0].cost = n(999); },
    c => { c.final.trade_rows.rows[0][c.final.trade_rows.columns.indexOf('open_timestamp')] += 1; },
    c => { c.opening.wallets.balances = []; },
    c => { c.resolved.config.dry_run_wallet = 42; }, c => { c.resolved.config.stake_amount = 999; },
    c => { c.resolved.config.strategy = 'Unselected'; }, c => { c.resolved.config.exchange.pair_whitelist = ['ETH/USDT']; },
    c => { c.resolved.config.timerange = '1767225600-1767312000'; },
    c => { c.resolved.config.order_types = {entry:'limit',exit:'market'}; }]) {
    const state = fixture(); edit(state.capture); const report = await verify(state);
    assert.equal(report.integrity, 'VALID'); assert.equal(report.accounting.attempts[0].capture.status, 'INVALID', report.accounting.attempts[0].reason_codes);
    assert.equal(report.accounting.attempts[0].exact_model, null);
  }
});
test('residual used wallet balance is unsupported and cannot promote a financial assessment', async () => {
  const state = fixture(); state.capture.final.wallets.balances[0].used = n(123);
  const report = await verify(state); const accounting = report.accounting.attempts[0];
  assert.equal(report.integrity, 'VALID');
  assert.deepEqual(accounting.capture, { status: 'UNSUPPORTED', reason_codes: ['RESIDUAL_OR_INCONSISTENT_WALLET'] });
  assert.equal(accounting.status, 'NOT_ASSESSABLE'); assert.equal(report.accounting.status, 'NOT_ASSESSABLE');
  assert.equal(accounting.events, null); assert.equal(accounting.exact_model, null); assert.equal(accounting.native_compatibility, null);
  assert.equal(Object.values(accounting.native_metrics).filter(item => item.status === 'NOT_SUPPLIED').length, 9);
  assert.notEqual(accounting.oracle.status, 'SUPPLIED_MATCHED');
});
test('same-bit alternate decimal provenance is unsupported rather than changing the exact fee operands', async () => {
  const state = fixture();
  state.capture.completions[0].order.safe_price = { encoding: 'binary64', repr: '100.000000000000001', hex: numberHex(100) };
  const report = await verify(state);
  assert.equal(report.accounting.attempts[0].capture.status, 'UNSUPPORTED');
  assert.deepEqual(report.accounting.attempts[0].capture.reason_codes, ['UNSUPPORTED_NATIVE_SPELLING']);
  assert.equal(report.accounting.attempts[0].exact_model, null);
});
test('optional oracle evidence is never inferred from hashes, missing files, a forged ledger or executable contents', async () => {
  const folder = prefix + 'accounting/';
  const partial = fixture(); partial.files.set(folder + 'events.json', bytes({}));
  assert.equal((await verify(partial)).accounting.attempts[0].oracle.status, 'MISSING');
  const seed = fixture(); const assessment = (await verify(seed)).accounting.attempts[0];
  const full = () => {
    const state = fixture(); const { files } = state;
    files.set(folder + 'events.json', bytes(assessment.events));
    files.set(folder + 'ledger.beancount', Buffer.from(generateOracleLedger(assessment.events)));
    files.set(folder + 'oracle-worker.py', Buffer.from('raise Exception("never execute supplied code")\n'));
    files.set(folder + 'oracle.stdout.json', bytes({})); files.set(folder + 'oracle.stderr.txt', Buffer.alloc(0));
    files.set(folder + 'report.json', bytes({ schema: 'n170.accounting.reconciliation.v2', computed: assessment.exact_model.computed,
      event_checkpoints: assessment.exact_model.event_checkpoints, oracle: {} }));
    return state;
  };
  const changedEvents = full(); changedEvents.files.set(folder + 'events.json', bytes({ ...assessment.events, evidence_class: 'synthetic_fixture' }));
  assert.deepEqual((await verify(changedEvents)).accounting.attempts[0].oracle.reason_codes, ['ORACLE_EVENT_BINDING_MISMATCH']);
  const changedLedger = full(); changedLedger.files.set(folder + 'ledger.beancount', Buffer.from('plugin "malicious"\n'));
  assert.deepEqual((await verify(changedLedger)).accounting.attempts[0].oracle.reason_codes, ['ORACLE_LEDGER_MISMATCH']);
  assert.equal((await verify(full())).accounting.attempts[0].oracle.status, 'INVALID');
  assert.equal((await verify(full())).accounting.attempts[0].status, 'NOT_ASSESSABLE');
});
test('optional original actual engine packages retain separate detector and accounting outcomes', { skip: !process.env.N170_ACCOUNTING_V2_PACKAGE_ROOT }, async () => {
  for (const name of ['flat-02', 'smooth', 'forced', 'smooth-oracle']) {
    const report = await verifyRunReviewV2(await readFile(join(process.env.N170_ACCOUNTING_V2_PACKAGE_ROOT, name + '.json'), 'utf8'));
    assert.equal(report.integrity, 'VALID', `${name}: ${report.reason_codes}`);
    for (const item of report.accounting.attempts) assert.equal(item.status, 'NOT_ASSESSABLE');
    const item = report.accounting.attempts[0];
    if (name === 'forced') { assert.equal(item.capture.status, 'UNSUPPORTED'); assert.equal(item.exact_model, null); }
    else { assert.equal(item.capture.status, 'SUPPORTED', item.reason_codes); assert.equal(item.native_compatibility.status, 'MATCHES_ENGINE_NUMERIC_POLICY'); }
    if (name === 'smooth-oracle') assert.equal(item.oracle.status, 'SUPPLIED_MATCHED', item.oracle.reason_codes);
  }
});
test('optional real oracle bytes are recomputed; forged summaries, worker code, provenance and output claims cannot pass', { skip: !process.env.N170_ACCOUNTING_V2_PACKAGE_ROOT }, async () => {
  const original = JSON.parse(await readFile(join(process.env.N170_ACCOUNTING_V2_PACKAGE_ROOT, 'smooth-oracle.json'), 'utf8'));
  const folder = prefix + 'accounting/';
  async function edited(edit) {
    const envelope = structuredClone(original), files = new Map(envelope.artifacts.map(d => [d.path, Buffer.from(d.base64, 'base64')]));
    edit(files); envelope.artifacts = [...files].sort(([a], [b]) => a < b ? -1 : 1).map(([p, raw]) => descriptor(p, raw));
    const manifest = JSON.parse(Buffer.from(envelope.manifest.base64, 'base64')); manifest.artifacts = envelope.artifacts.map(entry);
    for (const attempt of manifest.attempts) attempt.artifacts = manifest.artifacts.filter(i => i.path.startsWith(`attempts/${attempt.id}/`));
    envelope.manifest = descriptor('manifest.json', bytes(manifest)); return verifyRunReviewV2(JSON.stringify(envelope));
  }
  for (const edit of [files => files.delete(folder + 'oracle.stderr.txt'), files => files.set(folder + 'oracle-worker.py', Buffer.from('print("MATCHED")')),
    files => { const r = JSON.parse(files.get(folder + 'report.json')); r.computed.cash = '1'; files.set(folder + 'report.json', bytes(r)); },
    files => { const r = JSON.parse(files.get(folder + 'oracle.stdout.json')); r.computed.cash = '1'; files.set(folder + 'oracle.stdout.json', bytes(r)); },
    files => { const d = JSON.parse(files.get(folder + 'events.json')); d.events[0].fee_model.sources[0] = 'unrelated-source'; files.set(folder + 'events.json', bytes(d)); }]) {
    const report = await edited(edit); assert.equal(report.integrity, 'VALID'); assert.notEqual(report.accounting.attempts[0].oracle.status, 'SUPPLIED_MATCHED');
  }
  const disagrees = await edited(files => {
    const observation = JSON.parse(files.get(folder + 'oracle.stdout.json')); observation.computed.cash = '1';
    const raw = bytes(observation); files.set(folder + 'oracle.stdout.json', raw);
    const source = JSON.parse(files.get(folder + 'report.json')); source.oracle.observation = observation;
    source.oracle['oracle.stdout.json'] = { observed_bytes: raw.length, retained_bytes: raw.length, truncated: false, sha256: sha(raw) };
    source.oracle.different_metrics = ['cash']; source.oracle.status = 'DISCREPANCIES_FOUND'; files.set(folder + 'report.json', bytes(source));
  });
  assert.equal(disagrees.accounting.attempts[0].oracle.status, 'SUPPLIED_DISCREPANCIES');
  assert.equal(disagrees.accounting.status, 'NOT_ASSESSABLE');
});
