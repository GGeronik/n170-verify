# Full-baseline acquisition contract v1 (worker/run v2)

This contract introduces `n170.freqtrade-baseline-capture.v1`, worker
`n170.freqtrade-worker.v2`, run `n170.freqtrade-run.v2` and stdout prefix
`N170_RESULT_BUNDLE_V2:`. Existing v1 source, formats and validation are unchanged.
The new worker invokes the unchanged v1 helper under disclosed original observer
wrappers. The engine and CCXT stay separately installed; no upstream code is shipped.

## Exact capture objects

Every object below has exactly the listed keys. Nullable stage objects are null
until actually observed. `N` is a safe JSON integer, or exactly
`{encoding:"binary64",repr:string,hex:string}` from one finite Python binary64.
NumPy float64 is normalized before repr/hex; float32/longdouble are rejected.
Signed zero is preserved. UTC timestamps are explicit ISO strings ending `Z`.
Opaque native string values remain bounded data, never expressions to evaluate.

- Capture: `schema,capture_policy,binding,capture,runtime,scope,window,resolved,opening,completions,closes,pre_force_exit,final,trust`.
- Binding: `run_id,attempt_id,strategy,request_sha256,input_inventory,collector_sha256,worker_sha256,helper_sha256,market_metadata_sha256,engine_revision,engine_source_sha256,engine_source_after_sha256`.
  Inventory entries: `path,size,sha256`; input inventory excludes request.json.
- Capture state: `status,reason_codes,hook_counts,completion_count,closed_trade_count,terminal_order_count,truncated`.
  Status is COMPLETE, INCOMPLETE or FAILED. Hook counts have `baseline,backtest,opening,pre_force_exit,final`; complete requires exactly one each.
- Runtime: `implementation,python_version,float_info,numpy_version,ccxt_version,ccxt_precise_sha256,ccxt_precise_after_sha256`.
  Float info: `radix,mant_dig,max_exp,min_exp,rounds`; required runtime is CPython
  3.14.7, radix2/mantissa53, NumPy2.4.6, CCXT4.5.76. precise.py SHA-256 before/after:
  `445721221b65f37cc198adaeec26f68b214926e82ea2bfc0195a346ec94773ed`.
- Scope: `pair,timeframe,trading_mode,fee_model`. Constants: BTC/USDT, 5m, spot,
  `quote-filled-price-rate.v1`. These describe acquisition, not supported accounting.
- Window: `requested_timerange,backtest_start,backtest_end,processed_bounds,candle_count`.
  Processed bounds is a pair-keyed map of `{first,last,count}` observed after reset
  and before conversion; actual start/end are Backtesting.backtest arguments.
- Resolved: `config,strategy_settings`. Config is the complete observed resolved
  configuration, strictly data-encoded (string keys, explicit paths/enum values,
  N scalars, bool/null/list/object; never default=str). Strategy settings have
  `timeframe,startup_candle_count,minimal_roi,stoploss,can_short,position_adjustment_enable,order_types`.
- Wallet: `balances,cash,asset`. Balances is a currency-sorted list of
  `{currency,free,used,total}`. Cash/asset are actual get_total(USDT/BTC) observations;
  absence from balances remains visible separately from the query's default zero.
- Opening: `wallets,starting_balance,open_trades,closed_trade_count,total_closed_profit`.
- Order: `id,order_id,pair,side,type,status,is_open,amount,filled,remaining,price,average,safe_price,cost,fee_base,created_at,filled_at,tag`.
- Completion: `sequence,phase,trade_id,order,trade_fee_rates,trade_fee_costs,trade_fee_currencies`.
  Each of the three fee objects has `open,close`; phase is baseline or forced_liquidation.
  Sequence is monotonically increasing in actual completion order, without sorting.
- Close: `sequence,trade_id,close_profit_abs,total_profit_before,total_profit_after`.
  The observer calls actual LocalTrade.close_bt_trade once and preserves its result.
- Trade: `trade_id,pair,is_open,is_short,trading_mode,leverage,amount,stake_amount,open_rate,close_rate,fee_open,fee_close,fee_open_cost,fee_close_cost,fee_open_currency,fee_close_currency,open_date,close_date,exit_reason,entry_count,exit_count,close_profit_abs,realized_profit,funding_fees,has_open_orders,orders`.
- Pre-force: `wallets,open_trades,terminal_candles`. Terminal candles is pair-keyed:
  `{ohlcv,backtest_row}`. OHLCV has `date,open,high,low,close,volume` from the last
  processed source row. Backtest row has `date,open,high,low,close` actually supplied
  to forced handling. Matching date/OHLC is checked, not inferred.
- Final: `wallets,open_trades,closed_trades,trade_rows,native_final_balance,native_total_closed_profit,close_order,engine_counters,wallet_summary`.
  close_order is the actual final LocalTrade.bt_trades ID order, corroborated by closes.
  Dataframe (`trade_rows`,`wallet_summary`): `columns,rows` with each row an ordered
  list matching columns. The empty native wallet summary stays empty.
  Counters: `rejected_trades,timedout_entry_orders,timedout_exit_orders,canceled_trade_entries,canceled_entry_orders,replaced_entry_orders,canceled_exit_orders,replaced_exit_orders`.
- Trust: `execution,authenticity,completeness,fees,observer`. Values explicitly declare
  unsigned modeled backtest observations and runtime observer hooks.

## Acquisition, binding and transport

Only the full LookaheadAnalysis.fill_full_varholder invocation activates observers.
Snapshots are converted to independent data immediately; hooks are restored before
sliced detector runs and in every failure path. Exactly one full baseline is required.
Observers preserve original arguments and return values and invoke the original once.
Collector errors preserve an incomplete capture and do not manufacture native values.

The v2 attempt request adds exactly `schema,run_id,attempt_id` to v1's per-attempt
request, schema `n170.freqtrade-request.v2`. Staged source files include v2 entrypoint
as engine_worker.py, unchanged v1 engine_worker_v1.py and accounting_collector.py.
Worker receipt adds exactly `capture` with `schema,path,size,sha256,status,reason_codes`;
path is baseline-capture.json. The observer is separately disclosed in that artifact.
The attempt also adds `capture`, mirroring the exact worker descriptor when present;
it stays null when no worker result was transported. Acquisition verification reports
`INVENTORY_AND_CAPTURE_BINDINGS_CONSISTENT`, which makes no financial claim.
Optional offline oracle artifacts live outside worker output at
`attempts/NNN/accounting/{events.json,ledger.beancount,oracle-worker.py,oracle.stdout.json,oracle.stderr.txt,report.json}`.
They must appear in both run and attempt inventories. The portable review layer
validates their financial bindings; acquisition verification only checks their bytes.
Worker native outputs are the four v1 filenames plus baseline-capture.json. No
financial model, replay result or oracle statement is manufactured by the worker.

Limits: capture 2MiB, up to 10,000 completion/close records, 24 JSON levels,
200,000 nodes, 1MiB per string. Limit exhaustion records FAILED/truncated evidence;
no silent successful prefix. The unchanged host 8MiB log bound still applies.
V2 transport permits at most 6MiB encoded and 3MiB total decoded output; each native
output at most 2MiB. Finalized transport binds all emitted files exactly.

COMPLETE capture does not grant financial scope. Root's offline adapter validates
bijection and immutable order/trade identities, chronological sequence, full fills,
fixed quote-fee model and all source/runtime bindings. Forced exits remain captured
and `FORCED_LIQUIDATION_UNSUPPORTED`; no-trade/failed/interrupted cases stay explicit.
Native missing metrics are never filled with N170's model results. Detached hashes
bind bytes only; producer, broker and global historical completeness remain unknown.
