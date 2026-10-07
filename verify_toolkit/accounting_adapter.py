"""Original data-only bridge from bound native observations to exact accounting.

No strategy, supplied command, engine or external oracle is executed by this module.
Native float observations and exact decimal model claims deliberately stay separate.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import math
import re

from .run_review import strict_json

CAPTURE_SCHEMA = "n170.freqtrade-baseline-capture.v1"
POLICY = "freqtrade-2026.8-full-baseline-observer.v1"
ENGINE_REVISION = "9f10e357a93c1dcf10c2a2b367659214d89c073e"
ENGINE_SOURCE = "a96f980268301b69f8fb6e423d27606ede3f174449f63ff672aebb48f97ac6de"
PRECISE_SOURCE = "445721221b65f37cc198adaeec26f68b214926e82ea2bfc0195a346ec94773ed"
METRICS = ("cash", "quantity", "cost_basis", "fees", "realized_pnl", "unrealized_pnl", "external_flows", "net_pnl", "nav")
ORDER_KEYS = "id order_id pair side type status is_open amount filled remaining price average safe_price cost fee_base created_at filled_at tag".split()
TRADE_KEYS = "trade_id pair is_open is_short trading_mode leverage amount stake_amount open_rate close_rate fee_open fee_close fee_open_cost fee_close_cost fee_open_currency fee_close_currency open_date close_date exit_reason entry_count exit_count close_profit_abs realized_profit funding_fees has_open_orders orders".split()


class CaptureError(ValueError):
    def __init__(self, reason, status="INVALID"):
        self.status = status
        super().__init__(reason)


def require(condition, reason, status="INVALID"):
    if not condition:
        raise CaptureError(reason, status)


def keys(value, names, reason="INVALID_CAPTURE_FIELDS"):
    require(type(value) is dict and set(value) == set(names.split() if isinstance(names, str) else names), reason)


def numeric(value):
    """Exact decimal spelling; never quantize native observations into the domain."""
    if type(value) is int:
        require(abs(value) <= 2**53 - 1, "UNSAFE_NATIVE_INTEGER")
        return Decimal(value)
    keys(value, "encoding repr hex", "INVALID_NATIVE_NUMBER")
    require(value["encoding"] == "binary64" and type(value["repr"]) is str and type(value["hex"]) is str,
            "INVALID_NATIVE_NUMBER")
    require(len(value["repr"]) <= 32 and len(value["hex"]) <= 32, "INVALID_NATIVE_NUMBER")
    try:
        native = float.fromhex(value["hex"])
        spelled = float(value["repr"])
    except (ValueError, OverflowError):
        raise CaptureError("INVALID_NATIVE_NUMBER") from None
    require(math.isfinite(native) and native.hex() == value["hex"] and spelled.hex() == native.hex()
            and repr(native) == value["repr"], "NATIVE_FLOAT_ENCODING_MISMATCH")
    return Decimal(value["repr"])


def decimal_text(value):
    text = format(value, "f")
    return "0" if not value else (text.rstrip("0").rstrip(".") if "." in text else text)


def operand(value):
    from verify_accounting.v2 import number
    text = decimal_text(numeric(value))
    try:
        number(text, kind="operand")
    except ValueError:
        raise CaptureError("NATIVE_OPERAND_OUTSIDE_DECIMAL_DOMAIN", "UNSUPPORTED") from None
    return text


def stamp(value):
    require(type(value) is str and len(value) <= 32 and value.endswith("Z"), "INVALID_CAPTURE_TIME")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise CaptureError("INVALID_CAPTURE_TIME") from None
    require(2000 <= result.year <= 2100, "INVALID_CAPTURE_TIME")
    return result


def identity(value):
    require(type(value) is int and 0 < value <= 2**53 - 1, "INVALID_NATIVE_ID")
    return value


def _walk_scalars(value):
    if type(value) is dict:
        if "encoding" in value:
            numeric(value)
        else:
            for child in value.values():
                _walk_scalars(child)
    elif type(value) is list:
        for child in value:
            _walk_scalars(child)
    else:
        require(value is None or type(value) in (bool, str, int), "UNTAGGED_NATIVE_FLOAT")
        if type(value) is int:
            numeric(value)


def wallet(value):
    keys(value, "balances cash asset")
    require(type(value["balances"]) is list and len(value["balances"]) <= 32, "INVALID_WALLET")
    currencies = []
    for entry in value["balances"]:
        keys(entry, "currency free used total")
        currency = entry["currency"]
        require(type(currency) is str and re.fullmatch(r"[A-Z][A-Z0-9]{1,11}", currency), "INVALID_WALLET")
        currencies.append(currency)
        free, used, total = (numeric(entry[k]) for k in ("free", "used", "total"))
        require(min(free, used, total) >= 0, "NEGATIVE_NATIVE_WALLET", "UNSUPPORTED")
        require(used == 0 and free == total, "RESIDUAL_OR_INCONSISTENT_WALLET", "UNSUPPORTED")
        require(currency in {"BTC", "USDT"} or total == 0, "OTHER_ASSET_BALANCE_UNSUPPORTED", "UNSUPPORTED")
        if currency in {"BTC", "USDT"}:
            require(total == numeric(value["cash" if currency == "USDT" else "asset"]), "WALLET_QUERY_MISMATCH")
    require(currencies == sorted(set(currencies)), "INVALID_WALLET")
    numeric(value["cash"])
    numeric(value["asset"])
    for currency, query in (("USDT", "cash"), ("BTC", "asset")):
        require(currency in currencies or numeric(value[query]) == 0, "MISSING_WALLET_CURRENCY")


def order(value):
    keys(value, ORDER_KEYS)
    identity(value["id"])
    require(type(value["order_id"]) is str and 1 <= len(value["order_id"]) <= 64, "INVALID_NATIVE_ID")
    require(value["pair"] == "BTC/USDT" and value["side"] in {"buy", "sell"}, "ORDER_SCOPE_UNSUPPORTED", "UNSUPPORTED")
    require(value["type"] == "market" and value["status"] == "closed" and value["is_open"] is False,
            "ORDER_NOT_FULLY_CLOSED", "UNSUPPORTED")
    require(numeric(value["filled"]) > 0 and numeric(value["remaining"]) == 0
            and numeric(value["filled"]) == numeric(value["amount"]), "PARTIAL_OR_ZERO_FILL_UNSUPPORTED", "UNSUPPORTED")
    require(value["fee_base"] is None or numeric(value["fee_base"]) == 0, "BASE_FEE_UNSUPPORTED", "UNSUPPORTED")
    require(numeric(value["safe_price"]) > 0, "INVALID_FILL_PRICE")
    require(value["average"] is None or numeric(value["average"]) == numeric(value["safe_price"]), "FILL_PRICE_MISMATCH")
    require(numeric(value["price"]) == numeric(value["safe_price"]), "MULTIPLE_PRICE_SEMANTICS_UNSUPPORTED", "UNSUPPORTED")
    require(stamp(value["created_at"]) <= stamp(value["filled_at"]), "ORDER_TIME_MISMATCH")
    require(value["tag"] is None or type(value["tag"]) is str, "INVALID_ORDER_TAG")


def _binding(capture, context):
    require(type(context) is dict, "BOUND_RUN_CONTEXT_REQUIRED")
    bound = capture["binding"]
    keys(bound, "run_id attempt_id strategy request_sha256 input_inventory collector_sha256 worker_sha256 helper_sha256 market_metadata_sha256 engine_revision engine_source_sha256 engine_source_after_sha256")
    for key in ("run_id", "attempt_id", "strategy", "request_sha256", "input_inventory"):
        require(bound[key] == context[key], "CAPTURE_INPUT_BINDING_MISMATCH")
    require(bound["engine_revision"] == ENGINE_REVISION and bound["engine_source_sha256"] == ENGINE_SOURCE
            and bound["engine_source_after_sha256"] == ENGINE_SOURCE, "CAPTURE_ENGINE_BINDING_MISMATCH")
    for field, name in (("collector_sha256", "accounting_collector.py"), ("worker_sha256", "engine_worker.py"), ("helper_sha256", "engine_worker_v1.py")):
        require(bound[field] == hashlib.sha256(context["input_buffers"][name]).hexdigest(), "CAPTURE_SOURCE_BINDING_MISMATCH")
    require(bound["market_metadata_sha256"] == context["worker"]["offline_adapter"]["market_metadata_sha256"], "CAPTURE_MARKET_BINDING_MISMATCH")


def _derive(capture, context):
    from verify_accounting.v2 import modeled_fee
    keys(capture, "schema capture_policy binding capture runtime scope window resolved opening completions closes pre_force_exit final trust")
    require(capture["schema"] == CAPTURE_SCHEMA and capture["capture_policy"] == POLICY, "UNSUPPORTED_CAPTURE_SCHEMA", "UNSUPPORTED")
    _walk_scalars(capture)
    _binding(capture, context)
    state = capture["capture"]
    keys(state, "status reason_codes hook_counts completion_count closed_trade_count terminal_order_count truncated")
    keys(state["hook_counts"], "baseline backtest opening pre_force_exit final")
    require(all(type(state[k]) is int and 0 <= state[k] <= 10000 for k in ("completion_count", "closed_trade_count", "terminal_order_count"))
            and type(state["reason_codes"]) is list, "INVALID_CAPTURE_COUNTS")
    require(state["status"] == "COMPLETE" and state["truncated"] is False and not state["reason_codes"]
            and all(type(x) is int and x == 1 for x in state["hook_counts"].values()), "CAPTURE_NOT_COMPLETE", "UNSUPPORTED")
    keys(capture["scope"], "pair timeframe trading_mode fee_model")
    require(capture["scope"] == {"pair": "BTC/USDT", "timeframe": "5m", "trading_mode": "spot", "fee_model": "quote-filled-price-rate.v1"}, "CAPTURE_SCOPE_UNSUPPORTED", "UNSUPPORTED")
    runtime = capture["runtime"]
    keys(runtime, "implementation python_version float_info numpy_version ccxt_version ccxt_precise_sha256 ccxt_precise_after_sha256")
    require(runtime["implementation"] == "CPython" and runtime["python_version"] == "3.14.7"
            and runtime["numpy_version"] == "2.4.6" and runtime["ccxt_version"] == "4.5.76"
            and runtime["ccxt_precise_sha256"] == runtime["ccxt_precise_after_sha256"] == PRECISE_SOURCE,
            "NATIVE_RUNTIME_UNSUPPORTED", "UNSUPPORTED")
    require(runtime["float_info"] == {"radix": 2, "mant_dig": 53, "max_exp": 1024, "min_exp": -1021, "rounds": 1}, "NATIVE_RUNTIME_UNSUPPORTED", "UNSUPPORTED")
    keys(capture["resolved"], "config strategy_settings")
    settings = capture["resolved"]["strategy_settings"]
    keys(settings, "timeframe startup_candle_count minimal_roi stoploss can_short position_adjustment_enable order_types")
    require(settings["timeframe"] == "5m" and settings["can_short"] is False
            and settings["position_adjustment_enable"] is False
            and settings["order_types"].get("entry") == settings["order_types"].get("exit") == "market",
            "STRATEGY_ACCOUNTING_SCOPE_UNSUPPORTED", "UNSUPPORTED")
    resolved = capture["resolved"]["config"]
    require(type(resolved) is dict and resolved.get("trading_mode") == "spot"
            and resolved.get("stake_currency") == "USDT" and numeric(resolved.get("fee")) == Decimal("0.001"),
            "RESOLVED_ACCOUNTING_SCOPE_UNSUPPORTED", "UNSUPPORTED")
    requested_dates = context["request"]["timerange"].split("-")
    resolved_timerange = "-".join(str(int(datetime.strptime(day, "%Y%m%d").replace(tzinfo=timezone.utc).timestamp())) for day in requested_dates)
    require(resolved.get("dry_run") is True and resolved.get("strategy") == context["strategy"]
            and resolved.get("timeframe") == "5m" and resolved.get("timerange") == resolved_timerange
            and resolved.get("exchange", {}).get("pair_whitelist") == ["BTC/USDT"]
            and resolved.get("position_adjustment_enable") is False, "RESOLVED_CONFIG_BINDING_MISMATCH")
    effective = context["effective_config"]
    for field in ("dry_run_wallet", "fee", "stake_amount"):
        require(numeric(resolved[field]) == Decimal(str(effective[field])), "RESOLVED_CONFIG_BINDING_MISMATCH")
    require(effective.get("timerange") == context["request"]["timerange"], "RESOLVED_CONFIG_BINDING_MISMATCH")
    for field in ("stake_currency", "timeframe", "strategy", "trading_mode"):
        require(resolved[field] == effective[field], "RESOLVED_CONFIG_BINDING_MISMATCH")
    for field in ("timeframe", "startup_candle_count", "minimal_roi", "stoploss", "position_adjustment_enable", "order_types"):
        require(resolved.get(field) == settings[field], "RESOLVED_STRATEGY_BINDING_MISMATCH")
    window = capture["window"]
    keys(window, "requested_timerange backtest_start backtest_end processed_bounds candle_count")
    start, end = stamp(window["backtest_start"]), stamp(window["backtest_end"])
    require(start < end and window["requested_timerange"] == context["request"]["timerange"], "CAPTURE_TIME_BINDING_MISMATCH")
    require(type(window["candle_count"]) is int and 100 <= window["candle_count"] <= 10000, "CAPTURE_CANDLE_SCOPE_UNSUPPORTED", "UNSUPPORTED")
    require(set(window["processed_bounds"]) == {"BTC/USDT"}, "CAPTURE_SCOPE_UNSUPPORTED", "UNSUPPORTED")
    keys(window["processed_bounds"]["BTC/USDT"], "first last count")
    bounds = window["processed_bounds"]["BTC/USDT"]
    require(type(bounds["count"]) is int and 1 <= bounds["count"] <= window["candle_count"]
            and stamp(bounds["first"]) <= start <= end <= stamp(bounds["last"]), "PROCESSED_WINDOW_MISMATCH")
    opening, final, terminal = capture["opening"], capture["final"], capture["pre_force_exit"]
    keys(opening, "wallets starting_balance open_trades closed_trade_count total_closed_profit")
    keys(final, "wallets open_trades closed_trades trade_rows native_final_balance native_total_closed_profit close_order engine_counters wallet_summary")
    keys(terminal, "wallets open_trades terminal_candles")
    require(not terminal["open_trades"] and numeric(terminal["wallets"]["asset"]) == 0, "FORCED_LIQUIDATION_UNSUPPORTED", "UNSUPPORTED")
    for value in (opening["wallets"], final["wallets"], terminal["wallets"]):
        wallet(value)
    require(not opening["open_trades"] and opening["closed_trade_count"] == 0 and numeric(opening["total_closed_profit"]) == 0
            and numeric(opening["wallets"]["asset"]) == 0, "OPENING_POSITION_UNSUPPORTED", "UNSUPPORTED")
    require(numeric(opening["wallets"]["cash"]) == numeric(opening["starting_balance"]), "OPENING_CASH_MISMATCH")
    require(numeric(opening["starting_balance"]) == numeric(resolved["dry_run_wallet"]), "RESOLVED_OPENING_CASH_MISMATCH")
    require(not terminal["open_trades"] and numeric(terminal["wallets"]["asset"]) == 0, "FORCED_LIQUIDATION_UNSUPPORTED", "UNSUPPORTED")
    require(not final["open_trades"] and numeric(final["wallets"]["asset"]) == 0, "RESIDUAL_POSITION_UNSUPPORTED", "UNSUPPORTED")
    require(numeric(final["wallets"]["cash"]) == numeric(final["native_final_balance"]), "FINAL_CASH_MISMATCH")
    require(numeric(terminal["wallets"]["cash"]) == numeric(final["wallets"]["cash"]), "UNEXPLAINED_TERMINAL_CASH_CHANGE")
    require(set(terminal["terminal_candles"]) == {"BTC/USDT"}, "MISSING_TERMINAL_CANDLE")
    last = terminal["terminal_candles"]["BTC/USDT"]
    keys(last, "ohlcv backtest_row")
    keys(last["ohlcv"], "date open high low close volume")
    keys(last["backtest_row"], "date open high low close")
    require(last["ohlcv"]["date"] == last["backtest_row"]["date"]
            and all(numeric(last["ohlcv"][k]) == numeric(last["backtest_row"][k]) for k in ("open", "high", "low", "close")), "TERMINAL_CANDLE_MISMATCH")
    terminal_millis = int(stamp(last["ohlcv"]["date"]).timestamp() * 1000)
    source_candles = strict_json(context["input_buffers"]["data/BTC_USDT-5m.json"])
    require(len(source_candles) == window["candle_count"], "SOURCE_CANDLE_COUNT_MISMATCH")
    source_times = [row[0] for row in source_candles]
    first_millis = int(stamp(bounds["first"]).timestamp() * 1000)
    last_millis = int(stamp(bounds["last"]).timestamp() * 1000)
    require(first_millis in source_times and last_millis in source_times
            and source_times.index(last_millis) - source_times.index(first_millis) + 1 == bounds["count"], "PROCESSED_SOURCE_WINDOW_MISMATCH")
    source_matches = [row for row in source_candles if row[0] == terminal_millis]
    require(len(source_matches) == 1 and all(Decimal(str(source_matches[0][i])) == numeric(last["ohlcv"][key])
            for i, key in enumerate(("open", "high", "low", "close", "volume"), start=1)), "TERMINAL_SOURCE_CANDLE_MISMATCH")
    trades, fills, closes = final["closed_trades"], capture["completions"], capture["closes"]
    require(type(trades) is list and type(fills) is list and type(closes) is list and 0 < len(fills) <= 10000,
            "NO_CLOSED_TRADES_OR_INVALID_CAPTURE", "UNSUPPORTED")
    require(state["completion_count"] == len(fills) and state["closed_trade_count"] == len(trades)
            and state["terminal_order_count"] == len(fills) == len(trades) * 2 and len(closes) == len(trades), "CAPTURE_COUNT_MISMATCH")
    observed_orders, by_trade, order_ids, exchange_ids = {}, {}, set(), set()
    for trade in trades:
        keys(trade, TRADE_KEYS)
        tid = identity(trade["trade_id"])
        require(tid not in by_trade, "DUPLICATE_TRADE")
        by_trade[tid] = trade
        require(trade["pair"] == "BTC/USDT" and trade["trading_mode"] == "spot" and numeric(trade["leverage"]) == 1
                and trade["is_open"] is False and trade["is_short"] is False and trade["has_open_orders"] is False,
                "TRADE_SCOPE_UNSUPPORTED", "UNSUPPORTED")
        require(trade["exit_reason"] != "force_exit", "FORCED_LIQUIDATION_UNSUPPORTED", "UNSUPPORTED")
        require(type(trade["entry_count"]) is int and type(trade["exit_count"]) is int
                and trade["entry_count"] == trade["exit_count"] == 1 and numeric(trade["funding_fees"]) == 0,
                "TRADE_ADJUSTMENT_UNSUPPORTED", "UNSUPPORTED")
        require(numeric(trade["fee_open"]) == numeric(trade["fee_close"]) == Decimal("0.001"), "FEE_RATE_UNSUPPORTED", "UNSUPPORTED")
        require(trade["fee_open_currency"] in (None, "", "USDT") and trade["fee_close_currency"] in (None, "", "USDT"), "FEE_CURRENCY_UNSUPPORTED", "UNSUPPORTED")
        require(type(trade["orders"]) is list and len(trade["orders"]) == 2, "TRADE_ORDER_COUNT_MISMATCH")
        for native_order in trade["orders"]:
            order(native_order)
            oid = (native_order["id"], native_order["order_id"])
            require(oid not in observed_orders and native_order["id"] not in order_ids and native_order["order_id"] not in exchange_ids, "DUPLICATE_ORDER")
            order_ids.add(native_order["id"])
            exchange_ids.add(native_order["order_id"])
            observed_orders[oid] = (tid, native_order)
    for frame in (final["trade_rows"], final["wallet_summary"]):
        keys(frame, "columns rows")
        require(type(frame["columns"]) is list and type(frame["rows"]) is list and len(frame["columns"]) <= 128
                and all(type(x) is str for x in frame["columns"]) and len(set(frame["columns"])) == len(frame["columns"])
                and all(type(row) is list and len(row) == len(frame["columns"]) for row in frame["rows"]), "INVALID_NATIVE_DATAFRAME")
    require(len(final["trade_rows"]["rows"]) == len(trades), "NATIVE_TRADE_ROW_COUNT_MISMATCH")
    for trade, values in zip(trades, final["trade_rows"]["rows"]):
        row = dict(zip(final["trade_rows"]["columns"], values))
        for field in ("pair", "open_date", "close_date", "is_open", "is_short", "exit_reason"):
            require(type(row.get(field)) is type(trade[field]) and row.get(field) == trade[field], "NATIVE_TRADE_ROW_MISMATCH")
        for field in ("amount", "open_rate", "close_rate", "fee_open", "fee_close", "leverage", "funding_fees"):
            require(numeric(row[field]) == numeric(trade[field]), "NATIVE_TRADE_ROW_MISMATCH")
        # Pinned Trade.to_json line716 rounds this informational table field.
        # It never supplies the exact ledger's quantity, price, fee or cash.
        from verify_accounting.native_numeric import round8
        require(float(numeric(row["stake_amount"])).hex() == round8(float(numeric(trade["stake_amount"]))).hex(), "NATIVE_TRADE_ROW_STAKE_MISMATCH")
        require(row.get("profit_abs") == trade["close_profit_abs"], "NATIVE_TRADE_PROFIT_MISMATCH")
        for field in ("open", "close"):
            require(type(row.get(field + "_timestamp")) is int
                    and row[field + "_timestamp"] == int(stamp(trade[field + "_date"]).timestamp() * 1000), "NATIVE_TRADE_ROW_TIME_MISMATCH")
        require(type(row.get("orders")) is list and len(row["orders"]) == len(trade["orders"]), "NATIVE_TRADE_ROW_ORDER_MISMATCH")
        for summary, native_order in zip(row["orders"], trade["orders"]):
            keys(summary, "amount cost ft_is_entry ft_order_side ft_order_tag order_filled_timestamp safe_price")
            require(all(numeric(summary[k]) == numeric(native_order[k]) for k in ("amount", "cost", "safe_price"))
                    and summary["ft_order_side"] == native_order["side"] and summary["ft_order_tag"] == native_order["tag"]
                    and summary["ft_is_entry"] is (native_order["side"] == "buy")
                    and type(summary["order_filled_timestamp"]) is int
                    and summary["order_filled_timestamp"] == int(stamp(native_order["filled_at"]).timestamp() * 1000), "NATIVE_TRADE_ROW_ORDER_MISMATCH")
    keys(final["engine_counters"], "rejected_trades timedout_entry_orders timedout_exit_orders canceled_trade_entries canceled_entry_orders replaced_entry_orders canceled_exit_orders replaced_exit_orders")
    require(all(type(value) is int and value >= 0 for value in final["engine_counters"].values()), "INVALID_ENGINE_COUNTERS")
    require(all(value == 0 for name, value in final["engine_counters"].items() if name != "rejected_trades"), "ORDER_LIFECYCLE_UNSUPPORTED", "UNSUPPORTED")
    keys(capture["trust"], "execution authenticity completeness fees observer")
    require(final["close_order"] == list(by_trade) and [x["trade_id"] for x in closes] == final["close_order"], "CLOSE_ORDER_MISMATCH")
    events, seen, entries, replay = [], set(), {}, []
    previous, active = start, None
    for index, fill in enumerate(fills):
        keys(fill, "sequence phase trade_id order trade_fee_rates trade_fee_costs trade_fee_currencies")
        require(type(fill["sequence"]) is int and fill["sequence"] == index + 1, "COMPLETION_SEQUENCE_MISMATCH")
        require(fill["phase"] == "baseline", "FORCED_LIQUIDATION_UNSUPPORTED", "UNSUPPORTED")
        native_order = fill["order"]
        order(native_order)
        oid = (native_order["id"], native_order["order_id"])
        require(oid not in seen and oid in observed_orders and observed_orders[oid] == (fill["trade_id"], native_order), "COMPLETION_ORDER_BIJECTION_MISMATCH")
        seen.add(oid)
        moment = stamp(native_order["filled_at"])
        require(previous <= moment <= end, "COMPLETION_TIME_ORDER_MISMATCH")
        previous = moment
        for fee_field in ("trade_fee_rates", "trade_fee_costs", "trade_fee_currencies"):
            keys(fill[fee_field], "open close")
        require(all(numeric(rate) == Decimal("0.001") for rate in fill["trade_fee_rates"].values()), "FEE_RATE_UNSUPPORTED", "UNSUPPORTED")
        require(all(currency in (None, "", "USDT") for currency in fill["trade_fee_currencies"].values()), "FEE_CURRENCY_UNSUPPORTED", "UNSUPPORTED")
        size, price = operand(native_order["filled"]), operand(native_order["safe_price"])
        tid = fill["trade_id"]
        fee_side = "open" if native_order["side"] == "buy" else "close"
        events.append({"event_id": f"fill-{index + 1}", "timestamp": native_order["filled_at"], "type": native_order["side"].upper(),
                       "quantity": size, "price": price, "fee": modeled_fee(size, price), "fee_currency": "USDT",
                       "fee_model": {"kind": "modeled_fee", "quantity": size, "price": price, "rate": "0.001",
                                     "sources": [f"capture:/completions/{index}/order/filled", f"capture:/completions/{index}/order/safe_price", f"capture:/completions/{index}/trade_fee_rates/{fee_side}"]}})
        if native_order["side"] == "buy":
            require(active is None and tid not in entries, "OVERLAPPING_OR_ADJUSTED_TRADE_UNSUPPORTED", "UNSUPPORTED")
            active = tid
            entries[tid] = (size, price, native_order)
        else:
            require(active == tid and tid in entries, "TRADE_FILL_SEQUENCE_MISMATCH")
            entry_size, entry_price, entry_order = entries[tid]
            require(size == entry_size, "PARTIAL_OR_ADJUSTED_TRADE_UNSUPPORTED", "UNSUPPORTED")
            trade = by_trade[tid]
            require(numeric(trade["amount"]) == Decimal(size) and numeric(trade["open_rate"]) == Decimal(entry_price)
                    and numeric(trade["close_rate"]) == Decimal(price), "TRADE_FILL_OPERAND_MISMATCH")
            require(trade["open_date"] == entry_order["filled_at"] and trade["close_date"] == native_order["filled_at"], "TRADE_FILL_TIME_MISMATCH")
            replay.append({"trade_id": str(tid), "entry_quantity": entry_size, "entry_price": entry_price,
                           "exit_quantity": size, "exit_price": price, "fee_rate": "0.001", "native_profit": trade["close_profit_abs"]})
            active = None
    require(seen == set(observed_orders) and active is None and [x["trade_id"] for x in replay] == [str(tid) for tid in final["close_order"]], "COMPLETION_ORDER_BIJECTION_MISMATCH")
    total = 0.0
    for index, close in enumerate(closes):
        keys(close, "sequence trade_id close_profit_abs total_profit_before total_profit_after")
        require(type(close["sequence"]) is int and close["sequence"] == index + 1 and close["close_profit_abs"] == by_trade[close["trade_id"]]["close_profit_abs"], "CLOSE_OBSERVATION_MISMATCH")
        require(float(numeric(close["total_profit_before"])).hex() == total.hex(), "NATIVE_ACCUMULATION_MISMATCH")
        total += float(numeric(close["close_profit_abs"]))
        require(float(numeric(close["total_profit_after"])).hex() == total.hex(), "NATIVE_ACCUMULATION_MISMATCH")
    require(float(numeric(final["native_total_closed_profit"])).hex() == total.hex(), "NATIVE_ACCUMULATION_MISMATCH")
    document = {"schema": "n170.accounting.events.v2", "evidence_class": "supplied_events", "asset": "BTC", "cash_currency": "USDT",
                "opening": {"timestamp": window["backtest_start"], "cash": operand(opening["wallets"]["cash"])}, "events": events,
                "closing": {"timestamp": window["backtest_end"], "mark_price": operand(last["ohlcv"]["close"]), "reported": {}}}
    policy_runtime = {"image_reference": context["engine"]["reference"].rsplit("@", 1)[-1], "image_id": context["engine"]["image_id"],
                      "engine_revision": ENGINE_REVISION, "engine_source_sha256": ENGINE_SOURCE, "python": runtime["python_version"],
                      "ccxt": runtime["ccxt_version"], "numpy": runtime["numpy_version"], "precise_sha256": PRECISE_SOURCE}
    return document, replay, policy_runtime


def assess_capture(raw, context=None):
    result = {"schema": "n170.accounting.capture-assessment.v1", "status": "NOT_ASSESSABLE",
              "capture": {"status": "MISSING", "reason_codes": ["CAPTURE_NOT_SUPPLIED"]}, "events": None,
              "exact_model": None, "native_compatibility": None,
              "native_metrics": {name: {"status": "NOT_SUPPLIED"} for name in METRICS}, "oracle": {"status": "NOT_RUN"},
              "reason_codes": [], "trust": {"authenticity": "not_established", "completeness": "selected_capture_only; omissions outside bound evidence unknown",
              "fees": "modeled quote fees, not observed payments", "oracle": "separate execution required; never inferred from native agreement"}}
    if raw is None:
        return result
    try:
        require(type(raw) is bytes and len(raw) <= 2 * 1024 * 1024, "CAPTURE_SIZE_LIMIT")
        result["capture_sha256"] = hashlib.sha256(raw).hexdigest()
        capture = strict_json(raw)
        document, trades, runtime = _derive(capture, context)
        from verify_accounting.v2 import assess_document
        from verify_accounting.native_numeric import replay_native
        result["events"] = document
        result["exact_model"] = assess_document(document)
        require(result["exact_model"].get("computed") is not None, "EXACT_MODEL_UNAVAILABLE", "UNSUPPORTED")
        result["capture"] = {"status": "SUPPORTED", "reason_codes": ["BOUND_NATURALLY_CLOSED_SPOT_CAPTURE"], "fill_count": len(document["events"]), "trade_count": len(trades)}
        final = capture["final"]
        result["native_compatibility"] = replay_native(document["opening"]["cash"], trades, final["native_total_closed_profit"], final["wallets"]["cash"], runtime=runtime)
        for name, value, source in (("cash", final["wallets"]["cash"], "final/wallets/cash"), ("quantity", final["wallets"]["asset"], "final/wallets/asset"), ("net_pnl", final["native_total_closed_profit"], "final/native_total_closed_profit")):
            result["native_metrics"][name] = {"status": "SUPPLIED_NATIVE", "value": value, "source": "capture:/" + source}
        result["reason_codes"] = ["MISSING_NATIVE_METRICS", "EXACT_MODEL_AND_NATIVE_FLOAT_POLICY_ARE_SEPARATE", "ORACLE_NOT_RUN"]
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError, RecursionError) as error:
        reason = str(error) if isinstance(error, CaptureError) else "INVALID_OR_UNSUPPORTED_CAPTURE"
        result["capture"] = {"status": error.status if isinstance(error, CaptureError) else "INVALID", "reason_codes": [reason]}
        result["events"] = result["exact_model"] = result["native_compatibility"] = None
        result["reason_codes"] = [reason]
    return result
