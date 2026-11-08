"""Split-adjusted FIFO round-trip matching, Odean (1998) disposition spread, and ATR sizing discipline."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
import math
import re
import statistics
from typing import Any

from n170_verify.coaching.llm_coach import contains_currency_amount, contains_forbidden_claim
from n170_verify.contracts import (
    AssetClass,
    BehaviouralCoachingMetrics,
    CanonicalPortfolioLedger,
    CorporateActionRecord,
    CorporateActionType,
    CostAndDragBreakdown,
    NormalizedTrade,
    QuantDnaProfile,
    RedactedClosedTrade,
    SessionExpectancyCell,
    parse_utc_timestamp,
)


SECONDS_PER_HOUR: float = 3_600.0
SECONDS_PER_DAY: float = 86_400.0
SHORT_WINDOW_MIN_TRADES: int = 30
LONG_WINDOW_DAYS_GATE: int = 90
LONG_WINDOW_MIN_TRADES: int = 10

_ISO_DATE_PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")


@dataclass(slots=True)
class ClosedRoundTrip:
    """Internal split-adjusted FIFO closed round-trip record."""

    symbol: str
    asset_class: AssetClass
    side: str
    entry_timestamp_utc: str
    exit_timestamp_utc: str
    matched_quantity: float
    entry_price: float
    exit_price: float
    multiplier: float
    gross_pnl_base: float
    net_pnl_base: float
    return_pct: float
    holding_hours: float

    def to_redacted(self) -> RedactedClosedTrade:
        """Strip all dollar/quantity notionals for delayed leaf disclosure."""
        return RedactedClosedTrade(
            symbol=self.symbol,
            asset_class=self.asset_class,
            side=self.side,
            entry_timestamp_utc=self.entry_timestamp_utc,
            exit_timestamp_utc=self.exit_timestamp_utc,
            return_pct=round(self.return_pct, 6),
            holding_hours=round(self.holding_hours, 6),
        )


@dataclass(slots=True)
class _OpenLot:
    symbol: str
    asset_class: AssetClass
    side: str  # "long" or "short"
    remaining_qty: float
    entry_price: float
    multiplier: float
    fx_rate_to_base: float
    entry_fee_per_unit_base: float
    entry_timestamp_utc: str
    option_right: str | None = None
    strike: float | None = None
    expiry: str | None = None


@dataclass(slots=True)
class _OpeningFill:
    symbol: str
    timestamp_utc: str
    opened_quantity: float
    price: float
    multiplier: float
    fx_rate_to_base: float


@dataclass(slots=True)
class _DayLiquidationSnapshot:
    date_str: str
    realized_net_pnl_by_symbol: dict[tuple[str, str], float]
    open_avg_cost_by_symbol: dict[tuple[str, str], float]


def _instrument_key(
    symbol: str,
    asset_class: AssetClass,
    option_right: str | None,
    strike: float | None,
    expiry: str | None,
) -> tuple[str, str, str | None, float | None, str | None]:
    norm_sym = symbol.strip().upper()
    if asset_class in {AssetClass.OPTION, AssetClass.FUTURE}:
        return (norm_sym, asset_class.value, option_right, strike, expiry)
    return (norm_sym, asset_class.value, None, None, None)


def _compute_split_factor(action: CorporateActionRecord, open_total_qty: float) -> float | None:
    if action.ratio_numerator is not None and action.ratio_denominator is not None:
        raw_ratio = action.ratio_numerator / action.ratio_denominator
        if raw_ratio <= 0.0:
            return None
        if action.action_type == CorporateActionType.REVERSE_SPLIT and raw_ratio > 1.0:
            return 1.0 / raw_ratio
        if action.action_type == CorporateActionType.SPLIT and raw_ratio < 1.0:
            return 1.0 / raw_ratio
        return raw_ratio

    if action.quantity_delta != 0.0 and open_total_qty > 0.0:
        candidate = (open_total_qty + action.quantity_delta) / open_total_qty
        if candidate > 0.0:
            return candidate
    return None


def _apply_corporate_action(
    action: CorporateActionRecord,
    lots_by_key: dict[tuple[str, str, str | None, float | None, str | None], deque[_OpenLot]],
) -> None:
    target_sym = action.symbol.strip().upper()
    matching_keys = [key for key in list(lots_by_key.keys()) if key[0] == target_sym]
    if not matching_keys:
        return

    if action.action_type in {CorporateActionType.SPLIT, CorporateActionType.REVERSE_SPLIT}:
        for key in matching_keys:
            # Apply share splits primarily to non-option or matching lots; equity options use OCC adjustment.
            queue = lots_by_key[key]
            if not queue:
                continue
            open_qty = sum(lot.remaining_qty for lot in queue)
            factor = _compute_split_factor(action, open_qty)
            if factor is None or factor <= 0.0:
                continue
            for lot in queue:
                lot.remaining_qty *= factor
                lot.entry_price /= factor
                lot.entry_fee_per_unit_base /= factor

    elif action.action_type == CorporateActionType.SYMBOL_CHANGE and action.new_symbol:
        new_sym = action.new_symbol.strip().upper()
        if not new_sym or new_sym == target_sym:
            return
        for key in matching_keys:
            queue = lots_by_key.pop(key)
            if not queue:
                continue
            new_key = (new_sym, key[1], key[2], key[3], key[4])
            dest = lots_by_key.setdefault(new_key, deque())
            for lot in queue:
                lot.symbol = new_sym
                dest.append(lot)


def _snapshot_open_cost_basis(
    lots_by_key: Mapping[tuple[str, str, str | None, float | None, str | None], deque[_OpenLot]],
) -> dict[tuple[str, str], float]:
    agg_qty_cost: dict[tuple[str, str], list[float]] = {}
    for queue in lots_by_key.values():
        for lot in queue:
            if lot.remaining_qty <= 1e-12:
                continue
            sym_side = (lot.symbol, lot.side)
            bucket = agg_qty_cost.setdefault(sym_side, [0.0, 0.0])
            bucket[0] += lot.remaining_qty
            bucket[1] += lot.remaining_qty * lot.entry_price
    return {
        sym_side: qty_cost[1] / qty_cost[0]
        for sym_side, qty_cost in agg_qty_cost.items()
        if qty_cost[0] > 1e-12
    }


def _run_fifo_ledger_simulation(
    ledger: CanonicalPortfolioLedger,
) -> tuple[list[ClosedRoundTrip], list[_DayLiquidationSnapshot], list[_OpeningFill]]:
    events: list[tuple[datetime, int, int, CorporateActionRecord | NormalizedTrade]] = []
    for idx, ca in enumerate(ledger.corporate_actions):
        events.append((parse_utc_timestamp(ca.timestamp_utc), 0, idx, ca))
    for idx, tr in enumerate(ledger.trades):
        if tr.asset_class == AssetClass.CASH:
            continue
        events.append((parse_utc_timestamp(tr.timestamp_utc), 1, idx, tr))

    events.sort(key=lambda item: (item[0], item[1], item[2]))

    lots_by_key: dict[tuple[str, str, str | None, float | None, str | None], deque[_OpenLot]] = {}
    closed_trips: list[ClosedRoundTrip] = []
    opening_fills: list[_OpeningFill] = []
    day_snapshots: list[_DayLiquidationSnapshot] = []

    current_day: str | None = None
    day_realized_pnl: dict[tuple[str, str], float] = {}

    def _flush_day(date_label: str | None) -> None:
        if date_label and day_realized_pnl:
            day_snapshots.append(
                _DayLiquidationSnapshot(
                    date_str=date_label,
                    realized_net_pnl_by_symbol=dict(day_realized_pnl),
                    open_avg_cost_by_symbol=_snapshot_open_cost_basis(lots_by_key),
                )
            )

    for dt_utc, priority, _, record in events:
        event_day = dt_utc.strftime("%Y-%m-%d")
        if current_day is not None and event_day != current_day:
            _flush_day(current_day)
            day_realized_pnl = {}
        current_day = event_day

        if priority == 0 and isinstance(record, CorporateActionRecord):
            _apply_corporate_action(record, lots_by_key)
            continue

        assert isinstance(record, NormalizedTrade)
        qty = abs(record.quantity)
        if qty <= 1e-12:
            continue

        mult = record.multiplier if record.multiplier is not None else 1.0
        total_trade_fee_base = (abs(record.commission) + abs(record.tax)) * record.fx_rate_to_base
        fee_per_unit_base = total_trade_fee_base / qty
        trade_lot_side = "long" if record.side == "buy" else "short"

        key = _instrument_key(
            record.symbol,
            record.asset_class,
            record.option_right,
            record.strike,
            record.expiry,
        )
        queue = lots_by_key.setdefault(key, deque())

        remaining_to_process = qty
        while remaining_to_process > 1e-12 and queue and queue[0].side != trade_lot_side:
            lot = queue[0]
            matched = min(lot.remaining_qty, remaining_to_process)
            exit_fee_base = fee_per_unit_base * matched
            entry_fee_base = lot.entry_fee_per_unit_base * matched
            eff_mult = lot.multiplier

            entry_notional_base = matched * lot.entry_price * eff_mult * lot.fx_rate_to_base
            if lot.side == "long":
                if record.fx_rate_to_base == lot.fx_rate_to_base:
                    gross_pnl_base = (
                        (record.price - lot.entry_price) * matched * eff_mult * record.fx_rate_to_base
                    )
                else:
                    exit_notional_base = matched * record.price * eff_mult * record.fx_rate_to_base
                    gross_pnl_base = exit_notional_base - entry_notional_base
            else:
                gross_pnl_base = (
                    (lot.entry_price - record.price) * matched * eff_mult * record.fx_rate_to_base
                )

            net_pnl_base = gross_pnl_base - entry_fee_base - exit_fee_base
            return_pct = (
                (net_pnl_base / entry_notional_base) * 100.0 if entry_notional_base > 0.0 else 0.0
            )
            entry_dt = parse_utc_timestamp(lot.entry_timestamp_utc)
            holding_hours = max(0.0, (dt_utc - entry_dt).total_seconds() / SECONDS_PER_HOUR)

            closed_trips.append(
                ClosedRoundTrip(
                    symbol=lot.symbol,
                    asset_class=lot.asset_class,
                    side=lot.side,
                    entry_timestamp_utc=lot.entry_timestamp_utc,
                    exit_timestamp_utc=record.timestamp_utc,
                    matched_quantity=matched,
                    entry_price=lot.entry_price,
                    exit_price=record.price,
                    multiplier=eff_mult,
                    gross_pnl_base=gross_pnl_base,
                    net_pnl_base=net_pnl_base,
                    return_pct=return_pct,
                    holding_hours=holding_hours,
                )
            )
            sym_side_key = (lot.symbol, lot.side)
            day_realized_pnl[sym_side_key] = day_realized_pnl.get(sym_side_key, 0.0) + net_pnl_base

            lot.remaining_qty -= matched
            remaining_to_process -= matched
            if lot.remaining_qty <= 1e-12:
                queue.popleft()

        if remaining_to_process > 1e-12:
            norm_sym = record.symbol.strip().upper()
            queue.append(
                _OpenLot(
                    symbol=norm_sym,
                    asset_class=record.asset_class,
                    side=trade_lot_side,
                    remaining_qty=remaining_to_process,
                    entry_price=record.price,
                    multiplier=mult,
                    fx_rate_to_base=record.fx_rate_to_base,
                    entry_fee_per_unit_base=fee_per_unit_base,
                    entry_timestamp_utc=record.timestamp_utc,
                    option_right=record.option_right,
                    strike=record.strike,
                    expiry=record.expiry,
                )
            )
            opening_fills.append(
                _OpeningFill(
                    symbol=norm_sym,
                    timestamp_utc=record.timestamp_utc,
                    opened_quantity=remaining_to_process,
                    price=record.price,
                    multiplier=mult,
                    fx_rate_to_base=record.fx_rate_to_base,
                )
            )

    _flush_day(current_day)
    return closed_trips, day_snapshots, opening_fills


def match_fifo_round_trips(ledger: CanonicalPortfolioLedger) -> list[ClosedRoundTrip]:
    """Match split-adjusted long and short FIFO round-trips across a canonical portfolio ledger."""
    closed_trips, _, _ = _run_fifo_ledger_simulation(ledger)
    return closed_trips


def extract_delayed_closed_trades(
    closed_trades: Sequence[ClosedRoundTrip | RedactedClosedTrade | Mapping[str, Any]],
    as_of_utc: str | datetime,
    min_delay_days: float = 7,
) -> list[RedactedClosedTrade]:
    """Extract dollar-free ``RedactedClosedTrade`` records closed at least ``min_delay_days`` ago."""
    if min_delay_days < 0:
        raise ValueError("min_delay_days must be >= 0")
    as_of_dt = parse_utc_timestamp(as_of_utc, field_name="as_of_utc")
    cutoff_dt = as_of_dt - timedelta(days=float(min_delay_days))

    delayed: list[tuple[datetime, datetime, str, RedactedClosedTrade]] = []
    for item in closed_trades:
        if isinstance(item, ClosedRoundTrip):
            redacted = item.to_redacted()
        elif isinstance(item, RedactedClosedTrade):
            redacted = item
        elif isinstance(item, Mapping):
            redacted = RedactedClosedTrade.from_dict(item)
        else:
            raise ValueError(f"Unsupported closed trade type: {type(item).__name__}")

        exit_dt = parse_utc_timestamp(redacted.exit_timestamp_utc)
        if exit_dt <= cutoff_dt:
            entry_dt = parse_utc_timestamp(redacted.entry_timestamp_utc)
            delayed.append((exit_dt, entry_dt, redacted.symbol, redacted))

    delayed.sort(key=lambda row: (row[0], row[1], row[2]))
    return [row[3] for row in delayed]


def _normalize_symbol_date_table(
    snapshots: Mapping[str, Any] | None,
) -> tuple[dict[str, dict[str, float]], dict[str, float]]:
    """Normalize either ``{date: {symbol: val}}``, ``{symbol: {date: val}}``, or ``{symbol: val}``."""
    by_symbol_date: dict[str, dict[str, float]] = {}
    flat_by_symbol: dict[str, float] = {}
    if not snapshots:
        return by_symbol_date, flat_by_symbol

    for outer_key, outer_val in snapshots.items():
        if not isinstance(outer_key, str):
            continue
        cleaned_outer = outer_key.strip()
        if isinstance(outer_val, (int, float)) and not isinstance(outer_val, bool):
            flat_by_symbol[cleaned_outer.upper()] = float(outer_val)
            continue
        if not isinstance(outer_val, Mapping):
            continue

        if _ISO_DATE_PREFIX_RE.match(cleaned_outer):
            date_key = cleaned_outer[:10]
            for sym, price in outer_val.items():
                if isinstance(sym, str) and isinstance(price, (int, float)) and not isinstance(price, bool):
                    by_symbol_date.setdefault(sym.strip().upper(), {})[date_key] = float(price)
        else:
            sym_key = cleaned_outer.upper()
            for dt_key, price in outer_val.items():
                if (
                    isinstance(dt_key, str)
                    and isinstance(price, (int, float))
                    and not isinstance(price, bool)
                ):
                    by_symbol_date.setdefault(sym_key, {})[dt_key.strip()[:10]] = float(price)

    return by_symbol_date, flat_by_symbol


def _lookup_mark_on_date(
    symbol: str,
    date_str: str,
    by_symbol_date: Mapping[str, Mapping[str, float]],
    flat_by_symbol: Mapping[str, float],
) -> float | None:
    sym = symbol.strip().upper()
    dated = by_symbol_date.get(sym)
    if dated:
        if date_str in dated:
            return dated[date_str]
        # Allow causal latest mark on or before date_str within 5 days (weekends/holidays).
        prior = sorted(d for d in dated.keys() if d <= date_str)
        if prior:
            latest_d = prior[-1]
            dt_target = datetime.strptime(date_str, "%Y-%m-%d")
            dt_latest = datetime.strptime(latest_d, "%Y-%m-%d")
            if (dt_target - dt_latest).days <= 5:
                return dated[latest_d]
    return flat_by_symbol.get(sym)


def _lookup_causal_atr_t_minus_1(
    symbol: str,
    trade_date_str: str,
    by_symbol_date: Mapping[str, Mapping[str, float]],
    flat_by_symbol: Mapping[str, float],
) -> float | None:
    """Resolve causal ATR_14(t-1) strictly prior to ``trade_date_str`` when dated bars are given."""
    sym = symbol.strip().upper()
    dated = by_symbol_date.get(sym)
    if dated:
        strictly_prior = sorted(d for d in dated.keys() if d < trade_date_str)
        if strictly_prior:
            val = dated[strictly_prior[-1]]
            return val if val > 0.0 else None
        # Fallback if single pre-session snapshot keyed by trade_date_str is the earliest available.
        if trade_date_str in dated and len(dated) == 1:
            val = dated[trade_date_str]
            return val if val > 0.0 else None
        return None

    flat_val = flat_by_symbol.get(sym)
    if flat_val is not None and flat_val > 0.0:
        return flat_val
    return None


def compute_odean_disposition_spread(
    ledger: CanonicalPortfolioLedger,
    price_snapshots: Mapping[str, Any] | None,
) -> float | None:
    """Compute Odean (1998) ``PGR - PLR`` disposition spread across liquidation dates."""
    if not price_snapshots:
        return None
    _, day_snapshots, _ = _run_fifo_ledger_simulation(ledger)
    return _compute_odean_from_snapshots(day_snapshots, price_snapshots)


def _compute_odean_from_snapshots(
    day_snapshots: Sequence[_DayLiquidationSnapshot],
    price_snapshots: Mapping[str, Any] | None,
) -> float | None:
    if not price_snapshots or not day_snapshots:
        return None

    by_symbol_date, flat_by_symbol = _normalize_symbol_date_table(price_snapshots)
    if not by_symbol_date and not flat_by_symbol:
        return None

    realized_gains = 0
    realized_losses = 0
    paper_gains = 0
    paper_losses = 0
    evaluated_paper_positions = 0

    for snap in day_snapshots:
        # Evaluate open paper positions on this liquidation date first; skip dates lacking mark data.
        day_paper_gains = 0
        day_paper_losses = 0
        day_marks_found = 0
        for (sym, side), avg_cost in snap.open_avg_cost_by_symbol.items():
            if (sym, side) in snap.realized_net_pnl_by_symbol:
                continue
            mark = _lookup_mark_on_date(sym, snap.date_str, by_symbol_date, flat_by_symbol)
            if mark is None or mark <= 0.0:
                continue
            day_marks_found += 1
            if side == "long":
                if mark > avg_cost:
                    day_paper_gains += 1
                elif mark < avg_cost:
                    day_paper_losses += 1
            else:
                if mark < avg_cost:
                    day_paper_gains += 1
                elif mark > avg_cost:
                    day_paper_losses += 1

        if snap.open_avg_cost_by_symbol and day_marks_found == 0 and any(
            k not in snap.realized_net_pnl_by_symbol for k in snap.open_avg_cost_by_symbol
        ):
            continue

        for pnl in snap.realized_net_pnl_by_symbol.values():
            if pnl > 0.0:
                realized_gains += 1
            elif pnl < 0.0:
                realized_losses += 1

        paper_gains += day_paper_gains
        paper_losses += day_paper_losses
        evaluated_paper_positions += day_marks_found

    if evaluated_paper_positions == 0:
        return None

    gain_denom = realized_gains + paper_gains
    loss_denom = realized_losses + paper_losses
    if gain_denom == 0 or loss_denom == 0:
        return None

    pgr = realized_gains / gain_denom
    plr = realized_losses / loss_denom
    return round(pgr - plr, 6)


def _build_nav_drawdown_series(
    ledger: CanonicalPortfolioLedger,
) -> list[tuple[datetime, float, float]]:
    """Build chronological ``(timestamp_utc, nav_base, drawdown_decimal)`` series."""
    valid_nav = [
        (parse_utc_timestamp(pt.timestamp_utc), float(pt.nav_base))
        for pt in ledger.nav_points
        if pt.nav_base > 0.0
    ]
    if not valid_nav:
        return []
    valid_nav.sort(key=lambda item: item[0])

    ext_flows = sorted(
        (
            (
                parse_utc_timestamp(f.timestamp_utc),
                float(f.amount_base if f.amount_base is not None else f.amount * f.fx_rate_to_base),
            )
            for f in ledger.flows
            if f.is_external_capital_flow
        ),
        key=lambda item: item[0],
    )

    series: list[tuple[datetime, float, float]] = []
    wealth = 1.0
    hwm_wealth = 1.0
    flow_idx = 0
    n_flows = len(ext_flows)

    first_dt, first_nav = valid_nav[0]
    while flow_idx < n_flows and ext_flows[flow_idx][0] <= first_dt:
        flow_idx += 1
    series.append((first_dt, first_nav, 0.0))

    prev_nav = first_nav
    for dt_utc, nav_val in valid_nav[1:]:
        period_ext_flow = 0.0
        while flow_idx < n_flows and ext_flows[flow_idx][0] <= dt_utc:
            period_ext_flow += ext_flows[flow_idx][1]
            flow_idx += 1

        if prev_nav > 0.0:
            sub_ret = (nav_val - prev_nav - period_ext_flow) / prev_nav
            wealth = max(1e-9, wealth * (1.0 + sub_ret))
        hwm_wealth = max(hwm_wealth, wealth)
        dd = max(0.0, (hwm_wealth - wealth) / hwm_wealth) if hwm_wealth > 0.0 else 0.0
        series.append((dt_utc, nav_val, dd))
        prev_nav = nav_val

    return series


def _lookup_nav_and_drawdown(
    trade_dt: datetime,
    nav_dd_series: Sequence[tuple[datetime, float, float]],
) -> tuple[float, float] | None:
    if not nav_dd_series:
        return None
    chosen = nav_dd_series[0]
    for dt_utc, nav_val, dd in nav_dd_series:
        if dt_utc <= trade_dt:
            chosen = (dt_utc, nav_val, dd)
        else:
            break
    return chosen[1], chosen[2]


def compute_post_drawdown_sizing_discipline(
    ledger: CanonicalPortfolioLedger,
    *,
    atr_14_series: Mapping[str, Any] | None = None,
    near_hwm_threshold: float = 0.01,
    drawdown_threshold: float = 0.05,
) -> tuple[float | None, bool]:
    """Compute post-drawdown sizing discipline ratio (ATR-normalized or ``% NAV`` notional fallback)."""
    _, _, opening_fills = _run_fifo_ledger_simulation(ledger)
    return _compute_sizing_from_fills(
        ledger,
        opening_fills,
        atr_14_series=atr_14_series,
        near_hwm_threshold=near_hwm_threshold,
        drawdown_threshold=drawdown_threshold,
    )


def _compute_sizing_from_fills(
    ledger: CanonicalPortfolioLedger,
    opening_fills: Sequence[_OpeningFill],
    *,
    atr_14_series: Mapping[str, Any] | None = None,
    near_hwm_threshold: float = 0.01,
    drawdown_threshold: float = 0.05,
) -> tuple[float | None, bool]:
    nav_dd_series = _build_nav_drawdown_series(ledger)
    if not nav_dd_series or not opening_fills:
        return None, False

    atr_by_sym_date, atr_flat = _normalize_symbol_date_table(atr_14_series)
    has_atr_input = bool(atr_by_sym_date or atr_flat)

    near_hwm_notional: list[float] = []
    drawdown_notional: list[float] = []
    near_hwm_atr: list[float] = []
    drawdown_atr: list[float] = []
    atr_complete = has_atr_input

    for fill in opening_fills:
        fill_dt = parse_utc_timestamp(fill.timestamp_utc)
        nav_dd = _lookup_nav_and_drawdown(fill_dt, nav_dd_series)
        if nav_dd is None:
            continue
        nav_base, dd = nav_dd
        if nav_base <= 0.0:
            continue

        in_near_hwm = dd <= near_hwm_threshold
        in_drawdown = dd > drawdown_threshold
        if not (in_near_hwm or in_drawdown):
            continue

        notional_pct_nav = (
            fill.opened_quantity * fill.multiplier * fill.price * fill.fx_rate_to_base
        ) / nav_base
        if in_near_hwm:
            near_hwm_notional.append(notional_pct_nav)
        if in_drawdown:
            drawdown_notional.append(notional_pct_nav)

        if atr_complete:
            date_str = fill_dt.strftime("%Y-%m-%d")
            atr_val = _lookup_causal_atr_t_minus_1(fill.symbol, date_str, atr_by_sym_date, atr_flat)
            if atr_val is None or atr_val <= 0.0:
                atr_complete = False
            else:
                atr_risk_nav = (
                    fill.opened_quantity * fill.multiplier * atr_val * fill.fx_rate_to_base
                ) / nav_base
                if in_near_hwm:
                    near_hwm_atr.append(atr_risk_nav)
                if in_drawdown:
                    drawdown_atr.append(atr_risk_nav)

    if atr_complete and near_hwm_atr and drawdown_atr:
        med_hwm = statistics.median(near_hwm_atr)
        if med_hwm > 0.0:
            return round(statistics.median(drawdown_atr) / med_hwm, 6), True

    if near_hwm_notional and drawdown_notional:
        med_hwm_notional = statistics.median(near_hwm_notional)
        if med_hwm_notional > 0.0:
            return round(statistics.median(drawdown_notional) / med_hwm_notional, 6), False

    return None, False


def classify_holding_horizon(median_holding_hours: float) -> str:
    """Classify median round-trip holding duration into an institutional horizon bucket."""
    if median_holding_hours < 24.0:
        return "intraday"
    if median_holding_hours < 24.0 * 21.0:
        return "multi_day_swing"
    return "position_investor"


def _generate_actionable_improvements(
    *,
    sample_eligible: bool,
    min_trades_gate: int,
    observed_trades: int,
    observed_days: int,
    win_rate: float | None,
    winner_vs_loser_hold_ratio: float | None,
    odean_pgr_plr_spread: float | None,
    sdi_ratio: float | None,
    atr_normalized: bool,
    return_concentration_top5_pct: float | None,
    cost_drag: CostAndDragBreakdown | None,
) -> list[str]:
    improvements: list[str] = []
    if not sample_eligible:
        improvements.append(
            f"Accumulate at least {min_trades_gate} closed round-trips (currently {observed_trades} "
            f"across {observed_days} calendar days) before drawing firm behavioural conclusions."
        )
        if cost_drag is not None and cost_drag.total_friction_drag_bps >= 25.0:
            improvements.append(
                "Review execution commissions, financing charges, and FX conversion spreads to keep friction drag contained."
            )
        return improvements

    if odean_pgr_plr_spread is not None and odean_pgr_plr_spread > 0.15:
        improvements.append(
            "Define pre-trade invalidation stops on losing positions and systematic trailing exits on winners to reduce disposition asymmetry."
        )

    if winner_vs_loser_hold_ratio is not None and winner_vs_loser_hold_ratio < 0.75:
        improvements.append(
            "Introduce time-based review checkpoints on underwater positions so losing trades are not held longer than winning trades."
        )

    if sdi_ratio is not None and sdi_ratio > 1.25:
        unit_desc = "ATR-normalized risk units" if atr_normalized else "notional % NAV risk budgets"
        improvements.append(
            f"Cap per-trade {unit_desc} at or below baseline sizing when portfolio drawdown exceeds 5% below high-water mark."
        )

    if return_concentration_top5_pct is not None and return_concentration_top5_pct > 75.0:
        improvements.append(
            "Monitor position-level profit concentration, as more than three-quarters of gross gains stem from the top five round-trips."
        )

    if cost_drag is not None:
        if cost_drag.fx_conversion_drag_bps >= 5.0:
            improvements.append(
                "Batch cross-currency conversions or route through institutional spot FX pairs to reduce conversion spread drag."
            )
        if cost_drag.commission_and_fee_drag_bps >= 15.0:
            improvements.append(
                "Use passive limit orders where liquidity permits to lower cumulative commission and exchange fee drag."
            )
        if cost_drag.margin_and_funding_drag_bps >= 15.0:
            improvements.append(
                "Evaluate margin utilization and perpetual funding carry schedules to reduce financing drag."
            )

    if not improvements:
        if win_rate is not None and win_rate < 0.45:
            improvements.append(
                "Pair selective entry filtering with existing payoff asymmetry to lift base hit-rate without compressing average winner size."
            )
        else:
            improvements.append(
                "Maintain current position sizing discipline and periodically audit execution friction across venues."
            )

    return improvements


def compute_behavioural_coaching_metrics(
    ledger: CanonicalPortfolioLedger,
    *,
    price_snapshots: Mapping[str, Any] | None = None,
    atr_14_series: Mapping[str, Any] | None = None,
    cost_drag: CostAndDragBreakdown | None = None,
) -> BehaviouralCoachingMetrics:
    """Compute sample-gated behavioural coaching analytics from a canonical portfolio ledger."""
    closed_trips, day_snapshots, opening_fills = _run_fifo_ledger_simulation(ledger)

    start_dt = parse_utc_timestamp(ledger.period_start_utc)
    end_dt = parse_utc_timestamp(ledger.period_end_utc)
    elapsed_days_float = max(0.0, (end_dt - start_dt).total_seconds() / SECONDS_PER_DAY)
    observed_days = int(round(elapsed_days_float))
    if observed_days == 0 and (ledger.trades or ledger.nav_points):
        observed_days = 1

    observed_trades = len(closed_trips)
    min_trades_gate = (
        LONG_WINDOW_MIN_TRADES if observed_days >= LONG_WINDOW_DAYS_GATE else SHORT_WINDOW_MIN_TRADES
    )
    sample_eligible = observed_trades >= min_trades_gate

    if not sample_eligible:
        return BehaviouralCoachingMetrics(
            sample_eligible=False,
            min_trades_gate=min_trades_gate,
            observed_trades=observed_trades,
            observed_days=observed_days,
            median_holding_hours=None,
            holding_horizon_label="insufficient_sample",
            win_rate=None,
            profit_factor=None,
            winner_vs_loser_hold_ratio=None,
            odean_pgr_plr_spread=None,
            post_drawdown_sizing_discipline_atr=None,
            atr_normalized=False,
            return_concentration_top5_pct=None,
            actionable_improvements=_generate_actionable_improvements(
                sample_eligible=False,
                min_trades_gate=min_trades_gate,
                observed_trades=observed_trades,
                observed_days=observed_days,
                win_rate=None,
                winner_vs_loser_hold_ratio=None,
                odean_pgr_plr_spread=None,
                sdi_ratio=None,
                atr_normalized=False,
                return_concentration_top5_pct=None,
                cost_drag=cost_drag,
            ),
        )

    holding_hours_list = [rt.holding_hours for rt in closed_trips]
    median_holding_hours = round(float(statistics.median(holding_hours_list)), 6)
    horizon_label = classify_holding_horizon(median_holding_hours)

    winners = [rt for rt in closed_trips if rt.net_pnl_base > 0.0]
    losers = [rt for rt in closed_trips if rt.net_pnl_base < 0.0]

    win_rate = round(len(winners) / observed_trades, 6)

    gross_wins = sum(rt.net_pnl_base for rt in winners)
    gross_losses = abs(sum(rt.net_pnl_base for rt in losers))
    profit_factor = round(gross_wins / gross_losses, 6) if gross_losses > 0.0 else None

    winner_vs_loser_hold_ratio: float | None = None
    if winners and losers:
        med_win_hold = float(statistics.median(w.holding_hours for w in winners))
        med_loss_hold = float(statistics.median(l.holding_hours for l in losers))
        if med_loss_hold > 0.0:
            winner_vs_loser_hold_ratio = round(med_win_hold / med_loss_hold, 6)
        else:
            mean_loss_hold = float(statistics.mean(l.holding_hours for l in losers))
            if mean_loss_hold > 0.0:
                mean_win_hold = float(statistics.mean(w.holding_hours for w in winners))
                winner_vs_loser_hold_ratio = round(mean_win_hold / mean_loss_hold, 6)

    return_concentration_top5_pct: float | None = None
    if gross_wins > 0.0:
        top5_wins = sorted((w.net_pnl_base for w in winners), reverse=True)[:5]
        return_concentration_top5_pct = round(
            min(100.0, max(0.0, (sum(top5_wins) / gross_wins) * 100.0)), 6
        )

    odean_spread = _compute_odean_from_snapshots(day_snapshots, price_snapshots)
    sdi_ratio, atr_norm = _compute_sizing_from_fills(
        ledger,
        opening_fills,
        atr_14_series=atr_14_series,
    )

    improvements = _generate_actionable_improvements(
        sample_eligible=True,
        min_trades_gate=min_trades_gate,
        observed_trades=observed_trades,
        observed_days=observed_days,
        win_rate=win_rate,
        winner_vs_loser_hold_ratio=winner_vs_loser_hold_ratio,
        odean_pgr_plr_spread=odean_spread,
        sdi_ratio=sdi_ratio,
        atr_normalized=atr_norm,
        return_concentration_top5_pct=return_concentration_top5_pct,
        cost_drag=cost_drag,
    )

    return BehaviouralCoachingMetrics(
        sample_eligible=True,
        min_trades_gate=min_trades_gate,
        observed_trades=observed_trades,
        observed_days=observed_days,
        median_holding_hours=median_holding_hours,
        holding_horizon_label=horizon_label,
        win_rate=win_rate,
        profit_factor=profit_factor,
        winner_vs_loser_hold_ratio=winner_vs_loser_hold_ratio,
        odean_pgr_plr_spread=odean_spread,
        post_drawdown_sizing_discipline_atr=sdi_ratio,
        atr_normalized=atr_norm,
        return_concentration_top5_pct=return_concentration_top5_pct,
        actionable_improvements=improvements,
    )


ARCHETYPE_LOW_TURNOVER_COMPOUNDER = "Low-Turnover Compounder"
ARCHETYPE_CATALYST_SPECIALIST = "Event-Window Catalyst Specialist"
ARCHETYPE_INTRADAY_LIQUIDITY = "Intraday Liquidity Provider"
ARCHETYPE_HIGH_CONVICTION_SWING = "High-Conviction Swing Trader"
ARCHETYPE_SYSTEMATIC_ALLOCATOR = "Disciplined Systematic Allocator"


def compute_session_expectancy_heatmap(
    ledger_or_trades: CanonicalPortfolioLedger | Sequence[ClosedRoundTrip | RedactedClosedTrade],
    *,
    closed_round_trips: Sequence[ClosedRoundTrip | RedactedClosedTrade] | None = None,
    timestamp_basis: str = "entry",
) -> list[SessionExpectancyCell]:
    """Aggregate closed round-trip trades by ``(weekday: 0..6, hour_utc: 0..23)``.

    Emits privacy-preserving ``SessionExpectancyCell`` records containing strictly
    ``trade_count``, ``win_rate`` in ``[0.0, 1.0]``, and ``expectancy_bps`` (where
    ``1.0%`` trade return equals ``100.0`` bps). Zero currency amounts are included.
    """
    if timestamp_basis not in {"entry", "exit"}:
        raise ValueError("timestamp_basis must be 'entry' or 'exit'")

    if closed_round_trips is not None:
        trips: Sequence[ClosedRoundTrip | RedactedClosedTrade] = closed_round_trips
    elif isinstance(ledger_or_trades, CanonicalPortfolioLedger):
        trips = match_fifo_round_trips(ledger_or_trades)
    else:
        trips = ledger_or_trades

    buckets: dict[tuple[int, int], list[tuple[bool, float]]] = defaultdict(list)
    for rt in trips:
        ts_str = rt.entry_timestamp_utc if timestamp_basis == "entry" else rt.exit_timestamp_utc
        dt_utc = parse_utc_timestamp(ts_str)
        ret_pct = float(rt.return_pct)
        if not math.isfinite(ret_pct):
            continue
        is_win = (
            (rt.net_pnl_base > 0.0)
            if isinstance(rt, ClosedRoundTrip)
            else (ret_pct > 0.0)
        )
        buckets[(dt_utc.weekday(), dt_utc.hour)].append((is_win, ret_pct * 100.0))

    cells: list[SessionExpectancyCell] = []
    for (weekday, hour_utc) in sorted(buckets.keys()):
        rows = buckets[(weekday, hour_utc)]
        count = len(rows)
        if count == 0:
            continue
        wins = sum(1 for win_flag, _ in rows if win_flag)
        win_rate = max(0.0, min(1.0, round(wins / count, 6)))
        exp_bps = round(sum(bps for _, bps in rows) / count, 4)
        if exp_bps == 0.0:
            exp_bps = 0.0
        cells.append(
            SessionExpectancyCell(
                weekday=weekday,
                hour_utc=hour_utc,
                trade_count=count,
                win_rate=win_rate,
                expectancy_bps=exp_bps,
            )
        )
    return cells


def _clamp_dna_score(raw_value: float) -> float:
    if not math.isfinite(raw_value):
        return 50.0
    val = round(max(0.0, min(100.0, raw_value)), 2)
    return 0.0 if val == 0.0 else val


def compute_quant_dna_profile(
    ledger: CanonicalPortfolioLedger,
    *,
    behaviour: BehaviouralCoachingMetrics,
    cost_drag: CostAndDragBreakdown,
    catalyst_regime_win_rate: float | None = None,
    quiet_regime_win_rate: float | None = None,
    event_window_share_pct: float = 0.0,
    max_drawdown_decimal: float | None = None,
    closed_round_trips: Sequence[ClosedRoundTrip] | None = None,
) -> QuantDnaProfile:
    """Compute a 6-axis ``0.0..100.0`` normalized ``QuantDnaProfile`` and constructive archetype."""
    nav_dd_series = _build_nav_drawdown_series(ledger)
    if max_drawdown_decimal is not None and math.isfinite(max_drawdown_decimal):
        dd_mag = abs(float(max_drawdown_decimal))
    elif nav_dd_series:
        dd_mag = max((dd for _, _, dd in nav_dd_series), default=0.0)
    else:
        dd_mag = 0.0

    trips = list(closed_round_trips) if closed_round_trips is not None else match_fifo_round_trips(ledger)
    n_trips = len(trips)

    # Derive ungated sample fallbacks when sample_eligible is False so radar axes stay informative.
    eff_win_rate = behaviour.win_rate
    eff_pf = behaviour.profit_factor
    eff_hold_ratio = behaviour.winner_vs_loser_hold_ratio
    eff_top5_conc = behaviour.return_concentration_top5_pct
    eff_median_hours = behaviour.median_holding_hours
    if n_trips > 0 and eff_win_rate is None:
        winners = [t for t in trips if t.net_pnl_base > 0.0]
        losers = [t for t in trips if t.net_pnl_base < 0.0]
        eff_win_rate = len(winners) / n_trips
        gross_w = sum(t.net_pnl_base for t in winners)
        gross_l = abs(sum(t.net_pnl_base for t in losers))
        if gross_l > 0.0:
            eff_pf = gross_w / gross_l
        if winners and losers:
            med_l = float(statistics.median(t.holding_hours for t in losers))
            if med_l > 0.0:
                eff_hold_ratio = float(statistics.median(t.holding_hours for t in winners)) / med_l
        if gross_w > 0.0:
            top5 = sorted((t.net_pnl_base for t in winners), reverse=True)[:5]
            eff_top5_conc = min(100.0, max(0.0, (sum(top5) / gross_w) * 100.0))
        eff_median_hours = float(statistics.median(t.holding_hours for t in trips))

    # 1. Consistency score
    if n_trips > 0 and eff_win_rate is not None:
        wr_sub = min(100.0, max(0.0, (eff_win_rate / 0.65) * 85.0 + 15.0))
        if eff_pf is not None and eff_pf >= 0.0:
            pf_sub = 100.0 * (eff_pf / (eff_pf + 1.0))
        elif eff_win_rate >= 0.999:
            pf_sub = 95.0
        else:
            pf_sub = 45.0
        conc_sub = (
            100.0 - 0.6 * eff_top5_conc
            if (eff_top5_conc is not None and n_trips >= 6)
            else 65.0
        )
        consistency_raw = 0.40 * wr_sub + 0.35 * pf_sub + 0.25 * conc_sub
    elif len(nav_dd_series) >= 3:
        pos_steps = sum(
            1
            for (_, nav0, _), (_, nav1, _) in zip(nav_dd_series, nav_dd_series[1:])
            if nav1 >= nav0
        )
        consistency_raw = 25.0 + 65.0 * (pos_steps / max(1, len(nav_dd_series) - 1))
    else:
        consistency_raw = 50.0

    # 2. Drawdown resilience score
    drawdown_resilience_raw = 100.0 * math.exp(-3.2 * max(0.0, dd_mag))

    # 3. Cost efficiency score
    total_drag_bps = max(0.0, float(cost_drag.total_friction_drag_bps))
    ann_drag_bps = min(500.0, max(0.0, float(cost_drag.annualized_total_drag_bps)))
    blended_drag_bps = 0.65 * total_drag_bps + 0.35 * ann_drag_bps
    cost_efficiency_raw = 100.0 * math.exp(-blended_drag_bps / 120.0)

    # 4. Sizing discipline score
    sdi_val = behaviour.post_drawdown_sizing_discipline_atr
    if sdi_val is None:
        sdi_val, _ = compute_post_drawdown_sizing_discipline(ledger)
    if sdi_val is None:
        sizing_discipline_raw = 78.0 if dd_mag <= 0.05 else 65.0
    elif sdi_val <= 1.0:
        sizing_discipline_raw = min(100.0, 85.0 + 15.0 * max(0.0, 1.0 - abs(sdi_val - 0.85)))
    else:
        sizing_discipline_raw = 85.0 * math.exp(-1.4 * (sdi_val - 1.0))

    # 5. Exit symmetry score
    hold_sub = (
        100.0 * (eff_hold_ratio / (eff_hold_ratio + 0.8))
        if (eff_hold_ratio is not None and eff_hold_ratio >= 0.0)
        else 60.0
    )
    if behaviour.odean_pgr_plr_spread is not None:
        odean_sub = min(100.0, max(0.0, 75.0 - 120.0 * behaviour.odean_pgr_plr_spread))
        exit_symmetry_raw = 0.55 * hold_sub + 0.45 * odean_sub
    else:
        exit_symmetry_raw = hold_sub

    # 6. Catalyst alignment score
    ev_share = max(0.0, min(1.0, float(event_window_share_pct) / 100.0))
    if catalyst_regime_win_rate is not None and quiet_regime_win_rate is not None:
        blended_wr = ev_share * catalyst_regime_win_rate + (1.0 - ev_share) * quiet_regime_win_rate
        catalyst_alignment_raw = 30.0 + 65.0 * blended_wr
    elif catalyst_regime_win_rate is not None:
        catalyst_alignment_raw = 30.0 + 65.0 * catalyst_regime_win_rate
    elif quiet_regime_win_rate is not None:
        catalyst_alignment_raw = 30.0 + 60.0 * quiet_regime_win_rate
    elif eff_win_rate is not None:
        catalyst_alignment_raw = 35.0 + 50.0 * eff_win_rate
    else:
        catalyst_alignment_raw = 60.0

    consistency_score = _clamp_dna_score(consistency_raw)
    drawdown_resilience_score = _clamp_dna_score(drawdown_resilience_raw)
    cost_efficiency_score = _clamp_dna_score(cost_efficiency_raw)
    sizing_discipline_score = _clamp_dna_score(sizing_discipline_raw)
    exit_symmetry_score = _clamp_dna_score(exit_symmetry_raw)
    catalyst_alignment_score = _clamp_dna_score(catalyst_alignment_raw)

    horizon = behaviour.holding_horizon_label
    if horizon == "insufficient_sample" and eff_median_hours is not None:
        horizon = classify_holding_horizon(eff_median_hours)

    if event_window_share_pct >= 35.0:
        archetype = ARCHETYPE_CATALYST_SPECIALIST
    elif horizon == "intraday":
        archetype = ARCHETYPE_INTRADAY_LIQUIDITY
    elif horizon == "position_investor" or (
        behaviour.observed_days >= 60 and n_trips <= 15 and cost_efficiency_score >= 70.0
    ):
        archetype = ARCHETYPE_LOW_TURNOVER_COMPOUNDER
    elif horizon == "multi_day_swing" and (
        (eff_top5_conc is not None and eff_top5_conc >= 55.0) or exit_symmetry_score >= 68.0
    ):
        archetype = ARCHETYPE_HIGH_CONVICTION_SWING
    else:
        archetype = ARCHETYPE_SYSTEMATIC_ALLOCATOR

    return QuantDnaProfile(
        archetype_label=archetype,
        consistency_score=consistency_score,
        drawdown_resilience_score=drawdown_resilience_score,
        cost_efficiency_score=cost_efficiency_score,
        sizing_discipline_score=sizing_discipline_score,
        exit_symmetry_score=exit_symmetry_score,
        catalyst_alignment_score=catalyst_alignment_score,
    )


def sanitize_journal_tags(tags: Sequence[str] | None) -> list[str]:
    """Normalize, deduplicate, and claim-safety-filter imported trade journal setup tags."""
    if not tags:
        return []
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw_tag in tags:
        if not isinstance(raw_tag, str):
            continue
        candidate = "".join(ch for ch in raw_tag if ord(ch) >= 0x20 and ord(ch) != 0x7F)
        candidate = candidate.strip().lstrip("=+-@'| \t\r\n").strip()
        if not candidate or len(candidate) > 64:
            continue
        lowered = candidate.lower()
        if any(bad in candidate for bad in ("/", "\\", "<", ">")):
            continue
        if contains_forbidden_claim(candidate) or contains_currency_amount(candidate):
            continue
        if lowered not in seen:
            seen.add(lowered)
            cleaned.append(candidate)
        if len(cleaned) >= 50:
            break
    return cleaned


__all__ = [
    "ARCHETYPE_CATALYST_SPECIALIST",
    "ARCHETYPE_HIGH_CONVICTION_SWING",
    "ARCHETYPE_INTRADAY_LIQUIDITY",
    "ARCHETYPE_LOW_TURNOVER_COMPOUNDER",
    "ARCHETYPE_SYSTEMATIC_ALLOCATOR",
    "ClosedRoundTrip",
    "LONG_WINDOW_DAYS_GATE",
    "LONG_WINDOW_MIN_TRADES",
    "SHORT_WINDOW_MIN_TRADES",
    "classify_holding_horizon",
    "compute_behavioural_coaching_metrics",
    "compute_odean_disposition_spread",
    "compute_post_drawdown_sizing_discipline",
    "compute_quant_dna_profile",
    "compute_session_expectancy_heatmap",
    "extract_delayed_closed_trades",
    "match_fifo_round_trips",
    "sanitize_journal_tags",
]
