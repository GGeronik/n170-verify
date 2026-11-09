"""Portfolio friction and cost drag waterfall decomposition in basis points of average NAV."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re

from n170_verify.contracts import (
    AssetClass,
    CanonicalPortfolioLedger,
    CostAndDragBreakdown,
    FlowKind,
    NormalizedFlow,
    NormalizedTrade,
    parse_utc_timestamp,
)


BPS_MULTIPLIER: float = 10_000.0
SECONDS_PER_DAY: float = 86_400.0

_PAIR_SPLIT_RE = re.compile(r"[/._\-]+")


def normalize_fx_pair(symbol_or_pair: str) -> tuple[str, str] | None:
    """Parse an FX symbol such as 'EURUSD.FOREX', 'EUR.USD', 'EUR/USD', or 'EURUSD' into (base, quote)."""
    cleaned = symbol_or_pair.strip().upper()
    if not cleaned:
        return None
    if cleaned.endswith(".FOREX"):
        cleaned = cleaned[:-6]
    elif cleaned.endswith("=X"):
        cleaned = cleaned[:-2]

    parts = [p for p in _PAIR_SPLIT_RE.split(cleaned) if p]
    if len(parts) == 2 and all(2 <= len(p) <= 6 and p.isalnum() for p in parts):
        return parts[0], parts[1]
    if len(parts) == 1 and len(parts[0]) == 6 and parts[0].isalpha():
        return parts[0][:3], parts[0][3:]
    return None


def _lookup_rate_in_mapping(
    mapping: Mapping[str, object],
    candidate_keys: tuple[str, ...],
    date_str: str | None,
) -> float | None:
    if date_str and date_str in mapping:
        dated_sub = mapping[date_str]
        if isinstance(dated_sub, Mapping):
            for key in candidate_keys:
                val = dated_sub.get(key)
                if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0.0:
                    return float(val)

    for key in candidate_keys:
        if key not in mapping:
            continue
        raw = mapping[key]
        if isinstance(raw, (int, float)) and not isinstance(raw, bool) and raw > 0.0:
            return float(raw)
        if isinstance(raw, Mapping) and raw:
            if date_str and date_str in raw:
                dval = raw[date_str]
                if isinstance(dval, (int, float)) and not isinstance(dval, bool) and dval > 0.0:
                    return float(dval)
            # Causal latest-on-or-before lookup when keys are YYYY-MM-DD dates.
            if date_str:
                prior_dates = sorted(k for k in raw.keys() if isinstance(k, str) and k <= date_str)
                if prior_dates:
                    pval = raw[prior_dates[-1]]
                    if isinstance(pval, (int, float)) and not isinstance(pval, bool) and pval > 0.0:
                        return float(pval)
    return None


def resolve_forex_midpoint(
    from_ccy: str,
    to_ccy: str,
    *,
    base_currency: str | None = None,
    date_str: str | None = None,
    conversion_rates: Mapping[str, float] | None = None,
    forex_midpoints: Mapping[str, object] | None = None,
) -> float | None:
    """Resolve midpoint FX rate expressing units of ``to_ccy`` per 1 unit of ``from_ccy``."""
    src = from_ccy.strip().upper()
    dst = to_ccy.strip().upper()
    if not src or not dst:
        return None
    if src == dst:
        return 1.0

    base_norm = base_currency.strip().upper() if base_currency else None
    direct_keys: list[str] = [
        f"{src}{dst}.FOREX",
        f"{src}.{dst}.FOREX",
        f"{src}/{dst}",
        f"{src}.{dst}",
        f"{src}-{dst}",
        f"{src}{dst}",
    ]
    if base_norm and dst == base_norm:
        direct_keys.append(src)

    inverse_keys: list[str] = [
        f"{dst}{src}.FOREX",
        f"{dst}.{src}.FOREX",
        f"{dst}/{src}",
        f"{dst}.{src}",
        f"{dst}-{src}",
        f"{dst}{src}",
    ]
    if base_norm and src == base_norm:
        inverse_keys.append(dst)

    direct_tuple = tuple(direct_keys)
    inverse_tuple = tuple(inverse_keys)

    for source_map in (forex_midpoints, conversion_rates):
        if not source_map:
            continue
        direct = _lookup_rate_in_mapping(source_map, direct_tuple, date_str)
        if direct is not None:
            return direct
        inv = _lookup_rate_in_mapping(source_map, inverse_tuple, date_str)
        if inv is not None and inv > 0.0:
            return 1.0 / inv

    return None


def compute_time_weighted_average_nav(ledger: CanonicalPortfolioLedger) -> float:
    """Compute piecewise trapezoidal time-weighted average NAV in statement base currency."""
    valid_points: list[tuple[datetime, float]] = []
    for pt in ledger.nav_points:
        if pt.nav_base > 0.0:
            valid_points.append((parse_utc_timestamp(pt.timestamp_utc), float(pt.nav_base)))

    if len(valid_points) >= 2:
        valid_points.sort(key=lambda item: item[0])
        total_seconds = (valid_points[-1][0] - valid_points[0][0]).total_seconds()
        if total_seconds > 0.0:
            weighted_area = 0.0
            for idx in range(len(valid_points) - 1):
                t0, nav0 = valid_points[idx]
                t1, nav1 = valid_points[idx + 1]
                dt = (t1 - t0).total_seconds()
                if dt > 0.0:
                    weighted_area += 0.5 * (nav0 + nav1) * dt
            if weighted_area > 0.0:
                return weighted_area / total_seconds
        return sum(nav for _, nav in valid_points) / len(valid_points)

    if len(valid_points) == 1:
        return valid_points[0][1]

    prior_sum = sum(pos.market_value_base for pos in ledger.prior_positions)
    ending_sum = sum(pos.market_value_base for pos in ledger.ending_positions)
    candidates = [val for val in (prior_sum, ending_sum) if val > 0.0]
    if candidates:
        return sum(candidates) / len(candidates)
    return 0.0


def _flow_amount_base(flow: NormalizedFlow) -> float:
    if flow.amount_base is not None:
        return float(flow.amount_base)
    return float(flow.amount) * float(flow.fx_rate_to_base)


def _aggregate_strict_cost_flows(flows: list[NormalizedFlow]) -> float:
    """Aggregate strictly-cost flow categories, supporting both signed (<0) and magnitude (>0) conventions."""
    if not flows:
        return 0.0
    amounts = [_flow_amount_base(f) for f in flows]
    if any(a < 0.0 for a in amounts):
        return max(0.0, -sum(amounts))
    return sum(abs(a) for a in amounts)


def _aggregate_funding_and_margin_flows(
    margin_flows: list[NormalizedFlow],
    funding_flows: list[NormalizedFlow],
    *,
    ledger_uses_signed_costs: bool,
) -> float:
    margin_cost = _aggregate_strict_cost_flows(margin_flows)
    if not funding_flows:
        return margin_cost

    funding_amounts = [_flow_amount_base(f) for f in funding_flows]
    if any(a < 0.0 for a in funding_amounts) or ledger_uses_signed_costs:
        # Signed ledger convention: negative cash flow = funding paid (+drag), positive = funding received (-drag).
        funding_net_cost = -sum(funding_amounts)
    else:
        # Unsigned magnitude fallback unless description marks a credit/rebate.
        funding_net_cost = 0.0
        for flow, amt in zip(funding_flows, funding_amounts):
            desc = flow.description.lower()
            if any(tok in desc for tok in ("credit", "received", "rebate", "income")):
                funding_net_cost -= amt
            else:
                funding_net_cost += abs(amt)

    return margin_cost + funding_net_cost


def _compute_trade_fx_spread_cost_base(
    trade: NormalizedTrade,
    *,
    base_currency: str,
    conversion_rates: Mapping[str, float],
    forex_midpoints: Mapping[str, object] | None,
) -> float:
    date_str = parse_utc_timestamp(trade.timestamp_utc).strftime("%Y-%m-%d")
    mult = trade.multiplier if trade.multiplier is not None else 1.0
    qty = abs(trade.quantity)
    if qty <= 0.0:
        return 0.0

    if trade.asset_class == AssetClass.FX:
        parsed_pair = normalize_fx_pair(trade.symbol)
        if parsed_pair is None and trade.currency != base_currency:
            parsed_pair = (base_currency, trade.currency)
        if parsed_pair is None:
            return 0.0
        fx_base, fx_quote = parsed_pair
        mid = resolve_forex_midpoint(
            fx_base,
            fx_quote,
            base_currency=base_currency,
            date_str=date_str,
            conversion_rates=conversion_rates,
            forex_midpoints=forex_midpoints,
        )
        if mid is None or mid <= 0.0:
            return 0.0
        if trade.side == "buy":
            shortfall_quote = max(0.0, trade.price - mid) * qty * mult
        else:
            shortfall_quote = max(0.0, mid - trade.price) * qty * mult

        if trade.currency == fx_quote:
            return shortfall_quote * trade.fx_rate_to_base
        quote_to_base = resolve_forex_midpoint(
            fx_quote,
            base_currency,
            base_currency=base_currency,
            date_str=date_str,
            conversion_rates=conversion_rates,
            forex_midpoints=forex_midpoints,
        )
        return shortfall_quote * (quote_to_base if quote_to_base is not None else trade.fx_rate_to_base)

    # Non-FX trade settled in foreign currency with embedded AutoFX conversion spread.
    if trade.currency != base_currency:
        mid_to_base = resolve_forex_midpoint(
            trade.currency,
            base_currency,
            base_currency=base_currency,
            date_str=date_str,
            conversion_rates=conversion_rates,
            forex_midpoints=forex_midpoints,
        )
        if mid_to_base is not None and mid_to_base > 0.0:
            foreign_notional = qty * trade.price * mult
            if trade.side == "buy":
                return foreign_notional * max(0.0, trade.fx_rate_to_base - mid_to_base)
            return foreign_notional * max(0.0, mid_to_base - trade.fx_rate_to_base)

    return 0.0


def _compute_flow_fx_spread_cost_base(
    flow: NormalizedFlow,
    *,
    base_currency: str,
    conversion_rates: Mapping[str, float],
    forex_midpoints: Mapping[str, object] | None,
) -> float:
    if flow.kind == FlowKind.FX_TRANSLATION or flow.currency == base_currency or flow.amount == 0.0:
        return 0.0

    date_str = parse_utc_timestamp(flow.timestamp_utc).strftime("%Y-%m-%d")
    mid_to_base = resolve_forex_midpoint(
        flow.currency,
        base_currency,
        base_currency=base_currency,
        date_str=date_str,
        conversion_rates=conversion_rates,
        forex_midpoints=forex_midpoints,
    )
    if mid_to_base is None or mid_to_base <= 0.0:
        return 0.0

    effective_rate = (
        abs(_flow_amount_base(flow)) / abs(flow.amount)
        if flow.amount_base is not None
        else flow.fx_rate_to_base
    )
    if flow.amount > 0.0:
        # Foreign inflow converted below midpoint yields less base currency.
        return abs(flow.amount) * max(0.0, mid_to_base - effective_rate)
    # Foreign outflow converted above midpoint costs more base currency.
    return abs(flow.amount) * max(0.0, effective_rate - mid_to_base)


def compute_cost_and_drag_breakdown(
    ledger: CanonicalPortfolioLedger,
    *,
    forex_midpoints: Mapping[str, object] | None = None,
    average_nav_override: float | None = None,
    days_per_year: float = 365.0,
) -> CostAndDragBreakdown:
    """Compute the 4-component institutional cost & friction waterfall in bps of average NAV."""
    if days_per_year <= 0.0:
        raise ValueError("days_per_year must be > 0")

    avg_nav = (
        float(average_nav_override)
        if average_nav_override is not None
        else compute_time_weighted_average_nav(ledger)
    )
    if avg_nav <= 0.0:
        return CostAndDragBreakdown(
            commission_and_fee_drag_bps=0.0,
            margin_and_funding_drag_bps=0.0,
            fx_conversion_drag_bps=0.0,
            withholding_tax_drag_bps=0.0,
            total_friction_drag_bps=0.0,
            annualized_total_drag_bps=0.0,
        )

    # Detect whether ledger flows follow standard negative-outflow cash convention.
    strict_cost_kinds = {
        FlowKind.COMMISSION_FEE,
        FlowKind.MARGIN_INTEREST,
        FlowKind.WITHHOLDING_TAX,
        FlowKind.WITHDRAWAL,
    }
    ledger_uses_signed_costs = any(
        _flow_amount_base(f) < 0.0 for f in ledger.flows if f.kind in strict_cost_kinds
    )

    # (a) Commissions, transaction taxes, and standalone fee flows.
    trade_comm_and_tax_base = sum(
        (abs(t.commission) + abs(t.tax)) * t.fx_rate_to_base for t in ledger.trades
    )
    comm_flows = [f for f in ledger.flows if f.kind == FlowKind.COMMISSION_FEE]
    commission_and_fee_cost_base = trade_comm_and_tax_base + _aggregate_strict_cost_flows(comm_flows)

    # (b) Margin debit interest + crypto perpetual funding payments.
    margin_flows = [f for f in ledger.flows if f.kind == FlowKind.MARGIN_INTEREST]
    funding_flows = [f for f in ledger.flows if f.kind == FlowKind.PERP_FUNDING]
    margin_and_funding_cost_base = _aggregate_funding_and_margin_flows(
        margin_flows,
        funding_flows,
        ledger_uses_signed_costs=ledger_uses_signed_costs,
    )

    # (c) FX conversion spread vs .FOREX / midpoint rates + FX_TRANSLATION costs.
    fx_trade_spread_base = sum(
        _compute_trade_fx_spread_cost_base(
            t,
            base_currency=ledger.base_currency,
            conversion_rates=ledger.conversion_rates,
            forex_midpoints=forex_midpoints,
        )
        for t in ledger.trades
    )
    fx_flow_spread_base = sum(
        _compute_flow_fx_spread_cost_base(
            f,
            base_currency=ledger.base_currency,
            conversion_rates=ledger.conversion_rates,
            forex_midpoints=forex_midpoints,
        )
        for f in ledger.flows
    )
    fx_translation_flows = [f for f in ledger.flows if f.kind == FlowKind.FX_TRANSLATION]
    if fx_translation_flows:
        fx_trans_amounts = [_flow_amount_base(f) for f in fx_translation_flows]
        if any(a < 0.0 for a in fx_trans_amounts) or ledger_uses_signed_costs:
            fx_translation_cost_base = max(0.0, -sum(fx_trans_amounts))
        else:
            fx_translation_cost_base = sum(abs(a) for a in fx_trans_amounts)
    else:
        fx_translation_cost_base = 0.0

    fx_conversion_cost_base = fx_trade_spread_base + fx_flow_spread_base + fx_translation_cost_base

    # (d) Dividend withholding taxes.
    withholding_flows = [f for f in ledger.flows if f.kind == FlowKind.WITHHOLDING_TAX]
    withholding_tax_cost_base = _aggregate_strict_cost_flows(withholding_flows)

    comm_bps = round((commission_and_fee_cost_base / avg_nav) * BPS_MULTIPLIER, 6)
    margin_bps = round((margin_and_funding_cost_base / avg_nav) * BPS_MULTIPLIER, 6)
    fx_bps = round((fx_conversion_cost_base / avg_nav) * BPS_MULTIPLIER, 6)
    tax_bps = round((withholding_tax_cost_base / avg_nav) * BPS_MULTIPLIER, 6)
    total_bps = round(comm_bps + margin_bps + fx_bps + tax_bps, 6)

    start_dt = parse_utc_timestamp(ledger.period_start_utc)
    end_dt = parse_utc_timestamp(ledger.period_end_utc)
    elapsed_days = (end_dt - start_dt).total_seconds() / SECONDS_PER_DAY
    if elapsed_days <= 0.0 and len(ledger.nav_points) >= 2:
        nav_dts = sorted(parse_utc_timestamp(p.timestamp_utc) for p in ledger.nav_points)
        elapsed_days = (nav_dts[-1] - nav_dts[0]).total_seconds() / SECONDS_PER_DAY

    annualized_bps = (
        round(total_bps * (days_per_year / max(elapsed_days, 1.0)), 6)
        if elapsed_days > 0.0
        else 0.0
    )

    return CostAndDragBreakdown(
        commission_and_fee_drag_bps=comm_bps,
        margin_and_funding_drag_bps=margin_bps,
        fx_conversion_drag_bps=fx_bps,
        withholding_tax_drag_bps=tax_bps,
        total_friction_drag_bps=total_bps,
        annualized_total_drag_bps=annualized_bps,
    )


__all__ = [
    "BPS_MULTIPLIER",
    "compute_cost_and_drag_breakdown",
    "compute_time_weighted_average_nav",
    "normalize_fx_pair",
    "resolve_forex_midpoint",
]
