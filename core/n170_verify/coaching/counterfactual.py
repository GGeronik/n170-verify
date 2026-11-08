"""Hypothetical 'Actual vs. Disciplined Twin' counterfactual coaching simulator.

Compliance invariant:
- Strictly coaching-only simulation isolated inside ``TraderCoachingAndContextReport``.
- Always sets ``is_hypothetical_simulation=True`` and ``DEFAULT_COUNTERFACTUAL_DISCLAIMER``.
- Never mutates, replaces, or touches verified realized ``twr`` or ``xirr`` in
  ``PerformanceSummary`` or Merkle ``"core_metrics"``.
- Rebased to ``1.0`` at ``step=0`` with zero raw currency amounts.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
import math
from typing import Any

import numpy as np

from n170_verify.coaching.behaviour_metrics import (
    ClosedRoundTrip,
    compute_post_drawdown_sizing_discipline,
    match_fifo_round_trips,
)
from n170_verify.coaching.cost_and_drag import (
    BPS_MULTIPLIER,
    _compute_flow_fx_spread_cost_base,
    _compute_trade_fx_spread_cost_base,
    compute_cost_and_drag_breakdown,
)
from n170_verify.contracts import (
    BehaviouralCoachingMetrics,
    CanonicalPortfolioLedger,
    CostAndDragBreakdown,
    CounterfactualTwinReport,
    FlowKind,
    NormalizedNavPoint,
    parse_utc_timestamp,
)
from n170_verify.contracts.coaching import DEFAULT_COUNTERFACTUAL_DISCLAIMER


_CAPITAL_FLOW_KINDS: frozenset[FlowKind] = frozenset(
    {
        FlowKind.DEPOSIT,
        FlowKind.WITHDRAWAL,
        FlowKind.TRANSFER_IN_KIND,
        FlowKind.TRANSFER_OUT_KIND,
        FlowKind.INTERNAL_SUBACCOUNT_TRANSFER,
    }
)


def _signed_capital_flow_base(flow_kind: FlowKind, amount_base: float) -> float:
    if flow_kind in {FlowKind.WITHDRAWAL, FlowKind.TRANSFER_OUT_KIND}:
        return -abs(amount_base)
    return amount_base


def _deduplicated_positive_navs(
    ledger: CanonicalPortfolioLedger,
) -> list[tuple[datetime, NormalizedNavPoint]]:
    raw = [
        (parse_utc_timestamp(pt.timestamp_utc), pt)
        for pt in ledger.nav_points
        if pt.nav_base > 0.0 and math.isfinite(pt.nav_base)
    ]
    raw.sort(key=lambda item: item[0])
    deduped: list[tuple[datetime, NormalizedNavPoint]] = []
    for ts, pt in raw:
        if deduped and deduped[-1][0] == ts:
            deduped[-1] = (ts, pt)
        else:
            deduped.append((ts, pt))
    return deduped


def _locate_step_index(
    event_ts: datetime,
    intervals: Sequence[tuple[datetime, datetime, str, float, float]],
) -> int:
    if event_ts <= intervals[0][0]:
        return 0
    for idx, (prev_ts, curr_ts, _, _, _) in enumerate(intervals):
        if prev_ts < event_ts <= curr_ts:
            return idx
    return len(intervals) - 1


def simulate_counterfactual_twin(
    ledger: CanonicalPortfolioLedger,
    *,
    cost_drag: CostAndDragBreakdown | None = None,
    behaviour: BehaviouralCoachingMetrics | None = None,
    closed_round_trips: Sequence[ClosedRoundTrip] | None = None,
    forex_midpoints: Mapping[str, object] | None = None,
    atr_14_series: Mapping[str, Any] | None = None,
) -> CounterfactualTwinReport:
    """Simulate 3 hypothetical coaching counterfactual wealth paths rebased at ``1.0``.

    1. ``zero_friction``: Re-compounds returns adding back commissions, FX conversion spread
       drag, and avoidable margin/perpetual financing drag.
    2. ``disciplined_sizing``: Caps active position exposure during ``>5%`` underwater
       drawdowns to ``1.0x`` baseline near-HWM risk whenever post-drawdown sizing discipline
       exceeds ``1.0``.
    3. ``capped_tail_loss``: Caps closed trade losses beyond the ``95th`` loss-magnitude
       percentile at the ``90th`` percentile stop (with sub-period fallback when no closed
       trades exist).
    """
    nav_sorted = _deduplicated_positive_navs(ledger)
    if len(nav_sorted) < 2:
        fallback_date = (
            nav_sorted[0][1].timestamp_utc[:10]
            if nav_sorted
            else parse_utc_timestamp(ledger.period_start_utc).strftime("%Y-%m-%d")
        )
        return CounterfactualTwinReport(
            is_hypothetical_simulation=True,
            compliance_disclaimer=DEFAULT_COUNTERFACTUAL_DISCLAIMER,
            actual_ending_index=1.0,
            zero_friction_ending_index=1.0,
            disciplined_post_dd_sizing_ending_index=1.0,
            capped_tail_loss_ending_index=1.0,
            curve_points=[
                {
                    "step": 0,
                    "date": fallback_date,
                    "actual": 1.0,
                    "zero_friction": 1.0,
                    "disciplined_sizing": 1.0,
                    "capped_tail_loss": 1.0,
                }
            ],
        )

    start_ts = nav_sorted[0][0]
    end_ts = nav_sorted[-1][0]

    cap_flows: list[tuple[datetime, float]] = []
    for fl in ledger.flows:
        if fl.kind not in _CAPITAL_FLOW_KINDS:
            continue
        amt_base = (
            float(fl.amount_base)
            if (fl.amount_base is not None and math.isfinite(fl.amount_base))
            else float(fl.amount) * float(fl.fx_rate_to_base)
        )
        if not math.isfinite(amt_base):
            continue
        fts = parse_utc_timestamp(fl.timestamp_utc)
        if start_ts < fts <= end_ts:
            cap_flows.append((fts, _signed_capital_flow_base(fl.kind, amt_base)))
    cap_flows.sort(key=lambda item: item[0])

    intervals: list[tuple[datetime, datetime, str, float, float]] = []
    for (prev_ts, prev_pt), (curr_ts, curr_pt) in zip(nav_sorted, nav_sorted[1:]):
        net_flow = math.fsum(
            amt for fts, amt in cap_flows if prev_ts < fts <= curr_ts
        )
        open_nav = float(prev_pt.nav_base)
        close_nav = float(curr_pt.nav_base)
        raw_ret = ((close_nav - net_flow) / open_nav) - 1.0 if open_nav > 0.0 else 0.0
        if not math.isfinite(raw_ret):
            raw_ret = 0.0
        safe_ret = max(-0.999999, raw_ret)
        intervals.append((prev_ts, curr_ts, curr_pt.timestamp_utc[:10], open_nav, safe_ret))

    n_steps = len(intervals)
    resolved_cost_drag = (
        cost_drag
        if cost_drag is not None
        else compute_cost_and_drag_breakdown(ledger, forex_midpoints=forex_midpoints)
    )
    trips = (
        list(closed_round_trips)
        if closed_round_trips is not None
        else match_fifo_round_trips(ledger)
    )

    # --- 1. Zero-Friction per-step addback ---
    avoidable_bps = (
        max(0.0, float(resolved_cost_drag.commission_and_fee_drag_bps))
        + max(0.0, float(resolved_cost_drag.fx_conversion_drag_bps))
        + max(0.0, float(resolved_cost_drag.margin_and_funding_drag_bps))
    )
    avoidable_total_decimal = avoidable_bps / BPS_MULTIPLIER

    step_friction_dec = [0.0] * n_steps
    for tr in ledger.trades:
        tr_ts = parse_utc_timestamp(tr.timestamp_utc)
        if tr_ts > end_ts:
            continue
        idx = _locate_step_index(tr_ts, intervals)
        open_nav = intervals[idx][3]
        if open_nav <= 0.0:
            continue
        comm_cost_base = (abs(tr.commission) + abs(tr.tax)) * tr.fx_rate_to_base
        fx_spread_base = _compute_trade_fx_spread_cost_base(
            tr,
            base_currency=ledger.base_currency,
            conversion_rates=ledger.conversion_rates,
            forex_midpoints=forex_midpoints,
        )
        step_friction_dec[idx] += max(0.0, comm_cost_base + fx_spread_base) / open_nav

    signed_cost_convention = any(
        (fl.amount_base if fl.amount_base is not None else fl.amount * fl.fx_rate_to_base) < 0.0
        for fl in ledger.flows
        if fl.kind
        in {
            FlowKind.COMMISSION_FEE,
            FlowKind.MARGIN_INTEREST,
            FlowKind.WITHHOLDING_TAX,
            FlowKind.WITHDRAWAL,
        }
    )
    for fl in ledger.flows:
        fl_ts = parse_utc_timestamp(fl.timestamp_utc)
        if fl_ts > end_ts:
            continue
        idx = _locate_step_index(fl_ts, intervals)
        open_nav = intervals[idx][3]
        if open_nav <= 0.0:
            continue
        amt_base = (
            float(fl.amount_base)
            if fl.amount_base is not None
            else float(fl.amount) * float(fl.fx_rate_to_base)
        )
        flow_cost = 0.0
        if fl.kind in {FlowKind.COMMISSION_FEE, FlowKind.MARGIN_INTEREST}:
            flow_cost += max(0.0, -amt_base) if signed_cost_convention or amt_base < 0.0 else abs(amt_base)
        elif fl.kind == FlowKind.PERP_FUNDING:
            if signed_cost_convention or amt_base < 0.0:
                flow_cost += max(0.0, -amt_base)
            elif not any(tok in fl.description.lower() for tok in ("credit", "received", "rebate", "income")):
                flow_cost += abs(amt_base)
        elif fl.kind == FlowKind.FX_TRANSLATION:
            flow_cost += max(0.0, -amt_base) if signed_cost_convention or amt_base < 0.0 else abs(amt_base)

        flow_fx_spread = _compute_flow_fx_spread_cost_base(
            fl,
            base_currency=ledger.base_currency,
            conversion_rates=ledger.conversion_rates,
            forex_midpoints=forex_midpoints,
        )
        step_friction_dec[idx] += max(0.0, flow_cost + flow_fx_spread) / open_nav

    attributed_sum = sum(step_friction_dec)
    if avoidable_total_decimal > attributed_sum + 1e-12:
        per_step_residual = (avoidable_total_decimal - attributed_sum) / float(n_steps)
        step_friction_dec = [val + per_step_residual for val in step_friction_dec]
    elif avoidable_total_decimal <= 0.0:
        step_friction_dec = [0.0] * n_steps

    # --- 2. Disciplined Post-Drawdown Sizing ratio ---
    sdi_ratio: float | None = (
        float(behaviour.post_drawdown_sizing_discipline_atr)
        if (behaviour is not None and behaviour.post_drawdown_sizing_discipline_atr is not None)
        else None
    )
    if sdi_ratio is None:
        sdi_ratio, _ = compute_post_drawdown_sizing_discipline(
            ledger,
            atr_14_series=atr_14_series,
        )

    # --- 3. Tail-Capped Twin (95th loss percentile capped at 90th percentile stop) ---
    step_tail_addback = [0.0] * n_steps
    losing_trips = [
        rt
        for rt in trips
        if rt.net_pnl_base < 0.0 and rt.return_pct < 0.0 and math.isfinite(rt.return_pct)
    ]
    if len(losing_trips) >= 2:
        loss_magnitudes = np.asarray([abs(rt.return_pct) for rt in losing_trips], dtype=np.float64)
        p90_loss_pct = float(np.quantile(loss_magnitudes, 0.90))
        p95_loss_pct = float(np.quantile(loss_magnitudes, 0.95))
        for rt in losing_trips:
            mag = abs(rt.return_pct)
            if mag > p95_loss_pct and mag > p90_loss_pct and mag > 0.0:
                saved_pnl_base = abs(rt.net_pnl_base) * (1.0 - (p90_loss_pct / mag))
                exit_dt = parse_utc_timestamp(rt.exit_timestamp_utc)
                step_idx = _locate_step_index(exit_dt, intervals)
                open_nav = intervals[step_idx][3]
                if open_nav > 0.0:
                    step_tail_addback[step_idx] += max(0.0, saved_pnl_base / open_nav)
    elif not trips:
        neg_rets = [abs(item[4]) for item in intervals if item[4] < 0.0]
        if len(neg_rets) >= 2:
            sub_mags = np.asarray(neg_rets, dtype=np.float64)
            sub_p90 = float(np.quantile(sub_mags, 0.90))
            sub_p95 = float(np.quantile(sub_mags, 0.95))
            for idx, (_, _, _, _, ret_val) in enumerate(intervals):
                if ret_val < 0.0 and abs(ret_val) > sub_p95 and abs(ret_val) > sub_p90:
                    step_tail_addback[idx] = abs(ret_val) - sub_p90

    # --- Compound all 4 wealth curves starting at 1.0 ---
    w_actual = 1.0
    w_zero_friction = 1.0
    w_disciplined = 1.0
    w_capped_tail = 1.0
    hwm_actual = 1.0

    start_date_str = nav_sorted[0][1].timestamp_utc[:10]
    curve_points: list[dict[str, Any]] = [
        {
            "step": 0,
            "date": start_date_str,
            "actual": 1.0,
            "zero_friction": 1.0,
            "disciplined_sizing": 1.0,
            "capped_tail_loss": 1.0,
        }
    ]

    for step_idx, (_, _, date_str, _, r_actual) in enumerate(intervals, start=1):
        arr_idx = step_idx - 1
        dd_entering = (hwm_actual - w_actual) / hwm_actual if hwm_actual > 0.0 else 0.0

        r_zf = r_actual + step_friction_dec[arr_idx]
        if sdi_ratio is not None and sdi_ratio > 1.0 and dd_entering > 0.05:
            r_disc = r_actual * (1.0 / sdi_ratio)
        else:
            r_disc = r_actual
        r_tail = r_actual + step_tail_addback[arr_idx]

        w_actual = max(1e-9, w_actual * (1.0 + r_actual))
        w_zero_friction = max(1e-9, w_zero_friction * max(1e-9, 1.0 + r_zf))
        w_disciplined = max(1e-9, w_disciplined * max(1e-9, 1.0 + r_disc))
        w_capped_tail = max(1e-9, w_capped_tail * max(1e-9, 1.0 + r_tail))
        hwm_actual = max(hwm_actual, w_actual)

        curve_points.append(
            {
                "step": step_idx,
                "date": date_str,
                "actual": round(w_actual, 6),
                "zero_friction": round(w_zero_friction, 6),
                "disciplined_sizing": round(w_disciplined, 6),
                "capped_tail_loss": round(w_capped_tail, 6),
            }
        )

    return CounterfactualTwinReport(
        is_hypothetical_simulation=True,
        compliance_disclaimer=DEFAULT_COUNTERFACTUAL_DISCLAIMER,
        actual_ending_index=round(w_actual, 6),
        zero_friction_ending_index=round(w_zero_friction, 6),
        disciplined_post_dd_sizing_ending_index=round(w_disciplined, 6),
        capped_tail_loss_ending_index=round(w_capped_tail, 6),
        curve_points=curve_points,
    )


__all__ = [
    "simulate_counterfactual_twin",
]
