"""Multi-asset cash- and in-kind-transfer-aware portfolio performance calculator."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
import math
from statistics import mean, median, stdev

from n170_verify.contracts import (
    AssetClass,
    CanonicalPortfolioLedger,
    CapitalBracket,
    DailyCalendarCell,
    FlowKind,
    IndexedCurvePoint,
    NormalizedFlow,
    NormalizedNavPoint,
    PerformanceSummary,
    classify_capital_bracket,
    parse_utc_timestamp,
)
from n170_verify.performance.bootstrap import run_stationary_block_bootstrap
from n170_verify.performance.econometrics import (
    EconometricBundle,
    evaluate_econometric_diagnostics,
)
from n170_verify.reference.base import ReferenceDataProvider


CAPITAL_FLOW_KINDS_FOR_TWR: frozenset[FlowKind] = frozenset(
    {
        FlowKind.DEPOSIT,
        FlowKind.WITHDRAWAL,
        FlowKind.TRANSFER_IN_KIND,
        FlowKind.TRANSFER_OUT_KIND,
        FlowKind.INTERNAL_SUBACCOUNT_TRANSFER,
    }
)

SECONDS_PER_ACT365_YEAR = 365.0 * 86400.0


@dataclass(frozen=True, slots=True)
class SubperiodReturnObservation:
    """Flow-adjusted sub-period return over ``(prev_timestamp_utc, timestamp_utc]``."""

    timestamp_utc: str
    period_return: float
    net_external_flow_base: float


@dataclass(frozen=True, slots=True)
class PerformanceCalculationResult:
    """Detailed performance result exposing sub-period return observations internally."""

    summary: PerformanceSummary
    return_observations: tuple[SubperiodReturnObservation, ...]
    econometrics: EconometricBundle | None
    withheld: bool


def _has_valid_base_valuation(flow: NormalizedFlow, ledger: CanonicalPortfolioLedger) -> bool:
    """Return False when an external or in-kind flow lacks credible base-currency valuation."""
    if flow.amount_base is None or not math.isfinite(flow.amount_base):
        return False

    if flow.kind in {FlowKind.TRANSFER_IN_KIND, FlowKind.TRANSFER_OUT_KIND}:
        qty = flow.quantity
        if abs(flow.amount_base) == 0.0 and (qty is None or abs(qty) > 0.0):
            return False

    if (
        flow.currency != ledger.base_currency
        and abs(flow.amount) > 0.0
        and abs(flow.fx_rate_to_base - 1.0) < 1e-12
        and abs(flow.amount_base - flow.amount) < 1e-12
    ):
        ccy = flow.currency
        base = ledger.base_currency
        known_keys = {
            ccy,
            f"{ccy}/{base}",
            f"{ccy}{base}",
            f"{base}/{ccy}",
            f"{base}{ccy}",
        }
        if not any(k in ledger.conversion_rates for k in known_keys):
            return False

    return True


def _signed_flow_amount_base(flow: NormalizedFlow) -> float:
    """Normalize capital flow sign: contributions positive, withdrawals/out-transfers negative."""
    assert flow.amount_base is not None
    val = float(flow.amount_base)
    if flow.kind in {FlowKind.WITHDRAWAL, FlowKind.TRANSFER_OUT_KIND}:
        return -abs(val)
    if flow.kind in {FlowKind.DEPOSIT, FlowKind.TRANSFER_IN_KIND}:
        return val
    return val


def _scaled_log_npv(rate: float, cash_flows: Sequence[tuple[float, float]]) -> float:
    """Log-scaled NPV sign/zero evaluator immune to float overflow on long horizons or huge rates."""
    if rate <= -1.0:
        return float("inf")
    log1p_r = math.log1p(rate)
    terms: list[tuple[float, float]] = []
    for amount, years in cash_flows:
        if abs(amount) <= 1e-15:
            continue
        sign = 1.0 if amount > 0.0 else -1.0
        exponent = math.log(abs(amount)) - years * log1p_r
        terms.append((sign, exponent))
    if not terms:
        return 0.0
    max_exp = max(exp for _, exp in terms)
    return math.fsum(sign * math.exp(exp - max_exp) for sign, exp in terms)


def _bisect_scaled_npv(
    cash_flows: Sequence[tuple[float, float]],
    lower: float,
    upper: float,
) -> float:
    low_val = _scaled_log_npv(lower, cash_flows)
    for _ in range(200):
        mid = 0.5 * (lower + upper)
        mid_val = _scaled_log_npv(mid, cash_flows)
        if abs(mid_val) < 1e-12 or (upper - lower) < 1e-13:
            return mid
        if (low_val < 0.0) == (mid_val < 0.0):
            lower = mid
            low_val = mid_val
        else:
            upper = mid
    return 0.5 * (lower + upper)


def solve_xirr_act365(
    dated_cash_flows: Sequence[tuple[datetime, float]],
    *,
    preferred_rate: float | None = None,
) -> tuple[float | None, tuple[str, ...]]:
    """Solve ACT/365 money-weighted XIRR with log-scaled evaluation and multi-root verification."""
    if isinstance(preferred_rate, bool):
        raise ValueError("preferred_rate must be a finite float or None, not bool")
    if preferred_rate is not None and (
        not isinstance(preferred_rate, (int, float)) or not math.isfinite(float(preferred_rate))
    ):
        raise ValueError("preferred_rate must be a finite float or None")

    by_ts: dict[datetime, float] = defaultdict(float)
    for dt_val, amt in dated_cash_flows:
        if not isinstance(dt_val, datetime):
            raise ValueError("XIRR cash-flow timestamps must be datetime instances")
        if isinstance(amt, bool) or not isinstance(amt, (int, float)):
            raise ValueError("XIRR cash-flow amounts must be finite numbers (booleans rejected)")
        f_amt = float(amt)
        if not math.isfinite(f_amt):
            raise ValueError("XIRR cash-flow amounts must be finite numbers")
        new_total = by_ts[dt_val] + f_amt
        if not math.isfinite(new_total):
            raise ValueError("Aggregated XIRR cash flow overflows IEEE-754 finite float range")
        by_ts[dt_val] = new_total

    ordered = [(ts, by_ts[ts]) for ts in sorted(by_ts) if abs(by_ts[ts]) > 1e-12]
    if (
        len(ordered) < 2
        or not any(amt > 0.0 for _, amt in ordered)
        or not any(amt < 0.0 for _, amt in ordered)
    ):
        return None, ("XIRR requires at least one positive and one negative dated cash flow.",)

    origin = ordered[0][0]
    if ordered[-1][0] <= origin:
        return None, ("XIRR requires cash flows spanning a positive time interval.",)

    cf_years = [
        (amt, (ts - origin).total_seconds() / SECONDS_PER_ACT365_YEAR)
        for ts, amt in ordered
    ]

    grid = [
        -0.999999,
        -0.9999,
        -0.999,
        -0.99,
        -0.95,
        -0.9,
        -0.75,
        -0.5,
        -0.25,
        -0.1,
        -0.05,
        0.0,
        0.01,
        0.02,
        0.05,
        0.1,
        0.15,
        0.25,
        0.5,
        1.0,
        2.0,
        5.0,
        10.0,
        25.0,
        100.0,
        1_000.0,
        10_000.0,
        1_000_000.0,
    ]

    roots: list[float] = []
    prev_r = grid[0]
    prev_v = _scaled_log_npv(prev_r, cf_years)
    for r in grid[1:]:
        curr_v = _scaled_log_npv(r, cf_years)
        if abs(prev_v) < 1e-11:
            roots.append(prev_r)
        elif math.isfinite(prev_v) and math.isfinite(curr_v) and (prev_v < 0.0) != (curr_v < 0.0):
            roots.append(_bisect_scaled_npv(cf_years, prev_r, r))
        prev_r = r
        prev_v = curr_v
    if abs(prev_v) < 1e-11:
        roots.append(prev_r)

    unique_roots: list[float] = []
    for root in roots:
        if root > -1.0 and not any(abs(root - existing) < 1e-7 for existing in unique_roots):
            unique_roots.append(root)

    if not unique_roots:
        return None, ("No finite XIRR solution was found in the supported ACT/365 rate range.",)

    if preferred_rate is not None and math.isfinite(preferred_rate):
        chosen = min(unique_roots, key=lambda candidate: abs(candidate - preferred_rate))
    else:
        chosen = min(unique_roots, key=abs)

    warnings: list[str] = []
    if len(unique_roots) > 1:
        warnings.append(
            f"XIRR has {len(unique_roots)} mathematical roots due to multiple cash-flow sign changes; "
            "selected the economically closest root."
        )
    return chosen, tuple(warnings)


def _infer_capital_bracket(
    ledger: CanonicalPortfolioLedger,
    ending_nav_base: float,
    *,
    reference_provider: ReferenceDataProvider | None = None,
    end_date_str: str,
) -> tuple[CapitalBracket | None, str | None]:
    if ending_nav_base < 0.0 or not math.isfinite(ending_nav_base):
        return None, None

    base = ledger.base_currency
    if base == "USD":
        return classify_capital_bracket(ending_nav_base), None

    for key in (f"{base}USD", f"{base}/USD", base):
        if key in ledger.conversion_rates and ledger.conversion_rates[key] > 0.0:
            return classify_capital_bracket(ending_nav_base * ledger.conversion_rates[key]), None
    for inv_key in (f"USD{base}", f"USD/{base}"):
        if inv_key in ledger.conversion_rates and ledger.conversion_rates[inv_key] > 0.0:
            return classify_capital_bracket(ending_nav_base / ledger.conversion_rates[inv_key]), None

    if reference_provider is not None and reference_provider.is_available:
        fx = reference_provider.get_fx_rate(base, "USD", date_str=end_date_str)
        if fx is not None and fx > 0.0 and math.isfinite(fx):
            return classify_capital_bracket(ending_nav_base * fx), None

    return (
        None,
        f"Capital bracket omitted because {base}->USD conversion rate was unavailable.",
    )


def _build_daily_calendar_cells(
    ledger: CanonicalPortfolioLedger,
    observations: Sequence[SubperiodReturnObservation],
    *,
    start_ts: datetime,
    end_ts: datetime,
) -> list[DailyCalendarCell]:
    """Build privacy-preserving UTC daily calendar cells (percentage return + trade count only).

    ``return_pct`` is expressed in percentage points (e.g., ``+1.25`` for ``+1.25%``),
    compounded across any sub-period observations closing on the same UTC calendar day.
    Zero currency balances, account identifiers, or share quantities are emitted.
    """
    start_day = start_ts.strftime("%Y-%m-%d")
    end_day = end_ts.strftime("%Y-%m-%d")

    compounded_factor_by_day: dict[str, float] = {}
    for obs in observations:
        day_str = parse_utc_timestamp(obs.timestamp_utc).strftime("%Y-%m-%d")
        prev_factor = compounded_factor_by_day.get(day_str, 1.0)
        compounded_factor_by_day[day_str] = prev_factor * (1.0 + obs.period_return)

    trades_by_day: dict[str, int] = defaultdict(int)
    for trade in ledger.trades:
        if trade.asset_class == AssetClass.CASH or abs(trade.quantity) <= 1e-12:
            continue
        t_day = parse_utc_timestamp(trade.timestamp_utc).strftime("%Y-%m-%d")
        if start_day <= t_day <= end_day:
            trades_by_day[t_day] += 1

    all_days = sorted(set(compounded_factor_by_day.keys()) | set(trades_by_day.keys()))
    cells: list[DailyCalendarCell] = []
    for day_str in all_days:
        factor = compounded_factor_by_day.get(day_str, 1.0)
        ret_pct = round((factor - 1.0) * 100.0, 6)
        if ret_pct == 0.0:
            ret_pct = 0.0
        cells.append(
            DailyCalendarCell(
                date=day_str,
                return_pct=ret_pct,
                trade_count=int(trades_by_day.get(day_str, 0)),
            )
        )
    return cells


def calculate_portfolio_performance_detailed(
    ledger: CanonicalPortfolioLedger,
    *,
    reference_provider: ReferenceDataProvider | None = None,
    benchmark_symbol: str | None = None,
    annual_risk_free_rate: float = 0.0,
    periods_per_year: int = 252,
    cash_flow_timing: str = "end_of_day",
    psr_benchmark_sr: float = 0.0,
) -> PerformanceCalculationResult:
    """Compute cash- and in-kind-flow-adjusted TWR, CAGR, XIRR, GLM unsmoothing, and gated PSR."""
    if periods_per_year <= 0:
        raise ValueError("periods_per_year must be positive")
    if not math.isfinite(annual_risk_free_rate) or annual_risk_free_rate <= -1.0:
        raise ValueError("annual_risk_free_rate must be finite and > -1.0")
    if cash_flow_timing not in {"end_of_day", "start_of_day", "modified_dietz"}:
        raise ValueError("cash_flow_timing must be 'end_of_day', 'start_of_day', or 'modified_dietz'")

    warnings: list[str] = list(ledger.parser_warnings)
    methodology = (
        "daily_flow_adjusted_twr_v3"
        if cash_flow_timing == "end_of_day"
        else f"daily_flow_adjusted_twr_v3_{cash_flow_timing}"
    )

    if len(ledger.nav_points) < 2:
        warnings.append("At least two NAV observations are required to compute portfolio returns.")
        summary = PerformanceSummary(
            twr_decimal=0.0,
            psr_benchmark_sr=psr_benchmark_sr,
            methodology=methodology,
            warnings=list(dict.fromkeys(warnings)),
        )
        return PerformanceCalculationResult(
            summary=summary,
            return_observations=(),
            econometrics=None,
            withheld=True,
        )

    nav_sorted: list[tuple[datetime, NormalizedNavPoint]] = sorted(
        ((parse_utc_timestamp(pt.timestamp_utc), pt) for pt in ledger.nav_points),
        key=lambda item: item[0],
    )
    nav_timestamps = [ts for ts, _ in nav_sorted]
    if len(set(nav_timestamps)) != len(nav_timestamps):
        warnings.append("Performance metrics were withheld due to duplicate NAV timestamps.")
        summary = PerformanceSummary(
            twr_decimal=0.0,
            psr_benchmark_sr=psr_benchmark_sr,
            methodology=methodology,
            warnings=list(dict.fromkeys(warnings)),
        )
        return PerformanceCalculationResult(
            summary=summary,
            return_observations=(),
            econometrics=None,
            withheld=True,
        )

    start_ts = nav_timestamps[0]
    end_ts = nav_timestamps[-1]

    capital_flows_with_ts: list[tuple[datetime, NormalizedFlow]] = [
        (parse_utc_timestamp(fl.timestamp_utc), fl)
        for fl in ledger.flows
        if fl.kind in CAPITAL_FLOW_KINDS_FOR_TWR
    ]
    capital_flows_with_ts.sort(key=lambda item: item[0])

    before_count = sum(1 for ts, _ in capital_flows_with_ts if ts <= start_ts)
    after_count = sum(1 for ts, _ in capital_flows_with_ts if ts > end_ts)
    if before_count:
        warnings.append(
            f"Ignored {before_count} capital flow(s) on or before opening NAV to avoid double counting."
        )
    if after_count:
        warnings.append(f"Ignored {after_count} capital flow(s) after closing NAV.")

    in_period_flows = [(ts, fl) for ts, fl in capital_flows_with_ts if start_ts < ts <= end_ts]
    unvalued = [fl for _, fl in in_period_flows if not _has_valid_base_valuation(fl, ledger)]
    if unvalued:
        warnings.append(
            "Performance metrics were withheld because at least one in-period external or in-kind "
            "capital flow lacks base-currency valuation."
        )
        summary = PerformanceSummary(
            twr_decimal=0.0,
            psr_benchmark_sr=psr_benchmark_sr,
            methodology=methodology,
            warnings=list(dict.fromkeys(warnings)),
        )
        return PerformanceCalculationResult(
            summary=summary,
            return_observations=(),
            econometrics=None,
            withheld=True,
        )

    observations: list[SubperiodReturnObservation] = []
    for (prev_ts, prev_pt), (curr_ts, curr_pt) in zip(nav_sorted, nav_sorted[1:]):
        interval_flows = [
            (fts, _signed_flow_amount_base(fl))
            for fts, fl in in_period_flows
            if prev_ts < fts <= curr_ts
        ]
        net_flow = math.fsum(f_amt for _, f_amt in interval_flows)
        open_val = float(prev_pt.nav_base)
        close_val = float(curr_pt.nav_base)

        if cash_flow_timing == "end_of_day":
            denom = open_val
            period_ret = (close_val - net_flow) / denom - 1.0 if denom > 0.0 else float("nan")
        elif cash_flow_timing == "start_of_day":
            denom = open_val + net_flow
            period_ret = close_val / denom - 1.0 if denom > 0.0 else float("nan")
        else:
            span_sec = max((curr_ts - prev_ts).total_seconds(), 1e-9)
            weighted_flow = math.fsum(
                ((curr_ts - fts).total_seconds() / span_sec) * f_amt
                for fts, f_amt in interval_flows
            )
            denom = open_val + weighted_flow
            period_ret = (close_val - open_val - net_flow) / denom if denom > 0.0 else float("nan")

        if denom <= 0.0 or not math.isfinite(period_ret) or period_ret <= -1.0:
            warnings.append(
                f"Performance metrics were withheld because the flow-adjusted sub-period return ending "
                f"{curr_pt.timestamp_utc} is non-positive or invalid."
            )
            summary = PerformanceSummary(
                twr_decimal=0.0,
                psr_benchmark_sr=psr_benchmark_sr,
                methodology=methodology,
                warnings=list(dict.fromkeys(warnings)),
            )
            return PerformanceCalculationResult(
                summary=summary,
                return_observations=(),
                econometrics=None,
                withheld=True,
            )

        observations.append(
            SubperiodReturnObservation(
                timestamp_utc=curr_pt.timestamp_utc,
                period_return=period_ret,
                net_external_flow_base=net_flow,
            )
        )

    returns = [obs.period_return for obs in observations]

    # Optional licensing-safe benchmark return series (rebased to 100.0; zero raw OHLCV).
    bench_series = None
    if benchmark_symbol and reference_provider is not None and reference_provider.is_available:
        date_keys = [pt.timestamp_utc[:10] for _, pt in nav_sorted]
        bench_series = reference_provider.get_derived_benchmark_series(
            benchmark_symbol,
            dates=date_keys,
        )

    # Build privacy-preserving indexed-100 wealth curve (never raw dollar NAV).
    wealth = 1.0
    peak = 1.0
    max_dd = 0.0
    first_nav_pt = nav_sorted[0][1]
    first_bench = (
        bench_series.indexed_values_by_date.get(first_nav_pt.timestamp_utc[:10], 100.0)
        if bench_series is not None
        else None
    )
    indexed_curve: list[IndexedCurvePoint] = [
        IndexedCurvePoint(
            timestamp_utc=first_nav_pt.timestamp_utc,
            index_value=100.0,
            drawdown_pct=0.0,
            benchmark_index_value=first_bench,
        )
    ]

    for obs in observations:
        wealth *= 1.0 + obs.period_return
        peak = max(peak, wealth)
        dd_dec = min(0.0, (wealth / peak) - 1.0)
        max_dd = min(max_dd, dd_dec)
        b_val = (
            bench_series.indexed_values_by_date.get(obs.timestamp_utc[:10])
            if bench_series is not None
            else None
        )
        indexed_curve.append(
            IndexedCurvePoint(
                timestamp_utc=obs.timestamp_utc,
                index_value=round(wealth * 100.0, 8),
                drawdown_pct=round(dd_dec * 100.0, 8),
                benchmark_index_value=b_val,
            )
        )

    twr_decimal = wealth - 1.0
    elapsed_days = (end_ts - start_ts).total_seconds() / 86400.0
    cagr_decimal: float | None = None
    if elapsed_days > 0.0 and wealth > 0.0:
        try:
            cagr_decimal = wealth ** (365.0 / elapsed_days) - 1.0
        except OverflowError:
            cagr_decimal = None
        if elapsed_days < 90.0:
            warnings.append("CAGR over a period shorter than 90 days is highly unstable.")

    gaps_days = [
        (curr_ts - prev_ts).total_seconds() / 86400.0
        for (prev_ts, _), (curr_ts, _) in zip(nav_sorted, nav_sorted[1:])
    ]
    if gaps_days and median(gaps_days) > 4.0:
        warnings.append(
            f"NAV observations have median spacing > 4 days; {periods_per_year}-period annualization may distort volatility."
        )

    ann_vol: float | None = None
    sharpe: float | None = None
    sortino: float | None = None
    if len(returns) >= 2:
        ann_vol = stdev(returns) * math.sqrt(periods_per_year)
        rf_period = (1.0 + annual_risk_free_rate) ** (1.0 / periods_per_year) - 1.0
        excess = [r - rf_period for r in returns]
        excess_std = stdev(excess)
        if excess_std > 0.0:
            sharpe = (mean(excess) / excess_std) * math.sqrt(periods_per_year)
        else:
            warnings.append("Sharpe ratio is undefined because excess-return volatility is zero.")

        downside_dev = math.sqrt(mean(min(val, 0.0) ** 2 for val in excess))
        if downside_dev > 0.0:
            sortino = (mean(excess) / downside_dev) * math.sqrt(periods_per_year)
        else:
            warnings.append("Sortino ratio is undefined because there are no downside excess returns.")
    else:
        warnings.append("Volatility, Sharpe, and Sortino require at least two return observations.")

    xirr_cfs: list[tuple[datetime, float]] = [(start_ts, -float(nav_sorted[0][1].nav_base))]
    for fts, fl in in_period_flows:
        xirr_cfs.append((fts, -_signed_flow_amount_base(fl)))
    xirr_cfs.append((end_ts, float(nav_sorted[-1][1].nav_base)))
    xirr_val, xirr_warnings = solve_xirr_act365(xirr_cfs, preferred_rate=cagr_decimal)
    warnings.extend(xirr_warnings)

    econ = evaluate_econometric_diagnostics(
        returns,
        periods_per_year=float(periods_per_year),
        annual_risk_free_rate=annual_risk_free_rate,
        psr_benchmark_sr_annualized=psr_benchmark_sr,
    )
    warnings.extend(econ.warnings)

    cap_bracket, cap_warn = _infer_capital_bracket(
        ledger,
        float(nav_sorted[-1][1].nav_base),
        reference_provider=reference_provider,
        end_date_str=nav_sorted[-1][1].timestamp_utc[:10],
    )
    if cap_warn:
        warnings.append(cap_warn)

    bench_sym_out = bench_series.benchmark_symbol if bench_series is not None else benchmark_symbol
    bench_twr_out = bench_series.twr_decimal if bench_series is not None else None
    alpha_out = (twr_decimal - bench_twr_out) if bench_twr_out is not None else None

    daily_cells = _build_daily_calendar_cells(
        ledger,
        observations,
        start_ts=start_ts,
        end_ts=end_ts,
    )
    bootstrap_summary = run_stationary_block_bootstrap(returns)

    summary = PerformanceSummary(
        twr_decimal=twr_decimal,
        cagr_decimal=cagr_decimal,
        xirr_decimal=xirr_val,
        annualized_volatility=ann_vol,
        smoothing_index_xi=econ.smoothing_index_xi,
        lag1_autocorrelation=econ.lag1_autocorrelation,
        unsmoothed_volatility=econ.unsmoothed_volatility,
        unsmoothed_sharpe_ratio=econ.unsmoothed_sharpe_ratio,
        sharpe_ratio=sharpe,
        sortino_ratio=sortino,
        probabilistic_sharpe_ratio=econ.probabilistic_sharpe_ratio,
        psr_glm_unsmoothed=econ.psr_glm_unsmoothed,
        min_track_record_length_periods=econ.min_track_record_length_periods,
        psr_sample_eligible=econ.psr_sample_eligible,
        observation_count=econ.observation_count,
        psr_benchmark_sr=psr_benchmark_sr,
        max_drawdown_decimal=max_dd,
        skewness=econ.skewness,
        excess_kurtosis=econ.excess_kurtosis,
        capital_bracket=cap_bracket,
        benchmark_symbol=bench_sym_out,
        benchmark_twr_decimal=bench_twr_out,
        alpha_decimal=alpha_out,
        indexed_curve=indexed_curve,
        methodology=methodology,
        warnings=list(dict.fromkeys(warnings)),
        daily_calendar_cells=daily_cells,
        bootstrap_summary=bootstrap_summary,
    )

    return PerformanceCalculationResult(
        summary=summary,
        return_observations=tuple(observations),
        econometrics=econ,
        withheld=False,
    )


def calculate_portfolio_performance(
    ledger: CanonicalPortfolioLedger,
    *,
    reference_provider: ReferenceDataProvider | None = None,
    benchmark_symbol: str | None = None,
    annual_risk_free_rate: float = 0.0,
    periods_per_year: int = 252,
    cash_flow_timing: str = "end_of_day",
    psr_benchmark_sr: float = 0.0,
) -> PerformanceSummary:
    """Compute privacy-preserving ``PerformanceSummary`` for a ``CanonicalPortfolioLedger``."""
    return calculate_portfolio_performance_detailed(
        ledger,
        reference_provider=reference_provider,
        benchmark_symbol=benchmark_symbol,
        annual_risk_free_rate=annual_risk_free_rate,
        periods_per_year=periods_per_year,
        cash_flow_timing=cash_flow_timing,
        psr_benchmark_sr=psr_benchmark_sr,
    ).summary


__all__ = [
    "CAPITAL_FLOW_KINDS_FOR_TWR",
    "PerformanceCalculationResult",
    "SubperiodReturnObservation",
    "calculate_portfolio_performance",
    "calculate_portfolio_performance_detailed",
    "solve_xirr_act365",
]
