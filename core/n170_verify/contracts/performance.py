"""Performance contracts, capital brackets, GLM unsmoothing, and PSR (without single-account multiple-testing Sharpe deflation)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date as date_type
from enum import Enum
import math

from n170_verify.contracts.assurance import ContractModelMixin, parse_utc_timestamp


class CapitalBracket(str, Enum):
    """Coarse USD capital tier preventing exact dollar NAV disclosure."""

    UNDER_1K = "under_1k"
    BRACKET_1K_10K = "bracket_1k_10k"
    BRACKET_10K_100K = "bracket_10k_100k"
    BRACKET_100K_1M = "bracket_100k_1m"
    OVER_1M = "over_1m"


def classify_capital_bracket(nav_usd: float) -> CapitalBracket:
    """Map a non-negative USD net asset value into a coarse ``CapitalBracket``."""
    if isinstance(nav_usd, bool) or not isinstance(nav_usd, (int, float)):
        raise ValueError("nav_usd must be a finite non-negative number")
    val = float(nav_usd)
    if not math.isfinite(val) or val < 0.0:
        raise ValueError("nav_usd must be finite and >= 0")
    if val < 1_000.0:
        return CapitalBracket.UNDER_1K
    if val < 10_000.0:
        return CapitalBracket.BRACKET_1K_10K
    if val < 100_000.0:
        return CapitalBracket.BRACKET_10K_100K
    if val < 1_000_000.0:
        return CapitalBracket.BRACKET_100K_1M
    return CapitalBracket.OVER_1M


@dataclass(slots=True)
class IndexedCurvePoint(ContractModelMixin):
    """Privacy-preserving performance curve point rebased to 100.0 (never dollar NAV)."""

    timestamp_utc: str
    index_value: float
    drawdown_pct: float
    benchmark_index_value: float | None = None

    def _validate(self) -> None:
        parse_utc_timestamp(self.timestamp_utc, field_name="IndexedCurvePoint.timestamp_utc")
        if self.index_value <= 0.0:
            raise ValueError("IndexedCurvePoint.index_value must be > 0")
        if self.drawdown_pct > 1e-9:
            raise ValueError("IndexedCurvePoint.drawdown_pct must be <= 0.0")
        if self.drawdown_pct > 0.0:
            object.__setattr__(self, "drawdown_pct", 0.0)
        if self.benchmark_index_value is not None and self.benchmark_index_value <= 0.0:
            raise ValueError("IndexedCurvePoint.benchmark_index_value must be > 0")


@dataclass(slots=True)
class DailyCalendarCell(ContractModelMixin):
    """Privacy-preserving daily calendar heatmap cell (percentage return and trade count only)."""

    date: str
    return_pct: float
    trade_count: int

    def _validate(self) -> None:
        cleaned_date = self.date.strip()
        if not cleaned_date:
            raise ValueError("DailyCalendarCell.date must not be empty")
        try:
            date_type.fromisoformat(cleaned_date)
        except ValueError as exc:
            raise ValueError(
                f"DailyCalendarCell.date must be a valid ISO-8601 YYYY-MM-DD date: {self.date!r}"
            ) from exc
        if len(cleaned_date) != 10:
            raise ValueError(
                f"DailyCalendarCell.date must use YYYY-MM-DD format: {self.date!r}"
            )
        object.__setattr__(self, "date", cleaned_date)
        if not math.isfinite(self.return_pct):
            raise ValueError("DailyCalendarCell.return_pct must be finite")
        if self.trade_count < 0:
            raise ValueError("DailyCalendarCell.trade_count must be >= 0")


@dataclass(slots=True)
class BootstrapConePoint(ContractModelMixin):
    """Quantile envelope point at forward horizon ``step`` for stationary block bootstrap."""

    step: int
    p05: float
    p25: float
    p50: float
    p75: float
    p95: float

    def _validate(self) -> None:
        if self.step < 0:
            raise ValueError("BootstrapConePoint.step must be >= 0")
        quantiles = (self.p05, self.p25, self.p50, self.p75, self.p95)
        if any(not math.isfinite(q) for q in quantiles):
            raise ValueError("BootstrapConePoint quantiles must be finite")
        for lower, upper in zip(quantiles, quantiles[1:]):
            if lower > upper + 1e-9:
                raise ValueError(
                    "BootstrapConePoint quantiles must be non-decreasing (p05 <= p25 <= p50 <= p75 <= p95)"
                )


@dataclass(slots=True)
class BootstrapRiskSummary(ContractModelMixin):
    """Forward stationary block-bootstrap risk envelope and drawdown probabilities."""

    horizon_periods: int
    num_simulations: int
    block_length: int
    prob_drawdown_10pct: float
    prob_drawdown_20pct: float
    prob_positive_terminal: float
    cone: list[BootstrapConePoint] = field(default_factory=list)

    def _validate(self) -> None:
        if self.horizon_periods < 1:
            raise ValueError("BootstrapRiskSummary.horizon_periods must be >= 1")
        if self.num_simulations < 1:
            raise ValueError("BootstrapRiskSummary.num_simulations must be >= 1")
        if self.block_length < 1:
            raise ValueError("BootstrapRiskSummary.block_length must be >= 1")
        for attr_name in (
            "prob_drawdown_10pct",
            "prob_drawdown_20pct",
            "prob_positive_terminal",
        ):
            prob_val = getattr(self, attr_name)
            if not (0.0 <= prob_val <= 1.0):
                raise ValueError(f"BootstrapRiskSummary.{attr_name} must be in [0.0, 1.0]")


@dataclass(slots=True)
class ClaimPlausibilityAnalysis(ContractModelMixin):
    """Zero-login public screenshot Sharpe claim plausibility analysis (PSR & MinTRL)."""

    claimed_sharpe: float
    annualization_factor: int
    observed_periods: int
    skewness: float
    excess_kurtosis: float
    benchmark_sharpe: float
    implied_psr: float
    required_min_trl_periods_95pct: float | None
    sufficiency_tier: str
    bell_curve_points: list[dict[str, float]]
    plain_english_summary: str

    def _validate(self) -> None:
        if self.annualization_factor < 1:
            raise ValueError("ClaimPlausibilityAnalysis.annualization_factor must be >= 1")
        if self.observed_periods < 1:
            raise ValueError("ClaimPlausibilityAnalysis.observed_periods must be >= 1")
        if not (0.0 <= self.implied_psr <= 1.0):
            raise ValueError("ClaimPlausibilityAnalysis.implied_psr must be in [0.0, 1.0]")
        if (
            self.required_min_trl_periods_95pct is not None
            and self.required_min_trl_periods_95pct < 0.0
        ):
            raise ValueError(
                "ClaimPlausibilityAnalysis.required_min_trl_periods_95pct must be >= 0.0"
            )
        if not self.sufficiency_tier.strip():
            raise ValueError("ClaimPlausibilityAnalysis.sufficiency_tier must not be empty")
        if not self.plain_english_summary.strip():
            raise ValueError("ClaimPlausibilityAnalysis.plain_english_summary must not be empty")


@dataclass(slots=True)
class PerformanceSummary(ContractModelMixin):
    """Aggregate portfolio performance metrics with GLM unsmoothing and PSR.

    Field conventions:
    - ``twr_decimal`` / ``twr_pct``: Time-weighted cumulative return as decimal (0.15 = +15.0%) and percentage (15.0).
    - ``cagr_decimal`` / ``cagr_pct``: Compound annual growth rate as decimal and percentage.
    - ``xirr_decimal``: Money-weighted ACT/365 internal rate of return as decimal.
    - ``max_drawdown_decimal`` / ``max_drawdown_pct``: Peak-to-trough drawdown (non-positive, e.g. -0.12 / -12.0).
    - ``probabilistic_sharpe_ratio``: Bailey & Lopez de Prado (2012) PSR against ``psr_benchmark_sr`` (gated on ``observation_count >= 30``).
    - ``psr_glm_unsmoothed``: PSR recomputed with Getmansky-Lo-Makarov (2004) unsmoothed volatility when ``smoothing_index_xi < 0.80`` or ``lag1_autocorrelation > 0.20``.
    - Single-account multiple-testing Deflated Sharpe adjustment is intentionally omitted because multiple-testing trial count N is unobservable for a single account.
    """

    twr_decimal: float
    twr_pct: float | None = None
    cagr_decimal: float | None = None
    cagr_pct: float | None = None
    xirr_decimal: float | None = None
    annualized_volatility: float | None = None
    smoothing_index_xi: float | None = None
    lag1_autocorrelation: float | None = None
    unsmoothed_volatility: float | None = None
    unsmoothed_sharpe_ratio: float | None = None
    sharpe_ratio: float | None = None
    sortino_ratio: float | None = None
    probabilistic_sharpe_ratio: float | None = None
    psr_glm_unsmoothed: float | None = None
    min_track_record_length_periods: float | None = None
    psr_sample_eligible: bool = False
    observation_count: int = 0
    psr_benchmark_sr: float = 0.0
    non_iid_caveat: str = (
        "PSR accounts for skewness and excess kurtosis under stationary returns; "
        "GLM unsmoothing adjusts for first-order serial correlation, and unobserved "
        "multi-account selection trials cannot be ruled out without subaccount enumeration."
    )
    max_drawdown_decimal: float = 0.0
    max_drawdown_pct: float | None = None
    skewness: float | None = None
    excess_kurtosis: float | None = None
    capital_bracket: CapitalBracket | None = None
    benchmark_symbol: str | None = None
    benchmark_twr_decimal: float | None = None
    alpha_decimal: float | None = None
    indexed_curve: list[IndexedCurvePoint] = field(default_factory=list)
    methodology: str = "daily_flow_adjusted_twr_v3"
    warnings: list[str] = field(default_factory=list)
    daily_calendar_cells: list[DailyCalendarCell] = field(default_factory=list)
    bootstrap_summary: BootstrapRiskSummary | None = None

    def _validate(self) -> None:
        if self.twr_pct is None:
            val = round(self.twr_decimal * 100.0, 8)
            object.__setattr__(self, "twr_pct", 0.0 if val == 0.0 else val)
        if self.cagr_decimal is not None and self.cagr_pct is None:
            cval = round(self.cagr_decimal * 100.0, 8)
            object.__setattr__(self, "cagr_pct", 0.0 if cval == 0.0 else cval)
        if self.max_drawdown_decimal > 1e-9:
            raise ValueError("PerformanceSummary.max_drawdown_decimal must be <= 0.0")
        if self.max_drawdown_decimal > 0.0:
            object.__setattr__(self, "max_drawdown_decimal", 0.0)
        if self.max_drawdown_pct is None:
            dd_pct = round(self.max_drawdown_decimal * 100.0, 8)
            object.__setattr__(self, "max_drawdown_pct", 0.0 if dd_pct == 0.0 else dd_pct)
        elif self.max_drawdown_pct > 1e-7:
            raise ValueError("PerformanceSummary.max_drawdown_pct must be <= 0.0")

        if self.observation_count < 0:
            raise ValueError("PerformanceSummary.observation_count must be >= 0")
        if self.psr_sample_eligible and self.observation_count < 30:
            raise ValueError("psr_sample_eligible cannot be True when observation_count < 30")
        if self.probabilistic_sharpe_ratio is not None and not (
            0.0 <= self.probabilistic_sharpe_ratio <= 1.0
        ):
            raise ValueError("probabilistic_sharpe_ratio must be in [0.0, 1.0]")
        if self.psr_glm_unsmoothed is not None and not (0.0 <= self.psr_glm_unsmoothed <= 1.0):
            raise ValueError("psr_glm_unsmoothed must be in [0.0, 1.0]")

        if self.indexed_curve:
            first_idx = self.indexed_curve[0].index_value
            if abs(first_idx - 100.0) > 1e-5:
                raise ValueError(
                    f"indexed_curve[0].index_value must start at 100.0 (got {first_idx!r}); "
                    "raw dollar NAV curves are prohibited"
                )


__all__ = [
    "BootstrapConePoint",
    "BootstrapRiskSummary",
    "CapitalBracket",
    "ClaimPlausibilityAnalysis",
    "DailyCalendarCell",
    "IndexedCurvePoint",
    "PerformanceSummary",
    "classify_capital_bracket",
]
