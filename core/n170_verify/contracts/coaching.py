"""Trader coaching, friction drag, behavioural analytics, and uncertainty-aware catalyst contracts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
import math
from typing import Any

from n170_verify.contracts.assurance import ContractModelMixin, parse_utc_timestamp
from n170_verify.contracts.ledger import AssetClass


DEFAULT_COUNTERFACTUAL_DISCLAIMER = (
    "HYPOTHETICAL COACHING SIMULATION — Separate from verified realized performance; "
    "does not represent actual trading results (SEC/FINRA/GIPS)."
)


class CatalystAlignmentClass(str, Enum):
    """Uncertainty-aware alignment between execution timestamp and public catalyst window.

    Never asserts MNPI, insider trading, or backdating.
    """

    PRIOR_TO_EARLIEST_RECORDED_CATALYST = "prior_to_earliest_recorded_catalyst"
    AMBIGUOUS_PUBLIC_WINDOW = "ambiguous_public_window"
    POST_CONFIRMED_CATALYST = "post_confirmed_catalyst"
    QUIET_NON_CATALYST_REGIME = "quiet_non_catalyst_regime"


@dataclass(slots=True)
class CostAndDragBreakdown(ContractModelMixin):
    """Portfolio friction and cost drag decomposition in basis points of average NAV."""

    commission_and_fee_drag_bps: float
    margin_and_funding_drag_bps: float
    fx_conversion_drag_bps: float
    withholding_tax_drag_bps: float
    total_friction_drag_bps: float
    annualized_total_drag_bps: float = 0.0


@dataclass(slots=True)
class BehaviouralCoachingMetrics(ContractModelMixin):
    """Sample-size-gated behavioural coaching analytics."""

    sample_eligible: bool
    min_trades_gate: int
    observed_trades: int
    observed_days: int
    median_holding_hours: float | None = None
    holding_horizon_label: str = "insufficient_sample"
    win_rate: float | None = None
    profit_factor: float | None = None
    winner_vs_loser_hold_ratio: float | None = None
    odean_pgr_plr_spread: float | None = None
    post_drawdown_sizing_discipline_atr: float | None = None
    atr_normalized: bool = False
    return_concentration_top5_pct: float | None = None
    actionable_improvements: list[str] = field(default_factory=list)

    def _validate(self) -> None:
        if self.min_trades_gate < 1:
            raise ValueError("min_trades_gate must be >= 1")
        if self.observed_trades < 0:
            raise ValueError("observed_trades must be >= 0")
        if self.observed_days < 0:
            raise ValueError("observed_days must be >= 0")
        if self.sample_eligible and self.observed_trades < self.min_trades_gate:
            raise ValueError("sample_eligible cannot be True when observed_trades < min_trades_gate")
        if self.win_rate is not None and not (0.0 <= self.win_rate <= 1.0):
            raise ValueError("win_rate must be in [0.0, 1.0]")


@dataclass(slots=True)
class EventWindowObservation(ContractModelMixin):
    """Neutral public catalyst window observation around a trade execution."""

    symbol: str
    trade_timestamp_utc: str
    earliest_public_utc: str | None
    confirmed_public_utc: str | None
    event_sources: list[str]
    headline_or_event: str
    alignment_class: CatalystAlignmentClass
    timestamp_uncertainty_note: str

    def _validate(self) -> None:
        if not self.symbol.strip():
            raise ValueError("EventWindowObservation.symbol must not be empty")
        parse_utc_timestamp(
            self.trade_timestamp_utc, field_name="EventWindowObservation.trade_timestamp_utc"
        )
        if self.earliest_public_utc is not None:
            parse_utc_timestamp(
                self.earliest_public_utc, field_name="EventWindowObservation.earliest_public_utc"
            )
        if self.confirmed_public_utc is not None:
            parse_utc_timestamp(
                self.confirmed_public_utc, field_name="EventWindowObservation.confirmed_public_utc"
            )
        if not self.timestamp_uncertainty_note.strip():
            raise ValueError("EventWindowObservation.timestamp_uncertainty_note must not be empty")


@dataclass(slots=True)
class SessionExpectancyCell(ContractModelMixin):
    """Weekday x UTC-hour session expectancy cell (win rate and bps expectancy)."""

    weekday: int
    hour_utc: int
    trade_count: int
    win_rate: float
    expectancy_bps: float

    def _validate(self) -> None:
        if not (0 <= self.weekday <= 6):
            raise ValueError("SessionExpectancyCell.weekday must be in [0, 6]")
        if not (0 <= self.hour_utc <= 23):
            raise ValueError("SessionExpectancyCell.hour_utc must be in [0, 23]")
        if self.trade_count < 0:
            raise ValueError("SessionExpectancyCell.trade_count must be >= 0")
        if not (0.0 <= self.win_rate <= 1.0):
            raise ValueError("SessionExpectancyCell.win_rate must be in [0.0, 1.0]")
        if not math.isfinite(self.expectancy_bps):
            raise ValueError("SessionExpectancyCell.expectancy_bps must be finite")


@dataclass(slots=True, init=False)
class CounterfactualTwinReport(ContractModelMixin):
    """Hypothetical counterfactual behavioural simulation isolated from verified realized returns."""

    is_hypothetical_simulation: bool = True
    compliance_disclaimer: str = DEFAULT_COUNTERFACTUAL_DISCLAIMER
    actual_ending_index: float = field()
    zero_friction_ending_index: float = field()
    disciplined_post_dd_sizing_ending_index: float = field()
    capped_tail_loss_ending_index: float = field()
    curve_points: list[dict[str, Any]] = field(default_factory=list)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        all_names = (
            "is_hypothetical_simulation",
            "compliance_disclaimer",
            "actual_ending_index",
            "zero_friction_ending_index",
            "disciplined_post_dd_sizing_ending_index",
            "capped_tail_loss_ending_index",
            "curve_points",
        )
        valid_set = set(all_names)
        for key in kwargs:
            if key not in valid_set:
                raise TypeError(
                    f"CounterfactualTwinReport.__init__() got an unexpected keyword argument {key!r}"
                )

        if args and (isinstance(args[0], bool) or len(args) == 7):
            pos_order = all_names
        else:
            pos_order = (
                "compliance_disclaimer",
                "actual_ending_index",
                "zero_friction_ending_index",
                "disciplined_post_dd_sizing_ending_index",
                "capped_tail_loss_ending_index",
                "curve_points",
                "is_hypothetical_simulation",
            )

        if len(args) > len(pos_order):
            raise TypeError(
                f"CounterfactualTwinReport.__init__() takes at most {len(pos_order)} positional "
                f"arguments but {len(args)} were given"
            )

        bound: dict[str, Any] = {}
        for name, val in zip(pos_order, args):
            bound[name] = val
        for name, val in kwargs.items():
            if name in bound:
                raise TypeError(
                    f"CounterfactualTwinReport.__init__() got multiple values for argument {name!r}"
                )
            bound[name] = val

        required = (
            "actual_ending_index",
            "zero_friction_ending_index",
            "disciplined_post_dd_sizing_ending_index",
            "capped_tail_loss_ending_index",
        )
        missing = [name for name in required if name not in bound]
        if missing:
            missing_str = ", ".join(repr(m) for m in missing)
            raise TypeError(
                f"CounterfactualTwinReport.__init__() missing {len(missing)} required argument(s): {missing_str}"
            )

        object.__setattr__(
            self,
            "is_hypothetical_simulation",
            bound.get("is_hypothetical_simulation", True),
        )
        object.__setattr__(
            self,
            "compliance_disclaimer",
            bound.get("compliance_disclaimer", DEFAULT_COUNTERFACTUAL_DISCLAIMER),
        )
        object.__setattr__(self, "actual_ending_index", bound["actual_ending_index"])
        object.__setattr__(self, "zero_friction_ending_index", bound["zero_friction_ending_index"])
        object.__setattr__(
            self,
            "disciplined_post_dd_sizing_ending_index",
            bound["disciplined_post_dd_sizing_ending_index"],
        )
        object.__setattr__(
            self,
            "capped_tail_loss_ending_index",
            bound["capped_tail_loss_ending_index"],
        )
        raw_pts = bound["curve_points"] if "curve_points" in bound else []
        copied_pts = [dict(pt) if isinstance(pt, Mapping) else pt for pt in raw_pts]
        object.__setattr__(
            self,
            "curve_points",
            copied_pts,
        )
        self.__post_init__()

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError(
            f"CounterfactualTwinReport is immutable; cannot reassign {name!r}"
        )

    def __delattr__(self, name: str) -> None:
        raise AttributeError(
            f"CounterfactualTwinReport is immutable; cannot delete {name!r}"
        )

    def _validate(self) -> None:
        if self.is_hypothetical_simulation is not True:
            raise ValueError(
                "CounterfactualTwinReport.is_hypothetical_simulation must always be True"
            )
        if not self.compliance_disclaimer.strip():
            raise ValueError("CounterfactualTwinReport.compliance_disclaimer must not be empty")


@dataclass(slots=True)
class QuantDnaProfile(ContractModelMixin):
    """Six-axis behavioural & execution quality profile for radar visualization."""

    archetype_label: str
    consistency_score: float
    drawdown_resilience_score: float
    cost_efficiency_score: float
    sizing_discipline_score: float
    exit_symmetry_score: float
    catalyst_alignment_score: float

    def _validate(self) -> None:
        if not self.archetype_label.strip():
            raise ValueError("QuantDnaProfile.archetype_label must not be empty")
        for score_field in (
            "consistency_score",
            "drawdown_resilience_score",
            "cost_efficiency_score",
            "sizing_discipline_score",
            "exit_symmetry_score",
            "catalyst_alignment_score",
        ):
            val = getattr(self, score_field)
            if not (0.0 <= val <= 100.0):
                raise ValueError(f"QuantDnaProfile.{score_field} must be in [0.0, 100.0]")


@dataclass(slots=True)
class TraderCoachingAndContextReport(ContractModelMixin):
    """Complete trader coaching, cost drag, and catalyst regime context report."""

    cost_drag: CostAndDragBreakdown
    behaviour: BehaviouralCoachingMetrics
    catalyst_regime_win_rate: float | None = None
    quiet_regime_win_rate: float | None = None
    event_window_share_pct: float = 0.0
    event_observations: list[EventWindowObservation] = field(default_factory=list)
    llm_narrative_used: bool = False
    llm_model_id: str | None = None
    style_summary: str = ""
    coaching_takeaways: list[str] = field(default_factory=list)
    uncertainty_disclosures: list[str] = field(default_factory=list)
    session_heatmap: list[SessionExpectancyCell] = field(default_factory=list)
    counterfactual_twin: CounterfactualTwinReport | None = None
    quant_dna: QuantDnaProfile | None = None
    imported_journal_tags: list[str] = field(default_factory=list)

    def _validate(self) -> None:
        if not (0.0 <= self.event_window_share_pct <= 100.0):
            raise ValueError("event_window_share_pct must be in [0.0, 100.0]")
        if self.catalyst_regime_win_rate is not None and not (
            0.0 <= self.catalyst_regime_win_rate <= 1.0
        ):
            raise ValueError("catalyst_regime_win_rate must be in [0.0, 1.0]")
        if self.quiet_regime_win_rate is not None and not (
            0.0 <= self.quiet_regime_win_rate <= 1.0
        ):
            raise ValueError("quiet_regime_win_rate must be in [0.0, 1.0]")


@dataclass(slots=True)
class RedactedClosedTrade(ContractModelMixin):
    """Delayed closed round-trip trade leaf item with zero dollar quantities or notionals."""

    symbol: str
    asset_class: AssetClass
    side: str
    entry_timestamp_utc: str
    exit_timestamp_utc: str
    return_pct: float
    holding_hours: float

    def _validate(self) -> None:
        if not self.symbol.strip():
            raise ValueError("RedactedClosedTrade.symbol must not be empty")
        cleaned_side = self.side.strip().lower()
        if cleaned_side not in {"long", "short", "buy", "sell"}:
            raise ValueError("RedactedClosedTrade.side must be 'long', 'short', 'buy', or 'sell'")
        object.__setattr__(self, "side", cleaned_side)
        entry_dt = parse_utc_timestamp(
            self.entry_timestamp_utc, field_name="RedactedClosedTrade.entry_timestamp_utc"
        )
        exit_dt = parse_utc_timestamp(
            self.exit_timestamp_utc, field_name="RedactedClosedTrade.exit_timestamp_utc"
        )
        if exit_dt < entry_dt:
            raise ValueError("RedactedClosedTrade.exit_timestamp_utc must be >= entry_timestamp_utc")
        if self.holding_hours < 0.0:
            raise ValueError("RedactedClosedTrade.holding_hours must be >= 0")


__all__ = [
    "BehaviouralCoachingMetrics",
    "CatalystAlignmentClass",
    "CostAndDragBreakdown",
    "CounterfactualTwinReport",
    "DEFAULT_COUNTERFACTUAL_DISCLAIMER",
    "EventWindowObservation",
    "QuantDnaProfile",
    "RedactedClosedTrade",
    "SessionExpectancyCell",
    "TraderCoachingAndContextReport",
]
