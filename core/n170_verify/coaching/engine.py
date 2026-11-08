"""End-to-end Trader Coaching, Cost Drag, and Uncertainty-Aware Catalyst Engine."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from n170_verify.catalysts.eodhd_events import EodhdEconomicEvent, EodhdEventsClient, EodhdNewsEvent
from n170_verify.catalysts.event_context import (
    CatalystAvailabilityInterval,
    evaluate_portfolio_catalyst_context,
)
from n170_verify.catalysts.fred_alfred import (
    FredAlfredClient,
    GdeltArticleEvent,
    GdeltDocFallbackClient,
    MacroReleaseObservation,
)
from n170_verify.catalysts.sec_edgar import SecEdgarClient, SecEdgarFiling
from n170_verify.coaching.behaviour_metrics import (
    compute_behavioural_coaching_metrics,
    compute_quant_dna_profile,
    compute_session_expectancy_heatmap,
    extract_delayed_closed_trades,
    match_fifo_round_trips,
    sanitize_journal_tags,
)
from n170_verify.coaching.cost_and_drag import compute_cost_and_drag_breakdown
from n170_verify.coaching.counterfactual import simulate_counterfactual_twin
from n170_verify.coaching.llm_coach import (
    SmallLlmCoachClient,
    build_deterministic_coaching_narrative,
    contains_forbidden_claim,
)
from n170_verify.contracts import (
    AssetClass,
    CanonicalPortfolioLedger,
    RedactedClosedTrade,
    TraderCoachingAndContextReport,
)


@dataclass(slots=True)
class CoachingEngineOutput:
    """Combined ``coaching_and_context`` report and 7-day-delayed ``delayed_closed_trades`` leaf."""

    report: TraderCoachingAndContextReport
    delayed_closed_trades: list[RedactedClosedTrade] = field(default_factory=list)
    llm_safety_filter_triggered: bool = False
    llm_fallback_reason: str | None = None


def _compute_asset_class_mix_pct(ledger: CanonicalPortfolioLedger) -> dict[str, float]:
    totals: dict[str, float] = {}
    grand_total = 0.0
    for trade in ledger.trades:
        if trade.asset_class == AssetClass.CASH:
            continue
        notional = trade.notional_base
        if notional <= 0.0:
            continue
        key = trade.asset_class.value
        totals[key] = totals.get(key, 0.0) + notional
        grand_total += notional
    if grand_total <= 0.0:
        return {}
    return {k: round((v / grand_total) * 100.0, 2) for k, v in sorted(totals.items())}


class TraderCoachingEngine:
    """Institutional trader coaching, friction waterfall, and public catalyst regime orchestrator."""

    def __init__(
        self,
        *,
        llm_client: SmallLlmCoachClient | None = None,
        eodhd_client: EodhdEventsClient | None = None,
        sec_client: SecEdgarClient | None = None,
        fred_client: FredAlfredClient | None = None,
        gdelt_client: GdeltDocFallbackClient | None = None,
        macro_series_ids: Sequence[str] = (),
        min_trade_disclosure_delay_days: float = 7.0,
    ) -> None:
        self.llm_client = llm_client if llm_client is not None else SmallLlmCoachClient()
        self.eodhd_client = eodhd_client
        self.sec_client = sec_client
        self.fred_client = fred_client
        self.gdelt_client = gdelt_client
        self.macro_series_ids = tuple(macro_series_ids)
        self.min_trade_disclosure_delay_days = float(min_trade_disclosure_delay_days)

    def evaluate(
        self,
        ledger: CanonicalPortfolioLedger,
        *,
        as_of_utc: str | datetime | None = None,
        forex_midpoints: Mapping[str, object] | None = None,
        price_snapshots: Mapping[str, Any] | None = None,
        atr_14_series: Mapping[str, Any] | None = None,
        catalyst_intervals: Sequence[CatalystAvailabilityInterval] | None = None,
        sec_filings: Sequence[SecEdgarFiling] = (),
        eodhd_news: Sequence[EodhdNewsEvent] = (),
        gdelt_articles: Sequence[GdeltArticleEvent] = (),
        eodhd_macro_events: Sequence[EodhdEconomicEvent] = (),
        alfred_macro_releases: Sequence[MacroReleaseObservation] = (),
        enable_llm_narrative: bool = True,
        imported_journal_tags: Sequence[str] | None = None,
        max_drawdown_decimal: float | None = None,
    ) -> CoachingEngineOutput:
        """Compute ``TraderCoachingAndContextReport`` and 7-day-delayed ``RedactedClosedTrade`` list."""
        cost_drag = compute_cost_and_drag_breakdown(
            ledger,
            forex_midpoints=forex_midpoints,
        )
        closed_trips = match_fifo_round_trips(ledger)
        behaviour = compute_behavioural_coaching_metrics(
            ledger,
            price_snapshots=price_snapshots,
            atr_14_series=atr_14_series,
            cost_drag=cost_drag,
        )

        effective_as_of = as_of_utc if as_of_utc is not None else ledger.period_end_utc
        delayed_trades = extract_delayed_closed_trades(
            closed_trips,
            as_of_utc=effective_as_of,
            min_delay_days=self.min_trade_disclosure_delay_days,
        )

        catalyst_ctx = evaluate_portfolio_catalyst_context(
            ledger,
            intervals=catalyst_intervals,
            sec_filings=sec_filings,
            eodhd_news=eodhd_news,
            gdelt_articles=gdelt_articles,
            eodhd_macro_events=eodhd_macro_events,
            alfred_macro_releases=alfred_macro_releases,
            eodhd_client=self.eodhd_client,
            sec_client=self.sec_client,
            fred_client=self.fred_client,
            gdelt_client=self.gdelt_client,
            macro_series_ids=self.macro_series_ids,
            closed_round_trips=closed_trips,
            reference_now_utc=effective_as_of,
        )

        asset_mix_pct = _compute_asset_class_mix_pct(ledger)
        if enable_llm_narrative and self.llm_client is not None:
            narrative = self.llm_client.generate_coaching_narrative(
                cost_drag=cost_drag,
                behaviour=behaviour,
                catalyst_regime_win_rate=catalyst_ctx.catalyst_regime_win_rate,
                quiet_regime_win_rate=catalyst_ctx.quiet_regime_win_rate,
                event_window_share_pct=catalyst_ctx.event_window_share_pct,
                asset_class_shares_pct=asset_mix_pct,
            )
        else:
            narrative = build_deterministic_coaching_narrative(
                cost_drag=cost_drag,
                behaviour=behaviour,
                catalyst_regime_win_rate=catalyst_ctx.catalyst_regime_win_rate,
                quiet_regime_win_rate=catalyst_ctx.quiet_regime_win_rate,
                event_window_share_pct=catalyst_ctx.event_window_share_pct,
            )

        # Final belt-and-suspenders claim-safety check across all narrative fields.
        if contains_forbidden_claim(narrative.style_summary) or any(
            contains_forbidden_claim(t) for t in narrative.coaching_takeaways
        ):
            det = build_deterministic_coaching_narrative(
                cost_drag=cost_drag,
                behaviour=behaviour,
                catalyst_regime_win_rate=catalyst_ctx.catalyst_regime_win_rate,
                quiet_regime_win_rate=catalyst_ctx.quiet_regime_win_rate,
                event_window_share_pct=catalyst_ctx.event_window_share_pct,
            )
            det.safety_filter_triggered = True
            det.fallback_reason = "engine_post_check_rejected"
            narrative = det

        session_heatmap = compute_session_expectancy_heatmap(
            ledger,
            closed_round_trips=closed_trips,
        )
        counterfactual_twin = simulate_counterfactual_twin(
            ledger,
            cost_drag=cost_drag,
            behaviour=behaviour,
            closed_round_trips=closed_trips,
            forex_midpoints=forex_midpoints,
            atr_14_series=atr_14_series,
        )
        quant_dna = compute_quant_dna_profile(
            ledger,
            behaviour=behaviour,
            cost_drag=cost_drag,
            catalyst_regime_win_rate=catalyst_ctx.catalyst_regime_win_rate,
            quiet_regime_win_rate=catalyst_ctx.quiet_regime_win_rate,
            event_window_share_pct=catalyst_ctx.event_window_share_pct,
            max_drawdown_decimal=max_drawdown_decimal,
            closed_round_trips=closed_trips,
        )
        clean_journal_tags = sanitize_journal_tags(imported_journal_tags)

        report = TraderCoachingAndContextReport(
            cost_drag=cost_drag,
            behaviour=behaviour,
            catalyst_regime_win_rate=catalyst_ctx.catalyst_regime_win_rate,
            quiet_regime_win_rate=catalyst_ctx.quiet_regime_win_rate,
            event_window_share_pct=catalyst_ctx.event_window_share_pct,
            event_observations=catalyst_ctx.event_observations,
            llm_narrative_used=narrative.llm_narrative_used,
            llm_model_id=narrative.llm_model_id,
            style_summary=narrative.style_summary,
            coaching_takeaways=narrative.coaching_takeaways,
            uncertainty_disclosures=catalyst_ctx.uncertainty_disclosures,
            session_heatmap=session_heatmap,
            counterfactual_twin=counterfactual_twin,
            quant_dna=quant_dna,
            imported_journal_tags=clean_journal_tags,
        )

        return CoachingEngineOutput(
            report=report,
            delayed_closed_trades=delayed_trades,
            llm_safety_filter_triggered=narrative.safety_filter_triggered,
            llm_fallback_reason=narrative.fallback_reason,
        )


def build_trader_coaching_report(
    ledger: CanonicalPortfolioLedger,
    *,
    forex_midpoints: Mapping[str, object] | None = None,
    price_snapshots: Mapping[str, Any] | None = None,
    atr_14_series: Mapping[str, Any] | None = None,
    catalyst_intervals: Sequence[CatalystAvailabilityInterval] | None = None,
    sec_filings: Sequence[SecEdgarFiling] = (),
    eodhd_news: Sequence[EodhdNewsEvent] = (),
    gdelt_articles: Sequence[GdeltArticleEvent] = (),
    eodhd_macro_events: Sequence[EodhdEconomicEvent] = (),
    alfred_macro_releases: Sequence[MacroReleaseObservation] = (),
    llm_client: SmallLlmCoachClient | None = None,
    enable_llm_narrative: bool = True,
    imported_journal_tags: Sequence[str] | None = None,
    max_drawdown_decimal: float | None = None,
) -> TraderCoachingAndContextReport:
    """Convenience entrypoint returning a validated ``TraderCoachingAndContextReport``."""
    engine = TraderCoachingEngine(llm_client=llm_client)
    output = engine.evaluate(
        ledger,
        forex_midpoints=forex_midpoints,
        price_snapshots=price_snapshots,
        atr_14_series=atr_14_series,
        catalyst_intervals=catalyst_intervals,
        sec_filings=sec_filings,
        eodhd_news=eodhd_news,
        gdelt_articles=gdelt_articles,
        eodhd_macro_events=eodhd_macro_events,
        alfred_macro_releases=alfred_macro_releases,
        enable_llm_narrative=enable_llm_narrative,
        imported_journal_tags=imported_journal_tags,
        max_drawdown_decimal=max_drawdown_decimal,
    )
    return output.report


__all__ = [
    "CoachingEngineOutput",
    "TraderCoachingEngine",
    "build_trader_coaching_report",
]
