"""Uncertainty-aware catalyst availability intervals I_e = [t_earliest, t_confirmed] and regime metrics."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from zoneinfo import ZoneInfo

from n170_verify.catalysts.eodhd_events import EodhdEconomicEvent, EodhdEventsClient, EodhdNewsEvent
from n170_verify.catalysts.fred_alfred import (
    FredAlfredClient,
    GdeltArticleEvent,
    GdeltDocFallbackClient,
    MacroReleaseObservation,
)
from n170_verify.catalysts.sec_edgar import SecEdgarClient, SecEdgarFiling
from n170_verify.contracts import (
    AssetClass,
    CanonicalPortfolioLedger,
    CatalystAlignmentClass,
    EventWindowObservation,
    format_utc_timestamp,
    parse_utc_timestamp,
)

if TYPE_CHECKING:
    from n170_verify.coaching.behaviour_metrics import ClosedRoundTrip


EASTERN_TZ = ZoneInfo("America/New_York")
MACRO_SYMBOL_WILDCARD: str = "*"
DEFAULT_PRESS_WIRE_PRE_BUSINESS_DAYS: int = 4
DEFAULT_PRESS_WIRE_POST_HOURS: float = 2.0
DEFAULT_STANDALONE_WIRE_LAG_SECONDS: int = 60
DEFAULT_PRE_EVENT_WINDOW_HOURS: float = 24.0
DEFAULT_POST_EVENT_WINDOW_HOURS: float = 24.0


def _canonical_symbol(symbol: str, underlying_symbol: str | None = None) -> str:
    if underlying_symbol and underlying_symbol.strip():
        return underlying_symbol.strip().upper().split(".")[0]
    return symbol.strip().upper().split(".")[0]


def subtract_business_days(anchor_utc: datetime, business_days: int) -> datetime:
    """Subtract ``business_days`` (Mon-Fri in ``America/New_York``) from ``anchor_utc``."""
    if business_days < 0:
        raise ValueError("business_days must be >= 0")
    et_cur = anchor_utc.astimezone(EASTERN_TZ)
    remaining = business_days
    while remaining > 0:
        et_cur -= timedelta(days=1)
        if et_cur.weekday() < 5:  # Monday=0 .. Friday=4
            remaining -= 1
    return et_cur.astimezone(timezone.utc)


@dataclass(slots=True)
class CatalystAvailabilityInterval:
    """Fused uncertainty-aware public availability interval I_e = [earliest_public_utc, confirmed_public_utc]."""

    symbol: str
    earliest_public_utc: str
    confirmed_public_utc: str
    event_sources: list[str]
    headline_or_event: str
    timestamp_uncertainty_note: str
    is_macro: bool = False


@dataclass(slots=True)
class CatalystContextSummary:
    """Portfolio-level catalyst window alignment summary and regime win-rate split."""

    event_observations: list[EventWindowObservation] = field(default_factory=list)
    catalyst_regime_win_rate: float | None = None
    quiet_regime_win_rate: float | None = None
    event_window_share_pct: float = 0.0
    uncertainty_disclosures: list[str] = field(default_factory=list)


def build_catalyst_intervals(
    *,
    sec_filings: Sequence[SecEdgarFiling] = (),
    eodhd_news: Sequence[EodhdNewsEvent] = (),
    gdelt_articles: Sequence[GdeltArticleEvent] = (),
    eodhd_macro_events: Sequence[EodhdEconomicEvent] = (),
    alfred_macro_releases: Sequence[MacroReleaseObservation] = (),
    press_wire_pre_filing_business_days: int = DEFAULT_PRESS_WIRE_PRE_BUSINESS_DAYS,
    press_wire_post_filing_hours: float = DEFAULT_PRESS_WIRE_POST_HOURS,
    standalone_wire_lag_seconds: int = DEFAULT_STANDALONE_WIRE_LAG_SECONDS,
) -> list[CatalystAvailabilityInterval]:
    """Fuse issuer press wires, SEC EDGAR filings (+180s lag), and macro vintages into intervals I_e."""
    # Index all issuer news/wires by canonical symbol.
    # Each entry: (published_dt, source_label, title, is_press_wire, consumed_flag_list)
    news_by_symbol: dict[str, list[list[object]]] = {}
    for ev in eodhd_news:
        sym = ev.symbol.strip().upper().split(".")[0]
        dt = parse_utc_timestamp(ev.published_utc)
        src = ev.source_wire if ev.is_press_wire else "eodhd_news"
        news_by_symbol.setdefault(sym, []).append([dt, src, ev.title, ev.is_press_wire, False])

    for art in gdelt_articles:
        sym = art.symbol.strip().upper().split(".")[0]
        dt = parse_utc_timestamp(art.published_utc)
        src = "gdelt_press_wire" if art.is_press_wire else "gdelt_doc_v2"
        news_by_symbol.setdefault(sym, []).append([dt, src, art.title, art.is_press_wire, False])

    intervals: list[CatalystAvailabilityInterval] = []
    wire_lag = timedelta(seconds=max(0, standalone_wire_lag_seconds))

    for filing in sorted(sec_filings, key=lambda f: f.acceptance_timestamp_utc):
        sym = filing.symbol.strip().upper().split(".")[0]
        t_accept = parse_utc_timestamp(filing.acceptance_timestamp_utc)
        t_edgar_conf = parse_utc_timestamp(filing.confirmed_public_utc)

        search_start = subtract_business_days(t_accept, press_wire_pre_filing_business_days)
        search_end = t_accept + timedelta(hours=max(0.0, press_wire_post_filing_hours))

        candidates = news_by_symbol.get(sym, [])
        matched_wires: list[tuple[datetime, str, str]] = []
        for row in candidates:
            w_dt = row[0]
            assert isinstance(w_dt, datetime)
            if search_start <= w_dt <= search_end and not bool(row[4]):
                row[4] = True
                matched_wires.append((w_dt, str(row[1]), str(row[2])))

        earliest_dt = min([t_accept, *(w[0] for w in matched_wires)])
        confirmed_dt = max([t_edgar_conf, *(w[0] + wire_lag for w in matched_wires)])

        sources: list[str] = []
        for _, w_src, _ in matched_wires:
            if w_src not in sources:
                sources.append(w_src)
        sec_src = f"sec_edgar_{filing.form.lower().replace('-', '').replace('/', '_').replace(' ', '_')}"
        if sec_src not in sources:
            sources.append(sec_src)

        if matched_wires:
            earliest_wire_title = sorted(matched_wires, key=lambda x: x[0])[0][2]
            headline = f"{earliest_wire_title} / {filing.headline}"
            wire_note = (
                "Fused preceding/concurrent press-wire timestamp with SEC EDGAR acceptance "
                "(America/New_York normalized to UTC) plus 180s sec.gov public dissemination lag."
            )
        else:
            headline = filing.headline
            wire_note = (
                "Anchored on SEC EDGAR acceptanceDateTime (America/New_York normalized to UTC) "
                "plus 180s sec.gov public dissemination lag."
            )

        if filing.reg_st_filing_date_rolled:
            wire_note += (
                f" Post-17:30 ET submission rolled Reg S-T filingDate to {filing.filing_date}; "
                "availability is anchored strictly on acceptanceDateTime."
            )

        intervals.append(
            CatalystAvailabilityInterval(
                symbol=sym,
                earliest_public_utc=format_utc_timestamp(earliest_dt),
                confirmed_public_utc=format_utc_timestamp(confirmed_dt),
                event_sources=sources,
                headline_or_event=headline,
                timestamp_uncertainty_note=wire_note,
                is_macro=False,
            )
        )

    # Emit standalone news/wire intervals that were not fused with an EDGAR filing.
    for sym, rows in sorted(news_by_symbol.items()):
        for row in rows:
            if bool(row[4]):
                continue
            w_dt = row[0]
            assert isinstance(w_dt, datetime)
            src = str(row[1])
            title = str(row[2])
            intervals.append(
                CatalystAvailabilityInterval(
                    symbol=sym,
                    earliest_public_utc=format_utc_timestamp(w_dt),
                    confirmed_public_utc=format_utc_timestamp(w_dt + wire_lag),
                    event_sources=[src],
                    headline_or_event=title,
                    timestamp_uncertainty_note=(
                        f"Public news wire timestamp from {src} includes vendor feed aggregation "
                        f"latency window of {standalone_wire_lag_seconds}s."
                    ),
                    is_macro=False,
                )
            )

    # Emit EODHD economic calendar intervals.
    for macro_ev in eodhd_macro_events:
        rel_dt = parse_utc_timestamp(macro_ev.released_utc)
        intervals.append(
            CatalystAvailabilityInterval(
                symbol=MACRO_SYMBOL_WILDCARD,
                earliest_public_utc=format_utc_timestamp(rel_dt),
                confirmed_public_utc=format_utc_timestamp(rel_dt + wire_lag),
                event_sources=["eodhd_economic_events"],
                headline_or_event=f"{macro_ev.country} Macro Release: {macro_ev.event_type}",
                timestamp_uncertainty_note=(
                    "Scheduled macroeconomic calendar timestamp carries vendor feed propagation latency."
                ),
                is_macro=True,
            )
        )

    # Emit ALFRED point-in-time vintage macro intervals.
    for alfred_rel in alfred_macro_releases:
        intervals.append(
            CatalystAvailabilityInterval(
                symbol=MACRO_SYMBOL_WILDCARD,
                earliest_public_utc=alfred_rel.earliest_public_utc,
                confirmed_public_utc=alfred_rel.confirmed_public_utc,
                event_sources=["fred_alfred_vintage"],
                headline_or_event=alfred_rel.headline,
                timestamp_uncertainty_note=(
                    f"Point-in-time ALFRED realtime_start ({alfred_rel.vintage_release_date}) "
                    "mapped via canonical US Eastern release schedule; excludes subsequent revisions."
                ),
                is_macro=True,
            )
        )

    intervals.sort(key=lambda iv: (iv.earliest_public_utc, iv.confirmed_public_utc, iv.symbol))
    return intervals


def classify_trade_against_intervals(
    *,
    symbol: str,
    trade_timestamp_utc: str,
    intervals: Sequence[CatalystAvailabilityInterval],
    underlying_symbol: str | None = None,
    pre_event_window_hours: float = DEFAULT_PRE_EVENT_WINDOW_HOURS,
    post_event_window_hours: float = DEFAULT_POST_EVENT_WINDOW_HOURS,
) -> EventWindowObservation:
    """Classify a single execution fill relative to fused catalyst intervals I_e."""
    trade_dt = parse_utc_timestamp(trade_timestamp_utc, field_name="trade_timestamp_utc")
    canonical_sym = _canonical_symbol(symbol, underlying_symbol)
    pre_delta = timedelta(hours=max(0.0, pre_event_window_hours))
    post_delta = timedelta(hours=max(0.0, post_event_window_hours))

    issuer_intervals = [iv for iv in intervals if not iv.is_macro and iv.symbol == canonical_sym]
    macro_intervals = [iv for iv in intervals if iv.is_macro]

    for scope_intervals in (issuer_intervals, macro_intervals):
        ambiguous_matches: list[tuple[float, CatalystAvailabilityInterval]] = []
        post_matches: list[tuple[float, CatalystAvailabilityInterval]] = []
        prior_matches: list[tuple[float, CatalystAvailabilityInterval]] = []

        for iv in scope_intervals:
            t_early = parse_utc_timestamp(iv.earliest_public_utc)
            t_conf = parse_utc_timestamp(iv.confirmed_public_utc)
            if t_early <= trade_dt <= t_conf:
                dist = abs((trade_dt - t_early).total_seconds())
                ambiguous_matches.append((dist, iv))
            elif t_conf < trade_dt <= t_conf + post_delta:
                dist = (trade_dt - t_conf).total_seconds()
                post_matches.append((dist, iv))
            elif t_early - pre_delta <= trade_dt < t_early:
                dist = (t_early - trade_dt).total_seconds()
                prior_matches.append((dist, iv))

        if ambiguous_matches:
            ambiguous_matches.sort(key=lambda x: x[0])
            chosen = ambiguous_matches[0][1]
            return EventWindowObservation(
                symbol=symbol.strip().upper(),
                trade_timestamp_utc=format_utc_timestamp(trade_dt),
                earliest_public_utc=chosen.earliest_public_utc,
                confirmed_public_utc=chosen.confirmed_public_utc,
                event_sources=list(chosen.event_sources),
                headline_or_event=chosen.headline_or_event,
                alignment_class=CatalystAlignmentClass.AMBIGUOUS_PUBLIC_WINDOW,
                timestamp_uncertainty_note=(
                    f"Execution occurred within public availability interval "
                    f"[{chosen.earliest_public_utc}, {chosen.confirmed_public_utc}]. "
                    f"{chosen.timestamp_uncertainty_note}"
                ),
            )

        if post_matches:
            post_matches.sort(key=lambda x: x[0])
            chosen = post_matches[0][1]
            return EventWindowObservation(
                symbol=symbol.strip().upper(),
                trade_timestamp_utc=format_utc_timestamp(trade_dt),
                earliest_public_utc=chosen.earliest_public_utc,
                confirmed_public_utc=chosen.confirmed_public_utc,
                event_sources=list(chosen.event_sources),
                headline_or_event=chosen.headline_or_event,
                alignment_class=CatalystAlignmentClass.POST_CONFIRMED_CATALYST,
                timestamp_uncertainty_note=(
                    f"Execution occurred after confirmed public dissemination ({chosen.confirmed_public_utc}). "
                    f"{chosen.timestamp_uncertainty_note}"
                ),
            )

        if prior_matches:
            prior_matches.sort(key=lambda x: x[0])
            chosen = prior_matches[0][1]
            return EventWindowObservation(
                symbol=symbol.strip().upper(),
                trade_timestamp_utc=format_utc_timestamp(trade_dt),
                earliest_public_utc=chosen.earliest_public_utc,
                confirmed_public_utc=chosen.confirmed_public_utc,
                event_sources=list(chosen.event_sources),
                headline_or_event=chosen.headline_or_event,
                alignment_class=CatalystAlignmentClass.PRIOR_TO_EARLIEST_RECORDED_CATALYST,
                timestamp_uncertainty_note=(
                    f"Execution preceded earliest recorded timestamp ({chosen.earliest_public_utc}) in "
                    "queried feeds; unindexed wires, analyst notes, or feed clock skew may exist. "
                    f"{chosen.timestamp_uncertainty_note}"
                ),
            )

    return EventWindowObservation(
        symbol=symbol.strip().upper(),
        trade_timestamp_utc=format_utc_timestamp(trade_dt),
        earliest_public_utc=None,
        confirmed_public_utc=None,
        event_sources=[],
        headline_or_event="No recorded public catalyst within observation window",
        alignment_class=CatalystAlignmentClass.QUIET_NON_CATALYST_REGIME,
        timestamp_uncertainty_note=(
            "No issuer filing, press wire, or scheduled macro release recorded within the "
            "configured observation window across active public feeds."
        ),
    )


def evaluate_portfolio_catalyst_context(
    ledger: CanonicalPortfolioLedger,
    *,
    intervals: Sequence[CatalystAvailabilityInterval] | None = None,
    sec_filings: Sequence[SecEdgarFiling] = (),
    eodhd_news: Sequence[EodhdNewsEvent] = (),
    gdelt_articles: Sequence[GdeltArticleEvent] = (),
    eodhd_macro_events: Sequence[EodhdEconomicEvent] = (),
    alfred_macro_releases: Sequence[MacroReleaseObservation] = (),
    eodhd_client: EodhdEventsClient | None = None,
    sec_client: SecEdgarClient | None = None,
    fred_client: FredAlfredClient | None = None,
    gdelt_client: GdeltDocFallbackClient | None = None,
    macro_series_ids: Sequence[str] = (),
    closed_round_trips: Sequence[ClosedRoundTrip] | None = None,
    pre_event_window_hours: float = DEFAULT_PRE_EVENT_WINDOW_HOURS,
    post_event_window_hours: float = DEFAULT_POST_EVENT_WINDOW_HOURS,
    reference_now_utc: str | datetime | None = None,
) -> CatalystContextSummary:
    """Evaluate trade-level catalyst intervals and compute catalyst vs quiet regime win rates."""
    disclosures: list[str] = [
        "Public catalyst intervals combine regulatory acceptance clocks and press-wire timestamps with explicit propagation buffers for descriptive regime context only."
    ]

    active_trades = [t for t in ledger.trades if t.asset_class != AssetClass.CASH]
    if not active_trades:
        return CatalystContextSummary(
            event_observations=[],
            catalyst_regime_win_rate=None,
            quiet_regime_win_rate=None,
            event_window_share_pct=0.0,
            uncertainty_disclosures=disclosures,
        )

    all_sec = list(sec_filings)
    all_news = list(eodhd_news)
    all_gdelt = list(gdelt_articles)
    all_eodhd_macro = list(eodhd_macro_events)
    all_alfred = list(alfred_macro_releases)

    if intervals is None:
        start_dt = parse_utc_timestamp(ledger.period_start_utc) - timedelta(days=7)
        end_dt = parse_utc_timestamp(ledger.period_end_utc) + timedelta(days=2)
        unique_equities = sorted(
            {
                _canonical_symbol(t.symbol, t.underlying_symbol)
                for t in active_trades
                if t.asset_class in {AssetClass.EQUITY, AssetClass.ETF, AssetClass.OPTION}
            }
        )

        if sec_client is not None:
            for sym in unique_equities:
                all_sec.extend(
                    sec_client.fetch_company_filings(sym, from_utc=start_dt, to_utc=end_dt)
                )

        if eodhd_client is not None and eodhd_client.is_configured:
            for sym in unique_equities:
                all_news.extend(eodhd_client.fetch_company_news(sym, start_dt, end_dt))
            all_eodhd_macro.extend(eodhd_client.fetch_economic_events(start_dt, end_dt))
        elif gdelt_client is not None and unique_equities:
            any_truncated = False
            for sym in unique_equities:
                arts, truncated = gdelt_client.fetch_recent_articles(
                    sym,
                    start_dt,
                    end_dt,
                    reference_now_utc=reference_now_utc,
                )
                all_gdelt.extend(arts)
                any_truncated = any_truncated or truncated
            if any_truncated:
                disclosures.append(
                    "GDELT DOC 2.0 fallback retains fewer than 90 calendar days of rolling coverage; earlier sub-periods rely on regulatory and macro feeds."
                )

        if fred_client is not None and fred_client.is_configured and macro_series_ids:
            for series_id in macro_series_ids:
                all_alfred.extend(
                    fred_client.fetch_point_in_time_releases(
                        series_id,
                        from_release_date=start_dt,
                        to_release_date=end_dt,
                    )
                )

        resolved_intervals = build_catalyst_intervals(
            sec_filings=all_sec,
            eodhd_news=all_news,
            gdelt_articles=all_gdelt,
            eodhd_macro_events=all_eodhd_macro,
            alfred_macro_releases=all_alfred,
        )
    else:
        resolved_intervals = list(intervals)

    if any(f.reg_st_filing_date_rolled for f in all_sec):
        disclosures.append(
            "One or more post-17:30 ET SEC filings carried next-business-day Reg S-T filingDate values and were anchored strictly on acceptanceDateTime."
        )

    observations: list[EventWindowObservation] = []
    for trade in sorted(active_trades, key=lambda t: parse_utc_timestamp(t.timestamp_utc)):
        obs = classify_trade_against_intervals(
            symbol=trade.symbol,
            trade_timestamp_utc=trade.timestamp_utc,
            intervals=resolved_intervals,
            underlying_symbol=trade.underlying_symbol,
            pre_event_window_hours=pre_event_window_hours,
            post_event_window_hours=post_event_window_hours,
        )
        observations.append(obs)

    catalyst_obs_count = sum(
        1
        for obs in observations
        if obs.alignment_class != CatalystAlignmentClass.QUIET_NON_CATALYST_REGIME
    )
    event_window_share_pct = round((catalyst_obs_count / len(observations)) * 100.0, 6)

    if closed_round_trips is not None:
        trips = list(closed_round_trips)
    else:
        from n170_verify.coaching.behaviour_metrics import match_fifo_round_trips

        trips = match_fifo_round_trips(ledger)
    catalyst_trip_wins: list[bool] = []
    quiet_trip_wins: list[bool] = []

    for rt in trips:
        entry_obs = classify_trade_against_intervals(
            symbol=rt.symbol,
            trade_timestamp_utc=rt.entry_timestamp_utc,
            intervals=resolved_intervals,
            pre_event_window_hours=pre_event_window_hours,
            post_event_window_hours=post_event_window_hours,
        )
        won = rt.net_pnl_base > 0.0
        if entry_obs.alignment_class == CatalystAlignmentClass.QUIET_NON_CATALYST_REGIME:
            quiet_trip_wins.append(won)
        else:
            catalyst_trip_wins.append(won)

    catalyst_win_rate = (
        round(sum(1 for w in catalyst_trip_wins if w) / len(catalyst_trip_wins), 6)
        if catalyst_trip_wins
        else None
    )
    quiet_win_rate = (
        round(sum(1 for w in quiet_trip_wins if w) / len(quiet_trip_wins), 6)
        if quiet_trip_wins
        else None
    )

    return CatalystContextSummary(
        event_observations=observations,
        catalyst_regime_win_rate=catalyst_win_rate,
        quiet_regime_win_rate=quiet_win_rate,
        event_window_share_pct=event_window_share_pct,
        uncertainty_disclosures=disclosures,
    )


__all__ = [
    "CatalystAvailabilityInterval",
    "CatalystContextSummary",
    "DEFAULT_POST_EVENT_WINDOW_HOURS",
    "DEFAULT_PRESS_WIRE_POST_HOURS",
    "DEFAULT_PRESS_WIRE_PRE_BUSINESS_DAYS",
    "DEFAULT_PRE_EVENT_WINDOW_HOURS",
    "DEFAULT_STANDALONE_WIRE_LAG_SECONDS",
    "MACRO_SYMBOL_WILDCARD",
    "build_catalyst_intervals",
    "classify_trade_against_intervals",
    "evaluate_portfolio_catalyst_context",
    "subtract_business_days",
]
