"""Two-stage market fill envelope verification (EOD -> intraday) and corporate action checks."""

from __future__ import annotations

from datetime import datetime, time as dt_time, timedelta, timezone
from zoneinfo import ZoneInfo

from n170_verify.contracts import (
    AssetClass,
    CanonicalPortfolioLedger,
    CheckOutcome,
    CorporateActionType,
    NormalizedTrade,
    ReconciliationFinding,
    parse_utc_timestamp,
)
from n170_verify.reference.base import (
    DailyPriceEnvelope,
    ReferenceDataProvider,
    normalize_uk_currency_and_scale,
)
from n170_verify.reference.eodhd_client import normalize_eodhd_exchange


_NY_TZ = ZoneInfo("America/New_York")
_LONDON_TZ = ZoneInfo("Europe/London")

# Sub-penny / midpoint price-improvement micro-tolerance (5 bps or 1e-4 currency units).
FILL_BOUND_TOLERANCE_BPS = 5.0

BENIGN_FILL_CAUSES: tuple[str, ...] = (
    "Extended-hours / VWAP / OTC print",
    "Average-price institutional block or multi-fill allocation",
    "Unreported corporate reorganization",
    "Prior-day late print or exchange bust/adjustment",
)


def _session_date_and_us_after_hours_offset(
    fill_dt_utc: datetime,
    *,
    exchange: str,
) -> tuple[str, float | None]:
    """Return ``(session_date_iso, hours_after_us_extended_close)`` for a UTC trade timestamp.

    Exact ``00:00:00Z`` date-only timestamps preserve their UTC calendar date rather than shifting
    to the prior evening in New York. For intraday UTC timestamps on ``US`` venues:
    - ``04:00 ET .. 20:00 ET`` -> ``hours_after_us_extended_close = 0.0`` (within pre/RTH/post session)
    - ``20:00 ET .. 23:00 ET`` -> ``(0.0, 3.0]`` hours past 20:00 ET extended-hours close
    - ``23:00 ET .. 04:00 ET`` -> ``> 3.0`` hours past 20:00 ET extended-hours close (skip intraday!)
    """
    is_date_only_midnight = (
        fill_dt_utc.hour == 0
        and fill_dt_utc.minute == 0
        and fill_dt_utc.second == 0
        and fill_dt_utc.microsecond == 0
    )
    if is_date_only_midnight:
        return fill_dt_utc.date().isoformat(), 0.0 if exchange == "US" else None

    if exchange == "US":
        ny_dt = fill_dt_utc.astimezone(_NY_TZ)
        minutes_of_day = ny_dt.hour * 60 + ny_dt.minute + (ny_dt.second / 60.0)
        # Early morning 00:00..03:59 ET belongs to overnight gap (> 3h past prior evening 20:00 ET close).
        if minutes_of_day < 4 * 60:
            prev_session = (ny_dt.date() - timedelta(days=1)).isoformat()
            hours_past_ext_close = (minutes_of_day + 4 * 60) / 60.0  # 20:00 -> 24:00 is +4h
            return prev_session, hours_past_ext_close
        if minutes_of_day <= 20 * 60:
            return ny_dt.date().isoformat(), 0.0
        hours_past_ext_close = (minutes_of_day - 20 * 60) / 60.0
        return ny_dt.date().isoformat(), hours_past_ext_close

    if exchange == "LSE":
        lon_dt = fill_dt_utc.astimezone(_LONDON_TZ)
        return lon_dt.date().isoformat(), None

    return fill_dt_utc.date().isoformat(), None


def _us_extended_session_unix_bounds(session_date_str: str, exchange: str) -> tuple[int, int]:
    """Compute Unix epoch ``[start, end]`` covering pre-market + RTH + post-market (+3h buffer)."""
    d = datetime.fromisoformat(session_date_str).date()
    if exchange == "US":
        start_local = datetime.combine(d, dt_time(4, 0, 0), tzinfo=_NY_TZ)
        end_local = datetime.combine(d, dt_time(23, 0, 0), tzinfo=_NY_TZ)
        return int(start_local.timestamp()), int(end_local.timestamp())
    if exchange == "LSE":
        start_local = datetime.combine(d, dt_time(7, 0, 0), tzinfo=_LONDON_TZ)
        end_local = datetime.combine(d, dt_time(18, 0, 0), tzinfo=_LONDON_TZ)
        return int(start_local.timestamp()), int(end_local.timestamp())
    start_utc = datetime.combine(d, dt_time(0, 0, 0), tzinfo=timezone.utc)
    end_utc = datetime.combine(d, dt_time(23, 59, 59), tzinfo=timezone.utc)
    return int(start_utc.timestamp()), int(end_utc.timestamp())


def _within_bounds(price: float, low: float, high: float) -> tuple[bool, float]:
    """Return ``(inside, breach_bps)`` with a 5 bps / 1e-4 sub-penny microstructure tolerance."""
    tol = max(1e-4, (FILL_BOUND_TOLERANCE_BPS / 10_000.0) * max(high, 1e-9))
    if (low - tol) <= price <= (high + tol):
        return True, 0.0
    if price < low:
        bps = ((low - price) / max(low, 1e-9)) * 10_000.0
        return False, bps
    bps = ((price - high) / max(high, 1e-9)) * 10_000.0
    return False, bps


def _has_subsequent_ledger_split(
    ledger: CanonicalPortfolioLedger,
    symbol: str,
    fill_dt_utc: datetime,
) -> bool:
    sym_u = symbol.strip().upper()
    for ca in ledger.corporate_actions:
        if ca.symbol.strip().upper() == sym_u and ca.action_type in {
            CorporateActionType.SPLIT,
            CorporateActionType.REVERSE_SPLIT,
        }:
            if parse_utc_timestamp(ca.timestamp_utc) > fill_dt_utc:
                return True
    return False


def reconcile_trade_fills(
    ledger: CanonicalPortfolioLedger,
    *,
    reference_provider: ReferenceDataProvider | None = None,
    reference_now_utc: str | datetime | None = None,
) -> list[ReconciliationFinding]:
    """Run 2-Stage Fill Bound Check across equity/ETF/spot fills.

    Stage 1: Compare fill price against pure ``/api/splits/`` split-adjusted (and ``.LSE`` ``GBX``
             ``100x`` normalized) EOD ``[Low, High]`` (1 call weight).
    Stage 2: Escalate to ``/api/intraday/`` (``1m`` if age <= 120d, ``5m`` if <= 600d, skipping
             fills > 3h after US extended-hours close) ONLY when RTH ``[Low, High]`` is breached.
    """
    findings: list[ReconciliationFinding] = []
    eligible_classes = {AssetClass.EQUITY, AssetClass.ETF, AssetClass.CRYPTO_SPOT}
    target_trades = [tr for tr in ledger.trades if tr.asset_class in eligible_classes]
    if not target_trades:
        return findings

    if reference_provider is None or not reference_provider.is_available:
        for tr in target_trades:
            findings.append(
                ReconciliationFinding(
                    category="trade_fill_envelope",
                    outcome=CheckOutcome.NOT_EVALUATED,
                    date_or_timestamp=tr.timestamp_utc,
                    symbol=tr.symbol,
                    observed_value=float(tr.price),
                    math_identity="FillPrice in [SplitAdjustedLow, SplitAdjustedHigh]",
                    technical_explanation="Market reference provider unavailable; trade fill price envelope not evaluated.",
                    benign_causes_considered=list(BENIGN_FILL_CAUSES),
                )
            )
        return findings

    now_dt = (
        parse_utc_timestamp(reference_now_utc, field_name="reference_now_utc")
        if reference_now_utc is not None
        else max(datetime.now(timezone.utc), parse_utc_timestamp(ledger.period_end_utc))
    )

    for tr in target_trades:
        fill_dt = parse_utc_timestamp(tr.timestamp_utc)
        ex_code = (
            "CC"
            if tr.asset_class == AssetClass.CRYPTO_SPOT
            else normalize_eodhd_exchange(tr.exchange, isin=tr.isin, currency=tr.currency)
        )
        resolved = reference_provider.resolve_security(
            tr.symbol,
            exchange=ex_code,
            isin=tr.isin,
            currency=tr.currency,
        )
        if resolved is None:
            findings.append(
                ReconciliationFinding(
                    category="trade_fill_envelope",
                    outcome=CheckOutcome.NOT_EVALUATED,
                    date_or_timestamp=tr.timestamp_utc,
                    symbol=tr.symbol,
                    observed_value=float(tr.price),
                    math_identity="FillPrice in [SplitAdjustedLow, SplitAdjustedHigh]",
                    technical_explanation=f"Could not resolve canonical reference ticker for {tr.symbol}.",
                    benign_causes_considered=list(BENIGN_FILL_CAUSES),
                )
            )
            continue

        session_date, hours_past_us_ext = _session_date_and_us_after_hours_offset(
            fill_dt,
            exchange=resolved.exchange,
        )

        # Stage 1: EOD [Low, High] envelope (weight 1)
        envelopes = reference_provider.get_daily_envelopes(
            resolved.canonical_ticker,
            start_date=session_date,
            end_date=session_date,
            quote_currency_hint=tr.currency,
        )
        if not envelopes:
            findings.append(
                ReconciliationFinding(
                    category="trade_fill_envelope",
                    outcome=CheckOutcome.NOT_EVALUATED,
                    date_or_timestamp=tr.timestamp_utc,
                    symbol=tr.symbol,
                    observed_value=float(tr.price),
                    math_identity="FillPrice in [SplitAdjustedLow, SplitAdjustedHigh]",
                    technical_explanation=(
                        f"No EOD reference bar returned for {resolved.canonical_ticker} on {session_date}."
                    ),
                    benign_causes_considered=list(BENIGN_FILL_CAUSES),
                )
            )
            continue

        env: DailyPriceEnvelope = envelopes[-1]
        _, norm_trade_ccy, trade_scale = normalize_uk_currency_and_scale(tr.currency)
        normalized_fill = float(tr.price) * trade_scale
        if norm_trade_ccy != env.currency:
            fx = reference_provider.get_fx_rate(norm_trade_ccy, env.currency, date_str=session_date)
            if fx is not None and fx > 0.0:
                normalized_fill *= fx

        # Primary Stage-1 test: pure /api/splits/ split-adjusted [Low, High]
        ok_split, bps_split = _within_bounds(
            normalized_fill,
            env.split_adjusted_low,
            env.split_adjusted_high,
        )
        # Also honor raw pre-split [Low, High] when the ledger explicitly carries the subsequent
        # split corporate action (or when the statement period ended prior to a later split).
        allow_raw_pre_split = env.cumulative_split_factor != 1.0 and (
            _has_subsequent_ledger_split(ledger, tr.symbol, fill_dt)
            or ledger.period_end_utc[:10] >= session_date
        )
        ok_raw = False
        bps_raw = bps_split
        if env.cumulative_split_factor != 1.0 and _has_subsequent_ledger_split(ledger, tr.symbol, fill_dt):
            ok_raw, bps_raw = _within_bounds(normalized_fill, env.raw_low, env.raw_high)
        elif env.cumulative_split_factor != 1.0:
            # Check if statement closed prior to all post-trade splits on this ticker
            later_splits = reference_provider.get_splits(
                env.ticker,
                start_date=session_date,
            )
            post_trade_splits = [s for s in later_splits if s.effective_date > session_date]
            if post_trade_splits and all(
                s.effective_date > ledger.period_end_utc[:10] for s in post_trade_splits
            ):
                ok_raw, bps_raw = _within_bounds(normalized_fill, env.raw_low, env.raw_high)
        del allow_raw_pre_split

        if ok_split or ok_raw:
            used_low = env.raw_low if (ok_raw and not ok_split) else env.split_adjusted_low
            used_high = env.raw_high if (ok_raw and not ok_split) else env.split_adjusted_high
            findings.append(
                ReconciliationFinding(
                    category="trade_fill_envelope",
                    outcome=CheckOutcome.PASS,
                    date_or_timestamp=tr.timestamp_utc,
                    symbol=tr.symbol,
                    expected_value=0.5 * (used_low + used_high),
                    observed_value=normalized_fill,
                    residual_bps=0.0,
                    residual_base_currency=0.0,
                    math_identity=f"FillPrice in [{used_low:.6g}, {used_high:.6g}] ({env.currency})",
                    technical_explanation=(
                        f"Stage-1 EOD envelope check passed for {tr.symbol} ({env.ticker}) on {session_date}."
                    ),
                    benign_causes_considered=[],
                )
            )
            continue

        # Stage 2: Escalate to /api/intraday/ ONLY because Stage-1 RTH [Low, High] was breached!
        age_days = max(0.0, (now_dt - fill_dt).total_seconds() / 86400.0)
        skip_reason: str | None = None
        intraday_interval: str | None = None

        if resolved.exchange == "US" and hours_past_us_ext is not None and hours_past_us_ext > 3.0:
            skip_reason = (
                f"fill timestamp is {hours_past_us_ext:.2f}h past 20:00 ET US extended-hours close (> 3h guard)"
            )
        elif age_days <= 120.0:
            intraday_interval = "1m"
        elif age_days <= 600.0:
            intraday_interval = "5m"
        else:
            skip_reason = f"fill age ({age_days:.0f}d) exceeds 600-day intraday 1m/5m retention window"

        if intraday_interval is not None and skip_reason is None:
            start_u, end_u = _us_extended_session_unix_bounds(session_date, resolved.exchange)
            intra_env = reference_provider.get_intraday_envelope(
                env.ticker,
                start_unix=start_u,
                end_unix=end_u,
                interval=intraday_interval,
                trade_date=session_date,
                quote_currency_hint=tr.currency,
            )
            if intra_env is not None:
                intra_ok, intra_bps = _within_bounds(
                    normalized_fill,
                    intra_env.split_adjusted_low,
                    intra_env.split_adjusted_high,
                )
                if not intra_ok and ok_raw is False and env.cumulative_split_factor != 1.0 and _has_subsequent_ledger_split(ledger, tr.symbol, fill_dt):
                    intra_ok, intra_bps = _within_bounds(
                        normalized_fill,
                        intra_env.session_low,
                        intra_env.session_high,
                    )
                if intra_ok:
                    findings.append(
                        ReconciliationFinding(
                            category="trade_fill_envelope",
                            outcome=CheckOutcome.PASS,
                            date_or_timestamp=tr.timestamp_utc,
                            symbol=tr.symbol,
                            expected_value=0.5
                            * (intra_env.split_adjusted_low + intra_env.split_adjusted_high),
                            observed_value=normalized_fill,
                            residual_bps=0.0,
                            residual_base_currency=0.0,
                            math_identity=(
                                f"FillPrice in Intraday_{intraday_interval}"
                                f"[{intra_env.split_adjusted_low:.6g}, {intra_env.split_adjusted_high:.6g}] ({intra_env.currency})"
                            ),
                            technical_explanation=(
                                f"Fill breached RTH [{env.split_adjusted_low:.6g}, {env.split_adjusted_high:.6g}] "
                                f"but passed Stage-2 {intraday_interval} extended-hours envelope "
                                f"[{intra_env.split_adjusted_low:.6g}, {intra_env.split_adjusted_high:.6g}]."
                            ),
                            benign_causes_considered=list(BENIGN_FILL_CAUSES),
                        )
                    )
                    continue

                best_bps = min(bps_split, intra_bps)
                nearest_bound = (
                    intra_env.split_adjusted_low
                    if normalized_fill < intra_env.split_adjusted_low
                    else intra_env.split_adjusted_high
                )
                diff_per_unit = abs(normalized_fill - nearest_bound)
                mult = float(tr.multiplier or 1.0)
                res_base = diff_per_unit * abs(float(tr.quantity)) * mult * float(tr.fx_rate_to_base)
                findings.append(
                    ReconciliationFinding(
                        category="trade_fill_envelope",
                        outcome=CheckOutcome.DISCREPANCY,
                        date_or_timestamp=tr.timestamp_utc,
                        symbol=tr.symbol,
                        expected_value=nearest_bound,
                        observed_value=normalized_fill,
                        residual_bps=best_bps,
                        residual_base_currency=res_base,
                        math_identity=(
                            f"FillPrice in RTH[{env.split_adjusted_low:.6g}, {env.split_adjusted_high:.6g}] "
                            f"U Intraday_{intraday_interval}[{intra_env.split_adjusted_low:.6g}, {intra_env.split_adjusted_high:.6g}]"
                        ),
                        technical_explanation=(
                            f"Fill price {normalized_fill:.6g} {env.currency} lies outside both Stage-1 RTH "
                            f"[{env.split_adjusted_low:.6g}, {env.split_adjusted_high:.6g}] and Stage-2 "
                            f"{intraday_interval} extended-hours [{intra_env.split_adjusted_low:.6g}, "
                            f"{intra_env.split_adjusted_high:.6g}] bounds ({best_bps:.1f} bps beyond nearest bound)."
                        ),
                        benign_causes_considered=list(BENIGN_FILL_CAUSES),
                    )
                )
                continue

        # Reached when Stage 2 was skipped (>3h past US extended close or >600d) or returned empty intraday bars
        best_bps = min(bps_split, bps_raw)
        nearest_rth = (
            env.split_adjusted_low
            if normalized_fill < env.split_adjusted_low
            else env.split_adjusted_high
        )
        diff_unit = abs(normalized_fill - nearest_rth)
        mult = float(tr.multiplier or 1.0)
        res_base = diff_unit * abs(float(tr.quantity)) * mult * float(tr.fx_rate_to_base)
        note_suffix = f" (Stage-2 intraday skipped: {skip_reason})" if skip_reason else " (no intraday bars available)"
        findings.append(
            ReconciliationFinding(
                category="trade_fill_envelope",
                outcome=CheckOutcome.DISCREPANCY,
                date_or_timestamp=tr.timestamp_utc,
                symbol=tr.symbol,
                expected_value=nearest_rth,
                observed_value=normalized_fill,
                residual_bps=best_bps,
                residual_base_currency=res_base,
                math_identity=f"FillPrice in [{env.split_adjusted_low:.6g}, {env.split_adjusted_high:.6g}] ({env.currency})",
                technical_explanation=(
                    f"Fill price {normalized_fill:.6g} {env.currency} lies {best_bps:.1f} bps outside "
                    f"Stage-1 EOD [{env.split_adjusted_low:.6g}, {env.split_adjusted_high:.6g}]{note_suffix}."
                ),
                benign_causes_considered=list(BENIGN_FILL_CAUSES),
            )
        )

    return findings


def reconcile_corporate_actions_and_ending_marks(
    ledger: CanonicalPortfolioLedger,
    *,
    reference_provider: ReferenceDataProvider | None = None,
) -> list[ReconciliationFinding]:
    """Verify declared split ratios against ``/api/splits/`` and ending marks against EOD closes."""
    findings: list[ReconciliationFinding] = []
    if reference_provider is None or not reference_provider.is_available:
        return findings

    # 1. Verify declared SPLIT / REVERSE_SPLIT ratios against EODHD /api/splits/
    for ca in ledger.corporate_actions:
        if ca.action_type not in {CorporateActionType.SPLIT, CorporateActionType.REVERSE_SPLIT}:
            continue
        if ca.ratio_numerator is None or ca.ratio_denominator is None:
            continue
        declared_ratio = float(ca.ratio_numerator) / float(ca.ratio_denominator)
        resolved = reference_provider.resolve_security(ca.symbol, isin=ca.isin)
        if resolved is None:
            continue
        ca_dt = datetime.fromisoformat(ca.timestamp_utc[:10]).date()
        ref_splits = reference_provider.get_splits(
            resolved.canonical_ticker,
            start_date=(ca_dt - timedelta(days=5)).isoformat(),
            end_date=(ca_dt + timedelta(days=5)).isoformat(),
        )
        if not ref_splits:
            continue
        ref_ratio = ref_splits[0].ratio
        ratio_bps = (abs(declared_ratio - ref_ratio) / max(ref_ratio, 1e-9)) * 10_000.0
        ok = ratio_bps <= 10.0
        findings.append(
            ReconciliationFinding(
                category="corporate_action_split_ratio",
                outcome=CheckOutcome.PASS if ok else CheckOutcome.DISCREPANCY,
                date_or_timestamp=ca.timestamp_utc,
                symbol=ca.symbol,
                expected_value=ref_ratio,
                observed_value=declared_ratio,
                residual_bps=0.0 if ok else ratio_bps,
                math_identity="DeclaredSplitRatio == ReferenceSplitsRatio",
                technical_explanation=(
                    f"Declared split ratio ({declared_ratio:g}) matches /api/splits/ ({ref_ratio:g})."
                    if ok
                    else f"Declared split ratio ({declared_ratio:g}) diverges from /api/splits/ ({ref_ratio:g})."
                ),
                benign_causes_considered=["Special stock dividend + split combination"],
            )
        )

    # 2. Verify ending EQUITY / ETF closing marks against reference close on period_end
    end_date = ledger.period_end_utc[:10]
    end_dt = datetime.fromisoformat(end_date).date()
    start_lookback = (end_dt - timedelta(days=5)).isoformat()

    for pos in ledger.ending_positions:
        if pos.asset_class not in {AssetClass.EQUITY, AssetClass.ETF} or abs(pos.quantity) <= 1e-9:
            continue
        ex_code = normalize_eodhd_exchange(None, isin=pos.isin, currency=pos.currency)
        resolved = reference_provider.resolve_security(
            pos.symbol,
            exchange=ex_code,
            isin=pos.isin,
            currency=pos.currency,
        )
        if resolved is None:
            continue
        envs = reference_provider.get_daily_envelopes(
            resolved.canonical_ticker,
            start_date=start_lookback,
            end_date=end_date,
            quote_currency_hint=pos.currency,
        )
        if not envs:
            continue

        env = envs[-1]
        mult = float(pos.multiplier or 1.0)
        _, norm_pos_ccy, pos_scale = normalize_uk_currency_and_scale(pos.currency)
        implied_unit_mark = (abs(float(pos.market_value)) / (abs(float(pos.quantity)) * mult)) * pos_scale
        if norm_pos_ccy != env.currency:
            fx = reference_provider.get_fx_rate(norm_pos_ccy, env.currency, date_str=end_date)
            if fx is not None and fx > 0.0:
                implied_unit_mark *= fx

        # Compare against raw_close (as-held on period_end) or split_adjusted_close if post-end split occurred
        ref_close = env.raw_close
        diff_bps = (abs(implied_unit_mark - ref_close) / max(ref_close, 1e-9)) * 10_000.0
        if env.cumulative_split_factor != 1.0:
            alt_bps = (
                abs(implied_unit_mark - env.split_adjusted_close)
                / max(env.split_adjusted_close, 1e-9)
            ) * 10_000.0
            if alt_bps < diff_bps:
                ref_close = env.split_adjusted_close
                diff_bps = alt_bps

        if diff_bps <= 15.0:
            outcome = CheckOutcome.PASS
            explanation = (
                f"Ending mark for {pos.symbol} ({implied_unit_mark:.4f} {env.currency}) matches "
                f"reference close ({ref_close:.4f} {env.currency})."
            )
        elif diff_bps <= 75.0:
            outcome = CheckOutcome.EXPLAINED_CONVENTION
            explanation = (
                f"Ending mark for {pos.symbol} ({implied_unit_mark:.4f} vs {ref_close:.4f} {env.currency}, "
                f"{diff_bps:.1f} bps) consistent with composite vs primary exchange closing auction mark."
            )
        else:
            outcome = CheckOutcome.DISCREPANCY
            explanation = (
                f"Ending mark for {pos.symbol} ({implied_unit_mark:.4f} {env.currency}) deviates by "
                f"{diff_bps:.1f} bps from reference close ({ref_close:.4f} {env.currency})."
            )

        res_base = (
            abs(implied_unit_mark - ref_close)
            * abs(float(pos.quantity))
            * mult
            * (float(pos.fx_rate_to_base) / pos_scale)
        )
        findings.append(
            ReconciliationFinding(
                category="ending_position_mark",
                outcome=outcome,
                date_or_timestamp=ledger.period_end_utc,
                symbol=pos.symbol,
                expected_value=ref_close,
                observed_value=implied_unit_mark,
                residual_bps=diff_bps,
                residual_base_currency=res_base,
                math_identity="ImpliedPositionMark == ReferenceClose",
                technical_explanation=explanation,
                benign_causes_considered=[
                    "Primary exchange 16:00 auction vs 16:15/20:00 broker composite mark",
                    "Bid/ask midpoint vs last-trade valuation",
                ],
            )
        )

    return findings


__all__ = [
    "BENIGN_FILL_CAUSES",
    "FILL_BOUND_TOLERANCE_BPS",
    "reconcile_corporate_actions_and_ending_marks",
    "reconcile_trade_fills",
]
