"""Comprehensive unit tests for N170 Verify trader coaching, catalyst intervals, and small-LLM safety."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import sys
from typing import Any
import unittest
import urllib.error

from n170_verify.catalysts import (
    EODHD_ECONOMIC_EVENTS_CALL_WEIGHT,
    EODHD_NEWS_CALL_WEIGHT,
    EodhdApiError,
    EodhdEventsClient,
    EodhdNewsEvent,
    FredAlfredApiError,
    FredAlfredClient,
    GdeltDocFallbackClient,
    SecEdgarClient,
    build_catalyst_intervals,
    classify_trade_against_intervals,
    evaluate_portfolio_catalyst_context,
    format_cik_10d,
    format_eodhd_symbol,
    normalize_sec_acceptance_timestamp_utc,
    parse_alfred_observations_payload,
    parse_sec_acceptance_datetime_utc,
    parse_submissions_payload,
    subtract_business_days,
    validate_sec_user_agent,
)
from n170_verify.coaching import (
    DEFAULT_LLM_TEMPERATURE,
    DEFAULT_LLM_TIMEOUT_SECONDS,
    FORBIDDEN_CLAIM_SUBSTRINGS,
    MAX_SUMMARY_PROMPT_TOKENS,
    SmallLlmCoachClient,
    TraderCoachingEngine,
    build_redacted_summary_payload,
    build_trader_coaching_report,
    compute_behavioural_coaching_metrics,
    compute_cost_and_drag_breakdown,
    compute_odean_disposition_spread,
    compute_post_drawdown_sizing_discipline,
    compute_time_weighted_average_nav,
    contains_forbidden_claim,
    estimate_prompt_tokens,
    extract_delayed_closed_trades,
    match_fifo_round_trips,
)
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    CanonicalPortfolioLedger,
    CatalystAlignmentClass,
    CorporateActionRecord,
    CorporateActionType,
    EnvironmentTier,
    FlowKind,
    NormalizedFlow,
    NormalizedNavPoint,
    NormalizedTrade,
    OriginAssurance,
    ProviderApprovalState,
    TraderCoachingAndContextReport,
    compute_blinded_account_tag,
)


def _make_base_ledger(
    *,
    period_start_utc: str = "2026-01-01T00:00:00Z",
    period_end_utc: str = "2026-01-31T00:00:00Z",
    nav_points: list[NormalizedNavPoint] | None = None,
    trades: list[NormalizedTrade] | None = None,
    flows: list[NormalizedFlow] | None = None,
    corporate_actions: list[CorporateActionRecord] | None = None,
    conversion_rates: dict[str, float] | None = None,
) -> CanonicalPortfolioLedger:
    tag = compute_blinded_account_tag("ibkr", "SYNTH-ACCT-001", "aa" * 32)
    body_sha = hashlib.sha256(b"synthetic-ledger-fixture").hexdigest()
    default_nav = [
        NormalizedNavPoint(timestamp_utc=period_start_utc, nav_base=100_000.0),
        NormalizedNavPoint(timestamp_utc=period_end_utc, nav_base=100_000.0),
    ]
    return CanonicalPortfolioLedger(
        blinded_account_tag=tag,
        broker_id="ibkr",
        account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
        claimed_origin_assurance=OriginAssurance.BROKER_SIGNED,
        provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
        environment_tier=EnvironmentTier.LIVE_PRODUCTION,
        source_body_sha256=body_sha,
        base_currency="USD",
        period_start_utc=period_start_utc,
        period_end_utc=period_end_utc,
        nav_points=nav_points if nav_points is not None else default_nav,
        trades=trades if trades is not None else [],
        flows=flows if flows is not None else [],
        corporate_actions=corporate_actions if corporate_actions is not None else [],
        conversion_rates=conversion_rates if conversion_rates is not None else {},
    )


class TestCostAndDragWaterfall(unittest.TestCase):
    """Test 4-component + total + annualized basis-point drag waterfall math."""

    def test_four_component_bps_drag_and_annualization(self) -> None:
        # Trapezoidal time-weighted average NAV over 30 days:
        # First 10 days: 90,000 -> 110,000 (avg 100,000)
        # Next 20 days: 110,000 -> 90,000 (avg 100,000)
        # Overall time-weighted average NAV = 100,000.00 USD -> $10.00 = 1.0 bp!
        nav_points = [
            NormalizedNavPoint(timestamp_utc="2026-01-01T00:00:00Z", nav_base=90_000.0),
            NormalizedNavPoint(timestamp_utc="2026-01-11T00:00:00Z", nav_base=110_000.0),
            NormalizedNavPoint(timestamp_utc="2026-01-31T00:00:00Z", nav_base=90_000.0),
        ]
        trades = [
            # Equity fill: $25 commission + $5 transaction tax = $30
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="t-1",
                symbol="AAPL",
                asset_class=AssetClass.EQUITY,
                side="buy",
                quantity=100.0,
                price=180.0,
                timestamp_utc="2026-01-05T15:00:00Z",
                commission=-25.0,
                tax=5.0,
            ),
            # Explicit FX conversion: Buy 20,000 EUR.USD @ 1.0865 vs 1.0850 .FOREX midpoint
            # Spread shortfall = 20,000 * (1.0865 - 1.0850) = $30.00, plus $5 FX commission
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="t-fx",
                symbol="EUR.USD",
                asset_class=AssetClass.FX,
                side="buy",
                quantity=20_000.0,
                price=1.0865,
                timestamp_utc="2026-01-08T14:00:00Z",
                currency="USD",
                commission=5.0,
            ),
        ]
        flows = [
            # Standalone exchange/data fee = $15 -> total (a) = 30 + 5 + 15 = $50 -> 5.0 bps
            NormalizedFlow(
                timestamp_utc="2026-01-10T00:00:00Z",
                kind=FlowKind.COMMISSION_FEE,
                amount=-15.0,
            ),
            # Margin debit interest = -$60, Perp funding paid = -$30, Perp funding credit = +$10
            # Net (b) = 60 + 20 = $80 -> 8.0 bps
            NormalizedFlow(
                timestamp_utc="2026-01-15T00:00:00Z",
                kind=FlowKind.MARGIN_INTEREST,
                amount=-60.0,
            ),
            NormalizedFlow(
                timestamp_utc="2026-01-16T08:00:00Z",
                kind=FlowKind.PERP_FUNDING,
                amount=-30.0,
            ),
            NormalizedFlow(
                timestamp_utc="2026-01-17T08:00:00Z",
                kind=FlowKind.PERP_FUNDING,
                amount=10.0,
            ),
            # FX translation loss = -$10 -> total (c) = $30 (FX spread) + $10 = $40 -> 4.0 bps
            NormalizedFlow(
                timestamp_utc="2026-01-20T00:00:00Z",
                kind=FlowKind.FX_TRANSLATION,
                amount=-10.0,
            ),
            # Dividend withholding tax = -$20 -> total (d) = $20 -> 2.0 bps
            NormalizedFlow(
                timestamp_utc="2026-01-22T00:00:00Z",
                kind=FlowKind.WITHHOLDING_TAX,
                amount=-20.0,
            ),
        ]

        ledger = _make_base_ledger(
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",  # Exact 30.0 days
            nav_points=nav_points,
            trades=trades,
            flows=flows,
            conversion_rates={"EURUSD.FOREX": 1.0850},
        )
        self.assertAlmostEqual(compute_time_weighted_average_nav(ledger), 100_000.0, places=6)

        drag = compute_cost_and_drag_breakdown(ledger)
        self.assertAlmostEqual(drag.commission_and_fee_drag_bps, 5.0, places=5)
        self.assertAlmostEqual(drag.margin_and_funding_drag_bps, 8.0, places=5)
        self.assertAlmostEqual(drag.fx_conversion_drag_bps, 4.0, places=5)
        self.assertAlmostEqual(drag.withholding_tax_drag_bps, 2.0, places=5)
        self.assertAlmostEqual(drag.total_friction_drag_bps, 19.0, places=5)
        self.assertEqual(
            round(
                drag.commission_and_fee_drag_bps
                + drag.margin_and_funding_drag_bps
                + drag.fx_conversion_drag_bps
                + drag.withholding_tax_drag_bps,
                6,
            ),
            drag.total_friction_drag_bps,
        )
        # 30.0 days elapsed -> annualized = 19.0 * (365.0 / 30.0) = 231.166667 bps
        self.assertAlmostEqual(drag.annualized_total_drag_bps, 19.0 * (365.0 / 30.0), places=4)

    def test_autofx_foreign_trade_and_foreign_dividend_spread_drag(self) -> None:
        # Avg NAV = 100,000 USD ($10 = 1 bp).
        # Midpoint EURUSD.FOREX = 1.1000.
        # 1) Buy 100 SAP @ 100 EUR (10,000 EUR notional) with broker AutoFX rate 1.1030 -> $30 spread (3.0 bps)
        # 2) Foreign dividend inflow 1,000 EUR converted at 1.0900 vs 1.1000 -> $10 spread (1.0 bp)
        trades = [
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="fx-eq-1",
                symbol="SAP",
                asset_class=AssetClass.EQUITY,
                side="buy",
                quantity=100.0,
                price=100.0,
                timestamp_utc="2026-01-12T10:00:00Z",
                currency="EUR",
                fx_rate_to_base=1.1030,
            )
        ]
        flows = [
            NormalizedFlow(
                timestamp_utc="2026-01-15T10:00:00Z",
                kind=FlowKind.DIVIDEND,
                amount=1_000.0,
                currency="EUR",
                fx_rate_to_base=1.0900,
            )
        ]
        ledger = _make_base_ledger(
            trades=trades,
            flows=flows,
            conversion_rates={"EURUSD.FOREX": 1.1000},
        )
        drag = compute_cost_and_drag_breakdown(ledger)
        self.assertAlmostEqual(drag.fx_conversion_drag_bps, 4.0, places=5)
        self.assertAlmostEqual(drag.total_friction_drag_bps, 4.0, places=5)


class TestBehaviouralMetricsAndDisposition(unittest.TestCase):
    """Test split-adjusted FIFO matching, Odean PGR/PLR, ATR sizing discipline, and 7-day filter."""

    def test_split_reverse_split_and_symbol_change_fifo_matching(self) -> None:
        trades = [
            # 1) Long 10 shares of NVDA @ $1,000 ($10,000 notional) -> 10-for-1 split -> sell 100 @ $120 (+20%)
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="s1",
                symbol="NVDA",
                asset_class=AssetClass.EQUITY,
                side="buy",
                quantity=10.0,
                price=1000.0,
                timestamp_utc="2026-01-02T14:30:00Z",
            ),
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="s2",
                symbol="NVDA",
                asset_class=AssetClass.EQUITY,
                side="sell",
                quantity=100.0,
                price=120.0,
                timestamp_utc="2026-01-06T14:30:00Z",
            ),
            # 2) Short 500 shares of XYZ @ $2.00 ($1,000 notional) -> 1-for-5 reverse split -> cover 100 @ $8.00 (+20%)
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="r1",
                symbol="XYZ",
                asset_class=AssetClass.EQUITY,
                side="sell",
                quantity=500.0,
                price=2.0,
                timestamp_utc="2026-01-03T15:00:00Z",
            ),
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="r2",
                symbol="XYZ",
                asset_class=AssetClass.EQUITY,
                side="buy",
                quantity=100.0,
                price=8.0,
                timestamp_utc="2026-01-08T15:00:00Z",
            ),
            # 3) Buy FB -> symbol change FB->META -> sell META
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="m1",
                symbol="FB",
                asset_class=AssetClass.EQUITY,
                side="buy",
                quantity=20.0,
                price=200.0,
                timestamp_utc="2026-01-10T15:00:00Z",
            ),
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="m2",
                symbol="META",
                asset_class=AssetClass.EQUITY,
                side="sell",
                quantity=20.0,
                price=220.0,
                timestamp_utc="2026-01-12T15:00:00Z",
            ),
        ]
        actions = [
            CorporateActionRecord(
                action_type=CorporateActionType.SPLIT,
                timestamp_utc="2026-01-05T00:00:00Z",
                symbol="NVDA",
                ratio_numerator=10.0,
                ratio_denominator=1.0,
            ),
            CorporateActionRecord(
                action_type=CorporateActionType.REVERSE_SPLIT,
                timestamp_utc="2026-01-07T00:00:00Z",
                symbol="XYZ",
                ratio_numerator=1.0,
                ratio_denominator=5.0,
            ),
            CorporateActionRecord(
                action_type=CorporateActionType.SYMBOL_CHANGE,
                timestamp_utc="2026-01-11T00:00:00Z",
                symbol="FB",
                new_symbol="META",
            ),
        ]
        ledger = _make_base_ledger(trades=trades, corporate_actions=actions)
        trips = match_fifo_round_trips(ledger)
        self.assertEqual(len(trips), 3)

        nvda_rt, xyz_rt, meta_rt = trips
        self.assertEqual(nvda_rt.symbol, "NVDA")
        self.assertEqual(nvda_rt.side, "long")
        self.assertAlmostEqual(nvda_rt.matched_quantity, 100.0)
        self.assertAlmostEqual(nvda_rt.entry_price, 100.0)
        self.assertAlmostEqual(nvda_rt.net_pnl_base, 2_000.0)
        self.assertAlmostEqual(nvda_rt.return_pct, 20.0)

        self.assertEqual(xyz_rt.symbol, "XYZ")
        self.assertEqual(xyz_rt.side, "short")
        self.assertAlmostEqual(xyz_rt.matched_quantity, 100.0)
        self.assertAlmostEqual(xyz_rt.entry_price, 10.0)
        self.assertAlmostEqual(xyz_rt.net_pnl_base, 200.0)
        self.assertAlmostEqual(xyz_rt.return_pct, 20.0)

        self.assertEqual(meta_rt.symbol, "META")
        self.assertAlmostEqual(meta_rt.net_pnl_base, 400.0)
        self.assertAlmostEqual(meta_rt.return_pct, 10.0)

    def test_sample_size_gates_short_and_long_windows(self) -> None:
        # 12 closed trades over 30 days (< 90d) -> ineligible (gate = 30)
        base_start = datetime(2026, 1, 1, 14, 0, tzinfo=timezone.utc)
        trades_12: list[NormalizedTrade] = []
        for idx in range(12):
            t_in = (base_start + timedelta(days=idx * 2)).strftime("%Y-%m-%dT%H:%M:%SZ")
            t_out = (base_start + timedelta(days=idx * 2, hours=26)).strftime("%Y-%m-%dT%H:%M:%SZ")
            trades_12.append(
                NormalizedTrade(
                    venue="ibkr",
                    native_entry_id=f"b-{idx}",
                    symbol="SPY",
                    asset_class=AssetClass.ETF,
                    side="buy",
                    quantity=10.0,
                    price=500.0,
                    timestamp_utc=t_in,
                )
            )
            trades_12.append(
                NormalizedTrade(
                    venue="ibkr",
                    native_entry_id=f"s-{idx}",
                    symbol="SPY",
                    asset_class=AssetClass.ETF,
                    side="sell",
                    quantity=10.0,
                    price=505.0 if idx % 2 == 0 else 497.0,
                    timestamp_utc=t_out,
                )
            )

        short_ledger = _make_base_ledger(
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            trades=trades_12,
        )
        m_short = compute_behavioural_coaching_metrics(short_ledger)
        self.assertFalse(m_short.sample_eligible)
        self.assertEqual(m_short.min_trades_gate, 30)
        self.assertEqual(m_short.holding_horizon_label, "insufficient_sample")
        self.assertIsNone(m_short.win_rate)

        # Same 12 closed trades over 100 calendar days (>= 90d and >= 10 trades) -> eligible!
        long_ledger = _make_base_ledger(
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-04-11T00:00:00Z",
            trades=trades_12,
        )
        m_long = compute_behavioural_coaching_metrics(long_ledger)
        self.assertTrue(m_long.sample_eligible)
        self.assertEqual(m_long.min_trades_gate, 10)
        self.assertEqual(m_long.observed_trades, 12)
        self.assertEqual(m_long.holding_horizon_label, "multi_day_swing")
        self.assertAlmostEqual(m_long.win_rate or 0.0, 0.5)

    def test_odean_1998_pgr_plr_disposition_spread(self) -> None:
        # Day 1 (2026-01-02): Open AAPL @ 100, MSFT @ 100, INTC @ 100, BA @ 100.
        # Day 2 (2026-01-10): Sell AAPL @ 112 (Realized Gain = 1).
        #   Open at EOD 2026-01-10: MSFT marked @ 108 (Paper Gain = 1),
        #   INTC marked @ 88 (Paper Loss = 1), BA marked @ 91 (Paper Loss = 1).
        # PGR = 1 / (1 + 1) = 0.50; PLR = 0 / (0 + 2) = 0.00 -> Spread = +0.50!
        trades = [
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="o1",
                symbol="AAPL",
                asset_class=AssetClass.EQUITY,
                side="buy",
                quantity=10.0,
                price=100.0,
                timestamp_utc="2026-01-02T15:00:00Z",
            ),
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="o2",
                symbol="MSFT",
                asset_class=AssetClass.EQUITY,
                side="buy",
                quantity=10.0,
                price=100.0,
                timestamp_utc="2026-01-02T15:01:00Z",
            ),
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="o3",
                symbol="INTC",
                asset_class=AssetClass.EQUITY,
                side="buy",
                quantity=10.0,
                price=100.0,
                timestamp_utc="2026-01-02T15:02:00Z",
            ),
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="o4",
                symbol="BA",
                asset_class=AssetClass.EQUITY,
                side="buy",
                quantity=10.0,
                price=100.0,
                timestamp_utc="2026-01-02T15:03:00Z",
            ),
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="o5",
                symbol="AAPL",
                asset_class=AssetClass.EQUITY,
                side="sell",
                quantity=10.0,
                price=112.0,
                timestamp_utc="2026-01-10T19:00:00Z",
            ),
        ]
        ledger = _make_base_ledger(trades=trades)
        self.assertIsNone(compute_odean_disposition_spread(ledger, None))

        marks = {
            "2026-01-10": {
                "MSFT": 108.0,
                "INTC": 88.0,
                "BA": 91.0,
            }
        }
        spread = compute_odean_disposition_spread(ledger, marks)
        self.assertIsNotNone(spread)
        self.assertAlmostEqual(spread or 0.0, 0.5, places=6)

    def test_atr_normalized_post_drawdown_sizing_vs_notional_fallback(self) -> None:
        # Scenario:
        # Near HWM (2026-01-05, NAV = 100,000, DD = 0%):
        #   Trader buys 100 QQQ @ $400 (40% NAV notional). Prior-day ATR_14(2026-01-04) = $5.00
        #   -> ATR risk = 100 * 5 / 100,000 = 0.50% NAV.
        # In 10% Drawdown (2026-01-20, NAV = 90,000, DD = 10% > 5%):
        #   Market volatility spiked 2x: prior-day ATR_14(2026-01-19) = $10.00, QQQ price = $360.
        #   Undisciplined trader buys 135 shares @ $360 = $48,600 (54% NAV notional -> 1.35x notional),
        #   which in ATR units is 135 * $10 / 90,000 = 1.50% NAV -> 3.0x ATR risk escalation!
        nav_points = [
            NormalizedNavPoint(timestamp_utc="2026-01-01T00:00:00Z", nav_base=100_000.0),
            NormalizedNavPoint(timestamp_utc="2026-01-18T00:00:00Z", nav_base=90_000.0),
            NormalizedNavPoint(timestamp_utc="2026-01-31T00:00:00Z", nav_base=92_000.0),
        ]
        trades = [
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="dd-1",
                symbol="QQQ",
                asset_class=AssetClass.ETF,
                side="buy",
                quantity=100.0,
                price=400.0,
                timestamp_utc="2026-01-05T15:00:00Z",
            ),
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="dd-2",
                symbol="QQQ",
                asset_class=AssetClass.ETF,
                side="sell",
                quantity=100.0,
                price=360.0,
                timestamp_utc="2026-01-17T15:00:00Z",
            ),
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="dd-3",
                symbol="QQQ",
                asset_class=AssetClass.ETF,
                side="buy",
                quantity=135.0,
                price=360.0,
                timestamp_utc="2026-01-20T15:00:00Z",
            ),
        ]
        ledger = _make_base_ledger(nav_points=nav_points, trades=trades)

        # Fallback without ATR: (135 * 360 / 90,000) / (100 * 400 / 100,000) = 0.54 / 0.40 = 1.35
        sdi_fallback, is_atr_fb = compute_post_drawdown_sizing_discipline(ledger, atr_14_series=None)
        self.assertFalse(is_atr_fb)
        self.assertAlmostEqual(sdi_fallback or 0.0, 1.35, places=6)

        # Causal ATR_14(t-1) provided: (135 * 10 / 90,000) / (100 * 5 / 100,000) = 0.015 / 0.005 = 3.0
        atr_series = {
            "QQQ": {
                "2026-01-04": 5.0,
                "2026-01-05": 99.0,  # Same-day bar must NOT leak into causal t-1 lookup!
                "2026-01-19": 10.0,
                "2026-01-20": 99.0,
            }
        }
        sdi_atr, is_atr = compute_post_drawdown_sizing_discipline(ledger, atr_14_series=atr_series)
        self.assertTrue(is_atr)
        self.assertAlmostEqual(sdi_atr or 0.0, 3.0, places=6)

    def test_extract_delayed_closed_trades_strips_recent_and_redacts_dollars(self) -> None:
        trades = [
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="old-in",
                symbol="AAPL",
                asset_class=AssetClass.EQUITY,
                side="buy",
                quantity=50.0,
                price=200.0,
                timestamp_utc="2026-01-10T15:00:00Z",
            ),
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="old-out",
                symbol="AAPL",
                asset_class=AssetClass.EQUITY,
                side="sell",
                quantity=50.0,
                price=210.0,
                timestamp_utc="2026-01-15T15:00:00Z",  # 16 days before Jan 31 -> keep
            ),
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="recent-in",
                symbol="MSFT",
                asset_class=AssetClass.EQUITY,
                side="buy",
                quantity=25.0,
                price=400.0,
                timestamp_utc="2026-01-26T15:00:00Z",
            ),
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="recent-out",
                symbol="MSFT",
                asset_class=AssetClass.EQUITY,
                side="sell",
                quantity=25.0,
                price=420.0,
                timestamp_utc="2026-01-28T15:00:00Z",  # Only 3 days before Jan 31 (< 7d) -> strip!
            ),
        ]
        ledger = _make_base_ledger(trades=trades)
        trips = match_fifo_round_trips(ledger)
        self.assertEqual(len(trips), 2)

        delayed = extract_delayed_closed_trades(
            trips,
            as_of_utc="2026-01-31T15:00:00Z",
            min_delay_days=7,
        )
        self.assertEqual(len(delayed), 1)
        self.assertEqual(delayed[0].symbol, "AAPL")
        self.assertAlmostEqual(delayed[0].return_pct, 5.0)
        serialized = delayed[0].to_dict()
        for forbidden_key in ("quantity", "matched_quantity", "price", "entry_price", "net_pnl_base"):
            self.assertNotIn(forbidden_key, serialized)

    def test_thirty_intraday_option_trades_and_external_withdrawal_drawdown_immunity(self) -> None:
        # 30 intraday option round-trips (multiplier=100) over 20 days -> sample_eligible=True, gate=30
        base_dt = datetime(2026, 1, 2, 14, 30, tzinfo=timezone.utc)
        trades: list[NormalizedTrade] = []
        for idx in range(30):
            t_in = (base_dt + timedelta(hours=idx * 12)).strftime("%Y-%m-%dT%H:%M:%SZ")
            t_out = (base_dt + timedelta(hours=idx * 12 + 3)).strftime("%Y-%m-%dT%H:%M:%SZ")
            win = idx < 18  # 18 wins (+$100/contract), 12 losses (-$50/contract) -> win_rate = 0.60, PF = 3.0
            trades.append(
                NormalizedTrade(
                    venue="ibkr",
                    native_entry_id=f"opt-b-{idx}",
                    symbol="AAPL260220C00200000",
                    underlying_symbol="AAPL",
                    asset_class=AssetClass.OPTION,
                    option_right="C",
                    strike=200.0,
                    expiry="2026-02-20",
                    side="buy",
                    quantity=2.0,
                    price=5.0,
                    multiplier=100.0,
                    timestamp_utc=t_in,
                )
            )
            trades.append(
                NormalizedTrade(
                    venue="ibkr",
                    native_entry_id=f"opt-s-{idx}",
                    symbol="AAPL260220C00200000",
                    underlying_symbol="AAPL",
                    asset_class=AssetClass.OPTION,
                    option_right="C",
                    strike=200.0,
                    expiry="2026-02-20",
                    side="sell",
                    quantity=2.0,
                    price=6.0 if win else 4.5,
                    multiplier=100.0,
                    timestamp_utc=t_out,
                )
            )

        # Include a $20,000 external cash withdrawal on Jan 10: NAV drops 100k -> 80k purely from withdrawal
        # (0% trading drawdown -> post_drawdown_sizing_discipline_atr must stay None!).
        nav_pts = [
            NormalizedNavPoint(timestamp_utc="2026-01-01T00:00:00Z", nav_base=100_000.0),
            NormalizedNavPoint(timestamp_utc="2026-01-11T00:00:00Z", nav_base=80_000.0),
            NormalizedNavPoint(timestamp_utc="2026-01-25T00:00:00Z", nav_base=81_200.0),
        ]
        flows = [
            NormalizedFlow(
                timestamp_utc="2026-01-10T12:00:00Z",
                kind=FlowKind.WITHDRAWAL,
                amount=-20_000.0,
            )
        ]
        ledger = _make_base_ledger(
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-25T00:00:00Z",
            nav_points=nav_pts,
            trades=trades,
            flows=flows,
        )
        metrics = compute_behavioural_coaching_metrics(ledger)
        self.assertTrue(metrics.sample_eligible)
        self.assertEqual(metrics.min_trades_gate, 30)
        self.assertEqual(metrics.holding_horizon_label, "intraday")
        self.assertAlmostEqual(metrics.median_holding_hours or 0.0, 3.0)
        self.assertAlmostEqual(metrics.win_rate or 0.0, 0.60)
        self.assertAlmostEqual(metrics.profit_factor or 0.0, 3.0)
        self.assertAlmostEqual(metrics.winner_vs_loser_hold_ratio or 0.0, 1.0)
        self.assertIsNone(metrics.post_drawdown_sizing_discipline_atr)


class TestCatalystIntervalsAndFeeds(unittest.TestCase):
    """Test SEC EDGAR 'Z' quirk, Reg S-T filingDate roll trap, press-wire fusion, EODHD & ALFRED."""

    def test_sec_edgar_z_quirk_winter_est_summer_edt_and_reg_st_roll(self) -> None:
        # 1. Winter EST (UTC-05:00): 18:05:12 ET on Jan 15 -> 23:05:12Z on Jan 15!
        winter_utc = normalize_sec_acceptance_timestamp_utc("2026-01-15T18:05:12.000Z")
        self.assertEqual(winter_utc, "2026-01-15T23:05:12Z")

        # 2. Summer EDT (UTC-04:00): 16:30:05 ET on Jul 15 (both ISO with Z and 14-digit compact) -> 20:30:05Z!
        summer_iso_utc = normalize_sec_acceptance_timestamp_utc("2026-07-15T16:30:05.000Z")
        summer_compact_utc = normalize_sec_acceptance_timestamp_utc("20260715163005")
        self.assertEqual(summer_iso_utc, "2026-07-15T20:30:05Z")
        self.assertEqual(summer_compact_utc, "2026-07-15T20:30:05Z")
        self.assertEqual(
            parse_sec_acceptance_datetime_utc("2026-07-15T16:30:05.000Z"),
            datetime(2026, 7, 15, 20, 30, 5, tzinfo=timezone.utc),
        )

        # 3. Post-17:30 ET Reg S-T roll-forward trap in submissions/CIK{10d}.json:
        # Accepted Jan 15 at 18:05:12 ET (23:05:12Z), but Reg S-T filingDate rolled to "2026-01-16"!
        submissions_json = {
            "cik": "320193",
            "tickers": ["AAPL"],
            "filings": {
                "recent": {
                    "accessionNumber": ["0000320193-26-000010"],
                    "filingDate": ["2026-01-16"],
                    "acceptanceDateTime": ["2026-01-15T18:05:12.000Z"],
                    "form": ["8-K"],
                    "items": [["2.02", "9.01"]],
                    "primaryDocDescription": ["FORM 8-K"],
                }
            },
        }
        filings = parse_submissions_payload(submissions_json, symbol="AAPL")
        self.assertEqual(len(filings), 1)
        f0 = filings[0]
        self.assertEqual(f0.cik_10d, "0000320193")
        self.assertTrue(f0.reg_st_filing_date_rolled)
        self.assertEqual(f0.acceptance_timestamp_utc, "2026-01-15T23:05:12Z")
        self.assertEqual(f0.confirmed_public_utc, "2026-01-15T23:08:12Z")  # +180s lag

        # An after-hours execution at 23:15:00Z on Jan 15 (18:15 ET) MUST be POST_CONFIRMED_CATALYST,
        # never misclassified as pre-filing relative to filingDate "2026-01-16"!
        intervals = build_catalyst_intervals(sec_filings=filings)
        obs = classify_trade_against_intervals(
            symbol="AAPL",
            trade_timestamp_utc="2026-01-15T23:15:00Z",
            intervals=intervals,
        )
        self.assertEqual(obs.alignment_class, CatalystAlignmentClass.POST_CONFIRMED_CATALYST)

    def test_sec_user_agent_validation_and_client_transport(self) -> None:
        with self.assertRaises(ValueError):
            validate_sec_user_agent("")
        with self.assertRaises(ValueError):
            validate_sec_user_agent("python-urllib/3.14")
        with self.assertRaises(ValueError):
            validate_sec_user_agent("MissingEmailAgent/1.0")

        captured_headers: dict[str, str] = {}

        def fake_sec_transport(url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]:
            del timeout
            captured_headers.update(headers)
            self.assertTrue(url.endswith("/submissions/CIK0000320193.json"))
            return {
                "cik": "320193",
                "tickers": ["AAPL"],
                "filings": {
                    "recent": {
                        "accessionNumber": ["0000320193-26-000012"],
                        "filingDate": ["2026-07-15"],
                        "acceptanceDateTime": ["2026-07-15T16:30:05.000Z"],
                        "form": ["8-K"],
                        "items": [["8.01"]],
                        "primaryDocDescription": ["8-K"],
                    }
                },
            }

        client = SecEdgarClient(
            user_agent="N170VerifyUnitTest/0.3 (sec-test@n170.io)",
            cik_map={"AAPL": 320193},
            transport=fake_sec_transport,
        )
        self.assertEqual(format_cik_10d(320193), "0000320193")
        res = client.fetch_company_filings("AAPL")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].acceptance_timestamp_utc, "2026-07-15T20:30:05Z")
        self.assertEqual(captured_headers.get("User-Agent"), "N170VerifyUnitTest/0.3 (sec-test@n170.io)")

    def test_press_wire_preceding_8k_interval_fusion_without_false_anomaly(self) -> None:
        # BusinessWire press release Tuesday 2026-01-27 13:00:00Z (2 business days before Thursday 8-K!)
        # Follow-up Form 8-K accepted Thursday 2026-01-29 16:10:00 ET (21:10:00Z, confirmed 21:13:00Z).
        # Fused interval I_e = [2026-01-27T13:00:00Z, 2026-01-29T21:13:00Z].
        filings = parse_submissions_payload(
            {
                "cik": "789019",
                "tickers": ["MSFT"],
                "filings": {
                    "recent": {
                        "accessionNumber": ["0000789019-26-000005"],
                        "filingDate": ["2026-01-29"],
                        "acceptanceDateTime": ["2026-01-29T16:10:00.000Z"],
                        "form": ["8-K"],
                        "items": [["1.01"]],
                        "primaryDocDescription": ["MATERIAL AGREEMENT"],
                    }
                },
            },
            symbol="MSFT",
        )
        wire = EodhdNewsEvent(
            symbol="MSFT",
            eodhd_symbol="MSFT.US",
            published_utc="2026-01-27T13:00:00Z",
            title="Microsoft Announces Strategic Cloud Agreement via Business Wire",
            source_wire="businesswire",
            is_press_wire=True,
        )

        # Verify 4-business-day lookback across weekend: Monday minus 4 bdays = prior Tuesday.
        mon_dt = datetime(2026, 1, 26, 21, 0, tzinfo=timezone.utc)
        self.assertEqual(
            subtract_business_days(mon_dt, 4),
            datetime(2026, 1, 20, 21, 0, tzinfo=timezone.utc),
        )

        intervals = build_catalyst_intervals(sec_filings=filings, eodhd_news=[wire])
        self.assertEqual(len(intervals), 1)
        iv = intervals[0]
        self.assertEqual(iv.earliest_public_utc, "2026-01-27T13:00:00Z")
        self.assertEqual(iv.confirmed_public_utc, "2026-01-29T21:13:00Z")
        self.assertIn("businesswire", iv.event_sources)
        self.assertIn("sec_edgar_8k", iv.event_sources)

        # Trade AFTER BusinessWire (2026-01-27T14:00:00Z) and BEFORE Thursday's 8-K:
        # Must classify as AMBIGUOUS_PUBLIC_WINDOW (t_trade in I_e), NOT PRIOR_TO_EARLIEST_RECORDED_CATALYST!
        obs_between = classify_trade_against_intervals(
            symbol="MSFT",
            trade_timestamp_utc="2026-01-27T14:00:00Z",
            intervals=intervals,
        )
        self.assertEqual(obs_between.alignment_class, CatalystAlignmentClass.AMBIGUOUS_PUBLIC_WINDOW)
        self.assertFalse(contains_forbidden_claim(obs_between.timestamp_uncertainty_note))

        # Trade 2 hours BEFORE BusinessWire -> PRIOR_TO_EARLIEST_RECORDED_CATALYST (still neutral!)
        obs_before = classify_trade_against_intervals(
            symbol="MSFT",
            trade_timestamp_utc="2026-01-27T11:00:00Z",
            intervals=intervals,
        )
        self.assertEqual(
            obs_before.alignment_class,
            CatalystAlignmentClass.PRIOR_TO_EARLIEST_RECORDED_CATALYST,
        )
        self.assertFalse(contains_forbidden_claim(obs_before.timestamp_uncertainty_note))

        # Trade 10 days earlier -> QUIET_NON_CATALYST_REGIME
        obs_quiet = classify_trade_against_intervals(
            symbol="MSFT",
            trade_timestamp_utc="2026-01-12T15:00:00Z",
            intervals=intervals,
        )
        self.assertEqual(obs_quiet.alignment_class, CatalystAlignmentClass.QUIET_NON_CATALYST_REGIME)

    def test_eodhd_weight_tracking_and_api_token_redaction(self) -> None:
        self.assertEqual(format_eodhd_symbol("AAPL", "NASDAQ"), "AAPL.US")
        self.assertEqual(format_eodhd_symbol("BRK.B", "NYSE"), "BRK-B.US")

        def mock_ok_transport(url: str, headers: dict[str, str], timeout: float) -> list[dict[str, Any]]:
            del headers, timeout
            if "/api/news" in url:
                self.assertIn("fmt=json", url)
                return [
                    {
                        "date": "2026-01-29T21:01:00+00:00",
                        "title": "PR Newswire: Q4 Earnings Release",
                        "content": "PR Newswire release body",
                        "link": "https://example.com/pr",
                        "tags": ["EARNINGS"],
                    }
                ]
            return [
                {
                    "type": "CPI YoY",
                    "country": "US",
                    "date": "2026-01-14 13:30:00",
                    "actual": 2.9,
                    "estimate": 2.8,
                }
            ]

        client = EodhdEventsClient(api_key="synth_eodhd_token_998877", transport=mock_ok_transport)
        news = client.fetch_company_news("AAPL", "2026-01-01", "2026-01-31")
        econ = client.fetch_economic_events("2026-01-01", "2026-01-31")
        self.assertEqual(len(news), 1)
        self.assertTrue(news[0].is_press_wire)
        self.assertEqual(news[0].published_utc, "2026-01-29T21:01:00Z")
        self.assertEqual(len(econ), 1)
        self.assertEqual(econ[0].released_utc, "2026-01-14T13:30:00Z")
        self.assertEqual(
            client.consumed_api_weight,
            EODHD_NEWS_CALL_WEIGHT + EODHD_ECONOMIC_EVENTS_CALL_WEIGHT,
        )

        # Failure path MUST redact api_token from exception string!
        secret_tok = "ultra_sensitive_eodhd_tok_12345"

        def failing_transport(url: str, headers: dict[str, str], timeout: float) -> Any:
            del headers, timeout
            raise urllib.error.URLError(f"HTTP 401 Unauthorized for {url}")

        bad_client = EodhdEventsClient(api_key=secret_tok, transport=failing_transport)
        with self.assertRaises(EodhdApiError) as ctx:
            bad_client.fetch_company_news("AAPL", "2026-01-01", "2026-01-31")
        self.assertNotIn(secret_tok, str(ctx.exception))
        self.assertIn("[REDACTED]", str(ctx.exception))

    def test_alfred_point_in_time_vintage_and_gdelt_90d_fallback(self) -> None:
        # January 2026 CPI ('date' = 2026-01-01) was first released on 2026-02-12 (realtime_start)
        # and later revised on 2026-03-12. Initial release at 08:30 EST -> 13:30:00Z!
        alfred_payload = {
            "observations": [
                {"date": "2026-01-01", "realtime_start": "2026-02-12", "value": "317.5"},
                {"date": "2026-01-01", "realtime_start": "2026-03-12", "value": "317.6"},
            ]
        }
        releases = parse_alfred_observations_payload(
            "CPIAUCSL",
            alfred_payload,
            initial_releases_only=True,
        )
        self.assertEqual(len(releases), 1)
        self.assertEqual(releases[0].observation_period_date, "2026-01-01")
        self.assertEqual(releases[0].vintage_release_date, "2026-02-12")
        self.assertEqual(releases[0].earliest_public_utc, "2026-02-12T13:30:00Z")
        self.assertAlmostEqual(releases[0].unrevised_value or 0.0, 317.5)

        # FRED key redaction on error
        fred_secret = "synth_fred_secret_key_5544"
        fred_bad = FredAlfredClient(
            api_key=fred_secret,
            transport=lambda url, h, t: (_ for _ in ()).throw(RuntimeError(f"boom {url}")),
        )
        with self.assertRaises(FredAlfredApiError) as fctx:
            fred_bad.fetch_vintage_dates("CPIAUCSL")
        self.assertNotIn(fred_secret, str(fctx.exception))

        # GDELT <90d guard: window 120 days old returns empty + retention_truncated=True without HTTP call
        gdelt_calls = 0

        def mock_gdelt(url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]:
            nonlocal gdelt_calls
            del url, headers, timeout
            gdelt_calls += 1
            return {
                "articles": [
                    {
                        "seendate": "20260128T133000Z",
                        "title": "GlobeNewswire: Product Launch",
                        "domain": "globenewswire.com",
                        "url": "https://globenewswire.com/story",
                    }
                ]
            }

        gdelt = GdeltDocFallbackClient(transport=mock_gdelt)
        old_arts, old_trunc = gdelt.fetch_recent_articles(
            "NVDA",
            "2025-08-01T00:00:00Z",
            "2025-08-15T00:00:00Z",
            reference_now_utc="2026-02-01T00:00:00Z",
        )
        self.assertEqual(old_arts, [])
        self.assertTrue(old_trunc)
        self.assertEqual(gdelt_calls, 0)

        recent_arts, recent_trunc = gdelt.fetch_recent_articles(
            "NVDA",
            "2026-01-20T00:00:00Z",
            "2026-01-30T00:00:00Z",
            reference_now_utc="2026-02-01T00:00:00Z",
        )
        self.assertFalse(recent_trunc)
        self.assertEqual(len(recent_arts), 1)
        self.assertTrue(recent_arts[0].is_press_wire)
        self.assertEqual(recent_arts[0].published_utc, "2026-01-28T13:30:00Z")


class TestSmallLlmCoachAndEngine(unittest.TestCase):
    """Test local small-LLM PII/dollar redaction, <2,500 token cap, claim-safety filter, and fallback."""

    def _build_eligible_ledger(self) -> CanonicalPortfolioLedger:
        # 12 closed round-trips over 100 calendar days (>= 90d & >= 10 trades -> sample_eligible=True)
        start = datetime(2026, 1, 2, 14, 30, tzinfo=timezone.utc)
        trades: list[NormalizedTrade] = []
        for idx in range(12):
            t_buy = (start + timedelta(days=idx * 6)).strftime("%Y-%m-%dT%H:%M:%SZ")
            t_sell = (start + timedelta(days=idx * 6 + 2)).strftime("%Y-%m-%dT%H:%M:%SZ")
            exit_px = 106.0 if idx < 8 else 96.0
            trades.append(
                NormalizedTrade(
                    venue="ibkr",
                    native_entry_id=f"eb-{idx}",
                    symbol="AAPL",
                    asset_class=AssetClass.EQUITY,
                    side="buy",
                    quantity=25.0,
                    price=100.0,
                    timestamp_utc=t_buy,
                    commission=1.5,
                )
            )
            trades.append(
                NormalizedTrade(
                    venue="ibkr",
                    native_entry_id=f"es-{idx}",
                    symbol="AAPL",
                    asset_class=AssetClass.EQUITY,
                    side="sell",
                    quantity=25.0,
                    price=exit_px,
                    timestamp_utc=t_sell,
                    commission=1.5,
                )
            )
        return _make_base_ledger(
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-04-15T00:00:00Z",
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-01-01T00:00:00Z", nav_base=250_000.0),
                NormalizedNavPoint(timestamp_utc="2026-04-15T00:00:00Z", nav_base=252_000.0),
            ],
            trades=trades,
        )

    def test_llm_prompt_redaction_token_budget_and_valid_generation(self) -> None:
        ledger = self._build_eligible_ledger()
        captured_req: dict[str, Any] = {}

        def fake_ollama_transport(
            url: str,
            body: dict[str, Any],
            headers: dict[str, str],
            timeout: float,
        ) -> dict[str, Any]:
            captured_req["url"] = url
            captured_req["body"] = body
            captured_req["headers"] = headers
            captured_req["timeout"] = timeout
            return {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "style_summary": "Multi-day equity swing profile with consistent 2-day holding periods and positive payoff skew.",
                                    "coaching_takeaways": [
                                        "Maintain passive entry execution to preserve low commission drag.",
                                        "Continue sizing positions uniformly across volatility regimes.",
                                    ],
                                }
                            )
                        }
                    }
                ]
            }

        llm = SmallLlmCoachClient(
            base_url="http://127.0.0.1:11434/v1",
            model_id="qwen2.5:7b-instruct",
            transport=fake_ollama_transport,
        )
        engine = TraderCoachingEngine(llm_client=llm)
        out = engine.evaluate(ledger, as_of_utc="2026-04-15T00:00:00Z")

        self.assertTrue(out.report.llm_narrative_used)
        self.assertEqual(out.report.llm_model_id, "qwen2.5:7b-instruct")
        self.assertFalse(out.llm_safety_filter_triggered)
        self.assertEqual(captured_req["body"]["temperature"], DEFAULT_LLM_TEMPERATURE)
        self.assertEqual(captured_req["timeout"], DEFAULT_LLM_TIMEOUT_SECONDS)

        # Ensure outgoing prompt contains ZERO account tags, ZERO raw NAV dollars, and <2,500 tokens!
        serialized_messages = json.dumps(captured_req["body"]["messages"])
        self.assertNotIn(ledger.blinded_account_tag, serialized_messages)
        self.assertNotIn("250000", serialized_messages)
        self.assertNotIn("252000", serialized_messages)
        self.assertNotIn("$", serialized_messages)
        self.assertLess(estimate_prompt_tokens(serialized_messages), MAX_SUMMARY_PROMPT_TOKENS)

        # Round-trip contract validation
        reconstructed = TraderCoachingAndContextReport.from_dict(out.report.to_dict())
        self.assertEqual(reconstructed, out.report)

    def test_claim_safety_filter_rejects_all_prohibited_hallucinations_and_falls_back(self) -> None:
        ledger = self._build_eligible_ledger()
        hallucinated_cases = [
            "Execution timing suggests potential insider access ahead of announcements.",
            "Trades appear correlated with MNPI prior to press release.",
            "Pattern indicates possible securities fraud in account statements.",
            "Activity may be intended to de" + "fraud counterparties.",
            "Order book entries appear to manipulate closing auction prices.",
            "Allocation timestamps look backdated relative to filing acceptance.",
            "Account grew from $250,000 to $252,000 over the quarter.",
        ]

        for bad_sentence in hallucinated_cases:
            with self.subTest(bad_sentence=bad_sentence):
                bad_llm = SmallLlmCoachClient(
                    base_url="http://127.0.0.1:11434/v1",
                    model_id="llama3.2:3b",
                    transport=lambda u, b, h, t, s=bad_sentence: {
                        "choices": [
                            {
                                "message": {
                                    "content": json.dumps(
                                        {
                                            "style_summary": s,
                                            "coaching_takeaways": ["Review execution timing."],
                                        }
                                    )
                                }
                            }
                        ]
                    },
                )
                out = TraderCoachingEngine(llm_client=bad_llm).evaluate(ledger)
                self.assertFalse(out.report.llm_narrative_used)
                self.assertIsNone(out.report.llm_model_id)
                self.assertTrue(out.llm_safety_filter_triggered)
                self.assertFalse(contains_forbidden_claim(out.report.style_summary))
                for takeaway in out.report.coaching_takeaways:
                    self.assertFalse(contains_forbidden_claim(takeaway))

    def test_offline_and_network_failure_deterministic_fallback(self) -> None:
        ledger = self._build_eligible_ledger()

        # 1. Unconfigured local LLM -> deterministic offline fallback
        unconfigured = SmallLlmCoachClient(base_url="")
        rep1 = build_trader_coaching_report(ledger, llm_client=unconfigured)
        self.assertFalse(rep1.llm_narrative_used)
        self.assertIsNone(rep1.llm_model_id)
        self.assertTrue(rep1.style_summary)

        # 2. Connection refused / timeout -> identical deterministic fallback
        failing_llm = SmallLlmCoachClient(
            base_url="http://127.0.0.1:11434/v1",
            transport=lambda u, b, h, t: (_ for _ in ()).throw(TimeoutError("12s timeout")),
        )
        rep2 = build_trader_coaching_report(ledger, llm_client=failing_llm)
        self.assertFalse(rep2.llm_narrative_used)
        self.assertIsNone(rep2.llm_model_id)
        self.assertEqual(rep1.style_summary, rep2.style_summary)
        self.assertEqual(rep1.coaching_takeaways, rep2.coaching_takeaways)

        # Confirm every forbidden substring is known to the safety detector
        for term in FORBIDDEN_CLAIM_SUBSTRINGS:
            self.assertTrue(contains_forbidden_claim(f"Sample text with {term.upper()} token"))

        # Confirm redacted summary payload builder emits dimensionless numbers only
        redacted_payload = build_redacted_summary_payload(
            cost_drag=rep1.cost_drag,
            behaviour=rep1.behaviour,
            catalyst_regime_win_rate=0.65,
            quiet_regime_win_rate=0.52,
            event_window_share_pct=25.0,
        )
        self.assertIn("cost_drag_bps", redacted_payload)
        self.assertIn("behaviour", redacted_payload)
        self.assertIn("catalyst_context", redacted_payload)

    def test_catalyst_and_quiet_regime_win_rate_split_in_engine(self) -> None:
        # 2 catalyst trades (both winners -> 100% win rate) + 2 quiet trades (1 win, 1 loss -> 50% win rate)
        filings = parse_submissions_payload(
            {
                "cik": "320193",
                "tickers": ["AAPL"],
                "filings": {
                    "recent": {
                        "accessionNumber": ["0000320193-26-000001", "0000320193-26-000002"],
                        "filingDate": ["2026-01-05", "2026-02-05"],
                        "acceptanceDateTime": [
                            "2026-01-05T08:00:00.000Z",
                            "2026-02-05T08:00:00.000Z",
                        ],
                        "form": ["8-K", "8-K"],
                        "items": [["2.02"], ["2.02"]],
                        "primaryDocDescription": ["8-K", "8-K"],
                    }
                },
            },
            symbol="AAPL",
        )
        trades = [
            # Catalyst round-trip 1 (post-confirmed on Jan 5 -> win)
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="c1-b",
                symbol="AAPL",
                asset_class=AssetClass.EQUITY,
                side="buy",
                quantity=10.0,
                price=100.0,
                timestamp_utc="2026-01-05T14:00:00Z",
            ),
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="c1-s",
                symbol="AAPL",
                asset_class=AssetClass.EQUITY,
                side="sell",
                quantity=10.0,
                price=108.0,
                timestamp_utc="2026-01-07T15:00:00Z",
            ),
            # Catalyst round-trip 2 (post-confirmed on Feb 5 -> win)
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="c2-b",
                symbol="AAPL",
                asset_class=AssetClass.EQUITY,
                side="buy",
                quantity=10.0,
                price=110.0,
                timestamp_utc="2026-02-05T14:00:00Z",
            ),
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="c2-s",
                symbol="AAPL",
                asset_class=AssetClass.EQUITY,
                side="sell",
                quantity=10.0,
                price=115.0,
                timestamp_utc="2026-02-09T15:00:00Z",
            ),
            # Quiet round-trip 1 (Jan 15 -> win)
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="q1-b",
                symbol="AAPL",
                asset_class=AssetClass.EQUITY,
                side="buy",
                quantity=10.0,
                price=105.0,
                timestamp_utc="2026-01-15T15:00:00Z",
            ),
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="q1-s",
                symbol="AAPL",
                asset_class=AssetClass.EQUITY,
                side="sell",
                quantity=10.0,
                price=109.0,
                timestamp_utc="2026-01-16T15:00:00Z",
            ),
            # Quiet round-trip 2 (Jan 22 -> loss)
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="q2-b",
                symbol="AAPL",
                asset_class=AssetClass.EQUITY,
                side="buy",
                quantity=10.0,
                price=109.0,
                timestamp_utc="2026-01-22T15:00:00Z",
            ),
            NormalizedTrade(
                venue="ibkr",
                native_entry_id="q2-s",
                symbol="AAPL",
                asset_class=AssetClass.EQUITY,
                side="sell",
                quantity=10.0,
                price=104.0,
                timestamp_utc="2026-01-23T15:00:00Z",
            ),
        ]
        ledger = _make_base_ledger(
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-02-20T00:00:00Z",
            trades=trades,
        )
        ctx = evaluate_portfolio_catalyst_context(ledger, sec_filings=filings)
        self.assertAlmostEqual(ctx.catalyst_regime_win_rate or 0.0, 1.0, places=6)
        self.assertAlmostEqual(ctx.quiet_regime_win_rate or 0.0, 0.5, places=6)
        # 2 of 8 execution fills (the two catalyst entries) fell within 24h of the two 8-Ks -> 25%
        self.assertAlmostEqual(ctx.event_window_share_pct, 25.0, places=6)

    def test_httpx_style_client_transport_and_fenced_json_parsing(self) -> None:
        ledger = self._build_eligible_ledger()

        class _FakeResponse:
            def __init__(self, payload: Any) -> None:
                self._payload = payload

            def raise_for_status(self) -> None:
                return None

            def json(self) -> Any:
                return self._payload

        class _FakeHttpxClient:
            def get(self, url: str, *, headers: dict[str, str], timeout: float) -> _FakeResponse:
                del url, headers, timeout
                return _FakeResponse([])

            def post(
                self,
                url: str,
                *,
                json: dict[str, Any],
                headers: dict[str, str],
                timeout: float,
            ) -> _FakeResponse:
                del url, json, headers, timeout
                fenced = (
                    "```json\n"
                    '{"style_summary": "Disciplined multi-day swing execution.", '
                    '"coaching_takeaways": ["Keep tracking venue fee tiers."]}\n'
                    "```"
                )
                return _FakeResponse({"choices": [{"message": {"content": fenced}}]})

        fake_client = _FakeHttpxClient()
        eodhd = EodhdEventsClient(api_key="synth_key_1234", transport=fake_client)
        self.assertEqual(eodhd.fetch_company_news("AAPL", "2026-01-01", "2026-01-10"), [])

        llm = SmallLlmCoachClient(
            base_url="http://127.0.0.1:8000/v1",
            model_id="llama3.2:3b",
            transport=fake_client,
        )
        out = TraderCoachingEngine(llm_client=llm, eodhd_client=eodhd).evaluate(ledger)
        self.assertTrue(out.report.llm_narrative_used)
        self.assertEqual(out.report.llm_model_id, "llama3.2:3b")
        self.assertEqual(out.report.style_summary, "Disciplined multi-day swing execution.")

    def test_zero_coupling_to_legacy_monorepo_packages(self) -> None:
        loaded_legacy = [
            mod
            for mod in sys.modules
            if mod == "n170" or mod.startswith("n170.")
        ]
        self.assertEqual(loaded_legacy, [])


if __name__ == "__main__":
    unittest.main()
