"""Regression tests for Round 4 core findings (F1-F7, SEC-02/04/05/08/09/13)."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import time
import unittest

from n170_verify.coaching import (
    TraderCoachingEngine,
    build_deterministic_coaching_narrative,
    build_redacted_summary_payload,
    compute_behavioural_coaching_metrics,
    compute_cost_and_drag_breakdown,
    compute_quant_dna_profile,
    match_fifo_round_trips,
    simulate_counterfactual_twin,
)
from n170_verify.connectors import HyperliquidPublicReadOnlyAdapter
from n170_verify.connectors.ibkr_flex import _FLEX_XXE_DECL_RE, _XML_ENCODING_DECL_RE
from n170_verify.connectors.journal_migration import parse_journal_migration_csv
from n170_verify.connectors.mt5_tradovate import (
    _MT_ACCOUNT_RE,
    _MT_CURRENCY_RE,
    parse_mt4_statement,
    parse_mt5_statement,
    parse_tradovate_csv,
)
from n170_verify.connectors.statement_csv import (
    _XXE_DECL_SYSTEM_PUBLIC_RE,
    _parse_localized_float,
    parse_degiro_csv_bundle,
)
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    CanonicalPortfolioLedger,
    CorporateActionRecord,
    CorporateActionType,
    CostAndDragBreakdown,
    EnvironmentTier,
    FlowKind,
    HolderClaimStatus,
    NormalizedFlow,
    NormalizedNavPoint,
    NormalizedTrade,
    OriginAssurance,
    ProviderApprovalState,
    VerifyProofBundle,
    create_signed_proof_bundle,
    verify_proof_bundle,
)
from n170_verify.contracts.proof import (
    HOLDER_SCHEMA_VERSION,
    SIGNING_DOMAIN_HOLDER,
    _HOLDER_HANDLE_RE,
)
from n170_verify.crypto import (
    CANONICAL_LEAF_NAMES,
    ed25519_sign_domain,
    generate_ed25519_keypair,
    jcs_canonicalize,
)
from n170_verify.performance.calculator import calculate_portfolio_performance_detailed
from n170_verify.pipeline import (
    _WORKER_SERVER_ONLY_FETCH_KEYS,
    api_worker_pipeline_entrypoint,
    verify_portfolio,
)


def _make_ledger(
    *,
    nav_points: list[NormalizedNavPoint],
    trades: list[NormalizedTrade] | None = None,
    flows: list[NormalizedFlow] | None = None,
    corporate_actions: list[CorporateActionRecord] | None = None,
    enabled_sections: list[str] | None = None,
    period_start_utc: str | None = None,
    period_end_utc: str | None = None,
    broker_id: str = "ibkr_flex_offline",
) -> CanonicalPortfolioLedger:
    start = period_start_utc or (
        nav_points[0].timestamp_utc if nav_points else "2025-01-01T00:00:00Z"
    )
    end = period_end_utc or (
        nav_points[-1].timestamp_utc if nav_points else "2026-02-01T00:00:00Z"
    )
    return CanonicalPortfolioLedger(
        blinded_account_tag="ab" * 32,
        broker_id=broker_id,
        account_scope=AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED,
        claimed_origin_assurance=OriginAssurance.SELF_REPORTED,
        provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
        environment_tier=EnvironmentTier.LIVE_PRODUCTION,
        source_body_sha256="cd" * 32,
        base_currency="USD",
        period_start_utc=start,
        period_end_utc=end,
        nav_points=nav_points,
        flows=flows or [],
        trades=trades or [],
        corporate_actions=corporate_actions or [],
        enabled_sections=enabled_sections or [],
    )


class TestF1AnnualisedFiguresWithheld(unittest.TestCase):
    def test_xirr_withheld_when_annualization_withheld_or_span_under_365_days(self) -> None:
        two_pt_ledger = _make_ledger(
            nav_points=[
                NormalizedNavPoint("2025-01-01T23:59:59Z", 50_000.0),
                NormalizedNavPoint("2026-02-05T23:59:59Z", 62_000.0),
            ],
            flows=[
                NormalizedFlow(
                    timestamp_utc="2025-06-01T12:00:00Z",
                    kind=FlowKind.DEPOSIT,
                    amount=5_000.0,
                    currency="USD",
                )
            ],
        )
        two_pt_res = calculate_portfolio_performance_detailed(two_pt_ledger)
        self.assertIsNone(two_pt_res.annualization_periods_per_year)
        self.assertIsNone(two_pt_res.summary.xirr_decimal)
        self.assertTrue(
            any("XIRR" in w for w in two_pt_res.summary.warnings), two_pt_res.summary.warnings
        )

        short_nav = [
            NormalizedNavPoint(f"2026-01-{day:02d}T23:59:59Z", 50_000.0 + day * 100.0)
            for day in range(1, 32)
        ]
        short_ledger = _make_ledger(
            nav_points=short_nav,
            flows=[
                NormalizedFlow(
                    timestamp_utc="2026-01-15T12:00:00Z",
                    kind=FlowKind.DEPOSIT,
                    amount=1_000.0,
                    currency="USD",
                )
            ],
        )
        short_res = calculate_portfolio_performance_detailed(short_ledger)
        self.assertIsNotNone(short_res.annualization_periods_per_year)
        self.assertIsNone(short_res.summary.cagr_decimal)
        self.assertIsNone(short_res.summary.xirr_decimal)
        self.assertTrue(
            any("CAGR and XIRR" in w for w in short_res.summary.warnings),
            short_res.summary.warnings,
        )

        t0 = datetime(2025, 1, 1, 23, 59, 59, tzinfo=timezone.utc)
        year_nav = [
            NormalizedNavPoint(
                (t0 + timedelta(days=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                50_000.0 + i * 25.0,
            )
            for i in range(370)
        ]
        year_ledger = _make_ledger(
            nav_points=year_nav,
            flows=[
                NormalizedFlow(
                    timestamp_utc="2025-07-01T12:00:00Z",
                    kind=FlowKind.DEPOSIT,
                    amount=1_000.0,
                    currency="USD",
                )
            ],
        )
        year_res = calculate_portfolio_performance_detailed(year_ledger)
        self.assertIsNotNone(year_res.summary.cagr_decimal)
        self.assertIsNotNone(year_res.summary.xirr_decimal)

    def test_coaching_annualized_drag_withheld_when_annualization_disallowed(self) -> None:
        ledger = _make_ledger(
            nav_points=[
                NormalizedNavPoint("2026-01-02T23:59:59Z", 50_000.0),
                NormalizedNavPoint("2026-01-30T23:59:59Z", 52_000.0),
            ],
            trades=[
                NormalizedTrade(
                    venue="IBKR",
                    native_entry_id="t1",
                    timestamp_utc="2026-01-10T15:00:00Z",
                    symbol="AAPL",
                    asset_class=AssetClass.EQUITY,
                    side="buy",
                    quantity=10.0,
                    price=200.0,
                    commission=15.0,
                    currency="USD",
                )
            ],
        )
        direct_drag = compute_cost_and_drag_breakdown(ledger)
        self.assertIsNotNone(direct_drag.annualized_total_drag_bps)

        engine_out = TraderCoachingEngine().evaluate(ledger, annualization_allowed=False)
        self.assertIsNotNone(engine_out.report.cost_drag.total_friction_drag_bps)
        self.assertIsNone(engine_out.report.cost_drag.annualized_total_drag_bps)

        kp = generate_ed25519_keypair(bytes.fromhex("11" * 32))
        pipe_res = verify_portfolio(
            ledger=ledger,
            publisher_kid="test-kid",
            publisher_private_key_hex=kp.private_key_hex,
            blinding_salt_hex="22" * 32,
            issued_at_utc="2026-02-01T00:00:00Z",
        )
        self.assertIsNone(pipe_res.coaching.cost_drag.annualized_total_drag_bps)
        self.assertIsNotNone(pipe_res.coaching.cost_drag.total_friction_drag_bps)


class TestF6WithheldCostDragNoneGuards(unittest.TestCase):
    def test_all_coaching_consumers_handle_none_cost_drag_fields(self) -> None:
        ledger = _make_ledger(
            nav_points=[
                NormalizedNavPoint("2026-01-02T23:59:59Z", 10_000.0),
                NormalizedNavPoint("2026-01-15T23:59:59Z", 10_500.0),
                NormalizedNavPoint("2026-01-30T23:59:59Z", 11_000.0),
            ],
            trades=[
                NormalizedTrade(
                    venue="IBKR",
                    native_entry_id="b1",
                    timestamp_utc="2026-01-05T14:00:00Z",
                    symbol="MSFT",
                    asset_class=AssetClass.EQUITY,
                    side="buy",
                    quantity=10.0,
                    price=400.0,
                    commission=5.0,
                    currency="USD",
                ),
                NormalizedTrade(
                    venue="IBKR",
                    native_entry_id="s1",
                    timestamp_utc="2026-01-20T14:00:00Z",
                    symbol="MSFT",
                    asset_class=AssetClass.EQUITY,
                    side="sell",
                    quantity=10.0,
                    price=420.0,
                    commission=5.0,
                    currency="USD",
                ),
            ],
            enabled_sections=["PriorPeriodPositions"],
        )
        all_none = CostAndDragBreakdown(
            commission_and_fee_drag_bps=None,
            fx_conversion_drag_bps=None,
            margin_and_funding_drag_bps=None,
            withholding_tax_drag_bps=None,
            total_friction_drag_bps=None,
            annualized_total_drag_bps=None,
        )
        behav = compute_behavioural_coaching_metrics(ledger, cost_drag=all_none)
        self.assertFalse(any("bps" in msg for msg in behav.actionable_improvements))

        redacted = build_redacted_summary_payload(cost_drag=all_none, behaviour=behav)
        for k, v in redacted["cost_drag_bps"].items():
            self.assertIsNone(v, f"Expected None for {k}")

        narrative = build_deterministic_coaching_narrative(cost_drag=all_none, behaviour=behav)
        self.assertNotIn("bps", narrative.style_summary)

        self.assertIsNone(
            compute_quant_dna_profile(
                ledger,
                behaviour=behav,
                cost_drag=all_none,
            )
        )
        annualized_none = CostAndDragBreakdown(
            commission_and_fee_drag_bps=10.0,
            fx_conversion_drag_bps=0.0,
            margin_and_funding_drag_bps=0.0,
            withholding_tax_drag_bps=0.0,
            total_friction_drag_bps=10.0,
            annualized_total_drag_bps=None,
        )
        self.assertIsNone(
            compute_quant_dna_profile(
                ledger,
                behaviour=behav,
                cost_drag=annualized_none,
            )
        )
        self.assertIsNone(simulate_counterfactual_twin(ledger, cost_drag=all_none))


class TestF2F3RoundTripPairingAndPreLedgerHoldings(unittest.TestCase):
    def test_normalized_trade_position_id_normalization_and_roundtrip_dict(self) -> None:
        blank = NormalizedTrade(
            venue="IBKR",
            native_entry_id="t1",
            timestamp_utc="2026-01-05T10:00:00Z",
            symbol="AAPL",
            asset_class=AssetClass.EQUITY,
            side="buy",
            quantity=1.0,
            price=100.0,
            position_id="   ",
        )
        self.assertIsNone(blank.position_id)

        tagged = NormalizedTrade(
            venue="IBKR",
            native_entry_id="t2",
            timestamp_utc="2026-01-05T10:00:00Z",
            symbol="AAPL",
            asset_class=AssetClass.EQUITY,
            side="buy",
            quantity=1.0,
            price=100.0,
            position_id="ticket-42",
        )
        self.assertEqual(tagged.position_id, "ticket-42")
        rehydrated = NormalizedTrade.from_dict(tagged.to_dict())
        self.assertEqual(rehydrated.position_id, "ticket-42")

        legacy_dict = tagged.to_dict()
        legacy_dict.pop("position_id", None)
        self.assertIsNone(NormalizedTrade.from_dict(legacy_dict).position_id)

    def test_hedged_closed_rows_never_cross_pair_mt4_mt5_tradovate(self) -> None:
        # 1) MT4 hedged tickets
        mt4_html = """<html><body>
        <b>Account: 778899</b> <b>Currency: USD</b> <b>Date: 2026.01.31 23:59</b>
        <table>
        <tr><td>Closed Transactions:</td></tr>
        <tr><td>Ticket</td><td>Open Time</td><td>Type</td><td>Size</td><td>Item</td><td>Price</td><td>S / L</td><td>T / P</td><td>Close Time</td><td>Price</td><td>Commission</td><td>Taxes</td><td>Swap</td><td>Profit</td></tr>
        <tr><td>100</td><td>2026.01.01 09:00:00</td><td>balance</td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td>10000.00</td></tr>
        <tr><td>101</td><td>2026.01.05 10:00:00</td><td>buy</td><td>1.00</td><td>eurusd</td><td>1.1000</td><td>0</td><td>0</td><td>2026.01.05 16:00:00</td><td>1.0900</td><td>0.00</td><td>0.00</td><td>0.00</td><td>-1000.00</td></tr>
        <tr><td>102</td><td>2026.01.05 11:00:00</td><td>sell</td><td>1.00</td><td>eurusd</td><td>1.1000</td><td>0</td><td>0</td><td>2026.01.05 12:00:00</td><td>1.0800</td><td>0.00</td><td>0.00</td><td>0.00</td><td>2000.00</td></tr>
        <tr><td>Open Trades:</td></tr>
        <tr><td>Ticket</td><td>Open Time</td><td>Type</td><td>Size</td><td>Item</td><td>Price</td><td>S / L</td><td>T / P</td><td>Price</td><td>Commission</td><td>Taxes</td><td>Swap</td><td>Profit</td></tr>
        <tr><td colspan="13">No transactions</td></tr>
        </table>
        <b>Balance: 11000.00</b> <b>Equity: 11000.00</b>
        </body></html>"""
        mt4_trips = match_fifo_round_trips(parse_mt4_statement(mt4_html, blinding_salt_hex="aa" * 32))
        self.assertEqual(len(mt4_trips), 2)
        self.assertEqual(sum(1 for rt in mt4_trips if rt.net_pnl_base > 0), 1)
        self.assertEqual(sum(1 for rt in mt4_trips if rt.net_pnl_base < 0), 1)

        # 2) MT5 Positions hedged
        mt5_pos_html = """<html><body>
        <table>
        <tr><th>Account:</th><td>551122 (USD, MetaQuotes-Live, real)</td></tr>
        <tr><th>Positions</th></tr>
        <tr><td>Time</td><td>Position</td><td>Symbol</td><td>Type</td><td>Volume</td><td>Price</td><td>S / L</td><td>T / P</td><td>Time</td><td>Price</td><td>Commission</td><td>Swap</td><td>Profit</td></tr>
        <tr><td>2026.01.05 10:00:00</td><td>501</td><td>EURUSD</td><td>buy</td><td>1.00</td><td>1.1000</td><td></td><td></td><td>2026.01.05 16:00:00</td><td>1.0900</td><td>0.00</td><td>0.00</td><td>-1000.00</td></tr>
        <tr><td>2026.01.05 11:00:00</td><td>502</td><td>EURUSD</td><td>sell</td><td>1.00</td><td>1.1000</td><td></td><td></td><td>2026.01.05 12:00:00</td><td>1.0800</td><td>0.00</td><td>0.00</td><td>2000.00</td></tr>
        <tr><th>Open Positions</th></tr>
        <tr><td>Time</td><td>Position</td><td>Symbol</td><td>Type</td><td>Volume</td><td>Price</td><td>S / L</td><td>T / P</td><td>Price</td><td>Commission</td><td>Swap</td><td>Profit</td></tr>
        </table></body></html>"""
        mt5_pos_trips = match_fifo_round_trips(
            parse_mt5_statement(mt5_pos_html, blinding_salt_hex="aa" * 32)
        )
        self.assertEqual(len(mt5_pos_trips), 2)
        self.assertEqual(sum(1 for rt in mt5_pos_trips if rt.net_pnl_base > 0), 1)
        self.assertEqual(sum(1 for rt in mt5_pos_trips if rt.net_pnl_base < 0), 1)

        # 3) MT5 Deals hedged (long closed for loss while hedged short remains open)
        mt5_deals_html = """<html><body>
        <table>
        <tr><th>Account:</th><td>551122 (USD, MetaQuotes-Live, real)</td></tr>
        <tr><th>Deals</th></tr>
        <tr><td>Time</td><td>Deal</td><td>Symbol</td><td>Type</td><td>Direction</td><td>Volume</td><td>Price</td><td>Order</td><td>Commission</td><td>Fee</td><td>Swap</td><td>Profit</td><td>Balance</td><td>Comment</td></tr>
        <tr><td>2026.01.01 09:00:00</td><td>1</td><td></td><td>balance</td><td></td><td></td><td></td><td></td><td>0.00</td><td>0.00</td><td>0.00</td><td>10000.00</td><td>10000.00</td><td>Deposit</td></tr>
        <tr><td>2026.01.05 10:00:00</td><td>2</td><td>EURUSD</td><td>buy</td><td>in</td><td>1.00</td><td>1.1000</td><td>201</td><td>0.00</td><td>0.00</td><td>0.00</td><td>0.00</td><td>10000.00</td><td></td></tr>
        <tr><td>2026.01.05 11:00:00</td><td>3</td><td>EURUSD</td><td>sell</td><td>in</td><td>1.00</td><td>1.1200</td><td>202</td><td>0.00</td><td>0.00</td><td>0.00</td><td>0.00</td><td>10000.00</td><td>hedge short</td></tr>
        <tr><td>2026.01.05 16:00:00</td><td>4</td><td>EURUSD</td><td>sell</td><td>out</td><td>1.00</td><td>1.0900</td><td>203</td><td>0.00</td><td>0.00</td><td>0.00</td><td>-1000.00</td><td>9000.00</td><td>close long</td></tr>
        <tr><th>Open Positions</th></tr>
        <tr><td>Time</td><td>Position</td><td>Symbol</td><td>Type</td><td>Volume</td><td>Price</td><td>S / L</td><td>T / P</td><td>Price</td><td>Commission</td><td>Swap</td><td>Profit</td></tr>
        <tr><td>2026.01.05 11:00:00</td><td>202</td><td>EURUSD</td><td>sell</td><td>1.00</td><td>1.1200</td><td></td><td></td><td>1.0900</td><td>0.00</td><td>0.00</td><td>3000.00</td></tr>
        </table></body></html>"""
        mt5_deals_trips = match_fifo_round_trips(
            parse_mt5_statement(mt5_deals_html, blinding_salt_hex="aa" * 32)
        )
        self.assertEqual(len(mt5_deals_trips), 1)
        self.assertLess(mt5_deals_trips[0].net_pnl_base, 0.0)

        # 4) Tradovate Performance CSV hedged
        tv_csv = "\n".join(
            [
                "symbol,_priceFormat,_priceFormatType,_tickSize,buyFillId,sellFillId,qty,buyPrice,sellPrice,pnl,boughtTimestamp,soldTimestamp,duration",
                "ESH6,-2,0,0.25,1,4,1,5000.00,4990.00,-$500.00,01/05/2026 10:00:00,01/05/2026 16:00:00,6h",
                "ESH6,-2,0,0.25,3,2,1,4980.00,5000.00,$1000.00,01/05/2026 12:00:00,01/05/2026 11:00:00,1h",
            ]
        )
        tv_trips = match_fifo_round_trips(parse_tradovate_csv(tv_csv, blinding_salt_hex="aa" * 32))
        self.assertEqual(len(tv_trips), 2)
        self.assertEqual(sum(1 for rt in tv_trips if rt.net_pnl_base > 0), 1)
        self.assertEqual(sum(1 for rt in tv_trips if rt.net_pnl_base < 0), 1)

    def test_journal_open_row_never_pairs_with_subsequent_closed_row(self) -> None:
        ts_csv = "\n".join(
            [
                "Status,Symbol,Size,Open Date,Open Time,Close Date,Close Time,Entry Price,Exit Price,Net Return,Commission,Side",
                "OPEN,AAPL,10,2026-01-05,10:00:00,,,200.00,,0.00,1.00,LONG",
                "WIN,AAPL,10,2026-01-06,11:00:00,2026-01-06,15:00:00,190.00,180.00,100.00,1.00,SHORT",
            ]
        )
        res = parse_journal_migration_csv(ts_csv, blinding_salt_hex="aa" * 32)
        trips = match_fifo_round_trips(res.ledger)
        self.assertEqual(len(trips), 1)
        self.assertGreater(trips[0].net_pnl_base, 0.0)

    def test_close_ts_before_open_ts_rejected_across_parsers(self) -> None:
        mt4_bad = """<html><body><b>Account: 1</b> <b>Currency: USD</b><table>
        <tr><td>Closed Transactions:</td></tr>
        <tr><td>Ticket</td><td>Open Time</td><td>Type</td><td>Size</td><td>Item</td><td>Price</td><td>S / L</td><td>T / P</td><td>Close Time</td><td>Price</td><td>Commission</td><td>Taxes</td><td>Swap</td><td>Profit</td></tr>
        <tr><td>1</td><td>2026.01.05 16:00:00</td><td>buy</td><td>1.00</td><td>eurusd</td><td>1.1000</td><td>0</td><td>0</td><td>2026.01.05 10:00:00</td><td>1.1100</td><td>0</td><td>0</td><td>0</td><td>1000</td></tr>
        </table></body></html>"""
        with self.assertRaises(ValueError):
            parse_mt4_statement(mt4_bad, blinding_salt_hex="aa" * 32)

        mt5_bad = """<html><body><table>
        <tr><th>Account:</th><td>1 (USD, Live, real)</td></tr>
        <tr><th>Positions</th></tr>
        <tr><td>Time</td><td>Position</td><td>Symbol</td><td>Type</td><td>Volume</td><td>Price</td><td>S / L</td><td>T / P</td><td>Time</td><td>Price</td><td>Commission</td><td>Swap</td><td>Profit</td></tr>
        <tr><td>2026.01.05 16:00:00</td><td>1</td><td>EURUSD</td><td>buy</td><td>1.00</td><td>1.1000</td><td></td><td></td><td>2026.01.05 10:00:00</td><td>1.1100</td><td>0</td><td>0</td><td>1000</td></tr>
        </table></body></html>"""
        with self.assertRaises(ValueError):
            parse_mt5_statement(mt5_bad, blinding_salt_hex="aa" * 32)

        tv_bad = "\n".join(
            [
                "symbol,qty,buyPrice,sellPrice,pnl,boughtTimestamp,soldTimestamp,openTimestamp,closeTimestamp",
                "ESH6,1,5000.00,5010.00,$500.00,01/05/2026 16:00:00,01/05/2026 10:00:00,01/05/2026 16:00:00,01/05/2026 10:00:00",
            ]
        )
        with self.assertRaises(ValueError):
            parse_tradovate_csv(tv_bad, blinding_salt_hex="aa" * 32)

        journal_bad = "\n".join(
            [
                "Status,Symbol,Size,Open Date,Open Time,Close Date,Close Time,Entry Price,Exit Price,Net Return,Commission,Side",
                "WIN,AAPL,10,2026-01-06,16:00:00,2026-01-06,10:00:00,180.00,190.00,100.00,1.00,LONG",
            ]
        )
        with self.assertRaises(ValueError):
            parse_journal_migration_csv(journal_bad, blinding_salt_hex="aa" * 32)

    def test_pre_ledger_long_averaging_down_withheld_from_round_trips(self) -> None:
        ledger = _make_ledger(
            broker_id="schwab",
            nav_points=[
                NormalizedNavPoint("2026-01-02T23:59:59Z", 20_000.0),
                NormalizedNavPoint("2026-01-30T23:59:59Z", 18_000.0),
            ],
            trades=[
                NormalizedTrade(
                    venue="SCHWAB",
                    native_entry_id="b1",
                    timestamp_utc="2026-01-05T15:00:00Z",
                    symbol="AAPL",
                    asset_class=AssetClass.EQUITY,
                    side="buy",
                    quantity=10.0,
                    price=150.0,
                ),
                NormalizedTrade(
                    venue="SCHWAB",
                    native_entry_id="s1",
                    timestamp_utc="2026-01-20T15:00:00Z",
                    symbol="AAPL",
                    asset_class=AssetClass.EQUITY,
                    side="sell",
                    quantity=50.0,
                    price=170.0,
                ),
            ],
            enabled_sections=[],
        )
        self.assertEqual(match_fifo_round_trips(ledger), [])

        renamed_ledger = _make_ledger(
            broker_id="schwab",
            nav_points=[
                NormalizedNavPoint("2026-01-02T23:59:59Z", 20_000.0),
                NormalizedNavPoint("2026-01-30T23:59:59Z", 18_000.0),
            ],
            trades=[
                NormalizedTrade(
                    venue="SCHWAB",
                    native_entry_id="b-old",
                    timestamp_utc="2026-01-05T15:00:00Z",
                    symbol="FB",
                    asset_class=AssetClass.EQUITY,
                    side="buy",
                    quantity=10.0,
                    price=150.0,
                ),
                NormalizedTrade(
                    venue="SCHWAB",
                    native_entry_id="s-new",
                    timestamp_utc="2026-01-20T15:00:00Z",
                    symbol="META",
                    asset_class=AssetClass.EQUITY,
                    side="sell",
                    quantity=50.0,
                    price=170.0,
                ),
            ],
            corporate_actions=[
                CorporateActionRecord(
                    action_type=CorporateActionType.SYMBOL_CHANGE,
                    timestamp_utc="2026-01-10T00:00:00Z",
                    symbol="FB",
                    new_symbol="META",
                )
            ],
            enabled_sections=[],
        )
        self.assertEqual(match_fifo_round_trips(renamed_ledger), [])

    def test_mt5_deals_balance_filtered_against_positions_intervals(self) -> None:
        mt5_g = """<html><body><table>
        <tr><th>Account:</th><td>551122 (USD, MetaQuotes-Live, real)</td></tr>
        <tr><th>Positions</th></tr>
        <tr><td>Time</td><td>Position</td><td>Symbol</td><td>Type</td><td>Volume</td><td>Price</td><td>S / L</td><td>T / P</td><td>Time</td><td>Price</td><td>Commission</td><td>Swap</td><td>Profit</td></tr>
        <tr><td>2026.01.05 10:00:00</td><td>501</td><td>EURUSD</td><td>buy</td><td>1.00</td><td>1.1000</td><td></td><td></td><td>2026.01.20 16:00:00</td><td>1.1100</td><td>0.00</td><td>0.00</td><td>1000.00</td></tr>
        <tr><th>Deals</th></tr>
        <tr><td>Time</td><td>Deal</td><td>Symbol</td><td>Type</td><td>Direction</td><td>Volume</td><td>Price</td><td>Order</td><td>Commission</td><td>Fee</td><td>Swap</td><td>Profit</td><td>Balance</td><td>Comment</td></tr>
        <tr><td>2026.01.01 09:00:00</td><td>1</td><td></td><td>balance</td><td></td><td></td><td></td><td></td><td>0.00</td><td>0.00</td><td>0.00</td><td>10000.00</td><td>10000.00</td><td>Deposit</td></tr>
        <tr><td>2026.01.10 12:00:00</td><td>2</td><td></td><td>balance</td><td></td><td></td><td></td><td></td><td>0.00</td><td>0.00</td><td>0.00</td><td>500.00</td><td>10500.00</td><td>Deposit while pos 501 open</td></tr>
        <tr><th>Open Positions</th></tr>
        <tr><td>Time</td><td>Position</td><td>Symbol</td><td>Type</td><td>Volume</td><td>Price</td><td>S / L</td><td>T / P</td><td>Price</td><td>Commission</td><td>Swap</td><td>Profit</td></tr>
        </table></body></html>"""
        ledger = parse_mt5_statement(mt5_g, blinding_salt_hex="aa" * 32)
        self.assertNotIn("2026-01-10T12:00:00Z", [p.timestamp_utc for p in ledger.nav_points])


class TestSec04OpenWipeoutAndMissingEquityFailClosed(unittest.TestCase):
    def test_mt4_and_mt5_open_wipeout_withholds_return(self) -> None:
        kp = generate_ed25519_keypair(bytes.fromhex("11" * 32))
        for eq_str in ("0.00", "-200.00"):
            mt4_wipeout = f"""<html><body>
            <b>Account: 12345</b> <b>Currency: USD</b> <b>Date: 2026.02.28 23:59</b>
            <table>
            <tr><td>Closed Transactions:</td></tr>
            <tr><td>Ticket</td><td>Open Time</td><td>Type</td><td>Size</td><td>Item</td><td>Price</td><td>S / L</td><td>T / P</td><td>Close Time</td><td>Price</td><td>Commission</td><td>Taxes</td><td>Swap</td><td>Profit</td></tr>
            <tr><td>1</td><td>2026.02.01 09:00:00</td><td>balance</td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td>10000.00</td></tr>
            <tr><td>2</td><td>2026.02.05 10:00:00</td><td>buy</td><td>1.00</td><td>eurusd</td><td>1.1000</td><td>0</td><td>0</td><td>2026.02.06 10:00:00</td><td>1.1500</td><td>0</td><td>0</td><td>0</td><td>5000.00</td></tr>
            <tr><td>Open Trades:</td></tr>
            <tr><td>Ticket</td><td>Open Time</td><td>Type</td><td>Size</td><td>Item</td><td>Price</td><td>S / L</td><td>T / P</td><td>Price</td><td>Commission</td><td>Taxes</td><td>Swap</td><td>Profit</td></tr>
            <tr><td>3</td><td>2026.02.10 10:00:00</td><td>buy</td><td>5.00</td><td>eurusd</td><td>1.1500</td><td>0</td><td>0</td><td>1.1200</td><td>0</td><td>0</td><td>0</td><td>-15000.00</td></tr>
            </table>
            <b>Balance: 15000.00</b> <b>Equity: {eq_str}</b>
            </body></html>"""
            mt4_ledger = parse_mt4_statement(mt4_wipeout, blinding_salt_hex="aa" * 32)
            res4 = verify_portfolio(
                ledger=mt4_ledger,
                publisher_kid="k",
                publisher_private_key_hex=kp.private_key_hex,
                blinding_salt_hex="22" * 32,
                issued_at_utc="2026-03-01T00:00:00Z",
            )
            self.assertTrue(res4.performance_withheld)
            self.assertIs(
                res4.proof_bundle.get_disclosed_payload("core_metrics")["performance_withheld"],
                True,
            )

            mt5_wipeout = f"""<html><body>
            <div>Date: 2026.02.28 23:59</div>
            <table>
            <tr><th>Account:</th><td>12345 (USD, MetaQuotes-Live, real)</td></tr>
            <tr><th>Deals</th></tr>
            <tr><td>Time</td><td>Deal</td><td>Symbol</td><td>Type</td><td>Direction</td><td>Volume</td><td>Price</td><td>Order</td><td>Commission</td><td>Fee</td><td>Swap</td><td>Profit</td><td>Balance</td><td>Comment</td></tr>
            <tr><td>2026.02.01 09:00:00</td><td>1</td><td></td><td>balance</td><td></td><td></td><td></td><td></td><td>0</td><td>0</td><td>0</td><td>10000.00</td><td>10000.00</td><td>Deposit</td></tr>
            <tr><td>2026.02.05 10:00:00</td><td>2</td><td>EURUSD</td><td>buy</td><td>in</td><td>1.00</td><td>1.1000</td><td>10</td><td>0</td><td>0</td><td>0</td><td>0.00</td><td>10000.00</td><td></td></tr>
            <tr><td>2026.02.06 10:00:00</td><td>3</td><td>EURUSD</td><td>sell</td><td>out</td><td>1.00</td><td>1.1500</td><td>11</td><td>0</td><td>0</td><td>0</td><td>5000.00</td><td>15000.00</td><td></td></tr>
            <tr><td>2026.02.10 10:00:00</td><td>4</td><td>EURUSD</td><td>buy</td><td>in</td><td>5.00</td><td>1.1500</td><td>12</td><td>0</td><td>0</td><td>0</td><td>0.00</td><td>15000.00</td><td></td></tr>
            <tr><th>Open Positions</th></tr>
            <tr><td>Time</td><td>Position</td><td>Symbol</td><td>Type</td><td>Volume</td><td>Price</td><td>S / L</td><td>T / P</td><td>Price</td><td>Commission</td><td>Swap</td><td>Profit</td></tr>
            <tr><td>2026.02.10 10:00:00</td><td>12</td><td>EURUSD</td><td>buy</td><td>5.00</td><td>1.1500</td><td></td><td></td><td>1.1200</td><td>0</td><td>0</td><td>-15000.00</td></tr>
            <tr><td>Equity:</td><td>{eq_str}</td></tr>
            </table></body></html>"""
            mt5_ledger = parse_mt5_statement(mt5_wipeout, blinding_salt_hex="aa" * 32)
            res5 = verify_portfolio(
                ledger=mt5_ledger,
                publisher_kid="k",
                publisher_private_key_hex=kp.private_key_hex,
                blinding_salt_hex="22" * 32,
                issued_at_utc="2026-03-01T00:00:00Z",
            )
            self.assertTrue(res5.performance_withheld)
            self.assertIs(
                res5.proof_bundle.get_disclosed_payload("core_metrics")["performance_withheld"],
                True,
            )

    def test_mt4_and_mt5_open_position_without_date_or_equity_clears_nav_points(self) -> None:
        mt4_no_date = """<html><body>
        <b>Account: 12345</b> <b>Currency: USD</b>
        <table>
        <tr><td>Closed Transactions:</td></tr>
        <tr><td>Ticket</td><td>Open Time</td><td>Type</td><td>Size</td><td>Item</td><td>Price</td><td>S / L</td><td>T / P</td><td>Close Time</td><td>Price</td><td>Commission</td><td>Taxes</td><td>Swap</td><td>Profit</td></tr>
        <tr><td>1</td><td>2026.02.01 09:00:00</td><td>balance</td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td><td>10000.00</td></tr>
        <tr><td>2</td><td>2026.02.05 10:00:00</td><td>buy</td><td>1.00</td><td>eurusd</td><td>1.1000</td><td>0</td><td>0</td><td>2026.02.06 10:00:00</td><td>1.1500</td><td>0</td><td>0</td><td>0</td><td>5000.00</td></tr>
        <tr><td>Open Trades:</td></tr>
        <tr><td>Ticket</td><td>Open Time</td><td>Type</td><td>Size</td><td>Item</td><td>Price</td><td>S / L</td><td>T / P</td><td>Price</td><td>Commission</td><td>Taxes</td><td>Swap</td><td>Profit</td></tr>
        <tr><td>3</td><td>2026.02.10 10:00:00</td><td>buy</td><td>5.00</td><td>eurusd</td><td>1.1500</td><td>0</td><td>0</td><td>1.1200</td><td>0</td><td>0</td><td>0</td><td>-14000.00</td></tr>
        </table>
        <b>Balance: 15000.00</b> <b>Equity: 1000.00</b>
        </body></html>"""
        l4 = parse_mt4_statement(mt4_no_date, blinding_salt_hex="aa" * 32)
        self.assertEqual(l4.nav_points, [])
        self.assertTrue(l4.parser_warnings)

        mt5_no_eq = """<html><body>
        <div>Date: 2026.02.28 23:59</div>
        <table>
        <tr><th>Account:</th><td>12345 (USD, MetaQuotes-Live, real)</td></tr>
        <tr><th>Deals</th></tr>
        <tr><td>Time</td><td>Deal</td><td>Symbol</td><td>Type</td><td>Direction</td><td>Volume</td><td>Price</td><td>Order</td><td>Commission</td><td>Fee</td><td>Swap</td><td>Profit</td><td>Balance</td><td>Comment</td></tr>
        <tr><td>2026.02.01 09:00:00</td><td>1</td><td></td><td>balance</td><td></td><td></td><td></td><td></td><td>0</td><td>0</td><td>0</td><td>10000.00</td><td>10000.00</td><td>Deposit</td></tr>
        <tr><td>2026.02.05 10:00:00</td><td>2</td><td>EURUSD</td><td>buy</td><td>in</td><td>1.00</td><td>1.1000</td><td>10</td><td>0</td><td>0</td><td>0</td><td>0.00</td><td>10000.00</td><td></td></tr>
        <tr><td>2026.02.06 10:00:00</td><td>3</td><td>EURUSD</td><td>sell</td><td>out</td><td>1.00</td><td>1.1500</td><td>11</td><td>0</td><td>0</td><td>0</td><td>5000.00</td><td>15000.00</td><td></td></tr>
        <tr><th>Open Positions</th></tr>
        <tr><td>Time</td><td>Position</td><td>Symbol</td><td>Type</td><td>Volume</td><td>Price</td><td>S / L</td><td>T / P</td><td>Price</td><td>Commission</td><td>Swap</td><td>Profit</td></tr>
        <tr><td>2026.02.10 10:00:00</td><td>12</td><td>EURUSD</td><td>buy</td><td>5.00</td><td>1.1500</td><td></td><td></td><td>1.1200</td><td>0</td><td>0</td><td>-14000.00</td></tr>
        </table></body></html>"""
        l5 = parse_mt5_statement(mt5_no_eq, blinding_salt_hex="aa" * 32)
        self.assertEqual(l5.nav_points, [])
        self.assertTrue(l5.parser_warnings)

    def test_degiro_zero_ending_portfolio_does_not_fall_back_to_positive_account_cash(self) -> None:
        acct = "\n".join(
            [
                "Date,Time,Value date,Product,ISIN,Description,FX,Change,,Balance,,Order ID",
                "02-01-2026,09:00,02-01-2026,,,Deposit,,EUR,10000.00,EUR,10000.00,",
                "05-01-2026,10:00,05-01-2026,ACME,US0000000001,Buy 10 @ 100,,EUR,-1000.00,EUR,9000.00,ord1",
                "06-01-2026,10:00,06-01-2026,ACME,US0000000001,Sell 10 @ 150,,EUR,1500.00,EUR,10500.00,ord2",
            ]
        )
        tx = "\n".join(
            [
                "Date,Time,Product,ISIN,Reference exchange,Venue,Quantity,Price,,Local value,,Value,,Exchange rate,Transaction and/or third party fees,,Total,,Order ID",
                "05-01-2026,10:00,ACME,US0000000001,NDQ,XNAS,10,100.00,EUR,-1000.00,EUR,-1000.00,EUR,1.0,0.00,EUR,-1000.00,EUR,ord1",
                "06-01-2026,10:00,ACME,US0000000001,NDQ,XNAS,-10,150.00,EUR,1500.00,EUR,1500.00,EUR,1.0,0.00,EUR,1500.00,EUR,ord2",
            ]
        )
        port = "\n".join(
            [
                "Product,Symbol/ISIN,Amount,Closing,Local value,Value in EUR",
                "CASH & CASH FUND & FTX CASH (EUR),,0.00,1.00,EUR 0.00,0.00",
            ]
        )
        ledger = parse_degiro_csv_bundle(
            account_csv=acct,
            transactions_csv=tx,
            portfolio_csv=port,
            blinding_salt_hex="aa" * 32,
        )
        kp = generate_ed25519_keypair(bytes.fromhex("11" * 32))
        res = verify_portfolio(
            ledger=ledger,
            publisher_kid="k",
            publisher_private_key_hex=kp.private_key_hex,
            blinding_salt_hex="22" * 32,
            issued_at_utc="2026-02-01T00:00:00Z",
        )
        self.assertTrue(res.performance_withheld)


class TestSec05NonFiniteAndExtremeFloatRejection(unittest.TestCase):
    def test_nan_inf_and_extreme_floats_rejected(self) -> None:
        for bad in ("nan", "NaN", "inf", "-inf", "Infinity", "1e999", "1e31", "-1e31"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    _parse_localized_float(bad)

        mt5_nan = """<html><body><table>
        <tr><th>Account:</th><td>1 (USD, Live, real)</td></tr>
        <tr><th>Deals</th></tr>
        <tr><td>Time</td><td>Deal</td><td>Symbol</td><td>Type</td><td>Direction</td><td>Volume</td><td>Price</td><td>Order</td><td>Commission</td><td>Fee</td><td>Swap</td><td>Profit</td><td>Balance</td><td>Comment</td></tr>
        <tr><td>2026.01.01 09:00:00</td><td>1</td><td></td><td>balance</td><td></td><td></td><td></td><td></td><td>0</td><td>0</td><td>0</td><td>10000</td><td>10000</td><td>Deposit</td></tr>
        <tr><td>2026.01.02 09:00:00</td><td>2</td><td></td><td>balance</td><td></td><td></td><td></td><td></td><td>0</td><td>0</td><td>0</td><td>nan</td><td>nan</td><td>Bad</td></tr>
        </table></body></html>"""
        with self.assertRaises(ValueError):
            parse_mt5_statement(mt5_nan, blinding_salt_hex="aa" * 32)


class TestSec02RegexLinearTimeBounds(unittest.TestCase):
    def test_xxe_encoding_and_mt_header_regexes_run_under_50ms(self) -> None:
        checks = [
            ("csv_xxe", lambda: _XXE_DECL_SYSTEM_PUBLIC_RE.search(b"<!" * 10_000)),
            ("flex_xxe", lambda: _FLEX_XXE_DECL_RE.search(b"<!" * 10_000)),
            ("xml_enc", lambda: _XML_ENCODING_DECL_RE.search(b"<?xml " * 5_000)),
            ("mt_acct", lambda: _MT_ACCOUNT_RE.search("account" + " " * 8_000 + "x")),
            ("mt_ccy", lambda: _MT_CURRENCY_RE.search("currency" + " " * 8_000 + "1")),
        ]
        for label, fn in checks:
            with self.subTest(label=label):
                t0 = time.perf_counter()
                res = fn()
                dt = time.perf_counter() - t0
                self.assertIsNone(res)
                self.assertLess(dt, 0.05, f"{label} took {dt:.4f}s")

        self.assertIsNotNone(
            _XXE_DECL_SYSTEM_PUBLIC_RE.search(b'<!DOCTYPE foo SYSTEM "http://evil.invalid/x">')
        )
        self.assertIsNotNone(
            _FLEX_XXE_DECL_RE.search(b'<!ENTITY xxe PUBLIC "a" "http://evil.invalid/x">')
        )


class TestF4Sec08IssueWindowAndOfflineBrokerPinning(unittest.TestCase):
    def test_same_utc_day_date_only_report_date_clamped_to_issued_at_utc(self) -> None:
        kp = generate_ed25519_keypair(bytes.fromhex("11" * 32))
        same_day_ledger = _make_ledger(
            nav_points=[
                NormalizedNavPoint("2026-02-01T23:59:59Z", 50_000.0),
                NormalizedNavPoint("2026-02-28T23:59:59Z", 53_000.0),
            ],
            trades=[
                NormalizedTrade(
                    venue="IBKR",
                    native_entry_id="t1",
                    timestamp_utc="2026-02-28T14:00:00Z",
                    symbol="AAPL",
                    asset_class=AssetClass.EQUITY,
                    side="buy",
                    quantity=10.0,
                    price=200.0,
                )
            ],
        )
        res = verify_portfolio(
            ledger=same_day_ledger,
            publisher_kid="k",
            publisher_private_key_hex=kp.private_key_hex,
            blinding_salt_hex="22" * 32,
            issued_at_utc="2026-02-28T15:30:00Z",
        )
        self.assertEqual(res.proof_bundle.period_end_utc, "2026-02-28T15:30:00Z")

        future_ledger = _make_ledger(
            nav_points=[
                NormalizedNavPoint("2026-02-01T23:59:59Z", 50_000.0),
                NormalizedNavPoint("2027-03-01T23:59:59Z", 53_000.0),
            ],
        )
        with self.assertRaises(ValueError):
            verify_portfolio(
                ledger=future_ledger,
                publisher_kid="k",
                publisher_private_key_hex=kp.private_key_hex,
                blinding_salt_hex="22" * 32,
                issued_at_utc="2026-02-28T15:30:00Z",
            )

        ahead_ledger = _make_ledger(
            nav_points=[
                NormalizedNavPoint("2026-02-01T10:00:00Z", 50_000.0),
                NormalizedNavPoint("2026-02-28T17:30:00Z", 53_000.0),
            ],
        )
        with self.assertRaises(ValueError) as ctx:
            verify_portfolio(
                ledger=ahead_ledger,
                publisher_kid="k",
                publisher_private_key_hex=kp.private_key_hex,
                blinding_salt_hex="22" * 32,
                issued_at_utc="2026-02-28T15:30:00Z",
            )
        self.assertIn("UTC", str(ctx.exception))

    def test_offline_statement_broker_id_pinned_and_as_of_utc_blocked(self) -> None:
        self.assertIn("as_of_utc", _WORKER_SERVER_ONLY_FETCH_KEYS)
        flex = """<?xml version="1.0" encoding="UTF-8"?>
        <FlexQueryResponse queryName="q" type="AF"><FlexStatements count="1">
        <FlexStatement accountId="U8877665" baseCurrency="USD" fromDate="2026-01-01" toDate="2026-01-31">
          <EquitySummaryInBase>
            <EquitySummaryByReportDateInBase reportDate="2026-01-02" total="50000.00" />
            <EquitySummaryByReportDateInBase reportDate="2026-01-30" total="53000.00" />
          </EquitySummaryInBase>
        </FlexStatement></FlexStatements></FlexQueryResponse>"""
        base_payload = {
            "raw_statement_b64": base64.b64encode(flex.encode()).decode(),
            "blinding_salt_hex": "44" * 32,
            "issued_at_utc": "2026-02-01T12:00:00Z",
        }

        ok_alias = api_worker_pipeline_entrypoint({**base_payload, "broker_id": "ibkr_flex"})
        self.assertEqual(ok_alias["broker_id"], "ibkr_flex")

        for spoof in ("schwab", "hyperliquid", "degiro", "mt5"):
            with self.subTest(spoof=spoof):
                with self.assertRaises(ValueError):
                    api_worker_pipeline_entrypoint({**base_payload, "broker_id": spoof})


class TestSec09HyperliquidDailySpacing(unittest.TestCase):
    def test_hyperliquid_daily_closes_split_outside_20h_to_28h_while_keeping_intraday_wipeout(
        self,
    ) -> None:
        def ms(day: int, hour: int = 23, minute: int = 0) -> int:
            return int(datetime(2026, 1, day, hour, minute, tzinfo=timezone.utc).timestamp() * 1000)

        addr = "0x" + "1" * 40
        adapter = HyperliquidPublicReadOnlyAdapter()

        def run_hl(alltime_pts: list[list[object]]):
            return adapter.parse_payload(
                {
                    "portfolio": [["allTime", {"accountValueHistory": alltime_pts}]],
                    "ledger_updates": [],
                    "fills": [],
                },
                wallet_address=addr,
                blinding_salt_hex="66" * 32,
                as_of_utc="2026-01-20T00:00:00Z",
            )

        l_h5 = run_hl(
            [[ms(1, 0, 1), "10000"], [ms(2, 23, 59), "10500"], [ms(3, 23, 59), "11000"]]
        )
        self.assertEqual(len(l_h5.nav_points), 2)
        self.assertTrue(l_h5.parser_warnings)

        l_h5b = run_hl(
            [
                [ms(9, 3, 0), "10000"],
                [ms(10, 23, 0), "10200"],
                [ms(11, 23, 0), "10400"],
                [ms(12, 23, 0), "10600"],
            ]
        )
        self.assertEqual(len(l_h5b.nav_points), 3)
        self.assertTrue(l_h5b.parser_warnings)

        l_h1a = run_hl(
            [
                [ms(2, 23, 0), "15000"],
                [ms(3, 10, 0), "0"],
                [ms(3, 23, 0), "10000"],
                [ms(4, 23, 0), "12000"],
            ]
        )
        perf_h1a = calculate_portfolio_performance_detailed(l_h1a)
        self.assertTrue(perf_h1a.withheld)


class TestF7Sec13HolderClaimUnicodeAndUrlParity(unittest.TestCase):
    def setUp(self) -> None:
        pub = generate_ed25519_keypair(bytes.fromhex("77" * 32))
        self.bundle = create_signed_proof_bundle(
            proof_id="prf-r4-holder-001",
            issued_at_utc="2026-02-01T00:05:00Z",
            publisher_kid="dummy-kid",
            publisher_private_key_hex=pub.private_key_hex,
            broker_id="dummybroker",
            blinded_account_tag="ab" * 32,
            account_scope=AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="cd" * 32,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T23:59:59Z",
            base_currency="USD",
            leaf_payloads={n: {"placeholder": n} for n in CANONICAL_LEAF_NAMES},
        )

    def _verify_claim(
        self,
        *,
        display_name: str = "Ana Trader",
        handle: str | None = "@ana_trader",
        profile_url: str | None = "https://example.invalid/ana",
    ):
        kp = generate_ed25519_keypair()
        claim = {
            "claimed_at_utc": "2026-02-01T00:05:00Z",
            "display_name": display_name,
            "handle": handle,
            "holder_public_key_hex": kp.public_key_hex,
            "merkle_root": self.bundle.merkle_root,
            "profile_url": profile_url,
            "proof_hash": self.bundle.proof_hash(),
            "proof_id": self.bundle.proof_id,
            "schema_version": HOLDER_SCHEMA_VERSION,
        }
        claim["signature_hex"] = ed25519_sign_domain(
            kp.private_key_hex, SIGNING_DOMAIN_HOLDER, jcs_canonicalize(claim)
        )
        data = self.bundle.to_dict()
        data["holder_identity"] = claim
        parsed = VerifyProofBundle.from_dict(data)
        return verify_proof_bundle(parsed, now_utc="2026-03-01T00:00:00Z")

    def test_handle_regex_rejects_trailing_newline(self) -> None:
        self.assertIsNone(_HOLDER_HANDLE_RE.match("@alice\n"))
        self.assertIsNotNone(_HOLDER_HANDLE_RE.match("@alice"))

    def test_bad_holder_claims_parse_via_from_dict_and_verify_as_invalid(self) -> None:
        clean = self._verify_claim()
        self.assertTrue(clean.valid)
        self.assertEqual(clean.holder_claim_status, HolderClaimStatus.SELF_ASSERTED)
        self.assertEqual(clean.holder_display_name, "Ana Trader")

        bad_cases = [
            ("c1_nel", dict(display_name="Ana\x85Verified")),
            ("c1_csi", dict(display_name="Ana\x9b2JTrader")),
            ("zl_linesep", dict(display_name="Ana\u2028Verified")),
            ("zp_parasep", dict(display_name="Ana\u2029Verified")),
            ("zs_ideographic", dict(display_name="Ana\u3000Staff")),
            ("cgj_u034f", dict(display_name="A\u034fna")),
            ("alm_u061c", dict(display_name="Ana\u061c")),
            ("hangul_u115f", dict(display_name="Ana\u115f")),
            ("hangul_u1160", dict(display_name="Ana\u1160")),
            ("khmer_u17b4", dict(display_name="Ana\u17b4")),
            ("mongolian_u180e", dict(display_name="Ana\u180e")),
            ("braille_blank", dict(display_name="\u2800")),
            ("hangul_filler_only", dict(display_name="\u3164")),
            ("variation_selector_only", dict(display_name="\ufe0f")),
            ("halfwidth_hangul", dict(display_name="Ana\uffa0")),
            ("nonchar_uffff", dict(display_name="Ana\uffff")),
            ("variation_supp", dict(display_name="Ana\U000e0100")),
            ("private_use", dict(display_name="Ana\ue000")),
            ("unassigned_cn", dict(display_name="Ana\u0378")),
            ("punctuation_only_name", dict(display_name="---")),
            ("url_pct_rlo", dict(profile_url="https://example.invalid/%E2%80%AEana")),
            ("url_bad_pct_utf8", dict(profile_url="https://example.invalid/%FFana")),
            ("url_bare_https", dict(profile_url="https://")),
            ("url_userinfo", dict(profile_url="https://github.com@evil.example/x")),
            ("url_port", dict(profile_url="https://example.com:8443/ana")),
            ("url_localhost", dict(profile_url="https://localhost/ana")),
            ("url_ipv4", dict(profile_url="https://127.0.0.1/ana")),
            ("url_ipv6", dict(profile_url="https://[::1]/ana")),
            ("url_space", dict(profile_url="https://example.com/ana verified")),
            ("url_leading_dot", dict(profile_url="https://.example.com/ana")),
            ("url_trailing_dot", dict(profile_url="https://example.com./ana")),
        ]
        for label, overrides in bad_cases:
            with self.subTest(label=label):
                res = self._verify_claim(**overrides)
                self.assertTrue(res.valid, f"{label} unexpectedly invalidated bundle: {res.errors}")
                self.assertEqual(
                    res.holder_claim_status,
                    HolderClaimStatus.INVALID,
                    f"{label} should be INVALID, got {res.holder_claim_status}",
                )
                self.assertIsNone(res.holder_display_name)


if __name__ == "__main__":
    unittest.main()
