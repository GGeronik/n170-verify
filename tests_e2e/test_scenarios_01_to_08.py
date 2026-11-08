"""End-to-end institutional LP & red-team audit scenarios 1-8 (100% in-memory)."""

from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any
import sys
import unittest

_BOOT_ROOT = Path(__file__).resolve().parents[1]
for _p in (str(_BOOT_ROOT), str(_BOOT_ROOT / "core"), str(_BOOT_ROOT / "api")):
    if Path(_p).exists() and _p not in sys.path:
        sys.path.insert(0, _p)

from n170_verify.connectors import (
    AlpacaReadOnlyAdapter,
    CcxtExchangeReadOnlyAdapter,
    IBKR_FLEX_GET_STATEMENT_URL,
    IBKR_FLEX_SEND_REQUEST_URL,
    IbkrFlexWebServiceAdapter,
    MutatingCredentialRejectedError,
    PaperOrSandboxAccountRejectedError,
    deduplicate_coinbase_fills_by_entry_id,
)
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    CanonicalPortfolioLedger,
    CheckOutcome,
    CorporateActionRecord,
    CorporateActionType,
    EnvironmentTier,
    FlowKind,
    NormalizedFlow,
    NormalizedNavPoint,
    NormalizedPosition,
    NormalizedTrade,
    OriginAssurance,
    ProviderApprovalState,
    ReconciliationStatus,
    SignerTrustStatus,
    compute_blinded_account_tag,
    verify_proof_bundle,
)
from n170_verify.crypto import (
    PublisherKeyRecord,
    PublisherKeyRegistryDocument,
    generate_ed25519_keypair,
)
from n170_verify.pipeline import verify_portfolio
from n170_verify.reference import EodhdReferenceProvider

_SALT_HEX = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
_TAG = compute_blinded_account_tag("ibkr", "SYNTH-INST-LP-01", _SALT_HEX)
_SHA = "cd" * 32
_EODHD_TEST_KEY = "SYNTH_EODHD_KEY_01_08"
_REPO_DIR = Path(__file__).resolve().parents[1]
_NODE_BIN = "/opt/homebrew/bin/node" if Path("/opt/homebrew/bin/node").exists() else (shutil.which("node") or "node")

_ALL_SECTIONS = [
    "EquitySummaryByReportDateInBase",
    "Trades",
    "OpenPositions",
    "PriorPeriodPositions",
    "CashTransactions",
    "Transfers",
    "CorporateActions",
    "OptionEAE",
]


def _base_ledger(**overrides: Any) -> CanonicalPortfolioLedger:
    params: dict[str, Any] = {
        "blinded_account_tag": _TAG,
        "broker_id": "ibkr",
        "account_scope": AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
        "claimed_origin_assurance": OriginAssurance.OPERATOR_RETRIEVED,
        "provider_approval_state": ProviderApprovalState.APPROVED_LIVE,
        "environment_tier": EnvironmentTier.LIVE_PRODUCTION,
        "source_body_sha256": _SHA,
        "base_currency": "USD",
        "period_start_utc": "2026-03-01T20:00:00Z",
        "period_end_utc": "2026-03-31T20:00:00Z",
        "enabled_sections": list(_ALL_SECTIONS),
    }
    params.update(overrides)
    return CanonicalPortfolioLedger(**params)


class TestScenarios01To08(unittest.TestCase):
    """Institutional LP & adversarial red-team scenarios 1 through 8."""

    def test_scenario_01_honest_multicurrency_options_eodhd_split_gbx_t1(self) -> None:
        def eodhd_transport(url: str, params: Mapping[str, str]) -> Any:
            self.assertEqual(params.get("fmt"), "json")
            if "/api/search/VOD" in url:
                return [{"Code": "VOD", "Exchange": "LSE", "Currency": "GBX", "ISIN": "GB00BH4HKS39"}]
            if url.endswith("/api/eod/VOD.LSE"):
                return [
                    {"date": "2026-03-12", "open": 72.0, "high": 74.0, "low": 71.0, "close": 72.5, "adjusted_close": 72.5, "volume": 12_000_000},
                    {"date": "2026-03-31", "open": 72.5, "high": 74.0, "low": 72.0, "close": 73.0, "adjusted_close": 73.0, "volume": 14_000_000},
                ]
            if url.endswith("/api/eod/AAPL.US"):
                return [
                    {"date": "2026-03-03", "open": 400.0, "high": 404.0, "low": 396.0, "close": 400.0, "adjusted_close": 95.0, "volume": 50_000_000},
                    {"date": "2026-03-31", "open": 100.5, "high": 102.0, "low": 100.0, "close": 101.0, "adjusted_close": 101.0, "volume": 45_000_000},
                ]
            if url.endswith("/api/splits/AAPL.US"):
                return [{"date": "2026-03-10", "split": "4.000000/1.000000"}]
            if url.endswith("/api/eod/MSFT.US"):
                return [
                    {"date": "2026-03-20", "open": 399.0, "high": 401.0, "low": 397.0, "close": 399.0, "adjusted_close": 399.0, "volume": 20_000_000},
                    {"date": "2026-03-31", "open": 401.0, "high": 403.0, "low": 400.0, "close": 402.0, "adjusted_close": 402.0, "volume": 22_000_000},
                ]
            if url.endswith("/api/eod/ASML.US"):
                return [{"date": "2026-03-31", "open": 898.0, "high": 904.0, "low": 895.0, "close": 900.0, "adjusted_close": 900.0, "volume": 1_500_000}]
            if url.endswith("/api/div/ASML.US"):
                return [{"date": "2026-03-20", "paymentDate": "2026-03-27", "value": 1.52, "unadjustedValue": 1.60, "currency": "EUR"}]
            if url.endswith("/api/eod/KO.US"):
                return [{"date": "2026-03-31", "open": 49.8, "high": 50.4, "low": 49.5, "close": 50.0, "adjusted_close": 50.0, "volume": 9_000_000}]
            if url.endswith("/api/eod/EURUSD.FOREX"):
                return [{"date": "2026-03-31", "open": 1.08, "high": 1.082, "low": 1.078, "close": 1.0800}]
            if url.endswith("/api/eod/GBPUSD.FOREX"):
                return [{"date": "2026-03-31", "open": 1.27, "high": 1.272, "low": 1.268, "close": 1.2700}]
            return []

        provider = EodhdReferenceProvider(api_key=_EODHD_TEST_KEY, transport=eodhd_transport)
        ledger = _base_ledger(
            prior_positions=[
                NormalizedPosition(prior_period_or_ending="prior", symbol="ASML", asset_class=AssetClass.EQUITY, quantity=100.0, cost_basis=85_000.0, market_value=88_000.0),
                NormalizedPosition(prior_period_or_ending="prior", symbol="AAPL", asset_class=AssetClass.EQUITY, quantity=25.0, cost_basis=9_500.0, market_value=10_000.0),
            ],
            trades=[
                NormalizedTrade(venue="NASDAQ", native_entry_id="T-SPLIT-1", symbol="AAPL", asset_class=AssetClass.EQUITY, side="buy", quantity=20.0, price=100.50, timestamp_utc="2026-03-03T15:00:00Z", exchange="NASDAQ"),
                NormalizedTrade(venue="CBOE", native_entry_id="T-OPT-1", symbol="MSFT 260320P00400000", asset_class=AssetClass.OPTION, side="sell", quantity=1.0, price=3.50, timestamp_utc="2026-03-05T15:05:00Z", multiplier=100.0, option_right="P", strike=400.0, expiry="2026-03-20", underlying_symbol="MSFT"),
                NormalizedTrade(venue="LSE", native_entry_id="T-GBX-1", symbol="VOD", asset_class=AssetClass.EQUITY, side="buy", quantity=1_000.0, price=0.725, timestamp_utc="2026-03-12T11:00:00Z", currency="GBP", fx_rate_to_base=1.27, exchange="LSE"),
                NormalizedTrade(venue="NYSE", native_entry_id="T-T1-KO", symbol="KO", asset_class=AssetClass.EQUITY, side="buy", quantity=200.0, price=50.0, timestamp_utc="2026-03-31T19:00:00Z", exchange="NYSE"),
            ],
            corporate_actions=[
                CorporateActionRecord(action_type=CorporateActionType.SPLIT, timestamp_utc="2026-03-10T20:00:00Z", symbol="AAPL", quantity_delta=75.0),
                CorporateActionRecord(action_type=CorporateActionType.OPTION_ASSIGNMENT, timestamp_utc="2026-03-20T20:00:00Z", symbol="MSFT 260320P00400000", quantity_delta=1.0, underlying_symbol="MSFT", option_multiplier=100.0, strike=400.0),
            ],
            flows=[
                NormalizedFlow(timestamp_utc="2026-03-27T12:00:00Z", kind=FlowKind.DIVIDEND, amount=172.80, currency="USD", symbol="ASML"),
            ],
            ending_positions=[
                NormalizedPosition(prior_period_or_ending="ending", symbol="ASML", asset_class=AssetClass.EQUITY, quantity=100.0, cost_basis=85_000.0, market_value=90_000.0),
                NormalizedPosition(prior_period_or_ending="ending", symbol="AAPL", asset_class=AssetClass.EQUITY, quantity=120.0, cost_basis=11_510.0, market_value=12_120.0),
                NormalizedPosition(prior_period_or_ending="ending", symbol="MSFT", asset_class=AssetClass.EQUITY, quantity=100.0, cost_basis=39_650.0, market_value=40_200.0),
                NormalizedPosition(prior_period_or_ending="ending", symbol="VOD", asset_class=AssetClass.EQUITY, quantity=1_000.0, cost_basis=725.0, market_value=730.0, currency="GBP", fx_rate_to_base=1.27),
                NormalizedPosition(prior_period_or_ending="ending", symbol="KO", asset_class=AssetClass.EQUITY, quantity=200.0, cost_basis=10_000.0, market_value=10_000.0),
            ],
            conversion_rates={"EUR/USD": 1.081944, "GBP/USD": 1.27},
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-03-01T20:00:00Z", nav_base=200_000.0, cash_base=102_000.0, positions_base=98_000.0),
                NormalizedNavPoint(timestamp_utc="2026-03-31T20:00:00Z", nav_base=202_839.15, cash_base=59_592.05, positions_base=153_247.10),
            ],
        )

        out = verify_portfolio(ledger=ledger, reference_provider=provider, issued_at_utc="2026-04-02T12:00:00Z")
        self.assertEqual(out.reconciliation.status, ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE)
        self.assertEqual(out.reconciliation.discrepancy_count, 0)
        self.assertGreaterEqual(out.reconciliation.explained_convention_count, 3)
        self.assertTrue(out.verification.valid)

    def test_scenario_02_in_kind_acats_transfer_and_missing_section_trap(self) -> None:
        acats_flex_xml = """<?xml version="1.0" encoding="UTF-8"?>
<FlexQueryResponse queryName="ACATS Audit" type="AF">
  <FlexStatements count="1">
    <FlexStatement accountId="U8881112" baseCurrency="USD" fromDate="2026-01-01" toDate="2026-01-15">
      <EquitySummaryInBase>
        <EquitySummaryByReportDateInBase reportDate="2026-01-02" cash="10000.00" stock="0.00" total="10000.00" />
        <EquitySummaryByReportDateInBase reportDate="2026-01-15" cash="10000.00" stock="40000.00" total="50000.00" />
      </EquitySummaryInBase>
      <PriorPeriodPositions />
      <OpenPositions>
        <OpenPosition symbol="MSFT" isin="US5949181045" assetCategory="STK" position="100" costBasisMoney="40000.00" positionValue="40000.00" currency="USD" levelOfDetail="SUMMARY" />
      </OpenPositions>
      <Trades />
      <CashTransactions />
      <Transfers>
        <Transfer type="ACATS" direction="IN" symbol="MSFT" isin="US5949181045" quantity="100" positionAmount="40000.00" positionAmountInBase="40000.00" currency="USD" dateTime="2026-01-10;11:00:00" description="ACATS In-Kind Share Transfer" />
      </Transfers>
      <CorporateActions />
      <OptionEAE />
    </FlexStatement>
  </FlexStatements>
</FlexQueryResponse>"""
        ok_out = verify_portfolio(flex_xml=acats_flex_xml, blinding_salt_hex=_SALT_HEX, issued_at_utc="2026-01-20T12:00:00Z")
        self.assertEqual(ok_out.reconciliation.status, ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE)
        self.assertAlmostEqual(ok_out.performance.twr_decimal, 0.0, places=6)

        missing_transfers = _base_ledger(
            enabled_sections=[s for s in _ALL_SECTIONS if s != "Transfers"],
            period_start_utc="2026-01-02T20:00:00Z",
            period_end_utc="2026-01-10T20:00:00Z",
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-01-02T20:00:00Z", nav_base=10_000.0),
                NormalizedNavPoint(timestamp_utc="2026-01-10T20:00:00Z", nav_base=50_000.0),
            ],
            ending_positions=[
                NormalizedPosition(prior_period_or_ending="ending", symbol="MSFT", asset_class=AssetClass.EQUITY, quantity=100.0, cost_basis=40_000.0, market_value=40_000.0),
            ],
        )
        trap_transfers = verify_portfolio(ledger=missing_transfers, issued_at_utc="2026-01-20T12:00:00Z")
        self.assertEqual(trap_transfers.reconciliation.status, ReconciliationStatus.INSUFFICIENT_SECTIONS)
        self.assertFalse(trap_transfers.reconciliation.ledger_completeness_ok)
        self.assertIn("Transfers", trap_transfers.reconciliation.missing_sections)

        missing_opt_eae = _base_ledger(
            enabled_sections=[s for s in _ALL_SECTIONS if s != "OptionEAE"],
            period_start_utc="2026-01-02T20:00:00Z",
            period_end_utc="2026-01-16T20:00:00Z",
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-01-02T20:00:00Z", nav_base=50_000.0),
                NormalizedNavPoint(timestamp_utc="2026-01-16T20:00:00Z", nav_base=50_000.0),
            ],
            trades=[
                NormalizedTrade(venue="CBOE", native_entry_id="OPT-TRAP-1", symbol="AAPL 260116P00180000", asset_class=AssetClass.OPTION, side="sell", quantity=1.0, price=2.0, timestamp_utc="2026-01-05T15:00:00Z", multiplier=100.0, option_right="P", strike=180.0, expiry="2026-01-16", underlying_symbol="AAPL"),
            ],
            ending_positions=[
                NormalizedPosition(prior_period_or_ending="ending", symbol="AAPL", asset_class=AssetClass.EQUITY, quantity=100.0, cost_basis=17_800.0, market_value=18_000.0),
            ],
        )
        trap_eae = verify_portfolio(ledger=missing_opt_eae, issued_at_utc="2026-01-20T12:00:00Z")
        self.assertEqual(trap_eae.reconciliation.status, ReconciliationStatus.INSUFFICIENT_SECTIONS)
        self.assertFalse(trap_eae.reconciliation.ledger_completeness_ok)
        self.assertIn("OptionEAE", trap_eae.reconciliation.missing_sections)

    def test_scenario_03_edited_ending_nav_plus_10_pct(self) -> None:
        tampered_ledger = _base_ledger(
            period_start_utc="2026-02-01T20:00:00Z",
            period_end_utc="2026-02-10T20:00:00Z",
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-02-01T20:00:00Z", nav_base=100_000.0),
                NormalizedNavPoint(timestamp_utc="2026-02-10T20:00:00Z", nav_base=112_200.0),
            ],
            trades=[
                NormalizedTrade(venue="NASDAQ", native_entry_id="TR-EDIT-1", symbol="MSFT", asset_class=AssetClass.EQUITY, side="buy", quantity=100.0, price=400.0, timestamp_utc="2026-02-05T15:00:00Z"),
            ],
            ending_positions=[
                NormalizedPosition(prior_period_or_ending="ending", symbol="MSFT", asset_class=AssetClass.EQUITY, quantity=100.0, cost_basis=40_000.0, market_value=42_000.0),
            ],
        )
        out = verify_portfolio(ledger=tampered_ledger, issued_at_utc="2026-02-12T12:00:00Z")
        self.assertEqual(out.reconciliation.status, ReconciliationStatus.UNEXPLAINED_RESIDUAL)

        internal_bridge = next(
            f for f in out.reconciliation.findings
            if f.category == "nav_continuity_bridge" and f.outcome == CheckOutcome.DISCREPANCY
        )
        self.assertIsNotNone(internal_bridge.residual_base_currency)
        assert internal_bridge.residual_base_currency is not None
        self.assertAlmostEqual(internal_bridge.residual_base_currency, 10_200.0, places=2)

        recon_leaf = next(l for l in out.proof_bundle.disclosed_leaves if l.leaf_name == "reconciliation")
        pub_bridge = next(
            f for f in recon_leaf.payload["findings"]
            if f["category"] == "nav_continuity_bridge" and f["outcome"] == "discrepancy"
        )
        self.assertIsNone(pub_bridge["residual_base_currency"])
        self.assertIsNone(pub_bridge["expected_value"])
        self.assertIsNone(pub_bridge["observed_value"])
        self.assertIsInstance(pub_bridge["residual_bps"], float)
        self.assertGreater(abs(pub_bridge["residual_bps"]), 800.0)

        bundle_json = json.dumps(out.proof_bundle.to_dict())
        for raw_dollar_token in ("112200", "102000", "10200", "42000"):
            self.assertNotIn(raw_dollar_token, bundle_json)

    def test_scenario_04_two_stage_fill_bounds_extended_hours_vs_impossible_print(self) -> None:
        intraday_calls: list[tuple[str, str]] = []

        def transport(url: str, params: Mapping[str, str]) -> Any:
            if url.endswith("/api/eod/NVDA.US"):
                return [{"date": "2026-03-10", "open": 136.0, "high": 140.0, "low": 135.0, "close": 139.0, "adjusted_close": 139.0, "volume": 40_000_000}]
            if url.endswith("/api/intraday/NVDA.US"):
                intraday_calls.append(("NVDA.US", str(params.get("interval"))))
                return [{"timestamp": 1_773_145_800, "open": 141.0, "high": 143.5, "low": 140.5, "close": 142.5}]
            if url.endswith("/api/eod/MSFT.US"):
                return [{"date": "2026-03-10", "open": 398.0, "high": 405.0, "low": 395.0, "close": 400.0, "adjusted_close": 400.0, "volume": 20_000_000}]
            if url.endswith("/api/intraday/MSFT.US"):
                intraday_calls.append(("MSFT.US", str(params.get("interval"))))
                return [{"timestamp": 1_773_154_800, "open": 396.0, "high": 407.0, "low": 393.0, "close": 401.0}]
            return []

        provider = EodhdReferenceProvider(api_key=_EODHD_TEST_KEY, transport=transport)
        ledger = _base_ledger(
            period_start_utc="2026-03-09T20:00:00Z",
            period_end_utc="2026-03-10T20:00:00Z",
            trades=[
                NormalizedTrade(venue="NASDAQ", native_entry_id="PRE-OK", symbol="NVDA", asset_class=AssetClass.EQUITY, side="buy", quantity=10.0, price=142.50, timestamp_utc="2026-03-10T12:30:00Z", exchange="NASDAQ"),
                NormalizedTrade(venue="NASDAQ", native_entry_id="IMP-BAD", symbol="MSFT", asset_class=AssetClass.EQUITY, side="buy", quantity=10.0, price=250.00, timestamp_utc="2026-03-10T15:00:00Z", exchange="NASDAQ"),
            ],
            ending_positions=[
                NormalizedPosition(prior_period_or_ending="ending", symbol="NVDA", asset_class=AssetClass.EQUITY, quantity=10.0, cost_basis=1_425.0, market_value=1_390.0),
                NormalizedPosition(prior_period_or_ending="ending", symbol="MSFT", asset_class=AssetClass.EQUITY, quantity=10.0, cost_basis=2_500.0, market_value=4_000.0),
            ],
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-03-09T20:00:00Z", nav_base=20_000.0),
                NormalizedNavPoint(timestamp_utc="2026-03-10T20:00:00Z", nav_base=21_465.0),
            ],
        )

        out = verify_portfolio(ledger=ledger, reference_provider=provider, issued_at_utc="2026-03-20T12:00:00Z")
        self.assertIn(("NVDA.US", "1m"), intraday_calls)
        self.assertIn(("MSFT.US", "1m"), intraday_calls)

        nvda_findings = [f for f in out.reconciliation.findings if f.category == "trade_fill_envelope" and f.symbol == "NVDA"]
        self.assertEqual(len(nvda_findings), 1)
        self.assertEqual(nvda_findings[0].outcome, CheckOutcome.PASS)

        msft_disc = [
            f for f in out.reconciliation.findings
            if f.category == "trade_fill_envelope" and f.symbol == "MSFT" and f.outcome == CheckOutcome.DISCREPANCY
        ]
        self.assertEqual(len(msft_disc), 1)
        self.assertGreater(len(msft_disc[0].benign_causes_considered), 0)
        self.assertNotIn("fraud", json.dumps(out.reconciliation.to_dict()).lower())
        self.assertNotIn("fraud", json.dumps(out.proof_bundle.to_dict()).lower())

    def test_scenario_05_eodhd_delisted_isin_renamed_ticker_and_zero_raw_bars(self) -> None:
        def transport(url: str, params: Mapping[str, str]) -> Any:
            if "/api/search/US00507V1098" in url:
                return []
            if "/api/exchange-symbol-list/US" in url:
                self.assertEqual(params.get("delisted"), "1")
                return [{"Code": "ATVI", "Name": "Activision Blizzard", "Exchange": "NASDAQ", "Currency": "USD", "Isin": "US00507V1098"}]
            if url.endswith("/api/eod/ATVI.US"):
                return [{"date": "2023-10-10", "open": 94.12, "high": 94.55, "low": 93.95, "close": 94.42, "adjusted_close": 94.42, "volume": 18_321_000}]
            if url.endswith("/api/eod/FB.US"):
                return []
            if url.endswith("/api/symbol-change-history"):
                return [{"exchange": "US", "old_symbol": "FB", "new_symbol": "META", "effective": "2022-06-09"}]
            if url.endswith("/api/eod/META.US"):
                return [
                    {"date": "2023-10-10", "open": 323.0, "high": 329.0, "low": 321.5, "close": 325.0, "adjusted_close": 324.2, "volume": 19_400_000},
                    {"date": "2023-10-12", "open": 326.0, "high": 330.0, "low": 324.0, "close": 328.0, "adjusted_close": 327.2, "volume": 17_200_000},
                ]
            if url.endswith("/api/eod/SPY.US"):
                return [
                    {"date": "2023-10-09", "open": 430.0, "high": 432.0, "low": 428.0, "close": 430.0, "adjusted_close": 430.0, "volume": 65_000_000},
                    {"date": "2023-10-12", "open": 433.0, "high": 436.0, "low": 432.0, "close": 434.3, "adjusted_close": 434.3, "volume": 61_000_000},
                ]
            return []

        provider = EodhdReferenceProvider(api_key=_EODHD_TEST_KEY, transport=transport)
        atvi_sec = provider.resolve_security("ATVI", exchange="NASDAQ", isin="US00507V1098")
        self.assertIsNotNone(atvi_sec)
        assert atvi_sec is not None
        self.assertEqual(atvi_sec.canonical_ticker, "ATVI.US")
        self.assertTrue(atvi_sec.is_delisted)

        ledger = _base_ledger(
            period_start_utc="2023-10-09T20:00:00Z",
            period_end_utc="2023-10-12T20:00:00Z",
            trades=[
                NormalizedTrade(venue="NASDAQ", native_entry_id="DEL-1", symbol="ATVI", isin="US00507V1098", asset_class=AssetClass.EQUITY, side="buy", quantity=10.0, price=94.42, timestamp_utc="2023-10-10T14:30:00Z", exchange="NASDAQ"),
                NormalizedTrade(venue="NASDAQ", native_entry_id="DEL-2", symbol="ATVI", isin="US00507V1098", asset_class=AssetClass.EQUITY, side="sell", quantity=10.0, price=94.50, timestamp_utc="2023-10-10T19:30:00Z", exchange="NASDAQ"),
                NormalizedTrade(venue="NASDAQ", native_entry_id="REN-1", symbol="FB", asset_class=AssetClass.EQUITY, side="buy", quantity=10.0, price=325.0, timestamp_utc="2023-10-10T15:00:00Z", exchange="NASDAQ"),
            ],
            ending_positions=[
                NormalizedPosition(prior_period_or_ending="ending", symbol="FB", asset_class=AssetClass.EQUITY, quantity=10.0, cost_basis=3_250.0, market_value=3_280.0),
            ],
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2023-10-09T20:00:00Z", nav_base=10_000.0),
                NormalizedNavPoint(timestamp_utc="2023-10-12T20:00:00Z", nav_base=10_030.80),
            ],
        )

        out = verify_portfolio(
            ledger=ledger,
            reference_provider=provider,
            benchmark_symbol="SPY.US",
            issued_at_utc="2026-04-01T12:00:00Z",
        )
        self.assertEqual(provider.resolved_renames.get("FB.US"), "META.US")
        self.assertEqual(out.reconciliation.status, ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE)

        bundle_str = json.dumps(out.proof_bundle.to_dict())
        for forbidden_ohlcv_key in ("adjusted_close", "raw_close", "raw_open", "ohlcv", "18321000", "94.42", "434.3"):
            self.assertNotIn(forbidden_ohlcv_key, bundle_str)

    def test_scenario_06_mutating_crypto_key_rejection_and_coinbase_entry_id_dedup(self) -> None:
        mutating_cases: list[tuple[str, Any]] = [
            ("binance", {"enableReading": True, "enableWithdrawals": True, "enableInternalTransfer": False, "permitsUniversalTransfer": False, "enableSpotAndMarginTrading": True, "enableFutures": False, "enableMargin": False}),
            ("coinbase", {"can_view": True, "can_trade": True, "can_transfer": True}),
            ("kraken", {"error": [], "result": {"permissions": {"query_funds": True, "orders": True, "withdraw": True}}}),
            ("bybit", {"retCode": 0, "result": {"readOnly": 0, "userID": "9901", "permissions": {"ContractTrade": ["Order"], "Wallet": ["AccountTransfer"]}}}),
        ]
        for exchange_id, perm_payload in mutating_cases:
            seen_urls: list[str] = []
            adapter = CcxtExchangeReadOnlyAdapter(
                exchange_id,
                api_key="SYNTH_KEY",
                api_secret="SYNTH_SECRET",
                http_transport=lambda _m, u, _h, _b, payload=perm_payload, log=seen_urls: (log.append(u) or (200, {}, payload)),
            )
            with self.assertRaises(MutatingCredentialRejectedError):
                verify_portfolio(connector=adapter, blinding_salt_hex=_SALT_HEX)
            self.assertEqual(len(seen_urls), 1, f"{exchange_id} made extra calls beyond permission check: {seen_urls}")

        shared_trade_fills = [
            {"entry_id": "CB-ENTRY-A", "trade_id": "SHARED-TRD-500", "product_id": "ETH-USD", "side": "BUY", "size": "1.5", "price": "3100.00", "commission": "3.10", "trade_time": "2026-02-01T10:00:00Z"},
            {"entry_id": "CB-ENTRY-B", "trade_id": "SHARED-TRD-500", "product_id": "ETH-USD", "side": "BUY", "size": "2.5", "price": "3101.00", "commission": "5.15", "trade_time": "2026-02-01T10:00:01Z"},
            {"entry_id": "CB-ENTRY-A", "trade_id": "SHARED-TRD-500", "product_id": "ETH-USD", "side": "BUY", "size": "1.5", "price": "3100.00", "commission": "2.90", "trade_time": "2026-02-01T10:00:00Z"},
            {"entry_id": "CB-ENTRY-B-REPL", "replaces_entry_id": "CB-ENTRY-B", "trade_id": "SHARED-TRD-500", "product_id": "ETH-USD", "side": "BUY", "size": "2.5", "price": "3100.50", "commission": "5.00", "trade_time": "2026-02-01T10:00:02Z"},
        ]
        deduped = deduplicate_coinbase_fills_by_entry_id(shared_trade_fills)
        self.assertEqual([f["entry_id"] for f in deduped], ["CB-ENTRY-A", "CB-ENTRY-B-REPL"])

        def mock_cb(_m: str, url: str, _h: dict[str, str], _b: bytes | None) -> tuple[int, dict[str, str], Any]:
            if "/api/v3/brokerage/key_permissions" in url:
                return (200, {}, {"can_view": True, "can_trade": False, "can_transfer": False})
            if "/api/v3/brokerage/accounts" in url:
                return (200, {}, {"accounts": [{"retail_portfolio_id": "port-main"}], "has_next": False})
            if "/api/v3/brokerage/orders/historical/fills" in url:
                return (200, {}, {"fills": shared_trade_fills})
            raise AssertionError(f"Unexpected Coinbase URL {url}")

        cb_ledger = CcxtExchangeReadOnlyAdapter("coinbase", http_transport=mock_cb).fetch_canonical_ledger(
            blinding_salt_hex=_SALT_HEX,
            period_start_utc="2026-02-01T00:00:00Z",
            period_end_utc="2026-02-02T00:00:00Z",
        )
        self.assertEqual([t.native_entry_id for t in cb_ledger.trades], ["CB-ENTRY-A", "CB-ENTRY-B-REPL"])

    def test_scenario_07_ibkr_gdcdyn_url_trap_and_alpaca_paper_rejection(self) -> None:
        flex_calls: list[tuple[str, dict[str, str]]] = []
        statement_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<FlexQueryResponse queryName="Flex Web Audit" type="AF">
  <FlexStatements count="1">
    <FlexStatement accountId="U7771234" baseCurrency="USD" fromDate="2026-02-01" toDate="2026-02-05">
      <EquitySummaryInBase>
        <EquitySummaryByReportDateInBase reportDate="2026-02-02" cash="25000.00" stock="0.00" total="25000.00" />
        <EquitySummaryByReportDateInBase reportDate="2026-02-05" cash="25000.00" stock="0.00" total="25000.00" />
      </EquitySummaryInBase>
      <PriorPeriodPositions /><OpenPositions /><Trades /><CashTransactions /><Transfers /><CorporateActions /><OptionEAE />
    </FlexStatement>
  </FlexStatements>
</FlexQueryResponse>"""

        def mock_flex(_m: str, url: str, headers: dict[str, str], _b: bytes | None) -> tuple[int, dict[str, str], bytes]:
            flex_calls.append((url, dict(headers)))
            if "SendRequest" in url:
                send_resp = b"""<?xml version="1.0" encoding="UTF-8"?>
<FlexStatementResponse>
  <Status>Success</Status>
  <ReferenceCode>REF909090</ReferenceCode>
  <Url>https://gdcdyn.interactivebrokers.com/Universal/servlet/FlexStatementService.GetStatement</Url>
</FlexStatementResponse>"""
                return (200, {"content-type": "application/xml"}, send_resp)
            return (200, {"content-type": "application/xml"}, statement_xml)

        flex_adapter = IbkrFlexWebServiceAdapter(
            user_agent="N170InstitutionalAudit/3.0",
            http_transport=mock_flex,
            sleep_fn=lambda _: None,
        )
        out = verify_portfolio(
            connector=flex_adapter,
            connector_fetch_kwargs={"flex_token": "FLEX_TOK_SYNTH", "query_id": "QID_101"},
            blinding_salt_hex=_SALT_HEX,
            issued_at_utc="2026-02-06T12:00:00Z",
        )
        self.assertEqual(len(flex_calls), 2)
        self.assertTrue(flex_calls[0][0].startswith(IBKR_FLEX_SEND_REQUEST_URL))
        self.assertTrue(flex_calls[1][0].startswith(IBKR_FLEX_GET_STATEMENT_URL))
        self.assertNotIn("gdcdyn.interactivebrokers.com", flex_calls[1][0])
        self.assertEqual(flex_calls[0][1]["User-Agent"], "N170InstitutionalAudit/3.0")
        self.assertEqual(flex_calls[1][1]["User-Agent"], "N170InstitutionalAudit/3.0")
        self.assertEqual(out.reconciliation.status, ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE)

        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            AlpacaReadOnlyAdapter(
                api_key_id="PK_PAPER",
                api_secret_key="SK_PAPER",
                base_url="https://paper-api.alpaca.markets",
            )

        pa_adapter = AlpacaReadOnlyAdapter(
            api_key_id="AK_LIVE",
            api_secret_key="SK_LIVE",
            http_transport=lambda _m, _u, _h, _b: (
                200,
                {},
                {"account_number": "PA998877665", "currency": "USD", "equity": "50000"},
            ),
        )
        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            verify_portfolio(connector=pa_adapter, blinding_salt_hex=_SALT_HEX)

    def test_scenario_08_self_signed_fork_spoof_and_revoked_key_cross_runtime(self) -> None:
        official_kp = generate_ed25519_keypair()
        revoked_kp = generate_ed25519_keypair()
        attacker_fork_kp = generate_ed25519_keypair()

        registry = PublisherKeyRegistryDocument(
            updated_at_utc="2026-03-01T00:00:00Z",
            keys=[
                PublisherKeyRecord(
                    publisher_kid="n170-official-2026-q1",
                    public_key_hex=official_kp.public_key_hex,
                    status="active",
                    not_before_utc="2026-01-01T00:00:00Z",
                ),
                PublisherKeyRecord(
                    publisher_kid="n170-compromised-2026-01",
                    public_key_hex=revoked_kp.public_key_hex,
                    status="revoked",
                    not_before_utc="2026-01-01T00:00:00Z",
                    revoked_after_utc="2026-01-15T00:00:00Z",
                ),
            ],
        )

        ledger = _base_ledger(
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-03-01T20:00:00Z", nav_base=50_000.0),
                NormalizedNavPoint(timestamp_utc="2026-03-31T20:00:00Z", nav_base=50_000.0),
            ],
        )
        now_iso = "2026-04-01T12:00:00Z"

        spoof_bundle = verify_portfolio(
            ledger=ledger,
            issued_at_utc=now_iso,
            publisher_kid="attacker-fork-spoof-kid",
            publisher_private_key_hex=attacker_fork_kp.private_key_hex,
            registry_doc=registry,
        ).proof_bundle

        revoked_bundle = verify_portfolio(
            ledger=ledger,
            issued_at_utc=now_iso,
            publisher_kid="n170-compromised-2026-01",
            publisher_private_key_hex=revoked_kp.private_key_hex,
            registry_doc=registry,
        ).proof_bundle

        py_spoof = verify_proof_bundle(spoof_bundle, registry_doc=registry, now_utc=now_iso)
        py_revoked = verify_proof_bundle(revoked_bundle, registry_doc=registry, now_utc=now_iso)

        self.assertTrue(py_spoof.valid)
        self.assertEqual(py_spoof.signer_trust_status, SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER)
        self.assertEqual(py_spoof.effective_origin_assurance, OriginAssurance.SELF_REPORTED)

        self.assertFalse(py_revoked.valid)
        self.assertEqual(py_revoked.signer_trust_status, SignerTrustStatus.REVOKED_KEY)

        stdin_payload = json.dumps(
            {
                "spoof": spoof_bundle.to_dict(),
                "revoked": revoked_bundle.to_dict(),
                "registry": registry.to_dict(),
                "nowUtc": now_iso,
            }
        )

        mcp_js_code = (
            "const fs = require('node:fs');"
            "const { verifyProofBundle } = require('./mcp/server.js');"
            "(async () => {"
            "  const d = JSON.parse(fs.readFileSync(0, 'utf8'));"
            "  const spoof = await verifyProofBundle(d.spoof, { registryDoc: d.registry, nowUtc: d.nowUtc });"
            "  const revoked = await verifyProofBundle(d.revoked, { registryDoc: d.registry, nowUtc: d.nowUtc });"
            "  process.stdout.write(JSON.stringify({ spoof, revoked }));"
            "})();"
        )
        mcp_proc = subprocess.run(
            [_NODE_BIN, "-e", mcp_js_code],
            input=stdin_payload,
            text=True,
            capture_output=True,
            cwd=_REPO_DIR,
            check=True,
        )
        mcp_res = json.loads(mcp_proc.stdout)

        runtimes_to_check: list[tuple[str, Any]] = [("node_mcp", mcp_res)]
        if (_REPO_DIR / "web/src/lib/browserVerify.ts").is_file():
            ts_code = (
                "import fs from 'node:fs';"
                "import { verifyProofBundle } from './web/src/lib/browserVerify.ts';"
                "const d = JSON.parse(fs.readFileSync(0, 'utf8'));"
                "const spoof = await verifyProofBundle(d.spoof, { registryDoc: d.registry, nowUtc: d.nowUtc });"
                "const revoked = await verifyProofBundle(d.revoked, { registryDoc: d.registry, nowUtc: d.nowUtc });"
                "process.stdout.write(JSON.stringify({ spoof, revoked }));"
            )
            ts_proc = subprocess.run(
                [_NODE_BIN, "--experimental-strip-types", "--input-type=module", "-e", ts_code],
                input=stdin_payload,
                text=True,
                capture_output=True,
                cwd=_REPO_DIR,
                check=True,
            )
            ts_res = json.loads(ts_proc.stdout)
            runtimes_to_check.append(("webcrypto_ts", ts_res))

        for runtime_name, res in runtimes_to_check:
            with self.subTest(runtime=runtime_name):
                self.assertEqual(res["spoof"]["valid"], True)
                self.assertEqual(res["spoof"]["proof_hash"], py_spoof.proof_hash)
                self.assertEqual(res["spoof"]["signer_trust_status"], SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER.value)
                self.assertEqual(res["spoof"]["effective_origin_assurance"], OriginAssurance.SELF_REPORTED.value)

                self.assertEqual(res["revoked"]["valid"], False)
                self.assertEqual(res["revoked"]["proof_hash"], py_revoked.proof_hash)
                self.assertEqual(res["revoked"]["signer_trust_status"], SignerTrustStatus.REVOKED_KEY.value)


if __name__ == "__main__":
    unittest.main()
