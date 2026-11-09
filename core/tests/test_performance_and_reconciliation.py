"""Comprehensive unit tests for N170 Verify v3 reference, performance, and reconciliation modules."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
import json
import os
from typing import Any
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import numpy as np

from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    CanonicalPortfolioLedger,
    CapitalBracket,
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
    compute_blinded_account_tag,
)
from n170_verify.performance import (
    calculate_portfolio_performance,
    calculate_portfolio_performance_detailed,
    estimate_glm_ma2,
    solve_xirr_act365,
)
from n170_verify.reconciliation import (
    reconcile_portfolio_ledger,
)
from n170_verify.reference import (
    EodhdQuotaGuardError,
    EodhdRateLimitError,
    EodhdReferenceProvider,
    NullReferenceProvider,
    QuotaBudgetTracker,
    ReferenceProviderError,
    build_reference_provider,
)


_SYNTHETIC_SALT = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
_SYNTHETIC_TAG = compute_blinded_account_tag("ibkr", "ACCT-SYNTH-001", _SYNTHETIC_SALT)
_SYNTHETIC_SHA = "ab" * 32
_TEST_API_KEY = "TEST_EODHD_KEY_ALPHA_99"


def _make_base_ledger(**overrides: Any) -> CanonicalPortfolioLedger:
    defaults: dict[str, Any] = {
        "blinded_account_tag": _SYNTHETIC_TAG,
        "broker_id": "ibkr",
        "account_scope": AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
        "claimed_origin_assurance": OriginAssurance.OPERATOR_RETRIEVED,
        "provider_approval_state": ProviderApprovalState.APPROVED_LIVE,
        "environment_tier": EnvironmentTier.LIVE_PRODUCTION,
        "source_body_sha256": _SYNTHETIC_SHA,
        "base_currency": "USD",
        "period_start_utc": "2026-01-01T00:00:00Z",
        "period_end_utc": "2026-03-31T20:00:00Z",
        "enabled_sections": [
            "EquitySummaryByReportDateInBase",
            "Trades",
            "OpenPositions",
            "PriorPeriodPositions",
            "CashTransactions",
            "Transfers",
            "CorporateActions",
            "OptionEAE",
        ],
    }
    defaults.update(overrides)
    return CanonicalPortfolioLedger(**defaults)


class TestEodhdReferenceProvider(unittest.TestCase):
    """Tests for EODHD quota guards, secret redaction, and 4-stage normalization."""

    def test_null_provider_degradation_when_api_key_unset(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("EODHD_API_KEY", None)
            provider = build_reference_provider(None)
        self.assertIsInstance(provider, NullReferenceProvider)
        self.assertEqual(provider.provider_name, "none")
        self.assertFalse(provider.is_available)
        self.assertEqual(
            provider.get_daily_envelopes("AAPL.US", start_date="2026-01-02", end_date="2026-01-05"),
            [],
        )

    def test_fmt_json_enforced_and_bulk_symbols_blocked(self) -> None:
        captured_calls: list[tuple[str, dict[str, str]]] = []

        def transport(url: str, params: Mapping[str, str]) -> Any:
            captured_calls.append((url, dict(params)))
            return []

        provider = EodhdReferenceProvider(api_key=_TEST_API_KEY, transport=transport)
        provider.get_splits("AAPL.US")
        provider.get_dividends("AAPL.US", start_date="2026-01-01", end_date="2026-03-01")
        provider.get_bulk_last_day("US", date_str="2026-03-02")

        self.assertEqual(len(captured_calls), 3)
        for _, params in captured_calls:
            self.assertEqual(params.get("fmt"), "json")

        # Weights: 1 (splits) + 1 (div) + 100 (bulk) == 102
        self.assertEqual(provider.quota_tracker.daily_calls_used, 102)

        # Passing symbols= to /api/eod-bulk-last-day/ must be explicitly blocked (100 + K trap).
        with self.assertRaises(EodhdQuotaGuardError):
            provider.get_bulk_last_day("US", extra_params={"symbols": "AAPL,MSFT"})

        # Passing non-json fmt must also be rejected.
        with self.assertRaises(EodhdQuotaGuardError):
            provider._request_json("/api/eod/AAPL.US", {"fmt": "csv"})

    def test_secret_redaction_in_repr_logs_and_exceptions(self) -> None:
        def failing_transport(url: str, params: Mapping[str, str]) -> Any:
            leaked_url = f"{url}?api_token={params['api_token']}&fmt=json"
            raise HTTPError(
                url=leaked_url,
                code=403,
                msg=f"Forbidden for token {_TEST_API_KEY} at {leaked_url}",
                hdrs=None,  # type: ignore[arg-type]
                fp=None,
            )

        provider = EodhdReferenceProvider(api_key=_TEST_API_KEY, transport=failing_transport)
        self.assertNotIn(_TEST_API_KEY, repr(provider))
        self.assertNotIn(_TEST_API_KEY, str(provider))
        self.assertIn("[REDACTED]", repr(provider))

        with self.assertRaises(ReferenceProviderError) as ctx:
            provider.get_splits("AAPL.US")

        err = ctx.exception
        self.assertNotIn(_TEST_API_KEY, str(err))
        self.assertNotIn(_TEST_API_KEY, repr(err))
        self.assertIsNone(err.__cause__)
        self.assertIn("[REDACTED]", str(err))
        for logged_path, _ in provider.quota_tracker.call_log:
            self.assertNotIn(_TEST_API_KEY, logged_path)

    def test_rate_limiter_enforces_minute_and_daily_budgets(self) -> None:
        now = [100.0]
        tracker = QuotaBudgetTracker(
            max_requests_per_minute=2,
            max_calls_per_day=6,
            clock=lambda: now[0],
        )
        provider = EodhdReferenceProvider(
            api_key=_TEST_API_KEY,
            transport=lambda u, p: [],
            quota_tracker=tracker,
        )
        provider.get_splits("AAPL.US")
        provider.get_splits("MSFT.US")
        with self.assertRaises(EodhdRateLimitError):
            provider.get_splits("NVDA.US")

        # Advance past 60s minute window, then test daily weighted call limit (used=2, remaining=4 < intraday=5)
        now[0] += 61.0
        with self.assertRaises(EodhdRateLimitError):
            provider.get_intraday_envelope("AAPL.US", start_unix=1_700_000_000, end_unix=1_700_003_600)

    def test_delisted_isin_atvi_fallback_and_caching(self) -> None:
        delisted_calls = [0]

        def transport(url: str, params: Mapping[str, str]) -> Any:
            self.assertEqual(params["fmt"], "json")
            if "/api/search/US00507V1098" in url:
                # /api/search/ omits delisted ATVI.US!
                return []
            if "/api/exchange-symbol-list/US" in url:
                self.assertEqual(params.get("delisted"), "1")
                delisted_calls[0] += 1
                return [
                    {
                        "Code": "ATVI",
                        "Name": "Activision Blizzard Inc",
                        "Exchange": "NASDAQ",
                        "Currency": "USD",
                        "Isin": "US00507V1098",
                    }
                ]
            return []

        provider = EodhdReferenceProvider(api_key=_TEST_API_KEY, transport=transport)
        sec1 = provider.resolve_security("ATVI", exchange="NASDAQ", isin="US00507V1098")
        sec2 = provider.resolve_security("ATVI", exchange="US", isin="US00507V1098")
        self.assertIsNotNone(sec1)
        assert sec1 is not None and sec2 is not None
        self.assertEqual(sec1.canonical_ticker, "ATVI.US")
        self.assertTrue(sec1.is_delisted)
        self.assertEqual(sec1.resolution_source, "delisted_exchange_list")
        self.assertEqual(sec2.canonical_ticker, "ATVI.US")
        self.assertEqual(delisted_calls[0], 1)

    def test_renamed_ticker_fb_to_meta_resolution_on_empty_eod(self) -> None:
        def transport(url: str, params: Mapping[str, str]) -> Any:
            self.assertEqual(params["fmt"], "json")
            if url.endswith("/api/eod/FB.US"):
                return []
            if url.endswith("/api/symbol-change-history"):
                return [
                    {
                        "exchange": "US",
                        "old_symbol": "FB",
                        "new_symbol": "META",
                        "effective": "2022-06-09",
                    }
                ]
            if url.endswith("/api/eod/META.US"):
                return [
                    {
                        "date": "2021-10-15",
                        "open": 325.0,
                        "high": 329.0,
                        "low": 322.0,
                        "close": 324.76,
                        "adjusted_close": 323.10,
                        "volume": 15_000_000,
                    }
                ]
            if url.endswith("/api/splits/META.US"):
                return []
            return []

        provider = EodhdReferenceProvider(api_key=_TEST_API_KEY, transport=transport)
        bars = provider.get_daily_envelopes("FB.US", start_date="2021-10-15", end_date="2021-10-15")
        self.assertEqual(len(bars), 1)
        self.assertEqual(bars[0].ticker, "META.US")
        self.assertAlmostEqual(bars[0].raw_close, 324.76)
        self.assertEqual(provider.resolved_renames.get("FB.US"), "META.US")

    def test_pure_splits_reconstruction_ignores_dividend_corrupted_adjusted_close(self) -> None:
        def transport(url: str, params: Mapping[str, str]) -> Any:
            if url.endswith("/api/eod/AAPL.US"):
                # Raw pre-4:1-split bar; adjusted_close includes heavy cumulative dividends (ratio 0.2375 != 0.25)
                return [
                    {
                        "date": "2020-08-10",
                        "open": 400.0,
                        "high": 408.0,
                        "low": 396.0,
                        "close": 400.0,
                        "adjusted_close": 95.0,
                        "volume": 400_000_000,
                    }
                ]
            if url.endswith("/api/splits/AAPL.US"):
                return [{"date": "2020-08-31", "split": "4.000000/1.000000"}]
            return []

        provider = EodhdReferenceProvider(api_key=_TEST_API_KEY, transport=transport)
        envs = provider.get_daily_envelopes("AAPL.US", start_date="2020-08-10", end_date="2020-08-10")
        self.assertEqual(len(envs), 1)
        env = envs[0]
        self.assertAlmostEqual(env.cumulative_split_factor, 4.0)
        # Pure split-adjusted bounds MUST be [99.0, 102.0], NOT dividend-corrupted [94.05, 96.90]!
        self.assertAlmostEqual(env.split_adjusted_low, 99.0)
        self.assertAlmostEqual(env.split_adjusted_high, 102.0)
        self.assertAlmostEqual(env.split_adjusted_close, 100.0)
        self.assertAlmostEqual(env.raw_unadjusted_volume or 0.0, 100_000_000.0)

    def test_uk_lse_gbx_100x_normalization_and_licensing_safe_benchmark(self) -> None:
        def transport(url: str, params: Mapping[str, str]) -> Any:
            if "/api/search/VOD" in url:
                return [{"Code": "VOD", "Exchange": "LSE", "Currency": "GBX", "ISIN": "GB00BH4HKS39"}]
            if url.endswith("/api/eod/VOD.LSE"):
                return [
                    {
                        "date": "2026-02-02",
                        "open": 72.0,
                        "high": 74.0,
                        "low": 71.0,
                        "close": 72.0,
                        "adjusted_close": 72.0,
                        "volume": 50_000_000,
                    },
                    {
                        "date": "2026-02-03",
                        "open": 73.0,
                        "high": 76.0,
                        "low": 72.5,
                        "close": 75.6,
                        "adjusted_close": 75.6,
                        "volume": 48_000_000,
                    },
                ]
            if url.endswith("/api/splits/VOD.LSE"):
                return []
            return []

        provider = EodhdReferenceProvider(api_key=_TEST_API_KEY, transport=transport)
        envs = provider.get_daily_envelopes("VOD.LSE", start_date="2026-02-02", end_date="2026-02-03")
        self.assertEqual(len(envs), 2)
        self.assertEqual(envs[0].raw_currency, "GBX")
        self.assertEqual(envs[0].currency, "GBP")
        self.assertAlmostEqual(envs[0].raw_low, 0.71)
        self.assertAlmostEqual(envs[0].raw_high, 0.74)

        bench = provider.get_derived_benchmark_series("VOD.LSE", dates=["2026-02-02", "2026-02-03"])
        self.assertIsNotNone(bench)
        assert bench is not None
        self.assertAlmostEqual(bench.indexed_values_by_date["2026-02-02"], 100.0)
        self.assertAlmostEqual(bench.indexed_values_by_date["2026-02-03"], 105.0)
        self.assertAlmostEqual(bench.twr_decimal, 0.05)


class TestPerformanceAndEconometrics(unittest.TestCase):
    """Tests for TWR, in-kind flows, ACT/365 XIRR, PSR sample gate, and GLM MA(2) unsmoothing."""

    def test_psr_sample_size_gate_withholds_when_t_under_30(self) -> None:
        start = datetime(2026, 1, 1, 20, 0, tzinfo=timezone.utc)
        navs: list[NormalizedNavPoint] = []
        val = 54_321.0
        # 21 NAV points -> T = 20 return observations (< 30!)
        for day in range(21):
            if day > 0:
                val *= 1.002 if day % 3 != 0 else 0.999
            navs.append(
                NormalizedNavPoint(
                    timestamp_utc=(start + timedelta(days=day)).isoformat().replace("+00:00", "Z"),
                    nav_base=round(val, 4),
                )
            )

        ledger = _make_base_ledger(
            period_start_utc=navs[0].timestamp_utc,
            period_end_utc=navs[-1].timestamp_utc,
            nav_points=navs,
        )
        summary = calculate_portfolio_performance(ledger)
        self.assertEqual(summary.observation_count, 20)
        self.assertFalse(summary.psr_sample_eligible)
        self.assertIsNone(summary.probabilistic_sharpe_ratio)
        self.assertIsNone(summary.min_track_record_length_periods)
        self.assertIsNone(summary.psr_glm_unsmoothed)
        self.assertEqual(summary.capital_bracket, CapitalBracket.BRACKET_10K_100K)
        self.assertEqual(summary.indexed_curve[0].index_value, 100.0)
        self.assertTrue(any("at least 30" in w for w in summary.warnings))
        # Verify single-account deflated ratio and raw dollar NAV are completely absent from contract serialization.
        serialized = json.dumps(summary.to_dict())
        self.assertNotIn('"' + "d" + 'sr"', serialized.lower())
        self.assertNotIn("deflated_sharpe", serialized.lower())
        self.assertNotIn("54321", serialized)

    def test_glm_ma2_unsmoothing_populates_psr_glm_unsmoothed_when_xi_below_080(self) -> None:
        rng = np.random.default_rng(42)
        # Generate T = 90 true innovations and smooth with theta = (0.50, 0.35, 0.15) -> true xi = 0.395
        innov = rng.normal(loc=0.0025, scale=0.012, size=92)
        smoothed = 0.50 * innov[2:] + 0.35 * innov[1:-1] + 0.15 * innov[:-2]

        glm_direct = estimate_glm_ma2(smoothed.tolist())
        self.assertIsNotNone(glm_direct)
        assert glm_direct is not None
        self.assertAlmostEqual(
            glm_direct.theta_0 + glm_direct.theta_1 + glm_direct.theta_2,
            1.0,
            places=6,
        )
        self.assertLess(glm_direct.smoothing_index_xi, 0.80)

        start = datetime(2026, 1, 1, 20, 0, tzinfo=timezone.utc)
        nav_val = 250_000.0
        navs = [NormalizedNavPoint(timestamp_utc="2026-01-01T20:00:00Z", nav_base=nav_val)]
        for idx, r in enumerate(smoothed.tolist(), start=1):
            nav_val *= 1.0 + float(r)
            navs.append(
                NormalizedNavPoint(
                    timestamp_utc=(start + timedelta(days=idx)).isoformat().replace("+00:00", "Z"),
                    nav_base=nav_val,
                )
            )

        ledger = _make_base_ledger(
            period_start_utc=navs[0].timestamp_utc,
            period_end_utc=navs[-1].timestamp_utc,
            nav_points=navs,
        )
        summary = calculate_portfolio_performance(ledger)
        self.assertEqual(summary.observation_count, 90)
        self.assertTrue(summary.psr_sample_eligible)
        self.assertIsNotNone(summary.probabilistic_sharpe_ratio)
        self.assertIsNotNone(summary.min_track_record_length_periods)
        self.assertIsNotNone(summary.smoothing_index_xi)
        self.assertIsNotNone(summary.psr_glm_unsmoothed)
        assert (
            summary.smoothing_index_xi is not None
            and summary.unsmoothed_volatility is not None
            and summary.annualized_volatility is not None
            and summary.unsmoothed_sharpe_ratio is not None
            and summary.sharpe_ratio is not None
            and summary.psr_glm_unsmoothed is not None
            and summary.probabilistic_sharpe_ratio is not None
        )
        self.assertLess(summary.smoothing_index_xi, 0.80)
        self.assertGreater(summary.unsmoothed_volatility, summary.annualized_volatility)
        self.assertLess(summary.unsmoothed_sharpe_ratio, summary.sharpe_ratio)
        self.assertLess(summary.psr_glm_unsmoothed, summary.probabilistic_sharpe_ratio)

    def test_in_kind_transfer_twr_neutralization_and_unvalued_flow_withholding(self) -> None:
        # Day 0: $100,000 -> Day 1: +5% gain ($105,000) + $50,000 ACATS TRANSFER_IN_KIND = $155,000
        # Day 2: +2% gain on $155,000 = $158,100 -> true TWR = 1.05 * 1.02 - 1 = 0.071 (+7.1%)!
        navs = [
            NormalizedNavPoint(timestamp_utc="2026-02-01T20:00:00Z", nav_base=100_000.0),
            NormalizedNavPoint(timestamp_utc="2026-02-02T20:00:00Z", nav_base=155_000.0),
            NormalizedNavPoint(timestamp_utc="2026-02-03T20:00:00Z", nav_base=158_100.0),
        ]
        valued_acats = NormalizedFlow(
            timestamp_utc="2026-02-02T16:00:00Z",
            kind=FlowKind.TRANSFER_IN_KIND,
            amount=50_000.0,
            currency="USD",
            symbol="MSFT",
            quantity=125.0,
            transfer_type="ACATS",
        )
        ledger_ok = _make_base_ledger(
            period_start_utc=navs[0].timestamp_utc,
            period_end_utc=navs[-1].timestamp_utc,
            nav_points=navs,
            flows=[valued_acats],
        )
        summary_ok = calculate_portfolio_performance(ledger_ok)
        self.assertAlmostEqual(summary_ok.twr_decimal, 0.071, places=8)
        self.assertAlmostEqual(summary_ok.indexed_curve[-1].index_value, 107.1, places=6)

        # Unvalued in-kind transfer (quantity=125, amount=0.0) MUST withhold TWR rather than report +58.1%!
        unvalued_acats = NormalizedFlow(
            timestamp_utc="2026-02-02T16:00:00Z",
            kind=FlowKind.TRANSFER_IN_KIND,
            amount=0.0,
            currency="USD",
            symbol="MSFT",
            quantity=125.0,
            transfer_type="ACATS",
        )
        ledger_unvalued = _make_base_ledger(
            period_start_utc=navs[0].timestamp_utc,
            period_end_utc=navs[-1].timestamp_utc,
            nav_points=navs,
            flows=[unvalued_acats],
        )
        detail = calculate_portfolio_performance_detailed(ledger_unvalued)
        self.assertTrue(detail.withheld)
        self.assertEqual(detail.summary.indexed_curve, [])
        self.assertTrue(any("withheld" in w.lower() for w in detail.summary.warnings))

    def test_log_scaled_xirr_act365_multi_root_warning(self) -> None:
        t0 = datetime(2025, 1, 1, tzinfo=timezone.utc)
        t1 = t0 + timedelta(days=365)
        t2 = t0 + timedelta(days=730)
        # Multiple sign changes: -100, +230, -132 has exact annual IRR roots at r = 0.10 and r = 0.20!
        rate, warnings = solve_xirr_act365(
            [(t0, -100.0), (t1, 230.0), (t2, -132.0)],
            preferred_rate=0.11,
        )
        self.assertIsNotNone(rate)
        assert rate is not None
        self.assertAlmostEqual(rate, 0.10, places=6)
        self.assertTrue(any("roots" in w for w in warnings))


class TestCalibratedReconciliation(unittest.TestCase):
    """Tests for 2-stage fill envelopes, OptionEAE basis link, ACATS missing sections, and altered NAV."""

    def test_two_stage_fill_check_rth_vs_1m_extended_hours_vs_discrepancy_and_overnight_skip(self) -> None:
        intraday_calls: list[dict[str, str]] = []

        def transport(url: str, params: Mapping[str, str]) -> Any:
            if url.endswith("/api/eod/NVDA.US"):
                return [
                    {
                        "date": "2026-03-10",
                        "open": 181.0,
                        "high": 185.0,
                        "low": 180.0,
                        "close": 184.0,
                        "adjusted_close": 184.0,
                        "volume": 40_000_000,
                    }
                ]
            if url.endswith("/api/splits/NVDA.US"):
                return []
            if url.endswith("/api/intraday/NVDA.US"):
                intraday_calls.append(dict(params))
                return [
                    {"timestamp": 1_773_178_200, "open": 185.0, "high": 189.25, "low": 179.50, "close": 188.80},
                ]
            return []

        provider = EodhdReferenceProvider(api_key=_TEST_API_KEY, transport=transport)

        # Case A: RTH fill at 183.50 inside [180, 185] -> Stage 1 PASS, ZERO /api/intraday/ calls!
        rth_trade = NormalizedTrade(
            venue="NASDAQ",
            native_entry_id="T-RTH-1",
            symbol="NVDA",
            asset_class=AssetClass.EQUITY,
            side="buy",
            quantity=10.0,
            price=183.50,
            timestamp_utc="2026-03-10T15:30:00Z",
            exchange="NASDAQ",
        )
        ledger_rth = _make_base_ledger(
            period_start_utc="2026-03-09T20:00:00Z",
            period_end_utc="2026-03-10T20:00:00Z",
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-03-09T20:00:00Z", nav_base=10_000.0),
                NormalizedNavPoint(timestamp_utc="2026-03-10T20:00:00Z", nav_base=10_005.0),
            ],
            trades=[rth_trade],
            ending_positions=[
                NormalizedPosition(
                    prior_period_or_ending="ending",
                    symbol="NVDA",
                    asset_class=AssetClass.EQUITY,
                    quantity=10.0,
                    cost_basis=1_835.0,
                    market_value=1_840.0,
                )
            ],
        )
        rep_rth = reconcile_portfolio_ledger(
            ledger_rth,
            reference_provider=provider,
            reference_now_utc="2026-03-25T12:00:00Z",
        )
        self.assertEqual(rep_rth.status, ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE)
        self.assertEqual(len(intraday_calls), 0)

        # Case B: Post-market fill at 188.50 (17:15 EDT = 21:15Z) breaches RTH [180, 185] -> Stage 2 1m PASS!
        ext_trade = NormalizedTrade(
            venue="NASDAQ",
            native_entry_id="T-EXT-1",
            symbol="NVDA",
            asset_class=AssetClass.EQUITY,
            side="buy",
            quantity=10.0,
            price=188.50,
            timestamp_utc="2026-03-10T21:15:00Z",
            exchange="NASDAQ",
        )
        ledger_ext = _make_base_ledger(
            period_start_utc="2026-03-09T20:00:00Z",
            period_end_utc="2026-03-10T22:00:00Z",
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-03-09T20:00:00Z", nav_base=10_000.0),
                NormalizedNavPoint(timestamp_utc="2026-03-10T22:00:00Z", nav_base=9_955.0),
            ],
            trades=[ext_trade],
            ending_positions=[
                NormalizedPosition(
                    prior_period_or_ending="ending",
                    symbol="NVDA",
                    asset_class=AssetClass.EQUITY,
                    quantity=10.0,
                    cost_basis=1_885.0,
                    market_value=1_840.0,
                )
            ],
        )
        rep_ext = reconcile_portfolio_ledger(
            ledger_ext,
            reference_provider=provider,
            reference_now_utc="2026-03-25T12:00:00Z",
        )
        self.assertEqual(rep_ext.status, ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE)
        self.assertEqual(len(intraday_calls), 1)
        self.assertEqual(intraday_calls[0]["interval"], "1m")

        # Case C: Off-market fill at 199.00 breaches both Stage 1 and Stage 2 -> DISCREPANCY, zero "fraud" strings!
        off_trade = NormalizedTrade(
            venue="NASDAQ",
            native_entry_id="T-OFF-1",
            symbol="NVDA",
            asset_class=AssetClass.EQUITY,
            side="buy",
            quantity=10.0,
            price=199.00,
            timestamp_utc="2026-03-10T21:15:00Z",
            exchange="NASDAQ",
        )
        ledger_off = _make_base_ledger(
            period_start_utc="2026-03-09T20:00:00Z",
            period_end_utc="2026-03-10T22:00:00Z",
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-03-09T20:00:00Z", nav_base=10_000.0),
                NormalizedNavPoint(timestamp_utc="2026-03-10T22:00:00Z", nav_base=9_850.0),
            ],
            trades=[off_trade],
            ending_positions=[
                NormalizedPosition(
                    prior_period_or_ending="ending",
                    symbol="NVDA",
                    asset_class=AssetClass.EQUITY,
                    quantity=10.0,
                    cost_basis=1_990.0,
                    market_value=1_840.0,
                )
            ],
        )
        rep_off = reconcile_portfolio_ledger(
            ledger_off,
            reference_provider=provider,
            reference_now_utc="2026-03-25T12:00:00Z",
        )
        self.assertEqual(rep_off.status, ReconciliationStatus.UNEXPLAINED_RESIDUAL)
        fill_disc = [
            f
            for f in rep_off.findings
            if f.category == "trade_fill_envelope" and f.outcome == CheckOutcome.DISCREPANCY
        ]
        self.assertEqual(len(fill_disc), 1)
        self.assertTrue(len(fill_disc[0].benign_causes_considered) >= 2)
        self.assertNotIn("fraud", json.dumps(rep_off.to_dict()).lower())

        # Case D: Fill > 3h past US extended-hours close (23:30 EDT on 2026-03-10 == 2026-03-11T03:30:00Z) skips intraday!
        calls_before_overnight = len(intraday_calls)
        overnight_trade = NormalizedTrade(
            venue="NASDAQ",
            native_entry_id="T-OVN-1",
            symbol="NVDA",
            asset_class=AssetClass.EQUITY,
            side="buy",
            quantity=10.0,
            price=188.50,
            timestamp_utc="2026-03-11T03:30:00Z",
            exchange="NASDAQ",
        )
        ledger_ovn = _make_base_ledger(
            period_start_utc="2026-03-09T20:00:00Z",
            period_end_utc="2026-03-11T04:00:00Z",
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-03-09T20:00:00Z", nav_base=10_000.0),
                NormalizedNavPoint(timestamp_utc="2026-03-11T04:00:00Z", nav_base=9_955.0),
            ],
            trades=[overnight_trade],
            ending_positions=[
                NormalizedPosition(
                    prior_period_or_ending="ending",
                    symbol="NVDA",
                    asset_class=AssetClass.EQUITY,
                    quantity=10.0,
                    cost_basis=1_885.0,
                    market_value=1_840.0,
                )
            ],
        )
        reconcile_portfolio_ledger(
            ledger_ovn,
            reference_provider=provider,
            reference_now_utc="2026-03-25T12:00:00Z",
        )
        self.assertEqual(len(intraday_calls), calls_before_overnight)

    def test_option_eae_worthless_expiry_and_short_put_assignment_100x_delivery_and_basis_link(self) -> None:
        # Opening cash $50,000.
        # 1) Sell 1 call AAPL 260320C00210000 @ $2.00 ($200 credit) -> expires worthless (0 shares delivered).
        # 2) Sell 2 puts AAPL 260320P00180000 @ $3.50 ($700 credit) -> assigned -> +200 shares AAPL @ $180
        #    Strike cash paid = -$36,000; ending cash = 50,000 + 200 + 700 - 36,000 = $14,900.
        #    Ending AAPL stock cost basis = 200 * 180.0 - 700.0 = $35,300.00!
        #    Ending AAPL market value @ $178.00 = $35,600 -> Ending NAV = 14,900 + 35,600 = $50,500.
        sell_call = NormalizedTrade(
            venue="CBOE",
            native_entry_id="OPT-1",
            symbol="AAPL 260320C00210000",
            asset_class=AssetClass.OPTION,
            side="sell",
            quantity=1.0,
            price=2.00,
            timestamp_utc="2026-03-02T15:00:00Z",
            multiplier=100.0,
            option_right="C",
            strike=210.0,
            expiry="2026-03-20",
            underlying_symbol="AAPL",
        )
        sell_puts = NormalizedTrade(
            venue="CBOE",
            native_entry_id="OPT-2",
            symbol="AAPL 260320P00180000",
            asset_class=AssetClass.OPTION,
            side="sell",
            quantity=2.0,
            price=3.50,
            timestamp_utc="2026-03-02T15:05:00Z",
            multiplier=100.0,
            option_right="P",
            strike=180.0,
            expiry="2026-03-20",
            underlying_symbol="AAPL",
        )
        call_expiry = CorporateActionRecord(
            action_type=CorporateActionType.OPTION_EXPIRATION,
            timestamp_utc="2026-03-20T20:00:00Z",
            symbol="AAPL 260320C00210000",
            quantity_delta=1.0,
            underlying_symbol="AAPL",
            option_multiplier=100.0,
            strike=210.0,
        )
        put_assignment = CorporateActionRecord(
            action_type=CorporateActionType.OPTION_ASSIGNMENT,
            timestamp_utc="2026-03-20T20:00:00Z",
            symbol="AAPL 260320P00180000",
            quantity_delta=2.0,
            underlying_symbol="AAPL",
            option_multiplier=100.0,
            strike=180.0,
        )
        ending_aapl = NormalizedPosition(
            prior_period_or_ending="ending",
            symbol="AAPL",
            asset_class=AssetClass.EQUITY,
            quantity=200.0,
            cost_basis=35_300.0,
            market_value=35_600.0,
        )

        def transport(url: str, params: Mapping[str, str]) -> Any:
            if url.endswith("/api/eod/AAPL.US"):
                return [
                    {
                        "date": "2026-03-20",
                        "open": 179.0,
                        "high": 180.0,
                        "low": 177.0,
                        "close": 178.0,
                        "adjusted_close": 178.0,
                        "volume": 55_000_000,
                    }
                ]
            return []

        provider = EodhdReferenceProvider(api_key=_TEST_API_KEY, transport=transport)
        ledger = _make_base_ledger(
            period_start_utc="2026-03-01T20:00:00Z",
            period_end_utc="2026-03-20T20:00:00Z",
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-03-01T20:00:00Z", nav_base=50_000.0),
                NormalizedNavPoint(timestamp_utc="2026-03-20T20:00:00Z", nav_base=50_500.0),
            ],
            trades=[sell_call, sell_puts],
            corporate_actions=[call_expiry, put_assignment],
            ending_positions=[ending_aapl],
        )
        report = reconcile_portfolio_ledger(ledger, reference_provider=provider)
        self.assertEqual(report.status, ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE)
        self.assertEqual(report.discrepancy_count, 0)
        basis_checks = [f for f in report.findings if f.category == "option_eae_cost_basis_link"]
        self.assertEqual(len(basis_checks), 1)
        self.assertEqual(basis_checks[0].outcome, CheckOutcome.PASS)

    def test_missing_transfers_section_flags_insufficient_sections_on_acats_jump(self) -> None:
        # Ending position has 100 MSFT with zero trades/flows and "Transfers" omitted from enabled_sections
        ledger_missing = _make_base_ledger(
            enabled_sections=[
                "EquitySummaryByReportDateInBase",
                "Trades",
                "OpenPositions",
                "PriorPeriodPositions",
                "CashTransactions",
                "CorporateActions",
                "OptionEAE",
            ],
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-01-01T20:00:00Z", nav_base=10_000.0),
                NormalizedNavPoint(timestamp_utc="2026-01-15T20:00:00Z", nav_base=50_000.0),
            ],
            period_start_utc="2026-01-01T20:00:00Z",
            period_end_utc="2026-01-15T20:00:00Z",
            ending_positions=[
                NormalizedPosition(
                    prior_period_or_ending="ending",
                    symbol="MSFT",
                    asset_class=AssetClass.EQUITY,
                    quantity=100.0,
                    cost_basis=40_000.0,
                    market_value=40_000.0,
                )
            ],
        )
        rep = reconcile_portfolio_ledger(ledger_missing)
        self.assertEqual(rep.status, ReconciliationStatus.INSUFFICIENT_SECTIONS)
        self.assertFalse(rep.ledger_completeness_ok)
        self.assertIn("Transfers", rep.missing_sections)

    def test_altered_nav_plus_10_pct_triggers_unexplained_residual(self) -> None:
        # Genuine ending NAV is $102,000 ($60,000 cash + $42,000 MSFT); altered NAV is +10% ($112,200)!
        trade = NormalizedTrade(
            venue="NASDAQ",
            native_entry_id="TR-100",
            symbol="MSFT",
            asset_class=AssetClass.EQUITY,
            side="buy",
            quantity=100.0,
            price=400.0,
            timestamp_utc="2026-02-05T15:00:00Z",
        )
        ending_pos = NormalizedPosition(
            prior_period_or_ending="ending",
            symbol="MSFT",
            asset_class=AssetClass.EQUITY,
            quantity=100.0,
            cost_basis=40_000.0,
            market_value=42_000.0,
        )
        altered_ledger = _make_base_ledger(
            period_start_utc="2026-02-01T20:00:00Z",
            period_end_utc="2026-02-10T20:00:00Z",
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-02-01T20:00:00Z", nav_base=100_000.0),
                NormalizedNavPoint(timestamp_utc="2026-02-10T20:00:00Z", nav_base=112_200.0),
            ],
            trades=[trade],
            ending_positions=[ending_pos],
        )
        report = reconcile_portfolio_ledger(altered_ledger)
        self.assertEqual(report.status, ReconciliationStatus.UNEXPLAINED_RESIDUAL)
        self.assertGreaterEqual(report.discrepancy_count, 1)
        bridge_disc = [
            f
            for f in report.findings
            if f.category == "nav_continuity_bridge" and f.outcome == CheckOutcome.DISCREPANCY
        ]
        self.assertEqual(len(bridge_disc), 1)
        assert bridge_disc[0].residual_base_currency is not None
        self.assertAlmostEqual(bridge_disc[0].residual_base_currency, 10_200.0, places=2)

    def test_explained_conventions_fx_spread_dividend_accrual_and_settlement_lag(self) -> None:
        def transport(url: str, params: Mapping[str, str]) -> Any:
            if url.endswith("/api/eod/EURUSD.FOREX"):
                return [{"date": "2026-03-31", "open": 1.08, "high": 1.082, "low": 1.078, "close": 1.0800}]
            if url.endswith("/api/eod/EURGBP.FOREX"):
                return [{"date": "2026-03-31", "open": 0.85, "high": 0.852, "low": 0.848, "close": 0.8500}]
            if url.endswith("/api/div/ASML.US"):
                return [
                    {
                        "date": "2026-03-20",
                        "paymentDate": "2026-03-27",
                        "value": 1.52,
                        "unadjustedValue": 1.60,
                        "currency": "EUR",
                    }
                ]
            if url.endswith("/api/eod/ASML.US"):
                return [
                    {
                        "date": "2026-03-31",
                        "open": 900.0,
                        "high": 905.0,
                        "low": 895.0,
                        "close": 900.0,
                        "adjusted_close": 900.0,
                        "volume": 1_000_000,
                    }
                ]
            return []

        provider = EodhdReferenceProvider(api_key=_TEST_API_KEY, transport=transport)

        # EUR/USD at 1.081944 is ~18 bps off 1.0800 (<= 25 bps major -> EXPLAINED_CONVENTION)
        # EUR/GBP at 0.853825 is ~45 bps off 0.8500 (<= 60 bps cross -> EXPLAINED_CONVENTION)
        # ASML pay-date dividend on 2026-03-27 for 100 shares = 100 * 1.60 EUR * 1.08 = $172.80 (EXPLAINED_CONVENTION)
        prior_asml = NormalizedPosition(
            prior_period_or_ending="prior",
            symbol="ASML",
            asset_class=AssetClass.EQUITY,
            quantity=100.0,
            cost_basis=85_000.0,
            market_value=88_000.0,
        )
        end_asml = NormalizedPosition(
            prior_period_or_ending="ending",
            symbol="ASML",
            asset_class=AssetClass.EQUITY,
            quantity=100.0,
            cost_basis=85_000.0,
            market_value=90_000.0,
        )
        div_flow = NormalizedFlow(
            timestamp_utc="2026-03-27T12:00:00Z",
            kind=FlowKind.DIVIDEND,
            amount=172.80,
            currency="USD",
            symbol="ASML",
        )
        ledger = _make_base_ledger(
            period_start_utc="2026-03-01T20:00:00Z",
            period_end_utc="2026-03-31T20:00:00Z",
            prior_positions=[prior_asml],
            ending_positions=[end_asml],
            flows=[div_flow],
            conversion_rates={
                "EUR/USD": 1.081944,
                "EUR/GBP": 0.853825,
            },
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-03-01T20:00:00Z", nav_base=98_000.0),
                NormalizedNavPoint(timestamp_utc="2026-03-31T20:00:00Z", nav_base=100_172.80),
            ],
        )
        rep = reconcile_portfolio_ledger(ledger, reference_provider=provider)
        self.assertEqual(rep.status, ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE)
        self.assertEqual(rep.discrepancy_count, 0)
        self.assertGreaterEqual(rep.explained_convention_count, 3)

    def test_lse_gbx_fill_and_ending_mark_reconciliation_end_to_end(self) -> None:
        def transport(url: str, params: Mapping[str, str]) -> Any:
            if "/api/search/VOD" in url:
                return [{"Code": "VOD", "Exchange": "LSE", "Currency": "GBX", "ISIN": "GB00BH4HKS39"}]
            if url.endswith("/api/eod/VOD.LSE"):
                return [
                    {
                        "date": "2026-02-10",
                        "open": 72.0,
                        "high": 74.0,
                        "low": 71.0,
                        "close": 73.0,
                        "adjusted_close": 73.0,
                        "volume": 20_000_000,
                    }
                ]
            if url.endswith("/api/splits/VOD.LSE"):
                return []
            if url.endswith("/api/eod/GBPUSD.FOREX"):
                return [{"date": "2026-02-10", "open": 1.27, "high": 1.272, "low": 1.268, "close": 1.2700}]
            return []

        provider = EodhdReferenceProvider(api_key=_TEST_API_KEY, transport=transport)
        # Broker reports VOD trade in GBP (0.725 GBP == 72.5 GBX) while EODHD quotes VOD.LSE in GBX (71..74)!
        vod_trade = NormalizedTrade(
            venue="LSE",
            native_entry_id="LSE-1",
            symbol="VOD",
            asset_class=AssetClass.EQUITY,
            side="buy",
            quantity=1_000.0,
            price=0.725,
            timestamp_utc="2026-02-10T11:00:00Z",
            currency="GBP",
            fx_rate_to_base=1.27,
            exchange="LSE",
        )
        vod_end = NormalizedPosition(
            prior_period_or_ending="ending",
            symbol="VOD",
            asset_class=AssetClass.EQUITY,
            quantity=1_000.0,
            cost_basis=725.0,
            market_value=730.0,
            currency="GBP",
            fx_rate_to_base=1.27,
        )
        # Opening USD = $10,000; spent 725 * 1.27 = $920.75 -> cash = $9,079.25; ending MV = 730 * 1.27 = $927.10 -> NAV = $10,006.35
        ledger = _make_base_ledger(
            period_start_utc="2026-02-09T20:00:00Z",
            period_end_utc="2026-02-10T20:00:00Z",
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-02-09T20:00:00Z", nav_base=10_000.0),
                NormalizedNavPoint(timestamp_utc="2026-02-10T20:00:00Z", nav_base=10_006.35),
            ],
            trades=[vod_trade],
            ending_positions=[vod_end],
        )
        rep = reconcile_portfolio_ledger(ledger, reference_provider=provider)
        self.assertEqual(rep.status, ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE)
        self.assertEqual(rep.discrepancy_count, 0)

    def test_stage2_5m_intraday_escalation_and_split_adjusted_fill_pass(self) -> None:
        intervals_seen: list[str] = []

        def transport(url: str, params: Mapping[str, str]) -> Any:
            if url.endswith("/api/eod/AAPL.US"):
                return [
                    {
                        "date": "2025-07-01",
                        "open": 400.0,
                        "high": 408.0,
                        "low": 396.0,
                        "close": 400.0,
                        "adjusted_close": 95.0,
                        "volume": 400_000_000,
                    }
                ]
            if url.endswith("/api/splits/AAPL.US"):
                return [{"date": "2025-08-01", "split": "4.000000/1.000000"}]
            if url.endswith("/api/intraday/AAPL.US"):
                intervals_seen.append(str(params["interval"]))
                return [{"timestamp": 1_751_395_200, "open": 408.0, "high": 416.0, "low": 395.0, "close": 412.0}]
            return []

        provider = EodhdReferenceProvider(api_key=_TEST_API_KEY, transport=transport)
        # 1) Split-adjusted fill at 100.50 (inside pure split [99, 102], outside dividend-corrupted [94.05, 96.90])
        # 2) Post-market split-adjusted fill at 103.50 (aged ~270d -> Stage-2 5m intraday [98.75, 104.0])
        t_rth = NormalizedTrade(
            venue="NASDAQ",
            native_entry_id="SP-1",
            symbol="AAPL",
            asset_class=AssetClass.EQUITY,
            side="buy",
            quantity=20.0,
            price=100.50,
            timestamp_utc="2025-07-01T15:00:00Z",
            exchange="NASDAQ",
        )
        t_ext = NormalizedTrade(
            venue="NASDAQ",
            native_entry_id="SP-2",
            symbol="AAPL",
            asset_class=AssetClass.EQUITY,
            side="sell",
            quantity=20.0,
            price=103.50,
            timestamp_utc="2025-07-01T21:30:00Z",
            exchange="NASDAQ",
        )
        ledger = _make_base_ledger(
            period_start_utc="2025-06-30T20:00:00Z",
            period_end_utc="2025-09-01T20:00:00Z",
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2025-06-30T20:00:00Z", nav_base=20_000.0),
                NormalizedNavPoint(timestamp_utc="2025-09-01T20:00:00Z", nav_base=20_060.0),
            ],
            trades=[t_rth, t_ext],
        )
        rep = reconcile_portfolio_ledger(
            ledger,
            reference_provider=provider,
            reference_now_utc="2026-03-28T12:00:00Z",
        )
        self.assertEqual(rep.status, ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE)
        self.assertEqual(intervals_seen, ["5m"])

    def test_t2_settlement_lag_and_statistical_diagnostics_neutrality(self) -> None:
        # Unsettled T+1 buy on final day: trade-date positions_base = $10,000, settlement-date cash_base = $50,000,
        # while true economic NAV is $50,000 (cash not yet debited for -$10,000 unsettled purchase).
        trade = NormalizedTrade(
            venue="NYSE",
            native_entry_id="SET-1",
            symbol="KO",
            asset_class=AssetClass.EQUITY,
            side="buy",
            quantity=200.0,
            price=50.0,
            timestamp_utc="2026-03-31T19:00:00Z",
        )
        end_pos = NormalizedPosition(
            prior_period_or_ending="ending",
            symbol="KO",
            asset_class=AssetClass.EQUITY,
            quantity=200.0,
            cost_basis=10_000.0,
            market_value=10_000.0,
        )
        ledger = _make_base_ledger(
            period_start_utc="2026-03-30T20:00:00Z",
            period_end_utc="2026-03-31T20:00:00Z",
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-03-30T20:00:00Z", nav_base=50_000.0),
                NormalizedNavPoint(
                    timestamp_utc="2026-03-31T20:00:00Z",
                    nav_base=50_000.0,
                    cash_base=50_000.0,
                    positions_base=10_000.0,
                ),
            ],
            trades=[trade],
            ending_positions=[end_pos],
        )
        rep = reconcile_portfolio_ledger(ledger)
        self.assertEqual(rep.discrepancy_count, 0)
        self.assertGreaterEqual(rep.explained_convention_count, 1)

        diag_names = {d.metric_name for d in rep.statistical_diagnostics}
        self.assertEqual(
            diag_names,
            {
                "glm_smoothing_index_xi",
                "lag1_return_autocorrelation",
                "return_skewness",
                "return_excess_kurtosis",
                "top_3_period_return_concentration",
            },
        )
        for diag in rep.statistical_diagnostics:
            self.assertTrue(len(diag.caveats) >= 1)
            self.assertNotIn("fraud", diag.interpretation.lower())

    def test_internal_subaccount_transfer_and_modified_dietz_twr(self) -> None:
        navs = [
            NormalizedNavPoint(timestamp_utc="2026-03-01T00:00:00Z", nav_base=100_000.0),
            NormalizedNavPoint(timestamp_utc="2026-03-02T00:00:00Z", nav_base=126_000.0),
        ]
        # Midday +$25,000 internal subaccount sweep (weight = 0.5 under Modified Dietz):
        # Gain = 126,000 - 100,000 - 25,000 = 1,000; weighted capital = 100,000 + 0.5 * 25,000 = 112,500
        sweep = NormalizedFlow(
            timestamp_utc="2026-03-01T12:00:00Z",
            kind=FlowKind.INTERNAL_SUBACCOUNT_TRANSFER,
            amount=25_000.0,
            currency="USD",
        )
        ledger = _make_base_ledger(
            account_scope=AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED,
            period_start_utc=navs[0].timestamp_utc,
            period_end_utc=navs[-1].timestamp_utc,
            nav_points=navs,
            flows=[sweep],
        )
        summary_dietz = calculate_portfolio_performance(ledger, cash_flow_timing="modified_dietz")
        self.assertAlmostEqual(summary_dietz.twr_decimal, 1_000.0 / 112_500.0, places=8)


if __name__ == "__main__":
    unittest.main()
