"""Comprehensive unit and pipeline tests for Wave-4B Viral Quant & Visual Coaching tools."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import math
import time
import unittest

import pytest

from n170_verify.catalysts import CatalystAvailabilityInterval
from n170_verify.coaching import (
    ARCHETYPE_CATALYST_SPECIALIST,
    ARCHETYPE_HIGH_CONVICTION_SWING,
    ARCHETYPE_INTRADAY_LIQUIDITY,
    ARCHETYPE_LOW_TURNOVER_COMPOUNDER,
    ARCHETYPE_SYSTEMATIC_ALLOCATOR,
    ClosedRoundTrip,
    FORBIDDEN_CLAIM_SUBSTRINGS,
    TraderCoachingEngine,
    build_trader_coaching_report,
    compute_behavioural_coaching_metrics,
    compute_cost_and_drag_breakdown,
    compute_quant_dna_profile,
    compute_session_expectancy_heatmap,
    contains_currency_amount,
    contains_forbidden_claim,
    sanitize_journal_tags,
    simulate_counterfactual_twin,
)
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    CanonicalPortfolioLedger,
    ClaimPlausibilityAnalysis,
    EnvironmentTier,
    FlowKind,
    NormalizedFlow,
    NormalizedNavPoint,
    NormalizedTrade,
    OriginAssurance,
    ProviderApprovalState,
)
from n170_verify.contracts.coaching import DEFAULT_COUNTERFACTUAL_DISCLAIMER
from n170_verify.crypto import CANONICAL_LEAF_NAMES
import n170_verify.performance as perf_pkg
from n170_verify.performance import (
    CLAIM_SUFFICIENCY_BORDERLINE,
    CLAIM_SUFFICIENCY_NOISE_DOMINATED,
    CLAIM_SUFFICIENCY_SUFFICIENT_IF_UNSMOOTHED,
    calculate_portfolio_performance,
    compute_min_track_record_length,
    compute_probabilistic_sharpe_ratio,
    evaluate_claim_plausibility,
    run_stationary_block_bootstrap,
)
try:
    from n170_verify.pipeline import api_worker_pipeline_entrypoint, verify_portfolio
except ImportError:  # pragma: no cover - pipeline lands in Phase 3
    api_worker_pipeline_entrypoint = None
    verify_portfolio = None


def _make_base_ledger(
    *,
    nav_points: list[NormalizedNavPoint],
    trades: list[NormalizedTrade] | None = None,
    flows: list[NormalizedFlow] | None = None,
    period_start_utc: str | None = None,
    period_end_utc: str | None = None,
) -> CanonicalPortfolioLedger:
    start_iso = period_start_utc or (nav_points[0].timestamp_utc if nav_points else "2026-01-01T00:00:00Z")
    end_iso = period_end_utc or (nav_points[-1].timestamp_utc if nav_points else "2026-03-31T00:00:00Z")
    return CanonicalPortfolioLedger(
        blinded_account_tag="a1" * 32,
        broker_id="ibkr",
        account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
        claimed_origin_assurance=OriginAssurance.SELF_REPORTED,
        provider_approval_state=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
        environment_tier=EnvironmentTier.LIVE_PRODUCTION,
        source_body_sha256="b2" * 32,
        base_currency="USD",
        period_start_utc=start_iso,
        period_end_utc=end_iso,
        nav_points=nav_points,
        trades=trades or [],
        flows=flows or [],
        enabled_sections=[
            "PriorPeriodPositions",
            "OpenPositions",
            "Trades",
            "CashTransactions",
            "Transfers",
            "CorporateActions",
            "OptionEAE",
        ],
    )


class TestClaimPlausibilityMinTrlBuster(unittest.TestCase):
    """Tests for evaluate_claim_plausibility in performance/econometrics.py."""

    def test_reexport_in_performance_package(self) -> None:
        self.assertIn("evaluate_claim_plausibility", perf_pkg.__all__)
        self.assertIs(perf_pkg.evaluate_claim_plausibility, evaluate_claim_plausibility)

    def test_strict_input_validation_rejects_bools_nan_inf_and_out_of_bounds(self) -> None:
        # Reject bools on every argument
        with self.assertRaises(ValueError):
            evaluate_claim_plausibility(True, 60)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            evaluate_claim_plausibility(2.0, True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            evaluate_claim_plausibility(2.0, 60, annualization_factor=False)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            evaluate_claim_plausibility(2.0, 60, skewness=True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            evaluate_claim_plausibility(2.0, 60, excess_kurtosis=False)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            evaluate_claim_plausibility(2.0, 60, benchmark_sharpe=True)  # type: ignore[arg-type]

        # Reject non-int observed_periods / annualization_factor
        with self.assertRaises(ValueError):
            evaluate_claim_plausibility(2.0, 45.5)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            evaluate_claim_plausibility(2.0, 45, annualization_factor=252.0)  # type: ignore[arg-type]

        # Reject NaN / Inf
        for non_finite in (math.nan, math.inf, -math.inf):
            with self.assertRaises(ValueError):
                evaluate_claim_plausibility(non_finite, 60)
            with self.assertRaises(ValueError):
                evaluate_claim_plausibility(2.0, 60, skewness=non_finite)
            with self.assertRaises(ValueError):
                evaluate_claim_plausibility(2.0, 60, excess_kurtosis=non_finite)
            with self.assertRaises(ValueError):
                evaluate_claim_plausibility(2.0, 60, benchmark_sharpe=non_finite)

        # Domain bounds
        for bad_obs in (-10, 0, 1, 25_001):
            with self.assertRaises(ValueError):
                evaluate_claim_plausibility(2.0, bad_obs)
        for bad_ann in (-1, 0, 10_001):
            with self.assertRaises(ValueError):
                evaluate_claim_plausibility(2.0, 60, annualization_factor=bad_ann)
        for bad_sr in (-100.01, 100.01):
            with self.assertRaises(ValueError):
                evaluate_claim_plausibility(bad_sr, 60)
            with self.assertRaises(ValueError):
                evaluate_claim_plausibility(2.0, 60, benchmark_sharpe=bad_sr)
        for bad_skew in (-25.01, 25.01):
            with self.assertRaises(ValueError):
                evaluate_claim_plausibility(2.0, 60, skewness=bad_skew)
        for bad_ek in (-2.01, 200.01):
            with self.assertRaises(ValueError):
                evaluate_claim_plausibility(2.0, 60, excess_kurtosis=bad_ek)

    def test_exact_consistency_with_econometrics_psr_and_mintrl(self) -> None:
        cases = [
            # (claimed_sr, obs, ann, skew, excess_kurt, bench_sr)
            (2.4, 120, 252, 0.0, 0.0, 0.0),      # Gaussian (gamma_4 = 3 -> excess = 0)
            (3.2, 90, 252, -0.8, 3.0, 0.5),      # Fat-tailed negative skew
            (1.8, 365, 365, 0.4, 5.5, 0.2),      # Crypto 365-day annualization
            (1.1, 52, 52, -1.2, 2.0, 0.0),       # Weekly observations
        ]
        for claimed_sr, obs, ann, skew, ek, bench_sr in cases:
            res = evaluate_claim_plausibility(
                claimed_sr,
                obs,
                annualization_factor=ann,
                skewness=skew,
                excess_kurtosis=ek,
                benchmark_sharpe=bench_sr,
            )
            sr_hat = claimed_sr / math.sqrt(ann)
            sr_star = bench_sr / math.sqrt(ann)
            expected_psr = compute_probabilistic_sharpe_ratio(
                sr_hat,
                sr_star,
                observation_count=obs,
                skewness=skew,
                excess_kurtosis=ek,
            )
            expected_min_trl = compute_min_track_record_length(
                sr_hat,
                sr_star,
                observation_count=obs,
                skewness=skew,
                excess_kurtosis=ek,
                confidence_level=0.95,
            )
            assert expected_psr is not None
            assert expected_min_trl is not None
            self.assertEqual(res.implied_psr, pytest.approx(expected_psr, rel=1e-12, abs=1e-12))
            self.assertEqual(
                res.required_min_trl_periods_95pct,
                pytest.approx(expected_min_trl, rel=1e-12, abs=1e-12),
            )

        # Fat tails + negative skew strictly increase MinTRL relative to Gaussian returns
        gaussian = evaluate_claim_plausibility(4.0, 60, skewness=0.0, excess_kurtosis=0.0)
        fat_neg_skew = evaluate_claim_plausibility(4.0, 60, skewness=-1.5, excess_kurtosis=6.0)
        assert gaussian.required_min_trl_periods_95pct is not None
        assert fat_neg_skew.required_min_trl_periods_95pct is not None
        self.assertGreater(
            fat_neg_skew.required_min_trl_periods_95pct,
            gaussian.required_min_trl_periods_95pct,
        )
        self.assertLess(fat_neg_skew.implied_psr, gaussian.implied_psr)

    def test_sufficiency_tiers_bell_curve_and_neutral_language(self) -> None:
        # 1. Short track record (<30 periods) -> noise-dominated even at high Sharpe
        short_sample = evaluate_claim_plausibility(4.5, 18)
        self.assertEqual(short_sample.sufficiency_tier, CLAIM_SUFFICIENCY_NOISE_DOMINATED)

        # 2. Claimed <= benchmark -> required_min_trl_periods_95pct is None & noise-dominated
        below_bench = evaluate_claim_plausibility(0.4, 252, benchmark_sharpe=0.5)
        self.assertIsNone(below_bench.required_min_trl_periods_95pct)
        self.assertEqual(below_bench.sufficiency_tier, CLAIM_SUFFICIENCY_NOISE_DOMINATED)

        # 3. Borderline sample (T >= 30 and 0.80 <= PSR < 0.95)
        borderline = evaluate_claim_plausibility(1.5, 180, skewness=0.0, excess_kurtosis=0.0)
        self.assertGreaterEqual(borderline.implied_psr, 0.80)
        self.assertLess(borderline.implied_psr, 0.95)
        self.assertEqual(borderline.sufficiency_tier, CLAIM_SUFFICIENCY_BORDERLINE)

        # 4. Statistically sufficient if unsmoothed (T >= 30 and PSR >= 0.95)
        sufficient = evaluate_claim_plausibility(2.5, 300, skewness=0.0, excess_kurtosis=3.0)
        self.assertGreaterEqual(sufficient.implied_psr, 0.95)
        self.assertEqual(sufficient.sufficiency_tier, CLAIM_SUFFICIENCY_SUFFICIENT_IF_UNSMOOTHED)

        # Bell curve invariants & claim-safety across all outcomes
        for analysis in (short_sample, below_bench, borderline, sufficient):
            pts = analysis.bell_curve_points
            self.assertGreaterEqual(len(pts), 41)
            self.assertLessEqual(len(pts), 61)
            sharpes = [pt["sharpe"] for pt in pts]
            densities = [pt["density"] for pt in pts]
            self.assertEqual(sharpes, sorted(sharpes))
            self.assertTrue(all(d >= 0.0 and math.isfinite(d) for d in densities))
            mid_idx = len(pts) // 2
            self.assertEqual(sharpes[mid_idx], pytest.approx(analysis.claimed_sharpe, abs=1e-5))
            self.assertEqual(densities[mid_idx], max(densities))

            self.assertFalse(contains_forbidden_claim(analysis.plain_english_summary))
            self.assertFalse(contains_currency_amount(analysis.plain_english_summary))
            self.assertEqual(ClaimPlausibilityAnalysis.from_dict(analysis.to_dict()), analysis)


class TestStationaryBlockBootstrapAndCalendarCells(unittest.TestCase):
    """Tests for run_stationary_block_bootstrap and DailyCalendarCell integration."""

    def test_bootstrap_short_sample_and_validation(self) -> None:
        self.assertIsNone(run_stationary_block_bootstrap([]))
        self.assertIsNone(run_stationary_block_bootstrap([0.01, -0.005, 0.004, 0.002]))

        with self.assertRaises(ValueError):
            run_stationary_block_bootstrap([0.01] * 10, num_simulations=0)
        with self.assertRaises(ValueError):
            run_stationary_block_bootstrap([0.01] * 10, horizon_periods=0)
        with self.assertRaises(ValueError):
            run_stationary_block_bootstrap([0.01] * 10, block_length=0)
        with self.assertRaises(ValueError):
            run_stationary_block_bootstrap([0.01] * 10, seed=True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            run_stationary_block_bootstrap([0.01, math.nan, 0.01, 0.01, 0.01])
        with self.assertRaises(ValueError):
            run_stationary_block_bootstrap([0.01, -1.05, 0.01, 0.01, 0.01])

    def test_bootstrap_determinism_monotonicity_drawdown_probs_and_speed_budget(self) -> None:
        # Construct 120 daily returns with fat tails and local streaks
        returns = [
            0.008 if (i % 9 not in {3, 4}) else (-0.032 if i % 18 == 3 else -0.018)
            for i in range(120)
        ]

        # Warm call + deterministic seed check
        res_a = run_stationary_block_bootstrap(returns, num_simulations=1000, seed=170)
        res_b = run_stationary_block_bootstrap(returns, num_simulations=1000, seed=170)
        res_c = run_stationary_block_bootstrap(returns, num_simulations=1000, seed=171)
        assert res_a is not None and res_b is not None and res_c is not None
        self.assertEqual(res_a, res_b)
        self.assertNotEqual(res_a.cone[-1], res_c.cone[-1])

        # Speed budget: 1,000 paths over full 252-period horizon in <50ms
        timings: list[float] = []
        for _ in range(3):
            t0 = time.perf_counter()
            timed_res = run_stationary_block_bootstrap(
                returns,
                horizon_periods=252,
                num_simulations=1000,
                seed=170,
            )
            timings.append(time.perf_counter() - t0)
            assert timed_res is not None
        self.assertLess(min(timings), 0.050)

        # Step 0 rebase at 1.0 + strict quantile monotonicity at every step
        self.assertEqual(res_a.horizon_periods, 120)
        self.assertEqual(len(res_a.cone), 121)
        step0 = res_a.cone[0]
        self.assertEqual(
            (step0.step, step0.p05, step0.p25, step0.p50, step0.p75, step0.p95),
            (0, 1.0, 1.0, 1.0, 1.0, 1.0),
        )
        for idx, pt in enumerate(res_a.cone):
            self.assertEqual(pt.step, idx)
            self.assertLessEqual(pt.p05, pt.p25)
            self.assertLessEqual(pt.p25, pt.p50)
            self.assertLessEqual(pt.p50, pt.p75)
            self.assertLessEqual(pt.p75, pt.p95)

        self.assertLessEqual(res_a.prob_drawdown_20pct, res_a.prob_drawdown_10pct)
        self.assertGreaterEqual(res_a.prob_positive_terminal, 0.0)
        self.assertLessEqual(res_a.prob_positive_terminal, 1.0)

        # Strictly positive return series -> zero drawdown probability and 100% positive terminal
        pos_only = run_stationary_block_bootstrap([0.005] * 8, num_simulations=200, seed=170)
        assert pos_only is not None
        self.assertEqual(pos_only.horizon_periods, 20)
        self.assertEqual(pos_only.prob_drawdown_10pct, 0.0)
        self.assertEqual(pos_only.prob_drawdown_20pct, 0.0)
        self.assertEqual(pos_only.prob_positive_terminal, 1.0)

    def test_calculator_populates_daily_calendar_cells_and_bootstrap_without_touching_twr(self) -> None:
        base_dt = datetime(2026, 1, 5, 0, 0, tzinfo=timezone.utc)
        nav_vals = [100_000.0, 101_000.0, 100_495.0, 102_504.9, 103_529.949, 104_565.24849, 105_610.900975]
        nav_pts = [
            NormalizedNavPoint(
                timestamp_utc=(base_dt + timedelta(days=idx)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                nav_base=val,
            )
            for idx, val in enumerate(nav_vals)
        ]
        trades = [
            NormalizedTrade(
                venue="IBKR",
                native_entry_id="t1",
                symbol="AAPL",
                asset_class=AssetClass.EQUITY,
                side="buy",
                quantity=10.0,
                price=180.0,
                timestamp_utc="2026-01-06T14:30:00Z",
            ),
            NormalizedTrade(
                venue="IBKR",
                native_entry_id="t2",
                symbol="AAPL",
                asset_class=AssetClass.EQUITY,
                side="sell",
                quantity=10.0,
                price=185.0,
                timestamp_utc="2026-01-06T19:30:00Z",
            ),
            NormalizedTrade(
                venue="IBKR",
                native_entry_id="t_cash_ignored",
                symbol="USD",
                asset_class=AssetClass.CASH,
                side="buy",
                quantity=100.0,
                price=1.0,
                timestamp_utc="2026-01-06T20:00:00Z",
            ),
        ]
        ledger = _make_base_ledger(nav_points=nav_pts, trades=trades)
        perf = calculate_portfolio_performance(ledger)

        expected_twr = (nav_vals[-1] / nav_vals[0]) - 1.0
        self.assertEqual(perf.twr_decimal, pytest.approx(expected_twr, rel=1e-9))
        self.assertEqual(len(perf.daily_calendar_cells), 6)
        first_cell = perf.daily_calendar_cells[0]
        self.assertEqual(first_cell.date, "2026-01-06")
        self.assertEqual(first_cell.return_pct, pytest.approx(1.0, abs=1e-6))
        self.assertEqual(first_cell.trade_count, 2)  # CASH trade excluded
        self.assertEqual(set(first_cell.to_dict().keys()), {"date", "return_pct", "trade_count"})
        self.assertIsNotNone(perf.bootstrap_summary)
        assert perf.bootstrap_summary is not None
        self.assertEqual(perf.bootstrap_summary.cone[0].p50, 1.0)


class TestCounterfactualSessionMatrixAndQuantDna(unittest.TestCase):
    """Tests for CounterfactualTwinReport, SessionExpectancyCell, and QuantDnaProfile."""

    def test_zero_friction_twin_adds_back_commissions_fx_and_financing_drag(self) -> None:
        nav_pts = [
            NormalizedNavPoint(timestamp_utc="2026-02-01T00:00:00Z", nav_base=10_000.0),
            NormalizedNavPoint(timestamp_utc="2026-02-02T00:00:00Z", nav_base=10_050.0),
            NormalizedNavPoint(timestamp_utc="2026-02-03T00:00:00Z", nav_base=10_120.0),
            NormalizedNavPoint(timestamp_utc="2026-02-04T00:00:00Z", nav_base=10_180.0),
        ]
        trades = [
            NormalizedTrade(
                venue="IBKR",
                native_entry_id="f1",
                symbol="MSFT",
                asset_class=AssetClass.EQUITY,
                side="buy",
                quantity=20.0,
                price=400.0,
                commission=35.0,
                timestamp_utc="2026-02-02T15:00:00Z",
            ),
            NormalizedTrade(
                venue="IBKR",
                native_entry_id="f2",
                symbol="MSFT",
                asset_class=AssetClass.EQUITY,
                side="sell",
                quantity=20.0,
                price=410.0,
                commission=35.0,
                timestamp_utc="2026-02-03T16:00:00Z",
            ),
        ]
        flows = [
            NormalizedFlow(
                timestamp_utc="2026-02-04T00:00:00Z",
                kind=FlowKind.MARGIN_INTEREST,
                amount=-25.0,
                currency="USD",
            )
        ]
        ledger = _make_base_ledger(nav_points=nav_pts, trades=trades, flows=flows)
        twin = simulate_counterfactual_twin(ledger)

        self.assertTrue(twin.is_hypothetical_simulation)
        self.assertEqual(twin.compliance_disclaimer, DEFAULT_COUNTERFACTUAL_DISCLAIMER)
        self.assertEqual(twin.actual_ending_index, pytest.approx(1.018, abs=1e-6))
        self.assertGreater(twin.zero_friction_ending_index, twin.actual_ending_index)
        self.assertEqual(twin.curve_points[0]["actual"], 1.0)
        self.assertEqual(twin.curve_points[0]["zero_friction"], 1.0)
        self.assertFalse(contains_currency_amount(json.dumps(twin.to_dict())))

    def test_disciplined_sizing_twin_caps_underwater_revenge_sizing(self) -> None:
        # Day 0->1: near HWM (dd=0%), trader sizes 10 shares @ 100 (10% NAV)
        # Day 1->2: portfolio drops 8% into >5% underwater drawdown (10,000 -> 9,200)
        # Day 2->3: while >5% underwater, trader revenge-sizes 30 shares @ 100 (~32.6% NAV -> sdi > 3.0)
        #           and suffers another 10% portfolio loss (9,200 -> 8,280)
        nav_pts = [
            NormalizedNavPoint(timestamp_utc="2026-03-01T00:00:00Z", nav_base=10_000.0),
            NormalizedNavPoint(timestamp_utc="2026-03-02T00:00:00Z", nav_base=10_000.0),
            NormalizedNavPoint(timestamp_utc="2026-03-03T00:00:00Z", nav_base=9_200.0),
            NormalizedNavPoint(timestamp_utc="2026-03-04T00:00:00Z", nav_base=8_280.0),
        ]
        trades = [
            NormalizedTrade(
                venue="IBKR",
                native_entry_id="hwm_open",
                symbol="SPY",
                asset_class=AssetClass.ETF,
                side="buy",
                quantity=10.0,
                price=100.0,
                timestamp_utc="2026-03-01T14:30:00Z",
            ),
            NormalizedTrade(
                venue="IBKR",
                native_entry_id="hwm_close",
                symbol="SPY",
                asset_class=AssetClass.ETF,
                side="sell",
                quantity=10.0,
                price=92.0,
                timestamp_utc="2026-03-02T20:00:00Z",
            ),
            NormalizedTrade(
                venue="IBKR",
                native_entry_id="dd_revenge_open",
                symbol="SPY",
                asset_class=AssetClass.ETF,
                side="buy",
                quantity=30.0,
                price=100.0,
                timestamp_utc="2026-03-03T14:30:00Z",
            ),
            NormalizedTrade(
                venue="IBKR",
                native_entry_id="dd_revenge_close",
                symbol="SPY",
                asset_class=AssetClass.ETF,
                side="sell",
                quantity=30.0,
                price=69.3333,
                timestamp_utc="2026-03-03T20:00:00Z",
            ),
        ]
        ledger = _make_base_ledger(nav_points=nav_pts, trades=trades)
        twin = simulate_counterfactual_twin(ledger)
        self.assertGreater(
            twin.disciplined_post_dd_sizing_ending_index,
            twin.actual_ending_index,
        )

    def test_capped_tail_loss_twin_caps_losses_beyond_95th_percentile_at_90th_stop(self) -> None:
        base_dt = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
        nav_pts: list[NormalizedNavPoint] = []
        trades: list[NormalizedTrade] = []
        nav = 100_000.0
        nav_pts.append(NormalizedNavPoint(timestamp_utc="2026-01-01T00:00:00Z", nav_base=nav))

        # 20 small -1% closed losses followed by 1 fat-tail -30% closed blowup
        for day_idx in range(1, 22):
            dt_open = base_dt + timedelta(days=day_idx, hours=14)
            dt_close = base_dt + timedelta(days=day_idx, hours=18)
            dt_nav = base_dt + timedelta(days=day_idx + 1)
            exit_px = 99.0 if day_idx <= 20 else 70.0  # -1% vs -30%
            pnl = (exit_px - 100.0) * 100.0
            nav += pnl
            trades.append(
                NormalizedTrade(
                    venue="IBKR",
                    native_entry_id=f"open_{day_idx}",
                    symbol="QQQ",
                    asset_class=AssetClass.ETF,
                    side="buy",
                    quantity=100.0,
                    price=100.0,
                    timestamp_utc=dt_open.strftime("%Y-%m-%dT%H:%M:%SZ"),
                )
            )
            trades.append(
                NormalizedTrade(
                    venue="IBKR",
                    native_entry_id=f"close_{day_idx}",
                    symbol="QQQ",
                    asset_class=AssetClass.ETF,
                    side="sell",
                    quantity=100.0,
                    price=exit_px,
                    timestamp_utc=dt_close.strftime("%Y-%m-%dT%H:%M:%SZ"),
                )
            )
            nav_pts.append(
                NormalizedNavPoint(
                    timestamp_utc=dt_nav.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    nav_base=nav,
                )
            )

        ledger = _make_base_ledger(nav_points=nav_pts, trades=trades)
        twin = simulate_counterfactual_twin(ledger)
        self.assertGreater(twin.capped_tail_loss_ending_index, twin.actual_ending_index)

    def test_session_expectancy_heatmap_and_quant_dna_archetypes(self) -> None:
        # 2026-01-05 is Monday (weekday=0); 2026-01-07 is Wednesday (weekday=2)
        trips = [
            ClosedRoundTrip(
                symbol="NVDA",
                asset_class=AssetClass.EQUITY,
                side="long",
                entry_timestamp_utc="2026-01-05T14:15:00Z",
                exit_timestamp_utc="2026-01-05T16:15:00Z",
                matched_quantity=10.0,
                entry_price=100.0,
                exit_price=102.0,
                multiplier=1.0,
                gross_pnl_base=20.0,
                net_pnl_base=20.0,
                return_pct=2.0,
                holding_hours=2.0,
            ),
            ClosedRoundTrip(
                symbol="NVDA",
                asset_class=AssetClass.EQUITY,
                side="long",
                entry_timestamp_utc="2026-01-12T14:45:00Z",
                exit_timestamp_utc="2026-01-12T15:45:00Z",
                matched_quantity=10.0,
                entry_price=100.0,
                exit_price=99.0,
                multiplier=1.0,
                gross_pnl_base=-10.0,
                net_pnl_base=-10.0,
                return_pct=-1.0,
                holding_hours=1.0,
            ),
            ClosedRoundTrip(
                symbol="AAPL",
                asset_class=AssetClass.EQUITY,
                side="long",
                entry_timestamp_utc="2026-01-07T19:00:00Z",
                exit_timestamp_utc="2026-01-07T20:30:00Z",
                matched_quantity=10.0,
                entry_price=100.0,
                exit_price=103.0,
                multiplier=1.0,
                gross_pnl_base=30.0,
                net_pnl_base=30.0,
                return_pct=3.0,
                holding_hours=1.5,
            ),
        ]
        cells = compute_session_expectancy_heatmap(trips)
        self.assertEqual(len(cells), 2)
        self.assertEqual((cells[0].weekday, cells[0].hour_utc, cells[0].trade_count), (0, 14, 2))
        self.assertEqual(cells[0].win_rate, 0.5)
        self.assertEqual(cells[0].expectancy_bps, pytest.approx(50.0, abs=1e-4))
        self.assertEqual((cells[1].weekday, cells[1].hour_utc, cells[1].trade_count), (2, 19, 1))
        self.assertEqual(cells[1].win_rate, 1.0)
        self.assertEqual(cells[1].expectancy_bps, pytest.approx(300.0, abs=1e-4))

        # Quant DNA bounds & archetype coverage
        nav_pts = [
            NormalizedNavPoint(timestamp_utc="2026-01-01T00:00:00Z", nav_base=50_000.0),
            NormalizedNavPoint(timestamp_utc="2026-04-15T00:00:00Z", nav_base=56_000.0),
        ]
        ledger = _make_base_ledger(nav_points=nav_pts)
        low_drag = compute_cost_and_drag_breakdown(ledger)
        beh = compute_behavioural_coaching_metrics(ledger, cost_drag=low_drag)

        dna_intraday = compute_quant_dna_profile(
            ledger,
            behaviour=beh,
            cost_drag=low_drag,
            closed_round_trips=trips,
            event_window_share_pct=5.0,
        )
        self.assertEqual(dna_intraday.archetype_label, ARCHETYPE_INTRADAY_LIQUIDITY)

        dna_catalyst = compute_quant_dna_profile(
            ledger,
            behaviour=beh,
            cost_drag=low_drag,
            closed_round_trips=trips,
            catalyst_regime_win_rate=0.75,
            event_window_share_pct=50.0,
        )
        self.assertEqual(dna_catalyst.archetype_label, ARCHETYPE_CATALYST_SPECIALIST)

        dna_compounder = compute_quant_dna_profile(
            ledger,
            behaviour=beh,
            cost_drag=low_drag,
            closed_round_trips=[],
            event_window_share_pct=0.0,
        )
        self.assertEqual(dna_compounder.archetype_label, ARCHETYPE_LOW_TURNOVER_COMPOUNDER)
        self.assertIn(
            dna_compounder.archetype_label,
            {
                ARCHETYPE_LOW_TURNOVER_COMPOUNDER,
                ARCHETYPE_CATALYST_SPECIALIST,
                ARCHETYPE_INTRADAY_LIQUIDITY,
                ARCHETYPE_HIGH_CONVICTION_SWING,
                ARCHETYPE_SYSTEMATIC_ALLOCATOR,
            },
        )
        for score_attr in (
            "consistency_score",
            "drawdown_resilience_score",
            "cost_efficiency_score",
            "sizing_discipline_score",
            "exit_symmetry_score",
            "catalyst_alignment_score",
        ):
            val = getattr(dna_intraday, score_attr)
            self.assertGreaterEqual(val, 0.0)
            self.assertLessEqual(val, 100.0)

    def test_journal_tag_sanitization(self) -> None:
        unsafe_claim = f"tag_{FORBIDDEN_CLAIM_SUBSTRINGS[0]}_alert"
        raw_tags = [
            "  opening_range_breakout  ",
            "Opening_Range_Breakout",  # case-insensitive duplicate
            "vwap_reclaim",
            "risk_$500_setup",         # currency amount rejected
            "folder/subpath",          # path separator rejected
            unsafe_claim,              # forbidden claim rejected
            "",
        ]
        cleaned = sanitize_journal_tags(raw_tags)
        self.assertEqual(cleaned, ["opening_range_breakout", "vwap_reclaim"])

        nav_pts = [
            NormalizedNavPoint(timestamp_utc="2026-01-01T00:00:00Z", nav_base=20_000.0),
            NormalizedNavPoint(timestamp_utc="2026-01-10T00:00:00Z", nav_base=20_400.0),
        ]
        ledger = _make_base_ledger(nav_points=nav_pts)
        convenience_report = build_trader_coaching_report(
            ledger,
            enable_llm_narrative=False,
            imported_journal_tags=raw_tags,
        )
        self.assertEqual(
            convenience_report.imported_journal_tags,
            ["opening_range_breakout", "vwap_reclaim"],
        )
        engine_out = TraderCoachingEngine().evaluate(
            ledger,
            enable_llm_narrative=False,
            imported_journal_tags=["vwap_reclaim"],
        )
        self.assertEqual(engine_out.report.imported_journal_tags, ["vwap_reclaim"])


@unittest.skipIf(verify_portfolio is None, "pipeline lands in Phase 3")
class TestPipelineComplianceInvariantsAndEndToEndBundle(unittest.TestCase):
    """End-to-end verification of Merkle proofs and realized return immutability."""

    def test_verify_portfolio_wires_wave4b_fields_and_preserves_realized_twr_xirr(self) -> None:
        base_dt = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
        nav = 50_000.0
        nav_pts = [NormalizedNavPoint(timestamp_utc="2026-01-01T00:00:00Z", nav_base=nav)]
        trades: list[NormalizedTrade] = []

        for day_idx in range(1, 36):
            dt_buy = base_dt + timedelta(days=day_idx, hours=14)
            dt_sell = base_dt + timedelta(days=day_idx, hours=20)
            dt_nav = base_dt + timedelta(days=day_idx, hours=23)
            delta_px = 1.5 if day_idx % 3 != 0 else -1.0
            comm = 4.0
            pnl = (delta_px * 20.0) - (2.0 * comm)
            nav += pnl
            trades.append(
                NormalizedTrade(
                    venue="IBKR",
                    native_entry_id=f"b_{day_idx}",
                    symbol="MSFT",
                    asset_class=AssetClass.EQUITY,
                    side="buy",
                    quantity=20.0,
                    price=100.0,
                    commission=comm,
                    timestamp_utc=dt_buy.strftime("%Y-%m-%dT%H:%M:%SZ"),
                )
            )
            trades.append(
                NormalizedTrade(
                    venue="IBKR",
                    native_entry_id=f"s_{day_idx}",
                    symbol="MSFT",
                    asset_class=AssetClass.EQUITY,
                    side="sell",
                    quantity=20.0,
                    price=100.0 + delta_px,
                    commission=comm,
                    timestamp_utc=dt_sell.strftime("%Y-%m-%dT%H:%M:%SZ"),
                )
            )
            nav_pts.append(
                NormalizedNavPoint(
                    timestamp_utc=dt_nav.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    nav_base=nav,
                )
            )

        ledger = _make_base_ledger(nav_points=nav_pts, trades=trades)
        expected_realized_twr = (nav / 50_000.0) - 1.0
        fixed_salts = {
            leaf_name: f"{idx + 1:02x}" * 32 for idx, leaf_name in enumerate(CANONICAL_LEAF_NAMES)
        }

        catalyst_intervals = [
            CatalystAvailabilityInterval(
                symbol="MSFT",
                earliest_public_utc="2026-01-05T13:00:00Z",
                confirmed_public_utc="2026-01-05T13:30:00Z",
                headline_or_event="Scheduled quarterly guidance update",
                event_sources=("sec_edgar",),
                timestamp_uncertainty_note="SEC EDGAR acceptance timestamp window.",
            )
        ]

        out_1 = verify_portfolio(
            ledger=ledger,
            catalyst_intervals=catalyst_intervals,
            imported_journal_tags=["earnings_continuation", "high_volume_breakout"],
            issued_at_utc="2026-02-20T00:00:00Z",
            proof_id="prf-wave4b-e2e",
            leaf_salts=fixed_salts,
        )
        out_2 = verify_portfolio(
            ledger=ledger,
            catalyst_intervals=catalyst_intervals,
            imported_journal_tags=["earnings_continuation", "high_volume_breakout"],
            issued_at_utc="2026-02-20T00:00:00Z",
            proof_id="prf-wave4b-e2e",
            leaf_salts=fixed_salts,
        )

        # Signed proof bundle & deterministic Merkle root across runs
        self.assertTrue(out_1.verification.valid, out_1.verification.errors)
        self.assertEqual(out_1.proof_bundle.merkle_root, out_2.proof_bundle.merkle_root)

        # Performance Wave-4B enrichments
        self.assertEqual(len(out_1.performance.daily_calendar_cells), 35)
        self.assertIsNotNone(out_1.performance.bootstrap_summary)

        # Coaching Wave-4B enrichments
        coaching_rep = out_1.coaching
        self.assertGreater(len(coaching_rep.session_heatmap), 0)
        self.assertIsNotNone(coaching_rep.counterfactual_twin)
        self.assertIsNotNone(coaching_rep.quant_dna)
        self.assertEqual(
            coaching_rep.imported_journal_tags,
            ["earnings_continuation", "high_volume_breakout"],
        )

        assert coaching_rep.counterfactual_twin is not None
        self.assertTrue(coaching_rep.counterfactual_twin.is_hypothetical_simulation)
        self.assertGreater(
            coaching_rep.counterfactual_twin.zero_friction_ending_index,
            coaching_rep.counterfactual_twin.actual_ending_index,
        )

        # HARD COMPLIANCE INVARIANT: realized twr & xirr in PerformanceSummary and core_metrics
        # leaf match exact realized ledger performance and are NEVER overwritten by counterfactuals!
        self.assertEqual(
            out_1.performance.twr_decimal,
            pytest.approx(expected_realized_twr, rel=1e-9),
        )
        core_leaf = out_1.proof_bundle.get_disclosed_payload("core_metrics")
        assert isinstance(core_leaf, dict)
        self.assertEqual(core_leaf["twr_decimal"], pytest.approx(expected_realized_twr, rel=1e-9))
        self.assertEqual(core_leaf["xirr_decimal"], out_1.performance.xirr_decimal)
        self.assertNotEqual(
            core_leaf["twr_decimal"],
            coaching_rep.counterfactual_twin.zero_friction_ending_index - 1.0,
        )

        # Zero forbidden claims or currency amounts across serialized coaching & performance payloads
        coaching_json = json.dumps(coaching_rep.to_dict())
        perf_json = json.dumps(out_1.performance.to_dict())
        self.assertFalse(contains_forbidden_claim(coaching_json))
        self.assertFalse(contains_currency_amount(coaching_json))
        self.assertFalse(contains_currency_amount(perf_json))

        # Worker entrypoint forwards imported_journal_tags cleanly
        worker_out = api_worker_pipeline_entrypoint(
            {
                "ledger": ledger.to_dict(),
                "issued_at_utc": "2026-02-20T00:00:00Z",
                "imported_journal_tags": ["worker_tag_alpha"],
            }
        )
        coaching_leaf = next(
            lf["payload"]
            for lf in worker_out["disclosed_leaves"]
            if lf["leaf_name"] == "coaching_and_context"
        )
        self.assertEqual(coaching_leaf["imported_journal_tags"], ["worker_tag_alpha"])
        self.assertTrue(coaching_leaf["counterfactual_twin"]["is_hypothetical_simulation"])


if __name__ == "__main__":
    unittest.main()
