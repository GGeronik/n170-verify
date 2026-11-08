"""Additive Wave-4A contract tests for performance & coaching extensions."""

from __future__ import annotations

import dataclasses
import math
import unittest

import n170_verify.contracts as contracts_pkg
from n170_verify.contracts import (
    AccountScope,
    BehaviouralCoachingMetrics,
    BootstrapConePoint,
    BootstrapRiskSummary,
    CapitalBracket,
    ClaimPlausibilityAnalysis,
    CostAndDragBreakdown,
    CounterfactualTwinReport,
    DailyCalendarCell,
    EnvironmentTier,
    IndexedCurvePoint,
    OriginAssurance,
    PerformanceSummary,
    ProviderApprovalState,
    QuantDnaProfile,
    ReconciliationReport,
    ReconciliationStatus,
    SessionExpectancyCell,
    TraderCoachingAndContextReport,
    create_signed_proof_bundle,
    verify_proof_bundle,
)
from n170_verify.contracts.coaching import DEFAULT_COUNTERFACTUAL_DISCLAIMER
from n170_verify.crypto import generate_ed25519_keypair, jcs_canonicalize, jcs_sha256_hex
try:
    from n170_verify.pipeline import build_canonical_leaf_payloads
except ImportError:
    build_canonical_leaf_payloads = None  # type: ignore[assignment]


class TestWave4AContractExports(unittest.TestCase):
    """Verify all 7 new Wave-4A contract classes are exported from n170_verify.contracts."""

    EXPECTED_EXPORTS = (
        "DailyCalendarCell",
        "BootstrapConePoint",
        "BootstrapRiskSummary",
        "ClaimPlausibilityAnalysis",
        "SessionExpectancyCell",
        "CounterfactualTwinReport",
        "QuantDnaProfile",
    )

    def test_reexported_in_contracts_init_and_dunder_all(self) -> None:
        for symbol in self.EXPECTED_EXPORTS:
            self.assertIn(symbol, contracts_pkg.__all__)
            self.assertTrue(hasattr(contracts_pkg, symbol))


class TestWave4APerformanceContracts(unittest.TestCase):
    """Validate DailyCalendarCell, BootstrapConePoint, BootstrapRiskSummary, ClaimPlausibilityAnalysis."""

    def test_daily_calendar_cell_privacy_and_validation(self) -> None:
        cell = DailyCalendarCell(date="2026-02-10", return_pct=1.425, trade_count=4)
        self.assertEqual(
            cell.to_dict(),
            {"date": "2026-02-10", "return_pct": 1.425, "trade_count": 4},
        )
        self.assertEqual(DailyCalendarCell.from_dict(cell.to_dict()), cell)
        self.assertEqual(DailyCalendarCell.model_validate(cell.model_dump()), cell)

        # Strictly percentage-of-NAV and trade count — zero raw dollar fields serialized
        field_names = {f.name for f in dataclasses.fields(DailyCalendarCell)}
        self.assertEqual(field_names, {"date", "return_pct", "trade_count"})
        stripped = DailyCalendarCell.from_dict(
            {
                "date": "2026-02-10",
                "return_pct": 1.425,
                "trade_count": 4,
                "pnl_usd": 1250.0,
                "nav_usd": 50000.0,
            }
        )
        self.assertEqual(
            set(stripped.to_dict().keys()),
            {"date", "return_pct", "trade_count"},
        )

        # Reject non-finite return_pct, negative trade_count, bool trade_count, or malformed dates
        for bad_ret in (math.nan, math.inf, -math.inf):
            with self.assertRaises(ValueError):
                DailyCalendarCell(date="2026-02-10", return_pct=bad_ret, trade_count=1)
        with self.assertRaises(ValueError):
            DailyCalendarCell(date="2026-02-10", return_pct=0.5, trade_count=-1)
        with self.assertRaises(ValueError):
            DailyCalendarCell(date="2026-02-10", return_pct=0.5, trade_count=True)  # type: ignore[arg-type]
        for bad_date in ("", "   ", "2026-02-30", "20260210", "not-a-date"):
            with self.assertRaises(ValueError):
                DailyCalendarCell(date=bad_date, return_pct=0.5, trade_count=1)

    def test_bootstrap_cone_and_risk_summary_round_trip(self) -> None:
        pt0 = BootstrapConePoint(step=0, p05=100.0, p25=100.0, p50=100.0, p75=100.0, p95=100.0)
        pt1 = BootstrapConePoint(step=21, p05=94.2, p25=98.1, p50=101.4, p75=104.9, p95=110.3)

        # Accepts tuple of points and normalizes to list of BootstrapConePoint -> list of dicts
        summary_from_tuple = BootstrapRiskSummary(
            horizon_periods=21,
            num_simulations=1000,
            block_length=5,
            prob_drawdown_10pct=0.184,
            prob_drawdown_20pct=0.032,
            prob_positive_terminal=0.695,
            cone=(pt0, pt1),  # type: ignore[arg-type]
        )
        self.assertIsInstance(summary_from_tuple.cone, list)
        dumped = summary_from_tuple.to_dict()
        self.assertIsInstance(dumped["cone"], list)
        self.assertEqual(len(dumped["cone"]), 2)
        self.assertEqual(BootstrapRiskSummary.from_dict(dumped), summary_from_tuple)
        self.assertEqual(
            jcs_sha256_hex(summary_from_tuple),
            jcs_sha256_hex(dumped),
        )

        # Quantile monotonicity & parameter bounds enforced
        with self.assertRaises(ValueError):
            BootstrapConePoint(step=-1, p05=95.0, p25=98.0, p50=100.0, p75=102.0, p95=105.0)
        with self.assertRaises(ValueError):
            BootstrapConePoint(step=5, p05=101.0, p25=98.0, p50=100.0, p75=102.0, p95=105.0)
        with self.assertRaises(ValueError):
            BootstrapRiskSummary(
                horizon_periods=0,
                num_simulations=1000,
                block_length=5,
                prob_drawdown_10pct=0.1,
                prob_drawdown_20pct=0.02,
                prob_positive_terminal=0.7,
            )
        with self.assertRaises(ValueError):
            BootstrapRiskSummary(
                horizon_periods=21,
                num_simulations=1000,
                block_length=5,
                prob_drawdown_10pct=1.2,
                prob_drawdown_20pct=0.02,
                prob_positive_terminal=0.7,
            )

    def test_claim_plausibility_analysis_serialization_and_validation(self) -> None:
        claim = ClaimPlausibilityAnalysis(
            claimed_sharpe=3.5,
            annualization_factor=252,
            observed_periods=45,
            skewness=-0.35,
            excess_kurtosis=1.8,
            benchmark_sharpe=0.5,
            implied_psr=0.812,
            required_min_trl_periods_95pct=118.6,
            sufficiency_tier="under_powered_for_95pct",
            bell_curve_points=[
                {"sharpe": -1, "density": 0.012},  # int coerced to float
                {"sharpe": 3.5, "density": 0.241},
            ],
            plain_english_summary="45 daily observations are insufficient to confirm SR 3.5 at 95% confidence.",
        )
        self.assertIsInstance(claim.bell_curve_points[0]["sharpe"], float)
        restored = ClaimPlausibilityAnalysis.from_dict(claim.to_dict())
        self.assertEqual(restored, claim)

        # Also allows None for required_min_trl_periods_95pct when claimed_sharpe <= benchmark_sharpe
        unreachable = ClaimPlausibilityAnalysis(
            claimed_sharpe=0.2,
            annualization_factor=252,
            observed_periods=60,
            skewness=0.0,
            excess_kurtosis=0.0,
            benchmark_sharpe=0.5,
            implied_psr=0.19,
            required_min_trl_periods_95pct=None,
            sufficiency_tier="below_benchmark",
            bell_curve_points=[],
            plain_english_summary="Claimed Sharpe does not exceed the selected benchmark Sharpe.",
        )
        self.assertIsNone(
            ClaimPlausibilityAnalysis.from_dict(unreachable.to_dict()).required_min_trl_periods_95pct
        )

        # Reject invalid implied_psr, negative min_trl, or non-finite bell_curve_points
        with self.assertRaises(ValueError):
            ClaimPlausibilityAnalysis(
                claimed_sharpe=2.0,
                annualization_factor=252,
                observed_periods=60,
                skewness=0.0,
                excess_kurtosis=0.0,
                benchmark_sharpe=0.0,
                implied_psr=1.05,
                required_min_trl_periods_95pct=40.0,
                sufficiency_tier="high",
                bell_curve_points=[],
                plain_english_summary="Invalid PSR.",
            )
        with self.assertRaises(ValueError):
            ClaimPlausibilityAnalysis(
                claimed_sharpe=2.0,
                annualization_factor=252,
                observed_periods=60,
                skewness=0.0,
                excess_kurtosis=0.0,
                benchmark_sharpe=0.0,
                implied_psr=0.95,
                required_min_trl_periods_95pct=40.0,
                sufficiency_tier="high",
                bell_curve_points=[{"sharpe": math.nan, "density": 0.1}],
                plain_english_summary="Non-finite curve.",
            )

    def test_performance_summary_backward_compatibility_and_extensions(self) -> None:
        # Legacy Wave 1-3 dictionary omitting new Wave-4 fields must deserialize cleanly
        legacy_dict = {
            "twr_decimal": 0.12,
            "observation_count": 40,
            "psr_sample_eligible": True,
            "probabilistic_sharpe_ratio": 0.96,
            "max_drawdown_decimal": -0.04,
        }
        legacy_perf = PerformanceSummary.from_dict(legacy_dict)
        self.assertEqual(legacy_perf.daily_calendar_cells, [])
        self.assertIsNone(legacy_perf.bootstrap_summary)

        # Enriched Wave-4 PerformanceSummary round-trips cleanly
        enriched = PerformanceSummary(
            twr_decimal=0.12,
            observation_count=40,
            psr_sample_eligible=True,
            probabilistic_sharpe_ratio=0.96,
            max_drawdown_decimal=-0.04,
            indexed_curve=[
                IndexedCurvePoint(
                    timestamp_utc="2026-01-02T00:00:00Z", index_value=100.0, drawdown_pct=0.0
                ),
                IndexedCurvePoint(
                    timestamp_utc="2026-02-27T00:00:00Z", index_value=112.0, drawdown_pct=0.0
                ),
            ],
            daily_calendar_cells=[
                DailyCalendarCell(date="2026-01-02", return_pct=0.85, trade_count=2),
                DailyCalendarCell(date="2026-01-05", return_pct=-0.30, trade_count=1),
            ],
            bootstrap_summary=BootstrapRiskSummary(
                horizon_periods=30,
                num_simulations=500,
                block_length=5,
                prob_drawdown_10pct=0.14,
                prob_drawdown_20pct=0.02,
                prob_positive_terminal=0.74,
                cone=[
                    BootstrapConePoint(
                        step=30, p05=93.5, p25=98.2, p50=102.6, p75=107.1, p95=114.0
                    )
                ],
            ),
        )
        self.assertEqual(PerformanceSummary.from_dict(enriched.to_dict()), enriched)
        self.assertGreater(len(jcs_canonicalize(enriched)), 0)


class TestWave4ACoachingContracts(unittest.TestCase):
    """Validate SessionExpectancyCell, CounterfactualTwinReport, QuantDnaProfile, and Merkle compatibility."""

    def test_session_expectancy_cell_bounds(self) -> None:
        cell = SessionExpectancyCell(
            weekday=2, hour_utc=14, trade_count=18, win_rate=0.6111, expectancy_bps=24.5
        )
        self.assertEqual(SessionExpectancyCell.from_dict(cell.to_dict()), cell)

        for bad_kwargs in (
            {"weekday": -1, "hour_utc": 14, "trade_count": 5, "win_rate": 0.5, "expectancy_bps": 10.0},
            {"weekday": 7, "hour_utc": 14, "trade_count": 5, "win_rate": 0.5, "expectancy_bps": 10.0},
            {"weekday": 1, "hour_utc": -1, "trade_count": 5, "win_rate": 0.5, "expectancy_bps": 10.0},
            {"weekday": 1, "hour_utc": 24, "trade_count": 5, "win_rate": 0.5, "expectancy_bps": 10.0},
            {"weekday": 1, "hour_utc": 14, "trade_count": -1, "win_rate": 0.5, "expectancy_bps": 10.0},
            {"weekday": 1, "hour_utc": 14, "trade_count": 5, "win_rate": 1.2, "expectancy_bps": 10.0},
            {
                "weekday": 1,
                "hour_utc": 14,
                "trade_count": 5,
                "win_rate": 0.5,
                "expectancy_bps": math.inf,
            },
        ):
            with self.assertRaises(ValueError):
                SessionExpectancyCell(**bad_kwargs)

    def test_counterfactual_twin_report_constructor_modes_and_hypothetical_guard(self) -> None:
        # 1. Keyword construction omitting is_hypothetical_simulation
        twin_kw_omitted = CounterfactualTwinReport(
            compliance_disclaimer="HYPOTHETICAL SIMULATION — Not actual trading results.",
            actual_ending_index=1.10,
            zero_friction_ending_index=1.15,
            disciplined_post_dd_sizing_ending_index=1.12,
            capped_tail_loss_ending_index=1.14,
            curve_points=[{"step": 0, "actual": 1.0, "zero_friction": 1.0}],
        )
        self.assertTrue(twin_kw_omitted.is_hypothetical_simulation)

        # 2. Keyword construction explicitly passing is_hypothetical_simulation=True
        twin_kw_explicit = CounterfactualTwinReport(
            is_hypothetical_simulation=True,
            compliance_disclaimer="HYPOTHETICAL SIMULATION — Not actual trading results.",
            actual_ending_index=1.10,
            zero_friction_ending_index=1.15,
            disciplined_post_dd_sizing_ending_index=1.12,
            capped_tail_loss_ending_index=1.14,
            curve_points=[{"step": 0, "actual": 1.0, "zero_friction": 1.0}],
        )
        self.assertEqual(twin_kw_omitted, twin_kw_explicit)
        self.assertEqual(
            CounterfactualTwinReport.from_dict(twin_kw_explicit.to_dict()),
            twin_kw_explicit,
        )

        # 3. Default disclaimer + positional construction (both with and without leading bool)
        twin_default_disc = CounterfactualTwinReport(
            actual_ending_index=105.0,
            zero_friction_ending_index=106.4,
            disciplined_post_dd_sizing_ending_index=105.9,
            capped_tail_loss_ending_index=106.1,
        )
        self.assertEqual(twin_default_disc.compliance_disclaimer, DEFAULT_COUNTERFACTUAL_DISCLAIMER)
        self.assertEqual(twin_default_disc.curve_points, [])

        twin_pos_no_bool = CounterfactualTwinReport(
            "HYPOTHETICAL SIMULATION — Not actual trading results.",
            1.10,
            1.15,
            1.12,
            1.14,
            [{"step": 0, "actual": 1.0, "zero_friction": 1.0}],
        )
        twin_pos_with_bool = CounterfactualTwinReport(
            True,
            "HYPOTHETICAL SIMULATION — Not actual trading results.",
            1.10,
            1.15,
            1.12,
            1.14,
            [{"step": 0, "actual": 1.0, "zero_friction": 1.0}],
        )
        self.assertEqual(twin_pos_no_bool, twin_kw_explicit)
        self.assertEqual(twin_pos_with_bool, twin_kw_explicit)
        self.assertEqual(
            dataclasses.replace(twin_kw_explicit, actual_ending_index=1.11).actual_ending_index,
            1.11,
        )

        # 4. Compliance guardrail: is_hypothetical_simulation MUST never be False
        with self.assertRaises(ValueError):
            CounterfactualTwinReport(
                is_hypothetical_simulation=False,
                compliance_disclaimer="Attempted non-hypothetical override.",
                actual_ending_index=1.10,
                zero_friction_ending_index=1.15,
                disciplined_post_dd_sizing_ending_index=1.12,
                capped_tail_loss_ending_index=1.14,
                curve_points=[],
            )
        with self.assertRaises(ValueError):
            CounterfactualTwinReport(False, "Disclaimer", 1.1, 1.15, 1.12, 1.14, [])
        with self.assertRaises(ValueError):
            dumped_bad = twin_kw_explicit.to_dict()
            dumped_bad["is_hypothetical_simulation"] = False
            CounterfactualTwinReport.from_dict(dumped_bad)
        with self.assertRaises(ValueError):
            CounterfactualTwinReport(
                compliance_disclaimer="   ",
                actual_ending_index=1.10,
                zero_friction_ending_index=1.15,
                disciplined_post_dd_sizing_ending_index=1.12,
                capped_tail_loss_ending_index=1.14,
                curve_points=[],
            )

    def test_quant_dna_profile_and_coaching_merkle_proof_compatibility(self) -> None:
        dna = QuantDnaProfile(
            archetype_label="Disciplined Catalyst Swing",
            consistency_score=82.5,
            drawdown_resilience_score=88.0,
            cost_efficiency_score=76.4,
            sizing_discipline_score=91.0,
            exit_symmetry_score=69.5,
            catalyst_alignment_score=74.0,
        )
        self.assertEqual(QuantDnaProfile.from_dict(dna.to_dict()), dna)

        with self.assertRaises(ValueError):
            QuantDnaProfile(
                archetype_label="",
                consistency_score=80.0,
                drawdown_resilience_score=80.0,
                cost_efficiency_score=80.0,
                sizing_discipline_score=80.0,
                exit_symmetry_score=80.0,
                catalyst_alignment_score=80.0,
            )
        with self.assertRaises(ValueError):
            QuantDnaProfile(
                archetype_label="Invalid Score",
                consistency_score=105.0,
                drawdown_resilience_score=80.0,
                cost_efficiency_score=80.0,
                sizing_discipline_score=80.0,
                exit_symmetry_score=80.0,
                catalyst_alignment_score=80.0,
            )

        # Legacy Wave 1-3 dict omitting all 4 new coaching fields deserializes cleanly
        base_cost = CostAndDragBreakdown(
            commission_and_fee_drag_bps=6.0,
            margin_and_funding_drag_bps=1.5,
            fx_conversion_drag_bps=0.5,
            withholding_tax_drag_bps=0.0,
            total_friction_drag_bps=8.0,
            annualized_total_drag_bps=32.0,
        )
        base_beh = BehaviouralCoachingMetrics(
            sample_eligible=True,
            min_trades_gate=30,
            observed_trades=36,
            observed_days=28,
            win_rate=0.58,
        )
        legacy_coaching_dict = {
            "cost_drag": base_cost.to_dict(),
            "behaviour": base_beh.to_dict(),
            "style_summary": "Wave-3 legacy payload.",
        }
        legacy_report = TraderCoachingAndContextReport.from_dict(legacy_coaching_dict)
        self.assertEqual(legacy_report.session_heatmap, [])
        self.assertIsNone(legacy_report.counterfactual_twin)
        self.assertIsNone(legacy_report.quant_dna)
        self.assertEqual(legacy_report.imported_journal_tags, [])

        # Enriched report + PerformanceSummary verify end-to-end inside a signed 7-leaf Merkle bundle
        enriched_coaching = TraderCoachingAndContextReport(
            cost_drag=base_cost,
            behaviour=base_beh,
            style_summary="Wave-4 enriched coaching payload.",
            session_heatmap=[
                SessionExpectancyCell(
                    weekday=1, hour_utc=15, trade_count=12, win_rate=0.6667, expectancy_bps=31.2
                )
            ],
            counterfactual_twin=CounterfactualTwinReport(
                compliance_disclaimer=DEFAULT_COUNTERFACTUAL_DISCLAIMER,
                actual_ending_index=108.0,
                zero_friction_ending_index=109.2,
                disciplined_post_dd_sizing_ending_index=108.7,
                capped_tail_loss_ending_index=109.5,
                curve_points=[{"timestamp_utc": "2026-01-31T00:00:00Z", "actual": 108.0}],
            ),
            quant_dna=dna,
            imported_journal_tags=["a_setup_breakout", "post_earnings_drift"],
        )
        self.assertEqual(
            TraderCoachingAndContextReport.from_dict(enriched_coaching.to_dict()),
            enriched_coaching,
        )

        perf = PerformanceSummary(
            twr_decimal=0.08,
            observation_count=35,
            psr_sample_eligible=True,
            probabilistic_sharpe_ratio=0.94,
            max_drawdown_decimal=-0.025,
            capital_bracket=CapitalBracket.BRACKET_10K_100K,
            indexed_curve=[
                IndexedCurvePoint(
                    timestamp_utc="2026-01-01T00:00:00Z", index_value=100.0, drawdown_pct=0.0
                ),
                IndexedCurvePoint(
                    timestamp_utc="2026-01-31T00:00:00Z", index_value=108.0, drawdown_pct=0.0
                ),
            ],
            daily_calendar_cells=[
                DailyCalendarCell(date="2026-01-15", return_pct=1.15, trade_count=3)
            ],
            bootstrap_summary=BootstrapRiskSummary(
                horizon_periods=21,
                num_simulations=250,
                block_length=5,
                prob_drawdown_10pct=0.11,
                prob_drawdown_20pct=0.01,
                prob_positive_terminal=0.79,
                cone=[
                    BootstrapConePoint(
                        step=21, p05=96.0, p25=99.5, p50=102.1, p75=105.0, p95=109.8
                    )
                ],
            ),
        )
        recon = ReconciliationReport(
            status=ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE,
            reference_provider="none",
            ledger_completeness_ok=True,
            checks_evaluated=6,
        )
        if build_canonical_leaf_payloads is not None:
            leaves = build_canonical_leaf_payloads(
                performance=perf,
                reconciliation=recon,
                coaching=enriched_coaching,
                delayed_closed_trades=[],
                base_currency="USD",
            )
        else:
            core_dict = perf.to_dict()
            core_dict["capital_bracket"] = None
            core_dict["indexed_curve"] = []
            core_dict["benchmark_symbol"] = None
            core_dict["benchmark_twr_decimal"] = None
            core_dict["alpha_decimal"] = None
            leaves = {
                "core_metrics": core_dict,
                "indexed_curve": {
                    "base_index": 100.0,
                    "points": [pt.to_dict() for pt in perf.indexed_curve],
                },
                "reconciliation": recon.to_dict(),
                "coaching_and_context": enriched_coaching.to_dict(),
                "capital_bracket": {
                    "capital_bracket": perf.capital_bracket.value,
                    "valuation_currency": "USD",
                },
                "benchmark_alpha": {
                    "benchmark_symbol": perf.benchmark_symbol or "NONE",
                    "benchmark_twr_decimal": perf.benchmark_twr_decimal,
                    "alpha_decimal": perf.alpha_decimal,
                    "information_ratio": None,
                    "beta": None,
                },
                "delayed_closed_trades": {
                    "embargo_days": 7,
                    "trades": [],
                    "stripped_recent_count": 0,
                },
            }
        kp = generate_ed25519_keypair()
        bundle = create_signed_proof_bundle(
            proof_id="prf_w4a_001",
            issued_at_utc="2026-02-01T00:00:00Z",
            publisher_kid="w4a-test-key",
            publisher_private_key_hex=kp.private_key_hex,
            broker_id="ibkr",
            blinded_account_tag="aa" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.SELF_REPORTED,
            source_body_sha256="bb" * 32,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            base_currency="USD",
            leaf_payloads=leaves,
        )
        res = verify_proof_bundle(bundle)
        self.assertTrue(res.valid, res.errors)
        restored_coaching = TraderCoachingAndContextReport.from_dict(
            bundle.get_disclosed_payload("coaching_and_context")
        )
        self.assertEqual(restored_coaching, enriched_coaching)


if __name__ == "__main__":
    unittest.main()
