"""Calibrated multi-asset ledger and reference-market reconciliation engine."""

from __future__ import annotations

from datetime import datetime

from n170_verify.contracts import (
    CanonicalPortfolioLedger,
    CheckOutcome,
    PerformanceSummary,
    ReconciliationFinding,
    ReconciliationReport,
    ReconciliationStatus,
)
from n170_verify.performance.calculator import calculate_portfolio_performance_detailed
from n170_verify.reconciliation.accounting_checks import (
    reconcile_nav_identities,
    reconcile_position_rollforward,
)
from n170_verify.reconciliation.financing_checks import (
    reconcile_dividend_flows,
    reconcile_financing_accruals,
    reconcile_fx_conversion_marks,
)
from n170_verify.reconciliation.market_and_corp_actions import (
    reconcile_corporate_actions_and_ending_marks,
    reconcile_trade_fills,
)
from n170_verify.reconciliation.statistical_diagnostics import build_statistical_diagnostics
from n170_verify.reference.base import NullReferenceProvider, ReferenceDataProvider


class ReconciliationEngine:
    """Orchestrates accounting conservation, financing, market-envelope, and econometric checks."""

    def __init__(
        self,
        reference_provider: ReferenceDataProvider | None = None,
    ) -> None:
        self.reference_provider: ReferenceDataProvider = (
            reference_provider if reference_provider is not None else NullReferenceProvider()
        )

    def reconcile(
        self,
        ledger: CanonicalPortfolioLedger,
        *,
        performance_summary: PerformanceSummary | None = None,
        reference_now_utc: str | datetime | None = None,
    ) -> ReconciliationReport:
        provider = self.reference_provider
        findings: list[ReconciliationFinding] = []

        roll = reconcile_position_rollforward(ledger)
        findings.extend(roll.findings)
        ledger_completeness_ok = roll.ledger_completeness_ok
        missing_sections = list(roll.missing_sections)

        if not ledger.nav_points:
            ledger_completeness_ok = False
            if "EquitySummaryByReportDateInBase" not in missing_sections:
                missing_sections.append("EquitySummaryByReportDateInBase")

        findings.extend(
            reconcile_nav_identities(
                ledger,
                reference_provider=provider,
                implied_option_cash_delta_base=roll.implied_option_cash_delta_base,
                ledger_completeness_ok=ledger_completeness_ok,
            )
        )
        findings.extend(reconcile_fx_conversion_marks(ledger, reference_provider=provider))
        findings.extend(reconcile_dividend_flows(ledger, reference_provider=provider))
        findings.extend(reconcile_financing_accruals(ledger))
        findings.extend(
            reconcile_trade_fills(
                ledger,
                reference_provider=provider,
                reference_now_utc=reference_now_utc,
            )
        )
        findings.extend(
            reconcile_corporate_actions_and_ending_marks(
                ledger,
                reference_provider=provider,
            )
        )

        perf_detail = calculate_portfolio_performance_detailed(ledger)
        period_returns = [obs.period_return for obs in perf_detail.return_observations]
        effective_perf = performance_summary if performance_summary is not None else perf_detail.summary
        diagnostics = build_statistical_diagnostics(
            period_returns=period_returns,
            performance_summary=effective_perf,
        )

        checks_evaluated = sum(1 for f in findings if f.outcome != CheckOutcome.NOT_EVALUATED)
        discrepancy_count = sum(1 for f in findings if f.outcome == CheckOutcome.DISCREPANCY)
        explained_count = sum(1 for f in findings if f.outcome == CheckOutcome.EXPLAINED_CONVENTION)
        not_evaluated_count = sum(1 for f in findings if f.outcome == CheckOutcome.NOT_EVALUATED)

        # If non-position-rollforward discrepancies exist (e.g. altered NAV snapshot), surface
        # UNEXPLAINED_RESIDUAL; if unexplained position jumps stem from omitted export sections,
        # surface INSUFFICIENT_SECTIONS.
        non_roll_discrepancies = sum(
            1
            for f in findings
            if f.outcome == CheckOutcome.DISCREPANCY and f.category != "position_rollforward"
        )
        if not ledger_completeness_ok and non_roll_discrepancies == 0:
            status = ReconciliationStatus.INSUFFICIENT_SECTIONS
            summary_text = (
                f"Ledger completeness gate incomplete: missing section(s) {', '.join(missing_sections)} "
                f"prevent full position roll-forward reconciliation."
            )
        elif discrepancy_count > 0:
            status = ReconciliationStatus.UNEXPLAINED_RESIDUAL
            summary_text = (
                f"Evaluated {checks_evaluated} check(s) via provider={provider.provider_name}: "
                f"{discrepancy_count} unexplained residual(s), {explained_count} explained convention(s)."
            )
        elif not provider.is_available and not_evaluated_count > 0:
            status = ReconciliationStatus.REFERENCE_DATA_UNAVAILABLE
            summary_text = (
                f"Internal ledger accounting reconciled across {checks_evaluated} check(s); "
                f"{not_evaluated_count} external market check(s) not evaluated (reference provider='none')."
            )
        else:
            status = ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE
            summary_text = (
                f"Reconciled within tolerance across {checks_evaluated} check(s) via "
                f"provider={provider.provider_name} ({explained_count} explained convention(s), 0 discrepancies)."
            )

        return ReconciliationReport(
            status=status,
            reference_provider=provider.provider_name,
            ledger_completeness_ok=ledger_completeness_ok,
            missing_sections=missing_sections,
            checks_evaluated=checks_evaluated,
            discrepancy_count=discrepancy_count,
            explained_convention_count=explained_count,
            findings=findings,
            statistical_diagnostics=diagnostics,
            summary_text=summary_text,
        )


def reconcile_portfolio_ledger(
    ledger: CanonicalPortfolioLedger,
    *,
    reference_provider: ReferenceDataProvider | None = None,
    performance_summary: PerformanceSummary | None = None,
    reference_now_utc: str | datetime | None = None,
) -> ReconciliationReport:
    """Functional entry point returning a calibrated ``ReconciliationReport``."""
    engine = ReconciliationEngine(reference_provider=reference_provider)
    return engine.reconcile(
        ledger,
        performance_summary=performance_summary,
        reference_now_utc=reference_now_utc,
    )


__all__ = [
    "ReconciliationEngine",
    "reconcile_portfolio_ledger",
]
