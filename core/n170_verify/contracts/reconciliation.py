"""Calibrated accounting & market-reference reconciliation contracts (neutral, residual-based)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from n170_verify.contracts.assurance import ContractModelMixin


class ReconciliationStatus(str, Enum):
    """High-level accounting & market-reference reconciliation outcome."""

    RECONCILED_WITHIN_TOLERANCE = "reconciled_within_tolerance"
    UNEXPLAINED_RESIDUAL = "unexplained_residual"
    INSUFFICIENT_SECTIONS = "insufficient_sections"
    REFERENCE_DATA_UNAVAILABLE = "reference_data_unavailable"


class CheckOutcome(str, Enum):
    """Outcome of an individual accounting identity or market-envelope check."""

    PASS = "pass"
    EXPLAINED_CONVENTION = "explained_convention"
    DISCREPANCY = "discrepancy"
    NOT_EVALUATED = "not_evaluated"


@dataclass(slots=True)
class ReconciliationFinding(ContractModelMixin):
    """Specific mathematical identity check result with benign explanations considered."""

    category: str
    outcome: CheckOutcome
    date_or_timestamp: str
    symbol: str | None = None
    expected_value: float | None = None
    observed_value: float | None = None
    residual_bps: float | None = None
    residual_base_currency: float | None = None
    math_identity: str = ""
    technical_explanation: str = ""
    benign_causes_considered: list[str] = field(default_factory=list)

    def _validate(self) -> None:
        if not self.category.strip():
            raise ValueError("ReconciliationFinding.category must not be empty")
        if not self.date_or_timestamp.strip():
            raise ValueError("ReconciliationFinding.date_or_timestamp must not be empty")


@dataclass(slots=True)
class StatisticalDiagnostic(ContractModelMixin):
    """Non-accusatory statistical diagnostic with explicit caveats."""

    metric_name: str
    observed_value: float | None
    interpretation: str
    caveats: list[str] = field(default_factory=list)

    def _validate(self) -> None:
        if not self.metric_name.strip():
            raise ValueError("StatisticalDiagnostic.metric_name must not be empty")


@dataclass(slots=True)
class ReconciliationReport(ContractModelMixin):
    """Calibrated ledger & reference-market reconciliation report without arbitrary score cutoffs."""

    status: ReconciliationStatus
    reference_provider: str
    ledger_completeness_ok: bool
    missing_sections: list[str] = field(default_factory=list)
    checks_evaluated: int = 0
    discrepancy_count: int = 0
    explained_convention_count: int = 0
    findings: list[ReconciliationFinding] = field(default_factory=list)
    statistical_diagnostics: list[StatisticalDiagnostic] = field(default_factory=list)
    summary_text: str = ""

    def _validate(self) -> None:
        provider = self.reference_provider.strip().lower()
        if provider not in {"eodhd", "none"}:
            raise ValueError("ReconciliationReport.reference_provider must be 'eodhd' or 'none'")
        object.__setattr__(self, "reference_provider", provider)
        if self.checks_evaluated < 0:
            raise ValueError("checks_evaluated must be >= 0")
        if self.discrepancy_count < 0:
            raise ValueError("discrepancy_count must be >= 0")
        if self.explained_convention_count < 0:
            raise ValueError("explained_convention_count must be >= 0")


__all__ = [
    "CheckOutcome",
    "ReconciliationFinding",
    "ReconciliationReport",
    "ReconciliationStatus",
    "StatisticalDiagnostic",
]
