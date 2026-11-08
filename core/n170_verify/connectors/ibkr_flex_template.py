"""Guided setup template and security checklist for IBKR Activity Flex Queries.

Provides structured step-by-step configuration metadata for Interactive Brokers
Client Portal so users can generate a read-only Activity Flex XML export (or
short-lived Flex Web Service v3 token) with all 9 reconciliation sections enabled.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from n170_verify.contracts import ContractModelMixin


REQUIRED_IBKR_FLEX_SECTIONS: tuple[str, ...] = (
    "EquitySummaryInBase",
    "PriorPeriodPositions",
    "OpenPositions",
    "Trades",
    "CashTransactions",
    "Transfers",
    "CorporateActions",
    "OptionEAE",
    "ConversionRates",
)


@dataclass(slots=True)
class IbkrFlexSectionSpec(ContractModelMixin):
    """Metadata describing a required IBKR Activity Flex Query section."""

    section: str
    portal_label: str
    recommended_detail_level: str
    purpose: str

    def _validate(self) -> None:
        if not self.section.strip():
            raise ValueError("IbkrFlexSectionSpec.section must not be empty")
        if not self.portal_label.strip():
            raise ValueError("IbkrFlexSectionSpec.portal_label must not be empty")


@dataclass(slots=True)
class IbkrFlexSetupGuide(ContractModelMixin):
    """Structured setup guide for IBKR Activity Flex XML & Flex Web Service v3.

    Supports both dataclass attribute access (`guide.required_sections`) and
    dictionary key lookup (`guide["required_sections"]`) for ergonomic use across
    Python callers, API endpoints, and CLI/UI serializers.
    """

    broker_id: str
    title: str
    estimated_setup_minutes: int
    required_sections: list[str] = field(default_factory=list)
    section_checklist: list[IbkrFlexSectionSpec] = field(default_factory=list)
    steps: list[dict[str, Any]] = field(default_factory=list)
    format_configuration: dict[str, Any] = field(default_factory=dict)
    security_settings: dict[str, Any] = field(default_factory=dict)
    privacy_guarantees: dict[str, Any] = field(default_factory=dict)

    def _validate(self) -> None:
        if not self.broker_id.strip():
            raise ValueError("IbkrFlexSetupGuide.broker_id must not be empty")
        if self.estimated_setup_minutes <= 0:
            raise ValueError("IbkrFlexSetupGuide.estimated_setup_minutes must be > 0")
        missing = [s for s in REQUIRED_IBKR_FLEX_SECTIONS if s not in self.required_sections]
        if missing:
            raise ValueError(f"IbkrFlexSetupGuide missing required section(s): {missing}")

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

    def keys(self) -> list[str]:
        return list(self.to_dict().keys())

    def values(self) -> list[Any]:
        return list(self.to_dict().values())

    def items(self) -> list[tuple[str, Any]]:
        return list(self.to_dict().items())

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key in self.to_dict()

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())


def get_ibkr_flex_setup_guide() -> IbkrFlexSetupGuide:
    """Return the structured IBKR Activity Flex Query setup guide and security checklist."""
    checklist = [
        IbkrFlexSectionSpec(
            section="EquitySummaryInBase",
            portal_label="Net Asset Value (NAV) in Base",
            recommended_detail_level="Summary by Report Date",
            purpose="Provides daily starting/ending NAV, cash, stock, options, and accrual totals for flow-adjusted TWR.",
        ),
        IbkrFlexSectionSpec(
            section="PriorPeriodPositions",
            portal_label="Prior Period Positions",
            recommended_detail_level="SUMMARY",
            purpose="Anchors opening holdings at the start of the verification window for exact position roll-forward.",
        ),
        IbkrFlexSectionSpec(
            section="OpenPositions",
            portal_label="Open Positions",
            recommended_detail_level="SUMMARY",
            purpose="Reconciles ending portfolio quantities and mark-to-market valuations against executed trades.",
        ),
        IbkrFlexSectionSpec(
            section="Trades",
            portal_label="Trades",
            recommended_detail_level="EXECUTION",
            purpose="Captures execution-level fills, prices, multipliers, commissions, and taxes for FIFO lot matching.",
        ),
        IbkrFlexSectionSpec(
            section="CashTransactions",
            portal_label="Cash Transactions",
            recommended_detail_level="DETAIL",
            purpose="Separates external deposits/withdrawals from dividends, withholding taxes, and margin interest.",
        ),
        IbkrFlexSectionSpec(
            section="Transfers",
            portal_label="Transfers",
            recommended_detail_level="DETAIL",
            purpose="Captures ACATS, FOP, DWAC in-kind asset transfers and internal subaccount cash/position transfers.",
        ),
        IbkrFlexSectionSpec(
            section="CorporateActions",
            portal_label="Corporate Actions",
            recommended_detail_level="DETAIL",
            purpose="Adjusts open lots for forward/reverse stock splits, mergers, spin-offs, and symbol/ISIN changes.",
        ),
        IbkrFlexSectionSpec(
            section="OptionEAE",
            portal_label="Option Exercises, Assignments and Expirations",
            recommended_detail_level="DETAIL",
            purpose="Reconciles derivative lifecycle transitions into underlying equity positions without phantom residuals.",
        ),
        IbkrFlexSectionSpec(
            section="ConversionRates",
            portal_label="Conversion Rates",
            recommended_detail_level="Summary",
            purpose="Supplies statement FX rates to translate multi-currency fills, dividends, and positions into base currency.",
        ),
    ]

    steps: list[dict[str, Any]] = [
        {
            "step": 1,
            "title": "Open IBKR Flex Queries",
            "instruction": (
                "Sign in to IBKR Client Portal, navigate to Performance & Reports -> Flex Queries, "
                "and click '+' next to Activity Flex Query."
            ),
        },
        {
            "step": 2,
            "title": "Enable All 9 Required Reconciliation Sections",
            "instruction": (
                "Enable EquitySummaryInBase (Net Asset Value in Base), PriorPeriodPositions, "
                "OpenPositions (SUMMARY), Trades (EXECUTION), CashTransactions, Transfers, "
                "CorporateActions, OptionEAE, and ConversionRates, selecting 'Select All' fields in each section."
            ),
            "required_sections": list(REQUIRED_IBKR_FLEX_SECTIONS),
        },
        {
            "step": 3,
            "title": "Select XML Delivery Format & UTC/ISO Timestamps",
            "instruction": (
                "Under Delivery Configuration, set Format = XML, Date Format = yyyy-MM-dd, "
                "Time Format = HH:mm:ss, and Date/Time Separator = ';' (semicolon)."
            ),
        },
        {
            "step": 4,
            "title": "Download XML Offline OR Configure 6h IP-Restricted Flex Web Service Token",
            "instruction": (
                "For offline import (SELF_REPORTED), run the query and upload the XML directly. "
                "For higher-assurance automated retrieval (OPERATOR_RETRIEVED), open Flex Web Service "
                "Configuration, generate a read-only token with 6h expiry and IP restriction enabled, "
                "and provide the Query ID and short-lived token."
            ),
        },
    ]

    return IbkrFlexSetupGuide(
        broker_id="ibkr",
        title="Interactive Brokers Activity Flex Query Setup Guide (Read-Only)",
        estimated_setup_minutes=3,
        required_sections=list(REQUIRED_IBKR_FLEX_SECTIONS),
        section_checklist=checklist,
        steps=steps,
        format_configuration={
            "format": "XML",
            "period_recommendation": "Last 365 Calendar Days",
            "date_format": "yyyy-MM-dd",
            "time_format": "HH:mm:ss",
            "date_time_separator": ";",
            "trades_level_of_detail": "EXECUTION",
            "positions_level_of_detail": "SUMMARY",
        },
        security_settings={
            "token_expiry": "6h",
            "recommended_token_expiry_hours": 6,
            "ip_restriction": True,
            "ip_restriction_guidance": (
                "Bind the Flex Web Service token to the verifier CIDR/IP address and set token expiry to 6h."
            ),
            "read_only_scope": (
                "IBKR Flex tokens can only download historical statements; they cannot place orders, "
                "modify positions, or initiate withdrawals."
            ),
            "portal_credentials_required": False,
        },
        privacy_guarantees={
            "dollar_nav_blinded_locally": True,
            "raw_account_id_blinded_locally": True,
            "raw_share_quantities_blinded": True,
            "blinding_mechanism": "HMAC-SHA256 commitment with 256-bit local blinding salt",
            "summary": (
                "$ NAV balances and raw accountId identifiers are blinded locally before signing; "
                "only percentage-indexed curves, capital brackets, and cryptographic commitments leave the verifier."
            ),
        },
    )


__all__ = [
    "IbkrFlexSectionSpec",
    "IbkrFlexSetupGuide",
    "REQUIRED_IBKR_FLEX_SECTIONS",
    "get_ibkr_flex_setup_guide",
]
