"""Normalized multi-asset portfolio ledger contracts and blinded account tags."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import hmac

from n170_verify.contracts.assurance import (
    AccountScope,
    ContractModelMixin,
    EnvironmentTier,
    OriginAssurance,
    ProviderApprovalState,
    parse_utc_timestamp,
    validate_hex_digest,
)


ACCOUNT_TAG_DOMAIN = b"n170.verify.account_tag.v3\x00"


class AssetClass(str, Enum):
    """Supported brokerage and exchange instrument classes."""

    EQUITY = "equity"
    ETF = "etf"
    OPTION = "option"
    FUTURE = "future"
    FX = "fx"
    CRYPTO_SPOT = "crypto_spot"
    CRYPTO_PERP = "crypto_perp"
    CASH = "cash"


class FlowKind(str, Enum):
    """Normalized portfolio cash and in-kind transfer categories."""

    DEPOSIT = "deposit"
    WITHDRAWAL = "withdrawal"
    TRANSFER_IN_KIND = "transfer_in_kind"
    TRANSFER_OUT_KIND = "transfer_out_kind"
    INTERNAL_SUBACCOUNT_TRANSFER = "internal_subaccount_transfer"
    DIVIDEND = "dividend"
    WITHHOLDING_TAX = "withholding_tax"
    INTEREST = "interest"
    MARGIN_INTEREST = "margin_interest"
    PERP_FUNDING = "perp_funding"
    COMMISSION_FEE = "commission_fee"
    CORPORATE_ACTION_CASH = "corporate_action_cash"
    FX_TRANSLATION = "fx_translation"
    OTHER_INTERNAL = "other_internal"


class CorporateActionType(str, Enum):
    """Corporate action and derivative lifecycle event types."""

    SPLIT = "split"
    REVERSE_SPLIT = "reverse_split"
    SPIN_OFF = "spin_off"
    MERGER = "merger"
    SYMBOL_CHANGE = "symbol_change"
    OPTION_EXERCISE = "option_exercise"
    OPTION_ASSIGNMENT = "option_assignment"
    OPTION_EXPIRATION = "option_expiration"
    STOCK_GRANT = "stock_grant"


EXTERNAL_CAPITAL_FLOW_KINDS: frozenset[FlowKind] = frozenset(
    {
        FlowKind.DEPOSIT,
        FlowKind.WITHDRAWAL,
        FlowKind.TRANSFER_IN_KIND,
        FlowKind.TRANSFER_OUT_KIND,
    }
)


def compute_blinded_account_tag(
    broker_id: str,
    raw_account_id: str,
    blinding_salt_hex: str,
) -> str:
    """Compute a privacy-preserving HMAC-SHA256 commitment over (broker_id, raw_account_id).

    Raw account identifiers are never stored in ``CanonicalPortfolioLedger`` or
    ``VerifyProofBundle``; verifiers check account continuity via ``blinded_account_tag``.
    """
    if not isinstance(broker_id, str) or not broker_id.strip():
        raise ValueError("broker_id must be a non-empty string")
    if not isinstance(raw_account_id, str) or not raw_account_id.strip():
        raise ValueError("raw_account_id must be a non-empty string")
    if not isinstance(blinding_salt_hex, str):
        raise ValueError("blinding_salt_hex must be a hex string")

    cleaned_salt = blinding_salt_hex.strip().lower()
    if len(cleaned_salt) < 32 or len(cleaned_salt) % 2 != 0:
        raise ValueError("blinding_salt_hex must contain at least 16 bytes (32 hex chars)")
    try:
        salt_bytes = bytes.fromhex(cleaned_salt)
    except ValueError as exc:
        raise ValueError("blinding_salt_hex must be valid hexadecimal") from exc

    msg = (
        ACCOUNT_TAG_DOMAIN
        + broker_id.strip().lower().encode("utf-8")
        + b"\x00"
        + raw_account_id.strip().encode("utf-8")
    )
    return hmac.new(salt_bytes, msg, hashlib.sha256).hexdigest()


def is_external_capital_flow(flow_or_kind: NormalizedFlow | FlowKind | str) -> bool:
    """Return True iff the flow represents an external capital contribution or withdrawal."""
    if isinstance(flow_or_kind, NormalizedFlow):
        kind = flow_or_kind.kind
    elif isinstance(flow_or_kind, FlowKind):
        kind = flow_or_kind
    elif isinstance(flow_or_kind, str):
        kind = FlowKind(flow_or_kind)
    else:
        raise ValueError(f"Unsupported flow_or_kind type: {type(flow_or_kind).__name__}")
    return kind in EXTERNAL_CAPITAL_FLOW_KINDS


def _normalize_side(side: str, *, field_name: str) -> str:
    cleaned = side.strip().lower()
    mapping = {
        "buy": "buy",
        "bot": "buy",
        "long": "buy",
        "sell": "sell",
        "sld": "sell",
        "short": "sell",
    }
    if cleaned not in mapping:
        raise ValueError(f"{field_name} must be 'buy' or 'sell' (got {side!r})")
    return mapping[cleaned]


def _normalize_currency(code: str, *, field_name: str) -> str:
    cleaned = code.strip().upper()
    if not (2 <= len(cleaned) <= 12) or not cleaned.isalnum():
        raise ValueError(f"{field_name} must be a 2-12 character alphanumeric currency code")
    return cleaned


@dataclass(slots=True)
class NormalizedNavPoint(ContractModelMixin):
    """Timestamped portfolio net asset value in statement base currency."""

    timestamp_utc: str
    nav_base: float
    cash_base: float | None = None
    positions_base: float | None = None
    accruals_base: float | None = None

    def _validate(self) -> None:
        parse_utc_timestamp(self.timestamp_utc, field_name="NormalizedNavPoint.timestamp_utc")


@dataclass(slots=True)
class NormalizedTrade(ContractModelMixin):
    """Normalized execution fill with unique venue entry key and derivative metadata."""

    venue: str
    native_entry_id: str
    symbol: str
    asset_class: AssetClass
    side: str
    quantity: float
    price: float
    timestamp_utc: str
    currency: str = "USD"
    fx_rate_to_base: float = 1.0
    multiplier: float | None = None
    commission: float = 0.0
    tax: float = 0.0
    isin: str | None = None
    cusip: str | None = None
    exchange: str | None = None
    option_right: str | None = None
    strike: float | None = None
    expiry: str | None = None
    underlying_symbol: str | None = None

    def _validate(self) -> None:
        if not self.venue.strip():
            raise ValueError("NormalizedTrade.venue must not be empty")
        if not self.native_entry_id.strip():
            raise ValueError("NormalizedTrade.native_entry_id must not be empty")
        if not self.symbol.strip():
            raise ValueError("NormalizedTrade.symbol must not be empty")
        parse_utc_timestamp(self.timestamp_utc, field_name="NormalizedTrade.timestamp_utc")
        object.__setattr__(self, "side", _normalize_side(self.side, field_name="NormalizedTrade.side"))
        object.__setattr__(
            self, "currency", _normalize_currency(self.currency, field_name="NormalizedTrade.currency")
        )
        if self.fx_rate_to_base <= 0.0:
            raise ValueError("NormalizedTrade.fx_rate_to_base must be > 0")
        if self.price < 0.0:
            raise ValueError("NormalizedTrade.price must be >= 0")
        if self.multiplier is None:
            default_mult = 100.0 if self.asset_class == AssetClass.OPTION else 1.0
            object.__setattr__(self, "multiplier", default_mult)
        elif self.multiplier <= 0.0:
            raise ValueError("NormalizedTrade.multiplier must be > 0")
        if self.option_right is not None:
            right_norm = self.option_right.strip().upper()
            if right_norm in {"CALL", "C"}:
                object.__setattr__(self, "option_right", "C")
            elif right_norm in {"PUT", "P"}:
                object.__setattr__(self, "option_right", "P")
            else:
                raise ValueError("NormalizedTrade.option_right must be 'C'/'CALL' or 'P'/'PUT'")

    @property
    def notional_base(self) -> float:
        mult = self.multiplier if self.multiplier is not None else 1.0
        return abs(self.quantity) * self.price * mult * self.fx_rate_to_base


@dataclass(slots=True)
class NormalizedPosition(ContractModelMixin):
    """Prior-period or ending portfolio position record."""

    prior_period_or_ending: str
    symbol: str
    asset_class: AssetClass
    quantity: float
    cost_basis: float
    market_value: float
    currency: str = "USD"
    fx_rate_to_base: float = 1.0
    multiplier: float | None = None
    isin: str | None = None
    underlying_symbol: str | None = None
    option_right: str | None = None
    strike: float | None = None
    expiry: str | None = None

    def _validate(self) -> None:
        boundary = self.prior_period_or_ending.strip().lower()
        if boundary not in {"prior", "ending"}:
            raise ValueError("NormalizedPosition.prior_period_or_ending must be 'prior' or 'ending'")
        object.__setattr__(self, "prior_period_or_ending", boundary)
        if not self.symbol.strip():
            raise ValueError("NormalizedPosition.symbol must not be empty")
        object.__setattr__(
            self, "currency", _normalize_currency(self.currency, field_name="NormalizedPosition.currency")
        )
        if self.fx_rate_to_base <= 0.0:
            raise ValueError("NormalizedPosition.fx_rate_to_base must be > 0")
        if self.multiplier is None:
            default_mult = 100.0 if self.asset_class == AssetClass.OPTION else 1.0
            object.__setattr__(self, "multiplier", default_mult)
        elif self.multiplier <= 0.0:
            raise ValueError("NormalizedPosition.multiplier must be > 0")

    @property
    def market_value_base(self) -> float:
        return self.market_value * self.fx_rate_to_base


@dataclass(slots=True)
class NormalizedFlow(ContractModelMixin):
    """Cash flow or mark-to-market valued in-kind transfer (ACATS/FOP/DWAC)."""

    timestamp_utc: str
    kind: FlowKind
    amount: float
    currency: str = "USD"
    fx_rate_to_base: float = 1.0
    amount_base: float | None = None
    symbol: str | None = None
    quantity: float | None = None
    isin: str | None = None
    transfer_type: str | None = None
    description: str = ""

    def _validate(self) -> None:
        parse_utc_timestamp(self.timestamp_utc, field_name="NormalizedFlow.timestamp_utc")
        object.__setattr__(
            self, "currency", _normalize_currency(self.currency, field_name="NormalizedFlow.currency")
        )
        if self.fx_rate_to_base <= 0.0:
            raise ValueError("NormalizedFlow.fx_rate_to_base must be > 0")
        if self.amount_base is None:
            computed = self.amount * self.fx_rate_to_base
            object.__setattr__(self, "amount_base", 0.0 if computed == 0.0 else computed)
        if self.kind in {FlowKind.TRANSFER_IN_KIND, FlowKind.TRANSFER_OUT_KIND}:
            if self.symbol is not None and not self.symbol.strip():
                raise ValueError("In-kind transfer symbol must not be empty when provided")

    @property
    def is_external_capital_flow(self) -> bool:
        return self.kind in EXTERNAL_CAPITAL_FLOW_KINDS


@dataclass(slots=True)
class CorporateActionRecord(ContractModelMixin):
    """Split, merger, spin-off, symbol/ISIN change, or option exercise/assignment/expiration."""

    action_type: CorporateActionType
    timestamp_utc: str
    symbol: str
    new_symbol: str | None = None
    isin: str | None = None
    new_isin: str | None = None
    ratio_numerator: float | None = None
    ratio_denominator: float | None = None
    quantity_delta: float = 0.0
    cash_in_lieu_base: float = 0.0
    cost_basis_adjustment_base: float = 0.0
    underlying_symbol: str | None = None
    option_multiplier: float | None = None
    strike: float | None = None
    description: str = ""

    def _validate(self) -> None:
        parse_utc_timestamp(self.timestamp_utc, field_name="CorporateActionRecord.timestamp_utc")
        if not self.symbol.strip():
            raise ValueError("CorporateActionRecord.symbol must not be empty")
        if self.ratio_denominator is not None and self.ratio_denominator <= 0.0:
            raise ValueError("CorporateActionRecord.ratio_denominator must be > 0")
        if self.ratio_numerator is not None and self.ratio_numerator <= 0.0:
            raise ValueError("CorporateActionRecord.ratio_numerator must be > 0")


@dataclass(slots=True)
class CanonicalPortfolioLedger(ContractModelMixin):
    """Privacy-preserving canonical multi-asset ledger normalized across broker adapters."""

    blinded_account_tag: str
    broker_id: str
    account_scope: AccountScope
    claimed_origin_assurance: OriginAssurance
    provider_approval_state: ProviderApprovalState
    environment_tier: EnvironmentTier
    source_body_sha256: str
    base_currency: str
    period_start_utc: str
    period_end_utc: str
    enumerated_subaccount_count: int | None = None
    connected_subaccount_count: int | None = None
    prior_positions: list[NormalizedPosition] = field(default_factory=list)
    ending_positions: list[NormalizedPosition] = field(default_factory=list)
    nav_points: list[NormalizedNavPoint] = field(default_factory=list)
    trades: list[NormalizedTrade] = field(default_factory=list)
    flows: list[NormalizedFlow] = field(default_factory=list)
    corporate_actions: list[CorporateActionRecord] = field(default_factory=list)
    conversion_rates: dict[str, float] = field(default_factory=dict)
    enabled_sections: list[str] = field(default_factory=list)
    parser_warnings: list[str] = field(default_factory=list)

    def _validate(self) -> None:
        object.__setattr__(
            self,
            "blinded_account_tag",
            validate_hex_digest(
                self.blinded_account_tag,
                field_name="CanonicalPortfolioLedger.blinded_account_tag",
                num_bytes=32,
            ),
        )
        if not self.broker_id.strip():
            raise ValueError("CanonicalPortfolioLedger.broker_id must not be empty")
        object.__setattr__(self, "broker_id", self.broker_id.strip().lower())
        object.__setattr__(
            self,
            "source_body_sha256",
            validate_hex_digest(
                self.source_body_sha256,
                field_name="CanonicalPortfolioLedger.source_body_sha256",
                num_bytes=32,
            ),
        )
        object.__setattr__(
            self,
            "base_currency",
            _normalize_currency(
                self.base_currency, field_name="CanonicalPortfolioLedger.base_currency"
            ),
        )
        start_dt = parse_utc_timestamp(
            self.period_start_utc, field_name="CanonicalPortfolioLedger.period_start_utc"
        )
        end_dt = parse_utc_timestamp(
            self.period_end_utc, field_name="CanonicalPortfolioLedger.period_end_utc"
        )
        if end_dt < start_dt:
            raise ValueError("CanonicalPortfolioLedger.period_end_utc must be >= period_start_utc")
        if self.enumerated_subaccount_count is not None and self.enumerated_subaccount_count < 0:
            raise ValueError("enumerated_subaccount_count must be >= 0")
        if self.connected_subaccount_count is not None and self.connected_subaccount_count < 0:
            raise ValueError("connected_subaccount_count must be >= 0")
        for pair, rate in self.conversion_rates.items():
            if rate <= 0.0:
                raise ValueError(f"conversion_rates[{pair!r}] must be > 0")


__all__ = [
    "ACCOUNT_TAG_DOMAIN",
    "AssetClass",
    "CanonicalPortfolioLedger",
    "CorporateActionRecord",
    "CorporateActionType",
    "EXTERNAL_CAPITAL_FLOW_KINDS",
    "FlowKind",
    "NormalizedFlow",
    "NormalizedNavPoint",
    "NormalizedPosition",
    "NormalizedTrade",
    "compute_blinded_account_tag",
    "is_external_capital_flow",
]
