"""Read-only broker adapter ABC and capability boundary enforcement."""

from __future__ import annotations

from abc import ABC
from collections.abc import Iterable
from dataclasses import dataclass
import re

from n170_verify.contracts.assurance import (
    ContractModelMixin,
    OriginAssurance,
    ProviderApprovalState,
)


READ_ONLY_CAPABILITY_PREFIXES: tuple[str, ...] = (
    "read_",
    "list_",
    "get_",
    "fetch_",
    "parse_",
    "verify_",
)

FORBIDDEN_CAPABILITY_TOKENS: frozenset[str] = frozenset(
    {
        "order",
        "orders",
        "place",
        "submit",
        "cancel",
        "replace",
        "modify",
        "withdraw",
        "withdrawal",
        "withdrawals",
        "deposit_initiate",
        "send",
        "write",
        "delete",
        "mutate",
        "borrow",
        "repay",
        "stake",
        "unstake",
        "approve",
        "margin_change",
        "leverage",
    }
)


class ReadOnlyCapabilityViolationError(ValueError):
    """Raised when a broker adapter declares non-read-only or order/withdrawal capabilities."""


def validate_read_only_capabilities(capabilities: Iterable[str]) -> tuple[str, ...]:
    """Validate that every declared adapter capability is strictly read-only."""
    cap_list = list(capabilities)
    if not cap_list:
        raise ReadOnlyCapabilityViolationError(
            "Broker adapter must declare at least one read-only capability"
        )
    normalized: list[str] = []
    for raw in cap_list:
        if not isinstance(raw, str) or not raw.strip():
            raise ReadOnlyCapabilityViolationError("Capability names must be non-empty strings")
        cap = raw.strip().lower()
        if not cap.startswith(READ_ONLY_CAPABILITY_PREFIXES):
            raise ReadOnlyCapabilityViolationError(
                f"Capability {raw!r} violates read-only policy: must begin with one of "
                f"{READ_ONLY_CAPABILITY_PREFIXES}"
            )
        tokens = set(filter(None, re.split(r"[^a-z0-9]+", cap)))
        forbidden_hit = tokens & FORBIDDEN_CAPABILITY_TOKENS
        if forbidden_hit:
            raise ReadOnlyCapabilityViolationError(
                f"Capability {raw!r} contains prohibited mutation/trading/withdrawal token(s): "
                f"{sorted(forbidden_hit)}"
            )
        if cap in {"transfer_funds", "read_and_withdraw"}:
            raise ReadOnlyCapabilityViolationError(f"Capability {raw!r} is prohibited")
        normalized.append(cap)
    return tuple(dict.fromkeys(normalized))


@dataclass(slots=True)
class BrokerAdapterDescriptor(ContractModelMixin):
    """Serializable metadata describing a read-only broker adapter."""

    broker_id: str
    display_name: str
    approval_state: ProviderApprovalState
    default_origin_assurance: OriginAssurance
    supports_subaccount_enumeration: bool
    allowed_capabilities: tuple[str, ...]

    def _validate(self) -> None:
        if not self.broker_id.strip():
            raise ValueError("broker_id must not be empty")
        if not self.display_name.strip():
            raise ValueError("display_name must not be empty")
        validated_caps = validate_read_only_capabilities(self.allowed_capabilities)
        object.__setattr__(self, "allowed_capabilities", validated_caps)


class ReadOnlyBrokerAdapter(ABC):
    """Abstract base class for strictly read-only brokerage & exchange adapters.

    Order placement, order cancellation, margin modification, and fund withdrawals
    are structurally prohibited across all N170 Verify adapters.
    """

    broker_id: str = ""
    display_name: str = ""
    approval_state: ProviderApprovalState = ProviderApprovalState.OFFLINE_EXPORT_ONLY
    default_origin_assurance: OriginAssurance = OriginAssurance.SELF_REPORTED
    supports_subaccount_enumeration: bool = False
    allowed_capabilities: tuple[str, ...] = ()

    def __init__(self) -> None:
        if type(self) is ReadOnlyBrokerAdapter:
            raise TypeError(
                "ReadOnlyBrokerAdapter is an abstract base class and cannot be instantiated directly"
            )
        self.assert_read_only_capabilities()

    def assert_read_only_capabilities(self) -> tuple[str, ...]:
        """Enforce non-empty broker identity, enum types, and read-only capability allowlist."""
        if not isinstance(self.broker_id, str) or not self.broker_id.strip():
            raise ValueError(f"{type(self).__name__}.broker_id must be a non-empty string")
        if not isinstance(self.display_name, str) or not self.display_name.strip():
            raise ValueError(f"{type(self).__name__}.display_name must be a non-empty string")
        if not isinstance(self.approval_state, ProviderApprovalState):
            self.approval_state = ProviderApprovalState(self.approval_state)
        if not isinstance(self.default_origin_assurance, OriginAssurance):
            self.default_origin_assurance = OriginAssurance(self.default_origin_assurance)
        if not isinstance(self.supports_subaccount_enumeration, bool):
            raise ValueError("supports_subaccount_enumeration must be a bool")
        validated = validate_read_only_capabilities(self.allowed_capabilities)
        self.allowed_capabilities = validated
        return validated

    def describe_adapter(self) -> BrokerAdapterDescriptor:
        """Return validated descriptor for capability introspection."""
        caps = self.assert_read_only_capabilities()
        return BrokerAdapterDescriptor(
            broker_id=self.broker_id.strip().lower(),
            display_name=self.display_name.strip(),
            approval_state=self.approval_state,
            default_origin_assurance=self.default_origin_assurance,
            supports_subaccount_enumeration=self.supports_subaccount_enumeration,
            allowed_capabilities=caps,
        )


__all__ = [
    "BrokerAdapterDescriptor",
    "FORBIDDEN_CAPABILITY_TOKENS",
    "READ_ONLY_CAPABILITY_PREFIXES",
    "ReadOnlyBrokerAdapter",
    "ReadOnlyCapabilityViolationError",
    "validate_read_only_capabilities",
]
