"""Orthogonal assurance enums and shared validated contract model machinery."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import MISSING, dataclass, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
import math
import re
import types
from typing import Any, ClassVar, Self, Union, get_args, get_origin, get_type_hints


_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = re.compile(r"^[0-9a-f]{128}$")


def validate_hex_digest(value: str, *, field_name: str, num_bytes: int = 32) -> str:
    """Validate and normalize a lowercase hex string of exact byte length."""
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a hex string")
    normalized = value.strip().lower()
    expected_len = num_bytes * 2
    if len(normalized) != expected_len:
        raise ValueError(f"{field_name} must be {expected_len} hex characters ({num_bytes} bytes)")
    try:
        bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError(f"{field_name} contains non-hexadecimal characters") from exc
    return normalized


def parse_utc_timestamp(value: str | datetime, *, field_name: str = "timestamp") -> datetime:
    """Parse an ISO-8601 UTC timestamp string (or datetime) into an aware UTC datetime."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            raise ValueError(f"{field_name} must not be empty")
        if cleaned.endswith("Z") or cleaned.endswith("z"):
            cleaned = cleaned[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(cleaned)
        except ValueError as exc:
            raise ValueError(f"{field_name} must be a valid ISO-8601 timestamp: {value!r}") from exc
    else:
        raise ValueError(f"{field_name} must be an ISO-8601 string or datetime")

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


def format_utc_timestamp(dt: datetime) -> str:
    """Format a datetime as canonical ISO-8601 UTC string (``YYYY-MM-DDTHH:MM:SSZ``)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check_json_finite(value: Any, *, field_name: str) -> Any:
    """Ensure arbitrary JSON-like payloads contain no NaN or Infinity floats."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{field_name} must be finite (got {value!r})")
        return 0.0 if value == 0.0 else value
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return {
            str(k): _check_json_finite(v, field_name=f"{field_name}.{k}")
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [
            _check_json_finite(item, field_name=f"{field_name}[{idx}]")
            for idx, item in enumerate(value)
        ]
    return value


def _coerce_typed_value(hint: Any, value: Any, *, field_name: str) -> Any:
    """Runtime validation and coercion for dataclass field annotations."""
    if hint is Any or hint is object:
        return _check_json_finite(value, field_name=field_name)

    origin = get_origin(hint)
    if origin in (Union, types.UnionType):
        args = get_args(hint)
        if value is None:
            if type(None) in args:
                return None
            raise ValueError(f"{field_name} cannot be None")
        non_none = [arg for arg in args if arg is not type(None)]
        # Prioritize Enum subclasses before str since (str, Enum) subclasses str.
        ordered = sorted(
            non_none,
            key=lambda t: 0 if (isinstance(t, type) and issubclass(t, Enum)) else 1,
        )
        last_err: Exception | None = None
        for candidate in ordered:
            try:
                return _coerce_typed_value(candidate, value, field_name=field_name)
            except (ValueError, TypeError) as exc:
                last_err = exc
        raise ValueError(f"Invalid value for {field_name}: {value!r}") from last_err

    if origin is list:
        (item_hint,) = get_args(hint) or (Any,)
        if not isinstance(value, (list, tuple)) or isinstance(value, (str, bytes)):
            raise ValueError(f"{field_name} must be a list")
        return [
            _coerce_typed_value(item_hint, item, field_name=f"{field_name}[{idx}]")
            for idx, item in enumerate(value)
        ]

    if origin is tuple:
        tuple_args = get_args(hint)
        if not isinstance(value, (list, tuple)) or isinstance(value, (str, bytes)):
            raise ValueError(f"{field_name} must be a tuple")
        if len(tuple_args) == 2 and tuple_args[1] is Ellipsis:
            return tuple(
                _coerce_typed_value(tuple_args[0], item, field_name=f"{field_name}[{idx}]")
                for idx, item in enumerate(value)
            )
        if len(tuple_args) != len(value):
            raise ValueError(f"{field_name} expected {len(tuple_args)} elements, got {len(value)}")
        return tuple(
            _coerce_typed_value(sub_hint, item, field_name=f"{field_name}[{idx}]")
            for idx, (sub_hint, item) in enumerate(zip(tuple_args, value))
        )

    if origin is dict:
        key_hint, val_hint = get_args(hint) or (str, Any)
        if not isinstance(value, Mapping):
            raise ValueError(f"{field_name} must be a dict/mapping")
        return {
            _coerce_typed_value(key_hint, k, field_name=f"{field_name}.key"): _coerce_typed_value(
                val_hint, v, field_name=f"{field_name}[{k!r}]"
            )
            for k, v in value.items()
        }

    if isinstance(hint, type):
        if issubclass(hint, Enum):
            if isinstance(value, hint):
                return value
            if isinstance(value, str):
                try:
                    return hint(value)
                except ValueError as exc:
                    valid_vals = ", ".join(repr(member.value) for member in hint)
                    raise ValueError(
                        f"Invalid {hint.__name__} for {field_name}: {value!r} (expected one of {valid_vals})"
                    ) from exc
            raise ValueError(f"{field_name} must be {hint.__name__} or str, got {type(value).__name__}")

        if issubclass(hint, ContractModelMixin):
            if isinstance(value, hint):
                return value
            if isinstance(value, Mapping):
                return hint.from_dict(value)
            raise ValueError(f"{field_name} must be {hint.__name__} or dict, got {type(value).__name__}")

        if hint is bool:
            if not isinstance(value, bool):
                raise ValueError(f"{field_name} must be a bool, got {type(value).__name__}")
            return value

        if hint is int:
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"{field_name} must be an int, got {type(value).__name__}")
            return value

        if hint is float:
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ValueError(f"{field_name} must be a finite float, got {type(value).__name__}")
            fval = float(value)
            if not math.isfinite(fval):
                raise ValueError(f"{field_name} must be finite, got {value!r}")
            return 0.0 if fval == 0.0 else fval

        if hint is str:
            if isinstance(value, Enum) and isinstance(value.value, str):
                return value.value
            if not isinstance(value, str):
                raise ValueError(f"{field_name} must be a str, got {type(value).__name__}")
            return value

    return value


def _serialize_value(value: Any, *, exclude_none: bool = False) -> Any:
    """Recursively convert ContractModelMixin dataclasses and Enums into plain JSON dicts."""
    if isinstance(value, ContractModelMixin):
        return value.to_dict(exclude_none=exclude_none)
    if is_dataclass(value) and not isinstance(value, type):
        out: dict[str, Any] = {}
        for f in fields(value):
            fval = getattr(value, f.name)
            if exclude_none and fval is None:
                continue
            out[f.name] = _serialize_value(fval, exclude_none=exclude_none)
        return out
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, list):
        return [_serialize_value(item, exclude_none=exclude_none) for item in value]
    if isinstance(value, tuple):
        return [_serialize_value(item, exclude_none=exclude_none) for item in value]
    if isinstance(value, Mapping):
        return {
            str(k.value if isinstance(k, Enum) else k): _serialize_value(
                v, exclude_none=exclude_none
            )
            for k, v in value.items()
            if not (exclude_none and v is None)
        }
    if isinstance(value, float) and value == 0.0:
        return 0.0
    return value


class ContractModelMixin:
    """Stdlib dataclass mixin providing runtime validation and Pydantic-compatible serialization."""

    _resolved_type_hints_cache: ClassVar[dict[type, dict[str, Any]]] = {}

    @classmethod
    def _field_type_hints(cls) -> dict[str, Any]:
        cached = cls._resolved_type_hints_cache.get(cls)
        if cached is None:
            cached = get_type_hints(cls)
            cls._resolved_type_hints_cache[cls] = cached
        return cached

    def __post_init__(self) -> None:
        hints = self._field_type_hints()
        for f in fields(self):  # type: ignore[arg-type]
            hint = hints.get(f.name, Any)
            raw_val = getattr(self, f.name)
            coerced = _coerce_typed_value(hint, raw_val, field_name=f"{type(self).__name__}.{f.name}")
            object.__setattr__(self, f.name, coerced)
        self._validate()

    def _validate(self) -> None:
        """Hook overridden by subclasses for domain-specific invariants."""

    def to_dict(self, *, exclude_none: bool = False) -> dict[str, Any]:
        """Serialize model recursively into a JSON-compatible Python dictionary."""
        result: dict[str, Any] = {}
        for f in fields(self):  # type: ignore[arg-type]
            val = getattr(self, f.name)
            if exclude_none and val is None:
                continue
            result[f.name] = _serialize_value(val, exclude_none=exclude_none)
        return result

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | Self) -> Self:
        """Validate and construct an instance from a dictionary or existing instance."""
        if isinstance(data, cls):
            return data
        if not isinstance(data, Mapping):
            raise ValueError(f"{cls.__name__}.from_dict expected a mapping, got {type(data).__name__}")

        kwargs: dict[str, Any] = {}
        missing: list[str] = []
        for f in fields(cls):  # type: ignore[arg-type]
            if f.name in data:
                kwargs[f.name] = data[f.name]
            elif f.default is MISSING and f.default_factory is MISSING:
                missing.append(f.name)
        if missing:
            raise ValueError(
                f"{cls.__name__} missing required field(s): {', '.join(missing)}"
            )
        return cls(**kwargs)

    def model_dump(self, *, mode: str = "json", exclude_none: bool = False) -> dict[str, Any]:
        """Pydantic v2-compatible serialization alias."""
        del mode
        return self.to_dict(exclude_none=exclude_none)

    @classmethod
    def model_validate(cls, data: Mapping[str, Any] | Self) -> Self:
        """Pydantic v2-compatible deserialization alias."""
        return cls.from_dict(data)


class OriginAssurance(str, Enum):
    """Cryptographic origin assurance level (always dynamically derived by verifiers)."""

    BROKER_SIGNED = "broker_signed"
    INDEPENDENTLY_WITNESSED_TLS = "independently_witnessed_tls"
    OPERATOR_RETRIEVED = "operator_retrieved"
    SELF_REPORTED = "self_reported"


class AccountScope(str, Enum):
    """Subaccount completeness and survivorship scope."""

    ALL_ENUMERATED_SUBACCOUNTS = "all_enumerated_subaccounts"
    SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED = "single_account_survivorship_unverified"
    SUBACCOUNT_COMPLETENESS_UNSUPPORTED = "subaccount_completeness_unsupported"
    UNKNOWN_OFFLINE_SCOPE = "unknown_offline_scope"


class ProviderApprovalState(str, Enum):
    """Broker API integration governance state."""

    APPROVED_LIVE = "approved_live"
    USER_KEY_SELF_ATTESTED = "user_key_self_attested"
    PENDING_PROVIDER_APPROVAL = "pending_provider_approval"
    OFFLINE_EXPORT_ONLY = "offline_export_only"
    AGGREGATOR_RELAYED = "aggregator_relayed"
    PUBLIC_API_PERMISSIONLESS = "public_api_permissionless"


class EnvironmentTier(str, Enum):
    """Broker execution environment classification."""

    LIVE_PRODUCTION = "live_production"
    PAPER_OR_SANDBOX_REJECTED = "paper_or_sandbox_rejected"
    UNVERIFIED_OFFLINE = "unverified_offline"


class SignerTrustStatus(str, Enum):
    """Publisher Ed25519 signing key trust status against registry & C2SP checkpoint."""

    OFFICIAL_N170_HOSTED = "official_n170_hosted"
    RETIRED_HISTORICAL_VALID = "retired_historical_valid"
    REVOKED_KEY = "revoked_key"
    UNRECOGNIZED_SELF_HOSTED_SIGNER = "unrecognized_self_hosted_signer"


class ChainContinuityMode(str, Enum):
    """Prospective reporting continuity mode."""

    PROSPECTIVE_CONTINUOUS = "prospective_continuous"
    RETROSPECTIVE_BACKFILL = "retrospective_backfill"
    UNENROLLED_SINGLE_SNAPSHOT = "unenrolled_single_snapshot"
    CONTINUITY_BROKEN = "continuity_broken"


@dataclass(slots=True)
class AssuranceProfile(ContractModelMixin):
    """Composite six-axis assurance profile derived during verification."""

    effective_origin_assurance: OriginAssurance
    account_scope: AccountScope
    provider_approval_state: ProviderApprovalState
    environment_tier: EnvironmentTier
    signer_trust_status: SignerTrustStatus
    chain_continuity_mode: ChainContinuityMode


__all__ = [
    "AccountScope",
    "AssuranceProfile",
    "ChainContinuityMode",
    "ContractModelMixin",
    "EnvironmentTier",
    "OriginAssurance",
    "ProviderApprovalState",
    "SignerTrustStatus",
    "parse_utc_timestamp",
    "validate_hex_digest",
]
