"""Read-only SnapTrade V1 aggregator relay adapter with HMAC-SHA256 signing and 5-slot cap."""

from __future__ import annotations

import base64
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import os
import time
from typing import Any
import urllib.parse

from n170_verify.connectors.ccxt_crypto import (
    HttpExchangeResponse,
    HttpTransportCallable,
    PaperOrSandboxAccountRejectedError,
    invoke_http_transport,
    validate_ssrf_safe_https_url,
)
from n170_verify.connectors.ctrader_oauth import DisallowedCapabilityError
from n170_verify.connectors.mcp_allowlist_firewall import redact_sensitive_text
from n170_verify.connectors.statement_csv import reject_unofficial_scraper_credentials
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    BrokerAdapterDescriptor,
    CanonicalPortfolioLedger,
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
    ReadOnlyBrokerAdapter,
    compute_blinded_account_tag,
)

SNAPTRADE_LIVE_BASE_URL: str = "https://api.snaptrade.com"
DEFAULT_SNAPTRADE_USER_AGENT: str = "N170-Verify-SnapTrade-POC/1.0"
MAX_SNAPTRADE_POC_SLOTS: int = 5
MAX_SNAPTRADE_PERSONAL_SLOTS: int = 1
MAX_ACTIVITIES_PAGE_SIZE: int = 1000
MAX_ACTIVITIES_PAGES: int = 10

_PLACEHOLDER_CREDENTIAL_VALUES: frozenset[str] = frozenset(
    {
        "",
        "snaptrade-poc-client",
        "snaptrade-poc-key",
        "placeholder",
        "changeme",
        "change_me",
        "change-me",
        "your_client_id",
        "your_consumer_key",
        "your-client-id",
        "your-consumer-key",
        "replace_me",
        "replace-me",
        "none",
        "null",
        "todo",
        "xxx",
    }
)

SNAPTRADE_BLOCKED_MUTATING_ENDPOINTS: tuple[str, ...] = (
    "/api/v1/trade/place",
    "/api/v1/trade/cancel",
    "/api/v1/trade/crypto",
    "/api/v1/trade/orders",
    "/api/v1/accounts/transfer",
)

_BLOCKED_MUTATING_ACTIONS: frozenset[str] = frozenset(
    {
        "trade",
        "place_order",
        "cancel_order",
        "modify_order",
        "transfer_funds",
        "withdraw",
        "deposit",
        "borrow",
        "margin_change",
    }
)


class SnapTradeError(Exception):
    """Base error for SnapTrade aggregator relay operations."""


class SnapTradeSlotCapExceededError(SnapTradeError, ValueError):
    """Raised when attempting to allocate more than the capped 5 POC connection slots."""


class SnapTradeServiceError(SnapTradeError, RuntimeError):
    """Raised when SnapTrade relay upstream service encounters an unrecoverable HTTP/API error."""


class SnapTradeAuthenticationError(SnapTradeError, ValueError):
    """Raised when SnapTrade credentials or signatures are invalid or missing."""


def _is_non_placeholder_credential(raw: str | None) -> bool:
    if raw is None:
        return False
    cleaned = str(raw).strip()
    if not cleaned:
        return False
    lower = cleaned.lower()
    if lower in _PLACEHOLDER_CREDENTIAL_VALUES:
        return False
    if lower.startswith(("your_", "your-", "<", "replace_")):
        return False
    return True


def is_snaptrade_env_configured(env: Mapping[str, str] | None = None) -> bool:
    """Return True iff non-placeholder SNAPTRADE_CLIENT_ID and SNAPTRADE_CONSUMER_KEY are present."""
    source = os.environ if env is None else env
    client_id = source.get("SNAPTRADE_CLIENT_ID")
    consumer_key = source.get("SNAPTRADE_CONSUMER_KEY")
    return _is_non_placeholder_credential(client_id) and _is_non_placeholder_credential(
        consumer_key
    )


def is_snaptrade_personal_key(
    client_id: str | None,
    *,
    auth_mode: str | None = None,
) -> bool:
    """Return True when ``client_id`` or ``SNAPTRADE_AUTH_MODE`` selects SnapTrade Personal mode."""
    if auth_mode is not None and str(auth_mode).strip():
        norm_mode = str(auth_mode).strip().lower()
        if norm_mode in {"personal", "personal_key", "personal_1_slot"}:
            return True
        if norm_mode in {"commercial", "build", "developer_5_slot"}:
            return False
        if norm_mode != "auto":
            raise SnapTradeAuthenticationError(
                "SNAPTRADE_AUTH_MODE must be 'auto', 'personal', or 'commercial'"
            )
    if not isinstance(client_id, str):
        return False
    return client_id.strip().upper().startswith("PERS-")


def _normalize_snaptrade_api_path(api_path: str) -> str:
    cleaned = (api_path or "").strip()
    if not cleaned:
        raise ValueError("SnapTrade api_path must not be empty")
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    if "?" in cleaned:
        cleaned = cleaned.split("?", 1)[0]
    lower_path = cleaned.lower()
    if (
        cleaned in SNAPTRADE_BLOCKED_MUTATING_ENDPOINTS
        or lower_path.startswith("/api/v1/trade/")
        or lower_path == "/api/v1/trade"
        or lower_path.endswith("/transfer")
        or "/trade/place" in lower_path
        or "/trade/cancel" in lower_path
        or "/trade/orders" in lower_path
    ):
        raise DisallowedCapabilityError(
            f"SnapTrade endpoint {cleaned!r} is strictly disallowed by read-only policy"
        )
    return cleaned


def compute_snaptrade_signature(
    consumer_key: str,
    *,
    api_path: str,
    query_string: str,
    content: Any = None,
) -> str:
    """Compute Base64 HMAC-SHA256 SnapTrade V1 ``Signature`` header over canonical request metadata."""
    if not isinstance(consumer_key, str) or not consumer_key.strip():
        raise SnapTradeAuthenticationError("SnapTrade consumer_key must not be empty")

    norm_path = _normalize_snaptrade_api_path(api_path)
    norm_query = (query_string or "").lstrip("?")

    body_obj: Any
    if content is None:
        body_obj = None
    elif isinstance(content, (bytes, bytearray)):
        raw_str = bytes(content).decode("utf-8").strip()
        body_obj = json.loads(raw_str) if raw_str else None
    elif isinstance(content, str):
        raw_str = content.strip()
        body_obj = json.loads(raw_str) if raw_str else None
    else:
        body_obj = content

    sig_object = {
        "content": body_obj,
        "path": norm_path,
        "query": norm_query,
    }
    canonical_bytes = json.dumps(sig_object, separators=(",", ":"), sort_keys=True).encode("utf-8")
    digest = hmac.new(
        consumer_key.strip().encode("utf-8"),
        canonical_bytes,
        hashlib.sha256,
    ).digest()
    return base64.b64encode(digest).decode("ascii")


@dataclass(frozen=True, slots=True)
class SignedSnapTradeRequest(Mapping[str, Any]):
    """Signed SnapTrade V1 HTTP request specification (zero secrets in HTTP headers)."""

    method: str
    url: str
    api_path: str
    query_string: str
    headers: dict[str, str]
    body: bytes | None
    signature: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "api_path": self.api_path,
            "query_string": self.query_string,
            "headers": dict(self.headers),
            "body": self.body,
            "signature": self.signature,
            "timestamp": self.timestamp,
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return 8


def build_signed_request(
    method: str,
    api_path: str,
    *,
    client_id: str,
    consumer_key: str,
    base_url: str = SNAPTRADE_LIVE_BASE_URL,
    user_id: str | None = None,
    user_secret: str | None = None,
    extra_query_params: Mapping[str, Any] | None = None,
    json_body: Any = None,
    timestamp: int | str | None = None,
    auth_mode: str | None = None,
) -> SignedSnapTradeRequest:
    """Construct a signed SnapTrade V1 HTTP request with deterministic query params and HMAC header."""
    clean_client = (client_id or "").strip()
    clean_consumer = (consumer_key or "").strip()
    if not clean_client:
        raise SnapTradeAuthenticationError("SnapTrade client_id must not be empty")
    if not clean_consumer:
        raise SnapTradeAuthenticationError("SnapTrade consumer_key must not be empty")

    verb = (method or "GET").strip().upper()
    norm_path = _normalize_snaptrade_api_path(api_path)
    ts_str = str(int(time.time())) if timestamp is None else str(timestamp).strip()
    if not ts_str:
        raise SnapTradeAuthenticationError("SnapTrade timestamp must not be empty")

    params: dict[str, str] = {
        "clientId": clean_client,
        "timestamp": ts_str,
    }
    personal_mode = is_snaptrade_personal_key(clean_client, auth_mode=auth_mode)
    if not personal_mode:
        if user_id is not None and str(user_id).strip():
            params["userId"] = str(user_id).strip()
        if user_secret is not None and str(user_secret).strip():
            params["userSecret"] = str(user_secret).strip()
    if extra_query_params:
        for k, v in extra_query_params.items():
            k_str = str(k)
            if personal_mode and k_str in {"userId", "userSecret"}:
                continue
            if v is not None and str(v).strip() != "":
                params[k_str] = str(v)

    ordered_pairs = [(k, params[k]) for k in sorted(params.keys())]
    query_string = urllib.parse.urlencode(ordered_pairs, quote_via=urllib.parse.quote)

    body_obj: Any = None
    body_bytes: bytes | None = None
    if json_body is not None and not (verb in {"GET", "DELETE"} and json_body in (b"", "")):
        if isinstance(json_body, (bytes, bytearray)):
            decoded = bytes(json_body).decode("utf-8").strip()
            if decoded:
                body_obj = json.loads(decoded)
        elif isinstance(json_body, str):
            decoded = json_body.strip()
            if decoded:
                body_obj = json.loads(decoded)
        else:
            body_obj = json_body

        if body_obj is not None:
            body_bytes = json.dumps(body_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

    signature = compute_snaptrade_signature(
        clean_consumer,
        api_path=norm_path,
        query_string=query_string,
        content=body_obj,
    )

    headers: dict[str, str] = {
        "Accept": "application/json",
        "User-Agent": DEFAULT_SNAPTRADE_USER_AGENT,
        "Signature": signature,
    }
    if body_bytes is not None:
        headers["Content-Type"] = "application/json"

    full_url = f"{base_url.rstrip('/')}{norm_path}?{query_string}"
    return SignedSnapTradeRequest(
        method=verb,
        url=full_url,
        api_path=norm_path,
        query_string=query_string,
        headers=headers,
        body=body_bytes,
        signature=signature,
        timestamp=ts_str,
    )


@dataclass(slots=True)
class SnapTradeConnectionSlot:
    """Represents a registered connection slot within the capped 5-slot POC relay."""

    slot_id: int
    user_id: str
    registered_at_utc: str
    broker_authorization_id: str | None = None
    active: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "user_id": self.user_id,
            "registered_at_utc": self.registered_at_utc,
            "broker_authorization_id": self.broker_authorization_id,
            "active": self.active,
        }


class SnapTradeSlotManager:
    """In-memory coordinator enforcing the strict 5-slot ceiling for the POC aggregator relay."""

    def __init__(self, max_slots: int = MAX_SNAPTRADE_POC_SLOTS) -> None:
        if max_slots < 1:
            raise ValueError("max_slots must be at least 1")
        self._max_slots = max_slots
        self._slots: dict[str, SnapTradeConnectionSlot] = {}

    @property
    def max_slots(self) -> int:
        return self._max_slots

    def active_slot_count(self) -> int:
        return sum(1 for s in self._slots.values() if s.active)

    def available_slot_count(self) -> int:
        return max(0, self._max_slots - self.active_slot_count())

    def is_user_registered(self, user_id: str) -> bool:
        slot = self._slots.get((user_id or "").strip())
        return slot is not None and slot.active

    def get_slot(self, user_id: str) -> SnapTradeConnectionSlot | None:
        return self._slots.get((user_id or "").strip())

    def get_slot_by_id(self, slot_id: int) -> SnapTradeConnectionSlot | None:
        for slot in self._slots.values():
            if slot.active and slot.slot_id == slot_id:
                return slot
        return None

    def list_active_slots(self) -> list[SnapTradeConnectionSlot]:
        return sorted(
            [s for s in self._slots.values() if s.active],
            key=lambda s: s.slot_id,
        )

    def register_slot(
        self,
        user_id: str,
        *,
        broker_authorization_id: str | None = None,
        now_iso: str | None = None,
    ) -> SnapTradeConnectionSlot:
        """Register a user into a connection slot, enforcing the maximum slot cap."""
        if not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("user_id must be a non-empty string")
        clean_user = user_id.strip()

        existing = self._slots.get(clean_user)
        if existing and existing.active:
            if broker_authorization_id:
                existing.broker_authorization_id = broker_authorization_id
            return existing

        current_active = self.active_slot_count()
        if current_active >= self._max_slots:
            raise SnapTradeSlotCapExceededError(
                f"SnapTrade POC aggregator relay is strictly capped at {self._max_slots} connection slots; "
                f"cannot register user {clean_user!r} (currently {current_active}/{self._max_slots} active)"
            )

        occupied_ids = {s.slot_id for s in self._slots.values() if s.active}
        next_id = next(i for i in range(1, self._max_slots + 1) if i not in occupied_ids)

        ts = now_iso or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        )
        slot = SnapTradeConnectionSlot(
            slot_id=next_id,
            user_id=clean_user,
            registered_at_utc=ts,
            broker_authorization_id=broker_authorization_id,
            active=True,
        )
        self._slots[clean_user] = slot
        return slot

    def release_slot(self, user_id: str) -> bool:
        """Release an active connection slot, freeing it for subsequent connections."""
        clean_user = (user_id or "").strip()
        slot = self._slots.get(clean_user)
        if slot and slot.active:
            slot.active = False
            return True
        return False

    def clear(self) -> None:
        """Reset all connection slots."""
        self._slots.clear()


_GLOBAL_POC_SLOT_MANAGER = SnapTradeSlotManager(MAX_SNAPTRADE_POC_SLOTS)


def get_global_snaptrade_slot_manager() -> SnapTradeSlotManager:
    """Return the global singleton slot manager for the SnapTrade POC relay."""
    return _GLOBAL_POC_SLOT_MANAGER


def _fetch_time_ts() -> str:
    """The current time, used only for a snapshot whose accounts carry no timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso_ts(value: Any, *, end_of_day: bool = False) -> str | None:
    """Normalize a timestamp to UTC ``YYYY-MM-DDTHH:MM:SSZ``.

    A value without a zone is read as UTC, never as the server's local time. A missing or
    unreadable value returns ``None``: the caller decides, and a date is never guessed.
    """
    if value is None or not str(value).strip():
        return None
    raw = str(value).strip()
    if len(raw) == 10 and raw[4] == "-" and raw[7] == "-":
        raw = f"{raw}T23:59:59Z" if end_of_day else f"{raw}T00:00:00Z"
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    if end_of_day and dt.hour == 0 and dt.minute == 0 and dt.second == 0 and "00:00:00.000" in raw:
        dt = dt.replace(hour=23, minute=59, second=59)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# Stable text of the "no brokerage account is linked yet" refusal. Across a process boundary
# that forwards only the message, this text is what identifies the refusal.
SNAPTRADE_NO_LINKED_ACCOUNT_MESSAGE = "No brokerage accounts are connected to this SnapTrade session yet"
SNAPTRADE_INITIAL_SYNC_PENDING_MESSAGE = (
    "Brokerage account connected, initial holdings and transaction sync is still in progress"
)


class SnapTradeNoLinkedAccountError(ValueError):
    """No brokerage account is linked to this connection yet; a retry after linking can succeed.

    A ``ValueError`` subclass, so existing handlers still treat it as a validation refusal.
    ``reason_code`` is a class attribute, so it survives re-raising with a new message.
    """

    reason_code = "no_linked_account"


class SnapTradeInitialSyncPendingError(SnapTradeNoLinkedAccountError):
    """Brokerage account is linked, but SnapTrade initial sync has not finished yet."""

    reason_code = "initial_sync_pending"


class SnapTradeUnreadableDateError(ValueError):
    """A row that feeds a valuation or a flow has no readable date."""


class SnapTradeActivityPaginationLimitError(ValueError):
    """SnapTrade activities pagination hit MAX_ACTIVITIES_PAGES without exhausting history."""

    reason_code = "activities_pagination_limit_exceeded"


_TRADE_ACTIVITY_TYPES = frozenset({"buy", "sell", "rei"})
_FLOW_ACTIVITY_TYPES = frozenset(
    {
        "deposit",
        "contribution",
        "funds_contribution",
        "withdrawal",
        "funds_withdrawal",
        "dividend",
        "interest",
        "fee",
        "tax",
        "transfer",
    }
)
_CORPORATE_ACTION_TYPES = frozenset({"optionexpiration", "optionassignment", "optionexercise", "split"})


def _normalize_date_param(value: str | None, *, field_name: str) -> str | None:
    if value is None or not str(value).strip():
        return None
    raw = str(value).strip()
    date_part = raw[:10]
    try:
        datetime.strptime(date_part, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError(f"{field_name} must start with YYYY-MM-DD (got {value!r})") from exc
    return date_part


def _extract_currency_code(raw: Any, default: str = "USD") -> str:
    if isinstance(raw, Mapping):
        code = raw.get("code") or raw.get("currency") or raw.get("id")
        if code:
            cleaned = str(code).strip().upper()
            if 2 <= len(cleaned) <= 12 and cleaned.isalnum():
                return cleaned
        return default
    if isinstance(raw, str):
        cleaned = raw.strip().upper()
        if 2 <= len(cleaned) <= 12 and cleaned.isalnum():
            return cleaned
    return default


def _extract_symbol_and_currency(raw_symbol: Any, default_ccy: str = "USD") -> tuple[str, str, str]:
    """Unwrap nested SnapTrade UniversalSymbol/BrokerageSymbol objects into (ticker, ccy, type_code)."""
    if isinstance(raw_symbol, str):
        return raw_symbol.strip().upper(), default_ccy, ""
    if isinstance(raw_symbol, Mapping):
        node: Any = raw_symbol
        resolved_ccy = default_ccy
        for _ in range(3):
            if isinstance(node, Mapping):
                if node.get("currency") is not None:
                    resolved_ccy = _extract_currency_code(node.get("currency"), resolved_ccy)
                if isinstance(node.get("symbol"), Mapping):
                    node = node["symbol"]
                else:
                    break
            else:
                break
        if isinstance(node, str):
            return node.strip().upper(), resolved_ccy, ""
        if isinstance(node, Mapping):
            sym_val = node.get("raw_symbol") or node.get("symbol") or node.get("ticker") or ""
            if node.get("currency") is not None:
                resolved_ccy = _extract_currency_code(node.get("currency"), resolved_ccy)
            t_obj = node.get("type") or node.get("asset_type") or node.get("kind")
            if isinstance(t_obj, Mapping):
                t_code = str(
                    t_obj.get("code") or t_obj.get("id") or t_obj.get("description") or ""
                ).strip().lower()
            else:
                t_code = str(t_obj or "").strip().lower()
            return str(sym_val).strip().upper(), resolved_ccy, t_code
    return "", default_ccy, ""


def _extract_units(item: Mapping[str, Any]) -> float:
    """Extract share/contract quantity supporting SnapTrade ``units`` and ``fractional_units``."""
    raw_u = item.get("units")
    if raw_u is not None and raw_u != "":
        val = float(raw_u)
        if not math.isfinite(val) or abs(val) > 1e30:
            raise ValueError(f"Non-finite or out-of-range SnapTrade units: {raw_u!r}")
        if val != 0.0 or item.get("fractional_units") in (None, ""):
            return val
    raw_frac = item.get("fractional_units")
    if raw_frac is not None and raw_frac != "":
        val_f = float(raw_frac)
        if not math.isfinite(val_f) or abs(val_f) > 1e30:
            raise ValueError(f"Non-finite or out-of-range SnapTrade fractional_units: {raw_frac!r}")
        return val_f
    raw_qty = item.get("quantity")
    if raw_qty is not None and raw_qty != "":
        val_q = float(raw_qty)
        if not math.isfinite(val_q) or abs(val_q) > 1e30:
            raise ValueError(f"Non-finite or out-of-range SnapTrade quantity: {raw_qty!r}")
        return val_q
    return 0.0


def _extract_account_id(item: Mapping[str, Any], default_id: str = "") -> str:
    acct_field = item.get("account")
    if isinstance(acct_field, Mapping):
        aid = acct_field.get("id") or acct_field.get("account_number") or acct_field.get("number")
        if aid:
            return str(aid).strip()
    elif isinstance(acct_field, str) and acct_field.strip():
        return acct_field.strip()
    for key in ("account_id", "accountId", "id", "account_number", "number"):
        val = item.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return default_id


def _infer_asset_class(symbol: str, type_code: str, *, is_option: bool = False) -> AssetClass:
    if is_option or type_code in {"op", "opt", "option"}:
        return AssetClass.OPTION
    if type_code in {"et", "etf", "etn", "cef", "exchange traded fund", "closed end fund"}:
        return AssetClass.ETF
    if type_code in {"crypto", "cryptocurrency"}:
        return AssetClass.CRYPTO_SPOT
    if len(symbol) > 14 and any(c.isdigit() for c in symbol):
        return AssetClass.OPTION
    return AssetClass.EQUITY


def _position_asset_info(
    pos_map: Mapping[str, Any],
    default_ccy: str = "USD",
) -> tuple[str, str, AssetClass, float]:
    """Return ``(symbol, currency, asset_class, contract_multiplier)`` for a SnapTrade position."""
    pos_sym_source = (
        pos_map.get("symbol") if pos_map.get("symbol") is not None else pos_map.get("instrument")
    )
    sym_str, sym_ccy, sym_type = _extract_symbol_and_currency(pos_sym_source, default_ccy)
    opt_obj = pos_map.get("option_symbol")
    is_opt = isinstance(opt_obj, Mapping) and bool(opt_obj)
    if is_opt and isinstance(opt_obj, Mapping):
        opt_ticker = str(opt_obj.get("ticker") or sym_str or "").strip().upper()
        if opt_ticker:
            sym_str = opt_ticker
    asset_cls = _infer_asset_class(sym_str, sym_type, is_option=is_opt)
    mult = 100.0 if asset_cls == AssetClass.OPTION else 1.0
    resolved_ccy = _extract_currency_code(pos_map.get("currency"), sym_ccy or default_ccy)
    return sym_str, resolved_ccy, asset_cls, mult


def _parse_currency_rate_pairs(
    raw_currency_rates: Any,
    raw_conversion_rates: Any,
    base_currency: str,
) -> tuple[dict[tuple[str, str], float], dict[str, float]]:
    """Parse SnapTrade ``/currencies/rates`` rows and explicit FX maps into pair & ledger tables."""
    pair_rates: dict[tuple[str, str], float] = {}

    if isinstance(raw_currency_rates, list):
        for row in raw_currency_rates:
            if not isinstance(row, Mapping):
                continue
            src = _extract_currency_code(row.get("src"), default="")
            dst = _extract_currency_code(row.get("dst"), default="")
            raw_rate = row.get("exchange_rate")
            if raw_rate is None:
                raw_rate = row.get("rate")
            if src and dst and raw_rate is not None:
                try:
                    rate_val = float(raw_rate)
                except (TypeError, ValueError):
                    continue
                if math.isfinite(rate_val) and 0.0 < rate_val <= 1e30:
                    pair_rates[(src, dst)] = rate_val
    elif isinstance(raw_currency_rates, Mapping):
        raw_conversion_rates = (
            {**dict(raw_currency_rates), **dict(raw_conversion_rates)}
            if isinstance(raw_conversion_rates, Mapping)
            else raw_currency_rates
        )

    if isinstance(raw_conversion_rates, Mapping):
        for raw_k, raw_v in raw_conversion_rates.items():
            if raw_v is None:
                continue
            try:
                rate_val = float(raw_v)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(rate_val) or rate_val <= 0.0 or rate_val > 1e30:
                continue
            key_str = str(raw_k).strip().upper()
            if "/" in key_str:
                parts = key_str.split("/", 1)
                src = _extract_currency_code(parts[0], default="")
                dst = _extract_currency_code(parts[1], default="")
                if src and dst:
                    pair_rates[(src, dst)] = rate_val
            elif len(key_str) == 6 and key_str.isalpha():
                pair_rates[(key_str[:3], key_str[3:])] = rate_val
            else:
                src = _extract_currency_code(key_str, default="")
                if src and base_currency:
                    pair_rates[(src, base_currency)] = rate_val

    conversion_rates_out: dict[str, float] = {}
    for (src, dst), rate_val in list(pair_rates.items()):
        if src == dst or rate_val <= 0.0:
            continue
        conversion_rates_out[f"{src}/{dst}"] = rate_val
        conversion_rates_out.setdefault(f"{dst}/{src}", round(1.0 / rate_val, 10))

    if base_currency != "USD":
        base_to_usd = _lookup_fx_rate(base_currency, "USD", pair_rates)
        if base_to_usd is not None and base_to_usd > 0.0:
            conversion_rates_out.setdefault(f"{base_currency}/USD", base_to_usd)
            conversion_rates_out.setdefault(f"USD/{base_currency}", round(1.0 / base_to_usd, 10))

    return pair_rates, conversion_rates_out


def _lookup_fx_rate(
    src_currency: str,
    dst_currency: str,
    pair_rates: Mapping[tuple[str, str], float],
) -> float | None:
    """Resolve ``1 src_currency -> X dst_currency`` from direct, inverse, or USD-bridged pairs."""
    src = (src_currency or "").strip().upper()
    dst = (dst_currency or "").strip().upper()
    if not src or not dst or src == dst:
        return 1.0
    direct = pair_rates.get((src, dst))
    if direct is not None and direct > 0.0:
        return direct
    inverse = pair_rates.get((dst, src))
    if inverse is not None and inverse > 0.0:
        return round(1.0 / inverse, 10)
    if src != "USD" and dst != "USD":
        src_to_usd = pair_rates.get((src, "USD"))
        if src_to_usd is None and pair_rates.get(("USD", src)):
            src_to_usd = 1.0 / pair_rates[("USD", src)]
        usd_to_dst = pair_rates.get(("USD", dst))
        if usd_to_dst is None and pair_rates.get((dst, "USD")):
            usd_to_dst = 1.0 / pair_rates[(dst, "USD")]
        if src_to_usd and src_to_usd > 0.0 and usd_to_dst and usd_to_dst > 0.0:
            return round(src_to_usd * usd_to_dst, 10)
    return None


class SnapTradeMissingFxRateError(ValueError):
    """A value is in a currency that has no conversion rate to the currency it must be valued in.

    A ``ValueError`` (not an upstream service error): the account data is incomplete, so the
    record is refused as a validation failure with this reason.
    """


class SnapTradeSelectionError(ValueError):
    """A record was asked to claim accounts that this connection did not return."""


_CAPITAL_FLOW_KINDS = frozenset(
    {
        FlowKind.DEPOSIT,
        FlowKind.WITHDRAWAL,
        FlowKind.TRANSFER_IN_KIND,
        FlowKind.TRANSFER_OUT_KIND,
        FlowKind.INTERNAL_SUBACCOUNT_TRANSFER,
    }
)


def _trim_valuation_series(
    items: Sequence[tuple[str, tuple[float, float | None]]],
) -> list[tuple[str, tuple[float, float | None]]]:
    """Keep a time-ordered valuation series from its first positive value onward.

    A value at or below zero after a positive one stays in the series, so a wipe-out is
    visible to the return calculation and is never skipped. After the last positive value
    only the first non-positive one is kept (a full withdrawal); leading zeros before the
    account was funded are not part of the series.
    """
    ordered = sorted(items, key=lambda kv: kv[0])
    pos_idx = [i for i, (_, vals) in enumerate(ordered) if vals[0] > 0.0]
    if not pos_idx:
        return []
    first, last = pos_idx[0], pos_idx[-1]
    kept = ordered[first : last + 1]
    if last + 1 < len(ordered):
        kept.append(ordered[last + 1])
    return kept


def _require_fx_rate(
    src_currency: str,
    dst_currency: str,
    pair_rates: Mapping[tuple[str, str], float],
) -> float:
    """Return the ``src -> dst`` rate, or raise: a foreign amount is never valued at 1:1."""
    rate = _lookup_fx_rate(src_currency, dst_currency, pair_rates)
    if rate is None or not rate > 0.0:
        raise SnapTradeMissingFxRateError(
            f"No conversion rate from {src_currency} to {dst_currency} is available; "
            "the record is withheld rather than counting one currency as the other."
        )
    return rate


def _scrub_account_identifiers(text: str, raw_identifiers: Sequence[str]) -> str:
    cleaned = text or ""
    for raw_ident in raw_identifiers:
        tok = (raw_ident or "").strip()
        if len(tok) >= 4 and tok in cleaned:
            cleaned = cleaned.replace(tok, "[REDACTED]")
    return cleaned


class SnapTradeReadOnlyAdapter(ReadOnlyBrokerAdapter):
    """Read-only SnapTrade V1 aggregator relay adapter with HMAC-SHA256 signing and 5-slot cap."""

    broker_id = "snaptrade"
    display_name = "SnapTrade Aggregator Relay (POC)"
    approval_state = ProviderApprovalState.AGGREGATOR_RELAYED
    default_origin_assurance = OriginAssurance.OPERATOR_RETRIEVED
    supports_subaccount_enumeration = True
    allowed_capabilities = (
        "read_account_profile",
        "list_subaccounts",
        "read_balances",
        "fetch_positions",
        "fetch_executions",
        "fetch_cash_flows",
        "read_holdings",
    )

    def __init__(
        self,
        *,
        client_id: str | None = None,
        consumer_key: str | None = None,
        auth_mode: str | None = None,
        user_id: str | None = None,
        user_secret: str | None = None,
        base_url: str | None = None,
        slot_manager: SnapTradeSlotManager | None = None,
        http_transport: HttpTransportCallable | Any | None = None,
        require_live: bool = True,
        env: Mapping[str, str] | None = None,
        auto_register_slot: bool = True,
        timestamp_provider: Callable[[], int | str] | None = None,
        **extra_kwargs: Any,
    ) -> None:
        reject_unofficial_scraper_credentials(**extra_kwargs)
        super().__init__()

        env_map: Mapping[str, str] = os.environ if env is None else env

        if client_id is not None:
            resolved_client_id = client_id.strip()
        else:
            resolved_client_id = (
                env_map.get("SNAPTRADE_CLIENT_ID") or "snaptrade-poc-client"
            ).strip()

        if consumer_key is not None:
            resolved_consumer_key = consumer_key.strip()
        else:
            resolved_consumer_key = (
                env_map.get("SNAPTRADE_CONSUMER_KEY") or "snaptrade-poc-key"
            ).strip()

        resolved_auth_mode = (
            auth_mode if auth_mode is not None else env_map.get("SNAPTRADE_AUTH_MODE", "auto")
        )

        if not resolved_client_id:
            raise SnapTradeAuthenticationError("SnapTrade client_id must not be empty")
        if not resolved_consumer_key:
            raise SnapTradeAuthenticationError("SnapTrade consumer_key must not be empty")

        self.client_id = resolved_client_id
        self.consumer_key = resolved_consumer_key
        self.auth_mode = str(resolved_auth_mode or "auto").strip().lower() or "auto"
        self.is_personal_key = is_snaptrade_personal_key(
            self.client_id, auth_mode=self.auth_mode
        )
        self.user_id = (user_id or "").strip() or None
        self.user_secret = (user_secret or "").strip() or None
        self.require_live = require_live
        self._timestamp_provider = timestamp_provider

        expected_host = (
            urllib.parse.urlsplit(SNAPTRADE_LIVE_BASE_URL).hostname or "api.snaptrade.com"
        )
        self.base_url = validate_ssrf_safe_https_url(
            base_url or SNAPTRADE_LIVE_BASE_URL,
            allowed_hosts={expected_host},
            require_live=require_live,
            label="snaptrade",
        )
        self._transport = http_transport
        self.slot_manager = slot_manager or (
            SnapTradeSlotManager(MAX_SNAPTRADE_PERSONAL_SLOTS)
            if self.is_personal_key
            else _GLOBAL_POC_SLOT_MANAGER
        )

        if self.user_id and auto_register_slot:
            self.slot_manager.register_slot(self.user_id)

    def assert_action_permitted(self, action: str) -> None:
        """Enforce read-only policy: block trade execution, cancellation, and fund transfers."""
        clean_action = (action or "").strip().lower()
        if clean_action in _BLOCKED_MUTATING_ACTIONS or any(
            bad in clean_action for bad in ("order", "trade", "withdraw", "transfer", "cancel")
        ):
            raise DisallowedCapabilityError(
                f"Action {action!r} is strictly disallowed in SnapTrade read-only relay. "
                "Order placement, modification, cancellation, and fund transfers are prohibited."
            )

    def describe_adapter(self) -> BrokerAdapterDescriptor:
        return BrokerAdapterDescriptor(
            broker_id=self.broker_id,
            display_name=self.display_name,
            approval_state=self.approval_state,
            default_origin_assurance=self.default_origin_assurance,
            supports_subaccount_enumeration=self.supports_subaccount_enumeration,
            allowed_capabilities=self.allowed_capabilities,
        )

    def build_auth_headers(
        self,
        *,
        signature: str | None = None,
        has_json_body: bool = False,
    ) -> dict[str, str]:
        """Construct SnapTrade V1 HTTP headers (strictly omitting consumerKey and userSecret)."""
        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": DEFAULT_SNAPTRADE_USER_AGENT,
        }
        if has_json_body:
            headers["Content-Type"] = "application/json"
        if signature:
            headers["Signature"] = signature
        return headers

    def build_signed_request(
        self,
        method: str,
        api_path: str,
        *,
        user_id: str | None = None,
        user_secret: str | None = None,
        extra_query_params: Mapping[str, Any] | None = None,
        json_body: Any = None,
        timestamp: int | str | None = None,
    ) -> SignedSnapTradeRequest:
        """Build a signed SnapTrade V1 HTTP request bound to this adapter's credentials."""
        resolved_ts = (
            timestamp
            if timestamp is not None
            else (self._timestamp_provider() if self._timestamp_provider is not None else None)
        )
        return build_signed_request(
            method,
            api_path,
            client_id=self.client_id,
            consumer_key=self.consumer_key,
            base_url=self.base_url,
            user_id=user_id,
            user_secret=user_secret,
            extra_query_params=extra_query_params,
            json_body=json_body,
            timestamp=resolved_ts,
            auth_mode=self.auth_mode,
        )

    def _collect_secrets(self, *extra: str | None) -> list[str]:
        secrets_out: list[str] = [self.consumer_key]
        if len(self.client_id) >= 6:
            secrets_out.append(self.client_id)
        if self.user_secret:
            secrets_out.append(self.user_secret)
        for item in extra:
            if item and str(item).strip():
                secrets_out.append(str(item).strip())
        return secrets_out

    def _execute_signed(
        self,
        method: str,
        api_path: str,
        *,
        user_id: str | None = None,
        user_secret: str | None = None,
        extra_query_params: Mapping[str, Any] | None = None,
        json_body: Any = None,
    ) -> HttpExchangeResponse:
        signed_req = self.build_signed_request(
            method,
            api_path,
            user_id=user_id,
            user_secret=user_secret,
            extra_query_params=extra_query_params,
            json_body=json_body,
        )
        secrets_list = self._collect_secrets(user_secret, user_id)

        try:
            if callable(self._transport) and not hasattr(self._transport, "request"):
                raw_out = self._transport(
                    signed_req.method,
                    signed_req.url,
                    dict(signed_req.headers),
                    signed_req.body,
                )
                if isinstance(raw_out, HttpExchangeResponse):
                    return raw_out
                if hasattr(raw_out, "status_code"):
                    body_val = (
                        bytes(raw_out.body)
                        if hasattr(raw_out, "body")
                        else (
                            bytes(raw_out.content)
                            if hasattr(raw_out, "content")
                            else str(raw_out.text).encode("utf-8")
                        )
                    )
                    hdr_val = {
                        str(k).lower(): str(v)
                        for k, v in (getattr(raw_out, "headers", None) or {}).items()
                    }
                    return HttpExchangeResponse(
                        status_code=int(raw_out.status_code),
                        headers=hdr_val,
                        body=body_val,
                    )
                status, out_hdrs, out_payload = raw_out
                payload_bytes = (
                    out_payload
                    if isinstance(out_payload, bytes)
                    else (
                        out_payload.encode("utf-8")
                        if isinstance(out_payload, str)
                        else json.dumps(out_payload, separators=(",", ":")).encode("utf-8")
                    )
                )
                return HttpExchangeResponse(
                    status_code=int(status),
                    headers={str(k).lower(): str(v) for k, v in (out_hdrs or {}).items()},
                    body=payload_bytes,
                )

            return invoke_http_transport(
                self._transport,
                signed_req.method,
                signed_req.url,
                headers=signed_req.headers,
                body=signed_req.body,
                extra_secrets=secrets_list,
            )
        except Exception as exc:
            redacted = redact_sensitive_text(str(exc), extra_secrets=secrets_list)
            if isinstance(
                exc,
                (SnapTradeError, PaperOrSandboxAccountRejectedError, DisallowedCapabilityError),
            ):
                raise type(exc)(redacted) from None
            raise SnapTradeServiceError(
                f"SnapTrade {signed_req.method} {signed_req.api_path} transport error: {redacted}"
            ) from None

    def _decode_json_or_raise(
        self,
        resp: HttpExchangeResponse,
        *,
        api_path: str,
        allowed_statuses: Sequence[int] = (200,),
        extra_secrets: Sequence[str] = (),
    ) -> Any:
        secrets_list = self._collect_secrets(*extra_secrets)
        if resp.status_code not in allowed_statuses:
            snippet = resp.body[:256].decode("utf-8", errors="replace").strip()
            safe_detail = redact_sensitive_text(snippet, extra_secrets=secrets_list)
            msg = f"SnapTrade {api_path} failed with HTTP {resp.status_code}"
            if safe_detail:
                msg = f"{msg}: {safe_detail}"
            if resp.status_code in {401, 403}:
                raise SnapTradeAuthenticationError(msg)
            raise SnapTradeServiceError(msg)

        if not resp.body or not resp.body.strip():
            return {}
        try:
            return json.loads(resp.body.decode("utf-8"))
        except Exception as exc:
            raise SnapTradeServiceError(
                f"SnapTrade {api_path} returned malformed JSON response"
            ) from exc

    def register_user(self, user_id: str = "") -> dict[str, str]:
        """Allocate/reuse a slot and register a SnapTrade V1 user (skipped in PERS-* personal mode)."""
        if self.is_personal_key:
            clean_user = (user_id or self.user_id or "").strip() or "personal-owner"
            self.slot_manager.register_slot(clean_user)
            return {
                "userId": clean_user,
                "userSecret": "",
                "mode": "personal_1_slot",
            }

        if not isinstance(user_id, str) or not user_id.strip():
            raise SnapTradeAuthenticationError("user_id must be a non-empty string")
        clean_user = user_id.strip()

        was_active = self.slot_manager.is_user_registered(clean_user)
        self.slot_manager.register_slot(clean_user)

        try:
            resp = self._execute_signed(
                "POST",
                "/api/v1/snapTrade/registerUser",
                json_body={"userId": clean_user},
            )
            data = self._decode_json_or_raise(
                resp,
                api_path="/api/v1/snapTrade/registerUser",
                allowed_statuses=(200, 201),
                extra_secrets=(clean_user,),
            )
            if not isinstance(data, Mapping):
                raise SnapTradeServiceError(
                    "SnapTrade registerUser returned unexpected non-object JSON"
                )
            resolved_uid = str(data.get("userId") or clean_user).strip()
            resolved_secret = str(data.get("userSecret") or "").strip()
            if not resolved_secret:
                raise SnapTradeServiceError("SnapTrade registerUser response missing userSecret")
            return {
                "userId": resolved_uid,
                "userSecret": resolved_secret,
            }
        except Exception:
            if not was_active:
                self.slot_manager.release_slot(clean_user)
            raise

    def generate_connection_portal_url(
        self,
        user_id: str = "",
        user_secret: str = "",
        *,
        broker: str | None = None,
        custom_redirect: str | None = None,
        reconnect: str | None = None,
        connection_type: str = "read",
    ) -> dict[str, Any]:
        """Generate a read-only SnapTrade Connection Portal URL (``connectionType='read'``)."""
        norm_conn_type = (connection_type or "").strip().lower()
        if norm_conn_type != "read":
            raise DisallowedCapabilityError(
                f"SnapTrade Connection Portal strictly enforces connectionType='read' (got {connection_type!r}); "
                "mutating/trading connection scopes are prohibited."
            )

        if self.is_personal_key:
            clean_user = (user_id or self.user_id or "").strip() or "personal-owner"
            clean_secret = ""
        else:
            clean_user = (user_id or "").strip()
            clean_secret = (user_secret or "").strip()
            if not clean_user:
                raise SnapTradeAuthenticationError("user_id is required for Connection Portal login")
            if not clean_secret:
                raise SnapTradeAuthenticationError("user_secret is required for Connection Portal login")

        self.slot_manager.register_slot(clean_user)

        login_body: dict[str, Any] = {
            "connectionType": "read",
            "immediateRedirect": True,
        }
        if broker is not None and str(broker).strip():
            login_body["broker"] = str(broker).strip()
        if custom_redirect is not None and str(custom_redirect).strip():
            login_body["customRedirect"] = str(custom_redirect).strip()
        if reconnect is not None and str(reconnect).strip():
            login_body["reconnect"] = str(reconnect).strip()

        resp = self._execute_signed(
            "POST",
            "/api/v1/snapTrade/login",
            user_id=None if self.is_personal_key else clean_user,
            user_secret=None if self.is_personal_key else clean_secret,
            json_body=login_body,
        )
        data = self._decode_json_or_raise(
            resp,
            api_path="/api/v1/snapTrade/login",
            allowed_statuses=(200, 201),
            extra_secrets=(clean_secret, clean_user),
        )
        if not isinstance(data, Mapping):
            raise SnapTradeServiceError("SnapTrade login returned unexpected non-object JSON")

        redirect_uri = str(
            data.get("redirectURI") or data.get("redirectUri") or data.get("loginLink") or ""
        ).strip()
        if not redirect_uri or not redirect_uri.lower().startswith("https://"):
            raise SnapTradeServiceError(
                "SnapTrade login response did not contain a valid https:// redirectURI"
            )
        session_id = str(data.get("sessionId") or "").strip()
        return {
            "redirectURI": redirect_uri,
            "sessionId": session_id,
            "connectionType": "read",
        }

    def delete_user_and_release_slot(self, user_id: str = "") -> dict[str, Any]:
        """Delete a SnapTrade user upstream (skipped in PERS-* mode) and release its local slot."""
        if self.is_personal_key:
            clean_user = (user_id or self.user_id or "").strip() or "personal-owner"
            slot_released = self.slot_manager.release_slot(clean_user)
            return {
                "userId": clean_user,
                "status": "personal_key_retained_upstream",
                "slot_released": slot_released,
            }

        clean_user = (user_id or "").strip()
        if not clean_user:
            raise SnapTradeAuthenticationError("user_id is required to delete SnapTrade user")

        resp = self._execute_signed(
            "DELETE",
            "/api/v1/snapTrade/deleteUser",
            user_id=clean_user,
        )
        data = self._decode_json_or_raise(
            resp,
            api_path="/api/v1/snapTrade/deleteUser",
            allowed_statuses=(200, 202, 204, 404),
            extra_secrets=(clean_user,),
        )
        slot_released = self.slot_manager.release_slot(clean_user)
        status_str = (
            str(data.get("status") or "deleted")
            if isinstance(data, Mapping)
            else "deleted"
        )
        return {
            "userId": clean_user,
            "status": status_str,
            "slot_released": slot_released,
        }

    def list_authorizations(
        self,
        user_id: str = "",
        user_secret: str = "",
    ) -> list[dict[str, Any]]:
        """List read-only SnapTrade brokerage authorizations via ``GET /api/v1/authorizations``."""
        if self.is_personal_key:
            clean_user = (user_id or self.user_id or "").strip() or "personal-owner"
            clean_secret = ""
        else:
            clean_user = (user_id or self.user_id or "").strip()
            clean_secret = (user_secret or self.user_secret or "").strip()
            if not clean_user:
                raise SnapTradeAuthenticationError("user_id is required to list SnapTrade authorizations")
            if not clean_secret:
                raise SnapTradeAuthenticationError("user_secret is required to list SnapTrade authorizations")

        resp = self._execute_signed(
            "GET",
            "/api/v1/authorizations",
            user_id=None if self.is_personal_key else clean_user,
            user_secret=None if self.is_personal_key else clean_secret,
        )
        raw = self._decode_json_or_raise(
            resp,
            api_path="/api/v1/authorizations",
            extra_secrets=(clean_secret, clean_user),
        )
        items = raw if isinstance(raw, list) else ([raw] if isinstance(raw, Mapping) else [])
        return [dict(item) for item in items if isinstance(item, Mapping)]

    def parse_payload(
        self,
        payload: dict[str, Any] | str | bytes,
        *,
        blinding_salt_hex: str,
        selected_account_ids: Sequence[str] | None = None,
        require_live: bool = True,
        start_date: str | None = None,
        end_date: str | None = None,
        as_of_utc: str | None = None,
    ) -> CanonicalPortfolioLedger:
        """Normalize raw SnapTrade V1 JSON responses into ``CanonicalPortfolioLedger``."""
        if isinstance(payload, (bytes, str)):
            data = json.loads(payload)
        else:
            data = dict(payload)

        source_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
        source_sha256 = hashlib.sha256(source_bytes).hexdigest()

        raw_accounts_list: list[Mapping[str, Any]] = []
        raw_accounts = data.get("accounts", [])
        if isinstance(raw_accounts, Mapping):
            raw_accounts_list.append(raw_accounts)
        elif isinstance(raw_accounts, list):
            raw_accounts_list.extend(a for a in raw_accounts if isinstance(a, Mapping))

        holdings_raw = data.get("holdings") or []
        if isinstance(holdings_raw, Mapping):
            holdings_list: list[Mapping[str, Any]] = [holdings_raw]
        elif isinstance(holdings_raw, list):
            holdings_list = [h for h in holdings_raw if isinstance(h, Mapping)]
        else:
            holdings_list = []

        flattened_positions: list[dict[str, Any]] = []
        flattened_balances: list[dict[str, Any]] = []

        for h_entry in holdings_list:
            h_acct = h_entry.get("account")
            if isinstance(h_acct, Mapping):
                h_aid = _extract_account_id(h_acct)
                if h_aid and not any(_extract_account_id(a) == h_aid for a in raw_accounts_list):
                    raw_accounts_list.append(h_acct)

        selected_set = (
            {str(x).strip() for x in selected_account_ids if str(x).strip()}
            if selected_account_ids
            else None
        )

        def _in_scope(account_id: str) -> bool:
            return not selected_set or account_id in selected_set

        raw_acct_ids: list[str] = []
        raw_identifiers_to_scrub: list[str] = []
        is_paper_detected = False
        inferred_acct_ccy = ""

        for acct in raw_accounts_list:
            aid = _extract_account_id(acct)
            if aid and aid not in raw_acct_ids:
                raw_acct_ids.append(aid)
            for ident_key in ("id", "number", "account_number"):
                ident_val = acct.get(ident_key)
                if ident_val is not None and len(str(ident_val).strip()) >= 4:
                    clean_ident = str(ident_val).strip()
                    if clean_ident not in raw_identifiers_to_scrub:
                        raw_identifiers_to_scrub.append(clean_ident)
            meta = acct.get("meta") if isinstance(acct.get("meta"), Mapping) else {}
            raw_type = " ".join(
                str(x or "")
                for x in (
                    acct.get("type"),
                    meta.get("type"),
                    acct.get("name"),
                    acct.get("institution_name"),
                )
            ).lower()
            if (
                "paper" in raw_type
                or "demo" in raw_type
                or "simulated" in raw_type
                or "sandbox" in raw_type
                or bool(acct.get("is_paper"))
            ):
                is_paper_detected = True

            acct_bal = acct.get("balance")
            bal_total_ccy = (
                acct_bal.get("total", {}).get("currency")
                if isinstance(acct_bal, Mapping) and isinstance(acct_bal.get("total"), Mapping)
                else None
            )
            ccy = _extract_currency_code(
                acct.get("currency") or meta.get("currency") or bal_total_ccy,
                default="",
            )
            # The base currency comes only from accounts in scope.
            if ccy and len(ccy) == 3 and not inferred_acct_ccy and _in_scope(aid):
                inferred_acct_ccy = ccy

        explicit_base = _extract_currency_code(data.get("base_currency"), default="")
        inferred_holdings_ccy = ""
        for h_entry in holdings_list:
            h_scope_acct = h_entry.get("account")
            if not _in_scope(
                _extract_account_id(h_scope_acct)
                if isinstance(h_scope_acct, Mapping)
                else _extract_account_id(h_entry)
            ):
                continue
            h_tot = h_entry.get("total_value")
            if isinstance(h_tot, Mapping):
                cand = _extract_currency_code(h_tot.get("currency"), default="")
                if cand and len(cand) == 3:
                    inferred_holdings_ccy = cand
                    break
            h_bals = h_entry.get("balances")
            if isinstance(h_bals, list):
                for b_item in h_bals:
                    if isinstance(b_item, Mapping):
                        cand = _extract_currency_code(b_item.get("currency"), default="")
                        if cand and len(cand) == 3:
                            inferred_holdings_ccy = cand
                            break
                if inferred_holdings_ccy:
                    break

        inferred_bal_ccy = ""
        raw_bals_top = data.get("balances")
        if isinstance(raw_bals_top, Mapping):
            inferred_bal_ccy = _extract_currency_code(raw_bals_top.get("currency"), default="")
        elif isinstance(raw_bals_top, list):
            for b_item in raw_bals_top:
                if isinstance(b_item, Mapping) and _in_scope(str(b_item.get("account_id") or "").strip()):
                    cand = _extract_currency_code(b_item.get("currency"), default="")
                    if cand and len(cand) == 3:
                        inferred_bal_ccy = cand
                        break

        base_currency = (
            explicit_base
            or inferred_acct_ccy
            or inferred_holdings_ccy
            or inferred_bal_ccy
            or "USD"
        )
        pair_rates, conversion_rates_out = _parse_currency_rate_pairs(
            data.get("currency_rates"),
            data.get("conversion_rates"),
            base_currency,
        )

        # A selection must name accounts that were actually read for this connection, and it
        # applies before any value is converted, so a deselected account never affects the record.
        if selected_set and not selected_set <= set(raw_acct_ids):
            raise SnapTradeSelectionError(
                "The selected account(s) are not among the accounts read for this connection; "
                "a record can only claim accounts the connection actually returned."
            )
        selection_is_subset = bool(selected_set) and selected_set != set(raw_acct_ids)

        for h_entry in holdings_list:
            h_acct = h_entry.get("account")
            h_aid = (
                _extract_account_id(h_acct)
                if isinstance(h_acct, Mapping)
                else _extract_account_id(h_entry)
            )
            if selected_set and h_aid not in selected_set:
                continue

            h_positions = h_entry.get("positions") or []
            if isinstance(h_positions, list):
                for p in h_positions:
                    if isinstance(p, Mapping):
                        p_copy = dict(p)
                        if h_aid and not p_copy.get("account_id"):
                            p_copy["account_id"] = h_aid
                        flattened_positions.append(p_copy)

            h_total_obj = h_entry.get("total_value")
            h_balances = h_entry.get("balances") or []
            cash_sum = 0.0
            has_cash = False
            if isinstance(h_balances, list):
                for b_item in h_balances:
                    if isinstance(b_item, Mapping) and b_item.get("cash") is not None:
                        b_ccy = _extract_currency_code(b_item.get("currency"), base_currency)
                        b_fx = _require_fx_rate(b_ccy, base_currency, pair_rates)
                        cash_sum += float(b_item["cash"]) * b_fx
                        has_cash = True

            total_val: float | None = None
            if isinstance(h_total_obj, Mapping) and h_total_obj.get("value") is not None:
                tot_ccy = _extract_currency_code(h_total_obj.get("currency"), base_currency)
                tot_fx = _require_fx_rate(tot_ccy, base_currency, pair_rates)
                total_val = float(h_total_obj["value"]) * tot_fx
            elif isinstance(h_acct, Mapping):
                acct_bal = h_acct.get("balance")
                if isinstance(acct_bal, Mapping) and isinstance(acct_bal.get("total"), Mapping):
                    tot_inner = acct_bal["total"]
                    if tot_inner.get("amount") is not None:
                        tot_ccy = _extract_currency_code(tot_inner.get("currency"), base_currency)
                        tot_fx = _require_fx_rate(tot_ccy, base_currency, pair_rates)
                        total_val = float(tot_inner["amount"]) * tot_fx

            if total_val is not None or has_cash:
                pos_mkt_sum = 0.0
                if total_val is None:
                    for p in h_positions if isinstance(h_positions, list) else []:
                        if isinstance(p, Mapping):
                            u = _extract_units(p)
                            pr = float(p.get("price") or p.get("current_price") or 0.0)
                            _, p_ccy, _, p_mult = _position_asset_info(p, base_currency)
                            p_fx = _require_fx_rate(p_ccy, base_currency, pair_rates)
                            pos_mkt_sum += u * pr * p_mult * p_fx
                resolved_tot = total_val if total_val is not None else (cash_sum + pos_mkt_sum)
                sync_ts = None
                if isinstance(h_acct, Mapping) and isinstance(h_acct.get("sync_status"), Mapping):
                    holdings_sync = h_acct["sync_status"].get("holdings")
                    if isinstance(holdings_sync, Mapping):
                        sync_ts = holdings_sync.get("last_successful_sync")
                flattened_balances.append(
                    {
                        "account_id": h_aid,
                        "total": resolved_tot,
                        "cash": cash_sum if has_cash else None,
                        "currency": base_currency,
                        "updated_at": h_entry.get("updated_at") or sync_ts,
                    }
                )

        if not flattened_balances:
            for acct in raw_accounts_list:
                aid = _extract_account_id(acct)
                if selected_set and aid not in selected_set:
                    continue
                acct_bal = acct.get("balance")
                if isinstance(acct_bal, Mapping):
                    tot_map = acct_bal.get("total")
                    if isinstance(tot_map, Mapping) and tot_map.get("amount") is not None:
                        tot_ccy = _extract_currency_code(tot_map.get("currency"), base_currency)
                        tot_fx = _require_fx_rate(tot_ccy, base_currency, pair_rates)
                        flattened_balances.append(
                            {
                                "account_id": aid,
                                "total": float(tot_map["amount"]) * tot_fx,
                                "cash": None,
                                "currency": base_currency,
                                "updated_at": acct.get("updated_at") or acct.get("created_date"),
                            }
                        )

        if is_paper_detected:
            if require_live:
                raise PaperOrSandboxAccountRejectedError(
                    "SnapTrade paper or simulated account rejected for live verification"
                )
            env_tier = EnvironmentTier.PAPER_OR_SANDBOX_REJECTED
        else:
            env_tier = EnvironmentTier.LIVE_PRODUCTION

        if selected_set:
            account_scope = AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED
            filtered_accounts = [
                a for a in raw_accounts_list if _extract_account_id(a) in selected_set
            ]
        else:
            account_scope = AccountScope.ALL_ENUMERATED_SUBACCOUNTS
            filtered_accounts = raw_accounts_list

        raw_tag_seed = (
            ",".join(sorted(selected_set))
            if selected_set
            else (
                ",".join(sorted(raw_acct_ids))
                if raw_acct_ids
                else f"snaptrade:{source_sha256[:16]}"
            )
        )
        blinded_tag = compute_blinded_account_tag("snaptrade", raw_tag_seed, blinding_salt_hex)

        trades: list[NormalizedTrade] = []
        flows: list[NormalizedFlow] = []
        corporate_actions: list[CorporateActionRecord] = []
        ending_positions: list[NormalizedPosition] = []

        activities = data.get("activities") or data.get("trades") or []
        if isinstance(activities, Mapping) and isinstance(activities.get("data"), list):
            activities = activities["data"]

        for act in activities if isinstance(activities, list) else []:
            if not isinstance(act, Mapping):
                continue
            aid = _extract_account_id(act) if ("account" in act or "account_id" in act or "accountId" in act) else ""
            if selected_set and aid not in selected_set:
                continue
            act_type = str(act.get("type") or "").strip().lower()
            ts = _parse_iso_ts(
                act.get("trade_date")
                or act.get("settlement_date")
                or act.get("date")
                or act.get("created_at")
            )

            opt_obj = act.get("option_symbol")
            is_opt = isinstance(opt_obj, Mapping) and bool(opt_obj)
            sym_source = act.get("symbol") if act.get("symbol") is not None else act.get("instrument")
            sym_str, sym_ccy, sym_type = _extract_symbol_and_currency(sym_source, base_currency)
            if is_opt and isinstance(opt_obj, Mapping):
                opt_ticker = str(opt_obj.get("ticker") or sym_str or "").strip().upper()
                if opt_ticker:
                    sym_str = opt_ticker
            if ts is None and (
                act_type in _TRADE_ACTIVITY_TYPES
                or act_type in _FLOW_ACTIVITY_TYPES
                or (act_type in _CORPORATE_ACTION_TYPES and sym_str)
            ):
                # A trade, flow or corporate action is never placed at a guessed date.
                raise SnapTradeUnreadableDateError(
                    f"A {act_type} activity has no readable date; the record is refused rather "
                    "than placing it at a guessed time."
                )

            qty = abs(_extract_units(act))
            price = abs(float(act.get("price") or 0.0))
            fee = abs(float(act.get("fee") or act.get("commission") or 0.0))
            currency = _extract_currency_code(act.get("currency"), sym_ccy or base_currency)

            if act_type in _TRADE_ACTIVITY_TYPES:
                act_fx = _require_fx_rate(currency, base_currency, pair_rates)
                asset_cls = _infer_asset_class(sym_str, sym_type, is_option=is_opt)
                opt_right: str | None = None
                opt_strike: float | None = None
                opt_expiry: str | None = None
                opt_und: str | None = None
                if is_opt and isinstance(opt_obj, Mapping):
                    raw_ot = str(opt_obj.get("option_type") or "").strip().upper()
                    if raw_ot in {"CALL", "C"}:
                        opt_right = "C"
                    elif raw_ot in {"PUT", "P"}:
                        opt_right = "P"
                    if opt_obj.get("strike_price") is not None:
                        opt_strike = float(opt_obj["strike_price"])
                    if opt_obj.get("expiration_date"):
                        opt_expiry = str(opt_obj["expiration_date"])[:10]
                    und_sym, _, _ = _extract_symbol_and_currency(
                        opt_obj.get("underlying_symbol"), currency
                    )
                    opt_und = und_sym or None

                safe_entry_id = _scrub_account_identifiers(
                    str(act.get("id") or f"st-{len(trades) + 1}"),
                    raw_identifiers_to_scrub,
                )
                trades.append(
                    NormalizedTrade(
                        venue="SNAPTRADE_RELAY",
                        native_entry_id=safe_entry_id,
                        symbol=sym_str or "UNKNOWN",
                        asset_class=asset_cls,
                        side="sell" if act_type == "sell" else "buy",
                        quantity=qty,
                        price=price,
                        timestamp_utc=ts,
                        currency=currency,
                        fx_rate_to_base=act_fx,
                        commission=fee,
                        multiplier=100.0 if asset_cls == AssetClass.OPTION else 1.0,
                        option_right=opt_right,
                        strike=opt_strike,
                        expiry=opt_expiry,
                        underlying_symbol=opt_und,
                    )
                )
                if act_type == "rei":
                    amt = abs(float(act.get("amount") or (price * qty) or 0.0))
                    if amt > 0.0:
                        flows.append(
                            NormalizedFlow(
                                timestamp_utc=ts,
                                kind=FlowKind.DIVIDEND,
                                amount=amt,
                                currency=currency,
                                fx_rate_to_base=act_fx,
                                description="SnapTrade dividend reinvestment",
                            )
                        )
            elif act_type in _FLOW_ACTIVITY_TYPES:
                act_fx = _require_fx_rate(currency, base_currency, pair_rates)
                raw_amt = float(act.get("amount") if act.get("amount") is not None else (price * qty))
                if act_type in {"deposit", "contribution", "funds_contribution"}:
                    flow_kind = FlowKind.DEPOSIT
                    amt = abs(raw_amt)
                elif act_type in {"withdrawal", "funds_withdrawal"}:
                    flow_kind = FlowKind.WITHDRAWAL
                    amt = -abs(raw_amt)
                elif act_type == "dividend":
                    flow_kind = FlowKind.DIVIDEND
                    amt = raw_amt
                elif act_type == "interest":
                    flow_kind = FlowKind.INTEREST if raw_amt >= 0.0 else FlowKind.MARGIN_INTEREST
                    amt = raw_amt
                elif act_type == "fee":
                    flow_kind = FlowKind.COMMISSION_FEE
                    amt = -abs(raw_amt)
                elif act_type == "tax":
                    flow_kind = FlowKind.WITHHOLDING_TAX
                    amt = -abs(raw_amt)
                else:
                    if sym_str and qty > 0.0 and abs(raw_amt) > 0.0:
                        flow_kind = (
                            FlowKind.TRANSFER_IN_KIND if raw_amt >= 0.0 else FlowKind.TRANSFER_OUT_KIND
                        )
                        amt = raw_amt
                    else:
                        flow_kind = FlowKind.DEPOSIT if raw_amt >= 0.0 else FlowKind.WITHDRAWAL
                        amt = raw_amt

                flows.append(
                    NormalizedFlow(
                        timestamp_utc=ts,
                        kind=flow_kind,
                        amount=amt,
                        currency=currency,
                        fx_rate_to_base=act_fx,
                        symbol=sym_str or None if flow_kind in {FlowKind.TRANSFER_IN_KIND, FlowKind.TRANSFER_OUT_KIND} else None,
                        quantity=qty if flow_kind in {FlowKind.TRANSFER_IN_KIND, FlowKind.TRANSFER_OUT_KIND} else None,
                        description=_scrub_account_identifiers(
                            str(act.get("description") or f"SnapTrade {act_type}"),
                            raw_identifiers_to_scrub,
                        ),
                    )
                )
            elif act_type in _CORPORATE_ACTION_TYPES and sym_str:
                ca_map = {
                    "optionexpiration": CorporateActionType.OPTION_EXPIRATION,
                    "optionassignment": CorporateActionType.OPTION_ASSIGNMENT,
                    "optionexercise": CorporateActionType.OPTION_EXERCISE,
                    "split": CorporateActionType.SPLIT,
                }
                corporate_actions.append(
                    CorporateActionRecord(
                        action_type=ca_map[act_type],
                        timestamp_utc=ts,
                        symbol=sym_str,
                        quantity_delta=_extract_units(act),
                        description=_scrub_account_identifiers(
                            str(act.get("description") or f"SnapTrade {act_type}"),
                            raw_identifiers_to_scrub,
                        ),
                    )
                )

        positions_source = list(flattened_positions)
        raw_top_positions = data.get("positions") or []
        if isinstance(raw_top_positions, list):
            for p in raw_top_positions:
                if isinstance(p, Mapping):
                    positions_source.append(dict(p))

        for p in positions_source:
            aid = str(p.get("account_id") or "").strip()
            if selected_set and aid not in selected_set:
                continue
            sym_str, pos_ccy, asset_cls, mult = _position_asset_info(p, base_currency)
            pos_fx = _require_fx_rate(pos_ccy, base_currency, pair_rates)
            units = _extract_units(p)
            price = float(p.get("price") or p.get("current_price") or 0.0)
            avg_cost = p.get("average_purchase_price")
            if p.get("cost_basis") is not None:
                cost_basis = float(p["cost_basis"])
            elif avg_cost is not None:
                cost_basis = units * float(avg_cost) * mult
            else:
                cost_basis = units * price * mult

            ending_positions.append(
                NormalizedPosition(
                    prior_period_or_ending="ending",
                    symbol=sym_str or "UNKNOWN",
                    asset_class=asset_cls,
                    quantity=units,
                    cost_basis=cost_basis,
                    market_value=units * price * mult,
                    currency=pos_ccy,
                    fx_rate_to_base=pos_fx,
                    multiplier=mult,
                )
            )

        nav_by_ts: dict[str, tuple[float, float | None]] = {}
        parser_warnings: list[str] = []

        explicit_nav_points = data.get("nav_points") or []
        if not isinstance(explicit_nav_points, list):
            explicit_nav_points = []
        explicit_items = [np_item for np_item in explicit_nav_points if isinstance(np_item, Mapping)]

        # A valuation series is used only when it can be attributed to exactly the accounts the
        # record claims, and only when its currency is known.
        if explicit_items and selection_is_subset:
            raw_attr = data.get("nav_points_account_ids")
            attributed = (
                {str(x).strip() for x in raw_attr if str(x).strip()}
                if isinstance(raw_attr, (list, tuple))
                else set()
            )
            if attributed != selected_set:
                parser_warnings.append(
                    "The valuation series was not used because it cannot be attributed to the "
                    "selected accounts; returns are withheld."
                )
                explicit_items = []
        if explicit_items:
            scope_ccys: set[str] = set()
            for acct in filtered_accounts:
                meta = acct.get("meta") if isinstance(acct.get("meta"), Mapping) else {}
                acct_bal = acct.get("balance")
                bal_ccy = (
                    acct_bal.get("total", {}).get("currency")
                    if isinstance(acct_bal, Mapping) and isinstance(acct_bal.get("total"), Mapping)
                    else None
                )
                ccy = _extract_currency_code(
                    acct.get("currency") or meta.get("currency") or bal_ccy, default=""
                )
                if ccy:
                    scope_ccys.add(ccy)
            if len(scope_ccys) > 1 and any(
                np_item.get("nav_base") is None and not np_item.get("currency")
                for np_item in explicit_items
            ):
                parser_warnings.append(
                    "The valuation series was not used because the accounts span more than one "
                    "currency and the series does not state its currency; returns are withheld."
                )
                explicit_items = []

        # The valuation series is one total for the accounts in scope, one value per date: it is
        # never summed. (Per-account rows are summed only in the balances snapshot below.)
        series_rows: list[tuple[str, tuple[float, float | None]]] = []
        if explicit_items:
            for np_item in explicit_items:
                n_ts = _parse_iso_ts(
                    np_item.get("timestamp_utc") or np_item.get("date"),
                    end_of_day=("timestamp_utc" not in np_item),
                )
                if n_ts is None:
                    parser_warnings.append(
                        "The valuation series was not used because a point has no readable date; "
                        "returns are withheld."
                    )
                    series_rows = []
                    break
                if np_item.get("nav_base") is not None:
                    n_val = float(np_item["nav_base"])
                else:
                    np_ccy = _extract_currency_code(np_item.get("currency"), base_currency)
                    np_fx = _require_fx_rate(np_ccy, base_currency, pair_rates)
                    n_val = (
                        float(
                            np_item.get("total")
                            if np_item.get("total") is not None
                            else (np_item.get("value") or 0.0)
                        )
                        * np_fx
                    )
                n_cash = float(np_item["cash_base"]) if np_item.get("cash_base") is not None else None
                series_rows.append((n_ts, (n_val, n_cash)))
        series_dates = [ts_key[:10] for ts_key, _ in series_rows]
        if len(set(series_dates)) != len(series_dates):
            parser_warnings.append(
                "The valuation series was not used because it repeats a date, so it has more "
                "than one total for one day; returns are withheld."
            )
            series_rows = []
        nav_by_ts.update(series_rows)

        has_explicit_curve = len(_trim_valuation_series(list(nav_by_ts.items()))) >= 2

        balances_raw = data.get("balances")
        balances_source: list[Mapping[str, Any]] = []
        if isinstance(balances_raw, Mapping):
            balances_source.append(balances_raw)
        elif isinstance(balances_raw, list):
            balances_source.extend(b for b in balances_raw if isinstance(b, Mapping))
        else:
            balances_source.extend(flattened_balances)

        if not has_explicit_curve:
            # One balances fetch is one snapshot: all accounts are summed into a single NAV
            # point at one time (the latest account timestamp), never one point per account.
            # A record built from one snapshot has one point and its return is withheld.
            snap_total = 0.0
            snap_cash: float | None = None
            snap_ts_values: list[str] = []
            has_snapshot_row = False
            for b in balances_source:
                aid = str(b.get("account_id") or "").strip()
                if selected_set and aid not in selected_set:
                    continue
                tot_field = b.get("total")
                b_ccy = _extract_currency_code(b.get("currency"), base_currency)
                if isinstance(tot_field, Mapping):
                    b_ccy = _extract_currency_code(tot_field.get("currency"), b_ccy)
                    b_fx = _require_fx_rate(b_ccy, base_currency, pair_rates)
                    tot = float(tot_field.get("amount") or tot_field.get("value") or 0.0) * b_fx
                else:
                    b_fx = _require_fx_rate(b_ccy, base_currency, pair_rates)
                    tot = (
                        float(
                            tot_field
                            if tot_field is not None
                            else (b.get("current_balance") or b.get("equity") or b.get("cash") or 0.0)
                        )
                        * b_fx
                    )
                if b.get("cash") is not None:
                    cash_ccy = _extract_currency_code(b.get("currency"), base_currency)
                    cash_fx = _require_fx_rate(cash_ccy, base_currency, pair_rates)
                    snap_cash = (snap_cash or 0.0) + float(b["cash"]) * cash_fx
                snap_total += tot
                raw_b_ts = b.get("updated_at") or b.get("date")
                if raw_b_ts is not None and str(raw_b_ts).strip():
                    parsed_b_ts = _parse_iso_ts(raw_b_ts)
                    if parsed_b_ts is None:
                        raise SnapTradeUnreadableDateError(
                            "A balance row has no readable date; the record is refused rather "
                            "than placing the valuation at a guessed time."
                        )
                    snap_ts_values.append(parsed_b_ts)
                has_snapshot_row = True
            if has_snapshot_row:
                # The fetch time is used, once, only when no account carries a timestamp.
                resolved_as_of = _parse_iso_ts(as_of_utc) if as_of_utc else None
                b_ts = max(snap_ts_values) if snap_ts_values else (resolved_as_of or _fetch_time_ts())
                # Explicit points that do not form a curve are never combined with the
                # snapshot: values from two sources never make one return series.
                nav_by_ts = {b_ts: (snap_total, snap_cash)}

        nav_points = [
            NormalizedNavPoint(timestamp_utc=ts_key, nav_base=vals[0], cash_base=vals[1])
            for ts_key, vals in _trim_valuation_series(list(nav_by_ts.items()))
        ]

        # A capital flow in another currency is valued at an undated rate, not at a rate for
        # its own date, so a return over a series that contains it is not computable.
        if len(nav_points) >= 2:
            first_nav_ts = nav_points[0].timestamp_utc
            last_nav_ts = nav_points[-1].timestamp_utc
            if any(
                f.kind in _CAPITAL_FLOW_KINDS
                and f.currency != base_currency
                and first_nav_ts < f.timestamp_utc <= last_nav_ts
                for f in flows
            ):
                parser_warnings.append(
                    "A deposit, withdrawal or transfer in a currency other than the base currency "
                    "has no conversion rate for its own date; returns are withheld."
                )
                nav_points = [nav_points[-1]]

        all_ts = (
            [t.timestamp_utc for t in trades]
            + [f.timestamp_utc for f in flows]
            + [c.timestamp_utc for c in corporate_actions]
            + [n.timestamp_utc for n in nav_points]
        )
        norm_start = _normalize_date_param(start_date, field_name="start_date")
        norm_end = _normalize_date_param(end_date, field_name="end_date")
        fallback_as_of = _parse_iso_ts(as_of_utc) if as_of_utc else None
        default_start = (
            min(all_ts)
            if all_ts
            else (
                f"{fallback_as_of[:10]}T00:00:00Z"
                if fallback_as_of
                else datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z")
            )
        )
        default_end = (
            max(all_ts)
            if all_ts
            else (
                fallback_as_of
                if fallback_as_of
                else datetime.now(timezone.utc).strftime("%Y-%m-%dT23:59:59Z")
            )
        )
        period_start = f"{norm_start}T00:00:00Z" if norm_start else default_start
        period_end = f"{norm_end}T23:59:59Z" if norm_end else default_end
        if period_end < period_start:
            period_end = period_start

        # The record states one period: the span of its valuations when it has any (a single
        # snapshot is a single instant), otherwise the stated period. Activity dated outside that
        # period is not in the ledger, so no trade, cost or behaviour figure describes a time
        # the record does not state.
        if nav_points:
            period_start = nav_points[0].timestamp_utc
            period_end = nav_points[-1].timestamp_utc

        def _in_period(ts: str) -> bool:
            return period_start <= ts <= period_end

        def _instrument(t: NormalizedTrade) -> tuple[Any, ...]:
            return (t.symbol.strip().upper(), t.asset_class, t.option_right, t.strike, t.expiry)

        # A position opened before the period cannot be matched inside it: its later trades
        # would be read as new positions and make round trips that never happened, so every
        # trade in such an instrument is left out.
        held_into = {_instrument(t) for t in trades if t.timestamp_utc < period_start}
        in_period_trades = [t for t in trades if _in_period(t.timestamp_utc)]
        kept_trades = [t for t in in_period_trades if _instrument(t) not in held_into]
        if len(kept_trades) != len(in_period_trades):
            dropped_instruments = {_instrument(t) for t in in_period_trades} & held_into
            parser_warnings.append(
                f"Trades in {len(dropped_instruments)} instrument(s) held into the "
                f"{'valuation series' if nav_points else 'stated period'} from earlier are not in "
                "the ledger, so no round trip is matched against an opening trade outside the "
                "record's period."
            )
        trades = kept_trades
        flows = [f for f in flows if _in_period(f.timestamp_utc)]
        corporate_actions = [c for c in corporate_actions if _in_period(c.timestamp_utc)]

        prior_positions: list[NormalizedPosition] = []
        raw_prior_positions = data.get("prior_positions")
        if isinstance(raw_prior_positions, list):
            for pp in raw_prior_positions:
                if not isinstance(pp, Mapping):
                    continue
                aid = str(pp.get("account_id") or "").strip()
                if selected_set and aid and aid not in selected_set:
                    continue
                sym_str, pos_ccy, asset_cls, mult = _position_asset_info(pp, base_currency)
                pos_fx = _require_fx_rate(pos_ccy, base_currency, pair_rates)
                units = _extract_units(pp)
                price = float(pp.get("price") or pp.get("current_price") or 0.0)
                avg_cost = pp.get("average_purchase_price")
                if pp.get("cost_basis") is not None:
                    cost_basis = float(pp["cost_basis"])
                elif avg_cost is not None:
                    cost_basis = units * float(avg_cost) * mult
                else:
                    cost_basis = units * price * mult
                prior_positions.append(
                    NormalizedPosition(
                        prior_period_or_ending="prior",
                        symbol=sym_str or "UNKNOWN",
                        asset_class=asset_cls,
                        quantity=units,
                        cost_basis=cost_basis,
                        market_value=units * price * mult,
                        currency=pos_ccy,
                        fx_rate_to_base=pos_fx,
                        multiplier=mult,
                    )
                )

        enabled_secs = [
            "snaptrade_accounts",
            "snaptrade_holdings",
            "snaptrade_positions",
            "snaptrade_activities",
        ]
        # SnapTrade's live holdings/activities endpoints do not return pre-window opening
        # positions unless prior_positions is explicitly supplied; avoid claiming completeness
        # over pre-window positions when prior_positions is empty so pre-existing holdings
        # classify as INSUFFICIENT_SECTIONS instead of a false UNEXPLAINED_RESIDUAL.
        if prior_positions:
            enabled_secs.extend(
                [
                    "PriorPeriodPositions",
                    "Transfers",
                    "CorporateActions",
                    "OptionEAE",
                ]
            )

        return CanonicalPortfolioLedger(
            blinded_account_tag=blinded_tag,
            broker_id=self.broker_id,
            account_scope=account_scope,
            claimed_origin_assurance=self.default_origin_assurance,
            provider_approval_state=self.approval_state,
            environment_tier=env_tier,
            source_body_sha256=source_sha256,
            base_currency=base_currency,
            period_start_utc=period_start,
            period_end_utc=period_end,
            enumerated_subaccount_count=len(raw_acct_ids),
            connected_subaccount_count=len(filtered_accounts) if raw_acct_ids else 0,
            trades=sorted(trades, key=lambda t: (t.timestamp_utc, t.native_entry_id)),
            flows=sorted(flows, key=lambda f: f.timestamp_utc),
            corporate_actions=sorted(corporate_actions, key=lambda c: c.timestamp_utc),
            prior_positions=prior_positions,
            ending_positions=ending_positions,
            nav_points=nav_points,
            conversion_rates=conversion_rates_out,
            enabled_sections=enabled_secs,
            parser_warnings=parser_warnings,
        )

    @staticmethod
    def _summarize_accounts_sync_state(
        accounts_list: Sequence[Any],
        *,
        selected_account_ids: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        selected_filter = (
            {str(aid).strip() for aid in selected_account_ids if str(aid).strip()}
            if selected_account_ids
            else set()
        )
        valid_accounts: list[Mapping[str, Any]] = []
        for acct in accounts_list:
            if not isinstance(acct, Mapping):
                continue
            aid = _extract_account_id(acct)
            if not aid:
                continue
            if selected_filter and aid not in selected_filter:
                continue
            valid_accounts.append(acct)

        accounts_count = len(valid_accounts)
        holdings_pending = False
        transactions_pending = False
        first_dates: list[str] = []

        for acct in valid_accounts:
            sync_st = acct.get("sync_status")
            if not isinstance(sync_st, Mapping):
                continue
            h_st = sync_st.get("holdings")
            if isinstance(h_st, Mapping) and h_st.get("initial_sync_completed") is False:
                holdings_pending = True
            t_st = sync_st.get("transactions")
            if isinstance(t_st, Mapping):
                if t_st.get("initial_sync_completed") is False:
                    transactions_pending = True
                raw_first = t_st.get("first_transaction_date")
                if isinstance(raw_first, str) and raw_first.strip():
                    parsed_first = _parse_iso_ts(raw_first.strip())
                    if parsed_first is not None:
                        first_dates.append(parsed_first[:10])

        holdings_synced = bool(accounts_count > 0 and not holdings_pending)
        transactions_synced = bool(accounts_count > 0 and not transactions_pending)
        return {
            "accounts_count": accounts_count,
            "holdings_synced": holdings_synced,
            "transactions_synced": transactions_synced,
            "first_transaction_date": min(first_dates) if first_dates else None,
            "ready_to_verify": bool(
                accounts_count > 0 and holdings_synced and transactions_synced
            ),
        }

    def fetch_sync_status(
        self,
        user_id: str = "",
        user_secret: str = "",
    ) -> dict[str, Any]:
        """Inspect read-only SnapTrade authorization and account initial-sync progress (zero PII)."""
        if self.is_personal_key:
            clean_user = (user_id or self.user_id or "").strip() or "personal-owner"
            clean_secret = ""
            req_user: str | None = None
            req_secret: str | None = None
        else:
            clean_user = (user_id or "").strip()
            clean_secret = (user_secret or "").strip()
            if not clean_user:
                raise SnapTradeAuthenticationError("user_id is required for live SnapTrade queries")
            if not clean_secret:
                raise SnapTradeAuthenticationError("user_secret is required for live SnapTrade queries")
            req_user = clean_user
            req_secret = clean_secret

        secrets_list = self._collect_secrets(clean_secret, clean_user)
        try:
            auth_count: int | None = None
            auth_resp = self._execute_signed(
                "GET",
                "/api/v1/authorizations",
                user_id=req_user,
                user_secret=req_secret,
            )
            if auth_resp.status_code == 200:
                auth_raw = self._decode_json_or_raise(
                    auth_resp,
                    api_path="/api/v1/authorizations",
                    extra_secrets=(clean_secret, clean_user),
                )
                auth_items = (
                    auth_raw
                    if isinstance(auth_raw, list)
                    else ([auth_raw] if isinstance(auth_raw, Mapping) and auth_raw else [])
                )
                auth_count = sum(
                    1
                    for item in auth_items
                    if isinstance(item, Mapping) and item.get("disabled") is not True
                )
            elif auth_resp.status_code not in {404, 405, 501}:
                self._decode_json_or_raise(
                    auth_resp,
                    api_path="/api/v1/authorizations",
                    extra_secrets=(clean_secret, clean_user),
                )

            accts_resp = self._execute_signed(
                "GET",
                "/api/v1/accounts",
                user_id=req_user,
                user_secret=req_secret,
            )
            accts_raw = self._decode_json_or_raise(
                accts_resp,
                api_path="/api/v1/accounts",
                extra_secrets=(clean_secret, clean_user),
            )
            accounts_list = (
                accts_raw
                if isinstance(accts_raw, list)
                else ([accts_raw] if isinstance(accts_raw, Mapping) and accts_raw else [])
            )
            summary = self._summarize_accounts_sync_state(accounts_list)
            linked_auths = (
                auth_count
                if auth_count is not None
                else (1 if summary["accounts_count"] > 0 else 0)
            )
            return {
                "linked_authorizations": linked_auths,
                "accounts_count": summary["accounts_count"],
                "holdings_synced": summary["holdings_synced"],
                "transactions_synced": summary["transactions_synced"],
                "first_transaction_date": summary["first_transaction_date"],
                "ready_to_verify": summary["ready_to_verify"],
            }
        except Exception as exc:
            redacted_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_list)
            if isinstance(exc, (SnapTradeError, DisallowedCapabilityError, ValueError)):
                raise type(exc)(redacted_msg) from None
            raise SnapTradeServiceError(
                f"SnapTrade sync status query failed: {redacted_msg}"
            ) from None

    def fetch_live_ledger(
        self,
        user_id: str = "",
        user_secret: str = "",
        *,
        blinding_salt_hex: str,
        start_date: str | None = None,
        end_date: str | None = None,
        selected_account_ids: Sequence[str] | None = None,
        require_live: bool = True,
        as_of_utc: str | None = None,
    ) -> CanonicalPortfolioLedger:
        """Fetch live read-only accounts, holdings/positions, and paginated activities via SnapTrade V1."""
        if self.is_personal_key:
            clean_user = (user_id or self.user_id or "").strip() or "personal-owner"
            clean_secret = ""
            req_user: str | None = None
            req_secret: str | None = None
        else:
            clean_user = (user_id or "").strip()
            clean_secret = (user_secret or "").strip()
            if not clean_user:
                raise SnapTradeAuthenticationError("user_id is required for live SnapTrade queries")
            if not clean_secret:
                raise SnapTradeAuthenticationError("user_secret is required for live SnapTrade queries")
            req_user = clean_user
            req_secret = clean_secret

        norm_start = _normalize_date_param(start_date, field_name="start_date")
        norm_end = _normalize_date_param(end_date, field_name="end_date")

        self.slot_manager.register_slot(clean_user)
        secrets_list = self._collect_secrets(clean_secret, clean_user)

        try:
            # 1. GET /api/v1/accounts
            accts_resp = self._execute_signed(
                "GET",
                "/api/v1/accounts",
                user_id=req_user,
                user_secret=req_secret,
            )
            accts_raw = self._decode_json_or_raise(
                accts_resp,
                api_path="/api/v1/accounts",
                extra_secrets=(clean_secret, clean_user),
            )
            accounts_list = (
                accts_raw
                if isinstance(accts_raw, list)
                else ([accts_raw] if isinstance(accts_raw, Mapping) and accts_raw else [])
            )
            has_account_ids = any(
                isinstance(acct, Mapping) and bool(_extract_account_id(acct))
                for acct in accounts_list
            )
            if not has_account_ids:
                raise SnapTradeNoLinkedAccountError(
                    f"{SNAPTRADE_NO_LINKED_ACCOUNT_MESSAGE}; "
                    "complete the read-only broker sign-in first."
                )

            sync_summary = self._summarize_accounts_sync_state(
                accounts_list, selected_account_ids=selected_account_ids
            )
            if sync_summary["accounts_count"] > 0 and not sync_summary["ready_to_verify"]:
                raise SnapTradeInitialSyncPendingError(
                    f"{SNAPTRADE_INITIAL_SYNC_PENDING_MESSAGE}; try again in a few seconds."
                )

            # 2. GET /api/v1/holdings (with fallback to per-account positions & balances)
            holdings_resp = self._execute_signed(
                "GET",
                "/api/v1/holdings",
                user_id=req_user,
                user_secret=req_secret,
            )
            holdings_list: list[Any] = []
            fallback_positions: list[Any] = []
            fallback_balances: list[Any] = []
            pending_acct_fallbacks: list[
                tuple[Mapping[str, Any], str, list[dict[str, Any]], list[dict[str, Any]]]
            ] = []

            if holdings_resp.status_code == 200:
                holdings_raw = self._decode_json_or_raise(
                    holdings_resp,
                    api_path="/api/v1/holdings",
                    extra_secrets=(clean_secret, clean_user),
                )
                holdings_list = holdings_raw if isinstance(holdings_raw, list) else [holdings_raw]
            elif holdings_resp.status_code in {400, 404, 405, 410, 501} or (
                has_account_ids and holdings_resp.status_code in {401, 403, 422}
            ):
                for acct in accounts_list:
                    if not isinstance(acct, Mapping):
                        continue
                    aid = _extract_account_id(acct)
                    if not aid:
                        continue
                    safe_aid = urllib.parse.quote(aid, safe="")
                    acct_positions: list[dict[str, Any]] = []
                    pos_r = self._execute_signed(
                        "GET",
                        f"/api/v1/accounts/{safe_aid}/positions",
                        user_id=req_user,
                        user_secret=req_secret,
                    )
                    if pos_r.status_code == 200:
                        pos_data = self._decode_json_or_raise(
                            pos_r,
                            api_path="/api/v1/accounts/[REDACTED]/positions",
                            extra_secrets=(clean_secret, clean_user, aid),
                        )
                        for p in pos_data if isinstance(pos_data, list) else [pos_data]:
                            if isinstance(p, Mapping):
                                p_item = dict(p)
                                p_item.setdefault("account_id", aid)
                                acct_positions.append(p_item)
                                fallback_positions.append(p_item)
                    elif pos_r.status_code not in {404, 405, 501}:
                        self._decode_json_or_raise(
                            pos_r,
                            api_path="/api/v1/accounts/[REDACTED]/positions",
                            extra_secrets=(clean_secret, clean_user, aid),
                        )

                    bal_r = self._execute_signed(
                        "GET",
                        f"/api/v1/accounts/{safe_aid}/balances",
                        user_id=req_user,
                        user_secret=req_secret,
                    )
                    if bal_r.status_code == 200:
                        bal_data = self._decode_json_or_raise(
                            bal_r,
                            api_path="/api/v1/accounts/[REDACTED]/balances",
                            extra_secrets=(clean_secret, clean_user, aid),
                        )
                        bal_items = [
                            dict(b)
                            for b in (bal_data if isinstance(bal_data, list) else [bal_data])
                            if isinstance(b, Mapping)
                        ]
                        has_explicit_total = any(
                            b.get("total") is not None
                            or b.get("current_balance") is not None
                            or b.get("equity") is not None
                            for b in bal_items
                        )
                        if has_explicit_total:
                            for b_item in bal_items:
                                b_item.setdefault("account_id", aid)
                                fallback_balances.append(b_item)
                        elif bal_items:
                            pending_acct_fallbacks.append((acct, aid, bal_items, acct_positions))
                    elif bal_r.status_code not in {404, 405, 501}:
                        self._decode_json_or_raise(
                            bal_r,
                            api_path="/api/v1/accounts/[REDACTED]/balances",
                            extra_secrets=(clean_secret, clean_user, aid),
                        )
            else:
                self._decode_json_or_raise(
                    holdings_resp,
                    api_path="/api/v1/holdings",
                    extra_secrets=(clean_secret, clean_user),
                )

            # 3. GET /api/v1/activities (paginated up to MAX_ACTIVITIES_PAGES; fail closed on cap)
            activities_list: list[Any] = []
            offset = 0
            use_per_account_activities = False
            exhausted_global_activities = False
            for _ in range(MAX_ACTIVITIES_PAGES):
                act_params: dict[str, Any] = {
                    "limit": MAX_ACTIVITIES_PAGE_SIZE,
                    "offset": offset,
                }
                if norm_start:
                    act_params["startDate"] = norm_start
                if norm_end:
                    act_params["endDate"] = norm_end

                act_resp = self._execute_signed(
                    "GET",
                    "/api/v1/activities",
                    user_id=req_user,
                    user_secret=req_secret,
                    extra_query_params=act_params,
                )
                if offset == 0 and (
                    act_resp.status_code in {400, 404, 405, 410, 501}
                    or (has_account_ids and act_resp.status_code in {401, 403, 422})
                ):
                    use_per_account_activities = True
                    exhausted_global_activities = True
                    break
                act_raw = self._decode_json_or_raise(
                    act_resp,
                    api_path="/api/v1/activities",
                    extra_secrets=(clean_secret, clean_user),
                )
                if isinstance(act_raw, Mapping) and isinstance(act_raw.get("data"), list):
                    page_items = act_raw["data"]
                elif isinstance(act_raw, list):
                    page_items = act_raw
                elif isinstance(act_raw, Mapping) and act_raw:
                    page_items = [act_raw]
                else:
                    page_items = []

                activities_list.extend(page_items)
                if len(page_items) < MAX_ACTIVITIES_PAGE_SIZE:
                    exhausted_global_activities = True
                    break
                offset += MAX_ACTIVITIES_PAGE_SIZE

            if not use_per_account_activities and not exhausted_global_activities:
                raise SnapTradeActivityPaginationLimitError(
                    f"SnapTrade activities pagination reached {MAX_ACTIVITIES_PAGES} full pages "
                    f"({MAX_ACTIVITIES_PAGES * MAX_ACTIVITIES_PAGE_SIZE} rows); refusing silent "
                    "truncation of brokerage history."
                )

            if use_per_account_activities:
                for acct in accounts_list:
                    if not isinstance(acct, Mapping):
                        continue
                    aid = _extract_account_id(acct)
                    if not aid:
                        continue
                    safe_aid = urllib.parse.quote(aid, safe="")
                    acct_offset = 0
                    exhausted_acct_activities = False
                    for _ in range(MAX_ACTIVITIES_PAGES):
                        acct_act_params: dict[str, Any] = {
                            "limit": MAX_ACTIVITIES_PAGE_SIZE,
                            "offset": acct_offset,
                        }
                        if norm_start:
                            acct_act_params["startDate"] = norm_start
                        if norm_end:
                            acct_act_params["endDate"] = norm_end
                        acct_act_resp = self._execute_signed(
                            "GET",
                            f"/api/v1/accounts/{safe_aid}/activities",
                            user_id=req_user,
                            user_secret=req_secret,
                            extra_query_params=acct_act_params,
                        )
                        acct_act_raw = self._decode_json_or_raise(
                            acct_act_resp,
                            api_path="/api/v1/accounts/[REDACTED]/activities",
                            extra_secrets=(clean_secret, clean_user, aid),
                        )
                        if isinstance(acct_act_raw, Mapping) and isinstance(
                            acct_act_raw.get("data"), list
                        ):
                            acct_items = acct_act_raw["data"]
                        elif isinstance(acct_act_raw, list):
                            acct_items = acct_act_raw
                        elif isinstance(acct_act_raw, Mapping) and acct_act_raw:
                            acct_items = [acct_act_raw]
                        else:
                            acct_items = []
                        for item in acct_items:
                            if isinstance(item, Mapping):
                                item_copy = dict(item)
                                item_copy.setdefault("account_id", aid)
                                activities_list.append(item_copy)
                        if len(acct_items) < MAX_ACTIVITIES_PAGE_SIZE:
                            exhausted_acct_activities = True
                            break
                        acct_offset += MAX_ACTIVITIES_PAGE_SIZE
                    if not exhausted_acct_activities:
                        raise SnapTradeActivityPaginationLimitError(
                            f"SnapTrade per-account activities pagination reached {MAX_ACTIVITIES_PAGES} "
                            f"full pages ({MAX_ACTIVITIES_PAGES * MAX_ACTIVITIES_PAGE_SIZE} rows); "
                            "refusing silent truncation of brokerage history."
                        )

            # 3b. Opportunistic GET /api/v1/currencies/rates ONLY when non-USD or multi-currency
            # holdings/balances/activities exist (gracefully ignored if unavailable).
            observed_ccys: set[str] = set()
            for acct in accounts_list:
                if isinstance(acct, Mapping):
                    meta_obj = acct.get("meta") if isinstance(acct.get("meta"), Mapping) else {}
                    bal_obj = acct.get("balance")
                    bal_tot_c = (
                        bal_obj.get("total", {}).get("currency")
                        if isinstance(bal_obj, Mapping) and isinstance(bal_obj.get("total"), Mapping)
                        else None
                    )
                    c_code = _extract_currency_code(
                        acct.get("currency") or meta_obj.get("currency") or bal_tot_c,
                        default="",
                    )
                    if c_code:
                        observed_ccys.add(c_code)
            for h_item in holdings_list:
                if isinstance(h_item, Mapping):
                    h_tot = h_item.get("total_value")
                    if isinstance(h_tot, Mapping):
                        c_code = _extract_currency_code(h_tot.get("currency"), default="")
                        if c_code:
                            observed_ccys.add(c_code)
                    for b_item in h_item.get("balances") or []:
                        if isinstance(b_item, Mapping):
                            c_code = _extract_currency_code(b_item.get("currency"), default="")
                            if c_code:
                                observed_ccys.add(c_code)
                    for p_item in h_item.get("positions") or []:
                        if isinstance(p_item, Mapping):
                            _, p_ccy, _, _ = _position_asset_info(p_item, "")
                            if p_ccy:
                                observed_ccys.add(p_ccy)
            for _, _, raw_bals, raw_pos in pending_acct_fallbacks:
                for b_item in raw_bals:
                    c_code = _extract_currency_code(b_item.get("currency"), default="")
                    if c_code:
                        observed_ccys.add(c_code)
                for p_item in raw_pos:
                    _, p_ccy, _, _ = _position_asset_info(p_item, "")
                    if p_ccy:
                        observed_ccys.add(p_ccy)
            for b_item in fallback_balances:
                if isinstance(b_item, Mapping):
                    c_code = _extract_currency_code(b_item.get("currency"), default="")
                    if c_code:
                        observed_ccys.add(c_code)
            for p_item in fallback_positions:
                if isinstance(p_item, Mapping):
                    _, p_ccy, _, _ = _position_asset_info(p_item, "")
                    if p_ccy:
                        observed_ccys.add(p_ccy)
            for act_item in activities_list:
                if isinstance(act_item, Mapping):
                    sym_src = (
                        act_item.get("symbol")
                        if act_item.get("symbol") is not None
                        else act_item.get("instrument")
                    )
                    _, s_ccy, _ = _extract_symbol_and_currency(sym_src, "")
                    c_code = _extract_currency_code(act_item.get("currency"), s_ccy)
                    if c_code:
                        observed_ccys.add(c_code)

            currency_rates_list: list[Any] = []
            if len(observed_ccys) > 1 or (observed_ccys and observed_ccys != {"USD"}):
                rates_resp = self._execute_signed("GET", "/api/v1/currencies/rates")
                if rates_resp.status_code == 200 and rates_resp.body and rates_resp.body.strip():
                    try:
                        rates_raw = json.loads(rates_resp.body.decode("utf-8"))
                    except Exception:
                        rates_raw = None
                    if isinstance(rates_raw, list):
                        currency_rates_list = rates_raw

            live_pair_rates, _ = _parse_currency_rate_pairs(currency_rates_list, None, "USD")

            live_sel = {str(x).strip() for x in selected_account_ids or [] if str(x).strip()}
            for acct, aid, bal_items, acct_positions in pending_acct_fallbacks:
                if live_sel and aid not in live_sel:
                    # A deselected account is not valued, so it can never refuse the record.
                    continue
                meta_obj = acct.get("meta") if isinstance(acct.get("meta"), Mapping) else {}
                acct_bal_obj = acct.get("balance")
                acct_tot_val: float | None = None
                acct_tot_ccy = ""
                if isinstance(acct_bal_obj, Mapping) and isinstance(
                    acct_bal_obj.get("total"), Mapping
                ):
                    raw_tot = acct_bal_obj["total"].get("amount")
                    acct_tot_ccy = _extract_currency_code(
                        acct_bal_obj["total"].get("currency"), default=""
                    )
                    if raw_tot is not None:
                        acct_tot_val = float(raw_tot)
                first_ccy = _extract_currency_code(bal_items[0].get("currency"), "USD")
                acct_ccy = (
                    _extract_currency_code(
                        acct.get("currency") or meta_obj.get("currency") or acct_tot_ccy,
                        default="",
                    )
                    or first_ccy
                )
                cash_sum = 0.0
                for b_row in bal_items:
                    if b_row.get("cash") is not None:
                        row_ccy = _extract_currency_code(b_row.get("currency"), acct_ccy)
                        row_fx = _require_fx_rate(row_ccy, acct_ccy, live_pair_rates)
                        cash_sum += float(b_row["cash"]) * row_fx
                pos_mkt_sum = 0.0
                for p_row in acct_positions:
                    u = _extract_units(p_row)
                    pr = float(p_row.get("price") or p_row.get("current_price") or 0.0)
                    _, p_ccy, _, p_mult = _position_asset_info(p_row, acct_ccy)
                    p_fx = _require_fx_rate(p_ccy, acct_ccy, live_pair_rates)
                    pos_mkt_sum += u * pr * p_mult * p_fx
                if acct_tot_val is not None:
                    tot_fx = (
                        _require_fx_rate(acct_tot_ccy or acct_ccy, acct_ccy, live_pair_rates)
                    )
                    resolved_total = acct_tot_val * tot_fx
                else:
                    resolved_total = cash_sum + pos_mkt_sum
                fallback_balances.append(
                    {
                        "account_id": aid,
                        "total": resolved_total,
                        "cash": cash_sum,
                        "currency": acct_ccy,
                        "updated_at": bal_items[0].get("updated_at")
                        or acct.get("updated_at")
                        or acct.get("created_date"),
                    }
                )

            # 4. Opportunistic GET /api/v1/performance/custom for daily totalEquityTimeframe
            # (gracefully ignored when 4xx/5xx or unavailable on a brokerage/plan)
            perf_nav_points: list[dict[str, Any]] = []
            perf_end = norm_end or datetime.now(timezone.utc).strftime("%Y-%m-%d")
            perf_start = norm_start
            if not perf_start:
                act_dates = [
                    str(
                        item.get("trade_date")
                        or item.get("settlement_date")
                        or item.get("date")
                        or item.get("created_at")
                        or ""
                    ).strip()[:10]
                    for item in activities_list
                    if isinstance(item, Mapping)
                ]
                valid_dates = [d for d in act_dates if len(d) == 10 and d[4] == "-" and d[7] == "-"]
                perf_start = min(valid_dates) if valid_dates else None
            if perf_start and perf_start <= perf_end:
                perf_params: dict[str, Any] = {
                    "startDate": perf_start,
                    "endDate": perf_end,
                    "detailed": "true",
                    "frequency": "daily",
                }
                if selected_account_ids:
                    clean_sel = [str(x).strip() for x in selected_account_ids if str(x).strip()]
                    if clean_sel:
                        perf_params["accounts"] = ",".join(sorted(clean_sel))
                perf_resp = self._execute_signed(
                    "GET",
                    "/api/v1/performance/custom",
                    user_id=req_user,
                    user_secret=req_secret,
                    extra_query_params=perf_params,
                )
                if perf_resp.status_code == 200 and perf_resp.body and perf_resp.body.strip():
                    try:
                        perf_raw = json.loads(perf_resp.body.decode("utf-8"))
                    except Exception:
                        perf_raw = None
                    if isinstance(perf_raw, Mapping):
                        eq_tf = (
                            perf_raw.get("totalEquityTimeframe")
                            or perf_raw.get("total_equity_timeframe")
                            or []
                        )
                        if isinstance(eq_tf, list):
                            for pt in eq_tf:
                                if not isinstance(pt, Mapping):
                                    continue
                                raw_dt = pt.get("date") or pt.get("timestamp_utc")
                                raw_val = pt.get("value") if pt.get("value") is not None else pt.get("total")
                                if raw_dt and raw_val is not None:
                                    try:
                                        f_val = float(raw_val)
                                    except (TypeError, ValueError):
                                        continue
                                    # Zero and negative days are kept: dropping them would hide
                                    # a wipe-out from the return calculation.
                                    if math.isfinite(f_val):
                                        perf_nav_points.append({"date": str(raw_dt), "value": f_val})

            bundle_payload: dict[str, Any] = {
                "accounts": accounts_list,
                "holdings": holdings_list,
                "activities": activities_list,
            }
            if currency_rates_list:
                bundle_payload["currency_rates"] = currency_rates_list
            if len(perf_nav_points) >= 2:
                bundle_payload["nav_points"] = perf_nav_points
                if "accounts" in perf_params:
                    # The series was requested for exactly these accounts.
                    bundle_payload["nav_points_account_ids"] = perf_params["accounts"].split(",")
            if fallback_positions:
                bundle_payload["positions"] = fallback_positions
            if fallback_balances:
                bundle_payload["balances"] = fallback_balances

            return self.parse_payload(
                bundle_payload,
                blinding_salt_hex=blinding_salt_hex,
                selected_account_ids=selected_account_ids,
                require_live=require_live,
                start_date=norm_start,
                end_date=norm_end,
                as_of_utc=as_of_utc,
            )
        except Exception as exc:
            redacted_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_list)
            if isinstance(
                exc,
                (
                    SnapTradeError,
                    PaperOrSandboxAccountRejectedError,
                    DisallowedCapabilityError,
                    ValueError,
                ),
            ):
                raise type(exc)(redacted_msg) from None
            raise SnapTradeServiceError(f"SnapTrade relay query failed: {redacted_msg}") from None

    def fetch_canonical_ledger(
        self,
        *,
        blinding_salt_hex: str,
        user_id: str | None = None,
        user_secret: str | None = None,
        period_start_utc: str | None = None,
        period_end_utc: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        selected_account_ids: Sequence[str] | None = None,
        require_live: bool = True,
        as_of_utc: str | None = None,
    ) -> CanonicalPortfolioLedger:
        """Read-only canonical ledger adapter entrypoint delegating to ``fetch_live_ledger``."""
        target_user = (user_id or self.user_id or "").strip()
        target_secret = (user_secret or self.user_secret or "").strip()
        resolved_start = (
            start_date[:10]
            if start_date
            else (period_start_utc[:10] if period_start_utc else None)
        )
        resolved_end = (
            end_date[:10]
            if end_date
            else (period_end_utc[:10] if period_end_utc else None)
        )
        return self.fetch_live_ledger(
            target_user,
            target_secret,
            blinding_salt_hex=blinding_salt_hex,
            start_date=resolved_start,
            end_date=resolved_end,
            selected_account_ids=selected_account_ids,
            require_live=require_live,
            as_of_utc=as_of_utc,
        )


__all__ = [
    "DEFAULT_SNAPTRADE_USER_AGENT",
    "MAX_SNAPTRADE_PERSONAL_SLOTS",
    "MAX_SNAPTRADE_POC_SLOTS",
    "SNAPTRADE_BLOCKED_MUTATING_ENDPOINTS",
    "SNAPTRADE_INITIAL_SYNC_PENDING_MESSAGE",
    "SNAPTRADE_LIVE_BASE_URL",
    "SNAPTRADE_NO_LINKED_ACCOUNT_MESSAGE",
    "SignedSnapTradeRequest",
    "SnapTradeActivityPaginationLimitError",
    "SnapTradeAuthenticationError",
    "SnapTradeConnectionSlot",
    "SnapTradeError",
    "SnapTradeInitialSyncPendingError",
    "SnapTradeNoLinkedAccountError",
    "SnapTradeReadOnlyAdapter",
    "SnapTradeServiceError",
    "SnapTradeSlotCapExceededError",
    "SnapTradeSlotManager",
    "build_signed_request",
    "compute_snaptrade_signature",
    "get_global_snaptrade_slot_manager",
    "is_snaptrade_env_configured",
    "is_snaptrade_personal_key",
]
