"""Read-only SnapTrade V1 aggregator relay adapter with HMAC-SHA256 signing and 5-slot cap."""

from __future__ import annotations

import base64
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
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
    if user_id is not None and str(user_id).strip():
        params["userId"] = str(user_id).strip()
    if user_secret is not None and str(user_secret).strip():
        params["userSecret"] = str(user_secret).strip()
    if extra_query_params:
        for k, v in extra_query_params.items():
            if v is not None and str(v).strip() != "":
                params[str(k)] = str(v)

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


def _parse_iso_ts(value: str | None) -> str:
    if not value or not str(value).strip():
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = str(value).strip()
    if len(raw) == 10 and raw[4] == "-" and raw[7] == "-":
        raw = f"{raw}T00:00:00Z"
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return raw


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
        inner = raw_symbol.get("symbol")
        if isinstance(inner, Mapping):
            sym_val = inner.get("raw_symbol") or inner.get("symbol") or inner.get("ticker") or ""
            ccy_val = _extract_currency_code(inner.get("currency") or raw_symbol.get("currency"), default_ccy)
            t_obj = inner.get("type")
            t_code = str(t_obj.get("code") if isinstance(t_obj, Mapping) else (t_obj or "")).strip().lower()
            return str(sym_val).strip().upper(), ccy_val, t_code
        sym_val = raw_symbol.get("raw_symbol") or inner or raw_symbol.get("ticker") or ""
        ccy_val = _extract_currency_code(raw_symbol.get("currency"), default_ccy)
        t_obj = raw_symbol.get("type")
        t_code = str(t_obj.get("code") if isinstance(t_obj, Mapping) else (t_obj or "")).strip().lower()
        return str(sym_val).strip().upper(), ccy_val, t_code
    return "", default_ccy, ""


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
    if is_option or type_code in {"option", "opt"}:
        return AssetClass.OPTION
    if type_code in {"etf", "etn"}:
        return AssetClass.ETF
    if type_code in {"crypto", "cryptocurrency"}:
        return AssetClass.CRYPTO_SPOT
    if len(symbol) > 14 and any(c.isdigit() for c in symbol):
        return AssetClass.OPTION
    return AssetClass.EQUITY


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

        if not resolved_client_id:
            raise SnapTradeAuthenticationError("SnapTrade client_id must not be empty")
        if not resolved_consumer_key:
            raise SnapTradeAuthenticationError("SnapTrade consumer_key must not be empty")

        self.client_id = resolved_client_id
        self.consumer_key = resolved_consumer_key
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
        self.slot_manager = slot_manager or _GLOBAL_POC_SLOT_MANAGER

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

    def register_user(self, user_id: str) -> dict[str, str]:
        """Allocate/reuse a slot (max 5) and register a SnapTrade V1 user."""
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
        user_id: str,
        user_secret: str,
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
            user_id=clean_user,
            user_secret=clean_secret,
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

    def delete_user_and_release_slot(self, user_id: str) -> dict[str, Any]:
        """Delete a SnapTrade user upstream and release its local POC connection slot."""
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

    def parse_payload(
        self,
        payload: dict[str, Any] | str | bytes,
        *,
        blinding_salt_hex: str,
        selected_account_ids: Sequence[str] | None = None,
        require_live: bool = True,
        start_date: str | None = None,
        end_date: str | None = None,
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
            h_aid = ""
            if isinstance(h_acct, Mapping):
                h_aid = _extract_account_id(h_acct)
                if h_aid and not any(_extract_account_id(a) == h_aid for a in raw_accounts_list):
                    raw_accounts_list.append(h_acct)
            else:
                h_aid = _extract_account_id(h_entry)

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
            bal_ccy = "USD"
            if isinstance(h_balances, list):
                for b_item in h_balances:
                    if isinstance(b_item, Mapping):
                        if b_item.get("cash") is not None:
                            cash_sum += float(b_item["cash"])
                            has_cash = True
                        bal_ccy = _extract_currency_code(b_item.get("currency"), bal_ccy)

            total_val: float | None = None
            if isinstance(h_total_obj, Mapping) and h_total_obj.get("value") is not None:
                total_val = float(h_total_obj["value"])
                bal_ccy = _extract_currency_code(h_total_obj.get("currency"), bal_ccy)
            elif isinstance(h_acct, Mapping):
                acct_bal = h_acct.get("balance")
                if isinstance(acct_bal, Mapping) and isinstance(acct_bal.get("total"), Mapping):
                    tot_inner = acct_bal["total"]
                    if tot_inner.get("amount") is not None:
                        total_val = float(tot_inner["amount"])
                        bal_ccy = _extract_currency_code(tot_inner.get("currency"), bal_ccy)

            if total_val is not None or has_cash:
                pos_mkt_sum = 0.0
                if total_val is None:
                    for p in h_positions if isinstance(h_positions, list) else []:
                        if isinstance(p, Mapping):
                            u = float(p.get("units") or p.get("quantity") or 0.0)
                            pr = float(p.get("price") or p.get("current_price") or 0.0)
                            pos_mkt_sum += u * pr
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
                        "currency": bal_ccy,
                        "updated_at": h_entry.get("updated_at") or sync_ts,
                    }
                )

        raw_acct_ids: list[str] = []
        is_paper_detected = False
        base_currency = "USD"

        for acct in raw_accounts_list:
            aid = _extract_account_id(acct)
            if aid and aid not in raw_acct_ids:
                raw_acct_ids.append(aid)
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
            if ccy and len(ccy) == 3:
                base_currency = ccy

            if not flattened_balances and isinstance(acct_bal, Mapping):
                tot_map = acct_bal.get("total")
                if isinstance(tot_map, Mapping) and tot_map.get("amount") is not None:
                    flattened_balances.append(
                        {
                            "account_id": aid,
                            "total": float(tot_map["amount"]),
                            "cash": None,
                            "currency": _extract_currency_code(tot_map.get("currency"), base_currency),
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

        selected_set = (
            {str(x).strip() for x in selected_account_ids if str(x).strip()}
            if selected_account_ids
            else None
        )
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
            if selected_set and aid and aid not in selected_set:
                continue
            act_type = str(act.get("type") or "").strip().lower()
            ts = _parse_iso_ts(
                act.get("trade_date") or act.get("settlement_date") or act.get("created_at")
            )

            opt_obj = act.get("option_symbol")
            is_opt = isinstance(opt_obj, Mapping) and bool(opt_obj)
            sym_str, sym_ccy, sym_type = _extract_symbol_and_currency(act.get("symbol"), base_currency)
            if is_opt and isinstance(opt_obj, Mapping):
                opt_ticker = str(opt_obj.get("ticker") or sym_str or "").strip().upper()
                if opt_ticker:
                    sym_str = opt_ticker

            qty = abs(float(act.get("units") or act.get("quantity") or 0.0))
            price = abs(float(act.get("price") or 0.0))
            fee = abs(float(act.get("fee") or act.get("commission") or 0.0))
            currency = _extract_currency_code(act.get("currency"), sym_ccy or base_currency)

            if act_type in {"buy", "sell", "rei"}:
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

                trades.append(
                    NormalizedTrade(
                        venue="SNAPTRADE_RELAY",
                        native_entry_id=str(act.get("id") or f"st-{len(trades) + 1}"),
                        symbol=sym_str or "UNKNOWN",
                        asset_class=asset_cls,
                        side="sell" if act_type == "sell" else "buy",
                        quantity=qty,
                        price=price,
                        timestamp_utc=ts,
                        currency=currency,
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
                                description="SnapTrade dividend reinvestment",
                            )
                        )
            elif act_type in {
                "deposit",
                "contribution",
                "withdrawal",
                "dividend",
                "interest",
                "fee",
                "tax",
                "transfer",
            }:
                raw_amt = float(act.get("amount") if act.get("amount") is not None else (price * qty))
                if act_type in {"deposit", "contribution"}:
                    flow_kind = FlowKind.DEPOSIT
                    amt = abs(raw_amt)
                elif act_type == "withdrawal":
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
                        symbol=sym_str or None if flow_kind in {FlowKind.TRANSFER_IN_KIND, FlowKind.TRANSFER_OUT_KIND} else None,
                        quantity=qty if flow_kind in {FlowKind.TRANSFER_IN_KIND, FlowKind.TRANSFER_OUT_KIND} else None,
                        description=str(act.get("description") or f"SnapTrade {act_type}"),
                    )
                )
            elif act_type in {"optionexpiration", "optionassignment", "optionexercise", "split"} and sym_str:
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
                        quantity_delta=float(act.get("units") or 0.0),
                        description=str(act.get("description") or f"SnapTrade {act_type}"),
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
            if selected_set and aid and aid not in selected_set:
                continue
            sym_str, sym_ccy, sym_type = _extract_symbol_and_currency(p.get("symbol"), base_currency)
            units = float(p.get("units") or p.get("quantity") or 0.0)
            price = float(p.get("price") or p.get("current_price") or 0.0)
            avg_cost = p.get("average_purchase_price")
            asset_cls = _infer_asset_class(sym_str, sym_type)
            mult = 100.0 if asset_cls == AssetClass.OPTION else 1.0
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
                    currency=sym_ccy or base_currency,
                    multiplier=mult,
                )
            )

        nav_by_ts: dict[str, tuple[float, float | None]] = {}

        explicit_nav_points = data.get("nav_points") or []
        if isinstance(explicit_nav_points, list):
            for np_item in explicit_nav_points:
                if not isinstance(np_item, Mapping):
                    continue
                n_ts = _parse_iso_ts(np_item.get("timestamp_utc") or np_item.get("date"))
                n_val = float(np_item.get("nav_base") or np_item.get("total") or 0.0)
                n_cash = float(np_item["cash_base"]) if np_item.get("cash_base") is not None else None
                prev_nav, prev_cash = nav_by_ts.get(n_ts, (0.0, None))
                merged_cash = (
                    (prev_cash or 0.0) + n_cash
                    if (prev_cash is not None or n_cash is not None)
                    else None
                )
                nav_by_ts[n_ts] = (prev_nav + n_val, merged_cash)

        balances_raw = data.get("balances")
        balances_source: list[Mapping[str, Any]] = []
        if isinstance(balances_raw, Mapping):
            balances_source.append(balances_raw)
        elif isinstance(balances_raw, list):
            balances_source.extend(b for b in balances_raw if isinstance(b, Mapping))
        else:
            balances_source.extend(flattened_balances)

        for b in balances_source:
            aid = str(b.get("account_id") or "").strip()
            if selected_set and aid and aid not in selected_set:
                continue
            tot_field = b.get("total")
            if isinstance(tot_field, Mapping):
                tot = float(tot_field.get("amount") or tot_field.get("value") or 0.0)
            else:
                tot = float(
                    tot_field
                    if tot_field is not None
                    else (b.get("current_balance") or b.get("equity") or b.get("cash") or 0.0)
                )
            cash_val = float(b["cash"]) if b.get("cash") is not None else None
            b_ts = _parse_iso_ts(b.get("updated_at") or b.get("date"))
            prev_nav, prev_cash = nav_by_ts.get(b_ts, (0.0, None))
            merged_cash = (
                (prev_cash or 0.0) + cash_val
                if (prev_cash is not None or cash_val is not None)
                else None
            )
            nav_by_ts[b_ts] = (prev_nav + tot, merged_cash)

        nav_points = [
            NormalizedNavPoint(timestamp_utc=ts_key, nav_base=vals[0], cash_base=vals[1])
            for ts_key, vals in sorted(nav_by_ts.items(), key=lambda kv: kv[0])
            if vals[0] > 0.0
        ]

        all_ts = (
            [t.timestamp_utc for t in trades]
            + [f.timestamp_utc for f in flows]
            + [c.timestamp_utc for c in corporate_actions]
            + [n.timestamp_utc for n in nav_points]
        )
        norm_start = _normalize_date_param(start_date, field_name="start_date")
        norm_end = _normalize_date_param(end_date, field_name="end_date")
        default_start = (
            min(all_ts) if all_ts else datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z")
        )
        default_end = (
            max(all_ts) if all_ts else datetime.now(timezone.utc).strftime("%Y-%m-%dT23:59:59Z")
        )
        period_start = f"{norm_start}T00:00:00Z" if norm_start else default_start
        period_end = f"{norm_end}T23:59:59Z" if norm_end else default_end
        if period_end < period_start:
            period_end = period_start

        enabled_secs = [
            "snaptrade_accounts",
            "snaptrade_holdings",
            "snaptrade_positions",
            "snaptrade_activities",
            "Transfers",
            "CorporateActions",
            "OptionEAE",
        ]

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
            ending_positions=ending_positions,
            nav_points=nav_points,
            enabled_sections=enabled_secs,
        )

    def fetch_live_ledger(
        self,
        user_id: str,
        user_secret: str,
        *,
        blinding_salt_hex: str,
        start_date: str | None = None,
        end_date: str | None = None,
        selected_account_ids: Sequence[str] | None = None,
        require_live: bool = True,
    ) -> CanonicalPortfolioLedger:
        """Fetch live read-only accounts, holdings/positions, and paginated activities via SnapTrade V1."""
        clean_user = (user_id or "").strip()
        clean_secret = (user_secret or "").strip()
        if not clean_user:
            raise SnapTradeAuthenticationError("user_id is required for live SnapTrade queries")
        if not clean_secret:
            raise SnapTradeAuthenticationError("user_secret is required for live SnapTrade queries")

        norm_start = _normalize_date_param(start_date, field_name="start_date")
        norm_end = _normalize_date_param(end_date, field_name="end_date")

        self.slot_manager.register_slot(clean_user)
        secrets_list = self._collect_secrets(clean_secret, clean_user)

        try:
            # 1. GET /api/v1/accounts
            accts_resp = self._execute_signed(
                "GET",
                "/api/v1/accounts",
                user_id=clean_user,
                user_secret=clean_secret,
            )
            accts_raw = self._decode_json_or_raise(
                accts_resp,
                api_path="/api/v1/accounts",
                extra_secrets=(clean_secret, clean_user),
            )
            accounts_list = accts_raw if isinstance(accts_raw, list) else [accts_raw]

            # 2. GET /api/v1/holdings (with fallback to per-account positions & balances if 404)
            holdings_resp = self._execute_signed(
                "GET",
                "/api/v1/holdings",
                user_id=clean_user,
                user_secret=clean_secret,
            )
            holdings_list: list[Any] = []
            fallback_positions: list[Any] = []
            fallback_balances: list[Any] = []

            if holdings_resp.status_code == 200:
                holdings_raw = self._decode_json_or_raise(
                    holdings_resp,
                    api_path="/api/v1/holdings",
                    extra_secrets=(clean_secret, clean_user),
                )
                holdings_list = holdings_raw if isinstance(holdings_raw, list) else [holdings_raw]
            elif holdings_resp.status_code == 404:
                for acct in accounts_list:
                    if not isinstance(acct, Mapping):
                        continue
                    aid = _extract_account_id(acct)
                    if not aid:
                        continue
                    safe_aid = urllib.parse.quote(aid, safe="")
                    pos_r = self._execute_signed(
                        "GET",
                        f"/api/v1/accounts/{safe_aid}/positions",
                        user_id=clean_user,
                        user_secret=clean_secret,
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
                                fallback_positions.append(p_item)

                    bal_r = self._execute_signed(
                        "GET",
                        f"/api/v1/accounts/{safe_aid}/balances",
                        user_id=clean_user,
                        user_secret=clean_secret,
                    )
                    if bal_r.status_code == 200:
                        bal_data = self._decode_json_or_raise(
                            bal_r,
                            api_path="/api/v1/accounts/[REDACTED]/balances",
                            extra_secrets=(clean_secret, clean_user, aid),
                        )
                        for b in bal_data if isinstance(bal_data, list) else [bal_data]:
                            if isinstance(b, Mapping):
                                b_item = dict(b)
                                b_item.setdefault("account_id", aid)
                                fallback_balances.append(b_item)
            else:
                self._decode_json_or_raise(
                    holdings_resp,
                    api_path="/api/v1/holdings",
                    extra_secrets=(clean_secret, clean_user),
                )

            # 3. GET /api/v1/activities (paginated up to MAX_ACTIVITIES_PAGES)
            activities_list: list[Any] = []
            offset = 0
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
                    user_id=clean_user,
                    user_secret=clean_secret,
                    extra_query_params=act_params,
                )
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
                    break
                offset += MAX_ACTIVITIES_PAGE_SIZE

            bundle_payload: dict[str, Any] = {
                "accounts": accounts_list,
                "holdings": holdings_list,
                "activities": activities_list,
            }
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
            )
        except Exception as exc:
            redacted_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_list)
            if isinstance(
                exc,
                (SnapTradeError, PaperOrSandboxAccountRejectedError, DisallowedCapabilityError),
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
        selected_account_ids: Sequence[str] | None = None,
        require_live: bool = True,
    ) -> CanonicalPortfolioLedger:
        """Read-only canonical ledger adapter entrypoint delegating to ``fetch_live_ledger``."""
        target_user = (user_id or self.user_id or "").strip()
        target_secret = (user_secret or self.user_secret or "").strip()
        return self.fetch_live_ledger(
            target_user,
            target_secret,
            blinding_salt_hex=blinding_salt_hex,
            start_date=period_start_utc[:10] if period_start_utc else None,
            end_date=period_end_utc[:10] if period_end_utc else None,
            selected_account_ids=selected_account_ids,
            require_live=require_live,
        )


__all__ = [
    "DEFAULT_SNAPTRADE_USER_AGENT",
    "MAX_SNAPTRADE_POC_SLOTS",
    "SNAPTRADE_BLOCKED_MUTATING_ENDPOINTS",
    "SNAPTRADE_LIVE_BASE_URL",
    "SignedSnapTradeRequest",
    "SnapTradeAuthenticationError",
    "SnapTradeConnectionSlot",
    "SnapTradeError",
    "SnapTradeReadOnlyAdapter",
    "SnapTradeServiceError",
    "SnapTradeSlotCapExceededError",
    "SnapTradeSlotManager",
    "build_signed_request",
    "compute_snaptrade_signature",
    "get_global_snaptrade_slot_manager",
    "is_snaptrade_env_configured",
]
