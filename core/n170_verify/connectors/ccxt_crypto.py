"""Vault-bound read-only crypto exchange adapter with fail-closed key scope introspection.

Supports Binance, Coinbase Advanced Trade, Kraken, and Bybit v5 with mandatory
pre-flight API key permission introspection BEFORE any balance, fill, or ledger
request is issued. Community CCXT MCP servers are rejected by policy; when an
in-process ``ccxt`` exchange instance is supplied, mutating methods
(``create_order``, ``cancel_order``, ``edit_order``, ``withdraw``, ``transfer``)
are monkeypatched to raise ``DisallowedCapabilityError``.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import ipaddress
import json
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from n170_verify.connectors.mcp_allowlist_firewall import redact_sensitive_text
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    CanonicalPortfolioLedger,
    EnvironmentTier,
    FlowKind,
    NormalizedFlow,
    NormalizedNavPoint,
    NormalizedPosition,
    NormalizedTrade,
    OriginAssurance,
    ProviderApprovalState,
    ReadOnlyBrokerAdapter,
    ReadOnlyCapabilityViolationError,
    compute_blinded_account_tag,
    parse_utc_timestamp,
)


class MutatingCredentialRejectedError(ReadOnlyCapabilityViolationError):
    """Raised when an API key grants trading, margin, futures, transfer, or withdrawal scope."""


class DisallowedCapabilityError(ReadOnlyCapabilityViolationError):
    """Raised when a structurally forbidden mutating method or endpoint is invoked."""


class PaperOrSandboxAccountRejectedError(ReadOnlyCapabilityViolationError):
    """Raised when a paper, demo, sandbox, or testnet endpoint/account is presented for live verification."""


class UnsupportedScraperPolicyError(ReadOnlyCapabilityViolationError):
    """Raised when unofficial password/cookie/TOTP scraping credentials are supplied."""


class ProviderApprovalRequiredError(ReadOnlyCapabilityViolationError):
    """Raised when a hosted broker connector is gated pending commercial provider approval."""


def validate_ssrf_safe_https_url(
    url: str,
    *,
    allowed_hosts: Iterable[str] | None = None,
    require_live: bool = True,
    label: str = "connector",
) -> str:
    """Enforce HTTPS, block URL userinfo/IP literals/localhost/SSRF targets, and pin live hosts."""
    cleaned = (url or "").strip().rstrip("/")
    if not cleaned:
        raise PaperOrSandboxAccountRejectedError(f"{label} base_url must be a non-empty https:// URL")
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in cleaned):
        raise PaperOrSandboxAccountRejectedError(
            f"{label} base_url contains disallowed whitespace or control characters"
        )

    parsed = urllib.parse.urlsplit(cleaned)
    if parsed.scheme.lower() != "https":
        raise PaperOrSandboxAccountRejectedError(f"{label} adapter requires https:// transport")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise PaperOrSandboxAccountRejectedError(
            f"{label} base_url must not contain embedded URL credentials"
        )
    if parsed.query or parsed.fragment:
        raise PaperOrSandboxAccountRejectedError(
            f"{label} base_url must not contain query parameters or fragments"
        )

    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise PaperOrSandboxAccountRejectedError(f"{label} base_url is missing a valid hostname")

    if (
        host in {"localhost", "metadata.google.internal", "instance-data"}
        or host.endswith((".localhost", ".local", ".internal", ".home.arpa"))
        or host.startswith("0x")
        or host.replace(".", "").isdigit()
    ):
        raise PaperOrSandboxAccountRejectedError(
            f"{label} SSRF/local/numeric host {host!r} is forbidden"
        )

    ip_candidate = host.split("%", 1)[0]
    try:
        ipaddress.ip_address(ip_candidate)
        is_ip_literal = True
    except ValueError:
        is_ip_literal = False
    if is_ip_literal:
        raise PaperOrSandboxAccountRejectedError(
            f"{label} IP-literal host {host!r} is forbidden; pinned DNS hostname required"
        )

    if require_live:
        lower_path = parsed.path.lower()
        if any(tok in host or tok in lower_path for tok in ("sandbox", "demo", "testnet", "paper")):
            raise PaperOrSandboxAccountRejectedError(
                f"{label} paper/demo/sandbox/testnet endpoint {host!r} rejected for live verification"
            )
        if allowed_hosts is not None:
            allowed_set = {h.strip().lower().rstrip(".") for h in allowed_hosts if h.strip()}
            if host not in allowed_set:
                raise PaperOrSandboxAccountRejectedError(
                    f"{label} host {host!r} rejected: only official live endpoint(s) {sorted(allowed_set)} permitted"
                )

    return cleaned


class ConnectorHttpError(RuntimeError):
    """Secret-redacted HTTP transport error."""

    def __init__(self, status_code: int, message: str, *, headers: Mapping[str, str] | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.headers = dict(headers or {})


@dataclass(frozen=True, slots=True)
class HttpExchangeResponse:
    """Normalized HTTP response returned by stdlib, ``httpx``, or mock transports."""

    status_code: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))

    def text(self, encoding: str = "utf-8") -> str:
        return self.body.decode(encoding, errors="replace")


HttpTransportCallable = Callable[
    [str, str, Mapping[str, str], bytes | None],
    HttpExchangeResponse | tuple[int, Mapping[str, str], bytes | str | Mapping[str, Any] | list[Any]],
]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject all HTTP 3xx redirects on pinned live brokerage endpoints."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        hdrs: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        del msg, newurl
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"HTTP {code} redirect forbidden for pinned live broker endpoint",
            hdrs,
            fp,
        )


def invoke_http_transport(
    transport: HttpTransportCallable | Any | None,
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    timeout_seconds: float = 30.0,
    extra_secrets: Sequence[str] = (),
) -> HttpExchangeResponse:
    """Execute an HTTP request through ``urllib``, ``httpx.Client``, or a test callable."""
    hdrs = {str(k): str(v) for k, v in (headers or {}).items()}
    secrets_list = list(extra_secrets) + [
        v for k, v in hdrs.items() if k.lower() in {
            "authorization",
            "apca-api-key-id",
            "apca-api-secret-key",
            "x-mbx-apikey",
            "cb-access-key",
            "cb-access-sign",
            "cb-access-passphrase",
            "api-key",
            "api-sign",
            "x-bapi-api-key",
            "x-bapi-sign",
        }
    ]

    try:
        if transport is None:
            req = urllib.request.Request(url=url, data=body, headers=hdrs, method=method.upper())
            opener = urllib.request.build_opener(_NoRedirectHandler())
            try:
                with opener.open(req, timeout=timeout_seconds) as resp:
                    status_int = int(resp.status)
                    if 300 <= status_int < 400:
                        raise ConnectorHttpError(
                            status_int,
                            f"HTTP {status_int} redirect forbidden for pinned live broker endpoint",
                        )
                    resp_hdrs = {k.lower(): v for k, v in resp.headers.items()}
                    return HttpExchangeResponse(
                        status_code=status_int,
                        headers=resp_hdrs,
                        body=resp.read(),
                    )
            except urllib.error.HTTPError as http_exc:
                err_body = http_exc.read() if http_exc.fp is not None else b""
                resp_hdrs = (
                    {k.lower(): v for k, v in http_exc.headers.items()}
                    if http_exc.headers is not None
                    else {}
                )
                code_int = int(http_exc.code)
                if 300 <= code_int < 400:
                    raise ConnectorHttpError(
                        code_int,
                        f"HTTP {code_int} redirect forbidden for pinned live broker endpoint",
                        headers=resp_hdrs,
                    ) from None
                return HttpExchangeResponse(
                    status_code=code_int,
                    headers=resp_hdrs,
                    body=err_body,
                )

        if hasattr(transport, "request") and callable(transport.request):
            # Seamless httpx.Client / requests.Session compatibility (redirects disabled).
            import inspect as _inspect

            kwargs: dict[str, Any] = {"headers": hdrs}
            if body is not None:
                kwargs["content"] = body
            try:
                req_params = _inspect.signature(transport.request).parameters
                if "follow_redirects" in req_params:
                    kwargs["follow_redirects"] = False
                elif "allow_redirects" in req_params:
                    kwargs["allow_redirects"] = False
            except (TypeError, ValueError):
                pass
            raw_resp = transport.request(method.upper(), url, **kwargs)
            status_int = int(raw_resp.status_code)
            resp_hdrs = {str(k).lower(): str(v) for k, v in raw_resp.headers.items()}
            if bool(getattr(raw_resp, "is_redirect", False)) or (300 <= status_int < 400):
                raise ConnectorHttpError(
                    status_int,
                    f"HTTP {status_int} redirect forbidden for pinned live broker endpoint",
                    headers=resp_hdrs,
                )
            if hasattr(raw_resp, "content"):
                raw_bytes = bytes(raw_resp.content)
            elif hasattr(raw_resp, "body"):
                raw_bytes = bytes(raw_resp.body)
            else:
                raw_bytes = str(raw_resp.text).encode("utf-8")
            return HttpExchangeResponse(
                status_code=status_int,
                headers=resp_hdrs,
                body=raw_bytes,
            )

        if callable(transport):
            raw_out = transport(method.upper(), url, hdrs, body)
            if isinstance(raw_out, HttpExchangeResponse):
                if 300 <= int(raw_out.status_code) < 400:
                    raise ConnectorHttpError(
                        int(raw_out.status_code),
                        f"HTTP {int(raw_out.status_code)} redirect forbidden for pinned live broker endpoint",
                        headers=raw_out.headers,
                    )
                return raw_out
            status, out_hdrs, out_payload = raw_out
            status_int = int(status)
            norm_hdrs = {str(k).lower(): str(v) for k, v in (out_hdrs or {}).items()}
            if 300 <= status_int < 400:
                raise ConnectorHttpError(
                    status_int,
                    f"HTTP {status_int} redirect forbidden for pinned live broker endpoint",
                    headers=norm_hdrs,
                )
            if isinstance(out_payload, bytes):
                payload_bytes = out_payload
            elif isinstance(out_payload, str):
                payload_bytes = out_payload.encode("utf-8")
            else:
                payload_bytes = json.dumps(out_payload, separators=(",", ":")).encode("utf-8")
            return HttpExchangeResponse(
                status_code=status_int,
                headers=norm_hdrs,
                body=payload_bytes,
            )
    except Exception as exc:
        if isinstance(exc, ReadOnlyCapabilityViolationError):
            raise
        if isinstance(exc, ConnectorHttpError):
            safe_err = redact_sensitive_text(str(exc), secrets_list)
            raise ConnectorHttpError(exc.status_code, safe_err, headers=exc.headers) from None
        safe_url = redact_sensitive_text(url, secrets_list)
        safe_err = redact_sensitive_text(str(exc), secrets_list)
        raise ConnectorHttpError(0, f"HTTP {method.upper()} {safe_url} failed: {safe_err}") from None

    raise TypeError(f"Unsupported HTTP transport object: {type(transport).__name__}")


_MONKEYPATCHED_CCXT_METHODS: tuple[str, ...] = (
    "create_order",
    "cancel_order",
    "cancel_all_orders",
    "edit_order",
    "withdraw",
    "transfer",
    "create_market_order",
    "create_limit_order",
    "create_stop_order",
    "set_leverage",
    "set_margin_mode",
)


def harden_ccxt_exchange_instance(exchange: Any, *, require_live: bool = True) -> Any:
    """Monkeypatch mutating methods on a ``ccxt`` exchange instance to raise ``DisallowedCapabilityError``."""
    if exchange is None:
        raise ValueError("exchange instance cannot be None")

    if require_live:
        if bool(getattr(exchange, "sandbox", False)) or bool(getattr(exchange, "testnet", False)):
            raise PaperOrSandboxAccountRejectedError(
                "CCXT sandbox/testnet mode is rejected for live verification"
            )
        urls = getattr(exchange, "urls", None)
        if isinstance(urls, Mapping):
            api_val = urls.get("api")
            api_str = json.dumps(api_val).lower() if not isinstance(api_val, str) else api_val.lower()
            if any(tok in api_str for tok in ("testnet", "sandbox", "paper", "demo")):
                raise PaperOrSandboxAccountRejectedError(
                    "CCXT exchange instance configured against sandbox/testnet endpoint"
                )

    def _make_blocker(method_name: str) -> Callable[..., Any]:
        def _blocked(*_args: Any, **_kwargs: Any) -> Any:
            raise DisallowedCapabilityError(
                f"CCXT mutating method {method_name!r} is structurally disabled on N170 read-only adapter"
            )

        return _blocked

    for method_name in _MONKEYPATCHED_CCXT_METHODS:
        setattr(exchange, method_name, _make_blocker(method_name))

    return exchange


def split_time_windows_under_90d(
    start_utc: str | datetime,
    end_utc: str | datetime,
    *,
    max_window_days: int = 89,
) -> list[tuple[datetime, datetime]]:
    """Partition ``[start_utc, end_utc]`` into contiguous windows strictly ``< 90`` days for Binance."""
    if not (1 <= max_window_days < 90):
        raise ValueError("max_window_days must be in [1, 89] (< 90 days)")
    start_dt = parse_utc_timestamp(start_utc, field_name="start_utc")
    end_dt = parse_utc_timestamp(end_utc, field_name="end_utc")
    if end_dt < start_dt:
        raise ValueError("end_utc must be >= start_utc")
    if start_dt == end_dt:
        return [(start_dt, end_dt)]

    step = timedelta(days=max_window_days)
    windows: list[tuple[datetime, datetime]] = []
    cursor = start_dt
    while cursor < end_dt:
        nxt = min(cursor + step, end_dt)
        windows.append((cursor, nxt))
        if nxt >= end_dt:
            break
        cursor = nxt + timedelta(milliseconds=1)
    return windows


@dataclass(slots=True)
class KrakenDecayRateLimiter:
    """Tracks Kraken private API ledger/trade counter (``+4`` per ``Ledgers`` call, max ``20``)."""

    max_counter: float = 20.0
    ledger_cost: float = 4.0
    decay_per_second: float = 0.5
    now_fn: Callable[[], float] = time.monotonic
    sleep_fn: Callable[[float], None] = time.sleep
    current_counter: float = 0.0
    last_updated: float | None = None
    recorded_sleeps: list[float] = field(default_factory=list)

    def acquire(self, cost: float) -> None:
        if cost <= 0:
            return
        if cost > self.max_counter:
            raise ValueError(f"Call cost {cost} exceeds max_counter {self.max_counter}")
        now = self.now_fn()
        if self.last_updated is not None:
            elapsed = max(0.0, now - self.last_updated)
            self.current_counter = max(0.0, self.current_counter - elapsed * self.decay_per_second)
        self.last_updated = now

        if self.current_counter + cost > self.max_counter:
            needed_decay = (self.current_counter + cost) - self.max_counter
            wait_s = needed_decay / self.decay_per_second
            self.recorded_sleeps.append(wait_s)
            self.sleep_fn(wait_s)
            after_sleep = self.now_fn()
            actual_elapsed = max(wait_s, after_sleep - now)
            self.current_counter = max(
                0.0, self.current_counter - actual_elapsed * self.decay_per_second
            )
            self.last_updated = after_sleep

        self.current_counter += cost


@dataclass(frozen=True, slots=True)
class KeyScopeIntrospectionResult:
    """Verified read-only credential scope summary returned prior to any data fetch."""

    exchange_id: str
    read_only_verified: bool
    account_scope: AccountScope
    enumerated_subaccount_ids: tuple[str, ...]
    raw_permission_summary: dict[str, Any]


SUPPORTED_CRYPTO_EXCHANGES: dict[str, str] = {
    "binance": "https://api.binance.com",
    "coinbase": "https://api.coinbase.com",
    "coinbaseadvanced": "https://api.coinbase.com",
    "coinbase_advanced": "https://api.coinbase.com",
    "kraken": "https://api.kraken.com",
    "bybit": "https://api.bybit.com",
}

_CANONICAL_EXCHANGE_IDS: dict[str, str] = {
    "binance": "binance",
    "coinbase": "coinbase",
    "coinbaseadvanced": "coinbase",
    "coinbase_advanced": "coinbase",
    "kraken": "kraken",
    "bybit": "bybit",
}

_KRAKEN_FORBIDDEN_SCOPE_TOKENS: frozenset[str] = frozenset(
    {
        "orders",
        "order",
        "add_order",
        "create_order",
        "edit_order",
        "modify_order",
        "cancel_order",
        "batch_order",
        "withdraw",
        "withdraw_funds",
        "withdrawal",
        "transfer",
        "transfer_funds",
        "stake",
        "earn",
        "trade",
    }
)
_KRAKEN_READ_SCOPE_TOKENS: frozenset[str] = frozenset(
    {
        "funds",
        "query_funds",
        "balance",
        "ledgers",
        "query_ledgers",
        "trades",
        "query_open_orders_trades",
        "query_closed_orders_trades",
        "read",
        "export",
    }
)


def deduplicate_coinbase_fills_by_entry_id(
    raw_fills: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Key and deduplicate Coinbase Advanced Trade fills strictly by unique ``entry_id``.

    Coinbase ``trade_id`` is NOT unique across partial legs or post-trade fee/price
    adjustments. Distinct ``entry_id`` rows sharing a ``trade_id`` are preserved,
    while duplicate/adjusted rows sharing an ``entry_id`` (or explicitly superseding
    ``previous_entry_id`` / ``replaces_entry_id``) are deduplicated deterministically.
    """
    by_entry_id: dict[str, dict[str, Any]] = {}
    order_keys: list[str] = []

    for idx, raw in enumerate(raw_fills):
        if not isinstance(raw, Mapping):
            raise ValueError(f"Coinbase fill[{idx}] must be a mapping")
        entry_id_raw = raw.get("entry_id")
        if not isinstance(entry_id_raw, str) or not entry_id_raw.strip():
            raise ValueError(
                f"Coinbase fill[{idx}] missing mandatory unique entry_id (never fall back to trade_id)"
            )
        entry_id = entry_id_raw.strip()
        superseded = raw.get("replaces_entry_id") or raw.get("previous_entry_id")
        if isinstance(superseded, str) and superseded.strip() in by_entry_id:
            old_key = superseded.strip()
            del by_entry_id[old_key]
            order_keys = [k for k in order_keys if k != old_key]

        if entry_id not in by_entry_id:
            order_keys.append(entry_id)
        by_entry_id[entry_id] = dict(raw)

    return [by_entry_id[k] for k in order_keys]


class CcxtExchangeReadOnlyAdapter(ReadOnlyBrokerAdapter):
    """Vault-bound read-only crypto adapter with mandatory pre-fetch key scope introspection."""

    broker_id = "ccxt_crypto"
    display_name = "Crypto Exchange Read-Only Vault Adapter"
    approval_state = ProviderApprovalState.USER_KEY_SELF_ATTESTED
    default_origin_assurance = OriginAssurance.OPERATOR_RETRIEVED
    supports_subaccount_enumeration = True
    allowed_capabilities = (
        "verify_key_permissions",
        "read_account_profile",
        "list_subaccounts",
        "read_balances",
        "fetch_fills",
        "fetch_cash_flows",
        "read_ledgers",
    )

    def __init__(
        self,
        exchange_id: str,
        *,
        api_key: str = "vault-bound-key",
        api_secret: str = "vault-bound-secret",
        approval_state: ProviderApprovalState | str | None = None,
        base_url: str | None = None,
        ccxt_exchange: Any | None = None,
        http_transport: HttpTransportCallable | Any | None = None,
        require_live: bool = True,
        now_fn: Callable[[], float] = time.time,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        if not isinstance(exchange_id, str) or exchange_id.strip().lower() not in _CANONICAL_EXCHANGE_IDS:
            raise MutatingCredentialRejectedError(
                f"Unsupported crypto exchange {exchange_id!r}: fail-closed policy permits only "
                f"{sorted(set(_CANONICAL_EXCHANGE_IDS.values()))} with verified key scope introspection"
            )
        canonical_ex = _CANONICAL_EXCHANGE_IDS[exchange_id.strip().lower()]
        self.exchange_id = canonical_ex
        self.broker_id = canonical_ex
        self.display_name = f"{canonical_ex.capitalize()} Read-Only Adapter"
        self.supports_subaccount_enumeration = canonical_ex in {"coinbase", "bybit"}
        if approval_state is not None:
            self.approval_state = ProviderApprovalState(approval_state)
        super().__init__()

        default_live_url = SUPPORTED_CRYPTO_EXCHANGES[canonical_ex]
        expected_live_host = urllib.parse.urlsplit(default_live_url).hostname or ""
        resolved_base = validate_ssrf_safe_https_url(
            base_url or default_live_url,
            allowed_hosts={expected_live_host},
            require_live=require_live,
            label=canonical_ex,
        )

        if ccxt_exchange is not None:
            harden_ccxt_exchange_instance(ccxt_exchange, require_live=require_live)

        self._api_key = api_key
        self._api_secret = api_secret
        self._base_url = resolved_base
        self._ccxt = ccxt_exchange
        self._transport = http_transport
        self._require_live = require_live
        self._now_fn = now_fn
        self._sleep_fn = sleep_fn
        self.recorded_sleeps: list[float] = []
        self.kraken_limiter = KrakenDecayRateLimiter(
            now_fn=now_fn,
            sleep_fn=self._record_and_sleep,
        )
        self._raw_transcript_chunks: list[bytes] = []

    def _record_and_sleep(self, seconds: float) -> None:
        self.recorded_sleeps.append(seconds)
        self._sleep_fn(seconds)

    def _secrets(self) -> tuple[str, ...]:
        return (self._api_key, self._api_secret)

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        form_body: Mapping[str, Any] | None = None,
        signed: bool = True,
    ) -> Any:
        """Issue a signed read-only REST request with rate-limit safety and secret redaction."""
        query_dict = {k: v for k, v in (params or {}).items() if v is not None}
        headers: dict[str, str] = {"Accept": "application/json"}
        body_bytes: bytes | None = None

        if self.exchange_id == "binance":
            if signed:
                query_dict.setdefault("timestamp", int(self._now_fn() * 1000))
                qs = urllib.parse.urlencode(query_dict)
                sig = hmac.new(
                    self._api_secret.encode("utf-8"),
                    qs.encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
                qs = f"{qs}&signature={sig}"
            else:
                qs = urllib.parse.urlencode(query_dict)
            url = f"{self._base_url}{path}" + (f"?{qs}" if qs else "")
            headers["X-MBX-APIKEY"] = self._api_key
        elif self.exchange_id == "coinbase":
            qs = urllib.parse.urlencode(query_dict)
            url = f"{self._base_url}{path}" + (f"?{qs}" if qs else "")
            headers["Authorization"] = f"Bearer {self._api_key}"
        elif self.exchange_id == "kraken":
            nonce = str(int(self._now_fn() * 1000))
            post_data = {"nonce": nonce, **(form_body or {}), **query_dict}
            encoded_post = urllib.parse.urlencode(post_data)
            body_bytes = encoded_post.encode("utf-8")
            url = f"{self._base_url}{path}"
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["API-Key"] = self._api_key
            try:
                secret_decoded = base64.b64decode(self._api_secret)
            except Exception:
                secret_decoded = self._api_secret.encode("utf-8")
            sha256_digest = hashlib.sha256((nonce + encoded_post).encode("utf-8")).digest()
            mac = hmac.new(secret_decoded, path.encode("utf-8") + sha256_digest, hashlib.sha512)
            headers["API-Sign"] = base64.b64encode(mac.digest()).decode("ascii")
        elif self.exchange_id == "bybit":
            qs = urllib.parse.urlencode(query_dict)
            ts_ms = str(int(self._now_fn() * 1000))
            recv_window = "5000"
            sign_payload = f"{ts_ms}{self._api_key}{recv_window}{qs}"
            sig = hmac.digest(
                self._api_secret.encode("utf-8"),
                sign_payload.encode("utf-8"),
                "sha256",
            ).hex()
            url = f"{self._base_url}{path}" + (f"?{qs}" if qs else "")
            headers["X-BAPI-API-KEY"] = self._api_key
            headers["X-BAPI-TIMESTAMP"] = ts_ms
            headers["X-BAPI-RECV-WINDOW"] = recv_window
            headers["X-BAPI-SIGN"] = sig
        else:  # pragma: no cover
            raise MutatingCredentialRejectedError(f"Unsupported exchange {self.exchange_id!r}")

        # Binance HTTP 429 backoff BEFORE triggering HTTP 418 IP ban.
        max_attempts = 2
        for attempt in range(max_attempts):
            resp = invoke_http_transport(
                self._transport,
                method,
                url,
                headers=headers,
                body=body_bytes,
                extra_secrets=self._secrets(),
            )
            if resp.status_code == 418:
                raise ConnectorHttpError(
                    418,
                    "Binance HTTP 418 IP auto-ban detected; halting immediately to prevent escalation",
                    headers=resp.headers,
                )
            if resp.status_code == 429 and attempt == 0:
                retry_after_raw = resp.headers.get("retry-after", "5")
                try:
                    backoff_s = max(1.0, min(float(retry_after_raw), 60.0))
                except ValueError:
                    backoff_s = 5.0
                self._record_and_sleep(backoff_s)
                continue
            if resp.status_code < 200 or resp.status_code >= 300:
                safe_body = redact_sensitive_text(resp.text()[:240], self._secrets())
                safe_path = redact_sensitive_text(path, self._secrets())
                raise ConnectorHttpError(
                    resp.status_code,
                    f"{self.exchange_id} {method.upper()} {safe_path} returned HTTP {resp.status_code}: {safe_body}",
                    headers=resp.headers,
                )
            self._raw_transcript_chunks.append(resp.body)
            return resp.json()

        raise ConnectorHttpError(429, f"{self.exchange_id} rate limit persisted after Retry-After backoff")

    def verify_read_only_key_scope(
        self,
        *,
        selected_subaccounts: Sequence[str] | None = None,
    ) -> KeyScopeIntrospectionResult:
        """Programmatically verify that the API key is strictly read-only (fail-closed)."""
        if self.exchange_id == "binance":
            return self._verify_binance_scope()
        if self.exchange_id == "coinbase":
            return self._verify_coinbase_scope(selected_subaccounts=selected_subaccounts)
        if self.exchange_id == "kraken":
            return self._verify_kraken_scope()
        if self.exchange_id == "bybit":
            return self._verify_bybit_scope(selected_subaccounts=selected_subaccounts)
        raise MutatingCredentialRejectedError(f"Unsupported exchange {self.exchange_id!r}")

    def _verify_binance_scope(self) -> KeyScopeIntrospectionResult:
        try:
            data = self._request_json("GET", "/sapi/v1/account/apiRestrictions")
        except Exception as exc:
            raise MutatingCredentialRejectedError(
                f"Binance key permission introspection failed closed: "
                f"{redact_sensitive_text(str(exc), self._secrets())}"
            ) from None

        if not isinstance(data, Mapping):
            raise MutatingCredentialRejectedError(
                "Binance /sapi/v1/account/apiRestrictions returned non-object payload"
            )

        required_false_flags = (
            "enableWithdrawals",
            "enableInternalTransfer",
            "permitsUniversalTransfer",
            "enableSpotAndMarginTrading",
            "enableFutures",
            "enableMargin",
        )
        optional_false_flags = (
            "enablePortfolioMarginTrading",
            "enableVanillaOptions",
        )
        violations: list[str] = []
        for flag in required_false_flags:
            if flag not in data or data[flag] is not False:
                violations.append(f"{flag}={data.get(flag)!r}")
        for flag in optional_false_flags:
            if flag in data and data[flag] is not False:
                violations.append(f"{flag}={data.get(flag)!r}")

        if data.get("enableReading") is False:
            violations.append("enableReading=False")

        if violations:
            raise MutatingCredentialRejectedError(
                "Binance API key rejected: mutating or missing restriction flags: "
                + ", ".join(violations)
            )

        return KeyScopeIntrospectionResult(
            exchange_id="binance",
            read_only_verified=True,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
            enumerated_subaccount_ids=(),
            raw_permission_summary={k: bool(data.get(k)) for k in required_false_flags},
        )

    def _verify_coinbase_scope(
        self,
        *,
        selected_subaccounts: Sequence[str] | None = None,
    ) -> KeyScopeIntrospectionResult:
        try:
            perms = self._request_json("GET", "/api/v3/brokerage/key_permissions")
        except Exception as exc:
            raise MutatingCredentialRejectedError(
                f"Coinbase key_permissions introspection failed closed: "
                f"{redact_sensitive_text(str(exc), self._secrets())}"
            ) from None

        if not isinstance(perms, Mapping):
            raise MutatingCredentialRejectedError(
                "Coinbase /api/v3/brokerage/key_permissions returned non-object payload"
            )

        can_view = perms.get("can_view")
        can_trade = perms.get("can_trade")
        can_transfer = perms.get("can_transfer")
        if can_view is not True or can_trade is not False or can_transfer is not False:
            raise MutatingCredentialRejectedError(
                f"Coinbase API key rejected: expected can_view=True, can_trade=False, "
                f"can_transfer=False (got can_view={can_view!r}, can_trade={can_trade!r}, "
                f"can_transfer={can_transfer!r})"
            )

        # Enumerate all /api/v3/brokerage/accounts portfolios across pages.
        portfolio_ids: list[str] = []
        cursor: str | None = None
        for _ in range(50):
            params: dict[str, Any] = {"limit": 250}
            if cursor:
                params["cursor"] = cursor
            acct_page = self._request_json(
                "GET", "/api/v3/brokerage/accounts", params=params, signed=False
            )
            if not isinstance(acct_page, Mapping):
                break
            for acct in acct_page.get("accounts", []):
                if isinstance(acct, Mapping):
                    pid = str(
                        acct.get("retail_portfolio_id") or acct.get("uuid") or ""
                    ).strip()
                    if pid and pid not in portfolio_ids:
                        portfolio_ids.append(pid)
            has_next = bool(acct_page.get("has_next"))
            next_cursor = str(acct_page.get("cursor") or "").strip()
            if not has_next or not next_cursor:
                break
            cursor = next_cursor

        if selected_subaccounts is not None and portfolio_ids:
            selected_set = {s.strip() for s in selected_subaccounts if s.strip()}
            scope = (
                AccountScope.ALL_ENUMERATED_SUBACCOUNTS
                if selected_set == set(portfolio_ids)
                else AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED
            )
        elif portfolio_ids:
            scope = AccountScope.ALL_ENUMERATED_SUBACCOUNTS
        else:
            scope = AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED

        return KeyScopeIntrospectionResult(
            exchange_id="coinbase",
            read_only_verified=True,
            account_scope=scope,
            enumerated_subaccount_ids=tuple(portfolio_ids),
            raw_permission_summary={
                "can_view": True,
                "can_trade": False,
                "can_transfer": False,
            },
        )

    def _verify_kraken_scope(self) -> KeyScopeIntrospectionResult:
        try:
            resp = self._request_json("POST", "/0/private/GetApiKeyInfo")
        except Exception as exc:
            raise MutatingCredentialRejectedError(
                f"Kraken GetApiKeyInfo introspection failed closed: "
                f"{redact_sensitive_text(str(exc), self._secrets())}"
            ) from None

        if not isinstance(resp, Mapping) or resp.get("error"):
            raise MutatingCredentialRejectedError(
                "Kraken GetApiKeyInfo returned error or invalid payload"
            )

        result = resp.get("result")
        if not isinstance(result, Mapping) or not result:
            raise MutatingCredentialRejectedError("Kraken GetApiKeyInfo missing result payload")

        perms_raw = result.get("permissions", result.get("scopes", result))
        enabled_scopes: set[str] = set()
        if isinstance(perms_raw, Mapping):
            for k, v in perms_raw.items():
                if bool(v) and str(k).lower() not in {"id", "name", "description", "created", "modified"}:
                    enabled_scopes.add(str(k).strip().lower())
        elif isinstance(perms_raw, (list, tuple)):
            for item in perms_raw:
                if isinstance(item, str) and item.strip():
                    enabled_scopes.add(item.strip().lower())

        if not enabled_scopes:
            raise MutatingCredentialRejectedError(
                "Kraken API key rejected: no verifiable read scopes returned by GetApiKeyInfo"
            )

        mutating_hits: list[str] = []
        has_read = False
        for scope in sorted(enabled_scopes):
            tokens = set(scope.replace("-", "_").replace(":", "_").split("_")) | {scope}
            # Note: Kraken names read-only trade history "query_open_orders_trades" / "query_closed_orders_trades"
            if scope in {"query_open_orders_trades", "query_closed_orders_trades", "orders_and_trades_read"}:
                has_read = True
                continue
            if tokens & _KRAKEN_FORBIDDEN_SCOPE_TOKENS:
                mutating_hits.append(scope)
            if tokens & _KRAKEN_READ_SCOPE_TOKENS:
                has_read = True

        if mutating_hits or not has_read:
            raise MutatingCredentialRejectedError(
                f"Kraken API key rejected: mutating scopes={mutating_hits}, has_read={has_read}"
            )

        return KeyScopeIntrospectionResult(
            exchange_id="kraken",
            read_only_verified=True,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
            enumerated_subaccount_ids=(),
            raw_permission_summary={"enabled_scopes": sorted(enabled_scopes)},
        )

    def _verify_bybit_scope(
        self,
        *,
        selected_subaccounts: Sequence[str] | None = None,
    ) -> KeyScopeIntrospectionResult:
        try:
            resp = self._request_json("GET", "/v5/user/query-api")
        except Exception as exc:
            raise MutatingCredentialRejectedError(
                f"Bybit /v5/user/query-api introspection failed closed: "
                f"{redact_sensitive_text(str(exc), self._secrets())}"
            ) from None

        if not isinstance(resp, Mapping) or resp.get("retCode", 0) != 0:
            raise MutatingCredentialRejectedError("Bybit /v5/user/query-api returned non-zero retCode")

        result = resp.get("result")
        if not isinstance(result, Mapping):
            raise MutatingCredentialRejectedError("Bybit /v5/user/query-api missing result object")

        read_only_flag = result.get("readOnly")
        if isinstance(read_only_flag, bool) or read_only_flag != 1:
            raise MutatingCredentialRejectedError(
                f"Bybit API key rejected: expected readOnly == 1 (got {read_only_flag!r})"
            )

        permissions = result.get("permissions", {})
        if isinstance(permissions, Mapping):
            forbidden_bybit_perms = {
                "order",
                "position",
                "accounttransfer",
                "submembertransfer",
                "withdraw",
                "derivatives",
            }
            bad_perms: list[str] = []
            for group, entries in permissions.items():
                if isinstance(entries, list):
                    for p in entries:
                        if str(p).strip().lower() in forbidden_bybit_perms and group != "SpotRead":
                            bad_perms.append(f"{group}:{p}")
            if bad_perms:
                raise MutatingCredentialRejectedError(
                    f"Bybit API key rejected due to mutating permission entries: {bad_perms}"
                )

        master_uid = str(result.get("userID") or result.get("uid") or "master").strip()
        sub_resp = self._request_json("GET", "/v5/user/query-sub-members")
        sub_uids: list[str] = []
        if isinstance(sub_resp, Mapping) and sub_resp.get("retCode", 0) == 0:
            sub_res = sub_resp.get("result") or {}
            if isinstance(sub_res, Mapping):
                for member in sub_res.get("subMembers", []):
                    if isinstance(member, Mapping) and member.get("uid") is not None:
                        sub_uids.append(str(member["uid"]).strip())

        all_uids = (master_uid, *sub_uids)
        if selected_subaccounts is None:
            scope = AccountScope.ALL_ENUMERATED_SUBACCOUNTS
        else:
            sel = {str(x).strip() for x in selected_subaccounts if str(x).strip()}
            scope = (
                AccountScope.ALL_ENUMERATED_SUBACCOUNTS
                if sel == set(all_uids)
                else AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED
            )

        return KeyScopeIntrospectionResult(
            exchange_id="bybit",
            read_only_verified=True,
            account_scope=scope,
            enumerated_subaccount_ids=all_uids,
            raw_permission_summary={"readOnly": 1, "enumerated_uids": len(all_uids)},
        )

    def fetch_canonical_ledger(
        self,
        *,
        blinding_salt_hex: str,
        period_start_utc: str,
        period_end_utc: str,
        base_currency: str = "USD",
        selected_subaccounts: Sequence[str] | None = None,
        symbols: Sequence[str] = ("BTCUSDT",),
    ) -> CanonicalPortfolioLedger:
        """Verify read-only key scope FIRST, then fetch normalized crypto ledger."""
        self._raw_transcript_chunks.clear()
        scope_info = self.verify_read_only_key_scope(selected_subaccounts=selected_subaccounts)

        if self.exchange_id == "binance":
            return self._fetch_binance_ledger(
                scope_info=scope_info,
                blinding_salt_hex=blinding_salt_hex,
                period_start_utc=period_start_utc,
                period_end_utc=period_end_utc,
                base_currency=base_currency,
                symbols=symbols,
            )
        if self.exchange_id == "coinbase":
            return self._fetch_coinbase_ledger(
                scope_info=scope_info,
                blinding_salt_hex=blinding_salt_hex,
                period_start_utc=period_start_utc,
                period_end_utc=period_end_utc,
                base_currency=base_currency,
                selected_subaccounts=selected_subaccounts,
            )
        if self.exchange_id == "kraken":
            return self._fetch_kraken_ledger(
                scope_info=scope_info,
                blinding_salt_hex=blinding_salt_hex,
                period_start_utc=period_start_utc,
                period_end_utc=period_end_utc,
                base_currency=base_currency,
            )
        return self._fetch_bybit_ledger(
            scope_info=scope_info,
            blinding_salt_hex=blinding_salt_hex,
            period_start_utc=period_start_utc,
            period_end_utc=period_end_utc,
            base_currency=base_currency,
            selected_subaccounts=selected_subaccounts,
        )

    def _fetch_binance_ledger(
        self,
        *,
        scope_info: KeyScopeIntrospectionResult,
        blinding_salt_hex: str,
        period_start_utc: str,
        period_end_utc: str,
        base_currency: str,
        symbols: Sequence[str],
    ) -> CanonicalPortfolioLedger:
        acct = self._request_json("GET", "/api/v3/account")
        raw_acct_id = str(acct.get("uid") or "binance-spot-primary")
        positions: list[NormalizedPosition] = []
        nav_total = 0.0
        for bal in acct.get("balances", []):
            free_q = float(bal.get("free", 0.0))
            locked_q = float(bal.get("locked", 0.0))
            qty = free_q + locked_q
            if qty <= 0.0:
                continue
            asset = str(bal.get("asset", "USD")).upper()
            val_usd = float(bal.get("usdValuation", qty if asset in {"USD", "USDT", "USDC"} else 0.0))
            nav_total += val_usd
            positions.append(
                NormalizedPosition(
                    prior_period_or_ending="ending",
                    symbol=asset,
                    asset_class=AssetClass.CASH if asset in {"USD", "EUR"} else AssetClass.CRYPTO_SPOT,
                    quantity=qty,
                    cost_basis=val_usd,
                    market_value=val_usd,
                    currency=base_currency,
                )
            )

        flows: list[NormalizedFlow] = []
        for win_start, win_end in split_time_windows_under_90d(period_start_utc, period_end_utc):
            s_ms = int(win_start.timestamp() * 1000)
            e_ms = int(win_end.timestamp() * 1000)
            deposits = self._request_json(
                "GET",
                "/sapi/v1/capital/deposit/hisrec",
                params={"startTime": s_ms, "endTime": e_ms},
            )
            if isinstance(deposits, list):
                for dep in deposits:
                    ts = datetime.fromtimestamp(
                        float(dep.get("insertTime", s_ms)) / 1000.0, tz=timezone.utc
                    ).isoformat()
                    amt = abs(float(dep.get("amount", 0.0)))
                    coin = str(dep.get("coin", base_currency)).upper()
                    flows.append(
                        NormalizedFlow(
                            timestamp_utc=ts,
                            kind=FlowKind.DEPOSIT,
                            amount=amt,
                            currency=coin,
                            symbol=coin,
                            quantity=amt,
                            description="Binance deposit",
                        )
                    )
            withdraws = self._request_json(
                "GET",
                "/sapi/v1/capital/withdraw/apply",
                params={"startTime": s_ms, "endTime": e_ms},
            )
            if isinstance(withdraws, list):
                for wd in withdraws:
                    raw_time = wd.get("applyTime")
                    ts = (
                        raw_time.replace(" ", "T") + "Z"
                        if isinstance(raw_time, str) and "T" not in raw_time
                        else (raw_time or period_end_utc)
                    )
                    amt = -abs(float(wd.get("amount", 0.0)))
                    coin = str(wd.get("coin", base_currency)).upper()
                    flows.append(
                        NormalizedFlow(
                            timestamp_utc=ts,
                            kind=FlowKind.WITHDRAWAL,
                            amount=amt,
                            currency=coin,
                            symbol=coin,
                            quantity=amt,
                            description="Binance withdrawal",
                        )
                    )

        trades: list[NormalizedTrade] = []
        for sym in symbols:
            raw_trades = self._request_json("GET", "/api/v3/myTrades", params={"symbol": sym})
            if isinstance(raw_trades, list):
                for tr in raw_trades:
                    ts = datetime.fromtimestamp(
                        float(tr.get("time", 0)) / 1000.0, tz=timezone.utc
                    ).isoformat()
                    trades.append(
                        NormalizedTrade(
                            venue="binance",
                            native_entry_id=f"{sym}:{tr.get('id')}",
                            symbol=sym,
                            asset_class=AssetClass.CRYPTO_SPOT,
                            side="buy" if bool(tr.get("isBuyer", True)) else "sell",
                            quantity=abs(float(tr.get("qty", 0.0))),
                            price=float(tr.get("price", 0.0)),
                            timestamp_utc=ts,
                            currency=base_currency,
                            commission=abs(float(tr.get("commission", 0.0))),
                        )
                    )

        source_sha = hashlib.sha256(b"\n".join(self._raw_transcript_chunks)).hexdigest()
        nav_points = (
            [NormalizedNavPoint(timestamp_utc=period_end_utc, nav_base=nav_total)]
            if nav_total > 0.0
            else []
        )
        return CanonicalPortfolioLedger(
            blinded_account_tag=compute_blinded_account_tag("binance", raw_acct_id, blinding_salt_hex),
            broker_id="binance",
            account_scope=scope_info.account_scope,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=self.approval_state,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            source_body_sha256=source_sha,
            base_currency=base_currency,
            period_start_utc=period_start_utc,
            period_end_utc=period_end_utc,
            ending_positions=positions,
            nav_points=nav_points,
            trades=trades,
            flows=flows,
            enabled_sections=["apiRestrictions", "account", "deposits_90d", "withdrawals_90d", "myTrades"],
        )

    def _fetch_coinbase_ledger(
        self,
        *,
        scope_info: KeyScopeIntrospectionResult,
        blinding_salt_hex: str,
        period_start_utc: str,
        period_end_utc: str,
        base_currency: str,
        selected_subaccounts: Sequence[str] | None,
    ) -> CanonicalPortfolioLedger:
        fills_resp = self._request_json(
            "GET",
            "/api/v3/brokerage/orders/historical/fills",
            params={
                "start_sequence_timestamp": period_start_utc,
                "end_sequence_timestamp": period_end_utc,
            },
            signed=False,
        )
        raw_fills = fills_resp.get("fills", []) if isinstance(fills_resp, Mapping) else []
        deduped_fills = deduplicate_coinbase_fills_by_entry_id(raw_fills)

        trades: list[NormalizedTrade] = []
        for fill in deduped_fills:
            trades.append(
                NormalizedTrade(
                    venue="coinbase",
                    native_entry_id=str(fill["entry_id"]).strip(),
                    symbol=str(fill.get("product_id", "BTC-USD")),
                    asset_class=AssetClass.CRYPTO_SPOT,
                    side=str(fill.get("side", "BUY")),
                    quantity=abs(float(fill.get("size", 0.0))),
                    price=float(fill.get("price", 0.0)),
                    timestamp_utc=str(fill.get("trade_time", period_end_utc)),
                    currency=base_currency,
                    commission=abs(float(fill.get("commission", 0.0))),
                )
            )

        enum_ids = list(scope_info.enumerated_subaccount_ids)
        conn_ids = (
            [s for s in enum_ids if s in set(selected_subaccounts)]
            if selected_subaccounts is not None
            else enum_ids
        )
        raw_tag_input = ",".join(sorted(conn_ids)) if conn_ids else "coinbase-primary"
        source_sha = hashlib.sha256(b"\n".join(self._raw_transcript_chunks)).hexdigest()
        return CanonicalPortfolioLedger(
            blinded_account_tag=compute_blinded_account_tag("coinbase", raw_tag_input, blinding_salt_hex),
            broker_id="coinbase",
            account_scope=scope_info.account_scope,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=self.approval_state,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            source_body_sha256=source_sha,
            base_currency=base_currency,
            period_start_utc=period_start_utc,
            period_end_utc=period_end_utc,
            enumerated_subaccount_count=len(enum_ids),
            connected_subaccount_count=len(conn_ids),
            trades=trades,
            enabled_sections=["key_permissions", "accounts", "fills_entry_id_dedup"],
        )

    def _fetch_kraken_ledger(
        self,
        *,
        scope_info: KeyScopeIntrospectionResult,
        blinding_salt_hex: str,
        period_start_utc: str,
        period_end_utc: str,
        base_currency: str,
    ) -> CanonicalPortfolioLedger:
        bal_resp = self._request_json("POST", "/0/private/BalanceEx")
        balances = (bal_resp.get("result") or {}) if isinstance(bal_resp, Mapping) else {}

        # Respect +4 Kraken decay counter (max 20) before each Ledgers call!
        self.kraken_limiter.acquire(self.kraken_limiter.ledger_cost)
        ledgers_resp = self._request_json("POST", "/0/private/Ledgers")
        ledger_map = (
            (ledgers_resp.get("result") or {}).get("ledger", {})
            if isinstance(ledgers_resp, Mapping)
            else {}
        )

        flows: list[NormalizedFlow] = []
        latest_ledger_bal: dict[str, tuple[float, float]] = {}
        if isinstance(ledger_map, Mapping):
            for lid, entry in ledger_map.items():
                if not isinstance(entry, Mapping):
                    continue
                asset = str(entry.get("asset", base_currency)).upper()
                amt = float(entry.get("amount", 0.0))
                fee = float(entry.get("fee", 0.0))
                ts_val = float(entry.get("time", 0.0))
                bal_after = float(entry.get("balance", 0.0))
                prev = latest_ledger_bal.get(asset)
                if prev is None or ts_val >= prev[0]:
                    latest_ledger_bal[asset] = (ts_val, bal_after)

                ts_iso = datetime.fromtimestamp(ts_val, tz=timezone.utc).isoformat()
                ltype = str(entry.get("type", "")).lower()
                if ltype == "deposit":
                    kind = FlowKind.DEPOSIT
                elif ltype == "withdrawal":
                    kind = FlowKind.WITHDRAWAL
                elif ltype == "transfer":
                    kind = FlowKind.INTERNAL_SUBACCOUNT_TRANSFER
                elif ltype in {"staking", "dividend"}:
                    kind = FlowKind.DIVIDEND
                elif ltype in {"margin", "rollover"}:
                    kind = FlowKind.MARGIN_INTEREST
                else:
                    kind = FlowKind.OTHER_INTERNAL
                flows.append(
                    NormalizedFlow(
                        timestamp_utc=ts_iso,
                        kind=kind,
                        amount=amt - fee,
                        currency=asset[:12],
                        description=f"Kraken ledger {lid}: {ltype}",
                    )
                )

        warnings: list[str] = []
        positions: list[NormalizedPosition] = []
        if isinstance(balances, Mapping):
            for asset, bal_entry in balances.items():
                asset_code = str(asset).upper()
                if isinstance(bal_entry, Mapping):
                    reported_bal = float(bal_entry.get("balance", 0.0))
                else:
                    reported_bal = float(bal_entry)
                if asset_code in latest_ledger_bal:
                    _, ledger_bal = latest_ledger_bal[asset_code]
                    if abs(reported_bal - ledger_bal) > 1e-6:
                        warnings.append(
                            f"Kraken BalanceEx vs Ledgers mismatch for {asset_code}: "
                            f"BalanceEx={reported_bal:.8f}, Ledgers={ledger_bal:.8f}"
                        )
                if reported_bal > 0:
                    positions.append(
                        NormalizedPosition(
                            prior_period_or_ending="ending",
                            symbol=asset_code,
                            asset_class=AssetClass.CRYPTO_SPOT,
                            quantity=reported_bal,
                            cost_basis=reported_bal,
                            market_value=reported_bal,
                            currency=base_currency,
                        )
                    )

        source_sha = hashlib.sha256(b"\n".join(self._raw_transcript_chunks)).hexdigest()
        return CanonicalPortfolioLedger(
            blinded_account_tag=compute_blinded_account_tag(
                "kraken", "kraken-verified-key", blinding_salt_hex
            ),
            broker_id="kraken",
            account_scope=scope_info.account_scope,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=self.approval_state,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            source_body_sha256=source_sha,
            base_currency=base_currency,
            period_start_utc=period_start_utc,
            period_end_utc=period_end_utc,
            ending_positions=positions,
            flows=flows,
            enabled_sections=["GetApiKeyInfo", "BalanceEx", "Ledgers"],
            parser_warnings=warnings,
        )

    def _fetch_bybit_ledger(
        self,
        *,
        scope_info: KeyScopeIntrospectionResult,
        blinding_salt_hex: str,
        period_start_utc: str,
        period_end_utc: str,
        base_currency: str,
        selected_subaccounts: Sequence[str] | None,
    ) -> CanonicalPortfolioLedger:
        wallet_resp = self._request_json(
            "GET", "/v5/account/wallet-balance", params={"accountType": "UNIFIED"}
        )
        nav_total = 0.0
        if isinstance(wallet_resp, Mapping):
            acct_list = (wallet_resp.get("result") or {}).get("list", [])
            for item in acct_list:
                if isinstance(item, Mapping):
                    nav_total += float(item.get("totalEquity", 0.0))

        exec_resp = self._request_json(
            "GET", "/v5/execution/list", params={"category": "spot"}
        )
        trades: list[NormalizedTrade] = []
        if isinstance(exec_resp, Mapping):
            exec_list = (exec_resp.get("result") or {}).get("list", [])
            for ex in exec_list:
                if not isinstance(ex, Mapping):
                    continue
                ts_ms = float(ex.get("execTime", 0))
                ts_iso = (
                    datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc).isoformat()
                    if ts_ms > 0
                    else period_end_utc
                )
                trades.append(
                    NormalizedTrade(
                        venue="bybit",
                        native_entry_id=str(ex.get("execId", "")),
                        symbol=str(ex.get("symbol", "BTCUSDT")),
                        asset_class=AssetClass.CRYPTO_SPOT,
                        side=str(ex.get("side", "Buy")),
                        quantity=abs(float(ex.get("execQty", 0.0))),
                        price=float(ex.get("execPrice", 0.0)),
                        timestamp_utc=ts_iso,
                        currency=base_currency,
                        commission=abs(float(ex.get("execFee", 0.0))),
                    )
                )

        enum_ids = list(scope_info.enumerated_subaccount_ids)
        conn_ids = (
            [uid for uid in enum_ids if uid in set(selected_subaccounts)]
            if selected_subaccounts is not None
            else enum_ids
        )
        raw_tag_input = ",".join(sorted(conn_ids)) if conn_ids else "bybit-master"
        source_sha = hashlib.sha256(b"\n".join(self._raw_transcript_chunks)).hexdigest()
        nav_points = (
            [NormalizedNavPoint(timestamp_utc=period_end_utc, nav_base=nav_total)]
            if nav_total > 0.0
            else []
        )
        return CanonicalPortfolioLedger(
            blinded_account_tag=compute_blinded_account_tag("bybit", raw_tag_input, blinding_salt_hex),
            broker_id="bybit",
            account_scope=scope_info.account_scope,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=self.approval_state,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            source_body_sha256=source_sha,
            base_currency=base_currency,
            period_start_utc=period_start_utc,
            period_end_utc=period_end_utc,
            enumerated_subaccount_count=len(enum_ids),
            connected_subaccount_count=len(conn_ids),
            nav_points=nav_points,
            trades=trades,
            enabled_sections=["query-api", "query-sub-members", "wallet-balance", "execution-list"],
        )


__all__ = [
    "CcxtExchangeReadOnlyAdapter",
    "ConnectorHttpError",
    "DisallowedCapabilityError",
    "HttpExchangeResponse",
    "HttpTransportCallable",
    "KeyScopeIntrospectionResult",
    "KrakenDecayRateLimiter",
    "MutatingCredentialRejectedError",
    "PaperOrSandboxAccountRejectedError",
    "ProviderApprovalRequiredError",
    "SUPPORTED_CRYPTO_EXCHANGES",
    "UnsupportedScraperPolicyError",
    "deduplicate_coinbase_fills_by_entry_id",
    "harden_ccxt_exchange_instance",
    "invoke_http_transport",
    "split_time_windows_under_90d",
]
