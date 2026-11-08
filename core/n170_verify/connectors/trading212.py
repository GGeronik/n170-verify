"""Trading 212 live Invest/ISA read-only adapter with per-endpoint rate limiting.

Authenticates via HTTP Basic ``Base64(KEY:SECRET)``, honors ``x-ratelimit-remaining``
and ``x-ratelimit-reset`` headers alongside Trading 212's strict per-endpoint limits
(``1 req/5s`` account summary, ``6 req/min`` historical orders & dividends,
``20 req/min`` transactions), labels ``AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED``
(Invest and ISA API keys are separate), and rejects demo and CFD endpoints/accounts.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import time
from typing import Any
import urllib.parse

from n170_verify.connectors.ccxt_crypto import (
    ConnectorHttpError,
    DisallowedCapabilityError,
    HttpTransportCallable,
    PaperOrSandboxAccountRejectedError,
    invoke_http_transport,
    validate_ssrf_safe_https_url,
)
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
    compute_blinded_account_tag,
)


TRADING212_LIVE_BASE_URL = "https://live.trading212.com"

# Minimum spacing derived from Trading 212 public REST quotas:
# - summary / cash / info: 1 req / 5s (5.0s)
# - historical orders & dividends: 6 req / min (10.0s)
# - transactions: 20 req / min (3.0s)
TRADING212_BUCKET_INTERVALS_SECONDS: dict[str, float] = {
    "summary": 5.0,
    "orders": 10.0,
    "dividends": 10.0,
    "transactions": 3.0,
    "portfolio": 5.0,
}


def build_trading212_basic_auth_header(api_key: str, api_secret: str) -> str:
    """Encode ``Base64(KEY:SECRET)`` for Trading 212 HTTP Basic authentication."""
    key_clean = (api_key or "").strip()
    sec_clean = (api_secret or "").strip()
    if not key_clean or not sec_clean:
        raise ValueError("Trading 212 requires non-empty api_key and api_secret")
    encoded = base64.b64encode(f"{key_clean}:{sec_clean}".encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


@dataclass(slots=True)
class Trading212RateLimiter:
    """Per-bucket rate limiter honoring ``x-ratelimit-remaining`` and ``x-ratelimit-reset``."""

    now_fn: Callable[[], float] = time.time
    sleep_fn: Callable[[float], None] = time.sleep
    _next_allowed_at: dict[str, float] = field(default_factory=dict)
    recorded_sleeps: list[tuple[str, float]] = field(default_factory=list)

    def wait_before_request(self, bucket: str) -> None:
        now = self.now_fn()
        ready_at = self._next_allowed_at.get(bucket, 0.0)
        if ready_at > now:
            delay = ready_at - now
            self.recorded_sleeps.append((bucket, delay))
            self.sleep_fn(delay)

    def observe_response_headers(self, bucket: str, headers: Mapping[str, str]) -> None:
        now = self.now_fn()
        min_interval = TRADING212_BUCKET_INTERVALS_SECONDS.get(bucket, 3.0)
        next_time = now + min_interval

        lower = {k.lower(): v for k, v in headers.items()}
        rem_raw = lower.get("x-ratelimit-remaining")
        reset_raw = lower.get("x-ratelimit-reset")

        if rem_raw is not None:
            try:
                remaining = int(rem_raw.strip())
            except ValueError:
                remaining = 1
            if remaining <= 0 and reset_raw is not None:
                try:
                    reset_val = float(reset_raw.strip())
                    # Handle either epoch timestamp (>1e9) or delta seconds.
                    reset_target = reset_val if reset_val > 1_000_000_000 else (now + max(0.0, reset_val))
                    next_time = max(next_time, reset_target)
                except ValueError:
                    pass

        self._next_allowed_at[bucket] = next_time


class Trading212ReadOnlyAdapter(ReadOnlyBrokerAdapter):
    """Read-only connector for Trading 212 Live Invest & ISA REST v0 endpoints."""

    broker_id = "trading212"
    display_name = "Trading 212 Live Invest/ISA Read-Only Adapter"
    approval_state = ProviderApprovalState.USER_KEY_SELF_ATTESTED
    default_origin_assurance = OriginAssurance.OPERATOR_RETRIEVED
    supports_subaccount_enumeration = False
    allowed_capabilities = (
        "read_account_profile",
        "fetch_nav_history",
        "fetch_positions",
        "fetch_executions",
        "fetch_dividends",
        "fetch_transactions",
    )

    def __init__(
        self,
        *,
        api_key: str,
        api_secret: str,
        base_url: str = TRADING212_LIVE_BASE_URL,
        require_live: bool = True,
        http_transport: HttpTransportCallable | Any | None = None,
        now_fn: Callable[[], float] = time.time,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__()
        cleaned_base = validate_ssrf_safe_https_url(
            base_url or TRADING212_LIVE_BASE_URL,
            allowed_hosts={"live.trading212.com"},
            require_live=require_live,
            label="Trading 212",
        )
        parsed = urllib.parse.urlsplit(cleaned_base)
        if "/cfd" in parsed.path.lower():
            raise DisallowedCapabilityError("Trading 212 CFD endpoints are unsupported")

        self._api_key = api_key.strip()
        self._api_secret = api_secret.strip()
        self._basic_header = build_trading212_basic_auth_header(self._api_key, self._api_secret)
        self._base_url = cleaned_base
        self._require_live = require_live
        self._transport = http_transport
        self.rate_limiter = Trading212RateLimiter(now_fn=now_fn, sleep_fn=sleep_fn)
        self._raw_transcript_chunks: list[bytes] = []

    def _secrets(self, extra: Sequence[str] = ()) -> tuple[str, ...]:
        return (self._api_key, self._api_secret, self._basic_header, *extra)

    def _bucket_for_path(self, path: str) -> str:
        lower = path.lower()
        if "/cfd" in lower:
            raise DisallowedCapabilityError("Trading 212 CFD endpoints are structurally blocked")
        if "/account/" in lower:
            return "summary"
        if "/history/orders" in lower:
            return "orders"
        if "/dividends" in lower:
            return "dividends"
        if "/transactions" in lower:
            return "transactions"
        return "portfolio"

    def _get_json(self, path_or_next: str, *, params: Mapping[str, Any] | None = None) -> Any:
        if path_or_next.startswith("https://"):
            parsed_next = urllib.parse.urlsplit(path_or_next)
            if parsed_next.netloc.lower() != urllib.parse.urlsplit(self._base_url).netloc.lower():
                raise DisallowedCapabilityError("Cross-origin Trading 212 pagination path blocked")
            path = parsed_next.path + (f"?{parsed_next.query}" if parsed_next.query else "")
        else:
            path = path_or_next if path_or_next.startswith("/") else f"/{path_or_next}"

        bucket = self._bucket_for_path(path)
        q = {k: v for k, v in (params or {}).items() if v is not None}
        qs = urllib.parse.urlencode(q)
        sep = "&" if "?" in path else "?"
        url = f"{self._base_url}{path}" + (f"{sep}{qs}" if qs else "")
        headers = {
            "Authorization": self._basic_header,
            "Accept": "application/json",
        }

        for attempt in range(2):
            self.rate_limiter.wait_before_request(bucket)
            resp = invoke_http_transport(
                self._transport,
                "GET",
                url,
                headers=headers,
                extra_secrets=self._secrets(),
            )
            self.rate_limiter.observe_response_headers(bucket, resp.headers)
            if resp.status_code == 429 and attempt == 0:
                continue
            if resp.status_code < 200 or resp.status_code >= 300:
                safe_msg = redact_sensitive_text(resp.text()[:200], self._secrets())
                raise ConnectorHttpError(
                    resp.status_code,
                    f"Trading 212 GET {path.split('?')[0]} failed with HTTP {resp.status_code}: {safe_msg}",
                )
            self._raw_transcript_chunks.append(resp.body)
            return resp.json()

        raise ConnectorHttpError(429, f"Trading 212 bucket {bucket!r} rate limit exceeded")

    def _paginate_items(self, initial_path: str, *, limit: int = 50, max_pages: int = 20) -> list[dict[str, Any]]:
        collected: list[dict[str, Any]] = []
        next_path: str | None = initial_path
        first = True
        for _ in range(max_pages):
            if not next_path:
                break
            page = self._get_json(next_path, params={"limit": limit} if first else None)
            first = False
            if not isinstance(page, Mapping):
                break
            items = page.get("items") or []
            if isinstance(items, list):
                collected.extend(it for it in items if isinstance(it, Mapping))
            raw_next = page.get("nextPagePath")
            next_path = str(raw_next).strip() if isinstance(raw_next, str) and raw_next.strip() else None
        return collected

    def fetch_canonical_ledger(
        self,
        *,
        blinding_salt_hex: str,
        period_start_utc: str,
        period_end_utc: str,
    ) -> CanonicalPortfolioLedger:
        self._raw_transcript_chunks.clear()
        info = self._get_json("/api/v0/equity/account/info")
        if not isinstance(info, Mapping):
            raise ConnectorHttpError(502, "Trading 212 account/info returned invalid payload")

        acct_type = str(info.get("type") or info.get("accountType") or "INVEST").upper()
        if "CFD" in acct_type:
            raise DisallowedCapabilityError(
                "Trading 212 CFD accounts are rejected; only live Invest and ISA accounts are supported"
            )

        acct_id = str(info.get("id") or "").strip()
        if not acct_id:
            raise ConnectorHttpError(502, "Trading 212 account/info missing account id")
        base_ccy = str(info.get("currencyCode") or "GBP").upper()

        cash = self._get_json("/api/v0/equity/account/cash")
        total_nav = float(cash.get("total", 0.0)) if isinstance(cash, Mapping) else 0.0
        free_cash = float(cash.get("free", 0.0)) if isinstance(cash, Mapping) else None

        portfolio = self._get_json("/api/v0/equity/portfolio")
        ending_positions: list[NormalizedPosition] = []
        if isinstance(portfolio, list):
            for p in portfolio:
                if not isinstance(p, Mapping):
                    continue
                ticker = str(p.get("ticker") or "").strip()
                if not ticker:
                    continue
                qty = float(p.get("quantity", 0.0))
                avg_px = float(p.get("averagePrice", 0.0))
                cur_px = float(p.get("currentPrice", 0.0))
                ending_positions.append(
                    NormalizedPosition(
                        prior_period_or_ending="ending",
                        symbol=ticker,
                        asset_class=AssetClass.EQUITY,
                        quantity=qty,
                        cost_basis=qty * avg_px,
                        market_value=qty * cur_px,
                        currency=base_ccy,
                    )
                )

        trades: list[NormalizedTrade] = []
        for idx, order_item in enumerate(self._paginate_items("/api/v0/equity/history/orders")):
            order = order_item.get("order") if isinstance(order_item.get("order"), Mapping) else order_item
            fill = order_item.get("fill") if isinstance(order_item.get("fill"), Mapping) else order_item
            status = str(order.get("status") or "FILLED").upper()
            if status not in {"FILLED", "PARTIALLY_FILLED"}:
                continue
            ticker = str(order.get("ticker") or fill.get("ticker") or "").strip()
            if not ticker:
                continue
            raw_qty = float(fill.get("quantity") or order.get("filledQuantity") or 0.0)
            if raw_qty == 0.0:
                continue
            side = "sell" if raw_qty < 0 or str(order.get("side") or "").upper() == "SELL" else "buy"
            px = float(fill.get("price") or order.get("fillPrice") or 0.0)
            fill_id = str(fill.get("id") or order.get("id") or f"t212-fill-{idx}")
            ts = str(fill.get("filledAt") or order.get("dateModified") or period_end_utc)
            trades.append(
                NormalizedTrade(
                    venue="trading212",
                    native_entry_id=fill_id,
                    symbol=ticker,
                    asset_class=AssetClass.EQUITY,
                    side=side,
                    quantity=abs(raw_qty),
                    price=abs(px),
                    timestamp_utc=ts,
                    currency=base_ccy,
                )
            )

        flows: list[NormalizedFlow] = []
        for div in self._paginate_items("/api/v0/history/dividends"):
            amt = float(div.get("amountInEuro") if base_ccy == "EUR" and "amountInEuro" in div else div.get("amount", 0.0))
            ts = str(div.get("paidOn") or period_end_utc)
            flows.append(
                NormalizedFlow(
                    timestamp_utc=ts,
                    kind=FlowKind.DIVIDEND,
                    amount=amt,
                    currency=base_ccy,
                    symbol=div.get("ticker"),
                    description=str(div.get("type") or "Dividend"),
                )
            )

        for tx in self._paginate_items("/api/v0/history/transactions"):
            tx_type = str(tx.get("type") or "").upper()
            amt = float(tx.get("amount", 0.0))
            ts = str(tx.get("dateTime") or period_end_utc)
            if "DEPOSIT" in tx_type:
                kind = FlowKind.DEPOSIT
                amt = abs(amt)
            elif "WITHDRAW" in tx_type:
                kind = FlowKind.WITHDRAWAL
                amt = -abs(amt)
            elif "INTEREST" in tx_type:
                kind = FlowKind.INTEREST
            elif "FEE" in tx_type or "TAX" in tx_type:
                kind = FlowKind.COMMISSION_FEE
            else:
                kind = FlowKind.OTHER_INTERNAL
            flows.append(
                NormalizedFlow(
                    timestamp_utc=ts,
                    kind=kind,
                    amount=amt,
                    currency=base_ccy,
                    description=str(tx.get("reference") or tx_type),
                )
            )

        nav_points = (
            [NormalizedNavPoint(timestamp_utc=period_end_utc, nav_base=total_nav, cash_base=free_cash)]
            if total_nav > 0.0
            else []
        )
        source_sha = hashlib.sha256(b"\n".join(self._raw_transcript_chunks)).hexdigest()
        return CanonicalPortfolioLedger(
            blinded_account_tag=compute_blinded_account_tag("trading212", acct_id, blinding_salt_hex),
            broker_id="trading212",
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            source_body_sha256=source_sha,
            base_currency=base_ccy,
            period_start_utc=period_start_utc,
            period_end_utc=period_end_utc,
            ending_positions=ending_positions,
            nav_points=nav_points,
            trades=trades,
            flows=flows,
            enabled_sections=["account_info", "account_cash", "portfolio", "orders", "dividends", "transactions"],
        )


__all__ = [
    "TRADING212_BUCKET_INTERVALS_SECONDS",
    "TRADING212_LIVE_BASE_URL",
    "Trading212RateLimiter",
    "Trading212ReadOnlyAdapter",
    "build_trading212_basic_auth_header",
]
