"""Read-only SnapTrade POC aggregator relay adapter with a strict 5-slot connection cap."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time
from typing import Any
import urllib.parse

from n170_verify.connectors.ccxt_crypto import (
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
    validate_read_only_capabilities,
)

SNAPTRADE_LIVE_BASE_URL: str = "https://api.snaptrade.com"
DEFAULT_SNAPTRADE_USER_AGENT: str = "N170-Verify-SnapTrade-POC/1.0"
MAX_SNAPTRADE_POC_SLOTS: int = 5

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

    def is_user_registered(self, user_id: str) -> bool:
        slot = self._slots.get(user_id)
        return slot is not None and slot.active

    def get_slot(self, user_id: str) -> SnapTradeConnectionSlot | None:
        return self._slots.get(user_id)

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

        # If already active, return the existing slot without incrementing usage
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

        # Allocate lowest available slot_id from 1 to max_slots
        occupied_ids = {s.slot_id for s in self._slots.values() if s.active}
        next_id = next(i for i in range(1, self._max_slots + 1) if i not in occupied_ids)

        ts = now_iso or datetime.now(timezone.utc).isoformat()
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


# Module-level default slot manager singleton for the POC relay
_GLOBAL_POC_SLOT_MANAGER = SnapTradeSlotManager(MAX_SNAPTRADE_POC_SLOTS)


def get_global_snaptrade_slot_manager() -> SnapTradeSlotManager:
    """Return the global singleton slot manager for the SnapTrade POC relay."""
    return _GLOBAL_POC_SLOT_MANAGER


def _parse_iso_ts(value: str | None) -> str:
    if not value or not str(value).strip():
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = str(value).strip()
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return raw


class SnapTradeReadOnlyAdapter(ReadOnlyBrokerAdapter):
    """Read-only SnapTrade POC aggregator relay adapter with a strict 5-slot connection cap."""

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
        client_id: str = "snaptrade-poc-client",
        consumer_key: str = "snaptrade-poc-key",
        user_id: str | None = None,
        user_secret: str | None = None,
        base_url: str | None = None,
        slot_manager: SnapTradeSlotManager | None = None,
        http_transport: HttpTransportCallable | Any | None = None,
        require_live: bool = True,
        env: Mapping[str, str] | None = None,
        auto_register_slot: bool = True,
        **extra_kwargs: Any,
    ) -> None:
        reject_unofficial_scraper_credentials(**extra_kwargs)
        super().__init__()

        env_map = env or {}
        resolved_client_id = (
            env_map.get("SNAPTRADE_CLIENT_ID") or client_id or ""
        ).strip()
        resolved_consumer_key = (
            env_map.get("SNAPTRADE_CONSUMER_KEY") or consumer_key or ""
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

        expected_host = urllib.parse.urlsplit(SNAPTRADE_LIVE_BASE_URL).hostname or "api.snaptrade.com"
        self.base_url = validate_ssrf_safe_https_url(
            base_url or SNAPTRADE_LIVE_BASE_URL,
            allowed_hosts={expected_host},
            require_live=require_live,
            label="snaptrade",
        )
        self._transport = http_transport
        self.slot_manager = slot_manager or _GLOBAL_POC_SLOT_MANAGER

        # Enforce 5-slot cap when user_id is provided on initialization
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

    def build_auth_headers(self) -> dict[str, str]:
        """Construct read-only API authentication headers, omitting mutating scopes."""
        headers = {
            "Accept": "application/json",
            "User-Agent": DEFAULT_SNAPTRADE_USER_AGENT,
            "clientId": self.client_id,
            "consumerKey": self.consumer_key,
        }
        return headers

    def parse_payload(
        self,
        payload: dict[str, Any] | str | bytes,
        *,
        blinding_salt_hex: str,
        selected_account_ids: Sequence[str] | None = None,
        require_live: bool = True,
    ) -> CanonicalPortfolioLedger:
        """Normalize raw SnapTrade JSON response structure into CanonicalPortfolioLedger."""
        if isinstance(payload, (bytes, str)):
            data = json.loads(payload)
        else:
            data = payload

        source_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
        source_sha256 = hashlib.sha256(source_bytes).hexdigest()

        raw_accounts = data.get("accounts", [])
        if isinstance(raw_accounts, dict):
            raw_accounts = [raw_accounts]

        raw_acct_ids: list[str] = []
        is_paper_detected = False
        base_currency = "USD"

        for acct in raw_accounts:
            aid = str(acct.get("id") or acct.get("account_number") or "").strip()
            if aid and aid not in raw_acct_ids:
                raw_acct_ids.append(aid)
            meta = acct.get("meta") or {}
            raw_type = str(acct.get("type") or meta.get("type") or "").lower()
            if "paper" in raw_type or "demo" in raw_type or "simulated" in raw_type or acct.get("is_paper"):
                is_paper_detected = True
            ccy = str(acct.get("currency") or meta.get("currency") or "").strip().upper()
            if ccy and len(ccy) == 3:
                base_currency = ccy

        if is_paper_detected:
            if require_live:
                raise PaperOrSandboxAccountRejectedError(
                    "SnapTrade paper or simulated account rejected for live verification"
                )
            env_tier = EnvironmentTier.PAPER_OR_SANDBOX_REJECTED
        else:
            env_tier = EnvironmentTier.LIVE_PRODUCTION

        selected_set = {str(x).strip() for x in selected_account_ids} if selected_account_ids else None
        if selected_set:
            account_scope = AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED
            filtered_accounts = [a for a in raw_accounts if str(a.get("id") or a.get("account_number") or "").strip() in selected_set]
        else:
            account_scope = AccountScope.ALL_ENUMERATED_SUBACCOUNTS
            filtered_accounts = raw_accounts

        raw_tag_seed = ",".join(sorted(raw_acct_ids)) if raw_acct_ids else f"snaptrade:{source_sha256[:16]}"
        blinded_tag = compute_blinded_account_tag("snaptrade", raw_tag_seed, blinding_salt_hex)

        trades: list[NormalizedTrade] = []
        flows: list[NormalizedFlow] = []
        ending_positions: list[NormalizedPosition] = []
        nav_points: list[NormalizedNavPoint] = []

        # Parse activities / trades
        activities = data.get("activities") or data.get("trades") or []
        for act in activities:
            aid = str(act.get("account_id") or "").strip()
            if selected_set and aid and aid not in selected_set:
                continue
            act_type = str(act.get("type") or "").strip().lower()
            ts = _parse_iso_ts(act.get("trade_date") or act.get("settlement_date") or act.get("created_at"))
            symbol = str(act.get("symbol") or (act.get("option_symbol") or {}).get("ticker") or "").strip().upper()
            qty = abs(float(act.get("units") or act.get("quantity") or 0.0))
            price = float(act.get("price") or 0.0)
            fee = float(act.get("fee") or act.get("commission") or 0.0)
            currency = str(act.get("currency") or base_currency).strip().upper()

            if act_type in {"buy", "sell"}:
                trades.append(
                    NormalizedTrade(
                        venue="SNAPTRADE_RELAY",
                        native_entry_id=str(act.get("id") or f"st-{len(trades)+1}"),
                        symbol=symbol or "UNKNOWN",
                        asset_class=AssetClass.EQUITY,
                        side="buy" if act_type == "buy" else "sell",
                        quantity=qty,
                        price=price,
                        timestamp_utc=ts,
                        currency=currency,
                        commission=fee,
                        multiplier=1.0,
                    )
                )
            elif act_type in {"deposit", "withdrawal", "dividend", "interest"}:
                amt = float(act.get("amount") or (price * qty) or 0.0)
                if act_type == "withdrawal" and amt > 0:
                    amt = -amt
                flow_kind = FlowKind.DEPOSIT if act_type == "deposit" else (
                    FlowKind.WITHDRAWAL if act_type == "withdrawal" else (
                        FlowKind.DIVIDEND_CASH if act_type == "dividend" else FlowKind.INTEREST
                    )
                )
                flows.append(
                    NormalizedFlow(
                        timestamp_utc=ts,
                        kind=flow_kind,
                        amount=amt,
                        currency=currency,
                        description=str(act.get("description") or f"SnapTrade {act_type}"),
                    )
                )

        # Parse positions
        positions_raw = data.get("positions") or []
        for p in positions_raw:
            aid = str(p.get("account_id") or "").strip()
            if selected_set and aid and aid not in selected_set:
                continue
            sym = str((p.get("symbol") or {}).get("symbol") or p.get("symbol") or "").strip().upper()
            units = float(p.get("units") or p.get("quantity") or 0.0)
            price = float(p.get("price") or p.get("current_price") or 0.0)
            cost_basis = float(p.get("cost_basis") or (units * price) or 0.0)
            ccy = str((p.get("symbol") or {}).get("currency") or base_currency).strip().upper()
            ending_positions.append(
                NormalizedPosition(
                    prior_period_or_ending="ending",
                    symbol=sym or "UNKNOWN",
                    asset_class=AssetClass.EQUITY,
                    quantity=units,
                    cost_basis=cost_basis,
                    market_value=units * price,
                    currency=ccy,
                )
            )

        # Parse balances
        balances_raw = data.get("balances") or []
        if isinstance(balances_raw, dict):
            balances_raw = [balances_raw]
        for b in balances_raw:
            aid = str(b.get("account_id") or "").strip()
            if selected_set and aid and aid not in selected_set:
                continue
            tot = float(b.get("total") or b.get("current_balance") or b.get("equity") or 0.0)
            cash = float(b.get("cash") or 0.0)
            b_ts = _parse_iso_ts(b.get("updated_at") or b.get("date"))
            nav_points.append(
                NormalizedNavPoint(
                    timestamp_utc=b_ts,
                    nav_base=tot,
                    cash_base=cash,
                )
            )

        all_ts = [t.timestamp_utc for t in trades] + [f.timestamp_utc for f in flows] + [n.timestamp_utc for n in nav_points]
        period_start = min(all_ts) if all_ts else datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z")
        period_end = max(all_ts) if all_ts else datetime.now(timezone.utc).strftime("%Y-%m-%dT23:59:59Z")

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
            connected_subaccount_count=len(raw_acct_ids),
            trades=sorted(trades, key=lambda t: (t.timestamp_utc, t.native_entry_id)),
            flows=sorted(flows, key=lambda f: f.timestamp_utc),
            ending_positions=ending_positions,
            nav_points=sorted(nav_points, key=lambda n: n.timestamp_utc),
            enabled_sections=["snaptrade_accounts", "snaptrade_positions", "snaptrade_activities"],
        )

    def fetch_canonical_ledger(
        self,
        *,
        blinding_salt_hex: str,
        user_id: str | None = None,
        user_secret: str | None = None,
        selected_account_ids: Sequence[str] | None = None,
        require_live: bool = True,
    ) -> CanonicalPortfolioLedger:
        """Query SnapTrade read-only endpoints, enforcing 5-slot cap, secret redactions, and normalization."""
        target_user = (user_id or self.user_id or "").strip()
        target_secret = (user_secret or self.user_secret or "").strip()
        if not target_user:
            raise SnapTradeAuthenticationError("user_id required for live SnapTrade queries")

        # Slot cap enforcement
        self.slot_manager.register_slot(target_user)

        secrets = [self.client_id, self.consumer_key]
        if target_secret:
            secrets.append(target_secret)

        headers = self.build_auth_headers()
        base = self.base_url.rstrip("/")

        try:
            # 1. Fetch accounts
            accts_resp = invoke_http_transport(
                self._transport,
                "GET",
                f"{base}/api/v1/accounts?userId={urllib.parse.quote(target_user)}",
                headers=headers,
                extra_extra_secrets=secrets,
            )
            if accts_resp.status_code != 200:
                raise SnapTradeServiceError(
                    f"SnapTrade /api/v1/accounts failed with HTTP {accts_resp.status_code}"
                )
            accounts_data = json.loads(accts_resp.body.decode("utf-8")) if isinstance(accts_resp.body, bytes) else accts_resp.body

            # 2. Fetch positions
            pos_resp = invoke_http_transport(
                self._transport,
                "GET",
                f"{base}/api/v1/positions?userId={urllib.parse.quote(target_user)}",
                headers=headers,
                extra_extra_secrets=secrets,
            )
            positions_data = json.loads(pos_resp.body.decode("utf-8")) if isinstance(pos_resp.body, bytes) else pos_resp.body

            # 3. Fetch activities
            act_resp = invoke_http_transport(
                self._transport,
                "GET",
                f"{base}/api/v1/activities?userId={urllib.parse.quote(target_user)}",
                headers=headers,
                extra_extra_secrets=secrets,
            )
            activities_data = json.loads(act_resp.body.decode("utf-8")) if isinstance(act_resp.body, bytes) else act_resp.body

            bundle = {
                "accounts": accounts_data if isinstance(accounts_data, list) else [accounts_data],
                "positions": positions_data if isinstance(positions_data, list) else [positions_data],
                "activities": activities_data if isinstance(activities_data, list) else [activities_data],
            }
            return self.parse_payload(
                bundle,
                blinding_salt_hex=blinding_salt_hex,
                selected_account_ids=selected_account_ids,
                require_live=require_live,
            )
        except Exception as exc:
            redacted_msg = redact_sensitive_text(str(exc), extra_secrets=secrets)
            if isinstance(exc, (SnapTradeError, PaperOrSandboxAccountRejectedError, DisallowedCapabilityError)):
                raise
            raise SnapTradeServiceError(f"SnapTrade relay query failed: {redacted_msg}") from None


__all__ = [
    "DEFAULT_SNAPTRADE_USER_AGENT",
    "MAX_SNAPTRADE_POC_SLOTS",
    "SNAPTRADE_BLOCKED_MUTATING_ENDPOINTS",
    "SNAPTRADE_LIVE_BASE_URL",
    "SnapTradeAuthenticationError",
    "SnapTradeConnectionSlot",
    "SnapTradeError",
    "SnapTradeReadOnlyAdapter",
    "SnapTradeServiceError",
    "SnapTradeSlotCapExceededError",
    "SnapTradeSlotManager",
    "get_global_snaptrade_slot_manager",
]
