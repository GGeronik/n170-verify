"""Spotware cTrader Open API read-only OAuth2 adapter with strict scope & message firewalling.

Security & Governance Guarantees:
- Pre-flight OAuth2 scope enforcement: requires ``Scope: ACCOUNTS`` (``SCOPE_ACCOUNTS`` /
  ``"accounts"`` / ``ProtoOAPermissionScope.SCOPE_VIEW``) and rejects ``"trading"`` /
  ``SCOPE_TRADE`` or any write-capable scope with ``WriteCapableCredentialsRejectedError``
  BEFORE fetching account deal, cash-flow, or position data.
- Outgoing Open API message firewall: allows only read-only account/history/reconcile
  requests (``ProtoOAGetAccountListByAccessTokenReq``, ``ProtoOADealListReq``,
  ``ProtoOACashFlowHistoryListReq``, ``ProtoOAReconcileReq`` / ``ProtoVAReconcileReq``)
  and hard-blocks mutating trade message types (``ProtoOANewOrderReq``,
  ``ProtoOACancelOrderReq``, ``ProtoOAAmendOrderReq``, ``ProtoOAAmendPositionSLTPReq``,
  ``ProtoOAClosePositionReq``) with ``DisallowedCapabilityError``.
- Demo account rejection: rejects any ``ctidTraderAccount`` with ``isLive == False`` via
  ``PaperOrSandboxAccountRejectedError`` when ``require_live=True``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any

from n170_verify.connectors.ccxt_crypto import (
    ConnectorHttpError,
    DisallowedCapabilityError,
    HttpTransportCallable,
    MutatingCredentialRejectedError,
    PaperOrSandboxAccountRejectedError,
    invoke_http_transport,
    validate_ssrf_safe_https_url,
)
from n170_verify.connectors.mcp_allowlist_firewall import redact_sensitive_text
from n170_verify.connectors.mt5_tradovate import _infer_mt_instrument_spec
from n170_verify.contracts import (
    AccountScope,
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
    parse_utc_timestamp,
)


CTRADER_LIVE_BASE_URL = "https://openapi.ctrader.com"
SCOPE_ACCOUNTS = "accounts"
SCOPE_TRADING = "trading"

CTRADER_ALLOWED_SCOPES: frozenset[str] = frozenset(
    {
        "accounts",
        "scope_accounts",
        "scope_view",
        "view",
        "read_only",
        "readonly",
    }
)

CTRADER_FORBIDDEN_WRITE_SCOPES: frozenset[str] = frozenset(
    {
        "trading",
        "scope_trading",
        "scope_trade",
        "trade",
        "orders",
        "order",
        "write",
        "read_write",
        "withdraw",
        "transfer",
        "admin",
        "full",
        "all",
    }
)

CTRADER_BLOCKED_MUTATING_MESSAGE_TYPES: frozenset[str] = frozenset(
    {
        "ProtoOANewOrderReq",
        "ProtoOACancelOrderReq",
        "ProtoOAAmendOrderReq",
        "ProtoOAAmendPositionSLTPReq",
        "ProtoOAClosePositionReq",
    }
)

CTRADER_BLOCKED_NUMERIC_PAYLOAD_TYPES: frozenset[int] = frozenset(
    {
        2106,  # PROTO_OA_NEW_ORDER_REQ
        2107,  # PROTO_OA_AMEND_ORDER_REQ
        2108,  # PROTO_OA_CANCEL_ORDER_REQ
        2110,  # PROTO_OA_AMEND_POSITION_SLTP_REQ
        2111,  # PROTO_OA_CLOSE_POSITION_REQ
    }
)

CTRADER_ALLOWED_MESSAGE_TYPES: frozenset[str] = frozenset(
    {
        "ProtoOAApplicationAuthReq",
        "ProtoOAGetAccountListByAccessTokenReq",
        "ProtoOAAccountAuthReq",
        "ProtoOATraderReq",
        "ProtoOADealListReq",
        "ProtoOACashFlowHistoryListReq",
        "ProtoOAReconcileReq",
        "ProtoVAReconcileReq",
        "ProtoOASymbolsListReq",
        "ProtoOAAssetListReq",
    }
)

CTraderMessageTransport = Callable[[str, dict[str, Any]], Mapping[str, Any]]


class WriteCapableCredentialsRejectedError(MutatingCredentialRejectedError):
    """Raised when cTrader OAuth credentials include ``trading`` / ``SCOPE_TRADE`` write permissions."""


def validate_ctrader_oauth_scope(scope: str | Iterable[str] | int | None) -> tuple[str, ...]:
    """Validate that a cTrader OAuth2 token grants strictly read-only ``accounts`` scope."""
    if scope is None:
        raise WriteCapableCredentialsRejectedError(
            "cTrader OAuth scope is missing; explicit read-only 'accounts' scope is required"
        )
    if isinstance(scope, bool):
        raise WriteCapableCredentialsRejectedError("Invalid boolean cTrader OAuth scope")
    if isinstance(scope, int):
        # Spotware ProtoOAPermissionScope: 0 = SCOPE_VIEW (accounts), 1 = SCOPE_TRADE (trading)
        if scope == 0:
            return (SCOPE_ACCOUNTS,)
        raise WriteCapableCredentialsRejectedError(
            f"cTrader permissionScope={scope} grants trading/write access (only 0 / SCOPE_VIEW / 'accounts' is permitted)"
        )

    if isinstance(scope, str):
        raw_tokens = [tok for tok in re.split(r"[\s,;+|]+", scope.strip()) if tok]
    elif isinstance(scope, Iterable):
        raw_tokens = []
        for item in scope:
            if not isinstance(item, str):
                raise WriteCapableCredentialsRejectedError(
                    f"Unsupported cTrader scope item type: {type(item).__name__}"
                )
            raw_tokens.extend(tok for tok in re.split(r"[\s,;+|]+", item.strip()) if tok)
    else:
        raise WriteCapableCredentialsRejectedError(
            f"Unsupported cTrader scope type: {type(scope).__name__}"
        )

    if not raw_tokens:
        raise WriteCapableCredentialsRejectedError(
            "cTrader OAuth scope must be non-empty and restricted to 'accounts'"
        )

    normalized: list[str] = []
    for tok in raw_tokens:
        low = tok.strip().lower()
        if (
            low in CTRADER_FORBIDDEN_WRITE_SCOPES
            or "trad" in low
            or "order" in low
            or "write" in low
            or "withdraw" in low
        ):
            raise WriteCapableCredentialsRejectedError(
                f"cTrader OAuth scope {tok!r} grants trading/mutation capability; "
                f"only read-only {SCOPE_ACCOUNTS!r} scope is allowed"
            )
        if low not in CTRADER_ALLOWED_SCOPES:
            raise WriteCapableCredentialsRejectedError(
                f"Unrecognized cTrader OAuth scope {tok!r}; expected {SCOPE_ACCOUNTS!r}"
            )
        normalized.append(low)

    return tuple(dict.fromkeys(normalized))


def validate_ctrader_message_type(message_type: str | int) -> str:
    """Enforce outgoing cTrader Open API read-only message allowlist."""
    if isinstance(message_type, int) and not isinstance(message_type, bool):
        if message_type in CTRADER_BLOCKED_NUMERIC_PAYLOAD_TYPES:
            raise DisallowedCapabilityError(
                f"cTrader mutating payloadType={message_type} is structurally blocked"
            )
        raise DisallowedCapabilityError(
            f"Raw numeric cTrader payloadType={message_type} is disallowed; use named read-only message types"
        )
    if not isinstance(message_type, str) or not message_type.strip():
        raise DisallowedCapabilityError("cTrader message_type must be a non-empty string")

    cleaned = message_type.strip()
    blocked_lower = {m.lower(): m for m in CTRADER_BLOCKED_MUTATING_MESSAGE_TYPES}
    allowed_lower = {m.lower(): m for m in CTRADER_ALLOWED_MESSAGE_TYPES}

    if cleaned.lower() in blocked_lower:
        canonical_bad = blocked_lower[cleaned.lower()]
        raise DisallowedCapabilityError(
            f"cTrader mutating trade message {canonical_bad!r} is structurally forbidden on read-only adapter"
        )
    if any(
        bad_tok in cleaned.lower()
        for bad_tok in ("neworder", "cancelorder", "amendorder", "amendposition", "closeposition", "withdraw")
    ):
        raise DisallowedCapabilityError(
            f"cTrader mutating message {cleaned!r} is structurally forbidden on read-only adapter"
        )
    canonical_ok = allowed_lower.get(cleaned.lower())
    if canonical_ok is None:
        raise DisallowedCapabilityError(
            f"cTrader message {cleaned!r} is not in read-only allowlist {sorted(CTRADER_ALLOWED_MESSAGE_TYPES)}"
        )
    return canonical_ok


def _scale_money(val: Any, money_digits: int | None) -> float:
    if val is None:
        return 0.0
    fval = float(val)
    if money_digits is not None and money_digits > 0 and isinstance(val, int):
        fval = fval / float(10**money_digits)
    return 0.0 if fval == 0.0 else fval


def _parse_ctrader_timestamp(raw: Any, fallback: str) -> str:
    if raw is None or raw == "":
        return fallback
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        val = float(raw)
        # Spotware timestamps are UTC epoch milliseconds (e.g. 1768000000000)
        sec = val / 1000.0 if val > 1e11 else val
        return datetime.fromtimestamp(sec, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(raw, str):
        stripped = raw.strip()
        if stripped.isdigit():
            val = float(stripped)
            sec = val / 1000.0 if val > 1e11 else val
            return datetime.fromtimestamp(sec, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return parse_utc_timestamp(stripped, field_name="ctrader_timestamp").strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    return fallback


class CTraderReadOnlyOAuthAdapter(ReadOnlyBrokerAdapter):
    """Read-only Spotware cTrader Open API OAuth2 adapter (`Scope: ACCOUNTS` only)."""

    broker_id = "ctrader_oauth"
    display_name = "Spotware cTrader Open API Read-Only OAuth2 Adapter"
    approval_state = ProviderApprovalState.USER_KEY_SELF_ATTESTED
    default_origin_assurance = OriginAssurance.OPERATOR_RETRIEVED
    supports_subaccount_enumeration = True
    allowed_capabilities = (
        "read_account_list",
        "list_subaccounts",
        "fetch_deals",
        "fetch_cash_flows",
        "read_reconcile_positions",
    )

    def __init__(
        self,
        *,
        access_token: str = "",
        scope: str | Iterable[str] | int = SCOPE_ACCOUNTS,
        base_url: str = CTRADER_LIVE_BASE_URL,
        require_live: bool = True,
        reconcile_message_type: str = "ProtoOAReconcileReq",
        message_transport: CTraderMessageTransport | None = None,
        http_transport: HttpTransportCallable | Any | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        if env and env.get("N170_CTRADER_COMMERCIAL_APPROVED", "").strip().lower() in {
            "true",
            "1",
            "yes",
        }:
            self.approval_state = ProviderApprovalState.APPROVED_LIVE
        super().__init__()

        # Pre-flight scope check at initialization BEFORE any network call can occur!
        self._validated_scopes = validate_ctrader_oauth_scope(scope)
        self._reconcile_msg = validate_ctrader_message_type(reconcile_message_type)
        if self._reconcile_msg not in {"ProtoOAReconcileReq", "ProtoVAReconcileReq"}:
            raise ValueError(
                "reconcile_message_type must be 'ProtoOAReconcileReq' or 'ProtoVAReconcileReq'"
            )

        cleaned_base = validate_ssrf_safe_https_url(
            base_url or CTRADER_LIVE_BASE_URL,
            allowed_hosts={"openapi.ctrader.com", "live.ctraderapi.com"},
            require_live=require_live,
            label="cTrader Open API",
        )

        self._access_token = (access_token or "").strip()
        self._base_url = cleaned_base
        self._require_live = require_live
        self._message_transport = message_transport
        self._http_transport = http_transport
        self._raw_transcript_chunks: list[bytes] = []

    @property
    def validated_scopes(self) -> tuple[str, ...]:
        return self._validated_scopes

    def _blocked_mutation(self, msg_type: str) -> Any:
        validate_ctrader_message_type(msg_type)

    def place_order(self, *_args: Any, **_kwargs: Any) -> Any:
        return self._blocked_mutation("ProtoOANewOrderReq")

    def cancel_order(self, *_args: Any, **_kwargs: Any) -> Any:
        return self._blocked_mutation("ProtoOACancelOrderReq")

    def amend_order(self, *_args: Any, **_kwargs: Any) -> Any:
        return self._blocked_mutation("ProtoOAAmendOrderReq")

    def amend_position_sltp(self, *_args: Any, **_kwargs: Any) -> Any:
        return self._blocked_mutation("ProtoOAAmendPositionSLTPReq")

    def close_position(self, *_args: Any, **_kwargs: Any) -> Any:
        return self._blocked_mutation("ProtoOAClosePositionReq")

    def send_open_api_message(
        self,
        message_type: str | int,
        payload: Mapping[str, Any] | None = None,
        *,
        redact_ids: Sequence[str] = (),
    ) -> Mapping[str, Any]:
        """Validate and dispatch a strictly read-only cTrader Open API request."""
        canonical_type = validate_ctrader_message_type(message_type)
        # Re-verify credential scope invariant prior to every outbound request.
        validate_ctrader_oauth_scope(self._validated_scopes)

        if not self._access_token:
            raise ValueError("cTrader access_token must be non-empty")

        body_dict = {
            "payloadType": canonical_type,
            "payload": dict(payload or {}),
        }
        secrets = tuple(s for s in (self._access_token, *redact_ids) if s)

        if self._message_transport is not None:
            resp_obj = self._message_transport(canonical_type, dict(payload or {}))
            if not isinstance(resp_obj, Mapping):
                raise ConnectorHttpError(502, f"cTrader {canonical_type} returned non-mapping payload")
            encoded = json.dumps(resp_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self._raw_transcript_chunks.append(encoded)
            return resp_obj

        url = f"{self._base_url}/v2/rpc/{canonical_type}"
        raw_req = json.dumps(body_dict, separators=(",", ":")).encode("utf-8")
        resp = invoke_http_transport(
            self._http_transport,
            "POST",
            url,
            headers={
                "Authorization": f"Bearer {self._access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            body=raw_req,
            extra_secrets=secrets,
        )
        if resp.status_code < 200 or resp.status_code >= 300:
            safe_txt = redact_sensitive_text(resp.text()[:240], secrets)
            raise ConnectorHttpError(
                resp.status_code,
                f"cTrader {canonical_type} failed with HTTP {resp.status_code}: {safe_txt}",
            )
        self._raw_transcript_chunks.append(resp.body)
        parsed = resp.json()
        if not isinstance(parsed, Mapping):
            raise ConnectorHttpError(502, f"cTrader {canonical_type} returned invalid JSON object")
        # Unwrap optional {"payload": {...}} envelope if returned by JSON bridge
        inner = parsed.get("payload")
        if isinstance(inner, Mapping) and len(parsed) <= 3 and "ctidTraderAccount" not in parsed:
            merged = dict(inner)
            for k in ("permissionScope", "scope"):
                if k in parsed and k not in merged:
                    merged[k] = parsed[k]
            return merged
        return parsed

    def enumerate_accounts(self) -> list[dict[str, Any]]:
        """Execute ``ProtoOAGetAccountListByAccessTokenReq`` while enforcing read-only & live-account policy."""
        validate_ctrader_oauth_scope(self._validated_scopes)
        res = self.send_open_api_message(
            "ProtoOAGetAccountListByAccessTokenReq",
            {"accessToken": self._access_token},
        )

        # Enforce server-reported permissionScope BEFORE returning or using any account records!
        if "permissionScope" in res and res["permissionScope"] is not None:
            validate_ctrader_oauth_scope(res["permissionScope"])
        if "scope" in res and res["scope"] is not None:
            validate_ctrader_oauth_scope(res["scope"])

        raw_list = (
            res.get("ctidTraderAccount")
            or res.get("traderAccounts")
            or res.get("accounts")
            or []
        )
        if not isinstance(raw_list, list) or not raw_list:
            raise ConnectorHttpError(
                502, "cTrader ProtoOAGetAccountListByAccessTokenReq returned no accounts"
            )

        normalized_accounts: list[dict[str, Any]] = []
        for entry in raw_list:
            if not isinstance(entry, Mapping):
                continue
            acct_id = str(
                entry.get("ctidTraderAccountId") or entry.get("accountId") or ""
            ).strip()
            if not acct_id:
                continue
            raw_live = entry.get("isLive")
            is_live = (
                raw_live
                if isinstance(raw_live, bool)
                else str(raw_live).strip().lower() in {"true", "1", "live"}
            )
            if not is_live and self._require_live:
                raise PaperOrSandboxAccountRejectedError(
                    "cTrader demo account (isLive == False) rejected for live verification"
                )
            normalized_accounts.append(
                {
                    "ctidTraderAccountId": acct_id,
                    "traderLogin": str(entry.get("traderLogin") or ""),
                    "isLive": bool(is_live),
                    "currency": str(
                        entry.get("depositCurrency") or entry.get("currency") or "USD"
                    )
                    .strip()
                    .upper(),
                }
            )

        if not normalized_accounts:
            raise ConnectorHttpError(502, "cTrader account list contained no valid ctidTraderAccountId")
        return normalized_accounts

    def fetch_canonical_ledger(
        self,
        *,
        blinding_salt_hex: str,
        period_start_utc: str,
        period_end_utc: str,
        selected_account_ids: Sequence[str | int] | None = None,
        base_currency: str | None = None,
    ) -> CanonicalPortfolioLedger:
        """Fetch and reconcile cTrader accounts, deals, cash flows, and open positions."""
        self._raw_transcript_chunks.clear()
        validate_ctrader_oauth_scope(self._validated_scopes)

        start_dt = parse_utc_timestamp(period_start_utc, field_name="period_start_utc")
        end_dt = parse_utc_timestamp(period_end_utc, field_name="period_end_utc")
        if end_dt < start_dt:
            raise ValueError("period_end_utc must be >= period_start_utc")
        from_ms = int(start_dt.timestamp() * 1000)
        to_ms = int(end_dt.timestamp() * 1000)

        enumerated = self.enumerate_accounts()
        enum_ids = [a["ctidTraderAccountId"] for a in enumerated]
        redact_ids = tuple(
            [a["ctidTraderAccountId"] for a in enumerated]
            + [a["traderLogin"] for a in enumerated if a["traderLogin"]]
        )

        if selected_account_ids is None:
            connected = list(enumerated)
        else:
            wanted = {str(x).strip() for x in selected_account_ids if str(x).strip()}
            if not wanted or (wanted - set(enum_ids)):
                raise ValueError(
                    "selected_account_ids must be a non-empty subset of enumerated cTrader accounts"
                )
            connected = [a for a in enumerated if a["ctidTraderAccountId"] in wanted]

        env_tier = (
            EnvironmentTier.PAPER_OR_SANDBOX_REJECTED
            if any(not a["isLive"] for a in connected)
            else EnvironmentTier.LIVE_PRODUCTION
        )
        scope = (
            AccountScope.ALL_ENUMERATED_SUBACCOUNTS
            if {a["ctidTraderAccountId"] for a in connected} == set(enum_ids)
            else AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED
        )

        resolved_ccy = (base_currency or connected[0]["currency"] or "USD").strip().upper()
        trades: list[NormalizedTrade] = []
        flows: list[NormalizedFlow] = []
        ending_positions: list[NormalizedPosition] = []
        nav_by_ts: dict[str, NormalizedNavPoint] = {}

        for acct in connected:
            cid = acct["ctidTraderAccountId"]
            cid_param: int | str = int(cid) if cid.isdigit() else cid

            # 1. Historical Deals (ProtoOADealListReq)
            deal_res = self.send_open_api_message(
                "ProtoOADealListReq",
                {
                    "ctidTraderAccountId": cid_param,
                    "fromTimestamp": from_ms,
                    "toTimestamp": to_ms,
                },
                redact_ids=redact_ids,
            )
            raw_deals = deal_res.get("deal") or deal_res.get("deals") or []
            if isinstance(raw_deals, list):
                for d_idx, deal in enumerate(raw_deals):
                    if not isinstance(deal, Mapping):
                        continue
                    digits = deal.get("moneyDigits")
                    m_digits = int(digits) if isinstance(digits, int) else None
                    deal_id = str(deal.get("dealId") or f"{cid}-deal-{d_idx}")
                    sym_raw = str(deal.get("symbolName") or deal.get("symbol") or deal.get("symbolId") or "FX")
                    side_raw = deal.get("tradeSide") or deal.get("side")
                    if side_raw in {1, "1", "BUY", "buy", "ProtoOATradeSide.BUY"}:
                        side = "buy"
                    elif side_raw in {2, "2", "SELL", "sell", "ProtoOATradeSide.SELL"}:
                        side = "sell"
                    else:
                        continue

                    px = float(deal.get("executionPrice") or deal.get("price") or 0.0)
                    ts = _parse_ctrader_timestamp(
                        deal.get("executionTimestamp") or deal.get("createTimestamp"),
                        period_start_utc,
                    )
                    sym, ac, trade_ccy, default_mult, fx_to_base = _infer_mt_instrument_spec(
                        sym_raw, resolved_ccy, close_price=px
                    )

                    if "lots" in deal and deal["lots"] is not None:
                        qty = abs(float(deal["lots"]))
                        mult = default_mult
                    elif "lotSize" in deal and deal.get("lotSize"):
                        lot_sz = float(deal["lotSize"])
                        raw_v = float(deal.get("filledVolume") or deal.get("volume") or 0.0)
                        qty = abs(raw_v) / lot_sz
                        mult = lot_sz
                    else:
                        raw_v = abs(float(deal.get("filledVolume") or deal.get("volume") or 0.0))
                        if default_mult == 100_000.0 and raw_v >= 1000.0:
                            qty = raw_v / 100_000.0
                            mult = 100_000.0
                        else:
                            qty = raw_v
                            mult = default_mult

                    if qty <= 0.0 or px < 0.0:
                        continue

                    comm = abs(_scale_money(deal.get("commission"), m_digits))
                    close_detail = deal.get("closePositionDetail")
                    if isinstance(close_detail, Mapping):
                        cd_digits = close_detail.get("moneyDigits", m_digits)
                        cd_md = int(cd_digits) if isinstance(cd_digits, int) else None
                        if comm == 0.0 and close_detail.get("commission") is not None:
                            comm = abs(_scale_money(close_detail.get("commission"), cd_md))
                        swap_val = _scale_money(close_detail.get("swap"), cd_md)
                        if swap_val != 0.0:
                            flows.append(
                                NormalizedFlow(
                                    timestamp_utc=ts,
                                    kind=(
                                        FlowKind.MARGIN_INTEREST
                                        if swap_val < 0.0
                                        else FlowKind.INTEREST
                                    ),
                                    amount=swap_val,
                                    currency=resolved_ccy,
                                    symbol=sym,
                                    description=f"cTrader swap deal {deal_id}",
                                )
                            )
                        bal_after = _scale_money(close_detail.get("balance"), cd_md)
                        if bal_after > 0.0:
                            nav_by_ts[ts] = NormalizedNavPoint(
                                timestamp_utc=ts, nav_base=bal_after, cash_base=bal_after
                            )

                    trades.append(
                        NormalizedTrade(
                            venue="ctrader",
                            native_entry_id=f"ctrader-{deal_id}",
                            symbol=sym,
                            asset_class=ac,
                            side=side,
                            quantity=qty,
                            price=px,
                            timestamp_utc=ts,
                            currency=trade_ccy,
                            fx_rate_to_base=fx_to_base,
                            multiplier=mult,
                            commission=comm,
                        )
                    )

            # 2. Historical Cash Flows (ProtoOACashFlowHistoryListReq)
            cf_res = self.send_open_api_message(
                "ProtoOACashFlowHistoryListReq",
                {
                    "ctidTraderAccountId": cid_param,
                    "fromTimestamp": from_ms,
                    "toTimestamp": to_ms,
                },
                redact_ids=redact_ids,
            )
            raw_cfs = cf_res.get("depositWithdraw") or cf_res.get("cashFlows") or []
            if isinstance(raw_cfs, list):
                for cf in raw_cfs:
                    if not isinstance(cf, Mapping):
                        continue
                    digits = cf.get("moneyDigits")
                    m_digits = int(digits) if isinstance(digits, int) else None
                    delta = _scale_money(cf.get("delta") if "delta" in cf else cf.get("amount"), m_digits)
                    ts = _parse_ctrader_timestamp(
                        cf.get("changeBalanceTimestamp") or cf.get("timestamp"),
                        period_start_utc,
                    )
                    bal = _scale_money(cf.get("balance"), m_digits)
                    if bal > 0.0:
                        nav_by_ts[ts] = NormalizedNavPoint(
                            timestamp_utc=ts, nav_base=bal, cash_base=bal
                        )
                    if delta == 0.0:
                        continue
                    op_type = str(cf.get("operationType") or cf.get("type") or "").upper()
                    if "WITHDRAW" in op_type or delta < 0.0:
                        kind = FlowKind.WITHDRAWAL
                    else:
                        kind = FlowKind.DEPOSIT
                    flows.append(
                        NormalizedFlow(
                            timestamp_utc=ts,
                            kind=kind,
                            amount=delta,
                            currency=resolved_ccy,
                            description=str(cf.get("externalNote") or op_type or "cTrader cash flow"),
                        )
                    )

            # 3. Open Position Reconciliation (ProtoOAReconcileReq / ProtoVAReconcileReq)
            rec_res = self.send_open_api_message(
                self._reconcile_msg,
                {"ctidTraderAccountId": cid_param},
                redact_ids=redact_ids,
            )
            raw_positions = rec_res.get("position") or rec_res.get("positions") or []
            if isinstance(raw_positions, list):
                for pos in raw_positions:
                    if not isinstance(pos, Mapping):
                        continue
                    trade_data = pos.get("tradeData") if isinstance(pos.get("tradeData"), Mapping) else pos
                    sym_raw = str(
                        trade_data.get("symbolName")
                        or pos.get("symbolName")
                        or trade_data.get("symbolId")
                        or ""
                    )
                    if not sym_raw:
                        continue
                    px = float(pos.get("price") or trade_data.get("openPrice") or 0.0)
                    sym, ac, trade_ccy, default_mult, fx_to_base = _infer_mt_instrument_spec(
                        sym_raw, resolved_ccy, close_price=px
                    )
                    raw_side = trade_data.get("tradeSide") or pos.get("tradeSide")
                    sign = -1.0 if raw_side in {2, "2", "SELL", "sell"} else 1.0
                    if "lots" in trade_data and trade_data["lots"] is not None:
                        qty_abs = abs(float(trade_data["lots"]))
                    else:
                        vol_raw = abs(float(trade_data.get("volume") or pos.get("volume") or 0.0))
                        qty_abs = (
                            vol_raw / 100_000.0
                            if (default_mult == 100_000.0 and vol_raw >= 1000.0)
                            else vol_raw
                        )
                    if qty_abs <= 0.0:
                        continue
                    cost_val = qty_abs * px * default_mult
                    mv_val = float(pos.get("marketValue") or cost_val)
                    ending_positions.append(
                        NormalizedPosition(
                            prior_period_or_ending="ending",
                            symbol=sym,
                            asset_class=ac,
                            quantity=sign * qty_abs,
                            cost_basis=cost_val,
                            market_value=mv_val,
                            currency=trade_ccy,
                            fx_rate_to_base=fx_to_base,
                            multiplier=default_mult,
                        )
                    )

        source_sha = hashlib.sha256(b"\n".join(self._raw_transcript_chunks)).hexdigest()
        tag_seed = ",".join(sorted(a["ctidTraderAccountId"] for a in connected))
        return CanonicalPortfolioLedger(
            blinded_account_tag=compute_blinded_account_tag(
                "ctrader", tag_seed, blinding_salt_hex
            ),
            broker_id="ctrader",
            account_scope=scope,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=self.approval_state,
            environment_tier=env_tier,
            source_body_sha256=source_sha,
            base_currency=resolved_ccy,
            period_start_utc=start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            period_end_utc=end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            enumerated_subaccount_count=len(enum_ids),
            connected_subaccount_count=len(connected),
            ending_positions=ending_positions,
            nav_points=[nav_by_ts[k] for k in sorted(nav_by_ts)],
            trades=sorted(trades, key=lambda t: (t.timestamp_utc, t.native_entry_id)),
            flows=sorted(flows, key=lambda f: f.timestamp_utc),
            enabled_sections=[
                "ProtoOAGetAccountListByAccessTokenReq",
                "ProtoOADealListReq",
                "ProtoOACashFlowHistoryListReq",
                self._reconcile_msg,
            ],
        )


__all__ = [
    "CTRADER_ALLOWED_MESSAGE_TYPES",
    "CTRADER_ALLOWED_SCOPES",
    "CTRADER_BLOCKED_MUTATING_MESSAGE_TYPES",
    "CTRADER_LIVE_BASE_URL",
    "CTraderReadOnlyOAuthAdapter",
    "SCOPE_ACCOUNTS",
    "SCOPE_TRADING",
    "WriteCapableCredentialsRejectedError",
    "validate_ctrader_message_type",
    "validate_ctrader_oauth_scope",
]
