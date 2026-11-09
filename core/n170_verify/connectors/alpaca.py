"""Alpaca Markets live production read-only broker adapter.

Hardcodes ``https://api.alpaca.markets`` and rejects ``paper-api.alpaca.markets``
as well as paper trading account numbers (``PA...`` prefix), classifying them as
``EnvironmentTier.PAPER_OR_SANDBOX_REJECTED`` (and raising
``PaperOrSandboxAccountRejectedError`` when live verification is requested).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import re
from typing import Any
import urllib.parse

from n170_verify.connectors.ccxt_crypto import (
    ConnectorHttpError,
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


ALPACA_LIVE_BASE_URL = "https://api.alpaca.markets"
_PAPER_ALPACA_ACCOUNT_RE = re.compile(r"^PA[A-Z0-9_-]{3,}$", re.IGNORECASE)


def _validate_alpaca_live_url(base_url: str, *, require_live: bool) -> tuple[str, EnvironmentTier]:
    cleaned = validate_ssrf_safe_https_url(
        base_url or ALPACA_LIVE_BASE_URL,
        allowed_hosts={"api.alpaca.markets"},
        require_live=require_live,
        label="Alpaca",
    )
    parsed = urllib.parse.urlsplit(cleaned)
    host = (parsed.hostname or "").lower()
    if host != "api.alpaca.markets":
        if host != "paper-api.alpaca.markets":
            raise PaperOrSandboxAccountRejectedError(
                f"Alpaca host {host!r} rejected: only api.alpaca.markets is permitted"
            )
        return cleaned, EnvironmentTier.PAPER_OR_SANDBOX_REJECTED

    return ALPACA_LIVE_BASE_URL, EnvironmentTier.LIVE_PRODUCTION


class AlpacaReadOnlyAdapter(ReadOnlyBrokerAdapter):
    """Read-only live production connector for Alpaca Markets Trading API v2."""

    broker_id = "alpaca"
    display_name = "Alpaca Markets Live Read-Only Adapter"
    approval_state = ProviderApprovalState.USER_KEY_SELF_ATTESTED
    default_origin_assurance = OriginAssurance.OPERATOR_RETRIEVED
    supports_subaccount_enumeration = False
    allowed_capabilities = (
        "read_account_profile",
        "fetch_nav_history",
        "fetch_positions",
        "fetch_executions",
        "fetch_cash_flows",
        "fetch_corporate_actions",
    )

    def __init__(
        self,
        *,
        api_key_id: str = "",
        api_secret_key: str = "",
        oauth_access_token: str | None = None,
        base_url: str = ALPACA_LIVE_BASE_URL,
        env: Mapping[str, str] | None = None,
        require_live: bool = True,
        http_transport: HttpTransportCallable | Any | None = None,
    ) -> None:
        if oauth_access_token:
            self.approval_state = ProviderApprovalState.APPROVED_LIVE
        super().__init__()

        if env is not None:
            paper_flag = env.get("ALPACA_PAPER_TRADE", "").strip().lower()
            if paper_flag in {"true", "1", "yes"} and require_live:
                raise PaperOrSandboxAccountRejectedError(
                    "ALPACA_PAPER_TRADE=true is rejected for live Alpaca verification"
                )
            env_url = (
                env.get("APCA_API_BASE_URL")
                or env.get("ALPACA_BASE_URL")
                or env.get("ALPACA_API_BASE_URL")
            )
            if env_url and base_url == ALPACA_LIVE_BASE_URL:
                base_url = env_url

        resolved_url, initial_tier = _validate_alpaca_live_url(base_url, require_live=require_live)

        self._api_key_id = api_key_id.strip()
        self._api_secret_key = api_secret_key.strip()
        self._oauth_token = (oauth_access_token or "").strip()
        self._base_url = resolved_url
        self._initial_tier = initial_tier
        self._require_live = require_live
        self._transport = http_transport
        self._raw_transcript_chunks: list[bytes] = []

    def _secrets(self, extra: Sequence[str] = ()) -> tuple[str, ...]:
        return tuple(
            s for s in (self._api_key_id, self._api_secret_key, self._oauth_token, *extra) if s
        )

    def _auth_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._oauth_token:
            headers["Authorization"] = f"Bearer {self._oauth_token}"
        else:
            if not self._api_key_id or not self._api_secret_key:
                raise ValueError("Alpaca adapter requires api_key_id+api_secret_key or oauth_access_token")
            headers["APCA-API-KEY-ID"] = self._api_key_id
            headers["APCA-API-SECRET-KEY"] = self._api_secret_key
        return headers

    def _get_json(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        redact_ids: Sequence[str] = (),
    ) -> Any:
        q = {k: v for k, v in (params or {}).items() if v is not None}
        qs = urllib.parse.urlencode(q, doseq=True)
        url = f"{self._base_url}{path}" + (f"?{qs}" if qs else "")
        resp = invoke_http_transport(
            self._transport,
            "GET",
            url,
            headers=self._auth_headers(),
            extra_secrets=self._secrets(redact_ids),
        )
        if resp.status_code < 200 or resp.status_code >= 300:
            safe_msg = redact_sensitive_text(resp.text()[:240], self._secrets(redact_ids))
            raise ConnectorHttpError(
                resp.status_code,
                f"Alpaca GET {path} failed with HTTP {resp.status_code}: {safe_msg}",
            )
        self._raw_transcript_chunks.append(resp.body)
        return resp.json()

    def fetch_canonical_ledger(
        self,
        *,
        blinding_salt_hex: str,
        period_start_utc: str,
        period_end_utc: str,
    ) -> CanonicalPortfolioLedger:
        self._raw_transcript_chunks.clear()
        acct = self._get_json("/v2/account")
        if not isinstance(acct, Mapping):
            raise ConnectorHttpError(502, "Alpaca /v2/account returned invalid payload")

        acct_num = str(acct.get("account_number") or acct.get("id") or "").strip()
        if not acct_num:
            raise ConnectorHttpError(502, "Alpaca /v2/account missing account_number")

        is_paper_acct = bool(_PAPER_ALPACA_ACCOUNT_RE.match(acct_num)) or bool(
            acct.get("paper", False)
        )
        env_tier = self._initial_tier
        if is_paper_acct:
            if self._require_live:
                raise PaperOrSandboxAccountRejectedError(
                    "Alpaca paper trading account (PA... prefix) rejected for live verification"
                )
            env_tier = EnvironmentTier.PAPER_OR_SANDBOX_REJECTED

        base_ccy = str(acct.get("currency") or "USD").upper()
        redact_ids = (acct_num, str(acct.get("id") or ""))

        # Portfolio history -> NormalizedNavPoint
        hist = self._get_json(
            "/v2/account/portfolio/history",
            params={"timeframe": "1D", "start": period_start_utc, "end": period_end_utc},
            redact_ids=redact_ids,
        )
        nav_points: list[NormalizedNavPoint] = []
        if isinstance(hist, Mapping):
            ts_list = hist.get("timestamp") or []
            eq_list = hist.get("equity") or []
            for ts_raw, eq_raw in zip(ts_list, eq_list):
                if eq_raw is None or float(eq_raw) <= 0.0:
                    continue
                ts_iso = datetime.fromtimestamp(float(ts_raw), tz=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
                nav_points.append(NormalizedNavPoint(timestamp_utc=ts_iso, nav_base=float(eq_raw)))

        if not nav_points and acct.get("equity") is not None and float(acct["equity"]) > 0:
            nav_points.append(
                NormalizedNavPoint(
                    timestamp_utc=period_end_utc,
                    nav_base=float(acct["equity"]),
                    cash_base=float(acct.get("cash", 0.0)),
                )
            )

        # Open positions -> ending_positions
        pos_raw = self._get_json("/v2/positions", redact_ids=redact_ids)
        ending_positions: list[NormalizedPosition] = []
        if isinstance(pos_raw, list):
            for p in pos_raw:
                if not isinstance(p, Mapping):
                    continue
                sym = str(p.get("symbol") or "").strip()
                if not sym:
                    continue
                ac_raw = str(p.get("asset_class") or "us_equity").lower()
                if "option" in ac_raw:
                    ac = AssetClass.OPTION
                elif "crypto" in ac_raw:
                    ac = AssetClass.CRYPTO_SPOT
                else:
                    ac = AssetClass.EQUITY
                ending_positions.append(
                    NormalizedPosition(
                        prior_period_or_ending="ending",
                        symbol=sym,
                        asset_class=ac,
                        quantity=float(p.get("qty", 0.0)),
                        cost_basis=float(p.get("cost_basis", 0.0)),
                        market_value=float(p.get("market_value", 0.0)),
                        currency=base_ccy,
                    )
                )

        # Paginated account activities -> trades, flows, corporate_actions
        trades: list[NormalizedTrade] = []
        flows: list[NormalizedFlow] = []
        corp_actions: list[CorporateActionRecord] = []
        page_token: str | None = None
        for _ in range(100):
            act_params: dict[str, Any] = {
                "after": period_start_utc,
                "until": period_end_utc,
                "direction": "asc",
                "page_size": 100,
            }
            if page_token:
                act_params["page_token"] = page_token
            batch = self._get_json(
                "/v2/account/activities",
                params=act_params,
                redact_ids=redact_ids,
            )
            if not isinstance(batch, list) or not batch:
                break
            for item in batch:
                if not isinstance(item, Mapping):
                    continue
                atype = str(item.get("activity_type") or "").upper()
                act_id = str(item.get("id") or "")
                ts_str = str(
                    item.get("transaction_time") or item.get("date") or period_end_utc
                )
                if len(ts_str) == 10 and ts_str[4] == "-":
                    ts_str = f"{ts_str}T00:00:00Z"

                if atype == "FILL":
                    sym = str(item.get("symbol") or "").strip()
                    if not sym:
                        continue
                    trades.append(
                        NormalizedTrade(
                            venue="alpaca",
                            native_entry_id=act_id or f"alpaca-fill-{len(trades)}",
                            symbol=sym,
                            asset_class=AssetClass.CRYPTO_SPOT if "/" in sym else AssetClass.EQUITY,
                            side=str(item.get("side") or "buy"),
                            quantity=abs(float(item.get("qty", 0.0))),
                            price=float(item.get("price", 0.0)),
                            timestamp_utc=ts_str,
                            currency=base_ccy,
                        )
                    )
                elif atype in {"CSD", "CSW", "ACATC", "ACATS", "DIV", "DIVNRA", "INT", "FEE", "CFEE", "REG", "TAF"}:
                    net_amt = float(item.get("net_amount", 0.0))
                    if atype == "CSD":
                        kind = FlowKind.DEPOSIT
                    elif atype == "CSW":
                        kind = FlowKind.WITHDRAWAL
                    elif atype in {"ACATC", "ACATS"}:
                        kind = FlowKind.TRANSFER_IN_KIND if net_amt >= 0 else FlowKind.TRANSFER_OUT_KIND
                    elif atype == "DIV":
                        kind = FlowKind.DIVIDEND
                    elif atype == "DIVNRA":
                        kind = FlowKind.WITHHOLDING_TAX
                    elif atype == "INT":
                        kind = FlowKind.INTEREST if net_amt >= 0 else FlowKind.MARGIN_INTEREST
                    else:
                        kind = FlowKind.COMMISSION_FEE
                    flows.append(
                        NormalizedFlow(
                            timestamp_utc=ts_str,
                            kind=kind,
                            amount=net_amt,
                            currency=base_ccy,
                            symbol=item.get("symbol"),
                            description=str(item.get("description") or atype),
                        )
                    )
                elif atype in {"SPLIT", "OPEXP", "OPEXC", "OPASN", "SPIN", "MA", "NC"}:
                    sym = str(item.get("symbol") or "").strip()
                    if sym:
                        ca_map = {
                            "SPLIT": CorporateActionType.SPLIT,
                            "OPEXP": CorporateActionType.OPTION_EXPIRATION,
                            "OPEXC": CorporateActionType.OPTION_EXERCISE,
                            "OPASN": CorporateActionType.OPTION_ASSIGNMENT,
                            "SPIN": CorporateActionType.SPIN_OFF,
                            "MA": CorporateActionType.MERGER,
                            "NC": CorporateActionType.SYMBOL_CHANGE,
                        }
                        corp_actions.append(
                            CorporateActionRecord(
                                action_type=ca_map[atype],
                                timestamp_utc=ts_str,
                                symbol=sym,
                                quantity_delta=float(item.get("qty", 0.0) or 0.0),
                                description=str(item.get("description") or atype),
                            )
                        )

            if len(batch) < 100:
                break
            next_tok = str(batch[-1].get("id") or "").strip()
            if not next_tok or next_tok == page_token:
                break
            page_token = next_tok

        source_sha = hashlib.sha256(b"\n".join(self._raw_transcript_chunks)).hexdigest()
        claimed_origin = (
            OriginAssurance.SELF_REPORTED
            if env_tier == EnvironmentTier.PAPER_OR_SANDBOX_REJECTED
            else OriginAssurance.OPERATOR_RETRIEVED
        )
        return CanonicalPortfolioLedger(
            blinded_account_tag=compute_blinded_account_tag("alpaca", acct_num, blinding_salt_hex),
            broker_id="alpaca",
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
            claimed_origin_assurance=claimed_origin,
            provider_approval_state=self.approval_state,
            environment_tier=env_tier,
            source_body_sha256=source_sha,
            base_currency=base_ccy,
            period_start_utc=period_start_utc,
            period_end_utc=period_end_utc,
            ending_positions=ending_positions,
            nav_points=nav_points,
            trades=trades,
            flows=flows,
            corporate_actions=corp_actions,
            enabled_sections=["account", "portfolio_history", "positions", "activities"],
        )


__all__ = [
    "ALPACA_LIVE_BASE_URL",
    "AlpacaReadOnlyAdapter",
]
