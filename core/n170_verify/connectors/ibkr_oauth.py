"""Official IBKR Third-Party OAuth 1.0a & OAuth 2.0 `private_key_jwt` read-only adapter.

Onboarding reference: ``webapionboarding@interactivebrokers.com``.
In hosted multi-user mode, defaults to ``ProviderApprovalState.PENDING_PROVIDER_APPROVAL``
until ``N170_IBKR_CONSUMER_KEY`` is configured (Day-1 hosted users can immediately use
``IbkrFlexWebServiceAdapter`` or ``IbkrFlexOfflineAdapter`` while OAuth onboarding completes).

Enumerates all ``/portfolio/accounts`` (and ``/portfolio/subaccounts``) under the master
credential to distinguish complete subaccount consolidation
(``AccountScope.ALL_ENUMERATED_SUBACCOUNTS``) from partial subset selection
(``AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED``).
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping, Sequence
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from typing import Any
import urllib.parse

from n170_verify.connectors.ccxt_crypto import (
    ConnectorHttpError,
    HttpTransportCallable,
    PaperOrSandboxAccountRejectedError,
    ProviderApprovalRequiredError,
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


IBKR_ONBOARDING_CONTACT = "webapionboarding@interactivebrokers.com"
IBKR_WEB_API_BASE_URL = "https://api.ibkr.com/v1/api"
IBKR_OAUTH2_TOKEN_URL = "https://api.ibkr.com/v1/api/oauth2/api/v1/token"
JWT_BEARER_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

_PAPER_IBKR_ACCT_RE = re.compile(r"^D[UF][0-9]{4,}$", re.IGNORECASE)


def build_ibkr_oauth1a_authorization_header(
    *,
    method: str,
    url: str,
    consumer_key: str,
    access_token: str,
    live_session_token_b64: str,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> str:
    """Build IBKR Web API OAuth 1.0a ``HMAC-SHA256`` Authorization header using LST."""
    ts_str = str(timestamp if timestamp is not None else int(time.time()))
    nonce_str = nonce or secrets.token_hex(12)

    parsed = urllib.parse.urlsplit(url)
    base_uri = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

    oauth_params: dict[str, str] = {
        "oauth_consumer_key": consumer_key,
        "oauth_nonce": nonce_str,
        "oauth_signature_method": "HMAC-SHA256",
        "oauth_timestamp": ts_str,
        "oauth_token": access_token,
    }
    all_params = sorted(
        [(urllib.parse.quote(k, safe=""), urllib.parse.quote(v, safe="")) for k, v in query_pairs]
        + [(urllib.parse.quote(k, safe=""), urllib.parse.quote(v, safe="")) for k, v in oauth_params.items()]
    )
    normalized_param_str = "&".join(f"{k}={v}" for k, v in all_params)
    base_string = "&".join(
        [
            method.upper(),
            urllib.parse.quote(base_uri, safe=""),
            urllib.parse.quote(normalized_param_str, safe=""),
        ]
    )

    try:
        lst_bytes = base64.b64decode(live_session_token_b64)
    except Exception:
        lst_bytes = live_session_token_b64.encode("utf-8")

    sig_b64 = base64.b64encode(
        hmac.new(lst_bytes, base_string.encode("utf-8"), hashlib.sha256).digest()
    ).decode("ascii")
    oauth_params["oauth_signature"] = sig_b64

    header_items = ", ".join(
        f'{k}="{urllib.parse.quote(v, safe="")}"' for k, v in sorted(oauth_params.items())
    )
    return f"OAuth realm=\"limited_poa\", {header_items}"


class IbkrOAuthReadOnlyAdapter(ReadOnlyBrokerAdapter):
    """Official IBKR Third-Party OAuth 1.0a / OAuth 2.0 `private_key_jwt` read-only connector."""

    broker_id = "ibkr_oauth"
    display_name = "Interactive Brokers Official OAuth Web API"
    approval_state = ProviderApprovalState.PENDING_PROVIDER_APPROVAL
    default_origin_assurance = OriginAssurance.OPERATOR_RETRIEVED
    supports_subaccount_enumeration = True
    allowed_capabilities = (
        "read_account_profile",
        "list_subaccounts",
        "fetch_nav_history",
        "fetch_positions",
        "fetch_executions",
        "fetch_transactions",
    )

    def __init__(
        self,
        *,
        consumer_key: str | None = None,
        auth_mode: str = "oauth2_private_key_jwt",
        access_token: str | None = None,
        live_session_token_b64: str | None = None,
        client_assertion_jwt: str | None = None,
        hosted_mode: bool = True,
        env: Mapping[str, str] | None = None,
        base_url: str = IBKR_WEB_API_BASE_URL,
        http_transport: HttpTransportCallable | Any | None = None,
        require_live: bool = True,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        env_map = env if env is not None else os.environ
        resolved_consumer_key = (
            consumer_key
            if consumer_key is not None
            else env_map.get("N170_IBKR_CONSUMER_KEY", "")
        ).strip()

        if hosted_mode:
            self.approval_state = (
                ProviderApprovalState.APPROVED_LIVE
                if resolved_consumer_key
                else ProviderApprovalState.PENDING_PROVIDER_APPROVAL
            )
        else:
            self.approval_state = ProviderApprovalState.USER_KEY_SELF_ATTESTED

        super().__init__()

        norm_mode = auth_mode.strip().lower()
        if norm_mode not in {"oauth1a", "oauth2_private_key_jwt"}:
            raise ValueError("auth_mode must be 'oauth1a' or 'oauth2_private_key_jwt'")

        cleaned_base = validate_ssrf_safe_https_url(
            base_url or IBKR_WEB_API_BASE_URL,
            allowed_hosts={"api.ibkr.com"},
            require_live=require_live,
            label="IBKR OAuth",
        )

        self.auth_mode = norm_mode
        self.hosted_mode = hosted_mode
        self.onboarding_contact = IBKR_ONBOARDING_CONTACT
        self._consumer_key = resolved_consumer_key
        self._access_token = (access_token or "").strip()
        self._lst_b64 = (live_session_token_b64 or "").strip()
        self._client_assertion_jwt = (client_assertion_jwt or "").strip()
        self._base_url = cleaned_base
        self._transport = http_transport
        self._require_live = require_live
        self._now_fn = now_fn
        self._raw_transcript_chunks: list[bytes] = []

    def _secrets(self, extra: Sequence[str] = ()) -> tuple[str, ...]:
        return tuple(
            s
            for s in (
                self._consumer_key,
                self._access_token,
                self._lst_b64,
                self._client_assertion_jwt,
                *extra,
            )
            if s
        )

    def _assert_approved_to_execute(self) -> None:
        if self.approval_state == ProviderApprovalState.PENDING_PROVIDER_APPROVAL:
            raise ProviderApprovalRequiredError(
                f"IBKR hosted OAuth connector is gated PENDING_PROVIDER_APPROVAL until "
                f"N170_IBKR_CONSUMER_KEY is provisioned via {IBKR_ONBOARDING_CONTACT}. "
                f"Use IbkrFlexWebServiceAdapter or IbkrFlexOfflineAdapter for immediate Day-1 import."
            )

    def _ensure_oauth2_access_token(self) -> str:
        if self._access_token:
            return self._access_token
        if not self._client_assertion_jwt:
            raise ValueError(
                "oauth2_private_key_jwt requires either access_token or client_assertion_jwt"
            )
        form = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": self._consumer_key or "n170-self-hosted",
                "client_assertion_type": JWT_BEARER_ASSERTION_TYPE,
                "client_assertion": self._client_assertion_jwt,
                "scope": "portfolio.read trades.read statements.read",
            }
        ).encode("utf-8")
        resp = invoke_http_transport(
            self._transport,
            "POST",
            f"{self._base_url}/oauth2/api/v1/token",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            body=form,
            extra_secrets=self._secrets(),
        )
        if resp.status_code != 200:
            raise ConnectorHttpError(
                resp.status_code,
                f"IBKR OAuth 2.0 private_key_jwt token exchange failed with HTTP {resp.status_code}",
            )
        payload = resp.json()
        tok = str(payload.get("access_token", "")).strip()
        if not tok:
            raise ConnectorHttpError(500, "IBKR OAuth 2.0 token response missing access_token")
        self._access_token = tok
        return tok

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, Any] | None = None,
        redact_ids: Sequence[str] = (),
    ) -> Any:
        self._assert_approved_to_execute()
        url = f"{self._base_url}{path}"
        headers: dict[str, str] = {"Accept": "application/json"}
        body_bytes: bytes | None = None

        if json_body is not None:
            body_bytes = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"

        if self.auth_mode == "oauth1a":
            if not self._access_token or not self._lst_b64:
                raise ValueError("oauth1a requires access_token and live_session_token_b64")
            headers["Authorization"] = build_ibkr_oauth1a_authorization_header(
                method=method,
                url=url,
                consumer_key=self._consumer_key or "n170-self-hosted",
                access_token=self._access_token,
                live_session_token_b64=self._lst_b64,
                timestamp=int(self._now_fn()),
            )
        else:
            token = self._ensure_oauth2_access_token()
            headers["Authorization"] = f"Bearer {token}"

        resp = invoke_http_transport(
            self._transport,
            method,
            url,
            headers=headers,
            body=body_bytes,
            extra_secrets=self._secrets(redact_ids),
        )
        if resp.status_code < 200 or resp.status_code >= 300:
            safe_path = redact_sensitive_text(path, self._secrets(redact_ids))
            safe_msg = redact_sensitive_text(resp.text()[:200], self._secrets(redact_ids))
            raise ConnectorHttpError(
                resp.status_code,
                f"IBKR OAuth {method.upper()} {safe_path} failed with HTTP {resp.status_code}: {safe_msg}",
            )
        self._raw_transcript_chunks.append(resp.body)
        return resp.json()

    def enumerate_accounts(self) -> list[str]:
        """Enumerate all master & subaccounts via ``/portfolio/accounts``."""
        raw_accounts = self._request_json("GET", "/portfolio/accounts")
        if not isinstance(raw_accounts, list) or not raw_accounts:
            raise ConnectorHttpError(502, "IBKR /portfolio/accounts returned no accounts")

        account_ids: list[str] = []
        for entry in raw_accounts:
            if isinstance(entry, str):
                aid = entry.strip()
                is_paper = bool(_PAPER_IBKR_ACCT_RE.match(aid))
            elif isinstance(entry, Mapping):
                aid = str(entry.get("accountId") or entry.get("id") or "").strip()
                trading_type = str(entry.get("tradingType", "")).upper()
                is_paper = (
                    bool(_PAPER_IBKR_ACCT_RE.match(aid))
                    or bool(entry.get("isPaper", False))
                    or "PAPER" in trading_type
                )
            else:
                continue

            if not aid:
                continue
            if is_paper and self._require_live:
                raise PaperOrSandboxAccountRejectedError(
                    "IBKR paper subaccount detected in /portfolio/accounts; rejected for live verification"
                )
            if aid not in account_ids:
                account_ids.append(aid)

        if not account_ids:
            raise ConnectorHttpError(502, "No valid IBKR account identifiers returned")
        return account_ids

    def fetch_canonical_ledger(
        self,
        *,
        blinding_salt_hex: str,
        period_start_utc: str,
        period_end_utc: str,
        selected_account_ids: Sequence[str] | None = None,
        base_currency: str = "USD",
    ) -> CanonicalPortfolioLedger:
        """Enumerate all `/portfolio/accounts` and consolidate selected subaccount(s)."""
        self._raw_transcript_chunks.clear()
        enumerated_ids = self.enumerate_accounts()

        if selected_account_ids is None:
            connected_ids = list(enumerated_ids)
        else:
            requested = [s.strip() for s in selected_account_ids if s.strip()]
            if not requested:
                raise ValueError("selected_account_ids must not be empty when specified")
            unknown = set(requested) - set(enumerated_ids)
            if unknown:
                raise ValueError(
                    "Requested IBKR subaccount selection contains account(s) not present in /portfolio/accounts"
                )
            connected_ids = [aid for aid in enumerated_ids if aid in set(requested)]

        scope = (
            AccountScope.ALL_ENUMERATED_SUBACCOUNTS
            if set(connected_ids) == set(enumerated_ids)
            else AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED
        )

        ending_positions: list[NormalizedPosition] = []
        total_nav = 0.0
        for aid in connected_ids:
            summary = self._request_json(
                "GET", f"/portfolio/{aid}/summary", redact_ids=enumerated_ids
            )
            if isinstance(summary, Mapping):
                nlv = summary.get("netliquidation") or summary.get("netLiquidationValue") or {}
                if isinstance(nlv, Mapping):
                    total_nav += float(nlv.get("amount", 0.0))
                elif isinstance(nlv, (int, float)):
                    total_nav += float(nlv)

            pos_list = self._request_json(
                "GET", f"/portfolio/{aid}/positions/0", redact_ids=enumerated_ids
            )
            if isinstance(pos_list, list):
                for p in pos_list:
                    if not isinstance(p, Mapping):
                        continue
                    sym = str(p.get("contractDesc") or p.get("ticker") or p.get("symbol") or "").strip()
                    if not sym:
                        continue
                    ac_str = str(p.get("assetClass", "STK")).upper()
                    ac = AssetClass.OPTION if ac_str in {"OPT", "FOP"} else AssetClass.EQUITY
                    qty = float(p.get("position", 0.0))
                    avg_cost = float(p.get("avgCost", 0.0))
                    mkt_val = float(p.get("mktValue", 0.0))
                    ccy = str(p.get("currency", base_currency)).upper()
                    ending_positions.append(
                        NormalizedPosition(
                            prior_period_or_ending="ending",
                            symbol=sym,
                            asset_class=ac,
                            quantity=qty,
                            cost_basis=qty * avg_cost,
                            market_value=mkt_val,
                            currency=ccy,
                        )
                    )

        trades_resp = self._request_json(
            "GET", "/iserver/account/trades", redact_ids=enumerated_ids
        )
        trades: list[NormalizedTrade] = []
        if isinstance(trades_resp, list):
            conn_set = set(connected_ids)
            for idx, tr in enumerate(trades_resp):
                if not isinstance(tr, Mapping):
                    continue
                tr_acct = str(tr.get("account") or tr.get("acctId") or "").strip()
                if tr_acct and tr_acct not in conn_set:
                    continue
                sym = str(tr.get("symbol") or tr.get("contract_description_1") or "").strip()
                if not sym:
                    continue
                exec_id = str(tr.get("execution_id") or tr.get("order_ref") or f"ibkr-oauth-{idx}")
                side = "buy" if str(tr.get("side", "B")).upper().startswith("B") else "sell"
                trades.append(
                    NormalizedTrade(
                        venue="ibkr_oauth",
                        native_entry_id=exec_id,
                        symbol=sym,
                        asset_class=AssetClass.EQUITY,
                        side=side,
                        quantity=abs(float(tr.get("size", 0.0))),
                        price=float(tr.get("price", 0.0)),
                        timestamp_utc=str(tr.get("trade_time_r_iso") or period_end_utc),
                        currency=base_currency,
                        commission=abs(float(tr.get("commission", 0.0))),
                    )
                )

        flows: list[NormalizedFlow] = []
        tx_resp = self._request_json(
            "POST",
            "/pa/transactions",
            json_body={"acctIds": connected_ids, "currency": base_currency},
            redact_ids=enumerated_ids,
        )
        if isinstance(tx_resp, Mapping):
            for tx in (tx_resp.get("transactions") or []):
                if not isinstance(tx, Mapping):
                    continue
                amt = float(tx.get("amt", 0.0))
                raw_type = str(tx.get("type", "")).lower()
                if "deposit" in raw_type or ("transfer" in raw_type and amt > 0):
                    kind = FlowKind.DEPOSIT
                elif "withdraw" in raw_type or ("transfer" in raw_type and amt < 0):
                    kind = FlowKind.WITHDRAWAL
                elif "dividend" in raw_type:
                    kind = FlowKind.DIVIDEND
                else:
                    kind = FlowKind.OTHER_INTERNAL
                flows.append(
                    NormalizedFlow(
                        timestamp_utc=str(tx.get("date") or period_end_utc),
                        kind=kind,
                        amount=amt,
                        currency=str(tx.get("cur", base_currency)).upper(),
                        description=str(tx.get("desc", "")),
                    )
                )

        nav_points = (
            [NormalizedNavPoint(timestamp_utc=period_end_utc, nav_base=total_nav)]
            if total_nav > 0.0
            else []
        )
        source_sha = hashlib.sha256(b"\n".join(self._raw_transcript_chunks)).hexdigest()
        raw_tag_seed = ",".join(sorted(connected_ids))
        return CanonicalPortfolioLedger(
            blinded_account_tag=compute_blinded_account_tag("ibkr", raw_tag_seed, blinding_salt_hex),
            broker_id="ibkr_oauth",
            account_scope=scope,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=self.approval_state,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            source_body_sha256=source_sha,
            base_currency=base_currency,
            period_start_utc=period_start_utc,
            period_end_utc=period_end_utc,
            enumerated_subaccount_count=len(enumerated_ids),
            connected_subaccount_count=len(connected_ids),
            ending_positions=ending_positions,
            nav_points=nav_points,
            trades=trades,
            flows=flows,
            enabled_sections=["portfolio_accounts", "summary", "positions", "trades", "pa_transactions"],
        )


__all__ = [
    "IBKR_OAUTH2_TOKEN_URL",
    "IBKR_ONBOARDING_CONTACT",
    "IBKR_WEB_API_BASE_URL",
    "IbkrOAuthReadOnlyAdapter",
    "JWT_BEARER_ASSERTION_TYPE",
    "build_ibkr_oauth1a_authorization_header",
]
