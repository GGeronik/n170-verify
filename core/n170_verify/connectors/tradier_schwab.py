"""Tradier & Charles Schwab read-only brokerage adapters.

- ``TradierReadOnlyAdapter``: Enumerates all ``account_number`` records from
  ``/v1/user/profile`` (``ALL_ENUMERATED_SUBACCOUNTS`` vs
  ``SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED``), redacts ``/v1/accounts/{account_id}/``
  to ``/v1/accounts/[REDACTED]/`` across all logs/exceptions/witness targets, and
  blocks ``sandbox.tradier.com``.
- ``SchwabReadOnlyAdapter``: Gated ``PENDING_PROVIDER_APPROVAL`` by default in hosted
  multi-user mode until ``N170_SCHWAB_COMMERCIAL_APPROVED=true`` is set; enumerates
  ``/trader/v1/accounts/accountNumbers`` and audits ``/transactions`` for internal
  journal transfers (``FlowKind.INTERNAL_SUBACCOUNT_TRANSFER``).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import os
import re
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


TRADIER_LIVE_BASE_URL = "https://api.tradier.com"
SCHWAB_LIVE_BASE_URL = "https://api.schwabapi.com"

_TRADIER_ACCT_PATH_RE = re.compile(r"(/v\d+/accounts/)([^/?#\s'\"]+)", re.IGNORECASE)


def redact_tradier_account_path(text: str, extra_secrets: Sequence[str] = ()) -> str:
    """Redact ``/v1/accounts/{account_id}`` -> ``/v1/accounts/[REDACTED]`` plus tokens."""
    def _sub(match: re.Match[str]) -> str:
        prefix, seg = match.group(1), match.group(2)
        if seg.strip().lower() in {"[redacted]", "<redacted>", "redacted", "accountnumbers"}:
            return match.group(0)
        return f"{prefix}[REDACTED]"

    step1 = _TRADIER_ACCT_PATH_RE.sub(_sub, text or "")
    return redact_sensitive_text(step1, extra_secrets)


def _normalize_iso_utc(raw: str | None, fallback: str) -> str:
    if not raw or not raw.strip():
        return fallback
    cleaned = raw.strip()
    if len(cleaned) == 10 and cleaned[4] == "-" and cleaned[7] == "-":
        return f"{cleaned}T00:00:00Z"
    if cleaned.endswith("+0000"):
        return cleaned[:-5] + "Z"
    if not cleaned.endswith(("Z", "z")) and "+" not in cleaned[10:]:
        return f"{cleaned}Z"
    return cleaned


class TradierReadOnlyAdapter(ReadOnlyBrokerAdapter):
    """Read-only connector for Tradier live brokerage REST API (`/v1/`)."""

    broker_id = "tradier"
    display_name = "Tradier Brokerage Live Read-Only Adapter"
    approval_state = ProviderApprovalState.USER_KEY_SELF_ATTESTED
    default_origin_assurance = OriginAssurance.OPERATOR_RETRIEVED
    supports_subaccount_enumeration = True
    allowed_capabilities = (
        "read_account_profile",
        "list_subaccounts",
        "read_balances",
        "fetch_positions",
        "fetch_transactions",
    )

    def __init__(
        self,
        *,
        access_token: str,
        approval_state: ProviderApprovalState | str | None = None,
        base_url: str = TRADIER_LIVE_BASE_URL,
        require_live: bool = True,
        http_transport: HttpTransportCallable | Any | None = None,
    ) -> None:
        if approval_state is not None:
            self.approval_state = ProviderApprovalState(approval_state)
        super().__init__()
        cleaned_base = validate_ssrf_safe_https_url(
            base_url or TRADIER_LIVE_BASE_URL,
            allowed_hosts={"api.tradier.com"},
            require_live=require_live,
            label="Tradier",
        )
        host = (urllib.parse.urlsplit(cleaned_base).hostname or "").rstrip(".").lower()
        if host == "sandbox.tradier.com" or host.endswith(".sandbox.tradier.com"):
            raise PaperOrSandboxAccountRejectedError(
                f"Tradier host {host!r} rejected: sandbox.tradier.com and non-live endpoints are blocked"
            )
        tok = (access_token or "").strip()
        if not tok:
            raise ValueError("Tradier access_token must be non-empty")

        self._access_token = tok
        self._base_url = cleaned_base
        self._require_live = require_live
        self._transport = http_transport
        self._raw_transcript_chunks: list[bytes] = []

    def _get_json(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        redact_ids: Sequence[str] = (),
    ) -> Any:
        q = {k: v for k, v in (params or {}).items() if v is not None}
        qs = urllib.parse.urlencode(q)
        url = f"{self._base_url}{path}" + (f"?{qs}" if qs else "")
        secrets = (self._access_token, *redact_ids)
        try:
            resp = invoke_http_transport(
                self._transport,
                "GET",
                url,
                headers={
                    "Authorization": f"Bearer {self._access_token}",
                    "Accept": "application/json",
                },
                extra_secrets=secrets,
            )
        except ConnectorHttpError as exc:
            raise ConnectorHttpError(
                exc.status_code,
                redact_tradier_account_path(str(exc), secrets),
                headers=exc.headers,
            ) from None

        if resp.status_code < 200 or resp.status_code >= 300:
            safe_path = redact_tradier_account_path(path, secrets)
            safe_body = redact_tradier_account_path(resp.text()[:240], secrets)
            raise ConnectorHttpError(
                resp.status_code,
                f"Tradier GET {safe_path} failed with HTTP {resp.status_code}: {safe_body}",
            )
        self._raw_transcript_chunks.append(resp.body)
        return resp.json()

    def enumerate_accounts(self) -> list[str]:
        """Enumerate all `account_number` entries from `/v1/user/profile`."""
        payload = self._get_json("/v1/user/profile")
        profile = payload.get("profile") if isinstance(payload, Mapping) else None
        if not isinstance(profile, Mapping):
            raise ConnectorHttpError(502, "Tradier /v1/user/profile missing profile object")

        raw_acct = profile.get("account")
        acct_entries: list[Mapping[str, Any]] = []
        if isinstance(raw_acct, Mapping):
            acct_entries = [raw_acct]
        elif isinstance(raw_acct, list):
            acct_entries = [a for a in raw_acct if isinstance(a, Mapping)]

        account_numbers: list[str] = []
        for entry in acct_entries:
            anum = str(entry.get("account_number") or "").strip()
            if not anum:
                continue
            classification = str(entry.get("classification") or entry.get("type") or "").lower()
            if "paper" in classification or "sandbox" in classification:
                if self._require_live:
                    raise PaperOrSandboxAccountRejectedError(
                        "Tradier paper/sandbox account classification rejected"
                    )
            if anum not in account_numbers:
                account_numbers.append(anum)

        if not account_numbers:
            raise ConnectorHttpError(502, "Tradier /v1/user/profile returned no account_number entries")
        return account_numbers

    def fetch_canonical_ledger(
        self,
        *,
        blinding_salt_hex: str,
        period_start_utc: str,
        period_end_utc: str,
        selected_account_numbers: Sequence[str] | None = None,
    ) -> CanonicalPortfolioLedger:
        self._raw_transcript_chunks.clear()
        enumerated = self.enumerate_accounts()

        if selected_account_numbers is None:
            connected = list(enumerated)
        else:
            req = [s.strip() for s in selected_account_numbers if s.strip()]
            if not req or (set(req) - set(enumerated)):
                raise ValueError(
                    "selected_account_numbers must be a non-empty subset of enumerated Tradier accounts"
                )
            connected = [a for a in enumerated if a in set(req)]

        scope = (
            AccountScope.ALL_ENUMERATED_SUBACCOUNTS
            if set(connected) == set(enumerated)
            else AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED
        )

        total_equity = 0.0
        total_cash = 0.0
        ending_positions: list[NormalizedPosition] = []
        trades: list[NormalizedTrade] = []
        flows: list[NormalizedFlow] = []
        corp_actions: list[CorporateActionRecord] = []

        for acct_num in connected:
            bal_payload = self._get_json(
                f"/v1/accounts/{acct_num}/balances",
                redact_ids=enumerated,
            )
            balances = bal_payload.get("balances") if isinstance(bal_payload, Mapping) else {}
            if isinstance(balances, Mapping):
                total_equity += float(balances.get("total_equity", 0.0))
                total_cash += float(balances.get("total_cash", 0.0))

            pos_payload = self._get_json(
                f"/v1/accounts/{acct_num}/positions",
                redact_ids=enumerated,
            )
            pos_root = pos_payload.get("positions") if isinstance(pos_payload, Mapping) else None
            raw_pos = pos_root.get("position") if isinstance(pos_root, Mapping) else None
            pos_list = (
                [raw_pos]
                if isinstance(raw_pos, Mapping)
                else (raw_pos if isinstance(raw_pos, list) else [])
            )
            for p in pos_list:
                if not isinstance(p, Mapping):
                    continue
                sym = str(p.get("symbol") or "").strip()
                if not sym:
                    continue
                qty = float(p.get("quantity", 0.0))
                cb = float(p.get("cost_basis", 0.0))
                mv = float(p.get("market_value", cb))
                ending_positions.append(
                    NormalizedPosition(
                        prior_period_or_ending="ending",
                        symbol=sym,
                        asset_class=AssetClass.OPTION if len(sym) > 12 else AssetClass.EQUITY,
                        quantity=qty,
                        cost_basis=cb,
                        market_value=mv,
                        currency="USD",
                    )
                )

            hist_payload = self._get_json(
                f"/v1/accounts/{acct_num}/history",
                params={
                    "start": period_start_utc[:10],
                    "end": period_end_utc[:10],
                },
                redact_ids=enumerated,
            )
            hist_root = hist_payload.get("history") if isinstance(hist_payload, Mapping) else None
            raw_ev = hist_root.get("event") if isinstance(hist_root, Mapping) else None
            ev_list = (
                [raw_ev]
                if isinstance(raw_ev, Mapping)
                else (raw_ev if isinstance(raw_ev, list) else [])
            )
            for idx, ev in enumerate(ev_list):
                if not isinstance(ev, Mapping):
                    continue
                etype = str(ev.get("type") or "").lower()
                ts_iso = _normalize_iso_utc(str(ev.get("date") or ""), period_end_utc)
                amt = float(ev.get("amount", 0.0))

                if etype == "trade":
                    tr_det = ev.get("trade") if isinstance(ev.get("trade"), Mapping) else ev
                    sym = str(tr_det.get("symbol") or "").strip()
                    if not sym:
                        continue
                    tt = str(tr_det.get("trade_type") or "buy").lower()
                    side = "sell" if "sell" in tt else "buy"
                    trades.append(
                        NormalizedTrade(
                            venue="tradier",
                            native_entry_id=f"tradier-{len(trades)}-{idx}",
                            symbol=sym,
                            asset_class=(
                                AssetClass.OPTION
                                if str(tr_det.get("SecurityType", "")).lower() == "option" or len(sym) > 12
                                else AssetClass.EQUITY
                            ),
                            side=side,
                            quantity=abs(float(tr_det.get("quantity", 0.0))),
                            price=abs(float(tr_det.get("price", 0.0))),
                            timestamp_utc=ts_iso,
                            currency="USD",
                            commission=abs(float(tr_det.get("commission", 0.0))),
                        )
                    )
                elif etype in {"ach", "wire", "journal", "dividend", "interest", "fee"}:
                    if etype in {"ach", "wire"}:
                        kind = FlowKind.DEPOSIT if amt >= 0 else FlowKind.WITHDRAWAL
                    elif etype == "journal":
                        kind = FlowKind.INTERNAL_SUBACCOUNT_TRANSFER
                    elif etype == "dividend":
                        kind = FlowKind.DIVIDEND
                    elif etype == "interest":
                        kind = FlowKind.INTEREST if amt >= 0 else FlowKind.MARGIN_INTEREST
                    else:
                        kind = FlowKind.COMMISSION_FEE
                    flows.append(
                        NormalizedFlow(
                            timestamp_utc=ts_iso,
                            kind=kind,
                            amount=amt,
                            currency="USD",
                            description=etype,
                        )
                    )
                elif etype == "option":
                    opt_det = ev.get("option") if isinstance(ev.get("option"), Mapping) else ev
                    sym = str(opt_det.get("symbol") or "").strip()
                    opt_t = str(opt_det.get("option_type") or "expiration").lower()
                    if sym:
                        ca_type = (
                            CorporateActionType.OPTION_ASSIGNMENT
                            if "assign" in opt_t
                            else (
                                CorporateActionType.OPTION_EXERCISE
                                if "exerc" in opt_t
                                else CorporateActionType.OPTION_EXPIRATION
                            )
                        )
                        corp_actions.append(
                            CorporateActionRecord(
                                action_type=ca_type,
                                timestamp_utc=ts_iso,
                                symbol=sym,
                                quantity_delta=float(opt_det.get("quantity", 0.0)),
                                description=opt_t,
                            )
                        )

        nav_points = (
            [NormalizedNavPoint(timestamp_utc=period_end_utc, nav_base=total_equity, cash_base=total_cash)]
            if total_equity > 0.0
            else []
        )
        source_sha = hashlib.sha256(b"\n".join(self._raw_transcript_chunks)).hexdigest()
        raw_tag_seed = ",".join(sorted(connected))
        return CanonicalPortfolioLedger(
            blinded_account_tag=compute_blinded_account_tag("tradier", raw_tag_seed, blinding_salt_hex),
            broker_id="tradier",
            account_scope=scope,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=self.approval_state,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            source_body_sha256=source_sha,
            base_currency="USD",
            period_start_utc=period_start_utc,
            period_end_utc=period_end_utc,
            enumerated_subaccount_count=len(enumerated),
            connected_subaccount_count=len(connected),
            ending_positions=ending_positions,
            nav_points=nav_points,
            trades=trades,
            flows=flows,
            corporate_actions=corp_actions,
            enabled_sections=["user_profile", "balances", "positions", "history"],
        )


class SchwabReadOnlyAdapter(ReadOnlyBrokerAdapter):
    """Read-only Charles Schwab Trader API v1 adapter with hosted approval gate & journal audit."""

    broker_id = "schwab"
    display_name = "Charles Schwab Trader API Read-Only Adapter"
    approval_state = ProviderApprovalState.PENDING_PROVIDER_APPROVAL
    default_origin_assurance = OriginAssurance.OPERATOR_RETRIEVED
    supports_subaccount_enumeration = True
    allowed_capabilities = (
        "read_account_profile",
        "list_subaccounts",
        "read_balances",
        "fetch_positions",
        "fetch_transactions",
    )

    def __init__(
        self,
        *,
        access_token: str = "",
        hosted_mode: bool = True,
        env: Mapping[str, str] | None = None,
        base_url: str = SCHWAB_LIVE_BASE_URL,
        http_transport: HttpTransportCallable | Any | None = None,
    ) -> None:
        env_map = env if env is not None else os.environ
        commercial_ok = (
            env_map.get("N170_SCHWAB_COMMERCIAL_APPROVED", "").strip().lower() == "true"
        )
        if hosted_mode:
            self.approval_state = (
                ProviderApprovalState.APPROVED_LIVE
                if commercial_ok
                else ProviderApprovalState.PENDING_PROVIDER_APPROVAL
            )
        else:
            self.approval_state = ProviderApprovalState.USER_KEY_SELF_ATTESTED

        super().__init__()
        cleaned_base = validate_ssrf_safe_https_url(
            base_url or SCHWAB_LIVE_BASE_URL,
            allowed_hosts={"api.schwabapi.com"},
            require_live=True,
            label="Schwab",
        )
        self.hosted_mode = hosted_mode
        self._access_token = (access_token or "").strip()
        self._base_url = cleaned_base
        self._transport = http_transport
        self._raw_transcript_chunks: list[bytes] = []

    def _assert_approved(self) -> None:
        if self.approval_state == ProviderApprovalState.PENDING_PROVIDER_APPROVAL:
            raise ProviderApprovalRequiredError(
                "Schwab Trader API is gated PENDING_PROVIDER_APPROVAL in hosted multi-user mode "
                "until N170_SCHWAB_COMMERCIAL_APPROVED=true. Use SchwabOfflineCsvAdapter for Day-1 CSV import."
            )

    def _get_json(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        redact_ids: Sequence[str] = (),
    ) -> Any:
        self._assert_approved()
        if not self._access_token:
            raise ValueError("Schwab access_token is required")
        q = {k: v for k, v in (params or {}).items() if v is not None}
        qs = urllib.parse.urlencode(q)
        url = f"{self._base_url}{path}" + (f"?{qs}" if qs else "")
        secrets = (self._access_token, *redact_ids)
        resp = invoke_http_transport(
            self._transport,
            "GET",
            url,
            headers={
                "Authorization": f"Bearer {self._access_token}",
                "Accept": "application/json",
            },
            extra_secrets=secrets,
        )
        if resp.status_code < 200 or resp.status_code >= 300:
            safe_path = redact_sensitive_text(path, secrets)
            safe_msg = redact_sensitive_text(resp.text()[:200], secrets)
            raise ConnectorHttpError(
                resp.status_code,
                f"Schwab GET {safe_path} failed with HTTP {resp.status_code}: {safe_msg}",
            )
        self._raw_transcript_chunks.append(resp.body)
        return resp.json()

    def fetch_canonical_ledger(
        self,
        *,
        blinding_salt_hex: str,
        period_start_utc: str,
        period_end_utc: str,
        selected_account_hashes: Sequence[str] | None = None,
    ) -> CanonicalPortfolioLedger:
        self._raw_transcript_chunks.clear()
        acct_nums_raw = self._get_json("/trader/v1/accounts/accountNumbers")
        if not isinstance(acct_nums_raw, list) or not acct_nums_raw:
            raise ConnectorHttpError(502, "Schwab /trader/v1/accounts/accountNumbers returned no accounts")

        hash_to_plain: dict[str, str] = {}
        for item in acct_nums_raw:
            if isinstance(item, Mapping):
                hv = str(item.get("hashValue") or "").strip()
                an = str(item.get("accountNumber") or hv).strip()
                if hv:
                    hash_to_plain[hv] = an

        all_hashes = list(hash_to_plain.keys())
        redact_ids = [*all_hashes, *hash_to_plain.values()]

        if selected_account_hashes is None:
            connected_hashes = list(all_hashes)
        else:
            req = [h.strip() for h in selected_account_hashes if h.strip()]
            if not req or (set(req) - set(all_hashes)):
                raise ValueError("selected_account_hashes must be a subset of enumerated Schwab account hashes")
            connected_hashes = [h for h in all_hashes if h in set(req)]

        scope = (
            AccountScope.ALL_ENUMERATED_SUBACCOUNTS
            if set(connected_hashes) == set(all_hashes)
            else AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED
        )

        total_liq = 0.0
        ending_positions: list[NormalizedPosition] = []
        trades: list[NormalizedTrade] = []
        flows: list[NormalizedFlow] = []
        warnings: list[str] = []
        journal_transfer_count = 0

        for hv in connected_hashes:
            acct_doc = self._get_json(
                f"/trader/v1/accounts/{hv}",
                params={"fields": "positions"},
                redact_ids=redact_ids,
            )
            sec_acct = acct_doc.get("securitiesAccount") if isinstance(acct_doc, Mapping) else {}
            if isinstance(sec_acct, Mapping):
                cur_bal = sec_acct.get("currentBalances") or {}
                if isinstance(cur_bal, Mapping):
                    total_liq += float(cur_bal.get("liquidationValue", 0.0))
                for p in sec_acct.get("positions") or []:
                    if not isinstance(p, Mapping):
                        continue
                    inst = p.get("instrument") or {}
                    sym = str(inst.get("symbol") or "").strip()
                    if not sym:
                        continue
                    qty = float(p.get("longQuantity", 0.0)) - float(p.get("shortQuantity", 0.0))
                    mv = float(p.get("marketValue", 0.0))
                    avg_px = float(p.get("averagePrice", 0.0))
                    ending_positions.append(
                        NormalizedPosition(
                            prior_period_or_ending="ending",
                            symbol=sym,
                            asset_class=(
                                AssetClass.OPTION
                                if str(inst.get("assetType", "")).upper() == "OPTION"
                                else AssetClass.EQUITY
                            ),
                            quantity=qty,
                            cost_basis=abs(qty) * avg_px,
                            market_value=mv,
                            currency="USD",
                        )
                    )

            tx_list = self._get_json(
                f"/trader/v1/accounts/{hv}/transactions",
                params={"startDate": period_start_utc, "endDate": period_end_utc},
                redact_ids=redact_ids,
            )
            if isinstance(tx_list, list):
                for idx, tx in enumerate(tx_list):
                    if not isinstance(tx, Mapping):
                        continue
                    ttype = str(tx.get("type") or "").upper()
                    desc = str(tx.get("description") or "")
                    desc_upper = desc.upper()
                    ts_iso = _normalize_iso_utc(
                        str(tx.get("time") or tx.get("tradeDate") or ""), period_end_utc
                    )
                    net_amt = float(tx.get("netAmount", 0.0))

                    if ttype == "TRADE":
                        items = tx.get("transferItems") or []
                        for item in items:
                            if not isinstance(item, Mapping):
                                continue
                            inst = item.get("instrument") or {}
                            if str(inst.get("assetType", "")).upper() == "CURRENCY":
                                continue
                            sym = str(inst.get("symbol") or "").strip()
                            if not sym:
                                continue
                            amt_qty = float(item.get("amount", 0.0))
                            px = abs(float(item.get("price", 0.0)))
                            trades.append(
                                NormalizedTrade(
                                    venue="schwab",
                                    native_entry_id=str(tx.get("activityId") or f"schwab-{idx}"),
                                    symbol=sym,
                                    asset_class=(
                                        AssetClass.OPTION
                                        if str(inst.get("assetType", "")).upper() == "OPTION"
                                        else AssetClass.EQUITY
                                    ),
                                    side="buy" if amt_qty >= 0 else "sell",
                                    quantity=abs(amt_qty),
                                    price=px,
                                    timestamp_utc=ts_iso,
                                    currency="USD",
                                )
                            )
                    elif ttype in {"JOURNAL", "INTERNAL_TRANSFER"} or any(
                        m in desc_upper for m in ("JOURNAL", "INTERNAL TRANSFER", "INTRA-ACCOUNT")
                    ):
                        journal_transfer_count += 1
                        flows.append(
                            NormalizedFlow(
                                timestamp_utc=ts_iso,
                                kind=FlowKind.INTERNAL_SUBACCOUNT_TRANSFER,
                                amount=net_amt,
                                currency="USD",
                                transfer_type="SCHWAB_JOURNAL",
                                description=desc or ttype,
                            )
                        )
                    elif ttype in {"ELECTRONIC_FUND", "WIRE_IN", "WIRE_OUT", "CASH_RECEIPT", "CASH_DISBURSEMENT"}:
                        kind = FlowKind.DEPOSIT if net_amt >= 0 else FlowKind.WITHDRAWAL
                        flows.append(
                            NormalizedFlow(
                                timestamp_utc=ts_iso,
                                kind=kind,
                                amount=net_amt,
                                currency="USD",
                                description=desc or ttype,
                            )
                        )
                    elif ttype == "RECEIVE_AND_DELIVER":
                        kind = FlowKind.TRANSFER_IN_KIND if net_amt >= 0 else FlowKind.TRANSFER_OUT_KIND
                        flows.append(
                            NormalizedFlow(
                                timestamp_utc=ts_iso,
                                kind=kind,
                                amount=net_amt,
                                currency="USD",
                                transfer_type="RECEIVE_AND_DELIVER",
                                description=desc or ttype,
                            )
                        )
                    elif "DIVIDEND" in ttype:
                        flows.append(
                            NormalizedFlow(
                                timestamp_utc=ts_iso,
                                kind=FlowKind.DIVIDEND,
                                amount=net_amt,
                                currency="USD",
                                description=desc or ttype,
                            )
                        )

        if journal_transfer_count > 0 and scope != AccountScope.ALL_ENUMERATED_SUBACCOUNTS:
            warnings.append(
                f"Detected {journal_transfer_count} internal Schwab journal transfer(s) while "
                "account_scope != all_enumerated_subaccounts; consolidate all linked Schwab accounts "
                "to eliminate intra-household survivorship uncertainty."
            )

        nav_points = (
            [NormalizedNavPoint(timestamp_utc=period_end_utc, nav_base=total_liq)]
            if total_liq > 0.0
            else []
        )
        source_sha = hashlib.sha256(b"\n".join(self._raw_transcript_chunks)).hexdigest()
        plain_connected = sorted(hash_to_plain[h] for h in connected_hashes)
        return CanonicalPortfolioLedger(
            blinded_account_tag=compute_blinded_account_tag(
                "schwab", ",".join(plain_connected), blinding_salt_hex
            ),
            broker_id="schwab",
            account_scope=scope,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=self.approval_state,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            source_body_sha256=source_sha,
            base_currency="USD",
            period_start_utc=period_start_utc,
            period_end_utc=period_end_utc,
            enumerated_subaccount_count=len(all_hashes),
            connected_subaccount_count=len(connected_hashes),
            ending_positions=ending_positions,
            nav_points=nav_points,
            trades=trades,
            flows=flows,
            enabled_sections=["accountNumbers", "positions", "transactions_journal_audit"],
            parser_warnings=warnings,
        )


__all__ = [
    "SCHWAB_LIVE_BASE_URL",
    "SchwabReadOnlyAdapter",
    "TRADIER_LIVE_BASE_URL",
    "TradierReadOnlyAdapter",
    "redact_tradier_account_path",
]
