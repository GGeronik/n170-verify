"""POST /api/v1/verify route handler enforcing worker isolation and governance gates."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any
from urllib.parse import urlparse

from app.config import ApiConfig
from app.routes_proofs import parse_strict_bool, refuse_caller_clock
from app.routes_sync import (
    resolve_clamped_provider_approval_state,
    verify_sync_authorization,
)
from app.store import (
    GovernanceBlockedError,
    PaperOrSandboxRejectedError,
    ProofBundleInvalidError,
    ProofConflictError,
    ProofStore,
    enforce_bundle_governance,
)
from app.sync_vault import SyncVault, SyncVaultConflictError
from app.worker_isolation import (
    WORKER_LIMIT_ERRORS,
    WorkerBrokerUpstreamError,
    WorkerIsolationError,
    WorkerPipelineSpec,
    WorkerValidationError,
    _SYNTHETIC_SIGNING_ORACLE_KEYS,
    enforce_hosted_signing_oracle_policy,
    run_isolated_one_shot_verification,
    worker_limit_response,
)
from n170_verify.contracts import (
    EnvironmentTier,
    ProviderApprovalState,
    ReadOnlyCapabilityViolationError,
)


_PAPER_ACCOUNT_TYPES = frozenset({"paper", "sandbox", "demo", "simulated", "testnet"})
_IBKR_PAPER_RE = re.compile(r"^D[UF]\d{4,}$", re.IGNORECASE)
_ALPACA_PAPER_RE = re.compile(r"^PA[A-Z0-9]{4,}$", re.IGNORECASE)
_PAPER_HOSTS = frozenset(
    {
        "paper-api.alpaca.markets",
        "sandbox.tradier.com",
        "demo.trading212.com",
        "api.hyperliquid-testnet.xyz",
    }
)


_WINDOW_FETCH_KEYS = frozenset({"period_start_utc", "period_end_utc"})

# Fetch options a caller may set per live connector: the reporting window and, where the
# adapter narrows account_scope accordingly, an account subset. Everything else (the
# account-tag salt, the queried wallet or user, live/paper switches) is set by the server.
CALLER_FETCH_KWARGS_ALLOWLIST: dict[str, frozenset[str]] = {
    "hyperliquid": frozenset({"start_date", "end_date"}),
    "snaptrade": frozenset({"start_date", "end_date", "selected_account_ids"}),
    "snaptrade_relay": frozenset({"start_date", "end_date", "selected_account_ids"}),
    "snaptrade_poc": frozenset({"start_date", "end_date", "selected_account_ids"}),
    "alpaca": _WINDOW_FETCH_KEYS,
    "trading212": _WINDOW_FETCH_KEYS,
    "tradier": _WINDOW_FETCH_KEYS | {"selected_account_numbers"},
    "schwab": _WINDOW_FETCH_KEYS | {"selected_account_hashes"},
    "binance": _WINDOW_FETCH_KEYS | {"selected_subaccounts", "symbols"},
    "coinbase": _WINDOW_FETCH_KEYS | {"selected_subaccounts", "symbols"},
    "kraken": _WINDOW_FETCH_KEYS | {"selected_subaccounts", "symbols"},
    "bybit": _WINDOW_FETCH_KEYS | {"selected_subaccounts", "symbols"},
    "ibkr_oauth": _WINDOW_FETCH_KEYS | {"selected_account_ids"},
    "ctrader": _WINDOW_FETCH_KEYS | {"selected_account_ids"},
    "ctrader_oauth": _WINDOW_FETCH_KEYS | {"selected_account_ids"},
    "ibkr_flex_web": frozenset({"flex_token", "query_id", "query_ids", "start_date", "end_date"}),
}

# Request fields that carry a self-reported file or a pre-built ledger.
_STATEMENT_OR_LEDGER_KEYS: tuple[str, ...] = (
    "ledger",
    "flex_xml",
    "flex_xml_b64",
    "csv_source",
    "csv_b64",
    "raw_statement",
    "raw_statement_text",
    "raw_statement_b64",
    "degiro_account_csv",
    "degiro_transactions_csv",
    "degiro_portfolio_csv",
)


# Statement input fields a visitor may upload (a pre-built ``ledger`` is not one of them).
_STATEMENT_INPUT_KEYS: frozenset[str] = frozenset(_STATEMENT_OR_LEDGER_KEYS) - {"ledger"}

# Hosted mode: the worker job for this route is built from these request fields only.
_HOSTED_WORKER_REQUEST_FIELDS: frozenset[str] = frozenset(
    {
        "broker_id",
        "wallet_address",
        "connector_fetch_kwargs",
        "csv_format",
        "disclose_leaf_names",
        "issued_at_utc",
        *_STATEMENT_INPUT_KEYS,
    }
)

# Hosted mode: fields the route itself reads and does not forward to the worker.
_HOSTED_ROUTE_ONLY_FIELDS: frozenset[str] = frozenset(
    {
        "publish_proof",
        "opt_in_leaderboard",
        "persist_sync",
        "sync_credentials",
        "capabilities",
        "connection_id",
        "environment_tier",
    }
)

_HOSTED_BROKER_ID_RE = re.compile(r"[a-z0-9_]+")

# On a hosted deployment this route offers a live read only for a public, permissionless
# connector, or an uploaded statement under an offline id. Every other connector is refused
# on this route until it has been reviewed for hosted use.
HOSTED_VERIFY_OFFERED_APPROVAL_STATES: frozenset[ProviderApprovalState] = frozenset(
    {ProviderApprovalState.PUBLIC_API_PERMISSIONLESS, ProviderApprovalState.OFFLINE_EXPORT_ONLY}
)
HOSTED_VERIFY_OFFERED_BROKER_IDS: frozenset[str] = frozenset({"ibkr_flex_web"})


def _hosted_connector_not_offered(broker_id: str, config: ApiConfig) -> str | None:
    """Hosted: a reason when this route does not offer the configured connector."""
    state = config.connector_approval_states.get(broker_id)
    if (
        state is None
        or state in HOSTED_VERIFY_OFFERED_APPROVAL_STATES
        or broker_id in HOSTED_VERIFY_OFFERED_BROKER_IDS
    ):
        return None
    return (
        f"broker_id={broker_id!r} is not offered on this host through this route until it has "
        "been reviewed for hosted use; verify a public wallet address or upload a statement instead"
    )


def _hosted_broker_id_refusal(raw: Any, config: ApiConfig) -> str | None:
    """Hosted: a broker id is plain lower-case ASCII and one this host has configured."""
    if not isinstance(raw, str):
        return "broker_id must be a string"
    norm = raw.strip()
    if not norm.isascii() or _HOSTED_BROKER_ID_RE.fullmatch(norm.lower()) is None:
        return "broker_id must contain only lower-case letters, digits and underscores"
    if norm.lower() not in config.connector_approval_states:
        return f"broker_id={norm.lower()!r} is not a broker this host supports"
    return None


def _hosted_unlisted_fields(payload: Mapping[str, Any]) -> list[str]:
    """Request fields outside the hosted list; the oracle-policy keys keep their own refusal."""
    accepted = _HOSTED_WORKER_REQUEST_FIELDS | _HOSTED_ROUTE_ONLY_FIELDS | _SYNTHETIC_SIGNING_ORACLE_KEYS
    return sorted(str(k) for k in payload if str(k) not in accepted)


def _hosted_worker_request(
    payload: Mapping[str, Any], approval_state: ProviderApprovalState, env_tier: EnvironmentTier
) -> dict[str, Any]:
    """Build the hosted worker job from the listed fields and the route-resolved states."""
    forwarded = _HOSTED_WORKER_REQUEST_FIELDS | _SYNTHETIC_SIGNING_ORACLE_KEYS
    job = {str(k): v for k, v in payload.items() if str(k) in forwarded}
    job["broker_id"] = str(payload["broker_id"]).strip().lower()
    job["provider_approval_state"] = approval_state.value
    job["environment_tier"] = env_tier.value
    return job


def _check_caller_fetch_kwargs(payload: Mapping[str, Any], broker_id: str) -> str | None:
    """Return a refusal reason when caller fetch options go beyond the broker's allowlist."""
    raw = payload.get("connector_fetch_kwargs")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        return "connector_fetch_kwargs must be a JSON object"
    allowed = CALLER_FETCH_KWARGS_ALLOWLIST.get(broker_id, frozenset())
    refused = sorted(str(k) for k in raw if str(k) not in allowed)
    if refused:
        allowed_txt = ", ".join(sorted(allowed)) or "none"
        return (
            f"connector_fetch_kwargs field(s) not accepted for broker_id={broker_id!r}: "
            f"{', '.join(refused)} (accepted: {allowed_txt})"
        )
    return None


def _check_statement_input_matches_broker(
    payload: Mapping[str, Any], broker_id: str, config: ApiConfig
) -> str | None:
    """Statement or ledger input is accepted only under an offline-export broker id."""
    if not config.hosted_multi_user_mode:
        return None
    present = [k for k in _STATEMENT_OR_LEDGER_KEYS if payload.get(k) is not None]
    if not present:
        return None
    ceiling = config.connector_approval_states.get(
        broker_id, ProviderApprovalState.OFFLINE_EXPORT_ONLY
    )
    if ceiling == ProviderApprovalState.OFFLINE_EXPORT_ONLY:
        return None
    return (
        f"broker_id={broker_id!r} is a live connector; statement or ledger input "
        f"({', '.join(present)}) must use an offline broker_id such as 'auto_detect'"
    )


def _resolve_environment_tier(payload: Mapping[str, Any]) -> EnvironmentTier:
    if bool(payload.get("is_paper", False)) or bool(payload.get("is_sandbox", False)):
        return EnvironmentTier.PAPER_OR_SANDBOX_REJECTED
    acct_type = str(payload.get("account_type", "")).strip().lower()
    if acct_type in _PAPER_ACCOUNT_TYPES:
        return EnvironmentTier.PAPER_OR_SANDBOX_REJECTED

    broker_id = str(payload.get("broker_id", "")).strip().lower()
    nested_kw = payload.get("connector_kwargs")
    scopes: list[Mapping[str, Any]] = [payload]
    if isinstance(nested_kw, Mapping):
        scopes.append(nested_kw)
    for scope in scopes:
        for url_key in ("base_url", "api_url", "endpoint"):
            raw_url = str(scope.get(url_key) or "").strip()
            if raw_url:
                host = (urlparse(raw_url).hostname or raw_url).strip().lower()
                if (
                    host in _PAPER_HOSTS
                    or any(ph in raw_url.lower() for ph in _PAPER_HOSTS)
                    or "testnet" in host
                ):
                    return EnvironmentTier.PAPER_OR_SANDBOX_REJECTED

    raw_acct = str(payload.get("raw_account_id") or payload.get("account_number") or "").strip()
    if raw_acct:
        if broker_id == "alpaca" and _ALPACA_PAPER_RE.match(raw_acct):
            return EnvironmentTier.PAPER_OR_SANDBOX_REJECTED
        if broker_id.startswith("ibkr") and _IBKR_PAPER_RE.match(raw_acct):
            return EnvironmentTier.PAPER_OR_SANDBOX_REJECTED

    raw_tier = payload.get("environment_tier")
    if raw_tier is not None:
        return EnvironmentTier(str(raw_tier))
    return EnvironmentTier.LIVE_PRODUCTION


def _resolve_provider_approval_state(
    payload: Mapping[str, Any], config: ApiConfig
) -> ProviderApprovalState:
    broker_id = str(payload.get("broker_id", "")).strip().lower()
    return resolve_clamped_provider_approval_state(
        payload.get("provider_approval_state"),
        broker_id=broker_id,
        config=config,
        unhosted_default=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    )


def handle_post_verify(
    payload: Mapping[str, Any],
    *,
    config: ApiConfig,
    store: ProofStore,
    sync_vault: SyncVault,
    pipeline_spec: WorkerPipelineSpec = None,
    headers: Mapping[str, str] | None = None,
    hyperliquid_http_transport: Any = None,
    ibkr_flex_http_transport: Any = None,
) -> tuple[int, dict[str, Any]]:
    """Execute ``POST /api/v1/verify`` inside a single-use ``spawn`` worker subprocess."""
    if not isinstance(payload, Mapping):
        return 400, {"error": "invalid_request", "detail": "Request body must be a JSON object"}

    clock_refusal = refuse_caller_clock(config, payload, field_name="issued_at_utc")
    if clock_refusal is not None:
        return clock_refusal

    broker_id = str(payload.get("broker_id", "")).strip().lower()
    if not broker_id:
        return 422, {"error": "validation_error", "detail": "broker_id is required"}

    try:
        approval_state = _resolve_provider_approval_state(payload, config)
        env_tier = _resolve_environment_tier(payload)
    except ValueError as exc:
        return 422, {"error": "validation_error", "detail": str(exc)}

    try:
        enforce_bundle_governance(
            provider_approval_state=approval_state,
            environment_tier=env_tier,
            hosted_multi_user_mode=config.hosted_multi_user_mode,
        )
    except PaperOrSandboxRejectedError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    except GovernanceBlockedError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}

    for refusal in (
        _check_caller_fetch_kwargs(payload, broker_id),
        _check_statement_input_matches_broker(payload, broker_id, config),
    ):
        if refusal is not None:
            return 422, {"error": "validation_error", "detail": refusal}

    persist_sync, sync_bool_err = parse_strict_bool(payload, "persist_sync", default=False)
    if sync_bool_err is not None:
        return sync_bool_err
    if persist_sync:
        auth_ok, auth_status, auth_err = verify_sync_authorization(headers, config)
        if not auth_ok:
            return auth_status, auth_err

    if config.hosted_multi_user_mode:
        broker_refusal = _hosted_broker_id_refusal(payload.get("broker_id"), config)
        if broker_refusal is not None:
            return 422, {"error": "validation_error", "detail": broker_refusal}
        not_offered = _hosted_connector_not_offered(broker_id, config)
        if not_offered is not None:
            return 422, {"error": "connector_not_offered", "detail": not_offered}
        # Client-supplied series keep their own refusal ahead of the field list.
        try:
            enforce_hosted_signing_oracle_policy(
                payload,
                hosted_multi_user_mode=True,
                allow_hosted_signing=config.allow_hosted_signing,
                allow_client_supplied_series_for_tests=config.allow_client_supplied_series_for_tests,
                has_custom_pipeline=(pipeline_spec is not None),
            )
        except GovernanceBlockedError as exc:
            return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
        unlisted = _hosted_unlisted_fields(payload)
        if unlisted:
            return 422, {
                "error": "validation_error",
                "detail": f"request field(s) not accepted by this host: {', '.join(unlisted)}",
            }

    publish_proof, pub_err = parse_strict_bool(payload, "publish_proof", default=False)
    if pub_err is not None:
        return pub_err
    opt_in_leaderboard, opt_err = parse_strict_bool(payload, "opt_in_leaderboard", default=False)
    if opt_err is not None:
        return opt_err

    retention_mode = "opt_in_encrypted_sync" if persist_sync else "no_persistent_storage"

    if config.hosted_multi_user_mode:
        normalized_payload = _hosted_worker_request(payload, approval_state, env_tier)
    else:
        normalized_payload = dict(payload)
        normalized_payload["provider_approval_state"] = approval_state.value
        normalized_payload["environment_tier"] = env_tier.value

    result_meta: dict[str, Any] = {}
    try:
        bundle, receipt, stripped_trades = run_isolated_one_shot_verification(
            normalized_payload,
            config=config,
            pipeline_spec=pipeline_spec,
            retention_mode=retention_mode,
            persistent_rows_written=0,
            _hyperliquid_http_transport=hyperliquid_http_transport,
            _ibkr_flex_http_transport=ibkr_flex_http_transport,
            result_meta=result_meta,
        )
    except PaperOrSandboxRejectedError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    except GovernanceBlockedError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    except ReadOnlyCapabilityViolationError as exc:
        return 422, {"error": "read_only_capability_violation", "detail": str(exc)}
    except WORKER_LIMIT_ERRORS as exc:
        return worker_limit_response(exc)
    except WorkerValidationError as exc:
        return 422, {"error": "validation_error", "detail": str(exc)}
    except WorkerBrokerUpstreamError as exc:
        clean_upstream = re.split(r":\s+", str(exc), maxsplit=1)[0].strip()
        return 502, {
            "error": "broker_upstream_error",
            "detail": clean_upstream or "Broker upstream request failed",
        }
    except WorkerIsolationError as exc:
        return 500, {"error": "worker_isolation_error", "detail": str(exc)}

    rows_written = 0
    sync_record_dict: dict[str, Any] | None = None

    if persist_sync:
        sync_creds = payload.get("sync_credentials")
        sync_caps = payload.get("capabilities") or ("read_balances", "read_positions", "read_trades")
        if not isinstance(sync_creds, Mapping) or not sync_creds:
            return 422, {
                "error": "validation_error",
                "detail": "persist_sync=True requires non-empty sync_credentials",
            }
        try:
            sync_conn_id = (
                str(payload["connection_id"])
                if payload.get("connection_id") is not None
                else None
            )
            sync_rec = sync_vault.create_connection(
                broker_id=bundle.broker_id,
                credentials=sync_creds,
                capabilities=sync_caps,
                blinded_account_tag=bundle.blinded_account_tag,
                account_scope=bundle.account_scope,
                provider_approval_state=bundle.provider_approval_state,
                environment_tier=bundle.environment_tier,
                connection_id=sync_conn_id,
            )
            sync_record_dict = sync_rec.to_dict()
            rows_written += 1
        except SyncVaultConflictError as exc:
            return 409, {"error": "sync_connection_conflict", "detail": str(exc)}
        except (ReadOnlyCapabilityViolationError, ValueError) as exc:
            return 422, {"error": "validation_error", "detail": str(exc)}

    if publish_proof:
        try:
            bundle, verification = store.store_proof(
                bundle, opt_in_leaderboard=opt_in_leaderboard
            )
            rows_written += 1
        except ProofConflictError as exc:
            return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
        except ProofBundleInvalidError as exc:
            return 422, {"error": "invalid_proof_bundle", "errors": exc.errors}
        except GovernanceBlockedError as exc:
            return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    else:
        verification = store.verify_bundle_against_live_state(bundle)

    receipt.persistent_rows_written = rows_written

    response_body: dict[str, Any] = {
        "proof_bundle": bundle.to_dict(),
        "verification": verification.to_dict(),
        "isolation_receipt": receipt.to_dict(),
        "stripped_recent_closed_trades_count": stripped_trades,
        "performance_withheld": bool(result_meta.get("performance_withheld", False)),
    }
    if response_body["performance_withheld"]:
        response_body["withheld_reasons"] = list(result_meta.get("withheld_reasons") or [])
    if result_meta.get("record_warnings"):
        response_body["record_warnings"] = list(result_meta["record_warnings"])
    if sync_record_dict is not None:
        response_body["sync_connection"] = sync_record_dict

    return 200, response_body


__all__ = ["handle_post_verify"]
