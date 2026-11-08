"""POST /api/v1/verify route handler enforcing worker isolation and governance gates."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any
from urllib.parse import urlparse

from app.config import ApiConfig
from app.store import (
    GovernanceBlockedError,
    PaperOrSandboxRejectedError,
    ProofBundleInvalidError,
    ProofStore,
    enforce_bundle_governance,
)
from app.sync_vault import SyncVault
from app.worker_isolation import (
    WorkerIsolationError,
    WorkerPipelineSpec,
    WorkerValidationError,
    run_isolated_one_shot_verification,
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
    }
)


def _resolve_environment_tier(payload: Mapping[str, Any]) -> EnvironmentTier:
    if bool(payload.get("is_paper", False)) or bool(payload.get("is_sandbox", False)):
        return EnvironmentTier.PAPER_OR_SANDBOX_REJECTED
    acct_type = str(payload.get("account_type", "")).strip().lower()
    if acct_type in _PAPER_ACCOUNT_TYPES:
        return EnvironmentTier.PAPER_OR_SANDBOX_REJECTED

    broker_id = str(payload.get("broker_id", "")).strip().lower()
    for url_key in ("base_url", "api_url", "endpoint"):
        raw_url = str(payload.get(url_key) or "").strip()
        if raw_url:
            host = (urlparse(raw_url).hostname or raw_url).strip().lower()
            if host in _PAPER_HOSTS or any(ph in raw_url.lower() for ph in _PAPER_HOSTS):
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
    raw_state = payload.get("provider_approval_state")
    if raw_state is not None:
        return ProviderApprovalState(str(raw_state))
    broker_id = str(payload.get("broker_id", "")).strip().lower()
    return config.connector_approval_states.get(
        broker_id, ProviderApprovalState.OFFLINE_EXPORT_ONLY
    )


def handle_post_verify(
    payload: Mapping[str, Any],
    *,
    config: ApiConfig,
    store: ProofStore,
    sync_vault: SyncVault,
    pipeline_spec: WorkerPipelineSpec = None,
) -> tuple[int, dict[str, Any]]:
    """Execute ``POST /api/v1/verify`` inside a single-use ``spawn`` worker subprocess."""
    if not isinstance(payload, Mapping):
        return 400, {"error": "invalid_request", "detail": "Request body must be a JSON object"}

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

    persist_sync = bool(payload.get("persist_sync", False))
    publish_proof = bool(payload.get("publish_proof", False))
    opt_in_leaderboard = bool(payload.get("opt_in_leaderboard", False))

    retention_mode = "opt_in_encrypted_sync" if persist_sync else "no_persistent_storage"

    normalized_payload = dict(payload)
    normalized_payload["provider_approval_state"] = approval_state.value
    normalized_payload["environment_tier"] = env_tier.value

    try:
        bundle, receipt, stripped_trades = run_isolated_one_shot_verification(
            normalized_payload,
            config=config,
            pipeline_spec=pipeline_spec,
            retention_mode=retention_mode,
            persistent_rows_written=0,
        )
    except PaperOrSandboxRejectedError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    except GovernanceBlockedError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    except ReadOnlyCapabilityViolationError as exc:
        return 422, {"error": "read_only_capability_violation", "detail": str(exc)}
    except WorkerValidationError as exc:
        return 422, {"error": "validation_error", "detail": str(exc)}
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
            sync_rec = sync_vault.create_connection(
                broker_id=bundle.broker_id,
                credentials=sync_creds,
                capabilities=sync_caps,
                blinded_account_tag=bundle.blinded_account_tag,
                account_scope=bundle.account_scope,
                provider_approval_state=bundle.provider_approval_state,
                environment_tier=bundle.environment_tier,
            )
            sync_record_dict = sync_rec.to_dict()
            rows_written += 1
        except (ReadOnlyCapabilityViolationError, ValueError) as exc:
            return 422, {"error": "validation_error", "detail": str(exc)}

    if publish_proof:
        try:
            bundle, verification = store.store_proof(
                bundle, opt_in_leaderboard=opt_in_leaderboard
            )
            rows_written += 1
        except ProofBundleInvalidError as exc:
            return 422, {"error": "invalid_proof_bundle", "errors": exc.errors}
    else:
        verification = store.verify_bundle_against_live_state(bundle)

    receipt.persistent_rows_written = rows_written

    response_body: dict[str, Any] = {
        "proof_bundle": bundle.to_dict(),
        "verification": verification.to_dict(),
        "isolation_receipt": receipt.to_dict(),
        "stripped_recent_closed_trades_count": stripped_trades,
    }
    if sync_record_dict is not None:
        response_body["sync_connection"] = sync_record_dict

    return 200, response_body


__all__ = ["handle_post_verify"]
