"""Opt-in encrypted sync vault enrollment and NIST SP 800-88r2 revocation routes."""

from __future__ import annotations

from collections.abc import Mapping
import hmac
from typing import Any

from app.config import ApiConfig
from app.store import (
    GovernanceBlockedError,
    PaperOrSandboxRejectedError,
    enforce_bundle_governance,
)
from app.sync_vault import (
    SyncVault,
    SyncVaultConflictError,
    SyncVaultError,
    SyncVaultNotFoundError,
)
from n170_verify.contracts import (
    AccountScope,
    EnvironmentTier,
    ProviderApprovalState,
    ReadOnlyCapabilityViolationError,
)


PROVIDER_APPROVAL_RANK: dict[ProviderApprovalState, int] = {
    ProviderApprovalState.PENDING_PROVIDER_APPROVAL: 0,
    ProviderApprovalState.OFFLINE_EXPORT_ONLY: 1,
    ProviderApprovalState.USER_KEY_SELF_ATTESTED: 2,
    ProviderApprovalState.APPROVED_LIVE: 3,
}


def resolve_clamped_provider_approval_state(
    raw_state: Any,
    *,
    broker_id: str,
    config: ApiConfig,
    unhosted_default: ProviderApprovalState = ProviderApprovalState.OFFLINE_EXPORT_ONLY,
) -> ProviderApprovalState:
    """Resolve ``ProviderApprovalState``, clamping caller input to server ceiling in hosted mode."""
    norm_broker = broker_id.strip().lower()
    if not config.hosted_multi_user_mode:
        if raw_state is not None:
            return ProviderApprovalState(str(raw_state))
        return config.connector_approval_states.get(norm_broker, unhosted_default)

    ceiling = config.connector_approval_states.get(
        norm_broker, ProviderApprovalState.OFFLINE_EXPORT_ONLY
    )
    if raw_state is None:
        return ceiling
    caller_state = ProviderApprovalState(str(raw_state))
    if ceiling == ProviderApprovalState.PENDING_PROVIDER_APPROVAL:
        return ProviderApprovalState.PENDING_PROVIDER_APPROVAL
    if PROVIDER_APPROVAL_RANK[caller_state] <= PROVIDER_APPROVAL_RANK[ceiling]:
        return caller_state
    return ceiling


def verify_sync_authorization(
    headers: Mapping[str, str] | None,
    config: ApiConfig,
) -> tuple[bool, int, dict[str, Any]]:
    """Verify bearer or ``X-N170-Sync-Token`` authorization in hosted multi-user mode."""
    if not config.hosted_multi_user_mode:
        return True, 200, {}

    expected = config.sync_api_token.strip()
    if not expected:
        return (
            False,
            403,
            {
                "error": "sync_auth_unconfigured",
                "detail": "Sync vault endpoints require N170_VERIFY_SYNC_API_TOKEN in hosted multi-user mode",
            },
        )

    lower_headers: dict[str, str] = {}
    if headers is not None:
        for k, v in headers.items():
            lower_headers[str(k).strip().lower()] = str(v)

    candidate = ""
    auth_raw = lower_headers.get("authorization", "").strip()
    if auth_raw.lower().startswith("bearer "):
        candidate = auth_raw[7:].strip()
    elif "x-n170-sync-token" in lower_headers:
        candidate = lower_headers["x-n170-sync-token"].strip()

    if not candidate or not hmac.compare_digest(
        candidate.encode("utf-8"), expected.encode("utf-8")
    ):
        return (
            False,
            401,
            {
                "error": "sync_unauthorized",
                "detail": "Valid sync authorization token required",
            },
        )

    return True, 200, {}


def handle_post_sync(
    payload: Mapping[str, Any],
    *,
    config: ApiConfig,
    sync_vault: SyncVault,
    headers: Mapping[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Enroll an opt-in read-only sync connection via ``POST /api/v1/sync``."""
    auth_ok, auth_status, auth_err = verify_sync_authorization(headers, config)
    if not auth_ok:
        return auth_status, auth_err

    if not isinstance(payload, Mapping):
        return 400, {"error": "invalid_request", "detail": "Request body must be a JSON object"}

    broker_id = str(payload.get("broker_id", "")).strip().lower()
    if not broker_id:
        return 422, {"error": "validation_error", "detail": "broker_id is required"}

    credentials = payload.get("credentials")
    if not isinstance(credentials, Mapping) or not credentials:
        return 422, {
            "error": "validation_error",
            "detail": "credentials must be a non-empty JSON object",
        }

    capabilities = payload.get("capabilities")
    if not isinstance(capabilities, (list, tuple)) or not capabilities:
        return 422, {
            "error": "validation_error",
            "detail": "capabilities must list at least one read-only capability",
        }

    try:
        approval_state = resolve_clamped_provider_approval_state(
            payload.get("provider_approval_state"),
            broker_id=broker_id,
            config=config,
            unhosted_default=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
        )
        env_tier = EnvironmentTier(
            str(payload.get("environment_tier", EnvironmentTier.LIVE_PRODUCTION.value))
        )
        account_scope = AccountScope(
            str(payload.get("account_scope", AccountScope.ALL_ENUMERATED_SUBACCOUNTS.value))
        )
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

    try:
        record = sync_vault.create_connection(
            broker_id=broker_id,
            credentials=credentials,
            capabilities=capabilities,
            raw_account_id=str(payload["raw_account_id"])
            if payload.get("raw_account_id") is not None
            else None,
            blinded_account_tag=str(payload["blinded_account_tag"])
            if payload.get("blinded_account_tag") is not None
            else None,
            account_scope=account_scope,
            provider_approval_state=approval_state,
            environment_tier=env_tier,
            oauth_revocable=payload.get("oauth_revocable"),
            connection_id=str(payload["connection_id"])
            if payload.get("connection_id") is not None
            else None,
        )
    except SyncVaultConflictError as exc:
        return 409, {"error": "sync_connection_conflict", "detail": str(exc)}
    except ReadOnlyCapabilityViolationError as exc:
        return 422, {"error": "read_only_capability_violation", "detail": str(exc)}
    except ValueError as exc:
        return 422, {"error": "validation_error", "detail": str(exc)}

    return 201, {"connection": record.to_dict()}


def handle_get_sync(
    connection_id: str,
    *,
    sync_vault: SyncVault,
    config: ApiConfig | None = None,
    headers: Mapping[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Return non-secret connection metadata via ``GET /api/v1/sync/{connection_id}``."""
    if config is not None:
        auth_ok, auth_status, auth_err = verify_sync_authorization(headers, config)
        if not auth_ok:
            return auth_status, auth_err

    try:
        record = sync_vault.get_connection_metadata(connection_id)
    except SyncVaultNotFoundError:
        return 404, {
            "error": "sync_connection_not_found",
            "detail": f"Sync connection {connection_id!r} does not exist or has been revoked",
        }
    return 200, {"connection": record.to_dict()}


def handle_delete_sync(
    connection_id: str,
    *,
    sync_vault: SyncVault,
    config: ApiConfig | None = None,
    headers: Mapping[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Cryptographically erase credentials and issue ``RevocationReceipt`` via ``DELETE /api/v1/sync/{connection_id}``."""
    if config is not None:
        auth_ok, auth_status, auth_err = verify_sync_authorization(headers, config)
        if not auth_ok:
            return auth_status, auth_err

    try:
        receipt = sync_vault.revoke_and_erase(connection_id)
    except SyncVaultNotFoundError:
        return 404, {
            "error": "sync_connection_not_found",
            "detail": f"Sync connection {connection_id!r} does not exist or has already been revoked",
        }
    except SyncVaultError as exc:
        return 500, {"error": "sync_erasure_error", "detail": str(exc)}

    return 200, {"revocation_receipt": receipt.to_dict()}


__all__ = [
    "PROVIDER_APPROVAL_RANK",
    "handle_delete_sync",
    "handle_get_sync",
    "handle_post_sync",
    "resolve_clamped_provider_approval_state",
    "verify_sync_authorization",
]
