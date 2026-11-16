"""Ephemeral 5-slot SnapTrade V1 developer/promo relay routes for N170 Verify."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import secrets
import threading
import time
from typing import Any
from urllib.parse import urlsplit

from app.config import ApiConfig
from app.routes_viral import sanitize_public_label
from app.store import (
    GovernanceBlockedError,
    PaperOrSandboxRejectedError,
    ProofBundleInvalidError,
    ProofConflictError,
    ProofStore,
)
from app.worker_isolation import (
    WorkerIsolationError,
    WorkerPipelineSpec,
    WorkerValidationError,
    run_isolated_one_shot_verification,
)
from n170_verify.connectors import (
    DisallowedCapabilityError,
    MAX_SNAPTRADE_POC_SLOTS,
    PaperOrSandboxAccountRejectedError,
    SnapTradeAuthenticationError,
    SnapTradeError,
    SnapTradeReadOnlyAdapter,
    SnapTradeServiceError,
    SnapTradeSlotCapExceededError,
    SnapTradeSlotManager,
    is_snaptrade_env_configured,
    redact_sensitive_text,
)
from n170_verify.contracts import ReadOnlyCapabilityViolationError


SNAPTRADE_SESSION_TTL_SECONDS: float = 1800.0
MAX_EPHEMERAL_SNAPTRADE_SESSIONS: int = 64
SNAPTRADE_UNCONFIGURED_DETAIL: str = (
    "Set SNAPTRADE_CLIENT_ID and SNAPTRADE_CONSUMER_KEY on the API server "
    "to enable the 5-slot developer/promo relay."
)


@dataclass(slots=True)
class _EphemeralSnapTradeSession:
    """Bounded in-memory SnapTrade portal/verification session (never persisted to disk)."""

    session_token: str
    slot_id: int
    slot_label: str
    user_id: str
    user_secret: str
    created_at_utc: str
    expires_at_utc: str
    expires_monotonic: float


def _utc_iso_from_dt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def validate_snaptrade_redirect_url(raw_url: Any) -> tuple[bool, str | None, str | None]:
    """Validate optional ``redirect_url`` matches ``http://127.0.0.1:*`` or ``https://*``."""
    if raw_url is None:
        return True, None, None
    if not isinstance(raw_url, str):
        return False, None, "redirect_url must be a string"
    cleaned = raw_url.strip()
    if not cleaned:
        return True, None, None
    if len(cleaned) > 1024 or any(ord(ch) < 33 or ord(ch) == 127 for ch in cleaned):
        return False, None, "redirect_url contains disallowed whitespace, control chars, or length"

    parsed = urlsplit(cleaned)
    scheme = parsed.scheme.lower()
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        return False, None, "redirect_url must not contain embedded credentials"

    try:
        port = parsed.port
    except ValueError:
        return False, None, "redirect_url contains an invalid TCP port"
    if port is not None and not (1 <= port <= 65535):
        return False, None, "redirect_url port must be between 1 and 65535"

    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False, None, "redirect_url is missing a valid hostname"

    if scheme == "https":
        return True, cleaned, None
    if scheme == "http" and host == "127.0.0.1":
        return True, cleaned, None

    return (
        False,
        None,
        "redirect_url must use https://* or local http://127.0.0.1:* callback origin",
    )


def _derive_blinded_snaptrade_user_id(slot_label: str, salt_hex: str) -> str:
    salt_bytes = bytes.fromhex(salt_hex)
    digest = hmac.new(
        salt_bytes,
        b"n170.snaptrade.slot_user.v1\x00" + slot_label.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"n170-st-{digest[:24]}"


def _resolve_snaptrade_runtime(config: ApiConfig) -> tuple[bool, str, str, str]:
    client_id = (config.snaptrade_client_id or os.environ.get("SNAPTRADE_CLIENT_ID", "")).strip()
    consumer_key = (
        config.snaptrade_consumer_key or os.environ.get("SNAPTRADE_CONSUMER_KEY", "")
    ).strip()
    dev_key = (config.snaptrade_dev_key or os.environ.get("N170_SNAPTRADE_DEV_KEY", "")).strip()
    configured = is_snaptrade_env_configured(
        {
            "SNAPTRADE_CLIENT_ID": client_id,
            "SNAPTRADE_CONSUMER_KEY": consumer_key,
        }
    )
    return configured, client_id, consumer_key, dev_key


def _verify_dev_key_if_required(
    payload: Mapping[str, Any] | None,
    headers: Mapping[str, str] | None,
    expected_dev_key: str,
) -> tuple[bool, tuple[int, dict[str, Any]] | None]:
    if not expected_dev_key:
        return True, None

    candidate = ""
    if headers is not None:
        for k, v in headers.items():
            if str(k).strip().lower() == "x-n170-dev-key" and v is not None:
                candidate = str(v).strip()
                break
    if not candidate and isinstance(payload, Mapping):
        raw_body_key = payload.get("dev_key")
        if isinstance(raw_body_key, str):
            candidate = raw_body_key.strip()

    if not candidate or not hmac.compare_digest(
        candidate.encode("utf-8"),
        expected_dev_key.encode("utf-8"),
    ):
        return (
            False,
            (
                403,
                {
                    "error": "dev_key_required",
                    "detail": "Valid X-N170-Dev-Key header or dev_key field is required for this 5-slot developer relay.",
                },
            ),
        )
    return True, None


class SnapTradeRelayCoordinator:
    """Thread-safe ephemeral in-memory coordinator for the 5-slot SnapTrade V1 relay."""

    def __init__(
        self,
        *,
        slot_manager: SnapTradeSlotManager | None = None,
        http_transport: Any = None,
        session_ttl_seconds: float = SNAPTRADE_SESSION_TTL_SECONDS,
        max_sessions: int = MAX_EPHEMERAL_SNAPTRADE_SESSIONS,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.slot_manager = slot_manager or SnapTradeSlotManager(max_slots=MAX_SNAPTRADE_POC_SLOTS)
        self.http_transport = http_transport
        self.session_ttl_seconds = float(session_ttl_seconds)
        self.max_sessions = int(max_sessions)
        self._clock = monotonic_clock
        self._lock = threading.RLock()
        self._sessions: dict[str, _EphemeralSnapTradeSession] = {}
        self._labels_by_user: dict[str, str] = {}

    def purge_expired_sessions(self) -> int:
        """Purge expired ephemeral session tokens and in-memory userSecrets."""
        now_mono = self._clock()
        with self._lock:
            expired_tokens = [
                tok for tok, sess in self._sessions.items() if now_mono >= sess.expires_monotonic
            ]
            for tok in expired_tokens:
                self._sessions.pop(tok, None)
            return len(expired_tokens)

    def slot_status_dict(self, *, include_slots: bool = False) -> dict[str, Any]:
        """Return current 5-slot cap utilization summary (zero secrets or raw account IDs)."""
        self.purge_expired_sessions()
        with self._lock:
            active_slots = self.slot_manager.list_active_slots()
            active_count = len(active_slots)
            max_slots = self.slot_manager.max_slots
            out: dict[str, Any] = {
                "max_slots": max_slots,
                "active_slots": active_count,
                "available_slots": max(0, max_slots - active_count),
            }
            if include_slots:
                out["slots"] = [
                    {
                        "slot_id": s.slot_id,
                        "slot_label": self._labels_by_user.get(s.user_id, f"slot-{s.slot_id}"),
                        "registered_at_utc": s.registered_at_utc,
                    }
                    for s in active_slots
                ]
            return out

    def build_adapter(self, client_id: str, consumer_key: str) -> SnapTradeReadOnlyAdapter:
        return SnapTradeReadOnlyAdapter(
            client_id=client_id,
            consumer_key=consumer_key,
            slot_manager=self.slot_manager,
            http_transport=self.http_transport,
            require_live=True,
            auto_register_slot=False,
        )

    def find_active_secret_for_user(self, user_id: str) -> str | None:
        self.purge_expired_sessions()
        with self._lock:
            for sess in self._sessions.values():
                if sess.user_id == user_id and sess.user_secret:
                    return sess.user_secret
            return None

    def store_session(
        self,
        *,
        slot_id: int,
        slot_label: str,
        user_id: str,
        user_secret: str,
    ) -> _EphemeralSnapTradeSession:
        self.purge_expired_sessions()
        now_utc = datetime.now(timezone.utc)
        exp_utc = now_utc + timedelta(seconds=self.session_ttl_seconds)
        token = secrets.token_urlsafe(32)
        sess = _EphemeralSnapTradeSession(
            session_token=token,
            slot_id=slot_id,
            slot_label=slot_label,
            user_id=user_id,
            user_secret=user_secret,
            created_at_utc=_utc_iso_from_dt(now_utc),
            expires_at_utc=_utc_iso_from_dt(exp_utc),
            expires_monotonic=self._clock() + self.session_ttl_seconds,
        )
        with self._lock:
            self._labels_by_user[user_id] = slot_label
            while len(self._sessions) >= self.max_sessions:
                oldest_tok = min(
                    self._sessions.keys(),
                    key=lambda t: self._sessions[t].expires_monotonic,
                )
                self._sessions.pop(oldest_tok, None)
            self._sessions[token] = sess
        return sess

    def get_session(self, session_token: str) -> _EphemeralSnapTradeSession | None:
        self.purge_expired_sessions()
        with self._lock:
            return self._sessions.get(session_token)

    def purge_user_sessions_and_release_local(self, user_id: str) -> bool:
        with self._lock:
            dead_tokens = [
                tok for tok, sess in self._sessions.items() if sess.user_id == user_id
            ]
            for tok in dead_tokens:
                self._sessions.pop(tok, None)
            self._labels_by_user.pop(user_id, None)
            return self.slot_manager.release_slot(user_id)

    def resolve_users_for_release(
        self,
        *,
        slot_id: int | None = None,
        slot_label: str | None = None,
        release_all: bool = False,
    ) -> list[tuple[int, str]]:
        with self._lock:
            active = self.slot_manager.list_active_slots()
            if release_all:
                return [(s.slot_id, s.user_id) for s in active]
            if slot_id is not None:
                return [(s.slot_id, s.user_id) for s in active if s.slot_id == slot_id]
            if slot_label:
                clean_lbl = sanitize_public_label(slot_label, max_len=64)
                return [
                    (s.slot_id, s.user_id)
                    for s in active
                    if self._labels_by_user.get(s.user_id) == clean_lbl
                ]
            return []


def handle_get_snaptrade_status(
    *,
    config: ApiConfig,
    relay: SnapTradeRelayCoordinator,
) -> tuple[int, dict[str, Any]]:
    """Serve ``GET /api/v1/connect/snaptrade/status``."""
    configured, _, _, dev_key = _resolve_snaptrade_runtime(config)
    status_summary = relay.slot_status_dict(include_slots=True)
    return 200, {
        "configured": configured,
        "mode": "developer_5_slot",
        "requires_dev_key": bool(dev_key),
        "max_slots": status_summary["max_slots"],
        "active_slots": status_summary["active_slots"],
        "available_slots": status_summary["available_slots"],
        "slots": status_summary["slots"],
    }


def handle_post_snaptrade_portal(
    payload: Any,
    *,
    config: ApiConfig,
    relay: SnapTradeRelayCoordinator,
    headers: Mapping[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Serve ``POST /api/v1/connect/snaptrade/portal`` (strictly ``connectionType='read'``)."""
    if not isinstance(payload, Mapping):
        return 400, {"error": "invalid_request", "detail": "Request body must be a JSON object"}

    configured, client_id, consumer_key, dev_key = _resolve_snaptrade_runtime(config)
    if not configured:
        return 503, {"error": "snaptrade_unconfigured", "detail": SNAPTRADE_UNCONFIGURED_DETAIL}

    dev_ok, dev_err = _verify_dev_key_if_required(payload, headers, dev_key)
    if not dev_ok and dev_err is not None:
        return dev_err

    redir_ok, clean_redirect, redir_err = validate_snaptrade_redirect_url(
        payload.get("redirect_url")
    )
    if not redir_ok:
        return 422, {"error": "invalid_redirect_url", "detail": redir_err or "Invalid redirect_url"}

    raw_label = payload.get("slot_label")
    if raw_label is not None and not isinstance(raw_label, str):
        return 422, {"error": "validation_error", "detail": "slot_label must be a string"}
    clean_label = sanitize_public_label(raw_label, max_len=64) if raw_label else ""
    if not clean_label:
        clean_label = f"promo-slot-{secrets.token_hex(4)}"

    raw_broker = payload.get("broker")
    if raw_broker is not None and not isinstance(raw_broker, str):
        return 422, {"error": "validation_error", "detail": "broker must be a string"}
    clean_broker = sanitize_public_label(raw_broker, max_len=48).upper() if raw_broker else None

    raw_reconnect = payload.get("reconnect")
    if raw_reconnect is not None and not isinstance(raw_reconnect, str):
        return 422, {"error": "validation_error", "detail": "reconnect must be a string"}
    clean_reconnect = sanitize_public_label(raw_reconnect, max_len=64) if raw_reconnect else None

    # Reject any caller attempt to override connectionType away from "read"
    caller_conn_type = payload.get("connection_type") or payload.get("connectionType")
    if caller_conn_type is not None and str(caller_conn_type).strip().lower() != "read":
        return 422, {
            "error": "read_only_capability_violation",
            "detail": "SnapTrade relay strictly enforces connectionType='read'; trading scope is prohibited.",
        }

    user_id = _derive_blinded_snaptrade_user_id(clean_label, config.account_blinding_salt_hex)
    adapter = relay.build_adapter(client_id, consumer_key)
    secrets_to_redact = [consumer_key, client_id, user_id]

    try:
        with relay._lock:
            existing_secret = relay.find_active_secret_for_user(user_id)
            if existing_secret and relay.slot_manager.is_user_registered(user_id):
                user_secret = existing_secret
            else:
                if relay.slot_manager.is_user_registered(user_id) and not existing_secret:
                    try:
                        adapter.delete_user_and_release_slot(user_id)
                    except SnapTradeError:
                        relay.slot_manager.release_slot(user_id)
                reg = adapter.register_user(user_id)
                user_secret = reg["userSecret"]

            secrets_to_redact.append(user_secret)
            portal = adapter.generate_connection_portal_url(
                user_id,
                user_secret,
                broker=clean_broker or None,
                custom_redirect=clean_redirect,
                reconnect=clean_reconnect or None,
                connection_type="read",
            )
            slot_obj = relay.slot_manager.get_slot(user_id)
            if slot_obj is None or not slot_obj.active:
                slot_obj = relay.slot_manager.register_slot(user_id)

            sess = relay.store_session(
                slot_id=slot_obj.slot_id,
                slot_label=clean_label,
                user_id=user_id,
                user_secret=user_secret,
            )
            counts = relay.slot_status_dict(include_slots=False)

        return 200, {
            "slot_id": sess.slot_id,
            "slot_label": sess.slot_label,
            "session_token": sess.session_token,
            "portal_url": portal["redirectURI"],
            "connection_type": "read",
            "max_slots": counts["max_slots"],
            "active_slots": counts["active_slots"],
            "available_slots": counts["available_slots"],
        }
    except SnapTradeSlotCapExceededError as exc:
        counts = relay.slot_status_dict(include_slots=False)
        safe_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_to_redact)
        return 409, {
            "error": "slot_cap_exceeded",
            "detail": safe_msg,
            "max_slots": counts["max_slots"],
            "active_slots": counts["active_slots"],
            "available_slots": counts["available_slots"],
        }
    except DisallowedCapabilityError as exc:
        safe_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_to_redact)
        return 422, {"error": "read_only_capability_violation", "detail": safe_msg}
    except (SnapTradeAuthenticationError, SnapTradeServiceError, SnapTradeError) as exc:
        safe_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_to_redact)
        return 502, {"error": "snaptrade_upstream_error", "detail": safe_msg}


def handle_post_snaptrade_verify(
    payload: Any,
    *,
    config: ApiConfig,
    store: ProofStore,
    relay: SnapTradeRelayCoordinator,
    pipeline_spec: WorkerPipelineSpec = None,
    headers: Mapping[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Serve ``POST /api/v1/connect/snaptrade/verify`` via isolated single-use worker."""
    if not isinstance(payload, Mapping):
        return 400, {"error": "invalid_request", "detail": "Request body must be a JSON object"}

    configured, client_id, consumer_key, dev_key = _resolve_snaptrade_runtime(config)
    if not configured:
        return 503, {"error": "snaptrade_unconfigured", "detail": SNAPTRADE_UNCONFIGURED_DETAIL}

    dev_ok, dev_err = _verify_dev_key_if_required(payload, headers, dev_key)
    if not dev_ok and dev_err is not None:
        return dev_err

    raw_token = payload.get("session_token")
    if not isinstance(raw_token, str) or not raw_token.strip():
        return 422, {"error": "validation_error", "detail": "session_token is required"}

    sess = relay.get_session(raw_token.strip())
    if sess is None:
        return 404, {
            "error": "session_not_found",
            "detail": "SnapTrade relay session_token is invalid, expired, or already released.",
        }

    start_date = (
        str(payload["start_date"]).strip() if payload.get("start_date") is not None else None
    )
    end_date = str(payload["end_date"]).strip() if payload.get("end_date") is not None else None
    disclose_leaf_names = payload.get("disclose_leaf_names")
    if disclose_leaf_names is not None and (
        not isinstance(disclose_leaf_names, list)
        or not all(isinstance(x, str) for x in disclose_leaf_names)
    ):
        return 422, {
            "error": "validation_error",
            "detail": "disclose_leaf_names must be a list of leaf name strings",
        }

    selected_account_ids = payload.get("selected_account_ids")
    if selected_account_ids is not None and (
        not isinstance(selected_account_ids, list)
        or not all(isinstance(x, str) for x in selected_account_ids)
    ):
        return 422, {
            "error": "validation_error",
            "detail": "selected_account_ids must be a list of account ID strings",
        }

    release_slot_after = bool(payload.get("release_slot_after", False))
    publish_proof = bool(payload.get("publish_proof", False))
    opt_in_leaderboard = bool(payload.get("opt_in_leaderboard", False))

    adapter = relay.build_adapter(client_id, consumer_key)
    secrets_to_redact = [consumer_key, client_id, sess.user_secret, sess.user_id]

    try:
        live_ledger = adapter.fetch_live_ledger(
            sess.user_id,
            sess.user_secret,
            blinding_salt_hex=config.account_blinding_salt_hex,
            start_date=start_date,
            end_date=end_date,
            selected_account_ids=selected_account_ids,
            require_live=True,
        )
    except PaperOrSandboxAccountRejectedError as exc:
        safe_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_to_redact)
        return 422, {"error": "paper_or_sandbox_rejected", "detail": safe_msg}
    except (DisallowedCapabilityError, ReadOnlyCapabilityViolationError) as exc:
        safe_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_to_redact)
        return 422, {"error": "read_only_capability_violation", "detail": safe_msg}
    except ValueError as exc:
        safe_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_to_redact)
        return 422, {"error": "validation_error", "detail": safe_msg}
    except SnapTradeError as exc:
        safe_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_to_redact)
        return 502, {"error": "snaptrade_upstream_error", "detail": safe_msg}

    worker_payload: dict[str, Any] = {
        "broker_id": live_ledger.broker_id,
        "provider_approval_state": live_ledger.provider_approval_state.value,
        "environment_tier": live_ledger.environment_tier.value,
        "account_scope": live_ledger.account_scope.value,
        "claimed_origin_assurance": live_ledger.claimed_origin_assurance.value,
        "period_start_utc": live_ledger.period_start_utc,
        "period_end_utc": live_ledger.period_end_utc,
        "base_currency": live_ledger.base_currency,
        "ledger": live_ledger.to_dict(),
    }
    if disclose_leaf_names is not None:
        worker_payload["disclose_leaf_names"] = list(disclose_leaf_names)
    if payload.get("issued_at_utc") is not None:
        worker_payload["issued_at_utc"] = str(payload["issued_at_utc"])

    try:
        bundle, receipt, stripped_trades = run_isolated_one_shot_verification(
            worker_payload,
            config=config,
            pipeline_spec=pipeline_spec,
            retention_mode="no_persistent_storage",
            persistent_rows_written=0,
            _trusted_internal_input=True,
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
    if publish_proof:
        try:
            bundle, verification = store.store_proof(
                bundle, opt_in_leaderboard=opt_in_leaderboard
            )
            rows_written = 1
        except ProofConflictError as exc:
            return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
        except ProofBundleInvalidError as exc:
            return 422, {"error": "invalid_proof_bundle", "errors": exc.errors}
    else:
        verification = store.verify_bundle_against_live_state(bundle)

    receipt.persistent_rows_written = rows_written

    slot_released = False
    if release_slot_after:
        try:
            adapter.delete_user_and_release_slot(sess.user_id)
        except SnapTradeError:
            pass
        relay.purge_user_sessions_and_release_local(sess.user_id)
        slot_released = True
        token_disposal = "deleted_at_snaptrade_and_purged_from_memory"
    else:
        token_disposal = "ephemeral_in_memory_30m_ttl_slot_retained"

    slot_status = relay.slot_status_dict(include_slots=False)
    bundle_dict = bundle.to_dict()

    return 200, {
        "bundle": bundle_dict,
        "proof_bundle": bundle_dict,
        "verification": verification.to_dict(),
        "isolation": {
            "worker_isolated": bool(
                receipt.worker_terminated
                and receipt.worker_pid != receipt.parent_pid
                and receipt.worker_exitcode == 0
            ),
            "rlimit_core_zero": bool(
                receipt.rlimit_core_soft == 0 and receipt.rlimit_core_hard == 0
            ),
            "slot_released": slot_released,
            "token_disposal": token_disposal,
            "db_rows_written": rows_written,
            "connection_type": "read",
        },
        "isolation_receipt": receipt.to_dict(),
        "stripped_recent_closed_trades_count": stripped_trades,
        "slot_status": slot_status,
    }


def handle_post_snaptrade_release(
    payload: Any,
    *,
    config: ApiConfig,
    relay: SnapTradeRelayCoordinator,
    headers: Mapping[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Serve ``POST /api/v1/connect/snaptrade/release`` to recycle developer/promo slots."""
    if not isinstance(payload, Mapping):
        return 400, {"error": "invalid_request", "detail": "Request body must be a JSON object"}

    configured, client_id, consumer_key, dev_key = _resolve_snaptrade_runtime(config)
    if not configured:
        return 503, {"error": "snaptrade_unconfigured", "detail": SNAPTRADE_UNCONFIGURED_DETAIL}

    dev_ok, dev_err = _verify_dev_key_if_required(payload, headers, dev_key)
    if not dev_ok and dev_err is not None:
        return dev_err

    release_all = bool(payload.get("release_all", False))
    raw_slot_id = payload.get("slot_id")
    slot_id: int | None = None
    if raw_slot_id is not None:
        if isinstance(raw_slot_id, bool) or not isinstance(raw_slot_id, int):
            return 422, {"error": "validation_error", "detail": "slot_id must be an integer"}
        slot_id = int(raw_slot_id)

    raw_slot_label = payload.get("slot_label")
    if raw_slot_label is not None and not isinstance(raw_slot_label, str):
        return 422, {"error": "validation_error", "detail": "slot_label must be a string"}
    slot_label = raw_slot_label.strip() if isinstance(raw_slot_label, str) else None

    if not release_all and slot_id is None and not slot_label:
        return 422, {
            "error": "validation_error",
            "detail": "Provide slot_id, slot_label, or release_all=true",
        }

    targets = relay.resolve_users_for_release(
        slot_id=slot_id,
        slot_label=slot_label,
        release_all=release_all,
    )
    if not targets and not release_all:
        return 404, {
            "error": "slot_not_found",
            "detail": "No active SnapTrade slot matched the requested slot_id or slot_label.",
            "slot_status": relay.slot_status_dict(include_slots=True),
        }

    adapter = relay.build_adapter(client_id, consumer_key)
    released_ids: list[int] = []
    upstream_deleted_all = True

    for sid, uid in targets:
        try:
            adapter.delete_user_and_release_slot(uid)
        except SnapTradeError:
            upstream_deleted_all = False
        relay.purge_user_sessions_and_release_local(uid)
        released_ids.append(sid)

    updated_status = relay.slot_status_dict(include_slots=True)
    return 200, {
        "released": True,
        "released_slot_ids": sorted(released_ids),
        "upstream_deleted": upstream_deleted_all,
        "max_slots": updated_status["max_slots"],
        "active_slots": updated_status["active_slots"],
        "available_slots": updated_status["available_slots"],
        "slot_status": updated_status,
    }


__all__ = [
    "MAX_EPHEMERAL_SNAPTRADE_SESSIONS",
    "SNAPTRADE_SESSION_TTL_SECONDS",
    "SNAPTRADE_UNCONFIGURED_DETAIL",
    "SnapTradeRelayCoordinator",
    "handle_get_snaptrade_status",
    "handle_post_snaptrade_portal",
    "handle_post_snaptrade_release",
    "handle_post_snaptrade_verify",
    "validate_snaptrade_redirect_url",
]
