"""Ephemeral 5-slot SnapTrade V1 developer/promo relay routes for N170 Verify."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import importlib
import logging
import re
import secrets
import threading
import time
from typing import Any
from urllib.parse import unquote, urlsplit

from app.config import ApiConfig
from app.routes_proofs import parse_strict_bool, refuse_caller_clock
from app.routes_viral import sanitize_public_label
from app.store import (
    GovernanceBlockedError,
    PaperOrSandboxRejectedError,
    ProofBundleInvalidError,
    ProofConflictError,
    ProofStore,
)
from app.worker_isolation import (
    WORKER_LIMIT_ERRORS,
    WorkerBrokerUpstreamError,
    WorkerInputTooLargeError,
    WorkerIsolationError,
    WorkerPipelineSpec,
    WorkerValidationError,
    run_isolated_one_shot_verification,
    worker_limit_response,
)
from n170_verify.connectors import (
    DisallowedCapabilityError,
    MAX_SNAPTRADE_PERSONAL_SLOTS,
    MAX_SNAPTRADE_POC_SLOTS,
    PaperOrSandboxAccountRejectedError,
    SNAPTRADE_INITIAL_SYNC_PENDING_MESSAGE,
    SNAPTRADE_NO_LINKED_ACCOUNT_MESSAGE,
    SnapTradeAuthenticationError,
    SnapTradeError,
    SnapTradeNoLinkedAccountError,
    SnapTradeReadOnlyAdapter,
    SnapTradeServiceError,
    SnapTradeSlotCapExceededError,
    SnapTradeSlotManager,
    is_snaptrade_env_configured,
    is_snaptrade_personal_key,
    redact_sensitive_text,
)
from n170_verify.contracts import (
    EnvironmentTier,
    ProviderApprovalState,
    ReadOnlyCapabilityViolationError,
)


SNAPTRADE_SESSION_TTL_SECONDS: float = 1800.0
MAX_EPHEMERAL_SNAPTRADE_SESSIONS: int = 64
SNAPTRADE_UNCONFIGURED_DETAIL: str = (
    "Set SNAPTRADE_CLIENT_ID and SNAPTRADE_CONSUMER_KEY on the API server "
    "to enable the 5-slot developer/promo relay."
)
# Every upstream user this relay creates carries this prefix; start-up clean-up touches no other id.
SNAPTRADE_RELAY_USER_PREFIX: str = "n170-st-"
# A failed start-up listing is retried after this wait, doubling up to the maximum.
SWEEP_RETRY_INITIAL_SECONDS: float = 60.0
SWEEP_RETRY_MAX_SECONDS: float = 900.0
# A verify refusal with this reason can succeed on retry (the visitor has not finished linking
# an account yet), so the session and its seat are kept. Across the worker boundary only the
# message survives, so the connector's own message is matched there.
_RETRYABLE_REFUSAL_MARKERS: tuple[str, ...] = (
    SNAPTRADE_NO_LINKED_ACCOUNT_MESSAGE,
    SNAPTRADE_INITIAL_SYNC_PENDING_MESSAGE,
)

# One request retries at most this many queued upstream deletes before it answers.
MAX_QUEUED_DELETES_PER_REQUEST: int = 2

_LOG = logging.getLogger(__name__)


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
    is_personal: bool = False
    created_monotonic: float = 0.0


def _utc_iso_from_dt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _effective_port(scheme: str, port: int | None) -> int | None:
    if port is not None:
        return port
    return {"https": 443, "http": 80}.get(scheme)


def _parse_site_origin(raw_origin: str | None) -> tuple[str, str, int] | None:
    """Parse ``ApiConfig.site_origin`` (validated at start-up) into ``(scheme, host, port)``."""
    cleaned = (raw_origin or "").strip()
    if not cleaned:
        return None
    try:
        parsed = urlsplit(cleaned)
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").strip().lower()
    if (
        scheme not in ("http", "https")
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        return None
    eff = _effective_port(scheme, port)
    if eff is None:
        return None
    return scheme, host, eff


def resolve_snaptrade_site_origin(config: ApiConfig) -> str:
    """Return ``config.site_origin`` (may be empty). The environment is never read here."""
    return (config.site_origin or "").strip()


def validate_snaptrade_redirect_url(
    raw_url: Any,
    *,
    allowed_origin: str | None = None,
    hosted_multi_user_mode: bool = True,
) -> tuple[bool, str | None, str | None]:
    """Validate optional ``redirect_url``: the configured site origin or local ``http://127.0.0.1:*``."""
    if raw_url is None:
        return True, None, None
    if not isinstance(raw_url, str):
        return False, None, "redirect_url must be a string"
    cleaned = raw_url.strip()
    if not cleaned:
        return True, None, None
    if len(cleaned) > 1024 or any(ord(ch) < 33 or ord(ch) == 127 for ch in cleaned):
        return False, None, "redirect_url contains disallowed whitespace, control chars, or length"
    if "\\" in cleaned:
        return False, None, "redirect_url must not contain backslashes"

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

    if parsed.path:
        unquoted_path = unquote(parsed.path)
        if (
            not parsed.path.startswith("/")
            or parsed.path.startswith("//")
            or unquoted_path.startswith("//")
            or "\\" in unquoted_path
        ):
            return False, None, "redirect_url path must start with a single '/' and contain no backslashes"

    site = _parse_site_origin(allowed_origin)
    allow_loopback = (not hosted_multi_user_mode) or (
        site is not None and site[1] in {"localhost", "127.0.0.1"}
    )
    if allow_loopback and scheme == "http" and host == "127.0.0.1":
        return True, cleaned, None
    if site is not None and (scheme, host, _effective_port(scheme, port)) == site:
        return True, cleaned, None

    return (
        False,
        None,
        "redirect_url must be on this site's own origin or local http://127.0.0.1:* callback origin",
    )


_CLEAN_SNAPTRADE_HTTP_ERR_RE = re.compile(
    r"^(SnapTrade\s+/[A-Za-z0-9_./-]+\s+failed\s+with\s+HTTP\s+\d{3})\b"
)
_CLEAN_SNAPTRADE_TRANSPORT_ERR_RE = re.compile(
    r"^(SnapTrade\s+[A-Z]+\s+/[A-Za-z0-9_./-]+\s+transport\s+error)\b"
)
_CLEAN_SNAPTRADE_MALFORMED_ERR_RE = re.compile(
    r"^(SnapTrade\s+/[A-Za-z0-9_./-]+\s+returned\s+malformed\s+JSON\s+response)\b"
)


def _clean_snaptrade_upstream_detail(
    exc: BaseException, *, extra_secrets: list[str] | None = None
) -> str:
    """Return a clean upstream status message without echoing raw upstream 5xx body text."""
    redacted = redact_sensitive_text(str(exc), extra_secrets=extra_secrets or [])
    clean = "SnapTrade upstream request failed"
    for pat in (
        _CLEAN_SNAPTRADE_HTTP_ERR_RE,
        _CLEAN_SNAPTRADE_TRANSPORT_ERR_RE,
        _CLEAN_SNAPTRADE_MALFORMED_ERR_RE,
    ):
        m = pat.match(redacted)
        if m is not None:
            clean = m.group(1)
            break
    _LOG.warning("SnapTrade upstream error: %s", clean)
    return clean


def deployment_user_prefix(salt_hex: str) -> str:
    """This deployment's upstream user-id prefix: ``n170-st-<tag>-``.

    ``tag`` is the first 8 hex characters of HMAC-SHA256 keyed with the account blinding salt
    over the fixed label ``n170.snaptrade.deployment.v1``. It tells this deployment's users
    apart from those of another deployment sharing the consumer key; the salt itself is never
    sent or recoverable from it.
    """
    tag = hmac.new(
        bytes.fromhex(salt_hex), b"n170.snaptrade.deployment.v1", hashlib.sha256
    ).hexdigest()[:8]
    return f"{SNAPTRADE_RELAY_USER_PREFIX}{tag}-"


def _new_relay_user_id(salt_hex: str) -> str:
    """A fresh random upstream user id for one portal call (never derived from caller input)."""
    return f"{deployment_user_prefix(salt_hex)}{secrets.token_hex(12)}"


def _derive_blinded_snaptrade_user_id(slot_label: str, salt_hex: str) -> str:
    salt_bytes = bytes.fromhex(salt_hex)
    digest = hmac.new(
        salt_bytes,
        b"n170.snaptrade.slot_user.v1\x00" + slot_label.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"n170-st-{digest[:24]}"


def _resolve_snaptrade_runtime(config: ApiConfig) -> tuple[bool, str, str, str, str]:
    # Settings come only from ApiConfig (read once at start-up). Reading the process
    # environment here could see it empty while a verification worker is being started.
    client_id = (config.snaptrade_client_id or "").strip()
    consumer_key = (config.snaptrade_consumer_key or "").strip()
    dev_key = (config.snaptrade_dev_key or "").strip()
    auth_mode = (config.snaptrade_auth_mode or "").strip() or "auto"
    configured = is_snaptrade_env_configured(
        {
            "SNAPTRADE_CLIENT_ID": client_id,
            "SNAPTRADE_CONSUMER_KEY": consumer_key,
        }
    )
    return configured, client_id, consumer_key, dev_key, auth_mode


def _resolve_snaptrade_mode(
    configured: bool,
    client_id: str,
    *,
    auth_mode: str = "auto",
) -> tuple[bool, str, int]:
    """Resolve ``(is_personal, mode_label, max_slots)`` for SnapTrade Personal vs Build keys."""
    if configured and is_snaptrade_personal_key(client_id, auth_mode=auth_mode):
        return True, "personal_1_slot", MAX_SNAPTRADE_PERSONAL_SLOTS
    return False, "developer_5_slot", MAX_SNAPTRADE_POC_SLOTS


def _caller_presented_dev_key(
    payload: Mapping[str, Any] | None,
    headers: Mapping[str, str] | None,
    expected_dev_key: str,
) -> bool:
    """True only when a dev key is configured and this caller presented it."""
    if not expected_dev_key:
        return False
    ok, _ = _verify_dev_key_if_required(payload, headers, expected_dev_key)
    return ok


def _personal_mode_refusal(
    config: ApiConfig,
    *,
    is_personal: bool,
    dev_key: str,
) -> tuple[int, dict[str, Any]] | None:
    """In hosted mode a personal key serves only its owner, identified by a configured dev key."""
    if is_personal and config.hosted_multi_user_mode and not dev_key:
        return 403, {
            "error": "personal_key_requires_dev_key",
            "detail": (
                "A SnapTrade personal key belongs to one owner. In hosted mode the relay serves it "
                "only when N170_SNAPTRADE_DEV_KEY is configured and the caller presents it."
            ),
        }
    return None


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
        self.personal_slot_manager = SnapTradeSlotManager(max_slots=MAX_SNAPTRADE_PERSONAL_SLOTS)
        self.http_transport = http_transport
        self.session_ttl_seconds = float(session_ttl_seconds)
        self.max_sessions = int(max_sessions)
        self._clock = monotonic_clock
        self._lock = threading.RLock()
        self._sessions: dict[str, _EphemeralSnapTradeSession] = {}
        self._labels_by_user: dict[str, str] = {}
        self._pending_upstream_deletes: set[str] = set()
        self._deferred_in_use_deletes: dict[str, SnapTradeReadOnlyAdapter] = {}
        # Users whose seat is reserved while their upstream registration is in flight.
        self._reserved_users: set[str] = set()
        # Users whose session is being read by a verify right now: never expired or deleted
        # upstream until that verify has finished (count of verifies in flight per user).
        self._users_in_use: dict[str, int] = {}
        self._startup_cleanup_done = False
        self._sweep_running = False
        self._sweep_next_attempt = float("-inf")
        self._sweep_backoff_seconds = SWEEP_RETRY_INITIAL_SECONDS
        self.startup_cleanup_warnings: list[str] = []

    def _user_known_locked(self, user_id: str) -> bool:
        """True when this process holds the user: a seat, a reservation or a live session."""
        return (
            self.slot_manager.is_user_registered(user_id)
            or user_id in self._reserved_users
            or user_id in self._users_in_use
            or any(s.user_id == user_id for s in self._sessions.values())
        )

    def cleanup_leftover_upstream_users_once(
        self,
        adapter: SnapTradeReadOnlyAdapter,
        *,
        user_prefix: str,
    ) -> int:
        """Delete this deployment's relay users left upstream by an earlier process.

        Sessions live only in memory, so users created before a restart can no longer be used
        or released. Only build (non-personal) keys are touched and only ids starting with
        ``user_prefix`` (this deployment's own prefix) are deleted. No upstream call is made
        while holding the relay lock: each id is checked under the lock right before its
        delete, and a user with a seat, a reservation or a live session here is never removed.
        The sweep is marked done only after a successful listing; after a failure the next
        attempt waits SWEEP_RETRY_INITIAL_SECONDS, doubling up to SWEEP_RETRY_MAX_SECONDS, so a
        failing upstream adds at most one slow call per wait. Failures never stop the API.
        """
        if adapter.is_personal_key:
            return 0
        with self._lock:
            if (
                self._startup_cleanup_done
                or self._sweep_running
                or self._clock() < self._sweep_next_attempt
            ):
                return 0
            self._sweep_running = True
        try:
            try:
                resp = adapter._execute_signed("GET", "/api/v1/snapTrade/listUsers")
                listed = adapter._decode_json_or_raise(
                    resp, api_path="/api/v1/snapTrade/listUsers"
                )
            except Exception as exc:  # noqa: BLE001 - start-up clean-up must never stop the API
                self._record_cleanup_warning("listing upstream users failed", exc, adapter)
                self._schedule_sweep_retry()
                return 0
            if not isinstance(listed, list):
                self.startup_cleanup_warnings.append(
                    "SnapTrade start-up clean-up: listUsers returned a non-list response; will retry"
                )
                _LOG.warning(self.startup_cleanup_warnings[-1])
                self._schedule_sweep_retry()
                return 0
            with self._lock:
                self._startup_cleanup_done = True
            deleted = 0
            for uid in listed:
                if not isinstance(uid, str) or not uid.startswith(user_prefix):
                    continue
                with self._lock:
                    if self._user_known_locked(uid):
                        continue
                try:
                    adapter.delete_user_and_release_slot(uid)
                    deleted += 1
                except Exception as exc:  # noqa: BLE001
                    self._record_cleanup_warning(
                        "deleting a leftover upstream user failed", exc, adapter
                    )
            return deleted
        finally:
            with self._lock:
                self._sweep_running = False

    def _schedule_sweep_retry(self) -> None:
        with self._lock:
            self._sweep_next_attempt = self._clock() + self._sweep_backoff_seconds
            self._sweep_backoff_seconds = min(
                self._sweep_backoff_seconds * 2.0, SWEEP_RETRY_MAX_SECONDS
            )

    def reserve_seat(self, user_id: str, *, is_personal: bool) -> tuple[Any, bool]:
        """Reserve a seat for ``user_id`` before any upstream call; returns ``(slot, newly)``."""
        self.purge_expired_sessions()
        manager = self._manager_for(is_personal=is_personal)
        with self._lock:
            already = manager.is_user_registered(user_id)
            if len(self._sessions) >= self.max_sessions and not (is_personal and already):
                raise SnapTradeSlotCapExceededError(
                    "SnapTrade relay session table is full; try again later"
                )
            slot = manager.register_slot(user_id)
            if not is_personal:
                self._reserved_users.add(user_id)
            return slot, not already

    def cancel_reservation(self, user_id: str, *, is_personal: bool, newly: bool) -> None:
        """Free a seat reserved for a portal call that failed."""
        with self._lock:
            self._reserved_users.discard(user_id)
            if newly:
                self._manager_for(is_personal=is_personal).release_slot(user_id)

    def finalize_reservation(
        self,
        *,
        slot_id: int,
        slot_label: str,
        user_id: str,
        user_secret: str,
        is_personal: bool,
    ) -> _EphemeralSnapTradeSession:
        """Turn a reservation into a session in one step under the lock."""
        with self._lock:
            sess = self.store_session(
                slot_id=slot_id,
                slot_label=slot_label,
                user_id=user_id,
                user_secret=user_secret,
                is_personal=is_personal,
            )
            self._reserved_users.discard(user_id)
            return sess

    def _record_cleanup_warning(
        self,
        what: str,
        exc: BaseException,
        adapter: SnapTradeReadOnlyAdapter,
    ) -> None:
        safe = redact_sensitive_text(
            f"{type(exc).__name__}: {exc}",
            extra_secrets=[adapter.consumer_key, adapter.client_id],
        )
        msg = f"SnapTrade start-up clean-up: {what}; continuing ({safe})"
        self.startup_cleanup_warnings.append(msg)
        _LOG.warning(msg)

    def session_count(self) -> int:
        self.purge_expired_sessions()
        with self._lock:
            return len(self._sessions)

    def _manager_for(self, *, is_personal: bool) -> SnapTradeSlotManager:
        return self.personal_slot_manager if is_personal else self.slot_manager

    def purge_expired_sessions(self) -> int:
        """Purge expired session tokens, release orphaned local slots, and queue upstream cleanup."""
        now_mono = self._clock()
        with self._lock:
            expired_items = [
                (tok, sess)
                for tok, sess in self._sessions.items()
                if now_mono >= sess.expires_monotonic and sess.user_id not in self._users_in_use
            ]
            for tok, _ in expired_items:
                self._sessions.pop(tok, None)
            if expired_items:
                active_users = {s.user_id for s in self._sessions.values()}
                for _, exp_sess in expired_items:
                    if exp_sess.user_id not in active_users:
                        self._labels_by_user.pop(exp_sess.user_id, None)
                        self._manager_for(is_personal=exp_sess.is_personal).release_slot(
                            exp_sess.user_id
                        )
                        if not exp_sess.is_personal:
                            self._pending_upstream_deletes.add(exp_sess.user_id)
            return len(expired_items)

    def reap_expired_upstream_users(self, adapter: SnapTradeReadOnlyAdapter) -> int:
        """Delete any TTL-expired abandoned commercial/build slot users upstream at SnapTrade."""
        self.purge_expired_sessions()
        if adapter.is_personal_key:
            return 0
        with self._lock:
            active_users = {s.user_id for s in self._sessions.values()} | set(self._users_in_use)
            candidates = sorted(
                uid for uid in self._pending_upstream_deletes if uid not in active_users
            )[:MAX_QUEUED_DELETES_PER_REQUEST]
            for uid in candidates:
                self._pending_upstream_deletes.discard(uid)
        reaped = 0
        for uid in candidates:
            try:
                adapter.delete_user_and_release_slot(uid)
                with self._lock:
                    self._deferred_in_use_deletes.pop(uid, None)
                    self.slot_manager.release_slot(uid)
                reaped += 1
            except SnapTradeError:
                # Still upstream: try again on a later request.
                with self._lock:
                    self._pending_upstream_deletes.add(uid)
        return reaped

    def slot_status_dict(
        self,
        *,
        include_slots: bool = False,
        is_personal: bool = False,
    ) -> dict[str, Any]:
        """Return current slot cap utilization summary (zero secrets or raw account IDs)."""
        self.purge_expired_sessions()
        manager = self._manager_for(is_personal=is_personal)
        with self._lock:
            active_slots = manager.list_active_slots()
            active_count = len(active_slots)
            max_slots = manager.max_slots
            out: dict[str, Any] = {
                "max_slots": max_slots,
                "active_slots": active_count,
                "available_slots": max(0, max_slots - active_count),
            }
            if include_slots:
                out["slots"] = [
                    {
                        "slot_id": s.slot_id,
                        "registered_at_utc": s.registered_at_utc,
                    }
                    for s in active_slots
                ]
            return out

    def build_adapter(
        self,
        client_id: str,
        consumer_key: str,
        *,
        auth_mode: str = "auto",
    ) -> SnapTradeReadOnlyAdapter:
        is_personal = is_snaptrade_personal_key(client_id, auth_mode=auth_mode)
        resolved_transport = self.http_transport
        if isinstance(resolved_transport, str) and ":" in resolved_transport:
            mod_name, attr_name = resolved_transport.split(":", 1)
            resolved_transport = getattr(importlib.import_module(mod_name), attr_name)
        # The adapter gets its own throwaway slot book: seats are kept only in this
        # coordinator and changed only under its lock, never as a side effect of an HTTP call.
        return SnapTradeReadOnlyAdapter(
            client_id=client_id,
            consumer_key=consumer_key,
            auth_mode=auth_mode,
            slot_manager=SnapTradeSlotManager(
                max_slots=MAX_SNAPTRADE_PERSONAL_SLOTS if is_personal else MAX_SNAPTRADE_POC_SLOTS
            ),
            http_transport=resolved_transport,
            require_live=True,
            auto_register_slot=False,
        )

    def store_session(
        self,
        *,
        slot_id: int,
        slot_label: str,
        user_id: str,
        user_secret: str,
        is_personal: bool = False,
    ) -> _EphemeralSnapTradeSession:
        self.purge_expired_sessions()
        now_mono = self._clock()
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
            expires_monotonic=now_mono + self.session_ttl_seconds,
            is_personal=is_personal,
            created_monotonic=now_mono,
        )
        with self._lock:
            # One session holds one slot: a new session for the same user replaces the old one.
            for old_tok in [t for t, s in self._sessions.items() if s.user_id == user_id]:
                self._sessions.pop(old_tok, None)
            # Never evict another caller's session to make room; refuse instead.
            if len(self._sessions) >= self.max_sessions:
                raise SnapTradeSlotCapExceededError(
                    f"SnapTrade relay session table is full ({self.max_sessions} active sessions)"
                )
            self._labels_by_user[user_id] = slot_label
            self._pending_upstream_deletes.discard(user_id)
            self._deferred_in_use_deletes.pop(user_id, None)
            self._sessions[token] = sess
        return sess

    def get_session(self, session_token: str) -> _EphemeralSnapTradeSession | None:
        self.purge_expired_sessions()
        with self._lock:
            return self._sessions.get(session_token)

    def get_session_for_use(self, session_token: str) -> _EphemeralSnapTradeSession | None:
        """Look a session up and mark its user in use, in one step under the lock; the caller
        must call ``finish_use`` with the user id when it is done."""
        self.purge_expired_sessions()
        with self._lock:
            sess = self._sessions.get(session_token)
            if sess is not None:
                self._users_in_use[sess.user_id] = self._users_in_use.get(sess.user_id, 0) + 1
            return sess

    def refresh_session_ttl(
        self,
        session_token: str,
        *,
        min_window_seconds: float | None = None,
    ) -> _EphemeralSnapTradeSession | None:
        """Extend an active session's TTL up to the hard 30-minute S3 session ceiling."""
        now_mono = self._clock()
        now_utc = datetime.now(timezone.utc)
        window = max(self.session_ttl_seconds, float(min_window_seconds or 0.0))
        max_lifetime = max(self.session_ttl_seconds, SNAPTRADE_SESSION_TTL_SECONDS)
        with self._lock:
            sess = self._sessions.get(session_token)
            if sess is None:
                return None
            ceiling_mono = sess.created_monotonic + max_lifetime
            if now_mono >= ceiling_mono:
                return None
            next_mono = min(now_mono + window, ceiling_mono)
            if next_mono > sess.expires_monotonic:
                sess.expires_monotonic = next_mono
                sess.expires_at_utc = _utc_iso_from_dt(
                    now_utc + timedelta(seconds=next_mono - now_mono)
                )
            return sess

    def finish_use(
        self,
        user_id: str,
        *,
        adapter: SnapTradeReadOnlyAdapter | None = None,
    ) -> bool:
        delete_adapter: SnapTradeReadOnlyAdapter | None = None
        with self._lock:
            left = self._users_in_use.get(user_id, 0) - 1
            if left > 0:
                self._users_in_use[user_id] = left
                return False
            self._users_in_use.pop(user_id, None)
            deferred_adapter = self._deferred_in_use_deletes.pop(user_id, None)
            if deferred_adapter is not None and user_id in self._pending_upstream_deletes:
                has_live_session = any(s.user_id == user_id for s in self._sessions.values())
                if not has_live_session:
                    cand = adapter or deferred_adapter
                    if not cand.is_personal_key:
                        delete_adapter = cand
                        self._pending_upstream_deletes.discard(user_id)
        if delete_adapter is None:
            return False
        try:
            delete_adapter.delete_user_and_release_slot(user_id)
            with self._lock:
                self._pending_upstream_deletes.discard(user_id)
                self._deferred_in_use_deletes.pop(user_id, None)
                self.slot_manager.release_slot(user_id)
            return True
        except SnapTradeError:
            with self._lock:
                self._pending_upstream_deletes.add(user_id)
            return False

    def end_user(
        self,
        adapter: SnapTradeReadOnlyAdapter,
        user_id: str,
        *,
        is_personal: bool,
        held_by_caller: bool = False,
    ) -> bool:
        """End a relay user: purge sessions atomically, delete upstream, then free its seat.

        While another read is still using the user (``held_by_caller`` says whether the
        caller is one of the reads), nothing is deleted upstream: the local seat remains
        reserved and the delete runs as soon as the last read finishes. A failed upstream
        delete of a build-key user keeps the seat reserved until a later retry succeeds.
        Returns True when the upstream delete (or personal-session purge) succeeded now.
        """
        manager = self._manager_for(is_personal=is_personal)
        with self._lock:
            dead_tokens = [
                tok for tok, sess in self._sessions.items() if sess.user_id == user_id
            ]
            for tok in dead_tokens:
                self._sessions.pop(tok, None)
            self._labels_by_user.pop(user_id, None)
            if is_personal:
                self._pending_upstream_deletes.discard(user_id)
                self._deferred_in_use_deletes.pop(user_id, None)
                manager.release_slot(user_id)
                return True
            other_reads = self._users_in_use.get(user_id, 0) - (1 if held_by_caller else 0)
            if other_reads > 0:
                self._pending_upstream_deletes.add(user_id)
                self._deferred_in_use_deletes[user_id] = adapter
                return False
            self._pending_upstream_deletes.discard(user_id)
            self._deferred_in_use_deletes.pop(user_id, None)

        try:
            adapter.delete_user_and_release_slot(user_id)
            with self._lock:
                self._pending_upstream_deletes.discard(user_id)
                self._deferred_in_use_deletes.pop(user_id, None)
                manager.release_slot(user_id)
            return True
        except SnapTradeError:
            with self._lock:
                self._pending_upstream_deletes.add(user_id)
            return False

    def purge_user_sessions_and_release_local(
        self,
        user_id: str,
        *,
        is_personal: bool = False,
    ) -> bool:
        manager = self._manager_for(is_personal=is_personal)
        with self._lock:
            dead_tokens = [
                tok for tok, sess in self._sessions.items() if sess.user_id == user_id
            ]
            for tok in dead_tokens:
                self._sessions.pop(tok, None)
            self._labels_by_user.pop(user_id, None)
            self._pending_upstream_deletes.discard(user_id)
            self._deferred_in_use_deletes.pop(user_id, None)
            return manager.release_slot(user_id)

    def resolve_users_for_release(
        self,
        *,
        slot_id: int | None = None,
        slot_label: str | None = None,
        release_all: bool = False,
        is_personal: bool = False,
    ) -> list[tuple[int, str]]:
        manager = self._manager_for(is_personal=is_personal)
        with self._lock:
            active = manager.list_active_slots()
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
    configured, client_id, consumer_key, dev_key, auth_mode = _resolve_snaptrade_runtime(config)
    try:
        is_personal, mode_label, _ = _resolve_snaptrade_mode(
            configured, client_id, auth_mode=auth_mode
        )
    except SnapTradeAuthenticationError as exc:
        return 500, {"error": "snaptrade_config_error", "detail": str(exc)}
    if configured and not is_personal:
        status_adapter = relay.build_adapter(client_id, consumer_key, auth_mode=auth_mode)
        relay.cleanup_leftover_upstream_users_once(
            status_adapter, user_prefix=deployment_user_prefix(config.account_blinding_salt_hex)
        )
        relay.reap_expired_upstream_users(status_adapter)
    status_summary = relay.slot_status_dict(include_slots=True, is_personal=is_personal)
    return 200, {
        "configured": configured,
        "mode": mode_label,
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

    configured, client_id, consumer_key, dev_key, auth_mode = _resolve_snaptrade_runtime(config)
    if not configured:
        return 503, {"error": "snaptrade_unconfigured", "detail": SNAPTRADE_UNCONFIGURED_DETAIL}

    try:
        is_personal, mode_label, _ = _resolve_snaptrade_mode(
            configured, client_id, auth_mode=auth_mode
        )
    except SnapTradeAuthenticationError as exc:
        return 500, {"error": "snaptrade_config_error", "detail": str(exc)}

    dev_ok, dev_err = _verify_dev_key_if_required(payload, headers, dev_key)
    if not dev_ok and dev_err is not None:
        return dev_err
    refusal = _personal_mode_refusal(config, is_personal=is_personal, dev_key=dev_key)
    if refusal is not None:
        return refusal

    redir_ok, clean_redirect, redir_err = validate_snaptrade_redirect_url(
        payload.get("redirect_url"),
        allowed_origin=resolve_snaptrade_site_origin(config),
        hosted_multi_user_mode=config.hosted_multi_user_mode,
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

    raw_session_token = payload.get("session_token")
    if raw_session_token is not None and (
        not isinstance(raw_session_token, str) or not raw_session_token.strip()
    ):
        return 422, {
            "error": "validation_error",
            "detail": "session_token must be a non-empty string",
        }
    clean_session_token = (
        raw_session_token.strip() if isinstance(raw_session_token, str) else ""
    )

    adapter = relay.build_adapter(client_id, consumer_key, auth_mode=auth_mode)
    if clean_session_token:
        relay.cleanup_leftover_upstream_users_once(
            adapter, user_prefix=deployment_user_prefix(config.account_blinding_salt_hex)
        )
        relay.reap_expired_upstream_users(adapter)
        existing_sess = relay.get_session_for_use(clean_session_token)
        if existing_sess is None:
            return 404, {
                "error": "session_not_found",
                "detail": "SnapTrade relay session_token is invalid, expired, or already released.",
            }
        sess_secrets = [
            tok
            for tok in (
                consumer_key,
                client_id,
                existing_sess.user_id,
                existing_sess.user_secret,
                clean_session_token,
            )
            if tok
        ]
        refreshed_sess: _EphemeralSnapTradeSession | None = None
        try:
            portal = adapter.generate_connection_portal_url(
                existing_sess.user_id,
                existing_sess.user_secret,
                broker=clean_broker or None,
                custom_redirect=clean_redirect,
                reconnect=clean_reconnect or None,
                connection_type="read",
            )
            refreshed_sess = relay.refresh_session_ttl(existing_sess.session_token)
        except DisallowedCapabilityError as exc:
            safe_msg = redact_sensitive_text(str(exc), extra_secrets=sess_secrets)
            return 422, {"error": "read_only_capability_violation", "detail": safe_msg}
        except (SnapTradeAuthenticationError, SnapTradeServiceError, SnapTradeError) as exc:
            safe_msg = _clean_snaptrade_upstream_detail(exc, extra_secrets=sess_secrets)
            return 502, {"error": "snaptrade_upstream_error", "detail": safe_msg}
        finally:
            relay.finish_use(existing_sess.user_id, adapter=adapter)

        if refreshed_sess is None:
            return 404, {
                "error": "session_not_found",
                "detail": "SnapTrade relay session_token is invalid, expired, or already released.",
            }

        counts = relay.slot_status_dict(
            include_slots=False, is_personal=refreshed_sess.is_personal
        )
        return 200, {
            "mode": mode_label,
            "slot_id": refreshed_sess.slot_id,
            "slot_label": refreshed_sess.slot_label,
            "session_token": refreshed_sess.session_token,
            "portal_url": portal["redirectURI"],
            "connection_type": "read",
            "max_slots": counts["max_slots"],
            "active_slots": counts["active_slots"],
            "available_slots": counts["available_slots"],
        }

    manager = relay._manager_for(is_personal=is_personal)
    # A personal key has exactly one upstream identity (its owner). A build key gets a fresh
    # random user per portal call, so a session can only be used by the caller that created it.
    if is_personal:
        user_id = _derive_blinded_snaptrade_user_id(
            "personal-owner", config.account_blinding_salt_hex
        )
    else:
        user_id = _new_relay_user_id(config.account_blinding_salt_hex)
    secrets_to_redact = [consumer_key, client_id, user_id]

    try:
        relay.cleanup_leftover_upstream_users_once(
            adapter, user_prefix=deployment_user_prefix(config.account_blinding_salt_hex)
        )
        relay.reap_expired_upstream_users(adapter)
        # 1. Reserve the seat under the lock (no upstream call yet).
        slot_obj, newly_reserved = relay.reserve_seat(user_id, is_personal=is_personal)
        # 2. Upstream calls run without the relay lock.
        try:
            if is_personal:
                user_secret = ""
            else:
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
            # 3. Finalise under the lock.
            sess = relay.finalize_reservation(
                slot_id=slot_obj.slot_id,
                slot_label=clean_label,
                user_id=user_id,
                user_secret=user_secret,
                is_personal=is_personal,
            )
        except Exception:
            # No session will hold this user: free the reserved seat and remove the user.
            relay.cancel_reservation(user_id, is_personal=is_personal, newly=newly_reserved)
            if not is_personal:
                try:
                    adapter.delete_user_and_release_slot(user_id)
                except SnapTradeError:
                    with relay._lock:
                        relay._pending_upstream_deletes.add(user_id)
            raise
        counts = relay.slot_status_dict(include_slots=False, is_personal=is_personal)

        return 200, {
            "mode": mode_label,
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
        counts = relay.slot_status_dict(include_slots=False, is_personal=is_personal)
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
        safe_msg = _clean_snaptrade_upstream_detail(exc, extra_secrets=secrets_to_redact)
        return 502, {"error": "snaptrade_upstream_error", "detail": safe_msg}


def handle_post_snaptrade_session_status(
    payload: Any,
    *,
    config: ApiConfig,
    relay: SnapTradeRelayCoordinator,
    headers: Mapping[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Serve ``POST /api/v1/connect/snaptrade/session-status`` with zero PII/secrets."""
    if not isinstance(payload, Mapping):
        return 400, {"error": "invalid_request", "detail": "Request body must be a JSON object"}

    configured, client_id, consumer_key, dev_key, auth_mode = _resolve_snaptrade_runtime(config)
    if not configured:
        return 503, {"error": "snaptrade_unconfigured", "detail": SNAPTRADE_UNCONFIGURED_DETAIL}

    dev_ok, dev_err = _verify_dev_key_if_required(payload, headers, dev_key)
    if not dev_ok and dev_err is not None:
        return dev_err

    raw_token = payload.get("session_token")
    if not isinstance(raw_token, str) or not raw_token.strip():
        return 422, {"error": "validation_error", "detail": "session_token is required"}

    try:
        is_personal, mode_label, _ = _resolve_snaptrade_mode(
            configured, client_id, auth_mode=auth_mode
        )
        adapter = relay.build_adapter(client_id, consumer_key, auth_mode=auth_mode)
    except SnapTradeAuthenticationError as exc:
        return 500, {"error": "snaptrade_config_error", "detail": str(exc)}
    refusal = _personal_mode_refusal(config, is_personal=is_personal, dev_key=dev_key)
    if refusal is not None:
        return refusal

    sess = relay.get_session_for_use(raw_token.strip())
    if sess is None:
        return 404, {
            "error": "session_not_found",
            "detail": "SnapTrade relay session_token is invalid, expired, or already released.",
        }

    secrets_to_redact = [
        tok for tok in (consumer_key, client_id, sess.user_secret, sess.user_id) if tok
    ]
    expires_iso = sess.expires_at_utc
    try:
        sync_info = adapter.fetch_sync_status(sess.user_id, sess.user_secret)
        if (
            int(sync_info.get("linked_authorizations") or 0) > 0
            or int(sync_info.get("accounts_count") or 0) > 0
        ) and not bool(sync_info.get("ready_to_verify")):
            refreshed_sync = relay.refresh_session_ttl(
                sess.session_token, min_window_seconds=600.0
            )
            if refreshed_sync is not None:
                expires_iso = refreshed_sync.expires_at_utc
    except DisallowedCapabilityError as exc:
        safe_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_to_redact)
        return 422, {"error": "read_only_capability_violation", "detail": safe_msg}
    except (SnapTradeAuthenticationError, SnapTradeServiceError, SnapTradeError) as exc:
        safe_msg = _clean_snaptrade_upstream_detail(exc, extra_secrets=secrets_to_redact)
        return 502, {"error": "snaptrade_upstream_error", "detail": safe_msg}
    finally:
        relay.finish_use(sess.user_id, adapter=adapter)

    return 200, {
        "mode": mode_label,
        "session_active": True,
        "slot_id": sess.slot_id,
        "expires_at_utc": expires_iso,
        **sync_info,
    }


def handle_post_snaptrade_verify(
    payload: Any,
    *,
    config: ApiConfig,
    store: ProofStore,
    relay: SnapTradeRelayCoordinator,
    pipeline_spec: WorkerPipelineSpec = None,
    headers: Mapping[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Serve ``POST /api/v1/connect/snaptrade/verify`` via isolated single-use worker.

    The session's user is marked in use for the whole request, so neither its expiry nor a
    queued upstream delete can end it while its own read is running.
    """
    in_use: list[tuple[str, SnapTradeReadOnlyAdapter | None]] = []
    try:
        return _handle_post_snaptrade_verify(
            payload,
            config=config,
            store=store,
            relay=relay,
            pipeline_spec=pipeline_spec,
            headers=headers,
            in_use=in_use,
        )
    finally:
        for user_id, finish_adapter in in_use:
            relay.finish_use(user_id, adapter=finish_adapter)


def _handle_post_snaptrade_verify(
    payload: Any,
    *,
    config: ApiConfig,
    store: ProofStore,
    relay: SnapTradeRelayCoordinator,
    pipeline_spec: WorkerPipelineSpec,
    headers: Mapping[str, str] | None,
    in_use: list[tuple[str, SnapTradeReadOnlyAdapter | None]],
) -> tuple[int, dict[str, Any]]:
    if not isinstance(payload, Mapping):
        return 400, {"error": "invalid_request", "detail": "Request body must be a JSON object"}

    configured, client_id, consumer_key, dev_key, auth_mode = _resolve_snaptrade_runtime(config)
    if not configured:
        return 503, {"error": "snaptrade_unconfigured", "detail": SNAPTRADE_UNCONFIGURED_DETAIL}

    dev_ok, dev_err = _verify_dev_key_if_required(payload, headers, dev_key)
    if not dev_ok and dev_err is not None:
        return dev_err
    # The host sets the issue time of a signed record; a caller may not.
    clock_refusal = refuse_caller_clock(config, payload, field_name="issued_at_utc")
    if clock_refusal is not None:
        return clock_refusal

    raw_token = payload.get("session_token")
    if not isinstance(raw_token, str) or not raw_token.strip():
        return 422, {"error": "validation_error", "detail": "session_token is required"}

    release_slot_after, rel_err = parse_strict_bool(payload, "release_slot_after", default=True)
    if rel_err is not None:
        return rel_err
    publish_proof, pub_err = parse_strict_bool(payload, "publish_proof", default=False)
    if pub_err is not None:
        return pub_err
    opt_in_leaderboard, opt_err = parse_strict_bool(payload, "opt_in_leaderboard", default=False)
    if opt_err is not None:
        return opt_err

    try:
        is_personal, mode_label, _ = _resolve_snaptrade_mode(
            configured, client_id, auth_mode=auth_mode
        )
        adapter = relay.build_adapter(client_id, consumer_key, auth_mode=auth_mode)
    except SnapTradeAuthenticationError as exc:
        return 500, {"error": "snaptrade_config_error", "detail": str(exc)}
    refusal = _personal_mode_refusal(config, is_personal=is_personal, dev_key=dev_key)
    if refusal is not None:
        return refusal
    relay.cleanup_leftover_upstream_users_once(
        adapter, user_prefix=deployment_user_prefix(config.account_blinding_salt_hex)
    )
    relay.reap_expired_upstream_users(adapter)

    sess = relay.get_session_for_use(raw_token.strip())
    if sess is None:
        return 404, {
            "error": "session_not_found",
            "detail": "SnapTrade relay session_token is invalid, expired, or already released.",
        }
    in_use.append((sess.user_id, adapter))

    start_date = (
        str(payload["start_date"]).strip() if payload.get("start_date") is not None else None
    )
    end_date = str(payload["end_date"]).strip() if payload.get("end_date") is not None else None
    for date_label, date_val in (("start_date", start_date), ("end_date", end_date)):
        if date_val:
            try:
                datetime.strptime(date_val[:10], "%Y-%m-%d")
            except ValueError:
                return 422, {
                    "error": "validation_error",
                    "detail": f"{date_label} must start with YYYY-MM-DD",
                }
    norm_start = start_date[:10] if start_date else None
    norm_end = end_date[:10] if end_date else None
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

    secrets_to_redact = [
        tok for tok in (consumer_key, client_id, sess.user_secret, sess.user_id) if tok
    ]

    def _final_refusal(status: int, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """A refusal a retry cannot fix frees the seat and ends the session."""
        detail = str(body.get("detail") or "")
        if any(marker in detail for marker in _RETRYABLE_REFUSAL_MARKERS):
            return status, body
        relay.end_user(adapter, sess.user_id, is_personal=is_personal, held_by_caller=True)
        return status, {**body, "session_ended": True}

    def _worker_limit_refusal(exc: Exception) -> tuple[int, dict[str, Any]]:
        """A busy host or a timeout keeps the seat for a retry; an oversized input ends it."""
        status, body = worker_limit_response(exc)
        body["detail"] = redact_sensitive_text(str(body["detail"]), extra_secrets=secrets_to_redact)
        if isinstance(exc, WorkerInputTooLargeError):
            return _final_refusal(status, body)
        return status, body

    result_meta: dict[str, Any] = {}

    execute_fetch_in_worker = pipeline_spec is None and (
        relay.http_transport is None
        or (isinstance(relay.http_transport, str) and ":" in relay.http_transport)
    )

    if execute_fetch_in_worker:
        fetch_kwargs: dict[str, Any] = {}
        if norm_start is not None:
            fetch_kwargs["start_date"] = norm_start
        if norm_end is not None:
            fetch_kwargs["end_date"] = norm_end
        if selected_account_ids is not None:
            fetch_kwargs["selected_account_ids"] = list(selected_account_ids)

        worker_payload: dict[str, Any] = {
            "broker_id": "snaptrade",
            "provider_approval_state": ProviderApprovalState.AGGREGATOR_RELAYED.value,
            "environment_tier": EnvironmentTier.LIVE_PRODUCTION.value,
            "connector_kwargs": {
                "client_id": client_id,
                "consumer_key": consumer_key,
                "auth_mode": auth_mode,
                "user_id": sess.user_id,
                "user_secret": sess.user_secret,
                "auto_register_slot": False,
            },
            "connector_fetch_kwargs": fetch_kwargs,
        }
        if disclose_leaf_names is not None:
            worker_payload["disclose_leaf_names"] = list(disclose_leaf_names)
        if payload.get("issued_at_utc") is not None:
            worker_payload["issued_at_utc"] = str(payload["issued_at_utc"])

        try:
            bundle, receipt, stripped_trades = run_isolated_one_shot_verification(
                worker_payload,
                config=config,
                pipeline_spec=None,
                retention_mode="no_persistent_storage",
                persistent_rows_written=0,
                _snaptrade_http_transport=relay.http_transport,
                result_meta=result_meta,
            )
        except GovernanceBlockedError as exc:
            # Includes paper or sandbox accounts.
            safe_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_to_redact)
            return _final_refusal(exc.http_status, {"error": exc.error_code, "detail": safe_msg})
        except ReadOnlyCapabilityViolationError as exc:
            safe_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_to_redact)
            return _final_refusal(422, {"error": "read_only_capability_violation", "detail": safe_msg})
        except WORKER_LIMIT_ERRORS as exc:
            return _worker_limit_refusal(exc)
        except WorkerValidationError as exc:
            safe_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_to_redact)
            return _final_refusal(422, {"error": "validation_error", "detail": safe_msg})
        except WorkerBrokerUpstreamError as exc:
            safe_msg = _clean_snaptrade_upstream_detail(exc, extra_secrets=secrets_to_redact)
            return 502, {"error": "snaptrade_upstream_error", "detail": safe_msg}
        except WorkerIsolationError as exc:
            safe_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_to_redact)
            return 500, {"error": "worker_isolation_error", "detail": safe_msg}
    else:
        try:
            live_ledger = adapter.fetch_live_ledger(
                sess.user_id,
                sess.user_secret,
                blinding_salt_hex=config.account_blinding_salt_hex,
                start_date=norm_start,
                end_date=norm_end,
                selected_account_ids=selected_account_ids,
                require_live=True,
            )
        except PaperOrSandboxAccountRejectedError as exc:
            safe_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_to_redact)
            return _final_refusal(422, {"error": "paper_or_sandbox_rejected", "detail": safe_msg})
        except (DisallowedCapabilityError, ReadOnlyCapabilityViolationError) as exc:
            safe_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_to_redact)
            return _final_refusal(422, {"error": "read_only_capability_violation", "detail": safe_msg})
        except SnapTradeError as exc:
            safe_msg = _clean_snaptrade_upstream_detail(exc, extra_secrets=secrets_to_redact)
            return 502, {"error": "snaptrade_upstream_error", "detail": safe_msg}
        except SnapTradeNoLinkedAccountError as exc:
            # The visitor has not finished linking an account: keep the seat for a retry.
            safe_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_to_redact)
            return 422, {"error": "validation_error", "detail": safe_msg}
        except ValueError as exc:
            safe_msg = redact_sensitive_text(str(exc), extra_secrets=secrets_to_redact)
            return _final_refusal(422, {"error": "validation_error", "detail": safe_msg})

        worker_payload = {
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
                result_meta=result_meta,
            )
        except GovernanceBlockedError as exc:
            # Includes paper or sandbox accounts.
            return _final_refusal(exc.http_status, {"error": exc.error_code, "detail": str(exc)})
        except ReadOnlyCapabilityViolationError as exc:
            return _final_refusal(422, {"error": "read_only_capability_violation", "detail": str(exc)})
        except WORKER_LIMIT_ERRORS as exc:
            return _worker_limit_refusal(exc)
        except WorkerValidationError as exc:
            return _final_refusal(422, {"error": "validation_error", "detail": str(exc)})
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
            return _final_refusal(exc.http_status, {"error": exc.error_code, "detail": str(exc)})
        except ProofBundleInvalidError as exc:
            return _final_refusal(422, {"error": "invalid_proof_bundle", "errors": exc.errors})
        except GovernanceBlockedError as exc:
            # A record this host may not publish is refused with its own status and code.
            return _final_refusal(exc.http_status, {"error": exc.error_code, "detail": str(exc)})
    else:
        verification = store.verify_bundle_against_live_state(bundle)

    receipt.persistent_rows_written = rows_written

    slot_released = False
    if release_slot_after:
        deleted_now = relay.end_user(
            adapter, sess.user_id, is_personal=is_personal, held_by_caller=True
        )
        slot_released = True if is_personal else deleted_now
        if is_personal:
            token_disposal = "personal_session_purged_from_memory"
        else:
            token_disposal = (
                "deleted_at_snaptrade_and_purged_from_memory"
                if deleted_now
                else "queued_for_upstream_delete_and_purged_from_memory"
            )
    else:
        token_disposal = "ephemeral_in_memory_30m_ttl_slot_retained"

    slot_status = relay.slot_status_dict(include_slots=False, is_personal=is_personal)
    bundle_dict = bundle.to_dict()
    withheld = bool(result_meta.get("performance_withheld", False))
    withheld_fields: dict[str, Any] = {"performance_withheld": withheld}
    if withheld:
        withheld_fields["withheld_reasons"] = list(result_meta.get("withheld_reasons") or [])

    return 200, {
        **withheld_fields,
        "mode": mode_label,
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

    configured, client_id, consumer_key, dev_key, auth_mode = _resolve_snaptrade_runtime(config)
    if not configured:
        return 503, {"error": "snaptrade_unconfigured", "detail": SNAPTRADE_UNCONFIGURED_DETAIL}

    dev_ok, dev_err = _verify_dev_key_if_required(payload, headers, dev_key)
    if not dev_ok and dev_err is not None:
        return dev_err

    try:
        is_personal, mode_label, _ = _resolve_snaptrade_mode(
            configured, client_id, auth_mode=auth_mode
        )
        adapter = relay.build_adapter(client_id, consumer_key, auth_mode=auth_mode)
    except SnapTradeAuthenticationError as exc:
        return 500, {"error": "snaptrade_config_error", "detail": str(exc)}
    relay.cleanup_leftover_upstream_users_once(
        adapter, user_prefix=deployment_user_prefix(config.account_blinding_salt_hex)
    )
    relay.reap_expired_upstream_users(adapter)

    raw_token = payload.get("session_token")
    if raw_token is not None and (not isinstance(raw_token, str) or not raw_token.strip()):
        return 422, {"error": "validation_error", "detail": "session_token must be a non-empty string"}

    release_all, rel_all_err = parse_strict_bool(payload, "release_all", default=False)
    if rel_all_err is not None:
        return rel_all_err
    raw_slot_id = payload.get("slot_id")
    slot_id: int | None = None
    if raw_slot_id is not None:
        if isinstance(raw_slot_id, bool):
            return 422, {"error": "validation_error", "detail": "slot_id must be an integer"}
        if isinstance(raw_slot_id, int):
            slot_id = int(raw_slot_id)
        elif isinstance(raw_slot_id, str) and raw_slot_id.strip().isdigit():
            slot_id = int(raw_slot_id.strip())
        else:
            return 422, {"error": "validation_error", "detail": "slot_id must be an integer"}

    raw_slot_label = payload.get("slot_label")
    if raw_slot_label is not None and not isinstance(raw_slot_label, str):
        return 422, {"error": "validation_error", "detail": "slot_label must be a string"}
    slot_label = raw_slot_label.strip() if isinstance(raw_slot_label, str) else None

    targets_slots = release_all or slot_id is not None or bool(slot_label)
    if targets_slots and not _caller_presented_dev_key(payload, headers, dev_key):
        # Releasing by slot or releasing everything is an operator action; everyone else may
        # release only the session they created, by presenting its session_token.
        return 403, {
            "error": "session_token_required",
            "detail": (
                "Release your own slot with its session_token. Releasing by slot_id, slot_label "
                "or release_all requires the configured operator dev key."
            ),
        }

    if isinstance(raw_token, str) and raw_token.strip():
        own_sess = relay.get_session(raw_token.strip())
        if own_sess is None:
            return 404, {
                "error": "session_not_found",
                "detail": "SnapTrade relay session_token is invalid, expired, or already released.",
            }
        targets = [(own_sess.slot_id, own_sess.user_id)]
    elif not targets_slots:
        return 422, {
            "error": "validation_error",
            "detail": "Provide the session_token of the session to release",
        }
    else:
        targets = relay.resolve_users_for_release(
            slot_id=slot_id,
            slot_label=slot_label,
            release_all=release_all,
            is_personal=is_personal,
        )
    if not targets and not release_all:
        return 404, {
            "error": "slot_not_found",
            "detail": "No active SnapTrade slot matched the requested slot_id or slot_label.",
            "slot_status": relay.slot_status_dict(include_slots=True, is_personal=is_personal),
        }

    released_ids: list[int] = []
    upstream_deleted_all = not is_personal

    for sid, uid in targets:
        if not relay.end_user(adapter, uid, is_personal=is_personal):
            upstream_deleted_all = False
        released_ids.append(sid)

    updated_status = relay.slot_status_dict(include_slots=True, is_personal=is_personal)
    return 200, {
        "mode": mode_label,
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
    "SNAPTRADE_RELAY_USER_PREFIX",
    "SNAPTRADE_SESSION_TTL_SECONDS",
    "SNAPTRADE_UNCONFIGURED_DETAIL",
    "SnapTradeRelayCoordinator",
    "resolve_snaptrade_site_origin",
    "handle_get_snaptrade_status",
    "handle_post_snaptrade_portal",
    "handle_post_snaptrade_release",
    "handle_post_snaptrade_session_status",
    "handle_post_snaptrade_verify",
    "validate_snaptrade_redirect_url",
]
