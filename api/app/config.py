"""Runtime configuration and governance defaults for the N170 Verify v3 API."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import math
import os
import secrets

from n170_verify.contracts import (
    ProviderApprovalState,
    validate_hex_digest,
)
from n170_verify.crypto import (
    Ed25519KeyPair,
    L2BatchAnchor,
    NotaryNodeInfo,
    PublisherKeyRecord,
    generate_ed25519_keypair,
)


# Lifetime of an unfinished SnapTrade relay session (and the slot it holds).
SNAPTRADE_SESSION_TTL_ENV = "N170_SNAPTRADE_SESSION_TTL_SECONDS"
SNAPTRADE_SESSION_TTL_DEFAULT_SECONDS = 1800.0
SNAPTRADE_SESSION_TTL_MIN_SECONDS = 60.0
SNAPTRADE_SESSION_TTL_MAX_SECONDS = 1800.0


def _check_snaptrade_session_ttl(value: object, *, source: str) -> float:
    """Return a valid relay session lifetime in seconds, or raise ``ValueError`` naming ``source``."""
    if isinstance(value, bool):
        raise ValueError(f"{source} must be a number of seconds, not a boolean")
    try:
        seconds = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise ValueError(f"{source} must be a number of seconds, got {value!r}") from None
    if not math.isfinite(seconds) or not (
        SNAPTRADE_SESSION_TTL_MIN_SECONDS <= seconds <= SNAPTRADE_SESSION_TTL_MAX_SECONDS
    ):
        raise ValueError(
            f"{source} must be between {SNAPTRADE_SESSION_TTL_MIN_SECONDS:g} and "
            f"{SNAPTRADE_SESSION_TTL_MAX_SECONDS:g} seconds, got {value!r}"
        )
    return seconds


SITE_ORIGIN_ENV = "N170_VERIFY_SITE_ORIGIN"
HOSTED_MODE_ENV = "N170_VERIFY_HOSTED_MODE"
# SnapTrade auth-mode values that select the build (commercial) key path.
_SNAPTRADE_BUILD_MODES = frozenset({"commercial", "build", "developer_5_slot"})


def check_site_origin(value: str, *, source: str = SITE_ORIGIN_ENV) -> str:
    """Return a bare ``http(s)://host[:port]`` origin ('' when empty), or raise ``ValueError``."""
    from urllib.parse import urlsplit

    raw = (value or "").strip()
    if not raw:
        return ""
    trimmed = raw[:-1] if raw.endswith("/") else raw
    try:
        parts = urlsplit(trimmed)
        port = parts.port
    except ValueError:
        raise ValueError(f"{source} must be a bare http(s) origin, got {raw!r}") from None
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.path
        or parts.query
        or parts.fragment
        or "?" in trimmed
        or "#" in trimmed
        or parts.username is not None
        or parts.password is not None
    ):
        raise ValueError(
            f"{source} must be a bare http(s) origin such as https://verify.example.org, got {raw!r}"
        )
    host = parts.hostname
    return f"{parts.scheme}://{host}" + (f":{port}" if port is not None else "")


def _parse_hosted_mode(raw: str | None) -> bool:
    """Unset means hosted; otherwise only 'true' or 'false' (trimmed, any case) is accepted."""
    if raw is None:
        return True
    norm = raw.strip().lower()
    if norm == "true":
        return True
    if norm == "false":
        return False
    raise ValueError(f"{HOSTED_MODE_ENV} must be 'true' or 'false', got {raw!r}")


def utc_now_iso() -> str:
    """Return current UTC timestamp formatted as ISO-8601 with trailing Z."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_pinned_notaries() -> list[NotaryNodeInfo]:
    """Return an empty notary list by default; trusted notary public keys must be configured explicitly."""
    return []


DEFAULT_CONNECTOR_APPROVAL_STATES: dict[str, ProviderApprovalState] = {
    "ibkr_flex": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "ibkr_flex_offline": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "ibkr_flex_web": ProviderApprovalState.USER_KEY_SELF_ATTESTED,
    "ibkr_oauth": ProviderApprovalState.PENDING_PROVIDER_APPROVAL,
    "ibkr": ProviderApprovalState.USER_KEY_SELF_ATTESTED,
    "schwab": ProviderApprovalState.APPROVED_LIVE,
    "schwab_csv": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "alpaca": ProviderApprovalState.APPROVED_LIVE,
    "tradier": ProviderApprovalState.USER_KEY_SELF_ATTESTED,
    "trading212": ProviderApprovalState.USER_KEY_SELF_ATTESTED,
    "degiro": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "degiro_csv": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "robinhood": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "robinhood_csv": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "mt4": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "mt4_statement": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "mt5": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "mt5_statement": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "tradovate": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "tradovate_csv": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "tradersync": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "tradersync_journal": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "tradezella": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "tradezella_journal": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "journal_migration": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "auto_detect": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "coinbase": ProviderApprovalState.USER_KEY_SELF_ATTESTED,
    "binance": ProviderApprovalState.USER_KEY_SELF_ATTESTED,
    "kraken": ProviderApprovalState.USER_KEY_SELF_ATTESTED,
    "bybit": ProviderApprovalState.USER_KEY_SELF_ATTESTED,
    "ctrader": ProviderApprovalState.USER_KEY_SELF_ATTESTED,
    "ctrader_oauth": ProviderApprovalState.USER_KEY_SELF_ATTESTED,
    "snaptrade": ProviderApprovalState.AGGREGATOR_RELAYED,
    "snaptrade_relay": ProviderApprovalState.AGGREGATOR_RELAYED,
    "snaptrade_poc": ProviderApprovalState.AGGREGATOR_RELAYED,
    "hyperliquid": ProviderApprovalState.PUBLIC_API_PERMISSIONLESS,
    "fidelity_pending": ProviderApprovalState.PENDING_PROVIDER_APPROVAL,
    "robinhood_unapproved": ProviderApprovalState.PENDING_PROVIDER_APPROVAL,
}


@dataclass(slots=True)
class ApiConfig:
    """Typed configuration for N170 Verify API, key registry, worker isolation, and sync vault."""

    publisher_keypair: Ed25519KeyPair = field(default_factory=generate_ed25519_keypair)
    publisher_kid: str = ""
    publisher_issuer_org: str = "N170"
    publisher_key_not_before_utc: str = "2025-01-01T00:00:00Z"
    additional_registry_keys: list[PublisherKeyRecord] = field(default_factory=list)
    trusted_notaries: list[NotaryNodeInfo] = field(default_factory=default_pinned_notaries)
    pinned_broker_keys: dict[str, dict[str, str]] = field(default_factory=dict)
    checkpoint_origin: str = "verify.example.org/continuity-log/v3"
    checkpoint_witness_signers: list[tuple[str, str, str, str]] = field(default_factory=list)
    l2_anchor: L2BatchAnchor | None = None

    hosted_multi_user_mode: bool = True
    allow_hosted_signing: bool = False
    allow_client_supplied_series_for_tests: bool = False
    # The host sets the verification clock itself. Only test configurations may let a
    # request carry ``now_utc`` (or an issue time on the statement upload). This is
    # deliberately never read from the environment.
    allow_caller_clock_for_tests: bool = False
    connector_approval_states: dict[str, ProviderApprovalState] = field(
        default_factory=lambda: dict(DEFAULT_CONNECTOR_APPROVAL_STATES)
    )

    db_path: str = ":memory:"
    sync_db_path: str = ":memory:"
    vault_master_kek_hex: str = field(default_factory=lambda: secrets.token_hex(32))
    sync_api_token: str = ""
    sync_backup_retention_hours: int = 0
    account_blinding_salt_hex: str = field(default_factory=lambda: secrets.token_hex(32))
    eodhd_api_key: str = ""
    snaptrade_client_id: str = ""
    snaptrade_consumer_key: str = ""
    snaptrade_dev_key: str = ""
    snaptrade_auth_mode: str = "auto"
    snaptrade_session_ttl_seconds: float = SNAPTRADE_SESSION_TTL_DEFAULT_SECONDS
    # Public origin of the site (for example https://verify.example.org); '' when unset.
    site_origin: str = ""

    worker_timeout_seconds: float = 30.0
    delayed_trade_guard_days: int = 7

    def __post_init__(self) -> None:
        self.site_origin = check_site_origin(self.site_origin, source="ApiConfig.site_origin")
        if not self.publisher_kid.strip():
            self.publisher_kid = f"n170-pub-{self.publisher_keypair.key_id}"
        self.vault_master_kek_hex = validate_hex_digest(
            self.vault_master_kek_hex,
            field_name="ApiConfig.vault_master_kek_hex",
            num_bytes=32,
        )
        self.account_blinding_salt_hex = validate_hex_digest(
            self.account_blinding_salt_hex,
            field_name="ApiConfig.account_blinding_salt_hex",
            num_bytes=32,
        )
        if self.sync_backup_retention_hours < 0:
            raise ValueError("sync_backup_retention_hours must be >= 0")
        if self.worker_timeout_seconds <= 0.0:
            raise ValueError("worker_timeout_seconds must be > 0")
        if self.delayed_trade_guard_days < 1:
            raise ValueError("delayed_trade_guard_days must be >= 1")
        self.snaptrade_session_ttl_seconds = _check_snaptrade_session_ttl(
            self.snaptrade_session_ttl_seconds,
            source="ApiConfig.snaptrade_session_ttl_seconds",
        )

    @classmethod
    def from_env(cls) -> ApiConfig:
        """Construct ``ApiConfig`` from environment variables or external secret file."""
        hosted = _parse_hosted_mode(os.environ.get(HOSTED_MODE_ENV))
        seed_hex = os.environ.get("N170_VERIFY_SIGNING_SEED_HEX", "").strip()
        if not seed_hex:
            seed_file = os.environ.get("N170_VERIFY_SIGNING_SEED_FILE", "").strip()
            if seed_file:
                try:
                    st_info = os.stat(seed_file)
                except FileNotFoundError:
                    st_info = None
                except PermissionError as exc:
                    raise PermissionError(
                        f"Cannot access N170_VERIFY_SIGNING_SEED_FILE {seed_file!r} (UID={os.getuid()}): "
                        "fix the key directory and file ownership so this user can read it"
                    ) from exc
                if st_info is not None:
                    try:
                        with open(seed_file, encoding="utf-8") as fh:
                            seed_hex = fh.read().strip()
                    except PermissionError as exc:
                        raise PermissionError(
                            f"Cannot read N170_VERIFY_SIGNING_SEED_FILE {seed_file!r} (UID={os.getuid()}): "
                            "fix the file ownership so this user can read it"
                        ) from exc
                if not seed_hex:
                    # A configured seed file that yields no seed stops start-up: the
                    # host never signs with a key nobody can find again.
                    raise RuntimeError(
                        f"N170_VERIFY_SIGNING_SEED_FILE {seed_file!r} is set but no signing seed "
                        "was loaded from it (file missing or empty)"
                    )
        if seed_hex:
            norm_seed = validate_hex_digest(
                seed_hex, field_name="N170_VERIFY_SIGNING_SEED_HEX", num_bytes=32
            )
            keypair = generate_ed25519_keypair(bytes.fromhex(norm_seed))
        elif hosted:
            # The hosted signer must be the same key after every restart.
            raise RuntimeError(
                "Hosted mode needs a signing seed: set N170_VERIFY_SIGNING_SEED_FILE "
                "(or N170_VERIFY_SIGNING_SEED_HEX)"
            )
        else:
            keypair = generate_ed25519_keypair()

        kek_hex = os.environ.get("N170_VERIFY_VAULT_KEK_HEX", "").strip()
        if not kek_hex:
            if hosted:
                # Vault contents must stay readable after a restart.
                raise RuntimeError("N170_VERIFY_VAULT_KEK_HEX is required in hosted mode")
            kek_hex = secrets.token_hex(32)
        salt_hex = os.environ.get("N170_VERIFY_ACCOUNT_SALT_HEX", "").strip()
        if not salt_hex:
            if hosted:
                # Hosted mode needs a stable account salt so the same account keeps
                # the same blinded tag across restarts.
                raise RuntimeError(
                    "N170_VERIFY_ACCOUNT_SALT_HEX is required in hosted mode "
                    "(N170_VERIFY_HOSTED_MODE is true or unset)"
                )
            salt_hex = secrets.token_hex(32)
        hosted_signing_raw = (
            os.environ.get("N170_VERIFY_ALLOW_HOSTED_SIGNING", "false").strip().lower()
        )
        allow_hosted_signing = hosted_signing_raw in {"1", "true", "yes", "on"}
        eodhd_key = os.environ.get("EODHD_API_KEY", "").strip()
        sync_token = os.environ.get("N170_VERIFY_SYNC_API_TOKEN", "").strip()

        raw_notaries = os.environ.get("N170_VERIFY_TRUSTED_NOTARIES_JSON", "").strip()
        if raw_notaries:
            parsed_notaries = json.loads(raw_notaries)
            if not isinstance(parsed_notaries, list):
                raise ValueError("N170_VERIFY_TRUSTED_NOTARIES_JSON must decode to a JSON array")
            trusted_notaries = [NotaryNodeInfo.from_dict(item) for item in parsed_notaries]
        else:
            trusted_notaries = []

        checkpoint_origin = (
            os.environ.get("N170_VERIFY_CHECKPOINT_ORIGIN", "").strip()
            or "verify.example.org/continuity-log/v3"
        )
        # Unset or empty keeps the default; any other value must be valid or start-up stops.
        raw_ttl = os.environ.get(SNAPTRADE_SESSION_TTL_ENV, "").strip()
        snaptrade_session_ttl = (
            _check_snaptrade_session_ttl(raw_ttl, source=SNAPTRADE_SESSION_TTL_ENV)
            if raw_ttl
            else SNAPTRADE_SESSION_TTL_DEFAULT_SECONDS
        )

        site_origin = check_site_origin(os.environ.get(SITE_ORIGIN_ENV, ""))
        snaptrade_client_id = os.environ.get("SNAPTRADE_CLIENT_ID", "").strip()
        snaptrade_auth_mode = os.environ.get("SNAPTRADE_AUTH_MODE", "auto").strip().lower() or "auto"
        if (
            snaptrade_client_id.upper().startswith("PERS-")
            and snaptrade_auth_mode in _SNAPTRADE_BUILD_MODES
        ):
            # A personal key belongs to one owner; it is never served as a build key.
            raise RuntimeError(
                "SNAPTRADE_CLIENT_ID is a SnapTrade personal key, but SNAPTRADE_AUTH_MODE "
                f"{snaptrade_auth_mode!r} selects the build key path; use 'auto' or 'personal'"
            )

        return cls(
            publisher_keypair=keypair,
            publisher_kid=os.environ.get("N170_VERIFY_PUBLISHER_KID", "").strip(),
            trusted_notaries=trusted_notaries,
            checkpoint_origin=checkpoint_origin,
            hosted_multi_user_mode=hosted,
            allow_hosted_signing=allow_hosted_signing,
            db_path=os.environ.get("N170_VERIFY_DB_PATH", ":memory:").strip() or ":memory:",
            sync_db_path=(
                os.environ.get("N170_VERIFY_SYNC_DB_PATH", ":memory:").strip() or ":memory:"
            ),
            vault_master_kek_hex=kek_hex,
            sync_api_token=sync_token,
            sync_backup_retention_hours=int(
                os.environ.get("N170_VERIFY_SYNC_BACKUP_RETENTION_HOURS", "0")
            ),
            account_blinding_salt_hex=salt_hex,
            eodhd_api_key=eodhd_key,
            snaptrade_client_id=snaptrade_client_id,
            snaptrade_consumer_key=os.environ.get("SNAPTRADE_CONSUMER_KEY", "").strip(),
            snaptrade_dev_key=os.environ.get("N170_SNAPTRADE_DEV_KEY", "").strip(),
            snaptrade_auth_mode=snaptrade_auth_mode,
            snaptrade_session_ttl_seconds=snaptrade_session_ttl,
            site_origin=site_origin,
        )


__all__ = [
    "ApiConfig",
    "DEFAULT_CONNECTOR_APPROVAL_STATES",
    "check_site_origin",
    "default_pinned_notaries",
    "utc_now_iso",
]
