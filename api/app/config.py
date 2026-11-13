"""Runtime configuration and governance defaults for the N170 Verify v3 API."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
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
    "robinhood_csv": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    "coinbase": ProviderApprovalState.USER_KEY_SELF_ATTESTED,
    "binance": ProviderApprovalState.USER_KEY_SELF_ATTESTED,
    "kraken": ProviderApprovalState.USER_KEY_SELF_ATTESTED,
    "bybit": ProviderApprovalState.USER_KEY_SELF_ATTESTED,
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

    worker_timeout_seconds: float = 30.0
    delayed_trade_guard_days: int = 7

    def __post_init__(self) -> None:
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

    @classmethod
    def from_env(cls) -> ApiConfig:
        """Construct ``ApiConfig`` from environment variables or external secret file."""
        seed_hex = os.environ.get("N170_VERIFY_SIGNING_SEED_HEX", "").strip()
        if not seed_hex:
            seed_file = os.environ.get("N170_VERIFY_SIGNING_SEED_FILE", "").strip()
            if seed_file and os.path.isfile(seed_file):
                with open(seed_file, encoding="utf-8") as fh:
                    seed_hex = fh.read().strip()
        if seed_hex:
            norm_seed = validate_hex_digest(
                seed_hex, field_name="N170_VERIFY_SIGNING_SEED_HEX", num_bytes=32
            )
            keypair = generate_ed25519_keypair(bytes.fromhex(norm_seed))
        else:
            keypair = generate_ed25519_keypair()

        kek_hex = os.environ.get("N170_VERIFY_VAULT_KEK_HEX", "").strip() or secrets.token_hex(32)
        salt_hex = (
            os.environ.get("N170_VERIFY_ACCOUNT_SALT_HEX", "").strip() or secrets.token_hex(32)
        )
        hosted_raw = os.environ.get("N170_VERIFY_HOSTED_MODE", "true").strip().lower()
        hosted = hosted_raw in {"1", "true", "yes", "on"}
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
        )


__all__ = [
    "ApiConfig",
    "DEFAULT_CONNECTOR_APPROVAL_STATES",
    "default_pinned_notaries",
    "utc_now_iso",
]
