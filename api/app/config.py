"""Runtime configuration and governance defaults for the N170 Verify v3 API."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
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
    """Return deterministic default org/ASN-disjoint notary descriptors when none are configured."""
    notary_a = generate_ed25519_keypair(bytes.fromhex("71" * 32))
    notary_b = generate_ed25519_keypair(bytes.fromhex("72" * 32))
    return [
        NotaryNodeInfo(
            notary_id="pse-tlsn-notary-1",
            operator_org="Privacy & Scaling Explorations",
            asn="AS13335",
            public_key_hex=notary_a.public_key_hex,
            is_debug_build=False,
            attestation_type="production",
        ),
        NotaryNodeInfo(
            notary_id="swiss-independent-notary-2",
            operator_org="Swiss FinTech Witness Association",
            asn="AS3303",
            public_key_hex=notary_b.public_key_hex,
            is_debug_build=False,
            attestation_type="production",
        ),
    ]


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
    checkpoint_origin: str = "verify.n170.ai/continuity-log/v3"
    checkpoint_witness_signers: list[tuple[str, str, str, str]] = field(default_factory=list)
    l2_anchor: L2BatchAnchor | None = None

    hosted_multi_user_mode: bool = True
    connector_approval_states: dict[str, ProviderApprovalState] = field(
        default_factory=lambda: dict(DEFAULT_CONNECTOR_APPROVAL_STATES)
    )

    db_path: str = ":memory:"
    sync_db_path: str = ":memory:"
    vault_master_kek_hex: str = field(default_factory=lambda: secrets.token_hex(32))
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
        eodhd_key = os.environ.get("EODHD_API_KEY", "").strip()

        return cls(
            publisher_keypair=keypair,
            publisher_kid=os.environ.get("N170_VERIFY_PUBLISHER_KID", "").strip(),
            hosted_multi_user_mode=hosted,
            db_path=os.environ.get("N170_VERIFY_DB_PATH", ":memory:").strip() or ":memory:",
            sync_db_path=(
                os.environ.get("N170_VERIFY_SYNC_DB_PATH", ":memory:").strip() or ":memory:"
            ),
            vault_master_kek_hex=kek_hex,
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
