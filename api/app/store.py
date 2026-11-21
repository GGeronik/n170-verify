"""SQLite proof store, append-only continuity transparency log, and C2SP registry state."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
import sqlite3
import threading
from typing import Any

from app.config import ApiConfig, utc_now_iso
from n170_verify.contracts import (
    BundleVerificationResult,
    ChainContinuityMode,
    EnvironmentTier,
    HolderClaimStatus,
    ProviderApprovalState,
    SignerTrustStatus,
    VerifyProofBundle,
    parse_utc_timestamp,
    validate_hex_digest,
    verify_proof_bundle,
)
from n170_verify.crypto import (
    C2SPCheckpoint,
    ChainInvariantViolationCode,
    ChainVerificationResult,
    ContinuityLogLeaf,
    PublisherKeyRecord,
    PublisherKeyRegistryDocument,
    compute_merkle_root_from_leaf_hashes,
    create_signed_c2sp_checkpoint,
    evaluate_signer_trust,
    jcs_canonicalize_str,
    jcs_sha256_hex,
    verify_prospective_chain,
)


EMPTY_TLOG_ROOT_HEX = hashlib.sha256(b"n170.verify.tlog.empty.v3").hexdigest()


class GovernanceBlockedError(PermissionError):
    """Base error for provider approval or environment governance blocks."""

    error_code: str = "governance_blocked"
    http_status: int = 403


class ProviderApprovalPendingError(GovernanceBlockedError):
    """Raised when a connector is pending provider approval in hosted multi-user mode."""

    error_code = "provider_approval_pending"
    http_status = 403


class SigningOracleDisabledError(GovernanceBlockedError):
    """Raised when hosted mode refuses client-supplied synthetic leaf/series signing payloads."""

    error_code = "signing_oracle_disabled"
    http_status = 403


class PaperOrSandboxRejectedError(GovernanceBlockedError):
    """Raised when a paper or sandbox brokerage account is submitted for public proof."""

    error_code = "paper_or_sandbox_rejected"
    http_status = 422


class PublisherKeyNotInRegistryError(GovernanceBlockedError):
    """Raised when the hosted store is asked to publish a record whose signing key is not in its registry."""

    error_code = "publisher_key_not_in_registry"
    http_status = 403


# Keys found in the registry. A revoked key is in the registry too; its records
# are refused by verification as invalid (422), as before.
_REGISTRY_SIGNER_STATUSES = frozenset(
    {
        SignerTrustStatus.OFFICIAL_N170_HOSTED,
        SignerTrustStatus.RETIRED_HISTORICAL_VALID,
        SignerTrustStatus.REVOKED_KEY,
    }
)


class ChainRequiresProvenOwnershipError(GovernanceBlockedError):
    """Raised when hosted mode is asked to chain a record made without proof of account ownership."""

    error_code = "chain_requires_proven_ownership"
    http_status = 403


# PROPOSED policy (owner to confirm): in hosted mode a record made from a public
# address without proof of ownership is not enrolled in or appended to a
# continuity chain, so nobody can start a chain for an account that is not theirs.
CHAIN_REFUSED_APPROVAL_STATES_IN_HOSTED_MODE = frozenset(
    {ProviderApprovalState.PUBLIC_API_PERMISSIONLESS}
)


# PROPOSED policy (owner to confirm): in hosted mode a record made from a public address
# without proof of ownership cannot opt into or overwrite a wallet's row on the public leaderboard.
class LeaderboardRequiresProvenOwnershipError(GovernanceBlockedError):
    """Raised when hosted mode is asked to list a record made without proof of account ownership."""

    error_code = "leaderboard_requires_proven_ownership"
    http_status = 403


class ChainLinkMismatchError(ValueError):
    """Raised when a chain link's own fields disagree with the record that carries it."""

    error_code = "chain_link_mismatch"
    http_status = 422

    def __init__(self, message: str, *, errors: list[str]) -> None:
        super().__init__(message)
        self.errors = list(errors)


# Tolerance for comparing a link's period return with the record's proven return.
CHAIN_LINK_RETURN_ABS_TOL = 1e-9


def check_chain_link_matches_record(bundle: VerifyProofBundle) -> None:
    """Refuse a chain link whose fields are not those of the record that carries it.

    Compared: account tag, period start and end, and issue time against the signed
    header; the period return against the record's disclosed, Merkle-proven
    ``core_metrics`` return; and the link's index values against its own return.
    """
    from app.badges import return_not_computed, verified_leaf_payload

    link = bundle.prospective_chain_link
    if link is None:
        return
    errors: list[str] = []
    if link.blinded_account_tag.lower() != bundle.blinded_account_tag.lower():
        errors.append("chain link blinded_account_tag differs from the record's account tag")
    for name in ("period_start_utc", "period_end_utc", "issued_at_utc"):
        if parse_utc_timestamp(getattr(link, name)) != parse_utc_timestamp(getattr(bundle, name)):
            errors.append(f"chain link {name} differs from the record's {name}")

    core = verified_leaf_payload(bundle, "core_metrics")
    record_twr: float | None = None
    if not isinstance(core, Mapping):
        errors.append("the record does not disclose a proven core_metrics return to tie the link to")
    elif return_not_computed(core):
        errors.append("no return was computed for the record, so it cannot carry a chain link")
    else:
        raw = core.get("twr_decimal")
        if isinstance(raw, (int, float)) and not isinstance(raw, bool) and math.isfinite(raw):
            record_twr = float(raw)
        else:
            errors.append("the record's proven core_metrics carries no finite return")
    link_twr = float(link.period_twr_decimal)
    if record_twr is not None and not math.isclose(
        link_twr, record_twr, rel_tol=0.0, abs_tol=CHAIN_LINK_RETURN_ABS_TOL
    ):
        errors.append("chain link period_twr_decimal differs from the record's proven return")
    begin = float(link.beginning_index_value)
    end = float(link.ending_index_value)
    if not (math.isfinite(begin) and math.isfinite(end) and begin > 0.0) or not math.isclose(
        end / begin - 1.0, link_twr, rel_tol=0.0, abs_tol=1e-6
    ):
        errors.append("chain link index values do not match its period return")
    if errors:
        raise ChainLinkMismatchError(
            "The chain link does not match the record that carries it", errors=errors
        )


def refuse_chain_without_proven_ownership(bundle: VerifyProofBundle, *, hosted: bool) -> None:
    """PROPOSED: hosted mode does not chain a record made without proof of ownership."""
    if hosted and bundle.provider_approval_state in CHAIN_REFUSED_APPROVAL_STATES_IN_HOSTED_MODE:
        raise ChainRequiresProvenOwnershipError(
            "This host does not enrol a record made from a public address without proof of "
            "ownership in a continuity chain"
        )


class ProofNotFoundError(KeyError):
    """Raised when a proof bundle or enrolled chain ID does not exist."""


class ProofConflictError(RuntimeError):
    """Raised when a proof_id already exists with a different canonical proof_hash."""

    http_status: int = 409
    error_code: str = "proof_id_conflict"


class ProofAlreadyPublishedError(ProofConflictError):
    """Raised when a chain enrolment or append carries a record that is already published."""

    error_code = "proof_already_published"


class ProofBundleInvalidError(ValueError):
    """Raised when a submitted VerifyProofBundle fails cryptographic verification."""

    def __init__(self, message: str, *, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.errors = list(errors or [message])


class ChainViolationError(ValueError):
    """Raised when a prospective chain enrollment or append violates chain invariants."""

    http_status: int = 422

    def __init__(self, result: ChainVerificationResult) -> None:
        codes = [c.value for c in result.violation_codes]
        super().__init__(f"Prospective chain invariant violation: {codes}")
        self.chain_result = result


class ChainResetConflictError(ChainViolationError):
    """Raised on parallel chain reset attempts for an already-enrolled blinded_account_tag."""

    http_status = 409


@dataclass(slots=True)
class StoredProofEntry:
    """Stored redacted proof bundle alongside opt-in directory metadata."""

    bundle: VerifyProofBundle
    proof_hash: str
    opt_in_leaderboard: bool
    stored_at_utc: str


class ProfileNotFoundError(KeyError):
    """Raised when a holder profile handle or key does not exist."""


class ProfileOwnershipError(PermissionError):
    """Raised when a handle is already owned by a different Ed25519 holder key."""

    http_status: int = 403
    error_code: str = "handle_owned_by_another_key"


class ProfileSequenceError(RuntimeError):
    """Raised when a signed profile update has a non-monotonic sequence_number."""

    http_status: int = 409
    error_code: str = "stale_profile_sequence"


class ProfileInvalidError(ValueError):
    """Raised when a holder profile claim fails validation or Ed25519 verification."""

    http_status: int = 422
    error_code: str = "invalid_profile_claim"

    def __init__(self, message: str, *, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.errors = list(errors or [message])


@dataclass(slots=True)
class StoredHolderProfile:
    """Cryptographic holder-signed trader profile keyed by Ed25519 public key."""

    holder_public_key_hex: str
    handle: str
    display_name: str
    bio: str
    profile_url: str | None
    strategy_notes: str
    watchlist: list[dict[str, Any]]
    conviction_list: list[dict[str, Any]]
    list_on_leaderboard: bool
    pinned_proof_id: str | None
    sequence_number: int
    signed_claim: dict[str, Any]
    updated_at_utc: str
    created_at_utc: str
    leaderboard_signed_claim: dict[str, Any] | None = None


def enforce_bundle_governance(
    *,
    provider_approval_state: ProviderApprovalState,
    environment_tier: EnvironmentTier,
    hosted_multi_user_mode: bool,
) -> None:
    """Enforce ``ProviderApprovalState`` and ``EnvironmentTier`` gates."""
    if environment_tier == EnvironmentTier.PAPER_OR_SANDBOX_REJECTED:
        raise PaperOrSandboxRejectedError(
            "Paper, demo, and sandbox accounts are rejected from N170 Verify public proofs"
        )
    if (
        hosted_multi_user_mode
        and provider_approval_state == ProviderApprovalState.PENDING_PROVIDER_APPROVAL
    ):
        raise ProviderApprovalPendingError(
            "Connector is pending provider vendor approval and disabled in hosted multi-user mode"
        )


def enforce_bundle_seven_day_trade_guard(
    bundle: VerifyProofBundle,
    *,
    min_delay_days: int = 7,
) -> tuple[VerifyProofBundle, bool]:
    """Ensure no stored ``VerifyProofBundle`` exposes trades closed fewer than ``min_delay_days`` ago.

    Accepts both the canonical ``pipeline.py`` dict envelope
    (``{"embargo_days": ..., "trades": [...], ...}``) and legacy flat lists.
    If a pre-signed bundle discloses ``delayed_closed_trades`` containing any trade with
    ``exit_timestamp_utc > issued_at_utc - min_delay_days`` (or malformed payload/timestamps
    or ``embargo_days < min_delay_days``), the leaf is cryptographically redacted into
    ``undisclosed_leaf_hashes`` (preserving ``merkle_root`` and ``signature_hex``).
    """
    try:
        trades_payload = bundle.get_disclosed_payload("delayed_closed_trades")
    except KeyError:
        return bundle, False

    if isinstance(trades_payload, dict):
        embargo_days = trades_payload.get("embargo_days")
        if embargo_days is not None:
            if (
                isinstance(embargo_days, bool)
                or not isinstance(embargo_days, (int, float))
                or not math.isfinite(float(embargo_days))
                or float(embargo_days) < float(min_delay_days)
            ):
                return bundle.redact_leaves(["delayed_closed_trades"]), True
        raw_trades = trades_payload.get("trades")
        if not isinstance(raw_trades, list):
            return bundle.redact_leaves(["delayed_closed_trades"]), True
        trades_list = raw_trades
    elif isinstance(trades_payload, list):
        trades_list = trades_payload
    else:
        return bundle.redact_leaves(["delayed_closed_trades"]), True

    issued_dt = parse_utc_timestamp(bundle.issued_at_utc, field_name="bundle.issued_at_utc")
    cutoff_dt = issued_dt - timedelta(days=min_delay_days)
    for item in trades_list:
        if not isinstance(item, dict) or "exit_timestamp_utc" not in item:
            return bundle.redact_leaves(["delayed_closed_trades"]), True
        raw_exit_ts = item["exit_timestamp_utc"]
        if not isinstance(raw_exit_ts, str) or not raw_exit_ts.strip():
            return bundle.redact_leaves(["delayed_closed_trades"]), True
        try:
            exit_dt = parse_utc_timestamp(
                raw_exit_ts,
                field_name="delayed_closed_trades.exit_timestamp_utc",
            )
        except (ValueError, TypeError):
            return bundle.redact_leaves(["delayed_closed_trades"]), True
        if exit_dt > cutoff_dt:
            return bundle.redact_leaves(["delayed_closed_trades"]), True

    return bundle, False


def refuse_text_the_scanner_blocks(bundle: VerifyProofBundle) -> None:
    """Refuse, before anything is stored, a record that the outbound scanner would block.

    A stored record must always be readable, so text that looks like an account
    number, a raw statement excerpt or a credential is refused here. The reason
    does not repeat the text.
    """
    from app.privacy_scanner import OutboundPrivacyScanner

    if OutboundPrivacyScanner().scan_payload(bundle.to_dict()):
        raise ProofBundleInvalidError(
            "The record cannot be published",
            errors=[
                "The record contains text that looks like an account number, a raw statement "
                "excerpt or a credential; remove it from the statement or journal and try again"
            ],
        )


def _refuse_invalid_holder_claim(result: BundleVerificationResult) -> None:
    """The store never publishes a holder attestation that does not verify."""
    if result.holder_claim_status == HolderClaimStatus.INVALID:
        raise ProofBundleInvalidError(
            "The holder attestation does not verify for this record and cannot be published",
            errors=[
                "Holder attestation failed verification: publish without it, or attach a "
                "holder claim signed for this record's proof_id, merkle_root and proof_hash"
            ],
        )


class ProofStore:
    """SQLite store for opt-in redacted proofs, prospective chains, and append-only continuity log."""

    def __init__(self, config: ApiConfig) -> None:
        self._config = config
        self._lock = threading.RLock()
        if config.db_path != ":memory:" and not config.db_path.startswith("file:"):
            parent = os.path.dirname(os.path.abspath(config.db_path))
            if parent:
                os.makedirs(parent, exist_ok=True)
        self._conn = sqlite3.connect(
            config.db_path,
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._last_updated_utc = utc_now_iso()
        self._initialize_schema()

    @property
    def config(self) -> ApiConfig:
        return self._config

    def _initialize_schema(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = ON;")
            self._conn.execute("PRAGMA temp_store = MEMORY;")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS proofs (
                    proof_id TEXT PRIMARY KEY,
                    proof_hash TEXT NOT NULL UNIQUE,
                    blinded_account_tag TEXT NOT NULL,
                    broker_id TEXT NOT NULL,
                    chain_id TEXT,
                    sequence_number INTEGER,
                    bundle_json TEXT NOT NULL,
                    opt_in_leaderboard INTEGER NOT NULL DEFAULT 0,
                    stored_at_utc TEXT NOT NULL,
                    holder_public_key_hex TEXT
                )
                """
            )
            # Safe idempotent migration for existing SQLite databases created before holder profiles
            existing_cols = {
                str(r["name"])
                for r in self._conn.execute("PRAGMA table_info(proofs)").fetchall()
            }
            if "holder_public_key_hex" not in existing_cols:
                self._conn.execute("ALTER TABLE proofs ADD COLUMN holder_public_key_hex TEXT")
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_proofs_holder_pubkey ON proofs(holder_public_key_hex)"
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS holder_profiles (
                    holder_public_key_hex TEXT PRIMARY KEY,
                    handle TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    bio TEXT NOT NULL DEFAULT '',
                    profile_url TEXT,
                    strategy_notes TEXT NOT NULL DEFAULT '',
                    watchlist_json TEXT NOT NULL DEFAULT '[]',
                    conviction_list_json TEXT NOT NULL DEFAULT '[]',
                    list_on_leaderboard INTEGER NOT NULL DEFAULT 0,
                    pinned_proof_id TEXT,
                    sequence_number INTEGER NOT NULL DEFAULT 1,
                    signed_claim_json TEXT NOT NULL,
                    leaderboard_signed_claim_json TEXT,
                    updated_at_utc TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                )
                """
            )
            profile_cols = {
                str(r["name"])
                for r in self._conn.execute("PRAGMA table_info(holder_profiles)").fetchall()
            }
            if "leaderboard_signed_claim_json" not in profile_cols:
                self._conn.execute(
                    "ALTER TABLE holder_profiles ADD COLUMN leaderboard_signed_claim_json TEXT"
                )
            self._conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_holder_profiles_handle ON holder_profiles(handle)"
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chains (
                    chain_id TEXT PRIMARY KEY,
                    blinded_account_tag TEXT NOT NULL UNIQUE,
                    enrolled_at_utc TEXT NOT NULL,
                    expected_interval_seconds INTEGER NOT NULL,
                    grace_window_seconds INTEGER NOT NULL,
                    latest_sequence_number INTEGER NOT NULL,
                    latest_proof_hash TEXT NOT NULL,
                    opt_in_leaderboard INTEGER NOT NULL DEFAULT 0,
                    updated_at_utc TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS continuity_log (
                    log_index INTEGER PRIMARY KEY,
                    chain_id TEXT NOT NULL,
                    blinded_account_tag TEXT NOT NULL,
                    sequence_number INTEGER NOT NULL,
                    proof_hash TEXT NOT NULL,
                    logged_at_utc TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_continuity_log_no_update
                BEFORE UPDATE ON continuity_log
                BEGIN
                    SELECT RAISE(ABORT, 'continuity_log is strictly append-only');
                END;
                """
            )
            self._conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_continuity_log_no_delete
                BEFORE DELETE ON continuity_log
                BEGIN
                    SELECT RAISE(ABORT, 'continuity_log is strictly append-only');
                END;
                """
            )
            self._backfill_proof_holder_pubkeys()

    def _backfill_proof_holder_pubkeys(self) -> None:
        """Populate ``proofs.holder_public_key_hex`` for pre-existing proofs carrying a valid holder claim."""
        rows = self._conn.execute(
            "SELECT proof_id, bundle_json FROM proofs WHERE holder_public_key_hex IS NULL"
        ).fetchall()
        for r in rows:
            try:
                bundle = VerifyProofBundle.from_dict(json.loads(str(r["bundle_json"])))
                if bundle.holder_identity is None:
                    continue
                ver = verify_proof_bundle(bundle)
                if ver.holder_claim_status == HolderClaimStatus.SELF_ASSERTED:
                    self._conn.execute(
                        "UPDATE proofs SET holder_public_key_hex = ? WHERE proof_id = ?",
                        (bundle.holder_identity.holder_public_key_hex, str(r["proof_id"])),
                    )
            except Exception:
                continue

    def total_row_counts(self) -> dict[str, int]:
        """Return row counts across all persistence tables for zero-storage verification audits."""
        with self._lock:
            counts: dict[str, int] = {}
            for table in ("proofs", "chains", "continuity_log"):
                row = self._conn.execute(f"SELECT COUNT(*) AS cnt FROM {table}").fetchone()
                counts[table] = int(row["cnt"]) if row is not None else 0
            return counts

    def list_all_continuity_leaves(self) -> list[ContinuityLogLeaf]:
        """Return all append-only ``ContinuityLogLeaf`` entries ordered by ``log_index``."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT
                    log_index,
                    chain_id,
                    blinded_account_tag,
                    sequence_number,
                    proof_hash,
                    logged_at_utc
                FROM continuity_log
                ORDER BY log_index ASC
                """
            ).fetchall()
        return [
            ContinuityLogLeaf(
                log_index=int(r["log_index"]),
                chain_id=str(r["chain_id"]),
                blinded_account_tag=str(r["blinded_account_tag"]),
                sequence_number=int(r["sequence_number"]),
                proof_hash=str(r["proof_hash"]),
                logged_at_utc=str(r["logged_at_utc"]),
            )
            for r in rows
        ]

    def get_continuity_leaves_for_account(self, blinded_account_tag: str) -> list[ContinuityLogLeaf]:
        """Return ordered ``ContinuityLogLeaf`` entries for ``blinded_account_tag``."""
        norm_tag = validate_hex_digest(
            blinded_account_tag, field_name="blinded_account_tag", num_bytes=32
        )
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT
                    log_index,
                    chain_id,
                    blinded_account_tag,
                    sequence_number,
                    proof_hash,
                    logged_at_utc
                FROM continuity_log
                WHERE blinded_account_tag = ?
                ORDER BY log_index ASC
                """,
                (norm_tag,),
            ).fetchall()
        return [
            ContinuityLogLeaf(
                log_index=int(r["log_index"]),
                chain_id=str(r["chain_id"]),
                blinded_account_tag=str(r["blinded_account_tag"]),
                sequence_number=int(r["sequence_number"]),
                proof_hash=str(r["proof_hash"]),
                logged_at_utc=str(r["logged_at_utc"]),
            )
            for r in rows
        ]

    def build_signed_checkpoint(self) -> C2SPCheckpoint:
        """Compute Merkle root over the continuity transparency log and sign a C2SP checkpoint."""
        leaves = self.list_all_continuity_leaves()
        if not leaves:
            size = 0
            root_hex = EMPTY_TLOG_ROOT_HEX
        else:
            size = len(leaves)
            leaf_digests = [jcs_sha256_hex(leaf.to_dict()) for leaf in leaves]
            root_hex = compute_merkle_root_from_leaf_hashes(leaf_digests)

        return create_signed_c2sp_checkpoint(
            origin=self._config.checkpoint_origin,
            size=size,
            root_hash_hex=root_hex,
            publisher_kid=self._config.publisher_kid,
            publisher_private_key_hex=self._config.publisher_keypair.private_key_hex,
            witness_signers=self._config.checkpoint_witness_signers,
        )

    def build_registry_document(self) -> PublisherKeyRegistryDocument:
        """Assemble live ``PublisherKeyRegistryDocument`` with signed C2SP checkpoint."""
        active_record = PublisherKeyRecord(
            publisher_kid=self._config.publisher_kid,
            public_key_hex=self._config.publisher_keypair.public_key_hex,
            status="active",
            not_before_utc=self._config.publisher_key_not_before_utc,
            issuer_org=self._config.publisher_issuer_org,
        )
        keys: list[PublisherKeyRecord] = [active_record]
        seen = {active_record.publisher_kid}
        for extra in self._config.additional_registry_keys:
            if extra.publisher_kid not in seen:
                keys.append(extra)
                seen.add(extra.publisher_kid)

        checkpoint = self.build_signed_checkpoint()
        return PublisherKeyRegistryDocument(
            updated_at_utc=self._last_updated_utc,
            keys=keys,
            notaries=list(self._config.trusted_notaries),
            checkpoint=checkpoint,
            l2_anchor=self._config.l2_anchor,
            pinned_broker_keys=dict(self._config.pinned_broker_keys),
        )

    def require_registry_signer(self, bundle: VerifyProofBundle) -> None:
        """In hosted mode, publish only records signed by a key in this host's registry.

        A self-hosted store (hosted mode off) keeps accepting other signers; their
        records are still marked ``unrecognized_self_hosted_signer`` on verification.
        """
        if not self._config.hosted_multi_user_mode:
            return
        if not bundle.verify_publisher_signature():
            # A record whose signature does not verify is refused by verification
            # itself (422 invalid_proof_bundle) on every publish path, so the reason
            # given stays accurate. It is never stored.
            return
        status = evaluate_signer_trust(bundle, self.build_registry_document())
        if status not in _REGISTRY_SIGNER_STATUSES:
            raise PublisherKeyNotInRegistryError(
                f"This host publishes only records signed by a key in its own registry; "
                f"publisher key {bundle.publisher_kid!r} is {status.value}"
            )

    def get_chain_bundles(self, chain_id: str) -> list[VerifyProofBundle]:
        """Return ordered ``VerifyProofBundle`` sequence for ``chain_id``."""
        with self._lock:
            chain_row = self._conn.execute(
                "SELECT 1 FROM chains WHERE chain_id = ?",
                (chain_id,),
            ).fetchone()
            if chain_row is None:
                raise ProofNotFoundError(f"Chain {chain_id!r} not found")

            rows = self._conn.execute(
                """
                SELECT bundle_json
                FROM proofs
                WHERE chain_id = ?
                ORDER BY sequence_number ASC
                """,
                (chain_id,),
            ).fetchall()
        return [VerifyProofBundle.from_dict(json.loads(str(r["bundle_json"]))) for r in rows]

    def verify_bundle_against_live_state(
        self,
        bundle: VerifyProofBundle,
        *,
        chain_history: list[VerifyProofBundle] | None = None,
        now_utc: str | datetime | None = None,
        registry_doc: PublisherKeyRegistryDocument | None = None,
        continuity_leaves: list[ContinuityLogLeaf] | None = None,
    ) -> BundleVerificationResult:
        """Dynamically verify ``bundle`` against live publisher registry, chain history, and continuity log.

        A caller verifying many records in one request may pass the registry
        document and continuity leaves it built once for that request.
        """
        if registry_doc is None:
            registry_doc = self.build_registry_document()
        all_leaves = (
            continuity_leaves if continuity_leaves is not None else self.list_all_continuity_leaves()
        )

        resolved_history = chain_history
        if resolved_history is None and bundle.prospective_chain_link is not None:
            cid = bundle.prospective_chain_link.chain_id
            try:
                stored_chain = self.get_chain_bundles(cid)
                # Include prefix up to bundle sequence_number
                seq = bundle.prospective_chain_link.sequence_number
                prefix = [
                    b
                    for b in stored_chain
                    if b.prospective_chain_link is not None
                    and b.prospective_chain_link.sequence_number < seq
                ]
                resolved_history = [*prefix, bundle]
            except ProofNotFoundError:
                resolved_history = None

        return verify_proof_bundle(
            bundle,
            registry_doc=registry_doc,
            chain_history=resolved_history,
            continuity_log_leaves=all_leaves,
            now_utc=now_utc,
        )

    def store_proof(
        self,
        bundle: VerifyProofBundle,
        *,
        opt_in_leaderboard: bool = False,
        stored_at_utc: str | None = None,
        now_utc: str | datetime | None = None,
    ) -> tuple[VerifyProofBundle, BundleVerificationResult]:
        """Validate governance & cryptography, enforce 7-day trade guard, and persist redacted proof."""
        stored, verification, _ = self.publish_proof(
            bundle,
            opt_in_leaderboard=opt_in_leaderboard,
            stored_at_utc=stored_at_utc,
            now_utc=now_utc,
        )
        return stored, verification

    def publish_proof(
        self,
        bundle: VerifyProofBundle,
        *,
        opt_in_leaderboard: bool = False,
        stored_at_utc: str | None = None,
        now_utc: str | datetime | None = None,
    ) -> tuple[VerifyProofBundle, BundleVerificationResult, bool]:
        """Like ``store_proof``, and also say whether this post created the record.

        For a record that is already published the stored record is returned
        with its own verification, and the flag is False.
        """
        if self._config.hosted_multi_user_mode and bundle.proof_id.strip().lower().startswith(
            "specimen-"
        ):
            raise PaperOrSandboxRejectedError(
                "Synthetic sample specimens are for local preview only and cannot be published as live records"
            )
        enforce_bundle_governance(
            provider_approval_state=bundle.provider_approval_state,
            environment_tier=bundle.environment_tier,
            hosted_multi_user_mode=self._config.hosted_multi_user_mode,
        )
        self.require_registry_signer(bundle)
        sanitized_bundle, _ = enforce_bundle_seven_day_trade_guard(
            bundle,
            min_delay_days=self._config.delayed_trade_guard_days,
        )
        verification = self.verify_bundle_against_live_state(sanitized_bundle, now_utc=now_utc)
        if not verification.valid:
            raise ProofBundleInvalidError(
                "Proof bundle failed verification and cannot be published",
                errors=verification.errors,
            )
        _refuse_invalid_holder_claim(verification)
        refuse_text_the_scanner_blocks(sanitized_bundle)
        if (
            self._config.hosted_multi_user_mode
            and opt_in_leaderboard
            and sanitized_bundle.provider_approval_state in CHAIN_REFUSED_APPROVAL_STATES_IN_HOSTED_MODE
        ):
            raise LeaderboardRequiresProvenOwnershipError(
                "This host does not list a record made from a public address without proof of ownership on the public leaderboard"
            )

        now_str = stored_at_utc or utc_now_iso()
        chain_id = (
            sanitized_bundle.prospective_chain_link.chain_id
            if sanitized_bundle.prospective_chain_link is not None
            else None
        )
        seq_num = (
            sanitized_bundle.prospective_chain_link.sequence_number
            if sanitized_bundle.prospective_chain_link is not None
            else None
        )
        bundle_json = jcs_canonicalize_str(sanitized_bundle.to_dict())
        p_hash = sanitized_bundle.proof_hash()
        holder_pubkey = (
            sanitized_bundle.holder_identity.holder_public_key_hex
            if verification.holder_claim_status == HolderClaimStatus.SELF_ASSERTED
            and sanitized_bundle.holder_identity is not None
            else None
        )

        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                existing_row = self._conn.execute(
                    "SELECT proof_hash, bundle_json, opt_in_leaderboard FROM proofs WHERE proof_id = ?",
                    (sanitized_bundle.proof_id,),
                ).fetchone()
                if existing_row is not None:
                    if str(existing_row["proof_hash"]) != p_hash:
                        raise ProofConflictError(
                            f"Proof {sanitized_bundle.proof_id!r} already exists with a different proof_hash"
                        )
                    # A published record is immutable. proof_hash covers the signed
                    # header only, so a second post with the same hash can still
                    # carry another holder name, fewer disclosed leaves or the
                    # leaderboard flag. None of that is taken: the caller gets
                    # back what is already stored. To publish with a holder
                    # name, attach it before the first post.
                    self._conn.execute("COMMIT;")
                    stored_bundle = VerifyProofBundle.from_dict(
                        json.loads(str(existing_row["bundle_json"]))
                    )
                    stored_verification = self.verify_bundle_against_live_state(
                        stored_bundle, now_utc=now_utc
                    )
                    return stored_bundle, stored_verification, False

                effective_opt_in = bool(opt_in_leaderboard)
                profile_row = None
                if holder_pubkey is not None:
                    profile_row = self._conn.execute(
                        "SELECT list_on_leaderboard, pinned_proof_id FROM holder_profiles WHERE holder_public_key_hex = ?",
                        (holder_pubkey,),
                    ).fetchone()
                    if profile_row is not None:
                        profile_listed = bool(profile_row["list_on_leaderboard"])
                        if (
                            profile_listed
                            and not (
                                self._config.hosted_multi_user_mode
                                and sanitized_bundle.provider_approval_state
                                in CHAIN_REFUSED_APPROVAL_STATES_IN_HOSTED_MODE
                            )
                        ):
                            effective_opt_in = True
                        else:
                            # Signed holder profile preference is authoritative: an unsigned
                            # opt_in_leaderboard=True flag on POST /api/v1/proofs cannot override
                            # an explicit holder-signed list_on_leaderboard=False preference.
                            effective_opt_in = False

                self._conn.execute(
                    """
                    INSERT INTO proofs (
                        proof_id,
                        proof_hash,
                        blinded_account_tag,
                        broker_id,
                        chain_id,
                        sequence_number,
                        bundle_json,
                        opt_in_leaderboard,
                        stored_at_utc,
                        holder_public_key_hex
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sanitized_bundle.proof_id,
                        p_hash,
                        sanitized_bundle.blinded_account_tag,
                        sanitized_bundle.broker_id,
                        chain_id,
                        seq_num,
                        bundle_json,
                        1 if effective_opt_in else 0,
                        now_str,
                        holder_pubkey,
                    ),
                )
                if holder_pubkey is not None and profile_row is not None:
                    self._sync_holder_leaderboard_locked(
                        holder_pubkey,
                        list_on_leaderboard=bool(profile_row["list_on_leaderboard"]),
                        pinned_proof_id=(
                            str(profile_row["pinned_proof_id"])
                            if profile_row["pinned_proof_id"] is not None
                            else None
                        ),
                        enforce_hosted_governance=False,
                    )
                self._last_updated_utc = now_str
                self._conn.execute("COMMIT;")
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

        return sanitized_bundle, verification, True

    def _refuse_already_published(self, proof_id: str, proof_hash: str) -> None:
        row = self._conn.execute(
            "SELECT 1 FROM proofs WHERE proof_id = ? OR proof_hash = ?",
            (proof_id, proof_hash),
        ).fetchone()
        if row is not None:
            raise ProofAlreadyPublishedError(
                f"Record {proof_id!r} is already published; a published record cannot be "
                "enrolled in or appended to a chain afterwards"
            )

    def get_proof_entry(self, proof_id: str) -> StoredProofEntry:
        """Retrieve a stored redacted ``VerifyProofBundle`` by ``proof_id``."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT proof_hash, bundle_json, opt_in_leaderboard, stored_at_utc
                FROM proofs
                WHERE proof_id = ?
                """,
                (proof_id,),
            ).fetchone()
        if row is None:
            raise ProofNotFoundError(f"Proof {proof_id!r} not found")
        bundle = VerifyProofBundle.from_dict(json.loads(str(row["bundle_json"])))
        return StoredProofEntry(
            bundle=bundle,
            proof_hash=str(row["proof_hash"]),
            opt_in_leaderboard=bool(row["opt_in_leaderboard"]),
            stored_at_utc=str(row["stored_at_utc"]),
        )

    def list_leaderboard_candidates(self) -> list[StoredProofEntry]:
        """Return latest opted-in proof entry per ``blinded_account_tag``."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT
                    proof_id,
                    proof_hash,
                    blinded_account_tag,
                    sequence_number,
                    bundle_json,
                    opt_in_leaderboard,
                    stored_at_utc
                FROM proofs
                WHERE opt_in_leaderboard = 1
                ORDER BY stored_at_utc DESC, COALESCE(sequence_number, -1) DESC
                """
            ).fetchall()

        best_by_account: dict[str, tuple[tuple[int, datetime], StoredProofEntry]] = {}
        for r in rows:
            bundle = VerifyProofBundle.from_dict(json.loads(str(r["bundle_json"])))
            if (
                self._config.hosted_multi_user_mode
                and bundle.provider_approval_state in CHAIN_REFUSED_APPROVAL_STATES_IN_HOSTED_MODE
            ):
                continue
            seq_val = int(r["sequence_number"]) if r["sequence_number"] is not None else -1
            issued_dt = parse_utc_timestamp(bundle.issued_at_utc)
            rank_key = (seq_val, issued_dt)
            entry = StoredProofEntry(
                bundle=bundle,
                proof_hash=str(r["proof_hash"]),
                opt_in_leaderboard=True,
                stored_at_utc=str(r["stored_at_utc"]),
            )
            prev = best_by_account.get(bundle.blinded_account_tag)
            if prev is None or rank_key > prev[0]:
                best_by_account[bundle.blinded_account_tag] = (rank_key, entry)

        return [pair[1] for pair in best_by_account.values()]

    def enroll_chain(
        self,
        genesis_bundle: VerifyProofBundle,
        *,
        opt_in_leaderboard: bool = False,
        allow_retrospective_backfill: bool = False,
        logged_at_utc: str | None = None,
        now_utc: str | datetime | None = None,
    ) -> tuple[VerifyProofBundle, ContinuityLogLeaf, ChainVerificationResult]:
        """Enroll genesis prospective chain link (``sequence_number == 0``) and log in continuity log."""
        enforce_bundle_governance(
            provider_approval_state=genesis_bundle.provider_approval_state,
            environment_tier=genesis_bundle.environment_tier,
            hosted_multi_user_mode=self._config.hosted_multi_user_mode,
        )
        self.require_registry_signer(genesis_bundle)
        refuse_chain_without_proven_ownership(
            genesis_bundle, hosted=self._config.hosted_multi_user_mode
        )
        check_chain_link_matches_record(genesis_bundle)

        sanitized_bundle, _ = enforce_bundle_seven_day_trade_guard(
            genesis_bundle,
            min_delay_days=self._config.delayed_trade_guard_days,
        )
        link = sanitized_bundle.prospective_chain_link
        if link is None:
            raise ChainViolationError(
                ChainVerificationResult(
                    valid=False,
                    continuity_mode=ChainContinuityMode.CONTINUITY_BROKEN,
                    verified_length=0,
                    violation_codes=[ChainInvariantViolationCode.NON_MONOTONIC_SEQUENCE],
                    details=["Chain enrollment requires a genesis prospective_chain_link"],
                )
            )

        with self._lock:
            existing_acct_leaves = self.get_continuity_leaves_for_account(
                sanitized_bundle.blinded_account_tag
            )
            if existing_acct_leaves:
                raise ChainResetConflictError(
                    ChainVerificationResult(
                        valid=False,
                        continuity_mode=ChainContinuityMode.CONTINUITY_BROKEN,
                        verified_length=0,
                        violation_codes=[ChainInvariantViolationCode.PARALLEL_CHAIN_RESET_DETECTED],
                        details=[
                            "blinded_account_tag already has continuity log entries; "
                            "parallel chain reset at sequence_number == 0 is prohibited"
                        ],
                    )
                )

            existing_chain_row = self._conn.execute(
                "SELECT 1 FROM chains WHERE chain_id = ?",
                (link.chain_id,),
            ).fetchone()
            if existing_chain_row is not None:
                raise ChainResetConflictError(
                    ChainVerificationResult(
                        valid=False,
                        continuity_mode=ChainContinuityMode.CONTINUITY_BROKEN,
                        verified_length=0,
                        violation_codes=[ChainInvariantViolationCode.PARALLEL_CHAIN_RESET_DETECTED],
                        details=[f"chain_id {link.chain_id!r} is already enrolled"],
                    )
                )

            # Verify cryptographic signature, Merkle tree, transcript safety, signer trust
            registry_doc = self.build_registry_document()
            all_leaves = self.list_all_continuity_leaves()
            bundle_ver = verify_proof_bundle(
                sanitized_bundle,
                registry_doc=registry_doc,
                chain_history=[sanitized_bundle],
                continuity_log_leaves=all_leaves,
                now_utc=now_utc,
            )
            if (
                not bundle_ver.signature_valid
                or not bundle_ver.merkle_valid
                or not bundle_ver.transcript_safety_ok
                or bundle_ver.signer_trust_status == SignerTrustStatus.REVOKED_KEY
            ):
                raise ProofBundleInvalidError(
                    "Genesis proof bundle failed cryptographic verification",
                    errors=bundle_ver.errors,
                )
            _refuse_invalid_holder_claim(bundle_ver)
            refuse_text_the_scanner_blocks(sanitized_bundle)

            chain_res = verify_prospective_chain(
                [sanitized_bundle],
                continuity_log_leaves=all_leaves,
                now_utc=now_utc,
            )
            if ChainInvariantViolationCode.PARALLEL_CHAIN_RESET_DETECTED in chain_res.violation_codes:
                raise ChainResetConflictError(chain_res)

            if not chain_res.valid:
                only_backfill = (
                    allow_retrospective_backfill
                    and chain_res.continuity_mode == ChainContinuityMode.RETROSPECTIVE_BACKFILL
                    and chain_res.violation_codes
                    == [ChainInvariantViolationCode.GENESIS_BACKFILL_WINDOW_EXCEEDED]
                )
                if not only_backfill:
                    raise ChainViolationError(chain_res)

            now_str = logged_at_utc or utc_now_iso()
            p_hash = sanitized_bundle.proof_hash()
            bundle_json = jcs_canonicalize_str(sanitized_bundle.to_dict())
            holder_pubkey = (
                sanitized_bundle.holder_identity.holder_public_key_hex
                if bundle_ver.holder_claim_status == HolderClaimStatus.SELF_ASSERTED
                and sanitized_bundle.holder_identity is not None
                else None
            )

            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                self._refuse_already_published(sanitized_bundle.proof_id, p_hash)
                effective_opt_in = bool(opt_in_leaderboard)
                profile_row = None
                if holder_pubkey is not None:
                    profile_row = self._conn.execute(
                        "SELECT list_on_leaderboard, pinned_proof_id FROM holder_profiles WHERE holder_public_key_hex = ?",
                        (holder_pubkey,),
                    ).fetchone()
                    if profile_row is not None:
                        effective_opt_in = bool(profile_row["list_on_leaderboard"])

                idx_row = self._conn.execute(
                    "SELECT COALESCE(MAX(log_index), -1) + 1 AS next_idx FROM continuity_log"
                ).fetchone()
                next_idx = int(idx_row["next_idx"]) if idx_row is not None else 0

                log_leaf = ContinuityLogLeaf(
                    log_index=next_idx,
                    chain_id=link.chain_id,
                    blinded_account_tag=sanitized_bundle.blinded_account_tag,
                    sequence_number=link.sequence_number,
                    proof_hash=p_hash,
                    logged_at_utc=now_str,
                )
                self._conn.execute(
                    """
                    INSERT INTO continuity_log (
                        log_index,
                        chain_id,
                        blinded_account_tag,
                        sequence_number,
                        proof_hash,
                        logged_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        log_leaf.log_index,
                        log_leaf.chain_id,
                        log_leaf.blinded_account_tag,
                        log_leaf.sequence_number,
                        log_leaf.proof_hash,
                        log_leaf.logged_at_utc,
                    ),
                )
                self._conn.execute(
                    """
                    INSERT INTO chains (
                        chain_id,
                        blinded_account_tag,
                        enrolled_at_utc,
                        expected_interval_seconds,
                        grace_window_seconds,
                        latest_sequence_number,
                        latest_proof_hash,
                        opt_in_leaderboard,
                        updated_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        link.chain_id,
                        sanitized_bundle.blinded_account_tag,
                        link.enrolled_at_utc,
                        link.cadence_policy.expected_interval_seconds,
                        link.cadence_policy.grace_window_seconds,
                        link.sequence_number,
                        p_hash,
                        1 if effective_opt_in else 0,
                        now_str,
                    ),
                )
                self._conn.execute(
                    """
                    INSERT INTO proofs (
                        proof_id,
                        proof_hash,
                        blinded_account_tag,
                        broker_id,
                        chain_id,
                        sequence_number,
                        bundle_json,
                        opt_in_leaderboard,
                        stored_at_utc,
                        holder_public_key_hex
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sanitized_bundle.proof_id,
                        p_hash,
                        sanitized_bundle.blinded_account_tag,
                        sanitized_bundle.broker_id,
                        link.chain_id,
                        link.sequence_number,
                        bundle_json,
                        1 if effective_opt_in else 0,
                        now_str,
                        holder_pubkey,
                    ),
                )
                if holder_pubkey is not None and profile_row is not None:
                    self._sync_holder_leaderboard_locked(
                        holder_pubkey,
                        list_on_leaderboard=bool(profile_row["list_on_leaderboard"]),
                        pinned_proof_id=(
                            str(profile_row["pinned_proof_id"])
                            if profile_row["pinned_proof_id"] is not None
                            else None
                        ),
                        enforce_hosted_governance=False,
                    )
                self._last_updated_utc = now_str
                self._conn.execute("COMMIT;")
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

        return sanitized_bundle, log_leaf, chain_res

    def append_chain(
        self,
        chain_id: str,
        next_bundle: VerifyProofBundle,
        *,
        opt_in_leaderboard: bool | None = None,
        logged_at_utc: str | None = None,
        now_utc: str | datetime | None = None,
    ) -> tuple[VerifyProofBundle, ContinuityLogLeaf, ChainVerificationResult]:
        """Validate all 5 prospective chain invariants against history + log and append next link."""
        enforce_bundle_governance(
            provider_approval_state=next_bundle.provider_approval_state,
            environment_tier=next_bundle.environment_tier,
            hosted_multi_user_mode=self._config.hosted_multi_user_mode,
        )
        self.require_registry_signer(next_bundle)
        refuse_chain_without_proven_ownership(next_bundle, hosted=self._config.hosted_multi_user_mode)
        check_chain_link_matches_record(next_bundle)
        sanitized_bundle, _ = enforce_bundle_seven_day_trade_guard(
            next_bundle,
            min_delay_days=self._config.delayed_trade_guard_days,
        )
        link = sanitized_bundle.prospective_chain_link
        if link is None:
            raise ChainViolationError(
                ChainVerificationResult(
                    valid=False,
                    continuity_mode=ChainContinuityMode.CONTINUITY_BROKEN,
                    verified_length=0,
                    violation_codes=[ChainInvariantViolationCode.NON_MONOTONIC_SEQUENCE],
                    details=["Appended bundle is missing prospective_chain_link"],
                )
            )

        with self._lock:
            chain_row = self._conn.execute(
                """
                SELECT blinded_account_tag, opt_in_leaderboard
                FROM chains
                WHERE chain_id = ?
                """,
                (chain_id,),
            ).fetchone()
            if chain_row is None:
                raise ProofNotFoundError(f"Chain {chain_id!r} not found")

            if link.sequence_number == 0:
                raise ChainResetConflictError(
                    ChainVerificationResult(
                        valid=False,
                        continuity_mode=ChainContinuityMode.CONTINUITY_BROKEN,
                        verified_length=0,
                        violation_codes=[ChainInvariantViolationCode.PARALLEL_CHAIN_RESET_DETECTED],
                        details=[
                            "Cannot append sequence_number == 0 to an enrolled chain; "
                            "parallel chain reset detected"
                        ],
                    )
                )

            history = self.get_chain_bundles(chain_id)
            all_leaves = self.list_all_continuity_leaves()
            registry_doc = self.build_registry_document()

            candidate_chain = [*history, sanitized_bundle]
            chain_res = verify_prospective_chain(
                candidate_chain,
                continuity_log_leaves=all_leaves,
                now_utc=now_utc,
            )
            if ChainInvariantViolationCode.PARALLEL_CHAIN_RESET_DETECTED in chain_res.violation_codes:
                raise ChainResetConflictError(chain_res)
            if chain_res.continuity_mode == ChainContinuityMode.CONTINUITY_BROKEN:
                raise ChainViolationError(chain_res)

            bundle_ver = verify_proof_bundle(
                sanitized_bundle,
                registry_doc=registry_doc,
                chain_history=candidate_chain,
                continuity_log_leaves=all_leaves,
                now_utc=now_utc,
            )
            if (
                not bundle_ver.signature_valid
                or not bundle_ver.merkle_valid
                or not bundle_ver.transcript_safety_ok
                or bundle_ver.signer_trust_status == SignerTrustStatus.REVOKED_KEY
            ):
                raise ProofBundleInvalidError(
                    "Appended proof bundle failed cryptographic verification",
                    errors=bundle_ver.errors,
                )
            _refuse_invalid_holder_claim(bundle_ver)
            refuse_text_the_scanner_blocks(sanitized_bundle)

            resolved_opt_in = (
                bool(chain_row["opt_in_leaderboard"])
                if opt_in_leaderboard is None
                else bool(opt_in_leaderboard)
            )
            now_str = logged_at_utc or utc_now_iso()
            p_hash = sanitized_bundle.proof_hash()
            bundle_json = jcs_canonicalize_str(sanitized_bundle.to_dict())
            holder_pubkey = (
                sanitized_bundle.holder_identity.holder_public_key_hex
                if bundle_ver.holder_claim_status == HolderClaimStatus.SELF_ASSERTED
                and sanitized_bundle.holder_identity is not None
                else None
            )

            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                self._refuse_already_published(sanitized_bundle.proof_id, p_hash)
                profile_row = None
                if holder_pubkey is not None:
                    profile_row = self._conn.execute(
                        "SELECT list_on_leaderboard, pinned_proof_id FROM holder_profiles WHERE holder_public_key_hex = ?",
                        (holder_pubkey,),
                    ).fetchone()
                    if profile_row is not None:
                        resolved_opt_in = bool(profile_row["list_on_leaderboard"])

                idx_row = self._conn.execute(
                    "SELECT COALESCE(MAX(log_index), -1) + 1 AS next_idx FROM continuity_log"
                ).fetchone()
                next_idx = int(idx_row["next_idx"]) if idx_row is not None else 0

                log_leaf = ContinuityLogLeaf(
                    log_index=next_idx,
                    chain_id=chain_id,
                    blinded_account_tag=sanitized_bundle.blinded_account_tag,
                    sequence_number=link.sequence_number,
                    proof_hash=p_hash,
                    logged_at_utc=now_str,
                )
                self._conn.execute(
                    """
                    INSERT INTO continuity_log (
                        log_index,
                        chain_id,
                        blinded_account_tag,
                        sequence_number,
                        proof_hash,
                        logged_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        log_leaf.log_index,
                        log_leaf.chain_id,
                        log_leaf.blinded_account_tag,
                        log_leaf.sequence_number,
                        log_leaf.proof_hash,
                        log_leaf.logged_at_utc,
                    ),
                )
                self._conn.execute(
                    """
                    UPDATE chains
                    SET latest_sequence_number = ?,
                        latest_proof_hash = ?,
                        opt_in_leaderboard = ?,
                        updated_at_utc = ?
                    WHERE chain_id = ?
                    """,
                    (
                        link.sequence_number,
                        p_hash,
                        1 if resolved_opt_in else 0,
                        now_str,
                        chain_id,
                    ),
                )
                self._conn.execute(
                    """
                    INSERT INTO proofs (
                        proof_id,
                        proof_hash,
                        blinded_account_tag,
                        broker_id,
                        chain_id,
                        sequence_number,
                        bundle_json,
                        opt_in_leaderboard,
                        stored_at_utc,
                        holder_public_key_hex
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sanitized_bundle.proof_id,
                        p_hash,
                        sanitized_bundle.blinded_account_tag,
                        sanitized_bundle.broker_id,
                        chain_id,
                        link.sequence_number,
                        bundle_json,
                        1 if resolved_opt_in else 0,
                        now_str,
                        holder_pubkey,
                    ),
                )
                if holder_pubkey is not None and profile_row is not None:
                    self._sync_holder_leaderboard_locked(
                        holder_pubkey,
                        list_on_leaderboard=bool(profile_row["list_on_leaderboard"]),
                        pinned_proof_id=(
                            str(profile_row["pinned_proof_id"])
                            if profile_row["pinned_proof_id"] is not None
                            else None
                        ),
                        enforce_hosted_governance=False,
                    )
                self._last_updated_utc = now_str
                self._conn.execute("COMMIT;")
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

        return sanitized_bundle, log_leaf, chain_res

    @staticmethod
    def _parse_stored_timestamp(raw: str) -> datetime:
        try:
            return parse_utc_timestamp(raw, field_name="stored_at_utc")
        except (ValueError, TypeError):
            return datetime.min.replace(tzinfo=timezone.utc)

    @staticmethod
    def _sort_holder_proof_entries(entries: list[StoredProofEntry]) -> list[StoredProofEntry]:
        return sorted(
            entries,
            key=lambda e: (
                parse_utc_timestamp(e.bundle.period_end_utc),
                parse_utc_timestamp(e.bundle.issued_at_utc),
                ProofStore._parse_stored_timestamp(e.stored_at_utc),
                e.bundle.proof_id,
            ),
            reverse=True,
        )

    @staticmethod
    def _row_to_holder_profile(row: sqlite3.Row) -> StoredHolderProfile:
        lb_claim_raw = row["leaderboard_signed_claim_json"]
        return StoredHolderProfile(
            holder_public_key_hex=str(row["holder_public_key_hex"]),
            handle=str(row["handle"]),
            display_name=str(row["display_name"]),
            bio=str(row["bio"]),
            profile_url=str(row["profile_url"]) if row["profile_url"] is not None else None,
            strategy_notes=str(row["strategy_notes"]),
            watchlist=json.loads(str(row["watchlist_json"])),
            conviction_list=json.loads(str(row["conviction_list_json"])),
            list_on_leaderboard=bool(row["list_on_leaderboard"]),
            pinned_proof_id=(
                str(row["pinned_proof_id"]) if row["pinned_proof_id"] is not None else None
            ),
            sequence_number=int(row["sequence_number"]),
            signed_claim=json.loads(str(row["signed_claim_json"])),
            updated_at_utc=str(row["updated_at_utc"]),
            created_at_utc=str(row["created_at_utc"]),
            leaderboard_signed_claim=(
                json.loads(str(lb_claim_raw)) if lb_claim_raw is not None else None
            ),
        )

    def _list_proofs_for_holder_key_locked(self, norm_pubkey: str) -> list[StoredProofEntry]:
        rows = self._conn.execute(
            """
            SELECT proof_hash, bundle_json, opt_in_leaderboard, stored_at_utc
            FROM proofs
            WHERE holder_public_key_hex = ?
            """,
            (norm_pubkey,),
        ).fetchall()
        entries: list[StoredProofEntry] = []
        for r in rows:
            bundle = VerifyProofBundle.from_dict(json.loads(str(r["bundle_json"])))
            entries.append(
                StoredProofEntry(
                    bundle=bundle,
                    proof_hash=str(r["proof_hash"]),
                    opt_in_leaderboard=bool(r["opt_in_leaderboard"]),
                    stored_at_utc=str(r["stored_at_utc"]),
                )
            )
        return self._sort_holder_proof_entries(entries)

    def _clear_holder_leaderboard_flags_locked(self, holder_pubkey: str) -> None:
        self._conn.execute(
            "UPDATE proofs SET opt_in_leaderboard = 0 WHERE holder_public_key_hex = ?",
            (holder_pubkey,),
        )
        self._conn.execute(
            """
            UPDATE chains
            SET opt_in_leaderboard = 0
            WHERE chain_id IN (
                SELECT DISTINCT chain_id
                FROM proofs
                WHERE holder_public_key_hex = ? AND chain_id IS NOT NULL
            )
            """,
            (holder_pubkey,),
        )

    def _sync_holder_leaderboard_locked(
        self,
        holder_pubkey: str,
        *,
        list_on_leaderboard: bool,
        pinned_proof_id: str | None,
        enforce_hosted_governance: bool,
    ) -> None:
        """Synchronize ``proofs.opt_in_leaderboard`` and ``chains.opt_in_leaderboard`` for a holder key."""
        if not list_on_leaderboard:
            self._clear_holder_leaderboard_flags_locked(holder_pubkey)
            return

        entries = self._list_proofs_for_holder_key_locked(holder_pubkey)
        if not entries:
            return

        active = entries[0]
        if pinned_proof_id is not None:
            for item in entries:
                if item.bundle.proof_id == pinned_proof_id:
                    active = item
                    break

        unproven = (
            self._config.hosted_multi_user_mode
            and active.bundle.provider_approval_state in CHAIN_REFUSED_APPROVAL_STATES_IN_HOSTED_MODE
        )
        if unproven:
            if enforce_hosted_governance:
                raise LeaderboardRequiresProvenOwnershipError(
                    "This host does not list a record made from a public address without proof of ownership on the public leaderboard"
                )
            self._clear_holder_leaderboard_flags_locked(holder_pubkey)
            return

        self._clear_holder_leaderboard_flags_locked(holder_pubkey)
        self._conn.execute(
            "UPDATE proofs SET opt_in_leaderboard = 1 WHERE proof_id = ?",
            (active.bundle.proof_id,),
        )
        if active.bundle.prospective_chain_link is not None:
            self._conn.execute(
                "UPDATE chains SET opt_in_leaderboard = 1 WHERE chain_id = ?",
                (active.bundle.prospective_chain_link.chain_id,),
            )

    def upsert_holder_profile(
        self,
        *,
        holder_public_key_hex: str,
        handle: str,
        display_name: str,
        bio: str,
        profile_url: str | None,
        strategy_notes: str,
        watchlist: list[dict[str, Any]],
        conviction_list: list[dict[str, Any]],
        list_on_leaderboard: bool,
        pinned_proof_id: str | None,
        sequence_number: int,
        signed_claim: Mapping[str, Any],
        now_utc_str: str | None = None,
    ) -> tuple[StoredHolderProfile, bool]:
        """Claim or update an Ed25519-keyed holder profile and sync leaderboard visibility."""
        norm_pubkey = validate_hex_digest(
            holder_public_key_hex, field_name="holder_public_key_hex", num_bytes=32
        )
        norm_handle = handle.strip().lstrip("@").lower()
        now_str = now_utc_str or utc_now_iso()
        watchlist_json = jcs_canonicalize_str(watchlist)
        conviction_json = jcs_canonicalize_str(conviction_list)
        signed_claim_json = jcs_canonicalize_str(dict(signed_claim))

        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                existing_by_key = self._conn.execute(
                    "SELECT * FROM holder_profiles WHERE holder_public_key_hex = ?",
                    (norm_pubkey,),
                ).fetchone()
                existing_by_handle = self._conn.execute(
                    "SELECT holder_public_key_hex FROM holder_profiles WHERE handle = ?",
                    (norm_handle,),
                ).fetchone()
                if (
                    existing_by_handle is not None
                    and str(existing_by_handle["holder_public_key_hex"]) != norm_pubkey
                ):
                    raise ProfileOwnershipError(
                        f"Handle '@{norm_handle}' is already claimed by another holder key"
                    )

                if existing_by_key is not None:
                    current_seq = int(existing_by_key["sequence_number"])
                    if sequence_number <= current_seq:
                        raise ProfileSequenceError(
                            f"sequence_number must be greater than current profile sequence ({current_seq})"
                        )
                    created = False
                    created_at = str(existing_by_key["created_at_utc"])
                else:
                    if sequence_number < 1:
                        raise ProfileSequenceError("sequence_number must be at least 1")
                    created = True
                    created_at = now_str

                if pinned_proof_id is not None:
                    pin_row = self._conn.execute(
                        "SELECT holder_public_key_hex FROM proofs WHERE proof_id = ?",
                        (pinned_proof_id,),
                    ).fetchone()
                    if pin_row is None or str(pin_row["holder_public_key_hex"] or "") != norm_pubkey:
                        raise ProfileInvalidError(
                            "pinned_proof_id must reference a published record signed by this holder key"
                        )

                if created:
                    self._conn.execute(
                        """
                        INSERT INTO holder_profiles (
                            holder_public_key_hex,
                            handle,
                            display_name,
                            bio,
                            profile_url,
                            strategy_notes,
                            watchlist_json,
                            conviction_list_json,
                            list_on_leaderboard,
                            pinned_proof_id,
                            sequence_number,
                            signed_claim_json,
                            leaderboard_signed_claim_json,
                            updated_at_utc,
                            created_at_utc
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                        """,
                        (
                            norm_pubkey,
                            norm_handle,
                            display_name,
                            bio,
                            profile_url,
                            strategy_notes,
                            watchlist_json,
                            conviction_json,
                            1 if list_on_leaderboard else 0,
                            pinned_proof_id,
                            sequence_number,
                            signed_claim_json,
                            now_str,
                            created_at,
                        ),
                    )
                else:
                    self._conn.execute(
                        """
                        UPDATE holder_profiles
                        SET handle = ?,
                            display_name = ?,
                            bio = ?,
                            profile_url = ?,
                            strategy_notes = ?,
                            watchlist_json = ?,
                            conviction_list_json = ?,
                            list_on_leaderboard = ?,
                            pinned_proof_id = ?,
                            sequence_number = ?,
                            signed_claim_json = ?,
                            leaderboard_signed_claim_json = NULL,
                            updated_at_utc = ?
                        WHERE holder_public_key_hex = ?
                        """,
                        (
                            norm_handle,
                            display_name,
                            bio,
                            profile_url,
                            strategy_notes,
                            watchlist_json,
                            conviction_json,
                            1 if list_on_leaderboard else 0,
                            pinned_proof_id,
                            sequence_number,
                            signed_claim_json,
                            now_str,
                            norm_pubkey,
                        ),
                    )

                self._sync_holder_leaderboard_locked(
                    norm_pubkey,
                    list_on_leaderboard=bool(list_on_leaderboard),
                    pinned_proof_id=pinned_proof_id,
                    enforce_hosted_governance=True,
                )
                row = self._conn.execute(
                    "SELECT * FROM holder_profiles WHERE holder_public_key_hex = ?",
                    (norm_pubkey,),
                ).fetchone()
                self._conn.execute("COMMIT;")
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

        assert row is not None
        return self._row_to_holder_profile(row), created

    def set_holder_leaderboard_listing(
        self,
        *,
        holder_public_key_hex: str,
        handle: str,
        list_on_leaderboard: bool,
        sequence_number: int,
        signed_claim: Mapping[str, Any],
        now_utc_str: str | None = None,
    ) -> StoredHolderProfile:
        """Apply a holder-signed leaderboard list/unlist toggle for an existing handle."""
        norm_pubkey = validate_hex_digest(
            holder_public_key_hex, field_name="holder_public_key_hex", num_bytes=32
        )
        norm_handle = handle.strip().lstrip("@").lower()
        now_str = now_utc_str or utc_now_iso()
        lb_claim_json = jcs_canonicalize_str(dict(signed_claim))

        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                existing = self._conn.execute(
                    "SELECT * FROM holder_profiles WHERE handle = ?",
                    (norm_handle,),
                ).fetchone()
                if existing is None:
                    raise ProfileNotFoundError(f"Profile '@{norm_handle}' not found")
                if str(existing["holder_public_key_hex"]) != norm_pubkey:
                    raise ProfileOwnershipError(
                        f"Handle '@{norm_handle}' is owned by a different holder key"
                    )
                current_seq = int(existing["sequence_number"])
                if sequence_number <= current_seq:
                    raise ProfileSequenceError(
                        f"sequence_number must be greater than current profile sequence ({current_seq})"
                    )

                pinned_proof_id = (
                    str(existing["pinned_proof_id"])
                    if existing["pinned_proof_id"] is not None
                    else None
                )
                self._sync_holder_leaderboard_locked(
                    norm_pubkey,
                    list_on_leaderboard=bool(list_on_leaderboard),
                    pinned_proof_id=pinned_proof_id,
                    enforce_hosted_governance=True,
                )
                self._conn.execute(
                    """
                    UPDATE holder_profiles
                    SET list_on_leaderboard = ?,
                        sequence_number = ?,
                        leaderboard_signed_claim_json = ?,
                        updated_at_utc = ?
                    WHERE holder_public_key_hex = ?
                    """,
                    (
                        1 if list_on_leaderboard else 0,
                        sequence_number,
                        lb_claim_json,
                        now_str,
                        norm_pubkey,
                    ),
                )
                row = self._conn.execute(
                    "SELECT * FROM holder_profiles WHERE holder_public_key_hex = ?",
                    (norm_pubkey,),
                ).fetchone()
                self._conn.execute("COMMIT;")
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

        assert row is not None
        return self._row_to_holder_profile(row)

    def get_holder_profile_by_handle(self, handle: str) -> StoredHolderProfile:
        norm_handle = handle.strip().lstrip("@").lower()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM holder_profiles WHERE handle = ?",
                (norm_handle,),
            ).fetchone()
        if row is None:
            raise ProfileNotFoundError(f"Profile '@{norm_handle}' not found")
        return self._row_to_holder_profile(row)

    def get_holder_profile_by_key(self, holder_public_key_hex: str) -> StoredHolderProfile:
        norm_pubkey = validate_hex_digest(
            holder_public_key_hex, field_name="holder_public_key_hex", num_bytes=32
        )
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM holder_profiles WHERE holder_public_key_hex = ?",
                (norm_pubkey,),
            ).fetchone()
        if row is None:
            raise ProfileNotFoundError(f"Profile for key {norm_pubkey!r} not found")
        return self._row_to_holder_profile(row)

    def list_proofs_for_holder_key(self, holder_public_key_hex: str) -> list[StoredProofEntry]:
        norm_pubkey = validate_hex_digest(
            holder_public_key_hex, field_name="holder_public_key_hex", num_bytes=32
        )
        with self._lock:
            return self._list_proofs_for_holder_key_locked(norm_pubkey)

    def list_holder_handles_by_key(self) -> dict[str, tuple[str, str]]:
        """Map ``holder_public_key_hex`` -> ``(handle, display_name)`` for leaderboard enrichment."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT holder_public_key_hex, handle, display_name FROM holder_profiles"
            ).fetchall()
        return {
            str(r["holder_public_key_hex"]): (str(r["handle"]), str(r["display_name"]))
            for r in rows
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()


__all__ = [
    "CHAIN_REFUSED_APPROVAL_STATES_IN_HOSTED_MODE",
    "ChainLinkMismatchError",
    "ChainRequiresProvenOwnershipError",
    "ChainResetConflictError",
    "ChainViolationError",
    "EMPTY_TLOG_ROOT_HEX",
    "GovernanceBlockedError",
    "LeaderboardRequiresProvenOwnershipError",
    "PaperOrSandboxRejectedError",
    "ProfileInvalidError",
    "ProfileNotFoundError",
    "ProfileOwnershipError",
    "ProfileSequenceError",
    "ProofAlreadyPublishedError",
    "ProofBundleInvalidError",
    "ProofConflictError",
    "ProofNotFoundError",
    "ProofStore",
    "ProviderApprovalPendingError",
    "PublisherKeyNotInRegistryError",
    "StoredHolderProfile",
    "StoredProofEntry",
    "enforce_bundle_governance",
    "enforce_bundle_seven_day_trade_guard",
]
