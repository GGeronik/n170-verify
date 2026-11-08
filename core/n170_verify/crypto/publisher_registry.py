"""Publisher key registry, C2SP tlog-checkpoint cosigning, and Base L2 batch anchoring."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from n170_verify.contracts.assurance import (
    ContractModelMixin,
    SignerTrustStatus,
    parse_utc_timestamp,
    validate_hex_digest,
)
from n170_verify.crypto.signing import (
    SIGNING_DOMAIN_CHECKPOINT,
    ed25519_sign_domain,
    ed25519_verify_domain,
)
from n170_verify.crypto.witness_quorum import NotaryNodeInfo


def format_c2sp_checkpoint_body(origin: str, size: int, hash_b64: str) -> bytes:
    """Format canonical 3-line C2SP ``tlog-checkpoint`` body ``origin\\nsize\\nhash_b64\\n``."""
    if not isinstance(origin, str) or not origin.strip() or "\n" in origin or "\r" in origin:
        raise ValueError("C2SP checkpoint origin must be a non-empty single-line string")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ValueError("C2SP checkpoint size must be a non-negative integer")
    if not isinstance(hash_b64, str) or not hash_b64.strip() or "\n" in hash_b64:
        raise ValueError("C2SP checkpoint hash_b64 must be a non-empty base64 string")
    try:
        raw_hash = base64.b64decode(hash_b64.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("C2SP checkpoint hash_b64 must be valid base64") from exc
    if len(raw_hash) != 32:
        raise ValueError("C2SP checkpoint hash_b64 must decode to 32 bytes (SHA-256)")
    return f"{origin.strip()}\n{size}\n{hash_b64.strip()}\n".encode("utf-8")


def format_c2sp_cosignature_payload(checkpoint_body: bytes, timestamp_utc: str) -> bytes:
    """Format C2SP ``cosignature/v1`` witness message binding timestamp + 3-line checkpoint body."""
    dt = parse_utc_timestamp(timestamp_utc, field_name="cosignature.timestamp_utc")
    unix_seconds = int(dt.timestamp())
    return f"cosignature/v1\ntime {unix_seconds}\n".encode("utf-8") + checkpoint_body


@dataclass(slots=True)
class PublisherKeyRecord(ContractModelMixin):
    """Publisher Ed25519 verification key entry with active/retired/revoked lifecycle windows."""

    publisher_kid: str
    public_key_hex: str
    status: str
    not_before_utc: str
    not_after_utc: str | None = None
    revoked_after_utc: str | None = None
    issuer_org: str = "N170"

    def _validate(self) -> None:
        if not self.publisher_kid.strip():
            raise ValueError("PublisherKeyRecord.publisher_kid must not be empty")
        object.__setattr__(
            self,
            "public_key_hex",
            validate_hex_digest(
                self.public_key_hex, field_name="PublisherKeyRecord.public_key_hex", num_bytes=32
            ),
        )
        norm_status = self.status.strip().lower()
        if norm_status not in {"active", "retired", "revoked"}:
            raise ValueError("PublisherKeyRecord.status must be 'active', 'retired', or 'revoked'")
        object.__setattr__(self, "status", norm_status)

        nb_dt = parse_utc_timestamp(
            self.not_before_utc, field_name="PublisherKeyRecord.not_before_utc"
        )
        if self.not_after_utc is not None:
            na_dt = parse_utc_timestamp(
                self.not_after_utc, field_name="PublisherKeyRecord.not_after_utc"
            )
            if na_dt < nb_dt:
                raise ValueError("PublisherKeyRecord.not_after_utc must be >= not_before_utc")
        if self.revoked_after_utc is not None:
            parse_utc_timestamp(
                self.revoked_after_utc, field_name="PublisherKeyRecord.revoked_after_utc"
            )
        if not self.issuer_org.strip():
            raise ValueError("PublisherKeyRecord.issuer_org must not be empty")


@dataclass(slots=True)
class WitnessCheckpointCosignature(ContractModelMixin):
    """Independent witness cosignature over a C2SP ``tlog-checkpoint``."""

    witness_id: str
    public_key_hex: str
    timestamp_utc: str
    signature_hex: str

    def _validate(self) -> None:
        if not self.witness_id.strip():
            raise ValueError("WitnessCheckpointCosignature.witness_id must not be empty")
        object.__setattr__(
            self,
            "public_key_hex",
            validate_hex_digest(
                self.public_key_hex,
                field_name="WitnessCheckpointCosignature.public_key_hex",
                num_bytes=32,
            ),
        )
        parse_utc_timestamp(
            self.timestamp_utc, field_name="WitnessCheckpointCosignature.timestamp_utc"
        )
        object.__setattr__(
            self,
            "signature_hex",
            validate_hex_digest(
                self.signature_hex,
                field_name="WitnessCheckpointCosignature.signature_hex",
                num_bytes=64,
            ),
        )


@dataclass(slots=True)
class C2SPCheckpoint(ContractModelMixin):
    """Standard C2SP ``tlog-checkpoint`` 3-line body signed by publisher and cosigned by witnesses."""

    origin: str
    size: int
    hash_b64: str
    publisher_kid: str
    publisher_signature_hex: str
    witness_cosignatures: list[WitnessCheckpointCosignature] = field(default_factory=list)

    def _validate(self) -> None:
        format_c2sp_checkpoint_body(self.origin, self.size, self.hash_b64)
        object.__setattr__(self, "origin", self.origin.strip())
        object.__setattr__(self, "hash_b64", self.hash_b64.strip())
        if not self.publisher_kid.strip():
            raise ValueError("C2SPCheckpoint.publisher_kid must not be empty")
        object.__setattr__(
            self,
            "publisher_signature_hex",
            validate_hex_digest(
                self.publisher_signature_hex,
                field_name="C2SPCheckpoint.publisher_signature_hex",
                num_bytes=64,
            ),
        )

    def body_bytes(self) -> bytes:
        return format_c2sp_checkpoint_body(self.origin, self.size, self.hash_b64)

    def body_text(self) -> str:
        return self.body_bytes().decode("utf-8")


def create_signed_c2sp_checkpoint(
    *,
    origin: str,
    size: int,
    root_hash_hex: str,
    publisher_kid: str,
    publisher_private_key_hex: str,
    witness_signers: Sequence[tuple[str, str, str, str]] = (),
) -> C2SPCheckpoint:
    """Create a signed C2SP checkpoint from a 32-byte hex root hash and optional witness cosigners.

    Each tuple in ``witness_signers`` is ``(witness_id, witness_priv_hex, witness_pub_hex, timestamp_utc)``.
    """
    norm_root = validate_hex_digest(root_hash_hex, field_name="root_hash_hex", num_bytes=32)
    hash_b64 = base64.b64encode(bytes.fromhex(norm_root)).decode("ascii")
    body = format_c2sp_checkpoint_body(origin, size, hash_b64)
    pub_sig = ed25519_sign_domain(publisher_private_key_hex, SIGNING_DOMAIN_CHECKPOINT, body)

    cosigs: list[WitnessCheckpointCosignature] = []
    for witness_id, w_priv_hex, w_pub_hex, ts_utc in witness_signers:
        cosig_msg = format_c2sp_cosignature_payload(body, ts_utc)
        w_sig = ed25519_sign_domain(w_priv_hex, SIGNING_DOMAIN_CHECKPOINT, cosig_msg)
        cosigs.append(
            WitnessCheckpointCosignature(
                witness_id=witness_id,
                public_key_hex=w_pub_hex,
                timestamp_utc=ts_utc,
                signature_hex=w_sig,
            )
        )

    return C2SPCheckpoint(
        origin=origin,
        size=size,
        hash_b64=hash_b64,
        publisher_kid=publisher_kid,
        publisher_signature_hex=pub_sig,
        witness_cosignatures=cosigs,
    )


def verify_c2sp_checkpoint(
    checkpoint: C2SPCheckpoint,
    *,
    publisher_public_key_hex: str,
    trusted_witness_keys: Mapping[str, str] | None = None,
    min_witness_cosignatures: int = 0,
) -> tuple[bool, list[str]]:
    """Verify publisher signature and optional witness cosignatures on a C2SP checkpoint."""
    errors: list[str] = []
    body = checkpoint.body_bytes()
    if not ed25519_verify_domain(
        publisher_public_key_hex,
        SIGNING_DOMAIN_CHECKPOINT,
        body,
        checkpoint.publisher_signature_hex,
    ):
        errors.append("C2SP checkpoint publisher signature verification failed")

    valid_witnesses: set[str] = set()
    for cosig in checkpoint.witness_cosignatures:
        expected_pub = cosig.public_key_hex
        if trusted_witness_keys is not None:
            pinned_pub = trusted_witness_keys.get(cosig.witness_id)
            if pinned_pub is None or pinned_pub.strip().lower() != cosig.public_key_hex:
                errors.append(f"Untrusted or mismatched checkpoint witness {cosig.witness_id!r}")
                continue
            expected_pub = pinned_pub
        cosig_msg = format_c2sp_cosignature_payload(body, cosig.timestamp_utc)
        if ed25519_verify_domain(
            expected_pub,
            SIGNING_DOMAIN_CHECKPOINT,
            cosig_msg,
            cosig.signature_hex,
        ):
            valid_witnesses.add(cosig.witness_id)
        else:
            errors.append(f"Invalid checkpoint witness cosignature from {cosig.witness_id!r}")

    if len(valid_witnesses) < min_witness_cosignatures:
        errors.append(
            f"Checkpoint has {len(valid_witnesses)} valid witness cosignatures; "
            f"required >= {min_witness_cosignatures}"
        )

    return len(errors) == 0, errors


@dataclass(slots=True)
class L2BatchAnchor(ContractModelMixin):
    """Periodic EVM L2 batch root anchor (defaulting to Base Mainnet chain_id=8453)."""

    contract_address: str
    tx_hash: str
    batch_merkle_root: str
    chain_id: int = 8453
    block_number: int | None = None
    anchored_at_utc: str | None = None

    def _validate(self) -> None:
        if self.chain_id <= 0:
            raise ValueError("L2BatchAnchor.chain_id must be > 0")
        addr = self.contract_address.strip()
        if not (addr.startswith("0x") and len(addr) == 42):
            raise ValueError("L2BatchAnchor.contract_address must be a 42-char 0x EVM address")
        try:
            bytes.fromhex(addr[2:])
        except ValueError as exc:
            raise ValueError("L2BatchAnchor.contract_address must be hexadecimal") from exc
        tx = self.tx_hash.strip().lower()
        tx_hex = tx[2:] if tx.startswith("0x") else tx
        validate_hex_digest(tx_hex, field_name="L2BatchAnchor.tx_hash", num_bytes=32)
        object.__setattr__(self, "tx_hash", "0x" + tx_hex)
        object.__setattr__(
            self,
            "batch_merkle_root",
            validate_hex_digest(
                self.batch_merkle_root, field_name="L2BatchAnchor.batch_merkle_root", num_bytes=32
            ),
        )
        if self.anchored_at_utc is not None:
            parse_utc_timestamp(
                self.anchored_at_utc, field_name="L2BatchAnchor.anchored_at_utc"
            )


@dataclass(slots=True)
class PublisherKeyRegistryDocument(ContractModelMixin):
    """Canonical ``/.well-known/n170-verify-keys.json`` registry document."""

    updated_at_utc: str
    keys: list[PublisherKeyRecord]
    notaries: list[NotaryNodeInfo] = field(default_factory=list)
    checkpoint: C2SPCheckpoint | None = None
    l2_anchor: L2BatchAnchor | None = None
    pinned_broker_keys: dict[str, dict[str, str]] = field(default_factory=dict)
    schema_version: str = "n170-verify-keys-v3"

    def _validate(self) -> None:
        parse_utc_timestamp(
            self.updated_at_utc, field_name="PublisherKeyRegistryDocument.updated_at_utc"
        )
        seen_kids: set[str] = set()
        for rec in self.keys:
            if rec.publisher_kid in seen_kids:
                raise ValueError(f"Duplicate publisher_kid in registry: {rec.publisher_kid!r}")
            seen_kids.add(rec.publisher_kid)


def evaluate_signer_trust(
    proof_bundle: Any,
    registry_doc: PublisherKeyRegistryDocument | None,
) -> SignerTrustStatus:
    """Evaluate publisher key trust status for a ``VerifyProofBundle`` against ``registry_doc``."""
    if hasattr(proof_bundle, "verify_publisher_signature") and callable(
        proof_bundle.verify_publisher_signature
    ):
        if not proof_bundle.verify_publisher_signature():
            return SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER

    if registry_doc is None:
        return SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER

    key_map = {rec.publisher_kid: rec for rec in registry_doc.keys}

    # If the registry carries a C2SP checkpoint, verify its publisher signature first.
    if registry_doc.checkpoint is not None:
        ckpt_key = key_map.get(registry_doc.checkpoint.publisher_kid)
        if ckpt_key is None or ckpt_key.status == "revoked":
            return SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER
        ckpt_ok, _ = verify_c2sp_checkpoint(
            registry_doc.checkpoint,
            publisher_public_key_hex=ckpt_key.public_key_hex,
        )
        if not ckpt_ok:
            return SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER

    bundle_kid = getattr(proof_bundle, "publisher_kid", "")
    bundle_pub = getattr(proof_bundle, "publisher_public_key_hex", "").strip().lower()
    bundle_issued_str = getattr(proof_bundle, "issued_at_utc", "")

    key_record = key_map.get(bundle_kid)
    if key_record is None or key_record.public_key_hex.lower() != bundle_pub:
        return SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER

    if key_record.status == "revoked":
        return SignerTrustStatus.REVOKED_KEY

    issued_dt = parse_utc_timestamp(bundle_issued_str, field_name="proof_bundle.issued_at_utc")
    not_before_dt = parse_utc_timestamp(key_record.not_before_utc)
    if issued_dt < not_before_dt:
        return SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER

    if key_record.revoked_after_utc is not None:
        revoked_dt = parse_utc_timestamp(key_record.revoked_after_utc)
        if issued_dt >= revoked_dt:
            return SignerTrustStatus.REVOKED_KEY

    if key_record.not_after_utc is not None:
        not_after_dt = parse_utc_timestamp(key_record.not_after_utc)
        if issued_dt > not_after_dt:
            return SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER

    if key_record.status == "retired":
        return SignerTrustStatus.RETIRED_HISTORICAL_VALID

    return SignerTrustStatus.OFFICIAL_N170_HOSTED


__all__ = [
    "C2SPCheckpoint",
    "L2BatchAnchor",
    "PublisherKeyRecord",
    "PublisherKeyRegistryDocument",
    "WitnessCheckpointCosignature",
    "create_signed_c2sp_checkpoint",
    "evaluate_signer_trust",
    "format_c2sp_checkpoint_body",
    "format_c2sp_cosignature_payload",
    "verify_c2sp_checkpoint",
]
