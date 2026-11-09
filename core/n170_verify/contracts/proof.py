"""Complete VerifyProofBundle v3 contract, selective redaction, and end-to-end verification."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from n170_verify.contracts.assurance import (
    AccountScope,
    AssuranceProfile,
    ChainContinuityMode,
    ContractModelMixin,
    EnvironmentTier,
    OriginAssurance,
    ProviderApprovalState,
    SignerTrustStatus,
    parse_utc_timestamp,
    validate_hex_digest,
)
from n170_verify.crypto.canonical import jcs_canonicalize, jcs_sha256_hex
from n170_verify.crypto.chain_invariants import (
    ChainVerificationResult,
    ContinuityLogLeaf,
    ProspectiveChainLink,
    verify_prospective_chain,
)
from n170_verify.crypto.merkle_disclosure import (
    CANONICAL_LEAF_NAMES,
    DisclosedLeaf,
    SaltedMerkleTree,
    build_salted_merkle_tree,
    verify_selective_disclosure,
)
from n170_verify.crypto.publisher_registry import (
    PublisherKeyRegistryDocument,
    evaluate_signer_trust,
)
from n170_verify.crypto.signing import (
    SIGNING_DOMAIN_BUNDLE,
    derive_public_key_hex,
    ed25519_sign_domain,
    ed25519_verify_domain,
)
from n170_verify.crypto.witness_quorum import (
    BrokerNativeSignature,
    WitnessAttestation,
    WitnessQuorumEvaluation,
    evaluate_origin_assurance,
    inspect_transcript_safety,
)


VERIFY_SCHEMA_VERSION = "n170-verify-v3"
ALLOWED_RETENTION_MODES: frozenset[str] = frozenset(
    {
        "no_persistent_storage",
        "opt_in_encrypted_sync",
    }
)


@dataclass(slots=True)
class VerifyProofBundle(ContractModelMixin):
    """Signed N170 Verify v3 proof bundle supporting offline selective leaf disclosure."""

    proof_id: str
    issued_at_utc: str
    publisher_kid: str
    publisher_public_key_hex: str
    broker_id: str
    blinded_account_tag: str
    account_scope: AccountScope
    provider_approval_state: ProviderApprovalState
    environment_tier: EnvironmentTier
    claimed_origin_assurance: OriginAssurance
    source_body_sha256: str
    period_start_utc: str
    period_end_utc: str
    base_currency: str
    merkle_root: str
    signature_hex: str
    schema_version: str = VERIFY_SCHEMA_VERSION
    disclosed_leaves: list[DisclosedLeaf] = field(default_factory=list)
    undisclosed_leaf_hashes: dict[str, str] = field(default_factory=dict)
    witness_attestations: list[WitnessAttestation] = field(default_factory=list)
    broker_native_signature: BrokerNativeSignature | None = None
    prospective_chain_link: ProspectiveChainLink | None = None
    retention_mode: str = "no_persistent_storage"

    def _validate(self) -> None:
        if not self.proof_id.strip():
            raise ValueError("VerifyProofBundle.proof_id must not be empty")
        if not self.schema_version.strip():
            raise ValueError("VerifyProofBundle.schema_version must not be empty")
        parse_utc_timestamp(self.issued_at_utc, field_name="VerifyProofBundle.issued_at_utc")
        if not self.publisher_kid.strip():
            raise ValueError("VerifyProofBundle.publisher_kid must not be empty")
        object.__setattr__(
            self,
            "publisher_public_key_hex",
            validate_hex_digest(
                self.publisher_public_key_hex,
                field_name="VerifyProofBundle.publisher_public_key_hex",
                num_bytes=32,
            ),
        )
        if not self.broker_id.strip():
            raise ValueError("VerifyProofBundle.broker_id must not be empty")
        object.__setattr__(self, "broker_id", self.broker_id.strip().lower())
        object.__setattr__(
            self,
            "blinded_account_tag",
            validate_hex_digest(
                self.blinded_account_tag,
                field_name="VerifyProofBundle.blinded_account_tag",
                num_bytes=32,
            ),
        )
        object.__setattr__(
            self,
            "source_body_sha256",
            validate_hex_digest(
                self.source_body_sha256,
                field_name="VerifyProofBundle.source_body_sha256",
                num_bytes=32,
            ),
        )
        start_dt = parse_utc_timestamp(
            self.period_start_utc, field_name="VerifyProofBundle.period_start_utc"
        )
        end_dt = parse_utc_timestamp(
            self.period_end_utc, field_name="VerifyProofBundle.period_end_utc"
        )
        if end_dt < start_dt:
            raise ValueError("VerifyProofBundle.period_end_utc must be >= period_start_utc")
        cleaned_ccy = self.base_currency.strip().upper()
        if not (2 <= len(cleaned_ccy) <= 12) or not cleaned_ccy.isalnum():
            raise ValueError("VerifyProofBundle.base_currency must be an alphanumeric currency code")
        object.__setattr__(self, "base_currency", cleaned_ccy)
        object.__setattr__(
            self,
            "merkle_root",
            validate_hex_digest(
                self.merkle_root, field_name="VerifyProofBundle.merkle_root", num_bytes=32
            ),
        )
        norm_undisclosed: dict[str, str] = {}
        for k, v in self.undisclosed_leaf_hashes.items():
            norm_undisclosed[k] = validate_hex_digest(
                v, field_name=f"undisclosed_leaf_hashes[{k!r}]", num_bytes=32
            )
        object.__setattr__(self, "undisclosed_leaf_hashes", norm_undisclosed)

        norm_retention = self.retention_mode.strip().lower()
        if norm_retention not in ALLOWED_RETENTION_MODES:
            raise ValueError(
                f"VerifyProofBundle.retention_mode must be one of {sorted(ALLOWED_RETENTION_MODES)}"
            )
        object.__setattr__(self, "retention_mode", norm_retention)
        object.__setattr__(
            self,
            "signature_hex",
            validate_hex_digest(
                self.signature_hex, field_name="VerifyProofBundle.signature_hex", num_bytes=64
            ),
        )

    def signable_header(self) -> dict[str, Any]:
        """Return canonical signable header committed by ``signature_hex`` and chain ``prev_proof_hash``.

        Because all leaf payloads and 256-bit salts are committed inside ``merkle_root``,
        holders can redact leaves from ``disclosed_leaves`` into ``undisclosed_leaf_hashes``
        without invalidating the publisher signature or chain hash links.
        """
        return {
            "account_scope": self.account_scope.value,
            "base_currency": self.base_currency,
            "blinded_account_tag": self.blinded_account_tag,
            "broker_id": self.broker_id,
            "broker_native_signature": (
                self.broker_native_signature.to_dict()
                if self.broker_native_signature is not None
                else None
            ),
            "claimed_origin_assurance": self.claimed_origin_assurance.value,
            "environment_tier": self.environment_tier.value,
            "issued_at_utc": self.issued_at_utc,
            "merkle_root": self.merkle_root,
            "period_end_utc": self.period_end_utc,
            "period_start_utc": self.period_start_utc,
            "proof_id": self.proof_id,
            "prospective_chain_link": (
                self.prospective_chain_link.to_dict()
                if self.prospective_chain_link is not None
                else None
            ),
            "provider_approval_state": self.provider_approval_state.value,
            "publisher_kid": self.publisher_kid,
            "publisher_public_key_hex": self.publisher_public_key_hex,
            "retention_mode": self.retention_mode,
            "schema_version": self.schema_version,
            "source_body_sha256": self.source_body_sha256,
            "witness_attestations": [att.to_dict() for att in self.witness_attestations],
        }

    def signable_bytes(self) -> bytes:
        return jcs_canonicalize(self.signable_header())

    def proof_hash(self) -> str:
        """Return ``SHA256(JCS(signable_header))`` used for ``prev_proof_hash`` and continuity logs."""
        return jcs_sha256_hex(self.signable_header())

    def verify_publisher_signature(self) -> bool:
        """Verify domain-separated Ed25519 signature over ``signable_header()``."""
        return ed25519_verify_domain(
            self.publisher_public_key_hex,
            SIGNING_DOMAIN_BUNDLE,
            self.signable_bytes(),
            self.signature_hex,
        )

    def redact_leaves(self, leaf_names_to_hide: Iterable[str]) -> VerifyProofBundle:
        """Return a new ``VerifyProofBundle`` with selected leaves redacted (salts & payloads stripped)."""
        hide_set = set(leaf_names_to_hide)
        unknown = hide_set - set(CANONICAL_LEAF_NAMES)
        if unknown:
            raise ValueError(f"Cannot redact unknown canonical leaf name(s): {sorted(unknown)}")

        kept_disclosed: list[DisclosedLeaf] = []
        updated_undisclosed: dict[str, str] = dict(self.undisclosed_leaf_hashes)
        for leaf in self.disclosed_leaves:
            if leaf.leaf_name in hide_set:
                updated_undisclosed[leaf.leaf_name] = leaf.leaf_hash_hex
            else:
                kept_disclosed.append(leaf)

        return VerifyProofBundle(
            proof_id=self.proof_id,
            schema_version=self.schema_version,
            issued_at_utc=self.issued_at_utc,
            publisher_kid=self.publisher_kid,
            publisher_public_key_hex=self.publisher_public_key_hex,
            broker_id=self.broker_id,
            blinded_account_tag=self.blinded_account_tag,
            account_scope=self.account_scope,
            provider_approval_state=self.provider_approval_state,
            environment_tier=self.environment_tier,
            claimed_origin_assurance=self.claimed_origin_assurance,
            source_body_sha256=self.source_body_sha256,
            period_start_utc=self.period_start_utc,
            period_end_utc=self.period_end_utc,
            base_currency=self.base_currency,
            merkle_root=self.merkle_root,
            disclosed_leaves=kept_disclosed,
            undisclosed_leaf_hashes=updated_undisclosed,
            witness_attestations=list(self.witness_attestations),
            broker_native_signature=self.broker_native_signature,
            prospective_chain_link=self.prospective_chain_link,
            retention_mode=self.retention_mode,
            signature_hex=self.signature_hex,
        )

    def get_disclosed_payload(self, leaf_name: str) -> Any:
        """Return payload of a disclosed leaf or raise ``KeyError`` if undisclosed."""
        for leaf in self.disclosed_leaves:
            if leaf.leaf_name == leaf_name:
                return leaf.payload
        raise KeyError(f"Leaf {leaf_name!r} is not disclosed in this proof bundle")


def create_signed_proof_bundle(
    *,
    proof_id: str,
    issued_at_utc: str,
    publisher_kid: str,
    publisher_private_key_hex: str,
    broker_id: str,
    blinded_account_tag: str,
    account_scope: AccountScope,
    provider_approval_state: ProviderApprovalState,
    environment_tier: EnvironmentTier,
    claimed_origin_assurance: OriginAssurance,
    source_body_sha256: str,
    period_start_utc: str,
    period_end_utc: str,
    base_currency: str,
    leaf_payloads: Mapping[str, Any] | None = None,
    merkle_tree: SaltedMerkleTree | None = None,
    disclose_leaf_names: Iterable[str] | None = None,
    witness_attestations: Sequence[WitnessAttestation] = (),
    broker_native_signature: BrokerNativeSignature | None = None,
    prospective_chain_link: ProspectiveChainLink | None = None,
    retention_mode: str = "no_persistent_storage",
    schema_version: str = VERIFY_SCHEMA_VERSION,
) -> VerifyProofBundle:
    """Construct a salted 7-leaf Merkle tree, selectively disclose leaves, and Ed25519-sign the bundle."""
    if merkle_tree is None:
        if leaf_payloads is None:
            raise ValueError("Either leaf_payloads or merkle_tree must be provided")
        tree = build_salted_merkle_tree(leaf_payloads)
    else:
        tree = merkle_tree

    disclosed, undisclosed = tree.selectively_disclose(disclose_leaf_names)
    pub_hex = derive_public_key_hex(publisher_private_key_hex)

    # Assemble unsigned placeholder with dummy signature to validate & serialize header cleanly.
    dummy_sig = "00" * 64
    draft = VerifyProofBundle(
        proof_id=proof_id,
        schema_version=schema_version,
        issued_at_utc=issued_at_utc,
        publisher_kid=publisher_kid,
        publisher_public_key_hex=pub_hex,
        broker_id=broker_id,
        blinded_account_tag=blinded_account_tag,
        account_scope=account_scope,
        provider_approval_state=provider_approval_state,
        environment_tier=environment_tier,
        claimed_origin_assurance=claimed_origin_assurance,
        source_body_sha256=source_body_sha256,
        period_start_utc=period_start_utc,
        period_end_utc=period_end_utc,
        base_currency=base_currency,
        merkle_root=tree.merkle_root,
        disclosed_leaves=disclosed,
        undisclosed_leaf_hashes=undisclosed,
        witness_attestations=list(witness_attestations),
        broker_native_signature=broker_native_signature,
        prospective_chain_link=prospective_chain_link,
        retention_mode=retention_mode,
        signature_hex=dummy_sig,
    )
    sig_hex = ed25519_sign_domain(
        publisher_private_key_hex,
        SIGNING_DOMAIN_BUNDLE,
        draft.signable_bytes(),
    )
    object.__setattr__(draft, "signature_hex", sig_hex)
    return draft


@dataclass(slots=True)
class BundleVerificationResult(ContractModelMixin):
    """Comprehensive verification outcome with dynamically derived six-axis assurance profile."""

    valid: bool
    proof_id: str
    proof_hash: str
    signature_valid: bool
    merkle_valid: bool
    transcript_safety_ok: bool
    signer_trust_status: SignerTrustStatus
    effective_origin_assurance: OriginAssurance
    effective_chain_continuity_mode: ChainContinuityMode
    assurance_profile: AssuranceProfile
    disclosed_leaf_names: list[str]
    undisclosed_leaf_names: list[str]
    witness_quorum: WitnessQuorumEvaluation
    chain_verification: ChainVerificationResult | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def verify_proof_bundle(
    bundle: VerifyProofBundle | Mapping[str, Any],
    registry_doc: PublisherKeyRegistryDocument | None = None,
    chain_history: Sequence[VerifyProofBundle] | None = None,
    continuity_log_leaves: Sequence[ContinuityLogLeaf] | None = None,
    now_utc: str | datetime | None = None,
) -> BundleVerificationResult:
    """Verify a ``VerifyProofBundle`` end-to-end without trusting self-asserted origin claims."""
    proof_bundle = (
        bundle if isinstance(bundle, VerifyProofBundle) else VerifyProofBundle.from_dict(bundle)
    )
    errors: list[str] = []
    warnings: list[str] = []

    schema_ok = proof_bundle.schema_version == VERIFY_SCHEMA_VERSION
    if not schema_ok:
        errors.append(
            f"Unsupported schema_version {proof_bundle.schema_version!r}; expected {VERIFY_SCHEMA_VERSION!r}"
        )

    env_ok = proof_bundle.environment_tier == EnvironmentTier.LIVE_PRODUCTION
    if not env_ok:
        errors.append("Bundle environment_tier is paper_or_sandbox_rejected")

    signature_valid = proof_bundle.verify_publisher_signature()
    if not signature_valid:
        errors.append("Publisher Ed25519 signature verification failed")

    merkle_valid, merkle_errors = verify_selective_disclosure(
        proof_bundle.merkle_root,
        proof_bundle.disclosed_leaves,
        proof_bundle.undisclosed_leaf_hashes,
    )
    if not merkle_valid:
        errors.extend(merkle_errors)

    transcript_safety_ok = True
    for att in proof_bundle.witness_attestations:
        att_safe, att_violations = inspect_transcript_safety(att)
        if not att_safe:
            transcript_safety_ok = False
            errors.extend(att_violations)

    signer_trust = evaluate_signer_trust(proof_bundle, registry_doc)
    if signer_trust == SignerTrustStatus.REVOKED_KEY:
        errors.append(f"Publisher signing key {proof_bundle.publisher_kid!r} is revoked")

    publisher_org = "N170"
    notaries = ()
    pinned_broker_keys = None
    if registry_doc is not None:
        notaries = registry_doc.notaries
        pinned_broker_keys = registry_doc.pinned_broker_keys
        for rec in registry_doc.keys:
            if rec.publisher_kid == proof_bundle.publisher_kid:
                publisher_org = rec.issuer_org
                break

    witness_eval = evaluate_origin_assurance(
        source_body_sha256=proof_bundle.source_body_sha256,
        broker_id=proof_bundle.broker_id,
        signer_trust=signer_trust,
        publisher_kid=proof_bundle.publisher_kid,
        publisher_public_key_hex=proof_bundle.publisher_public_key_hex,
        publisher_org=publisher_org,
        environment_tier=proof_bundle.environment_tier,
        provider_approval_state=proof_bundle.provider_approval_state,
        claimed_origin_assurance=proof_bundle.claimed_origin_assurance,
        witness_attestations=proof_bundle.witness_attestations,
        notary_registry=notaries,
        broker_native_signature=proof_bundle.broker_native_signature,
        pinned_broker_keys=pinned_broker_keys,
    )
    effective_origin = witness_eval.effective_origin_assurance
    if effective_origin != proof_bundle.claimed_origin_assurance:
        warnings.append(
            f"Origin assurance dynamically evaluated as {effective_origin.value} "
            f"(bundle claimed {proof_bundle.claimed_origin_assurance.value})"
        )
        warnings.extend(witness_eval.downgrade_reasons)

    chain_result: ChainVerificationResult | None = None
    if proof_bundle.prospective_chain_link is None and not chain_history:
        continuity_mode = ChainContinuityMode.UNENROLLED_SINGLE_SNAPSHOT
        if continuity_log_leaves:
            # Check if account was previously enrolled in continuity log while presenting an unenrolled snapshot!
            enrolled_entries = [
                leaf
                for leaf in continuity_log_leaves
                if leaf.blinded_account_tag == proof_bundle.blinded_account_tag
            ]
            if enrolled_entries:
                continuity_mode = ChainContinuityMode.CONTINUITY_BROKEN
                errors.append(
                    "Account has enrolled continuity log entries but presented an unenrolled snapshot"
                )
    else:
        chain_elements = list(chain_history or [])
        if not chain_elements or chain_elements[-1].proof_id != proof_bundle.proof_id:
            chain_elements.append(proof_bundle)
        chain_result = verify_prospective_chain(
            chain_elements,
            continuity_log_leaves=continuity_log_leaves,
            now_utc=now_utc,
        )
        continuity_mode = chain_result.continuity_mode
        if continuity_mode == ChainContinuityMode.CONTINUITY_BROKEN:
            errors.extend(chain_result.details)
        elif continuity_mode == ChainContinuityMode.RETROSPECTIVE_BACKFILL:
            warnings.extend(chain_result.details)

    overall_valid = (
        schema_ok
        and env_ok
        and signature_valid
        and merkle_valid
        and transcript_safety_ok
        and signer_trust != SignerTrustStatus.REVOKED_KEY
        and continuity_mode != ChainContinuityMode.CONTINUITY_BROKEN
    )

    profile = AssuranceProfile(
        effective_origin_assurance=effective_origin,
        account_scope=proof_bundle.account_scope,
        provider_approval_state=proof_bundle.provider_approval_state,
        environment_tier=proof_bundle.environment_tier,
        signer_trust_status=signer_trust,
        chain_continuity_mode=continuity_mode,
    )

    return BundleVerificationResult(
        valid=overall_valid,
        proof_id=proof_bundle.proof_id,
        proof_hash=proof_bundle.proof_hash(),
        signature_valid=signature_valid,
        merkle_valid=merkle_valid,
        transcript_safety_ok=transcript_safety_ok,
        signer_trust_status=signer_trust,
        effective_origin_assurance=effective_origin,
        effective_chain_continuity_mode=continuity_mode,
        assurance_profile=profile,
        disclosed_leaf_names=[leaf.leaf_name for leaf in proof_bundle.disclosed_leaves],
        undisclosed_leaf_names=sorted(proof_bundle.undisclosed_leaf_hashes.keys()),
        witness_quorum=witness_eval,
        chain_verification=chain_result,
        errors=list(dict.fromkeys(errors)),
        warnings=list(dict.fromkeys(warnings)),
    )


__all__ = [
    "ALLOWED_RETENTION_MODES",
    "BundleVerificationResult",
    "VERIFY_SCHEMA_VERSION",
    "VerifyProofBundle",
    "create_signed_proof_bundle",
    "verify_proof_bundle",
]
