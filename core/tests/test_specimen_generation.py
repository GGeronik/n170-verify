"""Comprehensive tests for deterministic specimen generation and verification."""

import copy
import json
import pytest
from n170_verify.contracts import (
    AccountScope,
    ChainContinuityMode,
    EnvironmentTier,
    OriginAssurance,
    ProviderApprovalState,
    SignerTrustStatus,
    VerifyProofBundle,
    verify_proof_bundle,
)
from n170_verify.crypto import (
    CANONICAL_LEAF_NAMES,
    verify_c2sp_checkpoint,
)
from n170_verify.specimens.generator import (
    DEFAULT_SPECIMEN_SEED_HEX,
    generate_specimens,
)


class TestSpecimenGeneration:
    """Test suite for deterministic specimen generation and verification."""

    def test_deterministic_generation(self):
        seed1 = "11" * 32
        res1 = generate_specimens(seed_hex=seed1)
        res2 = generate_specimens(seed_hex=seed1)

        assert res1.bundle_s1.proof_id == res2.bundle_s1.proof_id
        assert res1.bundle_s1.merkle_root == res2.bundle_s1.merkle_root
        assert res1.bundle_s1.signature_hex == res2.bundle_s1.signature_hex
        assert res1.registry.checkpoint.publisher_signature_hex == res2.registry.checkpoint.publisher_signature_hex

        # Different seed produces different keys and signatures
        seed2 = "22" * 32
        res3 = generate_specimens(seed_hex=seed2)
        assert res1.bundle_s1.publisher_kid == res3.bundle_s1.publisher_kid
        assert res1.bundle_s1.signature_hex != res3.bundle_s1.signature_hex

    def test_specimen_s1_full_verification(self):
        res = generate_specimens(seed_hex=DEFAULT_SPECIMEN_SEED_HEX)
        bundle = res.bundle_s1
        registry = res.registry

        v_res = verify_proof_bundle(bundle, registry_doc=registry, now_utc="2026-04-02T00:00:00Z")
        assert v_res.valid is True
        assert len(v_res.errors) == 0
        assert len(v_res.proof_hash) == 64

        # 6-axis parity checks
        assert v_res.effective_origin_assurance == OriginAssurance.INDEPENDENTLY_WITNESSED_TLS
        assert v_res.assurance_profile.account_scope == AccountScope.ALL_ENUMERATED_SUBACCOUNTS
        assert v_res.assurance_profile.provider_approval_state == ProviderApprovalState.APPROVED_LIVE
        assert v_res.assurance_profile.environment_tier == EnvironmentTier.LIVE_PRODUCTION
        assert v_res.signer_trust_status == SignerTrustStatus.OFFICIAL_N170_HOSTED
        assert v_res.effective_chain_continuity_mode == ChainContinuityMode.UNENROLLED_SINGLE_SNAPSHOT

        # 3 disjoint notaries
        assert v_res.witness_quorum.disjoint_quorum_size == 3
        assert len(bundle.witness_attestations) == 3

        # All 7 leaves disclosed
        disclosed_names = [leaf.leaf_name for leaf in bundle.disclosed_leaves]
        assert set(disclosed_names) == set(CANONICAL_LEAF_NAMES)

    def test_specimen_offline_unverified_tier(self):
        res = generate_specimens(seed_hex=DEFAULT_SPECIMEN_SEED_HEX)
        offline_bundle = res.bundle_offline
        registry = res.registry

        assert offline_bundle.environment_tier == EnvironmentTier.UNVERIFIED_OFFLINE
        assert offline_bundle.provider_approval_state == ProviderApprovalState.OFFLINE_EXPORT_ONLY
        assert offline_bundle.claimed_origin_assurance == OriginAssurance.SELF_REPORTED

        # Publisher signature is valid
        assert offline_bundle.verify_publisher_signature() is True

        # Verify offline bundle with verify_proof_bundle
        v_res = verify_proof_bundle(offline_bundle, registry_doc=registry, now_utc="2026-04-02T00:00:00Z")
        assert v_res.assurance_profile.environment_tier == EnvironmentTier.UNVERIFIED_OFFLINE
        assert v_res.effective_origin_assurance == OriginAssurance.SELF_REPORTED
        # Non-live tier is rejected by the live production verification gate per contracts
        assert v_res.valid is False
        assert any("paper_or_sandbox_rejected" in err for err in v_res.errors)

    def test_tampered_specimen_s1_rejected(self):
        res = generate_specimens(seed_hex=DEFAULT_SPECIMEN_SEED_HEX)
        bundle = res.bundle_s1
        registry = res.registry

        # 1. Tamper with Merkle leaf payload
        bundle_dict = bundle.to_dict()
        for leaf in bundle_dict["disclosed_leaves"]:
            if leaf["leaf_name"] == "core_metrics":
                leaf["payload"]["twr_decimal"] = 0.999
        tampered_bundle = VerifyProofBundle.from_dict(bundle_dict)

        v_res = verify_proof_bundle(tampered_bundle, registry_doc=registry, now_utc="2026-04-02T00:00:00Z")
        assert v_res.valid is False
        assert any("merkle" in err.lower() for err in v_res.errors)

        # 2. Tamper with publisher signature
        bundle_dict2 = bundle.to_dict()
        bundle_dict2["signature_hex"] = "00" * 64
        tampered_bundle2 = VerifyProofBundle.from_dict(bundle_dict2)

        v_res2 = verify_proof_bundle(tampered_bundle2, registry_doc=registry, now_utc="2026-04-02T00:00:00Z")
        assert v_res2.valid is False
        assert any("signature" in err.lower() for err in v_res2.errors)

    def test_registry_checkpoint_verification(self):
        res = generate_specimens(seed_hex=DEFAULT_SPECIMEN_SEED_HEX)
        registry = res.registry
        ckpt = registry.checkpoint

        assert ckpt.origin == "n170.verify/transparency/v3"
        assert ckpt.size == 1284
        assert len(ckpt.witness_cosignatures) == 2

        # Verify checkpoint
        active_key = next(k for k in registry.keys if k.publisher_kid == ckpt.publisher_kid)

        valid, reasons = verify_c2sp_checkpoint(
            ckpt,
            publisher_public_key_hex=active_key.public_key_hex,
            trusted_witness_keys={w.witness_id: w.public_key_hex for w in ckpt.witness_cosignatures},
        )
        assert valid is True
        assert len(reasons) == 0
