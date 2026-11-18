"""A holder name on a record is reported as self-asserted and is not part of ``valid``.

The holder attestation is signed by a key that nothing ties to the broker account
or wallet the record describes. ``valid`` therefore describes the record only
(publisher signature, Merkle proofs, registry, chain and the other record
checks); the holder claim is reported on its own as absent, self-asserted or
invalid, and an invalid attestation never yields a name.
"""

from __future__ import annotations

import dataclasses
import unittest

from n170_verify.contracts import (
    SIGNING_DOMAIN_HOLDER,
    AccountScope,
    EnvironmentTier,
    HolderIdentityAttestation,
    OriginAssurance,
    ProviderApprovalState,
    VerifyProofBundle,
    create_signed_proof_bundle,
    verify_proof_bundle,
)
from n170_verify.crypto.canonical import jcs_canonicalize
from n170_verify.crypto import CANONICAL_LEAF_NAMES
from n170_verify.crypto.signing import ed25519_sign_domain, generate_ed25519_keypair

NOW = "2026-03-01T00:00:00Z"


def _bundle(proof_id: str = "prf-holder-semantics-001") -> VerifyProofBundle:
    publisher = generate_ed25519_keypair()
    return create_signed_proof_bundle(
        proof_id=proof_id,
        issued_at_utc="2026-02-01T00:05:00Z",
        publisher_kid="dummy-publisher-kid",
        publisher_private_key_hex=publisher.private_key_hex,
        broker_id="dummybroker",
        blinded_account_tag="ab" * 32,
        account_scope=AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED,
        provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
        environment_tier=EnvironmentTier.LIVE_PRODUCTION,
        claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
        source_body_sha256="cd" * 32,
        period_start_utc="2026-01-01T00:00:00Z",
        period_end_utc="2026-01-31T23:59:59Z",
        base_currency="USD",
        leaf_payloads={name: {"placeholder": name} for name in CANONICAL_LEAF_NAMES},
    )


def _attestation_for(target: VerifyProofBundle, name: str) -> HolderIdentityAttestation:
    """A holder attestation over ``target`` signed by a fresh dummy key."""
    holder = generate_ed25519_keypair()
    draft = HolderIdentityAttestation(
        display_name=name,
        proof_id=target.proof_id,
        proof_hash=target.proof_hash(),
        merkle_root=target.merkle_root,
        claimed_at_utc=NOW,
        holder_public_key_hex=holder.public_key_hex,
        signature_hex="00" * 64,
    )
    sig = ed25519_sign_domain(
        holder.private_key_hex, SIGNING_DOMAIN_HOLDER, jcs_canonicalize(draft.signable_claim())
    )
    return dataclasses.replace(draft, signature_hex=sig)


def _with_holder(bundle: VerifyProofBundle, att: HolderIdentityAttestation) -> VerifyProofBundle:
    data = bundle.to_dict()
    data["holder_identity"] = att.to_dict()
    return VerifyProofBundle.from_dict(data)


class HolderClaimIsReportedSeparatelyFromValidTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bundle = _bundle()
        self.base = verify_proof_bundle(self.bundle, now_utc=NOW)

    def test_record_without_holder_reports_absent(self) -> None:
        self.assertTrue(self.base.valid, self.base.errors)
        self.assertEqual(getattr(self.base, "holder_claim_status", None), "absent")
        self.assertIsNone(self.base.holder_display_name)
        self.assertFalse(any("holder" in w.lower() for w in self.base.warnings))

    def test_correct_holder_signature_is_self_asserted_and_leaves_valid_unchanged(self) -> None:
        res = verify_proof_bundle(
            _with_holder(self.bundle, _attestation_for(self.bundle, "Dummy Holder")), now_utc=NOW
        )
        self.assertEqual(res.valid, self.base.valid)
        self.assertEqual(res.errors, self.base.errors)
        self.assertEqual(getattr(res, "holder_claim_status", None), "self_asserted")
        self.assertEqual(res.holder_claim_status.value, "self_asserted")
        self.assertEqual(res.holder_display_name, "Dummy Holder")
        self.assertTrue(any("self-asserted" in w for w in res.warnings), res.warnings)
        self.assertEqual(res.to_dict()["holder_claim_status"], "self_asserted")

    def test_two_different_names_on_one_record_give_the_same_record_verdict(self) -> None:
        first = verify_proof_bundle(
            _with_holder(self.bundle, _attestation_for(self.bundle, "Dummy One")), now_utc=NOW
        )
        second = verify_proof_bundle(
            _with_holder(self.bundle, _attestation_for(self.bundle, "Dummy Two")), now_utc=NOW
        )
        self.assertEqual(first.valid, second.valid)
        self.assertEqual(getattr(first, "holder_claim_status", None), "self_asserted")
        self.assertEqual(getattr(second, "holder_claim_status", None), "self_asserted")

    def test_bad_holder_signature_is_invalid_claim_and_does_not_change_valid(self) -> None:
        att = _attestation_for(self.bundle, "Dummy Holder")
        broken = dataclasses.replace(att, signature_hex="11" * 64)
        res = verify_proof_bundle(_with_holder(self.bundle, broken), now_utc=NOW)
        self.assertTrue(res.valid, res.errors)
        self.assertEqual(res.errors, self.base.errors)
        self.assertEqual(getattr(res, "holder_claim_status", None), "invalid")
        self.assertNotEqual(getattr(res, "holder_claim_status", None), "self_asserted")
        self.assertIsNone(res.holder_display_name)
        self.assertTrue(any("holder" in w.lower() and "invalid" in w.lower() for w in res.warnings))
        self.assertFalse(any("self-asserted" in w for w in res.warnings))

    def test_a_holder_claim_with_a_format_character_is_invalid(self) -> None:
        # Bidi controls, zero-width characters, the soft hyphen, word joiners, the byte
        # order mark and tag characters (Unicode category Cf), assembled at run time.
        format_chars = ["‮", "‪", "⁦", "⁩", "؜", "​", "‏",
                        "⁠", "⁤", "﻿", "­", chr(0xE0041)]
        # (A handle is already limited to ASCII letters, digits and _ . - by its own rule.)
        for ch in [""] + format_chars:
            for field, value in (("display_name", f"Ana{ch} Trader"), ("display_name", f"{ch}deifirev"),
                                 ("profile_url", f"https://example.invalid/{ch}ana")):
                with self.subTest(char=f"U+{ord(ch):04X}" if ch else "none", field=field, value=repr(value)):
                    holder = generate_ed25519_keypair()
                    claim = _attestation_for(self.bundle, "Ana Trader").to_dict()
                    claim.pop("signature_hex")
                    claim.update({field: value, "holder_public_key_hex": holder.public_key_hex})
                    claim["signature_hex"] = ed25519_sign_domain(
                        holder.private_key_hex, SIGNING_DOMAIN_HOLDER, jcs_canonicalize(claim)
                    )
                    data = self.bundle.to_dict()
                    data["holder_identity"] = claim
                    res = verify_proof_bundle(VerifyProofBundle.from_dict(data), now_utc=NOW)
                    self.assertTrue(res.valid, res.errors)
                    if not ch:  # the same claim without a format character is self-asserted
                        self.assertEqual(res.holder_claim_status.value, "self_asserted")
                        continue
                    self.assertEqual(res.holder_claim_status.value, "invalid")
                    self.assertIsNone(res.holder_display_name)

    def test_attestation_for_another_record_is_invalid_claim(self) -> None:
        other = _bundle(proof_id="prf-holder-semantics-other")
        res = verify_proof_bundle(
            _with_holder(self.bundle, _attestation_for(other, "Dummy Holder")), now_utc=NOW
        )
        self.assertTrue(res.valid, res.errors)
        self.assertEqual(getattr(res, "holder_claim_status", None), "invalid")
        self.assertIsNone(res.holder_display_name)

    def test_self_asserted_holder_never_rescues_a_record_that_fails_its_own_checks(self) -> None:
        tampered = dataclasses.replace(self.bundle, base_currency="EUR")
        res = verify_proof_bundle(
            _with_holder(tampered, _attestation_for(tampered, "Dummy Holder")), now_utc=NOW
        )
        self.assertFalse(res.signature_valid)
        self.assertFalse(res.valid)
        self.assertEqual(getattr(res, "holder_claim_status", None), "self_asserted")


if __name__ == "__main__":
    unittest.main()
