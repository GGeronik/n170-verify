"""A published record cannot be changed by posting it again.

``proof_hash`` covers the signed header only. The holder name and which leaves
are disclosed sit outside it, so a second post of the same record with another
name, fewer disclosed leaves or the leaderboard flag set carries the same hash.
The store must treat such a post as "already published" and change nothing.
"""

from __future__ import annotations

import unittest

from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from n170_verify.contracts import (
    AccountScope,
    EnvironmentTier,
    OriginAssurance,
    ProviderApprovalState,
    VerifyProofBundle,
    create_signed_proof_bundle,
)
from n170_verify.contracts.proof import HOLDER_SCHEMA_VERSION, SIGNING_DOMAIN_HOLDER
from n170_verify.crypto import generate_ed25519_keypair
from n170_verify.crypto.canonical import jcs_canonicalize
from n170_verify.crypto.signing import ed25519_sign_domain

try:
    from tests.test_api_lifecycle_and_security import _build_leaf_payloads
except ImportError:  # run with api/tests on the path, as CI does
    from test_api_lifecycle_and_security import _build_leaf_payloads

LEADERBOARD_ALL = "/api/v1/leaderboard?min_capital_bracket=under_1k&include_private_bracket=true"


def _holder_claim(bundle: VerifyProofBundle, name: str, seed_byte: str) -> dict:
    """A holder claim signed by a fresh key, exactly as any browser can make one."""
    keypair = generate_ed25519_keypair(bytes.fromhex(seed_byte * 32))
    claim = {
        "claimed_at_utc": "2026-02-10T12:00:00Z",
        "display_name": name,
        "handle": None,
        "holder_public_key_hex": keypair.public_key_hex,
        "merkle_root": bundle.merkle_root,
        "profile_url": None,
        "proof_hash": bundle.proof_hash(),
        "proof_id": bundle.proof_id,
        "schema_version": HOLDER_SCHEMA_VERSION,
    }
    claim["signature_hex"] = ed25519_sign_domain(
        keypair.private_key_hex, SIGNING_DOMAIN_HOLDER, jcs_canonicalize(claim)
    )
    return claim


class TestPublishedRecordIsImmutable(unittest.TestCase):
    def setUp(self) -> None:
        self.publisher = generate_ed25519_keypair(bytes.fromhex("11" * 32))
        self.config = ApiConfig(
            publisher_keypair=self.publisher,
            publisher_kid="n170-active-2026",
            publisher_key_not_before_utc="2025-01-01T00:00:00Z",
            hosted_multi_user_mode=True,
            db_path=":memory:",
            sync_db_path=":memory:",
            vault_master_kek_hex="aa" * 32,
            account_blinding_salt_hex="bb" * 32,
        )
        self.client = VerifyApiTestClient(create_app(self.config, prefer_fastapi=False))

    def _signed_bundle(self, proof_id: str) -> VerifyProofBundle:
        return create_signed_proof_bundle(
            proof_id=proof_id,
            issued_at_utc="2026-02-10T12:00:00Z",
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.publisher.private_key_hex,
            broker_id="schwab",
            blinded_account_tag="12" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="34" * 32,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-02-10T00:00:00Z",
            base_currency="USD",
            leaf_payloads=_build_leaf_payloads(),
        )

    def _stored(self, proof_id: str) -> dict:
        response = self.client.get(f"/api/v1/proofs/{proof_id}")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        return body.get("proof_bundle") or body

    def _leaderboard_count(self) -> int:
        response = self.client.get(LEADERBOARD_ALL)
        self.assertEqual(response.status_code, 200, response.text)
        return int(response.json()["count"])

    def test_second_post_cannot_replace_the_holder_strip_leaves_or_list_the_record(self) -> None:
        bundle = self._signed_bundle("prf-immutable-claimed")
        first = bundle.to_dict()
        first["holder_identity"] = _holder_claim(bundle, "Alice Owner", "41")
        published = self.client.post(
            "/api/v1/proofs", json={"proof_bundle": first, "opt_in_leaderboard": False}
        )
        self.assertEqual(published.status_code, 201, published.text)

        before = self._stored(bundle.proof_id)
        self.assertEqual(before["holder_identity"]["display_name"], "Alice Owner")
        disclosed_before = len(before["disclosed_leaves"])
        self.assertGreater(disclosed_before, 0)
        self.assertEqual(self._leaderboard_count(), 0)

        # Someone else copies the public record, hides every leaf, signs their
        # own name with their own key and asks for the leaderboard.
        stripped = bundle.redact_leaves([leaf.leaf_name for leaf in bundle.disclosed_leaves])
        self.assertEqual(stripped.proof_hash(), bundle.proof_hash())
        second = stripped.to_dict()
        second["holder_identity"] = _holder_claim(bundle, "Mallory", "52")
        again = self.client.post(
            "/api/v1/proofs", json={"proof_bundle": second, "opt_in_leaderboard": True}
        )
        self.assertLess(again.status_code, 500, again.text)

        after = self._stored(bundle.proof_id)
        self.assertEqual(after["holder_identity"]["display_name"], "Alice Owner")
        self.assertEqual(len(after["disclosed_leaves"]), disclosed_before)
        self.assertEqual(self._leaderboard_count(), 0)
        if again.status_code < 300:
            echoed = again.json()["proof_bundle"]
            self.assertEqual(echoed["holder_identity"]["display_name"], "Alice Owner")

    def test_second_post_cannot_put_a_name_on_a_record_published_without_one(self) -> None:
        bundle = self._signed_bundle("prf-immutable-unclaimed")
        published = self.client.post(
            "/api/v1/proofs", json={"proof_bundle": bundle.to_dict(), "opt_in_leaderboard": False}
        )
        self.assertEqual(published.status_code, 201, published.text)
        self.assertIsNone(self._stored(bundle.proof_id).get("holder_identity"))

        claimed = bundle.to_dict()
        claimed["holder_identity"] = _holder_claim(bundle, "Mallory", "52")
        again = self.client.post(
            "/api/v1/proofs", json={"proof_bundle": claimed, "opt_in_leaderboard": True}
        )
        self.assertLess(again.status_code, 500, again.text)

        self.assertIsNone(self._stored(bundle.proof_id).get("holder_identity"))
        self.assertEqual(self._leaderboard_count(), 0)

    def test_first_post_with_a_holder_name_stores_it(self) -> None:
        bundle = self._signed_bundle("prf-immutable-first-write")
        first = bundle.to_dict()
        first["holder_identity"] = _holder_claim(bundle, "Alice Owner", "41")
        published = self.client.post(
            "/api/v1/proofs", json={"proof_bundle": first, "opt_in_leaderboard": True}
        )
        self.assertEqual(published.status_code, 201, published.text)
        self.assertEqual(
            self._stored(bundle.proof_id)["holder_identity"]["display_name"], "Alice Owner"
        )
        self.assertEqual(self._leaderboard_count(), 1)


if __name__ == "__main__":
    unittest.main()
