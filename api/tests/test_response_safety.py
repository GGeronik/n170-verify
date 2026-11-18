"""Responses stay safe and readable.

* What the outbound privacy scanner would block is refused before a record is
  signed or stored (422, with a reason that does not repeat the text), so a
  stored record can always be read back and a publish never ends in a 500.
* An error response that would repeat a caller's own field name or path id in
  a form the scanner blocks keeps its 4xx status and names only the problem.
* The account-id patterns match account ids, not ordinary upper-case words.
* A body that cannot be parsed, at any nesting depth, is a 400.
* The server module builds no application at import time; the one it offers
  is built from the environment, through every start-up check.
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from app.privacy_scanner import OutboundPrivacyScanner
from n170_verify.contracts import (
    AccountScope,
    EnvironmentTier,
    OriginAssurance,
    ProviderApprovalState,
    create_signed_proof_bundle,
)
from n170_verify.crypto import generate_ed25519_keypair

try:
    from tests.test_api_lifecycle_and_security import _build_leaf_payloads
except ImportError:  # run with api/tests on the path, as CI does
    from test_api_lifecycle_and_security import _build_leaf_payloads

HOST_KID = "n170-active-2026"
DEEP_BODY = b"[" * 200_000
# Synthetic example values, never real accounts.
ALPACA_LIKE_ID = "PA3K9XZ1ABCD"
IBKR_LIKE_ID = "U1234567"


class _Case(unittest.TestCase):
    def setUp(self) -> None:
        self.kp = generate_ed25519_keypair(bytes.fromhex("11" * 32))
        self.config = ApiConfig(
            publisher_keypair=self.kp,
            publisher_kid=HOST_KID,
            publisher_key_not_before_utc="2025-01-01T00:00:00Z",
            hosted_multi_user_mode=True,
            db_path=":memory:",
            sync_db_path=":memory:",
            vault_master_kek_hex="aa" * 32,
            account_blinding_salt_hex="bb" * 32,
        )
        self.app = create_app(self.config, prefer_fastapi=False)
        self.client = VerifyApiTestClient(self.app)

    def tearDown(self) -> None:
        self.app.verify_app.close()

    def _bundle_with_tags(self, proof_id: str, tags: list[str]):
        leaves = _build_leaf_payloads()
        leaves["coaching_and_context"] = {**leaves["coaching_and_context"], "imported_journal_tags": tags}
        return create_signed_proof_bundle(
            proof_id=proof_id,
            issued_at_utc="2026-02-10T12:00:00Z",
            publisher_kid=HOST_KID,
            publisher_private_key_hex=self.kp.private_key_hex,
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
            leaf_payloads=leaves,
        )


class TestScannerPatterns(unittest.TestCase):
    def test_ordinary_words_are_not_account_ids(self) -> None:
        scanner = OutboundPrivacyScanner()
        for text in ("PATTERNS", "PAYMENTS", "PARTNERSHIP", "PASSWORDS", "PANDEMIC", "DUPLICATE", "UNITED"):
            with self.subTest(text=text):
                self.assertEqual(scanner.scan_text(f'{{"tag": "{text}"}}'), [])

    def test_account_ids_are_still_caught(self) -> None:
        scanner = OutboundPrivacyScanner()
        for text in (ALPACA_LIKE_ID, "PA12345678", IBKR_LIKE_ID, "DU1234567", "6YA123456"):
            with self.subTest(text=text):
                self.assertTrue(scanner.scan_text(f'{{"tag": "{text}"}}'))


class TestBlockedTextIsRefusedBeforeStoring(_Case):
    def test_a_record_carrying_an_account_like_id_is_refused_and_not_stored(self) -> None:
        bundle = self._bundle_with_tags("prf-tag-account-like", ["Breakout", ALPACA_LIKE_ID])
        resp = self.client.post("/api/v1/proofs", json={"proof_bundle": bundle.to_dict(), "opt_in_leaderboard": True})
        self.assertEqual(resp.status_code, 422, resp.text)
        self.assertEqual(resp.json()["error"], "invalid_proof_bundle")
        self.assertNotIn(ALPACA_LIKE_ID, resp.text)
        self.assertEqual(self.app.verify_app.store.total_row_counts()["proofs"], 0)

    def test_a_record_with_ordinary_upper_case_words_is_stored_and_readable(self) -> None:
        bundle = self._bundle_with_tags("prf-tag-words", ["PATTERNS", "PAYMENTS"])
        resp = self.client.post("/api/v1/proofs", json={"proof_bundle": bundle.to_dict()})
        self.assertEqual(resp.status_code, 201, resp.text)
        got = self.client.get("/api/v1/proofs/prf-tag-words")
        self.assertEqual(got.status_code, 200, got.text)


class TestErrorsDoNotEchoBlockedCallerText(_Case):
    def test_a_missing_proof_named_like_an_account_id_is_a_404(self) -> None:
        resp = self.client.get(f"/api/v1/proofs/{IBKR_LIKE_ID}")
        self.assertEqual(resp.status_code, 404, resp.text)
        self.assertNotIn(IBKR_LIKE_ID, resp.text)

    def test_an_unknown_request_field_named_like_an_account_id_is_a_4xx(self) -> None:
        resp = self.client.post(
            "/api/v1/verify", json={"broker_id": "auto_detect", "raw_statement": "x", IBKR_LIKE_ID: 1}
        )
        self.assertGreaterEqual(resp.status_code, 400, resp.text)
        self.assertLess(resp.status_code, 500, resp.text)
        self.assertNotIn(IBKR_LIKE_ID, resp.text)


class TestUnparsableBodiesAreA400(_Case):
    def test_deeply_nested_bodies_are_refused_with_400(self) -> None:
        for path in ("/api/v1/verify", "/api/v1/proofs", "/api/v1/verify/auto-detect", "/api/v1/tools/plausibility"):
            with self.subTest(path=path):
                resp = self.client.post(path, content=DEEP_BODY, headers={"Content-Type": "application/json"})
                self.assertEqual(resp.status_code, 400, resp.text[:200])


class TestServerModuleBuildsNoApplicationAtImport(unittest.TestCase):
    def test_the_module_app_is_built_from_the_environment(self) -> None:
        import app.main as main_module

        self.assertNotIn("app", vars(main_module))
        # Hosted mode with nothing configured: every start-up check applies.
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                main_module.app  # noqa: B018


if __name__ == "__main__":
    unittest.main()
