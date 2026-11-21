"""Unit and HTTP API regression tests for delayed_closed_trades 7-day embargo guard."""

from __future__ import annotations

import math
import unittest

from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from app.store import enforce_bundle_seven_day_trade_guard
from n170_verify.contracts import (
    AccountScope,
    EnvironmentTier,
    OriginAssurance,
    ProviderApprovalState,
    VerifyProofBundle,
    create_signed_proof_bundle,
    verify_proof_bundle,
)
from n170_verify.crypto import generate_ed25519_keypair

try:
    from tests.test_api_lifecycle_and_security import _build_leaf_payloads
except ImportError:  # pragma: no cover
    from test_api_lifecycle_and_security import _build_leaf_payloads


class TestDelayedClosedTradesGuard(unittest.TestCase):
    def setUp(self) -> None:
        self.publisher = generate_ed25519_keypair(bytes.fromhex("23" * 32))
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

    def _make_bundle(
        self,
        proof_id: str,
        delayed_trades_leaf: object,
        *,
        issued_at_utc: str = "2026-02-15T12:00:00Z",
    ) -> VerifyProofBundle:
        leaves = _build_leaf_payloads()
        leaves["delayed_closed_trades"] = delayed_trades_leaf
        return create_signed_proof_bundle(
            proof_id=proof_id,
            issued_at_utc=issued_at_utc,
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.publisher.private_key_hex,
            broker_id="ibkr_flex",
            blinded_account_tag="45" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="67" * 32,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-02-15T00:00:00Z",
            base_currency="USD",
            leaf_payloads=leaves,
        )

    def test_pipeline_dict_envelope_survives_guard_and_post_proofs(self) -> None:
        """Regression: pipeline.py dict shape {embargo_days, trades, stripped_recent_count} MUST NOT be stripped."""
        canonical_leaf = {
            "embargo_days": 7,
            "stripped_recent_count": 1,
            "trades": [
                {
                    "symbol": "NVDA",
                    "asset_class": "equity",
                    "direction": "long",
                    "entry_timestamp_utc": "2026-01-05T14:30:00Z",
                    "exit_timestamp_utc": "2026-01-20T19:45:00Z",
                    "holding_hours": 365.25,
                    "realized_return_decimal": 0.142,
                },
                {
                    "symbol": "AAPL",
                    "asset_class": "equity",
                    "direction": "long",
                    "entry_timestamp_utc": "2026-02-01T14:30:00Z",
                    "exit_timestamp_utc": "2026-02-08T12:00:00Z",  # exact 7-day boundary
                    "holding_hours": 165.5,
                    "realized_return_decimal": 0.048,
                },
            ],
        }
        bundle = self._make_bundle("prf-pipeline-dict-ok", canonical_leaf)
        sanitized, redacted = enforce_bundle_seven_day_trade_guard(bundle, min_delay_days=7)
        self.assertFalse(redacted)
        self.assertEqual(sanitized.get_disclosed_payload("delayed_closed_trades"), canonical_leaf)

        # Round-trip through POST /api/v1/proofs and GET /api/v1/proofs/{proof_id}
        post_resp = self.client.post("/api/v1/proofs", json={"proof_bundle": bundle.to_dict()})
        self.assertEqual(post_resp.status_code, 201, post_resp.text)
        post_body = post_resp.json()
        self.assertTrue(post_body["verification"]["valid"])

        get_resp = self.client.get(f"/api/v1/proofs/{bundle.proof_id}")
        self.assertEqual(get_resp.status_code, 200, get_resp.text)
        stored = VerifyProofBundle.from_dict(get_resp.json()["proof_bundle"])
        self.assertEqual(stored.get_disclosed_payload("delayed_closed_trades"), canonical_leaf)
        self.assertNotIn("delayed_closed_trades", stored.undisclosed_leaf_hashes)

    def test_pipeline_dict_one_second_too_recent_is_redacted_preserving_merkle_and_signature(self) -> None:
        too_recent = {
            "embargo_days": 7,
            "stripped_recent_count": 0,
            "trades": [
                {
                    "symbol": "MSFT",
                    "entry_timestamp_utc": "2026-02-01T14:30:00Z",
                    "exit_timestamp_utc": "2026-02-08T12:00:01Z",  # 1 second inside 7-day window
                    "realized_return_decimal": 0.03,
                }
            ],
        }
        bundle = self._make_bundle("prf-pipeline-dict-too-recent", too_recent)
        sanitized, redacted = enforce_bundle_seven_day_trade_guard(bundle, min_delay_days=7)
        self.assertTrue(redacted)
        self.assertIn("delayed_closed_trades", sanitized.undisclosed_leaf_hashes)
        self.assertEqual(sanitized.merkle_root, bundle.merkle_root)
        self.assertEqual(sanitized.signature_hex, bundle.signature_hex)
        self.assertTrue(verify_proof_bundle(sanitized).valid)

        post_resp = self.client.post("/api/v1/proofs", json={"proof_bundle": bundle.to_dict()})
        self.assertEqual(post_resp.status_code, 201, post_resp.text)
        stored = VerifyProofBundle.from_dict(post_resp.json()["proof_bundle"])
        self.assertIn("delayed_closed_trades", stored.undisclosed_leaf_hashes)
        with self.assertRaises(KeyError):
            stored.get_disclosed_payload("delayed_closed_trades")

    def test_pipeline_dict_empty_trades_is_preserved(self) -> None:
        empty_leaf = {"embargo_days": 7, "trades": [], "stripped_recent_count": 2}
        bundle = self._make_bundle("prf-pipeline-empty", empty_leaf)
        sanitized, redacted = enforce_bundle_seven_day_trade_guard(bundle, min_delay_days=7)
        self.assertFalse(redacted)
        self.assertEqual(sanitized.get_disclosed_payload("delayed_closed_trades"), empty_leaf)

    def test_pipeline_dict_short_embargo_days_is_redacted(self) -> None:
        short_embargo = {
            "embargo_days": 6,
            "trades": [{"symbol": "SPY", "exit_timestamp_utc": "2026-01-10T15:00:00Z"}],
        }
        bundle = self._make_bundle("prf-short-embargo", short_embargo)
        sanitized, redacted = enforce_bundle_seven_day_trade_guard(bundle, min_delay_days=7)
        self.assertTrue(redacted)
        self.assertIn("delayed_closed_trades", sanitized.undisclosed_leaf_hashes)

    def test_malformed_dict_variants_are_redacted_without_raising(self) -> None:
        malformed_cases = [
            ("bool_embargo", {"embargo_days": True, "trades": []}),
            ("string_embargo", {"embargo_days": "7", "trades": []}),
            ("missing_trades_key", {"embargo_days": 7}),
            ("non_list_trades", {"embargo_days": 7, "trades": {"symbol": "AAPL"}}),
            ("missing_exit_ts", {"embargo_days": 7, "trades": [{"symbol": "AAPL"}]}),
            (
                "bad_exit_ts",
                {"embargo_days": 7, "trades": [{"symbol": "AAPL", "exit_timestamp_utc": "not-a-date"}]},
            ),
            (
                "int_exit_ts",
                {"embargo_days": 7, "trades": [{"symbol": "AAPL", "exit_timestamp_utc": 20260101}]},
            ),
            (
                "null_exit_ts",
                {"embargo_days": 7, "trades": [{"symbol": "AAPL", "exit_timestamp_utc": None}]},
            ),
            (
                "empty_exit_ts",
                {"embargo_days": 7, "trades": [{"symbol": "AAPL", "exit_timestamp_utc": "   "}]},
            ),
            ("scalar_leaf", "unexpected-string"),
            ("int_leaf", 42),
        ]
        for label, leaf_payload in malformed_cases:
            with self.subTest(case=label):
                bundle = self._make_bundle(f"prf-malformed-{label}", leaf_payload)
                sanitized, redacted = enforce_bundle_seven_day_trade_guard(bundle, min_delay_days=7)
                self.assertTrue(redacted)
                self.assertIn("delayed_closed_trades", sanitized.undisclosed_leaf_hashes)
                self.assertTrue(verify_proof_bundle(sanitized).valid)

    def test_nan_embargo_days_guard_rejects_cleanly(self) -> None:
        # Construct in-memory leaf with float('nan') embargo_days directly for guard check
        bundle = self._make_bundle("prf-nan-embargo", {"embargo_days": 7, "trades": []})
        for leaf in bundle.disclosed_leaves:
            if leaf.leaf_name == "delayed_closed_trades":
                leaf.payload = {"embargo_days": math.nan, "trades": []}
        sanitized, redacted = enforce_bundle_seven_day_trade_guard(bundle, min_delay_days=7)
        self.assertTrue(redacted)
        self.assertIn("delayed_closed_trades", sanitized.undisclosed_leaf_hashes)

    def test_legacy_flat_list_still_supported_and_enforced(self) -> None:
        old_list = [{"symbol": "QQQ", "exit_timestamp_utc": "2026-01-15T16:00:00Z"}]
        b_old = self._make_bundle("prf-legacy-ok", old_list)
        sanitized_old, redacted_old = enforce_bundle_seven_day_trade_guard(b_old, min_delay_days=7)
        self.assertFalse(redacted_old)
        self.assertEqual(sanitized_old.get_disclosed_payload("delayed_closed_trades"), old_list)

        new_list = [{"symbol": "QQQ", "exit_timestamp_utc": "2026-02-14T16:00:00Z"}]
        b_new = self._make_bundle("prf-legacy-recent", new_list)
        sanitized_new, redacted_new = enforce_bundle_seven_day_trade_guard(b_new, min_delay_days=7)
        self.assertTrue(redacted_new)
        self.assertIn("delayed_closed_trades", sanitized_new.undisclosed_leaf_hashes)

    def test_already_redacted_leaf_is_noop(self) -> None:
        bundle = self._make_bundle("prf-already-redacted", {"embargo_days": 7, "trades": []})
        redacted_before = bundle.redact_leaves(["delayed_closed_trades"])
        sanitized, was_redacted = enforce_bundle_seven_day_trade_guard(
            redacted_before, min_delay_days=7
        )
        self.assertFalse(was_redacted)
        self.assertEqual(sanitized.proof_hash(), redacted_before.proof_hash())

    def test_worker_pipeline_accepts_canonical_dict_delayed_closed_trades_leaf(self) -> None:
        from app.worker_isolation import default_standalone_worker_pipeline

        leaves = _build_leaf_payloads()
        leaves["delayed_closed_trades"] = {
            "embargo_days": 7,
            "stripped_recent_count": 1,
            "trades": [
                {
                    "symbol": "NVDA",
                    "asset_class": "equity",
                    "side": "long",
                    "entry_timestamp_utc": "2026-01-05T14:30:00Z",
                    "exit_timestamp_utc": "2026-01-20T19:45:00Z",
                    "holding_hours": 365.25,
                    "return_pct": 14.2,
                },
                {
                    "symbol": "MSFT",
                    "asset_class": "equity",
                    "side": "long",
                    "entry_timestamp_utc": "2026-02-10T14:30:00Z",
                    "exit_timestamp_utc": "2026-02-14T19:45:00Z",
                    "holding_hours": 101.25,
                    "return_pct": 2.5,
                },
            ],
        }
        job = {
            "broker_id": "ibkr_flex",
            "account_blinding_salt_hex": "bb" * 32,
            "blinded_account_tag": "45" * 32,
            "account_scope": "all_enumerated_subaccounts",
            "provider_approval_state": "approved_live",
            "environment_tier": "live_production",
            "claimed_origin_assurance": "operator_retrieved",
            "source_body_sha256": "67" * 32,
            "period_start_utc": "2026-01-01T00:00:00Z",
            "period_end_utc": "2026-02-15T00:00:00Z",
            "issued_at_utc": "2026-02-15T12:00:00Z",
            "base_currency": "USD",
            "delayed_trade_guard_days": 7,
            "leaf_payloads": leaves,
            "disclose_leaf_names": list(leaves.keys()),
        }
        res = default_standalone_worker_pipeline(job)
        self.assertEqual(res["stripped_recent_closed_trades_count"], 1)
        leaf_out = next(
            lf["payload"]
            for lf in res["disclosed_leaves"]
            if lf["leaf_name"] == "delayed_closed_trades"
        )
        self.assertIsInstance(leaf_out, dict)
        self.assertEqual(leaf_out["embargo_days"], 7)
        self.assertEqual(leaf_out["stripped_recent_count"], 2)
        self.assertEqual([t["symbol"] for t in leaf_out["trades"]], ["NVDA"])


if __name__ == "__main__":
    unittest.main()
