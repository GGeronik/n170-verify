"""End-to-end security, subprocess isolation, sync vault, C2SP registry, chain, badge, and leaderboard tests."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from urllib.parse import quote
import xml.etree.ElementTree as ET

from app.badges import render_proof_badge_svg
from app.config import ApiConfig
from app.main import VerifyApiApplication, VerifyApiTestClient, create_app
from app.sync_vault import (
    RevocationReceipt,
    SyncVaultIntegrityError,
    aes256_gcm_decrypt,
    aes256_gcm_encrypt,
)
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    BundleVerificationResult,
    CapitalBracket,
    ChainContinuityMode,
    EnvironmentTier,
    IndexedCurvePoint,
    OriginAssurance,
    PerformanceSummary,
    ProviderApprovalState,
    ReconciliationReport,
    ReconciliationStatus,
    RedactedClosedTrade,
    SignerTrustStatus,
    VerifyProofBundle,
    compute_blinded_account_tag,
    create_signed_proof_bundle,
)
from n170_verify.crypto import (
    CANONICAL_LEAF_NAMES,
    ChainCadencePolicy,
    ChainInvariantViolationCode,
    DisclosedLeaf,
    NotaryNodeInfo,
    ProspectiveChainLink,
    PublisherKeyRecord,
    PublisherKeyRegistryDocument,
    TranscriptCommitmentKind,
    create_signed_witness_attestation,
    generate_ed25519_keypair,
    verify_c2sp_checkpoint,
)


from app.worker_isolation import default_standalone_worker_pipeline


def sample_injected_wave3_pipeline(job: dict) -> dict:
    """Top-level picklable pipeline hook verifying Wave 3 dependency-injection compatibility."""
    enriched = dict(job)
    enriched["twr_decimal"] = 0.215
    enriched["probabilistic_sharpe_ratio"] = 0.994
    return default_standalone_worker_pipeline(enriched)


def _build_leaf_payloads(
    *,
    twr_decimal: float = 0.08,
    psr: float = 0.965,
    capital_bracket: CapitalBracket = CapitalBracket.BRACKET_100K_1M,
    recon_status: ReconciliationStatus = ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE,
    closed_trades: list[dict] | None = None,
    period_start_utc: str = "2026-01-01T00:00:00Z",
    period_end_utc: str = "2026-01-31T00:00:00Z",
) -> dict:
    end_idx = round(100.0 * (1.0 + twr_decimal), 8)
    curve = [
        IndexedCurvePoint(timestamp_utc=period_start_utc, index_value=100.0, drawdown_pct=0.0),
        IndexedCurvePoint(timestamp_utc=period_end_utc, index_value=end_idx, drawdown_pct=-1.2),
    ]
    perf = PerformanceSummary(
        twr_decimal=twr_decimal,
        probabilistic_sharpe_ratio=psr,
        psr_sample_eligible=True,
        observation_count=35,
        max_drawdown_decimal=-0.012,
        capital_bracket=capital_bracket,
        benchmark_symbol="SPY",
        benchmark_twr_decimal=0.03,
        alpha_decimal=round(twr_decimal - 0.03, 8),
        indexed_curve=curve,
    )
    recon = ReconciliationReport(
        status=recon_status,
        reference_provider="eodhd",
        ledger_completeness_ok=True,
        checks_evaluated=10,
        discrepancy_count=0,
        summary_text="Reconciled within calibrated tolerance.",
    )
    perf_d = perf.to_dict()
    return {
        "core_metrics": {
            "twr_decimal": perf_d["twr_decimal"],
            "twr_pct": perf_d["twr_pct"],
            "probabilistic_sharpe_ratio": perf_d["probabilistic_sharpe_ratio"],
            "psr_glm_unsmoothed": perf_d["psr_glm_unsmoothed"],
            "psr_sample_eligible": perf_d["psr_sample_eligible"],
            "observation_count": perf_d["observation_count"],
            "max_drawdown_decimal": perf_d["max_drawdown_decimal"],
            "non_iid_caveat": perf_d["non_iid_caveat"],
        },
        "indexed_curve": [pt.to_dict() for pt in curve],
        "reconciliation": recon.to_dict(),
        "coaching_and_context": {
            "style_summary": "Liquid swing equity profile",
            "event_window_share_pct": 12.0,
        },
        "capital_bracket": {"capital_bracket": capital_bracket.value},
        "benchmark_alpha": {
            "benchmark_symbol": "SPY",
            "benchmark_twr_decimal": 0.03,
            "alpha_decimal": round(twr_decimal - 0.03, 8),
        },
        "delayed_closed_trades": list(closed_trades or []),
    }


class TestN170VerifyApiLifecycleAndSecurity(unittest.TestCase):
    """Comprehensive verification suite for W2-D API security, isolation, vault, chains, badges, and leaderboard."""

    def setUp(self) -> None:
        self.pub_kp = generate_ed25519_keypair(bytes.fromhex("11" * 32))
        self.retired_kp = generate_ed25519_keypair(bytes.fromhex("22" * 32))
        self.revoked_kp = generate_ed25519_keypair(bytes.fromhex("33" * 32))
        self.notary_1_kp = generate_ed25519_keypair(bytes.fromhex("41" * 32))
        self.notary_2_kp = generate_ed25519_keypair(bytes.fromhex("42" * 32))
        self.ckpt_witness_kp = generate_ed25519_keypair(bytes.fromhex("51" * 32))

        self.notaries = [
            NotaryNodeInfo(
                notary_id="notary-pse-1",
                operator_org="PSE Foundation",
                asn="AS13335",
                public_key_hex=self.notary_1_kp.public_key_hex,
                is_debug_build=False,
                attestation_type="production",
            ),
            NotaryNodeInfo(
                notary_id="notary-ch-2",
                operator_org="Helvetia Witness Guild",
                asn="AS3303",
                public_key_hex=self.notary_2_kp.public_key_hex,
                is_debug_build=False,
                attestation_type="production",
            ),
        ]

        self.config = ApiConfig(
            publisher_keypair=self.pub_kp,
            publisher_kid="n170-active-2026",
            publisher_key_not_before_utc="2025-01-01T00:00:00Z",
            additional_registry_keys=[
                PublisherKeyRecord(
                    publisher_kid="n170-retired-2025",
                    public_key_hex=self.retired_kp.public_key_hex,
                    status="retired",
                    not_before_utc="2024-01-01T00:00:00Z",
                    not_after_utc="2025-12-31T23:59:59Z",
                ),
                PublisherKeyRecord(
                    publisher_kid="n170-revoked-key",
                    public_key_hex=self.revoked_kp.public_key_hex,
                    status="revoked",
                    not_before_utc="2025-01-01T00:00:00Z",
                    revoked_after_utc="2025-06-01T00:00:00Z",
                ),
            ],
            trusted_notaries=self.notaries,
            checkpoint_origin="verify.n170.ai/continuity-log/v3",
            checkpoint_witness_signers=[
                (
                    "witness-cosigner-1",
                    self.ckpt_witness_kp.private_key_hex,
                    self.ckpt_witness_kp.public_key_hex,
                    "2026-02-10T12:00:00Z",
                )
            ],
            hosted_multi_user_mode=True,
            db_path=":memory:",
            sync_db_path=":memory:",
            vault_master_kek_hex="aa" * 32,
            sync_backup_retention_hours=0,
            account_blinding_salt_hex="bb" * 32,
        )
        self.app = create_app(self.config, prefer_fastapi=False)
        self.client = VerifyApiTestClient(self.app)

    def tearDown(self) -> None:
        self.app.close()

    # ------------------------------------------------------------------
    # 1. Subprocess-Isolated One-Shot Mode & Governance Enforcement
    # ------------------------------------------------------------------
    def test_one_shot_verify_spawn_isolation_rlimit_core_and_zero_db_rows(self) -> None:
        os.environ["N170_CANARY_PARENT_SECRET"] = "do-not-leak-into-child-env"
        try:
            resp = self.client.post(
                "/api/v1/verify",
                json={
                    "broker_id": "ibkr_flex",
                    "raw_account_id": "U987654321",
                    "raw_statement_text": "SYNTHETIC-RAW-STATEMENT-CONFIDENTIAL-DO-NOT-STORE",
                    "ephemeral_credentials": {"flex_token": "ephemeral-secret-flex-999"},
                    "period_start_utc": "2026-01-01T00:00:00Z",
                    "period_end_utc": "2026-01-31T00:00:00Z",
                    "issued_at_utc": "2026-02-10T12:00:00Z",
                    "nav_points": [
                        {"timestamp_utc": "2026-01-01T00:00:00Z", "nav_base": 250000.0},
                        {"timestamp_utc": "2026-01-15T00:00:00Z", "nav_base": 265000.0},
                        {"timestamp_utc": "2026-01-31T00:00:00Z", "nav_base": 262500.0},
                    ],
                    "persist_sync": False,
                },
            )
        finally:
            os.environ.pop("N170_CANARY_PARENT_SECRET", None)

        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()

        receipt = body["isolation_receipt"]
        self.assertEqual(receipt["execution_mode"], "ephemeral_spawn_subprocess")
        self.assertEqual(receipt["parent_pid"], os.getpid())
        self.assertNotEqual(receipt["worker_pid"], os.getpid())
        self.assertEqual(receipt["worker_exitcode"], 0)
        self.assertTrue(receipt["worker_terminated"])
        self.assertEqual(receipt["rlimit_core"], [0, 0])
        self.assertEqual(receipt["rlimit_core_soft"], 0)
        self.assertEqual(receipt["rlimit_core_hard"], 0)
        self.assertTrue(receipt["sanitized_child_env"])
        self.assertNotIn("N170_CANARY_PARENT_SECRET", receipt["child_env_keys"])
        self.assertEqual(receipt["persistent_rows_written"], 0)
        self.assertEqual(receipt["retention_mode"], "no_persistent_storage")
        self.assertIn("RLIMIT_CORE=(0, 0)", receipt["memory_lifecycle_disclosure"])

        # Worker process must already be terminated at the OS level
        with self.assertRaises(ProcessLookupError):
            os.kill(int(receipt["worker_pid"]), 0)

        # Confirm ZERO rows written across ProofStore and SyncVault in one-shot mode
        self.assertEqual(
            self.app.store.total_row_counts(),
            {"proofs": 0, "chains": 0, "continuity_log": 0},
        )
        self.assertEqual(self.app.sync_vault.connection_count(), 0)

        # Confirm zero raw account IDs, tokens, raw statement text, or dollar NAVs in output
        serialized = resp.text
        self.assertNotIn("U987654321", serialized)
        self.assertNotIn("ephemeral-secret-flex-999", serialized)
        self.assertNotIn("SYNTHETIC-RAW-STATEMENT-CONFIDENTIAL", serialized)
        self.assertNotIn("250000", serialized)
        self.assertNotIn("265000", serialized)
        self.assertNotIn("262500", serialized)

        bundle = VerifyProofBundle.from_dict(body["proof_bundle"])
        self.assertEqual(bundle.retention_mode, "no_persistent_storage")
        self.assertEqual(
            bundle.get_disclosed_payload("capital_bracket"),
            {"capital_bracket": CapitalBracket.BRACKET_100K_1M.value},
        )
        curve_payload = bundle.get_disclosed_payload("indexed_curve")
        self.assertAlmostEqual(curve_payload[0]["index_value"], 100.0)
        self.assertAlmostEqual(curve_payload[-1]["index_value"], 105.0)
        self.assertTrue(body["verification"]["valid"])

    def test_governance_blocks_pending_provider_approval_and_paper_sandbox(self) -> None:
        # 1. Connector pending vendor approval blocked in hosted multi-user mode (HTTP 403)
        resp_pending = self.client.post(
            "/api/v1/verify",
            json={
                "broker_id": "fidelity_pending",
                "raw_account_id": "ACCT-1",
            },
        )
        self.assertEqual(resp_pending.status_code, 403)
        self.assertEqual(resp_pending.json()["error"], "provider_approval_pending")

        # Explicit provider_approval_state="pending_provider_approval" also blocked
        resp_pending_explicit = self.client.post(
            "/api/v1/verify",
            json={
                "broker_id": "custom_connector",
                "provider_approval_state": "pending_provider_approval",
                "raw_account_id": "ACCT-2",
            },
        )
        self.assertEqual(resp_pending_explicit.status_code, 403)
        self.assertEqual(resp_pending_explicit.json()["error"], "provider_approval_pending")

        # 2. Paper/sandbox accounts rejected with HTTP 422
        resp_paper_tier = self.client.post(
            "/api/v1/verify",
            json={
                "broker_id": "alpaca",
                "environment_tier": "paper_or_sandbox_rejected",
                "raw_account_id": "PA-12345",
            },
        )
        self.assertEqual(resp_paper_tier.status_code, 422)
        self.assertEqual(resp_paper_tier.json()["error"], "paper_or_sandbox_rejected")

        resp_paper_flag = self.client.post(
            "/api/v1/verify",
            json={
                "broker_id": "ibkr",
                "account_type": "paper",
                "raw_account_id": "DU999999",
            },
        )
        self.assertEqual(resp_paper_flag.status_code, 422)
        self.assertEqual(resp_paper_flag.json()["error"], "paper_or_sandbox_rejected")

    # ------------------------------------------------------------------
    # 2. 7-Day Delayed Closed-Trade Front-Run Guard
    # ------------------------------------------------------------------
    def test_seven_day_delayed_closed_trade_guard_strips_recent_trades(self) -> None:
        issued_at = "2026-02-10T12:00:00Z"
        trades = [
            {
                "symbol": "AAPL_OLD_ELIGIBLE",
                "asset_class": "equity",
                "side": "long",
                "entry_timestamp_utc": "2026-01-20T14:30:00Z",
                "exit_timestamp_utc": "2026-01-25T16:00:00Z",  # > 7d ago -> KEEP
                "return_pct": 4.2,
                "holding_hours": 121.5,
            },
            {
                "symbol": "MSFT_BOUNDARY_7D",
                "asset_class": "equity",
                "side": "long",
                "entry_timestamp_utc": "2026-02-01T12:00:00Z",
                "exit_timestamp_utc": "2026-02-03T12:00:00Z",  # == 7d ago -> KEEP
                "return_pct": 1.8,
                "holding_hours": 48.0,
            },
            {
                "symbol": "NVDA_RECENT_SECRET_2D",
                "asset_class": "equity",
                "side": "short",
                "entry_timestamp_utc": "2026-02-07T15:00:00Z",
                "exit_timestamp_utc": "2026-02-08T19:00:00Z",  # < 7d ago -> STRIP!
                "return_pct": 6.1,
                "holding_hours": 28.0,
            },
        ]

        resp = self.client.post(
            "/api/v1/verify",
            json={
                "broker_id": "schwab",
                "raw_account_id": "SCH-777",
                "period_start_utc": "2026-01-15T00:00:00Z",
                "period_end_utc": "2026-02-10T00:00:00Z",
                "issued_at_utc": issued_at,
                "closed_trades": trades,
            },
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        data = resp.json()
        self.assertEqual(data["stripped_recent_closed_trades_count"], 1)
        self.assertNotIn("NVDA_RECENT_SECRET_2D", resp.text)

        bundle = VerifyProofBundle.from_dict(data["proof_bundle"])
        disclosed_trades = bundle.get_disclosed_payload("delayed_closed_trades")
        self.assertEqual(
            [t["symbol"] for t in disclosed_trades],
            ["AAPL_OLD_ELIGIBLE", "MSFT_BOUNDARY_7D"],
        )

        # Also verify store ingestion strips/redacts pre-signed bundles disclosing <7d trades
        unsafe_leaves = _build_leaf_payloads(
            closed_trades=[
                RedactedClosedTrade(
                    symbol="TSLA_TOO_RECENT",
                    asset_class=AssetClass.EQUITY,
                    side="long",
                    entry_timestamp_utc="2026-02-08T10:00:00Z",
                    exit_timestamp_utc="2026-02-09T10:00:00Z",
                    return_pct=2.5,
                    holding_hours=24.0,
                ).to_dict()
            ]
        )
        pre_signed = create_signed_proof_bundle(
            proof_id="prf-presigned-recent-trade",
            issued_at_utc=issued_at,
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.pub_kp.private_key_hex,
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
            leaf_payloads=unsafe_leaves,
        )
        pub_resp = self.client.post(
            "/api/v1/proofs",
            json={"proof_bundle": pre_signed.to_dict()},
        )
        self.assertEqual(pub_resp.status_code, 201, pub_resp.text)
        self.assertNotIn("TSLA_TOO_RECENT", pub_resp.text)
        stored_bundle = VerifyProofBundle.from_dict(pub_resp.json()["proof_bundle"])
        self.assertIn("delayed_closed_trades", stored_bundle.undisclosed_leaf_hashes)
        self.assertTrue(pub_resp.json()["verification"]["valid"])

    # ------------------------------------------------------------------
    # 3. AES-256-GCM Envelope Sync Vault, Tamper Rejection & RevocationReceipt
    # ------------------------------------------------------------------
    def test_aes256_gcm_nist_vector_and_sync_vault_lifecycle(self) -> None:
        # NIST SP 800-38D Test Case 15/16 verification on OpenSSL ctypes & active backend
        zero_key = b"\x00" * 32
        zero_iv = b"\x00" * 12
        zero_pt = b"\x00" * 16
        for force_ossl in (False, True):
            ct_and_tag = aes256_gcm_encrypt(
                zero_key, zero_iv, zero_pt, b"", force_openssl=force_ossl
            )
            self.assertEqual(
                ct_and_tag.hex(),
                "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919",
            )
            recovered = aes256_gcm_decrypt(
                zero_key, zero_iv, ct_and_tag, b"", force_openssl=force_ossl
            )
            self.assertEqual(recovered, zero_pt)

        # Test file-backed sync vault strictly in TemporaryDirectory outside workspace
        with tempfile.TemporaryDirectory() as tmpdir:
            sync_db_file = str(Path(tmpdir) / "ephemeral_sync_vault.sqlite3")
            revoked_calls: list[tuple[str, str, str]] = []

            def _mock_schwab_oauth_revoke(conn_id: str, broker_id: str, creds: dict) -> bool:
                revoked_calls.append((conn_id, broker_id, str(creds.get("oauth_access_token"))))
                return True

            cfg = ApiConfig(
                publisher_keypair=self.pub_kp,
                publisher_kid="n170-active-2026",
                db_path=":memory:",
                sync_db_path=sync_db_file,
                vault_master_kek_hex="cc" * 32,
                sync_backup_retention_hours=0,
                account_blinding_salt_hex="dd" * 32,
            )
            vault_app = create_app(
                cfg,
                oauth_revocation_callbacks={"schwab": _mock_schwab_oauth_revoke},
                prefer_fastapi=False,
            )
            vclient = VerifyApiTestClient(vault_app)
            try:
                # Reject non-read-only capability scopes
                bad_cap_resp = vclient.post(
                    "/api/v1/sync",
                    json={
                        "broker_id": "schwab",
                        "raw_account_id": "SCH-LIVE-1",
                        "credentials": {"oauth_access_token": "tok"},
                        "capabilities": ["read_balances", "place_order"],
                    },
                )
                self.assertEqual(bad_cap_resp.status_code, 422)
                self.assertEqual(bad_cap_resp.json()["error"], "read_only_capability_violation")

                # Enroll two read-only connections
                secret_tok_a = "schwab-super-secret-oauth-token-alpha-98765"
                r_a = vclient.post(
                    "/api/v1/sync",
                    json={
                        "connection_id": "sync-alpha-001",
                        "broker_id": "schwab",
                        "raw_account_id": "SCH-LIVE-ALPHA",
                        "credentials": {
                            "oauth_access_token": secret_tok_a,
                            "refresh_token": "schwab-refresh-alpha",
                        },
                        "capabilities": ["read_accounts", "read_balances", "read_trades"],
                    },
                )
                self.assertEqual(r_a.status_code, 201, r_a.text)
                self.assertNotIn(secret_tok_a, r_a.text)

                r_b = vclient.post(
                    "/api/v1/sync",
                    json={
                        "connection_id": "sync-beta-002",
                        "broker_id": "schwab",
                        "raw_account_id": "SCH-LIVE-BETA",
                        "credentials": {"oauth_access_token": "beta-token"},
                        "capabilities": ["read_balances"],
                    },
                )
                self.assertEqual(r_b.status_code, 201)

                # Confirm raw SQLite file & ciphertext contain zero plaintext tokens
                raw_env_a = vault_app.sync_vault.inspect_raw_envelope_for_audit("sync-alpha-001")
                self.assertNotIn(secret_tok_a.encode("utf-8"), raw_env_a["payload_ciphertext"])
                raw_db_bytes = Path(sync_db_file).read_bytes()
                self.assertNotIn(secret_tok_a.encode("utf-8"), raw_db_bytes)

                # Internal decrypt succeeds before tamper
                dec_a = vault_app.sync_vault.decrypt_credentials_internal("sync-alpha-001")
                self.assertEqual(dec_a["oauth_access_token"], secret_tok_a)

                # Tamper test 1: Flip 1 bit in payload_ciphertext of beta
                raw_env_b = vault_app.sync_vault.inspect_raw_envelope_for_audit("sync-beta-002")
                corrupted_ct = bytearray(raw_env_b["payload_ciphertext"])
                corrupted_ct[0] ^= 0x01
                vault_app.sync_vault._conn.execute(
                    "UPDATE sync_connections SET payload_ciphertext = ? WHERE connection_id = ?",
                    (sqlite3.Binary(bytes(corrupted_ct)), "sync-beta-002"),
                )
                with self.assertRaises(SyncVaultIntegrityError):
                    vault_app.sync_vault.decrypt_credentials_internal("sync-beta-002")

                # Tamper test 2: Swap alpha's valid envelope onto beta's row (connection_id AAD mismatch!)
                vault_app.sync_vault._conn.execute(
                    """
                    UPDATE sync_connections
                    SET payload_nonce = ?, payload_ciphertext = ?, dek_wrap_nonce = ?, wrapped_dek = ?
                    WHERE connection_id = ?
                    """,
                    (
                        sqlite3.Binary(raw_env_a["payload_nonce"]),
                        sqlite3.Binary(raw_env_a["payload_ciphertext"]),
                        sqlite3.Binary(raw_env_a["dek_wrap_nonce"]),
                        sqlite3.Binary(raw_env_a["wrapped_dek"]),
                        "sync-beta-002",
                    ),
                )
                with self.assertRaises(SyncVaultIntegrityError):
                    vault_app.sync_vault.decrypt_credentials_internal("sync-beta-002")

                # DELETE /api/v1/sync/sync-alpha-001 -> OAuth revoke + zero overwrite + signed RevocationReceipt
                del_resp = vclient.delete("/api/v1/sync/sync-alpha-001")
                self.assertEqual(del_resp.status_code, 200, del_resp.text)
                receipt = RevocationReceipt.from_dict(del_resp.json()["revocation_receipt"])
                self.assertTrue(receipt.verify_signature())
                self.assertEqual(receipt.connection_id, "sync-alpha-001")
                self.assertEqual(receipt.upstream_oauth_revocation_status, "revoked_confirmed")
                self.assertTrue(receipt.primary_ciphertext_overwritten_and_deleted)
                self.assertTrue(receipt.primary_ciphertext_unrecoverable)
                self.assertTrue(receipt.sqlite_secure_delete_enabled)
                self.assertEqual(receipt.backup_retention_hours, 0)
                self.assertEqual(
                    revoked_calls,
                    [("sync-alpha-001", "schwab", secret_tok_a)],
                )

                # Subsequent GET and DELETE return 404
                self.assertEqual(vclient.get("/api/v1/sync/sync-alpha-001").status_code, 404)
                self.assertEqual(vclient.delete("/api/v1/sync/sync-alpha-001").status_code, 404)

                # Also erase sync-beta-002 (even when decrypt fails, primary cryptographic erasure succeeds!)
                del_beta = vclient.delete("/api/v1/sync/sync-beta-002")
                self.assertEqual(del_beta.status_code, 200, del_beta.text)
                beta_receipt = RevocationReceipt.from_dict(del_beta.json()["revocation_receipt"])
                self.assertTrue(beta_receipt.verify_signature())
                self.assertEqual(beta_receipt.upstream_oauth_revocation_status, "revocation_failed")
                self.assertTrue(beta_receipt.primary_ciphertext_unrecoverable)

                # Confirm raw ciphertext bytes of alpha are scrubbed from disk file after secure_delete + VACUUM
                post_delete_bytes = Path(sync_db_file).read_bytes()
                self.assertNotIn(raw_env_a["payload_ciphertext"], post_delete_bytes)
                self.assertNotIn(raw_env_a["wrapped_dek"], post_delete_bytes)
            finally:
                vault_app.close()

    # ------------------------------------------------------------------
    # 4. /.well-known/n170-verify-keys.json C2SP Checkpoint & CORS
    # ------------------------------------------------------------------
    def test_well_known_keys_registry_c2sp_checkpoint_and_cors(self) -> None:
        opt_resp = self.client.options("/.well-known/n170-verify-keys.json")
        self.assertEqual(opt_resp.status_code, 204)
        self.assertEqual(opt_resp.headers.get("Access-Control-Allow-Origin"), "*")

        get_resp = self.client.get("/.well-known/n170-verify-keys.json")
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.headers.get("Access-Control-Allow-Origin"), "*")

        reg_doc = PublisherKeyRegistryDocument.from_dict(get_resp.json())
        self.assertEqual(len(reg_doc.keys), 3)
        self.assertEqual(len(reg_doc.notaries), 2)
        self.assertIsNotNone(reg_doc.checkpoint)
        assert reg_doc.checkpoint is not None
        self.assertEqual(reg_doc.checkpoint.size, 0)

        ckpt_ok, ckpt_errs = verify_c2sp_checkpoint(
            reg_doc.checkpoint,
            publisher_public_key_hex=self.pub_kp.public_key_hex,
            trusted_witness_keys={"witness-cosigner-1": self.ckpt_witness_kp.public_key_hex},
            min_witness_cosignatures=1,
        )
        self.assertTrue(ckpt_ok, ckpt_errs)

    # ------------------------------------------------------------------
    # 5. All 5 Prospective Chain Invariants & Anti-Parallel-Reset Log
    # ------------------------------------------------------------------
    def _make_chain_bundle(
        self,
        *,
        proof_id: str,
        chain_id: str,
        seq: int,
        prev_hash: str | None,
        acct_tag: str,
        enrolled_at: str,
        start_utc: str,
        end_utc: str,
        issued_utc: str,
        cadence: ChainCadencePolicy,
        beg_idx: float,
        end_idx: float,
        twr_dec: float,
    ) -> VerifyProofBundle:
        link = ProspectiveChainLink(
            chain_id=chain_id,
            sequence_number=seq,
            prev_proof_hash=prev_hash,
            blinded_account_tag=acct_tag,
            enrolled_at_utc=enrolled_at,
            period_start_utc=start_utc,
            period_end_utc=end_utc,
            issued_at_utc=issued_utc,
            cadence_policy=cadence,
            beginning_index_value=beg_idx,
            ending_index_value=end_idx,
            period_twr_decimal=twr_dec,
        )
        return create_signed_proof_bundle(
            proof_id=proof_id,
            issued_at_utc=issued_utc,
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            broker_id="schwab",
            blinded_account_tag=acct_tag,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="56" * 32,
            period_start_utc=start_utc,
            period_end_utc=end_utc,
            base_currency="USD",
            leaf_payloads=_build_leaf_payloads(
                twr_decimal=twr_dec,
                period_start_utc=start_utc,
                period_end_utc=end_utc,
            ),
            prospective_chain_link=link,
        )

    def test_all_five_chain_invariants_and_anti_parallel_reset_continuity_log(self) -> None:
        cadence = ChainCadencePolicy(expected_interval_seconds=86400 * 30, grace_window_seconds=86400 * 3)
        acct_tag = compute_blinded_account_tag("schwab", "ACCT-LP-001", "bb" * 32)
        other_tag = compute_blinded_account_tag("schwab", "ACCT-LP-OTHER", "bb" * 32)

        # Invariant 1 failure: Genesis backfill window exceeded (> 24h enrollment delta)
        backfill_genesis = self._make_chain_bundle(
            proof_id="prf-backfill-0",
            chain_id="chain-backfill",
            seq=0,
            prev_hash=None,
            acct_tag=other_tag,
            enrolled_at="2026-01-20T00:00:00Z",  # 19 days after period_start_utc!
            start_utc="2026-01-01T00:00:00Z",
            end_utc="2026-01-31T00:00:00Z",
            issued_utc="2026-01-31T01:00:00Z",
            cadence=cadence,
            beg_idx=100.0,
            end_idx=105.0,
            twr_dec=0.05,
        )
        r_inv1 = self.client.post("/api/v1/chains", json={"proof_bundle": backfill_genesis.to_dict()})
        self.assertEqual(r_inv1.status_code, 422)
        self.assertIn(
            ChainInvariantViolationCode.GENESIS_BACKFILL_WINDOW_EXCEEDED.value,
            r_inv1.json()["violation_codes"],
        )

        # Valid Genesis Enrollment (sequence_number == 0, within 24h window)
        genesis = self._make_chain_bundle(
            proof_id="prf-lp-0",
            chain_id="chain-lp-main",
            seq=0,
            prev_hash=None,
            acct_tag=acct_tag,
            enrolled_at="2026-01-01T02:00:00Z",
            start_utc="2026-01-01T00:00:00Z",
            end_utc="2026-01-31T00:00:00Z",
            issued_utc="2026-01-31T02:00:00Z",
            cadence=cadence,
            beg_idx=100.0,
            end_idx=105.0,
            twr_dec=0.05,
        )
        r_gen = self.client.post(
            "/api/v1/chains",
            json={"proof_bundle": genesis.to_dict(), "opt_in_leaderboard": True},
        )
        self.assertEqual(r_gen.status_code, 201, r_gen.text)
        self.assertEqual(r_gen.json()["continuity_mode"], ChainContinuityMode.PROSPECTIVE_CONTINUOUS.value)
        self.assertEqual(r_gen.json()["log_leaf"]["log_index"], 0)
        self.assertEqual(r_gen.json()["checkpoint"]["size"], 1)

        # Anti-Parallel-Chain-Reset: Trying to start a NEW genesis chain (seq=0) for same blinded_account_tag!
        parallel_reset = self._make_chain_bundle(
            proof_id="prf-lp-reset-0",
            chain_id="chain-lp-sneaky-reset",
            seq=0,
            prev_hash=None,
            acct_tag=acct_tag,
            enrolled_at="2026-02-01T01:00:00Z",
            start_utc="2026-02-01T00:00:00Z",
            end_utc="2026-02-28T00:00:00Z",
            issued_utc="2026-02-28T01:00:00Z",
            cadence=cadence,
            beg_idx=100.0,
            end_idx=112.0,
            twr_dec=0.12,
        )
        r_reset = self.client.post("/api/v1/chains", json={"proof_bundle": parallel_reset.to_dict()})
        self.assertEqual(r_reset.status_code, 409)
        self.assertIn(
            ChainInvariantViolationCode.PARALLEL_CHAIN_RESET_DETECTED.value,
            r_reset.json()["violation_codes"],
        )

        # Invariant 2 failures: non-monotonic sequence, wrong prev_hash, mutated cadence
        bad_seq = self._make_chain_bundle(
            proof_id="prf-lp-bad-seq",
            chain_id="chain-lp-main",
            seq=2,  # skipped 1!
            prev_hash=genesis.proof_hash(),
            acct_tag=acct_tag,
            enrolled_at="2026-01-01T02:00:00Z",
            start_utc="2026-01-31T00:00:00Z",
            end_utc="2026-03-02T00:00:00Z",
            issued_utc="2026-03-02T02:00:00Z",
            cadence=cadence,
            beg_idx=105.0,
            end_idx=110.25,
            twr_dec=0.05,
        )
        r_bad_seq = self.client.post(
            "/api/v1/chains/chain-lp-main/append",
            json={"proof_bundle": bad_seq.to_dict()},
        )
        self.assertEqual(r_bad_seq.status_code, 422)
        self.assertIn(
            ChainInvariantViolationCode.NON_MONOTONIC_SEQUENCE.value,
            r_bad_seq.json()["violation_codes"],
        )

        bad_prev = self._make_chain_bundle(
            proof_id="prf-lp-bad-prev",
            chain_id="chain-lp-main",
            seq=1,
            prev_hash="ff" * 32,
            acct_tag=acct_tag,
            enrolled_at="2026-01-01T02:00:00Z",
            start_utc="2026-01-31T00:00:00Z",
            end_utc="2026-03-02T00:00:00Z",
            issued_utc="2026-03-02T02:00:00Z",
            cadence=cadence,
            beg_idx=105.0,
            end_idx=110.25,
            twr_dec=0.05,
        )
        r_bad_prev = self.client.post(
            "/api/v1/chains/chain-lp-main/append",
            json={"proof_bundle": bad_prev.to_dict()},
        )
        self.assertEqual(r_bad_prev.status_code, 422)
        self.assertIn(
            ChainInvariantViolationCode.PREV_HASH_MISMATCH.value,
            r_bad_prev.json()["violation_codes"],
        )

        bad_cadence = self._make_chain_bundle(
            proof_id="prf-lp-bad-cadence",
            chain_id="chain-lp-main",
            seq=1,
            prev_hash=genesis.proof_hash(),
            acct_tag=acct_tag,
            enrolled_at="2026-01-01T02:00:00Z",
            start_utc="2026-01-31T00:00:00Z",
            end_utc="2026-03-02T00:00:00Z",
            issued_utc="2026-03-02T02:00:00Z",
            cadence=ChainCadencePolicy(expected_interval_seconds=86400 * 90, grace_window_seconds=86400 * 10),
            beg_idx=105.0,
            end_idx=110.25,
            twr_dec=0.05,
        )
        r_bad_cadence = self.client.post(
            "/api/v1/chains/chain-lp-main/append",
            json={"proof_bundle": bad_cadence.to_dict()},
        )
        self.assertEqual(r_bad_cadence.status_code, 422)
        self.assertIn(
            ChainInvariantViolationCode.CADENCE_POLICY_MUTATED.value,
            r_bad_cadence.json()["violation_codes"],
        )

        # Invariant 3 failure: Switched blinded_account_tag mid-chain
        bad_acct = self._make_chain_bundle(
            proof_id="prf-lp-bad-acct",
            chain_id="chain-lp-main",
            seq=1,
            prev_hash=genesis.proof_hash(),
            acct_tag=other_tag,
            enrolled_at="2026-01-01T02:00:00Z",
            start_utc="2026-01-31T00:00:00Z",
            end_utc="2026-03-02T00:00:00Z",
            issued_utc="2026-03-02T02:00:00Z",
            cadence=cadence,
            beg_idx=105.0,
            end_idx=110.25,
            twr_dec=0.05,
        )
        r_bad_acct = self.client.post(
            "/api/v1/chains/chain-lp-main/append",
            json={"proof_bundle": bad_acct.to_dict()},
        )
        self.assertEqual(r_bad_acct.status_code, 422)
        self.assertIn(
            ChainInvariantViolationCode.ACCOUNT_CONTINUITY_VIOLATION.value,
            r_bad_acct.json()["violation_codes"],
        )

        # Invariant 4 failure: Missed/gap interval between prev.period_end_utc and curr.period_start_utc
        gap_link = self._make_chain_bundle(
            proof_id="prf-lp-gap",
            chain_id="chain-lp-main",
            seq=1,
            prev_hash=genesis.proof_hash(),
            acct_tag=acct_tag,
            enrolled_at="2026-01-01T02:00:00Z",
            start_utc="2026-02-05T00:00:00Z",  # 5-day gap hiding losses!
            end_utc="2026-03-02T00:00:00Z",
            issued_utc="2026-03-02T02:00:00Z",
            cadence=cadence,
            beg_idx=105.0,
            end_idx=110.25,
            twr_dec=0.05,
        )
        r_gap = self.client.post(
            "/api/v1/chains/chain-lp-main/append",
            json={"proof_bundle": gap_link.to_dict()},
        )
        self.assertEqual(r_gap.status_code, 422)
        self.assertIn(
            ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED.value,
            r_gap.json()["violation_codes"],
        )

        # Valid Link 1 Append
        link_1 = self._make_chain_bundle(
            proof_id="prf-lp-1",
            chain_id="chain-lp-main",
            seq=1,
            prev_hash=genesis.proof_hash(),
            acct_tag=acct_tag,
            enrolled_at="2026-01-01T02:00:00Z",
            start_utc="2026-01-31T00:00:00Z",
            end_utc="2026-03-02T00:00:00Z",
            issued_utc="2026-03-02T02:00:00Z",
            cadence=cadence,
            beg_idx=105.0,
            end_idx=110.25,
            twr_dec=0.05,
        )
        r_app1 = self.client.post(
            "/api/v1/chains/chain-lp-main/append",
            json={"proof_bundle": link_1.to_dict()},
        )
        self.assertEqual(r_app1.status_code, 200, r_app1.text)
        self.assertEqual(r_app1.json()["log_leaf"]["log_index"], 1)
        self.assertEqual(r_app1.json()["checkpoint"]["size"], 2)

        # Invariant 5: Presenting truncated tail [genesis] when seq=1 is in continuity log -> STALE_OR_TRUNCATED_TAIL!
        r_trunc = self.client.post(
            "/api/v1/proofs/verify",
            json={
                "proof_bundle": genesis.to_dict(),
                "chain_history": [genesis.to_dict()],
            },
        )
        self.assertEqual(r_trunc.status_code, 200)
        ver_trunc = BundleVerificationResult.from_dict(r_trunc.json())
        self.assertFalse(ver_trunc.valid)
        self.assertEqual(
            ver_trunc.effective_chain_continuity_mode,
            ChainContinuityMode.CONTINUITY_BROKEN,
        )
        assert ver_trunc.chain_verification is not None
        self.assertIn(
            ChainInvariantViolationCode.STALE_OR_TRUNCATED_TAIL,
            ver_trunc.chain_verification.violation_codes,
        )

        # Continuity log endpoint & SQLite append-only trigger check
        r_cont = self.client.get(f"/api/v1/continuity/{acct_tag}")
        self.assertEqual(r_cont.status_code, 200)
        self.assertEqual(r_cont.json()["entry_count"], 2)

        with self.assertRaises(sqlite3.IntegrityError):
            self.app.store._conn.execute("DELETE FROM continuity_log WHERE log_index = 0")
        with self.assertRaises(sqlite3.IntegrityError):
            self.app.store._conn.execute(
                "UPDATE continuity_log SET proof_hash = ? WHERE log_index = 0", ("00" * 32,)
            )

    # ------------------------------------------------------------------
    # 6. SVG Badge XSS Escaping + Dynamic Single-Notary Origin Downgrade
    # ------------------------------------------------------------------
    def test_svg_badge_xss_escaping_and_single_notary_dynamic_downgrade(self) -> None:
        source_sha = "77" * 32
        single_witness = create_signed_witness_attestation(
            notary_private_key_hex=self.notary_1_kp.private_key_hex,
            notary_id="notary-pse-1",
            server_sni="api.schwabapi.com",
            sanitized_request_target="/trader/v1/accounts/[redacted]/transactions",
            redacted_headers=["Authorization: [REDACTED]"],
            commitment_kind=TranscriptCommitmentKind.WHOLE_BODY_SHA256,
            response_body_sha256=source_sha,
            session_timestamp_utc="2026-02-01T12:00:00Z",
        )

        xss_proof_id = 'prf-<script>alert("xss")</script>&"quote\''
        xss_broker_id = 'schwab"><svg onload=alert(1)>'

        # Bundle over-claims INDEPENDENTLY_WITNESSED_TLS with only 1 notary witness!
        single_notary_bundle = create_signed_proof_bundle(
            proof_id=xss_proof_id,
            issued_at_utc="2026-02-01T12:05:00Z",
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            broker_id=xss_broker_id,
            blinded_account_tag="88" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
            source_body_sha256=source_sha,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            base_currency="USD",
            leaf_payloads=_build_leaf_payloads(twr_decimal=0.1234, psr=0.981),
            witness_attestations=[single_witness],
        )

        pub_r = self.client.post(
            "/api/v1/proofs",
            json={"proof_bundle": single_notary_bundle.to_dict()},
        )
        self.assertEqual(pub_r.status_code, 201, pub_r.text)

        encoded_id = quote(xss_proof_id, safe="")
        badge_r = self.client.get(f"/api/v1/badges/{encoded_id}.svg")
        self.assertEqual(badge_r.status_code, 200)
        self.assertIn("image/svg+xml", badge_r.headers.get("Content-Type", ""))
        self.assertIn("default-src 'none'", badge_r.headers.get("Content-Security-Policy", ""))

        svg_text = badge_r.text
        # Must parse as strictly valid XML (proves zero unescaped <, >, &, ")
        root = ET.fromstring(svg_text)
        self.assertTrue(root.tag.endswith("svg"))

        # Must NOT contain raw executable <script> or onload= elements/attributes
        self.assertNotIn("<script>", svg_text)
        self.assertNotIn("<svg onload=", svg_text)
        self.assertIn("&lt;script&gt;", svg_text)

        # Must render verifier-computed downgraded operator_retrieved, NEVER claimed independently_witnessed_tls!
        self.assertIn(OriginAssurance.OPERATOR_RETRIEVED.value, svg_text)
        self.assertNotIn(OriginAssurance.INDEPENDENTLY_WITNESSED_TLS.value, svg_text)
        self.assertIn(ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE.value, svg_text)
        self.assertIn(ChainContinuityMode.UNENROLLED_SINGLE_SNAPSHOT.value, svg_text)
        self.assertIn("+12.34%", svg_text)
        self.assertIn("98.1%", svg_text)

        # Confirm direct render_proof_badge_svg with 2 org/ASN-disjoint notaries upgrades to independently_witnessed_tls
        second_witness = create_signed_witness_attestation(
            notary_private_key_hex=self.notary_2_kp.private_key_hex,
            notary_id="notary-ch-2",
            server_sni="api.schwabapi.com",
            sanitized_request_target="/trader/v1/accounts/[redacted]/transactions",
            redacted_headers=["Authorization: [REDACTED]"],
            commitment_kind=TranscriptCommitmentKind.WHOLE_BODY_SHA256,
            response_body_sha256=source_sha,
            session_timestamp_utc="2026-02-01T12:00:05Z",
        )
        quorum_bundle = create_signed_proof_bundle(
            proof_id="prf-quorum-valid",
            issued_at_utc="2026-02-01T12:05:00Z",
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            broker_id="schwab",
            blinded_account_tag="89" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
            source_body_sha256=source_sha,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            base_currency="USD",
            leaf_payloads=_build_leaf_payloads(),
            witness_attestations=[single_witness, second_witness],
        )
        ver_q = self.app.store.verify_bundle_against_live_state(quorum_bundle)
        svg_q = render_proof_badge_svg(quorum_bundle, ver_q)
        self.assertIn(OriginAssurance.INDEPENDENTLY_WITNESSED_TLS.value, svg_q)

    # ------------------------------------------------------------------
    # 7. Leaderboard Merkle-Proven $10k+ Filtering & Assurance Filters
    # ------------------------------------------------------------------
    def test_leaderboard_merkle_proven_10k_default_and_assurance_filtering(self) -> None:
        source_sha = "91" * 32
        w1 = create_signed_witness_attestation(
            notary_private_key_hex=self.notary_1_kp.private_key_hex,
            notary_id="notary-pse-1",
            server_sni="api.schwabapi.com",
            sanitized_request_target="/trader/v1/accounts/[redacted]/balances",
            redacted_headers=["Authorization: [REDACTED]"],
            response_body_sha256=source_sha,
            session_timestamp_utc="2026-01-31T00:10:00Z",
        )
        w2 = create_signed_witness_attestation(
            notary_private_key_hex=self.notary_2_kp.private_key_hex,
            notary_id="notary-ch-2",
            server_sni="api.schwabapi.com",
            sanitized_request_target="/trader/v1/accounts/[redacted]/balances",
            redacted_headers=["Authorization: [REDACTED]"],
            response_body_sha256=source_sha,
            session_timestamp_utc="2026-01-31T00:10:03Z",
        )

        # Entry 1: $500 (under_1k) -> must be excluded by $10k+ default!
        b_under_1k = create_signed_proof_bundle(
            proof_id="prf-lb-under-1k",
            issued_at_utc="2026-01-31T01:00:00Z",
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            broker_id="schwab",
            blinded_account_tag="a1" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
            source_body_sha256=source_sha,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            base_currency="USD",
            leaf_payloads=_build_leaf_payloads(
                twr_decimal=0.90, capital_bracket=CapitalBracket.UNDER_1K
            ),
            witness_attestations=[w1, w2],
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/proofs",
                json={"proof_bundle": b_under_1k.to_dict(), "opt_in_leaderboard": True},
            ).status_code,
            201,
        )

        # Entry 2: $5,000 (bracket_1k_10k) -> must be excluded by $10k+ default!
        b_1k_10k = create_signed_proof_bundle(
            proof_id="prf-lb-1k-10k",
            issued_at_utc="2026-01-31T01:00:00Z",
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            broker_id="schwab",
            blinded_account_tag="a2" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
            source_body_sha256=source_sha,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            base_currency="USD",
            leaf_payloads=_build_leaf_payloads(
                twr_decimal=0.50, capital_bracket=CapitalBracket.BRACKET_1K_10K
            ),
            witness_attestations=[w1, w2],
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/proofs",
                json={"proof_bundle": b_1k_10k.to_dict(), "opt_in_leaderboard": True},
            ).status_code,
            201,
        )

        # Entry 3: $50k (bracket_10k_100k), witnessed TLS, all_enumerated_subaccounts, prospective_continuous!
        cadence = ChainCadencePolicy(expected_interval_seconds=86400 * 31, grace_window_seconds=86400 * 2)
        prospective_link = ProspectiveChainLink(
            chain_id="chain-lb-gold",
            sequence_number=0,
            prev_proof_hash=None,
            blinded_account_tag="a3" * 32,
            enrolled_at_utc="2026-01-01T01:00:00Z",
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            issued_at_utc="2026-01-31T01:00:00Z",
            cadence_policy=cadence,
            beginning_index_value=100.0,
            ending_index_value=118.0,
            period_twr_decimal=0.18,
        )
        b_gold = create_signed_proof_bundle(
            proof_id="prf-lb-gold-10k-100k",
            issued_at_utc="2026-01-31T01:00:00Z",
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            broker_id="schwab",
            blinded_account_tag="a3" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
            source_body_sha256=source_sha,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            base_currency="USD",
            leaf_payloads=_build_leaf_payloads(
                twr_decimal=0.18, psr=0.991, capital_bracket=CapitalBracket.BRACKET_10K_100K
            ),
            witness_attestations=[w1, w2],
            prospective_chain_link=prospective_link,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/chains",
                json={"proof_bundle": b_gold.to_dict(), "opt_in_leaderboard": True},
            ).status_code,
            201,
        )

        # Entry 4: $500k (bracket_100k_1m), self_reported, single_account_survivorship_unverified, unenrolled
        b_self = create_signed_proof_bundle(
            proof_id="prf-lb-self-100k",
            issued_at_utc="2026-01-31T01:00:00Z",
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            broker_id="ibkr_flex",
            blinded_account_tag="a4" * 32,
            account_scope=AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED,
            provider_approval_state=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,  # overclaimed -> downgraded to self_reported!
            source_body_sha256=source_sha,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            base_currency="USD",
            leaf_payloads=_build_leaf_payloads(
                twr_decimal=0.14, psr=0.94, capital_bracket=CapitalBracket.BRACKET_100K_1M
            ),
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/proofs",
                json={"proof_bundle": b_self.to_dict(), "opt_in_leaderboard": True},
            ).status_code,
            201,
        )

        # Entry 5: $500k where capital_bracket leaf is undisclosed (redacted) -> excluded because bracket unproven!
        b_hidden_bracket = create_signed_proof_bundle(
            proof_id="prf-lb-hidden-bracket",
            issued_at_utc="2026-01-31T01:00:00Z",
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            broker_id="schwab",
            blinded_account_tag="a5" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
            source_body_sha256=source_sha,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            base_currency="USD",
            leaf_payloads=_build_leaf_payloads(
                twr_decimal=0.35, capital_bracket=CapitalBracket.OVER_1M
            ),
            disclose_leaf_names=[n for n in CANONICAL_LEAF_NAMES if n != "capital_bracket"],
            witness_attestations=[w1, w2],
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/proofs",
                json={"proof_bundle": b_hidden_bracket.to_dict(), "opt_in_leaderboard": True},
            ).status_code,
            201,
        )

        # Entry 6: Non-opted-in >$1M bundle -> must never appear on leaderboard
        b_private = create_signed_proof_bundle(
            proof_id="prf-lb-private-not-opted-in",
            issued_at_utc="2026-01-31T01:00:00Z",
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            broker_id="schwab",
            blinded_account_tag="a6" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
            source_body_sha256=source_sha,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            base_currency="USD",
            leaf_payloads=_build_leaf_payloads(
                twr_decimal=0.60, capital_bracket=CapitalBracket.OVER_1M
            ),
            witness_attestations=[w1, w2],
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/proofs",
                json={"proof_bundle": b_private.to_dict(), "opt_in_leaderboard": False},
            ).status_code,
            201,
        )

        # Default GET /api/v1/leaderboard ($10k+ min_capital_bracket=bracket_10k_100k)
        lb_default = self.client.get("/api/v1/leaderboard")
        self.assertEqual(lb_default.status_code, 200, lb_default.text)
        ids_default = [e["proof_id"] for e in lb_default.json()["entries"]]
        self.assertEqual(ids_default, ["prf-lb-gold-10k-100k", "prf-lb-self-100k"])

        # Strict institutional filter: witnessed TLS + all_enumerated_subaccounts + prospective_continuous
        lb_strict = self.client.get(
            "/api/v1/leaderboard",
            params={
                "origin_assurance": "independently_witnessed_tls",
                "account_scope": "all_enumerated_subaccounts",
                "continuity_mode": "prospective_continuous",
                "min_capital_bracket": "bracket_10k_100k",
            },
        )
        self.assertEqual(lb_strict.status_code, 200)
        ids_strict = [e["proof_id"] for e in lb_strict.json()["entries"]]
        self.assertEqual(ids_strict, ["prf-lb-gold-10k-100k"])

        # Tampering with stored bundle's capital_bracket payload in DB invalidates Merkle check -> excluded!
        stored_row = self.app.store._conn.execute(
            "SELECT bundle_json FROM proofs WHERE proof_id = ?",
            ("prf-lb-under-1k",),
        ).fetchone()
        forged_dict = json.loads(str(stored_row["bundle_json"]))
        for leaf_d in forged_dict["disclosed_leaves"]:
            if leaf_d["leaf_name"] == "capital_bracket":
                leaf_d["payload"] = {"capital_bracket": CapitalBracket.OVER_1M.value}
        self.app.store._conn.execute(
            "UPDATE proofs SET bundle_json = ? WHERE proof_id = ?",
            (json.dumps(forged_dict), "prf-lb-under-1k"),
        )
        lb_after_tamper = self.client.get("/api/v1/leaderboard")
        self.assertNotIn(
            "prf-lb-under-1k",
            [e["proof_id"] for e in lb_after_tamper.json()["entries"]],
        )

    # ------------------------------------------------------------------
    # 8. Pure ASGI 3.0 Protocol Dispatch Verification
    # ------------------------------------------------------------------
    def test_pure_asgi_3_protocol_execution(self) -> None:
        raw_asgi: VerifyApiApplication = self.app

        async def _call_healthz() -> tuple[int, dict]:
            sent_events: list[dict] = []
            delivered = False

            async def receive() -> dict:
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": b"", "more_body": False}
                return {"type": "http.disconnect"}

            async def send(ev: dict) -> None:
                sent_events.append(dict(ev))

            scope = {
                "type": "http",
                "asgi": {"version": "3.0"},
                "method": "GET",
                "path": "/healthz",
                "raw_path": b"/healthz",
                "query_string": b"",
                "headers": [],
            }
            await raw_asgi(scope, receive, send)
            start_ev = sent_events[0]
            body_ev = sent_events[1]
            return int(start_ev["status"]), json.loads(body_ev["body"].decode("utf-8"))

        status_code, payload = asyncio.run(_call_healthz())
        self.assertEqual(status_code, 200)
        self.assertEqual(payload["status"], "ok")

    # ------------------------------------------------------------------
    # 9. Dependency-Injected Pipeline Protocol & Key Lifecycle Checks
    # ------------------------------------------------------------------
    def test_dependency_injected_pipeline_spec_in_spawn_worker(self) -> None:
        custom_app = create_app(
            self.config,
            pipeline_spec="test_api_lifecycle_and_security:sample_injected_wave3_pipeline",
            prefer_fastapi=False,
        )
        try:
            cclient = VerifyApiTestClient(custom_app)
            resp = cclient.post(
                "/api/v1/verify",
                json={
                    "broker_id": "schwab",
                    "raw_account_id": "WAVE3-HOOK-ACCT",
                    "period_start_utc": "2026-01-01T00:00:00Z",
                    "period_end_utc": "2026-01-31T00:00:00Z",
                },
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            bundle = VerifyProofBundle.from_dict(resp.json()["proof_bundle"])
            metrics = bundle.get_disclosed_payload("core_metrics")
            self.assertAlmostEqual(metrics["twr_decimal"], 0.215)
            self.assertAlmostEqual(metrics["probabilistic_sharpe_ratio"], 0.994)
            self.assertNotEqual(
                resp.json()["isolation_receipt"]["worker_pid"], os.getpid()
            )
        finally:
            custom_app.close()

    def test_retired_and_revoked_publisher_key_verification_routes(self) -> None:
        # Retired key within [not_before, not_after] -> RETIRED_HISTORICAL_VALID
        retired_bundle = create_signed_proof_bundle(
            proof_id="prf-retired-valid-2025",
            issued_at_utc="2025-06-15T12:00:00Z",
            publisher_kid="n170-retired-2025",
            publisher_private_key_hex=self.retired_kp.private_key_hex,
            broker_id="schwab",
            blinded_account_tag="b1" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="c1" * 32,
            period_start_utc="2025-05-01T00:00:00Z",
            period_end_utc="2025-05-31T00:00:00Z",
            base_currency="USD",
            leaf_payloads=_build_leaf_payloads(),
        )
        r_ret = self.client.post(
            "/api/v1/proofs/verify", json={"proof_bundle": retired_bundle.to_dict()}
        )
        self.assertEqual(r_ret.status_code, 200)
        self.assertTrue(r_ret.json()["valid"])
        self.assertEqual(
            r_ret.json()["signer_trust_status"],
            SignerTrustStatus.RETIRED_HISTORICAL_VALID.value,
        )

        # Revoked key -> REVOKED_KEY & rejected from /api/v1/proofs
        revoked_bundle = create_signed_proof_bundle(
            proof_id="prf-revoked-bad",
            issued_at_utc="2025-08-01T12:00:00Z",
            publisher_kid="n170-revoked-key",
            publisher_private_key_hex=self.revoked_kp.private_key_hex,
            broker_id="schwab",
            blinded_account_tag="b2" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="c2" * 32,
            period_start_utc="2025-07-01T00:00:00Z",
            period_end_utc="2025-07-31T00:00:00Z",
            base_currency="USD",
            leaf_payloads=_build_leaf_payloads(),
        )
        r_rev_ver = self.client.post(
            "/api/v1/proofs/verify", json={"proof_bundle": revoked_bundle.to_dict()}
        )
        self.assertEqual(r_rev_ver.status_code, 200)
        self.assertFalse(r_rev_ver.json()["valid"])
        self.assertEqual(
            r_rev_ver.json()["signer_trust_status"],
            SignerTrustStatus.REVOKED_KEY.value,
        )

        r_rev_pub = self.client.post(
            "/api/v1/proofs", json={"proof_bundle": revoked_bundle.to_dict()}
        )
        self.assertEqual(r_rev_pub.status_code, 422)

        # Missing proof & badge 404 checks
        self.assertEqual(self.client.get("/api/v1/proofs/missing-id").status_code, 404)
        self.assertEqual(self.client.get("/api/v1/badges/missing-id.svg").status_code, 404)
        self.assertEqual(self.client.get("/api/v1/chains/missing-chain").status_code, 404)


if __name__ == "__main__":
    unittest.main()
