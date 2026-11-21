"""Unit, security, and API integration tests for Ed25519 holder-signed /@<handle> Trader Profiles."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from app.routes_profiles import (
    HOLDER_LEADERBOARD_SIGNING_DOMAIN,
    HOLDER_PROFILE_SIGNING_DOMAIN,
    sign_holder_leaderboard_claim,
    sign_holder_profile_claim,
)
from app.store import ProofStore
from n170_verify.contracts import (
    AccountScope,
    EnvironmentTier,
    OriginAssurance,
    ProviderApprovalState,
    VerifyProofBundle,
    create_signed_proof_bundle,
)
from n170_verify.contracts.proof import HOLDER_SCHEMA_VERSION, SIGNING_DOMAIN_HOLDER
from n170_verify.crypto import (
    Ed25519KeyPair,
    ed25519_sign_domain,
    ed25519_verify_domain,
    generate_ed25519_keypair,
    jcs_canonicalize,
)

try:
    from tests.test_api_lifecycle_and_security import _build_leaf_payloads
except ImportError:  # pragma: no cover
    from test_api_lifecycle_and_security import _build_leaf_payloads


LEADERBOARD_ALL = "/api/v1/leaderboard?min_capital_bracket=under_1k&include_private_bracket=true"


def _attach_holder_identity(
    bundle: VerifyProofBundle,
    holder_kp: Ed25519KeyPair,
    *,
    display_name: str,
    handle: str | None = None,
) -> dict:
    claim = {
        "claimed_at_utc": bundle.issued_at_utc,
        "display_name": display_name,
        "handle": handle,
        "holder_public_key_hex": holder_kp.public_key_hex,
        "merkle_root": bundle.merkle_root,
        "profile_url": None,
        "proof_hash": bundle.proof_hash(),
        "proof_id": bundle.proof_id,
        "schema_version": HOLDER_SCHEMA_VERSION,
    }
    claim["signature_hex"] = ed25519_sign_domain(
        holder_kp.private_key_hex,
        SIGNING_DOMAIN_HOLDER,
        jcs_canonicalize(claim),
    )
    out = bundle.to_dict()
    out["holder_identity"] = claim
    return out


class TestHolderProfiles(unittest.TestCase):
    def setUp(self) -> None:
        self.publisher = generate_ed25519_keypair(bytes.fromhex("51" * 32))
        self.holder_kp = generate_ed25519_keypair(bytes.fromhex("62" * 32))
        self.mallory_kp = generate_ed25519_keypair(bytes.fromhex("73" * 32))
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
        self.app = create_app(self.config, prefer_fastapi=True)
        self.client = VerifyApiTestClient(self.app)

    def _signed_bundle(
        self,
        proof_id: str,
        *,
        period_start_utc: str = "2024-09-01T00:00:00Z",
        period_end_utc: str = "2025-12-31T00:00:00Z",
        issued_at_utc: str = "2026-01-10T12:00:00Z",
        twr_decimal: float = 0.25,
        provider_approval_state: ProviderApprovalState = ProviderApprovalState.APPROVED_LIVE,
        account_tag: str = "88" * 32,
    ) -> VerifyProofBundle:
        leaves = _build_leaf_payloads()
        leaves["core_metrics"]["twr_decimal"] = twr_decimal
        leaves["core_metrics"]["twr_pct"] = round(twr_decimal * 100.0, 2)
        leaves["delayed_closed_trades"] = {
            "embargo_days": 7,
            "stripped_recent_count": 0,
            "trades": [
                {
                    "symbol": "NVDA",
                    "entry_timestamp_utc": "2025-10-01T14:30:00Z",
                    "exit_timestamp_utc": "2025-11-15T19:00:00Z",
                    "holding_hours": 1084.5,
                    "realized_return_decimal": 0.18,
                }
            ],
        }
        return create_signed_proof_bundle(
            proof_id=proof_id,
            issued_at_utc=issued_at_utc,
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.publisher.private_key_hex,
            broker_id="ibkr_flex",
            blinded_account_tag=account_tag,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=provider_approval_state,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="99" * 32,
            period_start_utc=period_start_utc,
            period_end_utc=period_end_utc,
            base_currency="USD",
            leaf_payloads=leaves,
        )

    def test_claim_update_auto_latest_snapshot_release_history_and_pinning(self) -> None:
        # 1. Claim @geronik (George Geronik) before publishing any records
        claim_1 = sign_holder_profile_claim(
            holder_private_key_hex=self.holder_kp.private_key_hex,
            handle="@Geronik",
            display_name="George Geronik",
            bio="Systematic equity swing trader",
            profile_url="https://github.com/geronik",
            strategy_notes="Focus on earnings drift and high-RS breakouts.\nRisk capped per name.",
            watchlist=[
                {
                    "symbol": "nvda",
                    "thesis": "AI compute capex cycle leader",
                    "conviction": "high",
                    "status": "core",
                    "added_at_utc": "2026-01-05T10:00:00Z",
                },
                {
                    "symbol": "ASML",
                    "thesis": "EUV lithography monopoly",
                    "conviction": "medium",
                    "status": "watching",
                },
            ],
            conviction_list=[
                {
                    "symbol": "NVDA",
                    "thesis": "Multi-year data center buildout",
                    "conviction": "high",
                    "horizon": "1-3 years",
                }
            ],
            list_on_leaderboard=False,
            sequence_number=1,
            claimed_at_utc="2026-01-10T10:00:00Z",
        )
        r_create = self.client.post("/api/v1/profiles", json=claim_1)
        self.assertEqual(r_create.status_code, 201, r_create.text)
        body_1 = r_create.json()
        self.assertEqual(body_1["profile"]["handle"], "geronik")
        self.assertEqual(body_1["profile"]["handle_at"], "@geronik")
        self.assertEqual(body_1["profile"]["profile_path"], "/@geronik")
        self.assertEqual(body_1["profile"]["display_name"], "George Geronik")
        self.assertEqual(body_1["profile"]["watchlist"][0]["symbol"], "NVDA")
        self.assertEqual(body_1["profile"]["conviction_list"][0]["horizon"], "1-3 years")
        self.assertIsNone(body_1["active_proof"])
        self.assertEqual(body_1["release_count"], 0)

        # Verify total_row_counts() remains strictly the 3 canonical tables (zero-storage audit parity)
        self.assertEqual(
            self.app.verify_app.store.total_row_counts(),
            {"proofs": 0, "chains": 0, "continuity_log": 0},
        )

        # Lookup works by bare handle, @handle, and public key
        for url in (
            "/api/v1/profiles/geronik",
            "/api/v1/profiles/@geronik",
            f"/api/v1/profiles/by-key/{self.holder_kp.public_key_hex}",
        ):
            r_get = self.client.get(url)
            self.assertEqual(r_get.status_code, 200, f"{url}: {r_get.text}")
            self.assertEqual(r_get.json()["profile"]["handle"], "geronik")

        # 2. Publish older snapshot signed with holder key
        snap1 = self._signed_bundle(
            "prf-geronik-2025",
            period_end_utc="2025-12-31T00:00:00Z",
            issued_at_utc="2026-01-10T12:00:00Z",
            twr_decimal=0.22,
        )
        p1 = self.client.post(
            "/api/v1/proofs",
            json={
                "proof_bundle": _attach_holder_identity(
                    snap1, self.holder_kp, display_name="George Geronik", handle="@geronik"
                )
            },
        )
        self.assertEqual(p1.status_code, 201, p1.text)

        g1 = self.client.get("/api/v1/profiles/geronik").json()
        self.assertEqual(g1["active_proof_id"], "prf-geronik-2025")
        self.assertEqual(g1["release_count"], 1)
        self.assertEqual(g1["release_history"][0]["delayed_trades_count"], 1)
        self.assertTrue(g1["release_history"][0]["is_active"])
        self.assertTrue(g1["active_proof"]["verification"]["valid"])

        # 3. Publish newer snapshot under the SAME holder key -> /@geronik auto-updates active record!
        snap2 = self._signed_bundle(
            "prf-geronik-2026-q1",
            period_end_utc="2026-02-20T00:00:00Z",
            issued_at_utc="2026-02-21T12:00:00Z",
            twr_decimal=0.31,
        )
        p2 = self.client.post(
            "/api/v1/proofs",
            json={
                "proof_bundle": _attach_holder_identity(
                    snap2, self.holder_kp, display_name="George Geronik", handle="@geronik"
                )
            },
        )
        self.assertEqual(p2.status_code, 201, p2.text)

        g2 = self.client.get("/api/v1/profiles/geronik").json()
        self.assertEqual(g2["active_proof_id"], "prf-geronik-2026-q1")
        self.assertEqual(g2["release_count"], 2)
        self.assertEqual(
            [h["proof_id"] for h in g2["release_history"]],
            ["prf-geronik-2026-q1", "prf-geronik-2025"],
        )
        self.assertTrue(g2["release_history"][0]["is_active"])
        self.assertFalse(g2["release_history"][1]["is_active"])
        # Previous /p/<proof_id> snapshot remains live & independently verifiable
        self.assertEqual(self.client.get("/api/v1/proofs/prf-geronik-2025").status_code, 200)

        # 4. Pin snap1 via signed sequence_number=2 update
        claim_2 = sign_holder_profile_claim(
            holder_private_key_hex=self.holder_kp.private_key_hex,
            handle="geronik",
            display_name="George Geronik",
            bio="Updated bio",
            pinned_proof_id="prf-geronik-2025",
            sequence_number=2,
            claimed_at_utc="2026-02-22T10:00:00Z",
        )
        r_pin = self.client.post("/api/v1/profiles", json=claim_2)
        self.assertEqual(r_pin.status_code, 200, r_pin.text)
        self.assertEqual(r_pin.json()["active_proof_id"], "prf-geronik-2025")

        # Attempting to pin a proof NOT owned by this holder key fails with 422
        mallory_bundle = self._signed_bundle("prf-mallory-1", account_tag="77" * 32)
        self.assertEqual(
            self.client.post(
                "/api/v1/proofs",
                json={
                    "proof_bundle": _attach_holder_identity(
                        mallory_bundle, self.mallory_kp, display_name="Mallory"
                    )
                },
            ).status_code,
            201,
        )
        bad_pin = sign_holder_profile_claim(
            holder_private_key_hex=self.holder_kp.private_key_hex,
            handle="geronik",
            display_name="George Geronik",
            pinned_proof_id="prf-mallory-1",
            sequence_number=3,
            claimed_at_utc="2026-02-22T11:00:00Z",
        )
        self.assertEqual(self.client.post("/api/v1/profiles", json=bad_pin).status_code, 422)

    def test_holder_signed_leaderboard_toggle_and_auto_promotion(self) -> None:
        # Claim profile (unlisted initially) and publish snap1
        claim_1 = sign_holder_profile_claim(
            holder_private_key_hex=self.holder_kp.private_key_hex,
            handle="geronik",
            display_name="George Geronik",
            list_on_leaderboard=False,
            sequence_number=1,
            claimed_at_utc="2026-01-10T10:00:00Z",
        )
        self.assertEqual(self.client.post("/api/v1/profiles", json=claim_1).status_code, 201)

        snap1 = self._signed_bundle("prf-lb-1", period_end_utc="2025-12-31T00:00:00Z")
        self.assertEqual(
            self.client.post(
                "/api/v1/proofs",
                json={
                    "proof_bundle": _attach_holder_identity(
                        snap1, self.holder_kp, display_name="George Geronik"
                    )
                },
            ).status_code,
            201,
        )
        self.assertEqual(self.client.get(LEADERBOARD_ALL).json()["count"], 0)

        # Signed toggle ON -> listed on /api/v1/leaderboard with @geronik handle
        toggle_on = sign_holder_leaderboard_claim(
            holder_private_key_hex=self.holder_kp.private_key_hex,
            handle="geronik",
            list_on_leaderboard=True,
            sequence_number=2,
            claimed_at_utc="2026-01-11T10:00:00Z",
        )
        r_on = self.client.post("/api/v1/profiles/geronik/leaderboard", json=toggle_on)
        self.assertEqual(r_on.status_code, 200, r_on.text)
        body_on = r_on.json()
        self.assertTrue(body_on["profile"]["list_on_leaderboard"])

        # Both signed claims remain independently Ed25519 verifiable!
        p_claim = dict(body_on["profile"]["signed_claim"])
        p_sig = p_claim.pop("signature_hex")
        self.assertTrue(
            ed25519_verify_domain(
                self.holder_kp.public_key_hex,
                HOLDER_PROFILE_SIGNING_DOMAIN,
                jcs_canonicalize(p_claim),
                p_sig,
            )
        )
        lb_claim = dict(body_on["profile"]["leaderboard_signed_claim"])
        lb_sig = lb_claim.pop("signature_hex")
        self.assertTrue(
            ed25519_verify_domain(
                self.holder_kp.public_key_hex,
                HOLDER_LEADERBOARD_SIGNING_DOMAIN,
                jcs_canonicalize(lb_claim),
                lb_sig,
            )
        )

        lb_after_on = self.client.get(LEADERBOARD_ALL).json()
        self.assertEqual(lb_after_on["count"], 1)
        self.assertEqual(lb_after_on["entries"][0]["proof_id"], "prf-lb-1")
        self.assertEqual(lb_after_on["entries"][0]["holder_handle"], "@geronik")
        self.assertEqual(lb_after_on["entries"][0]["holder_display_name"], "George Geronik")

        # Publish newer snap2 (even with a different account tag and default opt_in=False) -> auto-promotes!
        snap2 = self._signed_bundle(
            "prf-lb-2",
            period_end_utc="2026-02-20T00:00:00Z",
            issued_at_utc="2026-02-21T12:00:00Z",
            account_tag="77" * 32,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/proofs",
                json={
                    "proof_bundle": _attach_holder_identity(
                        snap2, self.holder_kp, display_name="George Geronik"
                    )
                },
            ).status_code,
            201,
        )
        lb_after_snap2 = self.client.get(LEADERBOARD_ALL).json()
        self.assertEqual(lb_after_snap2["count"], 1)
        self.assertEqual(lb_after_snap2["entries"][0]["proof_id"], "prf-lb-2")

        # Signed toggle OFF -> unlisted immediately
        toggle_off = sign_holder_leaderboard_claim(
            holder_private_key_hex=self.holder_kp.private_key_hex,
            handle="geronik",
            list_on_leaderboard=False,
            sequence_number=3,
            claimed_at_utc="2026-02-22T10:00:00Z",
        )
        r_off = self.client.post("/api/v1/profiles/geronik/leaderboard", json=toggle_off)
        self.assertEqual(r_off.status_code, 200, r_off.text)
        self.assertFalse(r_off.json()["profile"]["list_on_leaderboard"])
        self.assertEqual(self.client.get(LEADERBOARD_ALL).json()["count"], 0)

    def test_security_defenses_signature_replay_hijack_reserved_bidi_privacy_and_hosted_governance(self) -> None:
        # 1. Tampered signature -> 422
        bad_sig = sign_holder_profile_claim(
            holder_private_key_hex=self.holder_kp.private_key_hex,
            handle="geronik",
            display_name="George Geronik",
            sequence_number=1,
            claimed_at_utc="2026-01-10T10:00:00Z",
        )
        bad_sig["bio"] = "Tampered after signing"
        r_bad = self.client.post("/api/v1/profiles", json=bad_sig)
        self.assertEqual(r_bad.status_code, 422)
        self.assertEqual(r_bad.json()["error"], "invalid_profile_signature")

        # 2. Valid claim
        valid_1 = sign_holder_profile_claim(
            holder_private_key_hex=self.holder_kp.private_key_hex,
            handle="geronik",
            display_name="George Geronik",
            sequence_number=1,
            claimed_at_utc="2026-01-10T10:00:00Z",
        )
        self.assertEqual(self.client.post("/api/v1/profiles", json=valid_1).status_code, 201)

        # 3. Replay with sequence_number == 1 -> 409 stale_profile_sequence
        r_replay = self.client.post("/api/v1/profiles", json=valid_1)
        self.assertEqual(r_replay.status_code, 409)
        self.assertEqual(r_replay.json()["error"], "stale_profile_sequence")

        # 4. Hijack attempt by Mallory -> 403 handle_owned_by_another_key
        hijack = sign_holder_profile_claim(
            holder_private_key_hex=self.mallory_kp.private_key_hex,
            handle="geronik",
            display_name="Mallory",
            sequence_number=5,
            claimed_at_utc="2026-01-11T10:00:00Z",
        )
        r_hijack = self.client.post("/api/v1/profiles", json=hijack)
        self.assertEqual(r_hijack.status_code, 403)
        self.assertEqual(r_hijack.json()["error"], "handle_owned_by_another_key")

        # Mallory trying leaderboard toggle on @geronik -> 403
        hijack_lb = sign_holder_leaderboard_claim(
            holder_private_key_hex=self.mallory_kp.private_key_hex,
            handle="geronik",
            list_on_leaderboard=True,
            sequence_number=5,
            claimed_at_utc="2026-01-11T10:00:00Z",
        )
        self.assertEqual(
            self.client.post("/api/v1/profiles/geronik/leaderboard", json=hijack_lb).status_code,
            403,
        )

        # 5. Reserved handles -> 422
        for reserved in ("leaderboard", "api", "connect", "admin"):
            r_res = self.client.post(
                "/api/v1/profiles",
                json={
                    "holder_public_key_hex": self.mallory_kp.public_key_hex,
                    "handle": reserved,
                    "display_name": "Test",
                    "sequence_number": 1,
                    "claimed_at_utc": "2026-01-10T10:00:00Z",
                    "signature_hex": "00" * 64,
                },
            )
            self.assertEqual(r_res.status_code, 422, f"reserved={reserved}")

        # 6. Forbidden Unicode bidi / HTML injection -> 422
        for bad_text_payload in (
            {"display_name": "Alice\u202eBob", "bio": ""},
            {"display_name": "Alice", "bio": "<script>alert(1)</script>"},
            {"display_name": "Alice", "strategy_notes": "Hello\u200bworld"},
            {"display_name": "Alice", "profile_url": "http://example.com"},
            {"display_name": "Alice", "profile_url": "https://127.0.0.1/x"},
        ):
            r_txt = self.client.post(
                "/api/v1/profiles",
                json={
                    "holder_public_key_hex": self.mallory_kp.public_key_hex,
                    "handle": "mallory1",
                    "sequence_number": 1,
                    "claimed_at_utc": "2026-01-10T10:00:00Z",
                    "signature_hex": "00" * 64,
                    **bad_text_payload,
                },
            )
            self.assertEqual(r_txt.status_code, 422)

        # 7. Watchlist / conviction share or dollar balance fields refused -> 422
        r_bal = self.client.post(
            "/api/v1/profiles",
            json={
                "holder_public_key_hex": self.mallory_kp.public_key_hex,
                "handle": "mallory2",
                "display_name": "Mallory",
                "watchlist": [{"symbol": "NVDA", "shares": 500}],
                "sequence_number": 1,
                "claimed_at_utc": "2026-01-10T10:00:00Z",
                "signature_hex": "00" * 64,
            },
        )
        self.assertEqual(r_bal.status_code, 422)

        # 8. Outbound privacy scanner blocks account number in strategy_notes without echoing it
        secret_acct = "U99887766"
        leaky_claim = sign_holder_profile_claim(
            holder_private_key_hex=self.mallory_kp.private_key_hex,
            handle="mallory3",
            display_name="Mallory",
            strategy_notes=f"My brokerage accountId={secret_acct} trades momentum.",
            sequence_number=1,
            claimed_at_utc="2026-01-10T10:00:00Z",
        )
        r_leak = self.client.post("/api/v1/profiles", json=leaky_claim)
        self.assertEqual(r_leak.status_code, 422, r_leak.text)
        self.assertEqual(r_leak.json()["error"], "privacy_content_refused")
        self.assertNotIn(secret_acct, r_leak.text)

        # 9. Hosted governance refuses unproven public-address record from listing on /leaderboard
        unproven_kp = generate_ed25519_keypair(bytes.fromhex("84" * 32))
        unproven_bundle = self._signed_bundle(
            "prf-unproven-pub",
            provider_approval_state=ProviderApprovalState.PUBLIC_API_PERMISSIONLESS,
            account_tag="55" * 32,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/proofs",
                json={
                    "proof_bundle": _attach_holder_identity(
                        unproven_bundle, unproven_kp, display_name="Public Wallet"
                    ),
                    "opt_in_leaderboard": False,
                },
            ).status_code,
            201,
        )
        unproven_claim = sign_holder_profile_claim(
            holder_private_key_hex=unproven_kp.private_key_hex,
            handle="pubwallet",
            display_name="Public Wallet",
            list_on_leaderboard=True,
            sequence_number=1,
            claimed_at_utc="2026-01-10T10:00:00Z",
        )
        r_gov = self.client.post("/api/v1/profiles", json=unproven_claim)
        self.assertEqual(r_gov.status_code, 403, r_gov.text)
        self.assertEqual(r_gov.json()["error"], "leaderboard_requires_proven_ownership")
        # Ensure atomic rollback: profile was NOT persisted
        self.assertEqual(self.client.get("/api/v1/profiles/pubwallet").status_code, 404)

    def test_existing_db_backfills_holder_public_key_on_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = str(Path(tmpdir) / "verify.db")
            cfg = ApiConfig(
                publisher_keypair=self.publisher,
                publisher_kid="n170-active-2026",
                publisher_key_not_before_utc="2025-01-01T00:00:00Z",
                hosted_multi_user_mode=True,
                db_path=db_file,
                sync_db_path=":memory:",
                vault_master_kek_hex="aa" * 32,
                account_blinding_salt_hex="bb" * 32,
            )
            store1 = ProofStore(cfg)
            snap = self._signed_bundle("prf-backfill-1")
            b_with_holder = VerifyProofBundle.from_dict(
                _attach_holder_identity(snap, self.holder_kp, display_name="George Geronik")
            )
            store1.publish_proof(b_with_holder)
            # Simulate pre-upgrade DB row with NULL holder_public_key_hex
            store1._conn.execute("UPDATE proofs SET holder_public_key_hex = NULL")
            store1.close()

            # Re-open store -> _backfill_proof_holder_pubkeys restores the index
            store2 = ProofStore(cfg)
            try:
                found = store2.list_proofs_for_holder_key(self.holder_kp.public_key_hex)
                self.assertEqual([e.bundle.proof_id for e in found], ["prf-backfill-1"])
            finally:
                store2.close()

    def test_manage_holder_profile_cli_signs_without_leaking_private_key(self) -> None:
        from scripts.manage_holder_profile import load_holder_private_key_hex, main as cli_main

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "holder.json"
            key_path.write_text(
                json.dumps({"private_key_hex": self.holder_kp.private_key_hex}),
                encoding="utf-8",
            )
            os.chmod(key_path, 0o600)

            watchlist_path = Path(tmpdir) / "watchlist.json"
            watchlist_path.write_text(
                json.dumps([{"symbol": "NVDA", "thesis": "Core compounder", "conviction": "high", "status": "core"}]),
                encoding="utf-8",
            )

            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()
            with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                rc = cli_main(
                    [
                        "--key-file",
                        str(key_path),
                        "--strict-perms",
                        "--dry-run",
                        "upsert",
                        "--handle",
                        "@geronik",
                        "--display-name",
                        "George Geronik",
                        "--bio",
                        "CLI signed profile",
                        "--watchlist-json",
                        str(watchlist_path),
                        "--sequence",
                        "1",
                    ]
                )
            self.assertEqual(rc, 0, stderr_buf.getvalue())
            out_text = stdout_buf.getvalue()
            self.assertNotIn(self.holder_kp.private_key_hex, out_text)
            self.assertNotIn(self.holder_kp.private_key_hex, stderr_buf.getvalue())

            signed_payload = json.loads(out_text)
            resp = self.client.post("/api/v1/profiles", json=signed_payload)
            self.assertEqual(resp.status_code, 201, resp.text)
            self.assertEqual(resp.json()["profile"]["handle"], "geronik")

            # Also verify JWK loader parity
            jwk_path = Path(tmpdir) / "holder_jwk.json"
            d_b64 = base64.urlsafe_b64encode(bytes.fromhex(self.holder_kp.private_key_hex)).decode("ascii").rstrip("=")
            jwk_path.write_text(
                json.dumps({"kty": "OKP", "crv": "Ed25519", "d": d_b64}),
                encoding="utf-8",
            )
            os.chmod(jwk_path, 0o600)
            self.assertEqual(
                load_holder_private_key_hex(jwk_path, strict_perms=True),
                self.holder_kp.private_key_hex,
            )

    def test_handle_rename_preserves_history_and_hosted_clock_refusal(self) -> None:
        # Claim @geronik and publish a proof
        c1 = sign_holder_profile_claim(
            holder_private_key_hex=self.holder_kp.private_key_hex,
            handle="geronik",
            display_name="George Geronik",
            sequence_number=1,
            claimed_at_utc="2026-01-10T10:00:00Z",
        )
        self.assertEqual(self.client.post("/api/v1/profiles", json=c1).status_code, 201)

        snap = self._signed_bundle("prf-rename-1")
        self.assertEqual(
            self.client.post(
                "/api/v1/proofs",
                json={
                    "proof_bundle": _attach_holder_identity(
                        snap, self.holder_kp, display_name="George Geronik"
                    )
                },
            ).status_code,
            201,
        )

        # Hosted mode refuses caller-supplied now_utc on profile reads and writes
        clock_get = self.client.get(
            "/api/v1/profiles/geronik", params={"now_utc": "2026-01-10T12:00:00Z"}
        )
        self.assertEqual(clock_get.status_code, 400)
        self.assertEqual(clock_get.json()["error"], "caller_clock_not_accepted")

        # Same holder key renames @geronik -> @george_g
        c2 = sign_holder_profile_claim(
            holder_private_key_hex=self.holder_kp.private_key_hex,
            handle="george_g",
            display_name="George Geronik",
            sequence_number=2,
            claimed_at_utc="2026-01-11T10:00:00Z",
        )
        r_rename = self.client.post("/api/v1/profiles", json=c2)
        self.assertEqual(r_rename.status_code, 200, r_rename.text)
        self.assertEqual(r_rename.json()["profile"]["handle"], "george_g")
        self.assertEqual(r_rename.json()["active_proof_id"], "prf-rename-1")
        self.assertEqual(self.client.get("/api/v1/profiles/geronik").status_code, 404)
        self.assertEqual(self.client.get("/api/v1/profiles/george_g").status_code, 200)

    def test_chain_enrollment_and_append_auto_link_to_holder_profile(self) -> None:
        from n170_verify.crypto import ChainCadencePolicy, ProspectiveChainLink

        c1 = sign_holder_profile_claim(
            holder_private_key_hex=self.holder_kp.private_key_hex,
            handle="chaintrader",
            display_name="Chain Trader",
            list_on_leaderboard=True,
            sequence_number=1,
            claimed_at_utc="2026-01-10T10:00:00Z",
        )
        self.assertEqual(self.client.post("/api/v1/profiles", json=c1).status_code, 201)

        acct_tag = "cc" * 32
        cadence = ChainCadencePolicy(
            expected_interval_seconds=30 * 86400,
            grace_window_seconds=7 * 86400,
        )
        leaves0 = _build_leaf_payloads()
        leaves0["core_metrics"]["twr_decimal"] = 0.10
        leaves0["core_metrics"]["twr_pct"] = 10.0
        link0 = ProspectiveChainLink(
            chain_id="chn-holder-profile-1",
            blinded_account_tag=acct_tag,
            sequence_number=0,
            prev_proof_hash=None,
            enrolled_at_utc="2026-01-01T00:00:00Z",
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            issued_at_utc="2026-02-01T00:00:00Z",
            beginning_index_value=100.0,
            ending_index_value=110.0,
            period_twr_decimal=0.10,
            cadence_policy=cadence,
        )
        b0 = create_signed_proof_bundle(
            proof_id="prf-chn-0",
            issued_at_utc="2026-02-01T00:00:00Z",
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.publisher.private_key_hex,
            broker_id="ibkr_flex",
            blinded_account_tag=acct_tag,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="aa" * 32,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            base_currency="USD",
            leaf_payloads=leaves0,
            prospective_chain_link=link0,
        )
        r_enr = self.client.post(
            "/api/v1/chains",
            json={
                "proof_bundle": _attach_holder_identity(
                    b0, self.holder_kp, display_name="Chain Trader"
                ),
                "opt_in_leaderboard": False,
                "allow_retrospective_backfill": True,
            },
        )
        self.assertEqual(r_enr.status_code, 201, r_enr.text)

        leaves1 = _build_leaf_payloads()
        leaves1["core_metrics"]["twr_decimal"] = 0.05
        leaves1["core_metrics"]["twr_pct"] = 5.0
        link1 = ProspectiveChainLink(
            chain_id="chn-holder-profile-1",
            blinded_account_tag=acct_tag,
            sequence_number=1,
            prev_proof_hash=b0.proof_hash(),
            enrolled_at_utc="2026-01-01T00:00:00Z",
            period_start_utc="2026-01-31T00:00:00Z",
            period_end_utc="2026-02-28T00:00:00Z",
            issued_at_utc="2026-03-01T00:00:00Z",
            beginning_index_value=110.0,
            ending_index_value=115.5,
            period_twr_decimal=0.05,
            cadence_policy=cadence,
        )
        b1 = create_signed_proof_bundle(
            proof_id="prf-chn-1",
            issued_at_utc="2026-03-01T00:00:00Z",
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.publisher.private_key_hex,
            broker_id="ibkr_flex",
            blinded_account_tag=acct_tag,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="bb" * 32,
            period_start_utc="2026-01-31T00:00:00Z",
            period_end_utc="2026-02-28T00:00:00Z",
            base_currency="USD",
            leaf_payloads=leaves1,
            prospective_chain_link=link1,
        )
        r_app = self.client.post(
            "/api/v1/chains/chn-holder-profile-1/append",
            json={
                "proof_bundle": _attach_holder_identity(
                    b1, self.holder_kp, display_name="Chain Trader"
                ),
            },
        )
        self.assertEqual(r_app.status_code, 200, r_app.text)

        prof = self.client.get("/api/v1/profiles/chaintrader").json()
        self.assertEqual(prof["active_proof_id"], "prf-chn-1")
        self.assertEqual([h["proof_id"] for h in prof["release_history"]], ["prf-chn-1", "prf-chn-0"])
        lb = self.client.get(LEADERBOARD_ALL).json()
        self.assertEqual(lb["count"], 1)
        self.assertEqual(lb["entries"][0]["proof_id"], "prf-chn-1")
        self.assertEqual(lb["entries"][0]["holder_handle"], "@chaintrader")

    def test_signed_unlist_prevents_chain_append_resurgence_and_unsigned_opt_in_bypass(self) -> None:
        from n170_verify.crypto import ChainCadencePolicy, ProspectiveChainLink

        # 1. Enroll chain with opt_in_leaderboard=True BEFORE claiming profile
        acct_tag = "cd" * 32
        cadence = ChainCadencePolicy(
            expected_interval_seconds=30 * 86400,
            grace_window_seconds=7 * 86400,
        )
        leaves0 = _build_leaf_payloads()
        leaves0["core_metrics"]["twr_decimal"] = 0.10
        leaves0["core_metrics"]["twr_pct"] = 10.0
        link0 = ProspectiveChainLink(
            chain_id="chn-unlist-guard",
            blinded_account_tag=acct_tag,
            sequence_number=0,
            prev_proof_hash=None,
            enrolled_at_utc="2026-01-01T00:00:00Z",
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            issued_at_utc="2026-02-01T00:00:00Z",
            beginning_index_value=100.0,
            ending_index_value=110.0,
            period_twr_decimal=0.10,
            cadence_policy=cadence,
        )
        b0 = create_signed_proof_bundle(
            proof_id="prf-unlist-chn-0",
            issued_at_utc="2026-02-01T00:00:00Z",
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.publisher.private_key_hex,
            broker_id="ibkr_flex",
            blinded_account_tag=acct_tag,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="aa" * 32,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            base_currency="USD",
            leaf_payloads=leaves0,
            prospective_chain_link=link0,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/chains",
                json={
                    "proof_bundle": _attach_holder_identity(
                        b0, self.holder_kp, display_name="George Geronik"
                    ),
                    "opt_in_leaderboard": True,
                    "allow_retrospective_backfill": True,
                },
            ).status_code,
            201,
        )
        self.assertEqual(self.client.get(LEADERBOARD_ALL).json()["count"], 1)

        # 2. Holder claims @geronik with list_on_leaderboard=False -> unlisted immediately
        c1 = sign_holder_profile_claim(
            holder_private_key_hex=self.holder_kp.private_key_hex,
            handle="geronik",
            display_name="George Geronik",
            list_on_leaderboard=False,
            sequence_number=1,
            claimed_at_utc="2026-02-02T10:00:00Z",
        )
        self.assertEqual(self.client.post("/api/v1/profiles", json=c1).status_code, 201)
        self.assertEqual(self.client.get(LEADERBOARD_ALL).json()["count"], 0)

        # 3. Appending seq 1 to the chain MUST NOT resurrect leaderboard listing
        leaves1 = _build_leaf_payloads()
        leaves1["core_metrics"]["twr_decimal"] = 0.05
        leaves1["core_metrics"]["twr_pct"] = 5.0
        link1 = ProspectiveChainLink(
            chain_id="chn-unlist-guard",
            blinded_account_tag=acct_tag,
            sequence_number=1,
            prev_proof_hash=b0.proof_hash(),
            enrolled_at_utc="2026-01-01T00:00:00Z",
            period_start_utc="2026-01-31T00:00:00Z",
            period_end_utc="2026-02-28T00:00:00Z",
            issued_at_utc="2026-03-01T00:00:00Z",
            beginning_index_value=110.0,
            ending_index_value=115.5,
            period_twr_decimal=0.05,
            cadence_policy=cadence,
        )
        b1 = create_signed_proof_bundle(
            proof_id="prf-unlist-chn-1",
            issued_at_utc="2026-03-01T00:00:00Z",
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.publisher.private_key_hex,
            broker_id="ibkr_flex",
            blinded_account_tag=acct_tag,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="bb" * 32,
            period_start_utc="2026-01-31T00:00:00Z",
            period_end_utc="2026-02-28T00:00:00Z",
            base_currency="USD",
            leaf_payloads=leaves1,
            prospective_chain_link=link1,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/chains/chn-unlist-guard/append",
                json={
                    "proof_bundle": _attach_holder_identity(
                        b1, self.holder_kp, display_name="George Geronik"
                    )
                },
            ).status_code,
            200,
        )
        self.assertEqual(self.client.get(LEADERBOARD_ALL).json()["count"], 0)

        # 4. Unauthenticated POST /api/v1/proofs with opt_in_leaderboard=True MUST NOT bypass signed unlist
        b2 = self._signed_bundle("prf-unsigned-optin-bypass", account_tag="de" * 32)
        self.assertEqual(
            self.client.post(
                "/api/v1/proofs",
                json={
                    "proof_bundle": _attach_holder_identity(
                        b2, self.holder_kp, display_name="George Geronik"
                    ),
                    "opt_in_leaderboard": True,
                },
            ).status_code,
            201,
        )
        self.assertEqual(self.client.get(LEADERBOARD_ALL).json()["count"], 0)
        # GET /api/v1/proofs/{id} also links back to the claimed holder_profile
        g_proof = self.client.get("/api/v1/proofs/prf-unsigned-optin-bypass").json()
        self.assertEqual(g_proof["holder_profile"]["handle"], "geronik")
        self.assertEqual(g_proof["holder_profile"]["profile_path"], "/@geronik")
        self.assertFalse(g_proof["opt_in_leaderboard"])

    def test_reserved_by_key_bad_now_utc_release_metrics_and_timestamp_tiebreak(self) -> None:
        from app.store import StoredProofEntry

        # 1. 'by-key' is reserved and cannot be squatted
        r_bykey = self.client.post(
            "/api/v1/profiles",
            json={
                "holder_public_key_hex": self.mallory_kp.public_key_hex,
                "handle": "by-key",
                "display_name": "Mallory",
                "sequence_number": 1,
                "claimed_at_utc": "2026-01-10T10:00:00Z",
                "signature_hex": "00" * 64,
            },
        )
        self.assertEqual(r_bykey.status_code, 422)

        # 2. Invalid now_utc returns 422 BEFORE persisting anything (when allow_caller_clock_for_tests=True)
        cfg_clk = ApiConfig(
            publisher_keypair=self.publisher,
            publisher_kid="n170-active-2026",
            publisher_key_not_before_utc="2025-01-01T00:00:00Z",
            hosted_multi_user_mode=False,
            allow_caller_clock_for_tests=True,
            db_path=":memory:",
            sync_db_path=":memory:",
            vault_master_kek_hex="aa" * 32,
            account_blinding_salt_hex="bb" * 32,
        )
        cl_clk = VerifyApiTestClient(create_app(cfg_clk, prefer_fastapi=False))
        c1 = sign_holder_profile_claim(
            holder_private_key_hex=self.holder_kp.private_key_hex,
            handle="clocktest",
            display_name="Clock Tester",
            sequence_number=1,
            claimed_at_utc="2026-01-10T10:00:00Z",
        )
        r_bad = cl_clk.post("/api/v1/profiles", json={**c1, "now_utc": "not-a-timestamp"})
        self.assertEqual(r_bad.status_code, 422, r_bad.text)
        self.assertEqual(cl_clk.get("/api/v1/profiles/clocktest").status_code, 404)

        self.assertEqual(cl_clk.post("/api/v1/profiles", json=c1).status_code, 201)
        self.assertEqual(
            cl_clk.get("/api/v1/profiles/clocktest", params={"now_utc": "bad-ts"}).status_code,
            422,
        )
        self.assertEqual(
            cl_clk.get(
                f"/api/v1/profiles/by-key/{self.holder_kp.public_key_hex}",
                params={"now_utc": "bad-ts"},
            ).status_code,
            422,
        )
        t_lb = sign_holder_leaderboard_claim(
            holder_private_key_hex=self.holder_kp.private_key_hex,
            handle="clocktest",
            list_on_leaderboard=True,
            sequence_number=2,
            claimed_at_utc="2026-01-11T10:00:00Z",
        )
        self.assertEqual(
            cl_clk.post(
                "/api/v1/profiles/clocktest/leaderboard",
                json={**t_lb, "now_utc": "bad-ts"},
            ).status_code,
            422,
        )
        self.assertFalse(cl_clk.get("/api/v1/profiles/clocktest").json()["profile"]["list_on_leaderboard"])

        # 3. release_history uses unsmoothed_sharpe_ratio, gates PSR < 30 obs, and suppresses withheld returns
        leaves_glm = _build_leaf_payloads()
        leaves_glm["core_metrics"]["sharpe_ratio"] = 2.40
        leaves_glm["core_metrics"]["unsmoothed_sharpe_ratio"] = 1.65
        leaves_glm["core_metrics"]["observation_count"] = 20
        leaves_glm["core_metrics"]["psr_sample_eligible"] = False
        leaves_glm["core_metrics"]["probabilistic_sharpe_ratio"] = 0.99
        b_glm = create_signed_proof_bundle(
            proof_id="prf-glm-check",
            issued_at_utc="2026-01-10T12:00:00Z",
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.publisher.private_key_hex,
            broker_id="ibkr_flex",
            blinded_account_tag="91" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="91" * 32,
            period_start_utc="2025-11-01T00:00:00Z",
            period_end_utc="2025-12-31T00:00:00Z",
            base_currency="USD",
            leaf_payloads=leaves_glm,
        )
        leaves_withheld = _build_leaf_payloads()
        leaves_withheld["core_metrics"]["performance_withheld"] = True
        leaves_withheld["core_metrics"]["withheld_reasons"] = ["insufficient_nav_history"]
        leaves_withheld["core_metrics"]["twr_decimal"] = 0.0
        leaves_withheld["core_metrics"]["twr_pct"] = 0.0
        b_withheld = create_signed_proof_bundle(
            proof_id="prf-withheld-check",
            issued_at_utc="2026-01-05T12:00:00Z",
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.publisher.private_key_hex,
            broker_id="ibkr_flex",
            blinded_account_tag="92" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="92" * 32,
            period_start_utc="2025-10-01T00:00:00Z",
            period_end_utc="2025-11-30T00:00:00Z",
            base_currency="USD",
            leaf_payloads=leaves_withheld,
        )
        for b in (b_glm, b_withheld):
            self.assertEqual(
                cl_clk.post(
                    "/api/v1/proofs",
                    json={"proof_bundle": _attach_holder_identity(b, self.holder_kp, display_name="Clock Tester")},
                ).status_code,
                201,
            )
        hist = {
            item["proof_id"]: item
            for item in cl_clk.get("/api/v1/profiles/clocktest").json()["release_history"]
        }
        self.assertAlmostEqual(hist["prf-glm-check"]["sharpe_ratio"], 1.65, places=6)
        self.assertIsNone(hist["prf-glm-check"]["probabilistic_sharpe_ratio"])
        self.assertFalse(hist["prf-glm-check"]["performance_withheld"])
        self.assertTrue(hist["prf-withheld-check"]["performance_withheld"])
        self.assertIsNone(hist["prf-withheld-check"]["twr_decimal"])
        self.assertIsNone(hist["prf-withheld-check"]["sharpe_ratio"])

        # 4. Chronological stored_at_utc tie-breaking handles fractional seconds vs trailing Z
        e_earlier = StoredProofEntry(
            bundle=b_glm, proof_hash="11" * 32, opt_in_leaderboard=False, stored_at_utc="2026-03-01T12:00:00Z"
        )
        e_later = StoredProofEntry(
            bundle=b_glm, proof_hash="22" * 32, opt_in_leaderboard=False, stored_at_utc="2026-03-01T12:00:00.500000Z"
        )
        ordered = ProofStore._sort_holder_proof_entries([e_earlier, e_later])
        self.assertEqual(ordered[0].stored_at_utc, "2026-03-01T12:00:00.500000Z")

    def test_manage_holder_profile_cli_partial_update_preserves_existing_fields(self) -> None:
        from unittest import mock
        from scripts import manage_holder_profile as cli_mod

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "holder.json"
            key_path.write_text(
                json.dumps({"private_key_hex": self.holder_kp.private_key_hex}),
                encoding="utf-8",
            )
            os.chmod(key_path, 0o600)

            wl_path = Path(tmpdir) / "watchlist.json"
            wl_path.write_text(
                json.dumps([{"symbol": "ASML", "thesis": "Lithography leader", "conviction": "high", "status": "core"}]),
                encoding="utf-8",
            )

            # Seed profile with bio, strategy_notes, conviction_list, and list_on_leaderboard=True
            seed = sign_holder_profile_claim(
                holder_private_key_hex=self.holder_kp.private_key_hex,
                handle="geronik",
                display_name="George Geronik",
                bio="Original bio",
                profile_url="https://github.com/geronik",
                strategy_notes="Keep risk tight.",
                conviction_list=[{"symbol": "NVDA", "thesis": "AI infra", "conviction": "high", "horizon": "2y"}],
                list_on_leaderboard=True,
                sequence_number=1,
                claimed_at_utc="2026-01-10T10:00:00Z",
            )
            self.assertEqual(self.client.post("/api/v1/profiles", json=seed).status_code, 201)

            def fake_http(method: str, url: str, payload: dict | None = None, *, timeout: float = 20.0):
                path = url.split("http://127.0.0.1:8080", 1)[1]
                if method == "GET":
                    resp = self.client.get(path)
                else:
                    resp = self.client.post(path, json=payload)
                return resp.status_code, resp.json()

            out_buf = io.StringIO()
            with mock.patch.object(cli_mod, "_http_json", side_effect=fake_http):
                with contextlib.redirect_stdout(out_buf):
                    rc = cli_mod.main(
                        [
                            "--key-file",
                            str(key_path),
                            "--strict-perms",
                            "upsert",
                            "--handle",
                            "@geronik",
                            "--display-name",
                            "George Geronik",
                            "--watchlist-json",
                            str(wl_path),
                        ]
                    )
            self.assertEqual(rc, 0, out_buf.getvalue())
            updated = self.client.get("/api/v1/profiles/geronik").json()["profile"]
            self.assertEqual(updated["sequence_number"], 2)
            self.assertEqual(updated["bio"], "Original bio")
            self.assertEqual(updated["profile_url"], "https://github.com/geronik")
            self.assertEqual(updated["strategy_notes"], "Keep risk tight.")
            self.assertTrue(updated["list_on_leaderboard"])
            self.assertEqual(updated["conviction_list"][0]["symbol"], "NVDA")
            self.assertEqual(updated["watchlist"][0]["symbol"], "ASML")


if __name__ == "__main__":
    unittest.main()
