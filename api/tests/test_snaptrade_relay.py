"""Comprehensive tests for the 5-slot SnapTrade V1 relay routes and hosted signing-oracle closure."""

from __future__ import annotations

import json
import os
from typing import Any
import unittest
from unittest import mock
import urllib.parse

from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from app.privacy_scanner import OutboundPrivacyScanner
from app.routes_snaptrade import SnapTradeRelayCoordinator
from n170_verify.connectors import compute_snaptrade_signature
from n170_verify.contracts import (
    CapitalBracket,
    EnvironmentTier,
    ProviderApprovalState,
    VerifyProofBundle,
    verify_proof_bundle,
)
from n170_verify.crypto import CANONICAL_LEAF_NAMES, generate_ed25519_keypair


def _make_mock_snaptrade_transport(
    *,
    expected_client_id: str = "N170-SNAP-DEV-CLIENT",
    expected_consumer_key: str = "snap-hmac-consumer-secret-xyz-12345",
) -> tuple[Any, list[dict[str, Any]]]:
    """Return a mock HTTP transport verifying SnapTrade V1 HMAC-SHA256 signatures with zero network calls."""
    recorded: list[dict[str, Any]] = []
    secret_counter = 0

    def transport(
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
    ) -> tuple[int, dict[str, str], Any]:
        nonlocal secret_counter
        parsed = urllib.parse.urlsplit(url)
        qs = urllib.parse.parse_qs(parsed.query)

        # Enforce zero consumerKey or userSecret in HTTP headers
        lower_keys = {k.lower() for k in headers}
        assert "consumerkey" not in lower_keys, f"Leaked consumerKey header in {headers}"
        assert "usersecret" not in lower_keys, f"Leaked userSecret header in {headers}"
        assert "signature" in lower_keys, f"Missing Signature header in {headers}"

        body_obj = json.loads(body.decode("utf-8")) if body else None
        expected_sig = compute_snaptrade_signature(
            expected_consumer_key,
            api_path=parsed.path,
            query_string=parsed.query,
            content=body_obj,
        )
        actual_sig = headers.get("Signature") or headers.get("signature")
        assert actual_sig == expected_sig, f"Signature mismatch on {method} {parsed.path}"
        assert qs.get("clientId") == [expected_client_id]

        recorded.append(
            {
                "method": method,
                "path": parsed.path,
                "query": qs,
                "body": body_obj,
            }
        )

        if method == "POST" and parsed.path == "/api/v1/snapTrade/registerUser":
            secret_counter += 1
            uid = str((body_obj or {}).get("userId", ""))
            return (
                200,
                {"Content-Type": "application/json"},
                {
                    "userId": uid,
                    "userSecret": f"snap-ephemeral-user-secret-{secret_counter:04d}-supersecret",
                },
            )

        if method == "POST" and parsed.path == "/api/v1/snapTrade/login":
            assert (body_obj or {}).get("connectionType") == "read"
            assert (body_obj or {}).get("immediateRedirect") is True
            broker_slug = (body_obj or {}).get("broker") or "ALL"
            return (
                200,
                {"Content-Type": "application/json"},
                {
                    "redirectURI": f"https://app.snaptrade.com/portal/session?broker={broker_slug}",
                    "sessionId": f"portal-sess-{secret_counter}",
                },
            )

        if method == "DELETE" and parsed.path == "/api/v1/snapTrade/deleteUser":
            return (
                200,
                {"Content-Type": "application/json"},
                {"status": "deleted", "userId": qs["userId"][0]},
            )

        if method == "GET" and parsed.path == "/api/v1/accounts":
            return (
                200,
                {"Content-Type": "application/json"},
                [
                    {
                        "id": "acct-live-st-001",
                        "number": "U99887766",
                        "name": "Primary Individual",
                        "institution_name": "Robinhood",
                        "balance": {"total": {"amount": 54000.0, "currency": "USD"}},
                        "meta": {"type": "Margin"},
                    }
                ],
            )

        if method == "GET" and parsed.path == "/api/v1/holdings":
            return (
                200,
                {"Content-Type": "application/json"},
                [
                    {
                        "account": {
                            "id": "acct-live-st-001",
                            "number": "U99887766",
                            "sync_status": {
                                "holdings": {"last_successful_sync": "2026-01-31T21:00:00Z"}
                            },
                        },
                        "balances": [{"currency": {"code": "USD"}, "cash": 32000.0}],
                        "positions": [
                            {
                                "symbol": {
                                    "symbol": {
                                        "symbol": "AAPL",
                                        "currency": {"code": "USD"},
                                        "type": {"code": "cs"},
                                    }
                                },
                                "units": 100.0,
                                "price": 220.0,
                                "average_purchase_price": 200.0,
                            }
                        ],
                        "total_value": {"value": 54000.0, "currency": "USD"},
                    }
                ],
            )

        if method == "GET" and parsed.path == "/api/v1/activities":
            return (
                200,
                {"Content-Type": "application/json"},
                [
                    {
                        "id": "act-dep-001",
                        "account": {"id": "acct-live-st-001"},
                        "type": "DEPOSIT",
                        "amount": 50000.0,
                        "currency": {"code": "USD"},
                        "trade_date": "2026-01-02T14:00:00Z",
                    },
                    {
                        "id": "act-buy-001",
                        "account": {"id": "acct-live-st-001"},
                        "type": "BUY",
                        "symbol": {"symbol": "AAPL", "currency": {"code": "USD"}},
                        "units": 100.0,
                        "price": 200.0,
                        "fee": 1.0,
                        "currency": {"code": "USD"},
                        "trade_date": "2026-01-06T15:00:00Z",
                    },
                ],
            )

        return (404, {"Content-Type": "application/json"}, {"error": "unknown_snaptrade_route"})

    return transport, recorded


class TestSnapTradeRelayEndpointsAndSecurity(unittest.TestCase):
    """End-to-end API route tests for the 5-slot SnapTrade V1 relay and hosted signing-oracle closure."""

    def setUp(self) -> None:
        self.pub_kp = generate_ed25519_keypair(bytes.fromhex("31" * 32))
        self.scanner = OutboundPrivacyScanner()

    def test_unconfigured_fail_closed_503_and_status_contract(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SNAPTRADE_CLIENT_ID", None)
            os.environ.pop("SNAPTRADE_CONSUMER_KEY", None)
            os.environ.pop("N170_SNAPTRADE_DEV_KEY", None)

            cfg = ApiConfig(
                publisher_keypair=self.pub_kp,
                publisher_kid="n170-snap-test-kid",
            )
            app = create_app(cfg, prefer_fastapi=True)
            client = VerifyApiTestClient(app)
            try:
                opt_r = client.options("/api/v1/connect/snaptrade/portal")
                self.assertEqual(opt_r.status_code, 204)
                self.assertEqual(opt_r.headers.get("Access-Control-Allow-Origin"), "*")
                self.assertIn(
                    "X-N170-Dev-Key",
                    opt_r.headers.get("Access-Control-Allow-Headers", ""),
                )
                self.assertIsNone(opt_r.headers.get("Set-Cookie"))

                st_r = client.get("/api/v1/connect/snaptrade/status")
                self.assertEqual(st_r.status_code, 200, st_r.text)
                self.assertIsNone(st_r.headers.get("Set-Cookie"))
                st_json = st_r.json()
                self.assertEqual(
                    st_json,
                    {
                        "configured": False,
                        "mode": "developer_5_slot",
                        "requires_dev_key": False,
                        "max_slots": 5,
                        "active_slots": 0,
                        "available_slots": 5,
                        "slots": [],
                    },
                )

                for route_path, req_body in (
                    ("/api/v1/connect/snaptrade/portal", {"slot_label": "founder-1"}),
                    ("/api/v1/connect/snaptrade/verify", {"session_token": "tok-123"}),
                    ("/api/v1/connect/snaptrade/release", {"slot_id": 1}),
                ):
                    act_r = client.post(route_path, json=req_body)
                    self.assertEqual(act_r.status_code, 503, act_r.text)
                    self.assertEqual(act_r.json()["error"], "snaptrade_unconfigured")
                    self.assertIsNone(act_r.headers.get("Set-Cookie"))
            finally:
                app.verify_app.close()

    def test_five_slot_ceiling_dev_key_redirect_validation_and_e2e_verify(self) -> None:
        transport, recorded = _make_mock_snaptrade_transport()
        fake_now = [1000.0]
        relay = SnapTradeRelayCoordinator(
            http_transport=transport,
            session_ttl_seconds=1800.0,
            monotonic_clock=lambda: fake_now[0],
        )
        cfg = ApiConfig(
            publisher_keypair=self.pub_kp,
            publisher_kid="n170-snap-live-kid",
            snaptrade_client_id="N170-SNAP-DEV-CLIENT",
            snaptrade_consumer_key="snap-hmac-consumer-secret-xyz-12345",
            snaptrade_dev_key="promo-gate-secret-2026",
            account_blinding_salt_hex="ab" * 32,
        )
        app = create_app(cfg, snaptrade_relay=relay, prefer_fastapi=False)
        client = VerifyApiTestClient(app)
        origin_env = mock.patch.dict(
            os.environ, {"N170_VERIFY_SITE_ORIGIN": "https://verify.example.org"}, clear=False
        )
        origin_env.start()
        self.addCleanup(origin_env.stop)
        try:
            # 1. Status reflects configured=True and requires_dev_key=True
            st_init = client.get("/api/v1/connect/snaptrade/status")
            self.assertEqual(st_init.status_code, 200)
            self.assertTrue(st_init.json()["configured"])
            self.assertTrue(st_init.json()["requires_dev_key"])
            self.assertEqual(st_init.json()["available_slots"], 5)

            # 2. Missing or wrong dev_key -> 403 dev_key_required
            r_no_key = client.post(
                "/api/v1/connect/snaptrade/portal",
                json={"slot_label": "founder-1"},
            )
            self.assertEqual(r_no_key.status_code, 403)
            self.assertEqual(r_no_key.json()["error"], "dev_key_required")

            r_bad_key = client.post(
                "/api/v1/connect/snaptrade/portal",
                json={"slot_label": "founder-1", "dev_key": "wrong-key"},
            )
            self.assertEqual(r_bad_key.status_code, 403)
            self.assertEqual(r_bad_key.json()["error"], "dev_key_required")

            dev_headers = {"X-N170-Dev-Key": "promo-gate-secret-2026"}

            # 3. Validate redirect_url allowlist (local http://127.0.0.1:* or the site's own origin)
            for bad_redir in (
                "http://evil.example.com/callback",
                "https://evil.example.com/callback",
                "javascript:alert(1)",
                "https://user:pass@example.com/cb",
            ):
                r_bad_url = client.post(
                    "/api/v1/connect/snaptrade/portal",
                    json={"slot_label": "founder-1", "redirect_url": bad_redir},
                    headers=dev_headers,
                )
                self.assertEqual(r_bad_url.status_code, 422, bad_redir)
                self.assertEqual(r_bad_url.json()["error"], "invalid_redirect_url")

            # Reject caller attempt to request mutating connectionType='trade'
            r_mut_type = client.post(
                "/api/v1/connect/snaptrade/portal",
                json={"slot_label": "founder-1", "connectionType": "trade"},
                headers=dev_headers,
            )
            self.assertEqual(r_mut_type.status_code, 422)
            self.assertEqual(r_mut_type.json()["error"], "read_only_capability_violation")

            # 4. Allocate all 5 developer/promo slots
            tokens: dict[int, str] = {}
            for idx in range(1, 6):
                p_resp = client.post(
                    "/api/v1/connect/snaptrade/portal",
                    json={
                        "slot_label": f"founder-{idx}",
                        "broker": "ROBINHOOD",
                        "redirect_url": "http://127.0.0.1:3000/connect?snaptrade=connected",
                    },
                    headers=dev_headers,
                )
                self.assertEqual(p_resp.status_code, 200, p_resp.text)
                self.scanner.assert_clean(p_resp.text)
                self.assertNotIn("supersecret", p_resp.text)
                self.assertNotIn("snap-hmac-consumer-secret-xyz-12345", p_resp.text)
                p_data = p_resp.json()
                self.assertEqual(p_data["slot_id"], idx)
                self.assertEqual(p_data["slot_label"], f"founder-{idx}")
                self.assertEqual(p_data["connection_type"], "read")
                self.assertTrue(p_data["portal_url"].startswith("https://app.snaptrade.com/"))
                self.assertEqual(p_data["max_slots"], 5)
                self.assertEqual(p_data["active_slots"], idx)
                self.assertEqual(p_data["available_slots"], 5 - idx)
                self.assertGreaterEqual(len(p_data["session_token"]), 32)
                tokens[idx] = p_data["session_token"]

            # 5. 6th distinct slot must fail with 409 slot_cap_exceeded
            r_sixth = client.post(
                "/api/v1/connect/snaptrade/portal",
                json={"slot_label": "founder-6-overflow"},
                headers=dev_headers,
            )
            self.assertEqual(r_sixth.status_code, 409, r_sixth.text)
            self.assertEqual(r_sixth.json()["error"], "slot_cap_exceeded")
            self.assertEqual(r_sixth.json()["active_slots"], 5)
            self.assertEqual(r_sixth.json()["available_slots"], 0)

            # 6. End-to-end /verify on slot 1 (retaining slot) -> signed VerifyProofBundle + isolation metadata
            v_resp = client.post(
                "/api/v1/connect/snaptrade/verify",
                json={
                    "session_token": tokens[1],
                    "disclose_leaf_names": ["core_metrics", "reconciliation", "capital_bracket"],
                    "start_date": "2026-01-01",
                    "end_date": "2026-01-31",
                    "release_slot_after": False,
                    "dev_key": "promo-gate-secret-2026",
                },
            )
            self.assertEqual(v_resp.status_code, 200, v_resp.text)
            self.scanner.assert_clean(v_resp.text)
            self.assertNotIn("U99887766", v_resp.text)
            self.assertNotIn("54000", v_resp.text)
            self.assertNotIn("50000", v_resp.text)
            self.assertNotIn("supersecret", v_resp.text)

            v_json = v_resp.json()
            self.assertEqual(
                v_json["isolation"]["worker_isolated"],
                True,
            )
            self.assertEqual(v_json["isolation"]["rlimit_core_zero"], True)
            self.assertEqual(v_json["isolation"]["slot_released"], False)
            self.assertEqual(v_json["isolation"]["db_rows_written"], 0)
            self.assertEqual(v_json["isolation"]["connection_type"], "read")
            self.assertIn("retained", v_json["isolation"]["token_disposal"])
            self.assertEqual(
                v_json["slot_status"],
                {"max_slots": 5, "active_slots": 5, "available_slots": 0},
            )
            self.assertEqual(
                app.store.total_row_counts(),
                {"proofs": 0, "chains": 0, "continuity_log": 0},
            )

            bundle = VerifyProofBundle.from_dict(v_json["bundle"])
            self.assertEqual(bundle.broker_id, "snaptrade")
            self.assertEqual(bundle.provider_approval_state, ProviderApprovalState.AGGREGATOR_RELAYED)
            self.assertEqual(bundle.environment_tier, EnvironmentTier.LIVE_PRODUCTION)
            self.assertEqual(
                sorted(lf.leaf_name for lf in bundle.disclosed_leaves),
                ["capital_bracket", "core_metrics", "reconciliation"],
            )
            ver_out = verify_proof_bundle(bundle)
            self.assertTrue(ver_out.valid, ver_out.errors)

            # 7. Release slot 2 via POST /api/v1/connect/snaptrade/release -> frees slot 2 for founder-6!
            rel_2 = client.post(
                "/api/v1/connect/snaptrade/release",
                json={"slot_id": 2},
                headers=dev_headers,
            )
            self.assertEqual(rel_2.status_code, 200, rel_2.text)
            self.assertEqual(rel_2.json()["released_slot_ids"], [2])
            self.assertEqual(rel_2.json()["slot_status"]["active_slots"], 4)
            self.assertEqual(rel_2.json()["slot_status"]["available_slots"], 1)

            # Released session_token for slot 2 is immediately purged from memory
            v_purged = client.post(
                "/api/v1/connect/snaptrade/verify",
                json={"session_token": tokens[2]},
                headers=dev_headers,
            )
            self.assertEqual(v_purged.status_code, 404)
            self.assertEqual(v_purged.json()["error"], "session_not_found")

            # Founder-6 now succeeds and claims recycled slot_id == 2!
            r_sixth_retry = client.post(
                "/api/v1/connect/snaptrade/portal",
                json={
                    "slot_label": "founder-6",
                    "redirect_url": "https://verify.example.org/connect?snaptrade=ok",
                },
                headers=dev_headers,
            )
            self.assertEqual(r_sixth_retry.status_code, 200, r_sixth_retry.text)
            self.assertEqual(r_sixth_retry.json()["slot_id"], 2)
            self.assertEqual(r_sixth_retry.json()["active_slots"], 5)

            # 8. Verify with release_slot_after=True deletes user at SnapTrade and releases slot
            tok_6 = r_sixth_retry.json()["session_token"]
            v_rel = client.post(
                "/api/v1/connect/snaptrade/verify",
                json={"session_token": tok_6, "release_slot_after": True},
                headers=dev_headers,
            )
            self.assertEqual(v_rel.status_code, 200, v_rel.text)
            self.assertTrue(v_rel.json()["isolation"]["slot_released"])
            self.assertIn("deleted", v_rel.json()["isolation"]["token_disposal"])
            self.assertEqual(v_rel.json()["slot_status"]["active_slots"], 4)
            self.assertEqual(v_rel.json()["slot_status"]["available_slots"], 1)

            # 9. Advance monotonic clock past 30-minute TTL -> remaining session_tokens auto-purge!
            fake_now[0] += 1805.0
            v_expired = client.post(
                "/api/v1/connect/snaptrade/verify",
                json={"session_token": tokens[1]},
                headers=dev_headers,
            )
            self.assertEqual(v_expired.status_code, 404)
            self.assertEqual(v_expired.json()["error"], "session_not_found")

            # 10. release_all cleans up remaining active slots upstream and locally
            rel_all = client.post(
                "/api/v1/connect/snaptrade/release",
                json={"release_all": True},
                headers=dev_headers,
            )
            self.assertEqual(rel_all.status_code, 200, rel_all.text)
            self.assertEqual(rel_all.json()["slot_status"]["active_slots"], 0)
            self.assertEqual(rel_all.json()["slot_status"]["available_slots"], 5)
            self.assertTrue(
                any(call["method"] == "DELETE" and call["path"] == "/api/v1/snapTrade/deleteUser" for call in recorded)
            )
        finally:
            app.close()

    def test_hosted_verify_blocks_synthetic_leaf_payloads_and_signing_oracle(self) -> None:
        # Default ApiConfig has hosted_multi_user_mode=True, allow_hosted_signing=False,
        # allow_client_supplied_series_for_tests=False
        default_cfg = ApiConfig(
            publisher_keypair=self.pub_kp,
            publisher_kid="n170-hosted-prod-kid",
        )
        self.assertTrue(default_cfg.hosted_multi_user_mode)
        self.assertFalse(default_cfg.allow_hosted_signing)
        self.assertFalse(default_cfg.allow_client_supplied_series_for_tests)

        app = create_app(default_cfg, prefer_fastapi=False)
        client = VerifyApiTestClient(app)
        try:
            synthetic_leaves = {
                name: {"forged": True} for name in CANONICAL_LEAF_NAMES
            }
            synthetic_leaves["capital_bracket"] = {"capital_bracket": CapitalBracket.OVER_1M.value}

            oracle_attempts = [
                {
                    "broker_id": "schwab",
                    "raw_account_id": "SCH-ORACLE-1",
                    "leaf_payloads": synthetic_leaves,
                },
                {
                    "broker_id": "schwab",
                    "raw_account_id": "SCH-ORACLE-2",
                    "performance_summary": {
                        "twr_decimal": 9.99,
                        "observation_count": 50,
                        "psr_sample_eligible": True,
                        "probabilistic_sharpe_ratio": 0.999,
                    },
                },
                {
                    "broker_id": "alpaca",
                    "raw_account_id": "ALP-ORACLE-3",
                    "nav_points": [
                        {"timestamp_utc": "2026-01-01T00:00:00Z", "nav_base": 10000.0},
                        {"timestamp_utc": "2026-01-31T00:00:00Z", "nav_base": 99000.0},
                    ],
                },
                {
                    "broker_id": "schwab",
                    "raw_account_id": "SCH-ORACLE-4",
                    "twr_decimal": 5.0,
                },
                {
                    "broker_id": "schwab",
                    "raw_account_id": "SCH-ORACLE-5",
                    "_trusted_internal_input": True,
                    "_hosted_signing_restricted": False,
                },
            ]

            for attempt in oracle_attempts:
                r = client.post("/api/v1/verify", json=attempt)
                self.assertEqual(r.status_code, 403, f"Attempt should fail closed: {attempt} -> {r.text}")
                self.assertEqual(r.json()["error"], "signing_oracle_disabled")

            # Real IBKR Flex XML statement on POST /api/v1/verify still succeeds in hosted mode!
            real_flex_xml = """<?xml version="1.0" encoding="UTF-8"?>
<FlexQueryResponse queryName="HostedRealCheck" type="AF">
  <FlexStatements count="1">
    <FlexStatement accountId="U7654321" baseCurrency="USD" fromDate="2026-01-01" toDate="2026-01-31">
      <EquitySummaryInBase>
        <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2026-01-02" cash="50000" stock="0" total="50000" />
        <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2026-01-30" cash="52500" stock="0" total="52500" />
      </EquitySummaryInBase>
      <Trades />
      <OpenPositions />
      <CashTransactions />
      <Transfers />
      <CorporateActions />
      <OptionEAE />
    </FlexStatement>
  </FlexStatements>
</FlexQueryResponse>"""
            r_real = client.post(
                "/api/v1/verify",
                json={
                    "broker_id": "ibkr_flex",
                    "flex_xml": real_flex_xml,
                    "issued_at_utc": "2026-02-10T12:00:00Z",
                },
            )
            self.assertEqual(r_real.status_code, 200, r_real.text)
            self.assertNotIn("U7654321", r_real.text)
            self.assertTrue(r_real.json()["verification"]["valid"])
        finally:
            app.close()


if __name__ == "__main__":
    unittest.main()
