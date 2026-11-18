"""API & spawn-worker integration tests for Hyperliquid 0x verification and SnapTrade PERS-* / auto-recycle."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any
import unittest
import urllib.parse

from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from app.privacy_scanner import OutboundPrivacyScanner
from app.routes_snaptrade import MAX_QUEUED_DELETES_PER_REQUEST, SnapTradeRelayCoordinator
from n170_verify.connectors import HYPERLIQUID_LIVE_BASE_URL, compute_snaptrade_signature
from n170_verify.contracts import (
    EnvironmentTier,
    OriginAssurance,
    ProviderApprovalState,
    VerifyProofBundle,
    verify_proof_bundle,
)
from n170_verify.crypto import generate_ed25519_keypair


MOCK_HL_WALLET = "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"


def picklable_hyperliquid_mock_transport(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
) -> tuple[int, dict[str, str], Any]:
    """Top-level picklable mock transport executed inside the isolated ``spawn`` child worker."""
    assert method == "POST"
    assert url == f"{HYPERLIQUID_LIVE_BASE_URL}/info"
    payload = json.loads(body.decode("utf-8"))
    q_type = payload.get("type")
    user = str(payload.get("user") or "")
    assert user == MOCK_HL_WALLET.lower()

    base_dt = dt.datetime(2026, 1, 5, 0, 0, 0, tzinfo=dt.timezone.utc)
    if q_type == "portfolio":
        pts = []
        nav = 25000.0
        for i in range(35):
            cur_ms = int((base_dt + dt.timedelta(days=i)).timestamp() * 1000)
            if i > 0:
                nav = round(nav * (1.004 if i % 3 != 0 else 0.996), 2)
                if i == 10:
                    nav = round(nav + 5000.0, 2)
            pts.append([cur_ms, f"{nav:.2f}"])
        return (
            200,
            {"Content-Type": "application/json"},
            [["allTime", {"accountValueHistory": pts}]],
        )

    if q_type == "userNonFundingLedgerUpdates":
        assert "startTime" in payload
        dep_ms = int((base_dt + dt.timedelta(days=10)).timestamp() * 1000)
        return (
            200,
            {"Content-Type": "application/json"},
            [{"time": dep_ms, "delta": {"type": "deposit", "usdc": "5000.00"}}],
        )

    f_in = int((base_dt + dt.timedelta(days=3, hours=10)).timestamp() * 1000)
    f_out = int((base_dt + dt.timedelta(days=4, hours=16)).timestamp() * 1000)
    fills = [
        {"coin": "BTC", "px": "94000.0", "sz": "0.2", "side": "B", "time": f_in, "fee": "2.0", "tid": 71},
        {"coin": "BTC", "px": "96500.0", "sz": "0.2", "side": "A", "time": f_out, "fee": "2.1", "tid": 72},
    ]
    if q_type == "userFills":
        return (200, {"Content-Type": "application/json"}, fills)

    if q_type == "userFillsByTime":
        # As the service answers: the wallet's fills at or after startTime (and at or before
        # endTime when given); this wallet has only the two fills above.
        start_ms = int(payload["startTime"])
        end_ms = payload.get("endTime")
        in_range = [
            f
            for f in fills
            if f["time"] >= start_ms and (end_ms is None or f["time"] <= int(end_ms))
        ]
        return (200, {"Content-Type": "application/json"}, in_range)

    return (400, {"Content-Type": "application/json"}, {"error": "unexpected_query"})


WORKER_SNAPTRADE_CLIENT_ID = "PERS-WORKER-ISOLATION-01"
WORKER_SNAPTRADE_CONSUMER_KEY = "worker-snaptrade-hmac-secret-key-999"


def picklable_snaptrade_worker_mock_transport(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
) -> tuple[int, dict[str, str], Any]:
    """Top-level picklable SnapTrade transport proving live fetches run inside the spawn worker."""
    import os
    import resource

    parsed = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qs(parsed.query)
    body_obj = json.loads(body.decode("utf-8")) if body else None
    expected_sig = compute_snaptrade_signature(
        WORKER_SNAPTRADE_CONSUMER_KEY,
        api_path=parsed.path,
        query_string=parsed.query,
        content=body_obj,
    )
    assert (headers.get("Signature") or headers.get("signature")) == expected_sig
    assert "userId" not in qs and "userSecret" not in qs

    if method == "POST" and parsed.path == "/api/v1/snapTrade/login":
        return (
            200,
            {"Content-Type": "application/json"},
            {"redirectURI": "https://app.snaptrade.com/portal/worker-pers", "sessionId": "s-w-1"},
        )

    # All brokerage data fetches (/accounts, /holdings, /positions, /balances, /activities) MUST
    # execute strictly inside the isolated spawn worker (RLIMIT_CORE=(0,0), scrubbed env)!
    assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0), "SnapTrade fetch ran outside isolated worker!"
    assert "N170_PARENT_PROCESS_SENTINEL" not in os.environ, "Unsanitized parent env leaked into worker!"

    if method == "GET" and parsed.path == "/api/v1/accounts":
        return (
            200,
            {"Content-Type": "application/json"},
            [
                {
                    "id": "acct-worker-pers-1",
                    "number": "U55443322",
                    "name": "Founder Worker Isolated",
                    "institution_name": "Interactive Brokers",
                    "balance": {"total": {"amount": 55000.0, "currency": "USD"}},
                    "updated_at": "2026-02-12T21:00:00Z",
                }
            ],
        )
    if method == "GET" and parsed.path == "/api/v1/holdings":
        # Exercise 403 fallback to per-account /positions + /balances inside the spawn worker
        return (403, {"Content-Type": "application/json"}, {"detail": "holdings restricted on PERS key"})
    if method == "GET" and parsed.path == "/api/v1/accounts/acct-worker-pers-1/positions":
        return (
            200,
            {"Content-Type": "application/json"},
            [
                {
                    "symbol": {
                        "symbol": {
                            "symbol": "VWCE",
                            "currency": {"code": "USD"},
                            "type": {"code": "et"},
                        }
                    },
                    "units": None,
                    "fractional_units": "50.0",
                    "price": 110.0,
                    "average_purchase_price": 100.0,
                }
            ],
        )
    if method == "GET" and parsed.path == "/api/v1/accounts/acct-worker-pers-1/balances":
        return (
            200,
            {"Content-Type": "application/json"},
            [{"currency": {"code": "USD"}, "cash": 49500.0}],
        )
    if method == "GET" and parsed.path == "/api/v1/activities":
        # Exercise 401 fallback to per-account /activities inside the spawn worker
        return (401, {"Content-Type": "application/json"}, {"detail": "use per-account activities"})
    if method == "GET" and parsed.path == "/api/v1/accounts/acct-worker-pers-1/activities":
        return (
            200,
            {"Content-Type": "application/json"},
            [
                {
                    "id": "act-w-1",
                    "type": "FUNDS_CONTRIBUTION",
                    "amount": "50000.0",
                    "currency": {"code": "USD"},
                    "date": "2026-01-05",
                },
                {
                    "id": "act-w-2",
                    "type": "BUY",
                    "symbol": {"symbol": "VWCE", "type": {"code": "et"}},
                    "units": None,
                    "fractional_units": "50.0",
                    "price": "100.0",
                    "fee": "1.0",
                    "currency": {"code": "USD"},
                    "date": "2026-01-06",
                },
            ],
        )
    if method == "GET" and parsed.path == "/api/v1/performance/custom":
        return (
            200,
            {"Content-Type": "application/json"},
            {
                "totalEquityTimeframe": [
                    {"date": "2026-01-05", "value": 50000.0},
                    {"date": "2026-02-12", "value": 55000.0},
                ]
            },
        )
    return (404, {"Content-Type": "application/json"}, {"error": "not_found"})


def picklable_snaptrade_upstream_error_transport(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
) -> tuple[int, dict[str, str], Any]:
    parsed = urllib.parse.urlsplit(url)
    if method == "POST" and parsed.path == "/api/v1/snapTrade/login":
        return (
            200,
            {"Content-Type": "application/json"},
            {"redirectURI": "https://app.snaptrade.com/portal/err-sess", "sessionId": "s-err"},
        )
    return (
        503,
        {"Content-Type": "application/json"},
        {
            "detail": f"Upstream outage for {WORKER_SNAPTRADE_CLIENT_ID} key {WORKER_SNAPTRADE_CONSUMER_KEY}"
        },
    )


def picklable_snaptrade_paper_transport(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
) -> tuple[int, dict[str, str], Any]:
    parsed = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qs(parsed.query)
    if method == "POST" and parsed.path == "/api/v1/snapTrade/registerUser":
        body_obj = json.loads(body.decode("utf-8")) if body else {}
        return (
            200,
            {"Content-Type": "application/json"},
            {"userId": body_obj.get("userId", "u1"), "userSecret": "paper-user-secret-xyz"},
        )
    if method == "POST" and parsed.path == "/api/v1/snapTrade/login":
        return (
            200,
            {"Content-Type": "application/json"},
            {"redirectURI": "https://app.snaptrade.com/portal/paper-sess", "sessionId": "s-paper"},
        )
    if method == "DELETE" and parsed.path == "/api/v1/snapTrade/deleteUser":
        return (200, {"Content-Type": "application/json"}, {"status": "deleted", "userId": qs["userId"][0]})
    if method == "GET" and parsed.path == "/api/v1/accounts":
        return (
            200,
            {"Content-Type": "application/json"},
            [
                {
                    "id": "acct-paper-1",
                    "number": "DU1234567",
                    "name": "Paper Simulated Account",
                    "is_paper": True,
                    "balance": {"total": {"amount": 100000.0, "currency": "USD"}},
                }
            ],
        )
    return (200, {"Content-Type": "application/json"}, [])


def picklable_snaptrade_empty_accounts_transport(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
) -> tuple[int, dict[str, str], Any]:
    parsed = urllib.parse.urlsplit(url)
    body_obj = json.loads(body.decode("utf-8")) if body else {}
    if method == "POST" and parsed.path == "/api/v1/snapTrade/registerUser":
        return (
            200,
            {"Content-Type": "application/json"},
            {"userId": body_obj.get("userId", "u1"), "userSecret": "empty-user-secret-xyz"},
        )
    if method == "POST" and parsed.path == "/api/v1/snapTrade/login":
        return (
            200,
            {"Content-Type": "application/json"},
            {"redirectURI": "https://app.snaptrade.com/portal/empty-sess", "sessionId": "s-empty"},
        )
    if method == "GET" and parsed.path == "/api/v1/accounts":
        return (200, {"Content-Type": "application/json"}, [])
    return (200, {"Content-Type": "application/json"}, [])


def _make_personal_snaptrade_mock(
    *,
    client_id: str = "PERS-FOUNDER-LIVE-01",
    consumer_key: str = "pers-consumer-secret-live-xyz",
) -> tuple[Any, list[dict[str, Any]]]:
    recorded: list[dict[str, Any]] = []

    def transport(
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
    ) -> tuple[int, dict[str, str], Any]:
        parsed = urllib.parse.urlsplit(url)
        qs = urllib.parse.parse_qs(parsed.query)
        body_obj = json.loads(body.decode("utf-8")) if body else None
        recorded.append({"method": method, "path": parsed.path, "query": qs, "body": body_obj})

        # Strictly mirror SnapTrade's HTTP 400 (1012) rejection if registerUser/deleteUser or userId/userSecret are sent
        if parsed.path in {"/api/v1/snapTrade/registerUser", "/api/v1/snapTrade/deleteUser"}:
            return (400, {"Content-Type": "application/json"}, {"code": "1012", "detail": "Personal key forbids registerUser/deleteUser"})
        if "userId" in qs or "userSecret" in qs:
            return (400, {"Content-Type": "application/json"}, {"code": "1012", "detail": "Personal key forbids userId/userSecret params"})

        expected_sig = compute_snaptrade_signature(
            consumer_key,
            api_path=parsed.path,
            query_string=parsed.query,
            content=body_obj,
        )
        assert (headers.get("Signature") or headers.get("signature")) == expected_sig
        assert qs.get("clientId") == [client_id]

        if method == "POST" and parsed.path == "/api/v1/snapTrade/login":
            assert (body_obj or {}).get("connectionType") == "read"
            return (
                200,
                {"Content-Type": "application/json"},
                {"redirectURI": "https://app.snaptrade.com/portal/founder-pers", "sessionId": "sess-pers-1"},
            )
        if method == "GET" and parsed.path == "/api/v1/accounts":
            return (
                200,
                {"Content-Type": "application/json"},
                [
                    {
                        "id": "acct-founder-001",
                        "number": "U11223344",
                        "name": "Founder Main",
                        "institution_name": "Interactive Brokers",
                        "balance": {"total": {"amount": 120000.0, "currency": "USD"}},
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
                            "id": "acct-founder-001",
                            "number": "U11223344",
                            "sync_status": {"holdings": {"last_successful_sync": "2026-02-15T21:00:00Z"}},
                        },
                        "balances": [{"currency": {"code": "USD"}, "cash": 70000.0}],
                        "positions": [
                            {
                                "symbol": {"symbol": {"symbol": "SPY", "currency": {"code": "USD"}, "type": {"code": "etf"}}},
                                "units": 100.0,
                                "price": 500.0,
                                "average_purchase_price": 475.0,
                            }
                        ],
                        "total_value": {"value": 120000.0, "currency": "USD"},
                    }
                ],
            )
        if method == "GET" and parsed.path == "/api/v1/activities":
            return (
                200,
                {"Content-Type": "application/json"},
                [
                    {
                        "id": "act-pers-dep",
                        "account": {"id": "acct-founder-001"},
                        "type": "DEPOSIT",
                        "amount": 117500.0,
                        "currency": {"code": "USD"},
                        "trade_date": "2026-01-03T14:00:00Z",
                    },
                    {
                        "id": "act-pers-buy",
                        "account": {"id": "acct-founder-001"},
                        "type": "BUY",
                        "symbol": {"symbol": "SPY", "currency": {"code": "USD"}},
                        "units": 100.0,
                        "price": 475.0,
                        "fee": 1.0,
                        "currency": {"code": "USD"},
                        "trade_date": "2026-01-04T15:00:00Z",
                    },
                ],
            )
        if method == "GET" and parsed.path == "/api/v1/performance/custom":
            return (
                200,
                {"Content-Type": "application/json"},
                {
                    "totalEquityTimeframe": [
                        {"date": "2026-01-03", "value": 117500.0},
                        {"date": "2026-01-20", "value": 118900.0},
                        {"date": "2026-02-15", "value": 120000.0},
                    ]
                },
            )
        return (404, {"Content-Type": "application/json"}, {"error": "unknown"})

    return transport, recorded


class TestLaunchBlockersHyperliquidAndSnapTrade(unittest.TestCase):
    """End-to-end API tests for Hyperliquid spawn-worker verification, PERS-* keys, and 5-slot auto-recycle."""

    def setUp(self) -> None:
        self.pub_kp = generate_ed25519_keypair(bytes.fromhex("42" * 32))
        self.scanner = OutboundPrivacyScanner()

    def test_hyperliquid_post_verify_in_isolated_spawn_worker_and_specimen_publish_block(self) -> None:
        cfg = ApiConfig(
            publisher_keypair=self.pub_kp,
            publisher_kid="n170-hl-live-kid",
            hosted_multi_user_mode=True,
            allow_hosted_signing=False,
            allow_caller_clock_for_tests=True,
            account_blinding_salt_hex="cd" * 32,
        )
        app = create_app(
            cfg,
            hyperliquid_http_transport=f"{__name__}:picklable_hyperliquid_mock_transport",
            prefer_fastapi=False,
        )
        client = VerifyApiTestClient(app)
        try:
            # 1. Testnet URL rejected with 422 paper_or_sandbox_rejected
            r_testnet = client.post(
                "/api/v1/verify",
                json={
                    "broker_id": "hyperliquid",
                    "wallet_address": MOCK_HL_WALLET,
                    "base_url": "https://api.hyperliquid-testnet.xyz",
                },
            )
            self.assertEqual(r_testnet.status_code, 422, r_testnet.text)
            self.assertEqual(r_testnet.json()["error"], "paper_or_sandbox_rejected")

            # 2. Invalid 0x address rejected with 422 validation_error
            r_bad_addr = client.post(
                "/api/v1/verify",
                json={
                    "broker_id": "hyperliquid",
                    "wallet_address": "0xnotavalidaddress",
                },
            )
            self.assertEqual(r_bad_addr.status_code, 422, r_bad_addr.text)
            self.assertEqual(r_bad_addr.json()["error"], "validation_error")

            # 3. Valid 0x address executes inside isolated single-use spawn worker and publishes opt-in proof
            r_ok = client.post(
                "/api/v1/verify",
                json={
                    "broker_id": "hyperliquid",
                    "wallet_address": MOCK_HL_WALLET,
                    "issued_at_utc": "2026-02-20T12:00:00Z",
                    "publish_proof": True,
                },
            )
            self.assertEqual(r_ok.status_code, 200, r_ok.text)
            self.scanner.assert_clean(r_ok.text)
            self.assertNotIn(MOCK_HL_WALLET.lower(), r_ok.text.lower())

            body = r_ok.json()
            receipt = body["isolation_receipt"]
            self.assertEqual(receipt["execution_mode"], "ephemeral_spawn_subprocess")
            self.assertNotEqual(receipt["worker_pid"], receipt["parent_pid"])
            self.assertEqual(receipt["rlimit_core"], [0, 0])
            self.assertTrue(receipt["sanitized_child_env"])
            self.assertEqual(receipt["persistent_rows_written"], 1)

            bundle = VerifyProofBundle.from_dict(body["proof_bundle"])
            self.assertEqual(bundle.broker_id, "hyperliquid")
            self.assertEqual(bundle.base_currency, "USD")
            self.assertEqual(bundle.provider_approval_state, ProviderApprovalState.PUBLIC_API_PERMISSIONLESS)
            self.assertEqual(bundle.claimed_origin_assurance, OriginAssurance.OPERATOR_RETRIEVED)
            self.assertEqual(bundle.environment_tier, EnvironmentTier.LIVE_PRODUCTION)

            ver = verify_proof_bundle(bundle)
            self.assertTrue(ver.valid, ver.errors)

            # Published /p/[proofId] lookup works
            r_lookup = client.get(f"/api/v1/proofs/{bundle.proof_id}")
            self.assertEqual(r_lookup.status_code, 200, r_lookup.text)
            self.assertEqual(r_lookup.json()["proof_bundle"]["proof_id"], bundle.proof_id)

            # 4. Synthetic specimen proof_id (`specimen-*`) is rejected from hosted POST /api/v1/proofs
            specimen_attempt = bundle.to_dict()
            specimen_attempt["proof_id"] = "specimen-hyperliquid-preview-v3"
            r_spec = client.post("/api/v1/proofs", json={"proof_bundle": specimen_attempt})
            self.assertEqual(r_spec.status_code, 422, r_spec.text)
            self.assertEqual(r_spec.json()["error"], "paper_or_sandbox_rejected")
        finally:
            app.verify_app.close()

    def test_snaptrade_personal_1_slot_mode_e2e_and_publish(self) -> None:
        transport, recorded = _make_personal_snaptrade_mock()
        relay = SnapTradeRelayCoordinator(http_transport=transport)
        cfg = ApiConfig(
            publisher_keypair=self.pub_kp,
            publisher_kid="n170-pers-kid",
            snaptrade_client_id="PERS-FOUNDER-LIVE-01",
            snaptrade_consumer_key="pers-consumer-secret-live-xyz",
            snaptrade_dev_key="dummy-founder-dev-key",
            account_blinding_salt_hex="ef" * 32,
            site_origin="http://127.0.0.1:3000",
        )
        app = create_app(cfg, snaptrade_relay=relay, prefer_fastapi=False)
        client = VerifyApiTestClient(app)
        owner = {"X-N170-Dev-Key": "dummy-founder-dev-key"}
        try:
            st = client.get("/api/v1/connect/snaptrade/status")
            self.assertEqual(st.status_code, 200, st.text)
            self.assertEqual(st.json()["mode"], "personal_1_slot")
            self.assertEqual(st.json()["max_slots"], 1)
            self.assertEqual(st.json()["available_slots"], 1)

            # Founder opens portal -> zero registerUser call, slot_id == 1, connectionType == 'read'
            p1 = client.post(
                "/api/v1/connect/snaptrade/portal",
                json={
                    "slot_label": "founder-ibkr",
                    "broker": "IBKR",
                    "redirect_url": "http://127.0.0.1:3000/connect?snaptrade=connected",
                },
                headers=owner,
            )
            self.assertEqual(p1.status_code, 200, p1.text)
            self.assertEqual(p1.json()["mode"], "personal_1_slot")
            self.assertEqual(p1.json()["slot_id"], 1)
            self.assertEqual(p1.json()["max_slots"], 1)
            self.assertEqual(p1.json()["active_slots"], 1)
            self.assertEqual(p1.json()["available_slots"], 0)
            self.assertEqual(p1.json()["connection_type"], "read")

            # Founder can reopen portal (e.g. to reconnect or add brokerage) without 409 self-lockout
            p2 = client.post(
                "/api/v1/connect/snaptrade/portal",
                json={"slot_label": "founder-reconnect"},
                headers=owner,
            )
            self.assertEqual(p2.status_code, 200, p2.text)
            self.assertEqual(p2.json()["slot_id"], 1)

            # Verify in isolated spawn worker + publish founder record
            v_resp = client.post(
                "/api/v1/connect/snaptrade/verify",
                json={
                    "session_token": p2.json()["session_token"],
                    "publish_proof": True,
                    "opt_in_leaderboard": True,
                    "release_slot_after": False,
                },
                headers=owner,
            )
            self.assertEqual(v_resp.status_code, 200, v_resp.text)
            self.scanner.assert_clean(v_resp.text)
            self.assertNotIn("U11223344", v_resp.text)
            self.assertNotIn("120000", v_resp.text)

            v_data = v_resp.json()
            self.assertEqual(v_data["mode"], "personal_1_slot")
            self.assertTrue(v_data["isolation"]["worker_isolated"])
            self.assertTrue(v_data["isolation"]["rlimit_core_zero"])
            self.assertEqual(v_data["isolation"]["db_rows_written"], 1)

            bundle = VerifyProofBundle.from_dict(v_data["bundle"])
            self.assertTrue(verify_proof_bundle(bundle).valid)
            core_metrics = bundle.get_disclosed_payload("core_metrics")
            curve_leaf = bundle.get_disclosed_payload("indexed_curve")
            self.assertAlmostEqual(core_metrics["twr_decimal"], (120000.0 / 117500.0) - 1.0, places=5)
            self.assertEqual(len(curve_leaf["points"]), 3)

            # Release with the session's own token purges the local slot without calling deleteUser
            rel = client.post(
                "/api/v1/connect/snaptrade/release",
                json={"session_token": p2.json()["session_token"]},
                headers=owner,
            )
            self.assertEqual(rel.status_code, 200, rel.text)
            self.assertEqual(rel.json()["released_slot_ids"], [1])
            self.assertEqual(rel.json()["upstream_deleted"], False)
            self.assertEqual(rel.json()["slot_status"]["available_slots"], 1)

            called_paths = [r["path"] for r in recorded]
            self.assertNotIn("/api/v1/snapTrade/registerUser", called_paths)
            self.assertNotIn("/api/v1/snapTrade/deleteUser", called_paths)
        finally:
            app.verify_app.close()

    def test_developer_5_slot_auto_recycle_supports_more_than_five_visitors(self) -> None:
        try:
            from tests.test_snaptrade_relay import _make_mock_snaptrade_transport
        except ImportError:
            from test_snaptrade_relay import _make_mock_snaptrade_transport

        transport, recorded = _make_mock_snaptrade_transport()
        relay = SnapTradeRelayCoordinator(http_transport=transport)
        cfg = ApiConfig(
            publisher_keypair=self.pub_kp,
            publisher_kid="n170-build-5slot-kid",
            snaptrade_client_id="N170-SNAP-DEV-CLIENT",
            snaptrade_consumer_key="snap-hmac-consumer-secret-xyz-12345",
            account_blinding_salt_hex="99" * 32,
        )
        app = create_app(cfg, snaptrade_relay=relay, prefer_fastapi=False)
        client = VerifyApiTestClient(app)
        try:
            # 7 sequential visitors verify with release_slot_after=True -> all 7 succeed on a 5-slot key!
            for visitor_idx in range(1, 8):
                p_r = client.post(
                    "/api/v1/connect/snaptrade/portal",
                    json={"slot_label": f"visitor-{visitor_idx}"},
                )
                self.assertEqual(p_r.status_code, 200, p_r.text)
                v_r = client.post(
                    "/api/v1/connect/snaptrade/verify",
                    json={
                        "session_token": p_r.json()["session_token"],
                        "release_slot_after": True,
                    },
                )
                self.assertEqual(v_r.status_code, 200, v_r.text)
                self.assertTrue(v_r.json()["isolation"]["slot_released"])
                self.assertEqual(v_r.json()["slot_status"]["active_slots"], 0)
                self.assertEqual(v_r.json()["slot_status"]["available_slots"], 5)

            delete_calls = [r for r in recorded if r["path"] == "/api/v1/snapTrade/deleteUser"]
            self.assertEqual(len(delete_calls), 7)
        finally:
            app.verify_app.close()

    def test_abandoned_ttl_sessions_auto_reap_and_seed_permission_fail_closed(self) -> None:
        import os
        import tempfile
        from unittest import mock

        try:
            from tests.test_snaptrade_relay import _make_mock_snaptrade_transport
        except ImportError:
            from test_snaptrade_relay import _make_mock_snaptrade_transport

        transport, recorded = _make_mock_snaptrade_transport()
        fake_now = [1000.0]
        relay = SnapTradeRelayCoordinator(
            http_transport=transport,
            session_ttl_seconds=1800.0,
            monotonic_clock=lambda: fake_now[0],
        )
        cfg = ApiConfig(
            publisher_keypair=self.pub_kp,
            publisher_kid="n170-build-reap-kid",
            snaptrade_client_id="N170-SNAP-DEV-CLIENT",
            snaptrade_consumer_key="snap-hmac-consumer-secret-xyz-12345",
            account_blinding_salt_hex="77" * 32,
        )
        app = create_app(cfg, snaptrade_relay=relay, prefer_fastapi=False)
        client = VerifyApiTestClient(app)
        try:
            # 5 visitors open the portal and close their browser tab without verifying
            for idx in range(1, 6):
                r_p = client.post(
                    "/api/v1/connect/snaptrade/portal",
                    json={"slot_label": f"bounced-{idx}"},
                )
                self.assertEqual(r_p.status_code, 200, r_p.text)
            self.assertEqual(client.get("/api/v1/connect/snaptrade/status").json()["available_slots"], 0)

            # Advance clock past 30m TTL -> all 5 local seats are freed at once; the upstream
            # deletes are queued and each request retries at most a few of them.
            fake_now[0] += 1805.0
            st_after = client.get("/api/v1/connect/snaptrade/status").json()
            self.assertEqual(st_after["available_slots"], 5)
            self.assertEqual(st_after["active_slots"], 0)
            delete_calls = [r for r in recorded if r["path"] == "/api/v1/snapTrade/deleteUser"]
            self.assertEqual(len(delete_calls), MAX_QUEUED_DELETES_PER_REQUEST)
            for _ in range(5):
                client.get("/api/v1/connect/snaptrade/status")
            delete_calls = [r for r in recorded if r["path"] == "/api/v1/snapTrade/deleteUser"]
            self.assertEqual(len(delete_calls), 5)

            # Visitor #6 now succeeds without any manual /release intervention
            r_six = client.post(
                "/api/v1/connect/snaptrade/portal",
                json={"slot_label": "visitor-6-fresh"},
            )
            self.assertEqual(r_six.status_code, 200, r_six.text)
            self.assertEqual(r_six.json()["slot_id"], 1)
        finally:
            app.verify_app.close()

        # Verify ApiConfig.from_env() fails closed on PermissionError instead of silently rotating keys
        if os.getuid() != 0:
            with tempfile.TemporaryDirectory() as tmpdir:
                locked_dir = os.path.join(tmpdir, "locked_keys")
                os.makedirs(locked_dir, mode=0o700)
                seed_path = os.path.join(locked_dir, "publisher_seed.hex")
                with open(seed_path, "w", encoding="utf-8") as fh:
                    fh.write("ab" * 32 + "\n")
                os.chmod(seed_path, 0o000)
                try:
                    with mock.patch.dict(
                        os.environ,
                        {
                            "N170_VERIFY_SIGNING_SEED_HEX": "",
                            "N170_VERIFY_SIGNING_SEED_FILE": seed_path,
                        },
                        clear=False,
                    ):
                        with self.assertRaises(PermissionError):
                            ApiConfig.from_env()
                finally:
                    os.chmod(seed_path, 0o600)

    def test_snaptrade_verify_executes_live_fetch_inside_isolated_spawn_worker(self) -> None:
        import os
        from unittest import mock

        with mock.patch.dict(os.environ, {"N170_PARENT_PROCESS_SENTINEL": "parent-only"}, clear=False):
            # 1. Happy path: live SnapTrade fetches (/accounts, /positions, /balances, /activities)
            # execute inside the single-use spawn worker with RLIMIT_CORE=(0,0) and scrubbed env!
            relay = SnapTradeRelayCoordinator(
                http_transport=f"{__name__}:picklable_snaptrade_worker_mock_transport"
            )
            cfg = ApiConfig(
                publisher_keypair=self.pub_kp,
                publisher_kid="n170-snap-worker-kid",
                snaptrade_client_id=WORKER_SNAPTRADE_CLIENT_ID,
                snaptrade_consumer_key=WORKER_SNAPTRADE_CONSUMER_KEY,
                snaptrade_dev_key="dummy-worker-dev-key",
                account_blinding_salt_hex="aa" * 32,
            )
            owner = {"X-N170-Dev-Key": "dummy-worker-dev-key"}
            app = create_app(cfg, snaptrade_relay=relay, prefer_fastapi=False)
            client = VerifyApiTestClient(app)
            try:
                p_r = client.post("/api/v1/connect/snaptrade/portal", json={"slot_label": "founder-worker"}, headers=owner)
                self.assertEqual(p_r.status_code, 200, p_r.text)
                v_r = client.post(
                    "/api/v1/connect/snaptrade/verify",
                    json={"session_token": p_r.json()["session_token"], "release_slot_after": False},
                    headers=owner,
                )
                self.assertEqual(v_r.status_code, 200, v_r.text)
                self.scanner.assert_clean(v_r.text)
                self.assertNotIn("U55443322", v_r.text)
                self.assertNotIn("55000", v_r.text)
                v_json = v_r.json()
                self.assertTrue(v_json["isolation"]["worker_isolated"])
                self.assertTrue(v_json["isolation"]["rlimit_core_zero"])
                bundle = VerifyProofBundle.from_dict(v_json["bundle"])
                self.assertTrue(verify_proof_bundle(bundle).valid)
                core_metrics = bundle.get_disclosed_payload("core_metrics")
                self.assertAlmostEqual(core_metrics["twr_decimal"], 0.10, places=5)
            finally:
                app.verify_app.close()

            # 2. Upstream 503 inside spawn worker maps to 502 snaptrade_upstream_error with secrets redacted
            err_relay = SnapTradeRelayCoordinator(
                http_transport=f"{__name__}:picklable_snaptrade_upstream_error_transport"
            )
            err_app = create_app(cfg, snaptrade_relay=err_relay, prefer_fastapi=False)
            err_client = VerifyApiTestClient(err_app)
            try:
                p_err = err_client.post("/api/v1/connect/snaptrade/portal", json={"slot_label": "err-slot"}, headers=owner)
                self.assertEqual(p_err.status_code, 200, p_err.text)
                v_err = err_client.post(
                    "/api/v1/connect/snaptrade/verify",
                    json={"session_token": p_err.json()["session_token"]},
                    headers=owner,
                )
                self.assertEqual(v_err.status_code, 502, v_err.text)
                self.assertEqual(v_err.json()["error"], "snaptrade_upstream_error")
                self.assertNotIn(WORKER_SNAPTRADE_CONSUMER_KEY, v_err.text)
                self.assertNotIn(WORKER_SNAPTRADE_CLIENT_ID, v_err.text)
            finally:
                err_app.verify_app.close()

            # 3. Paper account inside spawn worker maps to 422 paper_or_sandbox_rejected & recycles slot
            paper_cfg = ApiConfig(
                publisher_keypair=self.pub_kp,
                publisher_kid="n170-snap-paper-kid",
                snaptrade_client_id="BUILD-KEY-PAPER-TEST",
                snaptrade_consumer_key="build-consumer-secret-paper",
                account_blinding_salt_hex="bb" * 32,
            )
            paper_relay = SnapTradeRelayCoordinator(
                http_transport=f"{__name__}:picklable_snaptrade_paper_transport"
            )
            paper_app = create_app(paper_cfg, snaptrade_relay=paper_relay, prefer_fastapi=False)
            paper_client = VerifyApiTestClient(paper_app)
            try:
                p_pap = paper_client.post("/api/v1/connect/snaptrade/portal", json={"slot_label": "paper-vis"})
                self.assertEqual(p_pap.status_code, 200, p_pap.text)
                v_pap = paper_client.post(
                    "/api/v1/connect/snaptrade/verify",
                    json={"session_token": p_pap.json()["session_token"], "release_slot_after": True},
                )
                self.assertEqual(v_pap.status_code, 422, v_pap.text)
                self.assertEqual(v_pap.json()["error"], "paper_or_sandbox_rejected")
                st_pap = paper_client.get("/api/v1/connect/snaptrade/status").json()
                self.assertEqual(st_pap["active_slots"], 0)
                self.assertEqual(st_pap["available_slots"], 5)
            finally:
                paper_app.verify_app.close()

    def test_snaptrade_verify_rejects_unconnected_empty_accounts_and_bad_auth_mode(self) -> None:
        empty_cfg = ApiConfig(
            publisher_keypair=self.pub_kp,
            publisher_kid="n170-snap-empty-kid",
            snaptrade_client_id="BUILD-KEY-EMPTY-TEST",
            snaptrade_consumer_key="build-consumer-secret-empty",
            account_blinding_salt_hex="cc" * 32,
        )
        empty_relay = SnapTradeRelayCoordinator(
            http_transport=f"{__name__}:picklable_snaptrade_empty_accounts_transport"
        )
        empty_app = create_app(empty_cfg, snaptrade_relay=empty_relay, prefer_fastapi=False)
        empty_client = VerifyApiTestClient(empty_app)
        try:
            p_emp = empty_client.post(
                "/api/v1/connect/snaptrade/portal",
                json={"slot_label": "early-click"},
            )
            self.assertEqual(p_emp.status_code, 200, p_emp.text)
            v_emp = empty_client.post(
                "/api/v1/connect/snaptrade/verify",
                json={
                    "session_token": p_emp.json()["session_token"],
                    "release_slot_after": True,
                    "publish_proof": True,
                },
            )
            # Must reject with 422 validation_error (never sign a 200 proof for 0 accounts!)
            # and keep the session active so the visitor can finish linking and retry.
            self.assertEqual(v_emp.status_code, 422, v_emp.text)
            self.assertEqual(v_emp.json()["error"], "validation_error")
            self.assertIn("No brokerage accounts", v_emp.json()["detail"])
            st_emp = empty_client.get("/api/v1/connect/snaptrade/status").json()
            self.assertEqual(st_emp["active_slots"], 1)
            self.assertIsNotNone(empty_relay.get_session(p_emp.json()["session_token"]))
        finally:
            empty_app.verify_app.close()

        bad_mode_cfg = ApiConfig(
            publisher_keypair=self.pub_kp,
            publisher_kid="n170-snap-badmode-kid",
            snaptrade_client_id="PERS-BAD-MODE-01",
            snaptrade_consumer_key="pers-consumer-secret-badmode",
            snaptrade_auth_mode="invalid_mode",
            account_blinding_salt_hex="dd" * 32,
        )
        bad_app = create_app(bad_mode_cfg, prefer_fastapi=False)
        bad_client = VerifyApiTestClient(bad_app)
        try:
            for method, path, payload in (
                ("GET", "/api/v1/connect/snaptrade/status", None),
                ("POST", "/api/v1/connect/snaptrade/portal", {"slot_label": "s1"}),
                ("POST", "/api/v1/connect/snaptrade/verify", {"session_token": "tok-1"}),
                ("POST", "/api/v1/connect/snaptrade/release", {"release_all": True}),
            ):
                resp = (
                    bad_client.get(path)
                    if method == "GET"
                    else bad_client.post(path, json=payload)
                )
                self.assertEqual(resp.status_code, 500, resp.text)
                self.assertEqual(resp.json()["error"], "snaptrade_config_error")
        finally:
            bad_app.verify_app.close()

    def test_all_five_offline_statement_formats_verify_cleanly_in_spawn_worker(self) -> None:
        import os

        cfg = ApiConfig(
            publisher_keypair=self.pub_kp,
            publisher_kid="n170-offline-formats-kid",
            allow_caller_clock_for_tests=True,
            account_blinding_salt_hex="ee" * 32,
        )
        app = create_app(cfg, prefer_fastapi=False)
        client = VerifyApiTestClient(app)
        parent_pid = os.getpid()

        samples: list[tuple[str, str | None, str, str]] = [
            (
                "ibkr_flex_offline",
                None,
                "ibkr_flex_offline",
                "\n".join(
                    [
                        '<?xml version="1.0" encoding="UTF-8"?>',
                        '<FlexQueryResponse queryName="N170_ReadOnly_Audit_v3" type="AF">',
                        '  <FlexStatements count="1">',
                        '    <FlexStatement accountId="U9048120" currency="USD" fromDate="2026-01-01" toDate="2026-03-31" period="LastQuarter">',
                        '      <AccountInformation accountId="U9048120" currency="USD" accountType="Standard" />',
                        "      <EquitySummaryInBase>",
                        '        <EquitySummaryByReportDateInBase reportDate="2026-01-02" cash="50000.00" stock="0.00" total="50000.00" />',
                        '        <EquitySummaryByReportDateInBase reportDate="2026-02-18" cash="52197.00" stock="0.00" total="52197.00" />',
                        '        <EquitySummaryByReportDateInBase reportDate="2026-03-31" cash="53495.50" stock="0.00" total="53495.50" />',
                        "      </EquitySummaryInBase>",
                        '      <PriorPeriodPositions count="0" />',
                        '      <OpenPositions count="0" />',
                        "      <Trades>",
                        '        <Trade tradeID="T1001" symbol="AAPL" assetCategory="STK" buySell="BUY" quantity="100" tradePrice="200.00" ibCommission="-1.50" currency="USD" dateTime="2026-01-06;10:15:00" />',
                        '        <Trade tradeID="T1002" symbol="AAPL" assetCategory="STK" buySell="SELL" quantity="-100" tradePrice="222.00" ibCommission="-1.50" currency="USD" dateTime="2026-02-12;15:30:00" />',
                        "      </Trades>",
                        '      <CashTransactions count="0" />',
                        '      <Transfers count="0" />',
                        '      <CorporateActions count="0" />',
                        '      <OptionEAE count="0" />',
                        '      <ConversionRates count="0" />',
                        "    </FlexStatement>",
                        "  </FlexStatements>",
                        "</FlexQueryResponse>",
                    ]
                ),
            ),
            (
                "degiro_csv",
                "degiro",
                "degiro_csv",
                "\n".join(
                    [
                        "Datum,Tijd,Valutadatum,Product,ISIN,Beschrijving,FX,Mutatie,,Saldo,,Order Id",
                        "01-02-2026,08:30,01-02-2026,,,iDEAL storting,,EUR,20000.00,EUR,20000.00,",
                        "02-02-2026,09:15,02-02-2026,ASML HOLDING,NL0010273215,Koop 5 @ 680.40 EUR,,EUR,-3402.00,EUR,16598.00,fd81a200-1122",
                        "18-02-2026,15:40,18-02-2026,ASML HOLDING,NL0010273215,Verkoop 5 @ 712.80 EUR,,EUR,3564.00,EUR,20162.00,ab92c110-3344",
                    ]
                ),
            ),
            (
                "mt5_statement",
                None,
                "mt5",
                "\n".join(
                    [
                        "<html><head><title>MetaTrader 5 Trade History Report</title></head>",
                        "<body><table>",
                        "<tr><th colspan='14'>Positions</th></tr>",
                        "<tr><th colspan='14'>Deals</th></tr>",
                        "<tr><td>Time</td><td>Deal</td><td>Symbol</td><td>Type</td><td>Direction</td><td>Volume</td><td>Price</td><td>Order</td><td>Commission</td><td>Fee</td><td>Swap</td><td>Profit</td><td>Balance</td><td>Comment</td></tr>",
                        "<tr><td>2026.02.02 08:00:00</td><td>8801001</td><td></td><td>balance</td><td></td><td></td><td></td><td></td><td>0.00</td><td>0.00</td><td>0.00</td><td>10000.00</td><td>10000.00</td><td>Initial funding</td></tr>",
                        "<tr><td>2026.02.05 09:30:00</td><td>8801010</td><td>EURUSD</td><td>buy</td><td>in</td><td>1.00</td><td>1.08000</td><td>9901010</td><td>-3.50</td><td>0.00</td><td>0.00</td><td>0.00</td><td>9996.50</td><td></td></tr>",
                        "<tr><td>2026.02.10 14:15:00</td><td>8801025</td><td>EURUSD</td><td>sell</td><td>out</td><td>1.00</td><td>1.08250</td><td>9901025</td><td>-3.50</td><td>0.00</td><td>-1.20</td><td>250.00</td><td>10241.80</td><td></td></tr>",
                        "</table></body></html>",
                    ]
                ),
            ),
            (
                "tradovate_csv",
                None,
                "tradovate",
                "\n".join(
                    [
                        "symbol,_priceFormat,_tickSize,buyFillId,sellFillId,qty,buyPrice,sellPrice,pnl,boughtTimestamp,soldTimestamp",
                        "ESH6,-2,0.25,190012,190045,2,5812.25,5824.75,$1250.00,02/11/2026 09:34:12,02/11/2026 10:18:44",
                        "NQH6,-2,0.25,190088,190112,1,20410.50,20468.00,$1150.00,02/12/2026 14:05:09,02/12/2026 15:22:31",
                    ]
                ),
            ),
            (
                "tradezella_journal",
                None,
                "tradezella",
                "\n".join(
                    [
                        "Open Date,Close Date,Symbol,Side,Entry Price,Exit Price,Playbook,Setups,Mistakes,Custom Tags",
                        "2026-02-03,2026-02-03,NVDA,LONG,128.40,134.90,Momentum_Breakout,ORB_5m;Post_Earnings_Drift,None,a_plus_execution|catalyst_aligned",
                        "2026-02-06,2026-02-06,TSLA,SHORT,362.10,354.20,Mean_Reversion,VWAP_Fade,Early_Exit_Trim,ny_open_alpha",
                    ]
                ),
            ),
        ]

        try:
            for req_bid, req_cf, expected_bid, raw_stmt in samples:
                req_json: dict[str, Any] = {
                    "broker_id": req_bid,
                    "raw_statement": raw_stmt,
                    "publish_proof": False,
                    "issued_at_utc": "2026-04-15T12:00:00Z",
                }
                if req_cf is not None:
                    req_json["csv_format"] = req_cf
                resp = client.post("/api/v1/verify", json=req_json)
                self.assertEqual(resp.status_code, 200, f"{req_bid} failed: {resp.text}")
                data = resp.json()
                self.assertTrue(data["verification"]["valid"])
                self.assertEqual(data["proof_bundle"]["broker_id"], expected_bid)
                self.assertNotEqual(data["isolation_receipt"]["worker_pid"], parent_pid)
                self.assertEqual(data["isolation_receipt"]["rlimit_core_hard"], 0)
                trades_leaf = next(
                    lf["payload"]
                    for lf in data["proof_bundle"]["disclosed_leaves"]
                    if lf["leaf_name"] == "delayed_closed_trades"
                )
                self.assertGreaterEqual(len(trades_leaf["trades"]), 1, req_bid)
                if req_bid == "tradezella_journal":
                    coach_leaf = next(
                        lf["payload"]
                        for lf in data["proof_bundle"]["disclosed_leaves"]
                        if lf["leaf_name"] == "coaching_and_context"
                    )
                    self.assertIn("Momentum_Breakout", coach_leaf["imported_journal_tags"])
        finally:
            app.verify_app.close()


if __name__ == "__main__":
    unittest.main()
