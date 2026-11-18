"""Offline unit & accounting tests for Hyperliquid public 0x connector and SnapTrade PERS-* keys."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any
import unittest
import urllib.parse

from n170_verify.connectors import (
    CONNECTOR_CLASS_MAP,
    DisallowedCapabilityError,
    HYPERLIQUID_LIVE_BASE_URL,
    HttpExchangeResponse,
    HyperliquidPublicReadOnlyAdapter,
    HyperliquidServiceError,
    HyperliquidValidationError,
    MAX_SNAPTRADE_PERSONAL_SLOTS,
    MutatingCredentialRejectedError,
    PaperOrSandboxAccountRejectedError,
    SnapTradeReadOnlyAdapter,
    SnapTradeSlotCapExceededError,
    UnsupportedScraperPolicyError,
    build_signed_request,
    compute_snaptrade_signature,
    create_connector,
    get_connector_descriptor,
    is_snaptrade_personal_key,
    list_all_connector_descriptors,
    list_connector_descriptors,
    validate_hyperliquid_wallet_address,
)
from n170_verify.contracts import (
    AccountScope,
    EnvironmentTier,
    FlowKind,
    OriginAssurance,
    ProviderApprovalState,
    ReadOnlyCapabilityViolationError,
    is_external_capital_flow,
)
from n170_verify.pipeline import verify_portfolio


VALID_WALLET_MIXED = "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"
VALID_WALLET_LOWER = VALID_WALLET_MIXED.lower()
OTHER_WALLET = "0x2222222222222222222222222222222222222222"
TEST_SALT_HEX = "5a" * 32


def _build_hyperliquid_mock_transport(
    *,
    wallet_lower: str = VALID_WALLET_LOWER,
) -> tuple[Any, list[dict[str, Any]]]:
    calls: list[dict[str, Any]] = []

    t0 = int(dt.datetime(2026, 1, 10, 0, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)
    t1 = int(dt.datetime(2026, 1, 11, 0, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)
    t2 = int(dt.datetime(2026, 1, 12, 0, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)
    t3 = int(dt.datetime(2026, 1, 13, 0, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)

    def transport(
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str], Any]:
        assert method == "POST"
        assert url == f"{HYPERLIQUID_LIVE_BASE_URL}/info"
        parsed_body = json.loads(body.decode("utf-8"))
        calls.append({"method": method, "url": url, "headers": headers, "body": parsed_body})

        q_type = parsed_body.get("type")
        assert parsed_body.get("user") == wallet_lower

        if q_type == "portfolio":
            # Day 0: 10,000. Day 1: +10% trading gain -> 11,000, plus +500 deposit -> 11,500.
            # Day 2: +5% trading gain -> 12,075, minus 500 withdrawal (499 + 1 fee) -> 11,575.
            # Day 3: +10% trading gain -> 12,732.50.
            # Every interval's gross cash flows stay at or under 10% of its opening value.
            # True flow-adjusted TWR = 1.10 * ((11,575 + 499) / 11,500) * 1.10 - 1 = +27.04% (0.2704)
            return (
                200,
                {"Content-Type": "application/json"},
                [
                    [
                        "day",
                        {"accountValueHistory": [[t2, "11575.0"], [t3, "12732.5"]]},
                    ],
                    [
                        "allTime",
                        {
                            "accountValueHistory": [
                                [t0, "10000.00"],
                                [t1, "11500.00"],
                                [t2, "11575.00"],
                                [t3, "12732.50"],
                            ]
                        },
                    ],
                ],
            )

        if q_type == "userNonFundingLedgerUpdates":
            return (
                200,
                {"Content-Type": "application/json"},
                [
                    {"time": t1, "delta": {"type": "deposit", "usdc": "500.00"}},
                    {
                        "time": t1 + 3600_000,
                        "delta": {"type": "accountClassTransfer", "usdc": "300.00", "toPerp": True},
                    },
                    {
                        "time": t2,
                        "delta": {"type": "withdraw", "usdc": "499.00", "fee": "1.00"},
                    },
                    {
                        "time": t2 + 1000,
                        "delta": {
                            "type": "subAccountTransfer",
                            "usdc": "100.00",
                            "user": wallet_lower,
                            "destination": OTHER_WALLET,
                        },
                    },
                    {
                        "time": t2 + 2000,
                        "delta": {
                            "type": "subAccountTransfer",
                            "usdc": "100.00",
                            "user": OTHER_WALLET,
                            "destination": wallet_lower,
                        },
                    },
                    {
                        "time": t2 + 3000,
                        "delta": {
                            "type": "internalTransfer",
                            "usdc": "50.00",
                            "user": OTHER_WALLET,
                            "destination": wallet_lower,
                        },
                    },
                    {
                        "time": t2 + 4000,
                        "delta": {
                            "type": "internalTransfer",
                            "usdc": "50.00",
                            "fee": "0.0",
                            "user": wallet_lower,
                            "destination": OTHER_WALLET,
                        },
                    },
                ],
            )

        if q_type in {"userFills", "userFillsByTime"}:
            # Both round trips lie inside the scored closes (2026-01-10 .. 2026-01-13).
            # Closed trade 1: 2026-01-12 14:00 (> 7 days before issued_at 2026-01-19 17:00) -> kept
            old_in = int(dt.datetime(2026, 1, 11, 10, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)
            old_out = int(dt.datetime(2026, 1, 12, 14, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)
            # Closed trade 2: 2026-01-12 20:00 (< 7 days before issued_at) -> stripped by 7-day guard
            recent_in = int(dt.datetime(2026, 1, 12, 16, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)
            recent_out = int(dt.datetime(2026, 1, 12, 20, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)
            return (
                200,
                {"Content-Type": "application/json"},
                [
                    {
                        "coin": "ETH",
                        "px": "3000.0",
                        "sz": "2.0",
                        "side": "B",
                        "time": old_in,
                        "fee": "2.10",
                        "tid": 1001,
                    },
                    {
                        "coin": "ETH",
                        "px": "3500.0",
                        "sz": "2.0",
                        "side": "A",
                        "time": old_out,
                        "fee": "2.45",
                        "tid": 1002,
                    },
                    {
                        "coin": "BTC",
                        "px": "95000.0",
                        "sz": "0.1",
                        "side": "B",
                        "time": recent_in,
                        "fee": "3.00",
                        "tid": 1003,
                    },
                    {
                        "coin": "BTC",
                        "px": "98000.0",
                        "sz": "0.1",
                        "side": "A",
                        "time": recent_out,
                        "fee": "3.10",
                        "tid": 1004,
                    },
                ],
            )

        raise AssertionError(f"Unexpected query type: {q_type}")

    return transport, calls


class TestHyperliquidPublicReadOnlyAdapter(unittest.TestCase):
    """Offline tests for HyperliquidPublicReadOnlyAdapter validation, SSRF, accounting, and privacy."""

    def test_wallet_validation_and_case_canonicalization(self) -> None:
        self.assertEqual(validate_hyperliquid_wallet_address(VALID_WALLET_MIXED), VALID_WALLET_LOWER)
        self.assertEqual(
            validate_hyperliquid_wallet_address(f"  {VALID_WALLET_MIXED}  "),
            VALID_WALLET_LOWER,
        )

        for bad_addr in (
            "",
            "   ",
            None,
            12345,
            True,
            "Ab5801a7D398351b8bE11C439e05C5B3259aeC9B",  # missing 0x
            "0x1234",  # too short
            "0x" + "a" * 39,
            "0x" + "a" * 41,
            "0x" + "g" * 40,  # non-hex
        ):
            with self.assertRaises(HyperliquidValidationError, msg=f"Should reject {bad_addr!r}"):
                validate_hyperliquid_wallet_address(bad_addr)

    def test_rejects_testnet_ssrf_mutating_actions_and_secret_kwargs(self) -> None:
        # Testnet hosts must fail under PaperOrSandboxAccountRejectedError
        for testnet_url in (
            "https://api.hyperliquid-testnet.xyz",
            "https://api.hyperliquid-testnet.xyz/info",
        ):
            with self.assertRaises(PaperOrSandboxAccountRejectedError):
                HyperliquidPublicReadOnlyAdapter(
                    wallet_address=VALID_WALLET_MIXED,
                    base_url=testnet_url,
                )

        # SSRF / non-HTTPS / unpinned hosts must fail closed
        for unsafe_url in (
            "http://api.hyperliquid.xyz",
            "https://127.0.0.1",
            "https://169.254.169.254/latest/meta-data",
            "https://evil.example.org",
            "https://user@api.hyperliquid.xyz",
        ):
            with self.assertRaises(ReadOnlyCapabilityViolationError):
                HyperliquidPublicReadOnlyAdapter(
                    wallet_address=VALID_WALLET_MIXED,
                    base_url=unsafe_url,
                )

        # Secret/signing parameters and scraper credentials must be rejected
        for secret_kw in (
            {"private_key": "0xdeadbeef"},
            {"agent_private_key": "0xdeadbeef"},
            {"mnemonic": "twelve words"},
        ):
            with self.assertRaises(MutatingCredentialRejectedError):
                HyperliquidPublicReadOnlyAdapter(wallet_address=VALID_WALLET_MIXED, **secret_kw)

        with self.assertRaises(UnsupportedScraperPolicyError):
            HyperliquidPublicReadOnlyAdapter(
                wallet_address=VALID_WALLET_MIXED,
                session_cookie="sid=secret",
            )

        adapter = HyperliquidPublicReadOnlyAdapter(wallet_address=VALID_WALLET_MIXED)
        for bad_action in ("order", "place_order", "cancel", "withdraw3", "approve_agent", "exchange"):
            with self.assertRaises(DisallowedCapabilityError):
                adapter.assert_action_permitted(bad_action)

        with self.assertRaises(DisallowedCapabilityError):
            adapter._execute_bounded_post("/exchange", {"type": "portfolio", "user": VALID_WALLET_LOWER})

        with self.assertRaises(DisallowedCapabilityError):
            adapter._execute_bounded_post("/info", {"type": "placeOrder", "user": VALID_WALLET_LOWER})

    def test_timeout_and_response_size_bounds_and_error_redaction(self) -> None:
        for bad_timeout in (0.0, -5.0, 31.0, float("nan"), True):
            with self.assertRaises(HyperliquidValidationError):
                HyperliquidPublicReadOnlyAdapter(timeout_seconds=bad_timeout)  # type: ignore[arg-type]

        for bad_max_bytes in (512, 0, 20 * 1024 * 1024, False):
            with self.assertRaises(HyperliquidValidationError):
                HyperliquidPublicReadOnlyAdapter(max_response_bytes=bad_max_bytes)  # type: ignore[arg-type]

        # Oversized response fails closed
        def oversized_transport(method: str, url: str, headers: dict[str, str], body: bytes) -> Any:
            return (200, {"Content-Type": "application/json"}, b"[" + (b"1," * 2048) + b"1]")

        small_cap_adapter = HyperliquidPublicReadOnlyAdapter(
            wallet_address=VALID_WALLET_MIXED,
            http_transport=oversized_transport,
            max_response_bytes=1024,
        )
        with self.assertRaisesRegex(HyperliquidServiceError, "safety cap"):
            small_cap_adapter.fetch_canonical_ledger(blinding_salt_hex=TEST_SALT_HEX)

        # Upstream error redacts raw 0x wallet address
        def failing_transport(method: str, url: str, headers: dict[str, str], body: bytes) -> Any:
            return (
                503,
                {"Content-Type": "text/plain"},
                f"Upstream rate limit for {VALID_WALLET_LOWER} and {VALID_WALLET_MIXED}".encode("utf-8"),
            )

        err_adapter = HyperliquidPublicReadOnlyAdapter(
            wallet_address=VALID_WALLET_MIXED,
            http_transport=failing_transport,
        )
        with self.assertRaises(HyperliquidServiceError) as ctx:
            err_adapter.fetch_canonical_ledger(blinding_salt_hex=TEST_SALT_HEX)
        self.assertNotIn(VALID_WALLET_LOWER, str(ctx.exception).lower())

    def test_registry_descriptor_parity_and_end_to_end_accounting(self) -> None:
        self.assertIs(CONNECTOR_CLASS_MAP["hyperliquid"], HyperliquidPublicReadOnlyAdapter)
        desc = get_connector_descriptor("hyperliquid")
        self.assertEqual(desc.broker_id, "hyperliquid")
        self.assertEqual(desc.approval_state, ProviderApprovalState.PUBLIC_API_PERMISSIONLESS)
        self.assertEqual(desc.default_origin_assurance, OriginAssurance.OPERATOR_RETRIEVED)
        self.assertEqual(len(list_connector_descriptors(env={})), 14)
        self.assertEqual(len(list_connector_descriptors(env={}, include_permissionless=True)), 15)
        self.assertEqual(
            len(list_all_connector_descriptors(env={}, include_poc=True, include_permissionless=True)),
            21,
        )

        transport, calls = _build_hyperliquid_mock_transport()
        adapter = create_connector(
            "hyperliquid",
            wallet_address=VALID_WALLET_MIXED,
            http_transport=transport,
        )
        ledger = adapter.fetch_canonical_ledger(blinding_salt_hex=TEST_SALT_HEX)

        # The second ledger query confirms the history is complete (a page is final only when it adds
        # nothing); older fills are paged because the oldest recent fill is later than the first close.
        self.assertEqual([c["body"]["type"] for c in calls], [
            "portfolio",
            "userNonFundingLedgerUpdates",
            "userNonFundingLedgerUpdates",
            "userFills",
            "userFillsByTime",
            "userFillsByTime",
        ])
        # Paging starts at the first scored close.
        self.assertEqual(
            calls[1]["body"]["startTime"],
            int(dt.datetime(2026, 1, 10, tzinfo=dt.timezone.utc).timestamp() * 1000),
        )
        self.assertEqual(ledger.broker_id, "hyperliquid")
        self.assertEqual(ledger.base_currency, "USD")
        self.assertEqual(ledger.provider_approval_state, ProviderApprovalState.PUBLIC_API_PERMISSIONLESS)
        self.assertEqual(ledger.claimed_origin_assurance, OriginAssurance.OPERATOR_RETRIEVED)
        self.assertEqual(ledger.environment_tier, EnvironmentTier.LIVE_PRODUCTION)
        self.assertEqual(ledger.account_scope, AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED)
        self.assertNotIn(VALID_WALLET_LOWER, json.dumps(ledger.to_dict()).lower())

        # Verify Spot<->Perp class transfer on `allTime` is OTHER_INTERNAL (not external capital flow!)
        class_transfers = [f for f in ledger.flows if f.transfer_type == "accountClassTransfer"]
        self.assertEqual(len(class_transfers), 1)
        self.assertEqual(class_transfers[0].kind, FlowKind.OTHER_INTERNAL)
        self.assertFalse(is_external_capital_flow(class_transfers[0].kind))

        # Run full verify_portfolio pipeline with 7-day delayed trade embargo
        out = verify_portfolio(
            ledger=ledger,
            blinding_salt_hex=TEST_SALT_HEX,
            issued_at_utc="2026-01-19T17:00:00Z",
            embargo_days=7,
            allow_filesystem_paths=False,
        )
        self.assertTrue(out.verification.valid, out.verification.errors)
        # External +500 deposit and -499 withdrawal stripped out of TWR; true trading TWR ~ +27.04%
        self.assertAlmostEqual(out.performance.twr_decimal, 0.2704, delta=0.001)
        # 1 recent BTC round-trip stripped (< 7d old), 1 older ETH round-trip preserved
        self.assertEqual(out.stripped_recent_closed_trades_count, 1)
        self.assertEqual(len(out.delayed_closed_trades), 1)
        self.assertEqual(out.delayed_closed_trades[0].symbol, "ETH")
        bundle_json = json.dumps(out.proof_bundle.to_dict())
        self.assertNotIn(VALID_WALLET_LOWER, bundle_json.lower())
        self.assertNotIn("12732", bundle_json)


class TestSnapTradePersonalKeyAdapter(unittest.TestCase):
    """Offline tests for SnapTrade PERS-* personal single-user API keys vs 5-slot Build keys."""

    def test_personal_key_detection_and_omitted_query_params(self) -> None:
        self.assertTrue(is_snaptrade_personal_key("PERS-N170-FOUNDER"))
        self.assertTrue(is_snaptrade_personal_key("  pers-lower-key  "))
        self.assertFalse(is_snaptrade_personal_key("N170-DEV-BUILD-KEY"))
        self.assertFalse(is_snaptrade_personal_key(""))
        self.assertFalse(is_snaptrade_personal_key(None))

        req = build_signed_request(
            "GET",
            "/api/v1/accounts",
            client_id="PERS-FOUNDER-001",
            consumer_key="secret-consumer-key-pers",
            user_id="should-be-omitted",
            user_secret="should-also-be-omitted",
            extra_query_params={"userId": "blocked", "userSecret": "blocked", "limit": 100},
            timestamp="1700000000",
        )
        qs = urllib.parse.parse_qs(req.query_string)
        self.assertEqual(qs, {"clientId": ["PERS-FOUNDER-001"], "limit": ["100"], "timestamp": ["1700000000"]})
        self.assertNotIn("userId", req.url)
        self.assertNotIn("userSecret", req.url)
        expected_sig = compute_snaptrade_signature(
            "secret-consumer-key-pers",
            api_path="/api/v1/accounts",
            query_string=req.query_string,
            content=None,
        )
        self.assertEqual(req.signature, expected_sig)

    def test_personal_adapter_skips_register_delete_and_supports_per_account_fallbacks(self) -> None:
        personal_id = "PERS-FOUNDER-KEY-99"
        consumer_key = "pers-hmac-secret-999"
        calls: list[tuple[str, str, dict[str, list[str]]]] = []

        def transport(
            method: str,
            url: str,
            headers: dict[str, str],
            body: bytes | None,
        ) -> tuple[int, dict[str, str], Any]:
            parsed = urllib.parse.urlsplit(url)
            qs = urllib.parse.parse_qs(parsed.query)
            calls.append((method, parsed.path, qs))

            # SnapTrade returns HTTP 400 (1012) if registerUser/deleteUser or userId/userSecret are sent on PERS-*
            if parsed.path in {"/api/v1/snapTrade/registerUser", "/api/v1/snapTrade/deleteUser"}:
                return (400, {"Content-Type": "application/json"}, {"code": "1012", "detail": "Personal keys cannot register/delete users"})
            assert "userId" not in qs, f"PERS-* leaked userId on {parsed.path}: {qs}"
            assert "userSecret" not in qs, f"PERS-* leaked userSecret on {parsed.path}: {qs}"

            body_obj = json.loads(body.decode("utf-8")) if body else None
            expected_sig = compute_snaptrade_signature(
                consumer_key,
                api_path=parsed.path,
                query_string=parsed.query,
                content=body_obj,
            )
            assert headers.get("Signature") == expected_sig

            if method == "POST" and parsed.path == "/api/v1/snapTrade/login":
                assert (body_obj or {}).get("connectionType") == "read"
                return (
                    200,
                    {"Content-Type": "application/json"},
                    {"redirectURI": "https://app.snaptrade.com/portal/pers-session", "sessionId": "s-pers"},
                )
            if method == "GET" and parsed.path == "/api/v1/authorizations":
                return (200, {"Content-Type": "application/json"}, [{"id": "auth-pers-1", "type": "read"}])
            if method == "GET" and parsed.path == "/api/v1/accounts":
                return (
                    200,
                    {"Content-Type": "application/json"},
                    [
                        {
                            "id": "acct-pers-ibkr",
                            "number": "U7766554",
                            "name": "Founder Portfolio",
                            "institution_name": "Interactive Brokers",
                            "balance": {"total": {"amount": 85000.0, "currency": "USD"}},
                            "updated_at": "2026-02-20T21:00:00Z",
                        }
                    ],
                )
            if method == "GET" and parsed.path == "/api/v1/holdings":
                # Exercise fallback to /positions and /balances
                return (404, {"Content-Type": "application/json"}, {"detail": "use per-account endpoints"})
            if method == "GET" and parsed.path == "/api/v1/accounts/acct-pers-ibkr/positions":
                return (
                    200,
                    {"Content-Type": "application/json"},
                    [
                        {
                            "symbol": {"symbol": {"symbol": "MSFT", "currency": {"code": "USD"}, "type": {"code": "cs"}}},
                            "units": 100.0,
                            "price": 450.0,
                            "average_purchase_price": 410.0,
                        }
                    ],
                )
            if method == "GET" and parsed.path == "/api/v1/accounts/acct-pers-ibkr/balances":
                return (
                    200,
                    {"Content-Type": "application/json"},
                    [{"currency": {"code": "USD"}, "cash": 40000.0}],
                )
            if method == "GET" and parsed.path == "/api/v1/activities":
                # Exercise fallback to /accounts/{id}/activities
                return (404, {"Content-Type": "application/json"}, {"detail": "use account activities"})
            if method == "GET" and parsed.path == "/api/v1/accounts/acct-pers-ibkr/activities":
                return (
                    200,
                    {"Content-Type": "application/json"},
                    [
                        {
                            "id": "act-1",
                            "type": "DEPOSIT",
                            "amount": 81000.0,
                            "currency": {"code": "USD"},
                            "trade_date": "2026-01-05T14:00:00Z",
                        },
                        {
                            "id": "act-2",
                            "type": "BUY",
                            "symbol": {"symbol": "MSFT", "currency": {"code": "USD"}},
                            "units": 100.0,
                            "price": 410.0,
                            "fee": 1.0,
                            "currency": {"code": "USD"},
                            "trade_date": "2026-01-06T15:00:00Z",
                        },
                    ],
                )
            if method == "GET" and parsed.path == "/api/v1/performance/custom":
                # A valuation series covering the BUY keeps it inside the record's period (the opening
                # DEPOSIT, dated before the first close, stays outside it).
                return (
                    200,
                    {"Content-Type": "application/json"},
                    {
                        "totalEquityTimeframe": [
                            {"date": "2026-01-05", "value": 81000.0},
                            {"date": "2026-02-20", "value": 85000.0},
                        ]
                    },
                )
            return (404, {"Content-Type": "application/json"}, {"error": "not_found"})

        adapter = SnapTradeReadOnlyAdapter(
            client_id=personal_id,
            consumer_key=consumer_key,
            http_transport=transport,
            auto_register_slot=False,
        )
        self.assertTrue(adapter.is_personal_key)
        self.assertEqual(adapter.slot_manager.max_slots, MAX_SNAPTRADE_PERSONAL_SLOTS)

        reg = adapter.register_user("founder-owner")
        self.assertEqual(reg["userSecret"], "")
        self.assertEqual(len(calls), 0)  # Zero registerUser upstream call!

        # 2nd distinct user on 1-slot personal adapter must raise SnapTradeSlotCapExceededError
        with self.assertRaises(SnapTradeSlotCapExceededError):
            adapter.register_user("second-visitor")

        with self.assertRaises(DisallowedCapabilityError):
            adapter.generate_connection_portal_url("founder-owner", "", connection_type="trade")

        portal = adapter.generate_connection_portal_url("founder-owner", "")
        self.assertEqual(portal["connectionType"], "read")
        self.assertTrue(portal["redirectURI"].startswith("https://app.snaptrade.com/"))

        auths = adapter.list_authorizations("founder-owner", "")
        self.assertEqual(len(auths), 1)

        ledger = adapter.fetch_live_ledger(
            "founder-owner",
            "",
            blinding_salt_hex=TEST_SALT_HEX,
        )
        # Total NAV must include both cash ($40k) + MSFT ($45k) = $85k (not cash-only $40k!)
        self.assertEqual(ledger.nav_points[-1].nav_base, 85000.0)
        self.assertEqual(len(ledger.ending_positions), 1)
        self.assertEqual(ledger.ending_positions[0].symbol, "MSFT")
        self.assertEqual(len(ledger.trades), 1)

        rel = adapter.delete_user_and_release_slot("founder-owner")
        self.assertTrue(rel["slot_released"])
        called_paths = [p for _, p, _ in calls]
        self.assertNotIn("/api/v1/snapTrade/registerUser", called_paths)
        self.assertNotIn("/api/v1/snapTrade/deleteUser", called_paths)

    def test_hyperliquid_self_transfers_unvalued_spot_tokens_and_liquidation_guard(self) -> None:
        from n170_verify.performance.calculator import calculate_portfolio_performance_detailed

        adapter = HyperliquidPublicReadOnlyAdapter()
        t0 = int(dt.datetime(2026, 1, 1, 0, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)
        t1 = int(dt.datetime(2026, 1, 2, 0, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)
        t2 = int(dt.datetime(2026, 1, 3, 0, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)
        t3 = int(dt.datetime(2026, 1, 4, 0, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)

        # 1. Self-transfers (`user == destination == wallet`) across DEXes stay OTHER_INTERNAL
        ledger_self = adapter.parse_payload(
            {
                "portfolio": [["allTime", {"accountValueHistory": [[t1, "10000.0"], [t2, "12000.0"]]}]],
                "ledger_updates": [
                    {
                        "time": t1 + 3600_000,
                        "delta": {
                            "type": "send",
                            "user": VALID_WALLET_LOWER,
                            "destination": VALID_WALLET_LOWER,
                            "sourceDex": "",
                            "destinationDex": "spot",
                            "token": "USDC",
                            "amount": "4000.0",
                            "usdcValue": "4000.0",
                        },
                    },
                    {
                        "time": t1 + 7200_000,
                        "delta": {
                            "type": "spotTransfer",
                            "user": VALID_WALLET_LOWER,
                            "destination": VALID_WALLET_LOWER,
                            "token": "HYPE",
                            "amount": "100.0",
                            "usdcValue": "2500.0",
                        },
                    },
                ],
                "fills": [],
            },
            wallet_address=VALID_WALLET_MIXED,
            blinding_salt_hex=TEST_SALT_HEX,
        )
        self.assertTrue(all(f.kind == FlowKind.OTHER_INTERNAL for f in ledger_self.flows))
        perf_self = calculate_portfolio_performance_detailed(ledger_self)
        self.assertFalse(perf_self.withheld)
        self.assertAlmostEqual(perf_self.summary.twr_decimal, 0.20, places=6)

        # 2. Unvalued non-USDC spotTransfer omits usdcValue -> never treats token units as USD; withholds TWR
        ledger_unvalued = adapter.parse_payload(
            {
                "portfolio": [["allTime", {"accountValueHistory": [[t1, "1000.0"], [t2, "1500.0"]]}]],
                "ledger_updates": [
                    {
                        "time": t1 + 3600_000,
                        "delta": {
                            "type": "spotTransfer",
                            "user": OTHER_WALLET,
                            "destination": VALID_WALLET_LOWER,
                            "token": "PURR",
                            "amount": "50000.0",
                        },
                    }
                ],
                "fills": [],
            },
            wallet_address=VALID_WALLET_MIXED,
            blinding_salt_hex=TEST_SALT_HEX,
        )
        self.assertEqual(len(ledger_unvalued.flows), 1)
        self.assertEqual(ledger_unvalued.flows[0].kind, FlowKind.TRANSFER_IN_KIND)
        self.assertEqual(ledger_unvalued.flows[0].amount, 0.0)
        self.assertEqual(ledger_unvalued.flows[0].quantity, 50000.0)
        perf_unvalued = calculate_portfolio_performance_detailed(ledger_unvalued)
        self.assertTrue(perf_unvalued.withheld)

        # 2b. Unsolicited $0.00-valued spam airdrop dust (`usdcValue: "0.0"`) + multi-window `portfolio`
        # merging (`allTime` + `month` + `week` + `day`) preserves valid TWR without griefing withhold
        t_mid = t1 + 43200_000
        ledger_dust_and_merged = adapter.parse_payload(
            {
                "portfolio": [
                    ["allTime", {"accountValueHistory": [[t1, "1000.0"], [t3, "1500.0"]]}],
                    ["week", {"accountValueHistory": [[t2, "1250.0"], [t3, "1500.0"]]}],
                ],
                "ledger_updates": [
                    {
                        "time": t1 + 3600_000,
                        "delta": {
                            "type": "spotTransfer",
                            "user": OTHER_WALLET,
                            "destination": VALID_WALLET_LOWER,
                            "token": "MAX",
                            "amount": "1000000000.0",
                            "usdcValue": "0.0",
                        },
                    }
                ],
                "fills": [],
            },
            wallet_address=VALID_WALLET_MIXED,
            blinding_salt_hex=TEST_SALT_HEX,
        )
        self.assertEqual([p.nav_base for p in ledger_dust_and_merged.nav_points], [1000.0, 1250.0, 1500.0])
        self.assertEqual(ledger_dust_and_merged.flows[0].kind, FlowKind.OTHER_INTERNAL)
        perf_dust = calculate_portfolio_performance_detailed(ledger_dust_and_merged)
        self.assertFalse(perf_dust.withheld)
        self.assertAlmostEqual(perf_dust.summary.twr_decimal, 0.50, places=6)

        # 3a. Terminal 100% liquidation to 0.0 (no withdrawal) preserves 0.0 and withholds TWR
        ledger_liq = adapter.parse_payload(
            {
                "portfolio": [
                    [
                        "allTime",
                        {
                            "accountValueHistory": [
                                [t0, "0.0"],
                                [t1, "10000.0"],
                                [t2, "15000.0"],
                                [t3, "0.0"],
                            ]
                        },
                    ]
                ],
                "ledger_updates": [],
                "fills": [],
            },
            wallet_address=VALID_WALLET_MIXED,
            blinding_salt_hex=TEST_SALT_HEX,
        )
        self.assertEqual([p.nav_base for p in ledger_liq.nav_points], [10000.0, 15000.0, 0.0])
        perf_liq = calculate_portfolio_performance_detailed(ledger_liq)
        self.assertTrue(perf_liq.withheld)

        # 3b. A clean 100% withdrawal to 0.0 is a cash flow of 100% of the opening value inside one
        # valuation interval, so that interval's return cannot be computed and the return is withheld
        ledger_full_wd = adapter.parse_payload(
            {
                "portfolio": [
                    [
                        "allTime",
                        {
                            "accountValueHistory": [
                                [t0, "0.0"],
                                [t1, "10000.0"],
                                [t2, "15000.0"],
                                [t3, "0.0"],
                            ]
                        },
                    ]
                ],
                "ledger_updates": [
                    {"time": t3, "delta": {"type": "withdraw", "usdc": "15000.0", "fee": "0.0"}}
                ],
                "fills": [],
            },
            wallet_address=VALID_WALLET_MIXED,
            blinding_salt_hex=TEST_SALT_HEX,
        )
        perf_wd = calculate_portfolio_performance_detailed(ledger_full_wd)
        self.assertTrue(perf_wd.withheld)
        self.assertTrue(
            any(
                "cash flows of 100.0% of the opening value fall inside the valuation interval" in w
                for w in perf_wd.summary.warnings
            )
        )

    def test_snaptrade_auth_mode_override_and_performance_custom_equity_curve(self) -> None:
        from n170_verify.connectors import SnapTradeAuthenticationError
        from n170_verify.performance.calculator import calculate_portfolio_performance_detailed

        self.assertTrue(is_snaptrade_personal_key("CUSTOM-ID", auth_mode="personal"))
        self.assertFalse(is_snaptrade_personal_key("PERS-CUSTOM", auth_mode="commercial"))
        with self.assertRaises(SnapTradeAuthenticationError):
            is_snaptrade_personal_key("PERS-CUSTOM", auth_mode="bogus")

        def transport(
            method: str,
            url: str,
            headers: dict[str, str],
            body: bytes | None,
        ) -> tuple[int, dict[str, str], Any]:
            parsed = urllib.parse.urlsplit(url)
            qs = urllib.parse.parse_qs(parsed.query)
            assert "userId" not in qs and "userSecret" not in qs
            if parsed.path == "/api/v1/accounts":
                return (
                    200,
                    {"Content-Type": "application/json"},
                    [{"id": "acct-1", "balance": {"total": {"amount": 120000.0, "currency": "USD"}}}],
                )
            if parsed.path == "/api/v1/holdings":
                return (
                    200,
                    {"Content-Type": "application/json"},
                    [
                        {
                            "account": {
                                "id": "acct-1",
                                "sync_status": {"holdings": {"last_successful_sync": "2026-01-05T00:00:00Z"}},
                            },
                            "balances": [{"currency": {"code": "USD"}, "cash": 120000.0}],
                            "positions": [],
                            "total_value": {"value": 120000.0, "currency": "USD"},
                        }
                    ],
                )
            if parsed.path == "/api/v1/activities":
                return (
                    200,
                    {"Content-Type": "application/json"},
                    [
                        {
                            "id": "dep-1",
                            "type": "DEPOSIT",
                            "amount": 100000.0,
                            "currency": {"code": "USD"},
                            "trade_date": "2026-01-02T00:00:00Z",
                        }
                    ],
                )
            if parsed.path == "/api/v1/performance/custom":
                return (
                    200,
                    {"Content-Type": "application/json"},
                    {
                        "totalEquityTimeframe": [
                            {"date": "2026-01-02", "value": 100000.0},
                            {"date": "2026-01-05", "value": 120000.0},
                        ]
                    },
                )
            return (404, {"Content-Type": "application/json"}, {"error": "not_found"})

        adapter = SnapTradeReadOnlyAdapter(
            client_id="NON-PERS-ID-OVERRIDE",
            consumer_key="secret-consumer-key",
            auth_mode="personal",
            http_transport=transport,
            auto_register_slot=False,
        )
        ledger = adapter.fetch_live_ledger("founder", "", blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual([p.nav_base for p in ledger.nav_points], [100000.0, 120000.0])
        perf = calculate_portfolio_performance_detailed(ledger)
        self.assertFalse(perf.withheld)
        self.assertAlmostEqual(perf.summary.twr_decimal, 0.20, places=6)

    def test_snaptrade_funds_flows_fractional_units_symbol_codes_and_401_403_422_fallbacks(
        self,
    ) -> None:
        from n170_verify.connectors import SnapTradeAuthenticationError
        from n170_verify.contracts import AssetClass
        from n170_verify.performance.calculator import calculate_portfolio_performance_detailed

        raw_acct_id = "acct-secret-pers-777"
        raw_acct_num = "U9876543"

        def make_fallback_transport(status_code: int, *, fail_per_account_balances: bool = False) -> Any:
            def _transport(
                method: str,
                url: str,
                headers: dict[str, str],
                body: bytes | None,
            ) -> tuple[int, dict[str, str], Any]:
                parsed = urllib.parse.urlsplit(url)
                if parsed.path == "/api/v1/accounts":
                    return (
                        200,
                        {"Content-Type": "application/json"},
                        [
                            {
                                "id": raw_acct_id,
                                "number": raw_acct_num,
                                "name": "Founder Personal",
                                "institution_name": "Interactive Brokers",
                                "balance": {"total": {"amount": 25000.0, "currency": "USD"}},
                                "updated_at": "2026-02-10T21:00:00Z",
                            }
                        ],
                    )
                if parsed.path == "/api/v1/holdings":
                    return (status_code, {"Content-Type": "application/json"}, {"detail": "restricted"})
                if parsed.path == f"/api/v1/accounts/{raw_acct_id}/positions":
                    return (
                        200,
                        {"Content-Type": "application/json"},
                        [
                            {
                                "symbol": {
                                    "symbol": {
                                        "symbol": "VWCE",
                                        "currency": {"code": "USD"},
                                        "type": {"code": "et", "description": "Exchange Traded Fund"},
                                    }
                                },
                                "units": None,
                                "fractional_units": "12.5",
                                "price": 120.0,
                                "average_purchase_price": 100.0,
                            },
                            {
                                "instrument": {
                                    "symbol": {
                                        "raw_symbol": "CEF1",
                                        "currency": {"code": "USD"},
                                        "type": {"code": "cef"},
                                    }
                                },
                                "units": 0,
                                "fractional_units": 2.5,
                                "price": 200.0,
                                "average_purchase_price": 180.0,
                            },
                            {
                                "symbol": {
                                    "symbol": {
                                        "symbol": "SPY260320C00550000",
                                        "currency": {"code": "USD"},
                                        "type": {"code": "op"},
                                    }
                                },
                                "units": 1.0,
                                "price": 5.0,
                                "average_purchase_price": 4.0,
                            },
                        ],
                    )
                if parsed.path == f"/api/v1/accounts/{raw_acct_id}/balances":
                    if fail_per_account_balances:
                        return (401, {"Content-Type": "application/json"}, {"detail": "expired token"})
                    return (
                        200,
                        {"Content-Type": "application/json"},
                        [{"currency": {"code": "USD"}, "cash": 22500.0}],
                    )
                if parsed.path == "/api/v1/activities":
                    return (status_code, {"Content-Type": "application/json"}, {"detail": "restricted"})
                if parsed.path == f"/api/v1/accounts/{raw_acct_id}/activities":
                    return (
                        200,
                        {"Content-Type": "application/json"},
                        [
                            {
                                "id": f"tx-{raw_acct_id}-1",
                                "type": "FUNDS_CONTRIBUTION",
                                "amount": "20000.00",
                                "currency": {"code": "USD"},
                                "date": "2026-01-10",
                                "description": f"Initial funding into {raw_acct_num}",
                            },
                            {
                                "id": f"tx-{raw_acct_id}-2",
                                "type": "FUNDS_WITHDRAWAL",
                                "amount": "1000.00",
                                "currency": {"code": "USD"},
                                "date": "2026-01-20",
                                "description": f"Partial payout from {raw_acct_id}",
                            },
                            {
                                "id": f"tx-{raw_acct_id}-3",
                                "type": "BUY",
                                "symbol": {"symbol": "VWCE", "type": {"code": "et"}},
                                "units": None,
                                "fractional_units": "12.5",
                                "price": "100.00",
                                "fee": "0.50",
                                "currency": {"code": "USD"},
                                "date": "2026-01-12",
                            },
                        ],
                    )
                if parsed.path == "/api/v1/performance/custom":
                    return (
                        200,
                        {"Content-Type": "application/json"},
                        {
                            "totalEquityTimeframe": [
                                {"date": "2026-01-10", "value": 20000.0},
                                {"date": "2026-01-20", "value": 19500.0},
                                {"date": "2026-02-10", "value": 25000.0},
                            ]
                        },
                    )
                return (404, {"Content-Type": "application/json"}, {"error": "not_found"})

            return _transport

        for fallback_code in (401, 403, 422):
            adapter = SnapTradeReadOnlyAdapter(
                client_id="PERS-COMPAT-01",
                consumer_key="pers-compat-secret",
                http_transport=make_fallback_transport(fallback_code),
                auto_register_slot=False,
            )
            ledger = adapter.fetch_live_ledger("founder", "", blinding_salt_hex=TEST_SALT_HEX)
            pos_by_sym = {p.symbol: p for p in ledger.ending_positions}
            self.assertEqual(pos_by_sym["VWCE"].asset_class, AssetClass.ETF)
            self.assertAlmostEqual(pos_by_sym["VWCE"].quantity, 12.5)
            self.assertEqual(pos_by_sym["CEF1"].asset_class, AssetClass.ETF)
            self.assertAlmostEqual(pos_by_sym["CEF1"].quantity, 2.5)
            self.assertEqual(pos_by_sym["SPY260320C00550000"].asset_class, AssetClass.OPTION)
            self.assertAlmostEqual(pos_by_sym["SPY260320C00550000"].multiplier, 100.0)
            self.assertAlmostEqual(pos_by_sym["SPY260320C00550000"].market_value, 500.0)

            deposits = [f for f in ledger.flows if f.kind == FlowKind.DEPOSIT]
            withdrawals = [f for f in ledger.flows if f.kind == FlowKind.WITHDRAWAL]
            # The initial funding (2026-01-10 00:00) precedes the first valuation (that date's close),
            # so it lies outside the record's period and is not in the ledger.
            self.assertEqual(ledger.period_start_utc, "2026-01-10T23:59:59Z")
            self.assertEqual(deposits, [])
            self.assertEqual(len(withdrawals), 1)
            self.assertEqual(withdrawals[0].amount, -1000.0)
            self.assertEqual(withdrawals[0].timestamp_utc, "2026-01-20T00:00:00Z")

            self.assertEqual(len(ledger.trades), 1)
            self.assertEqual(ledger.trades[0].asset_class, AssetClass.ETF)
            self.assertAlmostEqual(ledger.trades[0].quantity, 12.5)

            serialized_ledger = json.dumps(ledger.to_dict())
            self.assertNotIn(raw_acct_id, serialized_ledger)
            self.assertNotIn(raw_acct_num, serialized_ledger)

            perf = calculate_portfolio_performance_detailed(ledger)
            self.assertFalse(perf.withheld)

        # Genuine 401 on per-account /balances must still fail closed!
        bad_adapter = SnapTradeReadOnlyAdapter(
            client_id="PERS-COMPAT-01",
            consumer_key="pers-compat-secret",
            http_transport=make_fallback_transport(403, fail_per_account_balances=True),
            auto_register_slot=False,
        )
        with self.assertRaises(SnapTradeAuthenticationError):
            bad_adapter.fetch_live_ledger("founder", "", blinding_salt_hex=TEST_SALT_HEX)

    def test_hyperliquid_pagination_boundary_overlap_and_explicit_period_forwarding(self) -> None:
        from n170_verify.connectors.hyperliquid import HYPERLIQUID_LEDGER_PAGE_SIZE
        from n170_verify.pipeline import ingest_portfolio_ledger

        t0 = int(dt.datetime(2026, 1, 10, 0, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)
        t_boundary = int(dt.datetime(2026, 1, 11, 0, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)
        t_end = int(dt.datetime(2026, 1, 12, 0, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)
        t_after = int(dt.datetime(2026, 1, 13, 0, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)

        ledger_queries: list[dict[str, Any]] = []

        # Page 1 has 2000 items ending at t_boundary (hash-a); Page 2 overlaps at t_boundary (hash-a + hash-b!)
        page_1 = [
            {
                "time": t0 + i,
                "hash": f"0xfiller{i:06d}",
                "delta": {"type": "accountClassTransfer", "usdc": "1.0", "toPerp": True},
            }
            for i in range(HYPERLIQUID_LEDGER_PAGE_SIZE - 1)
        ] + [
            {
                "time": t_boundary,
                "hash": "0xboundaryA",
                "delta": {"type": "deposit", "usdc": "2000.0"},
            }
        ]
        page_2 = [
            {
                "time": t_boundary,
                "hash": "0xboundaryA",
                "delta": {"type": "deposit", "usdc": "2000.0"},
            },
            {
                "time": t_boundary,
                "hash": "0xboundaryB",
                "delta": {"type": "deposit", "usdc": "3000.0"},
            },
            {
                "time": t_boundary + 60_000,
                "hash": "0xafterBoundary",
                "delta": {"type": "accountClassTransfer", "usdc": "1.0", "toPerp": True},
            },
        ]

        def paginated_transport(
            method: str,
            url: str,
            headers: dict[str, str],
            body: bytes,
        ) -> tuple[int, dict[str, str], Any]:
            req = json.loads(body.decode("utf-8"))
            q_type = req["type"]
            if q_type == "portfolio":
                return (
                    200,
                    {"Content-Type": "application/json"},
                    [
                        [
                            "allTime",
                            {
                                "accountValueHistory": [
                                    [t0 - 86400_000, "9000.0"],
                                    [t0, "10000.0"],
                                    [t_boundary, "15000.0"],
                                    [t_end, "16500.0"],
                                    [t_after, "99999.0"],
                                ]
                            },
                        ]
                    ],
                )
            if q_type == "userNonFundingLedgerUpdates":
                ledger_queries.append(req)
                if len(ledger_queries) == 1:
                    return (200, {"Content-Type": "application/json"}, page_1)
                return (200, {"Content-Type": "application/json"}, page_2)
            if q_type in {"userFills", "userFillsByTime"}:
                return (
                    200,
                    {"Content-Type": "application/json"},
                    [
                        {
                            "coin": "ETH",
                            "px": "3100.0",
                            "sz": "1.0",
                            "side": "B",
                            "time": t0 + 1000,
                            "fee": "1.0",
                            "tid": 1,
                        },
                        {
                            "coin": "ETH",
                            "px": "3400.0",
                            "sz": "1.0",
                            "side": "A",
                            "time": t_after,
                            "fee": "1.0",
                            "tid": 2,
                        },
                    ],
                )
            raise AssertionError(f"Unexpected query {q_type}")

        ledger = ingest_portfolio_ledger(
            broker_id="hyperliquid",
            connector_kwargs={
                "wallet_address": VALID_WALLET_MIXED,
                "http_transport": paginated_transport,
            },
            blinding_salt_hex=TEST_SALT_HEX,
            period_start_utc="2026-01-10T00:00:00Z",
            period_end_utc="2026-01-12T23:59:59Z",
        )

        # Explicit period bounds were forwarded to startTime / endTime on POST /info
        # Page 3 confirms the history is complete (a page is final only when it adds nothing).
        self.assertEqual(len(ledger_queries), 3)
        self.assertEqual(ledger_queries[0]["startTime"], t0)
        self.assertEqual(ledger_queries[0]["endTime"], t_end + 86_399_000)
        # Page 2 used inclusive boundary cursor `t_boundary` (NOT `t_boundary + 1`)
        self.assertEqual(ledger_queries[1]["startTime"], t_boundary)
        self.assertEqual(ledger_queries[1]["endTime"], t_end + 86_399_000)

        # Both deposits at t_boundary ($2,000 + $3,000) were captured without duplicating 0xboundaryA!
        deposit_amounts = [f.amount for f in ledger.flows if f.kind == FlowKind.DEPOSIT]
        self.assertEqual(deposit_amounts, [2000.0, 3000.0])

        # NAV snapshots and fills outside [period_start_utc, period_end_utc] were excluded
        self.assertEqual([p.nav_base for p in ledger.nav_points], [10000.0, 15000.0, 16500.0])
        self.assertEqual(len(ledger.trades), 1)
        self.assertEqual(ledger.trades[0].native_entry_id, "hl-tid-1")

    def test_snaptrade_empty_accounts_session_rejected_with_validation_error(self) -> None:
        from n170_verify.connectors.snaptrade import SnapTradeError

        def empty_accounts_transport(
            method: str,
            url: str,
            headers: dict[str, str],
            body: bytes | None,
        ) -> tuple[int, dict[str, str], Any]:
            parsed = urllib.parse.urlsplit(url)
            if parsed.path == "/api/v1/accounts":
                return (200, {"Content-Type": "application/json"}, [])
            return (200, {"Content-Type": "application/json"}, [])

        adapter = SnapTradeReadOnlyAdapter(
            client_id="PERS-EMPTY-CHECK-01",
            consumer_key="pers-empty-secret",
            http_transport=empty_accounts_transport,
            auto_register_slot=False,
        )
        with self.assertRaises(ValueError) as ctx:
            adapter.fetch_live_ledger("founder", "", blinding_salt_hex=TEST_SALT_HEX)
        self.assertNotIsInstance(ctx.exception, SnapTradeError)
        self.assertIn("No brokerage accounts", str(ctx.exception))

    def test_snaptrade_eur_multicurrency_rates_option_multiplier_and_capital_bracket(self) -> None:
        from n170_verify.performance.calculator import calculate_portfolio_performance_detailed
        from n170_verify.pipeline import verify_portfolio

        raw_acct_id = "acct-founder-eur-ibkr"
        raw_acct_num = "U7654321"

        def make_eur_transport(*, with_custom_curve: bool) -> Any:
            def _transport(
                method: str,
                url: str,
                headers: dict[str, str],
                body: bytes | None,
            ) -> tuple[int, dict[str, str], Any]:
                parsed = urllib.parse.urlsplit(url)
                qs = urllib.parse.parse_qs(parsed.query)
                if parsed.path == "/api/v1/currencies/rates":
                    self.assertNotIn("userId", qs)
                    self.assertNotIn("userSecret", qs)
                    return (
                        200,
                        {"Content-Type": "application/json"},
                        [
                            {
                                "src": {"code": "USD"},
                                "dst": {"code": "EUR"},
                                "exchange_rate": "0.90",
                            }
                        ],
                    )
                if parsed.path == "/api/v1/accounts":
                    # Mirror founder IBKR shape where account omits currency & balance.total
                    return (
                        200,
                        {"Content-Type": "application/json"},
                        [
                            {
                                "id": raw_acct_id,
                                "number": raw_acct_num,
                                "name": "Founder EUR Margin",
                                "institution_name": "Interactive Brokers",
                                "updated_at": "2026-02-20T21:00:00Z",
                            }
                        ],
                    )
                if parsed.path in {"/api/v1/holdings", "/api/v1/activities"}:
                    return (403, {"Content-Type": "application/json"}, {"detail": "restricted"})
                if parsed.path == f"/api/v1/accounts/{raw_acct_id}/positions":
                    return (
                        200,
                        {"Content-Type": "application/json"},
                        [
                            {
                                "symbol": {
                                    "symbol": {
                                        "symbol": "AAPL",
                                        "currency": {"code": "USD"},
                                        "type": {"code": "cs"},
                                    }
                                },
                                "units": 100.0,
                                "price": 200.0,
                                "average_purchase_price": 180.0,
                            },
                            {
                                "symbol": {
                                    "symbol": {
                                        "symbol": "VWCE",
                                        "currency": {"code": "EUR"},
                                        "type": {"code": "et"},
                                    }
                                },
                                "units": 200.0,
                                "price": 120.0,
                                "average_purchase_price": 110.0,
                            },
                            {
                                "symbol": {
                                    "symbol": {
                                        "symbol": "SPY260320C00550000",
                                        "currency": {"code": "USD"},
                                        "type": {"code": "op"},
                                    }
                                },
                                "units": 1.0,
                                "price": 5.0,
                                "average_purchase_price": 4.0,
                            },
                        ],
                    )
                if parsed.path == f"/api/v1/accounts/{raw_acct_id}/balances":
                    return (
                        200,
                        {"Content-Type": "application/json"},
                        [
                            {"currency": {"code": "EUR"}, "cash": 50000.0},
                            {"currency": {"code": "USD"}, "cash": 10000.0},
                        ],
                    )
                if parsed.path == f"/api/v1/accounts/{raw_acct_id}/activities":
                    return (
                        200,
                        {"Content-Type": "application/json"},
                        [
                            {
                                "id": "act-eur-1",
                                "type": "FUNDS_CONTRIBUTION",
                                "amount": "10000.00",
                                "currency": {"code": "USD"},
                                "date": "2026-01-15",
                            },
                            {
                                "id": "act-eur-2",
                                "type": "BUY",
                                "symbol": {
                                    "symbol": "AAPL",
                                    "currency": {"code": "USD"},
                                    "type": {"code": "cs"},
                                },
                                "units": 100.0,
                                "price": 180.0,
                                "fee": 1.0,
                                "currency": {"code": "USD"},
                                "date": "2026-01-16",
                            },
                        ],
                    )
                if parsed.path == "/api/v1/performance/custom":
                    if not with_custom_curve:
                        return (404, {"Content-Type": "application/json"}, {"detail": "unavailable"})
                    return (
                        200,
                        {"Content-Type": "application/json"},
                        {
                            "totalEquityTimeframe": [
                                {"date": "2026-01-10", "value": 85000.0},
                                {"date": "2026-01-20", "value": 96000.0},
                                {"date": "2026-02-20", "value": 101450.0},
                            ]
                        },
                    )
                return (404, {"Content-Type": "application/json"}, {"detail": "not_found"})

            return _transport

        # 1. Without /performance/custom: fallback NAV converts USD->EUR (0.90) AND applies option 100x multiplier:
        # Cash = 50,000 + (10,000 * 0.90) = 59,000 EUR
        # Positions = (100 * 200 * 0.90) + (200 * 120) + (1 * 5 * 100 * 0.90) = 18,000 + 24,000 + 450 = 42,450 EUR
        # Total = 101,450 EUR
        adapter_fallback = SnapTradeReadOnlyAdapter(
            client_id="PERS-FOUNDER-EUR-01",
            consumer_key="pers-eur-secret",
            http_transport=make_eur_transport(with_custom_curve=False),
            auto_register_slot=False,
        )
        ledger_fb = adapter_fallback.fetch_live_ledger("founder", "", blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(ledger_fb.base_currency, "EUR")
        self.assertEqual(len(ledger_fb.nav_points), 1)
        self.assertAlmostEqual(ledger_fb.nav_points[0].cash_base or 0.0, 59000.0, places=4)
        self.assertAlmostEqual(ledger_fb.nav_points[0].nav_base, 101450.0, places=4)

        # 2. With multi-day curve: the USD deposit inside the series has no conversion rate for its own
        # date (only today's rate is offered), so the return is withheld and no capital bracket is measured.
        adapter_curve = SnapTradeReadOnlyAdapter(
            client_id="PERS-FOUNDER-EUR-01",
            consumer_key="pers-eur-secret",
            http_transport=make_eur_transport(with_custom_curve=True),
            auto_register_slot=False,
        )
        ledger_curve = adapter_curve.fetch_live_ledger("founder", "", blinding_salt_hex=TEST_SALT_HEX)
        perf_curve = calculate_portfolio_performance_detailed(ledger_curve)
        self.assertTrue(perf_curve.withheld)
        self.assertIn(
            "A deposit, withdrawal or transfer in a currency other than the base currency has no "
            "conversion rate for its own date; returns are withheld.",
            ledger_curve.parser_warnings,
        )

        out = verify_portfolio(
            ledger=ledger_curve,
            blinding_salt_hex=TEST_SALT_HEX,
            issued_at_utc="2026-03-01T00:00:00Z",
        )
        bracket_leaf = next(
            lf.payload for lf in out.proof_bundle.disclosed_leaves if lf.leaf_name == "capital_bracket"
        )
        self.assertIsNone(bracket_leaf["capital_bracket"])
        self.assertEqual(bracket_leaf["valuation_currency"], "EUR")

    def test_hyperliquid_intraday_daily_bucketing_fill_pagination_and_modified_dietz_default(self) -> None:
        from n170_verify.connectors.hyperliquid import HYPERLIQUID_FILLS_PAGE_SIZE
        from n170_verify.performance.calculator import calculate_portfolio_performance_detailed
        from n170_verify.pipeline import verify_portfolio

        adapter = HyperliquidPublicReadOnlyAdapter()

        # 1. Brand-new 1-day wallet with 40 15-minute snapshots must NOT spoof T >= 30 PSR eligibility:
        # one UTC date has one close and no scored interval, so the record is withheld
        day0_ms = int(dt.datetime(2026, 3, 1, 0, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)
        intraday_40 = [
            [day0_ms + i * 15 * 60_000, str(10000.0 - 200.0 if i == 10 else 10000.0 + i * 25.0)]
            for i in range(40)
        ]
        with self.assertRaises(HyperliquidValidationError):
            adapter.parse_payload(
                {"portfolio": [["day", {"accountValueHistory": intraday_40}]], "ledger_updates": [], "fills": []},
                wallet_address=VALID_WALLET_MIXED,
                blinding_salt_hex=TEST_SALT_HEX,
            )

        # 2. Multi-day wallet with `allTime` + intraday `day`/`week` buckets to 1 UTC close per day,
        # and `verify_portfolio` defaults `cash_flow_timing` to `modified_dietz` for `hyperliquid`
        d1_ms = int(dt.datetime(2026, 2, 1, 23, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)
        d2_ms = int(dt.datetime(2026, 2, 2, 23, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)
        d3_ms = int(dt.datetime(2026, 2, 3, 23, 0, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)
        multi_win = [
            ["allTime", {"accountValueHistory": [[d1_ms, "10000.0"], [d2_ms, "10500.0"], [d3_ms, "11200.0"]]}],
            [
                "day",
                {
                    "accountValueHistory": [
                        [d3_ms - (12 - h) * 3600_000, str(11000.0 + h * 20.0)] for h in range(1, 13)
                    ]
                },
            ],
        ]
        out_hl = verify_portfolio(
            ledger=adapter.parse_payload(
                {"portfolio": multi_win, "ledger_updates": [], "fills": []},
                wallet_address=VALID_WALLET_MIXED,
                blinding_salt_hex=TEST_SALT_HEX,
            ),
            blinding_salt_hex=TEST_SALT_HEX,
            issued_at_utc="2026-03-01T00:00:00Z",
        )
        self.assertEqual(out_hl.performance.methodology, "daily_flow_adjusted_twr_v3_modified_dietz")
        curve_dates = [pt.timestamp_utc[:10] for pt in out_hl.performance.indexed_curve[1:]]
        self.assertEqual(len(curve_dates), len(set(curve_dates)))

        # 3. `userFills` hitting 2,000-fill cap paginates `userFillsByTime` + parses `Short > Long` / `Liquidated` dirs
        fill_queries: list[str] = []

        def paged_fills_transport(
            method: str,
            url: str,
            headers: dict[str, str],
            body: bytes,
        ) -> tuple[int, dict[str, str], Any]:
            req = json.loads(body.decode("utf-8"))
            q_type = req["type"]
            fill_queries.append(q_type)
            if q_type == "portfolio":
                return (
                    200,
                    {"Content-Type": "application/json"},
                    [["allTime", {"accountValueHistory": [[d1_ms, "10000.0"], [d2_ms, "11000.0"], [d3_ms, "12000.0"]]}]],
                )
            if q_type == "userNonFundingLedgerUpdates":
                return (200, {"Content-Type": "application/json"}, [])
            if q_type == "userFills":
                recent_2000 = [
                    {
                        "coin": "BTC",
                        "px": "95000.0",
                        "sz": "0.01",
                        "side": "",
                        "dir": "Short > Long" if i % 2 == 0 else "Liquidated Isolated Long",
                        "time": d2_ms + i * 1000,
                        "fee": "0.10",
                        "tid": 1000 + i,
                    }
                    for i in range(HYPERLIQUID_FILLS_PAGE_SIZE)
                ]
                return (200, {"Content-Type": "application/json"}, recent_2000)
            if q_type == "userFillsByTime":
                start_t = req["startTime"]
                if start_t <= d1_ms:
                    page1 = [
                        {
                            "coin": "ETH",
                            "px": "3000.0",
                            "sz": "1.0",
                            "side": "B",
                            "time": d1_ms + 500,
                            "fee": "0.50",
                            "tid": 1,
                        }
                    ] + [
                        {
                            "coin": "BTC",
                            "px": "95000.0",
                            "sz": "0.01",
                            "side": "B",
                            "time": d2_ms + i * 1000,
                            "fee": "0.10",
                            "tid": 1000 + i,
                        }
                        for i in range(HYPERLIQUID_FILLS_PAGE_SIZE - 1)
                    ]
                    return (200, {"Content-Type": "application/json"}, page1)
                return (
                    200,
                    {"Content-Type": "application/json"},
                    [
                        {
                            "coin": "BTC",
                            "px": "95000.0",
                            "sz": "0.01",
                            "side": "A",
                            "time": d2_ms + (HYPERLIQUID_FILLS_PAGE_SIZE - 1) * 1000,
                            "fee": "0.10",
                            "tid": 1000 + HYPERLIQUID_FILLS_PAGE_SIZE - 1,
                        }
                    ],
                )
            raise AssertionError(f"Unexpected query {q_type}")

        paged_adapter = HyperliquidPublicReadOnlyAdapter(
            wallet_address=VALID_WALLET_MIXED,
            http_transport=paged_fills_transport,
        )
        paged_ledger = paged_adapter.fetch_canonical_ledger(blinding_salt_hex=TEST_SALT_HEX)
        self.assertIn("userFillsByTime", fill_queries)
        self.assertEqual(len(paged_ledger.trades), HYPERLIQUID_FILLS_PAGE_SIZE + 1)
        self.assertTrue(any(t.native_entry_id == "hl-tid-1" for t in paged_ledger.trades))


if __name__ == "__main__":
    unittest.main()
