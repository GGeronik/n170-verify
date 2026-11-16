"""Comprehensive test suite for Phase 3 read-only connectors, MCP firewall, and SnapTrade POC relay."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any
import unittest
import urllib.parse

from n170_verify.connectors import (
    ALPACA_BLOCKED_MUTATING_TOOLS,
    ALPACA_LIVE_BASE_URL,
    CONNECTOR_CLASS_MAP,
    CTRADER_BLOCKED_MUTATING_MESSAGE_TYPES,
    DEFAULT_SNAPTRADE_USER_AGENT,
    MAX_SNAPTRADE_POC_SLOTS,
    REJECTED_MCP_SERVERS,
    SNAPTRADE_BLOCKED_MUTATING_ENDPOINTS,
    SNAPTRADE_LIVE_BASE_URL,
    TRADING212_BLOCKED_MUTATING_TOOLS,
    AlpacaReadOnlyAdapter,
    CcxtExchangeReadOnlyAdapter,
    CTraderReadOnlyOAuthAdapter,
    DegiroOfflineCsvAdapter,
    DisallowedCapabilityError,
    DisallowedMcpServerError,
    IbkrFlexOfflineAdapter,
    IbkrFlexWebServiceAdapter,
    IbkrOAuthReadOnlyAdapter,
    JournalMigrationOfflineAdapter,
    KrakenDecayRateLimiter,
    McpAllowlistFirewall,
    Mt4OfflineStatementAdapter,
    Mt5OfflineStatementAdapter,
    MutatingCredentialRejectedError,
    PaperOrSandboxAccountRejectedError,
    ProviderApprovalRequiredError,
    RobinhoodOfflineCsvAdapter,
    SchwabOfflineCsvAdapter,
    SchwabReadOnlyAdapter,
    SnapTradeAuthenticationError,
    SnapTradeConnectionSlot,
    SnapTradeError,
    SnapTradeReadOnlyAdapter,
    SnapTradeServiceError,
    SnapTradeSlotCapExceededError,
    SnapTradeSlotManager,
    TradierReadOnlyAdapter,
    Trading212ReadOnlyAdapter,
    TradovateOfflineCsvAdapter,
    UnsupportedScraperPolicyError,
    WriteCapableCredentialsRejectedError,
    build_signed_request,
    build_trading212_basic_auth_header,
    compute_snaptrade_signature,
    create_connector,
    deduplicate_coinbase_fills_by_entry_id,
    detect_and_parse_statement,
    get_connector_descriptor,
    is_snaptrade_env_configured,
    list_all_connector_descriptors,
    list_connector_descriptors,
    parse_degiro_csv_bundle,
    parse_ibkr_flex_xml,
    parse_journal_migration_csv,
    parse_robinhood_csv,
    parse_schwab_csv,
    redact_sensitive_text,
    redact_tradier_account_path,
)
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    BrokerAdapterDescriptor,
    CanonicalPortfolioLedger,
    EnvironmentTier,
    FlowKind,
    OriginAssurance,
    ProviderApprovalState,
    validate_read_only_capabilities,
)

TEST_SALT_HEX = "99" * 32


@dataclass
class _MockResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes

    @property
    def content(self) -> bytes:
        return self.body

    @property
    def text(self) -> str:
        return self.body.decode("utf-8")


class _MockHttpTransport:
    """Mock HTTP transport tracking requests without network calls."""

    def __init__(self, responder: Any) -> None:
        self.responder = responder
        self.recorded_calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def __call__(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        extra_secrets: Any = None,
    ) -> _MockResponse:
        hdrs = dict(headers or {})
        self.recorded_calls.append((method, url, hdrs, body))
        status, resp_headers, payload = self.responder(method, url, hdrs, body)
        raw_body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        return _MockResponse(status_code=status, headers=resp_headers, body=raw_body)


class TestConnectorDescriptorsAndGovernance(unittest.TestCase):
    """Test connector descriptors serialization and governance routing."""

    def test_all_connector_descriptors_serialize_and_validate(self) -> None:
        canonical_descriptors = list_all_connector_descriptors(env={})
        self.assertEqual(len(canonical_descriptors), 19)
        for desc in canonical_descriptors:
            self.assertIsInstance(desc, BrokerAdapterDescriptor)
            self.assertTrue(len(desc.broker_id) > 0)
            self.assertTrue(len(desc.display_name) > 0)
            self.assertIsInstance(desc.approval_state, ProviderApprovalState)
            self.assertIsInstance(desc.default_origin_assurance, OriginAssurance)
            self.assertIsInstance(desc.supports_subaccount_enumeration, bool)
            validate_read_only_capabilities(desc.allowed_capabilities)

            dumped = desc.to_dict()
            self.assertEqual(dumped["broker_id"], desc.broker_id)
            self.assertEqual(dumped["approval_state"], desc.approval_state.value)
            roundtrip = json.loads(json.dumps(dumped))
            self.assertEqual(roundtrip["broker_id"], desc.broker_id)

    def test_list_all_with_poc_includes_snaptrade(self) -> None:
        poc_descriptors = list_all_connector_descriptors(env={}, include_poc=True)
        self.assertEqual(len(poc_descriptors), 20)
        snap_desc = next(d for d in poc_descriptors if d.broker_id == "snaptrade")
        self.assertEqual(snap_desc.approval_state, ProviderApprovalState.AGGREGATOR_RELAYED)
        self.assertEqual(snap_desc.default_origin_assurance, OriginAssurance.OPERATOR_RETRIEVED)
        self.assertTrue(snap_desc.supports_subaccount_enumeration)
        validate_read_only_capabilities(snap_desc.allowed_capabilities)

    def test_get_connector_descriptor_lookups_and_aliases(self) -> None:
        for bid in ("snaptrade", "snaptrade_relay", "snaptrade_poc"):
            desc = get_connector_descriptor(bid)
            self.assertEqual(desc.broker_id, "snaptrade")
            self.assertEqual(desc.approval_state, ProviderApprovalState.AGGREGATOR_RELAYED)

        desc_degiro = get_connector_descriptor("degiro")
        self.assertEqual(desc_degiro.broker_id, "degiro_csv")
        self.assertEqual(desc_degiro.approval_state, ProviderApprovalState.OFFLINE_EXPORT_ONLY)

        desc_mt5 = get_connector_descriptor("mt5")
        self.assertEqual(desc_mt5.broker_id, "mt5_statement")

        with self.assertRaises(KeyError):
            get_connector_descriptor("unknown_nonexistent_broker")

    def test_connector_class_map_instantiation(self) -> None:
        for broker_key in sorted(CONNECTOR_CLASS_MAP.keys()):
            desc = get_connector_descriptor(broker_key)
            self.assertIsNotNone(desc)
            validate_read_only_capabilities(desc.allowed_capabilities)


class TestDirectBrokerConnectors(unittest.TestCase):
    """Test direct broker adapters: IBKR Flex, Alpaca, cTrader, Tradier, Schwab, Trading212, CCXT, MT5/Tradovate."""

    def test_alpaca_live_vs_paper_rejection_and_public_api(self) -> None:
        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            AlpacaReadOnlyAdapter(
                api_key_id="PKTEST",
                api_secret_key="SKTEST",
                base_url="https://paper-api.alpaca.markets",
                require_live=True,
            )

        def mock_handler(_m: str, url: str, _h: Any, _b: Any) -> tuple[int, dict[str, str], Any]:
            if "/account" in url:
                return (200, {}, {"account_number": "PA987654321", "currency": "USD"})
            return (200, {}, [])

        class _MockAlpacaHttpxClient:
            def request(self, method: str, url: str, *, headers: dict[str, str] | None = None, content: bytes | None = None):
                status, resp_headers, payload = mock_handler(method, url, headers or {}, content)
                raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
                return _MockResponse(status_code=status, headers=resp_headers, body=raw)

        adapter = AlpacaReadOnlyAdapter(
            api_key_id="AKLIVE",
            api_secret_key="SKLIVE",
            base_url=ALPACA_LIVE_BASE_URL,
            require_live=True,
            http_transport=_MockAlpacaHttpxClient(),
        )
        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            adapter.fetch_canonical_ledger(
                blinding_salt_hex=TEST_SALT_HEX,
                period_start_utc="2026-01-01T00:00:00Z",
                period_end_utc="2026-01-31T00:00:00Z",
            )

    def test_ctrader_scope_accounts_and_blocked_mutating_messages(self) -> None:
        from n170_verify.connectors.ctrader_oauth import validate_ctrader_message_type
        adapter = CTraderReadOnlyOAuthAdapter(access_token="CT_TOK")
        self.assertEqual(adapter.approval_state, ProviderApprovalState.USER_KEY_SELF_ATTESTED)
        for blocked_type in CTRADER_BLOCKED_MUTATING_MESSAGE_TYPES:
            with self.assertRaises(DisallowedCapabilityError):
                validate_ctrader_message_type(blocked_type)

    def test_tradier_path_redaction_and_permissionless_approval_state(self) -> None:
        self.assertEqual(
            redact_tradier_account_path("/v1/accounts/6YA12345/balances"),
            "/v1/accounts/[REDACTED]/balances",
        )
        tr = TradierReadOnlyAdapter(
            access_token="TOK123",
            approval_state=ProviderApprovalState.PUBLIC_API_PERMISSIONLESS,
        )
        self.assertEqual(tr.approval_state, ProviderApprovalState.PUBLIC_API_PERMISSIONLESS)

    def test_schwab_pending_approval_gate(self) -> None:
        adapter = SchwabReadOnlyAdapter()
        self.assertEqual(adapter.approval_state, ProviderApprovalState.PENDING_PROVIDER_APPROVAL)
        with self.assertRaises(ProviderApprovalRequiredError):
            adapter.fetch_canonical_ledger(
                blinding_salt_hex=TEST_SALT_HEX,
                period_start_utc="2026-01-01T00:00:00Z",
                period_end_utc="2026-01-31T00:00:00Z",
            )

    def test_trading212_basic_auth_and_permissionless_state(self) -> None:
        hdr = build_trading212_basic_auth_header("my_key", "my_secret")
        self.assertTrue(hdr.startswith("Basic "))
        t212 = Trading212ReadOnlyAdapter(
            api_key="k",
            api_secret="s",
            approval_state=ProviderApprovalState.PUBLIC_API_PERMISSIONLESS,
        )
        self.assertEqual(t212.approval_state, ProviderApprovalState.PUBLIC_API_PERMISSIONLESS)

    def test_ccxt_crypto_key_introspection_and_permissionless_state(self) -> None:
        ccxt_adapter = CcxtExchangeReadOnlyAdapter(
            "binance",
            approval_state=ProviderApprovalState.PUBLIC_API_PERMISSIONLESS,
        )
        self.assertEqual(ccxt_adapter.approval_state, ProviderApprovalState.PUBLIC_API_PERMISSIONLESS)
        desc = ccxt_adapter.describe_adapter()
        self.assertEqual(desc.approval_state, ProviderApprovalState.PUBLIC_API_PERMISSIONLESS)

        fills = [
            {"entry_id": "fill_1", "order_id": "ord_1", "amount": 1.0},
            {"entry_id": "fill_1", "order_id": "ord_1", "amount": 1.0},
            {"entry_id": "fill_2", "order_id": "ord_2", "amount": 2.0},
        ]
        deduped = deduplicate_coinbase_fills_by_entry_id(fills)
        self.assertEqual(len(deduped), 2)


class TestOfflineStatementImportUnverifiedOffline(unittest.TestCase):
    """Test that all offline statement imports default to EnvironmentTier.UNVERIFIED_OFFLINE."""

    def test_degiro_csv_unverified_offline(self) -> None:
        tx_csv = (
            "Date,Time,Product,ISIN,Reference exchange,Venue,Quantity,Price,,Local value,,Value,,Exchange rate,Transaction and/or third,Total,,Order ID\n"
            "05-01-2026,15:35,APPLE INC,US0378331005,NDQ,XNAS,10,200.00,USD,-2000.00,USD,-1818.18,EUR,1.1000,-1.00,EUR,-1819.18,EUR,ORD-1\n"
        )
        acct_csv = (
            "Date,Time,Value date,Product,ISIN,Description,FX,Change,,Balance,,Order ID\n"
            "02-01-2026,09:00,02-01-2026,,,Deposit,,EUR,5000.00,EUR,5000.00,\n"
        )
        port_csv = (
            "Product,Symbol/ISIN,Amount,Closing,Local value,Value in EUR\n"
            "APPLE INC,US0378331005,10,210.00,USD 2100.00,1909.09\n"
        )
        adapter = DegiroOfflineCsvAdapter()
        ledger = adapter.parse_export(
            transactions_csv=tx_csv,
            account_csv=acct_csv,
            portfolio_csv=port_csv,
            blinding_salt_hex=TEST_SALT_HEX,
        )
        self.assertEqual(ledger.environment_tier, EnvironmentTier.UNVERIFIED_OFFLINE)
        self.assertEqual(ledger.provider_approval_state, ProviderApprovalState.OFFLINE_EXPORT_ONLY)
        self.assertEqual(ledger.claimed_origin_assurance, OriginAssurance.SELF_REPORTED)

    def test_robinhood_csv_unverified_offline(self) -> None:
        rh_csv = (
            "Activity Date,Process Date,Settle Date,Instrument,Description,Trans Code,Quantity,Price,Amount\n"
            "01/03/2026,01/03/2026,01/03/2026,,ACH Deposit,ACH,,,$5000.00\n"
            "01/06/2026,01/06/2026,01/07/2026,AAPL,Apple Inc,Buy,10,$210.50,($2105.00)\n"
        )
        adapter = RobinhoodOfflineCsvAdapter()
        ledger = adapter.parse_export(rh_csv, blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(ledger.environment_tier, EnvironmentTier.UNVERIFIED_OFFLINE)
        self.assertEqual(ledger.provider_approval_state, ProviderApprovalState.OFFLINE_EXPORT_ONLY)

    def test_schwab_csv_unverified_offline(self) -> None:
        sc_csv = (
            '"Transactions for account Individual ...999 as of 01/31/2026"\n'
            '"Date","Action","Symbol","Description","Quantity","Price","Fees & Comm","Amount"\n'
            '"01/04/2026","MoneyLink Deposit","","Electronic Deposit","","","","$10,000.00"\n'
            '"01/18/2026","Buy","VTI","VANGUARD TOTAL STOCK MKT","20","$290.00","$0.00","-$5,800.00"\n'
        )
        adapter = SchwabOfflineCsvAdapter()
        ledger = adapter.parse_export(sc_csv, blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(ledger.environment_tier, EnvironmentTier.UNVERIFIED_OFFLINE)

    def test_journal_migration_csv_unverified_offline(self) -> None:
        ts_csv = (
            "Status,Symbol,Size,Open Date,Open Time,Close Date,Close Time,Entry Price,Exit Price,Return $,Side,Setups,Mistakes,Commission,Notes,Asset Type\n"
            "WIN,NVDA,100,2026-01-06,09:35:00,2026-01-06,10:45:00,138.00,142.50,448.00,LONG,\"Setup A\",,2.00,\"Note A\",STOCK\n"
        )
        adapter = JournalMigrationOfflineAdapter()
        ledger = adapter.parse_export(ts_csv, blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(ledger.environment_tier, EnvironmentTier.UNVERIFIED_OFFLINE)

    def test_ibkr_flex_offline_unverified_offline(self) -> None:
        sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
<FlexQueryResponse queryName="Test" type="AF">
  <FlexStatements count="1">
    <FlexStatement accountId="U1234567" baseCurrency="USD" fromDate="2026-01-01" toDate="2026-01-31">
      <Trades>
        <Trade accountId="U1234567" symbol="SPY" dateTime="2026-01-15;143000" quantity="10" tradePrice="590.0" buySell="BUY" ibCommission="-1.0" currency="USD" assetCategory="STK" transactionID="TR123" />
      </Trades>
    </FlexStatement>
  </FlexStatements>
</FlexQueryResponse>
"""
        adapter = IbkrFlexOfflineAdapter()
        ledger = adapter.parse_export(sample_xml, blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(ledger.environment_tier, EnvironmentTier.UNVERIFIED_OFFLINE)
        self.assertEqual(ledger.provider_approval_state, ProviderApprovalState.OFFLINE_EXPORT_ONLY)


class TestSnapTradeAggregatorRelay(unittest.TestCase):
    """Test the SnapTrade POC aggregator relay with 5-slot ceiling and read-only policy."""

    def test_snaptrade_slot_manager_5_slot_ceiling(self) -> None:
        mgr = SnapTradeSlotManager(max_slots=MAX_SNAPTRADE_POC_SLOTS)
        self.assertEqual(mgr.max_slots, 5)

        # Register 5 distinct slots
        slots: list[SnapTradeConnectionSlot] = []
        for i in range(1, 6):
            s = mgr.register_slot(f"user_{i}")
            self.assertEqual(s.slot_id, i)
            self.assertTrue(s.active)
            slots.append(s)

        self.assertEqual(mgr.active_slot_count(), 5)

        # Attempting to allocate slot 6 raises SnapTradeSlotCapExceededError
        with self.assertRaises(SnapTradeSlotCapExceededError) as ctx:
            mgr.register_slot("user_6_overflow")
        self.assertIn("strictly capped at 5 connection slots", str(ctx.exception))

        # Re-registering existing user returns active slot without incrementing usage
        same_user = mgr.register_slot("user_1")
        self.assertEqual(same_user.slot_id, 1)

        # Release user_2 -> allows user_6 to register into freed slot
        self.assertTrue(mgr.release_slot("user_2"))
        self.assertEqual(mgr.active_slot_count(), 4)

        reclaimed = mgr.register_slot("user_6")
        self.assertEqual(reclaimed.slot_id, 2)
        self.assertEqual(mgr.active_slot_count(), 5)

    def test_snaptrade_read_only_adapter_descriptor(self) -> None:
        adapter = SnapTradeReadOnlyAdapter()
        desc = adapter.describe_adapter()
        self.assertEqual(desc.broker_id, "snaptrade")
        self.assertEqual(desc.approval_state, ProviderApprovalState.AGGREGATOR_RELAYED)
        self.assertEqual(desc.default_origin_assurance, OriginAssurance.OPERATOR_RETRIEVED)
        self.assertTrue(desc.supports_subaccount_enumeration)
        validate_read_only_capabilities(desc.allowed_capabilities)

    def test_snaptrade_mutating_actions_blocked(self) -> None:
        adapter = SnapTradeReadOnlyAdapter()
        for forbidden in ("place_order", "trade", "withdraw", "transfer_funds", "cancel_order"):
            with self.assertRaises(DisallowedCapabilityError):
                adapter.assert_action_permitted(forbidden)

    def test_snaptrade_scraper_credentials_rejected(self) -> None:
        with self.assertRaises(UnsupportedScraperPolicyError):
            SnapTradeReadOnlyAdapter(username="scrape_user", password="scrape_password")

    def test_snaptrade_payload_normalization_and_paper_rejection(self) -> None:
        adapter = SnapTradeReadOnlyAdapter(client_id="CID", consumer_key="CKEY")

        # Live payload parsing
        live_payload = {
            "accounts": [
                {"id": "acct_01", "account_number": "1001", "currency": "USD", "type": "brokerage"}
            ],
            "positions": [
                {
                    "account_id": "acct_01",
                    "symbol": {"symbol": "AAPL", "currency": "USD"},
                    "units": 10.0,
                    "price": 220.0,
                    "cost_basis": 2000.0,
                    "as_of_date": "2026-01-20T16:00:00Z",
                }
            ],
            "activities": [
                {
                    "id": "act_1",
                    "account_id": "acct_01",
                    "type": "buy",
                    "symbol": "AAPL",
                    "units": 10.0,
                    "price": 200.0,
                    "fee": 1.0,
                    "trade_date": "2026-01-10T14:30:00Z",
                },
                {
                    "id": "act_2",
                    "account_id": "acct_01",
                    "type": "deposit",
                    "amount": 5000.0,
                    "trade_date": "2026-01-05T09:00:00Z",
                },
            ],
            "balances": [
                {"account_id": "acct_01", "total": 7200.0, "cash": 5000.0, "updated_at": "2026-01-20T16:00:00Z"}
            ],
        }

        ledger = adapter.parse_payload(live_payload, blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(ledger.broker_id, "snaptrade")
        self.assertEqual(ledger.provider_approval_state, ProviderApprovalState.AGGREGATOR_RELAYED)
        self.assertEqual(ledger.environment_tier, EnvironmentTier.LIVE_PRODUCTION)
        self.assertEqual(ledger.account_scope, AccountScope.ALL_ENUMERATED_SUBACCOUNTS)
        self.assertEqual(len(ledger.trades), 1)
        self.assertEqual(len(ledger.flows), 1)
        self.assertEqual(len(ledger.ending_positions), 1)

        # Paper account rejection
        paper_payload = {
            "accounts": [
                {"id": "paper_01", "account_number": "SIM1001", "currency": "USD", "type": "paper_trading", "is_paper": True}
            ],
            "activities": [],
            "positions": [],
        }
        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            adapter.parse_payload(paper_payload, blinding_salt_hex=TEST_SALT_HEX, require_live=True)

    def test_snaptrade_v1_hmac_signature_and_no_secret_in_headers(self) -> None:
        import base64
        import hashlib
        import hmac

        consumer_key = "st-live-consumer-secret-xyz"
        client_id = "N170-DEV-CLIENT"
        user_id = "n170-founder-1"
        user_secret = "usr-secret-very-sensitive-999"

        req = build_signed_request(
            "POST",
            "/api/v1/snapTrade/login",
            client_id=client_id,
            consumer_key=consumer_key,
            user_id=user_id,
            user_secret=user_secret,
            json_body={"connectionType": "read", "immediateRedirect": True},
            timestamp="1760000000",
        )

        expected_query = (
            f"clientId={urllib.parse.quote(client_id)}"
            "&timestamp=1760000000"
            f"&userId={urllib.parse.quote(user_id)}"
            f"&userSecret={urllib.parse.quote(user_secret)}"
        )
        self.assertEqual(req.query_string, expected_query)

        expected_sig_obj = {
            "content": {"connectionType": "read", "immediateRedirect": True},
            "path": "/api/v1/snapTrade/login",
            "query": expected_query,
        }
        canonical = json.dumps(expected_sig_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        expected_sig = base64.b64encode(
            hmac.new(consumer_key.encode("utf-8"), canonical, hashlib.sha256).digest()
        ).decode("ascii")

        self.assertEqual(req.signature, expected_sig)
        self.assertEqual(req.headers.get("Signature"), expected_sig)
        self.assertEqual(
            compute_snaptrade_signature(
                consumer_key,
                api_path="/api/v1/snapTrade/login",
                query_string=f"?{expected_query}",
                content={"immediateRedirect": True, "connectionType": "read"},
            ),
            expected_sig,
        )

        # Strictly ensure consumerKey and userSecret NEVER appear in HTTP headers
        lower_hdr_keys = {k.lower() for k in req.headers}
        self.assertNotIn("consumerkey", lower_hdr_keys)
        self.assertNotIn("usersecret", lower_hdr_keys)
        for hdr_val in req.headers.values():
            self.assertNotIn(consumer_key, hdr_val)
            self.assertNotIn(user_secret, hdr_val)

        adapter = SnapTradeReadOnlyAdapter(client_id=client_id, consumer_key=consumer_key)
        base_hdrs = adapter.build_auth_headers()
        self.assertNotIn("consumerKey", base_hdrs)
        self.assertNotIn("userSecret", base_hdrs)

        # GET request signs content=None
        get_req = build_signed_request(
            "GET",
            "/api/v1/accounts",
            client_id=client_id,
            consumer_key=consumer_key,
            user_id=user_id,
            user_secret=user_secret,
            timestamp=1760000005,
        )
        self.assertIsNone(get_req.body)
        get_canonical = json.dumps(
            {
                "content": None,
                "path": "/api/v1/accounts",
                "query": get_req.query_string,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.assertEqual(
            get_req.headers["Signature"],
            base64.b64encode(
                hmac.new(consumer_key.encode("utf-8"), get_canonical, hashlib.sha256).digest()
            ).decode("ascii"),
        )

    def test_snaptrade_env_configured_helper(self) -> None:
        self.assertFalse(is_snaptrade_env_configured({}))
        self.assertFalse(
            is_snaptrade_env_configured(
                {
                    "SNAPTRADE_CLIENT_ID": "snaptrade-poc-client",
                    "SNAPTRADE_CONSUMER_KEY": "snaptrade-poc-key",
                }
            )
        )
        self.assertFalse(
            is_snaptrade_env_configured(
                {
                    "SNAPTRADE_CLIENT_ID": "YOUR_CLIENT_ID",
                    "SNAPTRADE_CONSUMER_KEY": "real-secret-key",
                }
            )
        )
        self.assertTrue(
            is_snaptrade_env_configured(
                {
                    "SNAPTRADE_CLIENT_ID": "N170-PROD-DEV-ID",
                    "SNAPTRADE_CONSUMER_KEY": "real-hmac-consumer-key-99",
                }
            )
        )

    def test_snaptrade_v1_register_portal_live_ledger_and_delete_lifecycle(self) -> None:
        slot_mgr = SnapTradeSlotManager(max_slots=5)
        consumer_secret = "hmac-consumer-secret-alpha-77"
        issued_user_secret = "issued-snap-user-secret-beta-88"

        def responder(
            method: str,
            url: str,
            headers: dict[str, str],
            body: bytes | None,
        ) -> tuple[int, dict[str, str], Any]:
            # Every outbound request must carry Signature and zero consumerKey/userSecret headers
            self.assertIn("Signature", headers)
            self.assertNotIn("consumerKey", headers)
            self.assertNotIn("userSecret", headers)
            for hv in headers.values():
                self.assertNotIn(consumer_secret, hv)
                self.assertNotIn(issued_user_secret, hv)

            parsed_u = urllib.parse.urlsplit(url)
            qs = urllib.parse.parse_qs(parsed_u.query)
            self.assertEqual(qs["clientId"], ["N170-CID"])
            self.assertIn("timestamp", qs)

            if method == "POST" and parsed_u.path == "/api/v1/snapTrade/registerUser":
                req_json = json.loads((body or b"{}").decode("utf-8"))
                return (
                    200,
                    {"Content-Type": "application/json"},
                    {"userId": req_json["userId"], "userSecret": issued_user_secret},
                )

            if method == "POST" and parsed_u.path == "/api/v1/snapTrade/login":
                self.assertEqual(qs["userSecret"], [issued_user_secret])
                login_json = json.loads((body or b"{}").decode("utf-8"))
                self.assertEqual(login_json["connectionType"], "read")
                self.assertTrue(login_json["immediateRedirect"])
                return (
                    200,
                    {"Content-Type": "application/json"},
                    {
                        "redirectURI": "https://app.snaptrade.com/snapTrade/redeemToken?token=tok123",
                        "sessionId": "sess-read-001",
                    },
                )

            if method == "GET" and parsed_u.path == "/api/v1/accounts":
                return (
                    200,
                    {"Content-Type": "application/json"},
                    [
                        {
                            "id": "st-acct-uuid-1",
                            "number": "RH-99887766",
                            "name": "Individual Cash",
                            "institution_name": "Robinhood",
                            "balance": {"total": {"amount": 11200.0, "currency": "USD"}},
                            "meta": {"type": "Cash"},
                        }
                    ],
                )

            if method == "GET" and parsed_u.path == "/api/v1/holdings":
                return (
                    200,
                    {"Content-Type": "application/json"},
                    [
                        {
                            "account": {
                                "id": "st-acct-uuid-1",
                                "number": "RH-99887766",
                                "sync_status": {
                                    "holdings": {"last_successful_sync": "2026-01-31T21:00:00Z"}
                                },
                            },
                            "balances": [{"currency": {"code": "USD"}, "cash": 4600.0}],
                            "positions": [
                                {
                                    "symbol": {
                                        "symbol": {
                                            "symbol": "MSFT",
                                            "currency": {"code": "USD"},
                                            "type": {"code": "cs"},
                                        }
                                    },
                                    "units": 15.0,
                                    "price": 440.0,
                                    "average_purchase_price": 400.0,
                                }
                            ],
                            "total_value": {"value": 11200.0, "currency": "USD"},
                        }
                    ],
                )

            if method == "GET" and parsed_u.path == "/api/v1/activities":
                self.assertEqual(qs.get("startDate"), ["2026-01-01"])
                self.assertEqual(qs.get("endDate"), ["2026-01-31"])
                return (
                    200,
                    {"Content-Type": "application/json"},
                    [
                        {
                            "id": "act-dep-1",
                            "account": {"id": "st-acct-uuid-1"},
                            "type": "CONTRIBUTION",
                            "amount": 10000.0,
                            "currency": {"code": "USD"},
                            "trade_date": "2026-01-02T14:00:00Z",
                        },
                        {
                            "id": "act-buy-1",
                            "account": {"id": "st-acct-uuid-1"},
                            "type": "BUY",
                            "symbol": {"symbol": "MSFT", "currency": {"code": "USD"}},
                            "units": 15.0,
                            "price": 400.0,
                            "fee": 0.0,
                            "currency": {"code": "USD"},
                            "trade_date": "2026-01-05T15:30:00Z",
                        },
                        {
                            "id": "act-div-1",
                            "account": {"id": "st-acct-uuid-1"},
                            "type": "DIVIDEND",
                            "symbol": {"symbol": "MSFT", "currency": {"code": "USD"}},
                            "amount": 25.0,
                            "currency": {"code": "USD"},
                            "trade_date": "2026-01-20T12:00:00Z",
                        },
                    ],
                )

            if method == "DELETE" and parsed_u.path == "/api/v1/snapTrade/deleteUser":
                return (
                    200,
                    {"Content-Type": "application/json"},
                    {"status": "deleted", "userId": qs["userId"][0]},
                )

            return (404, {}, {"error": "unexpected_route"})

        transport = _MockHttpTransport(responder)
        adapter = SnapTradeReadOnlyAdapter(
            client_id="N170-CID",
            consumer_key=consumer_secret,
            slot_manager=slot_mgr,
            http_transport=transport,
            timestamp_provider=lambda: 1760000123,
        )

        reg = adapter.register_user("founder-user-1")
        self.assertEqual(reg["userId"], "founder-user-1")
        self.assertEqual(reg["userSecret"], issued_user_secret)
        self.assertEqual(slot_mgr.active_slot_count(), 1)

        # Trading scope on portal login must be rejected before any network request
        with self.assertRaises(DisallowedCapabilityError):
            adapter.generate_connection_portal_url(
                "founder-user-1",
                issued_user_secret,
                connection_type="trade",
            )

        portal = adapter.generate_connection_portal_url(
            "founder-user-1",
            issued_user_secret,
            broker="ROBINHOOD",
            custom_redirect="http://127.0.0.1:3000/connect?snaptrade=connected",
        )
        self.assertTrue(portal["redirectURI"].startswith("https://app.snaptrade.com/"))
        self.assertEqual(portal["sessionId"], "sess-read-001")

        ledger = adapter.fetch_live_ledger(
            "founder-user-1",
            issued_user_secret,
            blinding_salt_hex=TEST_SALT_HEX,
            start_date="2026-01-01",
            end_date="2026-01-31",
        )
        self.assertEqual(ledger.broker_id, "snaptrade")
        self.assertEqual(ledger.provider_approval_state, ProviderApprovalState.AGGREGATOR_RELAYED)
        self.assertEqual(ledger.environment_tier, EnvironmentTier.LIVE_PRODUCTION)
        self.assertEqual(ledger.account_scope, AccountScope.ALL_ENUMERATED_SUBACCOUNTS)
        self.assertEqual(len(ledger.trades), 1)
        self.assertEqual(ledger.trades[0].symbol, "MSFT")
        self.assertEqual(len(ledger.flows), 2)
        self.assertIn(FlowKind.DEPOSIT, {f.kind for f in ledger.flows})
        self.assertIn(FlowKind.DIVIDEND, {f.kind for f in ledger.flows})
        self.assertEqual(len(ledger.ending_positions), 1)
        self.assertEqual(len(ledger.nav_points), 1)
        self.assertNotIn("RH-99887766", json.dumps(ledger.to_dict()))

        deleted = adapter.delete_user_and_release_slot("founder-user-1")
        self.assertTrue(deleted["slot_released"])
        self.assertEqual(slot_mgr.active_slot_count(), 0)

        # Verify userSecret & consumerKey are redacted from upstream HTTP error details
        def error_responder(
            _m: str, _u: str, _h: dict[str, str], _b: bytes | None
        ) -> tuple[int, dict[str, str], Any]:
            return (
                401,
                {"Content-Type": "application/json"},
                {"detail": f"Invalid auth for secret {issued_user_secret} and key {consumer_secret}"},
            )

        err_adapter = SnapTradeReadOnlyAdapter(
            client_id="N170-CID",
            consumer_key=consumer_secret,
            slot_manager=SnapTradeSlotManager(max_slots=5),
            http_transport=_MockHttpTransport(error_responder),
        )
        with self.assertRaises(SnapTradeAuthenticationError) as err_ctx:
            err_adapter.fetch_live_ledger(
                "founder-user-err",
                issued_user_secret,
                blinding_salt_hex=TEST_SALT_HEX,
            )
        self.assertNotIn(issued_user_secret, str(err_ctx.exception))
        self.assertNotIn(consumer_secret, str(err_ctx.exception))


class TestMcpAllowlistFirewallAndRedactions(unittest.TestCase):
    """Test MCP firewall allowlist filtering and sensitive text redaction."""

    def test_mcp_profiles_block_all_mutating_tools(self) -> None:
        self.assertEqual(len(ALPACA_BLOCKED_MUTATING_TOOLS), 18)
        self.assertEqual(len(TRADING212_BLOCKED_MUTATING_TOOLS), 10)

        firewall = McpAllowlistFirewall("alpaca")
        for tool_name in ALPACA_BLOCKED_MUTATING_TOOLS:
            with self.assertRaises(Exception):
                firewall.validate_tool_call(tool_name, {})

        t212_firewall = McpAllowlistFirewall("trading212")
        for tool_name in TRADING212_BLOCKED_MUTATING_TOOLS:
            with self.assertRaises(Exception):
                t212_firewall.validate_tool_call(tool_name, {})

    def test_rejected_community_mcp_servers(self) -> None:
        for rejected_key in REJECTED_MCP_SERVERS:
            with self.assertRaises(DisallowedMcpServerError):
                create_connector(rejected_key)

    def test_redact_sensitive_text_masks_credentials(self) -> None:
        secrets = ["SECRET_TOKEN_XYZ", "SUPER_SECRET_KEY"]
        raw = "Query failed: authorization=Bearer SECRET_TOKEN_XYZ for key SUPER_SECRET_KEY"
        redacted = redact_sensitive_text(raw, extra_secrets=secrets)
        self.assertNotIn("SECRET_TOKEN_XYZ", redacted)
        self.assertNotIn("SUPER_SECRET_KEY", redacted)
        self.assertIn("[REDACTED]", redacted)


if __name__ == "__main__":
    unittest.main()
