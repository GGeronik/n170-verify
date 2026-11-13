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
    build_trading212_basic_auth_header,
    create_connector,
    deduplicate_coinbase_fills_by_entry_id,
    detect_and_parse_statement,
    get_connector_descriptor,
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
