"""Comprehensive unit tests for N170 Verify read-only connectors & MCP allowlist firewall."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
from pathlib import Path
import unittest
from typing import Any
import urllib.parse

from n170_verify.connectors import (
    ALPACA_BLOCKED_MUTATING_TOOLS,
    ALPACA_LIVE_BASE_URL,
    AlpacaReadOnlyAdapter,
    CcxtExchangeReadOnlyAdapter,
    ConnectorHttpError,
    DegiroOfflineCsvAdapter,
    DisallowedCapabilityError,
    DisallowedMcpServerError,
    HttpExchangeResponse,
    IBKR_FLEX_GET_STATEMENT_URL,
    IBKR_FLEX_SEND_REQUEST_URL,
    IbkrFlexOfflineAdapter,
    IbkrFlexServiceError,
    IbkrFlexWebServiceAdapter,
    IbkrFlexXmlSecurityError,
    IbkrOAuthReadOnlyAdapter,
    KrakenDecayRateLimiter,
    MCP_PROTOCOL_VERSION,
    McpAllowlistFirewall,
    McpArgumentValidationError,
    McpFirewallError,
    McpServerIdentityError,
    McpToolDisallowedError,
    MutatingCredentialRejectedError,
    PaperOrSandboxAccountRejectedError,
    ProviderApprovalRequiredError,
    RobinhoodOfflineCsvAdapter,
    SchwabOfflineCsvAdapter,
    SchwabReadOnlyAdapter,
    StdioMcpFirewallClient,
    StreamableHttpMcpFirewallClient,
    TRADING212_BLOCKED_MUTATING_TOOLS,
    TradierReadOnlyAdapter,
    Trading212ReadOnlyAdapter,
    UnsupportedScraperPolicyError,
    build_ibkr_oauth1a_authorization_header,
    build_trading212_basic_auth_header,
    create_connector,
    deduplicate_coinbase_fills_by_entry_id,
    get_connector_descriptor,
    harden_ccxt_exchange_instance,
    list_connector_descriptors,
    parse_degiro_csv_bundle,
    parse_ibkr_flex_xml,
    parse_robinhood_csv,
    parse_schwab_csv,
    redact_sensitive_text,
    redact_tradier_account_path,
    split_time_windows_under_90d,
)
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    CorporateActionType,
    EnvironmentTier,
    FlowKind,
    OriginAssurance,
    ProviderApprovalState,
    validate_read_only_capabilities,
)


TEST_SALT_HEX = "cd" * 32


def _build_comprehensive_flex_xml(*, account_id: str = "U7654321") -> str:
    """Build an in-memory multi-section IBKR Flex v3 XML document."""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<FlexQueryResponse queryName="N170 Full Verification Suite" type="AF">
  <FlexStatements count="1">
    <FlexStatement accountId="{account_id}" baseCurrency="USD" fromDate="2026-01-01" toDate="2026-01-31">
      <ConversionRates>
        <ConversionRate reportDate="2026-01-15" fromCurrency="EUR" toCurrency="USD" rate="1.10" />
      </ConversionRates>
      <EquitySummaryInBase>
        <EquitySummaryByReportDateInBase reportDate="2026-01-02" cash="20000.00" stock="80000.00" options="2500.00" dividendAccruals="125.00" interestAccruals="25.00" total="102650.00" />
        <EquitySummaryByReportDateInBase reportDate="2026-01-30" cash="25500.00" stock="92000.00" options="0.00" dividendAccruals="0.00" interestAccruals="0.00" total="117500.00" />
      </EquitySummaryInBase>
      <PriorPeriodPositions>
        <PriorPeriodPosition symbol="AAPL" isin="US0378331005" assetCategory="STK" position="400" costBasisMoney="68000.00" positionValue="80000.00" currency="USD" levelOfDetail="SUMMARY" />
      </PriorPeriodPositions>
      <OpenPositions>
        <OpenPosition symbol="ASML" isin="NL0010273215" assetCategory="STK" position="50" costBasisMoney="35000.00" positionValue="40000.00" currency="EUR" levelOfDetail="SUMMARY" />
        <OpenPosition symbol="AAPL  260220C00220000" underlyingSymbol="AAPL" assetCategory="OPT" putCall="C" strike="220" expiry="2026-02-20" multiplier="100" position="2" costBasisMoney="1200.00" positionValue="1800.00" currency="USD" levelOfDetail="SUMMARY" />
      </OpenPositions>
      <Trades>
        <Trade ibExecID="EXEC-STK-001" tradeID="TRD-001" symbol="ASML" isin="NL0010273215" assetCategory="STK" buySell="BUY" quantity="50" tradePrice="700.00" currency="EUR" ibCommission="-12.50" taxes="0" dateTime="2026-01-05;10:15:30" exchange="AEB" levelOfDetail="EXECUTION" />
        <Trade ibExecID="EXEC-OPT-002" tradeID="TRD-002" symbol="AAPL  260116C00200000" underlyingSymbol="AAPL" assetCategory="OPT" putCall="C" strike="200.0" expiry="2026-01-16" multiplier="100" buySell="BUY" quantity="3" tradePrice="4.50" currency="USD" ibCommission="-2.10" dateTime="2026-01-08;14:30:00" exchange="CBOE" levelOfDetail="EXECUTION" />
        <Trade tradeID="SUMMARY-IGNORED" symbol="ASML" assetCategory="STK" buySell="BUY" quantity="50" tradePrice="700.00" currency="EUR" dateTime="2026-01-05;10:15:30" levelOfDetail="ORDER" />
      </Trades>
      <CashTransactions>
        <CashTransaction type="Deposits/Withdrawals" description="Wire Deposit" amount="5000.00" currency="USD" dateTime="2026-01-06;09:00:00" levelOfDetail="DETAIL" />
        <CashTransaction type="Dividends" symbol="AAPL" isin="US0378331005" description="AAPL Cash Dividend" amount="100.00" currency="USD" dateTime="2026-01-12;08:00:00" levelOfDetail="DETAIL" />
        <CashTransaction type="Withholding Tax" symbol="AAPL" isin="US0378331005" description="US Foreign Tax Withholding" amount="-15.00" currency="USD" dateTime="2026-01-12;08:00:05" levelOfDetail="DETAIL" />
        <CashTransaction type="Broker Interest Paid" description="USD Margin Interest Paid" amount="-18.75" currency="USD" dateTime="2026-01-28;17:00:00" levelOfDetail="DETAIL" />
      </CashTransactions>
      <Transfers>
        <Transfer type="ACATS" direction="IN" symbol="MSFT" isin="US5949181045" quantity="25" positionAmount="10500.00" positionAmountInBase="10500.00" currency="USD" dateTime="2026-01-10;11:00:00" description="ACATS In-Kind Transfer" />
        <Transfer type="FOP" direction="OUT" symbol="NVDA" isin="US67066G1040" quantity="-10" positionAmount="1400.00" positionAmountInBase="1400.00" currency="USD" dateTime="2026-01-11;11:30:00" description="Free of Payment Outbound" />
        <Transfer type="DWAC" direction="IN" symbol="GOOGL" isin="US02079K3059" quantity="15" positionAmount="2700.00" positionAmountInBase="2700.00" currency="USD" dateTime="2026-01-13;12:00:00" description="DWAC Deposit" />
        <Transfer type="INTERNAL" direction="IN" cashTransfer="2500.00" currency="USD" dateTime="2026-01-14;13:00:00" description="Internal Subaccount Transfer" />
      </Transfers>
      <CorporateActions>
        <CorporateAction type="FS" symbol="NVDA" isin="US67066G1040" quantity="90" proceeds="0.00" currency="USD" dateTime="2026-01-18;20:00:00" description="NVDA SPLIT 10 FOR 1" levelOfDetail="DETAIL" />
        <CorporateAction type="TC" symbol="OLDCO" newSymbol="NEWCO" isin="US0000000001" newIsin="US0000000002" quantity="100" proceeds="42.50" currency="USD" dateTime="2026-01-19;20:00:00" description="OLDCO MERGER INTO NEWCO" levelOfDetail="DETAIL" />
      </CorporateActions>
      <OptionEAE>
        <OptionEAE transactionType="Exercise" symbol="AAPL  260116C00200000" underlyingSymbol="AAPL" strike="200.0" multiplier="100" quantity="-1" costBasisMoney="-450.00" currency="USD" date="2026-01-16" />
        <OptionEAE transactionType="Assignment" symbol="MSFT  260116P00400000" underlyingSymbol="MSFT" strike="400.0" multiplier="100" quantity="-1" costBasisMoney="320.00" currency="USD" date="2026-01-16" />
        <OptionEAE transactionType="Expiration" symbol="SPY   260116C00650000" underlyingSymbol="SPY" strike="650.0" multiplier="100" quantity="-2" costBasisMoney="0.00" currency="USD" date="2026-01-16" />
      </OptionEAE>
    </FlexStatement>
  </FlexStatements>
</FlexQueryResponse>
"""


@dataclass
class _MockHttpxResponse:
    status_code: int
    headers: dict[str, str]
    content: bytes


class _MockHttpxClient:
    """Mimics ``httpx.Client.request(...)`` without requiring ``httpx`` installed."""

    def __init__(self, handler: Any) -> None:
        self._handler = handler
        self.calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> _MockHttpxResponse:
        hdrs = dict(headers or {})
        self.calls.append((method, url, hdrs, content))
        status, resp_hdrs, payload = self._handler(method, url, hdrs, content)
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        return _MockHttpxResponse(status_code=status, headers=resp_hdrs, content=raw)


class TestConnectorRegistryAndGovernance(unittest.TestCase):
    def test_all_registered_descriptors_pass_read_only_validation(self) -> None:
        descriptors = list_connector_descriptors(env={})
        self.assertEqual(len(descriptors), 14)
        broker_ids = {d.broker_id for d in descriptors}
        self.assertEqual(
            broker_ids,
            {
                "ibkr_oauth",
                "ibkr_flex_web",
                "ibkr_flex_offline",
                "alpaca",
                "trading212",
                "tradier",
                "schwab",
                "schwab_csv",
                "degiro_csv",
                "robinhood_csv",
                "binance",
                "coinbase",
                "kraken",
                "bybit",
            },
        )
        for desc in descriptors:
            validate_read_only_capabilities(desc.allowed_capabilities)

        # Hosted approval gates default to PENDING_PROVIDER_APPROVAL when unconfigured
        self.assertEqual(
            get_connector_descriptor("ibkr_oauth", env={}).approval_state,
            ProviderApprovalState.PENDING_PROVIDER_APPROVAL,
        )
        self.assertEqual(
            get_connector_descriptor("schwab", env={}).approval_state,
            ProviderApprovalState.PENDING_PROVIDER_APPROVAL,
        )
        # Unlock when env approvals are configured
        self.assertEqual(
            get_connector_descriptor(
                "ibkr_oauth", env={"N170_IBKR_CONSUMER_KEY": "N170KEY"}
            ).approval_state,
            ProviderApprovalState.APPROVED_LIVE,
        )
        self.assertEqual(
            get_connector_descriptor(
                "schwab", env={"N170_SCHWAB_COMMERCIAL_APPROVED": "true"}
            ).approval_state,
            ProviderApprovalState.APPROVED_LIVE,
        )

    def test_registry_rejects_community_ccxt_mcp_servers(self) -> None:
        for rejected in (
            "pcriadoperez/ccxt-mcp",
            "lazy-dinosaur/ccxt-mcp",
            "doggybee/mcp-server-ccxt",
        ):
            with self.assertRaises(DisallowedMcpServerError):
                create_connector(rejected)


class TestMcpAllowlistFirewall(unittest.TestCase):
    def test_alpaca_profile_blocks_all_18_mutating_tools_and_allows_http_post_readonly(self) -> None:
        self.assertEqual(len(ALPACA_BLOCKED_MUTATING_TOOLS), 18)
        expected_18 = {
            "update_account_config",
            "place_stock_order",
            "place_crypto_order",
            "place_option_order",
            "exercise_options_position",
            "cancel_order_by_id",
            "cancel_all_orders",
            "close_position",
            "close_all_positions",
            "create_watchlist",
            "update_watchlist_by_id",
            "update_watchlist_by_name",
            "add_asset_to_watchlist_by_id",
            "add_asset_to_watchlist_by_name",
            "remove_asset_from_watchlist_by_id",
            "remove_asset_from_watchlist_by_name",
            "delete_watchlist_by_id",
            "delete_watchlist_by_name",
        }
        self.assertEqual(ALPACA_BLOCKED_MUTATING_TOOLS, expected_18)

        upstream_calls: list[tuple[str, dict[str, Any]]] = []

        def mock_streamable_http(
            method: str,
            url: str,
            body: bytes,
            headers: dict[str, str],
        ) -> tuple[int, dict[str, str], bytes]:
            self.assertEqual(method, "POST")
            self.assertEqual(headers.get("MCP-Protocol-Version"), MCP_PROTOCOL_VERSION)
            rpc = json.loads(body.decode("utf-8"))
            upstream_calls.append((rpc["method"], rpc))
            rpc_method = rpc["method"]
            if rpc_method == "initialize":
                return (
                    200,
                    {"content-type": "application/json", "mcp-session-id": "sess-alpaca-1"},
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": rpc["id"],
                            "result": {
                                "protocolVersion": MCP_PROTOCOL_VERSION,
                                "capabilities": {"tools": {}},
                                "serverInfo": {"name": "alpaca-mcp-server", "version": "1.0.0"},
                            },
                        }
                    ).encode("utf-8"),
                )
            if rpc_method == "notifications/initialized":
                return (202, {}, b"")
            if rpc_method == "tools/list":
                upstream_tools = [
                    {"name": "get_account_info", "inputSchema": {"type": "object"}},
                    {"name": "get_positions", "inputSchema": {"type": "object"}},
                    {"name": "get_portfolio_history", "inputSchema": {"type": "object"}},
                    {"name": "unlisted_experimental_tool", "inputSchema": {"type": "object"}},
                    *[
                        {"name": bad_tool, "inputSchema": {"type": "object"}}
                        for bad_tool in sorted(ALPACA_BLOCKED_MUTATING_TOOLS)
                    ],
                ]
                return (
                    200,
                    {"content-type": "application/json"},
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": rpc["id"],
                            "result": {"tools": upstream_tools},
                        }
                    ).encode("utf-8"),
                )
            if rpc_method == "tools/call":
                # Streamable HTTP SSE response format check
                sse_payload = "event: message\ndata: " + json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": rpc["id"],
                        "result": {"content": [{"type": "text", "text": '{"equity":"125000.00"}'}]},
                    }
                ) + "\n\n"
                return (200, {"content-type": "text/event-stream"}, sse_payload.encode("utf-8"))
            if rpc_method == "resources/read":
                return (
                    200,
                    {"content-type": "application/json"},
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": rpc["id"],
                            "result": {"contents": [{"uri": rpc["params"]["uri"], "text": "ok"}]},
                        }
                    ).encode("utf-8"),
                )
            raise AssertionError(f"Unexpected upstream method {rpc_method}")

        client = StreamableHttpMcpFirewallClient(
            server_id="alpacahq/alpaca-mcp-server",
            endpoint_url="https://mcp.internal.example/alpaca",
            auth_headers={"Authorization": "Bearer SUPER_SECRET_MCP_TOKEN"},
            http_transport=mock_streamable_http,
        )
        # Environment sanitization ignores ALPACA_TOOLSETS and blocks ALPACA_PAPER_TRADE=true
        sanitized_env = client.firewall.validate_and_sanitize_env(
            {"ALPACA_TOOLSETS": "orders,watchlists,account", "PATH": "/usr/bin"}
        )
        self.assertNotIn("ALPACA_TOOLSETS", sanitized_env)
        with self.assertRaises(McpFirewallError):
            client.firewall.validate_and_sanitize_env({"ALPACA_PAPER_TRADE": "true"})

        client.initialize()
        visible_tools = client.list_tools()
        visible_names = [t["name"] for t in visible_tools]
        self.assertEqual(visible_names, ["get_account_info", "get_positions", "get_portfolio_history"])
        for t in visible_tools:
            self.assertIs(t["inputSchema"]["additionalProperties"], False)
            self.assertIs(t["annotations"]["readOnlyHint"], True)

        # Legitimate HTTP POST tools/call and resources/read succeed
        call_res = client.call_tool(
            "get_portfolio_history",
            {"timeframe": "1D", "start": "2026-01-01", "end": "2026-01-31"},
        )
        self.assertIn("result", call_res)
        res_read = client.send_jsonrpc("resources/read", {"uri": "alpaca://account/summary"})
        self.assertIsNotNone(res_read)

        # Every single one of the 18 mutating tools is blocked client-side before hitting HTTP!
        count_before = len(upstream_calls)
        for mutating_tool in sorted(ALPACA_BLOCKED_MUTATING_TOOLS):
            with self.assertRaises(McpToolDisallowedError):
                client.call_tool(mutating_tool, {})
        self.assertEqual(len(upstream_calls), count_before)

        # Non-POST HTTP method is blocked on Streamable HTTP
        with self.assertRaises(McpFirewallError):
            client.send_jsonrpc("tools/list", {}, http_method="GET")

    def test_trading212_profile_blocks_all_10_mutating_tools_and_forbids_cache_dir(self) -> None:
        self.assertEqual(len(TRADING212_BLOCKED_MUTATING_TOOLS), 10)
        expected_10 = {
            "place_market_order",
            "place_limit_order",
            "place_stop_order",
            "place_stop_limit_order",
            "cancel_order",
            "create_pie",
            "update_pie",
            "delete_pie",
            "duplicate_pie",
            "request_csv_export",
        }
        self.assertEqual(TRADING212_BLOCKED_MUTATING_TOOLS, expected_10)

        # Persistent TRADING212_CACHE_DIR disk writes must be hard-blocked!
        fw = McpAllowlistFirewall.for_server("trading212-mcp-server")
        with self.assertRaises(McpFirewallError):
            fw.validate_and_sanitize_env({"TRADING212_CACHE_DIR": "/tmp/t212-cache"})
        clean_env = fw.validate_and_sanitize_env({"T212_KEY": "secret123"})
        self.assertEqual(clean_env["TRADING212_CACHE_ENABLED"], "false")

        def mock_stdio_line(line: str) -> str:
            req = json.loads(line)
            m = req["method"]
            if m == "initialize":
                return json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": req["id"],
                        "result": {
                            "protocolVersion": MCP_PROTOCOL_VERSION,
                            "serverInfo": {"name": "trading212-mcp-server", "version": "1.2.0"},
                        },
                    }
                )
            if m == "notifications/initialized":
                return ""
            if m == "tools/list":
                tools = [
                    {"name": "get_account_cash", "inputSchema": {"type": "object"}},
                    {"name": "get_historical_orders", "inputSchema": {"type": "object"}},
                    *[
                        {"name": bad, "inputSchema": {"type": "object"}}
                        for bad in sorted(TRADING212_BLOCKED_MUTATING_TOOLS)
                    ],
                ]
                return json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": {"tools": tools}})
            if m == "tools/call":
                return json.dumps(
                    {"jsonrpc": "2.0", "id": req["id"], "result": {"cash": 4200.0}}
                )
            raise AssertionError(f"Unexpected stdio method {m}")

        stdio_client = StdioMcpFirewallClient(
            server_id="trading212-mcp-server",
            env={"T212_API_KEY": "T212_SECRET_KEY_VAL"},
            line_exchange=mock_stdio_line,
        )
        stdio_client.initialize()
        tools = stdio_client.list_tools()
        self.assertEqual([t["name"] for t in tools], ["get_account_cash", "get_historical_orders"])
        ok = stdio_client.call_tool("get_historical_orders", {"limit": 25})
        self.assertEqual(ok["result"]["cash"], 4200.0)

        for bad_tool in sorted(TRADING212_BLOCKED_MUTATING_TOOLS):
            with self.assertRaises(McpToolDisallowedError):
                stdio_client.call_tool(bad_tool, {})

    def test_ccxt_server_rejection_schema_bounds_identity_pin_and_secret_redaction(self) -> None:
        for disallowed in (
            "pcriadoperez/ccxt-mcp",
            "lazy-dinosaur/ccxt-mcp",
            "doggybee/mcp-server-ccxt",
        ):
            with self.assertRaises(DisallowedMcpServerError):
                McpAllowlistFirewall.for_server(disallowed)

        fw = McpAllowlistFirewall.for_server(
            "alpacahq/alpaca-mcp-server",
            extra_secrets=("TOPSECRETTOKEN999",),
        )
        # Identity mismatch on initialize -> McpServerIdentityError
        with self.assertRaises(McpServerIdentityError):
            fw.inspect_incoming_response(
                "initialize",
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"serverInfo": {"name": "rogue-mcp-server", "version": "0.1"}},
                },
            )

        # Schema additionalProperties=false, limit bounds, date range bounds, credentials & paths
        bad_payloads: list[dict[str, Any]] = [
            {"name": "get_orders", "arguments": {"unexpected_flag": True}},
            {"name": "get_orders", "arguments": {"limit": 5000}},
            {"name": "get_orders", "arguments": {"after": "2026-02-01", "until": "2026-01-01"}},
            {"name": "get_orders", "arguments": {"after": "2000-01-01", "until": "2026-01-01"}},
            {"name": "get_orders", "arguments": {"apiKey": "leaked"}},
            {"name": "get_watchlist_by_name", "arguments": {"name": "/etc/passwd"}},
            {"name": "get_watchlist_by_name", "arguments": {"name": "/U" + "sers/alice/stmt.csv"}},
            {"name": "get_watchlist_by_name", "arguments": {"name": "-----BEGIN " + "PRIVATE KEY-----"}},
            {"name": "get_watchlist_by_name", "arguments": {"name": "Bearer SECRET_JWT_123456"}},
        ]
        for params in bad_payloads:
            with self.assertRaises(McpArgumentValidationError):
                fw.inspect_outgoing_request(
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": params}
                )

        # Redaction check across query tokens, headers, Tradier & IBKR account paths
        raw_err = (
            "Failed GET https://ndcdyn.interactivebrokers.com/GetStatement?t=FLEXTOK123&q=998877&v=3 "
            "and /v1/accounts/6YA99887/balances and /portfolio/U7766554/summary "
            "Authorization: Bearer TOPSECRETTOKEN999"
        )
        redacted = redact_sensitive_text(raw_err, ("FLEXTOK123", "TOPSECRETTOKEN999"))
        self.assertNotIn("FLEXTOK123", redacted)
        self.assertNotIn("998877", redacted)
        self.assertNotIn("6YA99887", redacted)
        self.assertNotIn("U7766554", redacted)
        self.assertNotIn("TOPSECRETTOKEN999", redacted)
        self.assertIn("/v1/accounts/[REDACTED]/balances", redacted)
        self.assertIn("/portfolio/[REDACTED]/summary", redacted)


class TestIbkrFlexConnector(unittest.TestCase):
    def test_flex_web_service_v3_ignores_gdcdyn_url_polls_1019_and_redacts_tokens(self) -> None:
        observed_requests: list[tuple[str, str, dict[str, str]]] = []
        poll_count = 0
        flex_xml_bytes = _build_comprehensive_flex_xml().encode("utf-8")

        def mock_flex_http(
            method: str,
            url: str,
            headers: dict[str, str],
            _body: bytes | None,
        ) -> tuple[int, dict[str, str], bytes]:
            nonlocal poll_count
            observed_requests.append((method, url, headers))
            if "SendRequest" in url:
                # Deliberately return deprecated gdcdyn <Url> that causes Error 1001 if followed!
                envelope = b"""<?xml version="1.0" encoding="UTF-8"?>
<FlexStatementResponse timestamp="07 November, 2026 10:00 AM EST">
  <Status>Success</Status>
  <ReferenceCode>REF555666777</ReferenceCode>
  <Url>https://gdcdyn.interactivebrokers.com/Universal/servlet/FlexStatementService.GetStatement</Url>
</FlexStatementResponse>"""
                return (200, {"content-type": "application/xml"}, envelope)

            poll_count += 1
            if poll_count == 1:
                busy = b"""<?xml version="1.0" encoding="UTF-8"?>
<FlexStatementResponse>
  <Status>Warn</Status>
  <ErrorCode>1019</ErrorCode>
  <ErrorMessage>Statement generation in progress. Please try again shortly.</ErrorMessage>
</FlexStatementResponse>"""
                return (200, {"content-type": "application/xml"}, busy)
            return (200, {"content-type": "application/xml"}, flex_xml_bytes)

        sleeps: list[float] = []
        adapter = IbkrFlexWebServiceAdapter(
            user_agent="N170VerifyTest/1.0",
            http_transport=mock_flex_http,
            sleep_fn=sleeps.append,
            poll_interval_seconds=1.5,
        )
        ledger = adapter.fetch_canonical_ledger(
            flex_token="SECRET_FLEX_TOKEN_ABC",
            query_id="QUERY_ID_443322",
            blinding_salt_hex=TEST_SALT_HEX,
        )

        self.assertEqual(len(observed_requests), 3)
        self.assertTrue(observed_requests[0][1].startswith(IBKR_FLEX_SEND_REQUEST_URL))
        self.assertIn("v=3", observed_requests[0][1])
        self.assertEqual(observed_requests[0][2]["User-Agent"], "N170VerifyTest/1.0")
        # Both GetStatement calls MUST hit hardcoded ndcdyn URL and NEVER gdcdyn!
        for idx in (1, 2):
            self.assertTrue(observed_requests[idx][1].startswith(IBKR_FLEX_GET_STATEMENT_URL))
            self.assertNotIn("gdcdyn.interactivebrokers.com", observed_requests[idx][1])
        self.assertEqual(sleeps, [1.5])
        self.assertEqual(ledger.claimed_origin_assurance, OriginAssurance.OPERATOR_RETRIEVED)

        # Default Python-urllib User-Agent is rejected
        with self.assertRaises(ValueError):
            IbkrFlexWebServiceAdapter(user_agent="Python-urllib/3.14")

        # Verify ?t= and ?q= token redaction when Flex returns an error containing echoed params
        def failing_flex_http(
            _method: str,
            url: str,
            _headers: dict[str, str],
            _body: bytes | None,
        ) -> tuple[int, dict[str, str], bytes]:
            escaped_url = url.replace("&", "&amp;")
            err_xml = (
                f"<FlexStatementResponse><Status>Fail</Status><ErrorCode>1012</ErrorCode>"
                f"<ErrorMessage>Token expired for {escaped_url}</ErrorMessage></FlexStatementResponse>"
            ).encode("utf-8")
            return (200, {"content-type": "application/xml"}, err_xml)

        err_adapter = IbkrFlexWebServiceAdapter(http_transport=failing_flex_http)
        with self.assertRaises(IbkrFlexServiceError) as ctx:
            err_adapter.fetch_statement_bytes(
                flex_token="ULTRA_SECRET_FLEX_999",
                query_id="PRIVATE_QUERY_888",
            )
        msg = str(ctx.exception)
        self.assertNotIn("ULTRA_SECRET_FLEX_999", msg)
        self.assertNotIn("PRIVATE_QUERY_888", msg)
        self.assertIn("[REDACTED]", msg)

    def test_xxe_and_dtd_rejected_in_utf8_and_utf16(self) -> None:
        xxe_doc = """<?xml version="1.0"?>
<!DOCTYPE FlexQueryResponse [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<FlexQueryResponse><FlexStatements><FlexStatement accountId="U1">&xxe;</FlexStatement></FlexStatements></FlexQueryResponse>
"""
        for encoded in (
            xxe_doc.encode("utf-8"),
            xxe_doc.encode("utf-16"),
            xxe_doc.encode("utf-16-le"),
            xxe_doc.encode("utf-16-be"),
        ):
            with self.assertRaises(IbkrFlexXmlSecurityError):
                parse_ibkr_flex_xml(encoded, blinding_salt_hex=TEST_SALT_HEX)

    def test_offline_flex_parses_all_sections_utf8_utf16_and_reviewed_fixtures(self) -> None:
        xml_str = _build_comprehensive_flex_xml(account_id="U7654321")
        utf8_ledger = parse_ibkr_flex_xml(xml_str.encode("utf-8"), blinding_salt_hex=TEST_SALT_HEX)

        utf16_xml = xml_str.replace('encoding="UTF-8"', 'encoding="UTF-16"').encode("utf-16")
        utf16_ledger = IbkrFlexOfflineAdapter().parse_export(
            utf16_xml, blinding_salt_hex=TEST_SALT_HEX
        )

        for ledger in (utf8_ledger, utf16_ledger):
            self.assertEqual(ledger.claimed_origin_assurance, OriginAssurance.SELF_REPORTED)
            self.assertEqual(ledger.account_scope, AccountScope.UNKNOWN_OFFLINE_SCOPE)
            self.assertEqual(ledger.conversion_rates["EUR/USD"], 1.10)
            self.assertEqual(len(ledger.nav_points), 2)
            self.assertAlmostEqual(ledger.nav_points[0].nav_base, 102650.0)
            self.assertEqual(len(ledger.prior_positions), 1)
            self.assertEqual(ledger.prior_positions[0].isin, "US0378331005")
            self.assertEqual(len(ledger.ending_positions), 2)
            # EUR position resolved via ConversionRates (1.10)
            asml_pos = next(p for p in ledger.ending_positions if p.symbol == "ASML")
            self.assertAlmostEqual(asml_pos.fx_rate_to_base, 1.10)
            # Trades: ORDER summary skipped, 2 EXECUTION rows retained (stock + option multiplier=100)
            self.assertEqual(len(ledger.trades), 2)
            opt_trade = next(t for t in ledger.trades if t.asset_class == AssetClass.OPTION)
            self.assertEqual(opt_trade.native_entry_id, "EXEC-OPT-002")
            self.assertEqual(opt_trade.multiplier, 100.0)
            self.assertEqual(opt_trade.option_right, "C")
            # CashTransactions (4) + Transfers (4: ACATS in, FOP out, DWAC in, INTERNAL)
            self.assertEqual(len(ledger.flows), 8)
            flow_kinds = [f.kind for f in ledger.flows]
            self.assertIn(FlowKind.TRANSFER_IN_KIND, flow_kinds)
            self.assertIn(FlowKind.TRANSFER_OUT_KIND, flow_kinds)
            self.assertIn(FlowKind.INTERNAL_SUBACCOUNT_TRANSFER, flow_kinds)
            self.assertIn(FlowKind.WITHHOLDING_TAX, flow_kinds)
            self.assertIn(FlowKind.MARGIN_INTEREST, flow_kinds)
            # CorporateActions (2: split 10:1 + merger) + OptionEAE (3: exercise, assignment, expiration)
            self.assertEqual(len(ledger.corporate_actions), 5)
            split_rec = next(
                c for c in ledger.corporate_actions if c.action_type == CorporateActionType.SPLIT
            )
            self.assertEqual(split_rec.ratio_numerator, 10.0)
            self.assertEqual(split_rec.ratio_denominator, 1.0)
            ca_types = {c.action_type for c in ledger.corporate_actions}
            self.assertTrue(
                {
                    CorporateActionType.SPLIT,
                    CorporateActionType.MERGER,
                    CorporateActionType.OPTION_EXERCISE,
                    CorporateActionType.OPTION_ASSIGNMENT,
                    CorporateActionType.OPTION_EXPIRATION,
                }.issubset(ca_types)
            )
            self.assertNotIn("U7654321", json.dumps(ledger.to_dict()))

        # Paper IBKR account DU... rejected in live mode
        paper_xml = _build_comprehensive_flex_xml(account_id="DU1234567").encode("utf-8")
        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            parse_ibkr_flex_xml(paper_xml, blinding_salt_hex=TEST_SALT_HEX, require_live=True)
        non_live_ledger = parse_ibkr_flex_xml(
            paper_xml, blinding_salt_hex=TEST_SALT_HEX, require_live=False
        )
        self.assertEqual(non_live_ledger.environment_tier, EnvironmentTier.PAPER_OR_SANDBOX_REJECTED)

        # Compatibility with synthetic multi-day Flex v3 XML variants purely in memory
        sample_xml_bytes = (
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            b"<FlexQueryResponse queryName=\"Synthetic Sample\" type=\"AF\">"
            b"<FlexStatements count=\"1\">"
            b"<FlexStatement accountId=\"REDACT-ME\" fromDate=\"20240102\" toDate=\"20240105\" period=\"Last4Days\" baseCurrency=\"USD\">"
            b"<EquitySummaryByReportDateInBase>"
            b"<EquitySummaryByReportDateInBase reportDate=\"20240102\" total=\"100000.00\" />"
            b"<EquitySummaryByReportDateInBase reportDate=\"20240103\" total=\"102000.00\" />"
            b"<EquitySummaryByReportDateInBase reportDate=\"20240104\" total=\"99040.00\" />"
            b"<EquitySummaryByReportDateInBase reportDate=\"20240105\" total=\"98049.60\" />"
            b"</EquitySummaryByReportDateInBase>"
            b"<CashTransactions>"
            b"<CashTransaction accountId=\"REDACT-ME\" reportDate=\"20240103\" currency=\"USD\" amount=\"1000.00\" type=\"Deposits/Withdrawals\" description=\"Deposit\" transactionID=\"SECRET-1\" />"
            b"<CashTransaction accountId=\"REDACT-ME\" reportDate=\"20240104\" currency=\"USD\" amount=\"-5000.00\" type=\"Deposits/Withdrawals\" description=\"Withdrawal\" transactionID=\"SECRET-2\" />"
            b"<CashTransaction accountId=\"REDACT-ME\" reportDate=\"20240105\" currency=\"USD\" amount=\"25.00\" type=\"Dividends\" description=\"Ordinary dividend\" transactionID=\"SECRET-3\" />"
            b"</CashTransactions>"
            b"<Trades>"
            b"<Trade accountId=\"REDACT-ME\" tradeID=\"SECRET-TRADE-1\" tradeDate=\"20240103\" currency=\"USD\" assetCategory=\"STK\" symbol=\"PRIVATE\" buySell=\"BUY\" quantity=\"10\" tradePrice=\"100\" proceeds=\"-1000\" ibCommission=\"-1\" fifoPnlRealized=\"0\" />"
            b"<Trade accountId=\"REDACT-ME\" tradeID=\"SECRET-TRADE-2\" tradeDate=\"20240105\" currency=\"USD\" assetCategory=\"STK\" symbol=\"PRIVATE\" buySell=\"SELL\" quantity=\"-10\" tradePrice=\"104\" proceeds=\"1040\" ibCommission=\"-1\" fifoPnlRealized=\"38\" />"
            b"</Trades>"
            b"</FlexStatement></FlexStatements></FlexQueryResponse>"
        )
        sample_ledger = parse_ibkr_flex_xml(
            sample_xml_bytes,
            blinding_salt_hex=TEST_SALT_HEX,
        )
        self.assertEqual(len(sample_ledger.nav_points), 4)
        self.assertEqual(len(sample_ledger.trades), 2)
        self.assertNotIn("REDACT-ME", json.dumps(sample_ledger.to_dict()))

        demo_xml_bytes = (
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            b"<FlexQueryResponse><FlexStatements count=\"1\">"
            b"<FlexStatement fromDate=\"20250102\" toDate=\"20250107\" period=\"SyntheticDemo\" baseCurrency=\"USD\">"
            b"<EquitySummaryByReportDateInBase>"
            b"<EquitySummaryByReportDateInBase reportDate=\"20250102\" total=\"100000.00\" />"
            b"<EquitySummaryByReportDateInBase reportDate=\"20250103\" total=\"101000.00\" />"
            b"<EquitySummaryByReportDateInBase reportDate=\"20250106\" total=\"103020.00\" />"
            b"<EquitySummaryByReportDateInBase reportDate=\"20250107\" total=\"101989.80\" />"
            b"</EquitySummaryByReportDateInBase>"
            b"<CashTransactions>"
            b"<CashTransaction reportDate=\"20250106\" currency=\"USD\" amount=\"1000.00\" type=\"Deposit\" description=\"Synthetic contribution\" />"
            b"</CashTransactions>"
            b"</FlexStatement></FlexStatements></FlexQueryResponse>"
        )
        demo_ledger = parse_ibkr_flex_xml(
            demo_xml_bytes,
            blinding_salt_hex=TEST_SALT_HEX,
        )
        self.assertEqual(len(demo_ledger.nav_points), 4)
        self.assertEqual(len(demo_ledger.flows), 1)


class TestIbkrOAuthConnector(unittest.TestCase):
    def test_pending_approval_gate_subaccount_survivorship_scope_and_oauth1a_signing(self) -> None:
        # Hosted mode without N170_IBKR_CONSUMER_KEY gates execution
        gated = IbkrOAuthReadOnlyAdapter(hosted_mode=True, env={})
        self.assertEqual(gated.approval_state, ProviderApprovalState.PENDING_PROVIDER_APPROVAL)
        with self.assertRaises(ProviderApprovalRequiredError):
            gated.enumerate_accounts()

        # Verify OAuth 1.0a HMAC-SHA256 header generation
        lst_b64 = base64.b64encode(b"live-session-secret-bytes-32-len").decode("ascii")
        oauth1_hdr = build_ibkr_oauth1a_authorization_header(
            method="GET",
            url="https://api.ibkr.com/v1/api/portfolio/accounts?foo=bar",
            consumer_key="N170CONSKEY",
            access_token="ACC_TOK_1",
            live_session_token_b64=lst_b64,
            timestamp=1760000000,
            nonce="fixednonce123",
        )
        self.assertTrue(oauth1_hdr.startswith('OAuth realm="limited_poa", '))
        self.assertIn('oauth_signature_method="HMAC-SHA256"', oauth1_hdr)

        def mock_ibkr_oauth(
            method: str,
            url: str,
            _headers: dict[str, str],
            body: bytes | None,
        ) -> tuple[int, dict[str, str], Any]:
            if url.endswith("/oauth2/api/v1/token"):
                self.assertEqual(method, "POST")
                form_str = (body or b"").decode("utf-8")
                self.assertIn("jwt-bearer", urllib.parse.unquote(form_str))
                return (200, {}, {"access_token": "IBKR_BEARER_TOK_SECRET"})
            if url.endswith("/portfolio/accounts"):
                return (
                    200,
                    {},
                    [
                        {"accountId": "U1111111", "tradingType": "STKNOPT"},
                        {"accountId": "U2222222", "tradingType": "STKNOPT"},
                    ],
                )
            if "/summary" in url:
                return (200, {}, {"netliquidation": {"amount": 50000.0}})
            if "/positions/0" in url:
                return (
                    200,
                    {},
                    [{"ticker": "AAPL", "assetClass": "STK", "position": 100, "avgCost": 180.0, "mktValue": 22000.0}],
                )
            if url.endswith("/iserver/account/trades"):
                return (
                    200,
                    {},
                    [
                        {
                            "execution_id": "EX-1",
                            "account": "U1111111",
                            "symbol": "AAPL",
                            "side": "B",
                            "size": 10,
                            "price": 215.0,
                            "commission": 1.0,
                            "trade_time_r_iso": "2026-01-15T15:00:00Z",
                        }
                    ],
                )
            if url.endswith("/pa/transactions"):
                return (
                    200,
                    {},
                    {"transactions": [{"type": "Deposit", "amt": 5000.0, "cur": "USD", "date": "2026-01-05T00:00:00Z"}]},
                )
            raise AssertionError(f"Unhandled IBKR URL {url}")

        live_adapter = IbkrOAuthReadOnlyAdapter(
            hosted_mode=True,
            env={"N170_IBKR_CONSUMER_KEY": "N170_APPROVED_CONS_KEY"},
            auth_mode="oauth2_private_key_jwt",
            client_assertion_jwt="eyJhbGciOiJSUzI1NiJ9.assertion.sig",
            http_transport=mock_ibkr_oauth,
        )
        self.assertEqual(live_adapter.approval_state, ProviderApprovalState.APPROVED_LIVE)

        full_ledger = live_adapter.fetch_canonical_ledger(
            blinding_salt_hex=TEST_SALT_HEX,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
        )
        self.assertEqual(full_ledger.account_scope, AccountScope.ALL_ENUMERATED_SUBACCOUNTS)
        self.assertEqual(full_ledger.enumerated_subaccount_count, 2)
        self.assertEqual(full_ledger.connected_subaccount_count, 2)

        subset_ledger = live_adapter.fetch_canonical_ledger(
            blinding_salt_hex=TEST_SALT_HEX,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            selected_account_ids=["U1111111"],
        )
        self.assertEqual(
            subset_ledger.account_scope,
            AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED,
        )
        self.assertEqual(subset_ledger.enumerated_subaccount_count, 2)
        self.assertEqual(subset_ledger.connected_subaccount_count, 1)


class TestCcxtCryptoScopeIntrospection(unittest.TestCase):
    def test_binance_mutating_key_flags_fail_closed_before_any_balance_or_trade_call(self) -> None:
        base_restrictions = {
            "enableReading": True,
            "enableWithdrawals": False,
            "enableInternalTransfer": False,
            "permitsUniversalTransfer": False,
            "enableSpotAndMarginTrading": False,
            "enableFutures": False,
            "enableMargin": False,
        }
        for bad_flag in (
            "enableWithdrawals",
            "enableInternalTransfer",
            "permitsUniversalTransfer",
            "enableSpotAndMarginTrading",
            "enableFutures",
            "enableMargin",
        ):
            called_urls: list[str] = []

            def transport(
                _m: str,
                url: str,
                _h: dict[str, str],
                _b: bytes | None,
                flag: str = bad_flag,
                log: list[str] = called_urls,
            ) -> tuple[int, dict[str, str], Any]:
                log.append(url)
                mutated = dict(base_restrictions)
                mutated[flag] = True
                return (200, {}, mutated)

            adapter = CcxtExchangeReadOnlyAdapter(
                "binance",
                api_key="BIN_KEY_SECRET",
                api_secret="BIN_HMAC_SECRET",
                http_transport=transport,
            )
            with self.assertRaises(MutatingCredentialRejectedError):
                adapter.fetch_canonical_ledger(
                    blinding_salt_hex=TEST_SALT_HEX,
                    period_start_utc="2026-01-01T00:00:00Z",
                    period_end_utc="2026-01-31T00:00:00Z",
                )
            # Zero calls beyond apiRestrictions!
            self.assertEqual(len(called_urls), 1)
            self.assertIn("/sapi/v1/account/apiRestrictions", called_urls[0])

    def test_binance_valid_readonly_429_backoff_418_halt_and_90d_window_paging(self) -> None:
        windows = split_time_windows_under_90d("2025-06-01T00:00:00Z", "2026-01-01T00:00:00Z")
        self.assertEqual(len(windows), 3)
        for ws, we in windows:
            self.assertLess((we - ws).total_seconds(), 90 * 86400)

        deposit_calls = 0
        trade_attempt = 0

        def mock_binance(
            _m: str,
            url: str,
            _h: dict[str, str],
            _b: bytes | None,
        ) -> tuple[int, dict[str, str], Any]:
            nonlocal deposit_calls, trade_attempt
            if "/sapi/v1/account/apiRestrictions" in url:
                return (
                    200,
                    {},
                    {
                        "enableReading": True,
                        "enableWithdrawals": False,
                        "enableInternalTransfer": False,
                        "permitsUniversalTransfer": False,
                        "enableSpotAndMarginTrading": False,
                        "enableFutures": False,
                        "enableMargin": False,
                    },
                )
            if "/api/v3/account" in url:
                return (
                    200,
                    {},
                    {
                        "uid": 99887766,
                        "balances": [{"asset": "USDT", "free": "15000.0", "locked": "0.0", "usdValuation": "15000.0"}],
                    },
                )
            if "/sapi/v1/capital/deposit/hisrec" in url:
                deposit_calls += 1
                return (
                    200,
                    {},
                    [{"insertTime": 1750000000000, "amount": "1000.0", "coin": "USDT"}]
                    if deposit_calls == 1
                    else [],
                )
            if "/sapi/v1/capital/withdraw/apply" in url:
                return (200, {}, [])
            if "/api/v3/myTrades" in url:
                trade_attempt += 1
                if trade_attempt == 1:
                    return (429, {"Retry-After": "4"}, {"msg": "Way too much request weight"})
                return (
                    200,
                    {},
                    [{"id": 701, "price": "95000.0", "qty": "0.1", "commission": "1.5", "time": 1755000000000, "isBuyer": True}],
                )
            raise AssertionError(f"Unexpected Binance URL {url}")

        sleeps: list[float] = []
        adapter = CcxtExchangeReadOnlyAdapter(
            "binance",
            http_transport=mock_binance,
            sleep_fn=sleeps.append,
        )
        ledger = adapter.fetch_canonical_ledger(
            blinding_salt_hex=TEST_SALT_HEX,
            period_start_utc="2025-06-01T00:00:00Z",
            period_end_utc="2026-01-01T00:00:00Z",
        )
        self.assertEqual(deposit_calls, 3)
        self.assertEqual(sleeps, [4.0])
        self.assertEqual(len(ledger.trades), 1)
        self.assertEqual(len(ledger.flows), 1)

        # HTTP 418 IP auto-ban halts immediately without retrying
        ban_calls = 0

        def mock_418(_m: str, url: str, _h: dict[str, str], _b: bytes | None) -> tuple[int, dict[str, str], Any]:
            nonlocal ban_calls
            ban_calls += 1
            if "apiRestrictions" in url:
                return (
                    200,
                    {},
                    {
                        "enableReading": True,
                        "enableWithdrawals": False,
                        "enableInternalTransfer": False,
                        "permitsUniversalTransfer": False,
                        "enableSpotAndMarginTrading": False,
                        "enableFutures": False,
                        "enableMargin": False,
                    },
                )
            return (418, {}, {"msg": "IP banned"})

        ban_adapter = CcxtExchangeReadOnlyAdapter("binance", http_transport=mock_418, sleep_fn=lambda _: None)
        with self.assertRaises(ConnectorHttpError) as ctx:
            ban_adapter.fetch_canonical_ledger(
                blinding_salt_hex=TEST_SALT_HEX,
                period_start_utc="2026-01-01T00:00:00Z",
                period_end_utc="2026-01-10T00:00:00Z",
            )
        self.assertEqual(ctx.exception.status_code, 418)
        self.assertEqual(ban_calls, 2)

    def test_coinbase_mutating_rejection_portfolio_enumeration_and_entry_id_dedup(self) -> None:
        # Mutating Coinbase permissions (can_trade=True or can_transfer=True) fail closed immediately
        for bad_perms in (
            {"can_view": True, "can_trade": True, "can_transfer": False},
            {"can_view": True, "can_trade": False, "can_transfer": True},
            {"can_view": False, "can_trade": False, "can_transfer": False},
        ):
            urls: list[str] = []
            adapter = CcxtExchangeReadOnlyAdapter(
                "coinbase",
                http_transport=lambda _m, u, _h, _b, p=bad_perms, log=urls: (log.append(u) or (200, {}, p)),
            )
            with self.assertRaises(MutatingCredentialRejectedError):
                adapter.fetch_canonical_ledger(
                    blinding_salt_hex=TEST_SALT_HEX,
                    period_start_utc="2026-01-01T00:00:00Z",
                    period_end_utc="2026-01-31T00:00:00Z",
                )
            self.assertEqual(len(urls), 1)

        # Direct unit test of entry_id deduplication when fills share non-unique trade_id
        raw_fills = [
            {
                "entry_id": "ENTRY-LEG-1",
                "trade_id": "SHARED-TRADE-99",
                "product_id": "BTC-USD",
                "side": "BUY",
                "size": "0.25",
                "price": "94000.00",
                "commission": "2.50",
                "trade_time": "2026-01-10T12:00:00Z",
            },
            {
                "entry_id": "ENTRY-LEG-2",
                "trade_id": "SHARED-TRADE-99",
                "product_id": "BTC-USD",
                "side": "BUY",
                "size": "0.75",
                "price": "94010.00",
                "commission": "7.50",
                "trade_time": "2026-01-10T12:00:01Z",
            },
            # Post-trade fee adjustment sharing ENTRY-LEG-1 -> updates ENTRY-LEG-1 in-place
            {
                "entry_id": "ENTRY-LEG-1",
                "trade_id": "SHARED-TRADE-99",
                "product_id": "BTC-USD",
                "side": "BUY",
                "size": "0.25",
                "price": "94000.00",
                "commission": "2.00",
                "trade_time": "2026-01-10T12:00:00Z",
            },
            # Replacement fill superseding ENTRY-LEG-2 via replaces_entry_id
            {
                "entry_id": "ENTRY-LEG-2-ADJ",
                "replaces_entry_id": "ENTRY-LEG-2",
                "trade_id": "SHARED-TRADE-99",
                "product_id": "BTC-USD",
                "side": "BUY",
                "size": "0.75",
                "price": "94005.00",
                "commission": "7.00",
                "trade_time": "2026-01-10T12:00:02Z",
            },
        ]
        deduped = deduplicate_coinbase_fills_by_entry_id(raw_fills)
        self.assertEqual([f["entry_id"] for f in deduped], ["ENTRY-LEG-1", "ENTRY-LEG-2-ADJ"])
        self.assertEqual(deduped[0]["commission"], "2.00")

        # Missing entry_id must never silently fall back to trade_id
        with self.assertRaises(ValueError):
            deduplicate_coinbase_fills_by_entry_id([{"trade_id": "ONLY-TRADE-ID"}])

        def mock_coinbase(_m: str, url: str, _h: dict[str, str], _b: bytes | None) -> tuple[int, dict[str, str], Any]:
            if "/api/v3/brokerage/key_permissions" in url:
                return (200, {}, {"can_view": True, "can_trade": False, "can_transfer": False})
            if "/api/v3/brokerage/accounts" in url:
                if "cursor=page2" in url:
                    return (
                        200,
                        {},
                        {"accounts": [{"retail_portfolio_id": "port-beta"}], "has_next": False},
                    )
                return (
                    200,
                    {},
                    {
                        "accounts": [{"retail_portfolio_id": "port-alpha"}],
                        "has_next": True,
                        "cursor": "page2",
                    },
                )
            if "/api/v3/brokerage/orders/historical/fills" in url:
                return (200, {}, {"fills": raw_fills})
            raise AssertionError(f"Unexpected Coinbase URL {url}")

        cb = CcxtExchangeReadOnlyAdapter("coinbase", http_transport=mock_coinbase)
        cb_all = cb.fetch_canonical_ledger(
            blinding_salt_hex=TEST_SALT_HEX,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
        )
        self.assertEqual(cb_all.account_scope, AccountScope.ALL_ENUMERATED_SUBACCOUNTS)
        self.assertEqual(cb_all.enumerated_subaccount_count, 2)
        self.assertEqual([t.native_entry_id for t in cb_all.trades], ["ENTRY-LEG-1", "ENTRY-LEG-2-ADJ"])

        cb_sub = cb.fetch_canonical_ledger(
            blinding_salt_hex=TEST_SALT_HEX,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            selected_subaccounts=["port-alpha"],
        )
        self.assertEqual(cb_sub.account_scope, AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED)

    def test_kraken_bybit_scope_checks_decay_limiter_and_ccxt_monkeypatching(self) -> None:
        # Kraken mutating scopes ('orders', 'withdraw', 'transfer') fail closed
        for bad_scope in ("orders", "withdraw", "transfer"):
            calls: list[str] = []
            kr_bad = CcxtExchangeReadOnlyAdapter(
                "kraken",
                http_transport=lambda _m, u, _h, _b, s=bad_scope, log=calls: (
                    log.append(u)
                    or (200, {}, {"error": [], "result": {"permissions": {"query_funds": True, s: True}}})
                ),
            )
            with self.assertRaises(MutatingCredentialRejectedError):
                kr_bad.fetch_canonical_ledger(
                    blinding_salt_hex=TEST_SALT_HEX,
                    period_start_utc="2026-01-01T00:00:00Z",
                    period_end_utc="2026-01-31T00:00:00Z",
                )
            self.assertEqual(len(calls), 1)

        # Kraken +4 decay counter max 20 verification
        fake_clock = [100.0]

        def advance_sleep(sec: float) -> None:
            fake_clock[0] += sec

        limiter = KrakenDecayRateLimiter(now_fn=lambda: fake_clock[0], sleep_fn=advance_sleep)
        for _ in range(5):
            limiter.acquire(4.0)  # 5 * 4 = 20 (at max, 0 sleeps)
        self.assertEqual(limiter.recorded_sleeps, [])
        limiter.acquire(4.0)  # 6th call exceeds 20 -> sleeps 4 / 0.5 = 8.0s
        self.assertEqual(limiter.recorded_sleeps, [8.0])

        # Kraken BalanceEx vs Ledgers reconciliation warning when balances diverge
        def mock_kraken(_m: str, url: str, _h: dict[str, str], _b: bytes | None) -> tuple[int, dict[str, str], Any]:
            if url.endswith("/0/private/GetApiKeyInfo"):
                return (
                    200,
                    {},
                    {
                        "error": [],
                        "result": {
                            "permissions": {
                                "query_funds": True,
                                "query_ledgers": True,
                                "query_closed_orders_trades": True,
                            }
                        },
                    },
                )
            if url.endswith("/0/private/BalanceEx"):
                return (200, {}, {"error": [], "result": {"ZUSD": {"balance": "10500.00"}}})
            if url.endswith("/0/private/Ledgers"):
                return (
                    200,
                    {},
                    {
                        "error": [],
                        "result": {
                            "ledger": {
                                "L-1": {
                                    "type": "deposit",
                                    "asset": "ZUSD",
                                    "amount": "10000.00",
                                    "fee": "0.00",
                                    "balance": "10000.00",
                                    "time": 1768000000.0,
                                }
                            }
                        },
                    },
                )
            raise AssertionError(f"Unexpected Kraken URL {url}")

        kr_ok = CcxtExchangeReadOnlyAdapter("kraken", http_transport=mock_kraken)
        kr_ledger = kr_ok.fetch_canonical_ledger(
            blinding_salt_hex=TEST_SALT_HEX,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
        )
        self.assertEqual(len(kr_ledger.parser_warnings), 1)
        self.assertIn("BalanceEx vs Ledgers mismatch", kr_ledger.parser_warnings[0])

        # Bybit v5: readOnly != 1 fails closed before any wallet/execution call
        bybit_bad_calls: list[str] = []
        bybit_bad = CcxtExchangeReadOnlyAdapter(
            "bybit",
            http_transport=lambda _m, u, _h, _b: (
                bybit_bad_calls.append(u)
                or (200, {}, {"retCode": 0, "result": {"readOnly": 0, "userID": "1001"}})
            ),
        )
        with self.assertRaises(MutatingCredentialRejectedError):
            bybit_bad.fetch_canonical_ledger(
                blinding_salt_hex=TEST_SALT_HEX,
                period_start_utc="2026-01-01T00:00:00Z",
                period_end_utc="2026-01-31T00:00:00Z",
            )
        self.assertEqual(len(bybit_bad_calls), 1)

        # Bybit v5: readOnly == 1 + query-sub-members enumeration
        def mock_bybit(_m: str, url: str, _h: dict[str, str], _b: bytes | None) -> tuple[int, dict[str, str], Any]:
            if "/v5/user/query-api" in url:
                return (
                    200,
                    {},
                    {
                        "retCode": 0,
                        "result": {"readOnly": 1, "userID": "M-100", "permissions": {"SpotRead": [" SpotTradeRead "]}},
                    },
                )
            if "/v5/user/query-sub-members" in url:
                return (
                    200,
                    {},
                    {"retCode": 0, "result": {"subMembers": [{"uid": "SUB-201"}, {"uid": "SUB-202"}]}},
                )
            if "/v5/account/wallet-balance" in url:
                return (200, {}, {"retCode": 0, "result": {"list": [{"totalEquity": "45000.0"}]}})
            if "/v5/execution/list" in url:
                return (
                    200,
                    {},
                    {
                        "retCode": 0,
                        "result": {
                            "list": [
                                {
                                    "execId": "BYB-EX-1",
                                    "symbol": "BTCUSDT",
                                    "side": "Buy",
                                    "execQty": "0.5",
                                    "execPrice": "90000.0",
                                    "execFee": "4.5",
                                    "execTime": "1768100000000",
                                }
                            ]
                        },
                    },
                )
            raise AssertionError(f"Unexpected Bybit URL {url}")

        class _DummyCcxtExchange:
            sandbox = False
            urls = {"api": "https://api.bybit.com"}

            def create_order(self, *args: Any, **kwargs: Any) -> Any:
                return {"id": "should-never-run"}

            def cancel_order(self, *args: Any, **kwargs: Any) -> Any:
                return {}

            def edit_order(self, *args: Any, **kwargs: Any) -> Any:
                return {}

            def withdraw(self, *args: Any, **kwargs: Any) -> Any:
                return {}

            def transfer(self, *args: Any, **kwargs: Any) -> Any:
                return {}

        dummy_ccxt = _DummyCcxtExchange()
        bybit_ok = CcxtExchangeReadOnlyAdapter(
            "bybit",
            ccxt_exchange=dummy_ccxt,
            http_transport=mock_bybit,
        )
        for mut_name in ("create_order", "cancel_order", "edit_order", "withdraw", "transfer"):
            with self.assertRaises(DisallowedCapabilityError):
                getattr(dummy_ccxt, mut_name)()

        bybit_ledger = bybit_ok.fetch_canonical_ledger(
            blinding_salt_hex=TEST_SALT_HEX,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
        )
        self.assertEqual(bybit_ledger.account_scope, AccountScope.ALL_ENUMERATED_SUBACCOUNTS)
        self.assertEqual(bybit_ledger.enumerated_subaccount_count, 3)

        # Sandbox CCXT instance rejected
        class _SandboxCcxt:
            sandbox = True

        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            harden_ccxt_exchange_instance(_SandboxCcxt())


class TestAlpacaTrading212TradierSchwab(unittest.TestCase):
    def test_alpaca_rejects_paper_host_and_pa_accounts_and_normalizes_live_httpx_client(self) -> None:
        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            AlpacaReadOnlyAdapter(
                api_key_id="PK_TEST",
                api_secret_key="SEC_TEST",
                base_url="https://paper-api.alpaca.markets",
            )
        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            AlpacaReadOnlyAdapter(
                api_key_id="PK_TEST",
                api_secret_key="SEC_TEST",
                env={"APCA_API_BASE_URL": "https://paper-api.alpaca.markets"},
            )

        # Paper PA... account number returned from live URL -> rejected when require_live=True
        pa_adapter = AlpacaReadOnlyAdapter(
            api_key_id="LIVE_KEY",
            api_secret_key="LIVE_SEC",
            http_transport=lambda _m, _u, _h, _b: (
                200,
                {},
                {"account_number": "PA399887766", "currency": "USD", "equity": "100000"},
            ),
        )
        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            pa_adapter.fetch_canonical_ledger(
                blinding_salt_hex=TEST_SALT_HEX,
                period_start_utc="2026-01-01T00:00:00Z",
                period_end_utc="2026-01-31T00:00:00Z",
            )

        # Live production Alpaca run via httpx-style .request() client
        def live_alpaca_handler(
            _m: str,
            url: str,
            _h: dict[str, str],
            _b: bytes | None,
        ) -> tuple[int, dict[str, str], Any]:
            self.assertTrue(url.startswith(ALPACA_LIVE_BASE_URL))
            if url.endswith("/v2/account"):
                return (
                    200,
                    {},
                    {"account_number": "892341223", "currency": "USD", "equity": "152000.00", "cash": "12000.00"},
                )
            if "/v2/account/portfolio/history" in url:
                return (200, {}, {"timestamp": [1767312000, 1769817600], "equity": [140000.0, 152000.0]})
            if url.endswith("/v2/positions"):
                return (
                    200,
                    {},
                    [{"symbol": "MSFT", "asset_class": "us_equity", "qty": "100", "cost_basis": "40000", "market_value": "44000"}],
                )
            if "/v2/account/activities" in url:
                return (
                    200,
                    {},
                    [
                        {
                            "id": "ACT-FILL-1",
                            "activity_type": "FILL",
                            "symbol": "MSFT",
                            "side": "buy",
                            "qty": "10",
                            "price": "430.0",
                            "transaction_time": "2026-01-10T15:00:00Z",
                        },
                        {
                            "id": "ACT-CSD-1",
                            "activity_type": "CSD",
                            "net_amount": "5000.0",
                            "date": "2026-01-04",
                        },
                    ],
                )
            raise AssertionError(f"Unhandled Alpaca URL {url}")

        mock_httpx = _MockHttpxClient(live_alpaca_handler)
        live_alpaca = AlpacaReadOnlyAdapter(
            api_key_id="ALP_LIVE_ID",
            api_secret_key="ALP_LIVE_SECRET",
            http_transport=mock_httpx,
        )
        ledger = live_alpaca.fetch_canonical_ledger(
            blinding_salt_hex=TEST_SALT_HEX,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
        )
        self.assertEqual(ledger.environment_tier, EnvironmentTier.LIVE_PRODUCTION)
        self.assertEqual(len(ledger.nav_points), 2)
        self.assertEqual(len(ledger.trades), 1)
        self.assertEqual(len(ledger.flows), 1)
        self.assertNotIn("892341223", json.dumps(ledger.to_dict()))

    def test_trading212_basic_auth_ratelimit_headers_and_demo_cfd_rejection(self) -> None:
        expected_b64 = base64.b64encode(b"T212KEY:T212SEC").decode("ascii")
        self.assertEqual(build_trading212_basic_auth_header("T212KEY", "T212SEC"), f"Basic {expected_b64}")

        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            Trading212ReadOnlyAdapter(
                api_key="K",
                api_secret="S",
                base_url="https://demo.trading212.com",
            )

        clock = [1_760_000_000.0]
        sleeps: list[float] = []

        def fake_sleep(sec: float) -> None:
            sleeps.append(sec)
            clock[0] += sec

        def mock_t212(
            _m: str,
            url: str,
            headers: dict[str, str],
            _b: bytes | None,
        ) -> tuple[int, dict[str, str], Any]:
            self.assertEqual(headers.get("Authorization"), f"Basic {expected_b64}")
            if url.endswith("/api/v0/equity/account/info"):
                # Exhaust summary bucket with reset 9s out (> 5s default)
                return (
                    200,
                    {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(clock[0] + 9.0)},
                    {"id": 445566, "currencyCode": "GBP", "type": "ISA"},
                )
            if url.endswith("/api/v0/equity/account/cash"):
                return (200, {"x-ratelimit-remaining": "1"}, {"total": 28500.0, "free": 3500.0})
            if url.endswith("/api/v0/equity/portfolio"):
                return (
                    200,
                    {},
                    [{"ticker": "VWRL_UK_EQ", "quantity": 200.0, "averagePrice": 100.0, "currentPrice": 125.0}],
                )
            if "/api/v0/equity/history/orders" in url:
                return (
                    200,
                    {},
                    {
                        "items": [
                            {
                                "order": {"id": "O-1", "ticker": "VWRL_UK_EQ", "status": "FILLED", "side": "BUY"},
                                "fill": {"id": "F-1", "quantity": 20.0, "price": 120.0, "filledAt": "2026-01-12T10:00:00Z"},
                            }
                        ],
                        "nextPagePath": None,
                    },
                )
            if "/api/v0/history/dividends" in url:
                return (
                    200,
                    {},
                    {"items": [{"ticker": "VWRL_UK_EQ", "amount": 85.0, "paidOn": "2026-01-15T00:00:00Z"}]},
                )
            if "/api/v0/history/transactions" in url:
                return (
                    200,
                    {},
                    {"items": [{"type": "DEPOSIT", "amount": 2000.0, "dateTime": "2026-01-03T09:00:00Z"}]},
                )
            raise AssertionError(f"Unhandled Trading 212 URL {url}")

        t212 = Trading212ReadOnlyAdapter(
            api_key="T212KEY",
            api_secret="T212SEC",
            http_transport=mock_t212,
            now_fn=lambda: clock[0],
            sleep_fn=fake_sleep,
        )
        t212_ledger = t212.fetch_canonical_ledger(
            blinding_salt_hex=TEST_SALT_HEX,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
        )
        # Summary bucket waited 9.0s before /account/cash due to x-ratelimit-remaining=0
        self.assertEqual(sleeps, [9.0])
        self.assertEqual(
            t212_ledger.account_scope,
            AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
        )
        self.assertEqual(len(t212_ledger.trades), 1)
        self.assertEqual(len(t212_ledger.flows), 2)

        # CFD account type is rejected
        cfd_t212 = Trading212ReadOnlyAdapter(
            api_key="T212KEY",
            api_secret="T212SEC",
            http_transport=lambda _m, _u, _h, _b: (200, {}, {"id": 99, "type": "CFD"}),
        )
        with self.assertRaises(DisallowedCapabilityError):
            cfd_t212.fetch_canonical_ledger(
                blinding_salt_hex=TEST_SALT_HEX,
                period_start_utc="2026-01-01T00:00:00Z",
                period_end_utc="2026-01-31T00:00:00Z",
            )

    def test_tradier_multi_account_scope_path_redaction_and_sandbox_rejection(self) -> None:
        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            TradierReadOnlyAdapter(
                access_token="TRADIER_TOK",
                base_url="https://sandbox.tradier.com",
            )

        self.assertEqual(
            redact_tradier_account_path("GET /v1/accounts/6YA55443/positions failed"),
            "GET /v1/accounts/[REDACTED]/positions failed",
        )

        def mock_tradier(_m: str, url: str, _h: dict[str, str], _b: bytes | None) -> tuple[int, dict[str, str], Any]:
            if url.endswith("/v1/user/profile"):
                return (
                    200,
                    {},
                    {
                        "profile": {
                            "account": [
                                {"account_number": "6YA10001", "classification": "individual"},
                                {"account_number": "6YA10002", "classification": "ira"},
                            ]
                        }
                    },
                )
            if "/balances" in url:
                return (200, {}, {"balances": {"total_equity": 40000.0, "total_cash": 5000.0}})
            if "/positions" in url:
                return (
                    200,
                    {},
                    {"positions": {"position": {"symbol": "SPY", "quantity": 50.0, "cost_basis": 25000.0, "market_value": 30000.0}}},
                )
            if "/history" in url:
                return (
                    200,
                    {},
                    {
                        "history": {
                            "event": [
                                {
                                    "type": "trade",
                                    "date": "2026-01-09T14:30:00Z",
                                    "trade": {"symbol": "SPY", "trade_type": "buy", "quantity": 10.0, "price": 590.0, "commission": 0.0},
                                },
                                {"type": "ach", "date": "2026-01-03", "amount": 2500.0},
                            ]
                        }
                    },
                )
            raise AssertionError(f"Unhandled Tradier URL {url}")

        tr = TradierReadOnlyAdapter(access_token="TRADIER_SECRET_BEARER", http_transport=mock_tradier)
        all_ledger = tr.fetch_canonical_ledger(
            blinding_salt_hex=TEST_SALT_HEX,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
        )
        self.assertEqual(all_ledger.account_scope, AccountScope.ALL_ENUMERATED_SUBACCOUNTS)
        self.assertEqual(all_ledger.enumerated_subaccount_count, 2)

        sub_ledger = tr.fetch_canonical_ledger(
            blinding_salt_hex=TEST_SALT_HEX,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            selected_account_numbers=["6YA10001"],
        )
        self.assertEqual(sub_ledger.account_scope, AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED)

        # Verify HTTP error redacts /v1/accounts/{account_id}/ and bearer token
        def failing_tradier(_m: str, url: str, _h: dict[str, str], _b: bytes | None) -> tuple[int, dict[str, str], Any]:
            if url.endswith("/v1/user/profile"):
                return (200, {}, {"profile": {"account": {"account_number": "6YA99999"}}})
            return (500, {}, f"Upstream crash at {url} with token TRADIER_SECRET_BEARER")

        tr_err = TradierReadOnlyAdapter(
            access_token="TRADIER_SECRET_BEARER", http_transport=failing_tradier
        )
        with self.assertRaises(ConnectorHttpError) as ctx:
            tr_err.fetch_canonical_ledger(
                blinding_salt_hex=TEST_SALT_HEX,
                period_start_utc="2026-01-01T00:00:00Z",
                period_end_utc="2026-01-31T00:00:00Z",
            )
        err_text = str(ctx.exception)
        self.assertNotIn("6YA99999", err_text)
        self.assertNotIn("TRADIER_SECRET_BEARER", err_text)
        self.assertIn("/v1/accounts/[REDACTED]/balances", err_text)

    def test_schwab_commercial_approval_gate_and_internal_journal_audit(self) -> None:
        gated = SchwabReadOnlyAdapter(access_token="SCHWAB_TOK", hosted_mode=True, env={})
        self.assertEqual(gated.approval_state, ProviderApprovalState.PENDING_PROVIDER_APPROVAL)
        with self.assertRaises(ProviderApprovalRequiredError):
            gated.fetch_canonical_ledger(
                blinding_salt_hex=TEST_SALT_HEX,
                period_start_utc="2026-01-01T00:00:00Z",
                period_end_utc="2026-01-31T00:00:00Z",
            )

        def mock_schwab(_m: str, url: str, _h: dict[str, str], _b: bytes | None) -> tuple[int, dict[str, str], Any]:
            if url.endswith("/trader/v1/accounts/accountNumbers"):
                return (
                    200,
                    {},
                    [
                        {"accountNumber": "11112222", "hashValue": "HASH_ACCT_A"},
                        {"accountNumber": "33334444", "hashValue": "HASH_ACCT_B"},
                    ],
                )
            if "/transactions" in url:
                return (
                    200,
                    {},
                    [
                        {
                            "activityId": 9001,
                            "type": "JOURNAL",
                            "description": "INTRA-ACCOUNT JOURNAL TRANSFER",
                            "netAmount": 10000.0,
                            "time": "2026-01-12T14:00:00+0000",
                        },
                        {
                            "activityId": 9002,
                            "type": "TRADE",
                            "time": "2026-01-14T15:30:00+0000",
                            "transferItems": [
                                {"instrument": {"symbol": "QQQ", "assetType": "EQUITY"}, "amount": 20.0, "price": 510.0}
                            ],
                        },
                    ],
                )
            if "/trader/v1/accounts/" in url:
                return (
                    200,
                    {},
                    {
                        "securitiesAccount": {
                            "currentBalances": {"liquidationValue": 85000.0},
                            "positions": [
                                {
                                    "instrument": {"symbol": "QQQ", "assetType": "EQUITY"},
                                    "longQuantity": 20.0,
                                    "shortQuantity": 0.0,
                                    "averagePrice": 510.0,
                                    "marketValue": 10400.0,
                                }
                            ],
                        }
                    },
                )
            raise AssertionError(f"Unhandled Schwab URL {url}")

        approved = SchwabReadOnlyAdapter(
            access_token="SCHWAB_LIVE_TOK",
            hosted_mode=True,
            env={"N170_SCHWAB_COMMERCIAL_APPROVED": "true"},
            http_transport=mock_schwab,
        )
        subset_ledger = approved.fetch_canonical_ledger(
            blinding_salt_hex=TEST_SALT_HEX,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            selected_account_hashes=["HASH_ACCT_A"],
        )
        self.assertEqual(
            subset_ledger.account_scope,
            AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED,
        )
        self.assertEqual(subset_ledger.flows[0].kind, FlowKind.INTERNAL_SUBACCOUNT_TRANSFER)
        self.assertTrue(
            any("internal Schwab journal transfer" in w for w in subset_ledger.parser_warnings)
        )


class TestOfflineCsvAndScraperBlock(unittest.TestCase):
    def test_degiro_multi_locale_en_nl_de_csv_import_preserves_isins_and_fx(self) -> None:
        # 1. English (EN)
        en_tx = (
            "Date,Time,Product,ISIN,Reference exchange,Venue,Quantity,Price,,Local value,,Value,,Exchange rate,Transaction and/or third,Total,,Order ID\n"
            "05-01-2026,15:35,APPLE INC,US0378331005,NDQ,XNAS,10,200.00,USD,-2000.00,USD,-1818.18,EUR,1.1000,-1.00,EUR,-1819.18,EUR,ORD-EN-1\n"
        )
        en_acct = (
            "Date,Time,Value date,Product,ISIN,Description,FX,Change,,Balance,,Order ID\n"
            "02-01-2026,09:00,02-01-2026,,,iDEAL Deposit,,EUR,5000.00,EUR,5000.00,\n"
            "15-01-2026,08:00,15-01-2026,APPLE INC,US0378331005,Dividend,1.1000,USD,25.00,USD,25.00,\n"
        )
        en_port = (
            "Product,Symbol/ISIN,Amount,Closing,Local value,Value in EUR\n"
            "CASH & CASH FUND & FTX CASH (EUR),,0,1.00,EUR 3180.82,3180.82\n"
            "APPLE INC,US0378331005,10,210.00,USD 2100.00,1909.09\n"
        )

        # 2. Dutch (NL)
        nl_tx = (
            "Datum,Tijd,Product,ISIN,Beurs,Uitvoeringsplaats,Aantal,Koers,,Lokale waarde,,Waarde,,Wisselkoers,Transactiekosten en/of,Totaal,,Order ID\n"
            "06-01-2026,10:15,ASML HOLDING,NL0010273215,EAM,XAMS,5,\"710,50\",EUR,\"-3.552,50\",EUR,\"-3.552,50\",EUR,,\"-2,00\",EUR,\"-3.554,50\",EUR,ORD-NL-1\n"
        )
        nl_acct = (
            "Datum,Tijd,Valutadatum,Product,ISIN,Omschrijving,Wisselkoers,Mutatie,,Saldo,,Order ID\n"
            "03-01-2026,09:00,03-01-2026,,,iDEAL storting,,EUR,\"4.000,00\",EUR,\"4.000,00\",\n"
            "18-01-2026,08:00,18-01-2026,ASML HOLDING,NL0010273215,Dividendbelasting,,EUR,\"-4,50\",EUR,\"440,00\",\n"
        )
        nl_port = (
            "Product,Symbool/ISIN,Aantal,Slotkoers,Lokale waarde,Waarde in EUR\n"
            "FLATEX EURO BANKACCOUNT,,0,\"1,00\",\"EUR 445,50\",\"445,50\"\n"
            "ASML HOLDING,NL0010273215,5,\"720,00\",\"EUR 3.600,00\",\"3.600,00\"\n"
        )

        # 3. German (DE — semicolon delimited with decimal commas)
        de_tx = (
            "Datum;Uhrzeit;Produkt;ISIN;Börse;Ausführungsort;Anzahl;Kurs;;Lokaler Wert;;Wert;;Wechselkurs;Transaktionsgebühren;Gesamt;;Order-ID\n"
            "07.01.2026;11:20;ISHARES CORE MSCI WORLD UCITS ETF;IE00B4L5Y983;XET;XETR;20;95,50;EUR;-1.910,00;EUR;-1.910,00;EUR;;-1,00;EUR;-1.911,00;EUR;ORD-DE-1\n"
            "08.01.2026;16:00;MICROSOFT CORP;US5949181045;NDQ;XNAS;4;440,00;USD;-1.760,00;USD;-1.600,00;EUR;1,1000;-1,00;EUR;-1.601,00;EUR;ORD-DE-2\n"
        )
        de_acct = (
            "Datum;Uhrzeit;Valutadatum;Produkt;ISIN;Beschreibung;Wechselkurs;Änderung;;Saldo;;Order-ID\n"
            "04.01.2026;10:00;04.01.2026;;;Einzahlung;;EUR;4.000,00;EUR;4.000,00;\n"
            "20.01.2026;09:00;20.01.2026;MICROSOFT CORP;US5949181045;Quellensteuer;1,1000;USD;-3,30;USD;18,70;\n"
        )
        de_port = (
            "Produkt;Symbol/ISIN;Anzahl;Schlusskurs;Lokaler Wert;Wert in EUR\n"
            "FLATEX GELDMARKTFONDS;;0;1,00;EUR 488,00;488,00\n"
            "ISHARES CORE MSCI WORLD UCITS ETF;IE00B4L5Y983;20;97,00;EUR 1.940,00;1.940,00\n"
            "MICROSOFT CORP;US5949181045;4;451,00;USD 1.804,00;1.640,00\n"
        )

        adapter = DegiroOfflineCsvAdapter()
        en_ledger = adapter.parse_export(
            transactions_csv=en_tx,
            account_csv=en_acct,
            portfolio_csv=en_port,
            blinding_salt_hex=TEST_SALT_HEX,
        )
        nl_ledger = parse_degiro_csv_bundle(
            transactions_csv=nl_tx,
            account_csv=nl_acct,
            portfolio_csv=nl_port,
            blinding_salt_hex=TEST_SALT_HEX,
        )
        de_ledger = parse_degiro_csv_bundle(
            transactions_csv=de_tx,
            account_csv=de_acct,
            portfolio_csv=de_port,
            blinding_salt_hex=TEST_SALT_HEX,
        )

        for ldg in (en_ledger, nl_ledger, de_ledger):
            self.assertEqual(ldg.claimed_origin_assurance, OriginAssurance.SELF_REPORTED)
            self.assertEqual(ldg.account_scope, AccountScope.UNKNOWN_OFFLINE_SCOPE)
            self.assertEqual(ldg.provider_approval_state, ProviderApprovalState.OFFLINE_EXPORT_ONLY)
            self.assertEqual(ldg.base_currency, "EUR")

        self.assertEqual(en_ledger.trades[0].isin, "US0378331005")
        self.assertAlmostEqual(en_ledger.trades[0].fx_rate_to_base, 1818.18 / 2000.0, places=5)
        self.assertIn("USD/EUR", en_ledger.conversion_rates)

        self.assertEqual(nl_ledger.trades[0].isin, "NL0010273215")
        self.assertAlmostEqual(nl_ledger.trades[0].price, 710.50)
        self.assertEqual(nl_ledger.flows[1].kind, FlowKind.WITHHOLDING_TAX)

        self.assertEqual(len(de_ledger.trades), 2)
        self.assertEqual(de_ledger.trades[0].isin, "IE00B4L5Y983")
        self.assertEqual(de_ledger.trades[0].asset_class, AssetClass.ETF)
        self.assertEqual(de_ledger.trades[1].isin, "US5949181045")
        self.assertAlmostEqual(de_ledger.trades[1].fx_rate_to_base, 1600.0 / 1760.0, places=5)

    def test_robinhood_and_schwab_offline_csv_and_scraper_credential_hard_block(self) -> None:
        # Hard-block unofficial Robinhood / DEGIRO username, password, session_cookie, or TOTP scraping
        scraper_attempts: list[dict[str, str]] = [
            {"username": "trader@example.com", "password": "pw"},
            {"session_cookie": "sid=abc123"},
            {"totp": "123456"},
            {"totp_secret": "JBSWY3DPEHPK3PXP"},
            {"mfa_code": "654321"},
        ]
        for creds in scraper_attempts:
            with self.assertRaises(UnsupportedScraperPolicyError):
                create_connector("robinhood", **creds)
            with self.assertRaises(UnsupportedScraperPolicyError):
                create_connector("degiro", **creds)
            with self.assertRaises(UnsupportedScraperPolicyError):
                RobinhoodOfflineCsvAdapter(**creds)
            with self.assertRaises(UnsupportedScraperPolicyError):
                DegiroOfflineCsvAdapter(**creds)
            with self.assertRaises(UnsupportedScraperPolicyError):
                parse_robinhood_csv("Activity Date,Instrument\n", **creds)

        rh_csv = (
            "Activity Date,Process Date,Settle Date,Instrument,Description,Trans Code,Quantity,Price,Amount\n"
            "01/03/2026,01/03/2026,01/03/2026,,ACH Deposit,ACH,,,$5000.00\n"
            "01/06/2026,01/06/2026,01/07/2026,AAPL,Apple Inc,Buy,10,$210.50,($2105.00)\n"
            "01/09/2026,01/09/2026,01/10/2026,AAPL,AAPL 02/20/2026 Call $225.00,BTO,1,$3.40,($340.00)\n"
            "01/15/2026,01/15/2026,01/15/2026,AAPL,Cash Dividend,CDIV,,,$12.50\n"
            "01/20/2026,01/20/2026,01/20/2026,NVDA,Forward Split,SPL,90,,\n"
        )
        rh_ledger = RobinhoodOfflineCsvAdapter().parse_export(rh_csv, blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(rh_ledger.claimed_origin_assurance, OriginAssurance.SELF_REPORTED)
        self.assertEqual(rh_ledger.account_scope, AccountScope.UNKNOWN_OFFLINE_SCOPE)
        self.assertEqual(len(rh_ledger.trades), 2)
        self.assertEqual(rh_ledger.trades[1].asset_class, AssetClass.OPTION)
        self.assertEqual(len(rh_ledger.flows), 2)
        self.assertEqual(len(rh_ledger.corporate_actions), 1)

        schwab_csv = (
            '"Transactions for account Individual ...999 as of 01/31/2026"\n'
            '"Date","Action","Symbol","Description","Quantity","Price","Fees & Comm","Amount"\n'
            '"01/04/2026","MoneyLink Deposit","","Electronic Deposit","","","","$10,000.00"\n'
            '"01/15/2026 as of 01/14/2026","Journal","","Journal from IRA","","","","$2,500.00"\n'
            '"01/18/2026","Buy","VTI","VANGUARD TOTAL STOCK MKT","20","$290.00","$0.00","-$5,800.00"\n'
            '"Transactions Total","","","","","","","$6,700.00"\n'
        )
        sc_ledger = SchwabOfflineCsvAdapter().parse_export(schwab_csv, blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(sc_ledger.claimed_origin_assurance, OriginAssurance.SELF_REPORTED)
        self.assertEqual(sc_ledger.account_scope, AccountScope.UNKNOWN_OFFLINE_SCOPE)
        self.assertEqual(len(sc_ledger.trades), 1)
        self.assertEqual(sc_ledger.flows[0].kind, FlowKind.DEPOSIT)
        self.assertEqual(sc_ledger.flows[1].kind, FlowKind.INTERNAL_SUBACCOUNT_TRANSFER)


if __name__ == "__main__":
    unittest.main()
