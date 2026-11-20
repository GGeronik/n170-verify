"""Fail-first tests for multi-year IBKR Activity Flex v3 & SnapTrade sync readiness."""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any
import unittest
import urllib.parse

from n170_verify.connectors import HttpExchangeResponse
from n170_verify.connectors.ibkr_flex import (
    IBKR_FLEX_GET_STATEMENT_URL,
    IBKR_FLEX_SEND_REQUEST_URL,
    IbkrFlexOfflineAdapter,
    IbkrFlexParseError,
    IbkrFlexWebServiceAdapter,
    parse_ibkr_flex_xml,
    split_ibkr_flex_date_chunks,
)
from n170_verify.connectors import snaptrade as _snaptrade_mod
from n170_verify.connectors.snaptrade import SnapTradeReadOnlyAdapter
from n170_verify.contracts import OriginAssurance, ReconciliationStatus
from n170_verify.crypto import (
    PublisherKeyRecord,
    PublisherKeyRegistryDocument,
    generate_ed25519_keypair,
)
from n170_verify.performance import calculate_portfolio_performance_detailed
from n170_verify.pipeline import verify_portfolio
from n170_verify.reconciliation import reconcile_portfolio_ledger


_SALT = "c4" * 32
_ISSUED = "2026-11-19T15:00:00Z"


def _business_days(start: date, end: date) -> list[date]:
    out: list[date] = []
    cur = start
    while cur <= end:
        if cur.weekday() < 5:
            out.append(cur)
        cur += timedelta(days=1)
    return out


def _build_chunk_xml(
    *,
    account_id: str = "U7654321",
    base_currency: str = "EUR",
    from_date: date,
    to_date: date,
    starting_cash: float,
    starting_stock: float,
    daily_ret: float = 0.0008,
    prior_qty: float = 0.0,
    ending_qty: float = 10.0,
    buy_on: tuple[date, float, float, float] | None = None,
    trades_xml: str = "",
    cash_xml: str = "",
    conv_rate: float = 0.92,
    deposit_on: tuple[date, float] | None = None,
    include_change_in_nav_twr_pct: float | None = None,
) -> tuple[bytes, float, float]:
    days = _business_days(from_date, to_date)
    cash_val = starting_cash
    stock_val = starting_stock
    eq_rows: list[str] = []
    conv_rows: list[str] = []
    starting_nav = round(cash_val + stock_val, 2)
    for idx, d in enumerate(days):
        if buy_on is not None and d == buy_on[0]:
            b_qty, b_price_usd, b_comm_usd = buy_on[1], buy_on[2], buy_on[3]
            trade_cost_eur = round(b_qty * b_price_usd * conv_rate, 2)
            comm_eur = round(b_comm_usd * conv_rate, 2)
            cash_val = round(cash_val - trade_cost_eur - comm_eur, 2)
            stock_val = round(stock_val + trade_cost_eur, 2)
        if (idx > 0 or prior_qty > 0.0) and stock_val > 0.0:
            stock_val = round(stock_val * (1.0 + daily_ret), 2)
        if deposit_on is not None and d == deposit_on[0]:
            cash_val = round(cash_val + deposit_on[1], 2)
        nav = round(cash_val + stock_val, 2)
        eq_rows.append(
            f'<EquitySummaryByReportDateInBase accountId="{account_id}" '
            f'reportDate="{d.isoformat()}" cash="{cash_val:.2f}" '
            f'stock="{stock_val:.2f}" options="0.00" dividendAccruals="0.00" '
            f'interestAccruals="0.00" total="{nav:.2f}" />'
        )
        conv_rows.append(
            f'<ConversionRate reportDate="{d.isoformat()}" '
            f'fromCurrency="USD" toCurrency="{base_currency}" rate="{conv_rate:.4f}" />'
        )

    ending_price_usd = round((stock_val / conv_rate) / ending_qty, 4) if ending_qty > 0 else 0.0
    prior_price_usd = round((starting_stock / conv_rate) / prior_qty, 4) if prior_qty > 0 else 0.0

    prior_xml = ""
    if prior_qty > 0:
        prior_xml = (
            f'<PriorPeriodPosition accountId="{account_id}" symbol="MSFT" '
            f'assetCategory="STK" position="{prior_qty}" currency="USD" '
            f'fxRateToBase="{conv_rate:.4f}" positionValue="{prior_qty * prior_price_usd:.2f}" '
            f'costBasisMoney="{prior_qty * 170.0:.2f}" levelOfDetail="SUMMARY" />'
        )
    open_xml = ""
    if ending_qty > 0:
        open_xml = (
            f'<OpenPosition accountId="{account_id}" symbol="MSFT" '
            f'assetCategory="STK" position="{ending_qty}" currency="USD" '
            f'fxRateToBase="{conv_rate:.4f}" positionValue="{ending_qty * ending_price_usd:.2f}" '
            f'costBasisMoney="{ending_qty * 170.0:.2f}" levelOfDetail="SUMMARY" />'
        )

    final_nav = round(cash_val + stock_val, 2)
    change_nav_xml = ""
    if include_change_in_nav_twr_pct is not None:
        dep_amt = deposit_on[1] if deposit_on is not None else 0.0
        change_nav_xml = (
            f'<ChangeInNAV accountId="{account_id}" '
            f'fromDate="{from_date.isoformat()}" toDate="{to_date.isoformat()}" '
            f'startingValue="{starting_nav:.2f}" depositsWithdrawals="{dep_amt:.2f}" '
            f'endingValue="{final_nav:.2f}" twr="{include_change_in_nav_twr_pct:.6f}" />'
        )

    stmt = (
        f'<FlexStatement accountId="{account_id}" baseCurrency="{base_currency}" '
        f'fromDate="{from_date.isoformat()}" toDate="{to_date.isoformat()}">'
        f"{change_nav_xml}"
        f"<EquitySummaryInBase>{''.join(eq_rows)}</EquitySummaryInBase>"
        f"<PriorPeriodPositions>{prior_xml}</PriorPeriodPositions>"
        f"<OpenPositions>{open_xml}</OpenPositions>"
        f"<Trades>{trades_xml}</Trades>"
        f"<CashTransactions>{cash_xml}</CashTransactions>"
        f"<Transfers></Transfers>"
        f"<CorporateActions></CorporateActions>"
        f"<OptionEAE></OptionEAE>"
        f"<ConversionRates>{''.join(conv_rows)}</ConversionRates>"
        f"</FlexStatement>"
    )
    return stmt.encode("utf-8"), cash_val, stock_val


class IbkrMultiYearFlexTests(unittest.TestCase):
    def test_multi_statement_single_account_eur_with_usd_equities_reconciles_cleanly(self) -> None:
        buy_xml = (
            '<Trade accountId="U7654321" ibExecID="EXEC-2024-01" symbol="MSFT" '
            'assetCategory="STK" buySell="BUY" quantity="10" tradePrice="170.00" '
            'ibCommission="-1.00" taxes="0.00" currency="USD" fxRateToBase="0.9200" '
            'dateTime="2024-09-03;14:35:00" levelOfDetail="EXECUTION" />'
        )
        s2024, cash_2024, stock_2024 = _build_chunk_xml(
            from_date=date(2024, 9, 2),
            to_date=date(2024, 12, 31),
            starting_cash=10000.0,
            starting_stock=0.0,
            prior_qty=0.0,
            ending_qty=10.0,
            buy_on=(date(2024, 9, 3), 10.0, 170.0, 1.0),
            trades_xml=buy_xml,
        )
        s2025, cash_2025, stock_2025 = _build_chunk_xml(
            from_date=date(2025, 1, 2),
            to_date=date(2025, 12, 31),
            starting_cash=cash_2024,
            starting_stock=stock_2024,
            prior_qty=10.0,
            ending_qty=10.0,
        )
        s2026, _, _ = _build_chunk_xml(
            from_date=date(2026, 1, 2),
            to_date=date(2026, 11, 18),
            starting_cash=cash_2025,
            starting_stock=stock_2025,
            prior_qty=10.0,
            ending_qty=10.0,
        )
        combined = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<FlexQueryResponse queryName="MultiYear" type="AF"><FlexStatements count="3">'
            + s2024
            + s2025
            + s2026
            + b"</FlexStatements></FlexQueryResponse>"
        )

        ledger = parse_ibkr_flex_xml(combined, blinding_salt_hex=_SALT)
        self.assertEqual(ledger.base_currency, "EUR")
        self.assertEqual(ledger.connected_subaccount_count, 1)
        self.assertEqual(ledger.period_start_utc, "2024-09-02T00:00:00Z")
        self.assertEqual(ledger.period_end_utc, "2026-11-18T23:59:59Z")
        self.assertEqual(len(ledger.prior_positions), 0)
        self.assertEqual(len(ledger.ending_positions), 1)
        self.assertEqual(ledger.ending_positions[0].quantity, 10.0)

        recon = reconcile_portfolio_ledger(ledger)
        self.assertIn(
            recon.status,
            {
                ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE,
                ReconciliationStatus.REFERENCE_DATA_UNAVAILABLE,
            },
        )
        self.assertEqual(recon.discrepancy_count, 0)

        perf = calculate_portfolio_performance_detailed(ledger)
        self.assertFalse(perf.withheld)
        self.assertIsNotNone(perf.summary.cagr_decimal)
        self.assertTrue(perf.summary.psr_sample_eligible)
        self.assertIsNotNone(perf.summary.capital_bracket)

    def test_missing_cross_currency_fx_rate_is_refused_never_defaulted_to_one(self) -> None:
        bad_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <FlexQueryResponse queryName="MissingFX" type="AF">
          <FlexStatements count="1">
            <FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="2026-01-02" toDate="2026-01-05">
              <EquitySummaryInBase>
                <EquitySummaryByReportDateInBase reportDate="2026-01-02" total="10000.00" />
                <EquitySummaryByReportDateInBase reportDate="2026-01-05" total="10100.00" />
              </EquitySummaryInBase>
              <Trades>
                <Trade accountId="U7654321" ibExecID="T-NO-FX" symbol="AAPL" assetCategory="STK"
                       buySell="BUY" quantity="5" tradePrice="200.00" currency="USD"
                       dateTime="2026-01-02;15:00:00" levelOfDetail="EXECUTION" />
              </Trades>
            </FlexStatement>
          </FlexStatements>
        </FlexQueryResponse>"""
        with self.assertRaises(IbkrFlexParseError) as ctx:
            parse_ibkr_flex_xml(bad_xml, blinding_salt_hex=_SALT)
        self.assertIn("USD", str(ctx.exception))
        self.assertIn("EUR", str(ctx.exception))

    def test_web_service_auto_chunks_multiyear_range_and_handles_large_eur_deposit_via_broker_twr(self) -> None:
        buy_xml = (
            '<Trade accountId="U7654321" ibExecID="EXEC-2024-01" symbol="MSFT" '
            'assetCategory="STK" buySell="BUY" quantity="10" tradePrice="170.00" '
            'ibCommission="-1.00" taxes="0.00" currency="USD" fxRateToBase="0.9200" '
            'dateTime="2024-09-03;14:35:00" levelOfDetail="EXECUTION" />'
        )
        deposit_date = date(2025, 3, 10)
        deposit_cash_xml = (
            '<CashTransaction accountId="U7654321" type="Deposits/Withdrawals" '
            'description="Wire Deposit" currency="EUR" fxRateToBase="1.0" '
            'amount="5000.00" dateTime="2025-03-10;11:00:00" />'
        )

        s2024, cash_2024, stock_2024 = _build_chunk_xml(
            from_date=date(2024, 9, 2),
            to_date=date(2024, 12, 31),
            starting_cash=10000.0,
            starting_stock=0.0,
            prior_qty=0.0,
            ending_qty=10.0,
            buy_on=(date(2024, 9, 3), 10.0, 170.0, 1.0),
            trades_xml=buy_xml,
        )
        days_before_dep = _business_days(date(2025, 1, 2), date(2025, 3, 7))
        cur_stock = stock_2024
        for _ in days_before_dep:
            cur_stock = round(cur_stock * 1.0008, 2)
        nav_pre_dep = round(cash_2024 + cur_stock, 2)
        stock_close_dep = round(cur_stock * 1.0008, 2)
        nav_close_dep = round(cash_2024 + 5000.0 + stock_close_dep, 2)
        exact_day_twr_pct = ((nav_close_dep - 5000.0) / nav_pre_dep - 1.0) * 100.0

        s2025, cash_2025, stock_2025 = _build_chunk_xml(
            from_date=date(2025, 1, 2),
            to_date=date(2025, 12, 31),
            starting_cash=cash_2024,
            starting_stock=stock_2024,
            prior_qty=10.0,
            ending_qty=10.0,
            cash_xml=deposit_cash_xml,
            deposit_on=(deposit_date, 5000.0),
        )
        s2026, _, _ = _build_chunk_xml(
            from_date=date(2026, 1, 2),
            to_date=date(2026, 11, 18),
            starting_cash=cash_2025,
            starting_stock=stock_2025,
            prior_qty=10.0,
            ending_qty=10.0,
        )

        def _wrap(stmt_bytes: bytes) -> bytes:
            return (
                b'<?xml version="1.0" encoding="UTF-8"?>'
                b'<FlexQueryResponse queryName="AF" type="AF"><FlexStatements count="1">'
                + stmt_bytes
                + b"</FlexStatements></FlexQueryResponse>"
            )

        one_day_dep_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<FlexQueryResponse queryName="AF" type="AF"><FlexStatements count="1">'
            + (
                f'<FlexStatement accountId="U7654321" baseCurrency="EUR" '
                f'fromDate="2025-03-10" toDate="2025-03-10">'
                f'<ChangeInNAV accountId="U7654321" fromDate="2025-03-10" toDate="2025-03-10" '
                f'startingValue="{nav_pre_dep:.2f}" depositsWithdrawals="5000.00" '
                f'endingValue="{nav_close_dep:.2f}" twr="{exact_day_twr_pct:.6f}" />'
                f'<EquitySummaryInBase>'
                f'<EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2025-03-10" total="{nav_close_dep:.2f}" />'
                f'</EquitySummaryInBase>'
                f'</FlexStatement>'
            ).encode("utf-8")
            + b"</FlexStatements></FlexQueryResponse>"
        )

        seen_send_windows: list[tuple[str | None, str | None]] = []
        sleeps: list[float] = []
        by_ref: dict[str, bytes] = {
            "REF-2024": _wrap(s2024),
            "REF-2025": _wrap(s2025),
            "REF-2026": _wrap(s2026),
            "REF-DEP": one_day_dep_xml,
        }

        def transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> HttpExchangeResponse:
            parsed = urllib.parse.urlsplit(url)
            qs = urllib.parse.parse_qs(parsed.query)
            if url.startswith(IBKR_FLEX_SEND_REQUEST_URL):
                fd = qs.get("fd", [None])[0]
                td = qs.get("td", [None])[0]
                seen_send_windows.append((fd, td))
                if (fd, td) == ("20240902", "20241231"):
                    ref = "REF-2024"
                elif (fd, td) == ("20250101", "20251231"):
                    ref = "REF-2025"
                elif (fd, td) == ("20260101", "20261118"):
                    ref = "REF-2026"
                elif (fd, td) == ("20250310", "20250310"):
                    ref = "REF-DEP"
                else:
                    raise AssertionError(f"Unexpected SendRequest window: {(fd, td)}")
                envelope = (
                    f"<FlexStatementResponse><Status>Success</Status>"
                    f"<ReferenceCode>{ref}</ReferenceCode>"
                    f"<Url>https://gdcdyn.interactivebrokers.com/deprecated</Url>"
                    f"</FlexStatementResponse>"
                ).encode("utf-8")
                return HttpExchangeResponse(status_code=200, headers={}, body=envelope)
            if url.startswith(IBKR_FLEX_GET_STATEMENT_URL):
                ref = qs["q"][0]
                return HttpExchangeResponse(status_code=200, headers={}, body=by_ref[ref])
            raise AssertionError(f"Unexpected URL: {url}")

        pub_kp = generate_ed25519_keypair(bytes.fromhex("77" * 32))
        pub_kid = f"n170-pub-{pub_kp.key_id}"
        reg_doc = PublisherKeyRegistryDocument(
            updated_at_utc=_ISSUED,
            keys=[
                PublisherKeyRecord(
                    publisher_kid=pub_kid,
                    public_key_hex=pub_kp.public_key_hex,
                    status="active",
                    issuer_org="N170",
                    not_before_utc="2024-01-01T00:00:00Z",
                )
            ]
        )
        adapter = IbkrFlexWebServiceAdapter(
            http_transport=transport,
            sleep_fn=sleeps.append,
        )
        out = verify_portfolio(
            connector=adapter,
            connector_fetch_kwargs={
                "flex_token": "FLEX-SECRET-TOKEN-999",
                "query_id": "887766",
                "start_date": "2024-09-02",
                "end_date": "2026-11-18",
            },
            blinding_salt_hex=_SALT,
            publisher_private_key_hex=pub_kp.private_key_hex,
            publisher_kid=pub_kid,
            registry_doc=reg_doc,
            issued_at_utc=_ISSUED,
        )
        self.assertEqual(
            seen_send_windows,
            [
                ("20240902", "20241231"),
                ("20250101", "20251231"),
                ("20260101", "20261118"),
                ("20250310", "20250310"),
            ],
        )
        self.assertGreaterEqual(len(sleeps), 3)
        self.assertFalse(out.performance_withheld)
        self.assertEqual(out.verification.effective_origin_assurance, OriginAssurance.OPERATOR_RETRIEVED)
        self.assertAlmostEqual(out.performance.twr_decimal, 0.0669585, places=4)
        self.assertIsNotNone(out.performance.cagr_decimal)
        self.assertTrue(out.performance.psr_sample_eligible)

        # Self-reported offline XML with the exact same >10% deposit and embedded <ChangeInNAV>
        # MUST NOT trust self-reported twr to bypass LARGE_INTERVAL_FLOW_FRACTION!
        forged_offline_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<FlexQueryResponse queryName="Offline" type="AF"><FlexStatements count="3">'
            + s2024
            + s2025.replace(
                b"<EquitySummaryInBase>",
                (
                    f'<ChangeInNAV accountId="U7654321" fromDate="2025-03-10" toDate="2025-03-10" '
                    f'startingValue="{nav_pre_dep:.2f}" depositsWithdrawals="5000.00" '
                    f'endingValue="{nav_close_dep:.2f}" twr="{exact_day_twr_pct:.6f}" />'
                    f"<EquitySummaryInBase>"
                ).encode("utf-8"),
            )
            + s2026
            + b"</FlexStatements></FlexQueryResponse>"
        )
        offline_ledger = IbkrFlexOfflineAdapter().parse_export(
            forged_offline_xml, blinding_salt_hex=_SALT
        )
        offline_perf = calculate_portfolio_performance_detailed(offline_ledger)
        self.assertTrue(offline_perf.withheld)

    def test_leap_year_date_chunking_and_missing_fx_rate_rejection(self) -> None:
        leap_chunks = split_ibkr_flex_date_chunks(date(2024, 1, 1), date(2024, 12, 31))
        self.assertEqual(
            leap_chunks,
            [("20240101", "20241230"), ("20241231", "20241231")],
        )
        for fd_str, td_str in split_ibkr_flex_date_chunks(date(2024, 1, 1), date(2026, 11, 18)):
            fd_d = date.fromisoformat(f"{fd_str[:4]}-{fd_str[4:6]}-{fd_str[6:8]}")
            td_d = date.fromisoformat(f"{td_str[:4]}-{td_str[4:6]}-{td_str[6:8]}")
            self.assertLessEqual((td_d - fd_d).days + 1, 365)

        missing_fx_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<FlexQueryResponse queryName="MissingFx" type="AF"><FlexStatements count="1">'
            b'<FlexStatement accountId="U7654321" fromDate="2024-09-02" toDate="2024-09-03">'
            b'<AccountInformation accountId="U7654321" currency="EUR" />'
            b'<EquitySummaryInBase>'
            b'<EquitySummaryByReportDateInBase reportDate="2024-09-02" cash="10000.00" stock="0.00" total="10000.00" />'
            b'<EquitySummaryByReportDateInBase reportDate="2024-09-03" cash="9000.00" stock="1000.00" total="10000.00" />'
            b'</EquitySummaryInBase>'
            b'<Trades>'
            b'<Trade transactionID="T1" tradeDate="2024-09-03" dateTime="2024-09-03;15:30:00" '
            b'symbol="MSFT" assetCategory="STK" buySell="BUY" quantity="3" tradePrice="400.00" '
            b'ibCommission="-1.00" ibCommissionCurrency="USD" currency="USD" />'
            b'</Trades>'
            b'<CashTransactions /><OpenPositions /><CorporateActions />'
            b'</FlexStatement></FlexStatements></FlexQueryResponse>'
        )
        with self.assertRaises(IbkrFlexParseError):
            parse_ibkr_flex_xml(missing_fx_xml, blinding_salt_hex=_SALT)

    def test_change_in_nav_percentage_points_base_summary_and_ten_monthly_deposits(self) -> None:
        from n170_verify.contracts import AccountScope, ProviderApprovalState

        # 1. Omitted depositsWithdrawals on +100% deposit day: twr="1.00" is +1.00% (0.01), never +100% (1.0)
        omitted_dep_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <FlexQueryResponse queryName="AF" type="AF"><FlexStatements count="1">
        <FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="2025-03-07" toDate="2025-03-10">
          <ChangeInNAV accountId="U7654321" fromDate="2025-03-10" toDate="2025-03-10"
                       startingValue="10000.00" endingValue="20200.00" twr="1.00" />
          <ChangeInNAV accountId="U7654321" fromDate="2025-01-01" toDate="2025-03-10"
                       startingValue="8000.00" endingValue="20200.00" twr="14.50" />
          <EquitySummaryInBase>
            <EquitySummaryByReportDateInBase accountId="U7654321" currency="BASE_SUMMARY" reportDate="2025-03-07" total="10000.00" />
            <EquitySummaryByReportDateInBase accountId="U7654321" currency="BASE_SUMMARY" reportDate="2025-03-10" total="20200.00" />
          </EquitySummaryInBase>
          <CashTransactions>
            <CashTransaction accountId="U7654321" type="Deposits/Withdrawals" currency="BASE_SUMMARY"
                             amount="10000.00" reportDate="2025-03-10" levelOfDetail="BASE_SUMMARY" />
            <CashTransaction accountId="U7654321" type="Deposits/Withdrawals" currency="EUR"
                             amount="10000.00" reportDate="2025-03-10" levelOfDetail="CURRENCY" />
            <CashTransaction accountId="U7654321" type="Deposits/Withdrawals" description="Wire Deposit"
                             currency="EUR" fxRateToBase="1.0" amount="10000.00"
                             dateTime="2025-03-10;10:00:00" levelOfDetail="DETAIL" />
          </CashTransactions>
        </FlexStatement></FlexStatements></FlexQueryResponse>"""
        ldg_omitted = parse_ibkr_flex_xml(
            omitted_dep_xml,
            blinding_salt_hex=_SALT,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
        )
        self.assertEqual(len(ldg_omitted.flows), 1)
        self.assertAlmostEqual(ldg_omitted.flows[0].amount, 10000.0)
        self.assertAlmostEqual(ldg_omitted.broker_period_returns["2025-03-10T23:59:59Z"], 0.01)

        # 2. Intraday rally + large deposit + afternoon dip with near-zero negative twr="-0.02" (-0.02% == -0.0002)
        near_zero_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <FlexQueryResponse queryName="AF" type="AF"><FlexStatements count="1">
        <FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="2025-03-07" toDate="2025-03-10">
          <ChangeInNAV accountId="U7654321" fromDate="2025-03-10" toDate="2025-03-10"
                       startingValue="10000.00" depositsWithdrawals="20000.00"
                       endingValue="29421.30" twr="-0.02" />
          <EquitySummaryInBase>
            <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2025-03-07" total="10000.00" />
            <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2025-03-10" total="29421.30" />
          </EquitySummaryInBase>
        </FlexStatement></FlexStatements></FlexQueryResponse>"""
        ldg_near_zero = parse_ibkr_flex_xml(
            near_zero_xml,
            blinding_salt_hex=_SALT,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
        )
        self.assertAlmostEqual(ldg_near_zero.broker_period_returns["2025-03-10T23:59:59Z"], -0.0002)

        # 3. 10 monthly >10% deposits (including a Saturday-settled wire) enrich cleanly via Flex Web Service
        days = _business_days(date(2025, 1, 2), date(2025, 6, 30))
        deposit_indices = [5, 15, 25, 35, 45, 55, 65, 75, 85, 95]
        nav = 2000.0
        eq_rows: list[str] = []
        cash_rows: list[str] = []
        probe_xml_by_window: dict[tuple[str, str], bytes] = {}
        for idx, d in enumerate(days):
            prev_nav = nav
            if idx > 0:
                nav = round(nav * 1.001, 2)
            if idx in deposit_indices:
                dep_amt = round(prev_nav * 0.25, 2)
                nav = round(nav + dep_amt, 2)
                # First deposit settles on the Saturday before Monday d if d is Monday, testing multi-day probe window
                prev_d = days[idx - 1]
                flow_d = prev_d + timedelta(days=1) if (d - prev_d).days > 1 else d
                cash_rows.append(
                    f'<CashTransaction accountId="U7654321" type="Deposits/Withdrawals" '
                    f'description="Monthly DCA" currency="EUR" fxRateToBase="1.0" '
                    f'amount="{dep_amt:.2f}" dateTime="{flow_d.isoformat()};09:00:00" levelOfDetail="DETAIL" />'
                )
                fd_key = flow_d.strftime("%Y%m%d")
                td_key = d.strftime("%Y%m%d")
                probe_xml_by_window[(fd_key, td_key)] = (
                    f'<?xml version="1.0" encoding="UTF-8"?>'
                    f'<FlexQueryResponse queryName="AF" type="AF"><FlexStatements count="1">'
                    f'<FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="{flow_d.isoformat()}" toDate="{d.isoformat()}">'
                    f'<ChangeInNAV accountId="U7654321" fromDate="{flow_d.isoformat()}" toDate="{d.isoformat()}" '
                    f'startingValue="{prev_nav:.2f}" endingValue="{nav:.2f}" twr="0.100000" />'
                    f'<EquitySummaryInBase>'
                    f'<EquitySummaryByReportDateInBase accountId="U7654321" reportDate="{d.isoformat()}" total="{nav:.2f}" />'
                    f'</EquitySummaryInBase>'
                    f'</FlexStatement></FlexStatements></FlexQueryResponse>'
                ).encode("utf-8")
            eq_rows.append(
                f'<EquitySummaryByReportDateInBase accountId="U7654321" reportDate="{d.isoformat()}" total="{nav:.2f}" />'
            )

        base_chunk_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<FlexQueryResponse queryName="AF" type="AF"><FlexStatements count="1">'
            f'<FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="2025-01-02" toDate="2025-06-30">'
            f"<EquitySummaryInBase>{''.join(eq_rows)}</EquitySummaryInBase>"
            f"<CashTransactions>{''.join(cash_rows)}</CashTransactions>"
            "</FlexStatement></FlexStatements></FlexQueryResponse>"
        ).encode("utf-8")

        ref_map: dict[str, bytes] = {"REF-MAIN": base_chunk_xml}

        def dca_transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> HttpExchangeResponse:
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            if url.startswith(IBKR_FLEX_SEND_REQUEST_URL):
                fd = qs["fd"][0]
                td = qs["td"][0]
                if (fd, td) == ("20250102", "20250630"):
                    ref = "REF-MAIN"
                else:
                    ref = f"REF-{fd}-{td}"
                    ref_map[ref] = probe_xml_by_window[(fd, td)]
                return HttpExchangeResponse(
                    status_code=200,
                    headers={},
                    body=f"<FlexStatementResponse><Status>Success</Status><ReferenceCode>{ref}</ReferenceCode></FlexStatementResponse>".encode(),
                )
            return HttpExchangeResponse(status_code=200, headers={}, body=ref_map[qs["q"][0]])

        dca_adapter = IbkrFlexWebServiceAdapter(http_transport=dca_transport, sleep_fn=lambda _s: None)
        dca_ledger = dca_adapter.fetch_canonical_ledger(
            flex_token="TOK-DCA",
            query_id="998877",
            blinding_salt_hex=_SALT,
            start_date="2025-01-02",
            end_date="2025-06-30",
        )
        self.assertEqual(len(dca_ledger.broker_period_returns), 10)
        dca_perf = calculate_portfolio_performance_detailed(dca_ledger)
        self.assertFalse(dca_perf.withheld)


class SnapTradeSyncReadinessTests(unittest.TestCase):
    def test_fetch_sync_status_and_initial_sync_pending_guard(self) -> None:
        state: dict[str, Any] = {"tx_synced": False}

        def fake_st_transport(
            method: str, url: str, headers: dict[str, str], body: bytes | None
        ) -> HttpExchangeResponse:
            path = urllib.parse.urlsplit(url).path
            if path == "/api/v1/authorizations":
                return HttpExchangeResponse(
                    status_code=200,
                    headers={},
                    body=b'[{"id":"auth-1","brokerage":{"slug":"INTERACTIVE-BROKERS-FLEX"},"disabled":false}]',
                )
            if path == "/api/v1/accounts":
                tx_done = "true" if state["tx_synced"] else "false"
                payload = (
                    '[{"id":"acct-secret-999","number":"U7654321","name":"Main EUR",'
                    '"balance":{"total":{"amount":25000.0,"currency":"EUR"}},'
                    '"sync_status":{'
                    '"holdings":{"initial_sync_completed":true},'
                    f'"transactions":{{"initial_sync_completed":{tx_done},"first_transaction_date":"2024-09-02"}}'
                    "}}]"
                ).encode("utf-8")
                return HttpExchangeResponse(status_code=200, headers={}, body=payload)
            raise AssertionError(f"Unexpected SnapTrade path: {path}")

        adapter = SnapTradeReadOnlyAdapter(
            client_id="N170-DEV-CLIENT",
            consumer_key="dev-consumer-secret",
            http_transport=fake_st_transport,
            auto_register_slot=False,
        )
        self.assertTrue(hasattr(adapter, "fetch_sync_status"), "fetch_sync_status missing")
        status_pending = adapter.fetch_sync_status("n170-st-user1", "sec-123")
        self.assertEqual(status_pending["linked_authorizations"], 1)
        self.assertEqual(status_pending["accounts_count"], 1)
        self.assertTrue(status_pending["holdings_synced"])
        self.assertFalse(status_pending["transactions_synced"])
        self.assertEqual(status_pending["first_transaction_date"], "2024-09-02")
        self.assertFalse(status_pending["ready_to_verify"])
        serialized = str(status_pending)
        self.assertNotIn("acct-secret-999", serialized)
        self.assertNotIn("U7654321", serialized)
        self.assertNotIn("sec-123", serialized)

        pending_err_cls = getattr(_snaptrade_mod, "SnapTradeInitialSyncPendingError")
        pending_msg = getattr(_snaptrade_mod, "SNAPTRADE_INITIAL_SYNC_PENDING_MESSAGE")
        with self.assertRaises(pending_err_cls) as ctx:
            adapter.fetch_live_ledger(
                "n170-st-user1",
                "sec-123",
                blinding_salt_hex=_SALT,
            )
        self.assertIn(pending_msg, str(ctx.exception))

        state["tx_synced"] = True
        status_ready = adapter.fetch_sync_status("n170-st-user1", "sec-123")
        self.assertTrue(status_ready["transactions_synced"])
        self.assertTrue(status_ready["ready_to_verify"])


class Round2EurUsdAndSnapTradeIntegrityTests(unittest.TestCase):
    def test_26month_eur_base_usd_equities_cash_conversions_and_fx_drift_reconcile(self) -> None:
        """Issue 1: EUR-base IBKR account converting EUR->USD via <Trade assetCategory='CASH' symbol='EUR.USD'>,
        buying USD equities, paying ibCommission in EUR, and holding USD cash across 2024-2026 EUR/USD moves
        (>250 bps) must NOT pollute equity trade_count/round-trips or trigger false UNEXPLAINED_RESIDUAL.
        """
        from n170_verify.coaching import compute_cost_and_drag_breakdown, match_fifo_round_trips
        from n170_verify.coaching.engine import _compute_asset_class_mix_pct
        from n170_verify.contracts import AssetClass

        # Sep 2024: EUR/USD = 1.1000 (USD/EUR = 0.90909091).
        # Deposit 50,000 EUR on 2024-09-02 (opening day).
        # Convert 40,000 EUR -> USD on 2024-09-03 via SELL 40,000 EUR.USD @ 1.0985 (15 bps spread vs 1.1000)
        #   EUR cash: 50,000 - 40,000 - 2.00 (ibCommission in EUR) = 9,998.00 EUR
        #   USD cash: +43,940.00 USD
        # Buy 100 NVDA @ 120.00 USD on 2024-09-04, comm = 1.00 USD:
        #   USD cash: 43,940.00 - 12,000.00 - 1.00 = 31,939.00 USD
        # Sell 40 NVDA @ 150.00 USD on 2025-05-15 (USD/EUR = 0.9250), comm = 1.00 USD:
        #   USD cash: 31,939.00 + 6,000.00 - 1.00 = 37,938.00 USD
        #   Remaining NVDA: 60 shares
        # Nov 2026 (2026-11-18): EUR/USD moved to 1.0400 (USD/EUR = 0.96153846, +5.77% USD appreciation!).
        #   Ending NVDA: 60 shares @ 180.00 USD = 10,800.00 USD -> 10,384.62 EUR
        #   Ending cash: 9,998.00 EUR + 37,938.00 USD * 0.96153846 = 9,998.00 + 36,478.85 = 46,476.85 EUR
        #   Ending NAV = 56,861.47 EUR (USD cash FX gain alone is ~+1,990 EUR = ~350 bps >> 60 bps cap!).
        fx_start = round(1.0 / 1.10, 8)
        fx_mid = 0.9250
        fx_end = round(1.0 / 1.04, 8)

        nav_rows: list[str] = []
        conv_rows: list[str] = []
        bdays = _business_days(date(2024, 9, 2), date(2026, 11, 18))
        n_days = len(bdays)
        for idx, d in enumerate(bdays):
            frac = idx / max(1, n_days - 1)
            fx_d = round(fx_start + (fx_end - fx_start) * frac, 8)
            if d == date(2024, 9, 2):
                fx_d = fx_start
                eur_c, usd_c, sh, px = 50_000.0, 0.0, 0.0, 120.0
            elif d == date(2024, 9, 3):
                fx_d = fx_start
                eur_c, usd_c, sh, px = 9_998.0, 43_940.0, 0.0, 120.0
            elif d < date(2025, 5, 15):
                eur_c, usd_c, sh = 9_998.0, 31_939.0, 100.0
                px = round(120.0 + 30.0 * (idx / n_days), 4)
            elif d == date(2025, 5, 15):
                fx_d = fx_mid
                eur_c, usd_c, sh, px = 9_998.0, 37_938.0, 60.0, 150.0
            else:
                eur_c, usd_c, sh = 9_998.0, 37_938.0, 60.0
                px = 180.0 if d == date(2026, 11, 18) else round(150.0 + 30.0 * frac, 4)
            if d == date(2026, 11, 18):
                fx_d = fx_end
            cash_eur = round(eur_c + usd_c * fx_d, 2)
            stock_eur = round(sh * px * fx_d, 2)
            tot_eur = round(cash_eur + stock_eur, 2)
            nav_rows.append(
                f'<EquitySummaryByReportDateInBase accountId="U9988776" reportDate="{d.isoformat()}" '
                f'cash="{cash_eur:.2f}" stock="{stock_eur:.2f}" options="0.00" '
                f'dividendAccruals="0.00" interestAccruals="0.00" total="{tot_eur:.2f}" />'
            )
            conv_rows.append(
                f'<ConversionRate reportDate="{d.isoformat()}" fromCurrency="USD" toCurrency="EUR" rate="{fx_d:.8f}" />'
            )

        xml_doc = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<FlexQueryResponse queryName="EUR_USD_26M" type="AF"><FlexStatements count="1">'
            '<FlexStatement accountId="U9988776" baseCurrency="EUR" fromDate="2024-09-02" toDate="2026-11-18">'
            '<AccountInformation accountId="U9988776" currency="EUR" />'
            f'<EquitySummaryInBase>{"".join(nav_rows)}</EquitySummaryInBase>'
            '<PriorPeriodPositions />'
            '<OpenPositions>'
            f'<OpenPosition accountId="U9988776" symbol="NVDA" assetCategory="STK" position="60" '
            f'currency="USD" fxRateToBase="{fx_end:.8f}" costBasisMoney="7200.60" '
            f'positionValue="10800.00" levelOfDetail="SUMMARY" />'
            '</OpenPositions>'
            '<Trades>'
            f'<Trade accountId="U9988776" ibExecID="FX-CONV-1" symbol="EUR.USD" assetCategory="CASH" '
            f'buySell="SELL" quantity="-40000" tradePrice="1.0985" currency="USD" '
            f'fxRateToBase="{fx_start:.8f}" ibCommission="-2.00" ibCommissionCurrency="EUR" '
            f'exchange="IDEALPRO" dateTime="2024-09-03;10:15:00" levelOfDetail="EXECUTION" />'
            f'<Trade accountId="U9988776" ibExecID="STK-BUY-1" symbol="NVDA" assetCategory="STK" '
            f'buySell="BUY" quantity="100" tradePrice="120.00" currency="USD" '
            f'fxRateToBase="{fx_start:.8f}" ibCommission="-1.00" ibCommissionCurrency="USD" '
            f'exchange="NASDAQ" dateTime="2024-09-04;14:30:00" levelOfDetail="EXECUTION" />'
            f'<Trade accountId="U9988776" ibExecID="STK-SELL-1" symbol="NVDA" assetCategory="STK" '
            f'buySell="SELL" quantity="-40" tradePrice="150.00" currency="USD" '
            f'fxRateToBase="{fx_mid:.8f}" ibCommission="-1.00" ibCommissionCurrency="USD" '
            f'exchange="NASDAQ" dateTime="2025-05-15;15:00:00" levelOfDetail="EXECUTION" />'
            '</Trades>'
            '<CashTransactions>'
            '<CashTransaction accountId="U9988776" type="Deposits/Withdrawals" currency="EUR" '
            'amount="50000.00" dateTime="2024-09-02;09:00:00" description="Initial Wire" />'
            '</CashTransactions>'
            '<Transfers /><CorporateActions /><OptionEAE />'
            f'<ConversionRates>{"".join(conv_rows)}</ConversionRates>'
            '</FlexStatement></FlexStatements></FlexQueryResponse>'
        ).encode("utf-8")

        ledger = parse_ibkr_flex_xml(
            xml_doc,
            blinding_salt_hex=_SALT,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
        )
        fx_conv_trade = next(t for t in ledger.trades if t.symbol == "EUR.USD")
        self.assertEqual(fx_conv_trade.asset_class, AssetClass.CASH)
        # ibCommission="-2.00" in ibCommissionCurrency="EUR" must equal 2.00 EUR when multiplied by fx_rate_to_base
        self.assertAlmostEqual(fx_conv_trade.commission * fx_conv_trade.fx_rate_to_base, 2.0, places=5)

        trips = match_fifo_round_trips(ledger)
        self.assertEqual(len(trips), 1)
        self.assertEqual(trips[0].symbol, "NVDA")
        self.assertEqual(_compute_asset_class_mix_pct(ledger), {"equity": 100.0})

        perf = calculate_portfolio_performance_detailed(ledger)
        self.assertFalse(perf.withheld)
        total_cal_trades = sum(c.trade_count for c in perf.summary.daily_calendar_cells)
        self.assertEqual(total_cal_trades, 2)  # Only the 2 NVDA trades, NOT EUR.USD cash conversion!

        drag = compute_cost_and_drag_breakdown(
            ledger,
            forex_midpoints={"2024-09-03": {"EUR/USD": 1.1000}},
        )
        self.assertGreater(drag.fx_conversion_drag_bps or 0.0, 0.5)
        self.assertGreater(drag.commission_and_fee_drag_bps or 0.0, 0.5)

        rec = reconcile_portfolio_ledger(ledger)
        self.assertNotEqual(rec.status, ReconciliationStatus.UNEXPLAINED_RESIDUAL)
        self.assertEqual(rec.discrepancy_count, 0)

        # Genuine +10% ending NAV tampering on the exact same EUR/USD ledger MUST still fail!
        tampered_dict = ledger.to_dict()
        tampered_dict["nav_points"][-1]["nav_base"] = round(ledger.nav_points[-1].nav_base * 1.10, 2)
        from n170_verify.contracts import CanonicalPortfolioLedger
        tampered_rec = reconcile_portfolio_ledger(CanonicalPortfolioLedger.from_dict(tampered_dict))
        self.assertEqual(tampered_rec.status, ReconciliationStatus.UNEXPLAINED_RESIDUAL)
        self.assertGreaterEqual(tampered_rec.discrepancy_count, 1)

    def test_ibkr_10_req_per_min_1018_backoff_and_missing_change_in_nav_deposit_handling(self) -> None:
        """Issue 2: Survive >12s of IBKR code=1018 rate-limiting on probe #8+, document ChangeInNAV
        in get_ibkr_flex_setup_guide, and score daily broker-retrieved EquitySummaryInBase series
        with >10% deposits when ChangeInNAV is omitted while preserving H1 wipeout & coarse guards.
        """
        from n170_verify.connectors import get_ibkr_flex_setup_guide

        guide = get_ibkr_flex_setup_guide()
        guide_str = str(guide.to_dict())
        self.assertIn("ChangeInNAV", guide_str)

        # Part A: 12 consecutive code=1018 responses (~42s window) on probe #8 must NOT drop TWR
        b2025, _, _ = _build_chunk_xml(
            from_date=date(2025, 1, 2),
            to_date=date(2025, 4, 30),
            starting_cash=10_000.0,
            starting_stock=0.0,
            prior_qty=0.0,
            ending_qty=0.0,
            deposit_on=(date(2025, 2, 10), 5_000.0),
            cash_xml=(
                '<CashTransaction accountId="U7654321" type="Deposits/Withdrawals" currency="EUR" '
                'amount="5000.00" dateTime="2025-02-10;10:00:00" description="Topup" />'
            ),
        )
        main_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<FlexQueryResponse queryName="AF" type="AF"><FlexStatements count="1">'
            + b2025.replace(
                b"<EquitySummaryInBase>",
                b'<ChangeInNAV accountId="U7654321" fromDate="2025-01-02" toDate="2025-04-30" '
                b'startingValue="10000.00" endingValue="15000.00" twr="0.00" /><EquitySummaryInBase>',
            )
            + b"</FlexStatements></FlexQueryResponse>"
        )
        day_probe_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<FlexQueryResponse queryName="AF" type="AF"><FlexStatements count="1">'
            b'<FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="2025-02-10" toDate="2025-02-10">'
            b'<ChangeInNAV accountId="U7654321" fromDate="2025-02-10" toDate="2025-02-10" '
            b'startingValue="10000.00" depositsWithdrawals="5000.00" endingValue="15000.00" twr="0.00" />'
            b'<EquitySummaryInBase>'
            b'<EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2025-02-10" total="15000.00" />'
            b'</EquitySummaryInBase></FlexStatement></FlexStatements></FlexQueryResponse>'
        )
        rate_limit_hits = 0

        def rate_limited_transport(
            method: str, url: str, headers: dict[str, str], body: bytes | None
        ) -> HttpExchangeResponse:
            nonlocal rate_limit_hits
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            if url.startswith(IBKR_FLEX_SEND_REQUEST_URL):
                fd = qs.get("fd", [""])[0]
                if fd == "20250210" and rate_limit_hits < 12:
                    rate_limit_hits += 1
                    return HttpExchangeResponse(
                        status_code=200,
                        headers={},
                        body=(
                            b"<FlexStatementResponse><Status>Warn</Status>"
                            b"<ErrorCode>1018</ErrorCode>"
                            b"<ErrorMessage>Too many requests. Please try again shortly.</ErrorMessage>"
                            b"</FlexStatementResponse>"
                        ),
                    )
                ref = "REF-MAIN" if fd == "20250102" else "REF-DAY"
                return HttpExchangeResponse(
                    status_code=200,
                    headers={},
                    body=f"<FlexStatementResponse><Status>Success</Status><ReferenceCode>{ref}</ReferenceCode></FlexStatementResponse>".encode(),
                )
            ref = qs["q"][0]
            return HttpExchangeResponse(
                status_code=200,
                headers={},
                body=main_xml if ref == "REF-MAIN" else day_probe_xml,
            )

        rl_adapter = IbkrFlexWebServiceAdapter(
            http_transport=rate_limited_transport,
            sleep_fn=lambda _s: None,
        )
        rl_ledger = rl_adapter.fetch_canonical_ledger(
            flex_token="TOK-RL",
            query_id="112233",
            blinding_salt_hex=_SALT,
            start_date="2025-01-02",
            end_date="2025-04-30",
        )
        self.assertEqual(rate_limit_hits, 12)
        self.assertIn("2025-02-10T23:59:59Z", rl_ledger.broker_period_returns)

        # Part B: Activity Flex Query WITHOUT ChangeInNAV enabled at all + >10% deposit (+50%)
        no_cin_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<FlexQueryResponse queryName="AF_NO_CIN" type="AF"><FlexStatements count="1">'
            + b2025
            + b"</FlexStatements></FlexQueryResponse>"
        )
        no_cin_ledger = parse_ibkr_flex_xml(
            no_cin_xml,
            blinding_salt_hex=_SALT,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
        )
        self.assertEqual(no_cin_ledger.broker_period_returns, {})
        no_cin_perf = calculate_portfolio_performance_detailed(no_cin_ledger)
        self.assertFalse(no_cin_perf.withheld)

        # Guard check: H1 wipeout hidden by same-day deposit on OPERATOR_RETRIEVED without ChangeInNAV MUST withhold!
        wipe_dict = no_cin_ledger.to_dict()
        for pt in wipe_dict["nav_points"]:
            if pt["timestamp_utc"].startswith("2025-02-10"):
                pt["nav_base"] = 5_500.0  # Pre-deposit 10k collapsed to 500 (-95%) hidden by +5k deposit!
        from n170_verify.contracts import CanonicalPortfolioLedger
        wipe_perf = calculate_portfolio_performance_detailed(
            CanonicalPortfolioLedger.from_dict(wipe_dict)
        )
        self.assertTrue(wipe_perf.withheld)

    def test_snaptrade_activities_pagination_fails_closed_and_empty_prior_positions_avoids_false_residual(
        self,
    ) -> None:
        """Issue 4: SnapTrade must fail closed on 10 full pages of activities (H4) and avoid
        false UNEXPLAINED_RESIDUAL when prior_positions is empty on pre-existing holdings.
        """
        page_calls = 0

        def paginated_transport(
            method: str, url: str, headers: dict[str, str], body: bytes | None
        ) -> HttpExchangeResponse:
            nonlocal page_calls
            path = urllib.parse.urlsplit(url).path
            if path == "/api/v1/accounts":
                return HttpExchangeResponse(
                    status_code=200,
                    headers={},
                    body=(
                        b'[{"id":"acct-1","number":"U111111","currency":"USD",'
                        b'"balance":{"total":{"amount":50000.0,"currency":"USD"},"updated_at":"2026-11-18T21:00:00Z"},'
                        b'"sync_status":{"holdings":{"initial_sync_completed":true},"transactions":{"initial_sync_completed":true}}}]'
                    ),
                )
            if path == "/api/v1/holdings":
                return HttpExchangeResponse(
                    status_code=200,
                    headers={},
                    body=(
                        b'[{"account":{"id":"acct-1","currency":"USD"},'
                        b'"total_value":{"value":50000.0,"currency":"USD"},'
                        b'"balances":[{"cash":30000.0,"currency":{"code":"USD"}}],'
                        b'"positions":[{"symbol":{"symbol":{"symbol":"AAPL","currency":{"code":"USD"}}},"units":100,"price":200.0}]}]'
                    ),
                )
            if path == "/api/v1/activities":
                page_calls += 1
                items = [
                    {
                        "id": f"act-{page_calls}-{i}",
                        "account": {"id": "acct-1"},
                        "type": "DIVIDEND",
                        "amount": 1.0,
                        "currency": {"code": "USD"},
                        "trade_date": "2026-11-18T12:00:00Z",
                    }
                    for i in range(_snaptrade_mod.MAX_ACTIVITIES_PAGE_SIZE)
                ]
                import json
                return HttpExchangeResponse(status_code=200, headers={}, body=json.dumps(items).encode())
            raise AssertionError(f"Unexpected path: {path}")

        adapter = SnapTradeReadOnlyAdapter(
            client_id="N170-DEV-CLIENT",
            consumer_key="dev-consumer-secret",
            http_transport=paginated_transport,
            auto_register_slot=False,
        )
        with self.assertRaises(ValueError) as p_ctx:
            adapter.fetch_live_ledger("n170-st-u1", "sec-1", blinding_salt_hex=_SALT)
        self.assertIn("pagination", str(p_ctx.exception).lower())

        # Pre-existing holding (100 AAPL bought prior to snapshot, 0 activities today)
        snap_ledger = adapter.parse_payload(
            {
                "accounts": [{"id": "acct-1", "currency": "USD"}],
                "holdings": [
                    {
                        "account": {"id": "acct-1", "currency": "USD"},
                        "total_value": {"value": 50_000.0, "currency": "USD"},
                        "balances": [{"cash": 30_000.0, "currency": {"code": "USD"}}],
                        "positions": [
                            {
                                "symbol": {"symbol": {"symbol": "AAPL", "currency": {"code": "USD"}}},
                                "units": 100.0,
                                "price": 200.0,
                            }
                        ],
                        "updated_at": "2026-11-18T21:00:00Z",
                    }
                ],
                "activities": [],
            },
            blinding_salt_hex=_SALT,
        )
        snap_rec = reconcile_portfolio_ledger(snap_ledger)
        self.assertEqual(snap_rec.status, ReconciliationStatus.INSUFFICIENT_SECTIONS)
        self.assertNotEqual(snap_rec.status, ReconciliationStatus.UNEXPLAINED_RESIDUAL)

    def test_day1_funding_fxconv_midlife_multiccy_cashreport_and_self_reported_inflation_guard(
        self,
    ) -> None:
        """Day-1 funding + EUR.USD conversion + USD stock buy, fxRateToBase-only multi-year
        revaluation, mid-life EUR/USD/GBP <CashReportCurrency> + USD withholding tax all
        reconcile with 0 discrepancies, while SELF_REPORTED +14% fake NAV inflation fails.
        """
        # 1. Day-1 deposit + EUR.USD FXCONV + USD AAPL buy after pre-funding 0.0 days trimmed
        xml_day1 = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<FlexQueryResponse queryName="Day1" type="AF"><FlexStatements count="1">'
            b'<FlexStatement accountId="U1234567" baseCurrency="EUR" fromDate="20240901" toDate="20261119">'
            b'<EquitySummaryInBase>'
            b'<EquitySummaryByReportDateInBase reportDate="20240909" total="0" cash="0" stock="0" currency="BASE_SUMMARY"/>'
            b'<EquitySummaryByReportDateInBase reportDate="20240910" total="10088.00" cash="1815.27" stock="8272.73" currency="BASE_SUMMARY"/>'
            b'<EquitySummaryByReportDateInBase reportDate="20261119" total="11390.19" cash="1854.19" stock="9536.00" currency="BASE_SUMMARY"/>'
            b'</EquitySummaryInBase>'
            b'<PriorPeriodPositions/>'
            b'<OpenPositions>'
            b'<OpenPosition symbol="AAPL" assetCategory="STK" position="50" markToMarket="10012.80" '
            b'positionValue="10012.80" costBasisMoney="9001.00" currency="USD" fxRateToBase="0.95238095" levelOfDetail="SUMMARY"/>'
            b'</OpenPositions>'
            b'<Trades>'
            b'<Trade ibExecID="fx1" symbol="EUR.USD" assetCategory="CASH" exchange="FXCONV" buySell="SELL" '
            b'quantity="-9000" tradePrice="1.10" currency="USD" fxRateToBase="0.90909091" '
            b'ibCommission="-2.0" ibCommissionCurrency="EUR" dateTime="20240910;140000" levelOfDetail="EXECUTION"/>'
            b'<Trade ibExecID="eq1" symbol="AAPL" assetCategory="STK" buySell="BUY" quantity="50" '
            b'tradePrice="180.00" currency="USD" fxRateToBase="0.90909091" ibCommission="-1.0" '
            b'ibCommissionCurrency="USD" dateTime="20240910;143000" levelOfDetail="EXECUTION"/>'
            b'</Trades>'
            b'<CashTransactions>'
            b'<CashTransaction type="Deposits/Withdrawals" description="Wire Deposit" amount="10000" '
            b'currency="EUR" fxRateToBase="1.0" dateTime="20240910;101500"/>'
            b'</CashTransactions>'
            b'<Transfers/><CorporateActions/><OptionEAE/>'
            b'<ConversionRates>'
            b'<ConversionRate reportDate="20240910" fromCurrency="USD" toCurrency="EUR" rate="0.90909091"/>'
            b'<ConversionRate reportDate="20261119" fromCurrency="USD" toCurrency="EUR" rate="0.95238095"/>'
            b'</ConversionRates>'
            b'</FlexStatement></FlexStatements></FlexQueryResponse>'
        )
        rec_day1 = reconcile_portfolio_ledger(parse_ibkr_flex_xml(xml_day1, blinding_salt_hex=_SALT))
        self.assertEqual(rec_day1.discrepancy_count, 0, rec_day1.findings)

        # 2. Row-level fxRateToBase without <ConversionRates> must keep latest 2026 rate (not 2024 setdefault)
        xml_no_cr = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<FlexQueryResponse queryName="NoCR" type="AF"><FlexStatements count="1">'
            b'<FlexStatement accountId="U1234567" baseCurrency="EUR" fromDate="20240901" toDate="20261119">'
            b'<EquitySummaryInBase>'
            b'<EquitySummaryByReportDateInBase reportDate="20240901" total="10000.00" cash="10000.00" stock="0" currency="BASE_SUMMARY"/>'
            b'<EquitySummaryByReportDateInBase reportDate="20261119" total="10888.89" cash="10888.89" stock="0" currency="BASE_SUMMARY"/>'
            b'</EquitySummaryInBase>'
            b'<PriorPeriodPositions/><OpenPositions/>'
            b'<Trades>'
            b'<Trade ibExecID="fx1" symbol="EUR.USD" assetCategory="CASH" exchange="FXCONV" buySell="SELL" '
            b'quantity="-10000" tradePrice="1.11111111" currency="USD" fxRateToBase="0.90" '
            b'ibCommission="0" dateTime="20240902;100000" levelOfDetail="EXECUTION"/>'
            b'</Trades>'
            b'<CashTransactions>'
            b'<CashTransaction type="Deposits/Withdrawals" description="Wire Deposit" amount="10000" '
            b'currency="EUR" fxRateToBase="1.0" dateTime="20240901;100000"/>'
            b'<CashTransaction type="Broker Interest Received" description="USD Credit Interest" amount="100" '
            b'currency="USD" fxRateToBase="0.97125" dateTime="20261119;080000"/>'
            b'</CashTransactions>'
            b'<Transfers/><CorporateActions/><OptionEAE/>'
            b'</FlexStatement></FlexStatements></FlexQueryResponse>'
        )
        ldg_no_cr = parse_ibkr_flex_xml(xml_no_cr, blinding_salt_hex=_SALT)
        self.assertAlmostEqual(ldg_no_cr.conversion_rates["USD/EUR"], 0.97125, places=6)
        rec_no_cr = reconcile_portfolio_ledger(ldg_no_cr)
        self.assertEqual(rec_no_cr.discrepancy_count, 0, rec_no_cr.findings)

        # 3. Mid-life EUR-base account with USD + GBP cash (<CashReportCurrency>), PriorPeriodPositions,
        # GBP->EUR conversion, and USD dividend + withholding tax
        # Opening 2025-01-02: EUR=2000, USD=10000 (@0.95 = 9500 EUR), GBP=5000 (@1.20 = 6000 EUR) -> cash=17500 EUR
        #   Prior MSFT: 20 sh @ $400 = $8000 (@0.95 = 7600 EUR) -> opening NAV = 25100 EUR
        # 2025-06-10: Dividend $100 USD - $15 USD withholding tax -> USD cash = 10085 USD
        #   Convert 2000 GBP -> EUR via SELL 2000 GBP.EUR @ 1.18 -> GBP cash = 3000 GBP, EUR cash = 4360 EUR
        # Closing 2026-11-19: USD/EUR=0.98, GBP/EUR=1.15, MSFT=20 @ $450 = $9000 (8820 EUR)
        #   Closing cash = 4360 + 10085*0.98 (9883.30) + 3000*1.15 (3450.00) = 17693.30 EUR
        #   Closing NAV = 17693.30 + 8820.00 = 26513.30 EUR
        xml_midlife = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<FlexQueryResponse queryName="MidLife3Ccy" type="AF"><FlexStatements count="1">'
            b'<FlexStatement accountId="U1234567" baseCurrency="EUR" fromDate="20250102" toDate="20261119">'
            b'<EquitySummaryInBase>'
            b'<EquitySummaryByReportDateInBase reportDate="20250102" total="25100.00" cash="17500.00" stock="7600.00" currency="BASE_SUMMARY"/>'
            b'<EquitySummaryByReportDateInBase reportDate="20261119" total="26513.30" cash="17693.30" stock="8820.00" currency="BASE_SUMMARY"/>'
            b'</EquitySummaryInBase>'
            b'<CashReport>'
            b'<CashReportCurrency currency="BASE_SUMMARY" startingCash="17500.00" levelOfDetail="BASE_SUMMARY"/>'
            b'<CashReportCurrency currency="EUR" startingCash="2000.00" fxRateToBase="1.0" fromDate="20250102" levelOfDetail="CURRENCY"/>'
            b'<CashReportCurrency currency="USD" startingCash="10000.00" fxRateToBase="0.95" fromDate="20250102" levelOfDetail="CURRENCY"/>'
            b'<CashReportCurrency currency="GBP" startingCash="5000.00" fxRateToBase="1.20" fromDate="20250102" levelOfDetail="CURRENCY"/>'
            b'</CashReport>'
            b'<PriorPeriodPositions>'
            b'<PriorPeriodPosition symbol="MSFT" assetCategory="STK" position="20" positionValue="8000.00" '
            b'costBasisMoney="7000.00" currency="USD" fxRateToBase="0.95" reportDate="20250102" levelOfDetail="SUMMARY"/>'
            b'</PriorPeriodPositions>'
            b'<OpenPositions>'
            b'<OpenPosition symbol="MSFT" assetCategory="STK" position="20" positionValue="9000.00" '
            b'costBasisMoney="7000.00" currency="USD" fxRateToBase="0.98" reportDate="20261119" levelOfDetail="SUMMARY"/>'
            b'</OpenPositions>'
            b'<Trades>'
            b'<Trade ibExecID="gbpfx1" symbol="GBP.EUR" assetCategory="CASH" exchange="FXCONV" buySell="SELL" '
            b'quantity="-2000" tradePrice="1.18" currency="EUR" fxRateToBase="1.0" ibCommission="0" '
            b'dateTime="20250610;110000" levelOfDetail="EXECUTION"/>'
            b'</Trades>'
            b'<CashTransactions>'
            b'<CashTransaction type="Dividends" description="MSFT Cash Dividend" symbol="MSFT" amount="100.00" '
            b'currency="USD" fxRateToBase="0.96" dateTime="20250610;090000"/>'
            b'<CashTransaction type="Withholding Tax" description="MSFT US Tax" symbol="MSFT" amount="-15.00" '
            b'currency="USD" fxRateToBase="0.96" dateTime="20250610;090001"/>'
            b'</CashTransactions>'
            b'<Transfers/><CorporateActions/><OptionEAE/>'
            b'<ConversionRates>'
            b'<ConversionRate reportDate="20261119" fromCurrency="USD" toCurrency="EUR" rate="0.98"/>'
            b'<ConversionRate reportDate="20261119" fromCurrency="GBP" toCurrency="EUR" rate="1.15"/>'
            b'</ConversionRates>'
            b'</FlexStatement></FlexStatements></FlexQueryResponse>'
        )
        rec_midlife = reconcile_portfolio_ledger(parse_ibkr_flex_xml(xml_midlife, blinding_salt_hex=_SALT))
        self.assertEqual(rec_midlife.discrepancy_count, 0, rec_midlife.findings)

        # 4. Adversarial SELF_REPORTED +14% fake NAV inflation with tiny $10 USD trade MUST fail!
        xml_fraud = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<FlexQueryResponse queryName="Fraud" type="AF"><FlexStatements count="1">'
            b'<FlexStatement accountId="U1234567" baseCurrency="EUR" fromDate="20240901" toDate="20261119">'
            b'<EquitySummaryInBase>'
            b'<EquitySummaryByReportDateInBase reportDate="20240901" total="100000.00" cash="100000.00" stock="0" currency="BASE_SUMMARY"/>'
            b'<EquitySummaryByReportDateInBase reportDate="20261119" total="114000.00" cash="114000.00" stock="0" currency="BASE_SUMMARY"/>'
            b'</EquitySummaryInBase>'
            b'<PriorPeriodPositions/><OpenPositions/>'
            b'<Trades>'
            b'<Trade ibExecID="f1" symbol="F" assetCategory="STK" buySell="BUY" quantity="1" tradePrice="10.00" '
            b'currency="USD" fxRateToBase="0.85" ibCommission="0" dateTime="20240902;140000" levelOfDetail="EXECUTION"/>'
            b'<Trade ibExecID="f2" symbol="F" assetCategory="STK" buySell="SELL" quantity="-1" tradePrice="10.00" '
            b'currency="USD" fxRateToBase="1.00" ibCommission="0" dateTime="20261118;140000" levelOfDetail="EXECUTION"/>'
            b'</Trades>'
            b'<CashTransactions/><Transfers/><CorporateActions/><OptionEAE/>'
            b'</FlexStatement></FlexStatements></FlexQueryResponse>'
        )
        rec_fraud = reconcile_portfolio_ledger(parse_ibkr_flex_xml(xml_fraud, blinding_salt_hex=_SALT))
        self.assertEqual(rec_fraud.status, ReconciliationStatus.UNEXPLAINED_RESIDUAL)
        self.assertGreaterEqual(rec_fraud.discrepancy_count, 1)


class Round3RegressionTests(unittest.TestCase):
    def test_intra_chunk_duplicate_flows_and_corporate_actions_preserved_across_merge(self) -> None:
        from n170_verify.connectors.ibkr_flex import merge_ibkr_flex_ledgers

        # Chunk 1 (2024) has TWO legitimate EUR 1,000 SEPA deposits at the same date/description
        # and TWO identical-shape OptionEAE / split entries in the same chunk; Chunk 2 (2025) overlaps
        # on 2024-12-31 with one flow that SHOULD deduplicate across chunks without dropping Chunk 1's pair.
        xml_2024 = b"""<?xml version="1.0" encoding="UTF-8"?>
        <FlexQueryResponse queryName="C1" type="AF"><FlexStatements count="1">
          <FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="2024-10-01" toDate="2024-12-31">
            <EquitySummaryInBase>
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2024-10-01" cash="10000.00" stock="0.00" total="10000.00" />
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2024-10-15" cash="12000.00" stock="0.00" total="12000.00" />
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2024-12-31" cash="12500.00" stock="0.00" total="12500.00" />
            </EquitySummaryInBase>
            <CashTransactions>
              <CashTransaction accountId="U7654321" type="Deposits/Withdrawals" description="SEPA Transfer"
                               currency="EUR" fxRateToBase="1.0" amount="1000.00" reportDate="2024-10-15" />
              <CashTransaction accountId="U7654321" type="Deposits/Withdrawals" description="SEPA Transfer"
                               currency="EUR" fxRateToBase="1.0" amount="1000.00" reportDate="2024-10-15" />
              <CashTransaction accountId="U7654321" type="Deposits/Withdrawals" description="YearEnd Topup"
                               currency="EUR" fxRateToBase="1.0" amount="500.00" reportDate="2024-12-31" />
            </CashTransactions>
            <OptionEAE>
              <OptionEAE accountId="U7654321" transactionType="Expiration" symbol="AAPL" currency="USD"
                         fxRateToBase="0.92" quantity="-1" strike="200" date="2024-11-15" />
              <OptionEAE accountId="U7654321" transactionType="Expiration" symbol="AAPL" currency="USD"
                         fxRateToBase="0.92" quantity="-1" strike="200" date="2024-11-15" />
            </OptionEAE>
          </FlexStatement>
        </FlexStatements></FlexQueryResponse>"""

        xml_2025 = b"""<?xml version="1.0" encoding="UTF-8"?>
        <FlexQueryResponse queryName="C2" type="AF"><FlexStatements count="1">
          <FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="2024-12-31" toDate="2025-01-10">
            <EquitySummaryInBase>
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2024-12-31" cash="12500.00" stock="0.00" total="12500.00" />
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2025-01-10" cash="12500.00" stock="0.00" total="12500.00" />
            </EquitySummaryInBase>
            <CashTransactions>
              <CashTransaction accountId="U7654321" type="Deposits/Withdrawals" description="YearEnd Topup"
                               currency="EUR" fxRateToBase="1.0" amount="500.00" reportDate="2024-12-31" />
            </CashTransactions>
          </FlexStatement>
        </FlexStatements></FlexQueryResponse>"""

        l1 = parse_ibkr_flex_xml(xml_2024, blinding_salt_hex=_SALT)
        l2 = parse_ibkr_flex_xml(xml_2025, blinding_salt_hex=_SALT)
        merged = merge_ibkr_flex_ledgers([l1, l2], raw_chunks=[xml_2024, xml_2025])
        oct15_flows = [f for f in merged.flows if f.timestamp_utc.startswith("2024-10-15")]
        dec31_flows = [f for f in merged.flows if f.timestamp_utc.startswith("2024-12-31")]
        self.assertEqual(len(oct15_flows), 2, "Intra-chunk duplicate EUR 1,000 deposits must be preserved")
        self.assertEqual(len(dec31_flows), 1, "Cross-chunk overlap on 2024-12-31 must still deduplicate")
        self.assertEqual(len(merged.corporate_actions), 2, "Intra-chunk duplicate OptionEAE rows must be preserved")

    def test_synthetic_trade_id_scoping_assurance_mismatch_unanchored_cin_and_broker_ret_scope(
        self,
    ) -> None:
        from n170_verify.connectors.ibkr_flex import merge_ibkr_flex_ledgers
        from n170_verify.contracts import AccountScope, EnvironmentTier, ProviderApprovalState

        # 1. Trades without ibExecID/tradeID across 2 chunks must NOT overwrite flex-trade-0
        c1_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <FlexQueryResponse queryName="T1" type="AF"><FlexStatements count="1">
          <FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="2024-10-01" toDate="2024-12-30">
            <EquitySummaryInBase>
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2024-10-01" total="10000.00" />
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2024-12-30" total="10500.00" />
            </EquitySummaryInBase>
            <Trades>
              <Trade accountId="U7654321" symbol="AAPL" assetCategory="STK" buySell="BUY" quantity="5"
                     tradePrice="200.00" currency="USD" fxRateToBase="0.92" dateTime="2024-10-02;15:00:00" />
            </Trades>
          </FlexStatement>
        </FlexStatements></FlexQueryResponse>"""
        c2_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <FlexQueryResponse queryName="T2" type="AF"><FlexStatements count="1">
          <FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="2024-12-31" toDate="2024-12-31">
            <ChangeInNAV accountId="U7654321" fromDate="2024-12-31" toDate="2024-12-31"
                         startingValue="99999.00" endingValue="10600.00" twr="50.0" />
            <EquitySummaryInBase>
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2024-12-31" total="10600.00" />
            </EquitySummaryInBase>
            <Trades>
              <Trade accountId="U7654321" symbol="MSFT" assetCategory="STK" buySell="BUY" quantity="3"
                     tradePrice="400.00" currency="USD" fxRateToBase="0.92" dateTime="2024-12-31;15:00:00" />
            </Trades>
          </FlexStatement>
        </FlexStatements></FlexQueryResponse>"""

        l1_op = parse_ibkr_flex_xml(
            c1_xml,
            blinding_salt_hex=_SALT,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
        )
        l2_op = parse_ibkr_flex_xml(
            c2_xml,
            blinding_salt_hex=_SALT,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
        )
        merged = merge_ibkr_flex_ledgers([l1_op, l2_op], raw_chunks=[c1_xml, c2_xml])
        self.assertEqual(len(merged.trades), 2, "Fallback synthetic trade IDs must not collide across chunks")
        # 2. 1-point chunk c2_xml had mismatched startingValue=99999.00 vs c1 closing 10500.00 -> must NOT enter broker_period_returns!
        self.assertNotIn("2024-12-31T23:59:59Z", merged.broker_period_returns)

        # Conversely, a 1-point chunk whose startingValue DOES match c1 closing 10500.00 verifies cleanly via raw_chunks
        c2_valid_cin = c2_xml.replace(b'startingValue="99999.00"', b'startingValue="10500.00"').replace(
            b'twr="50.0"', b'twr="0.952381"'
        )
        l2_valid = parse_ibkr_flex_xml(
            c2_valid_cin,
            blinding_salt_hex=_SALT,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
        )
        merged_valid = merge_ibkr_flex_ledgers([l1_op, l2_valid], raw_chunks=[c1_xml, c2_valid_cin])
        self.assertIn("2024-12-31T23:59:59Z", merged_valid.broker_period_returns)

        # 3. Merging chunks with mismatched assurance / approval / scope / environment_tier must raise IbkrFlexParseError
        l2_self = parse_ibkr_flex_xml(c2_xml, blinding_salt_hex=_SALT)
        with self.assertRaises(IbkrFlexParseError):
            merge_ibkr_flex_ledgers([l1_op, l2_self])

        l2_env_mismatch = parse_ibkr_flex_xml(
            c2_xml,
            blinding_salt_hex=_SALT,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
            environment_tier=EnvironmentTier.UNVERIFIED_OFFLINE,
        )
        with self.assertRaises(IbkrFlexParseError):
            merge_ibkr_flex_ledgers([l1_op, l2_env_mismatch])

        # 4. calculator.py must NOT let trusted_broker_ret override exact EOD valuation math on <=10% flow intervals!
        small_flow_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <FlexQueryResponse queryName="SmallFlow" type="AF"><FlexStatements count="1">
          <FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="2025-03-07" toDate="2025-03-10">
            <ChangeInNAV accountId="U7654321" fromDate="2025-03-10" toDate="2025-03-10"
                         startingValue="10000.00" endingValue="10100.00" twr="9.99" />
            <EquitySummaryInBase>
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2025-03-07" total="10000.00" />
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2025-03-10" total="10100.00" />
            </EquitySummaryInBase>
          </FlexStatement>
        </FlexStatements></FlexQueryResponse>"""
        small_ldg = parse_ibkr_flex_xml(
            small_flow_xml,
            blinding_salt_hex=_SALT,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
        )
        small_perf = calculate_portfolio_performance_detailed(small_ldg)
        # Exact EOD math: 10100 / 10000 - 1 = +0.01 (+1%), NOT the bogus 9.99% ChangeInNAV row!
        self.assertAlmostEqual(small_perf.summary.twr_decimal, 0.01, places=6)

    def test_connector_http_error_wrapping_1004_polling_ny_cutoff_and_1005_stepback(self) -> None:
        from datetime import datetime, timezone
        from n170_verify.connectors.ccxt_crypto import ConnectorHttpError
        from n170_verify.connectors.ibkr_flex import IbkrFlexServiceError
        from n170_verify.pipeline import api_worker_pipeline_entrypoint

        # 1. ConnectorHttpError in fetch_statement_bytes is wrapped in secret-redacted IbkrFlexServiceError
        def timeout_transport(
            method: str, url: str, headers: dict[str, str], body: bytes | None
        ) -> HttpExchangeResponse:
            raise ConnectorHttpError(0, f"Transport timeout contacting {url}")

        err_adapter = IbkrFlexWebServiceAdapter(http_transport=timeout_transport, sleep_fn=lambda _s: None)
        with self.assertRaises(IbkrFlexServiceError) as exc_ctx:
            err_adapter.fetch_statement_bytes(flex_token="SUPER-SECRET-FLEX-TOK", query_id="776655")
        self.assertNotIn("SUPER-SECRET-FLEX-TOK", str(exc_ctx.exception))
        self.assertNotIn("776655", str(exc_ctx.exception))

        # 2. Poll on err_code="1004" in SendRequest and GetStatement; NY date cutoff at 01:30 UTC;
        # and trailing 1005 step-back across a Jan 1-2 boundary skipping the unsettled 2026 chunk cleanly!
        send_calls: list[tuple[str | None, str | None]] = []
        get_attempts = 0
        send_1004_done = False

        y2025_bytes, _, _ = _build_chunk_xml(
            from_date=date(2025, 9, 2),
            to_date=date(2025, 12, 31),
            starting_cash=10_000.0,
            starting_stock=0.0,
            prior_qty=0.0,
            ending_qty=0.0,
        )
        wrapped_2025 = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<FlexQueryResponse queryName="AF" type="AF"><FlexStatements count="1">'
            + y2025_bytes
            + b"</FlexStatements></FlexQueryResponse>"
        )

        def ny_and_1005_transport(
            method: str, url: str, headers: dict[str, str], body: bytes | None
        ) -> HttpExchangeResponse:
            nonlocal get_attempts, send_1004_done
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            if url.startswith(IBKR_FLEX_SEND_REQUEST_URL):
                fd = qs.get("fd", [None])[0]
                td = qs.get("td", [None])[0]
                send_calls.append((fd, td))
                if not send_1004_done:
                    send_1004_done = True
                    return HttpExchangeResponse(
                        status_code=200,
                        headers={},
                        body=b"<FlexStatementResponse><Status>Warn</Status><ErrorCode>1004</ErrorCode><ErrorMessage>Statement is incomplete at this time.</ErrorMessage></FlexStatementResponse>",
                    )
                if fd == "20260101":
                    return HttpExchangeResponse(
                        status_code=200,
                        headers={},
                        body=b"<FlexStatementResponse><Status>Fail</Status><ErrorCode>1005</ErrorCode><ErrorMessage>Settlement data is not ready.</ErrorMessage></FlexStatementResponse>",
                    )
                return HttpExchangeResponse(
                    status_code=200,
                    headers={},
                    body=b"<FlexStatementResponse><Status>Success</Status><ReferenceCode>REF-2025</ReferenceCode></FlexStatementResponse>",
                )
            get_attempts += 1
            if get_attempts == 1:
                return HttpExchangeResponse(
                    status_code=200,
                    headers={},
                    body=b"<FlexStatementResponse><Status>Warn</Status><ErrorCode>1004</ErrorCode><ErrorMessage>Statement is incomplete.</ErrorMessage></FlexStatementResponse>",
                )
            return HttpExchangeResponse(status_code=200, headers={}, body=wrapped_2025)

        # 2026-01-02T02:00:00Z is 2026-01-01 21:00 EST in New York (NOT 2026-01-02!)
        ny_adapter = IbkrFlexWebServiceAdapter(
            http_transport=ny_and_1005_transport,
            sleep_fn=lambda _s: None,
            now_utc_fn=lambda: datetime(2026, 1, 2, 2, 0, 0, tzinfo=timezone.utc),
        )
        ny_ledger = ny_adapter.fetch_canonical_ledger(
            flex_token="TOK-NY",
            query_id="123456",
            blinding_salt_hex=_SALT,
            start_date="2025-09-02",
            end_date=None,
        )
        # First SendRequest window is 20250902..20251231 (retried once after 1004), then 20260101..20260101 (NY date, NOT 20260102!), which hits 1005 and steps back < fd_d -> skipped cleanly!
        self.assertIn(("20260101", "20260101"), send_calls)
        self.assertNotIn(("20260101", "20260102"), send_calls)
        self.assertEqual(ny_ledger.period_end_utc[:10], "2025-12-31")

        # 3. _WORKER_SERVER_ONLY_FETCH_KEYS blocks preloaded_xml_chunks and fetched_xml_chunks_out
        for forbidden_key in ("preloaded_xml_chunks", "fetched_xml_chunks_out"):
            with self.assertRaises(ValueError) as wk_ctx:
                api_worker_pipeline_entrypoint(
                    {
                        "broker_id": "ibkr_flex_web",
                        "connector_fetch_kwargs": {
                            "flex_token": "TOK-1",
                            "query_id": "123",
                            forbidden_key: [],
                        },
                    }
                )
            self.assertIn("set by the server", str(wk_ctx.exception))

    def test_same_day_clamping_preserves_broker_twr_wipeout_guard_and_linear_leap_year_merge(
        self,
    ) -> None:
        from n170_verify.connectors.ibkr_flex import (
            merge_ibkr_flex_ledgers,
            split_ibkr_flex_date_chunks,
        )
        from n170_verify.contracts import AccountScope, ProviderApprovalState

        # 1. Same-day NY close clamping (issued_at_utc on same UTC date as reportDate) must
        # re-key broker_period_returns so >10% flows on the issue date do NOT withhold!
        xml_same_day = b"""<?xml version="1.0" encoding="UTF-8"?>
        <FlexQueryResponse queryName="AF" type="AF"><FlexStatements count="1">
          <FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="2026-11-18" toDate="2026-11-19">
            <ChangeInNAV accountId="U7654321" fromDate="2026-11-19" toDate="2026-11-19"
                         startingValue="10000.00" depositsWithdrawals="-2000.00" endingValue="8200.00" twr="2.00" />
            <EquitySummaryInBase>
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2026-11-18" total="10000.00" />
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2026-11-19" total="8200.00" />
            </EquitySummaryInBase>
            <CashTransactions>
              <CashTransaction accountId="U7654321" type="Deposits/Withdrawals" description="SEPA Withdrawal"
                               currency="EUR" fxRateToBase="1.0" amount="-2000.00" dateTime="2026-11-19;10:00:00" />
            </CashTransactions>
          </FlexStatement>
        </FlexStatements></FlexQueryResponse>"""
        same_day_ldg = parse_ibkr_flex_xml(
            xml_same_day,
            blinding_salt_hex=_SALT,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
        )
        same_day_out = verify_portfolio(ledger=same_day_ldg, issued_at_utc="2026-11-19T22:15:00Z")
        self.assertFalse(same_day_out.performance_withheld)
        self.assertAlmostEqual(same_day_out.performance.twr_decimal, 0.02, places=6)

        # 2. Wipeout (close_val <= 0.0) on a >10% flow day with rounded ChangeInNAV twr="-99.99" MUST withhold (H1)!
        xml_wipe = b"""<?xml version="1.0" encoding="UTF-8"?>
        <FlexQueryResponse queryName="AF" type="AF"><FlexStatements count="1">
          <FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="2026-11-18" toDate="2026-11-19">
            <ChangeInNAV accountId="U7654321" fromDate="2026-11-19" toDate="2026-11-19"
                         startingValue="10000.00" depositsWithdrawals="2000.00" endingValue="0.00" twr="-99.99" />
            <EquitySummaryInBase>
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2026-11-18" total="10000.00" />
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2026-11-19" total="0.00" />
            </EquitySummaryInBase>
            <CashTransactions>
              <CashTransaction accountId="U7654321" type="Deposits/Withdrawals" description="Deposit"
                               currency="EUR" fxRateToBase="1.0" amount="2000.00" dateTime="2026-11-19;10:00:00" />
            </CashTransactions>
          </FlexStatement>
        </FlexStatements></FlexQueryResponse>"""
        wipe_ldg = parse_ibkr_flex_xml(
            xml_wipe,
            blinding_salt_hex=_SALT,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
        )
        wipe_perf = calculate_portfolio_performance_detailed(wipe_ldg)
        self.assertTrue(wipe_perf.withheld)

        # 3. Leap-year 2024 split ("20240101:20241230", "20241231:20241231", "20250101:20250110"):
        # 1-day Dec 31 chunk with two identical EUR 1,500 SEPA deposits (+30% > 10%) + ChangeInNAV
        # preserves both deposits, anchors startingValue against Dec 30 close, and parses each chunk ONCE!
        leap_chunks = split_ibkr_flex_date_chunks("2024-01-01", "2025-01-10")
        self.assertEqual(
            leap_chunks,
            [("20240101", "20241230"), ("20241231", "20241231"), ("20250101", "20250110")],
        )
        c_2024a = b"""<?xml version="1.0" encoding="UTF-8"?>
        <FlexQueryResponse queryName="LA" type="AF"><FlexStatements count="1">
          <FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="2024-01-01" toDate="2024-12-30">
            <EquitySummaryInBase>
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2024-12-27" total="10000.00" />
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2024-12-30" total="10000.00" />
            </EquitySummaryInBase>
          </FlexStatement>
        </FlexStatements></FlexQueryResponse>"""
        c_2024b = b"""<?xml version="1.0" encoding="UTF-8"?>
        <FlexQueryResponse queryName="LB" type="AF"><FlexStatements count="1">
          <FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="2024-12-31" toDate="2024-12-31">
            <ChangeInNAV accountId="U7654321" fromDate="2024-12-31" toDate="2024-12-31"
                         startingValue="10000.00" depositsWithdrawals="3000.00" endingValue="13130.00" twr="1.00" />
            <EquitySummaryInBase>
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2024-12-31" total="13130.00" />
            </EquitySummaryInBase>
            <CashTransactions>
              <CashTransaction accountId="U7654321" type="Deposits/Withdrawals" description="SEPA Transfer"
                               currency="EUR" fxRateToBase="1.0" amount="1500.00" dateTime="2024-12-31;09:00:00" />
              <CashTransaction accountId="U7654321" type="Deposits/Withdrawals" description="SEPA Transfer"
                               currency="EUR" fxRateToBase="1.0" amount="1500.00" dateTime="2024-12-31;09:00:00" />
            </CashTransactions>
          </FlexStatement>
        </FlexStatements></FlexQueryResponse>"""
        c_2025 = b"""<?xml version="1.0" encoding="UTF-8"?>
        <FlexQueryResponse queryName="LC" type="AF"><FlexStatements count="1">
          <FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="2025-01-01" toDate="2025-01-10">
            <EquitySummaryInBase>
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2025-01-02" total="13130.00" />
              <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2025-01-03" total="13261.30" />
            </EquitySummaryInBase>
          </FlexStatement>
        </FlexStatements></FlexQueryResponse>"""

        extract_calls = 0
        orig_extract = IbkrFlexWebServiceAdapter._extract_change_in_nav_candidates

        def count_extract(raw_xml: bytes) -> dict[str, list[tuple[str, float, float, float]]]:
            nonlocal extract_calls
            extract_calls += 1
            return orig_extract(raw_xml)

        IbkrFlexWebServiceAdapter._extract_change_in_nav_candidates = staticmethod(count_extract)  # type: ignore[method-assign]
        try:
            raws = [c_2024a, c_2024b, c_2025]
            ldgs = [
                parse_ibkr_flex_xml(
                    b,
                    blinding_salt_hex=_SALT,
                    claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
                    provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
                    account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
                )
                for b in raws
            ]
            leap_merged = merge_ibkr_flex_ledgers(ldgs, raw_chunks=raws)
        finally:
            IbkrFlexWebServiceAdapter._extract_change_in_nav_candidates = staticmethod(orig_extract)  # type: ignore[method-assign]

        self.assertEqual(extract_calls, 3, "merge_ibkr_flex_ledgers must parse each raw_chunk at most once")
        self.assertEqual(len(leap_merged.flows), 2)
        self.assertAlmostEqual(
            leap_merged.broker_period_returns["2024-12-31T23:59:59Z"], 0.01, places=6
        )
        leap_perf = calculate_portfolio_performance_detailed(leap_merged)
        self.assertFalse(leap_perf.withheld)

    def test_flex_web_service_accepts_verbose_statement_over_2mb_and_deduplicates_daily_open_positions(
        self,
    ) -> None:
        from n170_verify.connectors.ibkr_flex import IbkrFlexServiceError, IbkrFlexXmlSecurityError

        d0 = date(2025, 1, 2)
        d1 = date(2025, 4, 30)
        bdays = _business_days(d0, d1)
        eq_rows: list[str] = []
        open_pos_rows: list[str] = []
        conv_rows: list[str] = []
        cash_eur = 10_800.0
        px_usd = 100.0
        fx = 0.92
        pad_note = "IBKR verbose full-field attribute payload padding " * 6

        for idx, d in enumerate(bdays):
            if idx == 0:
                cash_eur = 10_800.0
            else:
                px_usd = round(px_usd * 1.002, 4)
            stock_eur = round(10.0 * px_usd * fx, 2)
            tot_eur = round(cash_eur + stock_eur, 2)
            eq_rows.append(
                f'<EquitySummaryByReportDateInBase accountId="U7654321" currency="BASE_SUMMARY" '
                f'reportDate="{d.isoformat()}" cash="{cash_eur:.2f}" stock="{stock_eur:.2f}" '
                f'options="0.00" dividendAccruals="0.00" interestAccruals="0.00" total="{tot_eur:.2f}" />'
            )
            # Simulate IBKR Activity Flex Query emitting OpenPosition rows for EVERY business day
            # PLUS LOT, SYMBOL_SUMMARY, and BASE_SUMMARY detail levels!
            mv_usd = round(10.0 * px_usd, 2)
            open_pos_rows.append(
                f'<OpenPosition accountId="U7654321" symbol="NVDA" assetCategory="STK" '
                f'currency="USD" fxRateToBase="{fx}" reportDate="{d.isoformat()}" '
                f'position="10" costBasisMoney="1000.00" positionValue="{mv_usd:.2f}" '
                f'levelOfDetail="SUMMARY" description="{pad_note}" />'
            )
            open_pos_rows.append(
                f'<OpenPosition accountId="U7654321" symbol="NVDA" assetCategory="STK" '
                f'currency="USD" fxRateToBase="{fx}" reportDate="{d.isoformat()}" '
                f'position="10" costBasisMoney="1000.00" positionValue="{mv_usd:.2f}" '
                f'levelOfDetail="LOT" description="{pad_note}" />'
            )
            open_pos_rows.append(
                f'<OpenPosition accountId="U7654321" symbol="NVDA" assetCategory="STK" '
                f'currency="BASE_SUMMARY" fxRateToBase="1.0" reportDate="{d.isoformat()}" '
                f'position="10" positionValue="{stock_eur:.2f}" levelOfDetail="BASE_SUMMARY" />'
            )
            for ccy in ("USD", "GBP", "CHF", "JPY", "CAD", "AUD", "SEK", "NOK", "DKK", "HKD"):
                conv_rows.append(
                    f'<ConversionRate reportDate="{d.isoformat()}" fromCurrency="{ccy}" '
                    f'toCurrency="EUR" rate="{fx}" comment="{pad_note}" />'
                )

        # Ensure statement exceeds legacy 2,097,152-byte _parse_flex_service_envelope ceiling
        unbundled_rows = [
            f'<UnbundledCommissionDetail accountId="U7654321" tradeID="T-{i}" note="{pad_note}" />'
            for i in range(4500)
        ]
        verbose_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<FlexQueryResponse queryName="VerboseAllOptions" type="AF"><FlexStatements count="1">'
            f'<FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="{d0.isoformat()}" toDate="{d1.isoformat()}">'
            '<AccountInformation accountId="U7654321" currency="EUR" />'
            f'<EquitySummaryInBase>{"".join(eq_rows)}</EquitySummaryInBase>'
            '<PriorPeriodPositions>'
            '<PriorPeriodPosition accountId="U7654321" symbol="EUR" assetCategory="CASH" currency="EUR" '
            f'fxRateToBase="1.0" reportDate="{d0.isoformat()}" position="20000.00" costBasisMoney="20000.00" positionValue="20000.00" levelOfDetail="SUMMARY" />'
            '</PriorPeriodPositions>'
            f'<OpenPositions>{"".join(open_pos_rows)}</OpenPositions>'
            '<Trades>'
            f'<Trade accountId="U7654321" ibExecID="EX-NVDA-1" symbol="NVDA" assetCategory="STK" '
            f'buySell="BUY" quantity="10" tradePrice="100.00" currency="USD" fxRateToBase="{fx}" '
            f'ibCommission="0.00" ibCommissionCurrency="USD" dateTime="{d0.isoformat()};14:30:00" levelOfDetail="EXECUTION" />'
            f'<Trade accountId="U7654321" tradeID="CL-1" symbol="NVDA" assetCategory="STK" '
            f'buySell="BUY" quantity="10" tradePrice="100.00" currency="USD" fxRateToBase="{fx}" '
            f'dateTime="{d0.isoformat()};14:30:00" levelOfDetail="CLOSED_LOT" />'
            f'<Trade accountId="U7654321" symbol="NVDA" assetCategory="STK" '
            f'quantity="10" currency="USD" fxRateToBase="{fx}" levelOfDetail="SYMBOL_SUMMARY" />'
            '</Trades>'
            '<CashTransactions /><Transfers /><CorporateActions /><OptionEAE />'
            f'<ConversionRates>{"".join(conv_rows)}</ConversionRates>'
            f'<UnbundledCommissionDetails>{"".join(unbundled_rows)}</UnbundledCommissionDetails>'
            '</FlexStatement></FlexStatements></FlexQueryResponse>'
        ).encode("utf-8")
        self.assertGreater(len(verbose_xml), 2 * 1024 * 1024 + 50_000)

        def verbose_transport(
            method: str, url: str, headers: dict[str, str], body: bytes | None
        ) -> HttpExchangeResponse:
            if url.startswith(IBKR_FLEX_SEND_REQUEST_URL):
                return HttpExchangeResponse(
                    status_code=200,
                    headers={},
                    body=b"<FlexStatementResponse><Status>Success</Status><ReferenceCode>REF-BIG-1</ReferenceCode></FlexStatementResponse>",
                )
            if url.startswith(IBKR_FLEX_GET_STATEMENT_URL):
                return HttpExchangeResponse(status_code=200, headers={}, body=verbose_xml)
            raise AssertionError(f"Unexpected URL: {url}")

        adapter = IbkrFlexWebServiceAdapter(
            http_transport=verbose_transport,
            sleep_fn=lambda _s: None,
        )
        ledger = adapter.fetch_canonical_ledger(
            flex_token="FLEX-TOK-BIG",
            query_id="123456",
            blinding_salt_hex=_SALT,
            start_date="2025-01-02",
            end_date="2025-04-30",
        )
        self.assertEqual(len(ledger.trades), 1)
        # Must keep ONLY the final business day's SUMMARY OpenPosition (10 shares, NOT 10 * len(bdays))!
        self.assertEqual(len(ledger.ending_positions), 1)
        self.assertAlmostEqual(ledger.ending_positions[0].quantity, 10.0)
        recon = reconcile_portfolio_ledger(ledger)
        self.assertEqual(recon.discrepancy_count, 0, recon.findings)
        perf = calculate_portfolio_performance_detailed(ledger)
        self.assertFalse(perf.withheld)

        # Malformed XML and XXE on GetStatement must still be rejected cleanly
        def xxe_transport(
            method: str, url: str, headers: dict[str, str], body: bytes | None
        ) -> HttpExchangeResponse:
            if url.startswith(IBKR_FLEX_SEND_REQUEST_URL):
                return HttpExchangeResponse(
                    status_code=200,
                    headers={},
                    body=b"<FlexStatementResponse><Status>Success</Status><ReferenceCode>REF-XXE</ReferenceCode></FlexStatementResponse>",
                )
            return HttpExchangeResponse(
                status_code=200,
                headers={},
                body=b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "bad">]><FlexQueryResponse/>',
            )

        with self.assertRaises(IbkrFlexXmlSecurityError):
            IbkrFlexWebServiceAdapter(
                http_transport=xxe_transport, sleep_fn=lambda _s: None
            ).fetch_statement_bytes(flex_token="TOK", query_id="111")

        def malformed_transport(
            method: str, url: str, headers: dict[str, str], body: bytes | None
        ) -> HttpExchangeResponse:
            if url.startswith(IBKR_FLEX_SEND_REQUEST_URL):
                return HttpExchangeResponse(
                    status_code=200,
                    headers={},
                    body=b"<FlexStatementResponse><Status>Success</Status><ReferenceCode>REF-BAD</ReferenceCode></FlexStatementResponse>",
                )
            return HttpExchangeResponse(
                status_code=200,
                headers={},
                body=b"<FlexQueryResponse><FlexStatements><Unclosed>",
            )

        with self.assertRaises(IbkrFlexServiceError):
            IbkrFlexWebServiceAdapter(
                http_transport=malformed_transport, sleep_fn=lambda _s: None
            ).fetch_statement_bytes(flex_token="TOK", query_id="111")

    def test_minimal_ibkr_flex_query_and_sub_200_char_ai_prompt_verify_without_false_discrepancy(
        self,
    ) -> None:
        from n170_verify.connectors.ibkr_flex_template import (
            IBKR_FLEX_AI_BUILDER_PROMPT,
            MINIMAL_IBKR_FLEX_SECTIONS,
            REQUIRED_IBKR_FLEX_SECTIONS,
            get_ibkr_flex_setup_guide,
        )
        from n170_verify.contracts import AccountScope, ProviderApprovalState

        guide = get_ibkr_flex_setup_guide()
        self.assertEqual(len(REQUIRED_IBKR_FLEX_SECTIONS), 9)
        self.assertEqual(
            list(MINIMAL_IBKR_FLEX_SECTIONS),
            [
                "AccountInformation",
                "EquitySummaryInBase",
                "ChangeInNAV",
                "Trades",
                "CashTransactions",
            ],
        )
        self.assertEqual(guide.minimal_sections, list(MINIMAL_IBKR_FLEX_SECTIONS))
        self.assertEqual(guide.ai_builder_prompt, IBKR_FLEX_AI_BUILDER_PROMPT)
        self.assertGreaterEqual(len(guide.ai_builder_prompt), 40)
        self.assertLessEqual(len(guide.ai_builder_prompt), 200)
        self.assertIn("XML", guide.ai_builder_prompt)
        self.assertIn("yyyy-MM-dd", guide.ai_builder_prompt)

        # Minimal 5-section EUR base IBKR Flex XML with USD equities (NO OpenPositions,
        # NO PriorPeriodPositions, NO Transfers, NO CorporateActions, NO OptionEAE, NO ConversionRates)
        d0 = date(2025, 1, 2)
        d1 = date(2025, 3, 31)
        bdays = _business_days(d0, d1)
        eq_rows: list[str] = []
        px = 100.0
        fx = 0.92
        cash_eur = 10_800.0
        for idx, d in enumerate(bdays):
            if idx > 0:
                px = round(px * 1.003, 4)
            stock_eur = round(100.0 * px * fx, 2)
            tot_eur = round(cash_eur + stock_eur, 2)
            eq_rows.append(
                f'<EquitySummaryByReportDateInBase accountId="U7654321" reportDate="{d.isoformat()}" '
                f'cash="{cash_eur:.2f}" stock="{stock_eur:.2f}" total="{tot_eur:.2f}" />'
            )

        # Trade 1 carries fxRateToBase="0.92" on d0; CashTransaction in USD omits fxRateToBase on d0
        # to verify cross-section fxRateToBase pre-indexing works without ConversionRates!
        minimal_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<FlexQueryResponse queryName="MinimalEasyAF" type="AF"><FlexStatements count="1">'
            f'<FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="{d0.isoformat()}" toDate="{d1.isoformat()}">'
            '<AccountInformation accountId="U7654321" currency="EUR" />'
            '<ChangeInNAV accountId="U7654321" fromDate="2025-01-02" toDate="2025-03-31" '
            'startingValue="20000.00" endingValue="21895.00" twr="9.48" />'
            f'<EquitySummaryInBase>{"".join(eq_rows)}</EquitySummaryInBase>'
            '<Trades>'
            f'<Trade accountId="U7654321" ibExecID="EX-MIN-1" symbol="MSFT" assetCategory="STK" '
            f'buySell="BUY" quantity="100" tradePrice="100.00" currency="USD" fxRateToBase="{fx}" '
            f'ibCommission="1.00" ibCommissionCurrency="USD" dateTime="{d0.isoformat()};15:00:00" levelOfDetail="EXECUTION" />'
            '</Trades>'
            '<CashTransactions>'
            f'<CashTransaction accountId="U7654321" type="Dividends" description="MSFT CASH DIV" '
            f'symbol="MSFT" currency="USD" amount="15.00" dateTime="{d0.isoformat()};18:00:00" />'
            '</CashTransactions>'
            '</FlexStatement></FlexStatements></FlexQueryResponse>'
        ).encode("utf-8")

        min_ledger = parse_ibkr_flex_xml(
            minimal_xml,
            blinding_salt_hex=_SALT,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
        )
        perf = calculate_portfolio_performance_detailed(min_ledger)
        self.assertFalse(perf.withheld)
        self.assertGreater(perf.summary.twr_decimal or 0.0, 0.05)

        recon = reconcile_portfolio_ledger(min_ledger)
        # Because OpenPositions was omitted in the minimal query, reconciliation must report
        # INSUFFICIENT_SECTIONS (0 discrepancies), NEVER a false UNEXPLAINED_RESIDUAL!
        self.assertEqual(recon.status, ReconciliationStatus.INSUFFICIENT_SECTIONS, recon.findings)
        self.assertEqual(recon.discrepancy_count, 0, recon.findings)
        self.assertIn("OpenPositions", recon.missing_sections)

        # Conversely, when <OpenPositions /> IS explicitly enabled and empty while stock > 0,
        # reconciliation MUST still flag UNEXPLAINED_RESIDUAL!
        tampered_xml = minimal_xml.replace(
            b"</EquitySummaryInBase>",
            b"</EquitySummaryInBase><PriorPeriodPositions /><OpenPositions /><Transfers /><CorporateActions /><OptionEAE />",
        )
        tampered_ledger = parse_ibkr_flex_xml(
            tampered_xml,
            blinding_salt_hex=_SALT,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
        )
        tampered_recon = reconcile_portfolio_ledger(tampered_ledger)
        self.assertEqual(tampered_recon.status, ReconciliationStatus.UNEXPLAINED_RESIDUAL)
        self.assertGreater(tampered_recon.discrepancy_count, 0)

    def test_ibkr_mixed_date_time_formats_and_closed_daily_open_positions_and_lot_only_exports(
        self,
    ) -> None:
        from n170_verify.connectors.ibkr_flex_template import IBKR_FLEX_AI_BUILDER_PROMPT
        from n170_verify.contracts import AccountScope, ProviderApprovalState

        # AI builder prompt must fit IBKR's <=200-char limit while covering custody sections
        # so published badge.svg achieves RECONCILIATION: Reconciled (not Insufficient Sections).
        self.assertLessEqual(len(IBKR_FLEX_AI_BUILDER_PROMPT), 200)
        self.assertIn("Open Positions", IBKR_FLEX_AI_BUILDER_PROMPT)
        self.assertIn("Transfers", IBKR_FLEX_AI_BUILDER_PROMPT)
        self.assertIn("Corporate Actions", IBKR_FLEX_AI_BUILDER_PROMPT)

        # Case 1: Trader buys 10 AAPL on 2025-01-02 (dateTime="2025-01-02;150000" -> yyyy-MM-dd + HHmmss),
        # deposits 5,000 EUR on 2025-01-10 (dateTime="2025-01-10;19:15:00 EST"),
        # sells all 10 AAPL on 2025-02-14 (dateTime="20250214;15:30:00" -> yyyyMMdd + HH:mm:ss),
        # and holds 100% cash through 2025-03-31 while <OpenPositions> has daily snapshots through 2025-02-13.
        d0 = date(2025, 1, 2)
        d_dep = date(2025, 1, 10)
        d_sell = date(2025, 2, 14)
        d1 = date(2025, 3, 31)
        bdays = _business_days(d0, d1)
        eq_rows: list[str] = []
        daily_open_rows: list[str] = []
        fx = 0.92
        cash_eur = 10_000.0
        shares = 0.0
        px = 100.0
        for d in bdays:
            if d == d0:
                shares = 10.0
                cash_eur = round(cash_eur - (10.0 * px * fx), 2)
            elif d == d_dep:
                cash_eur = round(cash_eur + 5_000.0, 2)
            elif d == d_sell:
                px = 110.0
                cash_eur = round(cash_eur + (10.0 * px * fx), 2)
                shares = 0.0
            stock_eur = round(shares * px * fx, 2)
            tot_eur = round(cash_eur + stock_eur, 2)
            eq_rows.append(
                f'<EquitySummaryByReportDateInBase accountId="U7654321" reportDate="{d.isoformat()}" '
                f'cash="{cash_eur:.2f}" stock="{stock_eur:.2f}" options="0.00" '
                f'dividendAccruals="0.00" interestAccruals="0.00" total="{tot_eur:.2f}" />'
            )
            if shares > 0:
                daily_open_rows.append(
                    f'<OpenPosition accountId="U7654321" symbol="AAPL" assetCategory="STK" '
                    f'currency="USD" fxRateToBase="{fx}" reportDate="{d.isoformat()}" '
                    f'position="10" costBasisMoney="1000.00" positionValue="{10.0 * px:.2f}" '
                    f'levelOfDetail="SUMMARY" />'
                )

        closed_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<FlexQueryResponse queryName="MixedFmtClosedPos" type="AF"><FlexStatements count="1">'
            f'<FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="{d0.isoformat()}" toDate="{d1.isoformat()}">'
            '<AccountInformation accountId="U7654321" currency="EUR" />'
            f'<EquitySummaryInBase>{"".join(eq_rows)}</EquitySummaryInBase>'
            '<PriorPeriodPositions>'
            f'<PriorPeriodPosition accountId="U7654321" symbol="EUR" assetCategory="CASH" currency="EUR" '
            f'fxRateToBase="1.0" reportDate="{d0.isoformat()}" position="10000.00" costBasisMoney="10000.00" positionValue="10000.00" levelOfDetail="SUMMARY" />'
            '</PriorPeriodPositions>'
            f'<OpenPositions>{"".join(daily_open_rows)}</OpenPositions>'
            '<Trades>'
            f'<Trade accountId="U7654321" ibExecID="EX-M1" symbol="AAPL" assetCategory="STK" '
            f'buySell="BUY" quantity="10" tradePrice="100.00" currency="USD" fxRateToBase="{fx}" '
            f'ibCommission="0.00" ibCommissionCurrency="USD" dateTime="2025-01-02;150000" levelOfDetail="EXECUTION" />'
            f'<Trade accountId="U7654321" ibExecID="EX-M2" symbol="AAPL" assetCategory="STK" '
            f'buySell="SELL" quantity="-10" tradePrice="110.00" currency="USD" fxRateToBase="{fx}" '
            f'ibCommission="0.00" ibCommissionCurrency="USD" dateTime="20250214;15:30:00" levelOfDetail="EXECUTION" />'
            f'<Trade accountId="U7654321" tradeID="LOT-CLOSED-1" symbol="AAPL" assetCategory="STK" '
            f'buySell="SELL" quantity="-10" tradePrice="110.00" currency="USD" fxRateToBase="{fx}" '
            f'dateTime="20250214;15:30:00" levelOfDetail="LOT" />'
            '</Trades>'
            '<CashTransactions>'
            '<CashTransaction accountId="U7654321" type="Deposits/Withdrawals" description="ELECTRONIC FUND TRANSFER" '
            'currency="EUR" amount="5000.00" dateTime="2025-01-10;19:15:00 EST" />'
            '</CashTransactions>'
            '<Transfers /><CorporateActions /><OptionEAE />'
            '</FlexStatement></FlexStatements></FlexQueryResponse>'
        ).encode("utf-8")

        closed_ledger = parse_ibkr_flex_xml(
            closed_xml,
            blinding_salt_hex=_SALT,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
        )
        self.assertEqual(len(closed_ledger.trades), 2)
        self.assertEqual(len(closed_ledger.flows), 1)
        self.assertEqual(closed_ledger.flows[0].timestamp_utc, "2025-01-10T19:15:00Z")
        self.assertEqual(closed_ledger.ending_positions, [])
        closed_recon = reconcile_portfolio_ledger(closed_ledger)
        self.assertTrue(closed_recon.ledger_completeness_ok, closed_recon.missing_sections)
        self.assertEqual(closed_recon.missing_sections, [])
        self.assertEqual(closed_recon.discrepancy_count, 0, closed_recon.findings)
        self.assertNotEqual(closed_recon.status, ReconciliationStatus.UNEXPLAINED_RESIDUAL)
        self.assertNotEqual(closed_recon.status, ReconciliationStatus.INSUFFICIENT_SECTIONS)

        # Case 2: LOT-only OpenPositions across multiple reportDates omitting positionValue (markPrice only)
        lot_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<FlexQueryResponse queryName="LotOnly" type="AF"><FlexStatements count="1">'
            '<FlexStatement accountId="U7654321" baseCurrency="EUR" fromDate="2025-01-02" toDate="2025-01-06">'
            '<AccountInformation accountId="U7654321" currency="EUR" />'
            '<EquitySummaryInBase>'
            '<EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2025-01-02" cash="5400.00" stock="4600.00" total="10000.00" />'
            '<EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2025-01-03" cash="2640.00" stock="7360.00" total="10000.00" />'
            '<EquitySummaryByReportDateInBase accountId="U7654321" reportDate="2025-01-06" cash="2640.00" stock="7728.00" total="10368.00" />'
            '</EquitySummaryInBase>'
            '<PriorPeriodPositions>'
            '<PriorPeriodPosition accountId="U7654321" symbol="EUR" assetCategory="CASH" currency="EUR" fxRateToBase="1.0" reportDate="2025-01-02" position="10000.00" costBasisMoney="10000.00" positionValue="10000.00" levelOfDetail="SUMMARY" />'
            '</PriorPeriodPositions>'
            '<OpenPositions>'
            '<OpenPosition accountId="U7654321" symbol="NVDA" assetCategory="STK" currency="USD" fxRateToBase="0.92" reportDate="2025-01-02" position="50" costBasisMoney="5000.00" markPrice="100.00" levelOfDetail="LOT" />'
            '<OpenPosition accountId="U7654321" symbol="NVDA" assetCategory="STK" currency="USD" fxRateToBase="0.92" reportDate="2025-01-06" position="50" costBasisMoney="5000.00" markPrice="105.00" levelOfDetail="LOT" />'
            '<OpenPosition accountId="U7654321" symbol="NVDA" assetCategory="STK" currency="USD" fxRateToBase="0.92" reportDate="2025-01-06" position="30" costBasisMoney="3000.00" markPrice="105.00" levelOfDetail="LOT" />'
            '</OpenPositions>'
            '<Trades>'
            '<Trade accountId="U7654321" ibExecID="EX-L1" symbol="NVDA" assetCategory="STK" buySell="BUY" quantity="50" tradePrice="100.00" currency="USD" fxRateToBase="0.92" ibCommission="0.00" dateTime="2025-01-02;143000" levelOfDetail="EXECUTION" />'
            '<Trade accountId="U7654321" ibExecID="EX-L2" symbol="NVDA" assetCategory="STK" buySell="BUY" quantity="30" tradePrice="100.00" currency="USD" fxRateToBase="0.92" ibCommission="0.00" dateTime="2025-01-03;143000" levelOfDetail="EXECUTION" />'
            '</Trades>'
            '<CashTransactions /><Transfers /><CorporateActions /><OptionEAE />'
            '</FlexStatement></FlexStatements></FlexQueryResponse>'
        ).encode("utf-8")
        lot_ledger = parse_ibkr_flex_xml(
            lot_xml,
            blinding_salt_hex=_SALT,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
        )
        self.assertEqual(len(lot_ledger.ending_positions), 2)
        self.assertAlmostEqual(sum(p.quantity for p in lot_ledger.ending_positions), 80.0)
        self.assertAlmostEqual(sum(p.market_value_base for p in lot_ledger.ending_positions), 7728.0)
        lot_recon = reconcile_portfolio_ledger(lot_ledger)
        self.assertEqual(lot_recon.discrepancy_count, 0, lot_recon.findings)


class IbkrAiBuilderRealSchemaAndFxDriftTests(unittest.TestCase):
    """Regression tests for real IBKR AI-Builder Activity Flex exports omitting ConversionRates/fxRateToBase."""

    def test_ai_builder_prompt_includes_conversion_rates_within_200_chars(self) -> None:
        from n170_verify.connectors.ibkr_flex_template import IBKR_FLEX_AI_BUILDER_PROMPT

        self.assertLessEqual(len(IBKR_FLEX_AI_BUILDER_PROMPT), 200)
        for token in ("Conversion Rates", "Open Positions", "Transfers", "Corporate Actions", "XML", "yyyy-MM-dd"):
            self.assertIn(token, IBKR_FLEX_AI_BUILDER_PROMPT)

    def test_multiyear_cross_chunk_fx_discovery_funds_stamp_duty_and_ticker_reorg(self) -> None:
        from datetime import datetime, timezone
        from n170_verify.coaching import TraderCoachingEngine, compute_cost_and_drag_breakdown

        # Year 1 (2024): EUR base, price-only PriorPeriodPosition for EUR ETF, CASH spot FX trades
        # (EUR.USD @ 1.05, EUR.GBP @ 0.84, USD.CHF @ 0.88 -> 2-hop CHF->EUR), UK stamp duty in netCash,
        # and ChangeInNAV lacking twr attribute (must NOT trigger deposit-day 1-day probes!).
        chunk_2024 = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<FlexQueryResponse queryName="AIBuilder" type="AF"><FlexStatements count="1">'
            '<FlexStatement accountId="U7771111" baseCurrency="EUR" fromDate="2024-09-02" toDate="2024-12-31">'
            '<AccountInformation accountId="U7771111" currency="EUR" dateOpened="2024-08-15" />'
            '<ChangeInNAV accountId="U7771111" startingValue="10000.00" endingValue="25000.00" />'
            '<EquitySummaryInBase>'
            '<EquitySummaryByReportDateInBase accountId="U7771111" reportDate="2024-09-02" cash="5000.00" stock="0.00" funds="5000.00" total="10000.00" />'
            '<EquitySummaryByReportDateInBase accountId="U7771111" reportDate="2024-10-15" cash="8104.30" stock="11872.29" funds="5000.00" total="25001.59" />'
            '<EquitySummaryByReportDateInBase accountId="U7771111" reportDate="2024-12-31" cash="9077.87" stock="11400.00" funds="5100.00" total="25577.87" />'
            '</EquitySummaryInBase>'
            '<PriorPeriodPositions>'
            '<PriorPeriodPosition accountId="U7771111" date="2024-09-02" symbol="VWCE" assetCategory="STK" subCategory="ETF" currency="EUR" price="100.00" />'
            '</PriorPeriodPositions>'
            '<OpenPositions />'
            '<Trades>'
            '<Trade accountId="U7771111" symbol="EUR.USD" assetCategory="CASH" buySell="SELL" quantity="-10000" tradePrice="1.0500" proceeds="10500.00" ibCommission="-2.00" netCash="10498.00" currency="USD" dateTime="2024-10-15;10:00:00" />'
            '<Trade accountId="U7771111" symbol="EUR.GBP" assetCategory="CASH" buySell="SELL" quantity="-3000" tradePrice="0.8400" proceeds="2520.00" ibCommission="-2.00" netCash="2518.00" currency="GBP" dateTime="2024-10-15;10:05:00" />'
            '<Trade accountId="U7771111" symbol="USD.CHF" assetCategory="CASH" buySell="SELL" quantity="-1000" tradePrice="0.8800" proceeds="880.00" ibCommission="-2.00" netCash="878.00" currency="CHF" dateTime="2024-10-15;10:10:00" />'
            '<Trade accountId="U7771111" symbol="OLDCO" assetCategory="STK" buySell="BUY" quantity="100" tradePrice="90.00" proceeds="-9000.00" cost="9001.00" ibCommission="-1.00" netCash="-9001.00" currency="USD" dateTime="2024-10-15;14:30:00" />'
            # UK buy with 0.5% SDRT stamp duty (10.00 GBP) embedded in netCash (-2012.00 vs proceeds -2000.00 - comm 2.00)
            '<Trade accountId="U7771111" symbol="AZN" assetCategory="STK" buySell="BUY" quantity="20" tradePrice="100.00" proceeds="-2000.00" cost="2012.00" ibCommission="-2.00" netCash="-2012.00" currency="GBP" dateTime="2024-10-15;11:00:00" />'
            '<Trade accountId="U7771111" symbol="NESN" assetCategory="STK" buySell="BUY" quantity="10" tradePrice="85.00" proceeds="-850.00" cost="852.00" ibCommission="-2.00" netCash="-852.00" currency="CHF" dateTime="2024-10-15;11:15:00" />'
            '<Trade accountId="U7771111" symbol="NESN" assetCategory="STK" buySell="SELL" quantity="-10" tradePrice="86.00" proceeds="860.00" cost="-852.00" ibCommission="-2.00" netCash="858.00" currency="CHF" dateTime="2024-11-20;11:15:00" />'
            '</Trades>'
            '<CashTransactions>'
            '<CashTransaction accountId="U7771111" type="Deposits/Withdrawals" currency="EUR" amount="15000.00" dateTime="2024-10-15;08:00:00" description="Wire" />'
            '<CashTransaction accountId="U7771111" type="Dividends" symbol="OLDCO" currency="USD" amount="47.25" dateTime="2024-11-01;12:00:00" description="OLDCO Cash Dividend" />'
            '</CashTransactions>'
            '<Transfers /><CorporateActions /><OptionEAE />'
            '</FlexStatement></FlexStatements></FlexQueryResponse>'
        ).encode("utf-8")

        # Year 2 (2025): NO CASH FX trades in 2025 at all! USD/EUR drifted from 1/1.05 (0.9524) to 0.8500
        # on closing OpenPositions; OLDCO renamed to NEWCO with exact 100 shares & 9001.00 USD costBasisMoney
        # while CorporateActions section is empty.
        # Ending positions on 2025-11-19:
        # VWCE (EUR fund): 50 * 110 = 5,500 EUR
        # NEWCO (USD stock): 100 * 120 = 12,000 USD * 0.85 = 10,200 EUR
        # AZN (GBP stock): 20 * 105 = 2,100 GBP * 1.19047619 (from 1/0.84) = 2,500 EUR
        # Total positions_base = 5,500 + 10,200 + 2,500 = 18,200 EUR; cash = 9,077.87 EUR -> NAV = 27,277.87 EUR
        chunk_2025 = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<FlexQueryResponse queryName="AIBuilder" type="AF"><FlexStatements count="1">'
            '<FlexStatement accountId="U7771111" baseCurrency="EUR" fromDate="2025-01-01" toDate="2025-11-19">'
            '<AccountInformation accountId="U7771111" currency="EUR" dateOpened="2024-08-15" />'
            '<ChangeInNAV accountId="U7771111" startingValue="25577.87" endingValue="27277.87" />'
            '<EquitySummaryInBase>'
            '<EquitySummaryByReportDateInBase accountId="U7771111" reportDate="2025-01-02" cash="9077.87" stock="11400.00" funds="5100.00" total="25577.87" />'
            '<EquitySummaryByReportDateInBase accountId="U7771111" reportDate="2025-11-19" cash="9077.87" stock="12700.00" funds="5500.00" total="27277.87" />'
            '</EquitySummaryInBase>'
            '<PriorPeriodPositions />'
            '<OpenPositions>'
            '<OpenPosition accountId="U7771111" symbol="VWCE" assetCategory="STK" subCategory="ETF" currency="EUR" position="50" markPrice="110.00" positionValue="5500.00" costBasisMoney="5000.00" percentOfNAV="20.16" />'
            '<OpenPosition accountId="U7771111" symbol="NEWCO" assetCategory="STK" currency="USD" position="100" markPrice="120.00" positionValue="12000.00" costBasisMoney="9001.00" percentOfNAV="37.39" />'
            '<OpenPosition accountId="U7771111" symbol="AZN" assetCategory="STK" currency="GBP" position="20" markPrice="105.00" positionValue="2100.00" costBasisMoney="2012.00" percentOfNAV="9.16" />'
            '</OpenPositions>'
            '<Trades />'
            '<CashTransactions />'
            '<Transfers /><CorporateActions /><OptionEAE />'
            '</FlexStatement></FlexStatements></FlexQueryResponse>'
        ).encode("utf-8")

        send_windows: list[tuple[str, str]] = []
        refs = {
            ("20240902", "20241231"): ("REF-24", chunk_2024),
            ("20250101", "20251119"): ("REF-25", chunk_2025),
        }

        def transport(
            _method: str, url: str, _headers: dict[str, str], _body: bytes | None
        ) -> HttpExchangeResponse:
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            if url.startswith(IBKR_FLEX_SEND_REQUEST_URL):
                win = (qs["fd"][0], qs["td"][0])
                send_windows.append(win)
                ref_id, _ = refs[win]
                return HttpExchangeResponse(
                    status_code=200,
                    headers={},
                    body=f"<FlexStatementResponse><Status>Success</Status><ReferenceCode>{ref_id}</ReferenceCode></FlexStatementResponse>".encode(),
                )
            q_ref = qs["q"][0]
            for r_id, payload in refs.values():
                if r_id == q_ref:
                    return HttpExchangeResponse(status_code=200, headers={}, body=payload)
            raise AssertionError(f"Unexpected ref {q_ref}")

        # 2025-11-20 11:00 UTC == 06:00 EST (< 18:00 NY), so auto_end must pick 2025-11-19 without 1003!
        adapter = IbkrFlexWebServiceAdapter(
            http_transport=transport,
            sleep_fn=lambda _s: None,
            now_utc_fn=lambda: datetime(2025, 11, 20, 11, 0, 0, tzinfo=timezone.utc),
        )
        ledger = adapter.fetch_canonical_ledger(
            flex_token="TOK-REAL-SCHEMA",
            query_id="778899",
            blinding_salt_hex=_SALT,
            start_date="2024-09-02",
        )
        # Must NOT send td=20251120 before NY close AND must NOT send 1-day ChangeInNAV probes when twr is absent!
        self.assertEqual(send_windows, [("20240902", "20241231"), ("20250101", "20251119")])

        # Price-only PriorPeriodPosition reconstructed VWCE = 50 shares
        self.assertEqual(len(ledger.prior_positions), 1)
        self.assertEqual(ledger.prior_positions[0].symbol, "VWCE")
        self.assertAlmostEqual(ledger.prior_positions[0].quantity, 50.0, places=5)

        # UK SDRT stamp duty (10 GBP) recovered on AZN buy; EUR.USD commission in EUR (fx_rate_to_base == 1.0)
        azn_buy = next(t for t in ledger.trades if t.symbol == "AZN")
        self.assertAlmostEqual(azn_buy.tax, 10.0, places=4)
        eur_usd = next(t for t in ledger.trades if t.symbol == "EUR.USD")
        self.assertAlmostEqual(eur_usd.commission * eur_usd.fx_rate_to_base, 2.0, places=5)

        # Reconciliation: 0 discrepancies both offline and with live FX ReferenceDataProvider
        recon = reconcile_portfolio_ledger(ledger)
        self.assertEqual(recon.discrepancy_count, 0, recon.findings)
        self.assertNotEqual(recon.status, ReconciliationStatus.UNEXPLAINED_RESIDUAL)

        class _MockClosingFxRef:
            is_available = True
            provider_name = "eodhd"

            def get_fx_rate(self, from_c: str, to_c: str, *, date_str: str) -> float | None:
                rates = {("USD", "EUR"): 0.8500, ("GBP", "EUR"): 1.0 / 0.84}
                return rates.get((from_c, to_c))

            def resolve_security(self, *args: object, **kwargs: object) -> None:
                return None

            def get_daily_bar(self, *args: object, **kwargs: object) -> None:
                return None

            def get_dividends(self, *args: object, **kwargs: object) -> list[object]:
                return []

            def get_splits(self, *args: object, **kwargs: object) -> list[object]:
                return []

        recon_with_ref = reconcile_portfolio_ledger(ledger, reference_provider=_MockClosingFxRef())  # type: ignore[arg-type]
        self.assertEqual(recon_with_ref.discrepancy_count, 0, recon_with_ref.findings)
        self.assertEqual(recon_with_ref.status, ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE)

        class _TamperedClosingFxRef(_MockClosingFxRef):
            def get_fx_rate(self, from_c: str, to_c: str, *, date_str: str) -> float | None:
                rates = {("USD", "EUR"): 0.7000, ("GBP", "EUR"): 1.0 / 0.84}
                return rates.get((from_c, to_c))

        recon_bad_fx = reconcile_portfolio_ledger(ledger, reference_provider=_TamperedClosingFxRef())  # type: ignore[arg-type]
        self.assertGreaterEqual(recon_bad_fx.discrepancy_count, 1)

        # Multi-year USD/EUR drift (0.9524 in 2024 vs 0.8500 at 2025 close) must NOT fabricate FX spread drag
        drag = compute_cost_and_drag_breakdown(ledger)
        self.assertEqual(drag.fx_conversion_drag_bps, 0.0)
        coach_out = TraderCoachingEngine().evaluate(ledger)
        self.assertIsNotNone(coach_out.report.quant_dna)
        assert coach_out.report.quant_dna is not None
        self.assertGreater(coach_out.report.quant_dna.cost_efficiency_score, 70.0)

    def test_adversarial_negative_guards_for_reorg_accruals_and_missing_fx(self) -> None:
        from n170_verify.contracts import CanonicalPortfolioLedger

        # 1. Missing FX with NO ConversionRates, NO fxRateToBase, NO CASH FX trades, and NO OpenPositions -> IbkrFlexParseError
        missing_fx_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<FlexQueryResponse queryName="MissingFX" type="AF"><FlexStatements count="1">'
            b'<FlexStatement accountId="U7771111" baseCurrency="EUR" fromDate="2025-01-02" toDate="2025-01-10">'
            b'<EquitySummaryInBase>'
            b'<EquitySummaryByReportDateInBase accountId="U7771111" reportDate="2025-01-02" cash="10000.00" stock="0.00" total="10000.00" />'
            b'<EquitySummaryByReportDateInBase accountId="U7771111" reportDate="2025-01-10" cash="10000.00" stock="0.00" total="10000.00" />'
            b'</EquitySummaryInBase>'
            b'<Trades>'
            b'<Trade accountId="U7771111" symbol="AAPL" assetCategory="STK" buySell="BUY" quantity="10" tradePrice="180.00" currency="USD" ibCommission="-1.00" dateTime="2025-01-03;15:00:00" />'
            b'<Trade accountId="U7771111" symbol="AAPL" assetCategory="STK" buySell="SELL" quantity="-10" tradePrice="182.00" currency="USD" ibCommission="-1.00" dateTime="2025-01-08;15:00:00" />'
            b'</Trades>'
            b'</FlexStatement></FlexStatements></FlexQueryResponse>'
        )
        with self.assertRaises(IbkrFlexParseError):
            parse_ibkr_flex_xml(missing_fx_xml, blinding_salt_hex=_SALT)

        # 2. Mismatched cost basis on symbol rename MUST NOT match 1:1 reorg -> UNEXPLAINED_RESIDUAL
        bad_reorg_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<FlexQueryResponse queryName="BadReorg" type="AF"><FlexStatements count="1">'
            b'<FlexStatement accountId="U7771111" baseCurrency="EUR" fromDate="2025-01-02" toDate="2025-01-10">'
            b'<EquitySummaryInBase>'
            b'<EquitySummaryByReportDateInBase accountId="U7771111" reportDate="2025-01-02" cash="10000.00" stock="0.00" total="10000.00" />'
            b'<EquitySummaryByReportDateInBase accountId="U7771111" reportDate="2025-01-10" cash="1000.00" stock="9000.00" total="10000.00" />'
            b'</EquitySummaryInBase>'
            b'<PriorPeriodPositions />'
            b'<OpenPositions>'
            b'<OpenPosition accountId="U7771111" symbol="FAKECO" assetCategory="STK" currency="EUR" position="100" markPrice="90.00" positionValue="9000.00" costBasisMoney="12500.00" />'
            b'</OpenPositions>'
            b'<Trades>'
            b'<Trade accountId="U7771111" symbol="OLDCO" assetCategory="STK" buySell="BUY" quantity="100" tradePrice="90.00" cost="9000.00" currency="EUR" ibCommission="0.00" dateTime="2025-01-03;15:00:00" />'
            b'</Trades>'
            b'<CashTransactions /><Transfers /><CorporateActions /><OptionEAE />'
            b'</FlexStatement></FlexStatements></FlexQueryResponse>'
        )
        bad_reorg_rec = reconcile_portfolio_ledger(parse_ibkr_flex_xml(bad_reorg_xml, blinding_salt_hex=_SALT))
        self.assertEqual(bad_reorg_rec.status, ReconciliationStatus.UNEXPLAINED_RESIDUAL)
        self.assertGreaterEqual(bad_reorg_rec.discrepancy_count, 2)

        # 3. >50 bps tampered snapshot total when accruals_base is None MUST flag UNEXPLAINED_RESIDUAL;
        # and 25 bps residual when dividendAccruals="0.00" IS explicitly exported MUST ALSO flag UNEXPLAINED_RESIDUAL!
        tampered_snap_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<FlexQueryResponse queryName="TamperedSnap" type="AF"><FlexStatements count="1">'
            b'<FlexStatement accountId="U7771111" baseCurrency="EUR" fromDate="2025-01-02" toDate="2025-01-10">'
            b'<EquitySummaryInBase>'
            b'<EquitySummaryByReportDateInBase accountId="U7771111" reportDate="2025-01-02" cash="100000.00" stock="0.00" total="101500.00" />'
            b'<EquitySummaryByReportDateInBase accountId="U7771111" reportDate="2025-01-10" cash="100000.00" stock="0.00" dividendAccruals="0.00" total="100250.00" />'
            b'</EquitySummaryInBase>'
            b'<PriorPeriodPositions /><OpenPositions /><Trades /><CashTransactions /><Transfers /><CorporateActions /><OptionEAE />'
            b'</FlexStatement></FlexStatements></FlexQueryResponse>'
        )
        tampered_snap_ldg = CanonicalPortfolioLedger.from_dict(
            parse_ibkr_flex_xml(tampered_snap_xml, blinding_salt_hex=_SALT).to_dict()
        )
        tampered_snap_rec = reconcile_portfolio_ledger(tampered_snap_ldg)
        self.assertEqual(tampered_snap_rec.status, ReconciliationStatus.UNEXPLAINED_RESIDUAL)
        nav_comp_discs = [
            f for f in tampered_snap_rec.findings
            if f.category == "nav_component_identity" and f.outcome.value == "discrepancy"
        ]
        self.assertEqual(len(nav_comp_discs), 2)

        # 4. Non-IBKR ledgers (e.g. Hyperliquid) with accruals_base=None MUST keep strict 5 bps nav_component_identity
        hl_tampered = CanonicalPortfolioLedger.from_dict(
            {
                **tampered_snap_ldg.to_dict(),
                "broker_id": "hyperliquid",
                "nav_points": [
                    {
                        "timestamp_utc": "2025-01-02T23:59:59Z",
                        "nav_base": 100000.0,
                        "cash_base": 100000.0,
                        "positions_base": 0.0,
                    },
                    {
                        "timestamp_utc": "2025-01-10T23:59:59Z",
                        "nav_base": 100400.0,  # 40 bps tampering (accruals_base is None)
                        "cash_base": 100000.0,
                        "positions_base": 0.0,
                    },
                ],
            }
        )
        hl_rec = reconcile_portfolio_ledger(hl_tampered)
        self.assertGreaterEqual(hl_rec.discrepancy_count, 1)

        # 5. Spoofed INFERRED_SINGLE_PRIOR_POSITION_WARNING in USD-base / nonzero-basis / non-IBKR ledger MUST fail
        from n170_verify.connectors.ibkr_flex import INFERRED_SINGLE_PRIOR_POSITION_WARNING

        spoof_prior_ldg = CanonicalPortfolioLedger.from_dict(
            {
                **tampered_snap_ldg.to_dict(),
                "base_currency": "USD",
                "enabled_sections": [
                    "AccountInformation",
                    "EquitySummaryInBase",
                    "OpenPositions",
                    "Trades",
                    "CashTransactions",
                    "Transfers",
                    "CorporateActions",
                ],
                "parser_warnings": [INFERRED_SINGLE_PRIOR_POSITION_WARNING],
                "nav_points": [
                    {
                        "timestamp_utc": "2025-01-02T23:59:59Z",
                        "nav_base": 200000.0,
                        "cash_base": 0.0,
                        "positions_base": 200000.0,
                        "accruals_base": 0.0,
                    },
                    {
                        "timestamp_utc": "2025-01-10T23:59:59Z",
                        "nav_base": 224000.0,
                        "cash_base": 0.0,
                        "positions_base": 224000.0,
                        "accruals_base": 0.0,
                    },
                ],
                "prior_positions": [
                    {
                        "prior_period_or_ending": "prior",
                        "symbol": "AAPL",
                        "asset_class": "equity",
                        "quantity": 1000.0,
                        "cost_basis": 0.0,
                        "market_value": 200000.0,
                        "currency": "USD",
                        "fx_rate_to_base": 1.0,
                    }
                ],
                "ending_positions": [
                    {
                        "prior_period_or_ending": "ending",
                        "symbol": "AAPL",
                        "asset_class": "equity",
                        "quantity": 1120.0,  # +12% fabricated share jump in same-currency account!
                        "cost_basis": 150000.0,
                        "market_value": 224000.0,
                        "currency": "USD",
                        "fx_rate_to_base": 1.0,
                    }
                ],
            }
        )
        spoof_rec = reconcile_portfolio_ledger(spoof_prior_ldg)
        self.assertEqual(spoof_rec.status, ReconciliationStatus.UNEXPLAINED_RESIDUAL)
        self.assertGreaterEqual(spoof_rec.discrepancy_count, 1)

    def test_cross_chunk_closing_fx_backfill_bond_accrued_int_and_post_rename_addon_buy(self) -> None:
        from datetime import datetime, timezone

        # Chunk 1 (2024): EUR base, NO CASH FX trades, NO ConversionRates, NO fxRateToBase;
        # buys 100 OLDCO in USD + buys EUR bond with accruedInt="-150.00" (must NOT become tax!).
        # Also tests <Trades> appearing BEFORE <AccountInformation currency="EUR"> in XML!
        c1 = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<FlexQueryResponse queryName="Backfill" type="AF"><FlexStatements count="1">'
            '<FlexStatement accountId="U7772222" fromDate="2024-09-02" toDate="2024-12-31">'
            '<Trades>'
            '<Trade accountId="U7772222" symbol="OLDCO" assetCategory="STK" buySell="BUY" quantity="100" tradePrice="50.00" proceeds="-5000.00" cost="5001.00" ibCommission="-1.00" netCash="-5001.00" currency="USD" dateTime="2024-10-10;15:00:00" />'
            '<Trade accountId="U7772222" symbol="DE10Y" assetCategory="BOND" buySell="BUY" quantity="10000" tradePrice="1.00" proceeds="-10000.00" ibCommission="-5.00" accruedInt="-150.00" netCash="-10155.00" currency="EUR" dateTime="2024-10-12;10:00:00" />'
            '</Trades>'
            '<AccountInformation accountId="U7772222" currency="EUR" />'
            '<EquitySummaryInBase>'
            '<EquitySummaryByReportDateInBase accountId="U7772222" reportDate="2024-09-02" cashLong="25000.00" cashShort="-5000.00" stock="0.00" bonds="0.00" total="20000.00" />'
            '<EquitySummaryByReportDateInBase accountId="U7772222" reportDate="2024-12-31" cash="5344.10" stock="4500.00" bonds="10000.00" total="19844.10" />'
            '</EquitySummaryInBase>'
            '<PriorPeriodPositions /><OpenPositions />'
            '<CashTransactions>'
            '<CashTransaction accountId="U7772222" type="Bond Interest Paid" currency="EUR" amount="-150.00" dateTime="2024-10-12;10:00:00" description="Purchased Bond Accrued Interest" />'
            '</CashTransactions>'
            '<Transfers /><CorporateActions /><OptionEAE />'
            '</FlexStatement></FlexStatements></FlexQueryResponse>'
        ).encode("utf-8")

        # Chunk 2 (2025): OLDCO renamed 1:1 to NEWCO + trader bought 50 MORE shares of NEWCO @ $60 ($3001 w/ comm)
        # -> ending 150 NEWCO with costBasisMoney="8002.00", closing USD/EUR = 0.90 from OpenPositions + EquitySummaryInBase!
        c2 = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<FlexQueryResponse queryName="Backfill" type="AF"><FlexStatements count="1">'
            '<FlexStatement accountId="U7772222" fromDate="2025-01-01" toDate="2025-11-19">'
            '<AccountInformation accountId="U7772222" currency="EUR" />'
            '<EquitySummaryInBase>'
            '<EquitySummaryByReportDateInBase accountId="U7772222" reportDate="2025-01-02" cash="5344.10" stock="4500.00" bonds="10000.00" total="19844.10" />'
            '<EquitySummaryByReportDateInBase accountId="U7772222" reportDate="2025-11-19" cash="2643.20" stock="8640.00" bonds="10000.00" total="21283.20" />'
            '</EquitySummaryInBase>'
            '<PriorPeriodPositions />'
            '<OpenPositions>'
            '<OpenPosition accountId="U7772222" symbol="NEWCO" assetCategory="STK" currency="USD" position="150" markPrice="64.00" positionValue="9600.00" costBasisMoney="8002.00" percentOfNAV="40.59" />'
            '<OpenPosition accountId="U7772222" symbol="DE10Y" assetCategory="BOND" currency="EUR" position="10000" markPrice="1.00" positionValue="10000.00" costBasisMoney="10005.00" percentOfNAV="46.99" />'
            '</OpenPositions>'
            '<Trades>'
            '<Trade accountId="U7772222" symbol="NEWCO" assetCategory="STK" buySell="BUY" quantity="50" tradePrice="60.00" proceeds="-3000.00" cost="3001.00" ibCommission="-1.00" netCash="-3001.00" currency="USD" dateTime="2025-03-10;15:00:00" />'
            '</Trades>'
            '<CashTransactions /><Transfers /><CorporateActions /><OptionEAE />'
            '</FlexStatement></FlexStatements></FlexQueryResponse>'
        ).encode("utf-8")

        refs = {
            ("20240902", "20241231"): ("R-C1", c1),
            ("20250101", "20251119"): ("R-C2", c2),
        }

        def transport(
            _method: str, url: str, _headers: dict[str, str], _body: bytes | None
        ) -> HttpExchangeResponse:
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            if url.startswith(IBKR_FLEX_SEND_REQUEST_URL):
                ref_id, _ = refs[(qs["fd"][0], qs["td"][0])]
                return HttpExchangeResponse(
                    status_code=200,
                    headers={},
                    body=f"<FlexStatementResponse><Status>Success</Status><ReferenceCode>{ref_id}</ReferenceCode></FlexStatementResponse>".encode(),
                )
            q_ref = qs["q"][0]
            for r_id, payload in refs.values():
                if r_id == q_ref:
                    return HttpExchangeResponse(status_code=200, headers={}, body=payload)
            raise AssertionError(q_ref)

        adapter = IbkrFlexWebServiceAdapter(
            http_transport=transport,
            sleep_fn=lambda _s: None,
            now_utc_fn=lambda: datetime(2025, 11, 20, 11, 0, 0, tzinfo=timezone.utc),
        )
        ldg = adapter.fetch_canonical_ledger(
            flex_token="TOK-BACKFILL",
            query_id="889900",
            blinding_salt_hex=_SALT,
            start_date="2024-09-02",
        )
        # cashLong + cashShort on 2024-09-02 == 20,000.00 EUR
        self.assertAlmostEqual(ldg.nav_points[0].cash_base or 0.0, 20000.0, places=2)
        # Bond accruedInt (-150 EUR) MUST NOT be misclassified as transaction tax
        bond_tr = next(t for t in ldg.trades if t.symbol == "DE10Y")
        self.assertEqual(bond_tr.tax, 0.0)
        # Post-rename add-on purchase (100 OLDCO + 50 NEWCO -> 150 NEWCO w/ conserved 8002 USD basis) reconciles with 0 discrepancies
        rec = reconcile_portfolio_ledger(ldg)
        self.assertEqual(rec.discrepancy_count, 0, rec.findings)


if __name__ == "__main__":
    unittest.main()
