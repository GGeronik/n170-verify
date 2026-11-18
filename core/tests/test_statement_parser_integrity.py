"""Statement parsers build a valuation series that describes one whole account, at true times.

Rules covered here:
- a valuation series is built for exactly one account: a Tradovate cash history or an
  Interactive Brokers Flex file that carries more than one account is refused, and a
  Tradovate cash history in more than one currency is refused;
- a Degiro account-statement valuation is emitted only when every currency's cash at that
  moment is accounted for; cash held in a currency other than the base is never left out;
- a MetaTrader balance rebuilt from the statement rows must reconcile with the statement's
  own summary balance; a mismatch or a negative running balance is refused, and without a
  summary figure to check against no rebuilt valuation is emitted;
- a MetaTrader summary equity is stamped at the statement's stated report time, never at
  the last deal; without a stated report time it is left out;
- an Interactive Brokers report-date valuation is the value at the end of that date, so a
  cash flow during that day belongs to the interval that ends at that day's valuation;
- a valuation at or below zero that follows a positive one is kept, so the return of a
  wiped-out account is withheld rather than computed from the surviving points.
"""

from __future__ import annotations

import unittest

from n170_verify.connectors.ibkr_flex import IbkrFlexParseError, parse_ibkr_flex_xml
from n170_verify.connectors.mt5_tradovate import (
    parse_mt4_statement,
    parse_mt5_statement,
    parse_tradovate_csv,
)
from n170_verify.connectors.statement_csv import parse_degiro_csv_bundle
from n170_verify.pipeline import api_worker_pipeline_entrypoint, verify_portfolio


_SALT = "5a" * 32
_ISSUED = "2026-12-20T00:00:00Z"


def _verify(ledger):
    return verify_portfolio(ledger=ledger, blinding_salt_hex=_SALT, issued_at_utc=_ISSUED)


# --------------------------------------------------------------------------- Tradovate

_TV_HEADER = "Account,Timestamp,Currency,Cash Change Type,Delta,Cash Balance,Comment"


def _tradovate_two_accounts() -> str:
    rows = [_TV_HEADER]
    for d in range(5, 15):
        rows.append(f"ACCTX01,2026-01-{d:02d} 21:00:00,USD,Trade Paired,{500 if d > 5 else 0},{50000 + 500 * (d - 5)},")
        rows.append(f"ACCTY02,2026-01-{d:02d} 22:00:00,USD,Trade Paired,{-50 if d > 5 else 0},{5000 - 50 * (d - 5)},")
    return "\n".join(rows) + "\n"


class TestTradovateOneAccountSeries(unittest.TestCase):
    def test_cash_history_with_two_accounts_is_refused(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            parse_tradovate_csv(_tradovate_two_accounts(), blinding_salt_hex=_SALT)
        self.assertIn("more than one account", str(ctx.exception))
        self.assertNotIn("ACCTX01", str(ctx.exception))

    def test_cash_history_with_two_accounts_is_refused_through_auto_detect(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            api_worker_pipeline_entrypoint(
                {
                    "broker_id": "auto_detect",
                    "raw_statement_text": _tradovate_two_accounts(),
                    "account_blinding_salt_hex": _SALT,
                }
            )
        self.assertIn("more than one account", str(ctx.exception))

    def test_cash_history_in_two_currencies_is_refused(self) -> None:
        csv = "\n".join(
            [
                _TV_HEADER,
                "ACCTX01,2026-01-05 21:00:00,USD,Deposit,50000,50000,",
                "ACCTX01,2026-01-06 21:00:00,EUR,Deposit,1000,1000,",
                "ACCTX01,2026-01-07 21:00:00,USD,Trade Paired,500,50500,",
            ]
        )
        with self.assertRaises(ValueError) as ctx:
            parse_tradovate_csv(csv, blinding_salt_hex=_SALT)
        self.assertIn("more than one currency", str(ctx.exception))

    def test_one_account_cash_history_still_scores(self) -> None:
        rows = [_TV_HEADER] + [
            f"ACCTX01,2026-01-{d:02d} 21:00:00,USD,Trade Paired,{500 if d > 5 else 0},{50000 + 500 * (d - 5)},"
            for d in range(5, 15)
        ]
        ledger = parse_tradovate_csv("\n".join(rows), blinding_salt_hex=_SALT)
        out = _verify(ledger)
        self.assertFalse(out.performance_withheld)
        self.assertAlmostEqual(out.performance.twr_decimal, 0.09, places=6)

    def test_non_positive_balance_after_a_positive_one_is_kept_and_withholds(self) -> None:
        csv = "\n".join(
            [
                _TV_HEADER,
                "ACCTX01,2026-01-05 21:00:00,USD,Trade Paired,0,10000,",
                "ACCTX01,2026-01-06 21:00:00,USD,Trade Paired,-2000,8000,",
                "ACCTX01,2026-01-07 21:00:00,USD,Trade Paired,-8500,-500,",
                "ACCTX01,2026-01-08 21:00:00,USD,Trade Paired,0,-500,",
            ]
        )
        ledger = parse_tradovate_csv(csv, blinding_salt_hex=_SALT)
        self.assertIn(-500.0, [p.nav_base for p in ledger.nav_points])
        self.assertTrue(_verify(ledger).performance_withheld)


# --------------------------------------------------------------------------- IBKR Flex


def _flex_stmt(acct: str, navs, cash: str = "") -> str:
    rows = "".join(
        f'<EquitySummaryByReportDateInBase reportDate="2026-01-{d:02d}" cash="{v}" stock="0" total="{v}" />'
        for d, v in navs
    )
    return (
        f'<FlexStatement accountId="{acct}" baseCurrency="USD" fromDate="2026-01-01" toDate="2026-01-31">'
        f"<EquitySummaryInBase>{rows}</EquitySummaryInBase>{cash}</FlexStatement>"
    )


def _flex_doc(*stmts: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?><FlexQueryResponse queryName="q" type="AF">'
        f'<FlexStatements count="{len(stmts)}">' + "".join(stmts) + "</FlexStatements></FlexQueryResponse>"
    )


_FLEX_A = [(d, round(100000 * 1.01 ** (d - 5), 2)) for d in range(5, 15)]
_FLEX_B = [(d, 10000.0) for d in range(5, 15)]


class TestIbkrFlexOneAccountSeries(unittest.TestCase):
    def test_two_accounts_in_one_file_are_refused_in_either_order(self) -> None:
        for xml in (
            _flex_doc(_flex_stmt("U0000001", _FLEX_A), _flex_stmt("U0000002", _FLEX_B)),
            _flex_doc(_flex_stmt("U0000002", _FLEX_B), _flex_stmt("U0000001", _FLEX_A)),
            _flex_doc(
                _flex_stmt("U0000002", [(d, 10000.0) for d in range(5, 10)]),
                _flex_stmt("U0000001", [(d, round(100000 * 1.01 ** (d - 10), 2)) for d in range(10, 15)]),
            ),
        ):
            with self.assertRaises(IbkrFlexParseError) as ctx:
                parse_ibkr_flex_xml(xml, blinding_salt_hex=_SALT)
            self.assertIn("more than one account", str(ctx.exception))
            self.assertNotIn("U0000001", str(ctx.exception))

    def test_one_account_file_still_scores(self) -> None:
        ledger = parse_ibkr_flex_xml(_flex_doc(_flex_stmt("U0000001", _FLEX_A)), blinding_salt_hex=_SALT)
        out = _verify(ledger)
        self.assertFalse(out.performance_withheld)
        self.assertAlmostEqual(out.performance.twr_decimal, 1.01**9 - 1.0, places=4)

    def test_report_date_valuation_is_the_value_at_the_end_of_that_date(self) -> None:
        flat = [(d, 10000.0) for d in range(5, 10)] + [(d, 10900.0) for d in range(10, 15)]
        deposit = (
            '<CashTransactions><CashTransaction type="Deposits/Withdrawals" currency="USD" amount="900" '
            'dateTime="2026-01-10;10:00:00" description="CASH RECEIPTS" /></CashTransactions>'
        )
        for cash in (deposit, deposit.replace("2026-01-10;10:00:00", "20260110")):
            ledger = parse_ibkr_flex_xml(_flex_doc(_flex_stmt("U0000001", flat, cash)), blinding_salt_hex=_SALT)
            self.assertEqual(ledger.nav_points[0].timestamp_utc, "2026-01-05T23:59:59Z")
            out = _verify(ledger)
            self.assertFalse(out.performance_withheld)
            self.assertAlmostEqual(out.performance.twr_decimal, 0.0, places=9)
            self.assertAlmostEqual(out.performance.max_drawdown_decimal, 0.0, places=9)

    def test_non_positive_total_after_a_positive_one_is_kept_and_withholds(self) -> None:
        navs = [(5, 10000.0), (6, 9000.0), (7, 0.0), (8, 0.0)]
        ledger = parse_ibkr_flex_xml(_flex_doc(_flex_stmt("U0000001", navs)), blinding_salt_hex=_SALT)
        self.assertEqual([p.nav_base for p in ledger.nav_points], [10000.0, 9000.0, 0.0])
        self.assertTrue(_verify(ledger).performance_withheld)


# --------------------------------------------------------------------------- Degiro

_DG_HEADER = "Date,Time,Value date,Product,ISIN,Description,FX,Change,,Balance,,Order Id"
_DG_ROWS = [
    '02-01-2026,09:00,02-01-2026,,,iDEAL Deposit,,EUR,"10000,00",EUR,"10000,00",',
    '05-01-2026,15:30,05-01-2026,APPLE INC,US0378331005,Buy 10 @ 200 USD,,USD,"-2000,00",USD,"-2000,00",o1',
    '05-01-2026,15:30,05-01-2026,,,FX Credit,"1,0870",USD,"2000,00",USD,"0,00",',
    '05-01-2026,15:30,05-01-2026,,,FX Debit,,EUR,"-1840,00",EUR,"8160,00",',
    '06-01-2026,15:30,06-01-2026,APPLE INC,US0378331005,Sell 10 @ 200 USD,,USD,"2000,00",USD,"2000,00",o2',
    '07-01-2026,09:00,07-01-2026,,,DEGIRO Connectivity Fee,,EUR,"-2,50",EUR,"8157,50",',
]
_DG_CLOSE_USD = [
    '09-01-2026,09:00,09-01-2026,,,FX Credit,,EUR,"1838,00",EUR,"9995,50",',
    '09-01-2026,09:00,09-01-2026,,,FX Debit,"1,0870",USD,"-2000,00",USD,"0,00",',
]


def _degiro(rows) -> object:
    csv = _DG_HEADER + "\n" + "\n".join(rows) + "\n"
    return parse_degiro_csv_bundle(account_csv=csv.encode(), blinding_salt_hex=_SALT, base_currency="EUR")


class TestDegiroAccountOnlyValuation(unittest.TestCase):
    def test_point_is_emitted_only_when_every_currency_cash_is_accounted_for(self) -> None:
        ledger = _degiro(_DG_ROWS + _DG_CLOSE_USD)
        self.assertEqual(
            [(p.timestamp_utc, p.nav_base) for p in ledger.nav_points],
            [("2026-01-02T09:00:00Z", 10000.0), ("2026-01-09T09:00:00Z", 9995.5)],
        )
        out = _verify(ledger)
        self.assertFalse(out.performance_withheld)
        self.assertAlmostEqual(out.performance.twr_decimal, -0.00045, places=6)
        self.assertGreater(out.performance.max_drawdown_decimal, -0.001)

    def test_newest_first_and_oldest_first_exports_give_the_same_series(self) -> None:
        oldest_first = _degiro(_DG_ROWS + _DG_CLOSE_USD)
        newest_first = _degiro(list(reversed(_DG_ROWS + _DG_CLOSE_USD)))
        self.assertEqual(
            [(p.timestamp_utc, p.nav_base) for p in newest_first.nav_points],
            [(p.timestamp_utc, p.nav_base) for p in oldest_first.nav_points],
        )
        self.assertEqual(
            _verify(newest_first).performance_withheld, _verify(oldest_first).performance_withheld
        )

    def test_statement_that_ends_holding_foreign_cash_withholds(self) -> None:
        ledger = _degiro(_DG_ROWS)
        self.assertEqual([p.nav_base for p in ledger.nav_points], [10000.0])
        self.assertTrue(_verify(ledger).performance_withheld)

    def test_foreign_cash_held_before_the_statement_drops_earlier_points(self) -> None:
        rows = [
            '02-01-2026,09:00,02-01-2026,,,iDEAL Deposit,,EUR,"10000,00",EUR,"10000,00",',
            '03-01-2026,09:00,03-01-2026,,,DEGIRO Connectivity Fee,,EUR,"-2,50",EUR,"9997,50",',
            '04-01-2026,09:00,04-01-2026,,,FX Credit,,EUR,"1838,00",EUR,"11835,50",',
            '04-01-2026,09:00,04-01-2026,,,FX Debit,"1,0870",USD,"-2000,00",USD,"0,00",',
            '05-01-2026,09:00,05-01-2026,,,DEGIRO Connectivity Fee,,EUR,"-2,50",EUR,"11833,00",',
        ]
        ledger = _degiro(rows)
        self.assertEqual(
            [p.timestamp_utc for p in ledger.nav_points],
            ["2026-01-04T09:00:00Z", "2026-01-05T09:00:00Z"],
        )


# --------------------------------------------------------------------------- MetaTrader

_MT4_HEAD = """<html><head><title>Statement: 50998877 - Live Trader</title></head><body><table>
<tr><td><b>Account: 50998877</b></td><td><b>Name: A B</b></td><td><b>Currency: USD</b></td><td><b>Server: ICMarketsSC-Live04</b></td>{report}</tr>
<tr><td colspan="14"><b>Closed Transactions:</b></td></tr>
<tr><td>Ticket</td><td>Open Time</td><td>Type</td><td>Size</td><td>Item</td><td>Price</td><td>S / L</td><td>T / P</td><td>Close Time</td><td>Price</td><td>Commission</td><td>Taxes</td><td>Swap</td><td>Profit</td></tr>
"""


def _mt4_trade(t: int, d_open: str, d_close: str, profit: str) -> str:
    return (
        f"<tr><td>{t}</td><td>{d_open}</td><td>buy</td><td>1.00</td><td>EURUSD</td><td>1.08500</td><td>0</td><td>0</td>"
        f"<td>{d_close}</td><td>1.09100</td><td>0.00</td><td>0.00</td><td>0.00</td><td>{profit}</td></tr>\n"
    )


def _mt4_dep(t: int, d: str, amt: str) -> str:
    return f'<tr><td>{t}</td><td>{d}</td><td>balance</td><td colspan="10">Deposit</td><td>{amt}</td></tr>\n'


_MT4_OPEN = """<tr><td colspan="14"><b>Open Trades:</b></td></tr>
<tr><td>Ticket</td><td>Open Time</td><td>Type</td><td>Size</td><td>Item</td><td>Price</td><td>S / L</td><td>T / P</td><td> </td><td>Price</td><td>Commission</td><td>Taxes</td><td>Swap</td><td>Profit</td></tr>
<tr><td>9</td><td>2026.02.20 12:00:00</td><td>buy</td><td>1.00</td><td>GBPUSD</td><td>1.26000</td><td>0</td><td>0</td><td> </td><td>1.26500</td><td>0.00</td><td>0.00</td><td>0.00</td><td>-3000.00</td></tr>
"""


def _mt4_tail(cells: str) -> str:
    return f'<tr><td colspan="14"><b>Summary:</b></td></tr><tr>{cells}</tr></table></body></html>'


def _mt4(body: str, tail_cells: str, report: str = "") -> str:
    return _MT4_HEAD.format(report=report) + body + _mt4_tail(tail_cells)


_MT4_NO_OPENING_ROW = (
    _mt4_trade(1, "2026.02.02 08:00:00", "2026.02.03 10:00:00", "600.00")
    + _mt4_trade(2, "2026.02.04 08:00:00", "2026.02.05 10:00:00", "-200.00")
    + _mt4_trade(3, "2026.02.06 08:00:00", "2026.02.09 10:00:00", "300.00")
)
_MT4_WITH_DEPOSIT = (
    _mt4_dep(1, "2026.02.02 08:00:00", "10 000.00")
    + _mt4_trade(2, "2026.02.03 08:00:00", "2026.02.04 10:00:00", "500.00")
    + _mt4_trade(3, "2026.02.05 08:00:00", "2026.02.06 10:00:00", "500.00")
)


class TestMetaTraderBalanceReconciliation(unittest.TestCase):
    def test_running_balance_that_misses_the_opening_balance_is_refused(self) -> None:
        html = _mt4(_MT4_NO_OPENING_ROW, "<td>Deposit/Withdrawal:</td><td>0.00</td><td>Equity:</td><td>10700.00</td>")
        with self.assertRaises(ValueError) as ctx:
            parse_mt4_statement(html, blinding_salt_hex=_SALT)
        self.assertIn("does not match", str(ctx.exception))
        with self.assertRaises(ValueError):
            api_worker_pipeline_entrypoint(
                {"broker_id": "auto_detect", "raw_statement_text": html, "account_blinding_salt_hex": _SALT}
            )

    def test_negative_running_balance_is_refused(self) -> None:
        body = _mt4_trade(1, "2026.02.02 08:00:00", "2026.02.03 10:00:00", "-600.00") + _mt4_dep(
            2, "2026.02.04 08:00:00", "10 000.00"
        )
        html = _mt4(body, "<td>Balance:</td><td>9400.00</td><td>Equity:</td><td>9400.00</td>")
        with self.assertRaises(ValueError) as ctx:
            parse_mt4_statement(html, blinding_salt_hex=_SALT)
        self.assertIn("below zero", str(ctx.exception))

    def test_reconciled_running_balance_is_kept(self) -> None:
        html = _mt4(_MT4_WITH_DEPOSIT, "<td>Balance:</td><td>11 000.00</td><td>Equity:</td><td>11 000.00</td>")
        ledger = parse_mt4_statement(html, blinding_salt_hex=_SALT)
        self.assertEqual([p.nav_base for p in ledger.nav_points], [10000.0, 10500.0, 11000.0])

    def test_without_a_summary_figure_no_rebuilt_balance_is_emitted(self) -> None:
        html = _mt4(_MT4_WITH_DEPOSIT + _MT4_OPEN, "<td>Equity:</td><td>8000.00</td>")
        ledger = parse_mt4_statement(html, blinding_salt_hex=_SALT)
        self.assertEqual(ledger.nav_points, [])

    def test_mt5_fallback_running_balance_is_reconciled(self) -> None:
        tsv = (
            "Time\tDeal\tSymbol\tType\tDirection\tVolume\tPrice\tOrder\tCommission\tFee\tSwap\tProfit\tComment\n"
            "2026.01.03 09:00:00\t2\tMESZ5\tbuy\tin\t2\t5800.00\t10\t0\t0\t0.00\t0.00\tOpen\n"
            "2026.01.03 11:00:00\t3\tMESZ5\tsell\tout\t2\t5810.00\t11\t0\t0\t0.00\t100.00\tClose\n"
            "Balance:\t15100.00\n"
        )
        with self.assertRaises(ValueError) as ctx:
            parse_mt5_statement(tsv, blinding_salt_hex=_SALT)
        self.assertIn("does not match", str(ctx.exception))


class TestMetaTraderEquityTimestamp(unittest.TestCase):
    def test_equity_is_not_stamped_at_the_last_deal(self) -> None:
        html_open = _mt4(
            _MT4_WITH_DEPOSIT + _MT4_OPEN,
            "<td>Balance:</td><td>11 000.00</td><td>Equity:</td><td>8000.00</td>",
        )
        ledger_open = parse_mt4_statement(html_open, blinding_salt_hex=_SALT)
        self.assertEqual(ledger_open.nav_points, [])
        self.assertTrue(_verify(ledger_open).performance_withheld)

        html_flat = _mt4(
            _MT4_WITH_DEPOSIT,
            "<td>Balance:</td><td>11 000.00</td><td>Equity:</td><td>8000.00</td>",
        )
        ledger_flat = parse_mt4_statement(html_flat, blinding_salt_hex=_SALT)
        self.assertNotIn(8000.0, [p.nav_base for p in ledger_flat.nav_points])
        self.assertEqual(ledger_flat.nav_points[-1].timestamp_utc, "2026-02-06T10:00:00Z")

    def test_equity_is_stamped_at_a_stated_report_time(self) -> None:
        html = _mt4(
            _MT4_WITH_DEPOSIT + _MT4_OPEN,
            "<td>Balance:</td><td>11 000.00</td><td>Equity:</td><td>8000.00</td>",
            report="<td><b>Date: 2026.02.27 18:00</b></td>",
        )
        ledger = parse_mt4_statement(html, blinding_salt_hex=_SALT)
        self.assertEqual(
            (ledger.nav_points[-1].timestamp_utc, ledger.nav_points[-1].nav_base),
            ("2026-02-27T18:00:00Z", 8000.0),
        )

    def test_mt5_equity_is_not_stamped_at_the_last_deal(self) -> None:
        tsv = (
            "Time\tDeal\tSymbol\tType\tDirection\tVolume\tPrice\tOrder\tCommission\tFee\tSwap\tProfit\tBalance\tComment\n"
            "2026.01.02 08:00:00\t1\t\tbalance\t\t\t\t\t0.00\t0.00\t0.00\t15000.00\t15000.00\tDeposit\n"
            "2026.01.03 09:00:00\t2\tMESZ5\tbuy\tin\t2\t5800.00\t10\t0\t0\t0.00\t0.00\t15000.00\tOpen\n"
            "2026.01.03 11:00:00\t3\tMESZ5\tsell\tout\t2\t5810.00\t11\t0\t0\t0.00\t100.00\t15100.00\tClose\n"
            "Equity:\t12000.00\n"
        )
        ledger = parse_mt5_statement(tsv, blinding_salt_hex=_SALT)
        self.assertEqual([p.nav_base for p in ledger.nav_points], [15000.0, 15100.0])

    def test_mt5_non_positive_balance_after_a_positive_one_is_kept(self) -> None:
        tsv = (
            "Time\tDeal\tSymbol\tType\tDirection\tVolume\tPrice\tOrder\tCommission\tFee\tSwap\tProfit\tBalance\tComment\n"
            "2026.01.02 08:00:00\t1\t\tbalance\t\t\t\t\t0.00\t0.00\t0.00\t1000.00\t1000.00\tDeposit\n"
            "2026.01.03 09:00:00\t2\tMESZ5\tbuy\tin\t2\t5800.00\t10\t0\t0\t0.00\t0.00\t1000.00\tOpen\n"
            "2026.01.03 11:00:00\t3\tMESZ5\tsell\tout\t2\t5810.00\t11\t0\t0\t0.00\t-1000.00\t0.00\tClose\n"
        )
        ledger = parse_mt5_statement(tsv, blinding_salt_hex=_SALT)
        self.assertEqual([p.nav_base for p in ledger.nav_points], [1000.0, 0.0])
        self.assertTrue(_verify(ledger).performance_withheld)


# --------------------------------------------------------------------------- open positions


class TestMetaTraderBalanceOnlyWhileFlat(unittest.TestCase):
    """A balance is the account's value only at an instant when no position is open."""

    def test_mt4_balance_while_a_position_is_open_is_not_a_valuation(self) -> None:
        open_since_day_two = _MT4_OPEN.replace("2026.02.20 12:00:00", "2026.02.03 09:00:00")
        html_no_report = _mt4(
            _MT4_WITH_DEPOSIT + open_since_day_two,
            "<td>Balance:</td><td>11 000.00</td><td>Equity:</td><td>8000.00</td>",
        )
        ledger_no_report = parse_mt4_statement(html_no_report, blinding_salt_hex=_SALT)
        self.assertEqual(ledger_no_report.nav_points, [])
        self.assertTrue(_verify(ledger_no_report).performance_withheld)

        html_with_report = _mt4(
            _MT4_WITH_DEPOSIT + open_since_day_two,
            "<td>Balance:</td><td>11 000.00</td><td>Equity:</td><td>8000.00</td>",
            report="<td><b>Date: 2026.02.27 18:00</b></td>",
        )
        ledger_with_report = parse_mt4_statement(html_with_report, blinding_salt_hex=_SALT)
        self.assertEqual(
            [p.timestamp_utc for p in ledger_with_report.nav_points],
            ["2026-02-02T08:00:00Z", "2026-02-27T18:00:00Z"],
        )

    def test_mt4_balance_inside_an_overlapping_trade_is_not_a_valuation(self) -> None:
        body = (
            _mt4_dep(1, "2026.02.02 08:00:00", "10 000.00")
            + _mt4_trade(2, "2026.02.04 08:00:00", "2026.02.05 10:00:00", "100.00")
            + _mt4_trade(3, "2026.02.06 08:00:00", "2026.02.07 10:00:00", "100.00")
            + _mt4_trade(4, "2026.02.03 08:00:00", "2026.02.10 10:00:00", "200.00")
        )
        html = _mt4(body, "<td>Balance:</td><td>10 400.00</td><td>Equity:</td><td>10 400.00</td>")
        ledger = parse_mt4_statement(html, blinding_salt_hex=_SALT)
        self.assertEqual(
            [(p.timestamp_utc, p.nav_base) for p in ledger.nav_points],
            [("2026-02-02T08:00:00Z", 10000.0), ("2026-02-10T10:00:00Z", 10400.0)],
        )

    def test_mt4_trader_flat_between_trades_is_scored(self) -> None:
        html = _mt4(_MT4_WITH_DEPOSIT, "<td>Balance:</td><td>11 000.00</td><td>Equity:</td><td>11 000.00</td>")
        out = _verify(parse_mt4_statement(html, blinding_salt_hex=_SALT))
        self.assertFalse(out.performance_withheld)
        self.assertAlmostEqual(out.performance.twr_decimal, 0.10, places=9)

    def test_mt5_deal_balance_while_a_position_is_open_is_not_a_valuation(self) -> None:
        tsv = (
            "Time\tDeal\tSymbol\tType\tDirection\tVolume\tPrice\tOrder\tCommission\tFee\tSwap\tProfit\tBalance\tComment\n"
            "2026.01.02 09:00:00\t9000\t\tbalance\t\t\t\t\t0.00\t0.00\t0.00\t10000.00\t10000.00\tFunding\n"
            "2026.01.03 09:00:00\t9001\tGBPUSD\tbuy\tin\t1.00\t1.26000\t1\t0.00\t0.00\t0.00\t0.00\t10000.00\t\n"
            "2026.01.04 08:00:00\t9002\tEURUSD\tbuy\tin\t1.00\t1.08000\t2\t0.00\t0.00\t0.00\t0.00\t10000.00\t\n"
            "2026.01.04 10:00:00\t9003\tEURUSD\tsell\tout\t1.00\t1.08500\t3\t0.00\t0.00\t0.00\t500.00\t10500.00\t\n"
            "2026.01.06 10:00:00\t9005\tEURUSD\tbuy\tin\t1.00\t1.08000\t4\t0.00\t0.00\t0.00\t0.00\t10500.00\t\n"
            "2026.01.06 12:00:00\t9006\tEURUSD\tsell\tout\t1.00\t1.08500\t5\t0.00\t0.00\t0.00\t500.00\t11000.00\t\n"
        )
        ledger = parse_mt5_statement(tsv, blinding_salt_hex=_SALT)
        self.assertEqual([p.timestamp_utc for p in ledger.nav_points], ["2026-01-02T09:00:00Z"])
        self.assertTrue(_verify(ledger).performance_withheld)

    def test_mt5_position_open_before_the_first_deal_drops_earlier_points(self) -> None:
        tsv = (
            "Time\tDeal\tSymbol\tType\tDirection\tVolume\tPrice\tOrder\tCommission\tFee\tSwap\tProfit\tBalance\tComment\n"
            "2026.01.02 09:00:00\t9000\t\tbalance\t\t\t\t\t0.00\t0.00\t0.00\t10000.00\t10000.00\tFunding\n"
            "2026.01.03 10:00:00\t9003\tEURUSD\tsell\tout\t1.00\t1.08500\t3\t0.00\t0.00\t0.00\t500.00\t10500.00\t\n"
            "2026.01.05 10:00:00\t9004\t\tbalance\t\t\t\t\t0.00\t0.00\t0.00\t100.00\t10600.00\tFunding\n"
        )
        ledger = parse_mt5_statement(tsv, blinding_salt_hex=_SALT)
        self.assertEqual(
            [p.timestamp_utc for p in ledger.nav_points],
            ["2026-01-03T10:00:00Z", "2026-01-05T10:00:00Z"],
        )


# --------------------------------------------------------------------------- CSV shapes

_TV_CASH_OK = (
    _TV_HEADER
    + "\nACCTX01,2026-01-02 08:00:00,USD,Deposit,25000.00,25000.00,Wire In"
    + "\nACCTX01,2026-01-05 08:00:00,USD,Trade Paired,10.00,25010.00,R\n"
)
_ROBINHOOD_OK = (
    "Activity Date,Process Date,Settle Date,Instrument,Description,Trans Code,Quantity,Price,Amount\n"
    "01/03/2026,01/03/2026,01/05/2026,,ACH Deposit,ACH,,,$5000.00\n"
    "01/06/2026,01/06/2026,01/07/2026,NVDA,NVIDIA Corp,Buy,20,$135.00,-$2700.00\n"
    "01/14/2026,01/14/2026,01/15/2026,NVDA,NVIDIA Corp,Sell,20,$148.50,$2970.00\n"
)
_TRADERSYNC_OK = (
    "Status,Symbol,Size,Open Date,Open Time,Close Date,Close Time,Entry Price,Exit Price,Return $,Side,Setups,Mistakes,Commission,Notes\n"
    "WIN,NVDA,50,2026-01-08,09:35:00,2026-01-08,10:20:00,140.00,145.00,248.00,LONG,ORB,,2.00,\n"
)
_MT4_CSV_OK = (
    "Ticket,Open Time,Type,Size,Item,Price,S / L,T / P,Close Time,Price,Commission,Taxes,Swap,Profit\n"
    "2002,2026.01.04 10:00:00,buy,0.50,EURUSD,1.1000,1.0950,1.1100,2026.01.04 15:00:00,1.1040,-3.50,0.00,0.00,200.00\n"
)
_DEGIRO_OK = (
    "Date,Time,Value date,Product,ISIN,Description,FX,Change,,Balance,,Order Id\n"
    "02-01-2026,09:00,02-01-2026,,,Deposit,,EUR,10000.00,EUR,10000.00,\n"
    "09-01-2026,09:00,09-01-2026,,,Deposit,,EUR,100.00,EUR,10100.00,\n"
)


def _shape(text: str):
    from n170_verify.connectors.statement_csv import detect_and_parse_statement

    res = detect_and_parse_statement(text, blinding_salt_hex=_SALT)
    led = res.ledger
    return (
        res.detected_format,
        [(p.timestamp_utc, p.nav_base) for p in led.nav_points],
        [(t.timestamp_utc, t.symbol, t.side) for t in led.trades],
        [(f.timestamp_utc, f.amount) for f in led.flows],
    )


class TestCsvLineEndingsAndLimits(unittest.TestCase):
    def test_carriage_return_line_endings_read_like_line_feeds(self) -> None:
        for name, text in (
            ("tradovate", _TV_CASH_OK),
            ("robinhood", _ROBINHOOD_OK),
            ("tradersync", _TRADERSYNC_OK),
            ("mt4 csv", _MT4_CSV_OK),
            ("degiro", _DEGIRO_OK),
        ):
            with self.subTest(fmt=name):
                expected = _shape(text)
                self.assertEqual(_shape(text.replace("\n", "\r")), expected)
                self.assertEqual(_shape(text.replace("\n", "\r\n")), expected)

    def test_field_longer_than_the_reader_allows_is_refused_with_a_plain_reason(self) -> None:
        text = _TV_HEADER + "\nACCTX01,2026-01-02 08:00:00,USD,Deposit,25000.00,25000.00," + "x" * 200_000 + "\n"
        with self.assertRaises(ValueError) as ctx:
            _shape(text)
        self.assertIn("cannot be read as CSV", str(ctx.exception))


# --------------------------------------------------------------------------- opening positions


def _round_trip_sides(ledger) -> list[str]:
    from n170_verify.coaching.behaviour_metrics import match_fifo_round_trips

    return sorted(rt.side for rt in match_fifo_round_trips(ledger))


class TestFormatsCompleteByConstruction(unittest.TestCase):
    """A file whose every trade row is a finished round trip accounts for its own opening
    positions, so a first sale in it is a genuine short; a fills or transactions export does
    not, so a first sale in it may close a position held from before and is not matched."""

    def test_tradovate_performance_short_round_trip_is_matched(self) -> None:
        perf = (
            "symbol,buyFillId,sellFillId,qty,buyPrice,sellPrice,pnl,boughtTimestamp,soldTimestamp\n"
            "NQM26,BF-NQ,SF-NQ,1,21025.00,21000.00,$(500.00),01/13/2026 11:15:00,01/13/2026 10:45:00\n"
        )
        self.assertEqual(_round_trip_sides(parse_tradovate_csv(perf, blinding_salt_hex=_SALT)), ["short"])

    def test_tradovate_orders_first_sale_is_not_matched(self) -> None:
        orders = (
            "orderId,Account,B/S,Contract,avgPrice,filledQty,Fill Time,Status\n"
            "101,ACCTX01,Sell,ESH6,5810.00,1,2026-01-15 14:30:00,Filled\n"
            "102,ACCTX01,Buy,ESH6,5800.00,1,2026-01-15 14:35:00,Filled\n"
        )
        self.assertEqual(_round_trip_sides(parse_tradovate_csv(orders, blinding_salt_hex=_SALT)), [])

    def test_mt4_closed_short_trade_is_matched(self) -> None:
        short = (
            "<tr><td>2</td><td>2026.02.03 08:00:00</td><td>sell</td><td>1.00</td><td>EURUSD</td><td>1.09100</td>"
            "<td>0</td><td>0</td><td>2026.02.04 10:00:00</td><td>1.08500</td><td>0.00</td><td>0.00</td><td>0.00</td>"
            "<td>600.00</td></tr>\n"
        )
        html = _mt4(
            _mt4_dep(1, "2026.02.02 08:00:00", "10 000.00") + short,
            "<td>Balance:</td><td>10 600.00</td><td>Equity:</td><td>10 600.00</td>",
        )
        self.assertEqual(_round_trip_sides(parse_mt4_statement(html, blinding_salt_hex=_SALT)), ["short"])

    def test_mt5_positions_short_round_trip_is_matched(self) -> None:
        tsv = (
            "Time\tPosition\tSymbol\tType\tVolume\tPrice\tS / L\tT / P\tTime\tPrice\tCommission\tSwap\tProfit\n"
            "2026.01.03 09:00:00\t1\tEURUSD\tsell\t1.00\t1.09100\t\t\t2026.01.04 10:00:00\t1.08500\t0.00\t0.00\t600.00\n"
        )
        self.assertEqual(_round_trip_sides(parse_mt5_statement(tsv, blinding_salt_hex=_SALT)), ["short"])

    def test_mt5_deals_first_sale_is_not_matched(self) -> None:
        tsv = (
            "Time\tDeal\tSymbol\tType\tDirection\tVolume\tPrice\tOrder\tCommission\tFee\tSwap\tProfit\tBalance\tComment\n"
            "2026.01.02 09:00:00\t9000\t\tbalance\t\t\t\t\t0.00\t0.00\t0.00\t10000.00\t10000.00\tFunding\n"
            "2026.01.03 09:00:00\t9001\tEURUSD\tsell\tin\t1.00\t1.09100\t1\t0.00\t0.00\t0.00\t0.00\t10000.00\t\n"
            "2026.01.04 10:00:00\t9002\tEURUSD\tbuy\tout\t1.00\t1.08500\t2\t0.00\t0.00\t0.00\t600.00\t10600.00\t\n"
        )
        self.assertEqual(_round_trip_sides(parse_mt5_statement(tsv, blinding_salt_hex=_SALT)), [])

    def test_journal_short_round_trips_are_matched(self) -> None:
        from n170_verify.connectors.journal_migration import parse_journal_migration_csv

        for name, text in (
            (
                "tradersync",
                "Status,Symbol,Size,Open Date,Open Time,Close Date,Close Time,Entry Price,Exit Price,Return $,Side\n"
                "WIN,NVDA,50,2026-01-08,09:35:00,2026-01-08,10:20:00,145.00,140.00,250.00,SHORT\n",
            ),
            (
                "tradezella",
                "Symbol,Side,Open Date,Close Date,Entry Price,Exit Price,Quantity,Net P&L\n"
                "NVDA,Short,2026-01-05 09:35:00,2026-01-06 15:50:00,108.00,100.00,10,80.00\n",
            ),
        ):
            with self.subTest(fmt=name):
                ledger = parse_journal_migration_csv(text, blinding_salt_hex=_SALT).ledger
                self.assertEqual(_round_trip_sides(ledger), ["short"])

    def test_transaction_exports_first_sale_is_not_matched(self) -> None:
        from n170_verify.connectors.statement_csv import parse_robinhood_csv, parse_schwab_csv

        robinhood = (
            "Activity Date,Process Date,Settle Date,Instrument,Description,Trans Code,Quantity,Price,Amount\n"
            "01/06/2026,01/06/2026,01/07/2026,NVDA,NVIDIA Corp,Sell,20,$148.50,$2970.00\n"
            "01/14/2026,01/14/2026,01/15/2026,NVDA,NVIDIA Corp,Buy,20,$135.00,-$2700.00\n"
        )
        schwab = (
            '"Date","Action","Symbol","Description","Quantity","Price","Fees & Comm","Amount"\n'
            '"01/06/2026","Sell","AAPL","Apple Inc","10","$210.00","$1.00","$2,099.00"\n'
            '"01/10/2026","Buy","AAPL","Apple Inc","10","$200.00","$1.00","-$2,001.00"\n'
        )
        degiro = (
            "Date,Time,Product,ISIN,Reference exchange,Quantity,Price,,Local value,,Value,,Exchange rate,Order ID\n"
            "06-01-2026,10:00,ASML HOLDING,NL0010273215,EAM,-5,712.80,EUR,3564.00,EUR,3564.00,EUR,,o1\n"
            "08-01-2026,10:00,ASML HOLDING,NL0010273215,EAM,5,680.40,EUR,-3402.00,EUR,-3402.00,EUR,,o2\n"
        )
        for name, ledger in (
            ("robinhood", parse_robinhood_csv(robinhood, blinding_salt_hex=_SALT)),
            ("schwab", parse_schwab_csv(schwab, blinding_salt_hex=_SALT)),
            ("degiro", parse_degiro_csv_bundle(transactions_csv=degiro, blinding_salt_hex=_SALT)),
        ):
            with self.subTest(fmt=name):
                self.assertGreaterEqual(len(ledger.trades), 2)
                self.assertEqual(_round_trip_sides(ledger), [])


if __name__ == "__main__":
    unittest.main()
