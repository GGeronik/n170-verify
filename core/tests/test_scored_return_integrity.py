"""A signed return, its coaching wealth path and its period describe only what was scored.

Rules covered here:
- when the cash flows inside one valuation interval are large next to the value at its
  start, that interval's return cannot be computed from its two valuations, and the
  record's return is withheld with a reason naming the date and the size;
- the coaching section's "actual" wealth path is the calculator's own path; when the
  return is withheld the signed record carries no such path;
- whenever a ledger has valuations, the signed period is exactly the span of the scored
  valuations; a requested period that would leave out a scored valuation is refused.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
import unittest

from n170_verify.coaching import simulate_counterfactual_twin
from n170_verify.contracts import (
    AssetClass,
    NormalizedTrade,
    AccountScope,
    CanonicalPortfolioLedger,
    EnvironmentTier,
    FlowKind,
    NormalizedFlow,
    NormalizedNavPoint,
    OriginAssurance,
    ProviderApprovalState,
    compute_blinded_account_tag,
)
from n170_verify.performance import calculate_portfolio_performance_detailed
from n170_verify.performance import calculator as _calculator
from n170_verify.pipeline import ingest_portfolio_ledger, verify_portfolio


_SALT = "b2" * 32
_TAG = compute_blinded_account_tag("dummy_broker", "DUMMY-ACCT-2", _SALT)
_ISSUED = "2026-12-20T12:00:00Z"
_DAY0 = datetime(2026, 11, 1, 23, 30, tzinfo=timezone.utc)


def _iso(ts: datetime) -> str:
    return ts.isoformat().replace("+00:00", "Z")


def _navs(values: list[float], start: datetime = _DAY0) -> list[NormalizedNavPoint]:
    return [
        NormalizedNavPoint(timestamp_utc=_iso(start + timedelta(days=i)), nav_base=v)
        for i, v in enumerate(values)
    ]


def _flow(ts: datetime, kind: FlowKind, amount: float) -> NormalizedFlow:
    return NormalizedFlow(timestamp_utc=_iso(ts), kind=kind, amount=amount, amount_base=amount)


def _ledger(
    navs: list[NormalizedNavPoint],
    flows: list[NormalizedFlow] | None = None,
    **overrides: Any,
) -> CanonicalPortfolioLedger:
    fields: dict[str, Any] = {
        "blinded_account_tag": _TAG,
        "broker_id": "dummy_broker",
        "account_scope": AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED,
        "claimed_origin_assurance": OriginAssurance.SELF_REPORTED,
        "provider_approval_state": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
        "environment_tier": EnvironmentTier.LIVE_PRODUCTION,
        "source_body_sha256": "cd" * 32,
        "base_currency": "USD",
        "period_start_utc": navs[0].timestamp_utc if navs else "2026-11-01T00:00:00Z",
        "period_end_utc": navs[-1].timestamp_utc if navs else "2026-11-30T00:00:00Z",
        "nav_points": navs,
        "flows": flows or [],
    }
    fields.update(overrides)
    return CanonicalPortfolioLedger(**fields)


_STEADY = [10000.0 * (1.0 + 0.002 * i) for i in range(12)]


class LargeIntervalFlowTests(unittest.TestCase):
    def test_threshold_is_ten_percent_of_the_opening_value(self) -> None:
        self.assertEqual(getattr(_calculator, "LARGE_INTERVAL_FLOW_FRACTION", None), 0.10)

    def test_a_large_flow_inside_one_interval_withholds_the_return(self) -> None:
        # Value 10,000; 9,000 withdrawn early in the next day; close 2,000.
        navs = _navs([10000.0, 2000.0, 2000.0])
        withdrawal = _flow(_DAY0 + timedelta(hours=1, minutes=30), FlowKind.WITHDRAWAL, 9000.0)
        for timing in ("end_of_day", "start_of_day", "modified_dietz"):
            with self.subTest(timing=timing):
                res = calculate_portfolio_performance_detailed(
                    _ledger(navs, [withdrawal]), cash_flow_timing=timing
                )
                self.assertTrue(res.withheld)
                self.assertTrue(res.summary.performance_withheld)
                reason = res.summary.withheld_reasons[0]
                self.assertIn(navs[1].timestamp_utc, reason)
                self.assertIn("90.0%", reason)

    def test_an_intraday_wipe_out_hidden_by_a_same_day_deposit_is_withheld(self) -> None:
        navs = _navs([10000.0, 11000.0, 11000.0])
        deposit = _flow(_DAY0 + timedelta(hours=12), FlowKind.DEPOSIT, 10000.0)
        out = verify_portfolio(ledger=_ledger(navs, [deposit]), cash_flow_timing="modified_dietz", issued_at_utc=_ISSUED)
        self.assertTrue(out.performance_withheld)
        self.assertIn("100.0%", out.withheld_reasons[0])

    def test_gross_flows_count_even_when_they_net_to_zero(self) -> None:
        navs = _navs([10000.0, 10100.0, 10200.0])
        flows = [
            _flow(_DAY0 + timedelta(hours=3), FlowKind.DEPOSIT, 3000.0),
            _flow(_DAY0 + timedelta(hours=6), FlowKind.WITHDRAWAL, 3000.0),
        ]
        res = calculate_portfolio_performance_detailed(_ledger(navs, flows))
        self.assertTrue(res.withheld)
        self.assertIn("60.0%", res.summary.withheld_reasons[0])

    def test_a_small_flow_is_still_scored(self) -> None:
        navs = _navs([10000.0, 10600.0, 10700.0])
        deposit = _flow(_DAY0 + timedelta(hours=6), FlowKind.DEPOSIT, 500.0)
        res = calculate_portfolio_performance_detailed(_ledger(navs, [deposit]))
        self.assertFalse(res.withheld)

    def test_a_zero_opening_value_keeps_its_existing_handling(self) -> None:
        navs = _navs([0.0, 10000.0, 10100.0])
        deposit = _flow(_DAY0 + timedelta(hours=6), FlowKind.DEPOSIT, 10000.0)
        res = calculate_portfolio_performance_detailed(_ledger(navs, [deposit]))
        self.assertTrue(res.withheld)
        self.assertIn("non-positive or invalid", res.summary.withheld_reasons[0])


class CoachingActualPathTests(unittest.TestCase):
    def _twin(self, out: Any) -> Any:
        return out.proof_bundle.get_disclosed_payload("coaching_and_context")["counterfactual_twin"]

    def test_a_withheld_return_signs_no_actual_wealth_path(self) -> None:
        navs = _navs([10000.0, 10100.0, 0.0, 6000.0, 6100.0])
        out = verify_portfolio(ledger=_ledger(navs), issued_at_utc=_ISSUED)
        self.assertTrue(out.performance_withheld)
        self.assertIsNone(self._twin(out))

    def test_the_actual_path_is_the_calculators_path(self) -> None:
        navs = _navs(_STEADY)
        deposit = _flow(_DAY0 + timedelta(days=3, hours=2), FlowKind.DEPOSIT, 600.0)
        navs[4] = NormalizedNavPoint(timestamp_utc=navs[4].timestamp_utc, nav_base=navs[4].nav_base + 600.0)
        for i in range(5, len(navs)):
            navs[i] = NormalizedNavPoint(timestamp_utc=navs[i].timestamp_utc, nav_base=navs[i].nav_base + 600.0)
        out = verify_portfolio(ledger=_ledger(navs, [deposit]), cash_flow_timing="modified_dietz", issued_at_utc=_ISSUED)
        self.assertFalse(out.performance_withheld)
        twin = self._twin(out)
        curve = out.performance.indexed_curve
        self.assertEqual(
            [pt["actual"] for pt in twin["curve_points"]],
            [round(pt.index_value / 100.0, 6) for pt in curve],
        )
        self.assertEqual(twin["actual_ending_index"], round(1.0 + out.performance.twr_decimal, 6))

    def test_where_both_paths_agree_the_coaching_twin_is_unchanged(self) -> None:
        navs = _navs(_STEADY)
        ledger = _ledger(navs, [_flow(_DAY0 + timedelta(days=2, hours=2), FlowKind.DEPOSIT, 300.0)])
        res = calculate_portfolio_performance_detailed(ledger)
        recomputed = simulate_counterfactual_twin(ledger)
        from_calculator = simulate_counterfactual_twin(
            ledger, scored_period_returns=[obs.period_return for obs in res.return_observations]
        )
        self.assertEqual(recomputed.to_dict(), from_calculator.to_dict())


class _WindowedConnector:
    """Connector stand-in that returns the valuations it has inside a requested window."""

    def __init__(self, navs: list[NormalizedNavPoint], flows: list[NormalizedFlow] | None = None) -> None:
        self.navs = navs
        self.flows = flows or []

    def fetch_canonical_ledger(
        self, *, blinding_salt_hex: str, start_date: str | None = None, end_date: str | None = None
    ) -> CanonicalPortfolioLedger:
        start = start_date or self.navs[0].timestamp_utc
        end = end_date or self.navs[-1].timestamp_utc
        inside = [pt for pt in self.navs if start <= pt.timestamp_utc <= end]
        return _ledger(inside, self.flows, period_start_utc=start, period_end_utc=end)


class SignedPeriodIsTheScoredSpanTests(unittest.TestCase):
    def test_a_fetch_window_wider_than_the_data_signs_only_the_scored_span(self) -> None:
        navs = _navs(_STEADY)
        for fetch_kw in (
            {"end_date": "2026-12-31T23:59:59Z"},
            {"start_date": "2026-01-01T00:00:00Z"},
            {"start_date": "2026-01-01T00:00:00Z", "end_date": "2027-06-30T23:59:59Z"},
        ):
            with self.subTest(fetch=sorted(fetch_kw)):
                out = verify_portfolio(
                    connector=_WindowedConnector(navs),
                    connector_fetch_kwargs=fetch_kw,
                    issued_at_utc=_ISSUED,
                )
                self.assertEqual(out.proof_bundle.period_start_utc, navs[0].timestamp_utc)
                self.assertEqual(out.proof_bundle.period_end_utc, navs[-1].timestamp_utc)

    def test_a_period_derived_from_activity_dates_is_replaced_by_the_scored_span(self) -> None:
        navs = _navs(_STEADY, start=datetime(2026, 10, 1, 20, 0, tzinfo=timezone.utc))
        old_deposit = _flow(datetime(2024, 1, 5, 12, 0, tzinfo=timezone.utc), FlowKind.DEPOSIT, 5000.0)
        ledger = ingest_portfolio_ledger(
            ledger=_ledger(navs, [old_deposit], period_start_utc="2024-01-05T12:00:00Z"),
        )
        self.assertEqual(ledger.period_start_utc, navs[0].timestamp_utc)
        self.assertEqual(ledger.period_end_utc, navs[-1].timestamp_utc)

    def test_a_requested_period_that_leaves_out_scored_valuations_is_refused(self) -> None:
        navs = _navs(_STEADY)
        for req in (
            {"period_start_utc": navs[3].timestamp_utc},
            {"period_end_utc": navs[-3].timestamp_utc},
        ):
            with self.subTest(request=sorted(req)):
                with self.assertRaises(ValueError) as ctx:
                    verify_portfolio(ledger=_ledger(navs), issued_at_utc=_ISSUED, **req)
                self.assertIn("scored valuation", str(ctx.exception))

    def test_one_valuation_signs_a_single_instant(self) -> None:
        navs = _navs([10000.0])
        ledger = ingest_portfolio_ledger(
            ledger=_ledger(navs, period_start_utc="2026-10-01T00:00:00Z", period_end_utc="2026-11-30T00:00:00Z")
        )
        self.assertEqual(ledger.period_start_utc, navs[0].timestamp_utc)
        self.assertEqual(ledger.period_end_utc, navs[0].timestamp_utc)


_TAG_SAMPLES = [
    "Oversized Account 99887766",
    "ORB_5m",
    "<b>Breakout</b>",
    "Size 12345 add",
    "=HYPERLINK(x)",
    "javascript:alert",
    "onload=Fade",
    "@everyone Ping",
    "risk_$500_setup",
    "Momentum_Breakout",
]
_TAG_EXPECTED = [
    "ORB_5m",
    "HYPERLINK(x)",
    "alert",
    "Fade",
    "everyone Ping",
    "Momentum_Breakout",
]


class SignedJournalTagTests(unittest.TestCase):
    """Imported journal tags are cleaned once in the shared pipeline before anything is signed.

    Tags with markup, path characters or currency amounts are dropped; digit runs of five or
    more, script schemes, event attributes and mass mentions are removed from the rest.
    """

    def test_the_pipeline_signs_cleaned_journal_tags(self) -> None:
        out = verify_portfolio(
            ledger=_ledger(_navs(_STEADY)), imported_journal_tags=_TAG_SAMPLES, issued_at_utc=_ISSUED
        )
        signed = out.proof_bundle.get_disclosed_payload("coaching_and_context")["imported_journal_tags"]
        self.assertEqual(signed, _TAG_EXPECTED)

    def test_a_statement_through_the_worker_signs_cleaned_journal_tags(self) -> None:
        from n170_verify.pipeline import api_worker_pipeline_entrypoint

        csv_text = "\n".join(
            [
                "Open Date,Close Date,Symbol,Side,Entry Price,Exit Price,Playbook,Setups,Mistakes,Custom Tags",
                "2026-02-03,2026-02-03,NVDA,LONG,128.40,134.90,Momentum_Breakout,ORB_5m,None,Oversized Account 99887766",
                "2026-02-06,2026-02-06,TSLA,SHORT,362.10,354.20,Mean_Reversion,VWAP_Fade,Early_Exit_Trim,ny_open_alpha",
            ]
        )
        result = api_worker_pipeline_entrypoint(
            {
                "broker_id": "tradezella_journal",
                "raw_statement": csv_text,
                "account_blinding_salt_hex": _SALT,
                "issued_at_utc": "2026-04-15T12:00:00Z",
            }
        )
        coaching = next(
            leaf["payload"] for leaf in result["disclosed_leaves"] if leaf["leaf_name"] == "coaching_and_context"
        )
        tags = coaching["imported_journal_tags"]
        self.assertIn("ORB_5m", tags)
        self.assertFalse(any("99887766" in t or t.startswith("Oversized") for t in tags))


def _returns_of(ledger: CanonicalPortfolioLedger, **kw: Any) -> tuple[Any, list[float]]:
    res = calculate_portfolio_performance_detailed(ledger, **kw)
    return res, [obs.period_return for obs in res.return_observations]


def _series(days: list[int], start: datetime = datetime(2023, 1, 2, 20, 0, tzinfo=timezone.utc)) -> list[NormalizedNavPoint]:
    out, v = [], 10000.0
    for i, d in enumerate(days):
        out.append(NormalizedNavPoint(timestamp_utc=_iso(start + timedelta(days=d)), nav_base=round(v, 4)))
        v *= 1.01 if i % 2 == 0 else 0.996
    return out


class AnnualisationFromTheSeriesTests(unittest.TestCase):
    """The annualisation factor is the number of scored intervals per year of the series."""

    def _check_factor(self, days: list[int]) -> float:
        import math
        from statistics import stdev

        navs = _series(days)
        res, rets = _returns_of(_ledger(navs))
        self.assertFalse(res.withheld)
        span_years = days[-1] / 365.0
        factor = (len(days) - 1) / span_years
        self.assertAlmostEqual(res.summary.annualized_volatility, stdev(rets) * math.sqrt(factor), places=9)
        self.assertAlmostEqual(res.annualization_periods_per_year, factor, places=9)
        return factor

    def test_calendar_daily_series_annualise_at_365(self) -> None:
        self.assertAlmostEqual(self._check_factor(list(range(60))), 365.0, places=6)

    def test_business_daily_series_annualise_by_their_own_count(self) -> None:
        days = [d for d in range(0, 120) if (d % 7) < 5]  # weekdays only, from a Monday
        factor = self._check_factor(days)
        self.assertTrue(255.0 < factor < 265.0, factor)

    def test_weekly_and_monthly_series_annualise_by_their_own_count(self) -> None:
        self.assertAlmostEqual(self._check_factor([7 * i for i in range(40)]), 365.0 / 7.0, places=6)
        months = [0]
        for i in range(1, 37):
            months.append(months[-1] + (31 if i % 2 else 30))
        factor = self._check_factor(months)
        self.assertTrue(11.5 < factor < 12.5, factor)

    def test_uneven_intervals_withhold_the_annualised_figures_not_the_return(self) -> None:
        days = list(range(40)) + [40 + 45, 40 + 46, 40 + 47]
        res, _ = _returns_of(_ledger(_series(days)))
        self.assertFalse(res.withheld)
        s = res.summary
        for name in (
            "annualized_volatility",
            "sharpe_ratio",
            "sortino_ratio",
            "unsmoothed_volatility",
            "unsmoothed_sharpe_ratio",
            "probabilistic_sharpe_ratio",
            "psr_glm_unsmoothed",
            "min_track_record_length_periods",
        ):
            self.assertIsNone(getattr(s, name), name)
        self.assertFalse(s.psr_sample_eligible)
        self.assertIsNone(res.annualization_periods_per_year)
        self.assertTrue(any("annualised figures are withheld" in w for w in s.warnings))
        self.assertNotEqual(s.twr_decimal, 0.0)

    def test_an_explicit_factor_from_a_library_caller_is_used_as_given(self) -> None:
        import math
        from statistics import stdev

        res, rets = _returns_of(_ledger(_series(list(range(60)))), periods_per_year=252)
        self.assertAlmostEqual(res.summary.annualized_volatility, stdev(rets) * math.sqrt(252), places=9)


class WithheldRecordCarriesNoValuationScoresTests(unittest.TestCase):
    def test_a_withheld_record_signs_no_drawdown_or_valuation_based_scores(self) -> None:
        navs = _navs([10000.0, 10100.0, 0.0, 6000.0, 6100.0])
        out = verify_portfolio(ledger=_ledger(navs), issued_at_utc=_ISSUED)
        self.assertTrue(out.performance_withheld)
        coaching = out.proof_bundle.get_disclosed_payload("coaching_and_context")
        self.assertIsNone(coaching["quant_dna"])
        self.assertIsNone(coaching["behaviour"]["post_drawdown_sizing_discipline_atr"])


class JournalTagNumberTests(unittest.TestCase):
    def test_tags_with_account_like_numbers_or_amounts_are_dropped(self) -> None:
        from n170_verify.coaching import sanitize_journal_tags

        dropped = [
            "acct U12345678",
            "U12345678",
            "acct_987654321",
            "x123456y",
            "1234 5678 9012 3456",
            "1234 5678 9012",
            "12,345 profit",
            "made 2500 usd",
            "1 555 123 4567",
            "50 dollars stop",
            "EUR 25 add",
            "lost 3 euros",
        ]
        kept = ["ORB_5m", "2R target", "ok tag", "1.2k win", "15m VWAP", "Top 10 gap"]
        self.assertEqual(sanitize_journal_tags(dropped + kept), kept)


def _trade(sym: str, side: str, ts: datetime, qty: float, px: float, tid: str) -> NormalizedTrade:
    return NormalizedTrade(
        venue="DUMMY", native_entry_id=tid, symbol=sym, asset_class=AssetClass.EQUITY,
        side=side, quantity=qty, price=px, timestamp_utc=_iso(ts),
    )


class ActivityInsideTheSignedPeriodTests(unittest.TestCase):
    def test_activity_outside_the_scored_span_is_not_in_the_ledger(self) -> None:
        jan5 = datetime(2026, 1, 5, 20, 0, tzinfo=timezone.utc)
        navs = _navs([10000.0, 10050.0, 10100.0, 10080.0, 10120.0], start=jan5)
        trades = [
            _trade("AAPL", "buy", datetime(2025, 11, 3, 14, 30, tzinfo=timezone.utc), 10, 200.0, "t1"),
            _trade("AAPL", "sell", datetime(2025, 11, 20, 14, 30, tzinfo=timezone.utc), 10, 210.0, "t2"),
            _trade("AAPL", "buy", jan5 + timedelta(days=1, hours=-3), 5, 205.0, "t3"),
            _trade("AAPL", "sell", jan5 + timedelta(days=2, hours=-3), 5, 207.0, "t4"),
            _trade("MSFT", "buy", jan5 + timedelta(days=1, hours=-2), 3, 400.0, "t5"),
            _trade("MSFT", "sell", jan5 + timedelta(days=3, hours=-2), 3, 404.0, "t6"),
        ]
        flows = [_flow(datetime(2025, 12, 1, 12, 0, tzinfo=timezone.utc), FlowKind.DEPOSIT, 2000.0)]
        ledger = ingest_portfolio_ledger(ledger=_ledger(navs, flows, trades=trades, period_start_utc="2025-11-01T00:00:00Z"))
        self.assertEqual(sorted(t.native_entry_id for t in ledger.trades), ["t5", "t6"])
        self.assertEqual(ledger.flows, [])
        self.assertTrue(any("held into the valuation series" in w for w in ledger.parser_warnings))

    def test_a_ledger_without_valuations_keeps_its_activity(self) -> None:
        trades = [
            _trade("AAPL", "buy", datetime(2025, 11, 3, 14, 30, tzinfo=timezone.utc), 10, 200.0, "t1"),
            _trade("AAPL", "sell", datetime(2025, 11, 20, 14, 30, tzinfo=timezone.utc), 10, 210.0, "t2"),
        ]
        ledger = ingest_portfolio_ledger(
            ledger=_ledger([], trades=trades, period_start_utc="2025-11-01T00:00:00Z", period_end_utc="2025-11-30T00:00:00Z")
        )
        self.assertEqual(len(ledger.trades), 2)


class ZeroOpeningValueTests(unittest.TestCase):
    def test_an_interval_opening_at_zero_withholds_in_every_timing_mode(self) -> None:
        navs = _navs([0.0, 10500.0, 10600.0])
        deposit = _flow(_DAY0 + timedelta(hours=12), FlowKind.DEPOSIT, 10000.0)
        for timing in ("end_of_day", "start_of_day", "modified_dietz"):
            with self.subTest(timing=timing):
                res = calculate_portfolio_performance_detailed(_ledger(navs, [deposit]), cash_flow_timing=timing)
                self.assertTrue(res.withheld)
                out = verify_portfolio(ledger=_ledger(navs, [deposit]), cash_flow_timing=timing, issued_at_utc=_ISSUED)
                self.assertTrue(out.performance_withheld)


_MT5_NO_CURRENCY = "\n".join(
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
)


class StatementCurrencyLabelTests(unittest.TestCase):
    def test_the_currency_label_comes_from_the_parser_not_the_request(self) -> None:
        from n170_verify.pipeline import api_worker_pipeline_entrypoint

        baseline = api_worker_pipeline_entrypoint(
            {"broker_id": "mt5_statement", "raw_statement": _MT5_NO_CURRENCY, "account_blinding_salt_hex": _SALT,
             "issued_at_utc": "2026-04-15T12:00:00Z"}
        )["base_currency"]
        for mismatched_broker in ("degiro", "degiro_csv"):
            with self.subTest(mismatched_broker=mismatched_broker):
                with self.assertRaises(ValueError):
                    api_worker_pipeline_entrypoint(
                        {
                            "broker_id": mismatched_broker,
                            "raw_statement": _MT5_NO_CURRENCY,
                            "account_blinding_salt_hex": _SALT,
                            "issued_at_utc": "2026-04-15T12:00:00Z",
                        }
                    )
        for extra in (
            {"broker_id": "mt5"},
            {"broker_id": "auto_detect", "base_currency": "EUR"},
            {"broker_id": "mt5_statement", "base_currency": "EUR", "base_currency_explicit": True},
        ):
            with self.subTest(extra=sorted(extra.items())):
                job = {"broker_id": "mt5_statement", "raw_statement": _MT5_NO_CURRENCY,
                       "account_blinding_salt_hex": _SALT, "issued_at_utc": "2026-04-15T12:00:00Z", **extra}
                self.assertEqual(api_worker_pipeline_entrypoint(job)["base_currency"], baseline)


class WithheldRecordDisclosureTests(unittest.TestCase):
    def test_a_withheld_record_always_discloses_its_core_metrics(self) -> None:
        navs = _navs([10000.0, 10100.0, 0.0, 6000.0, 6100.0])
        out = verify_portfolio(ledger=_ledger(navs), issued_at_utc=_ISSUED, disclose_leaf_names=["capital_bracket"])
        self.assertTrue(out.performance_withheld)
        self.assertIs(out.proof_bundle.get_disclosed_payload("core_metrics")["performance_withheld"], True)



class OpeningPositionBeforeTheLedgerTests(unittest.TestCase):
    """An instrument whose first trade in the ledger closes a position held from before is not matched into round trips."""

    def test_a_first_sale_with_nothing_bought_before_drops_the_instrument(self) -> None:
        nov3 = datetime(2025, 11, 3, 23, 59, 59, tzinfo=timezone.utc)
        navs = _navs([100000.0 + 10 * i for i in range(26)], start=nov3)
        trades = [
            _trade("AAPL", "sell", datetime(2025, 11, 5, 14, 30, tzinfo=timezone.utc), 100, 210.0, "a1"),
            _trade("AAPL", "buy", datetime(2025, 11, 6, 14, 30, tzinfo=timezone.utc), 100, 200.0, "a2"),
            _trade("AAPL", "sell", datetime(2025, 11, 10, 14, 30, tzinfo=timezone.utc), 100, 205.0, "a3"),
            _trade("MSFT", "buy", datetime(2025, 11, 6, 15, 0, tzinfo=timezone.utc), 10, 400.0, "m1"),
            _trade("MSFT", "sell", datetime(2025, 11, 12, 15, 0, tzinfo=timezone.utc), 10, 410.0, "m2"),
        ]
        out = verify_portfolio(ledger=_ledger(navs, trades=trades), issued_at_utc=_ISSUED)
        trips = out.proof_bundle.get_disclosed_payload("delayed_closed_trades")["trades"]
        self.assertEqual([t["symbol"] for t in trips], ["MSFT"])
        self.assertTrue(any("first trade in the ledger" in w for w in out.parser_warnings))

    def test_a_stated_opening_position_drops_the_instrument(self) -> None:
        from n170_verify.contracts import NormalizedPosition

        nov3 = datetime(2025, 11, 3, 23, 59, 59, tzinfo=timezone.utc)
        navs = _navs([100000.0 + 10 * i for i in range(26)], start=nov3)
        trades = [
            _trade("AAPL", "buy", datetime(2025, 11, 6, 14, 30, tzinfo=timezone.utc), 100, 200.0, "a2"),
            _trade("AAPL", "sell", datetime(2025, 11, 10, 14, 30, tzinfo=timezone.utc), 100, 205.0, "a3"),
        ]
        prior = [NormalizedPosition(prior_period_or_ending="prior", symbol="AAPL", asset_class=AssetClass.EQUITY,
                                    quantity=50.0, cost_basis=9000.0, market_value=10000.0)]
        out = verify_portfolio(ledger=_ledger(navs, trades=trades, prior_positions=prior), issued_at_utc=_ISSUED)
        self.assertEqual(out.proof_bundle.get_disclosed_payload("delayed_closed_trades")["trades"], [])
        self.assertTrue(any("first trade in the ledger" in w for w in out.parser_warnings))


class RecordDatesWithinIssueTimeTests(unittest.TestCase):
    def test_activity_after_the_issue_time_is_refused(self) -> None:
        navs = _navs(_STEADY, start=datetime(2027, 3, 1, 21, 0, tzinfo=timezone.utc))
        with self.assertRaises(ValueError) as ctx:
            verify_portfolio(ledger=_ledger(navs), issued_at_utc=_ISSUED)
        self.assertIn("after the record's issue time", str(ctx.exception))

    def test_activity_before_the_earliest_accepted_date_is_refused(self) -> None:
        old = [_trade("AAPL", "buy", datetime(1, 1, 2, tzinfo=timezone.utc), 1, 10.0, "o1")]
        with self.assertRaises(ValueError) as ctx:
            verify_portfolio(
                ledger=_ledger([], trades=old, period_start_utc="0001-01-01T00:00:00Z", period_end_utc="0001-01-31T00:00:00Z"),
                issued_at_utc=_ISSUED,
            )
        self.assertIn("before", str(ctx.exception))


class AnnualisationPreconditionTests(unittest.TestCase):
    """Annualised figures need three or more even intervals of at least a day; CAGR also a minimum span."""

    _ANNUALISED = (
        "annualized_volatility", "sharpe_ratio", "sortino_ratio", "unsmoothed_volatility",
        "unsmoothed_sharpe_ratio", "probabilistic_sharpe_ratio", "psr_glm_unsmoothed",
        "min_track_record_length_periods", "cagr_decimal",
    )

    def _summary(self, gaps_days: list[float]) -> Any:
        start = datetime(2025, 1, 2, 21, 0, tzinfo=timezone.utc)
        t, v, navs = start, 100000.0, []
        navs.append(NormalizedNavPoint(timestamp_utc=_iso(t), nav_base=v))
        for i, g in enumerate(gaps_days):
            t = t + timedelta(days=g)
            v *= 1.004 if i % 2 == 0 else 0.9968
            navs.append(NormalizedNavPoint(timestamp_utc=_iso(t), nav_base=round(v, 2)))
        res = calculate_portfolio_performance_detailed(_ledger(navs))
        self.assertFalse(res.withheld)
        return res

    def _assert_withheld(self, res: Any) -> None:
        for name in self._ANNUALISED:
            self.assertIsNone(getattr(res.summary, name), name)
        self.assertFalse(res.summary.psr_sample_eligible)
        self.assertIsNone(res.annualization_periods_per_year)
        self.assertNotEqual(res.summary.twr_decimal, 0.0)

    def test_two_intervals_are_not_annualised(self) -> None:
        self._assert_withheld(self._summary([59, 1]))

    def test_mixed_long_and_short_intervals_are_not_annualised_either_way_round(self) -> None:
        self._assert_withheld(self._summary([30] * 11 + [1] * 10))
        self._assert_withheld(self._summary([30] * 10 + [1] * 11))

    def test_intervals_shorter_than_a_day_are_not_annualised(self) -> None:
        self._assert_withheld(self._summary([1 / 1440] * 20))

    def test_cagr_needs_the_minimum_span(self) -> None:
        res = self._summary([1] * 20)
        self.assertIsNotNone(res.summary.annualized_volatility)
        self.assertIsNone(res.summary.cagr_decimal)
        long_res = self._summary([7] * 60)
        self.assertIsNotNone(long_res.summary.cagr_decimal)

    def test_a_daily_close_a_little_early_or_late_still_counts_as_a_day(self) -> None:
        res = self._summary([1, 1 - 4 / 24, 1 + 4 / 24] * 8)
        self.assertIsNotNone(res.summary.annualized_volatility)



class WithheldRecordCostDragTests(unittest.TestCase):
    """A withheld record signs no ratio divided by, or annualised over, its valuations."""

    _RATIOS = (
        "commission_and_fee_drag_bps",
        "margin_and_funding_drag_bps",
        "fx_conversion_drag_bps",
        "withholding_tax_drag_bps",
        "total_friction_drag_bps",
        "annualized_total_drag_bps",
    )

    def test_a_withheld_record_signs_null_cost_drag_ratios(self) -> None:
        navs = _navs([10000.0, 10100.0, 0.0, 6000.0, 6100.0])
        trades = [
            _trade("MSFT", "buy", _DAY0 + timedelta(hours=3), 3, 400.0, "w1"),
            _trade("MSFT", "sell", _DAY0 + timedelta(days=1, hours=3), 3, 404.0, "w2"),
        ]
        trades = [NormalizedTrade.from_dict({**t.to_dict(), "commission": 1.5}) for t in trades]
        out = verify_portfolio(ledger=_ledger(navs, trades=trades), issued_at_utc=_ISSUED)
        self.assertTrue(out.performance_withheld)
        coaching = out.proof_bundle.get_disclosed_payload("coaching_and_context")
        for name in self._RATIOS:
            self.assertIsNone(coaching["cost_drag"][name], name)
        self.assertNotIn("bps", coaching["style_summary"])
        self.assertFalse(any("bps" in t for t in coaching["coaching_takeaways"]))

    def test_cost_drag_with_null_ratios_round_trips_and_old_leaves_still_parse(self) -> None:
        from n170_verify.contracts import CostAndDragBreakdown

        empty = CostAndDragBreakdown(**{name: None for name in self._RATIOS})
        self.assertEqual(CostAndDragBreakdown.from_dict(empty.to_dict()), empty)
        old = {name: 1.25 for name in self._RATIOS}
        self.assertEqual(CostAndDragBreakdown.from_dict(old).to_dict(), old)


if __name__ == "__main__":
    unittest.main()
