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
    "Oversized Account",
    "ORB_5m",
    "Size add",
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
        self.assertIn("Oversized Account", tags)
        self.assertFalse(any(any(ch.isdigit() for ch in t) and "99887766" in t for t in tags))


if __name__ == "__main__":
    unittest.main()
