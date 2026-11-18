"""The signed period and the signed performance section never claim more than was computed.

Rules covered here:
- a requested period may narrow a record, never widen it beyond the first and last NAV
  point that were scored; a ledger without NAV points keeps the requested period;
- when a return cannot be computed, the signed performance section says so
  (``performance_withheld: true`` plus the reasons) and the pipeline output carries the
  same flag; a computed record carries neither key.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
import unittest

from n170_verify.contracts import (
    AccountScope,
    CanonicalPortfolioLedger,
    EnvironmentTier,
    NormalizedNavPoint,
    OriginAssurance,
    PerformanceSummary,
    ProviderApprovalState,
    compute_blinded_account_tag,
)
from n170_verify.performance import calculate_portfolio_performance_detailed
from n170_verify.pipeline import ingest_portfolio_ledger, verify_portfolio


_SALT = "a1" * 32
_TAG = compute_blinded_account_tag("dummy_broker", "DUMMY-ACCT-1", _SALT)
_ISSUED = "2026-04-15T12:00:00Z"


def _iso(ts: datetime) -> str:
    return ts.isoformat().replace("+00:00", "Z")


def _navs(start: datetime, values: list[float]) -> list[NormalizedNavPoint]:
    return [
        NormalizedNavPoint(timestamp_utc=_iso(start + timedelta(days=i)), nav_base=v)
        for i, v in enumerate(values)
    ]


def _ledger(nav_points: list[NormalizedNavPoint], **overrides: Any) -> CanonicalPortfolioLedger:
    fields: dict[str, Any] = {
        "blinded_account_tag": _TAG,
        "broker_id": "dummy_broker",
        "account_scope": AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED,
        "claimed_origin_assurance": OriginAssurance.SELF_REPORTED,
        "provider_approval_state": ProviderApprovalState.OFFLINE_EXPORT_ONLY,
        "environment_tier": EnvironmentTier.LIVE_PRODUCTION,
        "source_body_sha256": "ab" * 32,
        "base_currency": "USD",
        "period_start_utc": nav_points[0].timestamp_utc if nav_points else "2026-02-01T00:00:00Z",
        "period_end_utc": nav_points[-1].timestamp_utc if nav_points else "2026-02-20T00:00:00Z",
        "nav_points": nav_points,
    }
    fields.update(overrides)
    return CanonicalPortfolioLedger(**fields)


_FEB = datetime(2026, 2, 1, 20, 0, tzinfo=timezone.utc)
_COMPUTED_VALUES = [10000.0 * (1.0 + 0.001 * (i % 5)) for i in range(20)]


def _core_metrics(output: Any) -> dict[str, Any]:
    return output.proof_bundle.get_disclosed_payload("core_metrics")


class SignedPeriodTests(unittest.TestCase):
    def test_requested_period_never_widens_beyond_the_scored_nav_series(self) -> None:
        navs = _navs(_FEB, _COMPUTED_VALUES)
        out = verify_portfolio(
            ledger=_ledger(navs),
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-03-31T00:00:00Z",
            issued_at_utc=_ISSUED,
        )
        self.assertEqual(out.period_start_utc, navs[0].timestamp_utc)
        self.assertEqual(out.period_end_utc, navs[-1].timestamp_utc)
        self.assertEqual(out.proof_bundle.period_start_utc, navs[0].timestamp_utc)
        self.assertEqual(out.proof_bundle.period_end_utc, navs[-1].timestamp_utc)

    def test_requested_period_may_narrow_the_record(self) -> None:
        navs = _navs(_FEB, _COMPUTED_VALUES)
        ledger = ingest_portfolio_ledger(
            ledger=_ledger(navs),
            period_start_utc="2026-02-05T00:00:00Z",
            period_end_utc="2026-02-10T00:00:00Z",
        )
        self.assertEqual(ledger.period_start_utc, "2026-02-05T00:00:00Z")
        self.assertEqual(ledger.period_end_utc, "2026-02-10T00:00:00Z")

    def test_requested_period_outside_the_nav_series_is_refused(self) -> None:
        navs = _navs(_FEB, _COMPUTED_VALUES)
        with self.assertRaises(ValueError):
            ingest_portfolio_ledger(
                ledger=_ledger(navs),
                period_start_utc="2026-05-01T00:00:00Z",
                period_end_utc="2026-06-01T00:00:00Z",
            )

    def test_ledger_without_nav_points_keeps_the_requested_period(self) -> None:
        ledger = ingest_portfolio_ledger(
            ledger=_ledger([]),
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-03-31T00:00:00Z",
        )
        self.assertEqual(ledger.period_start_utc, "2026-01-01T00:00:00Z")
        self.assertEqual(ledger.period_end_utc, "2026-03-31T00:00:00Z")


class WithheldPerformanceTests(unittest.TestCase):
    def test_a_withheld_return_is_stated_in_the_signed_performance_section(self) -> None:
        wiped = _navs(_FEB, [10000.0, 10100.0, 0.0, 50.0, 60.0])
        duplicate = [
            NormalizedNavPoint(timestamp_utc=_iso(_FEB), nav_base=10000.0),
            NormalizedNavPoint(timestamp_utc=_iso(_FEB), nav_base=10100.0),
        ]
        single = _navs(_FEB, [10000.0])
        for label, navs in (("wipe_out", wiped), ("duplicate", duplicate), ("single", single)):
            with self.subTest(case=label):
                out = verify_portfolio(ledger=_ledger(navs), issued_at_utc=_ISSUED)
                metrics = _core_metrics(out)
                self.assertIs(metrics.get("performance_withheld"), True)
                self.assertTrue(metrics.get("withheld_reasons"))
                self.assertTrue(all("withheld" in r or "required" in r for r in metrics["withheld_reasons"]))
                self.assertIs(out.performance_withheld, True)
                self.assertEqual(out.withheld_reasons, metrics["withheld_reasons"])
                self.assertTrue(out.verification.signature_valid)

    def test_a_computed_record_carries_no_withheld_keys(self) -> None:
        out = verify_portfolio(ledger=_ledger(_navs(_FEB, _COMPUTED_VALUES)), issued_at_utc=_ISSUED)
        metrics = _core_metrics(out)
        self.assertNotIn("performance_withheld", metrics)
        self.assertNotIn("withheld_reasons", metrics)
        self.assertIs(out.performance_withheld, False)
        self.assertEqual(out.withheld_reasons, [])

        summary = calculate_portfolio_performance_detailed(_ledger(_navs(_FEB, _COMPUTED_VALUES))).summary
        self.assertNotIn("performance_withheld", summary.to_dict())
        self.assertNotIn("withheld_reasons", summary.to_dict())

    def test_capital_bracket_is_signed_only_when_it_was_measured(self) -> None:
        for label, navs in (("no_nav", []), ("single", _navs(_FEB, [10000.0]))):
            with self.subTest(case=label):
                out = verify_portfolio(ledger=_ledger(navs), issued_at_utc=_ISSUED)
                leaf = out.proof_bundle.get_disclosed_payload("capital_bracket")
                self.assertIsNone(leaf["capital_bracket"])
                self.assertTrue(out.verification.signature_valid)
                self.assertTrue(out.verification.merkle_valid)

        measured = verify_portfolio(ledger=_ledger(_navs(_FEB, _COMPUTED_VALUES)), issued_at_utc=_ISSUED)
        self.assertEqual(
            measured.proof_bundle.get_disclosed_payload("capital_bracket")["capital_bracket"],
            "bracket_10k_100k",
        )

    def test_withheld_flag_round_trips_and_cannot_be_half_set(self) -> None:
        withheld = PerformanceSummary(twr_decimal=0.0, performance_withheld=True, withheld_reasons=["x withheld"])
        self.assertEqual(PerformanceSummary.from_dict(withheld.to_dict()), withheld)
        with self.assertRaises(ValueError):
            PerformanceSummary(twr_decimal=0.0, withheld_reasons=["x withheld"])
        with self.assertRaises(ValueError):
            PerformanceSummary(twr_decimal=0.0, performance_withheld=True)


if __name__ == "__main__":
    unittest.main()
