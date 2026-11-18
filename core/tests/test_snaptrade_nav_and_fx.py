"""SnapTrade NAV snapshots and currency conversion fail closed.

Rules covered here:
- One balances snapshot is one NAV point: accounts synced at different times are summed
  into a single point at one time, so a balances-only record has one point and is withheld.
- A value in a currency with no conversion rate to the base currency is never counted
  as if it were the base currency; parsing raises instead.
"""

from __future__ import annotations

from typing import Any
import urllib.parse

import pytest

from n170_verify.connectors import SnapTradeReadOnlyAdapter
from n170_verify.performance.calculator import calculate_portfolio_performance_detailed

SALT = "11" * 32


def _adapter(transport: Any = None) -> SnapTradeReadOnlyAdapter:
    return SnapTradeReadOnlyAdapter(
        client_id="PERS-DUMMY-CLIENT-01",
        consumer_key="dummy-consumer-key-not-real",
        auth_mode="personal",
        http_transport=transport or (lambda *a: (404, {}, b"{}")),
        auto_register_slot=False,
    )


# ---------------------------------------------------------------------------
# One snapshot, one NAV point
# ---------------------------------------------------------------------------


def test_holdings_for_two_accounts_synced_minutes_apart_form_one_nav_point_and_withhold() -> None:
    payload = {
        "accounts": [
            {"id": "acct-dummy-a1", "currency": "USD", "balance": {"total": {"amount": 10000, "currency": "USD"}}},
            {"id": "acct-dummy-b2", "currency": "USD", "balance": {"total": {"amount": 50000, "currency": "USD"}}},
        ],
        "holdings": [
            {"account": {"id": "acct-dummy-a1"}, "total_value": {"value": 10000, "currency": "USD"},
             "updated_at": "2026-11-10T10:00:00Z", "positions": [], "balances": []},
            {"account": {"id": "acct-dummy-b2"}, "total_value": {"value": 50000, "currency": "USD"},
             "updated_at": "2026-11-10T10:05:00Z", "positions": [], "balances": []},
        ],
        "activities": [],
    }
    ledger = _adapter().parse_payload(payload, blinding_salt_hex=SALT)
    assert [(p.timestamp_utc, p.nav_base) for p in ledger.nav_points] == [
        ("2026-11-10T10:05:00Z", 60000.0)
    ]
    perf = calculate_portfolio_performance_detailed(ledger)
    assert perf.withheld is True
    assert perf.summary.twr_decimal == 0.0


def test_account_totals_with_different_updated_at_form_one_nav_point() -> None:
    payload = {
        "base_currency": "USD",
        "accounts": [
            {"id": "acct-dummy-a1", "balance": {"total": {"amount": 10000, "currency": "USD"}},
             "updated_at": "2026-01-01T00:00:00Z"},
            {"id": "acct-dummy-b2", "balance": {"total": {"amount": 40000, "currency": "USD"}},
             "updated_at": "2026-02-01T00:00:00Z"},
        ],
    }
    ledger = _adapter().parse_payload(payload, blinding_salt_hex=SALT)
    assert len(ledger.nav_points) == 1
    assert ledger.nav_points[0].nav_base == 50000.0
    assert ledger.nav_points[0].timestamp_utc == "2026-02-01T00:00:00Z"
    assert calculate_portfolio_performance_detailed(ledger).withheld is True


def test_balance_rows_with_different_updated_at_sum_into_one_point_with_cash() -> None:
    payload = {
        "base_currency": "USD",
        "balances": [
            {"account_id": "acct-dummy-a1", "total": 7000.0, "cash": 1000.0, "updated_at": "2026-03-01T16:00:00Z"},
            {"account_id": "acct-dummy-b2", "total": 3000.0, "cash": None, "updated_at": "2026-03-04T16:00:00Z"},
        ],
    }
    ledger = _adapter().parse_payload(payload, blinding_salt_hex=SALT)
    assert len(ledger.nav_points) == 1
    assert ledger.nav_points[0].nav_base == 10000.0
    assert ledger.nav_points[0].cash_base == 1000.0
    assert ledger.nav_points[0].timestamp_utc == "2026-03-04T16:00:00Z"


def test_selected_account_filter_still_applies_to_the_single_snapshot() -> None:
    payload = {
        "base_currency": "USD",
        "accounts": [{"id": "acct-dummy-a1"}, {"id": "acct-dummy-b2"}],
        "balances": [
            {"account_id": "acct-dummy-a1", "total": 7000.0, "updated_at": "2026-03-01T16:00:00Z"},
            {"account_id": "acct-dummy-b2", "total": 3000.0, "updated_at": "2026-03-04T16:00:00Z"},
        ],
    }
    ledger = _adapter().parse_payload(
        payload, blinding_salt_hex=SALT, selected_account_ids=["acct-dummy-a1"]
    )
    assert [(p.timestamp_utc, p.nav_base) for p in ledger.nav_points] == [
        ("2026-03-01T16:00:00Z", 7000.0)
    ]


def test_explicit_nav_curve_is_unchanged_by_snapshot_rule() -> None:
    payload = {
        "base_currency": "USD",
        "nav_points": [
            {"date": "2026-01-02", "value": 100000.0},
            {"date": "2026-01-05", "value": 120000.0},
        ],
        "balances": [{"account_id": "acct-dummy-a1", "total": 120000.0, "updated_at": "2026-01-05T16:00:00Z"}],
    }
    ledger = _adapter().parse_payload(payload, blinding_salt_hex=SALT)
    assert [p.nav_base for p in ledger.nav_points] == [100000.0, 120000.0]


def test_one_explicit_nav_point_is_never_paired_with_a_balances_snapshot() -> None:
    payload = {
        "base_currency": "USD",
        "nav_points": [{"date": "2026-01-02", "value": 100000.0}],
        "balances": [{"account_id": "acct-dummy-a1", "total": 150000.0, "updated_at": "2026-02-05T16:00:00Z"}],
    }
    ledger = _adapter().parse_payload(payload, blinding_salt_hex=SALT)
    assert len(ledger.nav_points) == 1
    perf = calculate_portfolio_performance_detailed(ledger)
    assert perf.withheld is True
    assert perf.summary.twr_decimal == 0.0


def test_explicit_points_that_make_no_curve_are_never_paired_with_a_snapshot() -> None:
    # Two explicit entries on one date merge into one point: still not a curve of two.
    payload = {
        "base_currency": "USD",
        "nav_points": [
            {"date": "2026-01-02", "value": 60000.0},
            {"date": "2026-01-02", "value": 40000.0},
        ],
        "balances": [{"account_id": "acct-dummy-a1", "total": 150000.0, "updated_at": "2026-02-05T16:00:00Z"}],
    }
    ledger = _adapter().parse_payload(payload, blinding_salt_hex=SALT)
    assert len(ledger.nav_points) == 1
    assert calculate_portfolio_performance_detailed(ledger).withheld is True


def test_explicit_curve_of_three_points_is_unchanged_when_a_snapshot_is_present() -> None:
    payload = {
        "base_currency": "USD",
        "nav_points": [
            {"date": "2026-01-02", "value": 100000.0},
            {"date": "2026-01-05", "value": 110000.0},
            {"date": "2026-01-09", "value": 120000.0},
        ],
        "balances": [{"account_id": "acct-dummy-a1", "total": 999999.0, "updated_at": "2026-02-05T16:00:00Z"}],
    }
    ledger = _adapter().parse_payload(payload, blinding_salt_hex=SALT)
    assert [(p.timestamp_utc, p.nav_base) for p in ledger.nav_points] == [
        ("2026-01-02T23:59:59Z", 100000.0),
        ("2026-01-05T23:59:59Z", 110000.0),
        ("2026-01-09T23:59:59Z", 120000.0),
    ]
    perf = calculate_portfolio_performance_detailed(ledger)
    assert perf.withheld is False
    assert perf.summary.twr_decimal == pytest.approx(0.20)


# ---------------------------------------------------------------------------
# Missing conversion rate raises
# ---------------------------------------------------------------------------

MISSING_RATE = r"conversion rate.*EUR.*USD"


def _raises_missing_eur(payload: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=MISSING_RATE):
        _adapter().parse_payload(payload, blinding_salt_hex=SALT)


def test_holdings_total_in_foreign_currency_without_rate_raises() -> None:
    _raises_missing_eur({
        "base_currency": "USD",
        "holdings": [{"account": {"id": "acct-dummy-a1"}, "total_value": {"value": 1000, "currency": "EUR"},
                      "updated_at": "2026-03-01T00:00:00Z"}],
    })


def test_holdings_account_balance_total_in_foreign_currency_without_rate_raises() -> None:
    _raises_missing_eur({
        "base_currency": "USD",
        "holdings": [{"account": {"id": "acct-dummy-a1",
                                  "balance": {"total": {"amount": 1000, "currency": "EUR"}}}}],
    })


def test_holdings_cash_in_foreign_currency_without_rate_raises() -> None:
    _raises_missing_eur({
        "base_currency": "USD",
        "holdings": [{"account": {"id": "acct-dummy-a1"},
                      "balances": [{"currency": {"code": "EUR"}, "cash": 500.0}],
                      "total_value": {"value": 500, "currency": "USD"}}],
    })


def test_holdings_position_value_in_foreign_currency_without_rate_raises() -> None:
    _raises_missing_eur({
        "base_currency": "USD",
        "holdings": [{"account": {"id": "acct-dummy-a1"},
                      "balances": [{"currency": {"code": "USD"}, "cash": 500.0}],
                      "positions": [{"symbol": {"symbol": {"symbol": "VWCE", "currency": {"code": "EUR"}}},
                                     "units": 2.0, "price": 100.0}]}],
    })


def test_account_total_in_foreign_currency_without_rate_raises() -> None:
    _raises_missing_eur({
        "base_currency": "USD",
        "accounts": [{"id": "acct-dummy-a1", "balance": {"total": {"amount": 1000, "currency": "EUR"}}}],
    })


def test_trade_in_foreign_currency_without_rate_raises() -> None:
    _raises_missing_eur({
        "base_currency": "USD",
        "activities": [{"id": "t1", "type": "BUY", "currency": {"code": "EUR"}, "units": 1.0, "price": 10.0,
                        "symbol": {"symbol": "VWCE", "currency": {"code": "EUR"}}, "date": "2026-01-02"}],
    })


def test_cash_flow_in_foreign_currency_without_rate_raises() -> None:
    _raises_missing_eur({
        "base_currency": "USD",
        "activities": [{"id": "d1", "type": "DIVIDEND", "amount": 5.0, "currency": {"code": "EUR"},
                        "date": "2026-01-02"}],
    })


def test_ending_position_in_foreign_currency_without_rate_raises() -> None:
    _raises_missing_eur({
        "base_currency": "USD",
        "positions": [{"symbol": {"symbol": {"symbol": "VWCE", "currency": {"code": "EUR"}}},
                       "units": 2.0, "price": 100.0}],
    })


def test_nav_point_value_in_foreign_currency_without_rate_raises() -> None:
    _raises_missing_eur({
        "base_currency": "USD",
        "nav_points": [{"date": "2026-01-02", "value": 100.0, "currency": "EUR"},
                       {"date": "2026-01-03", "value": 110.0, "currency": "EUR"}],
    })


def test_balance_row_total_in_foreign_currency_without_rate_raises() -> None:
    _raises_missing_eur({
        "base_currency": "USD",
        "balances": [{"account_id": "acct-dummy-a1", "total": {"amount": 1000.0, "currency": "EUR"}}],
    })
    _raises_missing_eur({
        "base_currency": "USD",
        "balances": [{"account_id": "acct-dummy-a1", "total": 1000.0, "currency": "EUR"}],
    })


def test_balance_row_cash_in_foreign_currency_without_rate_raises() -> None:
    _raises_missing_eur({
        "base_currency": "USD",
        "balances": [{"account_id": "acct-dummy-a1", "currency": "EUR",
                      "total": {"amount": 1000.0, "currency": "USD"}, "cash": 200.0}],
    })


def test_values_that_need_no_conversion_do_not_raise() -> None:
    # A nav point already in base currency, a balance row without cash, and an option
    # expiry carry a foreign currency code but no foreign amount that needs a rate.
    ledger = _adapter().parse_payload(
        {
            "base_currency": "USD",
            "nav_points": [
                {"date": "2026-01-02", "nav_base": 100.0, "currency": "EUR"},
                {"date": "2026-01-03", "nav_base": 110.0, "currency": "EUR"},
            ],
            "activities": [{"id": "x1", "type": "OPTIONEXPIRATION", "currency": {"code": "EUR"},
                            "symbol": {"symbol": "OPT1", "currency": {"code": "EUR"}}, "units": -1,
                            "date": "2026-01-03"}],
        },
        blinding_salt_hex=SALT,
    )
    assert [p.nav_base for p in ledger.nav_points] == [100.0, 110.0]
    assert len(ledger.corporate_actions) == 1


def test_foreign_currency_with_rate_converts() -> None:
    ledger = _adapter().parse_payload(
        {
            "base_currency": "USD",
            "currency_rates": [{"src": {"code": "EUR"}, "dst": {"code": "USD"}, "exchange_rate": "1.10"}],
            "holdings": [{"account": {"id": "acct-dummy-a1"}, "total_value": {"value": 1000, "currency": "EUR"},
                          "updated_at": "2026-03-01T00:00:00Z"}],
        },
        blinding_salt_hex=SALT,
    )
    assert len(ledger.nav_points) == 1
    assert ledger.nav_points[0].nav_base == pytest.approx(1100.0)


def _live_transport(*, rates_available: bool) -> Any:
    acct_id = "acct-dummy-live-1"

    def _transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, dict[str, str], Any]:
        path = urllib.parse.urlsplit(url).path
        if path == "/api/v1/currencies/rates":
            if not rates_available:
                return (404, {"Content-Type": "application/json"}, {"detail": "unavailable"})
            return (200, {"Content-Type": "application/json"},
                    [{"src": {"code": "USD"}, "dst": {"code": "EUR"}, "exchange_rate": "0.90"}])
        if path == "/api/v1/accounts":
            return (200, {"Content-Type": "application/json"},
                    [{"id": acct_id, "name": "Dummy", "updated_at": "2026-02-20T21:00:00Z"}])
        if path in {"/api/v1/holdings", "/api/v1/activities"}:
            return (403, {"Content-Type": "application/json"}, {"detail": "restricted"})
        if path == f"/api/v1/accounts/{acct_id}/positions":
            return (200, {"Content-Type": "application/json"}, [])
        if path == f"/api/v1/accounts/{acct_id}/balances":
            return (200, {"Content-Type": "application/json"},
                    [{"currency": {"code": "EUR"}, "cash": 5000.0},
                     {"currency": {"code": "USD"}, "cash": 1000.0}])
        if path == f"/api/v1/accounts/{acct_id}/activities":
            return (200, {"Content-Type": "application/json"}, [])
        return (404, {"Content-Type": "application/json"}, {"detail": "not_found"})

    return _transport


def test_live_fetch_with_foreign_cash_and_no_rates_raises() -> None:
    adapter = _adapter(_live_transport(rates_available=False))
    with pytest.raises(ValueError, match=r"conversion rate.*USD.*EUR"):
        adapter.fetch_live_ledger("dummy-user", "", blinding_salt_hex=SALT)


def test_live_fetch_with_foreign_cash_and_rates_converts() -> None:
    adapter = _adapter(_live_transport(rates_available=True))
    ledger = adapter.fetch_live_ledger("dummy-user", "", blinding_salt_hex=SALT)
    assert ledger.base_currency == "EUR"
    assert len(ledger.nav_points) == 1
    assert ledger.nav_points[0].nav_base == pytest.approx(5900.0)


# ---------------------------------------------------------------------------
# A value at or below zero after a positive one stays in the series
# ---------------------------------------------------------------------------


def _usd_acct(aid: str, ccy: str = "USD") -> dict[str, Any]:
    return {"id": aid, "currency": ccy, "name": "Individual",
            "balance": {"total": {"amount": 1000, "currency": ccy}}}


def _series(vals: list[float], start_day: int = 1) -> list[dict[str, Any]]:
    return [{"date": f"2026-10-{start_day + i:02d}", "value": v} for i, v in enumerate(vals)]


def test_zero_value_day_after_a_positive_one_is_kept_and_the_return_is_withheld() -> None:
    payload = {
        "accounts": [_usd_acct("acct-dummy-a1")],
        "activities": [{"account": {"id": "acct-dummy-a1"}, "type": "DEPOSIT", "amount": 5000,
                        "currency": "USD", "trade_date": "2026-10-03T00:00:00Z"}],
        "nav_points": _series([10000, 0, 6000, 6000]),
    }
    ledger = _adapter().parse_payload(payload, blinding_salt_hex=SALT)
    assert [p.nav_base for p in ledger.nav_points] == [10000.0, 0.0, 6000.0, 6000.0]
    assert calculate_portfolio_performance_detailed(ledger).withheld is True


def test_leading_zero_days_before_funding_are_not_part_of_the_series() -> None:
    ledger = _adapter().parse_payload(
        {"accounts": [_usd_acct("acct-dummy-a1")], "nav_points": _series([0, 0, 10000, 11000])},
        blinding_salt_hex=SALT,
    )
    assert [p.nav_base for p in ledger.nav_points] == [10000.0, 11000.0]


def test_after_the_last_positive_day_only_the_first_zero_is_kept() -> None:
    ledger = _adapter().parse_payload(
        {"accounts": [_usd_acct("acct-dummy-a1")], "nav_points": _series([10000, 11000, 0, 0])},
        blinding_salt_hex=SALT,
    )
    assert [p.nav_base for p in ledger.nav_points] == [10000.0, 11000.0, 0.0]


def _curve_transport(values: list[float], seen: dict[str, Any], acct_ids: tuple[str, ...] = ("acct-dummy-live-1",)) -> Any:
    def _transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, dict[str, str], Any]:
        parts = urllib.parse.urlsplit(url)
        path = parts.path
        if path == "/api/v1/accounts":
            return (200, {"Content-Type": "application/json"},
                    [{"id": a, "currency": "USD", "balance": {"total": {"amount": values[-1], "currency": "USD"}}}
                     for a in acct_ids])
        if path == "/api/v1/holdings":
            return (403, {"Content-Type": "application/json"}, {"detail": "restricted"})
        if path == "/api/v1/activities":
            return (200, {"Content-Type": "application/json"}, [])
        if path.endswith("/positions") or path.endswith("/activities"):
            return (200, {"Content-Type": "application/json"}, [])
        if path.endswith("/balances"):
            return (200, {"Content-Type": "application/json"}, [{"currency": {"code": "USD"}, "cash": values[-1]}])
        if path == "/api/v1/performance/custom":
            seen["perf_query"] = urllib.parse.parse_qs(parts.query)
            return (200, {"Content-Type": "application/json"},
                    {"totalEquityTimeframe": _series(values)})
        return (404, {"Content-Type": "application/json"}, {"detail": "not_found"})

    return _transport


def test_live_performance_series_keeps_a_zero_value_day() -> None:
    seen: dict[str, Any] = {}
    adapter = _adapter(_curve_transport([10000, 0, 6000], seen))
    ledger = adapter.fetch_live_ledger("dummy-user", "", blinding_salt_hex=SALT, start_date="2026-10-01",
                                       end_date="2026-10-03")
    assert [p.nav_base for p in ledger.nav_points] == [10000.0, 0.0, 6000.0]
    assert calculate_portfolio_performance_detailed(ledger).withheld is True


# ---------------------------------------------------------------------------
# A selection is limited to accounts actually read
# ---------------------------------------------------------------------------


def test_selecting_an_account_that_was_not_read_is_refused() -> None:
    payload = {"accounts": [_usd_acct("acct-dummy-mine")], "nav_points": _series([10000, 12000, 15000])}
    with pytest.raises(ValueError, match="not among the accounts"):
        _adapter().parse_payload(payload, blinding_salt_hex=SALT, selected_account_ids=["acct-dummy-other"])


def test_selecting_an_account_when_no_accounts_were_read_is_refused() -> None:
    with pytest.raises(ValueError, match="not among the accounts"):
        _adapter().parse_payload({"nav_points": _series([10000, 12000])}, blinding_salt_hex=SALT,
                                 selected_account_ids=["acct-dummy-other"])


def test_under_a_selection_rows_without_an_account_id_are_not_counted() -> None:
    payload = {
        "accounts": [_usd_acct("acct-dummy-a1"), _usd_acct("acct-dummy-b2")],
        "activities": [{"id": "d1", "type": "DEPOSIT", "amount": 500.0, "currency": "USD", "date": "2026-10-02"}],
        "positions": [{"symbol": {"symbol": {"symbol": "SPY", "currency": {"code": "USD"}}}, "units": 1.0, "price": 10.0}],
        "balances": [
            {"account_id": "acct-dummy-a1", "total": 7000.0, "updated_at": "2026-10-04T16:00:00Z"},
            {"total": 3000.0, "updated_at": "2026-10-04T16:00:00Z"},
        ],
    }
    ledger = _adapter().parse_payload(payload, blinding_salt_hex=SALT, selected_account_ids=["acct-dummy-a1"])
    assert ledger.flows == []
    assert ledger.ending_positions == []
    assert [p.nav_base for p in ledger.nav_points] == [7000.0]


def test_unattributed_series_is_not_used_for_a_record_that_claims_a_subset() -> None:
    payload = {
        "accounts": [_usd_acct("acct-dummy-a1"), _usd_acct("acct-dummy-b2")],
        "nav_points": _series([10000, 12000, 15000]),
        "balances": [{"account_id": "acct-dummy-a1", "total": 7000.0, "updated_at": "2026-10-04T16:00:00Z"}],
    }
    ledger = _adapter().parse_payload(payload, blinding_salt_hex=SALT, selected_account_ids=["acct-dummy-a1"])
    assert [p.nav_base for p in ledger.nav_points] == [7000.0]
    assert any("selected accounts" in w for w in ledger.parser_warnings)
    assert calculate_portfolio_performance_detailed(ledger).withheld is True


def test_series_stated_for_the_selected_accounts_is_used() -> None:
    payload = {
        "accounts": [_usd_acct("acct-dummy-a1"), _usd_acct("acct-dummy-b2")],
        "nav_points": _series([10000, 12000, 15000]),
        "nav_points_account_ids": ["acct-dummy-a1"],
    }
    ledger = _adapter().parse_payload(payload, blinding_salt_hex=SALT, selected_account_ids=["acct-dummy-a1"])
    assert [p.nav_base for p in ledger.nav_points] == [10000.0, 12000.0, 15000.0]


def test_selection_of_every_account_read_uses_the_series() -> None:
    payload = {"accounts": [_usd_acct("acct-dummy-a1")], "nav_points": _series([10000, 12000])}
    ledger = _adapter().parse_payload(payload, blinding_salt_hex=SALT, selected_account_ids=["acct-dummy-a1"])
    assert [p.nav_base for p in ledger.nav_points] == [10000.0, 12000.0]


def test_live_selection_of_one_account_uses_the_series_requested_for_it() -> None:
    seen: dict[str, Any] = {}
    adapter = _adapter(_curve_transport([10000, 11000], seen, acct_ids=("acct-dummy-a1", "acct-dummy-b2")))
    ledger = adapter.fetch_live_ledger("dummy-user", "", blinding_salt_hex=SALT, start_date="2026-10-01",
                                       end_date="2026-10-02", selected_account_ids=["acct-dummy-a1"])
    assert seen["perf_query"]["accounts"] == ["acct-dummy-a1"]
    assert [p.nav_base for p in ledger.nav_points] == [10000.0, 11000.0]


def test_live_selection_of_an_account_not_read_is_refused() -> None:
    adapter = _adapter(_curve_transport([10000, 11000], {}))
    with pytest.raises(ValueError, match="not among the accounts"):
        adapter.fetch_live_ledger("dummy-user", "", blinding_salt_hex=SALT, start_date="2026-10-01",
                                  end_date="2026-10-02", selected_account_ids=["acct-dummy-other"])


# ---------------------------------------------------------------------------
# Foreign-currency capital flows and a series of unstated currency
# ---------------------------------------------------------------------------


def test_in_period_capital_flow_in_another_currency_withholds_the_return() -> None:
    payload = {
        "accounts": [_usd_acct("acct-dummy-c1", "CAD")],
        "currency_rates": [{"src": "USD", "dst": "CAD", "exchange_rate": 1.35}],
        "activities": [{"account": {"id": "acct-dummy-c1"}, "type": "DEPOSIT", "amount": 1000.0,
                        "currency": "USD", "trade_date": "2026-10-02T14:00:00Z"}],
        "nav_points": _series([50000, 52000, 52500]),
    }
    ledger = _adapter().parse_payload(payload, blinding_salt_hex=SALT)
    assert ledger.base_currency == "CAD"
    assert len(ledger.nav_points) == 1
    assert ledger.nav_points[0].nav_base == 52500.0
    assert any("rate for its own date" in w for w in ledger.parser_warnings)
    assert calculate_portfolio_performance_detailed(ledger).withheld is True


def test_capital_flow_in_another_currency_outside_the_series_does_not_withhold() -> None:
    payload = {
        "accounts": [_usd_acct("acct-dummy-c1", "CAD")],
        "currency_rates": [{"src": "USD", "dst": "CAD", "exchange_rate": 1.35}],
        "activities": [{"account": {"id": "acct-dummy-c1"}, "type": "DEPOSIT", "amount": 1000.0,
                        "currency": "USD", "trade_date": "2024-01-05T00:00:00Z"}],
        "nav_points": _series([50000, 52000, 52500]),
    }
    ledger = _adapter().parse_payload(payload, blinding_salt_hex=SALT)
    assert len(ledger.nav_points) == 3
    assert ledger.parser_warnings == []


def test_series_of_unstated_currency_over_accounts_in_two_currencies_is_not_used() -> None:
    payload = {
        "accounts": [_usd_acct("acct-dummy-g1", "GBP"), _usd_acct("acct-dummy-u2", "USD")],
        "currency_rates": [{"src": "GBP", "dst": "USD", "exchange_rate": 1.25}],
        "nav_points": _series([10000, 10100]),
    }
    ledger = _adapter().parse_payload(payload, blinding_salt_hex=SALT)
    assert len(ledger.nav_points) == 1
    assert any("does not state its currency" in w for w in ledger.parser_warnings)
    assert calculate_portfolio_performance_detailed(ledger).withheld is True


def test_series_that_states_its_currency_over_accounts_in_two_currencies_is_converted() -> None:
    payload = {
        "accounts": [_usd_acct("acct-dummy-g1", "GBP"), _usd_acct("acct-dummy-u2", "USD")],
        "currency_rates": [{"src": "USD", "dst": "GBP", "exchange_rate": 0.8}],
        "nav_points": [{"date": "2026-10-01", "value": 10000.0, "currency": "USD"},
                       {"date": "2026-10-02", "value": 10100.0, "currency": "USD"}],
    }
    ledger = _adapter().parse_payload(payload, blinding_salt_hex=SALT)
    assert ledger.base_currency == "GBP"
    assert [p.nav_base for p in ledger.nav_points] == pytest.approx([8000.0, 8080.0])
    assert ledger.parser_warnings == []


# ---------------------------------------------------------------------------
# The selection applies before any conversion
# ---------------------------------------------------------------------------


def test_deselected_account_in_a_currency_without_rate_does_not_refuse_the_record() -> None:
    payload = {
        "accounts": [_usd_acct("acct-dummy-u1", "USD"), _usd_acct("acct-dummy-c2", "CAD")],
        "holdings": [
            {"account": {"id": "acct-dummy-u1"}, "total_value": {"value": 10000, "currency": "USD"},
             "updated_at": "2026-10-03T00:00:00Z", "positions": [], "balances": []},
            {"account": {"id": "acct-dummy-c2"}, "total_value": {"value": 5000, "currency": "CAD"},
             "updated_at": "2026-10-03T00:00:00Z", "positions": [], "balances": []},
        ],
    }
    ledger = _adapter().parse_payload(payload, blinding_salt_hex=SALT, selected_account_ids=["acct-dummy-u1"])
    assert [p.nav_base for p in ledger.nav_points] == [10000.0]


def test_live_deselected_account_with_unconvertible_cash_does_not_refuse_the_record() -> None:
    def _transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, dict[str, str], Any]:
        path = urllib.parse.urlsplit(url).path
        if path == "/api/v1/accounts":
            return (200, {"Content-Type": "application/json"},
                    [{"id": "acct-dummy-u1", "currency": "USD"}, {"id": "acct-dummy-x2", "currency": "EUR"}])
        if path in {"/api/v1/holdings", "/api/v1/activities", "/api/v1/currencies/rates"}:
            return (403, {"Content-Type": "application/json"}, {"detail": "restricted"})
        if path == "/api/v1/accounts/acct-dummy-u1/balances":
            return (200, {"Content-Type": "application/json"}, [{"currency": {"code": "USD"}, "cash": 4000.0}])
        if path == "/api/v1/accounts/acct-dummy-x2/balances":
            return (200, {"Content-Type": "application/json"},
                    [{"currency": {"code": "EUR"}, "cash": 10.0}, {"currency": {"code": "JPY"}, "cash": 10.0}])
        if path.endswith("/positions") or path.endswith("/activities"):
            return (200, {"Content-Type": "application/json"}, [])
        return (404, {"Content-Type": "application/json"}, {"detail": "not_found"})

    ledger = _adapter(_transport).fetch_live_ledger("dummy-user", "", blinding_salt_hex=SALT,
                                                    selected_account_ids=["acct-dummy-u1"])
    assert [p.nav_base for p in ledger.nav_points] == [4000.0]
