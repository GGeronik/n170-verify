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
