"""Fail-closed rules for Hyperliquid records that cannot be computed correctly.

A record is withheld with a stated reason, never estimated: a wipe-out before a new
deposit, a ledger or fill history longer than the page limit, a failed page, or an
unknown ledger entry that moves value. Return series use daily closes only, and an
unvalued token sent in by another address is recorded at $0 only where the scored
window cannot see that token.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import pytest

from n170_verify.connectors import (
    HyperliquidPublicReadOnlyAdapter,
    HyperliquidServiceError,
    HyperliquidValidationError,
)
from n170_verify.connectors import hyperliquid as hyperliquid_module
from n170_verify.connectors.hyperliquid import (
    HYPERLIQUID_FILLS_PAGE_SIZE,
    HYPERLIQUID_LEDGER_PAGE_SIZE,
    MAX_HYPERLIQUID_FILL_PAGES,
    MAX_HYPERLIQUID_LEDGER_PAGES,
)
from n170_verify.contracts import FlowKind
from n170_verify.performance.calculator import calculate_portfolio_performance_detailed

WALLET = "0x" + "ab" * 20
OTHER_WALLET = "0x" + "22" * 20
SALT = "5a" * 32
DAY_MS = 86_400_000


def _ms(year: int, month: int, day: int, hour: int = 0) -> int:
    return int(dt.datetime(year, month, day, hour, tzinfo=dt.timezone.utc).timestamp() * 1000)


def _parse(payload: dict[str, Any], **kwargs: Any):
    return HyperliquidPublicReadOnlyAdapter().parse_payload(
        payload, wallet_address=WALLET, blinding_salt_hex=SALT, **kwargs
    )


def _daily_history(start_ms: int, days: int, nav: float = 10_000.0, step: float = 1.002) -> list[list[Any]]:
    out: list[list[Any]] = []
    for i in range(days):
        out.append([start_ms + i * DAY_MS, f"{nav:.4f}"])
        nav *= step
    return out


# ---------------------------------------------------------------------------
# Wipe-out followed by a new deposit
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("timing", ["modified_dietz", "end_of_day"])
def test_wipe_out_followed_by_new_deposit_withholds_record(timing: str) -> None:
    history = [
        [_ms(2026, 1, 1), "10000"],
        [_ms(2026, 1, 2), "15000"],
        [_ms(2026, 1, 3), "0"],
        [_ms(2026, 1, 4), "10000"],
        [_ms(2026, 1, 5), "12000"],
    ]
    ledger = _parse(
        {
            "portfolio": [["allTime", {"accountValueHistory": history}]],
            "ledger_updates": [
                {"time": _ms(2026, 1, 4) - 12 * 3_600_000, "delta": {"type": "deposit", "usdc": "10000"}}
            ],
            "fills": [],
        }
    )
    assert 0.0 in [p.nav_base for p in ledger.nav_points]
    perf = calculate_portfolio_performance_detailed(ledger, cash_flow_timing=timing)
    assert perf.withheld


def test_wipe_out_spanning_several_zero_days_before_deposit_withholds_record() -> None:
    history = [
        [_ms(2026, 1, 1), "10000"],
        [_ms(2026, 1, 2), "15000"],
        [_ms(2026, 1, 3), "0"],
        [_ms(2026, 1, 4), "0"],
        [_ms(2026, 1, 5), "0"],
        [_ms(2026, 1, 6), "0"],
        [_ms(2026, 1, 7), "0"],
        [_ms(2026, 1, 8), "10000"],
        [_ms(2026, 1, 9), "12000"],
    ]
    ledger = _parse(
        {
            "portfolio": [["allTime", {"accountValueHistory": history}]],
            "ledger_updates": [
                {"time": _ms(2026, 1, 8) - 12 * 3_600_000, "delta": {"type": "deposit", "usdc": "10000"}}
            ],
            "fills": [],
        }
    )
    perf = calculate_portfolio_performance_detailed(ledger, cash_flow_timing="modified_dietz")
    assert perf.withheld


def test_clean_full_withdrawal_then_redeposit_computes_under_default_timing() -> None:
    history = [
        [_ms(2026, 1, 1), "10000"],
        [_ms(2026, 1, 2), "15000"],
        [_ms(2026, 1, 3), "0"],
        [_ms(2026, 1, 4), "10000"],
        [_ms(2026, 1, 5), "12000"],
    ]
    ledger = _parse(
        {
            "portfolio": [["allTime", {"accountValueHistory": history}]],
            "ledger_updates": [
                {"time": _ms(2026, 1, 3), "delta": {"type": "withdraw", "usdc": "15000", "fee": "0"}},
                {"time": _ms(2026, 1, 4) - 12 * 3_600_000, "delta": {"type": "deposit", "usdc": "10000"}},
            ],
            "fills": [],
        }
    )
    perf = calculate_portfolio_performance_detailed(ledger, cash_flow_timing="modified_dietz")
    assert not perf.withheld
    assert perf.summary.twr_decimal == pytest.approx(0.8, abs=1e-9)


# ---------------------------------------------------------------------------
# Ledger and fill pagination
# ---------------------------------------------------------------------------


def _portfolio_response() -> list[Any]:
    return [["allTime", {"accountValueHistory": _daily_history(_ms(2026, 1, 1), 10)}]]


def _ledger_entry(t_ms: int, idx: int) -> dict[str, Any]:
    return {
        "time": t_ms,
        "hash": f"0x{idx:064x}",
        "delta": {"type": "accountClassTransfer", "usdc": "1.0", "toPerp": True},
    }


def _fill(t_ms: int, tid: int) -> dict[str, Any]:
    return {"coin": "ETH", "px": "3000.0", "sz": "0.01", "side": "B", "time": t_ms, "fee": "0.1", "tid": tid}


def _adapter(transport: Any) -> HyperliquidPublicReadOnlyAdapter:
    return HyperliquidPublicReadOnlyAdapter(wallet_address=WALLET, http_transport=transport)


def test_ledger_history_longer_than_page_limit_withholds_record() -> None:
    calls: list[int] = []
    base = _ms(2026, 1, 1)

    def transport(method: str, url: str, headers: dict[str, str], body: bytes):
        req = json.loads(body.decode("utf-8"))
        if req["type"] == "portfolio":
            return 200, {}, _portfolio_response()
        if req["type"] == "userNonFundingLedgerUpdates":
            page_no = len(calls)
            calls.append(page_no)
            start = base + page_no * HYPERLIQUID_LEDGER_PAGE_SIZE
            return 200, {}, [
                _ledger_entry(start + i, page_no * HYPERLIQUID_LEDGER_PAGE_SIZE + i)
                for i in range(HYPERLIQUID_LEDGER_PAGE_SIZE)
            ]
        if req["type"] == "userFills":
            return 200, {}, []
        raise AssertionError(req["type"])

    with pytest.raises(HyperliquidValidationError, match="ledger"):
        _adapter(transport).fetch_canonical_ledger(blinding_salt_hex=SALT)
    assert len(calls) == MAX_HYPERLIQUID_LEDGER_PAGES


def test_ledger_full_page_with_no_new_entries_withholds_record() -> None:
    same_ms = _ms(2026, 1, 3)
    full_page = [_ledger_entry(same_ms, i) for i in range(HYPERLIQUID_LEDGER_PAGE_SIZE)]

    def transport(method: str, url: str, headers: dict[str, str], body: bytes):
        req = json.loads(body.decode("utf-8"))
        if req["type"] == "portfolio":
            return 200, {}, _portfolio_response()
        if req["type"] == "userNonFundingLedgerUpdates":
            return 200, {}, full_page
        if req["type"] == "userFills":
            return 200, {}, []
        raise AssertionError(req["type"])

    with pytest.raises(HyperliquidValidationError, match="ledger"):
        _adapter(transport).fetch_canonical_ledger(blinding_salt_hex=SALT)


def test_failed_fill_page_withholds_record() -> None:
    base = _ms(2026, 1, 2)

    def transport(method: str, url: str, headers: dict[str, str], body: bytes):
        req = json.loads(body.decode("utf-8"))
        if req["type"] == "portfolio":
            return 200, {}, _portfolio_response()
        if req["type"] == "userNonFundingLedgerUpdates":
            return 200, {}, []
        if req["type"] == "userFills":
            return 200, {}, [_fill(base + i, 10_000 + i) for i in range(HYPERLIQUID_FILLS_PAGE_SIZE)]
        if req["type"] == "userFillsByTime":
            return 500, {}, {"error": "upstream unavailable"}
        raise AssertionError(req["type"])

    with pytest.raises(HyperliquidServiceError):
        _adapter(transport).fetch_canonical_ledger(blinding_salt_hex=SALT)


def _fresh_fill_pages_transport(page_len: int, pages: list[int]):
    base = _ms(2026, 1, 2)

    def transport(method: str, url: str, headers: dict[str, str], body: bytes):
        req = json.loads(body.decode("utf-8"))
        if req["type"] == "portfolio":
            return 200, {}, _portfolio_response()
        if req["type"] == "userNonFundingLedgerUpdates":
            return 200, {}, []
        if req["type"] == "userFills":
            return 200, {}, [_fill(base + i, 10_000 + i) for i in range(HYPERLIQUID_FILLS_PAGE_SIZE)]
        if req["type"] == "userFillsByTime":
            page_no = len(pages)
            pages.append(page_no)
            start = base + page_no * page_len
            return 200, {}, [_fill(start + i, 100_000 + page_no * page_len + i) for i in range(page_len)]
        raise AssertionError(req["type"])

    return transport


def test_fill_history_reaching_the_available_limit_withholds_record() -> None:
    pages: list[int] = []
    with pytest.raises(HyperliquidValidationError, match="most recent"):
        _adapter(_fresh_fill_pages_transport(HYPERLIQUID_FILLS_PAGE_SIZE, pages)).fetch_canonical_ledger(
            blinding_salt_hex=SALT
        )
    assert len(pages) == hyperliquid_module.HYPERLIQUID_FILLS_BY_TIME_AVAILABLE // HYPERLIQUID_FILLS_PAGE_SIZE


def test_fill_history_longer_than_page_limit_withholds_record() -> None:
    pages: list[int] = []
    with pytest.raises(HyperliquidValidationError, match="pages"):
        _adapter(_fresh_fill_pages_transport(100, pages)).fetch_canonical_ledger(blinding_salt_hex=SALT)
    assert len(pages) == MAX_HYPERLIQUID_FILL_PAGES


def _ranged_transport(
    *,
    ledger_entries: list[dict[str, Any]] | None = None,
    fills: list[dict[str, Any]] | None = None,
    recent_fills: list[dict[str, Any]] | None = None,
    cap: int,
    queries: list[dict[str, Any]] | None = None,
    portfolio: list[Any] | None = None,
):
    """Serve entries with time >= startTime, at most ``cap`` per response, ascending."""
    ledger_entries = ledger_entries or []
    fills = fills or []

    def transport(method: str, url: str, headers: dict[str, str], body: bytes):
        req = json.loads(body.decode("utf-8"))
        if queries is not None:
            queries.append(req)
        if req["type"] == "portfolio":
            return 200, {}, portfolio if portfolio is not None else _portfolio_response()
        if req["type"] == "userNonFundingLedgerUpdates":
            return 200, {}, [e for e in ledger_entries if e["time"] >= req["startTime"]][:cap]
        if req["type"] == "userFills":
            return 200, {}, recent_fills if recent_fills is not None else fills[-HYPERLIQUID_FILLS_PAGE_SIZE:]
        if req["type"] == "userFillsByTime":
            return 200, {}, [f for f in fills if f["time"] >= req["startTime"]][:cap]
        raise AssertionError(req["type"])

    return transport


def test_short_ledger_pages_are_not_taken_as_final() -> None:
    base = _ms(2026, 1, 2)
    entries = [_ledger_entry(base + i, i) for i in range(1500)]
    ledger = _adapter(_ranged_transport(ledger_entries=entries, cap=500)).fetch_canonical_ledger(
        blinding_salt_hex=SALT
    )
    assert len(ledger.flows) == 1500


def test_short_fill_pages_are_not_taken_as_final() -> None:
    base = _ms(2026, 1, 2)
    fills = [_fill(base + i * 10, i + 1) for i in range(3000)]
    ledger = _adapter(_ranged_transport(fills=fills, cap=500)).fetch_canonical_ledger(blinding_salt_hex=SALT)
    assert len(ledger.trades) == 3000


def test_full_page_inside_one_timestamp_withholds_record() -> None:
    base = _ms(2026, 1, 2)
    same_ms = _ms(2026, 1, 3)
    entries = [_ledger_entry(base + i, i) for i in range(1000)] + [
        _ledger_entry(same_ms, 1000 + i) for i in range(3000)
    ]
    with pytest.raises(HyperliquidValidationError, match="one timestamp"):
        _adapter(_ranged_transport(ledger_entries=entries, cap=2000)).fetch_canonical_ledger(
            blinding_salt_hex=SALT
        )


def _non_list_transport(bad_type: str):
    base = _ms(2026, 1, 2)

    def transport(method: str, url: str, headers: dict[str, str], body: bytes):
        req = json.loads(body.decode("utf-8"))
        if req["type"] == bad_type:
            return 200, {}, {"unexpected": "object"}
        if req["type"] == "portfolio":
            return 200, {}, _portfolio_response()
        if req["type"] == "userNonFundingLedgerUpdates":
            return 200, {}, []
        if req["type"] == "userFills":
            return 200, {}, [_fill(base + i, 10_000 + i) for i in range(HYPERLIQUID_FILLS_PAGE_SIZE)]
        raise AssertionError(req["type"])

    return transport


@pytest.mark.parametrize("bad_type", ["userNonFundingLedgerUpdates", "userFills", "userFillsByTime"])
def test_page_body_that_is_not_a_list_is_an_upstream_failure(bad_type: str) -> None:
    with pytest.raises(HyperliquidServiceError, match="list"):
        _adapter(_non_list_transport(bad_type)).fetch_canonical_ledger(blinding_salt_hex=SALT)


def test_capped_recent_fills_with_no_paged_fills_withholds_record() -> None:
    base = _ms(2026, 1, 2)
    recent = [_fill(base + i, 10_000 + i) for i in range(HYPERLIQUID_FILLS_PAGE_SIZE)]
    with pytest.raises(HyperliquidValidationError, match="fill"):
        _adapter(_ranged_transport(fills=[], recent_fills=recent, cap=2000)).fetch_canonical_ledger(
            blinding_salt_hex=SALT
        )


def test_recent_fills_reaching_back_past_the_period_start_need_no_paging() -> None:
    queries: list[dict[str, Any]] = []
    before_start = _ms(2025, 12, 20)
    recent = [_fill(before_start + i * 1000, 10_000 + i) for i in range(HYPERLIQUID_FILLS_PAGE_SIZE)]
    ledger = _adapter(
        _ranged_transport(fills=[], recent_fills=recent, cap=2000, queries=queries)
    ).fetch_canonical_ledger(blinding_salt_hex=SALT)
    assert "userFillsByTime" not in [q["type"] for q in queries]
    assert ledger.trades


def test_short_final_pages_still_produce_a_record() -> None:
    def transport(method: str, url: str, headers: dict[str, str], body: bytes):
        req = json.loads(body.decode("utf-8"))
        if req["type"] == "portfolio":
            return 200, {}, _portfolio_response()
        if req["type"] == "userNonFundingLedgerUpdates":
            return 200, {}, [_ledger_entry(_ms(2026, 1, 3), 1)]
        if req["type"] == "userFills":
            return 200, {}, [_fill(_ms(2026, 1, 3), 1)]
        raise AssertionError(req["type"])

    ledger = _adapter(transport).fetch_canonical_ledger(blinding_salt_hex=SALT)
    assert len(ledger.trades) == 1


# ---------------------------------------------------------------------------
# Return series spacing
# ---------------------------------------------------------------------------


def _coarse_then_daily_portfolio() -> list[Any]:
    coarse = [[_ms(2025, 10, 1) + i * 7 * DAY_MS, f"{8000 + i * 100:.1f}"] for i in range(9)]
    daily_start = _ms(2025, 12, 1)
    daily = _daily_history(daily_start, 31)
    return [
        ["allTime", {"accountValueHistory": coarse + [daily[-1]]}],
        ["month", {"accountValueHistory": daily}],
    ]


def _consecutive_dates(points: list[Any]) -> bool:
    dates = [dt.date.fromisoformat(p.timestamp_utc[:10]) for p in points]
    return all((b - a).days <= 1 for a, b in zip(dates, dates[1:]))


def test_coarse_points_before_daily_run_are_excluded_from_return_series() -> None:
    ledger = _parse({"portfolio": _coarse_then_daily_portfolio(), "ledger_updates": [], "fills": []})
    assert _consecutive_dates(ledger.nav_points)
    assert ledger.nav_points[0].timestamp_utc.startswith("2025-12-01")
    assert ledger.period_start_utc == ledger.nav_points[0].timestamp_utc
    assert any("daily" in w for w in ledger.parser_warnings)


def test_explicit_start_date_reports_first_daily_point_as_period_start() -> None:
    ledger = _parse(
        {"portfolio": _coarse_then_daily_portfolio(), "ledger_updates": [], "fills": []},
        start_date="2025-10-01",
    )
    assert ledger.period_start_utc == ledger.nav_points[0].timestamp_utc
    assert ledger.period_start_utc.startswith("2025-12-01")


def test_daily_series_is_unchanged_and_carries_no_spacing_warning() -> None:
    history = _daily_history(_ms(2026, 1, 1), 40)
    ledger = _parse({"portfolio": [["allTime", {"accountValueHistory": history}]], "ledger_updates": [], "fills": []})
    assert len(ledger.nav_points) == 40
    assert ledger.parser_warnings == []


def test_coarse_only_series_withholds_record() -> None:
    history = [[_ms(2026, 1, 1) + i * 7 * DAY_MS, f"{10000 + i * 100:.1f}"] for i in range(5)]
    with pytest.raises(HyperliquidValidationError, match="most recent month"):
        _parse({"portfolio": [["allTime", {"accountValueHistory": history}]], "ledger_updates": [], "fills": []})


def test_two_points_several_days_apart_withhold_record() -> None:
    history = [[_ms(2026, 1, 1), "10000"], [_ms(2026, 1, 6), "11000"]]
    with pytest.raises(HyperliquidValidationError, match="most recent month"):
        _parse({"portfolio": [["allTime", {"accountValueHistory": history}]], "ledger_updates": [], "fills": []})


def test_end_date_older_than_daily_history_withholds_record() -> None:
    with pytest.raises(HyperliquidValidationError, match="most recent month"):
        _parse(
            {"portfolio": _coarse_then_daily_portfolio(), "ledger_updates": [], "fills": []},
            end_date="2025-11-20",
        )


def test_entries_before_the_first_daily_close_are_dropped() -> None:
    early = _ms(2025, 10, 15)
    inside = _ms(2025, 12, 10)
    ledger = _parse(
        {
            "portfolio": _coarse_then_daily_portfolio(),
            "ledger_updates": [
                {"time": early, "delta": {"type": "deposit", "usdc": "500"}},
                {"time": early + 1000, "delta": {"type": "someFutureType", "usdc": "700"}},
                {"time": inside, "delta": {"type": "deposit", "usdc": "300"}},
            ],
            "fills": [_fill(early, 1), _fill(inside, 2)],
        }
    )
    assert [f.amount for f in ledger.flows] == [300.0]
    assert [t.native_entry_id for t in ledger.trades] == ["hl-tid-2"]


def test_ledger_and_fill_paging_start_at_the_first_daily_close() -> None:
    queries: list[dict[str, Any]] = []
    first_daily = _ms(2025, 12, 1)
    recent = [_fill(_ms(2025, 12, 5) + i, 10_000 + i) for i in range(HYPERLIQUID_FILLS_PAGE_SIZE)]
    _adapter(
        _ranged_transport(
            fills=recent, recent_fills=recent, cap=2000, queries=queries, portfolio=_coarse_then_daily_portfolio()
        )
    ).fetch_canonical_ledger(blinding_salt_hex=SALT)
    ledger_starts = [q["startTime"] for q in queries if q["type"] == "userNonFundingLedgerUpdates"]
    fill_starts = [q["startTime"] for q in queries if q["type"] == "userFillsByTime"]
    assert ledger_starts[0] == first_daily
    assert fill_starts and fill_starts[0] == first_daily


# ---------------------------------------------------------------------------
# Unvalued token transfers
# ---------------------------------------------------------------------------


def _token_payload(window: str, delta: dict[str, Any]) -> dict[str, Any]:
    history = [[_ms(2026, 1, 1), "1000.0"], [_ms(2026, 1, 2), "1100.0"]]
    return {
        "portfolio": [[window, {"accountValueHistory": history}]],
        "ledger_updates": [{"time": _ms(2026, 1, 1, 6), "delta": delta}],
        "fills": [],
    }


@pytest.mark.parametrize("delta_type", ["spotTransfer", "send", "spotSend"])
def test_inbound_unvalued_token_from_another_address_on_perp_window_is_zero_internal_with_warning(
    delta_type: str,
) -> None:
    ledger = _parse(
        _token_payload(
            "perpAllTime",
            {"type": delta_type, "user": OTHER_WALLET, "destination": WALLET, "token": "PURR", "amount": "50000"},
        )
    )
    assert [f.kind for f in ledger.flows] == [FlowKind.OTHER_INTERNAL]
    assert ledger.flows[0].amount == 0.0
    assert any("unvalued" in w for w in ledger.parser_warnings)
    perf = calculate_portfolio_performance_detailed(ledger)
    assert not perf.withheld
    assert perf.summary.twr_decimal == pytest.approx(0.1)


@pytest.mark.parametrize("delta_type", ["spotTransfer", "send"])
def test_inbound_unvalued_token_on_combined_window_still_withholds(delta_type: str) -> None:
    ledger = _parse(
        _token_payload(
            "allTime",
            {"type": delta_type, "user": OTHER_WALLET, "destination": WALLET, "token": "PURR", "amount": "50000"},
        )
    )
    assert calculate_portfolio_performance_detailed(ledger).withheld


@pytest.mark.parametrize("window", ["allTime", "perpAllTime"])
def test_outbound_unvalued_token_still_withholds(window: str) -> None:
    ledger = _parse(
        _token_payload(
            window,
            {"type": "spotTransfer", "user": WALLET, "destination": OTHER_WALLET, "token": "PURR", "amount": "50000"},
        )
    )
    assert calculate_portfolio_performance_detailed(ledger).withheld


def _self_send_crossing_perp(token: str = "HYPE") -> dict[str, Any]:
    return {
        "type": "send",
        "user": WALLET,
        "destination": WALLET,
        "sourceDex": "spot",
        "destinationDex": "",
        "token": token,
        "amount": "10",
    }


def test_unvalued_self_transfer_crossing_perp_boundary_withholds_on_perp_window() -> None:
    ledger = _parse(_token_payload("perpAllTime", _self_send_crossing_perp()))
    assert calculate_portfolio_performance_detailed(ledger).withheld


def test_unvalued_self_transfer_on_combined_window_stays_internal() -> None:
    ledger = _parse(_token_payload("allTime", _self_send_crossing_perp()))
    assert [f.kind for f in ledger.flows] == [FlowKind.OTHER_INTERNAL]
    assert not calculate_portfolio_performance_detailed(ledger).withheld


def test_unvalued_token_without_counterparty_still_withholds_on_perp_window() -> None:
    ledger = _parse(_token_payload("perpAllTime", {"type": "spotTransfer", "token": "PURR", "amount": "50000"}))
    assert calculate_portfolio_performance_detailed(ledger).withheld


# ---------------------------------------------------------------------------
# Unknown ledger entry types
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "delta",
    [
        {"type": "someFutureType", "usdc": "10000"},
        {"type": "cStakingTransfer", "token": "HYPE", "amount": "400", "isDeposit": False},
        {"type": "vaultCreate", "usdc": "5000"},
        {"type": "someFutureType", "usdcValue": "12.5"},
        {"type": "someFutureType", "netWithdrawnUsd": "-3"},
    ],
)
def test_unknown_ledger_type_that_moves_value_withholds_record(delta: dict[str, Any]) -> None:
    history = _daily_history(_ms(2026, 1, 1), 10)
    with pytest.raises(HyperliquidValidationError, match="ledger entry type"):
        _parse(
            {
                "portfolio": [["allTime", {"accountValueHistory": history}]],
                "ledger_updates": [{"time": _ms(2026, 1, 5), "delta": delta}],
                "fills": [],
            }
        )


def test_unknown_ledger_type_without_value_fields_is_ignored() -> None:
    history = _daily_history(_ms(2026, 1, 1), 10)
    ledger = _parse(
        {
            "portfolio": [["allTime", {"accountValueHistory": history}]],
            "ledger_updates": [
                {
                    "time": _ms(2026, 1, 5),
                    "delta": {
                        "type": "liquidation",
                        "accountValue": "9000",
                        "liquidatedNtlPos": "40000",
                        "leverageType": "Cross",
                    },
                },
                {"time": _ms(2026, 1, 6), "delta": {"type": "someFutureType", "usdc": "0"}},
            ],
            "fills": [],
        }
    )
    assert ledger.flows == []
