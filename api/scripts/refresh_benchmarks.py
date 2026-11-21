#!/usr/bin/env python3
"""Refresh bundled daily total-return ETF benchmark series for N170 Verify.

Emits strictly licensing-safe normalized daily total-return index levels (rebased to
100.0 at series start) and daily EUR/USD closing spot rates — zero raw OHLCV data.

Usage:
    # Live EODHD refresh (requires EODHD_API_KEY in environment):
    python3 api/scripts/refresh_benchmarks.py --live

    # Offline deterministic reference seed (clearly tagged source='bundled_reference'):
    python3 api/scripts/refresh_benchmarks.py --seed-reference
"""

from __future__ import annotations

import argparse
from datetime import date, timedelta
import json
import math
import os
from pathlib import Path
import sys
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_API_OUT = REPO_ROOT / "api" / "app" / "data" / "etf_benchmarks_daily.json"

BENCHMARK_TICKERS: dict[str, dict[str, str]] = {
    "SPY": {
        "eodhd_ticker": "SPY.US",
        "yahoo_ticker": "SPY",
        "name": "SPDR S&P 500 ETF Trust",
        "native_currency": "USD",
    },
    "QQQ": {
        "eodhd_ticker": "QQQ.US",
        "yahoo_ticker": "QQQ",
        "name": "Invesco QQQ Trust",
        "native_currency": "USD",
    },
    "VWCE": {
        "eodhd_ticker": "VWCE.XETRA",
        "yahoo_ticker": "VWCE.DE",
        "name": "Vanguard FTSE All-World UCITS ETF (Acc)",
        "native_currency": "EUR",
    },
    "VT": {
        "eodhd_ticker": "VT.US",
        "yahoo_ticker": "VT",
        "name": "Vanguard Total World Stock ETF",
        "native_currency": "USD",
    },
    "GLD": {
        "eodhd_ticker": "GLD.US",
        "yahoo_ticker": "GLD",
        "name": "SPDR Gold Shares",
        "native_currency": "USD",
    },
}


def _business_days(start: date, end: date) -> list[str]:
    out: list[str] = []
    cur = start
    while cur <= end:
        if cur.weekday() < 5:
            out.append(cur.isoformat())
        cur += timedelta(days=1)
    return out


def _interpolate_anchor_series(
    dates: list[str],
    anchors: list[tuple[str, float]],
    *,
    vol: float,
    seed: int,
    market_shock: list[float],
    beta: float,
) -> list[float]:
    """Build deterministic daily bridge passing smoothly through milestone anchors."""
    anchor_idx: list[tuple[int, float]] = []
    date_to_idx = {d: i for i, d in enumerate(dates)}
    for a_date, a_val in anchors:
        idx = date_to_idx.get(a_date)
        if idx is None:
            idx = 0
            for i, d in enumerate(dates):
                if d <= a_date:
                    idx = i
                else:
                    break
        if not anchor_idx or idx > anchor_idx[-1][0]:
            anchor_idx.append((idx, a_val))

    n = len(dates)
    values = [100.0] * n
    state = (seed * 1103515245 + 12345) & 0x7FFFFFFF

    def rand_norm() -> float:
        nonlocal state
        u_vals = []
        for _ in range(2):
            state = (state * 1103515245 + 12345) & 0x7FFFFFFF
            u_vals.append(max(1e-7, state / 0x7FFFFFFF))
        return math.sqrt(-2.0 * math.log(u_vals[0])) * math.cos(2.0 * math.pi * u_vals[1])

    for seg in range(len(anchor_idx) - 1):
        i0, v0 = anchor_idx[seg]
        i1, v1 = anchor_idx[seg + 1]
        steps = max(1, i1 - i0)
        target_log = math.log(v1 / v0)
        raw: list[float] = []
        for k in range(steps):
            t_idx = i0 + k + 1
            idio = rand_norm() * vol * 0.55
            sys_part = market_shock[t_idx] * beta * vol
            raw.append(sys_part + idio)
        drift_adj = (target_log - sum(raw)) / steps
        cur = v0
        values[i0] = v0
        for k in range(steps):
            cur *= math.exp(raw[k] + drift_adj)
            values[i0 + k + 1] = cur

    base = values[0] if values[0] > 0 else 100.0
    return [round((v / base) * 100.0, 2) for v in values]


def build_reference_dataset(
    start_str: str = "2024-01-02",
    end_str: str = "2026-11-20",
) -> dict[str, Any]:
    """Create a deterministic offline reference dataset clearly tagged bundled_reference."""
    dates = _business_days(date.fromisoformat(start_str), date.fromisoformat(end_str))
    n = len(dates)
    state = 42170
    market_shock: list[float] = []
    for _ in range(n):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        u1 = max(1e-7, state / 0x7FFFFFFF)
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        u2 = max(1e-7, state / 0x7FFFFFFF)
        z = math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)
        market_shock.append(max(-3.2, min(3.2, z)))

    spy_anchors = [
        ("2024-01-02", 100.0),
        ("2024-03-28", 110.4),
        ("2024-04-19", 105.1),
        ("2024-07-16", 119.5),
        ("2024-08-05", 109.8),
        ("2024-09-02", 119.8),
        ("2024-12-31", 125.0),
        ("2025-02-19", 130.6),
        ("2025-04-08", 106.2),
        ("2025-06-30", 132.4),
        ("2025-09-30", 142.8),
        ("2025-12-31", 147.5),
        ("2026-03-31", 152.1),
        ("2026-06-30", 158.9),
        ("2026-09-30", 163.4),
        ("2026-11-20", 168.2),
    ]
    qqq_anchors = [
        ("2024-01-02", 100.0),
        ("2024-03-28", 108.7),
        ("2024-04-19", 101.6),
        ("2024-07-10", 123.4),
        ("2024-08-05", 107.1),
        ("2024-09-02", 116.8),
        ("2024-12-31", 125.6),
        ("2025-02-19", 132.5),
        ("2025-04-08", 101.8),
        ("2025-06-30", 135.2),
        ("2025-09-30", 148.9),
        ("2025-12-31", 156.4),
        ("2026-03-31", 163.1),
        ("2026-06-30", 172.0),
        ("2026-09-30", 178.4),
        ("2026-11-20", 185.6),
    ]
    vt_anchors = [
        ("2024-01-02", 100.0),
        ("2024-03-28", 107.9),
        ("2024-04-19", 103.3),
        ("2024-07-16", 114.2),
        ("2024-08-05", 105.6),
        ("2024-09-02", 114.8),
        ("2024-12-31", 117.1),
        ("2025-02-19", 122.4),
        ("2025-04-08", 102.9),
        ("2025-06-30", 127.8),
        ("2025-09-30", 136.4),
        ("2025-12-31", 140.9),
        ("2026-03-31", 145.6),
        ("2026-06-30", 151.4),
        ("2026-09-30", 155.8),
        ("2026-11-20", 160.3),
    ]
    gld_anchors = [
        ("2024-01-02", 100.0),
        ("2024-03-28", 107.6),
        ("2024-06-28", 112.4),
        ("2024-09-02", 121.3),
        ("2024-10-30", 134.8),
        ("2024-12-31", 126.9),
        ("2025-03-31", 150.2),
        ("2025-06-30", 160.1),
        ("2025-09-30", 171.5),
        ("2025-12-31", 176.8),
        ("2026-03-31", 183.4),
        ("2026-06-30", 189.2),
        ("2026-09-30", 195.6),
        ("2026-11-20", 201.4),
    ]
    eurusd_anchors = [
        ("2024-01-02", 1.0950),
        ("2024-04-16", 1.0620),
        ("2024-08-26", 1.1180),
        ("2024-09-02", 1.1065),
        ("2024-11-22", 1.0418),
        ("2024-12-31", 1.0355),
        ("2025-02-03", 1.0285),
        ("2025-04-21", 1.1510),
        ("2025-06-30", 1.1740),
        ("2025-09-30", 1.1680),
        ("2025-12-31", 1.1520),
        ("2026-03-31", 1.1410),
        ("2026-06-30", 1.1340),
        ("2026-09-30", 1.1280),
        ("2026-11-20", 1.1240),
    ]

    spy = _interpolate_anchor_series(dates, spy_anchors, vol=0.0085, seed=101, market_shock=market_shock, beta=1.00)
    qqq = _interpolate_anchor_series(dates, qqq_anchors, vol=0.0115, seed=202, market_shock=market_shock, beta=1.22)
    vt = _interpolate_anchor_series(dates, vt_anchors, vol=0.0078, seed=303, market_shock=market_shock, beta=0.92)
    gld = _interpolate_anchor_series(dates, gld_anchors, vol=0.0082, seed=404, market_shock=market_shock, beta=0.12)

    eurusd_idx = _interpolate_anchor_series(
        dates,
        [(d, v / eurusd_anchors[0][1] * 100.0) for d, v in eurusd_anchors],
        vol=0.0042,
        seed=505,
        market_shock=market_shock,
        beta=-0.10,
    )
    eurusd = [round(eurusd_anchors[0][1] * (v / 100.0), 4) for v in eurusd_idx]

    vwce_raw = [
        vt[i] * (eurusd[0] / eurusd[i]) * (1.0 - 0.000008 * i)
        for i in range(n)
    ]
    vwce = [round((v / vwce_raw[0]) * 100.0, 2) for v in vwce_raw]

    return {
        "schema_version": "n170-benchmarks-v1",
        "source": "bundled_reference",
        "as_of_date": dates[-1],
        "base_date": dates[0],
        "meta": {
            sym: {
                "symbol": sym,
                "name": info["name"],
                "native_currency": info["native_currency"],
            }
            for sym, info in BENCHMARK_TICKERS.items()
        },
        "dates": dates,
        "series": {
            "SPY": spy,
            "QQQ": qqq,
            "VWCE": vwce,
            "VT": vt,
            "GLD": gld,
        },
        "eurusd": eurusd,
    }


def fetch_live_eodhd_dataset(
    api_key: str,
    start_str: str = "2024-01-02",
    end_str: str | None = None,
) -> dict[str, Any]:
    """Fetch real dividend-adjusted total-return series from EODHD (rebased to 100.0)."""
    sys.path.insert(0, str(REPO_ROOT / "core"))
    from n170_verify.reference.eodhd_client import EodhdReferenceProvider

    provider = EodhdReferenceProvider(api_key=api_key)
    end_date = end_str or date.today().isoformat()
    raw_by_sym: dict[str, dict[str, float]] = {}
    all_dates: set[str] = set()

    for sym, info in BENCHMARK_TICKERS.items():
        envelopes = provider.get_daily_envelopes(
            info["eodhd_ticker"],
            start_date=start_str,
            end_date=end_date,
        )
        marks: dict[str, float] = {}
        for env in envelopes:
            mark = (
                env.total_return_adjusted_close
                if env.total_return_adjusted_close is not None and env.total_return_adjusted_close > 0
                else env.split_adjusted_close
            )
            if mark > 0 and math.isfinite(mark):
                marks[env.trade_date] = mark
                all_dates.add(env.trade_date)
        if len(marks) < 2:
            raise RuntimeError(f"Insufficient EODHD rows for {sym} ({info['eodhd_ticker']})")
        raw_by_sym[sym] = marks

    fx_envelopes = provider.get_daily_envelopes(
        "EURUSD.FOREX",
        start_date=start_str,
        end_date=end_date,
    )
    fx_marks = {
        env.trade_date: env.split_adjusted_close
        for env in fx_envelopes
        if env.split_adjusted_close > 0 and math.isfinite(env.split_adjusted_close)
    }
    if not fx_marks:
        raise RuntimeError("Insufficient EODHD rows for EURUSD.FOREX")

    dates = sorted(all_dates)

    def align(marks: dict[str, float], rebase: bool) -> list[float]:
        first_known = marks[min(marks.keys())]
        last_val = first_known
        aligned: list[float] = []
        for d in dates:
            if d in marks:
                last_val = marks[d]
            aligned.append(last_val)
        if not rebase:
            return [round(v, 4) for v in aligned]
        base = aligned[0]
        return [round((v / base) * 100.0, 2) for v in aligned]

    return {
        "schema_version": "n170-benchmarks-v1",
        "source": "eodhd_total_return",
        "as_of_date": dates[-1],
        "base_date": dates[0],
        "meta": {
            sym: {
                "symbol": sym,
                "name": info["name"],
                "native_currency": info["native_currency"],
            }
            for sym, info in BENCHMARK_TICKERS.items()
        },
        "dates": dates,
        "series": {sym: align(raw_by_sym[sym], rebase=True) for sym in BENCHMARK_TICKERS},
        "eurusd": align(fx_marks, rebase=False),
    }


def fetch_live_yahoo_dataset(
    *,
    start_str: str = "2024-01-02",
    end_str: str | None = None,
) -> dict[str, Any]:
    """Fetch real dividend- and split-adjusted daily total-return series via Yahoo Finance chart API (rebased to 100.0)."""
    from datetime import datetime, timezone
    import urllib.parse
    import urllib.request

    start_d = date.fromisoformat(start_str)
    end_d = date.fromisoformat(end_str) if end_str else date.today()
    p1 = int(datetime(start_d.year, start_d.month, start_d.day, tzinfo=timezone.utc).timestamp())
    p2 = int(datetime(end_d.year, end_d.month, end_d.day, 23, 59, 59, tzinfo=timezone.utc).timestamp()) + 86400

    def fetch_symbol(yahoo_sym: str, *, use_adjclose: bool) -> dict[str, float]:
        q_sym = urllib.parse.quote(yahoo_sym, safe="")
        url = (
            f"https://query1.finance.yahoo.com/v8/finance/chart/{q_sym}"
            f"?period1={p1}&period2={p2}&interval=1d&events=div%2Csplits"
        )
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        res = payload["chart"]["result"][0]
        timestamps = res.get("timestamp") or []
        adj = (res.get("indicators", {}).get("adjclose") or [{}])[0].get("adjclose") or []
        close = (res.get("indicators", {}).get("quote") or [{}])[0].get("close") or []
        vals = adj if (use_adjclose and adj) else close
        marks: dict[str, float] = {}
        for ts, v in zip(timestamps, vals):
            if v is None or not isinstance(v, (int, float)) or not math.isfinite(float(v)) or float(v) <= 0:
                continue
            d_iso = datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")
            if start_str <= d_iso <= end_d.isoformat():
                marks[d_iso] = float(v)
        return marks

    raw_by_sym: dict[str, dict[str, float]] = {}
    all_dates: set[str] = set()
    for sym, info in BENCHMARK_TICKERS.items():
        marks = fetch_symbol(info["yahoo_ticker"], use_adjclose=True)
        if len(marks) < 2:
            raise RuntimeError(f"Insufficient Yahoo total-return rows for {sym} ({info['yahoo_ticker']})")
        raw_by_sym[sym] = marks
        all_dates.update(marks.keys())

    fx_marks = fetch_symbol("EURUSD=X", use_adjclose=False)
    if len(fx_marks) < 2:
        raise RuntimeError("Insufficient Yahoo FX rows for EURUSD=X")

    dates = sorted(all_dates)

    def align(marks: dict[str, float], rebase: bool) -> list[float]:
        first_known = marks[min(marks.keys())]
        last_val = first_known
        aligned: list[float] = []
        for d in dates:
            if d in marks:
                last_val = marks[d]
            aligned.append(last_val)
        if not rebase:
            return [round(v, 4) for v in aligned]
        base = aligned[0]
        return [round((v / base) * 100.0, 2) for v in aligned]

    return {
        "schema_version": "n170-benchmarks-v1",
        "source": "yahoo_total_return",
        "as_of_date": dates[-1],
        "base_date": dates[0],
        "meta": {
            sym: {
                "symbol": sym,
                "name": info["name"],
                "native_currency": info["native_currency"],
            }
            for sym, info in BENCHMARK_TICKERS.items()
        },
        "dates": dates,
        "series": {sym: align(raw_by_sym[sym], rebase=True) for sym in BENCHMARK_TICKERS},
        "eurusd": align(fx_marks, rebase=False),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh N170 Verify daily ETF benchmark series.")
    parser.add_argument("--live", action="store_true", help="Fetch live total-return data from EODHD.")
    parser.add_argument("--yahoo", action="store_true", help="Fetch live dividend/split-adjusted total-return data via Yahoo Finance.")
    parser.add_argument("--seed-reference", action="store_true", help="Generate offline reference dataset.")
    parser.add_argument("--start-date", default="2024-01-02")
    parser.add_argument("--end-date", default="2026-11-20")
    parser.add_argument("--out", default="", help="Optional single output JSON file path.")
    args = parser.parse_args()

    if args.live:
        api_key = os.environ.get("EODHD_API_KEY", "").strip()
        if not api_key:
            print("EODHD_API_KEY is required for --live refresh", file=sys.stderr)
            return 2
        dataset = fetch_live_eodhd_dataset(api_key, start_str=args.start_date, end_str=args.end_date)
    elif args.yahoo:
        dataset = fetch_live_yahoo_dataset(start_str=args.start_date, end_str=args.end_date)
    else:
        dataset = build_reference_dataset(start_str=args.start_date, end_str=args.end_date)

    encoded = json.dumps(dataset, separators=(",", ":"))
    target = Path(args.out) if args.out else DEFAULT_API_OUT
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(encoded + "\n", encoding="utf-8")
    print(f"Wrote {target} ({len(encoded)} bytes, {len(dataset['dates'])} trading days, source={dataset['source']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
