"""Daily total-return ETF benchmark series routes (SPY, QQQ, VWCE, VT, GLD) with USD/EUR currency awareness."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date, timedelta
import json
import math
from pathlib import Path
from statistics import mean
import threading
import time
from typing import Any

from app.badges import verified_leaf_payload
from app.config import ApiConfig
from app.store import ProofNotFoundError, ProofStore
from n170_verify.reference.eodhd_client import EodhdReferenceProvider, TransportCallable


SUPPORTED_BENCHMARKS: dict[str, dict[str, str]] = {
    "SPY": {
        "symbol": "SPY",
        "eodhd_ticker": "SPY.US",
        "name": "SPDR S&P 500 ETF Trust",
        "native_currency": "USD",
    },
    "QQQ": {
        "symbol": "QQQ",
        "eodhd_ticker": "QQQ.US",
        "name": "Invesco QQQ Trust",
        "native_currency": "USD",
    },
    "VWCE": {
        "symbol": "VWCE",
        "eodhd_ticker": "VWCE.XETRA",
        "name": "Vanguard FTSE All-World UCITS ETF (Acc)",
        "native_currency": "EUR",
    },
    "VT": {
        "symbol": "VT",
        "eodhd_ticker": "VT.US",
        "name": "Vanguard Total World Stock ETF",
        "native_currency": "USD",
    },
    "GLD": {
        "symbol": "GLD",
        "eodhd_ticker": "GLD.US",
        "name": "SPDR Gold Shares",
        "native_currency": "USD",
    },
}

SUPPORTED_CURRENCIES = frozenset({"USD", "EUR", "EUR_HEDGED"})

_DEFAULT_LIVE_START_ISO = "2024-01-02"
_CACHE_TTL_SECONDS = 6 * 3600
_MAX_LIVE_CACHE_ENTRIES = 32
_CACHE_LOCK = threading.RLock()
# Keyed by eodhd_ticker -> (fetched_monotonic, covered_start_iso, covered_end_iso, sorted_unique_marks)
_LIVE_SERIES_CACHE: dict[str, tuple[float, str, str, list[tuple[str, float]]]] = {}
_BUNDLED_CACHE: dict[str, Any] | None = None


def _load_bundled_dataset() -> dict[str, Any]:
    """Load the bundled daily reference dataset once."""
    global _BUNDLED_CACHE
    with _CACHE_LOCK:
        if _BUNDLED_CACHE is not None:
            return _BUNDLED_CACHE

        app_dir = Path(__file__).resolve().parent
        repo_root = app_dir.parents[1]
        candidates = [
            app_dir / "data" / "etf_benchmarks_daily.json",
            repo_root / "web" / "src" / "lib" / "benchmarkData.json",
        ]
        for path in candidates:
            if path.is_file():
                parsed = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(parsed, dict) and isinstance(parsed.get("dates"), list):
                    _BUNDLED_CACHE = parsed
                    return _BUNDLED_CACHE

        raise FileNotFoundError("Bundled ETF benchmark dataset etf_benchmarks_daily.json not found")


def clear_benchmark_cache() -> None:
    """Clear in-memory live benchmark cache (used in tests)."""
    with _CACHE_LOCK:
        _LIVE_SERIES_CACHE.clear()


def _parse_iso_date(raw: str | None, *, field_name: str) -> date | None:
    if raw is None or not raw.strip():
        return None
    cleaned = raw.strip()
    if len(cleaned) != 10:
        raise ValueError(f"{field_name} must be YYYY-MM-DD, got {raw!r}")
    try:
        return date.fromisoformat(cleaned)
    except ValueError:
        raise ValueError(f"{field_name} must be YYYY-MM-DD, got {raw!r}") from None


def _is_positive_finite_number(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and float(value) > 0.0
    )


def _compute_live_fetch_window(
    start_dt: date | None,
    end_dt: date | None,
    *,
    today: date | None = None,
    widen_for_cache: bool = True,
) -> tuple[str, str] | None:
    """Compute a valid ``(fetch_start, fetch_end)`` range with ``fetch_start <= fetch_end <= today``."""
    ref_today = today or date.today()
    today_iso = ref_today.isoformat()

    req_end_dt = min(end_dt, ref_today) if end_dt is not None else ref_today
    if start_dt is not None:
        if start_dt > ref_today:
            return None
        req_start_dt = start_dt - timedelta(days=7)
    else:
        default_start_dt = date.fromisoformat(_DEFAULT_LIVE_START_ISO)
        if req_end_dt < default_start_dt:
            req_start_dt = req_end_dt - timedelta(days=365)
        else:
            req_start_dt = default_start_dt

    if req_start_dt > req_end_dt:
        req_start_dt = req_end_dt - timedelta(days=7)

    if widen_for_cache:
        default_start_dt = date.fromisoformat(_DEFAULT_LIVE_START_ISO)
        fetch_start = min(req_start_dt, default_start_dt).isoformat()
        fetch_end = today_iso
    else:
        fetch_start = req_start_dt.isoformat()
        fetch_end = req_end_dt.isoformat()

    if fetch_start > fetch_end:
        return None
    return fetch_start, fetch_end


def _fetch_eodhd_daily_marks(
    eodhd_ticker: str,
    *,
    api_key: str,
    start_date: str,
    end_date: str,
    transport: TransportCallable | None = None,
    use_cache: bool | None = None,
) -> list[tuple[str, float]]:
    cache_enabled = (transport is None) if use_cache is None else bool(use_cache)
    now = time.monotonic()
    if cache_enabled:
        with _CACHE_LOCK:
            cached = _LIVE_SERIES_CACHE.get(eodhd_ticker)
            if (
                cached is not None
                and (now - cached[0]) < _CACHE_TTL_SECONDS
                and cached[1] <= start_date
                and cached[2] >= end_date
            ):
                return cached[3]

    provider = EodhdReferenceProvider(api_key=api_key, transport=transport)
    envelopes = provider.get_daily_envelopes(
        eodhd_ticker,
        start_date=start_date,
        end_date=end_date,
    )
    by_date: dict[str, float] = {}
    for env in envelopes:
        val = (
            env.total_return_adjusted_close
            if _is_positive_finite_number(env.total_return_adjusted_close)
            else env.split_adjusted_close
        )
        if _is_positive_finite_number(val) and env.trade_date:
            by_date[env.trade_date] = float(val)
    marks = sorted(by_date.items(), key=lambda item: item[0])

    if len(marks) >= 2 and cache_enabled:
        with _CACHE_LOCK:
            # Prune expired entries and enforce strict bounded size
            expired = [
                k for k, entry in _LIVE_SERIES_CACHE.items() if (now - entry[0]) >= _CACHE_TTL_SECONDS
            ]
            for k in expired:
                _LIVE_SERIES_CACHE.pop(k, None)
            while len(_LIVE_SERIES_CACHE) >= _MAX_LIVE_CACHE_ENTRIES and eodhd_ticker not in _LIVE_SERIES_CACHE:
                oldest_key = min(_LIVE_SERIES_CACHE.items(), key=lambda kv: kv[1][0])[0]
                _LIVE_SERIES_CACHE.pop(oldest_key, None)
            _LIVE_SERIES_CACHE[eodhd_ticker] = (now, start_date, end_date, marks)
    return marks


def _currency_basis_label(*, native_currency: str, target_currency: str) -> str:
    if target_currency == native_currency:
        return f"native_{native_currency.lower()}"
    if target_currency == "EUR_HEDGED":
        return "native_eur" if native_currency == "EUR" else "local_currency_hedged_approx"
    if native_currency == "USD" and target_currency == "EUR":
        return "fx_translated_eur"
    if native_currency == "EUR" and target_currency == "USD":
        return "fx_translated_usd"
    return f"native_{native_currency.lower()}"


def _convert_series_currency(
    marks: list[tuple[str, float]],
    *,
    native_currency: str,
    target_currency: str,
    eurusd_by_date: list[tuple[str, float]],
) -> list[tuple[str, float]]:
    """Convert total-return marks into target_currency using carry-forward EUR/USD spot."""
    if not marks:
        return []
    if target_currency == "EUR_HEDGED" or target_currency == native_currency:
        return list(marks)

    if not eurusd_by_date:
        raise ValueError(
            f"Missing EUR/USD FX series required to convert {native_currency} marks to {target_currency}"
        )

    sorted_fx = sorted(eurusd_by_date, key=lambda item: item[0])
    converted: list[tuple[str, float]] = []
    fx_idx = 0
    last_fx = sorted_fx[0][1]
    for d_str, val in marks:
        while fx_idx < len(sorted_fx) and sorted_fx[fx_idx][0] <= d_str:
            last_fx = sorted_fx[fx_idx][1]
            fx_idx += 1
        if not _is_positive_finite_number(last_fx):
            continue
        if native_currency == "USD" and target_currency == "EUR":
            converted.append((d_str, val / last_fx))
        elif native_currency == "EUR" and target_currency == "USD":
            converted.append((d_str, val * last_fx))
        else:
            converted.append((d_str, val))
    return converted


def _slice_and_rebase(
    marks: list[tuple[str, float]],
    *,
    start_dt: date | None,
    end_dt: date | None,
) -> list[dict[str, Any]]:
    if not marks:
        return []
    start_iso = start_dt.isoformat() if start_dt else None
    end_iso = end_dt.isoformat() if end_dt else None

    selected: list[tuple[str, float]] = []
    anchor_before_start: tuple[str, float] | None = None
    for d_str, val in marks:
        if end_iso is not None and d_str > end_iso:
            continue
        if start_iso is not None and d_str < start_iso:
            anchor_before_start = (d_str, val)
            continue
        selected.append((d_str, val))

    if start_iso is not None and anchor_before_start is not None:
        if not selected or selected[0][0] > start_iso:
            selected.insert(0, anchor_before_start)

    if len(selected) < 2:
        return []

    base_val = selected[0][1]
    if base_val <= 0.0:
        return []

    return [
        {
            "date": d_str,
            "index_value": round((val / base_val) * 100.0, 6),
        }
        for d_str, val in selected
    ]


def _compute_max_drawdown_decimal(values: Sequence[float]) -> float:
    """Return non-positive peak-to-trough max drawdown decimal (e.g. -0.15 for -15%)."""
    if not values:
        return 0.0
    peak = values[0]
    max_dd = 0.0
    for v in values:
        if v > peak:
            peak = v
        if peak > 0.0:
            dd = (v / peak) - 1.0
            if dd < max_dd:
                max_dd = dd
    return 0.0 if abs(max_dd) < 1e-12 else round(max_dd, 8)


def _extract_trader_daily_curve(indexed_curve_payload: Any) -> list[tuple[str, float]]:
    """Extract sorted unique daily ``(YYYY-MM-DD, index_value)`` pairs from a verified ``indexed_curve`` leaf."""
    raw_points: Any = None
    if isinstance(indexed_curve_payload, Mapping):
        raw_points = indexed_curve_payload.get("points")
    elif isinstance(indexed_curve_payload, list):
        raw_points = indexed_curve_payload
    if not isinstance(raw_points, list):
        return []

    by_date: dict[str, float] = {}
    for pt in raw_points:
        if not isinstance(pt, Mapping):
            continue
        raw_ts = pt.get("timestamp_utc") or pt.get("date")
        raw_val = pt.get("index_value")
        if not isinstance(raw_ts, str) or len(raw_ts.strip()) < 10:
            continue
        d_iso = raw_ts.strip()[:10]
        try:
            date.fromisoformat(d_iso)
        except ValueError:
            continue
        if not _is_positive_finite_number(raw_val):
            continue
        by_date[d_iso] = float(raw_val)
    return sorted(by_date.items(), key=lambda item: item[0])


def compute_benchmark_comparison(
    trader_curve: Sequence[tuple[str, float]],
    benchmark_marks: Sequence[tuple[str, float]],
) -> dict[str, Any] | None:
    """Compute Cumulative Excess Return, Annualized Alpha, Beta, and Max Drawdown delta over exact statement dates.

    Aligns benchmark marks onto the trader's exact dates via zero-lookahead carry-forward
    (latest benchmark observation on or before each statement date) and rebases the aligned
    benchmark series to ``100.0`` on the first aligned statement date.
    """
    if len(trader_curve) < 2 or len(benchmark_marks) < 2:
        return None

    sorted_trader = sorted(trader_curve, key=lambda item: item[0])
    sorted_bench = sorted(benchmark_marks, key=lambda item: item[0])

    aligned: list[tuple[str, float, float]] = []
    b_idx = 0
    last_b: float | None = None
    for d_str, p_val in sorted_trader:
        while b_idx < len(sorted_bench) and sorted_bench[b_idx][0] <= d_str:
            last_b = sorted_bench[b_idx][1]
            b_idx += 1
        if last_b is not None and _is_positive_finite_number(p_val) and _is_positive_finite_number(last_b):
            aligned.append((d_str, float(p_val), float(last_b)))

    if len(aligned) < 2:
        return None

    start_date, p_start, b_start = aligned[0]
    end_date, p_end, b_end = aligned[-1]
    trader_twr = (p_end / p_start) - 1.0
    bench_twr = (b_end / b_start) - 1.0
    excess_return = trader_twr - bench_twr

    trader_vals = [row[1] for row in aligned]
    bench_vals = [row[2] for row in aligned]
    trader_mdd = _compute_max_drawdown_decimal(trader_vals)
    bench_mdd = _compute_max_drawdown_decimal(bench_vals)
    mdd_delta = trader_mdd - bench_mdd  # positive = trader had shallower drawdown than benchmark

    p_rets: list[float] = []
    b_rets: list[float] = []
    for (_, p0, b0), (_, p1, b1) in zip(aligned, aligned[1:]):
        r_p = (p1 / p0) - 1.0
        r_b = (b1 / b0) - 1.0
        if math.isfinite(r_p) and math.isfinite(r_b):
            p_rets.append(r_p)
            b_rets.append(r_b)

    beta: float | None = None
    annualized_alpha: float | None = None
    if len(p_rets) >= 2:
        mean_p = mean(p_rets)
        mean_b = mean(b_rets)
        var_b = sum((b - mean_b) ** 2 for b in b_rets) / (len(b_rets) - 1)
        if var_b > 1e-16:
            cov_pb = sum((p - mean_p) * (b - mean_b) for p, b in zip(p_rets, b_rets)) / (
                len(p_rets) - 1
            )
            beta = round(cov_pb / var_b, 6)
            span_days = (date.fromisoformat(end_date) - date.fromisoformat(start_date)).days
            if span_days >= 1:
                obs_per_year = min(365.25, len(p_rets) / (span_days / 365.25))
                alpha_val = (mean_p - (cov_pb / var_b) * mean_b) * obs_per_year
                if math.isfinite(alpha_val):
                    annualized_alpha = round(alpha_val, 6)

    aligned_benchmark_points = [
        {
            "date": d_str,
            "index_value": round((b_val / b_start) * 100.0, 6),
        }
        for d_str, _, b_val in aligned
    ]

    return {
        "aligned_start_date": start_date,
        "aligned_end_date": end_date,
        "aligned_observation_count": len(aligned),
        "trader_twr_decimal": round(trader_twr, 8),
        "benchmark_twr_decimal": round(bench_twr, 8),
        "cumulative_excess_return_decimal": round(excess_return, 8),
        "annualized_alpha_decimal": annualized_alpha,
        "beta": beta,
        "trader_max_drawdown_decimal": trader_mdd,
        "benchmark_max_drawdown_decimal": bench_mdd,
        "max_drawdown_delta_decimal": round(mdd_delta, 8),
        "aligned_benchmark_points": aligned_benchmark_points,
    }


def _resolve_single_benchmark(
    symbol: str,
    *,
    currency: str,
    start_dt: date | None,
    end_dt: date | None,
    config: ApiConfig,
    eodhd_transport: TransportCallable | None = None,
    trader_curve: Sequence[tuple[str, float]] | None = None,
) -> dict[str, Any]:
    info = SUPPORTED_BENCHMARKS[symbol]
    native_ccy = info["native_currency"]
    source = "bundled_reference"
    marks: list[tuple[str, float]] = []
    fx_marks: list[tuple[str, float]] = []

    if config.eodhd_api_key.strip():
        fetch_window = _compute_live_fetch_window(
            start_dt,
            end_dt,
            widen_for_cache=(eodhd_transport is None),
        )
        if fetch_window is not None:
            fetch_start, fetch_end = fetch_window
            try:
                live_marks = _fetch_eodhd_daily_marks(
                    info["eodhd_ticker"],
                    api_key=config.eodhd_api_key.strip(),
                    start_date=fetch_start,
                    end_date=fetch_end,
                    transport=eodhd_transport,
                )
                if len(live_marks) >= 2:
                    needs_fx = currency in {"USD", "EUR"} and currency != native_ccy
                    if needs_fx:
                        live_fx = _fetch_eodhd_daily_marks(
                            "EURUSD.FOREX",
                            api_key=config.eodhd_api_key.strip(),
                            start_date=fetch_start,
                            end_date=fetch_end,
                            transport=eodhd_transport,
                        )
                        if live_fx:
                            marks = live_marks
                            fx_marks = live_fx
                            source = "eodhd_total_return"
                    else:
                        marks = live_marks
                        source = "eodhd_total_return"
            except Exception:
                marks = []

    if not marks:
        dataset = _load_bundled_dataset()
        dates_arr = dataset.get("dates", [])
        vals_arr = dataset.get("series", {}).get(symbol, [])
        fx_arr = dataset.get("eurusd", [])
        source = str(dataset.get("source") or "bundled_reference")
        marks = [
            (str(d), float(v))
            for d, v in zip(dates_arr, vals_arr)
            if _is_positive_finite_number(v)
        ]
        fx_marks = [
            (str(d), float(v))
            for d, v in zip(dates_arr, fx_arr)
            if _is_positive_finite_number(v)
        ]

    converted = _convert_series_currency(
        marks,
        native_currency=native_ccy,
        target_currency=currency,
        eurusd_by_date=fx_marks,
    )
    points = _slice_and_rebase(converted, start_dt=start_dt, end_dt=end_dt)

    entry: dict[str, Any] = {
        "symbol": symbol,
        "name": info["name"],
        "native_currency": native_ccy,
        "currency": currency,
        "currency_basis": _currency_basis_label(
            native_currency=native_ccy,
            target_currency=currency,
        ),
        "source": source,
        "point_count": len(points),
        "start_date": points[0]["date"] if points else None,
        "end_date": points[-1]["date"] if points else None,
        "points": points,
    }
    if trader_curve is not None:
        entry["comparison"] = compute_benchmark_comparison(trader_curve, converted)
    return entry


def handle_get_benchmarks_catalog() -> tuple[int, dict[str, Any]]:
    """Return supported benchmark symbols and metadata via ``GET /api/v1/benchmarks``."""
    dataset = _load_bundled_dataset()
    return 200, {
        "supported_currencies": sorted(SUPPORTED_CURRENCIES),
        "bundled_base_date": dataset.get("base_date"),
        "bundled_as_of_date": dataset.get("as_of_date"),
        "benchmarks": [
            {
                "symbol": sym,
                "name": info["name"],
                "native_currency": info["native_currency"],
            }
            for sym, info in SUPPORTED_BENCHMARKS.items()
        ],
    }


def handle_get_benchmark_series(
    query_params: Mapping[str, str],
    *,
    config: ApiConfig,
    store: ProofStore | None = None,
    eodhd_transport: TransportCallable | None = None,
) -> tuple[int, dict[str, Any]]:
    """Serve rebased-100 daily total-return benchmark series via ``GET /api/v1/benchmarks/series``."""
    if "symbols" in query_params:
        raw_symbols = query_params["symbols"]
    elif "symbol" in query_params:
        raw_symbols = query_params["symbol"]
    else:
        raw_symbols = "SPY"

    requested = [s.strip().upper() for s in raw_symbols.split(",") if s.strip()]
    if not requested:
        return 422, {
            "error": "validation_error",
            "detail": "At least one benchmark symbol is required (SPY, QQQ, VWCE, VT, GLD)",
        }

    invalid_syms = [s for s in requested if s not in SUPPORTED_BENCHMARKS]
    if invalid_syms:
        return 422, {
            "error": "unsupported_benchmark_symbol",
            "detail": (
                f"Unsupported benchmark symbol(s): {', '.join(invalid_syms)}. "
                f"Supported: {', '.join(SUPPORTED_BENCHMARKS.keys())}"
            ),
        }

    try:
        start_dt = _parse_iso_date(query_params.get("start_date"), field_name="start_date")
        end_dt = _parse_iso_date(query_params.get("end_date"), field_name="end_date")
    except ValueError as exc:
        return 422, {"error": "validation_error", "detail": str(exc)}

    if start_dt is not None and end_dt is not None and end_dt < start_dt:
        return 422, {
            "error": "validation_error",
            "detail": "end_date must be on or after start_date",
        }

    trader_curve: list[tuple[str, float]] | None = None
    proof_id_raw = (query_params.get("proof_id") or "").strip()
    proof_base_currency: str | None = None
    if proof_id_raw:
        if store is None:
            return 422, {
                "error": "validation_error",
                "detail": "proof_id comparison is unavailable without a proof store",
            }
        try:
            stored_entry = store.get_proof_entry(proof_id_raw)
        except ProofNotFoundError:
            return 404, {
                "error": "proof_not_found",
                "detail": f"Proof {proof_id_raw!r} not found",
            }
        curve_leaf = verified_leaf_payload(stored_entry.bundle, "indexed_curve")
        trader_curve = _extract_trader_daily_curve(curve_leaf)
        if len(trader_curve) < 2:
            return 422, {
                "error": "indexed_curve_undisclosed",
                "detail": "This record does not disclose an indexed_curve with at least 2 daily points",
            }
        proof_base_currency = stored_entry.bundle.base_currency.strip().upper()
        if start_dt is None:
            start_dt = date.fromisoformat(trader_curve[0][0])
        if end_dt is None:
            end_dt = date.fromisoformat(trader_curve[-1][0])
        if end_dt < start_dt:
            return 422, {
                "error": "validation_error",
                "detail": "end_date must be on or after start_date",
            }

    default_ccy = (
        proof_base_currency
        if proof_base_currency in {"USD", "EUR"}
        else "USD"
    )
    currency = (query_params.get("currency") or default_ccy).strip().upper()
    if currency not in SUPPORTED_CURRENCIES:
        return 422, {
            "error": "unsupported_currency",
            "detail": f"currency must be one of {sorted(SUPPORTED_CURRENCIES)}, got {currency!r}",
        }

    deduped: list[str] = []
    for sym in requested:
        if sym not in deduped:
            deduped.append(sym)

    series_map = {
        sym: _resolve_single_benchmark(
            sym,
            currency=currency,
            start_dt=start_dt,
            end_dt=end_dt,
            config=config,
            eodhd_transport=eodhd_transport,
            trader_curve=trader_curve,
        )
        for sym in deduped
    }

    response: dict[str, Any] = {
        "currency": currency,
        "series": series_map,
    }
    if proof_id_raw:
        response["proof_id"] = proof_id_raw
    if len(deduped) == 1:
        single = series_map[deduped[0]]
        response["symbol"] = single["symbol"]
        response["name"] = single["name"]
        response["native_currency"] = single["native_currency"]
        response["currency_basis"] = single["currency_basis"]
        response["source"] = single["source"]
        response["points"] = single["points"]
        if "comparison" in single:
            response["comparison"] = single["comparison"]
    return 200, response


__all__ = [
    "SUPPORTED_BENCHMARKS",
    "SUPPORTED_CURRENCIES",
    "clear_benchmark_cache",
    "compute_benchmark_comparison",
    "handle_get_benchmark_series",
    "handle_get_benchmarks_catalog",
]
