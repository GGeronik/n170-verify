"""Original synthetic inputs for offline engineering checks, not market performance."""

from __future__ import annotations

import json
import math
from pathlib import Path


STRATEGIES = {
    "N170Clean": False,
    "N170Biased": True,
}


def build_config(request: dict) -> dict:
    """Build a deliberately narrow, credential-free spot backtest configuration."""
    return {
        "max_open_trades": 1,
        "stake_currency": "USDT",
        "stake_amount": 10000,
        "tradable_balance_ratio": 1.0,
        "dry_run": True,
        "dry_run_wallet": 1000000000,
        "trading_mode": "spot",
        "timeframe": request.get("timeframe", "5m"),
        "timerange": request.get("timerange", "20260101-20260104"),
        "fee": request.get("fee", 0.001),
        "dataformat_ohlcv": "json",
        "exchange": {
            "name": "binance",
            "pair_whitelist": ["BTC/USDT"],
            "pair_blacklist": [],
            "enable_ws": False,
        },
        "pairlists": [{"method": "StaticPairList"}],
        "entry_pricing": {"price_side": "other", "use_order_book": False},
        "exit_pricing": {"price_side": "other", "use_order_book": False},
        "unfilledtimeout": {"entry": 10, "exit": 10, "unit": "minutes"},
        "cancel_open_orders_on_exit": False,
        "bot_name": "n170-offline-synthetic",
        "initial_state": "stopped",
    }


def strategy_source(name: str, *, biased: bool = False, never: bool = False, fail: bool = False) -> str:
    """Return original, transparent periodic strategies with an optional future column."""
    indicator = (
        '        dataframe["future_close"] = dataframe["close"].shift(-1)\n'
        if biased else
        '        dataframe["past_mean"] = dataframe["close"].rolling(3).mean()\n'
    )
    if fail:
        indicator = '        raise RuntimeError("Original deliberate failure control")\n'
    entry_condition = ('dataframe["volume"] < 0' if never else
                       '(dataframe["date"].dt.minute % 30 == 0) & (dataframe["volume"] > 0)')
    return (
        '# Original N170 synthetic engineering fixture. SPDX-License-Identifier: Apache-2.0\n'
        '# This is not a financial strategy or real-market performance evidence.\n'
        'from freqtrade.strategy import IStrategy\n\n\n'
        f'class {name}(IStrategy):\n'
        '    INTERFACE_VERSION = 3\n'
        '    timeframe = "5m"\n'
        '    startup_candle_count = 3\n'
        '    minimal_roi = {"0": 100.0}\n'
        '    stoploss = -0.99\n'
        '    can_short = False\n'
        '    def populate_indicators(self, dataframe, metadata):\n'
        + indicator +
        '        return dataframe\n\n'
        '    def populate_entry_trend(self, dataframe, metadata):\n'
        f'        dataframe.loc[{entry_condition}, "enter_long"] = 1\n'
        '        return dataframe\n\n'
        '    def populate_exit_trend(self, dataframe, metadata):\n'
        '        dataframe.loc[dataframe["date"].dt.minute % 30 == 10, "exit_long"] = 1\n'
        '        return dataframe\n'
    )


def generate_fixture(destination: str | Path) -> Path:
    """Create a new fixture directory exclusively; never reuse stale fixture files."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "data").mkdir()
    (destination / "strategies").mkdir()
    # Three days of original deterministic five-minute OHLCV plus startup candles.
    start_ms = 1767225600000 - 12 * 300000
    candles = []
    for index in range(3 * 24 * 12 + 12):
        opening = 100 + 2 * math.sin(index / 13) + 0.2 * math.cos(index / 7)
        closing = opening + 0.1 * math.sin(index / 3)
        candles.append([
            start_ms + index * 300000,
            round(opening, 8), round(max(opening, closing) + 0.25, 8),
            round(min(opening, closing) - 0.25, 8), round(closing, 8),
            round(1000 + index % 29, 8),
        ])
    (destination / "data" / "BTC_USDT-5m.json").write_text(
        json.dumps(candles, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    (destination / "config.json").write_text(
        json.dumps(build_config({}), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    for name, biased in STRATEGIES.items():
        (destination / "strategies" / f"{name}.py").write_text(
            strategy_source(name, biased=biased), encoding="utf-8"
        )
    for name, flags in [("N170Never", {"never": True}), ("N170Failure", {"fail": True})]:
        (destination / "strategies" / f"{name}.py").write_text(
            strategy_source(name, **flags), encoding="utf-8"
        )
    (destination / "SCOPE.txt").write_text(
        "Original deterministic synthetic market data and benign local strategies.\n"
        "Engineering controls only; no real-market strategy performance claim.\n"
        "N170Biased deliberately reads the following candle using shift(-1).\n",
        encoding="utf-8",
    )
    return destination
