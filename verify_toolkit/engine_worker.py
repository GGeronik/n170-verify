"""Original interoperability worker for a separately installed GPL Freqtrade engine.

Run only inside the documented isolated container. No engine source is bundled.
The synthetic spot exchange metadata adapter replaces network initialization only;
Freqtrade's lookahead detector and backtesting implementation remain unmodified.
"""

from __future__ import annotations

import hashlib
import base64
import importlib.metadata
import json
import logging
import os
import platform
import sys
import traceback
from pathlib import Path


ENGINE_REVISION = "9f10e357a93c1dcf10c2a2b367659214d89c073e"
ENGINE_SOURCE_SHA256 = "a96f980268301b69f8fb6e423d27606ede3f174449f63ff672aebb48f97ac6de"
INPUT = Path("/input")
OUTPUT = Path("/output")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def inventory(root: Path, *, python_only: bool = False) -> list[dict]:
    result = []
    for item in sorted(root.rglob("*.py" if python_only else "*")):
        if item.is_symlink():
            raise ValueError(f"Symlink input/source rejected: {item}")
        if not item.is_file():
            continue
        raw = item.read_bytes()
        result.append({"path": item.relative_to(root).as_posix(), "size": len(raw), "sha256": digest(raw)})
    return result


def write_json(path: Path, data) -> None:
    # Exclusive output creation makes accidental stale output reuse an error.
    with path.open("x", encoding="utf-8") as handle:
        json.dump(data, handle, sort_keys=True, indent=2, default=str)
        handle.write("\n")


def synthetic_markets() -> dict:
    """Original minimal CCXT spot metadata; no claim to exchange-authenticated data."""
    return {"BTC/USDT": {
        "id": "BTCUSDT", "symbol": "BTC/USDT", "base": "BTC", "quote": "USDT",
        "baseId": "BTC", "quoteId": "USDT", "active": True, "type": "spot",
        "spot": True, "margin": False, "swap": False, "future": False,
        "option": False, "contract": False, "linear": None, "inverse": None,
        "taker": 0.001, "maker": 0.001,
        "precision": {"amount": 0.000001, "price": 0.000001},
        "limits": {"amount": {"min": 0.000001, "max": None},
                   "price": {"min": 0.000001, "max": None},
                   "cost": {"min": 1.0, "max": None}},
        "info": {"scope": "original-synthetic-engineering-fixture"},
    }}


def run(receipt: dict) -> None:
    request_bytes = (INPUT / "request.json").read_bytes()
    request = json.loads(request_bytes)
    receipt["strategy"] = request["strategy"]
    receipt["request_sha256"] = digest(request_bytes)
    actual_inputs = [item for item in inventory(INPUT) if item["path"] != "request.json"]
    receipt["input_inventory"] = actual_inputs
    if actual_inputs != request["input_inventory"]:
        raise ValueError("INPUT_CHANGED: staged input inventory differs from request")
    strategy = request["strategy"]
    if not strategy.isidentifier() or strategy.startswith("_"):
        raise ValueError("Invalid strategy name")
    selected_path = INPUT / "strategies" / f"{strategy}.py"
    if list((INPUT / "strategies").iterdir()) != [selected_path]:
        raise ValueError("Only the explicitly selected local strategy file may be staged")
    if request.get("timeframe", "5m") != "5m":
        raise ValueError("Only five-minute synthetic spot metadata is supported")
    if any(name.startswith("FREQTRADE__") for name in os.environ):
        raise ValueError("Environment configuration overrides are forbidden")

    import freqtrade
    package = Path(freqtrade.__file__).parent
    source_files = inventory(package, python_only=True)
    source_sha256 = digest(canonical(source_files))
    receipt["engine"] = {
        "version": freqtrade.__version__, "revision": ENGINE_REVISION,
        "source_sha256": source_sha256, "source_files": source_files,
        "source_inventory_algorithm": "sha256(canonical-json sorted [{path,size,sha256}] for freqtrade/**/*.py)",
    }
    if freqtrade.__version__ != "2026.8" or source_sha256 != ENGINE_SOURCE_SHA256:
        raise ValueError("ENGINE_CHANGED: installed engine is not the pinned upstream source")
    receipt["environment"] = {
        "python": sys.version, "platform": platform.platform(),
        "machine": platform.machine(), "uid": os.getuid(),
        "packages": sorted(
            [{"name": item.metadata.get("Name", ""), "version": item.version}
             for item in importlib.metadata.distributions()], key=lambda item: (item["name"], item["version"])
        ),
    }

    from freqtrade.configuration import setup_utils_configuration
    from freqtrade.enums import RunMode
    from freqtrade.exchange import Exchange
    from freqtrade.optimize.analysis.lookahead import LookaheadAnalysis
    from freqtrade.optimize.analysis.lookahead_helpers import LookaheadAnalysisSubFunctions
    from freqtrade.util import get_progress_tracker

    userdir = Path("/tmp/n170-user")
    userdir.mkdir(exist_ok=False)
    args = {
        "command": "lookahead-analysis", "config": [str(INPUT / "config.json")],
        "user_data_dir": str(userdir), "datadir": str(INPUT / "data"),
        "strategy_path": str(INPUT / "strategies"), "strategy": strategy,
        "timeframe": "5m", "timerange": request["timerange"],
        "minimum_trade_amount": request["minimum_trade_amount"],
        "targeted_trade_amount": request["targeted_trade_amount"],
        "fee": request["fee"], "dataformat_ohlcv": "json",
        "lookahead_analysis_exportfilename": str(OUTPUT / "lookahead.csv"),
    }
    receipt["engine_arguments"] = args
    config = setup_utils_configuration(args, RunMode.UTIL_NO_EXCHANGE)
    if config["exchange"]["name"] != "binance" or config["exchange"]["pair_whitelist"] != ["BTC/USDT"]:
        raise ValueError("Only synthetic BTC/USDT spot metadata is supported")
    if config.get("trading_mode", "spot") != "spot":
        raise ValueError("Only spot mode is supported")
    config = LookaheadAnalysisSubFunctions.calculate_config_overrides(config)
    effective_bytes = canonical(config)
    write_json(OUTPUT / "effective-config.json", config)
    receipt["effective_config_sha256"] = digest((OUTPUT / "effective-config.json").read_bytes())
    receipt["effective_config_canonical_sha256"] = digest(effective_bytes)
    receipt["effective_config_stage"] = (
        "Normalized Freqtrade configuration after lookahead overrides, before strategy defaults. "
        "Resolved strategy defaults are logged by the pinned engine; selected source is inventoried."
    )

    # CCXT's public set_markets installs offline metadata. The Freqtrade cache
    # assignment is the sole private interoperability hook, pinned to this engine.
    exchange = Exchange(config, validate=False)
    markets = synthetic_markets()
    exchange._api.set_markets(markets)
    exchange._api_async.set_markets(markets)
    exchange._markets = exchange._api.markets
    exchange.validate_config(config)
    write_json(OUTPUT / "market-metadata.json", markets)
    receipt["offline_adapter"] = {
        "scope": "original synthetic BTC/USDT spot market metadata",
        "detector_modified": False,
        "hook": "Exchange(validate=False), CCXT.set_markets, Exchange._markets cache, validate_config",
        "market_metadata_sha256": digest((OUTPUT / "market-metadata.json").read_bytes()),
    }
    instance = LookaheadAnalysis(config, {"name": strategy, "location": selected_path})
    instance.exchange = exchange
    try:
        with get_progress_tracker() as progress:
            instance.start(progress)
        analysis = instance.current_analysis
        baseline_results = instance.full_varHolder.result["results"]
        receipt["analysis"] = {
            "has_bias": bool(analysis.has_bias), "total_signals": int(analysis.total_signals),
            "biased_entry_signals": int(analysis.false_entry_signals),
            "biased_exit_signals": int(analysis.false_exit_signals),
            "biased_indicators": list(analysis.false_indicators),
            "failed_bias_check": bool(instance.failed_bias_check),
            "baseline_trade_count": len(baseline_results),
            "forced_exit_count": int(baseline_results["exit_reason"].str.contains("force_exit").sum()) if len(baseline_results) else 0,
            "minimum_trade_amount": request["minimum_trade_amount"],
            "targeted_trade_amount": request["targeted_trade_amount"],
        }
        LookaheadAnalysisSubFunctions.text_table_lookahead_analysis_instances(config, [instance])
        LookaheadAnalysisSubFunctions.export_to_csv(config, [instance])
        receipt["outcome"] = (
            # The pinned exporter omits an exactly-minimum result; do not promote
            # a rowless receipt to an assessable CSV observation.
            "INSUFFICIENT" if instance.failed_bias_check or analysis.total_signals <= request["minimum_trade_amount"]
            else "COMPLETED"
        )
    finally:
        exchange.close()
    if actual_inputs != [item for item in inventory(INPUT) if item["path"] != "request.json"]:
        raise ValueError("INPUT_CHANGED: staged input bytes changed during execution")
    if digest(canonical(inventory(package, python_only=True))) != ENGINE_SOURCE_SHA256:
        raise ValueError("ENGINE_CHANGED: installed engine source changed during execution")
    receipt["engine"]["source_after_sha256"] = ENGINE_SOURCE_SHA256


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    receipt = {"schema": "n170.freqtrade-worker.v1", "outcome": "FAILED"}
    try:
        run(receipt)
    except BaseException as exc:
        receipt["outcome"] = "FAILED"
        receipt["error"] = {"type": type(exc).__name__, "message": str(exc)}
        traceback.print_exc()
    write_json(OUTPUT / "worker-result.json", receipt)
    bundle = {}
    allowed = {"worker-result.json", "lookahead.csv", "effective-config.json", "market-metadata.json"}
    for item in sorted(OUTPUT.iterdir()):
        if item.name not in allowed or item.is_symlink() or not item.is_file():
            raise ValueError("Unexpected output entry")
        bundle[item.name] = base64.b64encode(item.read_bytes()).decode("ascii")
    encoded = base64.b64encode(canonical(bundle)).decode("ascii")
    if len(encoded) > 4 * 1024 * 1024:
        raise ValueError("Output bundle exceeds 4 MiB")
    print("N170_RESULT_BUNDLE_V1:" + encoded, flush=True)
    return 0 if receipt["outcome"] != "FAILED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
