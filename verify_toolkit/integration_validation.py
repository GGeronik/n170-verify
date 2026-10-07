"""Opt-in real-engine validation using only original synthetic engineering inputs.

This is intentionally separate from fast stdlib unit tests. It launches the
pinned separately installed engine, and never treats a mocked transport as proof.
"""
import argparse
import json
from pathlib import Path
import threading

from .runner import DEFAULT_IMAGE, run_freqtrade
from .run_contract import digest, json_bytes, read_file, verify_run
from .synthetic import generate_fixture, strategy_source


def validate(destination, *, acknowledge_local_code=False, image=DEFAULT_IMAGE):
    if not acknowledge_local_code:
        raise ValueError("Explicit opt-in required")
    root = Path(destination).absolute()
    root.mkdir(mode=0o700, exist_ok=False)
    fixture = generate_fixture(root / "fixtures")
    data = fixture / "data/BTC_USDT-5m.json"
    names = ["N170Clean", "N170Biased", "N170Never", "N170Failure"]
    strategies = {name: fixture / "strategies" / (name + ".py") for name in names}
    expected = ["NO_FINDINGS_REPORTED", "FINDINGS_REPORTED", "INSUFFICIENT", "FAILED"]
    checks, runs = [], []
    for name in ("controls", "rerun"):
        manifest = run_freqtrade(root / name, image=image, strategies=strategies, data=data,
                                 acknowledge_local_code=True)
        observed = [a["outcome"] for a in manifest["attempts"]]
        checks.append({"case": name + "_outcomes", "expected": expected, "observed": observed, "passed": observed == expected})
        verification = verify_run(root / name)
        checks.append({"case": name + "_receipt", "passed": verification["reason_codes"] == ["INVENTORY_AND_ACCOUNTING_CONSISTENT", "UNASSESSABLE_ATTEMPTS"]})
        runs.append({"path": name, "manifest_sha256": digest(read_file(root / name / "manifest.json"))})
    for index in range(3):
        rel = f"attempts/{index:03d}/output/lookahead.csv"
        first, second = root / "controls" / rel, root / "rerun" / rel
        equal = first.exists() and second.exists() and read_file(first) == read_file(second)
        checks.append({"case": names[index] + "_csv_repeat", "passed": equal})
    slow = fixture / "strategies/N170Slow.py"
    slow.write_text(strategy_source("N170Slow").replace(
        '        dataframe["past_mean"]', '        import time\n        time.sleep(30)\n        dataframe["past_mean"]'), encoding="utf-8")
    for name, timeout, cancellation in (("timeout", 1, False), ("cancellation", 120, True)):
        event = threading.Event()
        timer = threading.Timer(3, event.set) if cancellation else None
        if timer:
            timer.start()
        try:
            manifest = run_freqtrade(root / name, image=image, strategies={"N170Slow": slow, "N170Clean": strategies["N170Clean"]},
                                     data=data, acknowledge_local_code=True, timeout_seconds=timeout, cancel_event=event)
        finally:
            if timer:
                timer.cancel()
        first = manifest["attempts"][0]
        outcome = "CANCELLED" if cancellation else "TIMED_OUT"
        checks.append({"case": name, "expected": outcome, "observed": first["outcome"],
                       "cleanup_confirmed": first.get("cleanup_confirmed"),
                       "passed": first["outcome"] == outcome and first.get("cleanup_confirmed") is True})
        if cancellation:
            checks.append({"case": "cancelled_remainder_skipped", "passed": manifest["attempts"][1]["outcome"] == "SKIPPED"})
        verification = verify_run(root / name)
        checks.append({"case": name + "_not_clean", "passed": verification["status"] == "NOT_ASSESSABLE"})
        runs.append({"path": name, "manifest_sha256": digest(read_file(root / name / "manifest.json"))})
    result = {"schema": "n170.freqtrade-real-integration.v1", "scope": "original synthetic engineering controls; agent-run, not external human review",
              "real_engine_required": True, "checks": checks, "runs": runs,
              "passed": all(check["passed"] for check in checks)}
    (root / "validation-summary.json").write_bytes(json_bytes(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--acknowledge-local-code", action="store_true")
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    args = parser.parse_args()
    result = validate(args.output, acknowledge_local_code=args.acknowledge_local_code, image=args.image)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
