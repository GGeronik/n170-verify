"""Original offline receipt verification. Never imports or executes Freqtrade."""
from __future__ import annotations

import hashlib
import base64
import json
import os
from pathlib import Path
import re
import stat

from .freqtrade import UPSTREAM_REVISION, assess_lookahead

SCHEMA = "n170.freqtrade-run.v2"
WORKER_SCHEMA = "n170.freqtrade-worker.v2"
ENGINE_SOURCE_SHA256 = "a96f980268301b69f8fb6e423d27606ede3f174449f63ff672aebb48f97ac6de"
ASSESSABLE = {"NO_FINDINGS_REPORTED", "FINDINGS_REPORTED"}
OUTCOMES = ASSESSABLE | {"INSUFFICIENT", "FAILED", "TIMED_OUT", "CANCELLED", "SKIPPED", "MISSING_OUTPUT", "INVALID_OUTPUT", "INPUT_CHANGED"}
MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
TRUST = {
    "execution": "local_runner_receipt; recipient has not witnessed execution",
    "authenticity": "unsigned; no broker, publisher, hardware or remote execution authentication",
    "completeness": "selected attempts only; previous trials and omitted strategy families unknown",
    "reproduction": "not established by integrity verification; independently rerun the captured inputs",
    "detector_coverage": "exercised Freqtrade lookahead signals only; no profitability, fill realism or absence-of-bias guarantee",
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("Duplicate field")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("Nonfinite value")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def safe_relative(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_./-]{1,240}", value):
        raise ValueError("Unsupported artifact path")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("Unsafe artifact path")
    return value


def read_file(path, limit=MAX_FILE):
    """Anchor each parent and reject symlinks/special files; read one byte buffer."""
    absolute = Path(os.path.abspath(path))
    current = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        fd = os.open(absolute.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
        with os.fdopen(fd, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ValueError("Regular file required")
            raw = source.read(limit + 1)
            if len(raw) > limit:
                raise ValueError("File limit exceeded")
            return raw
    finally:
        os.close(current)


def inventory_entry(path, raw):
    return {"path": safe_relative(path), "size": len(raw), "sha256": digest(raw)}


def summarize(attempts):
    counts = {key: sum(a.get("outcome") == key for a in attempts) for key in sorted(OUTCOMES)}
    all_done = bool(attempts) and all(a.get("state") == "FINALIZED" and a.get("outcome") in ASSESSABLE for a in attempts)
    status = ("FINDINGS_REPORTED" if counts["FINDINGS_REPORTED"] else "NO_FINDINGS_REPORTED") if all_done else "NOT_ASSESSABLE"
    return {"status": status, "selected_count": len(attempts), "assessed_count": sum(counts[k] for k in ASSESSABLE), "findings_count": counts["FINDINGS_REPORTED"], "outcome_counts": counts}



def execution_environment(timeout_seconds):
    return {"network": "none", "uid": 1000, "read_only_root": True, "input_mount": "read_only",
            "memory_bytes": 1073741824, "cpus": 1, "pids": 64, "output_tmpfs_bytes": 16777216,
            "temporary_tmpfs_bytes": 134217728, "log_bytes": 8388608, "wall_seconds": timeout_seconds}


def engine_arguments(request):
    return {"command": "lookahead-analysis", "config": ["/input/config.json"],
            "user_data_dir": "/tmp/n170-user", "datadir": "/input/data",
            "strategy_path": "/input/strategies", "strategy": request["strategy"],
            "timeframe": "5m", "timerange": request["timerange"],
            "minimum_trade_amount": request["minimum_trade_amount"],
            "targeted_trade_amount": request["targeted_trade_amount"], "fee": request["fee"],
            "dataformat_ohlcv": "json", "lookahead_analysis_exportfilename": "/output/lookahead.csv"}

def classify_worker(worker, csv_raw, strategy, request, expected_inputs, request_raw):
    """Require input/engine receipts AND one matching interpretable detector row."""
    if type(worker) is not dict or worker.get("schema") != WORKER_SCHEMA or worker.get("strategy") != strategy:
        return "INVALID_OUTPUT"
    engine = worker.get("engine", {})
    if type(engine) is not dict:
        return "INVALID_OUTPUT"
    if (engine.get("version") != "2026.8" or engine.get("revision") != UPSTREAM_REVISION or engine.get("source_sha256") != ENGINE_SOURCE_SHA256):
        return "INVALID_OUTPUT"
    if worker.get("input_inventory") != expected_inputs or worker.get("request_sha256") != digest(request_raw):
        return "INPUT_CHANGED"
    if worker.get("outcome") == "FAILED":
        return "FAILED"
    if worker.get("outcome") == "INSUFFICIENT":
        return "INSUFFICIENT"
    if worker.get("outcome") != "COMPLETED":
        return "INVALID_OUTPUT"
    environment = worker.get("environment")
    if (type(environment) is not dict or environment.get("uid") != 1000
            or any(type(environment.get(k)) is not str or not environment[k] for k in ("python", "platform", "machine"))
            or type(environment.get("packages")) is not list or not environment["packages"]):
        return "INVALID_OUTPUT"
    source_files = engine.get("source_files")
    if (type(source_files) is not list or len(source_files) != 332
            or any(type(item) is not dict or set(item) != {"path", "size", "sha256"}
                   or type(item["path"]) is not str or type(item["size"]) is not int
                   or type(item["sha256"]) is not str for item in source_files)
            or digest(json.dumps(source_files, sort_keys=True, separators=(",", ":")).encode()) != ENGINE_SOURCE_SHA256
            or engine.get("source_after_sha256") != ENGINE_SOURCE_SHA256):
        return "INVALID_OUTPUT"
    if worker.get("engine_arguments") != engine_arguments(request):
        return "INVALID_OUTPUT"
    if csv_raw is None:
        return "MISSING_OUTPUT"
    try:
        observation = assess_lookahead(csv_raw.decode("utf-8"), context={
            "freqtrade_version": "2026.8", "run_status": "COMPLETED", "expected_strategy_count": 1,
            "run_config": {"minimum_trade_amount": request["minimum_trade_amount"], "targeted_trade_amount": request["targeted_trade_amount"]},
        })
        if observation["status"] not in ASSESSABLE or len(observation["rows"]) != 1:
            return "INVALID_OUTPUT"
        row = observation["rows"][0]
        analysis = worker.get("analysis", {})
        if type(analysis) is not dict:
            return "INVALID_OUTPUT"
        if row["strategy"] != strategy or row["filename"] != strategy + ".py":
            return "INVALID_OUTPUT"
        for key in ("has_bias", "total_signals", "biased_entry_signals", "biased_exit_signals", "biased_indicators"):
            if analysis.get(key) != row[key]:
                return "INVALID_OUTPUT"
        if analysis.get("failed_bias_check") is not False:
            return "INSUFFICIENT"
        return observation["status"]
    except (ValueError, KeyError, TypeError):
        return "INVALID_OUTPUT"



def decode_bundle(stdout):
    """Decode only the fixed data-only stdout transport, never archive paths."""
    prefix = b"N170_RESULT_BUNDLE_V2:"
    lines = [line[len(prefix):] for line in stdout.splitlines() if line.startswith(prefix)]
    if not lines:
        return None
    if len(lines) != 1:
        raise ValueError("Ambiguous worker result")
    if len(lines[0]) > 6 * 1024 * 1024:
        raise ValueError("Oversized transport")
    files = strict_json(base64.b64decode(lines[0], validate=True))
    allowed = {"worker-result.json", "lookahead.csv", "effective-config.json", "market-metadata.json", "baseline-capture.json"}
    if type(files) is not dict or not set(files) <= allowed or "worker-result.json" not in files:
        raise ValueError("Invalid output bundle")
    result = {}
    for name, encoded in sorted(files.items()):
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("Oversized output")
        result[name] = raw
    if sum(map(len, result.values())) > 3 * 1024 * 1024:
        raise ValueError("Output total limit")
    return result

def _files(root):
    found = []
    visited = 0
    for parent, directories, filenames in os.walk(root, followlinks=False):
        visited += 1
        if visited > 128 or len(found) + len(filenames) > 128:
            raise ValueError("Inventory traversal limit")
        for name in directories:
            if (Path(parent) / name).is_symlink():
                raise ValueError("Symlink directory")
        for name in filenames:
            found.append((Path(parent) / name).relative_to(root).as_posix())
    return sorted(found)


def verify_run_bytes(raw, artifact_buffers, manifest_sha256=None):
    """Check an in-memory receipt without extracting or executing supplied bytes."""
    report = {"schema": "n170.freqtrade-run-verification.v2", "status": "NOT_ASSESSABLE", "reason_codes": [], "summary": None, "trust": dict(TRUST)}
    try:
        report["manifest_sha256"] = digest(raw)
        report["manifest_pin"] = "not_supplied" if manifest_sha256 is None else "mismatched_or_invalid"
        if manifest_sha256 is not None and (not re.fullmatch(r"[a-f0-9]{64}", manifest_sha256) or digest(raw) != manifest_sha256):
            raise ValueError("MANIFEST_PIN_MISMATCH")
        if manifest_sha256 is not None:
            report["manifest_pin"] = "matched"
        m = strict_json(raw)
        if m["schema"] != SCHEMA or m["state"] != "FINALIZED":
            raise ValueError("INCOMPLETE_MANIFEST")
        if not re.fullmatch(r"[a-f0-9]{32}", m["run_id"]) or not m["started_at"] or not m["finished_at"] or m["trust"] != TRUST:
            raise ValueError("INVALID_MANIFEST_METADATA")
        if type(m["execution_root"]) is not str or not Path(m["execution_root"]).is_absolute():
            raise ValueError("INVALID_EXECUTION_ROOT")
        names = m["request"]["strategies"]
        attempts = m["attempts"]
        if not isinstance(names, list) or not 1 <= len(names) <= 8 or len(set(names)) != len(names):
            raise ValueError("INVALID_SELECTION")
        if len(attempts) != len(names) or [a["strategy"] for a in attempts] != names:
            raise ValueError("INCOMPLETE_ATTEMPTS")
        inventory = m["artifacts"]
        if type(inventory) is not list or len(inventory) > 128:
            raise ValueError("INVALID_INVENTORY")
        buffers, total = {}, 0
        for item in inventory:
            path = safe_relative(item["path"])
            if path == "manifest.json" or path in buffers or type(item["size"]) is not int:
                raise ValueError("INVALID_INVENTORY")
            b = artifact_buffers[path]
            total += len(b)
            if total > MAX_TOTAL or inventory_entry(path, b) != item:
                raise ValueError("ARTIFACT_MISMATCH")
            buffers[path] = b
        if sorted(artifact_buffers) != sorted(buffers):
            raise ValueError("UNINVENTORIED_ARTIFACT")
        if m["engine"]["revision"] != UPSTREAM_REVISION or m["engine"]["version"] != "2026.8":
            raise ValueError("ENGINE_MISMATCH")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", m["engine"]["image_id"]):
            raise ValueError("ENGINE_MISMATCH")
        inputs = m["inputs"]
        required_input_inventory = [i for i in inventory if re.fullmatch(r"attempts/[0-9]{3}/input/.+", i["path"])]
        if type(inputs) is not list or inputs != required_input_inventory:
            raise ValueError("INPUT_INVENTORY_MISMATCH")
        for index, a in enumerate(attempts):
            prefix = f"attempts/{index:03d}/"
            if a["id"] != f"{index:03d}" or a["state"] != "FINALIZED" or a["outcome"] not in OUTCOMES:
                raise ValueError("INCOMPLETE_ATTEMPTS")
            if a["artifacts"] != [i for i in inventory if i["path"].startswith(prefix)]:
                raise ValueError("ATTEMPT_INVENTORY_MISMATCH")
            expected = [dict(i, path=i["path"][len(prefix + "input/"):]) for i in inputs if i["path"].startswith(prefix + "input/") and not i["path"].endswith("/request.json")]
            request_raw = buffers.get(prefix + "input/request.json")
            if request_raw is None:
                if a["outcome"] != "SKIPPED":
                    raise ValueError("MISSING_INPUT")
                continue
            required_inputs = {"config.json", "engine_worker.py", "engine_worker_v1.py", "accounting_collector.py", "data/BTC_USDT-5m.json", "strategies/" + a["strategy"] + ".py"}
            if {i["path"] for i in expected} != required_inputs or len(expected) != 6:
                raise ValueError("MISSING_REQUIRED_INPUT")
            if a["argv"] and any(prefix + filename not in buffers for filename in ("stdout.log", "stderr.log")):
                raise ValueError("MISSING_EXECUTION_LOG")
            request = strict_json(request_raw)
            declared_request = {key: value for key, value in m["request"].items() if key != "strategies"}
            declared_request.update(strategy=a["strategy"], input_inventory=expected, schema="n170.freqtrade-request.v2", run_id=m["run_id"], attempt_id=a["id"])
            if request != declared_request:
                raise ValueError("INPUT_INVENTORY_MISMATCH")
            from .synthetic import build_config
            config_bytes = buffers.get(prefix + "input/config.json")
            if config_bytes != json_bytes(build_config(request)):
                raise ValueError("CONFIGURATION_MISMATCH")
            if a["argv"]:
                from .runner_v2 import _argv
                wanted = _argv(a["argv"][0], m["engine"]["image_id"], Path(m["execution_root"]) / prefix / "input",
                               "n170-" + m["run_id"] + "-" + a["id"])
                if a["argv"] != wanted:
                    raise ValueError("INVOCATION_MISMATCH")
            output_buffers = {path[len(prefix + "output/"):]: data for path, data in buffers.items() if path.startswith(prefix + "output/")}
            if output_buffers:
                emitted = decode_bundle(buffers.get(prefix + "stdout.log", b""))
                if emitted != output_buffers:
                    raise ValueError("OUTPUT_TRANSPORT_MISMATCH")
                worker_all = strict_json(output_buffers["worker-result.json"])
                if a.get("capture") != worker_all.get("capture"):
                    raise ValueError("CAPTURE_RECEIPT_MISMATCH")
                verify_capture_binding(worker_all, output_buffers.get("baseline-capture.json"), request, request_raw, expected)
            if a["outcome"] in ASSESSABLE | {"INSUFFICIENT", "MISSING_OUTPUT", "INVALID_OUTPUT", "INPUT_CHANGED"}:
                worker_path = prefix + "output/worker-result.json"
                if worker_path not in buffers:
                    computed = "MISSING_OUTPUT"
                else:
                    try:
                        worker = strict_json(buffers[worker_path])
                        computed = classify_worker(worker, buffers.get(prefix + "output/lookahead.csv"), a["strategy"], request, expected, request_raw)
                    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
                        # Malformed output may itself be a consistently recorded failure.
                        computed = "INVALID_OUTPUT"
                if a["exit_code"] != 0 or computed != a["outcome"]:
                    raise ValueError("OUTCOME_MISMATCH")
            if a["outcome"] in ASSESSABLE:
                wanted_environment = execution_environment(request["timeout_seconds"])
                wanted_environment["observed"] = worker.get("environment")
                if (a["environment"] != wanted_environment or a.get("cleanup_confirmed") is not None
                        or a.get("container_name") != "n170-" + m["run_id"] + "-" + a["id"]):
                    raise ValueError("INVALID_ENVIRONMENT_RECEIPT")
                if not a["argv"] or type(a["started_at"]) is not str or type(a["finished_at"]) is not str:
                    raise ValueError("MISSING_EXECUTION_RECEIPT")
                if worker.get("effective_config_sha256") != digest(buffers[prefix + "output/effective-config.json"]):
                    raise ValueError("EFFECTIVE_CONFIGURATION_MISMATCH")
                if worker.get("offline_adapter", {}).get("market_metadata_sha256") != digest(buffers[prefix + "output/market-metadata.json"]):
                    raise ValueError("MARKET_METADATA_MISMATCH")
                emitted = decode_bundle(buffers[prefix + "stdout.log"])
                retained = {path[len(prefix + "output/"):]: data for path, data in buffers.items() if path.startswith(prefix + "output/")}
                if emitted != retained:
                    raise ValueError("OUTPUT_TRANSPORT_MISMATCH")
                if "observed" in a["environment"] and a["environment"]["observed"] != worker.get("environment"):
                    raise ValueError("ENVIRONMENT_MISMATCH")
        summary = summarize(attempts)
        if m["summary"] != summary:
            raise ValueError("SUMMARY_MISMATCH")
        report["summary"] = summary
        report["status"] = summary["status"]
        report["reason_codes"] = ["INVENTORY_AND_CAPTURE_BINDINGS_CONSISTENT"]
        if report["status"] == "NOT_ASSESSABLE":
            report["reason_codes"].append("UNASSESSABLE_ATTEMPTS")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, OverflowError):
        report["reason_codes"] = ["INVALID_OR_INCOMPLETE_RUN_BUNDLE"]
        report["status"] = "NOT_ASSESSABLE"
    return report


def verify_run(directory, manifest_sha256=None):
    """Read the complete local directory once, then verify the retained bytes."""
    try:
        root = Path(directory)
        raw = read_file(root / "manifest.json", 4 * 1024 * 1024)
        buffers, total = {}, 0
        for path in _files(root):
            if path == "manifest.json":
                continue
            b = read_file(root / safe_relative(path))
            total += len(b)
            if total > MAX_TOTAL:
                raise ValueError("Inventory size limit")
            buffers[path] = b
        return verify_run_bytes(raw, buffers, manifest_sha256)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, OverflowError):
        return {"schema": "n170.freqtrade-run-verification.v2", "status": "NOT_ASSESSABLE",
                "reason_codes": ["INVALID_OR_INCOMPLETE_RUN_BUNDLE"], "summary": None, "trust": dict(TRUST)}


def verify_capture_binding(worker, raw, request, request_raw, expected):
    """Acquisition identity only; financial semantics belong to the offline adapter."""
    descriptor = worker.get("capture")
    if type(descriptor) is not dict or set(descriptor) != {"schema", "path", "size", "sha256", "status", "reason_codes"}:
        raise ValueError("MISSING_CAPTURE_DESCRIPTOR")
    if descriptor["schema"] != "n170.freqtrade-baseline-capture.v1" or descriptor["path"] != "baseline-capture.json":
        raise ValueError("CAPTURE_SCHEMA_MISMATCH")
    if raw is None:
        if descriptor["status"] != "FAILED" or descriptor["sha256"] is not None or descriptor["size"] is not None:
            raise ValueError("MISSING_CAPTURE")
        return None
    if type(descriptor["size"]) is not int or descriptor["size"] != len(raw) or descriptor["sha256"] != digest(raw):
        raise ValueError("CAPTURE_BYTES_MISMATCH")
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("CAPTURE_LIMIT")
    capture = strict_json(raw)
    binding = capture["binding"]
    engine = worker.get("engine", {})
    by_name = {item["path"]: item["sha256"] for item in expected}
    wanted = {"run_id": request["run_id"], "attempt_id": request["attempt_id"], "strategy": request["strategy"],
        "request_sha256": digest(request_raw), "input_inventory": expected,
        "collector_sha256": by_name["accounting_collector.py"], "worker_sha256": by_name["engine_worker.py"],
        "helper_sha256": by_name["engine_worker_v1.py"], "market_metadata_sha256": worker.get("offline_adapter", {}).get("market_metadata_sha256"),
        "engine_revision": engine.get("revision"), "engine_source_sha256": engine.get("source_sha256"), "engine_source_after_sha256": engine.get("source_after_sha256")}
    if binding != wanted or capture["schema"] != descriptor["schema"]:
        raise ValueError("CAPTURE_BINDING_MISMATCH")
    if descriptor["status"] != capture["capture"]["status"] or descriptor["reason_codes"] != capture["capture"]["reason_codes"]:
        raise ValueError("CAPTURE_STATE_MISMATCH")
    return capture
