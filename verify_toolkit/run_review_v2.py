"""Bounded, data-only transport and comparison for selected local run receipts.

No supplied Python, command, archive or path is executed or extracted. Consistency
of a self-contained unsigned package cannot authenticate its author or execution.
"""
from __future__ import annotations

import base64
import binascii
import copy
import json
import math
from pathlib import Path
import re

from . import run_contract_v2 as contract

SCHEMA = "n170.run-review.v2"
MAX_ENVELOPE = 96 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024
MAX_MANIFEST = 4 * 1024 * 1024
MAX_ARTIFACTS = 128
MAX_DEPTH = 24
MAX_NODES = 200_000
MAX_STRING = 4 * 1024 * 1024
MAX_SAFE_INTEGER = 2**53 - 1
BUNDLE_PREFIX = b"N170_RESULT_BUNDLE_V2:"
HEX = re.compile(r"[a-f0-9]{64}\Z")
LOG_TIMESTAMP = re.compile(rb"(?m)^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}(?=(?: - freqtrade(?:\.[A-Za-z_][A-Za-z0-9_]*)* - (?:DEBUG|INFO|WARNING|ERROR|CRITICAL) - | (?:DEBUG|INFO|WARNING|ERROR|CRITICAL) freqtrade(?:\.[A-Za-z_][A-Za-z0-9_]*)* ))")
TRUST = {
    **contract.TRUST,
    "integrity": "consistency of supplied manifest and artifact bytes only; attacker-authored receipts can be self-consistent",
    "identity": "not established; a digest pin authenticates no producer or delivery channel",
    "scope": "synthetic BTC/USDT spot metadata; single pair; five-minute candles; pinned Freqtrade 2026.8 lookahead method",
    "import": "data only; no imported code, command or file is executed or extracted",
}


class ReviewError(ValueError):
    """A bounded public reason code, never untrusted parser text."""


def _require(condition, reason):
    if not condition:
        raise ReviewError(reason)


def strict_json(raw, *, envelope=False):
    """Parse finite safe JSON after a lexical depth guard, then bound all nodes."""
    if type(raw) is bytes:
        _require(len(raw) <= (MAX_ENVELOPE if envelope else MAX_FILE), "JSON_SIZE_LIMIT")
        text = raw.decode("utf-8", errors="strict")
    elif type(raw) is str:
        _require(len(raw.encode("utf-8", errors="strict")) <= (MAX_ENVELOPE if envelope else MAX_FILE), "JSON_SIZE_LIMIT")
        text = raw
    else:
        raise ReviewError("RAW_JSON_REQUIRED")
    _require(not text.startswith("\ufeff"), "INVALID_JSON")
    depth, quoted, escaped, primitive, lexical_nodes = -1, False, False, False, 0
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
            primitive = False
            lexical_nodes += 1
        elif char in "[{":
            lexical_nodes += 1
            primitive = False
            depth += 1
            _require(depth <= MAX_DEPTH, "JSON_DEPTH_LIMIT")
        elif char in "]}":
            depth -= 1
            primitive = False
        elif char in ",:" or char.isspace():
            primitive = False
        elif not primitive:
            primitive = True
            lexical_nodes += 1
        _require(lexical_nodes <= MAX_NODES, "JSON_NODE_LIMIT")
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "DUPLICATE_JSON_KEY")
            _require(key not in {"__proto__", "prototype", "constructor"}, "FORBIDDEN_JSON_KEY")
            result[key] = value
        return result
    def invalid(_):
        raise ReviewError("NONFINITE_JSON_NUMBER")
    def integer(value):
        _require(value != "-0", "NEGATIVE_ZERO")
        return int(value)
    def fractional(value):
        number = float(value)
        _require(math.isfinite(number), "NONFINITE_JSON_NUMBER")
        _require(not (number == 0 and math.copysign(1, number) < 0), "NEGATIVE_ZERO")
        if number.is_integer():
            _require(abs(number) <= MAX_SAFE_INTEGER, "UNSAFE_JSON_INTEGER")
            return int(number)
        return number
    result = json.loads(text, object_pairs_hook=pairs, parse_constant=invalid, parse_int=integer, parse_float=fractional)
    pending, nodes = [(result, 0)], 0
    while pending:
        value, level = pending.pop()
        nodes += 1
        _require(nodes <= MAX_NODES, "JSON_NODE_LIMIT")
        _require(level <= MAX_DEPTH, "JSON_DEPTH_LIMIT")
        if type(value) is dict:
            pending.extend((v, level + 1) for v in value.values())
            pending.extend((k, level + 1) for k in value)
        elif type(value) is list:
            pending.extend((v, level + 1) for v in value)
        elif type(value) is str:
            _require(not any(0xD800 <= ord(c) <= 0xDFFF for c in value), "INVALID_UNICODE")
            _require(envelope or len(value.encode("utf-8")) <= MAX_STRING, "JSON_STRING_LIMIT")
        elif type(value) in (int, float):
            _require(math.isfinite(value), "NONFINITE_JSON_NUMBER")
            _require(not (type(value) is float and value == 0 and math.copysign(1, value) < 0), "NEGATIVE_ZERO")
            _require(not (type(value) is int or value.is_integer()) or abs(value) <= MAX_SAFE_INTEGER, "UNSAFE_JSON_INTEGER")
        else:
            _require(value is None or type(value) is bool, "INVALID_JSON_TYPE")
    return result


def _path(value):
    try:
        return contract.safe_relative(value)
    except (ValueError, TypeError):
        raise ReviewError("INVALID_ARTIFACT_PATH") from None


def _paths(paths):
    _require(paths == sorted(paths), "UNSORTED_ARTIFACT_PATHS")
    folded = set()
    for path in paths:
        _path(path)
        key = path.lower()
        _require(key not in folded, "COLLIDING_ARTIFACT_PATH")
        folded.add(key)
    for path in folded:
        segments = path.split("/")
        _require(not any("/".join(segments[:i]) in folded for i in range(1, len(segments))), "ARTIFACT_PATH_PREFIX_COLLISION")


def _descriptor(item, *, manifest=False):
    _require(type(item) is dict and set(item) == {"path", "size", "sha256", "base64"}, "INVALID_DESCRIPTOR")
    path = _path(item["path"])
    _require(not manifest or path == "manifest.json", "INVALID_MANIFEST_PATH")
    _require(manifest or path.lower() != "manifest.json", "INVALID_ARTIFACT_PATH")
    limit = MAX_MANIFEST if manifest else MAX_FILE
    _require(type(item["size"]) is int and 0 <= item["size"] <= limit, "ARTIFACT_SIZE_LIMIT")
    _require(type(item["sha256"]) is str and HEX.fullmatch(item["sha256"]), "INVALID_DIGEST")
    value = item["base64"]
    _require(type(value) is str and len(value) <= 4 * ((limit + 2) // 3), "BASE64_SIZE_LIMIT")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ReviewError("INVALID_BASE64") from None
    _require(base64.b64encode(raw).decode("ascii") == value, "NONCANONICAL_BASE64")
    _require(len(raw) == item["size"] and contract.digest(raw) == item["sha256"], "ARTIFACT_MISMATCH")
    return raw


def _decode(raw):
    package = strict_json(raw, envelope=True)
    _require(type(package) is dict and set(package) == {"schema", "manifest", "artifacts"} and package["schema"] == SCHEMA, "INVALID_PACKAGE_SCHEMA")
    _require(type(package["artifacts"]) is list and len(package["artifacts"]) <= MAX_ARTIFACTS, "ARTIFACT_COUNT_LIMIT")
    manifest_raw = _descriptor(package["manifest"], manifest=True)
    buffers, total = {}, len(manifest_raw)
    paths = []
    for item in package["artifacts"]:
        data = _descriptor(item)
        total += len(data)
        _require(total <= MAX_TOTAL, "TOTAL_DECODED_SIZE_LIMIT")
        paths.append(item["path"])
        buffers[item["path"]] = data
    _paths(paths)
    _paths(sorted(["manifest.json", *paths]))
    manifest = strict_json(manifest_raw)
    return manifest_raw, manifest, buffers


def _inventory(manifest, buffers):
    inventory = [contract.inventory_entry(path, data) for path, data in buffers.items()]
    _require(manifest.get("artifacts") == inventory, "MANIFEST_INVENTORY_MISMATCH")
    for item in manifest["artifacts"]:
        _require(type(item) is dict and set(item) == {"path", "size", "sha256"}
                 and type(item["size"]) is int, "INVALID_INVENTORY")


def _structural(manifest, buffers):
    _require(type(manifest) is dict, "INVALID_MANIFEST")
    _require(set(manifest) == {"schema", "run_id", "execution_root", "state", "started_at", "finished_at", "engine", "request", "inputs", "artifacts", "attempts", "summary", "trust"}, "INVALID_MANIFEST_FIELDS")
    _inventory(manifest, buffers)
    _require(_typed_equal(manifest["inputs"], [item for item in manifest["artifacts"] if re.fullmatch(r"attempts/[0-9]{3}/input/.+", item["path"])]), "INPUT_INVENTORY_MISMATCH")
    for key in ("started_at", "finished_at", "execution_root", "run_id", "schema", "state"):
        _require(type(manifest[key]) is str and bool(manifest[key]), "INVALID_MANIFEST_METADATA")
    _require(manifest["execution_root"].startswith("/") and not any(c in manifest["execution_root"] for c in ("\n", "\r", ",", "\x00")), "INVALID_EXECUTION_ROOT")
    request = manifest["request"]
    _require(type(request) is dict and set(request) == {"strategies", "timeout_seconds", "minimum_trade_amount", "targeted_trade_amount", "timerange", "timeframe", "fee", "market_metadata"}, "INVALID_REQUEST")
    names = request["strategies"]
    _require(type(names) is list and 1 <= len(names) <= 8 and all(type(n) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", n) for n in names) and len(set(names)) == len(names), "INVALID_SELECTION")
    _require(type(request["timeout_seconds"]) is int and 1 <= request["timeout_seconds"] <= 600, "INVALID_REQUEST")
    _require(type(request["minimum_trade_amount"]) is int and type(request["targeted_trade_amount"]) is int and 1 <= request["minimum_trade_amount"] < request["targeted_trade_amount"] <= 100, "INVALID_REQUEST")
    _require(type(request["timerange"]) is str and re.fullmatch(r"[0-9]{8}-[0-9]{8}", request["timerange"]) and request["timeframe"] == "5m" and type(request["fee"]) in (int, float) and request["fee"] == 0.001 and request["market_metadata"] == "original_synthetic_spot_BTC_USDT", "UNSUPPORTED_RUN_SCOPE")
    engine = manifest["engine"]
    _require(type(engine) is dict and {"version", "revision", "image_id", "reference"} <= set(engine) <= {"version", "revision", "image_id", "reference", "os", "architecture", "docker_version"}, "INVALID_ENGINE")
    _require(all(type(engine[k]) is str and bool(engine[k]) for k in ("version", "revision", "image_id", "reference")), "INVALID_ENGINE")
    for key in ("os", "architecture"):
        _require(key not in engine or type(engine[key]) is str, "INVALID_ENGINE")
    _require("docker_version" not in engine or type(engine["docker_version"]) is dict, "INVALID_ENGINE")
    attempts = manifest["attempts"]
    _require(type(attempts) is list and len(attempts) == len(names), "INCOMPLETE_ATTEMPTS")
    required = {"id", "strategy", "state", "outcome", "reason_codes", "argv", "environment", "started_at", "finished_at", "exit_code", "artifacts"}
    known = required | {"container_name", "cleanup_confirmed", "capture"}
    allowed = set()
    for index, attempt in enumerate(attempts):
        _require(type(attempt) is dict and required <= set(attempt) <= known, "INVALID_ATTEMPT")
        _require(attempt["id"] == f"{index:03d}" and attempt["strategy"] == names[index] and attempt["state"] == "FINALIZED" and type(attempt["outcome"]) is str and attempt["outcome"] in contract.OUTCOMES, "INCOMPLETE_ATTEMPTS")
        _require(type(attempt["argv"]) is list and all(type(v) is str for v in attempt["argv"])
                 and type(attempt["environment"]) is dict and type(attempt["artifacts"]) is list
                 and type(attempt["reason_codes"]) is list and bool(attempt["reason_codes"])
                 and all(type(v) is str and bool(v) for v in attempt["reason_codes"]), "INVALID_ATTEMPT")
        _require(attempt["started_at"] is None or type(attempt["started_at"]) is str, "INVALID_ATTEMPT")
        _require(type(attempt["finished_at"]) is str and bool(attempt["finished_at"]), "INVALID_ATTEMPT")
        _require(attempt["exit_code"] is None or type(attempt["exit_code"]) is int, "INVALID_ATTEMPT")
        _require(attempt.get("cleanup_confirmed") is None or type(attempt["cleanup_confirmed"]) is bool, "INVALID_ATTEMPT")
        if "container_name" in attempt:
            _require(attempt["container_name"] == "n170-" + manifest["run_id"] + "-" + attempt["id"], "INVALID_CONTAINER_NAME")
        prefix = f"attempts/{index:03d}/"
        _require(_typed_equal(attempt["artifacts"], [item for item in manifest["artifacts"] if item["path"].startswith(prefix)]), "ATTEMPT_INVENTORY_MISMATCH")
        request_raw = buffers.get(prefix + "input/request.json")
        if request_raw is not None:
            wanted = {key: value for key, value in request.items() if key != "strategies"}
            wanted.update(schema="n170.freqtrade-request.v2", run_id=manifest["run_id"], attempt_id=attempt["id"], strategy=names[index], input_inventory=[dict(item, path=item["path"][len(prefix + "input/"):]) for item in manifest["inputs"] if item["path"].startswith(prefix + "input/") and not item["path"].endswith("/request.json")])
            _require(_typed_equal(strict_json(request_raw), wanted), "INPUT_INVENTORY_MISMATCH")
        allowed.update(prefix + path for path in ("input/request.json", "input/config.json", "input/engine_worker.py", "input/engine_worker_v1.py", "input/accounting_collector.py", "input/data/BTC_USDT-5m.json", "input/strategies/" + names[index] + ".py", "stdout.log", "stderr.log", "output/worker-result.json", "output/effective-config.json", "output/market-metadata.json", "output/lookahead.csv", "output/baseline-capture.json"))
        allowed.update(prefix + "accounting/" + name for name in ("events.json", "ledger.beancount", "oracle-worker.py", "oracle.stdout.json", "oracle.stderr.txt", "report.json"))
        if attempt["outcome"] == "SKIPPED":
            _require(not attempt["argv"] and attempt["started_at"] is None and attempt["exit_code"] is None, "INVALID_SKIPPED_ATTEMPT")
        elif attempt["argv"]:
            _require(attempt["started_at"] is not None, "MISSING_EXECUTION_RECEIPT")
    _require(set(buffers) <= allowed, "UNEXPECTED_ARTIFACT")
    _require(type(manifest["summary"]) is dict and _typed_equal(manifest["summary"], contract.summarize(attempts)), "SUMMARY_MISMATCH")
    for path, data in buffers.items():
        if (path.endswith("/input/engine_worker.py") or path.endswith("/input/engine_worker_v1.py") or path.endswith("/input/accounting_collector.py")) or "/input/strategies/" in path:
            _require(len(data) <= 256 * 1024, "SOURCE_SIZE_LIMIT")
        if path.endswith("/input/data/BTC_USDT-5m.json"):
            _require(len(data) <= 8 * 1024 * 1024, "CANDLE_SIZE_LIMIT")
            candles = strict_json(data)
            _require(type(candles) is list and 100 <= len(candles) <= 10000, "INVALID_CANDLES")
            previous = -1
            for candle in candles:
                _require(type(candle) is list and len(candle) == 6 and all(type(v) in (int, float) and math.isfinite(v) for v in candle), "INVALID_CANDLES")
                timestamp, opened, high, low, closed, volume = candle
                _require(type(timestamp) is int and timestamp > previous and timestamp % 300000 == 0 and min(opened, high, low, closed) > 0 and volume >= 0 and high >= max(opened, closed, low) and low <= min(opened, closed), "INVALID_CANDLES")
                previous = timestamp
        if path.endswith(".json"):
            # Invalid retained output is evidence of a recorded INVALID_OUTPUT,
            # but never accepted as interpretable worker evidence.
            try:
                strict_json(data)
            except (ValueError, UnicodeError, RecursionError, OverflowError):
                index = int(path.split("/")[1])
                _require("/accounting/" in path or "/output/" in path and attempts[index]["outcome"] in {"INVALID_OUTPUT", "FAILED", "TIMED_OUT", "CANCELLED"}, "INVALID_ARTIFACT_JSON")


def _typed_equal(left, right):
    """Unlike Python ==, never equate boolean metadata with numeric counts."""
    return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == json.dumps(right, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _transport(stdout):
    lines = [line[len(BUNDLE_PREFIX):] for line in stdout.splitlines() if line.startswith(BUNDLE_PREFIX)]
    if not lines:
        return None
    _require(len(lines) == 1, "AMBIGUOUS_OUTPUT_TRANSPORT")
    try:
        encoded = lines[0]
        _require(len(encoded) <= 6 * 1024 * 1024, "OUTPUT_TRANSPORT_SIZE_LIMIT")
        raw = base64.b64decode(encoded, validate=True)
        _require(base64.b64encode(raw) == encoded, "NONCANONICAL_BASE64")
        files = strict_json(raw)
        _require(type(files) is dict and "worker-result.json" in files and set(files) <= {"worker-result.json", "lookahead.csv", "effective-config.json", "market-metadata.json", "baseline-capture.json"}, "INVALID_OUTPUT_TRANSPORT")
        decoded = {}
        for path, value in files.items():
            _require(type(value) is str and len(value) <= 4 * ((2 * 1024 * 1024 + 2) // 3), "OUTPUT_TRANSPORT_SIZE_LIMIT")
            data = base64.b64decode(value, validate=True)
            _require(len(data) <= 2 * 1024 * 1024 and base64.b64encode(data).decode() == value, "INVALID_OUTPUT_TRANSPORT")
            decoded[path] = data
        _require(sum(map(len, decoded.values())) <= 3 * 1024 * 1024, "OUTPUT_TRANSPORT_SIZE_LIMIT")
        return decoded
    except (binascii.Error, UnicodeError):
        raise ReviewError("INVALID_OUTPUT_TRANSPORT") from None


def _relationships(manifest, buffers):
    for attempt in manifest["attempts"]:
        prefix = "attempts/" + attempt["id"] + "/"
        output = {path[len(prefix + "output/"):]: data for path, data in buffers.items() if path.startswith(prefix + "output/")}
        stdout = buffers.get(prefix + "stdout.log")
        if stdout is not None:
            try:
                emitted = _transport(stdout)
            except (ValueError, TypeError, RecursionError, OverflowError):
                _require(attempt["outcome"] in {"INVALID_OUTPUT", "FAILED", "TIMED_OUT", "CANCELLED"} and not output, "OUTPUT_TRANSPORT_MISMATCH")
                emitted = None
            # Interrupted runners retain stdout without unpacking outputs.
            if attempt["outcome"] not in {"TIMED_OUT", "CANCELLED"} or output:
                _require((emitted or {}) == output, "OUTPUT_TRANSPORT_MISMATCH")
        else:
            _require(not output, "MISSING_OUTPUT_TRANSPORT")
        raw = output.get("worker-result.json")
        if raw is None:
            continue
        try:
            worker = strict_json(raw)
        except (ValueError, UnicodeError, RecursionError, OverflowError):
            _require(attempt["outcome"] in {"INVALID_OUTPUT", "FAILED", "TIMED_OUT", "CANCELLED"}, "INVALID_WORKER_RECEIPT")
            continue
        _require(type(worker) is dict, "INVALID_WORKER_RECEIPT")
        request_raw = buffers.get(prefix + "input/request.json")
        _require(request_raw is not None, "MISSING_INPUT")
        request = strict_json(request_raw)
        expected = request["input_inventory"]
        # A mismatched input report may be preserved only as the explicit failure.
        for key, wanted in (("schema", contract.WORKER_SCHEMA), ("strategy", attempt["strategy"]), ("request_sha256", contract.digest(request_raw)), ("input_inventory", expected)):
            if key in worker:
                _require(_typed_equal(worker[key], wanted) or attempt["outcome"] == "INPUT_CHANGED" and key == "input_inventory", "WORKER_INPUT_MISMATCH")
            else:
                _require(attempt["outcome"] in {"FAILED", "INVALID_OUTPUT", "TIMED_OUT", "CANCELLED"}, "MISSING_WORKER_METADATA")
        if "engine_arguments" in worker:
            _require(_typed_equal(worker["engine_arguments"], contract.engine_arguments(request)), "ENGINE_ARGUMENTS_MISMATCH")
        if "environment" in worker and "observed" in attempt["environment"]:
            _require(_typed_equal(worker["environment"], attempt["environment"]["observed"]), "ENVIRONMENT_MISMATCH")
        engine = worker.get("engine")
        if engine is not None:
            _require(type(engine) is dict, "INVALID_WORKER_ENGINE")
            _require(engine.get("version") == "2026.8" and engine.get("revision") == contract.UPSTREAM_REVISION and engine.get("source_sha256") == contract.ENGINE_SOURCE_SHA256, "WORKER_ENGINE_MISMATCH")
            source_files = engine.get("source_files")
            _require(type(source_files) is list and len(source_files) == 332 and contract.digest(json.dumps(source_files, sort_keys=True, separators=(",", ":")).encode()) == contract.ENGINE_SOURCE_SHA256, "WORKER_ENGINE_SOURCE_MISMATCH")
            _require("source_after_sha256" not in engine or engine["source_after_sha256"] == contract.ENGINE_SOURCE_SHA256, "WORKER_ENGINE_SOURCE_MISMATCH")
        for filename, declared in (("effective-config.json", worker.get("effective_config_sha256")), ("market-metadata.json", worker.get("offline_adapter", {}).get("market_metadata_sha256") if type(worker.get("offline_adapter", {})) is dict else None)):
            if filename in output or declared is not None:
                _require(filename in output and declared == contract.digest(output[filename]), "OUTPUT_DIGEST_MISMATCH")
        captured, capture_claim = output.get("baseline-capture.json"), worker.get("capture")
        if captured is not None or capture_claim is not None:
            _require(type(capture_claim) is dict and set(capture_claim) == {"schema", "path", "size", "sha256", "status", "reason_codes"}, "INVALID_CAPTURE_DESCRIPTOR")
            _require(captured is not None and capture_claim["schema"] == "n170.freqtrade-baseline-capture.v1"
                     and capture_claim["path"] == "baseline-capture.json" and type(capture_claim["size"]) is int
                     and capture_claim["size"] == len(captured) and capture_claim["sha256"] == contract.digest(captured), "CAPTURE_DIGEST_MISMATCH")
            native_capture = strict_json(captured)
            _require(native_capture.get("schema") == capture_claim["schema"] and type(native_capture.get("capture")) is dict
                     and native_capture["capture"].get("status") == capture_claim["status"]
                     and native_capture["capture"].get("reason_codes") == capture_claim["reason_codes"], "CAPTURE_STATE_MISMATCH")
        analysis = worker.get("analysis")
        if analysis is not None:
            _require(type(analysis) is dict, "INVALID_WORKER_ANALYSIS")
            for key in ("has_bias", "failed_bias_check"):
                _require(key not in analysis or type(analysis[key]) is bool, "INVALID_WORKER_ANALYSIS")
            for key in ("total_signals", "biased_entry_signals", "biased_exit_signals", "baseline_trade_count", "forced_exit_count", "minimum_trade_amount", "targeted_trade_amount"):
                _require(key not in analysis or type(analysis[key]) is int and analysis[key] >= 0, "INVALID_WORKER_ANALYSIS")
        if attempt["outcome"] == "FAILED":
            _require(attempt["exit_code"] != 0 or worker.get("outcome") == "FAILED", "OUTCOME_MISMATCH")


def _reproducibility(manifest, buffers):
    missing = []
    for attempt in manifest["attempts"]:
        prefix = "attempts/" + attempt["id"] + "/input/"
        for filename in ("request.json", "config.json", "engine_worker.py", "engine_worker_v1.py", "accounting_collector.py", "data/BTC_USDT-5m.json", "strategies/" + attempt["strategy"] + ".py"):
            if prefix + filename not in buffers:
                missing.append(prefix + filename)
    if manifest["engine"]["image_id"] == "sha256:" + "0" * 64:
        missing.append("pinned_engine_image_identity")
    return {"status": "NOT_REPRODUCIBLE" if missing else "READY_TO_RERUN", "missing": missing}


def _accounting(manifest, buffers):
    from .accounting_adapter import assess_capture
    results = []
    for attempt in manifest["attempts"]:
        prefix = f"attempts/{attempt['id']}/"
        raw = buffers.get(prefix + "output/baseline-capture.json")
        request_raw = buffers.get(prefix + "input/request.json")
        worker_raw = buffers.get(prefix + "output/worker-result.json")
        context = None
        if request_raw is not None and worker_raw is not None:
            try:
                request, worker = strict_json(request_raw), strict_json(worker_raw)
                context = {"run_id": manifest["run_id"], "attempt_id": attempt["id"], "strategy": attempt["strategy"],
                           "request": request, "request_sha256": contract.digest(request_raw),
                           "input_inventory": request["input_inventory"], "engine": manifest["engine"], "worker": worker,
                           "effective_config": strict_json(buffers[prefix + "output/effective-config.json"]),
                           "input_buffers": {path[len(prefix + 'input/'):]: data for path, data in buffers.items() if path.startswith(prefix + 'input/')}}
            except (ValueError, KeyError, TypeError):
                context = None
        assessed = assess_capture(raw, context)
        if attempt["outcome"] in {"TIMED_OUT", "CANCELLED", "FAILED", "SKIPPED", "MISSING_OUTPUT", "INVALID_OUTPUT", "INPUT_CHANGED"}:
            assessed.update(events=None, exact_model=None, native_compatibility=None)
            assessed["capture"] = {"status": "UNSUPPORTED" if raw is not None else "MISSING", "reason_codes": ["RUN_ATTEMPT_NOT_COMPLETED"]}
            assessed["native_metrics"] = {name: {"status": "NOT_SUPPLIED", "reason_codes": ["RUN_ATTEMPT_NOT_COMPLETED"]} for name in assessed["native_metrics"]}
            assessed["reason_codes"] = ["RUN_ATTEMPT_NOT_COMPLETED"]
        assessed["oracle"] = _oracle_evidence(prefix, buffers, assessed)
        if assessed["oracle"]["status"] != "NOT_RUN":
            assessed["reason_codes"] = [code for code in assessed["reason_codes"] if code != "ORACLE_NOT_RUN"] + ["ORACLE_" + assessed["oracle"]["status"]]
        results.append(dict(assessed, id=attempt["id"], detector_outcome=attempt["outcome"]))
    return {"schema": "n170.accounting.run-assessment.v1", "status": "NOT_ASSESSABLE", "attempts": results,
            "reason_codes": ["INDEPENDENT_ACCOUNTING_DIMENSIONS_NO_AGGREGATE_FINANCIAL_PASS"]}


def _oracle_evidence(prefix, buffers, assessed):
    """Check a supplied external receipt against freshly derived model inputs.

    This does not execute Beancount or authenticate that the supplied run occurred.
    """
    names = ("events.json", "ledger.beancount", "oracle-worker.py", "oracle.stdout.json", "oracle.stderr.txt", "report.json")
    files = {name: buffers[prefix + "accounting/" + name] for name in names if prefix + "accounting/" + name in buffers}
    result = {"status": "NOT_RUN", "reason_codes": [], "execution": "supplied local receipt; not witnessed or authenticated by recipient"}
    if not files:
        return result
    if len(files) != len(names):
        return dict(result, status="MISSING", reason_codes=["INCOMPLETE_ORACLE_EVIDENCE"])
    if assessed["capture"]["status"] != "SUPPORTED" or assessed["events"] is None:
        return dict(result, status="UNAVAILABLE", reason_codes=["SUPPORTED_CAPTURE_REQUIRED"])
    try:
        from verify_accounting.core import canonical
        from verify_accounting.oracle_v2 import generate_ledger, _validate_observation, INSTALLED_INVENTORY_SHA256, BEANCOUNT_REVISION
        events = canonical(assessed["events"])
        ledger = generate_ledger(assessed["events"])
        _require(files["events.json"] == events, "ORACLE_EVENT_BINDING_MISMATCH")
        _require(files["ledger.beancount"] == ledger, "ORACLE_LEDGER_BINDING_MISMATCH")
        known_worker = contract.read_file(Path(__file__).parent.parent / "verify_accounting" / "_oracle_worker.py")
        _require(files["oracle-worker.py"] == known_worker, "ORACLE_WORKER_MISMATCH")
        supplied = strict_json(files["report.json"])
        receipt = supplied["oracle"]
        _require(type(receipt) is dict and receipt.get("engine") == "beancount" and receipt.get("expected_revision") == BEANCOUNT_REVISION
                 and receipt.get("expected_installed_inventory_sha256") == INSTALLED_INVENTORY_SHA256, "ORACLE_IDENTITY_MISMATCH")
        for field, name in (("input_sha256", "events.json"), ("ledger_sha256", "ledger.beancount"), ("worker_sha256", "oracle-worker.py")):
            _require(receipt.get(field) == contract.digest(files[name]), "ORACLE_ARTIFACT_BINDING_MISMATCH")
        truncated = False
        for name in ("oracle.stdout.json", "oracle.stderr.txt"):
            claim = receipt.get(name)
            _require(type(claim) is dict and set(claim) == {"observed_bytes", "sha256", "retained_bytes", "truncated"}
                     and type(claim["observed_bytes"]) is int and type(claim["retained_bytes"]) is int
                     and type(claim["truncated"]) is bool and type(claim["sha256"]) is str and HEX.fullmatch(claim["sha256"])
                     and claim["retained_bytes"] == len(files[name]) <= 2 * 1024 * 1024, "ORACLE_OUTPUT_BINDING_MISMATCH")
            if claim["truncated"]:
                _require(claim["observed_bytes"] > claim["retained_bytes"], "ORACLE_OUTPUT_BINDING_MISMATCH")
                truncated = True
            else:
                _require(claim["observed_bytes"] == claim["retained_bytes"] and claim["sha256"] == contract.digest(files[name]), "ORACLE_OUTPUT_BINDING_MISMATCH")
        _require(supplied.get("schema") == "n170.accounting.reconciliation.v2"
                 and supplied.get("computed") == assessed["exact_model"]["computed"], "ORACLE_MODEL_BINDING_MISMATCH")
        result["artifacts"] = [contract.inventory_entry(prefix + "accounting/" + name, files[name]) for name in names]
        if truncated or receipt.get("status") == "UNAVAILABLE":
            _require(receipt.get("status") == "UNAVAILABLE", "ORACLE_STATUS_MISMATCH")
            return dict(result, status="UNAVAILABLE", reason_codes=["SUPPLIED_ORACLE_DID_NOT_COMPLETE"], reported_reasons=receipt.get("reason_codes", []))
        observed = strict_json(files["oracle.stdout.json"])
        _require(_typed_equal(receipt.get("observation"), observed), "ORACLE_STDOUT_MISMATCH")
        _validate_observation(observed)
        differences = [key for key, value in assessed["exact_model"]["computed"].items() if observed["computed"].get(key) != value]
        _require(type(receipt.get("exit_code")) is int and receipt["exit_code"] in (0, 1), "ORACLE_EXIT_FAILURE")
        disagree = bool(differences or observed["validation_error_count"] or receipt["exit_code"])
        _require(receipt.get("status") == ("DISCREPANCIES_FOUND" if disagree else "MATCHED")
                 and receipt.get("different_metrics") == differences, "ORACLE_STATUS_MISMATCH")
        return dict(result, status="SUPPLIED_DISCREPANCIES" if disagree else "SUPPLIED_MATCHED",
                    reason_codes=["SUPPLIED_ORACLE_EVIDENCE_CHECKED_AGAINST_EXACT_MODEL"], different_metrics=differences,
                    validation_error_count=observed["validation_error_count"], inventory_sha256=observed["installed_code_inventory_sha256"])
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, OverflowError) as error:
        return dict(result, status="INVALID", reason_codes=[str(error) if isinstance(error, ReviewError) else "INVALID_ORACLE_EVIDENCE"])


def _inspect(raw, manifest_sha256=None):
    report = {"schema": "n170.run-review-verification.v2", "integrity": "INVALID", "status": "NOT_ASSESSABLE", "manifest_sha256": None, "manifest_pin": "not_supplied" if manifest_sha256 is None else "mismatched_or_invalid", "summary": None, "attempts": [], "reproducibility": {"status": "NOT_REPRODUCIBLE", "missing": ["valid_complete_package"]}, "trust": dict(TRUST), "reason_codes": []}
    manifest, buffers = None, None
    try:
        manifest_raw, manifest, buffers = _decode(raw)
        report["manifest_sha256"] = contract.digest(manifest_raw)
        if manifest_sha256 is not None:
            _require(type(manifest_sha256) is str and HEX.fullmatch(manifest_sha256) and manifest_sha256 == report["manifest_sha256"], "MANIFEST_PIN_MISMATCH")
            report["manifest_pin"] = "matched"
        _structural(manifest, buffers)
        _relationships(manifest, buffers)
        local = contract.verify_run_bytes(manifest_raw, buffers, manifest_sha256)
        _require(local["reason_codes"] != ["INVALID_OR_INCOMPLETE_RUN_BUNDLE"], "INVALID_OR_INCOMPLETE_RUN_BUNDLE")
        report.update(integrity="VALID", status=local["status"], summary=local["summary"], reason_codes=["PACKAGE_BYTES_AND_RECEIPT_CONSISTENT"] + (["UNASSESSABLE_ATTEMPTS"] if local["status"] == "NOT_ASSESSABLE" else []), attempts=[{key: attempt[key] for key in ("id", "strategy", "state", "outcome", "reason_codes", "exit_code")} for attempt in manifest["attempts"]], reproducibility=_reproducibility(manifest, buffers))
        if report["reproducibility"]["missing"]:
            report["reason_codes"].append("MISSING_REPRODUCTION_PREREQUISITES")
        report["accounting"] = _accounting(manifest, buffers)
        report["artifacts"] = manifest["artifacts"]
        return report, manifest, buffers
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, OverflowError) as error:
        report["reason_codes"] = [str(error) if type(error) is ReviewError else "INVALID_OR_INCOMPLETE_PACKAGE"]
        if type(manifest) is dict and type(buffers) is dict and type(manifest.get("artifacts")) is list:
            missing = []
            for item in manifest["artifacts"][:MAX_ARTIFACTS]:
                try:
                    path = _path(item["path"])
                    if path not in buffers:
                        missing.append(path)
                except (ValueError, TypeError, KeyError):
                    continue
            report["reproducibility"]["missing"] = [*missing, "valid_complete_package"]
        return report, None, None


def verify_run_review(raw, manifest_sha256=None):
    """Verify bytes and relationships; never assert authentic or witnessed execution."""
    return _inspect(raw, manifest_sha256)[0]


def export_run_review(directory):
    """Read a bounded directory once and return an intact data-only package."""
    root = Path(directory)
    def descriptor(path, raw):
        return dict(contract.inventory_entry(path, raw), base64=base64.b64encode(raw).decode("ascii"))
    def bounded_read(path, limit):
        try:
            return contract.read_file(path, limit)
        except ValueError as error:
            if str(error) == "File limit exceeded":
                raise ReviewError("EXPORT_FILE_SIZE_LIMIT") from None
            raise
    manifest_raw = bounded_read(root / "manifest.json", MAX_MANIFEST)
    artifacts, total = [], len(manifest_raw)
    files = contract._files(root)
    _paths(files)
    for path in files:
        if path == "manifest.json":
            continue
        raw = bounded_read(root / _path(path), MAX_FILE)
        total += len(raw)
        _require(total <= MAX_TOTAL, "TOTAL_DECODED_SIZE_LIMIT")
        artifacts.append(descriptor(path, raw))
    package = {"schema": SCHEMA, "manifest": descriptor("manifest.json", manifest_raw), "artifacts": artifacts}
    report = verify_run_review(contract.json_bytes(package))
    _require(report["integrity"] == "VALID", "EXPORT_REQUIRES_CONSISTENT_RUN")
    return package


def _semantic(manifest, buffers):
    value = copy.deepcopy(manifest)
    for key in ("run_id", "execution_root", "started_at", "finished_at", "artifacts", "inputs"):
        del value[key]
    for attempt in value["attempts"]:
        for key in ("started_at", "finished_at", "container_name", "artifacts"):
            attempt.pop(key, None)
        if attempt["argv"]:
            # These positions are already checked against the original runner argv.
            argv = attempt["argv"]
            argv[0] = "<host-docker-executable>"
            argv[argv.index("--name") + 1] = "<run-container-name>"
            argv[argv.index("--mount") + 1] = "type=bind,src=<captured-input>,dst=/input,readonly"
    artifacts = {}
    for path, data in buffers.items():
        if path.endswith("/stdout.log"):
            # The validated data transport is already bound by each output file.
            # All other bytes, including diagnostic timestamps, remain significant.
            data = b"".join(line for line in data.splitlines(keepends=True) if not line.startswith(BUNDLE_PREFIX))
        if path.endswith(("/stdout.log", "/stderr.log")):
            data = LOG_TIMESTAMP.sub(b"<incidental-log-time>", data)
        artifacts[path] = contract.digest(data)
    return {"receipt": value, "artifacts": artifacts}


def compare_run_reviews(left_raw, right_raw):
    """Conservative semantic comparison, not proof that either execution occurred."""
    left, lm, lb = _inspect(left_raw)
    right, rm, rb = _inspect(right_raw)
    report = {"schema": "n170.run-review-comparison.v2", "status": "NOT_COMPARABLE", "left": left, "right": right, "differences": [], "evidence_differences": [], "ignored_incidental_fields": ["manifest.run_id", "manifest.execution_root", "manifest.started_at", "manifest.finished_at", "attempt.started_at", "attempt.finished_at", "attempt.container_name", "validated argv host executable/mount/container name", "validated stdout result transport encoding", "anchored known Freqtrade logger timestamp prefix"], "outcome_status": None, "reproduction": "not established; comparison examines supplied evidence only", "trust": dict(TRUST), "reason_codes": []}
    if left["integrity"] != "VALID" or right["integrity"] != "VALID":
        report["reason_codes"] = ["INVALID_PACKAGE"]
        return report
    if left["reproducibility"]["status"] != "READY_TO_RERUN" or right["reproducibility"]["status"] != "READY_TO_RERUN":
        report["reason_codes"] = ["MISSING_REPRODUCTION_PREREQUISITES"]
        return report
    ls, rs = _semantic(lm, lb), _semantic(rm, rb)
    for key in sorted(set(ls["receipt"]) | set(rs["receipt"])):
        if not _typed_equal(ls["receipt"].get(key), rs["receipt"].get(key)):
            report["differences"].append("receipt." + key)
    for path in sorted(set(ls["artifacts"]) | set(rs["artifacts"])):
        if ls["artifacts"].get(path) != rs["artifacts"].get(path):
            report["differences"].append("artifact:" + path)
    if left["manifest_sha256"] != right["manifest_sha256"]:
        report["evidence_differences"].append("manifest.json")
    for path in sorted(set(lb) | set(rb)):
        if lb.get(path) != rb.get(path):
            report["evidence_differences"].append(path)
    report["outcome_status"] = {"left": left["status"], "right": right["status"]}
    report["status"] = "DIFFERENT" if report["differences"] else "SAME"
    report["reason_codes"] = ["SEMANTIC_DIFFERENCES" if report["differences"] else "SUPPLIED_SEMANTICS_MATCH"]
    return report
