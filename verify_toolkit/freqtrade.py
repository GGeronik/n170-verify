"""Read supplied Freqtrade CSV observations; never execute or authenticate a run.

Original interoperability code. No Freqtrade implementation is imported or copied.
The supported upstream format and its important omissions are in FREQTRADE.md.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re


SCHEMA = "n170.tool-evidence.freqtrade-lookahead.v1"
UPSTREAM_REVISION = "9f10e357a93c1dcf10c2a2b367659214d89c073e"
MAX_CSV_BYTES = 1_048_576
MAX_ROWS = 1_000
MAX_COUNT = 1_000_000_000
MAX_INDICATORS = 128
HEADERS = (
    "filename", "strategy", "has_bias", "total_signals",
    "biased_entry_signals", "biased_exit_signals", "biased_indicators",
)
_COUNTS = HEADERS[3:6]
_LIMITATIONS = (
    "This is supplied tool output. N170 did not execute Freqtrade or authenticate its source.",
    "No findings reported describes these CSV rows only; it does not establish absence of lookahead bias.",
    "Untested signals, omitted strategies and earlier trials are not evidenced by this export.",
    "Freqtrade exports can omit unsuccessful analyses and retain rows from earlier runs; run completeness and freshness are not established.",
    "Reported indicators can include FreqAI targets, and order assumptions can cause false positives; findings require review.",
    "This report does not assess data authenticity, point-in-time validity, statistical robustness, execution realism or investment performance.",
    "Filenames, strategy names and indicator names are retained locally; review them before sharing this report.",
)


class _Rejected(ValueError):
    """A fixed reason code, never an echo of supplied evidence."""


def _reject(code):
    raise _Rejected(code)


def _count(value, *, positive=False):
    if type(value) is not str or not re.fullmatch(r"0|[1-9][0-9]{0,9}", value):
        _reject("INVALID_COUNT")
    number = int(value)
    if number > MAX_COUNT or (positive and number == 0):
        _reject("NO_TESTED_SIGNALS" if number == 0 else "COUNT_LIMIT_EXCEEDED")
    return number


def _context(raw):
    """Keep only a small data-only declaration schema; reject arbitrary config."""
    if raw is None:
        return {}
    allowed = {
        "freqtrade_version", "run_status", "config_sha256", "strategy_sha256",
        "data_sha256", "expected_strategy_count", "run_config",
    }
    if type(raw) is not dict or len(raw) > len(allowed) or not set(raw) <= allowed:
        _reject("UNSUPPORTED_CONTEXT")
    out = {}
    for key, value in raw.items():
        if key.endswith("_sha256"):
            if type(value) is not str or not re.fullmatch(r"[a-fA-F0-9]{64}", value):
                _reject("INVALID_CONTEXT")
            out[key] = value.lower()
        elif key == "freqtrade_version":
            if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}", value):
                _reject("INVALID_CONTEXT")
            out[key] = value
        elif key == "run_status":
            if type(value) is not str or len(value) > 16 or value.upper() not in {
                "COMPLETED", "FAILED", "SKIPPED", "NOT_RUN", "CANCELLED",
            }:
                _reject("INVALID_CONTEXT")
            out[key] = value.upper()
        elif key == "expected_strategy_count":
            if type(value) is not int or not 1 <= value <= MAX_ROWS:
                _reject("INVALID_CONTEXT")
            out[key] = value
        else:
            config_keys = {
                "timerange", "timeframe", "minimum_trade_amount",
                "targeted_trade_amount", "lookahead_allow_limit_orders",
            }
            if type(value) is not dict or len(value) > len(config_keys) or not set(value) <= config_keys:
                _reject("UNSUPPORTED_RUN_CONFIG")
            config = {}
            for setting, supplied in value.items():
                if setting in {"minimum_trade_amount", "targeted_trade_amount"}:
                    if type(supplied) is not int or not 1 <= supplied <= MAX_COUNT:
                        _reject("INVALID_RUN_CONFIG")
                elif setting == "lookahead_allow_limit_orders":
                    if type(supplied) is not bool:
                        _reject("INVALID_RUN_CONFIG")
                elif setting == "timeframe":
                    if type(supplied) is not str or not re.fullmatch(r"[1-9][0-9]{0,5}[smhdwM]", supplied):
                        _reject("INVALID_RUN_CONFIG")
                elif type(supplied) is not str or not re.fullmatch(r"[0-9T:-]{1,64}", supplied):
                    _reject("INVALID_RUN_CONFIG")
                config[setting] = supplied
            minimum, targeted = config.get("minimum_trade_amount"), config.get("targeted_trade_amount")
            if minimum is not None and targeted is not None and minimum > targeted:
                _reject("CONTRADICTORY_RUN_CONFIG")
            out[key] = config
    return out


def _row(raw, position, declared):
    filename, strategy = raw["filename"], raw["strategy"]
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_. -]{0,127}", filename):
        _reject("INVALID_FILENAME")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", strategy):
        _reject("INVALID_STRATEGY")
    bias = raw["has_bias"].lower()
    if bias not in {"true", "false", "yes", "no"}:
        _reject("UNRECOGNIZED_OR_UNSUCCESSFUL_RESULT")
    has_bias = bias in {"true", "yes"}
    counts = {key: _count(raw[key], positive=key == "total_signals") for key in _COUNTS}
    total = counts["total_signals"]
    if any(counts[key] > total for key in _COUNTS[1:]):
        _reject("CONTRADICTORY_COUNTS")
    cell = raw["biased_indicators"]
    if len(cell) > 8_192:
        _reject("INDICATOR_LIMIT_EXCEEDED")
    indicators = [part.strip() for part in cell.split(",")] if cell else []
    if len(indicators) > MAX_INDICATORS:
        _reject("INDICATOR_LIMIT_EXCEEDED")
    if any(not re.fullmatch(r"[A-Za-z0-9_&%][A-Za-z0-9_.:&% +/()=-]{0,127}", item) for item in indicators):
        _reject("INVALID_INDICATORS")
    if len(set(indicators)) != len(indicators):
        _reject("DUPLICATE_INDICATORS")
    evidence_of_findings = bool(indicators or counts["biased_entry_signals"] or counts["biased_exit_signals"])
    if has_bias != evidence_of_findings:
        _reject("CONTRADICTORY_BIAS_RESULT")
    minimum = declared.get("run_config", {}).get("minimum_trade_amount")
    # The supported exporter admits only totals strictly above its minimum.
    if minimum is not None and total <= minimum:
        _reject("BELOW_DECLARED_EXPORT_MINIMUM")
    targeted = declared.get("run_config", {}).get("targeted_trade_amount")
    if targeted is not None and total > targeted:
        _reject("EXCEEDS_DECLARED_TARGET")
    return {
        "row_number": position, "filename": filename, "strategy": strategy,
        "has_bias": has_bias, **counts, "biased_indicators": indicators,
        "status": "FINDINGS_REPORTED" if has_bias else "NO_FINDINGS_REPORTED",
        "reason_codes": ["UPSTREAM_FINDINGS_REPORTED" if has_bias else "NO_FINDINGS_IN_SUPPLIED_ROW"],
    }


def assess_lookahead(csv_text: str, *, context: dict | None = None) -> dict:
    """Assess the shape and declared result of a bounded, supplied CSV string.

    Invalid, empty, inconsistent or unsupported evidence returns NOT_ASSESSABLE.
    No path, command, strategy module, URL or broker connection is ever opened.
    Context is an unverified declaration, not a receipt of an observed execution.
    """
    report = {
        "schema": SCHEMA, "tool": "freqtrade", "evidence_class": "supplied_tool_output",
        "status": "NOT_ASSESSABLE", "tested_strategy_count": 0, "rows": [],
        "reason_codes": [], "limitations": list(_LIMITATIONS),
        "scope": {
            "analysis": "lookahead-analysis", "source_sha256": None,
            "adapter_format_reference": {"version": "2026.8", "revision": UPSTREAM_REVISION},
            "tool_execution": "not_performed", "source_authenticity": "unverified",
            "run_completeness": "not_established", "run_freshness": "not_established",
            "context_authenticity": "unverified", "declared_context": {},
            "tested_strategy_count_basis": "valid supplied rows with positive signal counts; not independently observed tests",
        },
    }
    reasons = report["reason_codes"]
    try:
        declared = _context(context)
        report["scope"]["declared_context"] = declared
    except _Rejected as exc:
        declared = {}
        reasons.append(str(exc))
    try:
        if type(csv_text) is not str:
            _reject("INVALID_CSV_TYPE")
        # Bound before allocating encoded bytes, then enforce the byte budget.
        if len(csv_text) > MAX_CSV_BYTES:
            _reject("CSV_LIMIT_EXCEEDED")
        encoded = csv_text.encode("utf-8", errors="strict")
        if len(encoded) > MAX_CSV_BYTES:
            _reject("CSV_LIMIT_EXCEEDED")
        report["scope"]["source_sha256"] = hashlib.sha256(encoded).hexdigest()
        if any((ord(char) < 32 and char not in "\r\n") or ord(char) == 127 for char in csv_text):
            _reject("INVALID_CSV_CONTROL")
        reader = csv.reader(io.StringIO(csv_text.removeprefix("\ufeff"), newline=""), strict=True)
        headers = next(reader, None)
        if headers is None:
            _reject("EMPTY_EXPORT")
        headers = [cell.strip() for cell in headers]
        leading_index = headers[0] in {"", "Unnamed: 0"} if headers else False
        names = headers[1:] if leading_index else headers
        if len(set(names)) != len(names):
            _reject("DUPLICATE_COLUMNS")
        if len(names) != len(HEADERS) or set(names) != set(HEADERS):
            _reject("UNSUPPORTED_COLUMNS")
        identities, indices = set(), set()
        for position, values in enumerate(reader, start=1):
            if position > MAX_ROWS:
                _reject("ROW_LIMIT_EXCEEDED")
            try:
                if len(values) != len(headers):
                    _reject("MALFORMED_ROW")
                if any(len(value) > 8_192 for value in values):
                    _reject("FIELD_LIMIT_EXCEEDED")
                if leading_index:
                    index = _count(values[0])
                    if index in indices:
                        _reject("DUPLICATE_INDEX")
                    indices.add(index)
                    values = values[1:]
                row = _row(dict(zip(names, (value.strip() for value in values))), position, declared)
                identity = (row["filename"], row["strategy"])
                if identity in identities:
                    _reject("DUPLICATE_STRATEGY")
                identities.add(identity)
                report["rows"].append(row)
                report["tested_strategy_count"] += 1
            except _Rejected as exc:
                code = str(exc)
                reasons.append(code)
                report["rows"].append({"row_number": position, "status": "NOT_ASSESSABLE", "reason_codes": [code]})
        if not report["rows"]:
            _reject("EMPTY_EXPORT")
    except _Rejected as exc:
        reasons.append(str(exc))
    except (csv.Error, UnicodeError):
        reasons.append("MALFORMED_CSV")
    if declared.get("run_status") not in {None, "COMPLETED"}:
        reasons.append("DECLARED_RUN_NOT_COMPLETED")
    expected = declared.get("expected_strategy_count")
    if expected is not None and expected != report["tested_strategy_count"]:
        reasons.append("DECLARED_STRATEGY_COUNT_MISMATCH")
    if not reasons:
        found = any(row["has_bias"] for row in report["rows"])
        report["status"] = "FINDINGS_REPORTED" if found else "NO_FINDINGS_REPORTED"
        reasons.append("UPSTREAM_FINDINGS_REPORTED" if found else "NO_FINDINGS_IN_SUPPLIED_ROWS")
    report["reason_codes"] = list(dict.fromkeys(reasons))
    return report
