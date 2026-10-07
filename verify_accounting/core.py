"""Exact-decimal FIFO accounting, not source authentication or fill validation."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from decimal import Decimal, localcontext
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SCHEMA = "n170.accounting.events.v1"
REPORT_SCHEMA = "n170.accounting.reconciliation.v1"
MAX_BYTES = 2 * 1024 * 1024
MAX_EVENTS = 10_000
METRICS = ("cash", "quantity", "cost_basis", "fees", "realized_pnl", "unrealized_pnl", "external_flows", "net_pnl", "nav")
LIMITATIONS = [
    "Reconciliation checks supplied events and reported balances; source authenticity is not established.",
    "Completeness is unknown beyond the selected source. Balanced books cannot expose every omitted or fabricated event.",
    "Single asset, one cash currency, FIFO cost basis, immediate spot settlement, quote-currency fees expensed immediately; opening positions must be zero.",
    "Prices and closing marks are supplied, not authenticated or assessed for fill feasibility, liquidity or historical availability.",
    "No returns, investment skill, statistical validity, broker ownership or actual trading claim is made.",
    "No borrowing, shorting, FX, dividends, interest, taxes, splits, transfers of assets, delayed settlement or fees in other currencies are supported.",
]


class AccountingError(ValueError):
    """Fixed public reason code; supplied values are never exception text."""


def reject(code):
    raise AccountingError(code)


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def number(value, *, nonnegative=False, positive=False, reported=False):
    pattern = r"-?(?:0|[1-9][0-9]{0,30})(?:\.[0-9]{1,16})?" if reported else r"-?(?:0|[1-9][0-9]{0,12})(?:\.[0-9]{1,8})?"
    if type(value) is not str or not re.fullmatch(pattern, value):
        reject("INVALID_DECIMAL")
    amount = Decimal(value)
    if amount.copy_abs() > Decimal("1e30" if reported else "1e12"):
        reject("AMOUNT_LIMIT_EXCEEDED")
    if (nonnegative and amount < 0) or (positive and amount <= 0):
        reject("INVALID_AMOUNT_SIGN")
    return amount


def text_decimal(value):
    if not value:
        return "0"
    text = format(value, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def timestamp(value):
    if type(value) is not str or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})", value):
        reject("INVALID_TIMESTAMP")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        if not 2000 <= parsed.year <= 2100:
            reject("TIMESTAMP_OUT_OF_SCOPE")
        return parsed
    except (ValueError, OverflowError):
        reject("INVALID_TIMESTAMP")


def keys(value, required, optional=()):
    if type(value) is not dict:
        reject("INVALID_OBJECT")
    actual = set(value)
    if not set(required) <= actual:
        reject("MISSING_REQUIRED_FIELD")
    if actual - set(required) - set(optional):
        reject("UNSUPPORTED_FIELD")


def validate_document(document):
    keys(document, ("schema", "evidence_class", "asset", "cash_currency", "opening", "events", "closing"))
    if document["schema"] != SCHEMA:
        reject("UNSUPPORTED_SCHEMA")
    if document["evidence_class"] not in ("synthetic_fixture", "supplied_events"):
        reject("UNSUPPORTED_EVIDENCE_CLASS")
    for field in ("asset", "cash_currency"):
        if type(document[field]) is not str or not re.fullmatch(r"[A-Z][A-Z0-9]{1,11}", document[field]):
            reject("INVALID_COMMODITY")
    if document["asset"] == document["cash_currency"]:
        reject("IDENTICAL_ASSET_AND_CASH")
    opening, closing = document["opening"], document["closing"]
    keys(opening, ("timestamp", "cash"))
    keys(closing, ("timestamp", "mark_price", "reported"))
    start, end = timestamp(opening["timestamp"]), timestamp(closing["timestamp"])
    if end <= start:
        reject("INVALID_PERIOD")
    number(opening["cash"], nonnegative=True)
    number(closing["mark_price"], nonnegative=True)
    keys(closing["reported"], (), METRICS)
    for amount in closing["reported"].values():
        number(amount, reported=True)
    events = document["events"]
    if type(events) is not list or len(events) > MAX_EVENTS:
        reject("INVALID_EVENT_COUNT")
    known, last = set(), start
    for event in events:
        keys(event, ("event_id", "timestamp", "type"), ("quantity", "price", "fee", "fee_currency", "amount"))
        event_id = event["event_id"]
        if type(event_id) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", event_id):
            reject("INVALID_EVENT_ID")
        if event_id in known:
            reject("DUPLICATE_EVENT")
        known.add(event_id)
        instant = timestamp(event["timestamp"])
        if instant < last or instant > end:
            reject("EVENT_CHRONOLOGY_MISMATCH")
        last = instant
        kind = event["type"]
        if kind in ("BUY", "SELL"):
            keys(event, ("event_id", "timestamp", "type", "quantity", "price", "fee", "fee_currency"))
            for field in ("quantity", "price"):
                number(event[field], positive=True)
            number(event["fee"], nonnegative=True)
            if event["fee_currency"] != document["cash_currency"]:
                reject("UNSUPPORTED_FEE_CURRENCY")
        elif kind in ("DEPOSIT", "WITHDRAWAL"):
            keys(event, ("event_id", "timestamp", "type", "amount"))
            number(event["amount"], positive=True)
        else:
            reject("UNSUPPORTED_EVENT")
    return document


def _parent_descriptor(path):
    """Open an absolute parent through descriptors; reject all symlink parents."""
    absolute = Path(os.path.abspath(path))
    directory = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in absolute.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        return directory, absolute.name
    except BaseException:
        os.close(directory)
        raise


def create_private_directory(path):
    directory, name = _parent_descriptor(path)
    try:
        os.mkdir(name, mode=0o700, dir_fd=directory)
    finally:
        os.close(directory)


def write_new_file(path, raw):
    """Exclusive private output through non-following parent descriptors."""
    directory, name = _parent_descriptor(path)
    try:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
    finally:
        os.close(directory)


def read_bytes(path):
    """Read one bounded regular file through non-following path descriptors."""
    directory, name = _parent_descriptor(path)
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                reject("REGULAR_FILE_REQUIRED")
            raw = handle.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                reject("INPUT_LIMIT_EXCEEDED")
            return raw
    finally:
        os.close(directory)


def parse_bytes(raw):
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        reject("INVALID_OR_OVERSIZED_INPUT")
    def pairs(items):
        out = {}
        for name, value in items:
            if name in out:
                reject("DUPLICATE_JSON_FIELD")
            out[name] = value
        return out
    def invalid(_):
        reject("NONFINITE_JSON")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid)
    except AccountingError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        reject("INVALID_JSON")


def _base():
    return {
        "schema": REPORT_SCHEMA, "status": "NOT_ASSESSABLE", "reason_codes": [],
        "evidence_class": "unassessed", "source_inventory": [], "event_inventory": [],
        "checks": {}, "computed": None, "event_checkpoints": [],
        "source_authenticity": "not_established", "selected_source_completeness": "unknown",
        "oracle": {"status": "NOT_RUN"}, "limitations": list(LIMITATIONS),
        "scope": None,
    }


def _assess(document, result):
    validate_document(document)
    result["evidence_class"] = document["evidence_class"]
    result["scope"] = {
        "asset": document["asset"], "cash_currency": document["cash_currency"],
        "opening_timestamp": document["opening"]["timestamp"], "closing_timestamp": document["closing"]["timestamp"],
        "selected_event_count": len(document["events"]), "opening_positions": "zero_required",
        "cost_basis_policy": "FIFO_in_supplied_chronological_order", "fee_policy": "quote_currency_expensed_immediately",
        "settlement_policy": "immediate_spot", "mark_policy": "supplied_nonnegative_closing_price",
    }
    result["event_inventory"] = [{"event_id": e["event_id"], "sequence": i + 1, "sha256": digest(canonical(e))} for i, e in enumerate(document["events"])]
    with localcontext() as context:
        # All admitted operands have <=13 integral and <=8 fractional digits;
        # this covers every exact product and 10,000-event sum without rounding.
        context.prec = 80
        cash = opening = number(document["opening"]["cash"])
        quantity = fees = realized = flows = Decimal(0)
        lots = deque()
        for event in document["events"]:
            kind = event["type"]
            if kind in ("DEPOSIT", "WITHDRAWAL"):
                amount = number(event["amount"]) * (1 if kind == "DEPOSIT" else -1)
                cash += amount
                flows += amount
            else:
                size, price, fee = (number(event[k]) for k in ("quantity", "price", "fee"))
                fees += fee
                if kind == "BUY":
                    cash -= size * price + fee
                    quantity += size
                    lots.append([size, price])
                else:
                    if size > quantity:
                        reject("SELL_EXCEEDS_POSITION")
                    cash += size * price - fee
                    quantity -= size
                    remaining, cost = size, Decimal(0)
                    while remaining:
                        lot = lots[0]
                        taken = min(remaining, lot[0])
                        cost += taken * lot[1]
                        lot[0] -= taken
                        remaining -= taken
                        if not lot[0]:
                            lots.popleft()
                    realized += size * price - cost
            if cash < 0:
                reject("NEGATIVE_CASH_UNSUPPORTED")
            result["event_checkpoints"].append({"event_id": event["event_id"], "cash": text_decimal(cash), "quantity": text_decimal(quantity)})
        basis = sum((size * price for size, price in lots), Decimal(0))
        market = quantity * number(document["closing"]["mark_price"])
        nav, unrealized = cash + market, market - basis
        profit = realized + unrealized - fees
        if nav - opening - flows != profit:
            reject("INTERNAL_ACCOUNTING_IDENTITY_FAILURE")
        computed = dict(zip(METRICS, (cash, quantity, basis, fees, realized, unrealized, flows, profit, nav)))
        result["computed"] = {key: text_decimal(value) for key, value in computed.items()}
        reported = document["closing"]["reported"]
        for key, value in computed.items():
            if key not in reported:
                result["checks"][key] = {"status": "NOT_SUPPLIED", "computed": text_decimal(value)}
                continue
            actual = number(reported[key], reported=True)
            result["checks"][key] = {"status": "MATCH" if actual == value else "DISCREPANCY", "computed": text_decimal(value), "reported": text_decimal(actual), "difference_reported_minus_computed": text_decimal(actual - value)}
        if any(check["status"] == "DISCREPANCY" for check in result["checks"].values()):
            result["status"] = "DISCREPANCIES_FOUND"
            result["reason_codes"] = ["REPORTED_VALUES_DIFFER"]
        elif any(check["status"] == "NOT_SUPPLIED" for check in result["checks"].values()):
            result["reason_codes"] = ["MISSING_REPORTED_METRIC"]
        else:
            result["status"] = "RECONCILED_UNDER_ASSUMPTIONS"
            result["reason_codes"] = ["SUPPLIED_EVENTS_AND_REPORTED_VALUES_RECONCILE"]
    return result


def assess_bytes(raw):
    result = _base()
    if type(raw) is bytes and len(raw) <= MAX_BYTES:
        result["source_inventory"] = [{"role": "supplied_event_document", "size_bytes": len(raw), "sha256": digest(raw), "binding": "exact_supplied_bytes"}]
    try:
        return _assess(parse_bytes(raw), result)
    except AccountingError as exc:
        result["reason_codes"] = [str(exc)]
        return result


def assess_document(document):
    """Assess a JSON-compatible object; source binding is its canonical encoding."""
    try:
        raw = canonical(document)
    except (TypeError, ValueError, RecursionError):
        result = _base()
        result["reason_codes"] = ["INVALID_JSON_OBJECT"]
        return result
    result = assess_bytes(raw)
    if result["source_inventory"]:
        result["source_inventory"][0]["binding"] = "canonical_encoding_of_supplied_object"
    return result
