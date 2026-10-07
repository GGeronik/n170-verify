"""Versioned exact decimal ledger with explicitly modeled 0.001 quote fees.

V1 is untouched. This ledger can diagnose FIFO/open holdings; it does not grant
Freqtrade capture scope. Native binary64 observations belong in native_numeric,
never in invented closing claims. No engine is imported or executed here.
"""
from collections import deque
from decimal import Context, Decimal, Inexact, Rounded, localcontext
import re

from .core import AccountingError, LIMITATIONS, MAX_EVENTS, METRICS, canonical, digest, keys, parse_bytes, reject, text_decimal, timestamp

SCHEMA = "n170.accounting.events.v2"
REPORT_SCHEMA = "n170.accounting.reconciliation.v2"
POLICY = "decimal80-operand8-modeledfee19-result19.v1"


def exact_context():
    context = Context(prec=80, Emin=-999, Emax=999)
    context.traps[Inexact] = context.traps[Rounded] = True
    return localcontext(context)


def number(value, *, kind="operand", nonnegative=False, positive=False):
    limits = {"operand": (8, 12), "fee": (19, 21), "result": (19, 30)}
    if kind not in limits:
        reject("UNSUPPORTED_NUMERIC_KIND")
    scale, magnitude = limits[kind]
    if type(value) is not str or not re.fullmatch(r"-?(?:0|[1-9][0-9]{0," + str(magnitude) + r"})(?:\.[0-9]{1," + str(scale) + r"})?", value):
        reject("INVALID_DECIMAL")
    amount = Decimal(value)
    if amount.copy_abs() > Decimal("1e" + str(magnitude)):
        reject("AMOUNT_LIMIT_EXCEEDED")
    if nonnegative and amount < 0 or positive and amount <= 0:
        reject("INVALID_AMOUNT_SIGN")
    return amount


def modeled_fee(quantity, price):
    with exact_context():
        value = number(quantity, positive=True) * number(price, positive=True) * Decimal("0.001")
        return text_decimal(number(text_decimal(value), kind="fee", nonnegative=True))


def validate_document(document):
    keys(document, ("schema", "evidence_class", "asset", "cash_currency", "opening", "events", "closing"))
    if document["schema"] != SCHEMA:
        reject("UNSUPPORTED_SCHEMA")
    if document["evidence_class"] not in ("synthetic_fixture", "supplied_events"):
        reject("UNSUPPORTED_EVIDENCE_CLASS")
    for key in ("asset", "cash_currency"):
        if type(document[key]) is not str or not re.fullmatch(r"[A-Z][A-Z0-9]{1,11}", document[key]):
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
    for value in closing["reported"].values():
        number(value, kind="result")
    if type(document["events"]) is not list or len(document["events"]) > MAX_EVENTS:
        reject("INVALID_EVENT_COUNT")
    known, last = set(), start
    for event in document["events"]:
        keys(event, ("event_id", "timestamp", "type"), ("quantity", "price", "fee", "fee_currency", "fee_model", "amount"))
        identity = event["event_id"]
        if type(identity) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", identity):
            reject("INVALID_EVENT_ID")
        if identity in known:
            reject("DUPLICATE_EVENT")
        known.add(identity)
        instant = timestamp(event["timestamp"])
        if instant < last or instant > end:
            reject("EVENT_CHRONOLOGY_MISMATCH")
        last = instant
        if event["type"] in ("BUY", "SELL"):
            keys(event, ("event_id", "timestamp", "type", "quantity", "price", "fee", "fee_currency", "fee_model"))
            for field in ("quantity", "price"):
                number(event[field], positive=True)
            fee = number(event["fee"], kind="fee", nonnegative=True)
            if event["fee_currency"] != document["cash_currency"]:
                reject("UNSUPPORTED_FEE_CURRENCY")
            model = event["fee_model"]
            keys(model, ("kind", "quantity", "price", "rate", "sources"))
            if model["kind"] != "modeled_fee" or model["rate"] != "0.001":
                reject("UNSUPPORTED_FEE_MODEL")
            if model["quantity"] != event["quantity"] or model["price"] != event["price"]:
                reject("FEE_OPERANDS_MISMATCH")
            refs = model["sources"]
            if type(refs) is not list or not 1 <= len(refs) <= 8 or any(type(ref) is not str or not re.fullmatch(r"[A-Za-z0-9_./:#-]{1,240}", ref) for ref in refs) or len(set(refs)) != len(refs):
                reject("INVALID_FEE_SOURCE_REFERENCES")
            if fee != Decimal(modeled_fee(event["quantity"], event["price"])):
                reject("MODELED_FEE_MISMATCH")
        elif event["type"] in ("DEPOSIT", "WITHDRAWAL"):
            keys(event, ("event_id", "timestamp", "type", "amount"))
            number(event["amount"], positive=True)
        else:
            reject("UNSUPPORTED_EVENT")
    return document


def _base():
    return {"schema": REPORT_SCHEMA, "numeric_policy": POLICY, "status": "NOT_ASSESSABLE", "reason_codes": [], "evidence_class": "unassessed", "source_inventory": [], "event_inventory": [], "checks": {}, "computed": None, "event_checkpoints": [], "source_authenticity": "not_established", "selected_source_completeness": "unknown", "oracle": {"status": "NOT_RUN"}, "limitations": [*LIMITATIONS, "Fees are modeled from selected quantity, price and fixed 0.001 rate; referenced source fields and fee payments are not authenticated."], "scope": None}


def _assess(document, result):
    validate_document(document)
    result["evidence_class"] = document["evidence_class"]
    result["scope"] = {"asset": document["asset"], "cash_currency": document["cash_currency"], "opening_timestamp": document["opening"]["timestamp"], "closing_timestamp": document["closing"]["timestamp"], "selected_event_count": len(document["events"]), "opening_positions": "zero_required", "cost_basis_policy": "FIFO_in_supplied_chronological_order", "fee_policy": "modeled_quote_quantity_price_rate_0.001_expensed_immediately", "settlement_policy": "immediate_spot", "mark_policy": "supplied_nonnegative_closing_price", "engine_scope": "not_granted_by_ledger_diagnostics"}
    result["event_inventory"] = [{"event_id": e["event_id"], "sequence": i + 1, "sha256": digest(canonical(e))} for i, e in enumerate(document["events"])]
    with exact_context():
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
                size, price = number(event["quantity"]), number(event["price"])
                fee = number(event["fee"], kind="fee")
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
            basis = sum((size * price for size, price in lots), Decimal(0))
            result["event_checkpoints"].append(dict(event_id=event["event_id"], **{key: text_decimal(value) for key, value in {"cash": cash, "quantity": quantity, "fifo_cost_basis": basis, "gross_realized_pnl": realized, "fees": fees}.items()}))
        basis = sum((size * price for size, price in lots), Decimal(0))
        market = quantity * number(document["closing"]["mark_price"])
        nav, unrealized = cash + market, market - basis
        profit = realized + unrealized - fees
        if nav - opening - flows != profit:
            reject("INTERNAL_ACCOUNTING_IDENTITY_FAILURE")
        computed = dict(zip(METRICS, (cash, quantity, basis, fees, realized, unrealized, flows, profit, nav)))
        result["computed"] = {key: text_decimal(number(text_decimal(value), kind="result")) for key, value in computed.items()}
        for key, value in computed.items():
            if key not in document["closing"]["reported"]:
                result["checks"][key] = {"status": "NOT_SUPPLIED", "computed": text_decimal(value)}
            else:
                actual = number(document["closing"]["reported"][key], kind="result")
                result["checks"][key] = {"status": "MATCH" if actual == value else "DISCREPANCY", "computed": text_decimal(value), "reported": text_decimal(actual), "difference_reported_minus_computed": text_decimal(actual - value)}
        if any(c["status"] == "DISCREPANCY" for c in result["checks"].values()):
            result.update(status="DISCREPANCIES_FOUND", reason_codes=["REPORTED_VALUES_DIFFER"])
        elif any(c["status"] == "NOT_SUPPLIED" for c in result["checks"].values()):
            result["reason_codes"] = ["MISSING_REPORTED_METRIC"]
        else:
            result.update(status="RECONCILED_UNDER_ASSUMPTIONS", reason_codes=["SUPPLIED_EVENTS_AND_REPORTED_VALUES_RECONCILE"])
    return result


def assess_bytes(raw):
    result = _base()
    from .core import MAX_BYTES
    if type(raw) is bytes and len(raw) <= MAX_BYTES:
        result["source_inventory"] = [{"role": "supplied_event_document", "size_bytes": len(raw), "sha256": digest(raw), "binding": "exact_supplied_bytes"}]
    try:
        return _assess(parse_bytes(raw), result)
    except (AccountingError, Inexact, Rounded) as error:
        result["reason_codes"] = [str(error) if isinstance(error, AccountingError) else "INEXACT_ARITHMETIC_REJECTED"]
        return result


def assess_document(document):
    try:
        raw = canonical(document)
    except (TypeError, ValueError, RecursionError):
        result = _base(); result["reason_codes"] = ["INVALID_JSON_OBJECT"]; return result
    result = assess_bytes(raw)
    if result["source_inventory"]:
        result["source_inventory"][0]["binding"] = "canonical_encoding_of_supplied_object"
    return result
