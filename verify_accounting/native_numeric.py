"""Original, bounded strict replay of a documented native operation graph.

Source study (not copied implementation): pinned Freqtrade trade_model.py 1055,
1094,1167,1196,1272,1304,1542 and wallets.py171; FtPrecise delegates to CCXT
Precise. Installed helper inspection established exact scaled-integer +/-/*,
float(str(value)), and default 18-place division. With one positive entry and
<=8-place operands, average-price division is exact. Generic negative/truncated
CCXT division is deliberately outside this policy. Original arithmetic probes in
read-only pinned image matched retained smooth profits/cash and signed tie vectors.

This module uses rational ties-even rounding, NOT decimal quantization of repr(x).
Captured source/runtime identities are supplied claims, never authentication.
"""
from decimal import Decimal
from fractions import Fraction
import math
import re
import sys

from .core import AccountingError, keys, reject
from .v2 import number

POLICY = "freqtrade-2026.8-cpython3147-serial-round8.v1"
PINNED_RUNTIME = {
    "image_reference": "sha256:289f403917e170ecced1f3c537a2580435a581f2b21311c488c4efcb1694f666",
    "engine_revision": "9f10e357a93c1dcf10c2a2b367659214d89c073e",
    "engine_source_sha256": "a96f980268301b69f8fb6e423d27606ede3f174449f63ff672aebb48f97ac6de",
    "python": "3.14.7", "ccxt": "4.5.76", "numpy": "2.4.6",
    "precise_sha256": "445721221b65f37cc198adaeec26f68b214926e82ea2bfc0195a346ec94773ed",
}
PROOF = {
    "policy": POLICY,
    "engine_sources": {"persistence/trade_model.py": "c884ff5ae0009c2f9ebc6c0fb9c8cbf297fdcb416f5b48ff6486a4727bc60f9d", "wallets.py": "28a6c1e166520d4775a97b852049f136c41cdda97bd9f10b801c9c302d237db8", "util/ft_precise.py": "0338b928d761ad076f79ce6cb49a4894723170f79d7894212504e248de6fee07"},
    "observed_runtime_files": {"ccxt/base/precise.py": PINNED_RUNTIME["precise_sha256"], "libpython3.14.so.1.0": "62e5213ccba3bc19e4fdf4ae2c11af62a597f43d94f6f745b8f5b1a148e10cc7", "numpy/_core/_multiarray_umath.cpython-314-aarch64-linux-gnu.so": "5feaaf551b3b49f197607abf366e348569a4af4a424b71e0222ba74c7f24261a"},
    "operations": ["exact decimal-string q*p*(1+0.001) and q*p*(1-0.001)", "convert each leg separately RN-even binary64", "RN-even binary64 exit leg minus entry leg", "round exact binary value to decimal quantum1e-8 ties-even then convert RN-even binary64", "RN-even add to initial positive zero per closed trade", "RN-even serial closed-trade accumulation in supplied close order", "RN-even opening capital plus accumulated profit"],
    "scope": "positive one-entry/full-exit, fixed0.001 quote model, no base fees, external flows, residual holdings or forced exits",
    "limits": "local source/runtime study and independent challenges, not external audit or attestation; capture binding is caller responsibility",
}


def rational(value):
    value = Fraction(value)
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def rational_decimal(value):
    """Exact finite decimal, without Decimal context rounding."""
    value = Fraction(value)
    denominator = value.denominator
    twos = fives = 0
    while denominator % 2 == 0:
        denominator //= 2; twos += 1
    while denominator % 5 == 0:
        denominator //= 5; fives += 1
    if denominator != 1:
        reject("NONTERMINATING_DECIMAL")
    scale = max(twos, fives)
    integer = abs(value.numerator) * 2 ** (scale - twos) * 5 ** (scale - fives)
    digits = str(integer).zfill(scale + 1)
    text = (digits[:-scale] + "." + digits[-scale:]).rstrip("0").rstrip(".") if scale else digits
    return ("-" if value < 0 else "") + text


def dto(value):
    if type(value) is not float or not math.isfinite(value):
        reject("INVALID_NATIVE_FLOAT")
    return {"encoding": "binary64", "repr": repr(value), "hex": value.hex()}


def decode_native(value):
    keys(value, ("encoding", "repr", "hex"))
    if value["encoding"] != "binary64" or type(value["repr"]) is not str or type(value["hex"]) is not str or len(value["repr"]) > 32 or len(value["hex"]) > 32:
        reject("INVALID_NATIVE_FLOAT")
    if not re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:e[+-][0-9]+)?", value["repr"]):
        reject("NONCANONICAL_NATIVE_SPELLING")
    try:
        result = float(value["repr"])
        if not math.isfinite(result) or repr(result) != value["repr"] or result.hex() != value["hex"]:
            reject("NATIVE_REPR_HEX_MISMATCH")
        return result
    except (ValueError, OverflowError):
        reject("NATIVE_REPR_HEX_MISMATCH")


def rn64(value):
    result = float(Fraction(value))
    if not math.isfinite(result):
        reject("NATIVE_OVERFLOW")
    return result


def add64(left, right):
    result = rn64(Fraction(left) + Fraction(right))
    if result == 0 and left == 0 and right == 0 and math.copysign(1, left) < 0 and math.copysign(1, right) < 0:
        return -0.0
    return result


def subtract64(left, right):
    return add64(left, -right)


def round8(value):
    """Round the exact finite binary64 rational, preserving negative rounded zero."""
    if type(value) is not float or not math.isfinite(value):
        reject("INVALID_NATIVE_FLOAT")
    scaled = Fraction(value) * 100_000_000
    whole, remainder = divmod(abs(scaled.numerator), scaled.denominator)
    if 2 * remainder > scaled.denominator or 2 * remainder == scaled.denominator and whole % 2:
        whole += 1
    negative = math.copysign(1, value) < 0
    if whole == 0:
        return -0.0 if negative else 0.0
    return rn64(Fraction(-whole if negative else whole, 100_000_000))


def serial_total(values):
    total = 0.0
    for value in values:
        total = add64(total, value)
    return total


def compare_native_metric(value, expected, model):
    if value is None:
        return {"status": "NOT_SUPPLIED", "expected": dto(expected), "model": rational_decimal(model)}
    observed = decode_native(value)
    difference = Fraction(observed) - Fraction(model)
    printed = Fraction(Decimal(value["repr"])) - Fraction(model)
    return {"status": "MATCHES_ENGINE_NUMERIC_POLICY" if observed.hex() == expected.hex() else "MISMATCH", "observed": value, "expected": dto(expected), "model": rational_decimal(model), "decimal_model_equal": difference == 0, "exact_binary_minus_model": rational(difference), "exact_binary_minus_model_decimal": rational_decimal(difference), "printed_decimal_minus_model": rational_decimal(printed)}


def replay_native(opening_cash, trades, native_total_profit=None, native_cash=None, *, runtime):
    result = {"schema": "n170.accounting.native-replay.v1", "policy": POLICY, "status": "NOT_ASSESSABLE", "reason_codes": [], "runtime": runtime, "trades": [], "checks": {}, "expected": None, "source_authenticity": "not_established", "selected_source_completeness": "unknown", "proof": PROOF}
    try:
        keys(runtime, (*PINNED_RUNTIME, "image_id"))
        if any(runtime[key] != value for key, value in PINNED_RUNTIME.items()) or type(runtime["image_id"]) is not str or not re.fullmatch(r"sha256:[a-f0-9]{64}", runtime["image_id"]):
            reject("UNSUPPORTED_NATIVE_RUNTIME")
        if sys.float_info.radix != 2 or sys.float_info.mant_dig != 53 or sys.float_info.rounds != 1:
            reject("UNSUPPORTED_REPLAY_HOST")
        opening = Fraction(number(opening_cash, nonnegative=True))
        if type(trades) is not list or not 1 <= len(trades) <= 5000:
            reject("INVALID_TRADE_COUNT")
        seen = set(); profits = []; exact_total = Fraction(0)
        for trade in trades:
            keys(trade, ("trade_id", "entry_quantity", "entry_price", "exit_quantity", "exit_price", "fee_rate", "native_profit"))
            identity = trade["trade_id"]
            if type(identity) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", identity) or identity in seen:
                reject("INVALID_OR_DUPLICATE_TRADE_ID")
            seen.add(identity)
            q, entry, exit_q, exit_price = [Fraction(number(trade[key], positive=True)) for key in ("entry_quantity", "entry_price", "exit_quantity", "exit_price")]
            if q != exit_q or trade["fee_rate"] != "0.001":
                reject("UNSUPPORTED_NATIVE_TRADE")
            opened = q * entry * Fraction(1001, 1000)
            closed = q * exit_price * Fraction(999, 1000)
            exact_profit = closed - opened
            entry_leg, exit_leg = rn64(opened), rn64(closed)
            delta = subtract64(exit_leg, entry_leg)
            profit = add64(0.0, round8(delta))
            profits.append(profit); exact_total += exact_profit
            result["trades"].append({"trade_id": identity, "entry_leg": dto(entry_leg), "exit_leg": dto(exit_leg), "unrounded_profit": dto(delta), "check": compare_native_metric(trade["native_profit"], profit, exact_profit)})
        total = serial_total(profits)
        cash = add64(rn64(opening), total)
        result["expected"] = {"cash": dto(cash), "net_pnl": dto(total), "quantity": "0"}
        result["checks"] = {"cash": compare_native_metric(native_cash, cash, opening + exact_total), "net_pnl": compare_native_metric(native_total_profit, total, exact_total)}
        checks = [*(trade["check"] for trade in result["trades"]), *result["checks"].values()]
        if any(c["status"] == "MISMATCH" for c in checks):
            result.update(status="MISMATCH", reason_codes=["NATIVE_REPLAY_DIFFERENCE"])
        elif any(c["status"] == "NOT_SUPPLIED" for c in checks):
            result["reason_codes"] = ["MISSING_NATIVE_OBSERVATION"]
        else:
            result.update(status="MATCHES_ENGINE_NUMERIC_POLICY", reason_codes=["SUPPLIED_NATIVE_BITS_MATCH_PINNED_POLICY"])
    except (AccountingError, ValueError, OverflowError, TypeError) as error:
        result["reason_codes"] = [str(error) if isinstance(error, AccountingError) else "INVALID_NATIVE_INPUT"]
        result["status"] = "NOT_ASSESSABLE"
    return result
