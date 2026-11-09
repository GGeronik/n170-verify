"""Strict RFC 8785 JSON Canonicalization Scheme (JCS) implementation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from decimal import Decimal
from enum import Enum
import hashlib
import math
from typing import Any

import numpy as np


_CONTROL_ESCAPES: dict[int, str] = {
    0x08: r"\b",
    0x09: r"\t",
    0x0A: r"\n",
    0x0C: r"\f",
    0x0D: r"\r",
    0x22: r"\"",
    0x5C: r"\\",
}


def _format_es6_float(val: float) -> str:
    """Format an IEEE-754 binary64 float per ECMA-262 7.1.12.1 / RFC 8785 Section 3.2.2.3."""
    if not math.isfinite(val):
        raise ValueError(f"RFC 8785 JCS forbids non-finite numbers: {val!r}")
    if val == 0.0:
        return "0"
    if val < 0.0:
        return "-" + _format_es6_float(-val)

    d = Decimal(repr(val)).normalize()
    _, digit_tuple, exp = d.as_tuple()
    digits = "".join(str(x) for x in digit_tuple)
    k = len(digits)
    n = k + int(exp)

    if k <= n <= 21:
        return digits + ("0" * (n - k))
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + ("0" * (-n)) + digits

    exponent = n - 1
    sign = "+" if exponent >= 0 else "-"
    mantissa = digits[0] if k == 1 else f"{digits[0]}.{digits[1:]}"
    return f"{mantissa}e{sign}{abs(exponent)}"


def _escape_jcs_string(value: str) -> str:
    """Serialize a UTF-8 JSON string per RFC 8785 Section 3.2.2.2."""
    out: list[str] = ['"']
    for ch in value:
        code = ord(ch)
        if 0xD800 <= code <= 0xDFFF:
            raise ValueError(f"RFC 8785 JCS forbids lone UTF-16 surrogate U+{code:04X}")
        escaped = _CONTROL_ESCAPES.get(code)
        if escaped is not None:
            out.append(escaped)
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_code_unit_sort_key(key: str) -> bytes:
    """Sort key ordering strings by big-endian 16-bit UTF-16 code units (RFC 8785 Section 3.2.3)."""
    try:
        return key.encode("utf-16-be")
    except UnicodeEncodeError as exc:
        raise ValueError("RFC 8785 JCS forbids lone UTF-16 surrogates in object keys") from exc


def _jcs_serialize(obj: Any) -> str:
    if obj is None:
        return "null"
    if isinstance(obj, bool) or isinstance(obj, np.bool_):
        return "true" if bool(obj) else "false"
    if isinstance(obj, Enum):
        return _jcs_serialize(obj.value)
    if isinstance(obj, (int, np.integer)):
        ival = int(obj)
        if abs(ival) <= 9_007_199_254_740_991:
            return str(ival)
        try:
            fval = float(ival)
        except OverflowError as exc:
            raise ValueError(
                "Integer exceeds IEEE-754 double range supported by RFC 8785"
            ) from exc
        if not math.isfinite(fval):
            raise ValueError("Integer exceeds IEEE-754 double range supported by RFC 8785")
        return _format_es6_float(fval)
    if isinstance(obj, (float, np.floating)):
        return _format_es6_float(float(obj))
    if isinstance(obj, str):
        return _escape_jcs_string(obj)
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return _jcs_serialize(obj.to_dict())
    if is_dataclass(obj) and not isinstance(obj, type):
        return _jcs_serialize({f.name: getattr(obj, f.name) for f in fields(obj)})
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_jcs_serialize(item) for item in obj) + "]"
    if isinstance(obj, Mapping):
        normalized_items: list[tuple[bytes, str, Any]] = []
        seen_keys: set[str] = set()
        for raw_key, val in obj.items():
            if isinstance(raw_key, Enum) and isinstance(raw_key.value, str):
                key_str = raw_key.value
            elif isinstance(raw_key, str):
                key_str = raw_key
            else:
                raise TypeError(
                    f"RFC 8785 JCS object keys must be strings, got {type(raw_key).__name__}"
                )
            if key_str in seen_keys:
                raise ValueError(f"Duplicate JCS object key after normalization: {key_str!r}")
            seen_keys.add(key_str)
            normalized_items.append((_utf16_code_unit_sort_key(key_str), key_str, val))

        normalized_items.sort(key=lambda entry: entry[0])
        members = [
            f"{_escape_jcs_string(key_str)}:{_jcs_serialize(val)}"
            for _, key_str, val in normalized_items
        ]
        return "{" + ",".join(members) + "}"

    raise TypeError(f"Unsupported type for RFC 8785 JCS canonicalization: {type(obj).__name__}")


def jcs_canonicalize_str(obj: Any) -> str:
    """Return canonical RFC 8785 JSON as a UTF-8 Python ``str``."""
    return _jcs_serialize(obj)


def jcs_canonicalize(obj: Any) -> bytes:
    """Return canonical RFC 8785 JSON encoded as UTF-8 ``bytes``."""
    return _jcs_serialize(obj).encode("utf-8")


def jcs_sha256_hex(obj: Any) -> str:
    """Return lowercase 64-character SHA-256 hex digest of ``jcs_canonicalize(obj)``."""
    return hashlib.sha256(jcs_canonicalize(obj)).hexdigest()


def domain_separated_sha256_hex(domain: bytes, payload: bytes) -> str:
    """Compute SHA-256(domain || 0x00 || payload) as lowercase 64-char hex."""
    if not isinstance(domain, bytes) or not domain:
        raise ValueError("domain must be non-empty bytes")
    if not isinstance(payload, bytes):
        raise ValueError("payload must be bytes")
    return hashlib.sha256(domain + b"\x00" + payload).hexdigest()


__all__ = [
    "domain_separated_sha256_hex",
    "jcs_canonicalize",
    "jcs_canonicalize_str",
    "jcs_sha256_hex",
]
