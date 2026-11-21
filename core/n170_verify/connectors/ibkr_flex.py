"""IBKR Flex Web Service v3 client and XXE-hardened streaming Flex XML parser.

Implements two assurance tiers for Interactive Brokers Flex statements:
1. ``IbkrFlexWebServiceAdapter`` (``OPERATOR_RETRIEVED`` / ``INDEPENDENTLY_WITNESSED_TLS``):
   Executes the Flex Web Service ``v=3`` ``SendRequest`` -> ``GetStatement`` flow with a
   mandatory custom ``User-Agent``, hardcoding
   ``https://ndcdyn.interactivebrokers.com/AccountManagement/FlexWebService/GetStatement``
   and explicitly ignoring the deprecated ``<Url>`` tag returned by ``SendRequest``
   (which points to ``gdcdyn.interactivebrokers.com`` and triggers IBKR Error 1001).
   All ``?t=`` and ``?q=`` query tokens are redacted from logs and exceptions.
2. ``IbkrFlexOfflineAdapter`` / ``parse_ibkr_flex_xml`` (``SELF_REPORTED``):
   Streaming ``iterparse`` XML parser supporting UTF-8 and UTF-16 exports while
   hard-failing on any ``<!DOCTYPE`` or ``<!ENTITY`` declaration (XXE/billion-laughs
   prevention). Normalizes ``EquitySummaryInBase``, ``PriorPeriodPositions``,
   ``OpenPositions``, ``Trades``, ``CashTransactions``, ``Transfers``,
   ``CorporateActions``, ``OptionEAE``, and ``ConversionRates`` into
   ``CanonicalPortfolioLedger``.
"""

from __future__ import annotations

import bisect
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import hashlib
from io import BytesIO
import math
from pathlib import Path
import re
import time
from typing import Any
import urllib.parse
import xml.etree.ElementTree as ET

from n170_verify.connectors.ccxt_crypto import (
    ConnectorHttpError,
    HttpTransportCallable,
    PaperOrSandboxAccountRejectedError,
    invoke_http_transport,
)
from n170_verify.connectors.mcp_allowlist_firewall import redact_sensitive_text
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    CanonicalPortfolioLedger,
    CorporateActionRecord,
    CorporateActionType,
    EnvironmentTier,
    FlowKind,
    NormalizedFlow,
    NormalizedNavPoint,
    NormalizedPosition,
    NormalizedTrade,
    OriginAssurance,
    ProviderApprovalState,
    ReadOnlyBrokerAdapter,
    compute_blinded_account_tag,
)


IBKR_FLEX_SEND_REQUEST_URL = (
    "https://ndcdyn.interactivebrokers.com/AccountManagement/FlexWebService/SendRequest"
)
IBKR_FLEX_GET_STATEMENT_URL = (
    "https://ndcdyn.interactivebrokers.com/AccountManagement/FlexWebService/GetStatement"
)
DEFAULT_IBKR_FLEX_USER_AGENT = "N170-Verify/0.3 (ReadOnlyFlexClient)"

DEFAULT_MAX_FLEX_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_FLEX_ELEMENTS = 1_000_000
DEFAULT_MAX_SECTION_ROWS = 250_000
INFERRED_SINGLE_PRIOR_POSITION_WARNING = (
    "Inferred single opening prior position quantity from EquitySummaryInBase and "
    "PriorPeriodPosition price (position attribute omitted in Flex query)."
)
OMITTED_PRIOR_POSITION_QTY_WARNING = (
    "PriorPeriodPositions section omitted position quantities; opening share roll-forward "
    "completeness was omitted."
)
OMITTED_PRIOR_POSITION_SYMBOLS_PREFIX = (
    "PriorPeriodPositions omitted quantity symbols: "
)

_PAPER_IBKR_ACCOUNT_RE = re.compile(r"^D[UF][0-9]{4,}$", re.IGNORECASE)
_SPLIT_RATIO_RE = re.compile(
    r"\b([0-9]+(?:\.[0-9]+)?)\s*(?:FOR|:|/)\s*([0-9]+(?:\.[0-9]+)?)\b",
    re.IGNORECASE,
)
_XML_ENCODING_DECL_RE = re.compile(
    rb'(<\?xml[^<>]{0,4096}\bencoding\s*=\s*["\'])([^"\']+)(["\'])',
    re.IGNORECASE,
)
_FLEX_FORMULA_TRIGGER_CHARS: frozenset[str] = frozenset(
    {"=", "+", "-", "@", "'", "|", "\t", "\r", "\n", "\v", "\f"}
)
_FLEX_XXE_DECL_RE = re.compile(
    rb"<![^<>]{0,4096}\b(?:doctype|entity|element|attlist|system|public)\b",
    re.IGNORECASE | re.DOTALL,
)
_FLEX_XXE_URI_RE = re.compile(
    rb"\b(?:system|public)\s+['\"](?:file|https?|ftp|jar|netdoc|php|gopher|data|expect):",
    re.IGNORECASE,
)


class IbkrFlexParseError(ValueError):
    """Raised when an IBKR Flex XML payload is malformed or exceeds safety bounds."""


class IbkrFlexXmlSecurityError(IbkrFlexParseError):
    """Raised when DTD or XML entity declarations (XXE / entity expansion) are detected."""


class IbkrFlexServiceError(RuntimeError):
    """Secret-redacted error raised when IBKR Flex Web Service v3 fails."""

    def __init__(self, message: str, error_code: str | None = None) -> None:
        super().__init__(message)
        self.error_code = error_code


def _current_ny_date(now_utc: datetime | None = None) -> date:
    """Return current calendar date in ``America/New_York`` (EST fallback when tzdata is absent)."""
    ts = (now_utc or datetime.now(timezone.utc)).astimezone(timezone.utc)
    try:
        from zoneinfo import ZoneInfo

        return ts.astimezone(ZoneInfo("America/New_York")).date()
    except Exception:
        return (ts - timedelta(hours=5)).date()


def _default_auto_end_ny_date(now_utc: datetime | None = None) -> date:
    """Return latest settleable Activity Flex end date in ``America/New_York``.

    IBKR Activity Flex statements are end-of-day batch reports and are never available for the
    current New York calendar date before the US session closes; probing ``td=today`` during
    pre-close hours triggers ``code=1003`` and increments IBKR's ``code=1025`` failed-attempt
    throttle counter.
    """
    ts = (now_utc or datetime.now(timezone.utc)).astimezone(timezone.utc)
    try:
        from zoneinfo import ZoneInfo

        ny_dt = ts.astimezone(ZoneInfo("America/New_York"))
    except Exception:
        ny_dt = ts - timedelta(hours=5)
    if ny_dt.hour < 18:
        return ny_dt.date() - timedelta(days=1)
    return ny_dt.date()


def _is_settlement_not_ready_error(exc: IbkrFlexServiceError) -> bool:
    if exc.error_code in {"1003", "1005", "1020"}:
        return True
    msg = str(exc)
    return any(f"(code={c})" in msg for c in ("1003", "1005", "1020"))


def _local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _sanitize_flex_text(value: str | None) -> str:
    if value is None:
        return ""
    cleaned = str(value).replace("\x00", "")
    if not cleaned:
        return ""
    lines: list[str] = []
    for raw_line in cleaned.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw_line.replace("\t", " ")
        idx = 0
        n = len(line)
        while idx < n and (line[idx].isspace() or line[idx] in _FLEX_FORMULA_TRIGGER_CHARS):
            idx += 1
        seg = line[idx:].strip()
        if seg:
            lines.append(seg)
    joined = " ".join(lines).strip()
    idx = 0
    n = len(joined)
    while idx < n and (joined[idx].isspace() or joined[idx] in _FLEX_FORMULA_TRIGGER_CHARS):
        idx += 1
    return joined[idx:].strip()


def _first_attr(attrs: dict[str, str], names: Iterable[str]) -> str | None:
    lowered = {k.lower(): v for k, v in attrs.items()}
    for name in names:
        val = lowered.get(name.lower())
        if val is not None and val.strip() != "":
            return val.strip()
    return None


def _first_text_attr(attrs: dict[str, str], names: Iterable[str]) -> str | None:
    raw = _first_attr(attrs, names)
    if raw is None:
        return None
    sanitized = _sanitize_flex_text(raw)
    return sanitized if sanitized else None


def _parse_flex_float(raw: str | None, *, default: float | None = None) -> float | None:
    if raw is None:
        return default
    cleaned = raw.strip().replace(",", "")
    if not cleaned or cleaned in {"--", "N/A", "n/a"}:
        return default
    if cleaned.startswith("(") and cleaned.endswith(")"):
        cleaned = "-" + cleaned[1:-1]
    try:
        dec = Decimal(cleaned)
    except InvalidOperation as exc:
        raise IbkrFlexParseError(f"Invalid numeric value in Flex XML: {raw!r}") from exc
    if not dec.is_finite() or abs(dec) > Decimal("1E30"):
        raise IbkrFlexParseError("Numeric value in Flex XML exceeds finite safety bounds")
    fval = float(dec)
    return 0.0 if fval == 0.0 else fval


_TRAILING_FLEX_TZ_LABEL_RE = re.compile(
    r"\s+(?:UTC|GMT|EST|EDT|CST|CDT|MST|MDT|PST|PDT|CET|CEST|EET|EEST|BST|JST|HKT|SGT|AEST|AEDT|[A-Za-z]+/[A-Za-z0-9_+-]+)$",
    re.IGNORECASE,
)
_ISO_NUMERIC_OFFSET_RE = re.compile(r"[-+]\d{2}:\d{2}$")


def _parse_flex_timestamp_utc(raw: str | None) -> str | None:
    if not raw:
        return None
    candidate = _TRAILING_FLEX_TZ_LABEL_RE.sub("", raw.strip()).strip()
    # Common IBKR Flex formats (including mixed Date Format + Time Format settings):
    # "20240103", "2024-01-03", "20240103;154512", "2024-01-03;15:45:12",
    # "2024-01-03;154512", "20240103;15:45:12", "2024-01-03, 15:45:12",
    # "2024-01-03;15:45:12 EST", "2024-01-03T15:45:12Z"
    normalized = candidate.replace(", ", "T").replace(",", "T").replace(";", "T").replace(" ", "T")
    while "TT" in normalized:
        normalized = normalized.replace("TT", "T")
    if normalized.endswith(("Z", "z")) or _ISO_NUMERIC_OFFSET_RE.search(normalized[10:]):
        try:
            dt = datetime.fromisoformat(normalized.replace("Z", "+00:00").replace("z", "+00:00"))
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass

    for fmt in (
        "%Y%m%dT%H%M%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H%M%S",
        "%Y%m%dT%H:%M:%S",
        "%Y%m%d",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(normalized, fmt).replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return None


_DATE_ONLY_RE = re.compile(r"^\s*(?:\d{8}|\d{4}-\d{2}-\d{2})\s*$")


def _trim_valuation_series(points: Sequence[NormalizedNavPoint]) -> list[NormalizedNavPoint]:
    """Keep a time-ordered valuation series from its first positive value onward.

    A value at or below zero after a positive one stays in the series, so a wipe-out is
    visible to the return calculation (which then withholds) and is never skipped. After
    the last positive value only the first non-positive one is kept; values before the
    account was first funded are not part of the series.
    """
    ordered = sorted(points, key=lambda p: p.timestamp_utc)
    pos_idx = [i for i, p in enumerate(ordered) if p.nav_base > 0.0]
    if not pos_idx:
        return []
    first, last = pos_idx[0], pos_idx[-1]
    kept = ordered[first : last + 1]
    if last + 1 < len(ordered):
        kept.append(ordered[last + 1])
    return kept


def _decode_and_guard_xml_bytes(raw: bytes, *, max_bytes: int) -> bytes:
    """Reject DTD/XXE across UTF-8/16/32 and normalize UTF-16 into UTF-8 bytes for ElementTree."""
    if len(raw) > max_bytes:
        raise IbkrFlexParseError(f"Flex XML payload exceeds {max_bytes}-byte limit")
    if not raw.strip(b"\x00 \t\r\n"):
        raise IbkrFlexParseError("Flex XML payload is empty")

    # Strip NUL bytes so UTF-16/UTF-32 ASCII markup cannot evade DTD/ENTITY detection.
    nul_stripped = raw.replace(b"\x00", b"")
    nul_stripped_lower = nul_stripped.lower()
    for forbidden in (b"<!doctype", b"<!entity", b"<!element", b"<!attlist"):
        if forbidden in nul_stripped_lower:
            raise IbkrFlexXmlSecurityError(
                "DTD and XML entity declarations (<!DOCTYPE / <!ENTITY) are forbidden in Flex XML"
            )
    if _FLEX_XXE_DECL_RE.search(nul_stripped) or _FLEX_XXE_URI_RE.search(nul_stripped):
        raise IbkrFlexXmlSecurityError(
            "External SYSTEM / PUBLIC entity declarations are forbidden in Flex XML"
        )

    # Detect UTF-16 BOM or UTF-16 byte pattern and transcode cleanly to UTF-8 for iterparse.
    text: str | None = None
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        try:
            text = raw.decode("utf-16")
        except UnicodeDecodeError as exc:
            raise IbkrFlexParseError("Malformed UTF-16 Flex XML payload") from exc
    elif b"\x00<\x00" in raw[:128] or b"<\x00?\x00" in raw[:128] or b"<\x00F\x00" in raw[:128] or b"<\x00!\x00" in raw[:128]:
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                candidate = raw.decode(enc)
                if "<" in candidate:
                    text = candidate
                    break
            except UnicodeDecodeError:
                continue

    if text is not None:
        utf8_bytes = text.encode("utf-8")
        lowered_utf8 = utf8_bytes.lower()
        for forbidden in (b"<!doctype", b"<!entity", b"<!element", b"<!attlist"):
            if forbidden in lowered_utf8:
                raise IbkrFlexXmlSecurityError(
                    "DTD and XML entity declarations are forbidden in Flex XML"
                )
        if _FLEX_XXE_DECL_RE.search(utf8_bytes) or _FLEX_XXE_URI_RE.search(utf8_bytes):
            raise IbkrFlexXmlSecurityError(
                "External SYSTEM / PUBLIC entity declarations are forbidden in Flex XML"
            )
        return _XML_ENCODING_DECL_RE.sub(rb"\1UTF-8\3", utf8_bytes, count=1)

    return raw


_FX_PAIR_SPLIT_RE = re.compile(r"[/._\-]+")


def _parse_fx_pair_symbol(symbol: str | None) -> tuple[str, str] | None:
    cleaned = (symbol or "").strip().upper()
    if not cleaned:
        return None
    if cleaned.endswith(".FOREX"):
        cleaned = cleaned[:-6]
    parts = [p for p in _FX_PAIR_SPLIT_RE.split(cleaned) if p]
    if len(parts) == 2 and all(len(p) == 3 and p.isalpha() for p in parts):
        return parts[0], parts[1]
    if len(parts) == 1 and len(parts[0]) == 6 and parts[0].isalpha():
        return parts[0][:3], parts[0][3:]
    return None


def _map_ibkr_asset_class(
    raw_cat: str | None,
    *,
    sub_cat: str | None = None,
    symbol: str | None = None,
) -> AssetClass:
    cat = (raw_cat or "STK").strip().upper()
    sub = (sub_cat or "").strip().upper()
    if cat == "STK":
        return AssetClass.ETF if sub == "ETF" else AssetClass.EQUITY
    if cat in {"OPT", "FOP", "IOPT", "WAR"}:
        return AssetClass.OPTION
    if cat in {"FUT", "CFD", "CMDTY"}:
        return AssetClass.FUTURE
    if cat == "CASH":
        return AssetClass.FX if _parse_fx_pair_symbol(symbol) is not None else AssetClass.CASH
    if cat in {"CRYPTO", "DIGITALASSET"}:
        return AssetClass.CRYPTO_SPOT
    return AssetClass.EQUITY


def _classify_cash_transaction_kind(attrs: dict[str, str], amount: float) -> FlowKind:
    raw_type = (
        _first_attr(attrs, ("type", "transactionType", "category", "activityCode")) or ""
    ).lower()
    desc = (
        _first_attr(attrs, ("description", "activityDescription", "transactionDescription")) or ""
    ).lower()
    combined = f"{raw_type} {desc}"

    if "withholding" in combined or "foreign tax" in combined:
        return FlowKind.WITHHOLDING_TAX
    if "dividend" in combined or "payment in lieu" in combined:
        return FlowKind.DIVIDEND
    if "interest" in combined:
        if amount < 0 or "paid" in combined or "debit" in combined or "margin" in combined:
            return FlowKind.MARGIN_INTEREST
        return FlowKind.INTEREST
    if "commission" in combined or "other fee" in combined or "exposure fee" in combined:
        return FlowKind.COMMISSION_FEE
    if "merger" in combined or "cash in lieu" in combined or "spinoff" in combined:
        return FlowKind.CORPORATE_ACTION_CASH
    if any(
        tok in combined
        for tok in (
            "deposit",
            "withdrawal",
            "wire",
            "ach",
            "electronic transfer",
            "cash transfer",
            "funds transfer",
            "contribution",
            "distribution",
        )
    ):
        if "internal" in combined and "account" in combined:
            return FlowKind.INTERNAL_SUBACCOUNT_TRANSFER
        return FlowKind.DEPOSIT if amount >= 0.0 else FlowKind.WITHDRAWAL
    return FlowKind.OTHER_INTERNAL


def _classify_corporate_action(attrs: dict[str, str]) -> tuple[CorporateActionType, float | None, float | None]:
    code = (_first_attr(attrs, ("type", "actionType", "code")) or "").upper()
    desc = _first_attr(attrs, ("description", "actionDescription")) or ""
    desc_lower = desc.lower()

    num: float | None = None
    den: float | None = None
    ratio_match = _SPLIT_RATIO_RE.search(desc)
    if ratio_match:
        try:
            n_val = float(ratio_match.group(1))
            d_val = float(ratio_match.group(2))
            if (
                math.isfinite(n_val)
                and math.isfinite(d_val)
                and 0.0 < n_val <= 1e30
                and 0.0 < d_val <= 1e30
            ):
                num, den = n_val, d_val
        except ValueError:
            pass

    if code == "RS" or "reverse split" in desc_lower or (num is not None and den is not None and num < den):
        return CorporateActionType.REVERSE_SPLIT, num, den
    if code == "FS" or "split" in desc_lower:
        return CorporateActionType.SPLIT, num, den
    if code == "SO" or "spin-off" in desc_lower or "spinoff" in desc_lower:
        return CorporateActionType.SPIN_OFF, num, den
    if code in {"TC", "IC", "BM", "DW"} or "merger" in desc_lower or "acquisition" in desc_lower:
        return CorporateActionType.MERGER, num, den
    if code in {"SC", "NC", "IS"} or "symbol" in desc_lower or "cusip/isin change" in desc_lower:
        return CorporateActionType.SYMBOL_CHANGE, num, den
    if code == "SD" or "stock dividend" in desc_lower or "grant" in desc_lower:
        return CorporateActionType.STOCK_GRANT, num, den
    return CorporateActionType.MERGER, num, den


_IBKR_BASE_RATIO_ATTR_PAIRS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("positionAmountInBase", ("positionAmount", "cashTransfer", "amount")),
    ("amountInBase", ("amount", "netAmount")),
    ("positionValueInBase", ("positionValue", "marketValue", "value")),
    ("markToMarketInBase", ("markToMarket", "mtm")),
    ("valueInBase", ("value", "positionValue", "marketValue", "amount")),
    ("costBasisInBase", ("costBasisMoney", "costBasis", "cost")),
    ("proceedsInBase", ("proceeds", "tradeMoney")),
    ("netCashInBase", ("netCash",)),
)


def _extract_row_implied_fx(attrs: Mapping[str, str]) -> float | None:
    """Extract explicit ``fxRateToBase``/``fxRate`` or a base-to-native attribute ratio."""
    explicit = _parse_flex_float(_first_attr(attrs, ("fxRateToBase", "fxRate")))
    if explicit is not None and explicit > 0.0 and math.isfinite(explicit):
        return explicit
    for b_attr, raw_attrs in _IBKR_BASE_RATIO_ATTR_PAIRS:
        v_base = _parse_flex_float(_first_attr(attrs, (b_attr,)))
        v_raw = _parse_flex_float(_first_attr(attrs, raw_attrs))
        if (
            v_base is not None
            and v_raw is not None
            and math.isfinite(v_base)
            and math.isfinite(v_raw)
            and abs(v_raw) > 1e-12
            and abs(v_base) > 0.0
            and (v_base > 0.0) == (v_raw > 0.0)
        ):
            ratio = abs(v_base / v_raw)
            if ratio > 0.0 and math.isfinite(ratio):
                return ratio
    return None


class _DatedFxIndex:
    """Sorted-date FX rate index per ``(from_ccy, to_ccy)`` with ``bisect`` nearest-date lookup."""

    def __init__(self, initial: Mapping[tuple[str, str, str], float] | None = None) -> None:
        self._by_pair: dict[tuple[str, str], dict[date, tuple[str, float]]] = {}
        self._sorted_dates: dict[tuple[str, str], list[date]] = {}
        self._raw: dict[tuple[str, str, str], float] = {}
        if initial:
            for (d_str, from_c, to_c), rate in initial.items():
                self.add(d_str, from_c, to_c, rate, overwrite=True)

    def add(self, d_str: str, from_c: str, to_c: str, rate: float, *, overwrite: bool = True) -> None:
        if (
            not d_str
            or not from_c
            or not to_c
            or from_c == to_c
            or rate <= 0.0
            or not math.isfinite(rate)
        ):
            return
        try:
            d_obj = date.fromisoformat(d_str[:10])
        except ValueError:
            return
        ymd = d_obj.isoformat()
        key = (ymd, from_c, to_c)
        if not overwrite and key in self._raw:
            return
        self._raw[key] = float(rate)
        pair = (from_c, to_c)
        pair_map = self._by_pair.setdefault(pair, {})
        is_new = d_obj not in pair_map
        pair_map[d_obj] = (ymd, float(rate))
        if is_new:
            dates_list = self._sorted_dates.setdefault(pair, [])
            bisect.insort(dates_list, d_obj)

    def raw_items(self) -> dict[tuple[str, str, str], float]:
        return dict(self._raw)

    def lookup(
        self,
        query_ymd: str | None,
        from_c: str,
        to_c: str,
        *,
        max_days: int | None = None,
    ) -> float | None:
        if from_c == to_c:
            return 1.0
        q_date: date | None = None
        if query_ymd:
            try:
                q_date = date.fromisoformat(query_ymd[:10])
            except ValueError:
                q_date = None

        if q_date is not None:
            direct_map = self._by_pair.get((from_c, to_c))
            if direct_map and q_date in direct_map:
                return direct_map[q_date][1]
            inv_map = self._by_pair.get((to_c, from_c))
            if inv_map and q_date in inv_map:
                return 1.0 / inv_map[q_date][1]

            best_rank: tuple[int, int, int, str] | None = None
            best_val: float | None = None
            for pair, is_inv in (((from_c, to_c), 0), ((to_c, from_c), 1)):
                dates_list = self._sorted_dates.get(pair)
                pair_map = self._by_pair.get(pair)
                if not dates_list or not pair_map:
                    continue
                pos = bisect.bisect_left(dates_list, q_date)
                for idx in (pos - 1, pos):
                    if 0 <= idx < len(dates_list):
                        c_date = dates_list[idx]
                        c_ymd, raw_r = pair_map[c_date]
                        cand_r = (1.0 / raw_r) if is_inv else raw_r
                        dist = abs((c_date - q_date).days)
                        if max_days is not None and dist > max_days:
                            continue
                        future_pen = 0 if c_date <= q_date else 1
                        rank = (dist, future_pen, is_inv, c_ymd)
                        if best_rank is None or rank < best_rank:
                            best_rank = rank
                            best_val = cand_r
            return best_val

        if max_days is not None:
            return None

        # No query date: prefer latest chronological dated rate (direct over inverse on tie).
        best_latest: tuple[date, int] | None = None
        best_val = None
        for pair, is_inv in (((from_c, to_c), 0), ((to_c, from_c), 1)):
            dates_list = self._sorted_dates.get(pair)
            pair_map = self._by_pair.get(pair)
            if not dates_list or not pair_map:
                continue
            c_date = dates_list[-1]
            _, raw_r = pair_map[c_date]
            cand_r = (1.0 / raw_r) if is_inv else raw_r
            key = (c_date, -is_inv)
            if best_latest is None or key > best_latest:
                best_latest = key
                best_val = cand_r
        return best_val


def parse_ibkr_flex_xml(
    source: bytes | str | Path,
    *,
    blinding_salt_hex: str = "ab" * 32,
    claimed_origin_assurance: OriginAssurance = OriginAssurance.SELF_REPORTED,
    provider_approval_state: ProviderApprovalState = ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    account_scope: AccountScope = AccountScope.UNKNOWN_OFFLINE_SCOPE,
    require_live: bool = True,
    environment_tier: EnvironmentTier | str | None = None,
    max_bytes: int = DEFAULT_MAX_FLEX_BYTES,
    max_elements: int = DEFAULT_MAX_FLEX_ELEMENTS,
    max_section_rows: int = DEFAULT_MAX_SECTION_ROWS,
    fallback_conversion_rates: Mapping[str, float] | None = None,
    fallback_dated_conversion_rates: Mapping[tuple[str, str, str], float] | None = None,
    fallback_closing_inferred_rates: Mapping[tuple[str, str, str], float] | None = None,
) -> CanonicalPortfolioLedger:
    """Stream-parse an IBKR Flex XML payload (UTF-8 or UTF-16) into a ``CanonicalPortfolioLedger``."""
    if isinstance(source, bytes):
        if len(source) > max_bytes:
            raise IbkrFlexParseError(f"Flex XML payload exceeds {max_bytes}-byte limit")
        raw_original = source
    elif isinstance(source, str) and (
        source.lstrip("\ufeff \t\r\n").startswith("<")
        or "\n" in source
        or "\r" in source
        or "\x00" in source
        or len(source) > 1024
    ):
        if len(source) > max_bytes:
            raise IbkrFlexParseError(f"Flex XML payload exceeds {max_bytes}-byte limit")
        raw_original = source.encode("utf-8")
        if len(raw_original) > max_bytes:
            raise IbkrFlexParseError(f"Flex XML payload exceeds {max_bytes}-byte limit")
    else:
        try:
            src_path = Path(source)
            if src_path.stat().st_size > max_bytes:
                raise IbkrFlexParseError(f"Flex XML file exceeds {max_bytes}-byte limit")
            raw_original = src_path.read_bytes()
        except IbkrFlexParseError:
            raise
        except OSError as exc:
            raise IbkrFlexParseError("Unable to read Flex XML input") from exc

    source_sha256 = hashlib.sha256(raw_original).hexdigest()
    xml_utf8_bytes = _decode_and_guard_xml_bytes(raw_original, max_bytes=max_bytes)

    root_tag: str | None = None
    statement_attrs_list: list[dict[str, str]] = []
    enabled_sections: list[str] = []
    seen_sections: set[str] = set()

    nav_rows: list[dict[str, str]] = []
    change_nav_rows: list[dict[str, str]] = []
    prior_pos_by_stmt: list[tuple[int, dict[str, str]]] = []
    open_pos_by_stmt: list[tuple[int, dict[str, str]]] = []
    cash_report_by_stmt: list[tuple[int, dict[str, str]]] = []
    trade_rows: list[dict[str, str]] = []
    cash_tx_rows: list[dict[str, str]] = []
    transfer_rows: list[dict[str, str]] = []
    corp_action_rows: list[dict[str, str]] = []
    option_eae_rows: list[dict[str, str]] = []
    conv_rate_rows: list[dict[str, str]] = []
    aux_fx_rows: list[dict[str, str]] = []

    element_count = 0
    in_statement = False
    current_stmt_idx = -1
    statement_depth: int | None = None
    stack: list[ET.Element] = []
    prior_pos_section_stmts: set[int] = set()

    def _mark_section(sec_name: str) -> None:
        if sec_name not in seen_sections:
            seen_sections.add(sec_name)
            enabled_sections.append(sec_name)

    def _append_bounded(target: list[dict[str, str]], attrs: dict[str, str], label: str) -> None:
        if len(target) >= max_section_rows:
            raise IbkrFlexParseError(f"Flex section {label} exceeds {max_section_rows}-row limit")
        target.append(dict(attrs))

    def _append_bounded_indexed(
        target: list[tuple[int, dict[str, str]]],
        stmt_idx: int,
        attrs: dict[str, str],
        label: str,
    ) -> None:
        if len(target) >= max_section_rows:
            raise IbkrFlexParseError(f"Flex section {label} exceeds {max_section_rows}-row limit")
        target.append((stmt_idx, dict(attrs)))

    try:
        for event, elem in ET.iterparse(BytesIO(xml_utf8_bytes), events=("start", "end")):
            if event == "start":
                element_count += 1
                if element_count > max_elements:
                    raise IbkrFlexParseError(f"Flex XML exceeds {max_elements}-element safety limit")
                stack.append(elem)
                ltag = _local_tag(elem.tag)
                if root_tag is None:
                    root_tag = ltag

                if ltag == "flexstatement":
                    in_statement = True
                    statement_depth = len(stack)
                    current_stmt_idx = len(statement_attrs_list)
                    statement_attrs_list.append(dict(elem.attrib))
                    continue

                if not in_statement:
                    continue

                if (
                    len(aux_fx_rows) < max_section_rows
                    and _first_attr(
                        elem.attrib,
                        (
                            "fxRateToBase",
                            "fxRate",
                            "positionAmountInBase",
                            "amountInBase",
                            "positionValueInBase",
                            "markToMarketInBase",
                            "valueInBase",
                            "costBasisInBase",
                            "proceedsInBase",
                            "netCashInBase",
                        ),
                    )
                    is not None
                ):
                    aux_fx_rows.append(dict(elem.attrib))

                if ltag in {"accountinformation", "acctinfo"}:
                    _mark_section("AccountInformation")
                    acct_ccy = _first_attr(elem.attrib, ("currency", "baseCurrency"))
                    if acct_ccy and current_stmt_idx >= 0:
                        cur_stmt = statement_attrs_list[current_stmt_idx]
                        existing_ccy = _first_attr(cur_stmt, ("baseCurrency", "currency"))
                        if existing_ccy and existing_ccy.upper() != acct_ccy.upper():
                            raise IbkrFlexParseError(
                                f"Conflicting base currencies in FlexStatement ({existing_ccy} vs {acct_ccy})"
                            )
                        cur_stmt.setdefault("baseCurrency", acct_ccy)
                    acct_id = _first_attr(elem.attrib, ("accountId", "acctCode"))
                    if acct_id and current_stmt_idx >= 0:
                        statement_attrs_list[current_stmt_idx].setdefault("accountId", acct_id)
                elif ltag in {"equitysummaryinbase", "equitysummarybyreportdateinbase", "netassetvalue", "nav"}:
                    _mark_section("EquitySummaryInBase")
                    if _first_attr(elem.attrib, ("reportDate", "date", "asOfDate", "toDate", "total", "netLiquidationValue")):
                        _append_bounded(nav_rows, elem.attrib, "EquitySummaryInBase")
                elif ltag in {"changeinnav", "navstatement"}:
                    _mark_section("ChangeInNAV")
                    if _first_attr(elem.attrib, ("twr", "startingValue", "endingValue")):
                        _append_bounded(change_nav_rows, elem.attrib, "ChangeInNAV")
                elif ltag == "priorperiodpositions":
                    if current_stmt_idx >= 0:
                        prior_pos_section_stmts.add(current_stmt_idx)
                elif ltag == "priorperiodposition":
                    if current_stmt_idx >= 0:
                        prior_pos_section_stmts.add(current_stmt_idx)
                    lod = (_first_attr(elem.attrib, ("levelOfDetail",)) or "").upper()
                    if lod not in {"BASE_SUMMARY", "CURRENCY", "ASSET_SUMMARY", "SYMBOL_SUMMARY"}:
                        _append_bounded_indexed(
                            prior_pos_by_stmt, current_stmt_idx, elem.attrib, "PriorPeriodPositions"
                        )
                elif ltag == "openpositions":
                    _mark_section("OpenPositions")
                elif ltag == "openposition":
                    _mark_section("OpenPositions")
                    lod = (_first_attr(elem.attrib, ("levelOfDetail",)) or "").upper()
                    if lod not in {"BASE_SUMMARY", "CURRENCY", "ASSET_SUMMARY", "SYMBOL_SUMMARY"}:
                        _append_bounded_indexed(
                            open_pos_by_stmt, current_stmt_idx, elem.attrib, "OpenPositions"
                        )
                elif ltag == "trades":
                    _mark_section("Trades")
                elif ltag == "trade":
                    _mark_section("Trades")
                    lod = (_first_attr(elem.attrib, ("levelOfDetail",)) or "").upper()
                    if lod not in {
                        "BASE_SUMMARY",
                        "CURRENCY",
                        "ASSET_SUMMARY",
                        "SYMBOL_SUMMARY",
                        "SUMMARY",
                        "WASH_SALE",
                        "CLOSED_LOT",
                        "LOT",
                    }:
                        _append_bounded(trade_rows, elem.attrib, "Trades")
                elif ltag == "cashtransactions":
                    _mark_section("CashTransactions")
                elif ltag == "cashtransaction":
                    _mark_section("CashTransactions")
                    lod = (_first_attr(elem.attrib, ("levelOfDetail",)) or "").upper()
                    if lod not in {
                        "BASE_SUMMARY",
                        "CURRENCY",
                        "ASSET_SUMMARY",
                        "SYMBOL_SUMMARY",
                        "SUMMARY",
                    }:
                        _append_bounded(cash_tx_rows, elem.attrib, "CashTransactions")
                elif ltag == "transfers":
                    _mark_section("Transfers")
                elif ltag == "transfer":
                    _mark_section("Transfers")
                    _append_bounded(transfer_rows, elem.attrib, "Transfers")
                elif ltag == "corporateactions":
                    _mark_section("CorporateActions")
                elif ltag == "corporateaction":
                    _mark_section("CorporateActions")
                    lod = (_first_attr(elem.attrib, ("levelOfDetail",)) or "").upper()
                    if lod not in {
                        "BASE_SUMMARY",
                        "CURRENCY",
                        "ASSET_SUMMARY",
                        "SYMBOL_SUMMARY",
                        "SUMMARY",
                    }:
                        _append_bounded(corp_action_rows, elem.attrib, "CorporateActions")
                elif ltag == "optioneae":
                    _mark_section("OptionEAE")
                    if _first_attr(elem.attrib, ("transactionType", "symbol", "date", "reportDate")):
                        _append_bounded(option_eae_rows, elem.attrib, "OptionEAE")
                elif ltag == "conversionrates":
                    _mark_section("ConversionRates")
                elif ltag == "conversionrate":
                    _mark_section("ConversionRates")
                    _append_bounded(conv_rate_rows, elem.attrib, "ConversionRates")
                elif ltag == "cashreport":
                    _mark_section("CashReport")
                elif ltag == "cashreportcurrency":
                    _mark_section("CashReport")
                    _append_bounded_indexed(
                        cash_report_by_stmt, current_stmt_idx, elem.attrib, "CashReport"
                    )
                continue

            # event == "end": detach & clear immediately for O(1) streaming memory.
            if in_statement and statement_depth == len(stack) and _local_tag(elem.tag) == "flexstatement":
                in_statement = False
            if len(stack) > 1:
                stack[-2].remove(elem)
            elem.clear()
            stack.pop()
    except ET.ParseError as exc:
        raise IbkrFlexParseError("Malformed IBKR Flex XML document") from exc

    if root_tag not in {"flexqueryresponse", "flexstatement"} or not statement_attrs_list:
        raise IbkrFlexParseError("XML document is not a valid IBKR FlexQueryResponse / FlexStatement")

    primary_stmt = statement_attrs_list[0]
    base_ccy = (_first_attr(primary_stmt, ("baseCurrency", "currency")) or "USD").upper()
    if len(base_ccy) != 3 or not base_ccy.isalpha():
        base_ccy = "USD"
    for extra_stmt in statement_attrs_list[1:]:
        extra_ccy_raw = _first_attr(extra_stmt, ("baseCurrency", "currency"))
        if extra_ccy_raw:
            extra_ccy = extra_ccy_raw.upper()
            if len(extra_ccy) == 3 and extra_ccy.isalpha() and extra_ccy != base_ccy:
                raise IbkrFlexParseError(
                    f"Conflicting base currencies across FlexStatement blocks ({base_ccy} vs {extra_ccy})"
                )

    def _stmt_sort_key(idx_and_attrs: tuple[int, dict[str, str]]) -> tuple[str, str, int]:
        idx_val, st_attrs = idx_and_attrs
        s_ts = _parse_flex_timestamp_utc(_first_attr(st_attrs, ("fromDate", "startDate"))) or ""
        e_ts = _parse_flex_timestamp_utc(_first_attr(st_attrs, ("toDate", "endDate"))) or ""
        return (s_ts, e_ts, idx_val)

    ordered_stmts = sorted(enumerate(statement_attrs_list), key=_stmt_sort_key)
    earliest_stmt_idx = ordered_stmts[0][0]
    latest_stmt_idx = ordered_stmts[-1][0]
    prior_pos_rows = [attrs for s_idx, attrs in prior_pos_by_stmt if s_idx == earliest_stmt_idx]
    open_pos_rows = [attrs for s_idx, attrs in open_pos_by_stmt if s_idx == latest_stmt_idx]
    earliest_cash_report_rows = [
        attrs for s_idx, attrs in cash_report_by_stmt if s_idx == earliest_stmt_idx
    ]
    has_prior_pos_qty_attr = any(
        _first_attr(r_pp, ("position", "quantity")) is not None for r_pp in prior_pos_rows
    )
    if earliest_stmt_idx in prior_pos_section_stmts and (
        not prior_pos_rows or has_prior_pos_qty_attr
    ):
        _mark_section("PriorPeriodPositions")

    raw_acct_ids: list[str] = []
    for st in statement_attrs_list:
        aid = _first_attr(st, ("accountId", "acctCode"))
        if aid and aid not in raw_acct_ids:
            raw_acct_ids.append(aid)
    for row in nav_rows:
        aid = _first_attr(row, ("accountId", "acctCode"))
        if aid and aid != "-" and aid not in raw_acct_ids:
            raw_acct_ids.append(aid)
    # A valuation series describes exactly one account: valuations of several accounts are
    # never merged by date, since no file proves every account is valued at every date.
    statements_without_id = sum(
        1 for st in statement_attrs_list if not _first_attr(st, ("accountId", "acctCode"))
    )
    if len(raw_acct_ids) > 1 or (len(statement_attrs_list) > 1 and statements_without_id):
        raise IbkrFlexParseError(
            "This Flex file contains statements for more than one account. A performance "
            "record covers one account: run the Flex query for a single account and upload "
            "one file per account."
        )

    if environment_tier is not None:
        env_tier = EnvironmentTier(environment_tier)
    else:
        env_tier = EnvironmentTier.LIVE_PRODUCTION
        for aid in raw_acct_ids:
            if _PAPER_IBKR_ACCOUNT_RE.match(aid):
                if require_live:
                    raise PaperOrSandboxAccountRejectedError(
                        "IBKR paper trading account (DU/DF prefix) rejected for live verification"
                    )
                env_tier = EnvironmentTier.PAPER_OR_SANDBOX_REJECTED

    raw_tag_seed = ",".join(sorted(raw_acct_ids)) if raw_acct_ids else f"anonymous_flex:{source_sha256[:16]}"
    blinded_tag = compute_blinded_account_tag("ibkr", raw_tag_seed, blinding_salt_hex)

    def _normalize_flex_currency(raw: str | None, default: str) -> str:
        cleaned = (raw or "").strip()
        if not cleaned or cleaned.upper() == "BASE_SUMMARY":
            return default
        if cleaned == "GBp" or cleaned.upper() == "GBX":
            return "GBX"
        return cleaned.upper()

    # 1. EquitySummaryInBase -> NormalizedNavPoint (parsed ahead of FX discovery so closing
    # base-currency stock/position totals can anchor OpenPositions FX when ConversionRates is omitted).
    nav_by_ts: dict[str, NormalizedNavPoint] = {}
    warnings: list[str] = []
    has_base_summary_nav = any(
        (_first_attr(r, ("currency",)) or "").upper() == "BASE_SUMMARY" for r in nav_rows
    )
    _POS_COMPONENT_KEYS = (
        "stock",
        "options",
        "commodities",
        "bonds",
        "notes",
        "funds",
        "warrants",
        "cfd",
    )
    for row in nav_rows:
        row_nav_ccy = (_first_attr(row, ("currency",)) or "").upper()
        if has_base_summary_nav and row_nav_ccy and row_nav_ccy != "BASE_SUMMARY":
            continue
        raw_date = _first_attr(row, ("reportDate", "date", "asOfDate", "toDate"))
        ts = _parse_flex_timestamp_utc(raw_date)
        if ts is not None and raw_date is not None and _DATE_ONLY_RE.match(raw_date):
            # A report-date valuation is the value at the end of that date, so a cash flow
            # during that day falls in the interval that ends at this valuation.
            ts = ts[:10] + "T23:59:59Z"
        total = _parse_flex_float(
            _first_attr(row, ("total", "netLiquidationValue", "netAssetValue", "value", "endingValue"))
        )
        if ts is None or total is None:
            warnings.append("Ignored invalid EquitySummaryInBase row.")
            continue
        prior = nav_by_ts.get(ts)
        if prior is not None and abs(prior.nav_base - total) > 1e-6:
            raise IbkrFlexParseError(
                "This Flex file reports two different account values for the same date; "
                "upload a single statement that covers the period once."
            )
        row_lower_keys = {x.lower() for x in row}
        if "cash" in row_lower_keys:
            cash_raw = _parse_flex_float(_first_attr(row, ("cash",)))
        elif "cashlong" in row_lower_keys or "cashshort" in row_lower_keys:
            cash_raw = (
                (_parse_flex_float(_first_attr(row, ("cashLong",)), default=0.0) or 0.0)
                + (_parse_flex_float(_first_attr(row, ("cashShort",)), default=0.0) or 0.0)
            )
        else:
            cash_raw = None
        slb_cash = _parse_flex_float(_first_attr(row, ("slbCashCollateral",)), default=0.0) or 0.0
        cash_b = (cash_raw + slb_cash) if cash_raw is not None else None
        if any(k in row_lower_keys for k in _POS_COMPONENT_KEYS):
            pos_b = math.fsum(
                _parse_flex_float(_first_attr(row, (k,)), default=0.0) or 0.0
                for k in _POS_COMPONENT_KEYS
            )
        else:
            pos_b = None
        if "dividendaccruals" in row_lower_keys:
            div_acc = _parse_flex_float(_first_attr(row, ("dividendAccruals",)), default=0.0) or 0.0
        else:
            div_acc = (
                (_parse_flex_float(_first_attr(row, ("dividendAccrualsLong",)), default=0.0) or 0.0)
                + (_parse_flex_float(_first_attr(row, ("dividendAccrualsShort",)), default=0.0) or 0.0)
            )
        if "interestaccruals" in row_lower_keys:
            int_acc = _parse_flex_float(_first_attr(row, ("interestAccruals",)), default=0.0) or 0.0
        else:
            int_acc = (
                (_parse_flex_float(_first_attr(row, ("interestAccrualsLong",)), default=0.0) or 0.0)
                + (_parse_flex_float(_first_attr(row, ("interestAccrualsShort",)), default=0.0) or 0.0)
            )
        acc_b = (
            (div_acc + int_acc)
            if any(
                k in row_lower_keys
                for k in (
                    "dividendaccruals",
                    "dividendaccrualslong",
                    "dividendaccrualsshort",
                    "interestaccruals",
                    "interestaccrualslong",
                    "interestaccrualsshort",
                )
            )
            else None
        )
        nav_by_ts[ts] = NormalizedNavPoint(
            timestamp_utc=ts,
            nav_base=total,
            cash_base=cash_b,
            positions_base=pos_b,
            accruals_base=acc_b,
        )
    nav_points = _trim_valuation_series([nav_by_ts[k] for k in sorted(nav_by_ts)])

    # 2. ConversionRates + statement-attested FX discovery (explicit fxRateToBase, *InBase ratios,
    # and spot FX trade executions), kept separate from closing EquitySummaryInBase-inferred FX.
    conversion_rates: dict[str, float] = {}
    undated_conv_rates: dict[str, float] = {}
    latest_conv_meta_by_canon: dict[tuple[str, str], tuple[str, int]] = {}
    dated_fx_index = _DatedFxIndex(fallback_dated_conversion_rates)
    closing_inferred_fx_index = _DatedFxIndex(fallback_closing_inferred_rates)
    end_ref_ymd = nav_points[-1].timestamp_utc[:10] if nav_points else ""
    start_ref_ymd = nav_points[0].timestamp_utc[:10] if nav_points else ""

    def _record_pair_rate(
        from_c: str,
        to_c: str,
        rate_val: float,
        *,
        date_str: str = "",
        source_prio: int = 0,
    ) -> None:
        if not from_c or not to_c or from_c == to_c or rate_val <= 0.0:
            return
        canon = (from_c, to_c) if from_c < to_c else (to_c, from_c)
        prev_meta = latest_conv_meta_by_canon.get(canon)
        cand_meta = (date_str, source_prio)
        if prev_meta is None or cand_meta >= prev_meta:
            latest_conv_meta_by_canon[canon] = cand_meta
            conversion_rates.pop(f"{to_c}/{from_c}", None)
            conversion_rates[f"{from_c}/{to_c}"] = rate_val

    def _lookup_dated_fx(
        query_ymd: str | None,
        from_c: str,
        to_c: str,
        *,
        max_days: int | None = None,
    ) -> float | None:
        return dated_fx_index.lookup(query_ymd, from_c, to_c, max_days=max_days)

    for row in conv_rate_rows:
        from_ccy = _normalize_flex_currency(_first_attr(row, ("fromCurrency",)), "")
        to_ccy = _normalize_flex_currency(_first_attr(row, ("toCurrency",)), "")
        rate = _parse_flex_float(_first_attr(row, ("rate",)))
        raw_cr_date = _first_attr(row, ("reportDate", "date", "asOfDate"))
        cr_ts = _parse_flex_timestamp_utc(raw_cr_date)
        if from_ccy and to_ccy and rate is not None and rate > 0.0:
            d_str = cr_ts[:10] if cr_ts is not None else ""
            if d_str:
                dated_fx_index.add(d_str, from_ccy, to_ccy, rate, overwrite=True)
            else:
                undated_conv_rates.pop(f"{to_ccy}/{from_ccy}", None)
                undated_conv_rates[f"{from_ccy}/{to_ccy}"] = rate
            _record_pair_rate(from_ccy, to_ccy, rate, date_str=d_str, source_prio=3)

    def _stmt_boundary_ymd(stmt_idx: int, attr_names: tuple[str, ...], fallback_ymd: str) -> str:
        if 0 <= stmt_idx < len(statement_attrs_list):
            b_ts = _parse_flex_timestamp_utc(_first_attr(statement_attrs_list[stmt_idx], attr_names))
            if b_ts is not None:
                return b_ts[:10]
        return fallback_ymd

    # Pre-index explicit row-level fxRateToBase and *InBase ratios across all statement elements
    # (including rollup rows and auxiliary sections) so queries omitting <ConversionRates> resolve FX.
    prescan_row_sources: list[tuple[dict[str, str], str]] = []
    for s_row in aux_fx_rows:
        prescan_row_sources.append((s_row, ""))
    for s_idx, s_row in prior_pos_by_stmt:
        prescan_row_sources.append(
            (s_row, _stmt_boundary_ymd(s_idx, ("fromDate", "startDate"), start_ref_ymd))
        )
    for s_idx, s_row in open_pos_by_stmt:
        prescan_row_sources.append(
            (s_row, _stmt_boundary_ymd(s_idx, ("toDate", "endDate"), end_ref_ymd))
        )
    for s_idx, s_row in cash_report_by_stmt:
        prescan_row_sources.append(
            (s_row, _stmt_boundary_ymd(s_idx, ("toDate", "endDate"), end_ref_ymd))
        )
    for section_rows in (
        trade_rows,
        cash_tx_rows,
        transfer_rows,
        corp_action_rows,
        option_eae_rows,
    ):
        for s_row in section_rows:
            prescan_row_sources.append((s_row, ""))

    for s_row, boundary_ymd in prescan_row_sources:
        s_ccy = _normalize_flex_currency(
            _first_attr(s_row, ("currency", "currencyPrimary")), base_ccy
        )
        if not s_ccy or s_ccy == base_ccy:
            continue
        s_fx = _extract_row_implied_fx(s_row)
        if s_fx is None or s_fx <= 0.0:
            continue
        s_ts = _parse_flex_timestamp_utc(
            _first_attr(
                s_row,
                (
                    "dateTime",
                    "reportDate",
                    "tradeDate",
                    "settleDate",
                    "fromDate",
                    "toDate",
                    "asOfDate",
                    "date",
                ),
            )
        )
        s_date = s_ts[:10] if s_ts is not None else boundary_ymd
        if s_date:
            dated_fx_index.add(s_date, s_ccy, base_ccy, s_fx, overwrite=False)
        _record_pair_rate(s_ccy, base_ccy, s_fx, date_str=s_date, source_prio=2)

    # Extract dated FX execution rates from spot FX <Trade assetCategory="CASH"> pairs (e.g. EUR.USD,
    # EUR.GBP, EUR.CHF, and 2-hop cross pairs like USD.CHF when neither leg is baseCurrency).
    spot_fx_cross_obs: list[tuple[str, str, str, float]] = []
    for tr_row in trade_rows:
        tr_cat = (_first_attr(tr_row, ("assetCategory", "assetClass")) or "").strip().upper()
        if tr_cat != "CASH":
            continue
        pair = _parse_fx_pair_symbol(_first_text_attr(tr_row, ("symbol", "underlyingSymbol")))
        tr_px = _parse_flex_float(_first_attr(tr_row, ("tradePrice", "price")))
        if pair is None or tr_px is None or tr_px <= 0.0:
            continue
        fx_b, fx_q = pair
        tr_ts = _parse_flex_timestamp_utc(
            _first_attr(tr_row, ("dateTime", "tradeDate", "reportDate", "date"))
        )
        t_ymd = tr_ts[:10] if tr_ts is not None else ""
        if fx_b == base_ccy and fx_q != base_ccy:
            implied_q_to_base = 1.0 / tr_px
            if t_ymd:
                dated_fx_index.add(t_ymd, fx_q, base_ccy, implied_q_to_base, overwrite=False)
            if fx_q == "USD" or not end_ref_ymd or (
                t_ymd and abs((date.fromisoformat(end_ref_ymd) - date.fromisoformat(t_ymd)).days) <= 7
            ):
                _record_pair_rate(fx_q, base_ccy, implied_q_to_base, date_str=t_ymd, source_prio=1)
        elif fx_q == base_ccy and fx_b != base_ccy:
            implied_b_to_base = tr_px
            if t_ymd:
                dated_fx_index.add(t_ymd, fx_b, base_ccy, implied_b_to_base, overwrite=False)
            if fx_b == "USD" or not end_ref_ymd or (
                t_ymd and abs((date.fromisoformat(end_ref_ymd) - date.fromisoformat(t_ymd)).days) <= 7
            ):
                _record_pair_rate(fx_b, base_ccy, implied_b_to_base, date_str=t_ymd, source_prio=1)
        elif fx_b != fx_q:
            spot_fx_cross_obs.append((t_ymd, fx_b, fx_q, tr_px))

    for t_ymd, fx_b, fx_q, tr_px in spot_fx_cross_obs:
        r_b = _lookup_dated_fx(t_ymd or None, fx_b, base_ccy)
        r_q = _lookup_dated_fx(t_ymd or None, fx_q, base_ccy)
        if r_b is not None and r_b > 0.0 and r_q is None:
            implied_q = r_b / tr_px
            if t_ymd:
                dated_fx_index.add(t_ymd, fx_q, base_ccy, implied_q, overwrite=False)
        elif r_q is not None and r_q > 0.0 and r_b is None:
            implied_b = tr_px * r_q
            if t_ymd:
                dated_fx_index.add(t_ymd, fx_b, base_ccy, implied_b, overwrite=False)

    _SUMMARY_ROLLUP_LODS = {
        "BASE_SUMMARY",
        "CURRENCY",
        "ASSET_SUMMARY",
        "SYMBOL_SUMMARY",
    }

    def _scope_position_rows(
        rows: list[dict[str, str]], boundary: str
    ) -> list[tuple[dict[str, str], str | None]]:
        non_rollup: list[tuple[dict[str, str], str | None]] = []
        dated_ymds: list[str] = []
        for r in rows:
            lod = (_first_attr(r, ("levelOfDetail",)) or "").upper()
            if lod in _SUMMARY_ROLLUP_LODS:
                continue
            pos_ts = _parse_flex_timestamp_utc(_first_attr(r, ("reportDate", "date", "asOfDate")))
            if pos_ts is not None:
                dated_ymds.append(pos_ts[:10])
            non_rollup.append((r, pos_ts))
        target_ymd: str | None = None
        if dated_ymds:
            target_ymd = min(dated_ymds) if boundary == "prior" else max(dated_ymds)
        if boundary == "prior" and target_ymd is not None and nav_points:
            first_nav_ymd = nav_points[0].timestamp_utc[:10]
            if (date.fromisoformat(target_ymd) - date.fromisoformat(first_nav_ymd)).days > 5:
                return []
        stale_dated_ending = False
        if boundary == "ending" and target_ymd is not None and nav_points:
            last_pt = nav_points[-1]
            last_nav_ymd = last_pt.timestamp_utc[:10]
            if target_ymd < last_nav_ymd and (
                (last_pt.positions_base is not None and abs(last_pt.positions_base) <= 1e-6)
                or (date.fromisoformat(last_nav_ymd) - date.fromisoformat(target_ymd)).days > 4
            ):
                stale_dated_ending = True
        scoped = [
            (r, pos_ts)
            for r, pos_ts in non_rollup
            if (
                pos_ts is None
                if stale_dated_ending
                else (target_ymd is None or pos_ts is None or pos_ts[:10] == target_ymd)
            )
        ]
        has_summary = any(
            (_first_attr(r, ("levelOfDetail",)) or "").upper() == "SUMMARY"
            for r, _ in scoped
        )
        return [
            (r, pos_ts)
            for r, pos_ts in scoped
            if not (
                has_summary
                and (_first_attr(r, ("levelOfDetail",)) or "").upper() not in {"", "SUMMARY"}
            )
        ]

    # Anchor closing OpenPositions FX on last_nav_ymd when ConversionRates and row fxRateToBase are omitted,
    # keeping closing-snapshot inference separate from dated_fx_index so it never back-propagates onto
    # historical trades (>31d) or external capital flows (strict S6).
    if nav_points and open_pos_rows and not conv_rate_rows:
        last_pt = nav_points[-1]
        last_nav_ymd = last_pt.timestamp_utc[:10]
        scoped_open = _scope_position_rows(open_pos_rows, "ending")
        has_explicit_open_fx = any(
            (_extract_row_implied_fx(r) or 0.0) > 0.0
            and _normalize_flex_currency(_first_attr(r, ("currency", "currencyPrimary")), base_ccy) != base_ccy
            for r, _ in scoped_open
        )
        if not has_explicit_open_fx:
            sum_mv_by_ccy: dict[str, float] = {}
            sum_pct_by_ccy: dict[str, float] = {}
            for r, _ in scoped_open:
                if _first_attr(r, ("position", "quantity")) is None:
                    continue
                sym = _first_text_attr(r, ("symbol", "underlyingSymbol", "description"))
                if not sym:
                    continue
                ac = _map_ibkr_asset_class(
                    _first_attr(r, ("assetCategory", "assetClass")),
                    sub_cat=_first_attr(r, ("subCategory",)),
                    symbol=sym,
                )
                if ac == AssetClass.CASH:
                    continue
                qty = _parse_flex_float(_first_attr(r, ("position", "quantity")), default=0.0) or 0.0
                mult = _parse_flex_float(_first_attr(r, ("multiplier",)))
                eff_mult = mult if mult and mult > 0 else 1.0
                raw_mv_attr = _first_attr(r, ("positionValue", "markToMarket", "marketValue", "value"))
                if raw_mv_attr is not None:
                    mv = _parse_flex_float(raw_mv_attr, default=0.0) or 0.0
                else:
                    mark_px = _parse_flex_float(_first_attr(r, ("markPrice", "closePrice")), default=None)
                    mv = (qty * mark_px * eff_mult) if mark_px is not None else 0.0
                ccy = _normalize_flex_currency(_first_attr(r, ("currency", "currencyPrimary")), base_ccy)
                sum_mv_by_ccy[ccy] = sum_mv_by_ccy.get(ccy, 0.0) + mv
                pct_nav = _parse_flex_float(_first_attr(r, ("percentOfNAV",)), default=0.0) or 0.0
                sum_pct_by_ccy[ccy] = sum_pct_by_ccy.get(ccy, 0.0) + pct_nav

            foreign_open_ccys = [
                c for c, mv_tot in sum_mv_by_ccy.items() if c != base_ccy and abs(mv_tot) > 1e-6
            ]
            raw_dated = dated_fx_index.raw_items()
            for f_ccy in foreign_open_ccys:
                if (last_nav_ymd, f_ccy, base_ccy) in raw_dated:
                    continue
                mv_tot = sum_mv_by_ccy[f_ccy]
                pct_tot = sum_pct_by_ccy.get(f_ccy, 0.0)
                prior_ref = _lookup_dated_fx(last_nav_ymd, f_ccy, base_ccy)
                if (
                    prior_ref is not None
                    and last_pt.nav_base > 0.0
                    and abs(pct_tot) >= 0.50
                    and (mv_tot * pct_tot) > 0.0
                ):
                    cand_fx = (pct_tot / 100.0) * last_pt.nav_base / mv_tot
                    if cand_fx > 0.0 and (0.65 * prior_ref <= cand_fx <= 1.50 * prior_ref):
                        closing_inferred_fx_index.add(
                            last_nav_ymd, f_ccy, base_ccy, cand_fx, overwrite=False
                        )

            if (
                foreign_open_ccys
                and last_pt.positions_base is not None
                and last_pt.positions_base > 0.0
            ):
                dom_ccy = max(
                    foreign_open_ccys,
                    key=lambda c: abs(sum_mv_by_ccy[c])
                    * (
                        closing_inferred_fx_index.lookup(last_nav_ymd, c, base_ccy, max_days=4)
                        or _lookup_dated_fx(last_nav_ymd, c, base_ccy)
                        or 1.0
                    ),
                )
                other_rates: dict[str, float] = {}
                others_ok = True
                for o_ccy in foreign_open_ccys:
                    if o_ccy == dom_ccy:
                        continue
                    r_o = closing_inferred_fx_index.lookup(
                        last_nav_ymd, o_ccy, base_ccy, max_days=4
                    ) or _lookup_dated_fx(last_nav_ymd, o_ccy, base_ccy)
                    if r_o is None and fallback_conversion_rates:
                        r_o = fallback_conversion_rates.get(f"{o_ccy}/{base_ccy}")
                        if r_o is None and fallback_conversion_rates.get(f"{base_ccy}/{o_ccy}"):
                            r_o = 1.0 / fallback_conversion_rates[f"{base_ccy}/{o_ccy}"]
                    if r_o is None or r_o <= 0.0:
                        others_ok = False
                        break
                    other_rates[o_ccy] = r_o
                if others_ok and abs(sum_mv_by_ccy[dom_ccy]) > 1e-6:
                    rem_base = (
                        float(last_pt.positions_base)
                        - sum_mv_by_ccy.get(base_ccy, 0.0)
                        - math.fsum(sum_mv_by_ccy[c] * r_v for c, r_v in other_rates.items())
                    )
                    exact_dom_fx = rem_base / sum_mv_by_ccy[dom_ccy]
                    dom_ref = _lookup_dated_fx(last_nav_ymd, dom_ccy, base_ccy)
                    if (
                        exact_dom_fx > 0.0
                        and math.isfinite(exact_dom_fx)
                        and (sum_mv_by_ccy[dom_ccy] * rem_base) > 0.0
                        and (dom_ref is None or (0.65 * dom_ref <= exact_dom_fx <= 1.50 * dom_ref))
                    ):
                        closing_inferred_fx_index.add(
                            last_nav_ymd, dom_ccy, base_ccy, exact_dom_fx, overwrite=True
                        )

    if base_ccy != "USD" and f"USD/{base_ccy}" not in conversion_rates and f"{base_ccy}/USD" not in conversion_rates:
        usd_latest = _lookup_dated_fx(end_ref_ymd or None, "USD", base_ccy)
        if usd_latest is not None and usd_latest > 0.0:
            _record_pair_rate("USD", base_ccy, usd_latest, date_str=end_ref_ymd, source_prio=0)

    def _lookup_undated_conv_pair(from_c: str, to_c: str) -> float | None:
        d_val = undated_conv_rates.get(f"{from_c}/{to_c}")
        if d_val is not None and d_val > 0.0:
            return float(d_val)
        i_val = undated_conv_rates.get(f"{to_c}/{from_c}")
        if i_val is not None and i_val > 0.0:
            return 1.0 / float(i_val)
        return None

    def _lookup_fallback_pair(from_c: str, to_c: str) -> float | None:
        if not fallback_conversion_rates:
            return None
        d_val = fallback_conversion_rates.get(f"{from_c}/{to_c}")
        if d_val is not None and d_val > 0.0:
            return float(d_val)
        i_val = fallback_conversion_rates.get(f"{to_c}/{from_c}")
        if i_val is not None and i_val > 0.0:
            return 1.0 / float(i_val)
        return None

    omitted_fx_currencies: list[str] = []

    def _resolve_fx_optional(
        attrs: dict[str, str],
        ccy: str,
        *,
        row_ts: str | None = None,
        track_omitted: bool = True,
        is_capital_flow: bool = False,
        is_position_snapshot: bool = False,
    ) -> float | None:
        ccy_upper = _normalize_flex_currency(ccy, base_ccy)
        date_key = row_ts[:10] if row_ts else None
        explicit = _parse_flex_float(_first_attr(attrs, ("fxRateToBase", "fxRate")))
        if explicit is not None and explicit > 0.0:
            if ccy_upper != base_ccy:
                if date_key is not None:
                    dated_fx_index.add(date_key, ccy_upper, base_ccy, explicit, overwrite=False)
                _record_pair_rate(
                    ccy_upper,
                    base_ccy,
                    explicit,
                    date_str=date_key or "",
                    source_prio=2,
                )
            return explicit
        if ccy_upper == base_ccy:
            return 1.0
        implied = _extract_row_implied_fx(attrs)
        if implied is not None and implied > 0.0:
            if ccy_upper != base_ccy:
                if date_key is not None:
                    dated_fx_index.add(date_key, ccy_upper, base_ccy, implied, overwrite=False)
                _record_pair_rate(
                    ccy_upper,
                    base_ccy,
                    implied,
                    date_str=date_key or "",
                    source_prio=2,
                )
            return implied

        if is_capital_flow:
            cap_near = _lookup_dated_fx(date_key, ccy_upper, base_ccy, max_days=7)
            if cap_near is not None and cap_near > 0.0:
                return cap_near
            u_cap = _lookup_undated_conv_pair(ccy_upper, base_ccy)
            if u_cap is not None and u_cap > 0.0:
                return u_cap
            fb_cap = _lookup_fallback_pair(ccy_upper, base_ccy)
            if fb_cap is not None and fb_cap > 0.0:
                return fb_cap
            if ccy_upper == "GBX":
                if base_ccy == "GBP":
                    return 0.01
                gbp_cap = _lookup_dated_fx(date_key, "GBP", base_ccy, max_days=7)
                if gbp_cap is not None and gbp_cap > 0.0:
                    return 0.01 * gbp_cap
                gbp_u = _lookup_undated_conv_pair("GBP", base_ccy)
                if gbp_u is not None and gbp_u > 0.0:
                    return 0.01 * gbp_u
                fb_gbp = _lookup_fallback_pair("GBP", base_ccy)
                if fb_gbp is not None and fb_gbp > 0.0:
                    return 0.01 * fb_gbp
            if track_omitted and ccy_upper not in omitted_fx_currencies:
                omitted_fx_currencies.append(ccy_upper)
            return None

        if is_position_snapshot:
            same_day = _lookup_dated_fx(date_key, ccy_upper, base_ccy, max_days=0)
            if same_day is not None and same_day > 0.0:
                return same_day
            snap_inferred = closing_inferred_fx_index.lookup(
                date_key, ccy_upper, base_ccy, max_days=4
            )
            if snap_inferred is not None and snap_inferred > 0.0:
                return snap_inferred
        nearest = _lookup_dated_fx(date_key, ccy_upper, base_ccy)
        if nearest is not None and nearest > 0.0:
            return nearest
        closing_near = closing_inferred_fx_index.lookup(
            date_key, ccy_upper, base_ccy, max_days=31
        )
        if closing_near is not None and closing_near > 0.0:
            return closing_near
        direct = conversion_rates.get(f"{ccy_upper}/{base_ccy}")
        if direct is not None and direct > 0.0:
            return direct
        inverse = conversion_rates.get(f"{base_ccy}/{ccy_upper}")
        if inverse is not None and inverse > 0.0:
            return 1.0 / inverse
        fb_direct = _lookup_fallback_pair(ccy_upper, base_ccy)
        if fb_direct is not None and fb_direct > 0.0:
            return fb_direct
        if ccy_upper == "GBX":
            if base_ccy == "GBP":
                return 0.01
            if is_position_snapshot:
                gbp_same = _lookup_dated_fx(date_key, "GBP", base_ccy, max_days=0)
                if gbp_same is not None and gbp_same > 0.0:
                    return 0.01 * gbp_same
                gbp_snap = closing_inferred_fx_index.lookup(
                    date_key, "GBP", base_ccy, max_days=4
                )
                if gbp_snap is not None and gbp_snap > 0.0:
                    return 0.01 * gbp_snap
            gbp_dated = _lookup_dated_fx(date_key, "GBP", base_ccy)
            if gbp_dated is not None and gbp_dated > 0.0:
                return 0.01 * gbp_dated
            gbp_cnear = closing_inferred_fx_index.lookup(
                date_key, "GBP", base_ccy, max_days=31
            )
            if gbp_cnear is not None and gbp_cnear > 0.0:
                return 0.01 * gbp_cnear
            gbp_direct = conversion_rates.get(f"GBP/{base_ccy}")
            if gbp_direct is not None and gbp_direct > 0.0:
                return 0.01 * gbp_direct
            gbp_inv = conversion_rates.get(f"{base_ccy}/GBP")
            if gbp_inv is not None and gbp_inv > 0.0:
                return 0.01 / gbp_inv
            fb_gbp = _lookup_fallback_pair("GBP", base_ccy)
            if fb_gbp is not None and fb_gbp > 0.0:
                return 0.01 * fb_gbp
        if track_omitted and ccy_upper not in omitted_fx_currencies:
            omitted_fx_currencies.append(ccy_upper)
        return None

    # 3. PriorPeriodPositions & OpenPositions
    def _parse_positions(rows: list[dict[str, str]], boundary: str) -> list[NormalizedPosition]:
        scoped_rows = _scope_position_rows(rows, boundary)
        out: list[NormalizedPosition] = []
        for r, pos_ts in scoped_rows:
            if _first_attr(r, ("position", "quantity")) is None:
                continue
            sym = _first_text_attr(r, ("symbol", "underlyingSymbol", "description"))
            if not sym:
                continue
            qty = _parse_flex_float(_first_attr(r, ("position", "quantity")), default=0.0) or 0.0
            cost = _parse_flex_float(_first_attr(r, ("costBasisMoney", "costBasis", "costBasisPrice")), default=0.0) or 0.0
            mult = _parse_flex_float(_first_attr(r, ("multiplier",)))
            eff_mult = mult if mult and mult > 0 else 1.0
            raw_mv_attr = _first_attr(r, ("positionValue", "markToMarket", "marketValue", "value"))
            if raw_mv_attr is not None:
                mv = _parse_flex_float(raw_mv_attr, default=0.0) or 0.0
            else:
                mark_px = _parse_flex_float(_first_attr(r, ("markPrice", "closePrice")), default=None)
                mv = (qty * mark_px * eff_mult) if mark_px is not None else 0.0
            ccy = _normalize_flex_currency(_first_attr(r, ("currency", "currencyPrimary")), base_ccy)
            eff_pos_ts = pos_ts or (
                (nav_points[-1].timestamp_utc if boundary == "ending" else nav_points[0].timestamp_utc)
                if nav_points
                else None
            )
            fx = _resolve_fx_optional(r, ccy, row_ts=eff_pos_ts, is_position_snapshot=True)
            ac = _map_ibkr_asset_class(
                _first_attr(r, ("assetCategory", "assetClass")),
                sub_cat=_first_attr(r, ("subCategory",)),
                symbol=sym,
            )
            put_call = _first_attr(r, ("putCall",))
            opt_right = put_call.upper()[0] if put_call and put_call.upper()[0] in {"C", "P"} else None
            out.append(
                NormalizedPosition(
                    prior_period_or_ending=boundary,
                    symbol=sym,
                    asset_class=ac,
                    quantity=qty,
                    cost_basis=cost,
                    market_value=mv,
                    currency=ccy,
                    fx_rate_to_base=fx,
                    multiplier=mult if mult and mult > 0 else None,
                    isin=_first_text_attr(r, ("isin",)),
                    underlying_symbol=_first_text_attr(r, ("underlyingSymbol",)),
                    option_right=opt_right,
                    strike=_parse_flex_float(_first_attr(r, ("strike",))),
                    expiry=_first_text_attr(r, ("expiry",)),
                )
            )
        return out

    prior_positions = _parse_positions(prior_pos_rows, "prior")
    if (
        not prior_positions
        and not has_prior_pos_qty_attr
        and prior_pos_rows
        and nav_points
        and (nav_points[0].positions_base or 0.0) > 1e-6
    ):
        scoped_prior_price_only = _scope_position_rows(prior_pos_rows, "prior")
        price_candidates: list[tuple[dict[str, str], str, float]] = []
        seen_opening_syms: set[str] = set()
        for r_pp, _ in scoped_prior_price_only:
            sym_pp = _first_text_attr(r_pp, ("symbol", "underlyingSymbol"))
            px_pp = _parse_flex_float(_first_attr(r_pp, ("price", "markPrice", "closePrice")))
            if sym_pp and px_pp is not None and px_pp > 0.0 and sym_pp.upper() not in seen_opening_syms:
                seen_opening_syms.add(sym_pp.upper())
                price_candidates.append((r_pp, sym_pp, px_pp))
        if len(price_candidates) == 1:
            r_pp0, sym_pp0, px_pp0 = price_candidates[0]
            open_nav_ts = nav_points[0].timestamp_utc
            traded_on_or_before_open = any(
                (_first_text_attr(tr_r, ("symbol", "underlyingSymbol")) or "").upper() == sym_pp0.upper()
                and (
                    (
                        t_parsed := _parse_flex_timestamp_utc(
                            _first_attr(tr_r, ("dateTime", "tradeDate", "reportDate", "date"))
                        )
                    )
                    is not None
                    and t_parsed <= open_nav_ts
                )
                for tr_r in trade_rows
            )
            if not traded_on_or_before_open:
                ccy_pp0 = _normalize_flex_currency(
                    _first_attr(r_pp0, ("currency", "currencyPrimary")), base_ccy
                )
                fx_pp0 = _resolve_fx_optional(r_pp0, ccy_pp0, row_ts=open_nav_ts)
                if fx_pp0 is not None and fx_pp0 > 0.0:
                    mult_pp0 = _parse_flex_float(_first_attr(r_pp0, ("multiplier",)))
                    eff_mult_pp0 = mult_pp0 if mult_pp0 and mult_pp0 > 0 else 1.0
                    mv_native_pp0 = float(nav_points[0].positions_base or 0.0) / fx_pp0
                    qty_est_pp0 = mv_native_pp0 / (px_pp0 * eff_mult_pp0)
                    ac_pp0 = _map_ibkr_asset_class(
                        _first_attr(r_pp0, ("assetCategory", "assetClass")),
                        sub_cat=_first_attr(r_pp0, ("subCategory",)),
                        symbol=sym_pp0,
                    )
                    prior_positions.append(
                        NormalizedPosition(
                            prior_period_or_ending="prior",
                            symbol=sym_pp0,
                            asset_class=ac_pp0,
                            quantity=qty_est_pp0,
                            cost_basis=0.0,
                            market_value=mv_native_pp0,
                            currency=ccy_pp0,
                            fx_rate_to_base=fx_pp0,
                            multiplier=mult_pp0 if mult_pp0 and mult_pp0 > 0 else None,
                            isin=_first_text_attr(r_pp0, ("isin",)),
                        )
                    )
                    warnings.append(INFERRED_SINGLE_PRIOR_POSITION_WARNING)
    if (
        not prior_positions
        and not has_prior_pos_qty_attr
        and prior_pos_rows
    ):
        scoped_pp_for_syms = _scope_position_rows(prior_pos_rows, "prior") or [
            (r_pp, None) for r_pp in prior_pos_rows
        ]
        omitted_pp_syms = sorted(
            {
                sym_u
                for r_pp, _ in scoped_pp_for_syms
                if (
                    sym_u := (
                        _first_text_attr(r_pp, ("symbol", "underlyingSymbol", "description")) or ""
                    )
                    .strip()
                    .upper()
                )
            }
        )
        enabled_sections = [s for s in enabled_sections if s != "PriorPeriodPositions"]
        warnings.append(OMITTED_PRIOR_POSITION_QTY_WARNING)
        if omitted_pp_syms:
            warnings.append(f"{OMITTED_PRIOR_POSITION_SYMBOLS_PREFIX}{','.join(omitted_pp_syms)}")

    existing_prior_cash_ccys = {
        pos.currency for pos in prior_positions if pos.asset_class == AssetClass.CASH
    }
    for cr_row in earliest_cash_report_rows:
        cr_lod = (_first_attr(cr_row, ("levelOfDetail",)) or "").upper()
        raw_cr_ccy = (_first_attr(cr_row, ("currency", "currencyPrimary")) or "").strip()
        if not raw_cr_ccy or raw_cr_ccy.upper() == "BASE_SUMMARY" or cr_lod == "BASE_SUMMARY":
            continue
        cr_ccy = _normalize_flex_currency(raw_cr_ccy, base_ccy)
        if cr_ccy in existing_prior_cash_ccys:
            continue
        start_cash = _parse_flex_float(
            _first_attr(cr_row, ("startingCash", "startingSettledCash")),
            default=None,
        )
        if start_cash is None or abs(start_cash) <= 1e-9:
            continue
        cr_from_ts = _parse_flex_timestamp_utc(
            _first_attr(cr_row, ("fromDate", "reportDate", "date"))
        )
        cr_fx = _resolve_fx_optional(cr_row, cr_ccy, row_ts=cr_from_ts)
        prior_positions.append(
            NormalizedPosition(
                prior_period_or_ending="prior",
                symbol=cr_ccy,
                asset_class=AssetClass.CASH,
                quantity=start_cash,
                cost_basis=start_cash,
                market_value=start_cash,
                currency=cr_ccy,
                fx_rate_to_base=cr_fx,
            )
        )
        existing_prior_cash_ccys.add(cr_ccy)
    ending_positions = _parse_positions(open_pos_rows, "ending")
    open_or_prior_fx_pairs = {
        pair
        for pos in (*prior_positions, *ending_positions)
        if pos.asset_class == AssetClass.FX
        and abs(pos.quantity) > 1e-12
        and (pair := _parse_fx_pair_symbol(pos.symbol)) is not None
    }

    # 4. Trades
    has_exec_lod = any(
        (_first_attr(r, ("levelOfDetail",)) or "").upper() == "EXECUTION" for r in trade_rows
    )
    has_order_lod = any(
        (_first_attr(r, ("levelOfDetail",)) or "").upper() == "ORDER" for r in trade_rows
    )
    trades_by_id: dict[str, NormalizedTrade] = {}
    for idx, r in enumerate(trade_rows):
        lod = (_first_attr(r, ("levelOfDetail",)) or "").upper()
        if lod in (_SUMMARY_ROLLUP_LODS | {"SUMMARY", "WASH_SALE", "CLOSED_LOT", "LOT"}):
            continue
        if has_exec_lod and lod and lod != "EXECUTION":
            continue
        if not has_exec_lod and has_order_lod and lod and lod != "ORDER":
            continue
        ts = _parse_flex_timestamp_utc(_first_attr(r, ("dateTime", "tradeDate", "reportDate", "date")))
        sym = _first_text_attr(r, ("symbol", "underlyingSymbol", "description"))
        if ts is None or not sym:
            continue
        raw_qty = _parse_flex_float(_first_attr(r, ("quantity", "shares")), default=0.0) or 0.0
        side_raw = _first_attr(r, ("buySell", "side"))
        if not side_raw:
            side_raw = "BUY" if raw_qty >= 0.0 else "SELL"
        # Strip cancel suffix like "BUY (Ca.)" if present
        side_token = side_raw.split()[0]
        price = abs(_parse_flex_float(_first_attr(r, ("tradePrice", "price")), default=0.0) or 0.0)
        ccy = _normalize_flex_currency(_first_attr(r, ("currency", "currencyPrimary")), base_ccy)
        fx = _resolve_fx_optional(r, ccy, row_ts=ts)
        raw_cat_str = (_first_attr(r, ("assetCategory", "assetClass")) or "STK").strip().upper()
        exchange_text = _first_text_attr(r, ("exchange", "listingExchange"))
        if raw_cat_str == "CASH":
            if (exchange_text or "").upper() == "FXCONV" or (
                _parse_fx_pair_symbol(sym) not in open_or_prior_fx_pairs
            ):
                ac = AssetClass.CASH
            else:
                ac = AssetClass.FX
        else:
            ac = _map_ibkr_asset_class(
                raw_cat_str,
                sub_cat=_first_attr(r, ("subCategory",)),
                symbol=sym,
            )
        mult = _parse_flex_float(_first_attr(r, ("multiplier",)))
        comm_raw = abs(_parse_flex_float(_first_attr(r, ("ibCommission", "commission")), default=0.0) or 0.0)
        comm_ccy_attr = _first_attr(r, ("ibCommissionCurrency", "commissionCurrency"))
        effective_comm_ccy_attr = comm_ccy_attr or (base_ccy if raw_cat_str == "CASH" else None)
        if comm_raw > 0.0 and effective_comm_ccy_attr:
            comm_ccy = _normalize_flex_currency(effective_comm_ccy_attr, ccy)
            if comm_ccy != ccy:
                comm_fx = _resolve_fx_optional({}, comm_ccy, row_ts=ts, track_omitted=False)
                if fx is not None and fx > 0.0 and comm_fx is not None and comm_fx > 0.0:
                    comm = comm_raw * (comm_fx / fx)
                else:
                    comm = 0.0
            else:
                comm = comm_raw
        else:
            comm = comm_raw
        raw_tax_attr = _first_attr(r, ("taxes", "tax"))
        tax_raw = abs(_parse_flex_float(raw_tax_attr, default=0.0) or 0.0)
        tax_ccy_attr = _first_attr(r, ("taxCurrency",))
        if tax_raw > 0.0 and tax_ccy_attr:
            tax_ccy = _normalize_flex_currency(tax_ccy_attr, ccy)
            if tax_ccy != ccy:
                tax_fx = _resolve_fx_optional({}, tax_ccy, row_ts=ts, track_omitted=False)
                if fx is not None and fx > 0.0 and tax_fx is not None and tax_fx > 0.0:
                    tax = tax_raw * (tax_fx / fx)
                else:
                    tax = 0.0
            else:
                tax = tax_raw
        elif (
            raw_tax_attr is None
            and ac in {AssetClass.EQUITY, AssetClass.ETF}
            and abs(_parse_flex_float(_first_attr(r, ("accruedInt",)), default=0.0) or 0.0) <= 1e-9
            and (not comm_ccy_attr or _normalize_flex_currency(comm_ccy_attr, ccy) == ccy)
        ):
            proc_signed = _parse_flex_float(_first_attr(r, ("proceeds",)))
            nc_signed = _parse_flex_float(_first_attr(r, ("netCash",)))
            if proc_signed is not None and nc_signed is not None and abs(proc_signed) > 0.0:
                implied_tax = (proc_signed - comm_raw) - nc_signed
                if 1e-4 < implied_tax <= 0.05 * abs(proc_signed):
                    tax = implied_tax
                else:
                    tax = 0.0
            else:
                tax = 0.0
        else:
            tax = tax_raw
        entry_id = (
            _first_text_attr(r, ("ibExecID", "tradeID"))
            or f"flex-trade-{source_sha256[:12]}-{idx}"
        )
        put_call = _first_attr(r, ("putCall",))
        opt_right = put_call.upper()[0] if put_call and put_call.upper()[0] in {"C", "P"} else None
        trades_by_id[entry_id] = NormalizedTrade(
            venue="ibkr",
            native_entry_id=entry_id,
            symbol=sym,
            asset_class=ac,
            side=side_token,
            quantity=abs(raw_qty),
            price=price,
            timestamp_utc=ts,
            currency=ccy,
            fx_rate_to_base=fx,
            multiplier=mult if mult and mult > 0 else None,
            commission=comm,
            tax=tax,
            isin=_first_text_attr(r, ("isin",)),
            cusip=_first_text_attr(r, ("cusip",)),
            exchange=exchange_text,
            option_right=opt_right,
            strike=_parse_flex_float(_first_attr(r, ("strike",))),
            expiry=_first_text_attr(r, ("expiry",)),
            underlying_symbol=_first_text_attr(r, ("underlyingSymbol",)),
        )

    # 5. CashTransactions & 6. Transfers -> NormalizedFlow
    _CAPITAL_FLOW_KINDS = {
        FlowKind.DEPOSIT,
        FlowKind.WITHDRAWAL,
        FlowKind.TRANSFER_IN_KIND,
        FlowKind.TRANSFER_OUT_KIND,
        FlowKind.INTERNAL_SUBACCOUNT_TRANSFER,
    }
    flows: list[NormalizedFlow] = []
    for r in cash_tx_rows:
        lod = (_first_attr(r, ("levelOfDetail",)) or "").upper()
        if lod in (_SUMMARY_ROLLUP_LODS | {"SUMMARY"}):
            continue
        ts = _parse_flex_timestamp_utc(
            _first_attr(r, ("dateTime", "reportDate", "settleDate", "tradeDate", "date"))
        )
        amt = _parse_flex_float(_first_attr(r, ("amount", "netAmount")))
        if ts is None or amt is None:
            continue
        ccy = _normalize_flex_currency(_first_attr(r, ("currency", "currencyPrimary")), base_ccy)
        kind = _classify_cash_transaction_kind(r, amt)
        fx = _resolve_fx_optional(
            r,
            ccy,
            row_ts=ts,
            is_capital_flow=(kind in _CAPITAL_FLOW_KINDS),
        )
        flows.append(
            NormalizedFlow(
                timestamp_utc=ts,
                kind=kind,
                amount=amt,
                currency=ccy,
                fx_rate_to_base=fx,
                symbol=_first_text_attr(r, ("symbol",)),
                isin=_first_text_attr(r, ("isin",)),
                description=_first_text_attr(r, ("description", "type")) or "",
            )
        )

    for r in transfer_rows:
        ts = _parse_flex_timestamp_utc(_first_attr(r, ("dateTime", "reportDate", "date", "settleDate")))
        if ts is None:
            continue
        ttype = (_first_text_attr(r, ("type", "transferType")) or "TRANSFER").upper()
        direction = (_first_text_attr(r, ("direction",)) or "").upper()
        sym = _first_text_attr(r, ("symbol",))
        qty = _parse_flex_float(_first_attr(r, ("quantity",)))
        ccy = _normalize_flex_currency(_first_attr(r, ("currency", "currencyPrimary")), base_ccy)
        fx = _resolve_fx_optional(r, ccy, row_ts=ts, is_capital_flow=True)
        pos_amt_base = _parse_flex_float(_first_attr(r, ("positionAmountInBase",)))
        pos_amt = _parse_flex_float(_first_attr(r, ("positionAmount", "cashTransfer", "amount")), default=0.0) or 0.0

        if direction == "OUT" and pos_amt > 0:
            pos_amt = -pos_amt
        elif direction == "IN" and pos_amt < 0:
            pos_amt = abs(pos_amt)
        if pos_amt_base is not None:
            if direction == "OUT" and pos_amt_base > 0:
                pos_amt_base = -pos_amt_base
            elif direction == "IN" and pos_amt_base < 0:
                pos_amt_base = abs(pos_amt_base)

        if ttype == "INTERNAL":
            kind = FlowKind.INTERNAL_SUBACCOUNT_TRANSFER
        elif sym or (qty is not None and qty != 0.0):
            is_out = direction == "OUT" or (direction != "IN" and (pos_amt < 0 or (qty or 0.0) < 0))
            kind = FlowKind.TRANSFER_OUT_KIND if is_out else FlowKind.TRANSFER_IN_KIND
        else:
            kind = FlowKind.WITHDRAWAL if (direction == "OUT" or pos_amt < 0) else FlowKind.DEPOSIT

        flows.append(
            NormalizedFlow(
                timestamp_utc=ts,
                kind=kind,
                amount=pos_amt,
                currency=ccy,
                fx_rate_to_base=fx,
                amount_base=pos_amt_base,
                symbol=sym,
                quantity=qty,
                isin=_first_text_attr(r, ("isin",)),
                transfer_type=ttype,
                description=_first_text_attr(r, ("description",)) or f"IBKR {ttype} {direction}".strip(),
            )
        )

    # 7. CorporateActions & 8. OptionEAE -> CorporateActionRecord
    corporate_actions: list[CorporateActionRecord] = []
    for r in corp_action_rows:
        lod = (_first_attr(r, ("levelOfDetail",)) or "").upper()
        if lod in (_SUMMARY_ROLLUP_LODS | {"SUMMARY"}):
            continue
        ts = _parse_flex_timestamp_utc(_first_attr(r, ("dateTime", "reportDate", "date")))
        sym = _first_text_attr(r, ("symbol", "underlyingSymbol"))
        if ts is None or not sym:
            continue
        act_type, num, den = _classify_corporate_action(r)
        ccy = _normalize_flex_currency(_first_attr(r, ("currency", "currencyPrimary")), base_ccy)
        fx = _resolve_fx_optional(r, ccy, row_ts=ts)
        qty_delta = _parse_flex_float(_first_attr(r, ("quantity",)), default=0.0) or 0.0
        raw_lieu = _parse_flex_float(_first_attr(r, ("proceeds", "amount")), default=0.0) or 0.0
        cash_lieu = (raw_lieu * fx) if fx is not None else 0.0
        corporate_actions.append(
            CorporateActionRecord(
                action_type=act_type,
                timestamp_utc=ts,
                symbol=sym,
                new_symbol=_first_text_attr(r, ("newSymbol",)),
                isin=_first_text_attr(r, ("isin",)),
                new_isin=_first_text_attr(r, ("newIsin",)),
                ratio_numerator=num,
                ratio_denominator=den,
                quantity_delta=qty_delta,
                cash_in_lieu_base=cash_lieu,
                description=_first_text_attr(r, ("description", "actionDescription")) or "",
            )
        )

    for r in option_eae_rows:
        ts = _parse_flex_timestamp_utc(_first_attr(r, ("date", "reportDate", "dateTime")))
        sym = _first_text_attr(r, ("symbol", "underlyingSymbol"))
        if ts is None or not sym:
            continue
        tx_type = (_first_attr(r, ("transactionType", "type")) or "").strip().lower()
        if "assign" in tx_type:
            eae_action = CorporateActionType.OPTION_ASSIGNMENT
        elif "exercis" in tx_type:
            eae_action = CorporateActionType.OPTION_EXERCISE
        else:
            eae_action = CorporateActionType.OPTION_EXPIRATION
        ccy = _normalize_flex_currency(_first_attr(r, ("currency", "currencyPrimary")), base_ccy)
        fx = _resolve_fx_optional(r, ccy, row_ts=ts)
        qty_delta = _parse_flex_float(_first_attr(r, ("quantity",)), default=0.0) or 0.0
        mult = _parse_flex_float(_first_attr(r, ("multiplier",)), default=100.0)
        raw_basis = _parse_flex_float(_first_attr(r, ("costBasisMoney", "proceeds")), default=0.0) or 0.0
        basis_adj = (raw_basis * fx) if fx is not None else 0.0
        corporate_actions.append(
            CorporateActionRecord(
                action_type=eae_action,
                timestamp_utc=ts,
                symbol=sym,
                isin=_first_text_attr(r, ("isin",)),
                quantity_delta=qty_delta,
                cost_basis_adjustment_base=basis_adj,
                underlying_symbol=_first_text_attr(r, ("underlyingSymbol",)),
                option_multiplier=mult if mult and mult > 0 else 100.0,
                strike=_parse_flex_float(_first_attr(r, ("strike",))),
                description=_first_text_attr(r, ("transactionType", "description")) or eae_action.value,
            )
        )

    for (c_ymd, from_c, to_c), c_rate in closing_inferred_fx_index.raw_items().items():
        if (
            c_ymd == end_ref_ymd
            and to_c == base_ccy
            and (
                from_c not in omitted_fx_currencies
                or f"{from_c}/{base_ccy}" in conversion_rates
                or f"{base_ccy}/{from_c}" in conversion_rates
            )
        ):
            _record_pair_rate(from_c, base_ccy, c_rate, date_str=end_ref_ymd, source_prio=2)

    if omitted_fx_currencies:
        pairs_label = ", ".join(f"{c}->{base_ccy}" for c in omitted_fx_currencies)
        warnings.append(
            f"ConversionRates and row-level fxRateToBase were omitted in the IBKR Flex query "
            f"for {pairs_label}; base-currency custody reconciliation completeness was omitted."
        )

    # 9. Single-interval <ChangeInNAV twr=...> (populated ONLY for broker-retrieved origins).
    # In IBKR's Activity Flex XML schema, ChangeInNAV.twr is strictly expressed in percentage
    # points (e.g. twr="1.25" == +1.25% == 0.0125 decimal).
    broker_period_returns: dict[str, float] = {}
    if claimed_origin_assurance in {
        OriginAssurance.OPERATOR_RETRIEVED,
        OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
        OriginAssurance.BROKER_SIGNED,
    }:
        kept_nav_by_ts: dict[str, NormalizedNavPoint] = {
            pt.timestamp_utc: pt for pt in nav_points
        }
        prev_nav_by_ts: dict[str, NormalizedNavPoint] = {
            curr_pt.timestamp_utc: prev_pt
            for prev_pt, curr_pt in zip(nav_points, nav_points[1:])
        }
        for c_row in change_nav_rows:
            c_from = _parse_flex_timestamp_utc(_first_attr(c_row, ("fromDate", "reportDate", "date")))
            c_to = _parse_flex_timestamp_utc(_first_attr(c_row, ("toDate", "reportDate", "date")))
            if c_from is None or c_to is None or c_from[:10] > c_to[:10]:
                continue
            day_eod = c_to[:10] + "T23:59:59Z"
            twr_raw = _parse_flex_float(_first_attr(c_row, ("twr",)))
            s_val = _parse_flex_float(_first_attr(c_row, ("startingValue",)))
            e_val = _parse_flex_float(_first_attr(c_row, ("endingValue",)))
            if twr_raw is None or s_val is None or e_val is None or s_val <= 0.0:
                continue
            target_nav = kept_nav_by_ts.get(day_eod)
            prev_nav = prev_nav_by_ts.get(day_eod)
            if target_nav is None or prev_nav is None:
                continue
            if not (prev_nav.timestamp_utc[:10] < c_from[:10] <= c_to[:10]):
                continue
            if abs(s_val - prev_nav.nav_base) > max(2.0, 1e-3 * abs(prev_nav.nav_base)):
                continue
            if abs(e_val - target_nav.nav_base) > max(2.0, 1e-3 * abs(target_nav.nav_base)):
                continue
            chosen_ret = twr_raw / 100.0
            if math.isfinite(chosen_ret) and chosen_ret > -1.0:
                broker_period_returns[day_eod] = chosen_ret

    stmt_starts: list[str] = []
    stmt_ends: list[str] = []
    for st_item in statement_attrs_list:
        s_parsed = _parse_flex_timestamp_utc(_first_attr(st_item, ("fromDate", "startDate")))
        if s_parsed is not None:
            stmt_starts.append(s_parsed)
        raw_e = _first_attr(st_item, ("toDate", "endDate"))
        e_parsed = _parse_flex_timestamp_utc(raw_e)
        if e_parsed is not None:
            if raw_e is not None and _DATE_ONLY_RE.match(raw_e):
                # The statement's last date is inclusive: it ends with that date's valuation.
                e_parsed = e_parsed[:10] + "T23:59:59Z"
            stmt_ends.append(e_parsed)

    stmt_start = min(stmt_starts) if stmt_starts else None
    stmt_end = max(stmt_ends) if stmt_ends else None
    all_ts = (
        [p.timestamp_utc for p in nav_points]
        + [t.timestamp_utc for t in trades_by_id.values()]
        + [f.timestamp_utc for f in flows]
        + [c.timestamp_utc for c in corporate_actions]
    )
    if stmt_start is None:
        stmt_start = min(all_ts) if all_ts else "2025-01-01T00:00:00Z"
    if stmt_end is None:
        stmt_end = max(all_ts) if all_ts else stmt_start

    return CanonicalPortfolioLedger(
        blinded_account_tag=blinded_tag,
        broker_id="ibkr",
        account_scope=account_scope,
        claimed_origin_assurance=claimed_origin_assurance,
        provider_approval_state=provider_approval_state,
        environment_tier=env_tier,
        source_body_sha256=source_sha256,
        base_currency=base_ccy,
        period_start_utc=stmt_start,
        period_end_utc=stmt_end,
        connected_subaccount_count=len(raw_acct_ids) if raw_acct_ids else 1,
        prior_positions=prior_positions,
        ending_positions=ending_positions,
        nav_points=nav_points,
        trades=sorted(trades_by_id.values(), key=lambda t: (t.timestamp_utc, t.native_entry_id)),
        flows=sorted(flows, key=lambda f: f.timestamp_utc),
        corporate_actions=sorted(corporate_actions, key=lambda c: c.timestamp_utc),
        conversion_rates=conversion_rates,
        broker_period_returns=broker_period_returns,
        enabled_sections=enabled_sections,
        parser_warnings=warnings,
    )


def _parse_ibkr_date_only(raw: str | None, *, field_name: str) -> date | None:
    if raw is None:
        return None
    cleaned = str(raw).strip()
    if not cleaned:
        return None
    ts = _parse_flex_timestamp_utc(cleaned)
    if ts is None:
        raise ValueError(f"{field_name} must be YYYY-MM-DD or YYYYMMDD, got {raw!r}")
    return date.fromisoformat(ts[:10])


def split_ibkr_flex_date_chunks(
    start_date: str | date,
    end_date: str | date,
    *,
    max_chunk_days: int = 365,
    max_chunks: int = 10,
) -> list[tuple[str, str]]:
    """Split ``[start_date, end_date]`` into contiguous ``(YYYYMMDD, YYYYMMDD)`` chunks ``<= 365`` days."""
    d_start = (
        start_date
        if isinstance(start_date, date)
        else _parse_ibkr_date_only(start_date, field_name="start_date")
    )
    d_end = (
        end_date
        if isinstance(end_date, date)
        else _parse_ibkr_date_only(end_date, field_name="end_date")
    )
    if d_start is None or d_end is None:
        raise ValueError("start_date and end_date must be non-empty dates")
    if d_end < d_start:
        raise ValueError("end_date must be on or after start_date")
    if max_chunk_days < 1 or max_chunk_days > 365:
        raise ValueError("max_chunk_days must be between 1 and 365")

    chunks: list[tuple[str, str]] = []
    cur = d_start
    while cur <= d_end:
        if len(chunks) >= max_chunks:
            raise ValueError(
                f"IBKR Flex date range exceeds maximum of {max_chunks} yearly chunks"
            )
        year_end = date(cur.year, 12, 31)
        cap_end = cur + timedelta(days=max_chunk_days - 1)
        chunk_end = min(year_end, cap_end, d_end)
        chunks.append((cur.strftime("%Y%m%d"), chunk_end.strftime("%Y%m%d")))
        cur = chunk_end + timedelta(days=1)
    return chunks


def _hash_ibkr_xml_chunks(raw_chunks: Sequence[bytes]) -> str:
    if len(raw_chunks) == 1:
        return hashlib.sha256(raw_chunks[0]).hexdigest()
    h = hashlib.sha256(b"n170.ibkr_flex.multi.v1\x00")
    for chunk in raw_chunks:
        h.update(len(chunk).to_bytes(8, "big"))
        h.update(chunk)
    return h.hexdigest()


def merge_ibkr_flex_ledgers(
    ledgers: Sequence[CanonicalPortfolioLedger],
    *,
    raw_chunks: Sequence[bytes] | None = None,
) -> CanonicalPortfolioLedger:
    """Merge chronological single-account ``CanonicalPortfolioLedger`` chunks deterministically."""
    if not ledgers:
        raise ValueError("At least one CanonicalPortfolioLedger is required to merge")
    if len(ledgers) == 1 and (raw_chunks is None or len(raw_chunks) == 1):
        return ledgers[0]

    ordered = sorted(ledgers, key=lambda ldg: (ldg.period_start_utc, ldg.period_end_utc))
    first = ordered[0]
    last = ordered[-1]

    for item in ordered[1:]:
        if item.blinded_account_tag != first.blinded_account_tag:
            raise IbkrFlexParseError(
                "IBKR Flex chunks belong to different accounts; multi-period verification requires a single account."
            )
        if item.base_currency != first.base_currency:
            raise IbkrFlexParseError(
                f"IBKR Flex chunks declare conflicting base currencies ({first.base_currency} vs {item.base_currency})."
            )
        if item.broker_id != first.broker_id:
            raise IbkrFlexParseError(
                f"IBKR Flex chunks declare conflicting broker_id values ({first.broker_id} vs {item.broker_id})."
            )
        if item.claimed_origin_assurance != first.claimed_origin_assurance:
            raise IbkrFlexParseError(
                "IBKR Flex chunks declare conflicting claimed_origin_assurance values across merged periods."
            )
        if item.provider_approval_state != first.provider_approval_state:
            raise IbkrFlexParseError(
                "IBKR Flex chunks declare conflicting provider_approval_state values across merged periods."
            )
        if item.account_scope != first.account_scope:
            raise IbkrFlexParseError(
                "IBKR Flex chunks declare conflicting account_scope values across merged periods."
            )
        if item.environment_tier != first.environment_tier:
            raise IbkrFlexParseError(
                "IBKR Flex chunks declare conflicting environment_tier values across merged periods."
            )

    nav_by_ts: dict[str, NormalizedNavPoint] = {}
    for item in ordered:
        for pt in item.nav_points:
            existing = nav_by_ts.get(pt.timestamp_utc)
            if existing is not None and abs(existing.nav_base - pt.nav_base) > 1e-6:
                raise IbkrFlexParseError(
                    f"Conflicting IBKR Flex valuations on {pt.timestamp_utc[:10]} across merged statements."
                )
            nav_by_ts[pt.timestamp_utc] = pt
    merged_navs = _trim_valuation_series([nav_by_ts[k] for k in sorted(nav_by_ts)])
    merged_prev_by_ts: dict[str, NormalizedNavPoint] = {
        curr_pt.timestamp_utc: prev_pt
        for prev_pt, curr_pt in zip(merged_navs, merged_navs[1:])
    }

    trades_by_id: dict[str, NormalizedTrade] = {}
    for item in ordered:
        for tr in item.trades:
            trades_by_id[tr.native_entry_id] = tr

    seen_flows: set[tuple[tuple[Any, ...], int]] = set()
    merged_flows: list[NormalizedFlow] = []
    for item in ordered:
        chunk_flow_counts: dict[tuple[Any, ...], int] = {}
        for fl in item.flows:
            fkey = (
                fl.timestamp_utc,
                fl.kind,
                round(fl.amount, 8),
                fl.currency,
                fl.symbol,
                round(fl.quantity, 8) if fl.quantity is not None else None,
                fl.description,
            )
            within_chunk_occurrence_idx = chunk_flow_counts.get(fkey, 0)
            chunk_flow_counts[fkey] = within_chunk_occurrence_idx + 1
            flow_dedup_key = (fkey, within_chunk_occurrence_idx)
            if flow_dedup_key not in seen_flows:
                seen_flows.add(flow_dedup_key)
                merged_flows.append(fl)

    seen_ca: set[tuple[tuple[Any, ...], int]] = set()
    merged_ca: list[CorporateActionRecord] = []
    for item in ordered:
        chunk_ca_counts: dict[tuple[Any, ...], int] = {}
        for ca in item.corporate_actions:
            ckey = (
                ca.timestamp_utc,
                ca.action_type,
                ca.symbol,
                ca.new_symbol,
                round(ca.quantity_delta, 8),
                round(ca.cash_in_lieu_base, 8),
                round(ca.cost_basis_adjustment_base, 8),
                ca.strike,
            )
            within_chunk_ca_idx = chunk_ca_counts.get(ckey, 0)
            chunk_ca_counts[ckey] = within_chunk_ca_idx + 1
            ca_dedup_key = (ckey, within_chunk_ca_idx)
            if ca_dedup_key not in seen_ca:
                seen_ca.add(ca_dedup_key)
                merged_ca.append(ca)

    merged_rates: dict[str, float] = {}
    merged_broker_returns: dict[str, float] = {}
    enabled_sections: list[str] = []
    warnings: list[str] = []
    any_conv_rates_section = any("ConversionRates" in x.enabled_sections for x in ordered)
    ending_ccys = {pos.currency for pos in last.ending_positions}
    for item_idx, item in enumerate(ordered):
        for rk, rv in item.conversion_rates.items():
            if not any_conv_rates_section and item is not last and last.conversion_rates:
                pair_ccys = set(rk.split("/", 1)) if "/" in rk else {rk}
                foreign_leg = next((c for c in pair_ccys if c != first.base_currency), "")
                if foreign_leg and foreign_leg != "USD" and foreign_leg not in ending_ccys:
                    continue
            if "/" in rk:
                ra, rb = rk.split("/", 1)
                merged_rates.pop(f"{rb}/{ra}", None)
            merged_rates[rk] = rv
        item_prev_by_ts = {
            curr_pt.timestamp_utc: prev_pt
            for prev_pt, curr_pt in zip(item.nav_points, item.nav_points[1:])
        }
        for b_ts, b_ret in item.broker_period_returns.items():
            item_prev = item_prev_by_ts.get(b_ts)
            merged_prev = merged_prev_by_ts.get(b_ts)
            if (
                item_prev is not None
                and merged_prev is not None
                and merged_prev.timestamp_utc == item_prev.timestamp_utc
                and abs(merged_prev.nav_base - item_prev.nav_base) <= 1e-6
            ):
                merged_broker_returns[b_ts] = b_ret
        for sec in item.enabled_sections:
            if sec == "PriorPeriodPositions" and item is not first:
                continue
            if sec not in enabled_sections:
                enabled_sections.append(sec)
        for w in item.parser_warnings:
            if item_idx > 0 and (
                w in {INFERRED_SINGLE_PRIOR_POSITION_WARNING, OMITTED_PRIOR_POSITION_QTY_WARNING}
                or w.startswith(OMITTED_PRIOR_POSITION_SYMBOLS_PREFIX)
            ):
                continue
            if w not in warnings:
                warnings.append(w)

    if raw_chunks and first.claimed_origin_assurance in {
        OriginAssurance.OPERATOR_RETRIEVED,
        OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
        OriginAssurance.BROKER_SIGNED,
    }:
        missing_pairs = [
            (prev_pt, curr_pt)
            for prev_pt, curr_pt in zip(merged_navs, merged_navs[1:])
            if curr_pt.timestamp_utc not in merged_broker_returns
        ]
        if missing_pairs:
            all_cin_by_to: dict[str, list[tuple[str, float, float, float]]] = {}
            for raw_chunk in raw_chunks:
                chunk_cin = IbkrFlexWebServiceAdapter._extract_change_in_nav_candidates(raw_chunk)
                for to_ymd, rows in chunk_cin.items():
                    all_cin_by_to.setdefault(to_ymd, []).extend(rows)
            if all_cin_by_to:
                for prev_pt, curr_pt in missing_pairs:
                    cand_rows = all_cin_by_to.get(curr_pt.timestamp_utc[:10])
                    if not cand_rows:
                        continue
                    verified_ret = IbkrFlexWebServiceAdapter._match_verified_interval_twr(
                        cand_rows,
                        prev_pt=prev_pt,
                        curr_pt=curr_pt,
                    )
                    if verified_ret is not None:
                        merged_broker_returns[curr_pt.timestamp_utc] = verified_ret

    if raw_chunks is not None and len(raw_chunks) >= 1:
        source_sha256 = _hash_ibkr_xml_chunks(raw_chunks)
    else:
        h = hashlib.sha256(b"n170.ibkr_flex.multi_sha.v1\x00")
        for item in ordered:
            h.update(bytes.fromhex(item.source_body_sha256))
        source_sha256 = h.hexdigest()

    return CanonicalPortfolioLedger(
        blinded_account_tag=first.blinded_account_tag,
        broker_id=first.broker_id,
        account_scope=first.account_scope,
        claimed_origin_assurance=first.claimed_origin_assurance,
        provider_approval_state=first.provider_approval_state,
        environment_tier=first.environment_tier,
        source_body_sha256=source_sha256,
        base_currency=first.base_currency,
        period_start_utc=min(x.period_start_utc for x in ordered),
        period_end_utc=max(x.period_end_utc for x in ordered),
        connected_subaccount_count=first.connected_subaccount_count,
        prior_positions=list(first.prior_positions),
        ending_positions=list(last.ending_positions),
        nav_points=merged_navs,
        trades=sorted(trades_by_id.values(), key=lambda t: (t.timestamp_utc, t.native_entry_id)),
        flows=sorted(merged_flows, key=lambda f: f.timestamp_utc),
        corporate_actions=sorted(merged_ca, key=lambda c: c.timestamp_utc),
        conversion_rates=merged_rates,
        broker_period_returns=merged_broker_returns,
        enabled_sections=enabled_sections,
        parser_warnings=warnings,
    )


def _parse_flex_service_envelope(
    raw_xml: bytes,
    secrets: Sequence[str],
    *,
    max_bytes: int = DEFAULT_MAX_FLEX_BYTES,
) -> tuple[str, str | None, str | None, str | None]:
    """Return ``(status, reference_code, error_code, error_message)`` while ignoring ``<Url>``."""
    safe_bytes = _decode_and_guard_xml_bytes(raw_xml, max_bytes=max_bytes)
    root_tag: str | None = None
    is_envelope = False
    status = ""
    ref_code: str | None = None
    err_code: str | None = None
    err_msg: str | None = None
    stack: list[ET.Element] = []
    elem_count = 0
    try:
        for ev, elem in ET.iterparse(BytesIO(safe_bytes), events=("start", "end")):
            if ev == "start":
                elem_count += 1
                if elem_count > DEFAULT_MAX_FLEX_ELEMENTS:
                    raise IbkrFlexParseError(
                        f"Flex XML exceeds {DEFAULT_MAX_FLEX_ELEMENTS}-element safety limit"
                    )
                stack.append(elem)
                if root_tag is None:
                    root_tag = _local_tag(elem.tag)
                    is_envelope = root_tag == "flexstatementresponse"
                continue

            if is_envelope and len(stack) == 2:
                ctag = _local_tag(elem.tag)
                val = (elem.text or "").strip()
                if ctag == "status":
                    status = val
                elif ctag == "referencecode":
                    ref_code = val
                elif ctag == "errorcode":
                    err_code = val
                elif ctag == "errormessage":
                    err_msg = redact_sensitive_text(val, secrets)
                elif ctag == "url":
                    # EXPLICITLY IGNORE deprecated <Url> pointing to gdcdyn.interactivebrokers.com (Error 1001).
                    pass

            if len(stack) > 1:
                stack[-2].remove(elem)
            elem.clear()
            stack.pop()
    except ET.ParseError as exc:
        raise IbkrFlexServiceError("Invalid XML returned by IBKR Flex Web Service") from exc

    if root_tag is None:
        raise IbkrFlexServiceError("Invalid XML returned by IBKR Flex Web Service")
    if not is_envelope:
        return "StatementReady", None, None, None
    return status, ref_code, err_code, err_msg


class IbkrFlexWebServiceAdapter(ReadOnlyBrokerAdapter):
    """Read-only IBKR Flex Web Service v3 adapter (`ndcdyn.interactivebrokers.com` pinned)."""

    broker_id = "ibkr_flex_web"
    display_name = "Interactive Brokers Flex Web Service v3"
    approval_state = ProviderApprovalState.USER_KEY_SELF_ATTESTED
    default_origin_assurance = OriginAssurance.OPERATOR_RETRIEVED
    supports_subaccount_enumeration = False
    allowed_capabilities = (
        "fetch_nav_history",
        "fetch_positions",
        "fetch_executions",
        "fetch_cash_flows",
        "fetch_transfers",
        "fetch_corporate_actions",
    )

    def __init__(
        self,
        *,
        user_agent: str = DEFAULT_IBKR_FLEX_USER_AGENT,
        http_transport: HttpTransportCallable | Any | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        now_utc_fn: Callable[[], datetime] | None = None,
        max_poll_attempts: int = 12,
        poll_interval_seconds: float = 3.5,
        max_rate_limit_retries: int = 20,
        rate_limit_backoff_seconds: float = 6.0,
        chunk_pacing_seconds: float = 3.0,
    ) -> None:
        super().__init__()
        cleaned_ua = (user_agent or "").strip()
        if not cleaned_ua or cleaned_ua.lower().startswith("python-urllib"):
            raise ValueError(
                "IBKR Flex Web Service v3 requires a non-empty custom User-Agent header"
            )
        self.user_agent = cleaned_ua
        self._transport = http_transport
        self._sleep_fn = sleep_fn
        self._now_utc_fn = now_utc_fn or (lambda: datetime.now(timezone.utc))
        self._max_poll_attempts = max(1, max_poll_attempts)
        self._poll_interval_seconds = max(0.0, poll_interval_seconds)
        self._max_rate_limit_retries = max(1, max_rate_limit_retries)
        self._rate_limit_backoff_seconds = max(0.0, rate_limit_backoff_seconds)
        self._chunk_pacing_seconds = max(0.0, chunk_pacing_seconds)

    def fetch_statement_bytes(
        self,
        *,
        flex_token: str,
        query_id: str,
        from_date: str | None = None,
        to_date: str | None = None,
    ) -> bytes:
        """Execute ``SendRequest`` -> ``GetStatement`` (``v=3``) against ``ndcdyn`` only."""
        token_clean = (flex_token or "").strip()
        query_clean = (query_id or "").strip()
        if not token_clean or not query_clean:
            raise ValueError("flex_token and query_id must be non-empty strings")

        if (from_date is None) != (to_date is None):
            raise ValueError("from_date and to_date must both be provided or both omitted")

        send_params: dict[str, str] = {"t": token_clean, "q": query_clean, "v": "3"}
        if from_date is not None and to_date is not None:
            fd_d = _parse_ibkr_date_only(from_date, field_name="from_date")
            td_d = _parse_ibkr_date_only(to_date, field_name="to_date")
            if fd_d is None or td_d is None or td_d < fd_d:
                raise ValueError("from_date and to_date must form a valid date interval")
            if (td_d - fd_d).days + 1 > 365:
                raise ValueError("Single IBKR Flex SendRequest interval cannot exceed 365 days")
            send_params["fd"] = fd_d.strftime("%Y%m%d")
            send_params["td"] = td_d.strftime("%Y%m%d")

        secrets = (token_clean, query_clean)
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/xml, text/xml",
        }

        send_qs = urllib.parse.urlencode(send_params)
        send_url = f"{IBKR_FLEX_SEND_REQUEST_URL}?{send_qs}"
        ref_code: str | None = None
        send_1018_retries = 0
        send_1019_retries = 0
        while True:
            try:
                send_resp = invoke_http_transport(
                    self._transport,
                    "GET",
                    send_url,
                    headers=headers,
                    extra_secrets=secrets,
                )
            except ConnectorHttpError as exc:
                safe_detail = redact_sensitive_text(str(exc), secrets)
                raise IbkrFlexServiceError(
                    f"IBKR Flex SendRequest transport error: {safe_detail}"
                ) from exc
            if send_resp.status_code != 200:
                raise IbkrFlexServiceError(
                    f"IBKR Flex SendRequest failed with HTTP {send_resp.status_code} "
                    f"(target={IBKR_FLEX_SEND_REQUEST_URL}?t=[REDACTED]&q=[REDACTED]&v=3)"
                )

            status, cand_ref, err_code, err_msg = _parse_flex_service_envelope(
                send_resp.body, secrets
            )
            if status.lower() == "success" and cand_ref:
                ref_code = cand_ref
                break
            if err_code == "1018" and send_1018_retries < self._max_rate_limit_retries:
                send_1018_retries += 1
                self._sleep_fn(self._rate_limit_backoff_seconds)
                continue
            if err_code in {"1019", "1004"} and send_1019_retries + 1 < self._max_poll_attempts:
                send_1019_retries += 1
                self._sleep_fn(self._poll_interval_seconds)
                continue
            raise IbkrFlexServiceError(
                f"IBKR Flex SendRequest rejected (code={err_code or 'unknown'}): {err_msg or 'no reference code'}",
                err_code,
            )
        if not ref_code:
            raise IbkrFlexServiceError("IBKR Flex SendRequest polling timed out")

        all_secrets = (token_clean, query_clean, ref_code)
        get_qs = urllib.parse.urlencode({"t": token_clean, "q": ref_code, "v": "3"})
        # Always use hardcoded IBKR_FLEX_GET_STATEMENT_URL (ndcdyn); never use SendRequest <Url>!
        get_url = f"{IBKR_FLEX_GET_STATEMENT_URL}?{get_qs}"

        stmt_1018_retries = 0
        stmt_1019_retries = 0
        while True:
            try:
                stmt_resp = invoke_http_transport(
                    self._transport,
                    "GET",
                    get_url,
                    headers=headers,
                    extra_secrets=all_secrets,
                )
            except ConnectorHttpError as exc:
                safe_detail = redact_sensitive_text(str(exc), all_secrets)
                raise IbkrFlexServiceError(
                    f"IBKR Flex GetStatement transport error: {safe_detail}"
                ) from exc
            if stmt_resp.status_code != 200:
                raise IbkrFlexServiceError(
                    f"IBKR Flex GetStatement failed with HTTP {stmt_resp.status_code} "
                    f"(target={IBKR_FLEX_GET_STATEMENT_URL}?t=[REDACTED]&q=[REDACTED]&v=3)"
                )
            st_status, _, st_err_code, st_err_msg = _parse_flex_service_envelope(
                stmt_resp.body, all_secrets
            )
            if st_status == "StatementReady":
                return stmt_resp.body
            if st_err_code == "1018" and stmt_1018_retries < self._max_rate_limit_retries:
                stmt_1018_retries += 1
                self._sleep_fn(self._rate_limit_backoff_seconds)
                continue
            if st_err_code in {"1019", "1004"} and stmt_1019_retries + 1 < self._max_poll_attempts:
                stmt_1019_retries += 1
                self._sleep_fn(self._poll_interval_seconds)
                continue
            raise IbkrFlexServiceError(
                f"IBKR Flex GetStatement failed (code={st_err_code or 'unknown'}): "
                f"{st_err_msg or 'statement unavailable'}",
                st_err_code,
            )

    @staticmethod
    def _extract_change_in_nav_candidates(
        raw_xml: bytes,
    ) -> dict[str, list[tuple[str, float, float, float]]]:
        """Parse all ``<ChangeInNAV>`` rows in ``raw_xml`` once, indexed by ``toDate`` (``YYYY-MM-DD``)."""
        by_to_date: dict[str, list[tuple[str, float, float, float]]] = {}
        try:
            utf8_xml = _decode_and_guard_xml_bytes(raw_xml, max_bytes=DEFAULT_MAX_FLEX_BYTES)
            lowered_probe = utf8_xml.lower()
            if b"changeinnav" not in lowered_probe and b"navstatement" not in lowered_probe:
                return by_to_date
            stack: list[ET.Element] = []
            elem_count = 0
            for ev, elem in ET.iterparse(BytesIO(utf8_xml), events=("start", "end")):
                if ev == "start":
                    elem_count += 1
                    if elem_count > DEFAULT_MAX_FLEX_ELEMENTS:
                        return {}
                    stack.append(elem)
                    if _local_tag(elem.tag) not in {"changeinnav", "navstatement"}:
                        continue
                    c_from = _parse_flex_timestamp_utc(
                        _first_attr(elem.attrib, ("fromDate", "reportDate", "date"))
                    )
                    c_to = _parse_flex_timestamp_utc(
                        _first_attr(elem.attrib, ("toDate", "reportDate", "date"))
                    )
                    if c_from is None or c_to is None or c_from[:10] > c_to[:10]:
                        continue
                    s_val = _parse_flex_float(_first_attr(elem.attrib, ("startingValue",)))
                    e_val = _parse_flex_float(_first_attr(elem.attrib, ("endingValue",)))
                    twr_raw = _parse_flex_float(_first_attr(elem.attrib, ("twr",)))
                    if s_val is None or e_val is None or twr_raw is None or s_val <= 0.0:
                        continue
                    ret_dec = twr_raw / 100.0
                    if math.isfinite(ret_dec) and ret_dec > -1.0:
                        by_to_date.setdefault(c_to[:10], []).append(
                            (c_from[:10], s_val, e_val, ret_dec)
                        )
                else:
                    if len(stack) > 1:
                        stack[-2].remove(elem)
                    elem.clear()
                    stack.pop()
        except (ET.ParseError, IbkrFlexParseError, ValueError):
            return {}
        return by_to_date

    @staticmethod
    def _match_verified_interval_twr(
        candidates: Sequence[tuple[str, float, float, float]],
        *,
        prev_pt: NormalizedNavPoint,
        curr_pt: NormalizedNavPoint,
    ) -> float | None:
        prev_ymd = prev_pt.timestamp_utc[:10]
        curr_ymd = curr_pt.timestamp_utc[:10]
        s_tol = max(2.0, 1e-3 * abs(prev_pt.nav_base))
        e_tol = max(2.0, 1e-3 * abs(curr_pt.nav_base))
        for c_from_ymd, s_val, e_val, ret_dec in candidates:
            if not (prev_ymd < c_from_ymd <= curr_ymd):
                continue
            if abs(s_val - prev_pt.nav_base) > s_tol:
                continue
            if abs(e_val - curr_pt.nav_base) > e_tol:
                continue
            return ret_dec
        return None

    @staticmethod
    def _extract_verified_interval_twr_from_xml(
        raw_xml: bytes,
        *,
        prev_pt: NormalizedNavPoint,
        curr_pt: NormalizedNavPoint,
    ) -> float | None:
        """Extract percentage-point ``<ChangeInNAV twr=...>`` only when start/end NAVs match ``(prev_pt, curr_pt)``."""
        by_to = IbkrFlexWebServiceAdapter._extract_change_in_nav_candidates(raw_xml)
        rows = by_to.get(curr_pt.timestamp_utc[:10])
        if not rows:
            return None
        return IbkrFlexWebServiceAdapter._match_verified_interval_twr(
            rows, prev_pt=prev_pt, curr_pt=curr_pt
        )

    @staticmethod
    def _prescan_single_account_fx_and_cin(
        raw_chunks: Sequence[bytes],
    ) -> tuple[dict[tuple[str, str, str], float], dict[tuple[str, str, str], float], bool]:
        """Collect dated FX rates and closing-inferred FX rates across chunks, and detect twr-less <ChangeInNAV>."""
        dated_fx_index = _DatedFxIndex()
        closing_fx_index = _DatedFxIndex()
        cross_obs: list[tuple[str, str, str, float]] = []
        raw_elem_fx_obs: list[tuple[str, str, float]] = []
        chunk_closing_data: list[
            tuple[list[tuple[str, str, float, float | None]], list[dict[str, str]]]
        ] = []
        seen_accts: set[str] = set()
        seen_bases: set[str] = set()
        saw_any_cin = False
        saw_cin_with_twr = False
        _PRESCAN_POS_KEYS = (
            "stock",
            "options",
            "commodities",
            "bonds",
            "notes",
            "funds",
            "warrants",
            "cfd",
        )

        for raw in raw_chunks:
            try:
                utf8_xml = _decode_and_guard_xml_bytes(raw, max_bytes=DEFAULT_MAX_FLEX_BYTES)
                stack: list[ET.Element] = []
                elem_count = 0
                stmt_from_ymd = ""
                stmt_to_ymd = ""
                chunk_nav_rows: list[tuple[str, str, float, float | None]] = []
                chunk_open_rows: list[dict[str, str]] = []
                for ev, elem in ET.iterparse(BytesIO(utf8_xml), events=("start", "end")):
                    if ev == "start":
                        elem_count += 1
                        if elem_count > DEFAULT_MAX_FLEX_ELEMENTS:
                            return {}, {}, False
                        stack.append(elem)
                        ltag = _local_tag(elem.tag)
                        if ltag == "flexstatement":
                            from_ts = _parse_flex_timestamp_utc(
                                _first_attr(elem.attrib, ("fromDate", "startDate"))
                            )
                            to_ts = _parse_flex_timestamp_utc(
                                _first_attr(elem.attrib, ("toDate", "endDate"))
                            )
                            stmt_from_ymd = from_ts[:10] if from_ts is not None else ""
                            stmt_to_ymd = to_ts[:10] if to_ts is not None else ""
                        if ltag in {"flexstatement", "accountinformation", "acctinfo"}:
                            aid = _first_attr(elem.attrib, ("accountId", "acctCode"))
                            if aid:
                                seen_accts.add(aid)
                            ccy_a = _first_attr(elem.attrib, ("baseCurrency", "currency"))
                            if ccy_a and len(ccy_a.strip()) == 3 and ccy_a.strip().isalpha():
                                seen_bases.add(ccy_a.strip().upper())
                        elif ltag in {"changeinnav", "navstatement"}:
                            if _first_attr(elem.attrib, ("twr", "startingValue", "endingValue")):
                                saw_any_cin = True
                                if _parse_flex_float(_first_attr(elem.attrib, ("twr",))) is not None:
                                    saw_cin_with_twr = True
                        elif ltag in {"equitysummarybyreportdateinbase", "equitysummaryinbase"}:
                            nav_ccy_u = (_first_attr(elem.attrib, ("currency",)) or "").strip().upper()
                            n_ts = _parse_flex_timestamp_utc(
                                _first_attr(elem.attrib, ("reportDate", "date", "asOfDate", "toDate"))
                            )
                            n_tot = _parse_flex_float(
                                _first_attr(
                                    elem.attrib,
                                    ("total", "netLiquidationValue", "netAssetValue", "value", "endingValue"),
                                )
                            )
                            if n_ts and n_tot is not None and n_tot > 0.0:
                                lkeys = {x.lower() for x in elem.attrib}
                                n_pos = (
                                    math.fsum(
                                        _parse_flex_float(_first_attr(elem.attrib, (k,)), default=0.0) or 0.0
                                        for k in _PRESCAN_POS_KEYS
                                    )
                                    if any(k in lkeys for k in _PRESCAN_POS_KEYS)
                                    else None
                                )
                                chunk_nav_rows.append((nav_ccy_u, n_ts[:10], n_tot, n_pos))
                        elif ltag == "openposition" and len(chunk_open_rows) < DEFAULT_MAX_SECTION_ROWS:
                            chunk_open_rows.append(dict(elem.attrib))
                        elif ltag == "conversionrate":
                            fc = (_first_attr(elem.attrib, ("fromCurrency",)) or "").strip().upper()
                            tc = (_first_attr(elem.attrib, ("toCurrency",)) or "").strip().upper()
                            rt = _parse_flex_float(_first_attr(elem.attrib, ("rate",)))
                            ts = _parse_flex_timestamp_utc(
                                _first_attr(elem.attrib, ("reportDate", "date", "asOfDate"))
                            )
                            if fc and tc and fc != tc and rt is not None and rt > 0.0 and ts:
                                dated_fx_index.add(ts[:10], fc, tc, rt, overwrite=True)
                        elif ltag == "trade":
                            cat = (_first_attr(elem.attrib, ("assetCategory", "assetClass")) or "").strip().upper()
                            if cat == "CASH":
                                pair = _parse_fx_pair_symbol(
                                    _first_text_attr(elem.attrib, ("symbol", "underlyingSymbol"))
                                )
                                px = _parse_flex_float(_first_attr(elem.attrib, ("tradePrice", "price")))
                                ts = _parse_flex_timestamp_utc(
                                    _first_attr(elem.attrib, ("dateTime", "tradeDate", "reportDate", "date"))
                                )
                                if pair and px is not None and px > 0.0 and ts:
                                    cross_obs.append((ts[:10], pair[0], pair[1], px))
                        fx_exp = _extract_row_implied_fx(elem.attrib)
                        if fx_exp is not None and fx_exp > 0.0:
                            rc_raw = _first_attr(elem.attrib, ("currency", "currencyPrimary")) or ""
                            rc = "GBX" if rc_raw.strip() == "GBp" else rc_raw.strip().upper()
                            ts = _parse_flex_timestamp_utc(
                                _first_attr(
                                    elem.attrib,
                                    (
                                        "dateTime",
                                        "reportDate",
                                        "tradeDate",
                                        "settleDate",
                                        "fromDate",
                                        "toDate",
                                        "asOfDate",
                                        "date",
                                    ),
                                )
                            )
                            obs_ymd = (
                                ts[:10]
                                if ts is not None
                                else (stmt_from_ymd if ltag == "priorperiodposition" else stmt_to_ymd)
                            )
                            if rc and rc != "BASE_SUMMARY" and obs_ymd:
                                raw_elem_fx_obs.append((obs_ymd, rc, fx_exp))
                    else:
                        if ltag == "flexstatement":
                            stmt_from_ymd = ""
                            stmt_to_ymd = ""
                        if len(stack) > 1:
                            stack[-2].remove(elem)
                        elem.clear()
                        stack.pop()
                if chunk_nav_rows and chunk_open_rows:
                    chunk_closing_data.append((chunk_nav_rows, chunk_open_rows))
            except (ET.ParseError, IbkrFlexParseError, ValueError):
                return {}, {}, False

        if len(seen_accts) > 1 or len(seen_bases) > 1:
            return {}, {}, False

        base_ccy = next(iter(seen_bases), "USD")
        for d_s, rc, fx_exp in raw_elem_fx_obs:
            if rc != base_ccy:
                dated_fx_index.add(d_s, rc, base_ccy, fx_exp, overwrite=False)

        remaining_cross: list[tuple[str, str, str, float]] = []
        for d_s, fb, fq, px in cross_obs:
            if fb == base_ccy and fq != base_ccy:
                dated_fx_index.add(d_s, fq, base_ccy, 1.0 / px, overwrite=False)
            elif fq == base_ccy and fb != base_ccy:
                dated_fx_index.add(d_s, fb, base_ccy, px, overwrite=False)
            elif fb != fq:
                remaining_cross.append((d_s, fb, fq, px))

        if remaining_cross:
            for d_s, fb, fq, px in remaining_cross:
                r_b = dated_fx_index.lookup(d_s, fb, base_ccy)
                r_q = dated_fx_index.lookup(d_s, fq, base_ccy)
                if r_b is not None and r_b > 0.0 and r_q is None:
                    dated_fx_index.add(d_s, fq, base_ccy, r_b / px, overwrite=False)
                elif r_q is not None and r_q > 0.0 and r_b is None:
                    dated_fx_index.add(d_s, fb, base_ccy, px * r_q, overwrite=False)

        # Extract closing <OpenPositions> FX per chunk into closing_fx_index (kept strictly
        # separate from dated_fx_index so closing snapshots never back-propagate >31d or onto capital flows).
        _ROLLUP_LODS = {"BASE_SUMMARY", "CURRENCY", "ASSET_SUMMARY", "SYMBOL_SUMMARY"}
        for chunk_nav_rows, chunk_open_rows in chunk_closing_data:
            has_bs = any(c_u == "BASE_SUMMARY" for c_u, _, _, _ in chunk_nav_rows)
            chunk_navs: dict[str, tuple[float, float | None]] = {}
            for c_u, d_ymd, n_tot, n_pos in chunk_nav_rows:
                if has_bs:
                    if c_u == "BASE_SUMMARY":
                        chunk_navs[d_ymd] = (n_tot, n_pos)
                elif not c_u or c_u == base_ccy:
                    chunk_navs[d_ymd] = (n_tot, n_pos)
            if not chunk_navs:
                continue
            last_ymd = max(chunk_navs)
            last_nav_tot, last_pos_tot = chunk_navs[last_ymd]
            dated_open_ymds = [
                ts[:10]
                for r in chunk_open_rows
                if ((_first_attr(r, ("levelOfDetail",)) or "").upper() not in _ROLLUP_LODS)
                and (ts := _parse_flex_timestamp_utc(_first_attr(r, ("reportDate", "date", "asOfDate"))))
            ]
            max_open_ymd = max(dated_open_ymds) if dated_open_ymds else None
            if max_open_ymd is not None and (
                date.fromisoformat(last_ymd) - date.fromisoformat(max_open_ymd)
            ).days > 4:
                continue
            scoped = [
                r
                for r in chunk_open_rows
                if ((_first_attr(r, ("levelOfDetail",)) or "").upper() not in _ROLLUP_LODS)
                and (
                    max_open_ymd is None
                    or _first_attr(r, ("reportDate", "date", "asOfDate")) is None
                    or (
                        (ts := _parse_flex_timestamp_utc(_first_attr(r, ("reportDate", "date", "asOfDate"))))
                        and ts[:10] == max_open_ymd
                    )
                )
            ]
            has_sum_lod = any((_first_attr(r, ("levelOfDetail",)) or "").upper() == "SUMMARY" for r in scoped)
            if has_sum_lod:
                scoped = [
                    r for r in scoped if (_first_attr(r, ("levelOfDetail",)) or "").upper() in {"", "SUMMARY"}
                ]
            mv_by_ccy: dict[str, float] = {}
            pct_by_ccy: dict[str, float] = {}
            for r in scoped:
                if _first_attr(r, ("position", "quantity")) is None:
                    continue
                sym = _first_text_attr(r, ("symbol", "underlyingSymbol", "description"))
                if not sym:
                    continue
                ac = _map_ibkr_asset_class(
                    _first_attr(r, ("assetCategory", "assetClass")),
                    sub_cat=_first_attr(r, ("subCategory",)),
                    symbol=sym,
                )
                if ac == AssetClass.CASH:
                    continue
                qty = _parse_flex_float(_first_attr(r, ("position", "quantity")), default=0.0) or 0.0
                mult = _parse_flex_float(_first_attr(r, ("multiplier",)))
                eff_mult = mult if mult and mult > 0 else 1.0
                raw_mv = _first_attr(r, ("positionValue", "markToMarket", "marketValue", "value"))
                if raw_mv is not None:
                    mv = _parse_flex_float(raw_mv, default=0.0) or 0.0
                else:
                    m_px = _parse_flex_float(_first_attr(r, ("markPrice", "closePrice")), default=None)
                    mv = (qty * m_px * eff_mult) if m_px is not None else 0.0
                rc_raw = _first_attr(r, ("currency", "currencyPrimary")) or ""
                rc = (
                    base_ccy
                    if not rc_raw.strip() or rc_raw.strip().upper() == "BASE_SUMMARY"
                    else ("GBX" if rc_raw.strip() == "GBp" else rc_raw.strip().upper())
                )
                mv_by_ccy[rc] = mv_by_ccy.get(rc, 0.0) + mv
                pct_by_ccy[rc] = pct_by_ccy.get(rc, 0.0) + (
                    _parse_flex_float(_first_attr(r, ("percentOfNAV",)), default=0.0) or 0.0
                )
            f_ccys = [c for c, v in mv_by_ccy.items() if c != base_ccy and abs(v) > 1e-6]
            raw_now = dated_fx_index.raw_items()
            for fc in f_ccys:
                if (last_ymd, fc, base_ccy) in raw_now:
                    continue
                pct_v = pct_by_ccy.get(fc, 0.0)
                mv_v = mv_by_ccy[fc]
                prior_r = dated_fx_index.lookup(last_ymd, fc, base_ccy)
                if (
                    prior_r is not None
                    and last_nav_tot > 0.0
                    and abs(pct_v) >= 0.50
                    and (mv_v * pct_v) > 0.0
                ):
                    cand = (pct_v / 100.0) * last_nav_tot / mv_v
                    if cand > 0.0 and (0.65 * prior_r <= cand <= 1.50 * prior_r):
                        closing_fx_index.add(last_ymd, fc, base_ccy, cand, overwrite=False)
            if f_ccys and last_pos_tot is not None and last_pos_tot > 0.0:
                dom_fc = max(
                    f_ccys,
                    key=lambda c: abs(mv_by_ccy[c])
                    * (
                        closing_fx_index.lookup(last_ymd, c, base_ccy, max_days=4)
                        or dated_fx_index.lookup(last_ymd, c, base_ccy)
                        or 1.0
                    ),
                )
                other_rs: dict[str, float] = {}
                others_ok = True
                for oc in f_ccys:
                    if oc == dom_fc:
                        continue
                    ro = closing_fx_index.lookup(
                        last_ymd, oc, base_ccy, max_days=4
                    ) or dated_fx_index.lookup(last_ymd, oc, base_ccy)
                    if ro is None or ro <= 0.0:
                        others_ok = False
                        break
                    other_rs[oc] = ro
                if others_ok and abs(mv_by_ccy[dom_fc]) > 1e-6:
                    rem_b = (
                        last_pos_tot
                        - mv_by_ccy.get(base_ccy, 0.0)
                        - math.fsum(mv_by_ccy[c] * rv for c, rv in other_rs.items())
                    )
                    exact_fx = rem_b / mv_by_ccy[dom_fc]
                    dom_prior = dated_fx_index.lookup(last_ymd, dom_fc, base_ccy)
                    if (
                        exact_fx > 0.0
                        and math.isfinite(exact_fx)
                        and (mv_by_ccy[dom_fc] * rem_b) > 0.0
                        and (dom_prior is None or (0.65 * dom_prior <= exact_fx <= 1.50 * dom_prior))
                    ):
                        closing_fx_index.add(last_ymd, dom_fc, base_ccy, exact_fx, overwrite=True)

        return dated_fx_index.raw_items(), closing_fx_index.raw_items(), (saw_any_cin and not saw_cin_with_twr)

    def _enrich_large_flow_days_with_broker_twr(
        self,
        ledger: CanonicalPortfolioLedger,
        raw_chunks: list[bytes],
        *,
        flex_token: str,
        query_id: str,
        blinding_salt_hex: str,
        require_live: bool,
        max_revaluation_days: int = 24,
        preloaded_xml_chunks: Mapping[str, bytes] | None = None,
        fetched_xml_chunks_out: dict[str, bytes] | None = None,
        shared_dated_fx: Mapping[tuple[str, str, str], float] | None = None,
        query_omits_cin_twr: bool = False,
    ) -> CanonicalPortfolioLedger:
        """Fetch targeted IBKR ``<ChangeInNAV>`` TWR for in-period >10% flow intervals when missing."""
        if len(ledger.nav_points) < 2 or query_omits_cin_twr:
            return ledger
        capital_kinds = {
            FlowKind.DEPOSIT,
            FlowKind.WITHDRAWAL,
            FlowKind.TRANSFER_IN_KIND,
            FlowKind.TRANSFER_OUT_KIND,
            FlowKind.INTERNAL_SUBACCOUNT_TRANSFER,
        }
        nav_sorted = sorted(ledger.nav_points, key=lambda p: p.timestamp_utc)
        start_ts = nav_sorted[0].timestamp_utc
        end_ts = nav_sorted[-1].timestamp_utc
        cap_flows = [
            f
            for f in ledger.flows
            if f.kind in capital_kinds and start_ts < f.timestamp_utc <= end_ts and f.amount_base is not None
        ]
        if not cap_flows:
            return ledger

        candidate_days: list[tuple[NormalizedNavPoint, NormalizedNavPoint, list[NormalizedFlow]]] = []
        for prev_pt, curr_pt in zip(nav_sorted, nav_sorted[1:]):
            if prev_pt.nav_base <= 0.0 or curr_pt.timestamp_utc in ledger.broker_period_returns:
                continue
            iv_flows = [
                f
                for f in cap_flows
                if prev_pt.timestamp_utc < f.timestamp_utc <= curr_pt.timestamp_utc
            ]
            gross = math.fsum(abs(float(f.amount_base or 0.0)) for f in iv_flows)
            if gross > 0.10 * prev_pt.nav_base:
                candidate_days.append((prev_pt, curr_pt, iv_flows))

        if not candidate_days:
            return ledger
        if len(candidate_days) > max_revaluation_days:
            # Prioritize intervals with withdrawals, churn, or >4-day spans first because
            # single-day positive deposits have a verified Modified Dietz fallback.
            def _probe_priority(
                entry: tuple[NormalizedNavPoint, NormalizedNavPoint, list[NormalizedFlow]],
            ) -> tuple[int, str]:
                p_pt, c_pt, fls = entry
                p_d = date.fromisoformat(p_pt.timestamp_utc[:10])
                c_d = date.fromisoformat(c_pt.timestamp_utc[:10])
                all_pos_dep = all(
                    (float(f.amount_base or 0.0) > 0.0 and f.kind != FlowKind.WITHDRAWAL)
                    for f in fls
                )
                needs_strict_cin = (not all_pos_dep) or ((c_d - p_d).days > 4)
                return (0 if needs_strict_cin else 1, c_pt.timestamp_utc)

            candidate_days = sorted(candidate_days, key=_probe_priority)[:max_revaluation_days]

        updated_returns = dict(ledger.broker_period_returns)
        extra_warnings = list(ledger.parser_warnings)
        changed = False
        query_omits_change_in_nav = False
        for prev_pt, curr_pt, iv_flows in candidate_days:
            if query_omits_change_in_nav:
                break
            prev_d = date.fromisoformat(prev_pt.timestamp_utc[:10])
            curr_d = date.fromisoformat(curr_pt.timestamp_utc[:10])
            min_from_d = prev_d + timedelta(days=1)
            earliest_flow_d = min(
                (date.fromisoformat(f.timestamp_utc[:10]) for f in iv_flows),
                default=curr_d,
            )
            primary_from_d = max(min_from_d, min(curr_d, earliest_flow_d))
            probe_windows = [(primary_from_d.strftime("%Y%m%d"), curr_d.strftime("%Y%m%d"))]
            if primary_from_d > min_from_d and (curr_d - min_from_d).days + 1 <= 365:
                probe_windows.append((min_from_d.strftime("%Y%m%d"), curr_d.strftime("%Y%m%d")))

            for fd_str, td_str in probe_windows:
                cache_key = f"{fd_str}:{td_str}"
                cached_probe = (
                    preloaded_xml_chunks.get(cache_key)
                    if preloaded_xml_chunks is not None
                    else None
                )
                try:
                    if cached_probe is not None:
                        day_xml = bytes(cached_probe)
                    else:
                        self._sleep_fn(self._chunk_pacing_seconds)
                        day_xml = self.fetch_statement_bytes(
                            flex_token=flex_token,
                            query_id=query_id,
                            from_date=fd_str,
                            to_date=td_str,
                        )
                        if fetched_xml_chunks_out is not None:
                            fetched_xml_chunks_out[cache_key] = day_xml
                    day_ledger = parse_ibkr_flex_xml(
                        day_xml,
                        blinding_salt_hex=blinding_salt_hex,
                        claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
                        provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
                        account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
                        require_live=require_live,
                        fallback_conversion_rates=ledger.conversion_rates,
                        fallback_dated_conversion_rates=shared_dated_fx,
                    )
                except (IbkrFlexServiceError, IbkrFlexParseError, ValueError) as exc:
                    warn_msg = (
                        f"IBKR ChangeInNAV probe for {curr_pt.timestamp_utc[:10]} did not return "
                        f"a statement ({type(exc).__name__})."
                    )
                    if warn_msg not in extra_warnings:
                        extra_warnings.append(warn_msg)
                    continue
                if (
                    day_ledger.blinded_account_tag != ledger.blinded_account_tag
                    or day_ledger.base_currency != ledger.base_currency
                ):
                    continue
                verified_ret = self._extract_verified_interval_twr_from_xml(
                    day_xml,
                    prev_pt=prev_pt,
                    curr_pt=curr_pt,
                )
                if verified_ret is not None:
                    updated_returns[curr_pt.timestamp_utc] = verified_ret
                    raw_chunks.append(day_xml)
                    changed = True
                    break
                _, _, day_omits_twr = self._prescan_single_account_fx_and_cin((day_xml,))
                if day_omits_twr or (
                    "ChangeInNAV" not in ledger.enabled_sections
                    and "ChangeInNAV" not in day_ledger.enabled_sections
                ):
                    query_omits_change_in_nav = True
                    break

        if not changed and extra_warnings == list(ledger.parser_warnings):
            return ledger
        data = ledger.to_dict()
        data["broker_period_returns"] = updated_returns
        data["parser_warnings"] = extra_warnings
        if changed:
            data["source_body_sha256"] = _hash_ibkr_xml_chunks(raw_chunks)
        return CanonicalPortfolioLedger.from_dict(data)

    def fetch_canonical_ledger(
        self,
        *,
        flex_token: str,
        query_id: str = "",
        query_ids: Sequence[str] | str | None = None,
        blinding_salt_hex: str,
        start_date: str | None = None,
        end_date: str | None = None,
        require_live: bool = True,
        preloaded_xml_chunks: Mapping[str, bytes] | None = None,
        fetched_xml_chunks_out: dict[str, bytes] | None = None,
    ) -> CanonicalPortfolioLedger:
        resolved_qids: list[str] = []
        if query_ids is not None:
            if isinstance(query_ids, str):
                resolved_qids.extend(
                    part.strip() for part in query_ids.split(",") if part.strip()
                )
            else:
                resolved_qids.extend(str(q).strip() for q in query_ids if str(q).strip())
        if (query_id or "").strip() and (query_id or "").strip() not in resolved_qids:
            resolved_qids.insert(0, query_id.strip())
        if not resolved_qids:
            raise ValueError("query_id (or query_ids) must be non-empty")
        if len(resolved_qids) > 10:
            raise ValueError("At most 10 IBKR Flex query IDs may be combined in one verification")

        raw_chunks: list[bytes] = []
        parsed_ledgers: list[CanonicalPortfolioLedger] = []

        norm_start_d = _parse_ibkr_date_only(start_date, field_name="start_date")
        norm_end_d = _parse_ibkr_date_only(end_date, field_name="end_date")
        auto_end = norm_start_d is not None and norm_end_d is None
        if auto_end:
            assert norm_start_d is not None
            norm_end_d = max(norm_start_d, _default_auto_end_ny_date(self._now_utc_fn()))
        elif norm_end_d is not None and norm_start_d is None:
            raise ValueError("start_date is required when end_date is specified for IBKR Flex")

        if norm_start_d is not None and norm_end_d is not None and len(resolved_qids) == 1:
            primary_qid = resolved_qids[0]
            date_chunks = split_ibkr_flex_date_chunks(norm_start_d, norm_end_d)
            live_fetches_done = 0
            for chunk_idx, (fd_s, td_s) in enumerate(date_chunks):
                chunk_key = f"{fd_s}:{td_s}"
                cached_bytes = (
                    preloaded_xml_chunks.get(chunk_key)
                    if preloaded_xml_chunks is not None
                    else None
                )
                if cached_bytes is not None:
                    chunk_bytes = bytes(cached_bytes)
                else:
                    if live_fetches_done > 0:
                        self._sleep_fn(self._chunk_pacing_seconds)
                    try:
                        chunk_bytes = self.fetch_statement_bytes(
                            flex_token=flex_token,
                            query_id=primary_qid,
                            from_date=fd_s,
                            to_date=td_s,
                        )
                        live_fetches_done += 1
                    except IbkrFlexServiceError as exc:
                        live_fetches_done += 1
                        is_final_auto_chunk = auto_end and chunk_idx == len(date_chunks) - 1
                        if not is_final_auto_chunk or not _is_settlement_not_ready_error(exc):
                            raise
                        fd_d = date.fromisoformat(f"{fd_s[:4]}-{fd_s[4:6]}-{fd_s[6:8]}")
                        orig_td_d = date.fromisoformat(f"{td_s[:4]}-{td_s[4:6]}-{td_s[6:8]}")
                        last_exc: IbkrFlexServiceError = exc
                        skip_trailing_chunk = False
                        recovered_bytes: bytes | None = None
                        for step_back in (1, 2, 3):
                            stepped_td_d = orig_td_d - timedelta(days=step_back)
                            if stepped_td_d < fd_d:
                                if raw_chunks:
                                    skip_trailing_chunk = True
                                    break
                                raise last_exc
                            stepped_td_s = stepped_td_d.strftime("%Y%m%d")
                            stepped_key = f"{fd_s}:{stepped_td_s}"
                            stepped_cached = (
                                preloaded_xml_chunks.get(stepped_key)
                                if preloaded_xml_chunks is not None
                                else None
                            )
                            if stepped_cached is not None:
                                chunk_key = stepped_key
                                recovered_bytes = bytes(stepped_cached)
                                break
                            self._sleep_fn(self._chunk_pacing_seconds)
                            try:
                                recovered_bytes = self.fetch_statement_bytes(
                                    flex_token=flex_token,
                                    query_id=primary_qid,
                                    from_date=fd_s,
                                    to_date=stepped_td_s,
                                )
                                live_fetches_done += 1
                                chunk_key = stepped_key
                                break
                            except IbkrFlexServiceError as retry_exc:
                                live_fetches_done += 1
                                if not _is_settlement_not_ready_error(retry_exc):
                                    raise
                                last_exc = retry_exc
                        if skip_trailing_chunk:
                            continue
                        if recovered_bytes is None:
                            raise last_exc
                        chunk_bytes = recovered_bytes
                    if fetched_xml_chunks_out is not None:
                        fetched_xml_chunks_out[chunk_key] = chunk_bytes
                raw_chunks.append(chunk_bytes)
        else:
            for idx, qid in enumerate(resolved_qids):
                if idx > 0:
                    self._sleep_fn(self._chunk_pacing_seconds)
                chunk_bytes = self.fetch_statement_bytes(flex_token=flex_token, query_id=qid)
                raw_chunks.append(chunk_bytes)

        shared_dated_fx, shared_closing_fx, query_omits_cin_twr = (
            self._prescan_single_account_fx_and_cin(raw_chunks)
        )
        for chunk_bytes in raw_chunks:
            parsed_ledgers.append(
                parse_ibkr_flex_xml(
                    chunk_bytes,
                    blinding_salt_hex=blinding_salt_hex,
                    claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
                    provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
                    account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
                    require_live=require_live,
                    fallback_dated_conversion_rates=shared_dated_fx,
                    fallback_closing_inferred_rates=shared_closing_fx,
                )
            )

        merged = merge_ibkr_flex_ledgers(parsed_ledgers, raw_chunks=raw_chunks)
        if norm_start_d is None and "ChangeInNAV" not in merged.enabled_sections:
            return merged
        return self._enrich_large_flow_days_with_broker_twr(
            merged,
            raw_chunks,
            flex_token=flex_token,
            query_id=resolved_qids[0],
            blinding_salt_hex=blinding_salt_hex,
            require_live=require_live,
            preloaded_xml_chunks=preloaded_xml_chunks,
            fetched_xml_chunks_out=fetched_xml_chunks_out,
            shared_dated_fx=shared_dated_fx,
            query_omits_cin_twr=query_omits_cin_twr,
        )


class IbkrFlexOfflineAdapter(ReadOnlyBrokerAdapter):
    """Offline IBKR Flex XML parser adapter (`SELF_REPORTED`, `UNKNOWN_OFFLINE_SCOPE`)."""

    broker_id = "ibkr_flex_offline"
    display_name = "Interactive Brokers Offline Flex XML Import"
    approval_state = ProviderApprovalState.OFFLINE_EXPORT_ONLY
    default_origin_assurance = OriginAssurance.SELF_REPORTED
    supports_subaccount_enumeration = False
    allowed_capabilities = ("parse_statement_export",)

    def parse_export(
        self,
        source: bytes | str | Path,
        *,
        blinding_salt_hex: str,
        require_live: bool = True,
        environment_tier: EnvironmentTier | str = EnvironmentTier.UNVERIFIED_OFFLINE,
    ) -> CanonicalPortfolioLedger:
        return parse_ibkr_flex_xml(
            source,
            blinding_salt_hex=blinding_salt_hex,
            claimed_origin_assurance=OriginAssurance.SELF_REPORTED,
            provider_approval_state=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
            account_scope=AccountScope.UNKNOWN_OFFLINE_SCOPE,
            require_live=require_live,
            environment_tier=environment_tier,
        )


__all__ = [
    "DEFAULT_IBKR_FLEX_USER_AGENT",
    "IBKR_FLEX_GET_STATEMENT_URL",
    "IBKR_FLEX_SEND_REQUEST_URL",
    "INFERRED_SINGLE_PRIOR_POSITION_WARNING",
    "OMITTED_PRIOR_POSITION_QTY_WARNING",
    "OMITTED_PRIOR_POSITION_SYMBOLS_PREFIX",
    "IbkrFlexOfflineAdapter",
    "IbkrFlexParseError",
    "IbkrFlexServiceError",
    "IbkrFlexWebServiceAdapter",
    "IbkrFlexXmlSecurityError",
    "merge_ibkr_flex_ledgers",
    "parse_ibkr_flex_xml",
    "split_ibkr_flex_date_chunks",
]
