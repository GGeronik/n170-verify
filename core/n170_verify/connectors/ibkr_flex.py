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

from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
from io import BytesIO
from pathlib import Path
import re
import time
from typing import Any
import urllib.parse
import xml.etree.ElementTree as ET

from n170_verify.connectors.ccxt_crypto import (
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

DEFAULT_MAX_FLEX_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_FLEX_ELEMENTS = 150_000
DEFAULT_MAX_SECTION_ROWS = 25_000

_PAPER_IBKR_ACCOUNT_RE = re.compile(r"^D[UF][0-9]{4,}$", re.IGNORECASE)
_SPLIT_RATIO_RE = re.compile(
    r"\b([0-9]+(?:\.[0-9]+)?)\s*(?:FOR|:|/)\s*([0-9]+(?:\.[0-9]+)?)\b",
    re.IGNORECASE,
)
_XML_ENCODING_DECL_RE = re.compile(
    rb'(<\?xml[^>]*?\bencoding\s*=\s*["\'])([^"\']+)(["\'])',
    re.IGNORECASE,
)
_FLEX_FORMULA_TRIGGER_CHARS: frozenset[str] = frozenset(
    {"=", "+", "-", "@", "'", "|", "\t", "\r", "\n", "\v", "\f"}
)
_FLEX_XXE_DECL_RE = re.compile(
    rb"<![^>]*?\b(?:doctype|entity|element|attlist|system|public)\b",
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


def _parse_flex_timestamp_utc(raw: str | None) -> str | None:
    if not raw:
        return None
    candidate = raw.strip()
    # Common IBKR Flex formats:
    # "20240103", "2024-01-03", "20240103;154512", "2024-01-03;15:45:12",
    # "2024-01-03, 15:45:12", "2024-01-03T15:45:12Z"
    normalized = candidate.replace(", ", "T").replace(";", "T").replace(" ", "T")
    if normalized.endswith(("Z", "z")) or "+" in normalized[10:]:
        try:
            dt = datetime.fromisoformat(normalized.replace("Z", "+00:00").replace("z", "+00:00"))
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass

    for fmt in (
        "%Y%m%dT%H%M%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y%m%d",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(normalized, fmt).replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return None


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


def _map_ibkr_asset_class(raw_cat: str | None, *, sub_cat: str | None = None) -> AssetClass:
    cat = (raw_cat or "STK").strip().upper()
    sub = (sub_cat or "").strip().upper()
    if cat == "STK":
        return AssetClass.ETF if sub == "ETF" else AssetClass.EQUITY
    if cat in {"OPT", "FOP", "IOPT", "WAR"}:
        return AssetClass.OPTION
    if cat in {"FUT", "CFD", "CMDTY"}:
        return AssetClass.FUTURE
    if cat == "CASH":
        return AssetClass.FX
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
            "electronic fund",
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
            if n_val > 0 and d_val > 0:
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


def parse_ibkr_flex_xml(
    source: bytes | str | Path,
    *,
    blinding_salt_hex: str = "ab" * 32,
    claimed_origin_assurance: OriginAssurance = OriginAssurance.SELF_REPORTED,
    provider_approval_state: ProviderApprovalState = ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    account_scope: AccountScope = AccountScope.UNKNOWN_OFFLINE_SCOPE,
    require_live: bool = True,
    max_bytes: int = DEFAULT_MAX_FLEX_BYTES,
    max_elements: int = DEFAULT_MAX_FLEX_ELEMENTS,
    max_section_rows: int = DEFAULT_MAX_SECTION_ROWS,
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
    prior_pos_rows: list[dict[str, str]] = []
    open_pos_rows: list[dict[str, str]] = []
    trade_rows: list[dict[str, str]] = []
    cash_tx_rows: list[dict[str, str]] = []
    transfer_rows: list[dict[str, str]] = []
    corp_action_rows: list[dict[str, str]] = []
    option_eae_rows: list[dict[str, str]] = []
    conv_rate_rows: list[dict[str, str]] = []

    element_count = 0
    in_statement = False
    statement_depth: int | None = None
    stack: list[ET.Element] = []

    def _mark_section(sec_name: str) -> None:
        if sec_name not in seen_sections:
            seen_sections.add(sec_name)
            enabled_sections.append(sec_name)

    def _append_bounded(target: list[dict[str, str]], attrs: dict[str, str], label: str) -> None:
        if len(target) >= max_section_rows:
            raise IbkrFlexParseError(f"Flex section {label} exceeds {max_section_rows}-row limit")
        target.append(dict(attrs))

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
                    statement_attrs_list.append(dict(elem.attrib))
                    continue

                if not in_statement:
                    continue

                if ltag in {"equitysummaryinbase", "equitysummarybyreportdateinbase", "netassetvalue", "nav"}:
                    _mark_section("EquitySummaryInBase")
                    if _first_attr(elem.attrib, ("reportDate", "date", "asOfDate", "toDate", "total", "netLiquidationValue")):
                        _append_bounded(nav_rows, elem.attrib, "EquitySummaryInBase")
                elif ltag == "priorperiodpositions":
                    _mark_section("PriorPeriodPositions")
                elif ltag == "priorperiodposition":
                    _mark_section("PriorPeriodPositions")
                    _append_bounded(prior_pos_rows, elem.attrib, "PriorPeriodPositions")
                elif ltag == "openpositions":
                    _mark_section("OpenPositions")
                elif ltag == "openposition":
                    _mark_section("OpenPositions")
                    _append_bounded(open_pos_rows, elem.attrib, "OpenPositions")
                elif ltag == "trades":
                    _mark_section("Trades")
                elif ltag == "trade":
                    _mark_section("Trades")
                    _append_bounded(trade_rows, elem.attrib, "Trades")
                elif ltag == "cashtransactions":
                    _mark_section("CashTransactions")
                elif ltag == "cashtransaction":
                    _mark_section("CashTransactions")
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

    raw_acct_ids: list[str] = []
    for st in statement_attrs_list:
        aid = _first_attr(st, ("accountId", "acctCode"))
        if aid and aid not in raw_acct_ids:
            raw_acct_ids.append(aid)

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
        if not cleaned:
            return default
        if cleaned == "GBp" or cleaned.upper() == "GBX":
            return "GBX"
        return cleaned.upper()

    # 1. ConversionRates
    conversion_rates: dict[str, float] = {}
    for row in conv_rate_rows:
        from_ccy = _normalize_flex_currency(_first_attr(row, ("fromCurrency",)), "")
        to_ccy = _normalize_flex_currency(_first_attr(row, ("toCurrency",)), "")
        rate = _parse_flex_float(_first_attr(row, ("rate",)))
        if from_ccy and to_ccy and rate is not None and rate > 0.0:
            conversion_rates[f"{from_ccy}/{to_ccy}"] = rate

    def _resolve_fx(attrs: dict[str, str], ccy: str) -> float:
        explicit = _parse_flex_float(_first_attr(attrs, ("fxRateToBase", "fxRate")))
        if explicit is not None and explicit > 0.0:
            return explicit
        ccy_upper = _normalize_flex_currency(ccy, base_ccy)
        if ccy_upper == base_ccy:
            return 1.0
        direct = conversion_rates.get(f"{ccy_upper}/{base_ccy}")
        if direct is not None and direct > 0.0:
            return direct
        inverse = conversion_rates.get(f"{base_ccy}/{ccy_upper}")
        if inverse is not None and inverse > 0.0:
            return 1.0 / inverse
        if ccy_upper == "GBX":
            if base_ccy == "GBP":
                return 0.01
            gbp_direct = conversion_rates.get(f"GBP/{base_ccy}")
            if gbp_direct is not None and gbp_direct > 0.0:
                return 0.01 * gbp_direct
            gbp_inv = conversion_rates.get(f"{base_ccy}/GBP")
            if gbp_inv is not None and gbp_inv > 0.0:
                return 0.01 / gbp_inv
        return 1.0

    # 2. EquitySummaryInBase -> NormalizedNavPoint
    nav_by_ts: dict[str, NormalizedNavPoint] = {}
    warnings: list[str] = []
    for row in nav_rows:
        ts = _parse_flex_timestamp_utc(_first_attr(row, ("reportDate", "date", "asOfDate", "toDate")))
        total = _parse_flex_float(
            _first_attr(row, ("total", "netLiquidationValue", "netAssetValue", "value", "endingValue"))
        )
        if ts is None or total is None or total <= 0.0:
            warnings.append("Ignored invalid or non-positive EquitySummaryInBase row.")
            continue
        cash_b = _parse_flex_float(_first_attr(row, ("cash", "cashLong")))
        stock_b = _parse_flex_float(_first_attr(row, ("stock",)), default=0.0) or 0.0
        opt_b = _parse_flex_float(_first_attr(row, ("options",)), default=0.0) or 0.0
        comm_b = _parse_flex_float(_first_attr(row, ("commodities", "bonds")), default=0.0) or 0.0
        pos_b = (stock_b + opt_b + comm_b) if any(k.lower() in {x.lower() for x in row} for k in ("stock", "options", "commodities", "bonds")) else None
        div_acc = _parse_flex_float(_first_attr(row, ("dividendAccruals",)), default=0.0) or 0.0
        int_acc = _parse_flex_float(_first_attr(row, ("interestAccruals",)), default=0.0) or 0.0
        acc_b = (div_acc + int_acc) if any(k.lower() in {x.lower() for x in row} for k in ("dividendAccruals", "interestAccruals")) else None
        nav_by_ts[ts] = NormalizedNavPoint(
            timestamp_utc=ts,
            nav_base=total,
            cash_base=cash_b,
            positions_base=pos_b,
            accruals_base=acc_b,
        )
    nav_points = [nav_by_ts[k] for k in sorted(nav_by_ts)]

    # 3. PriorPeriodPositions & OpenPositions
    def _parse_positions(rows: list[dict[str, str]], boundary: str) -> list[NormalizedPosition]:
        has_summary = any(
            (_first_attr(r, ("levelOfDetail",)) or "").upper() == "SUMMARY" for r in rows
        )
        out: list[NormalizedPosition] = []
        for r in rows:
            lod = (_first_attr(r, ("levelOfDetail",)) or "").upper()
            if has_summary and lod and lod != "SUMMARY":
                continue
            sym = _first_text_attr(r, ("symbol", "underlyingSymbol", "description"))
            if not sym:
                continue
            qty = _parse_flex_float(_first_attr(r, ("position", "quantity")), default=0.0) or 0.0
            cost = _parse_flex_float(_first_attr(r, ("costBasisMoney", "costBasis", "costBasisPrice")), default=0.0) or 0.0
            mv = _parse_flex_float(
                _first_attr(r, ("positionValue", "markToMarket", "marketValue", "value")),
                default=0.0,
            ) or 0.0
            ccy = _normalize_flex_currency(_first_attr(r, ("currency", "currencyPrimary")), base_ccy)
            fx = _resolve_fx(r, ccy)
            ac = _map_ibkr_asset_class(_first_attr(r, ("assetCategory", "assetClass")), sub_cat=_first_attr(r, ("subCategory",)))
            mult = _parse_flex_float(_first_attr(r, ("multiplier",)))
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
    ending_positions = _parse_positions(open_pos_rows, "ending")

    # 4. Trades
    has_exec_lod = any(
        (_first_attr(r, ("levelOfDetail",)) or "").upper() == "EXECUTION" for r in trade_rows
    )
    trades_by_id: dict[str, NormalizedTrade] = {}
    for idx, r in enumerate(trade_rows):
        lod = (_first_attr(r, ("levelOfDetail",)) or "").upper()
        if has_exec_lod and lod and lod != "EXECUTION":
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
        fx = _resolve_fx(r, ccy)
        ac = _map_ibkr_asset_class(_first_attr(r, ("assetCategory", "assetClass")), sub_cat=_first_attr(r, ("subCategory",)))
        mult = _parse_flex_float(_first_attr(r, ("multiplier",)))
        comm = abs(_parse_flex_float(_first_attr(r, ("ibCommission", "commission")), default=0.0) or 0.0)
        tax = abs(_parse_flex_float(_first_attr(r, ("taxes", "tax")), default=0.0) or 0.0)
        entry_id = _first_text_attr(r, ("ibExecID", "tradeID")) or f"flex-trade-{idx}"
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
            exchange=_first_text_attr(r, ("exchange", "listingExchange")),
            option_right=opt_right,
            strike=_parse_flex_float(_first_attr(r, ("strike",))),
            expiry=_first_text_attr(r, ("expiry",)),
            underlying_symbol=_first_text_attr(r, ("underlyingSymbol",)),
        )

    # 5. CashTransactions & 6. Transfers -> NormalizedFlow
    flows: list[NormalizedFlow] = []
    for r in cash_tx_rows:
        lod = (_first_attr(r, ("levelOfDetail",)) or "").upper()
        if lod == "SUMMARY":
            continue
        ts = _parse_flex_timestamp_utc(
            _first_attr(r, ("dateTime", "reportDate", "settleDate", "tradeDate", "date"))
        )
        amt = _parse_flex_float(_first_attr(r, ("amount", "netAmount")))
        if ts is None or amt is None:
            continue
        ccy = _normalize_flex_currency(_first_attr(r, ("currency", "currencyPrimary")), base_ccy)
        fx = _resolve_fx(r, ccy)
        kind = _classify_cash_transaction_kind(r, amt)
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
        fx = _resolve_fx(r, ccy)
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
        if lod == "SUMMARY":
            continue
        ts = _parse_flex_timestamp_utc(_first_attr(r, ("dateTime", "reportDate", "date")))
        sym = _first_text_attr(r, ("symbol", "underlyingSymbol"))
        if ts is None or not sym:
            continue
        act_type, num, den = _classify_corporate_action(r)
        ccy = _normalize_flex_currency(_first_attr(r, ("currency", "currencyPrimary")), base_ccy)
        fx = _resolve_fx(r, ccy)
        qty_delta = _parse_flex_float(_first_attr(r, ("quantity",)), default=0.0) or 0.0
        cash_lieu = (_parse_flex_float(_first_attr(r, ("proceeds", "amount")), default=0.0) or 0.0) * fx
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
        fx = _resolve_fx(r, ccy)
        qty_delta = _parse_flex_float(_first_attr(r, ("quantity",)), default=0.0) or 0.0
        mult = _parse_flex_float(_first_attr(r, ("multiplier",)), default=100.0)
        basis_adj = (_parse_flex_float(_first_attr(r, ("costBasisMoney", "proceeds")), default=0.0) or 0.0) * fx
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

    stmt_start = _parse_flex_timestamp_utc(_first_attr(primary_stmt, ("fromDate", "startDate")))
    stmt_end = _parse_flex_timestamp_utc(_first_attr(primary_stmt, ("toDate", "endDate")))
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
        connected_subaccount_count=len(statement_attrs_list),
        prior_positions=prior_positions,
        ending_positions=ending_positions,
        nav_points=nav_points,
        trades=sorted(trades_by_id.values(), key=lambda t: (t.timestamp_utc, t.native_entry_id)),
        flows=sorted(flows, key=lambda f: f.timestamp_utc),
        corporate_actions=sorted(corporate_actions, key=lambda c: c.timestamp_utc),
        conversion_rates=conversion_rates,
        enabled_sections=enabled_sections,
        parser_warnings=warnings,
    )


def _parse_flex_service_envelope(raw_xml: bytes, secrets: Sequence[str]) -> tuple[str, str | None, str | None, str | None]:
    """Return ``(status, reference_code, error_code, error_message)`` while ignoring ``<Url>``."""
    safe_bytes = _decode_and_guard_xml_bytes(raw_xml, max_bytes=2 * 1024 * 1024)
    try:
        root = ET.fromstring(safe_bytes)
    except ET.ParseError as exc:
        raise IbkrFlexServiceError("Invalid XML returned by IBKR Flex Web Service") from exc

    if _local_tag(root.tag) != "flexstatementresponse":
        return "StatementReady", None, None, None

    status = ""
    ref_code: str | None = None
    err_code: str | None = None
    err_msg: str | None = None
    for child in root:
        ctag = _local_tag(child.tag)
        val = (child.text or "").strip()
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
            continue
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
        max_poll_attempts: int = 5,
        poll_interval_seconds: float = 2.0,
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
        self._max_poll_attempts = max(1, max_poll_attempts)
        self._poll_interval_seconds = max(0.0, poll_interval_seconds)

    def fetch_statement_bytes(self, *, flex_token: str, query_id: str) -> bytes:
        """Execute ``SendRequest`` -> ``GetStatement`` (``v=3``) against ``ndcdyn`` only."""
        token_clean = (flex_token or "").strip()
        query_clean = (query_id or "").strip()
        if not token_clean or not query_clean:
            raise ValueError("flex_token and query_id must be non-empty strings")

        secrets = (token_clean, query_clean)
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/xml, text/xml",
        }

        send_qs = urllib.parse.urlencode({"t": token_clean, "q": query_clean, "v": "3"})
        send_url = f"{IBKR_FLEX_SEND_REQUEST_URL}?{send_qs}"
        send_resp = invoke_http_transport(
            self._transport,
            "GET",
            send_url,
            headers=headers,
            extra_secrets=secrets,
        )
        if send_resp.status_code != 200:
            raise IbkrFlexServiceError(
                f"IBKR Flex SendRequest failed with HTTP {send_resp.status_code} "
                f"(target={IBKR_FLEX_SEND_REQUEST_URL}?t=[REDACTED]&q=[REDACTED]&v=3)"
            )

        status, ref_code, err_code, err_msg = _parse_flex_service_envelope(send_resp.body, secrets)
        if status.lower() != "success" or not ref_code:
            raise IbkrFlexServiceError(
                f"IBKR Flex SendRequest rejected (code={err_code or 'unknown'}): {err_msg or 'no reference code'}"
            )

        all_secrets = (token_clean, query_clean, ref_code)
        get_qs = urllib.parse.urlencode({"t": token_clean, "q": ref_code, "v": "3"})
        # Always use hardcoded IBKR_FLEX_GET_STATEMENT_URL (ndcdyn); never use SendRequest <Url>!
        get_url = f"{IBKR_FLEX_GET_STATEMENT_URL}?{get_qs}"

        for attempt in range(self._max_poll_attempts):
            stmt_resp = invoke_http_transport(
                self._transport,
                "GET",
                get_url,
                headers=headers,
                extra_secrets=all_secrets,
            )
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
            if st_err_code in {"1018", "1019"} and attempt + 1 < self._max_poll_attempts:
                self._sleep_fn(self._poll_interval_seconds)
                continue
            raise IbkrFlexServiceError(
                f"IBKR Flex GetStatement failed (code={st_err_code or 'unknown'}): "
                f"{st_err_msg or 'statement unavailable'}"
            )

        raise IbkrFlexServiceError("IBKR Flex GetStatement polling timed out")

    def fetch_canonical_ledger(
        self,
        *,
        flex_token: str,
        query_id: str,
        blinding_salt_hex: str,
        require_live: bool = True,
    ) -> CanonicalPortfolioLedger:
        xml_bytes = self.fetch_statement_bytes(flex_token=flex_token, query_id=query_id)
        return parse_ibkr_flex_xml(
            xml_bytes,
            blinding_salt_hex=blinding_salt_hex,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
            require_live=require_live,
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
    ) -> CanonicalPortfolioLedger:
        return parse_ibkr_flex_xml(
            source,
            blinding_salt_hex=blinding_salt_hex,
            claimed_origin_assurance=OriginAssurance.SELF_REPORTED,
            provider_approval_state=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
            account_scope=AccountScope.UNKNOWN_OFFLINE_SCOPE,
            require_live=require_live,
        )


__all__ = [
    "DEFAULT_IBKR_FLEX_USER_AGENT",
    "IBKR_FLEX_GET_STATEMENT_URL",
    "IBKR_FLEX_SEND_REQUEST_URL",
    "IbkrFlexOfflineAdapter",
    "IbkrFlexParseError",
    "IbkrFlexServiceError",
    "IbkrFlexWebServiceAdapter",
    "IbkrFlexXmlSecurityError",
    "parse_ibkr_flex_xml",
]
