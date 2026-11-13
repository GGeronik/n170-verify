"""Offline statement parsers, CSV/XXE hardening, and zero-dropdown format auto-detection.

Security & ToS Governance:
- Unofficial Robinhood / DEGIRO username, password, session-cookie, or TOTP/MFA
  scraping is HARD-BLOCKED (``ProviderApprovalState.OFFLINE_EXPORT_ONLY``, raising
  ``UnsupportedScraperPolicyError`` if any credential/session/TOTP parameter is passed).
- All offline exports carry ``OriginAssurance.SELF_REPORTED`` and
  ``AccountScope.UNKNOWN_OFFLINE_SCOPE``.
- ``sanitize_csv_text_field`` neutralizes leading spreadsheet formula-injection triggers
  (``=``, ``+``, ``-``, ``@``, ``\\t``, ``\\r``, ``\\n``, even after leading spaces) across
  all text columns while keeping signed numeric parsing intact.
- ``MAX_STATEMENT_BYTES`` (``25 MB``) and ``reject_xxe_and_dtd_declarations`` block
  oversize payloads and ``<!DOCTYPE`` / ``<!ENTITY`` / ``SYSTEM`` / ``PUBLIC`` external
  entities in memory before any XML or HTML parser executes.
"""

from __future__ import annotations

from collections.abc import Mapping
import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from io import StringIO
import re
from typing import Any

from n170_verify.connectors.ccxt_crypto import UnsupportedScraperPolicyError
from n170_verify.connectors.ibkr_flex import IbkrFlexXmlSecurityError, parse_ibkr_flex_xml
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    CanonicalPortfolioLedger,
    ContractModelMixin,
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
    ReconciliationStatus,
    compute_blinded_account_tag,
)


MAX_STATEMENT_BYTES: int = 25 * 1024 * 1024

ALLOWED_DETECTED_FORMATS: frozenset[str] = frozenset(
    {
        "ibkr_flex_xml",
        "degiro_csv",
        "robinhood_csv",
        "schwab_csv",
        "mt4_statement",
        "mt5_statement",
        "tradovate_csv",
        "tradersync_journal",
        "tradezella_journal",
    }
)

_FORMULA_TRIGGER_CHARS: frozenset[str] = frozenset(
    {"=", "+", "-", "@", "'", "|", "\t", "\r", "\n", "\v", "\f"}
)

_XXE_DECL_SYSTEM_PUBLIC_RE = re.compile(
    rb"<![^>]*?\b(?:doctype|entity|element|attlist|system|public)\b",
    re.IGNORECASE | re.DOTALL,
)
_XXE_EXTERNAL_URI_RE = re.compile(
    rb"\b(?:system|public)\s+['\"](?:file|https?|ftp|jar|netdoc|php|gopher|data|expect):",
    re.IGNORECASE,
)


class StatementSizeLimitExceededError(ValueError):
    """Raised when an uploaded statement exceeds ``MAX_STATEMENT_BYTES`` (25 MB)."""


class StatementXmlHtmlSecurityError(IbkrFlexXmlSecurityError):
    """Raised when DTD, entity, SYSTEM, or PUBLIC declarations are detected in XML/HTML."""


_SCRAPER_FORBIDDEN_KWARGS: frozenset[str] = frozenset(
    {
        "username",
        "user",
        "email",
        "password",
        "passphrase",
        "totp",
        "totp_secret",
        "mfa_code",
        "sms_code",
        "otp",
        "session_cookie",
        "cookie",
        "cookies",
        "session_id",
        "int_account",
        "device_token",
        "bearer_token",
        "access_token",
        "refresh_token",
        "api_key",
        "api_secret",
        "login_url",
    }
)

_ISIN_RE = re.compile(r"^[A-Z]{2}[A-Z0-9]{9}[0-9]$")
_CCY_AMOUNT_RE = re.compile(r"^([A-Z]{3})\s*([-+]?[0-9.,]+)$")


def sanitize_csv_text_field(value: str | None) -> str:
    """Strip leading whitespace and spreadsheet formula-injection triggers (`=`, `+`, `-`, `@`, `\\t`, `\\r`, `\\n`).

    Applied exclusively to text/identifier/comment columns; signed numeric columns
    must be parsed directly as floats before text sanitization.
    """
    if value is None:
        return ""
    cleaned = str(value).replace("\x00", "")
    if not cleaned:
        return ""

    sanitized_lines: list[str] = []
    for raw_line in cleaned.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw_line.replace("\t", " ")
        idx = 0
        n = len(line)
        while idx < n and (line[idx].isspace() or line[idx] in _FORMULA_TRIGGER_CHARS):
            idx += 1
        seg = line[idx:].strip()
        if seg:
            sanitized_lines.append(seg)

    joined = " ".join(sanitized_lines).strip()
    idx = 0
    n = len(joined)
    while idx < n and (joined[idx].isspace() or joined[idx] in _FORMULA_TRIGGER_CHARS):
        idx += 1
    return joined[idx:].strip()


def enforce_statement_size_limit(
    raw: bytes | str | None,
    *,
    max_bytes: int = MAX_STATEMENT_BYTES,
) -> bytes:
    """Convert statement payload to raw bytes while enforcing bounded ``max_bytes``."""
    if raw is None:
        return b""
    if isinstance(raw, bytes):
        if len(raw) > max_bytes:
            raise StatementSizeLimitExceededError(
                f"Statement payload ({len(raw)} bytes) exceeds {max_bytes}-byte safety limit"
            )
        return raw
    if isinstance(raw, str):
        # Fast upper-bound check before encoding huge strings, then exact UTF-8 byte check.
        if len(raw) > max_bytes:
            raise StatementSizeLimitExceededError(
                f"Statement payload exceeds {max_bytes}-byte safety limit"
            )
        encoded = raw.encode("utf-8")
        if len(encoded) > max_bytes:
            raise StatementSizeLimitExceededError(
                f"Statement payload ({len(encoded)} bytes) exceeds {max_bytes}-byte safety limit"
            )
        return encoded
    raise TypeError(f"Expected bytes or str for statement input, got {type(raw).__name__}")


def reject_xxe_and_dtd_declarations(raw: bytes | str) -> None:
    """Hard-reject ``<!DOCTYPE``, ``<!ENTITY``, ``SYSTEM``, or ``PUBLIC`` declarations in memory."""
    raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
    candidates: list[bytes] = [raw_bytes.replace(b"\x00", b"")]
    if isinstance(raw, bytes) and raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            candidates.append(raw.decode("utf-16", errors="ignore").encode("utf-8"))
        except Exception:
            pass
    for candidate in candidates:
        lowered = candidate.lower()
        for token in (b"<!doctype", b"<!entity", b"<!element", b"<!attlist"):
            if token in lowered:
                raise StatementXmlHtmlSecurityError(
                    "XML/HTML DTD and entity declarations (<!DOCTYPE / <!ENTITY) are strictly forbidden"
                )
        if _XXE_DECL_SYSTEM_PUBLIC_RE.search(candidate) or _XXE_EXTERNAL_URI_RE.search(candidate):
            raise StatementXmlHtmlSecurityError(
                "External SYSTEM / PUBLIC entity declarations are strictly forbidden in statement inputs"
            )


def decode_statement_bytes(
    raw: bytes | str | None,
    *,
    max_bytes: int = MAX_STATEMENT_BYTES,
) -> tuple[str, bytes]:
    """Enforce size bounds and decode UTF-8 / UTF-16 statement payloads in memory."""
    if raw is None:
        return "", b""
    raw_bytes = enforce_statement_size_limit(raw, max_bytes=max_bytes)
    if isinstance(raw, str):
        return raw.lstrip("\ufeff"), raw_bytes

    if raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw_bytes.decode("utf-16").lstrip("\ufeff"), raw_bytes
        except UnicodeDecodeError as exc:
            raise ValueError("Malformed UTF-16 statement payload") from exc

    head = raw_bytes[:128]
    if b"\x00" in head:
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                decoded = raw_bytes.decode(enc).lstrip("\ufeff")
                if decoded.strip():
                    return decoded, raw_bytes
            except UnicodeDecodeError:
                continue
        raise ValueError("Binary or corrupted NUL-containing statement payload cannot be decoded")

    try:
        return raw_bytes.decode("utf-8-sig"), raw_bytes
    except UnicodeDecodeError:
        return raw_bytes.decode("latin-1"), raw_bytes


def reject_unofficial_scraper_credentials(**kwargs: Any) -> None:
    """Hard-block any unofficial Robinhood/DEGIRO credential, cookie, or TOTP parameter."""
    offending: list[str] = []
    for raw_k in kwargs:
        norm = re.sub(r"[^a-z0-9]+", "_", raw_k.strip().lower()).strip("_")
        if norm in _SCRAPER_FORBIDDEN_KWARGS or raw_k.strip().lower() in _SCRAPER_FORBIDDEN_KWARGS:
            offending.append(raw_k)
    if offending:
        raise UnsupportedScraperPolicyError(
            f"Unofficial credential/cookie/TOTP scraping is strictly forbidden "
            f"(OFFLINE_EXPORT_ONLY policy; rejected parameter(s): {sorted(offending)})."
        )


def _parse_localized_float(raw: str | None, *, default: float | None = None) -> float | None:
    if raw is None:
        return default
    cleaned = (
        raw.strip()
        .replace("$", "")
        .replace("€", "")
        .replace("£", "")
        .replace("\xa0", "")
        .strip()
    )
    if not cleaned or cleaned in {"-", "--", "N/A", "n/a"}:
        return default
    neg = False
    if cleaned.startswith("(") and cleaned.endswith(")"):
        neg = True
        cleaned = cleaned[1:-1].strip().replace("$", "").replace("€", "").replace("£", "").strip()
    elif cleaned.startswith("-(") and cleaned.endswith(")"):
        neg = True
        cleaned = cleaned[2:-1].strip()

    # Remove thousands-separator spaces between digits (e.g. MT4/MT5 "10 000.00")
    cleaned = re.sub(r"(?<=\d)\s+(?=\d)", "", cleaned)

    if "," in cleaned and "." in cleaned:
        if cleaned.rfind(",") > cleaned.rfind("."):
            # European 1.234,56 -> 1234.56
            cleaned = cleaned.replace(".", "").replace(",", ".")
        else:
            # Anglo 1,234.56 -> 1234.56
            cleaned = cleaned.replace(",", "")
    elif "," in cleaned:
        parts = cleaned.split(",")
        if len(parts) == 2 and len(parts[1]) != 3:
            cleaned = cleaned.replace(",", ".")
        elif len(parts) == 2 and len(parts[0]) <= 3 and len(parts[1]) <= 4:
            # Ambiguous e.g. 1,0850 FX rate in DE/NL -> decimal comma unless >=1000 integer
            cleaned = cleaned.replace(",", ".")
        else:
            cleaned = cleaned.replace(",", "")

    try:
        val = float(cleaned)
    except ValueError:
        return default
    if neg and val > 0:
        val = -val
    return 0.0 if val == 0.0 else val


def _parse_multi_format_timestamp(date_str: str, time_str: str = "") -> str | None:
    d_clean = (date_str or "").strip()
    if not d_clean:
        return None
    # Schwab "01/15/2026 as of 01/14/2026" -> take primary date prefix
    if " as of " in d_clean.lower():
        d_clean = d_clean.lower().split(" as of ")[0].strip()

    t_clean = (time_str or "").strip()
    combined = f"{d_clean} {t_clean}".strip() if t_clean else d_clean

    if combined.endswith(("Z", "z")) or (len(combined) > 10 and "+" in combined[10:]):
        try:
            dt = datetime.fromisoformat(combined.replace("Z", "+00:00").replace("z", "+00:00"))
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass

    formats = (
        "%d-%m-%Y %H:%M:%S",
        "%d-%m-%Y %H:%M",
        "%d.%m.%Y %H:%M:%S",
        "%d.%m.%Y %H:%M",
        "%Y.%m.%d %H:%M:%S",
        "%Y.%m.%d %H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%m-%d-%Y %H:%M:%S",
        "%m-%d-%Y %H:%M",
        "%d-%m-%Y",
        "%d.%m.%Y",
        "%Y.%m.%d",
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%m/%d/%Y",
        "%m-%d-%Y",
    )
    for fmt in formats:
        try:
            dt = datetime.strptime(combined, fmt).replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return None


def _read_csv_rows(text: str) -> list[list[str]]:
    stripped = text.strip()
    if not stripped:
        return []
    first_line = stripped.splitlines()[0]
    tab_count = first_line.count("\t")
    semi_count = first_line.count(";")
    comma_count = first_line.count(",")
    if tab_count >= 2 and tab_count > semi_count and tab_count > comma_count:
        delimiter = "\t"
    elif semi_count > comma_count:
        delimiter = ";"
    else:
        delimiter = ","
    reader = csv.reader(StringIO(stripped), delimiter=delimiter)
    return [row for row in reader if any(cell.strip() for cell in row)]


def _find_col(headers_lower: list[str], aliases: tuple[str, ...]) -> int | None:
    for alias in aliases:
        al = alias.lower()
        for idx, h in enumerate(headers_lower):
            if h == al or h.startswith(al):
                return idx
    return None


def _cell(row: list[str], idx: int | None) -> str:
    if idx is None or idx < 0 or idx >= len(row):
        return ""
    return row[idx].strip()


def _valid_isin(raw: str) -> str | None:
    cand = sanitize_csv_text_field(raw).upper()
    return cand if _ISIN_RE.match(cand) else None


def _classify_degiro_account_flow(desc: str, amount: float) -> FlowKind | None:
    d = desc.strip().lower()
    if not d:
        return None
    # Ignore trade cash settlement lines in Account.csv (already captured via Transactions.csv)
    if any(
        d.startswith(prefix)
        for prefix in ("buy ", "sell ", "koop ", "verkoop ", "kauf ", "verkauf ")
    ):
        return None
    if any(
        m in d
        for m in (
            "dividend tax",
            "dividendbelasting",
            "dividendensteuer",
            "quellensteuer",
            "withholding",
        )
    ):
        return FlowKind.WITHHOLDING_TAX
    if "dividend" in d or "dividende" in d:
        return FlowKind.DIVIDEND
    if any(
        m in d
        for m in (
            "deposit",
            "storting",
            "einzahlung",
            "ideal",
            "sofort",
        )
    ):
        return FlowKind.DEPOSIT if amount >= 0 else FlowKind.WITHDRAWAL
    if any(
        m in d
        for m in (
            "withdrawal",
            "terugstorting",
            "opname",
            "auszahlung",
        )
    ):
        return FlowKind.WITHDRAWAL
    if any(m in d for m in ("interest", "rente", "zinsen")):
        return FlowKind.MARGIN_INTEREST if amount < 0 else FlowKind.INTEREST
    if any(
        m in d
        for m in (
            "fx credit",
            "fx debit",
            "valuta creditering",
            "valuta debitering",
            "währungswechsel",
            "waehrungswechsel",
        )
    ):
        return FlowKind.FX_TRANSLATION
    if any(
        m in d
        for m in (
            "fee",
            "transactiekosten",
            "aansluitingskosten",
            "gebühr",
            "gebuehr",
            "fremdkosten",
            "stamp duty",
        )
    ):
        return FlowKind.COMMISSION_FEE
    return FlowKind.OTHER_INTERNAL


def parse_degiro_csv_bundle(
    *,
    transactions_csv: bytes | str | None = None,
    account_csv: bytes | str | None = None,
    portfolio_csv: bytes | str | None = None,
    blinding_salt_hex: str = "ab" * 32,
    base_currency: str = "EUR",
    max_bytes: int = MAX_STATEMENT_BYTES,
    environment_tier: EnvironmentTier | str = EnvironmentTier.UNVERIFIED_OFFLINE,
    **extra_kwargs: Any,
) -> CanonicalPortfolioLedger:
    """Parse multi-locale (EN / NL / DE) DEGIRO CSV exports preserving ISINs and FX rates."""
    reject_unofficial_scraper_credentials(**extra_kwargs)

    tx_text, tx_bytes = decode_statement_bytes(transactions_csv, max_bytes=max_bytes)
    acct_text, acct_bytes = decode_statement_bytes(account_csv, max_bytes=max_bytes)
    port_text, port_bytes = decode_statement_bytes(portfolio_csv, max_bytes=max_bytes)
    if len(tx_bytes) + len(acct_bytes) + len(port_bytes) > max_bytes:
        raise StatementSizeLimitExceededError(
            f"Combined DEGIRO CSV bundle exceeds {max_bytes}-byte safety limit"
        )

    if not (tx_text.strip() or acct_text.strip() or port_text.strip()):
        raise ValueError(
            "At least one DEGIRO CSV (transactions_csv, account_csv, or portfolio_csv) is required"
        )

    source_sha = hashlib.sha256(
        b"\n--DEGIRO-PART--\n".join([tx_bytes, acct_bytes, port_bytes])
    ).hexdigest()
    base_ccy = base_currency.strip().upper()
    enabled_sections: list[str] = []
    conversion_rates: dict[str, float] = {}
    trades: list[NormalizedTrade] = []
    flows: list[NormalizedFlow] = []
    ending_positions: list[NormalizedPosition] = []

    # 1. Transactions CSV (EN / NL / DE)
    tx_rows = _read_csv_rows(tx_text)
    if len(tx_rows) >= 2:
        enabled_sections.append("degiro_transactions_csv")
        hdrs = [h.strip().lower() for h in tx_rows[0]]
        c_date = _find_col(hdrs, ("date", "datum"))
        c_time = _find_col(hdrs, ("time", "tijd", "uhrzeit"))
        c_prod = _find_col(hdrs, ("product", "produkt"))
        c_isin = _find_col(hdrs, ("isin",))
        c_exch = _find_col(hdrs, ("reference exchange", "beurs", "börse", "boerse"))
        c_qty = _find_col(hdrs, ("quantity", "aantal", "anzahl"))
        c_px = _find_col(hdrs, ("price", "koers", "kurs"))
        c_local = _find_col(hdrs, ("local value", "lokale waarde", "lokaler wert", "lokale wert"))
        c_val = None
        for idx, h in enumerate(hdrs):
            if h in {"value", "waarde", "wert"}:
                c_val = idx
                break
        c_fx = _find_col(hdrs, ("exchange rate", "wisselkoers", "wechselkurs"))
        c_fee = _find_col(
            hdrs,
            (
                "transaction and/or third",
                "autofx",
                "transactiekosten",
                "transaktionsgebühren",
                "transaktionsgebuehren",
            ),
        )
        c_oid = _find_col(hdrs, ("order id", "order-id"))

        for r_idx, row in enumerate(tx_rows[1:]):
            ts = _parse_multi_format_timestamp(_cell(row, c_date), _cell(row, c_time))
            prod = sanitize_csv_text_field(_cell(row, c_prod))
            isin = _valid_isin(_cell(row, c_isin))
            qty_signed = _parse_localized_float(_cell(row, c_qty))
            px = _parse_localized_float(_cell(row, c_px))
            if ts is None or qty_signed is None or qty_signed == 0.0 or px is None:
                continue

            # DEGIRO places currency in the unnamed column immediately following Price / Local value / Value
            px_ccy = sanitize_csv_text_field(
                _cell(
                    row,
                    c_px + 1
                    if c_px is not None and (c_px + 1) < len(hdrs) and hdrs[c_px + 1] == ""
                    else None,
                )
            ).upper()
            local_val = _parse_localized_float(_cell(row, c_local))
            local_ccy = sanitize_csv_text_field(
                _cell(
                    row,
                    c_local + 1
                    if c_local is not None and (c_local + 1) < len(hdrs) and hdrs[c_local + 1] == ""
                    else None,
                )
            ).upper()
            val_base = _parse_localized_float(_cell(row, c_val))
            val_ccy = sanitize_csv_text_field(
                _cell(
                    row,
                    c_val + 1
                    if c_val is not None and (c_val + 1) < len(hdrs) and hdrs[c_val + 1] == ""
                    else None,
                )
            ).upper()
            if val_ccy and len(val_ccy) == 3 and val_ccy.isalpha():
                base_ccy = val_ccy

            trade_ccy = local_ccy or px_ccy or base_ccy
            if len(trade_ccy) != 3 or not trade_ccy.isalpha():
                trade_ccy = base_ccy

            raw_fx = _parse_localized_float(_cell(row, c_fx))
            if trade_ccy == base_ccy:
                fx_to_base = 1.0
            elif local_val and val_base and abs(local_val) > 0:
                fx_to_base = abs(val_base) / abs(local_val)
            elif raw_fx and raw_fx > 0:
                # DEGIRO quotes Wisselkoers/Wechselkurs as 1 EUR = X Local (e.g. 1.08 USD/EUR)
                fx_to_base = 1.0 / raw_fx
            else:
                fx_to_base = 1.0

            if trade_ccy != base_ccy and fx_to_base > 0:
                conversion_rates[f"{trade_ccy}/{base_ccy}"] = fx_to_base

            fee = abs(_parse_localized_float(_cell(row, c_fee), default=0.0) or 0.0)
            oid = sanitize_csv_text_field(_cell(row, c_oid)) or f"degiro-tx-{r_idx}"
            symbol = isin or prod or f"INST-{r_idx}"
            exch = sanitize_csv_text_field(_cell(row, c_exch)) or None

            trades.append(
                NormalizedTrade(
                    venue="degiro",
                    native_entry_id=f"{oid}:{r_idx}",
                    symbol=symbol,
                    asset_class=(
                        AssetClass.ETF
                        if "etf" in prod.lower() or "ucits" in prod.lower()
                        else AssetClass.EQUITY
                    ),
                    side="buy" if qty_signed > 0 else "sell",
                    quantity=abs(qty_signed),
                    price=abs(px),
                    timestamp_utc=ts,
                    currency=trade_ccy,
                    fx_rate_to_base=fx_to_base,
                    commission=fee,
                    isin=isin,
                    exchange=exch,
                )
            )

    # 2. Account CSV (EN / NL / DE)
    acct_rows = _read_csv_rows(acct_text)
    if len(acct_rows) >= 2:
        enabled_sections.append("degiro_account_csv")
        hdrs = [h.strip().lower() for h in acct_rows[0]]
        c_date = _find_col(hdrs, ("date", "datum"))
        c_time = _find_col(hdrs, ("time", "tijd", "uhrzeit"))
        c_isin = _find_col(hdrs, ("isin",))
        c_desc = _find_col(hdrs, ("description", "omschrijving", "beschreibung"))
        c_fx = _find_col(hdrs, ("fx", "wisselkoers", "wechselkurs"))
        c_chg = _find_col(hdrs, ("change", "mutatie", "änderung", "aenderung"))

        for row in acct_rows[1:]:
            ts = _parse_multi_format_timestamp(_cell(row, c_date), _cell(row, c_time))
            desc = sanitize_csv_text_field(_cell(row, c_desc))
            if ts is None or not desc:
                continue

            chg_cell = _cell(row, c_chg)
            next_cell = _cell(row, c_chg + 1 if c_chg is not None else None)
            if chg_cell.isalpha() and len(chg_cell) == 3:
                ccy = chg_cell.upper()
                amt = _parse_localized_float(next_cell)
            else:
                amt = _parse_localized_float(chg_cell)
                ccy = next_cell.upper() if (len(next_cell) == 3 and next_cell.isalpha()) else base_ccy

            if amt is None or amt == 0.0:
                continue
            kind = _classify_degiro_account_flow(desc, amt)
            if kind is None:
                continue

            raw_fx = _parse_localized_float(_cell(row, c_fx))
            if ccy == base_ccy:
                fx_to_base = 1.0
            elif raw_fx and raw_fx > 0:
                fx_to_base = 1.0 / raw_fx
            else:
                fx_to_base = conversion_rates.get(f"{ccy}/{base_ccy}", 1.0)

            isin = _valid_isin(_cell(row, c_isin))
            flows.append(
                NormalizedFlow(
                    timestamp_utc=ts,
                    kind=kind,
                    amount=amt,
                    currency=ccy,
                    fx_rate_to_base=fx_to_base,
                    symbol=isin,
                    isin=isin,
                    description=desc,
                )
            )

    # 3. Portfolio CSV (EN / NL / DE)
    port_rows = _read_csv_rows(port_text)
    ending_nav = 0.0
    ending_cash = 0.0
    if len(port_rows) >= 2:
        enabled_sections.append("degiro_portfolio_csv")
        hdrs = [h.strip().lower() for h in port_rows[0]]
        c_prod = _find_col(hdrs, ("product", "produkt"))
        c_isin = _find_col(hdrs, ("symbol/isin", "symbool/isin", "isin"))
        c_amt = _find_col(hdrs, ("amount", "aantal", "anzahl"))
        c_local = _find_col(hdrs, ("local value", "lokale waarde", "lokaler wert", "lokale wert"))
        c_eur = _find_col(hdrs, ("value in eur", "waarde in eur", "wert in eur", "value in"))
        if c_eur is not None and "eur" in hdrs[c_eur]:
            base_ccy = "EUR"

        for row in port_rows[1:]:
            prod = sanitize_csv_text_field(_cell(row, c_prod))
            sym_isin = sanitize_csv_text_field(_cell(row, c_isin))
            isin = _valid_isin(sym_isin)
            val_eur = _parse_localized_float(_cell(row, c_eur), default=0.0) or 0.0
            ending_nav += val_eur

            if (
                "cash" in prod.lower()
                or "geldmarktfonds" in prod.lower()
                or "flatex" in prod.lower()
            ):
                ending_cash += val_eur
                continue

            qty = _parse_localized_float(_cell(row, c_amt), default=0.0) or 0.0
            if qty == 0.0 and val_eur == 0.0:
                continue

            loc_cell = _cell(row, c_local)
            m_ccy = _CCY_AMOUNT_RE.match(loc_cell)
            if m_ccy:
                pos_ccy = m_ccy.group(1).upper()
                loc_val = _parse_localized_float(m_ccy.group(2), default=val_eur) or val_eur
            else:
                pos_ccy = base_ccy
                loc_val = _parse_localized_float(loc_cell, default=val_eur) or val_eur

            fx_to_base = (
                1.0
                if pos_ccy == base_ccy
                else (
                    abs(val_eur / loc_val)
                    if loc_val != 0.0
                    else conversion_rates.get(f"{pos_ccy}/{base_ccy}", 1.0)
                )
            )
            if pos_ccy != base_ccy and fx_to_base > 0:
                conversion_rates[f"{pos_ccy}/{base_ccy}"] = fx_to_base

            symbol = isin or sym_isin or prod
            if not symbol:
                continue
            ending_positions.append(
                NormalizedPosition(
                    prior_period_or_ending="ending",
                    symbol=symbol,
                    asset_class=(
                        AssetClass.ETF
                        if "etf" in prod.lower() or "ucits" in prod.lower()
                        else AssetClass.EQUITY
                    ),
                    quantity=qty,
                    cost_basis=loc_val,
                    market_value=loc_val,
                    currency=pos_ccy,
                    fx_rate_to_base=fx_to_base,
                    isin=isin,
                )
            )

    all_ts = [t.timestamp_utc for t in trades] + [f.timestamp_utc for f in flows]
    period_start = min(all_ts) if all_ts else "2025-01-01T00:00:00Z"
    period_end = max(all_ts) if all_ts else "2025-01-01T00:00:00Z"
    nav_points = (
        [NormalizedNavPoint(timestamp_utc=period_end, nav_base=ending_nav, cash_base=ending_cash)]
        if ending_nav > 0.0
        else []
    )

    return CanonicalPortfolioLedger(
        blinded_account_tag=compute_blinded_account_tag(
            "degiro", f"offline:{source_sha[:16]}", blinding_salt_hex
        ),
        broker_id="degiro",
        account_scope=AccountScope.UNKNOWN_OFFLINE_SCOPE,
        claimed_origin_assurance=OriginAssurance.SELF_REPORTED,
        provider_approval_state=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
        environment_tier=EnvironmentTier(environment_tier),
        source_body_sha256=source_sha,
        base_currency=base_ccy,
        period_start_utc=period_start,
        period_end_utc=period_end,
        ending_positions=ending_positions,
        nav_points=nav_points,
        trades=sorted(trades, key=lambda t: (t.timestamp_utc, t.native_entry_id)),
        flows=sorted(flows, key=lambda f: f.timestamp_utc),
        conversion_rates=conversion_rates,
        enabled_sections=enabled_sections,
    )


def parse_robinhood_csv(
    csv_source: bytes | str,
    *,
    blinding_salt_hex: str = "ab" * 32,
    base_currency: str = "USD",
    max_bytes: int = MAX_STATEMENT_BYTES,
    environment_tier: EnvironmentTier | str = EnvironmentTier.UNVERIFIED_OFFLINE,
    **extra_kwargs: Any,
) -> CanonicalPortfolioLedger:
    """Parse an offline Robinhood Account Activity CSV (`SELF_REPORTED`, `UNKNOWN_OFFLINE_SCOPE`)."""
    reject_unofficial_scraper_credentials(**extra_kwargs)
    text, raw_bytes = decode_statement_bytes(csv_source, max_bytes=max_bytes)
    rows = _read_csv_rows(text)
    if len(rows) < 2:
        raise ValueError("Robinhood CSV must contain a header and at least one activity row")

    ccy = base_currency.strip().upper() or "USD"
    hdrs = [h.strip().lower() for h in rows[0]]
    c_date = _find_col(hdrs, ("activity date", "process date", "date"))
    c_inst = _find_col(hdrs, ("instrument", "symbol"))
    c_desc = _find_col(hdrs, ("description",))
    c_code = _find_col(hdrs, ("trans code", "type"))
    c_qty = _find_col(hdrs, ("quantity",))
    c_px = _find_col(hdrs, ("price",))
    c_amt = _find_col(hdrs, ("amount",))

    trades: list[NormalizedTrade] = []
    flows: list[NormalizedFlow] = []
    corp_actions: list[CorporateActionRecord] = []

    for idx, row in enumerate(rows[1:]):
        ts = _parse_multi_format_timestamp(_cell(row, c_date))
        if ts is None:
            continue
        inst = sanitize_csv_text_field(_cell(row, c_inst))
        desc = sanitize_csv_text_field(_cell(row, c_desc))
        code = sanitize_csv_text_field(_cell(row, c_code)).upper()
        qty = _parse_localized_float(_cell(row, c_qty))
        px = _parse_localized_float(_cell(row, c_px))
        amt = _parse_localized_float(_cell(row, c_amt), default=0.0) or 0.0

        if code in {"BUY", "SELL", "BTO", "BTC", "STO", "STC"} and inst and qty:
            is_opt = (
                code in {"BTO", "BTC", "STO", "STC"}
                or " call " in f" {desc.lower()} "
                or " put " in f" {desc.lower()} "
            )
            side = "buy" if code in {"BUY", "BTO", "BTC"} else "sell"
            trades.append(
                NormalizedTrade(
                    venue="robinhood",
                    native_entry_id=f"rh-{idx}",
                    symbol=inst,
                    asset_class=AssetClass.OPTION if is_opt else AssetClass.EQUITY,
                    side=side,
                    quantity=abs(qty),
                    price=abs(px or 0.0),
                    timestamp_utc=ts,
                    currency=ccy,
                )
            )
        elif code in {"ACH", "RTP", "WRF", "DCF"}:
            flows.append(
                NormalizedFlow(
                    timestamp_utc=ts,
                    kind=FlowKind.DEPOSIT if amt >= 0 else FlowKind.WITHDRAWAL,
                    amount=amt,
                    currency=ccy,
                    description=desc or code,
                )
            )
        elif code in {"ACATI", "ACATO"}:
            flows.append(
                NormalizedFlow(
                    timestamp_utc=ts,
                    kind=FlowKind.TRANSFER_IN_KIND if code == "ACATI" else FlowKind.TRANSFER_OUT_KIND,
                    amount=amt,
                    currency=ccy,
                    symbol=inst or None,
                    quantity=qty,
                    transfer_type="ACATS",
                    description=desc or code,
                )
            )
        elif code == "CDIV":
            flows.append(
                NormalizedFlow(
                    timestamp_utc=ts,
                    kind=FlowKind.DIVIDEND,
                    amount=amt,
                    currency=ccy,
                    symbol=inst or None,
                    description=desc or "Dividend",
                )
            )
        elif code in {"INT", "MINT"}:
            flows.append(
                NormalizedFlow(
                    timestamp_utc=ts,
                    kind=(
                        FlowKind.MARGIN_INTEREST
                        if (code == "MINT" or amt < 0)
                        else FlowKind.INTEREST
                    ),
                    amount=amt,
                    currency=ccy,
                    description=desc or code,
                )
            )
        elif code in {"GOLD", "DFEE", "AFEE"}:
            flows.append(
                NormalizedFlow(
                    timestamp_utc=ts,
                    kind=FlowKind.COMMISSION_FEE,
                    amount=amt,
                    currency=ccy,
                    description=desc or code,
                )
            )
        elif code in {"SPL", "OEXP", "OASGN", "OEXCS"} and inst:
            ca_map = {
                "SPL": CorporateActionType.SPLIT,
                "OEXP": CorporateActionType.OPTION_EXPIRATION,
                "OASGN": CorporateActionType.OPTION_ASSIGNMENT,
                "OEXCS": CorporateActionType.OPTION_EXERCISE,
            }
            corp_actions.append(
                CorporateActionRecord(
                    action_type=ca_map[code],
                    timestamp_utc=ts,
                    symbol=inst,
                    quantity_delta=qty or 0.0,
                    description=desc or code,
                )
            )

    source_sha = hashlib.sha256(raw_bytes).hexdigest()
    all_ts = (
        [t.timestamp_utc for t in trades]
        + [f.timestamp_utc for f in flows]
        + [c.timestamp_utc for c in corp_actions]
    )
    start_ts = min(all_ts) if all_ts else "2025-01-01T00:00:00Z"
    end_ts = max(all_ts) if all_ts else "2025-01-01T00:00:00Z"
    return CanonicalPortfolioLedger(
        blinded_account_tag=compute_blinded_account_tag(
            "robinhood", f"offline:{source_sha[:16]}", blinding_salt_hex
        ),
        broker_id="robinhood",
        account_scope=AccountScope.UNKNOWN_OFFLINE_SCOPE,
        claimed_origin_assurance=OriginAssurance.SELF_REPORTED,
        provider_approval_state=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
        environment_tier=EnvironmentTier(environment_tier),
        source_body_sha256=source_sha,
        base_currency=ccy,
        period_start_utc=start_ts,
        period_end_utc=end_ts,
        trades=sorted(trades, key=lambda t: t.timestamp_utc),
        flows=sorted(flows, key=lambda f: f.timestamp_utc),
        corporate_actions=sorted(corp_actions, key=lambda c: c.timestamp_utc),
        enabled_sections=["robinhood_activity_csv"],
    )


def parse_schwab_csv(
    csv_source: bytes | str,
    *,
    blinding_salt_hex: str = "ab" * 32,
    base_currency: str = "USD",
    max_bytes: int = MAX_STATEMENT_BYTES,
    environment_tier: EnvironmentTier | str = EnvironmentTier.UNVERIFIED_OFFLINE,
    **extra_kwargs: Any,
) -> CanonicalPortfolioLedger:
    """Parse an offline Charles Schwab Transactions CSV (`SELF_REPORTED`, `UNKNOWN_OFFLINE_SCOPE`)."""
    reject_unofficial_scraper_credentials(**extra_kwargs)
    text, raw_bytes = decode_statement_bytes(csv_source, max_bytes=max_bytes)
    all_rows = _read_csv_rows(text)
    if not all_rows:
        raise ValueError("Schwab CSV is empty")

    ccy = base_currency.strip().upper() or "USD"

    # Skip optional "Transactions for account ..." banner line before header row.
    header_idx = 0
    for idx, row in enumerate(all_rows):
        lowered = [c.strip().lower() for c in row]
        if "date" in lowered and "action" in lowered:
            header_idx = idx
            break

    hdrs = [c.strip().lower() for c in all_rows[header_idx]]
    c_date = _find_col(hdrs, ("date",))
    c_act = _find_col(hdrs, ("action",))
    c_sym = _find_col(hdrs, ("symbol",))
    c_desc = _find_col(hdrs, ("description",))
    c_qty = _find_col(hdrs, ("quantity",))
    c_px = _find_col(hdrs, ("price",))
    c_fee = _find_col(hdrs, ("fees & comm", "fees"))
    c_amt = _find_col(hdrs, ("amount",))

    trades: list[NormalizedTrade] = []
    flows: list[NormalizedFlow] = []
    corp_actions: list[CorporateActionRecord] = []

    for idx, row in enumerate(all_rows[header_idx + 1 :]):
        raw_date = _cell(row, c_date)
        if raw_date.lower().startswith("transactions total"):
            continue
        ts = _parse_multi_format_timestamp(raw_date)
        if ts is None:
            continue
        action = sanitize_csv_text_field(_cell(row, c_act))
        act_low = action.lower()
        sym = sanitize_csv_text_field(_cell(row, c_sym))
        desc = sanitize_csv_text_field(_cell(row, c_desc))
        qty = _parse_localized_float(_cell(row, c_qty))
        px = _parse_localized_float(_cell(row, c_px))
        fee = abs(_parse_localized_float(_cell(row, c_fee), default=0.0) or 0.0)
        amt = _parse_localized_float(_cell(row, c_amt), default=0.0) or 0.0

        if act_low.startswith(("buy", "sell")) and sym and qty:
            is_opt = "to open" in act_low or "to close" in act_low
            trades.append(
                NormalizedTrade(
                    venue="schwab_csv",
                    native_entry_id=f"schwab-csv-{idx}",
                    symbol=sym,
                    asset_class=AssetClass.OPTION if is_opt else AssetClass.EQUITY,
                    side="buy" if act_low.startswith("buy") else "sell",
                    quantity=abs(qty),
                    price=abs(px or 0.0),
                    timestamp_utc=ts,
                    currency=ccy,
                    commission=fee,
                )
            )
        elif "journal" in act_low:
            flows.append(
                NormalizedFlow(
                    timestamp_utc=ts,
                    kind=FlowKind.INTERNAL_SUBACCOUNT_TRANSFER,
                    amount=amt,
                    currency=ccy,
                    symbol=sym or None,
                    quantity=qty,
                    transfer_type="SCHWAB_JOURNAL",
                    description=desc or action,
                )
            )
        elif any(m in act_low for m in ("moneylink", "wire", "ach", "cash transfer")):
            flows.append(
                NormalizedFlow(
                    timestamp_utc=ts,
                    kind=FlowKind.DEPOSIT if amt >= 0 else FlowKind.WITHDRAWAL,
                    amount=amt,
                    currency=ccy,
                    description=desc or action,
                )
            )
        elif "security transfer" in act_low:
            flows.append(
                NormalizedFlow(
                    timestamp_utc=ts,
                    kind=(
                        FlowKind.TRANSFER_IN_KIND
                        if (qty or amt) >= 0
                        else FlowKind.TRANSFER_OUT_KIND
                    ),
                    amount=amt,
                    currency=ccy,
                    symbol=sym or None,
                    quantity=qty,
                    description=desc or action,
                )
            )
        elif "dividend" in act_low:
            flows.append(
                NormalizedFlow(
                    timestamp_utc=ts,
                    kind=FlowKind.DIVIDEND,
                    amount=amt,
                    currency=ccy,
                    symbol=sym or None,
                    description=desc or action,
                )
            )
        elif "tax" in act_low:
            flows.append(
                NormalizedFlow(
                    timestamp_utc=ts,
                    kind=FlowKind.WITHHOLDING_TAX,
                    amount=amt,
                    currency=ccy,
                    symbol=sym or None,
                    description=desc or action,
                )
            )
        elif "interest" in act_low:
            flows.append(
                NormalizedFlow(
                    timestamp_utc=ts,
                    kind=(
                        FlowKind.MARGIN_INTEREST
                        if ("margin" in act_low or amt < 0)
                        else FlowKind.INTEREST
                    ),
                    amount=amt,
                    currency=ccy,
                    description=desc or action,
                )
            )
        elif sym and any(m in act_low for m in ("split", "expired", "assigned", "exercised")):
            ca_type = (
                CorporateActionType.SPLIT
                if "split" in act_low
                else (
                    CorporateActionType.OPTION_ASSIGNMENT
                    if "assigned" in act_low
                    else (
                        CorporateActionType.OPTION_EXERCISE
                        if "exercised" in act_low
                        else CorporateActionType.OPTION_EXPIRATION
                    )
                )
            )
            corp_actions.append(
                CorporateActionRecord(
                    action_type=ca_type,
                    timestamp_utc=ts,
                    symbol=sym,
                    quantity_delta=qty or 0.0,
                    description=desc or action,
                )
            )

    source_sha = hashlib.sha256(raw_bytes).hexdigest()
    all_ts = (
        [t.timestamp_utc for t in trades]
        + [f.timestamp_utc for f in flows]
        + [c.timestamp_utc for c in corp_actions]
    )
    start_ts = min(all_ts) if all_ts else "2025-01-01T00:00:00Z"
    end_ts = max(all_ts) if all_ts else "2025-01-01T00:00:00Z"
    return CanonicalPortfolioLedger(
        blinded_account_tag=compute_blinded_account_tag(
            "schwab", f"offline:{source_sha[:16]}", blinding_salt_hex
        ),
        broker_id="schwab",
        account_scope=AccountScope.UNKNOWN_OFFLINE_SCOPE,
        claimed_origin_assurance=OriginAssurance.SELF_REPORTED,
        provider_approval_state=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
        environment_tier=EnvironmentTier(environment_tier),
        source_body_sha256=source_sha,
        base_currency=ccy,
        period_start_utc=start_ts,
        period_end_utc=end_ts,
        trades=sorted(trades, key=lambda t: t.timestamp_utc),
        flows=sorted(flows, key=lambda f: f.timestamp_utc),
        corporate_actions=sorted(corp_actions, key=lambda c: c.timestamp_utc),
        enabled_sections=["schwab_transactions_csv"],
    )


@dataclass(slots=True)
class DetectedStatementResult(ContractModelMixin):
    """Unified auto-detection envelope returned by ``detect_and_parse_statement``."""

    detected_format: str
    broker_id: str
    ledger: CanonicalPortfolioLedger
    origin_assurance: OriginAssurance = OriginAssurance.SELF_REPORTED
    reconciliation_status_override: ReconciliationStatus | None = None
    imported_journal_tags: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def _validate(self) -> None:
        fmt = self.detected_format.strip().lower()
        if fmt not in ALLOWED_DETECTED_FORMATS:
            raise ValueError(
                f"DetectedStatementResult.detected_format must be one of "
                f"{sorted(ALLOWED_DETECTED_FORMATS)}, got {self.detected_format!r}"
            )
        object.__setattr__(self, "detected_format", fmt)
        if not self.broker_id.strip():
            raise ValueError("DetectedStatementResult.broker_id must not be empty")
        object.__setattr__(self, "broker_id", self.broker_id.strip().lower())


def _classify_degiro_single_csv_role(rows: list[list[str]]) -> str:
    hdrs = [c.strip().lower() for c in rows[0]] if rows else []
    hdr_set = set(hdrs)
    if (
        "symbol/isin" in hdr_set
        or "symbool/isin" in hdr_set
        or any(h.startswith(("value in", "waarde in", "wert in")) for h in hdrs)
    ):
        return "portfolio_csv"
    if any(
        h in {"change", "mutatie", "änderung", "aenderung", "description", "omschrijving", "beschreibung"}
        for h in hdrs
    ):
        return "account_csv"
    return "transactions_csv"


def _infer_degiro_currency(rows: list[list[str]], fallback: str) -> str:
    for row in rows[:6]:
        for cell in row:
            up = cell.strip().upper()
            if up == "EUR" or "EUR" in up.split():
                return "EUR"
    return fallback


def detect_and_parse_statement(
    source: bytes | str | Mapping[str, bytes | str],
    *,
    filename: str | None = None,
    blinding_salt_hex: str = "ab" * 32,
    base_currency: str = "USD",
    **kwargs: Any,
) -> DetectedStatementResult:
    """Zero-dropdown in-memory statement sniffer across IBKR, DEGIRO, Robinhood, Schwab, MT4, MT5, Tradovate, TraderSync & TradeZella."""
    reject_unofficial_scraper_credentials(**kwargs)
    max_bytes = int(kwargs.pop("max_bytes", MAX_STATEMENT_BYTES))
    reject_demo = bool(kwargs.pop("reject_demo", kwargs.get("require_live", True)))

    from n170_verify.connectors.journal_migration import parse_journal_migration_csv
    from n170_verify.connectors.mt5_tradovate import (
        parse_mt4_statement,
        parse_mt5_statement,
        parse_tradovate_csv,
    )

    # 1. Mapping bundle (e.g. DEGIRO multi-CSV or Tradovate multi-CSV)
    if isinstance(source, Mapping):
        if not source:
            raise ValueError("Statement bundle is empty")
        total_bytes = 0
        norm_map: dict[str, bytes | str] = {}
        for k, v in source.items():
            if v is None:
                continue
            part_bytes = enforce_statement_size_limit(v, max_bytes=max_bytes)
            reject_xxe_and_dtd_declarations(part_bytes)
            total_bytes += len(part_bytes)
            if total_bytes > max_bytes:
                raise StatementSizeLimitExceededError(
                    f"Statement bundle ({total_bytes} bytes) exceeds {max_bytes}-byte safety limit"
                )
            if part_bytes.strip():
                norm_map[str(k).strip().lower()] = v

        if not norm_map:
            raise ValueError("Statement bundle contains no non-empty files")

        degiro_keys = {
            "transactions_csv",
            "account_csv",
            "portfolio_csv",
            "transactions",
            "account",
            "portfolio",
        }
        tradovate_keys = {
            "performance_csv",
            "orders_csv",
            "cash_history_csv",
            "performance",
            "orders",
            "cash_history",
        }
        if set(norm_map) & degiro_keys:
            degiro_ccy = "EUR" if base_currency.upper() == "USD" else base_currency
            ledger = parse_degiro_csv_bundle(
                transactions_csv=norm_map.get("transactions_csv") or norm_map.get("transactions"),
                account_csv=norm_map.get("account_csv") or norm_map.get("account"),
                portfolio_csv=norm_map.get("portfolio_csv") or norm_map.get("portfolio"),
                blinding_salt_hex=blinding_salt_hex,
                base_currency=degiro_ccy,
                max_bytes=max_bytes,
            )
            return DetectedStatementResult(
                detected_format="degiro_csv",
                broker_id=ledger.broker_id,
                ledger=ledger,
                origin_assurance=OriginAssurance.SELF_REPORTED,
                warnings=list(ledger.parser_warnings),
            )
        if set(norm_map) & tradovate_keys:
            ledger = parse_tradovate_csv(
                norm_map,
                blinding_salt_hex=blinding_salt_hex,
                base_currency=base_currency,
                reject_demo=reject_demo,
                max_bytes=max_bytes,
            )
            return DetectedStatementResult(
                detected_format="tradovate_csv",
                broker_id=ledger.broker_id,
                ledger=ledger,
                origin_assurance=OriginAssurance.SELF_REPORTED,
                warnings=list(ledger.parser_warnings),
            )
        if len(norm_map) == 1:
            sole_key, sole_val = next(iter(norm_map.items()))
            return detect_and_parse_statement(
                sole_val,
                filename=filename or sole_key,
                blinding_salt_hex=blinding_salt_hex,
                base_currency=base_currency,
                max_bytes=max_bytes,
                reject_demo=reject_demo,
                **kwargs,
            )
        raise ValueError(f"Unrecognized statement bundle keys: {sorted(norm_map)}")

    if not isinstance(source, (bytes, str)):
        raise ValueError(f"Unsupported statement source type: {type(source).__name__}")

    text, raw_bytes = decode_statement_bytes(source, max_bytes=max_bytes)
    if not text.strip():
        raise ValueError("Statement payload is empty")

    # Always run XXE / DTD / SYSTEM / PUBLIC inspection in memory before any XML/HTML parser!
    reject_xxe_and_dtd_declarations(raw_bytes)
    reject_xxe_and_dtd_declarations(text)

    stripped = text.lstrip()
    head_lower = stripped[:16384].lower()
    full_lower = stripped.lower()
    fname_lower = (filename or "").strip().lower()

    # 2. XML / HTML markup payloads
    if stripped.startswith("<") or "<table" in head_lower or "<html" in head_lower:
        if "<flexqueryresponse" in head_lower or "<flexstatement" in head_lower:
            require_live = bool(kwargs.get("require_live", reject_demo))
            ledger = parse_ibkr_flex_xml(
                raw_bytes,
                blinding_salt_hex=blinding_salt_hex,
                require_live=require_live,
                max_bytes=max_bytes,
            )
            return DetectedStatementResult(
                detected_format="ibkr_flex_xml",
                broker_id=ledger.broker_id,
                ledger=ledger,
                origin_assurance=OriginAssurance.SELF_REPORTED,
                warnings=list(ledger.parser_warnings),
            )

        if "<html" in head_lower or "<table" in head_lower or "<tr" in head_lower:
            is_mt5 = (
                "metatrader 5" in full_lower
                or (
                    "deals" in full_lower
                    and ("direction" in full_lower or ("orders" in full_lower and "fee" in full_lower))
                )
                or ("trade history report" in full_lower and "deals" in full_lower)
            )
            is_mt4 = (
                "metatrader 4" in full_lower
                or "closed transactions" in full_lower
                or (
                    "ticket" in full_lower
                    and "open time" in full_lower
                    and "close time" in full_lower
                    and "profit" in full_lower
                )
            )
            if is_mt5 and not ("metatrader 4" in full_lower):
                ledger = parse_mt5_statement(
                    raw_bytes,
                    blinding_salt_hex=blinding_salt_hex,
                    base_currency=base_currency,
                    reject_demo=reject_demo,
                    max_bytes=max_bytes,
                )
                return DetectedStatementResult(
                    detected_format="mt5_statement",
                    broker_id=ledger.broker_id,
                    ledger=ledger,
                    origin_assurance=OriginAssurance.SELF_REPORTED,
                    warnings=list(ledger.parser_warnings),
                )
            if is_mt4:
                ledger = parse_mt4_statement(
                    raw_bytes,
                    blinding_salt_hex=blinding_salt_hex,
                    base_currency=base_currency,
                    reject_demo=reject_demo,
                    max_bytes=max_bytes,
                )
                return DetectedStatementResult(
                    detected_format="mt4_statement",
                    broker_id=ledger.broker_id,
                    ledger=ledger,
                    origin_assurance=OriginAssurance.SELF_REPORTED,
                    warnings=list(ledger.parser_warnings),
                )
            raise ValueError("Unrecognized HTML statement format (expected MetaTrader 4 or MetaTrader 5)")

        raise ValueError("Unrecognized XML statement format (expected IBKR FlexQueryResponse)")

    # 3. Delimited CSV / TSV statement payloads
    rows = _read_csv_rows(text)
    if not rows:
        raise ValueError("Statement CSV is empty")

    banner_lower = " ".join(" ".join(r).lower() for r in rows[:5])

    for row in rows[:10]:
        hdrs = [c.strip().lower() for c in row if c is not None]
        hdr_set = set(hdrs)
        if len([h for h in hdrs if h]) < 3:
            continue

        # 3a. DEGIRO (EN / NL / DE)
        has_isin_col = bool(hdr_set & {"isin", "symbol/isin", "symbool/isin"})
        degiro_markers = {
            "product",
            "produkt",
            "local value",
            "lokale waarde",
            "lokaler wert",
            "lokale wert",
            "value in eur",
            "waarde in eur",
            "wert in eur",
            "wisselkoers",
            "wechselkurs",
            "exchange rate",
            "mutatie",
            "omschrijving",
            "änderung",
            "aenderung",
        }
        if has_isin_col and (
            bool(hdr_set & degiro_markers)
            or any(h.startswith(("value in", "waarde in", "wert in", "transaction and/or")) for h in hdrs)
        ):
            role = _classify_degiro_single_csv_role(rows)
            eff_ccy = _infer_degiro_currency(rows, base_currency)
            ledger = parse_degiro_csv_bundle(
                **{role: raw_bytes},
                blinding_salt_hex=blinding_salt_hex,
                base_currency=eff_ccy,
                max_bytes=max_bytes,
            )
            return DetectedStatementResult(
                detected_format="degiro_csv",
                broker_id=ledger.broker_id,
                ledger=ledger,
                origin_assurance=OriginAssurance.SELF_REPORTED,
                warnings=list(ledger.parser_warnings),
            )

        # 3b. Robinhood Activity CSV
        if "trans code" in hdr_set and bool(
            hdr_set & {"activity date", "process date", "settle date", "instrument"}
        ):
            ledger = parse_robinhood_csv(
                raw_bytes,
                blinding_salt_hex=blinding_salt_hex,
                base_currency=base_currency,
                max_bytes=max_bytes,
            )
            return DetectedStatementResult(
                detected_format="robinhood_csv",
                broker_id=ledger.broker_id,
                ledger=ledger,
                origin_assurance=OriginAssurance.SELF_REPORTED,
                warnings=list(ledger.parser_warnings),
            )

        # 3c. Charles Schwab Transactions CSV
        if (
            "date" in hdr_set
            and "action" in hdr_set
            and (
                "fees & comm" in hdr_set
                or "transactions for account" in banner_lower
                or ("symbol" in hdr_set and "description" in hdr_set and "amount" in hdr_set)
            )
        ):
            ledger = parse_schwab_csv(
                raw_bytes,
                blinding_salt_hex=blinding_salt_hex,
                base_currency=base_currency,
                max_bytes=max_bytes,
            )
            return DetectedStatementResult(
                detected_format="schwab_csv",
                broker_id=ledger.broker_id,
                ledger=ledger,
                origin_assurance=OriginAssurance.SELF_REPORTED,
                warnings=list(ledger.parser_warnings),
            )

        # 3d. Tradovate Performance / Orders / Cash History CSV
        is_tradovate_perf = "buyprice" in hdr_set and "sellprice" in hdr_set and bool(
            hdr_set & {"boughttimestamp", "soldtimestamp", "pnl", "buyfillid", "sellfillid"}
        )
        is_tradovate_orders = bool(hdr_set & {"b/s", "orderid", "order id"}) and bool(
            hdr_set & {"avgprice", "filledqty", "fill time", "filltime", "contract"}
        )
        is_tradovate_cash = "cash change type" in hdr_set or (
            "cash balance" in hdr_set and "delta" in hdr_set and "timestamp" in hdr_set
        )
        if is_tradovate_perf or is_tradovate_orders or is_tradovate_cash:
            ledger = parse_tradovate_csv(
                raw_bytes,
                blinding_salt_hex=blinding_salt_hex,
                base_currency=base_currency,
                reject_demo=reject_demo,
                max_bytes=max_bytes,
            )
            return DetectedStatementResult(
                detected_format="tradovate_csv",
                broker_id=ledger.broker_id,
                ledger=ledger,
                origin_assurance=OriginAssurance.SELF_REPORTED,
                warnings=list(ledger.parser_warnings),
            )

        # 3e. MetaTrader 5 CSV (Deals / Positions)
        if (
            "deal" in hdr_set
            and "profit" in hdr_set
            and bool(hdr_set & {"direction", "volume", "swap", "fee", "order"})
        ) or ("metatrader 5" in banner_lower and "profit" in hdr_set):
            ledger = parse_mt5_statement(
                raw_bytes,
                blinding_salt_hex=blinding_salt_hex,
                base_currency=base_currency,
                reject_demo=reject_demo,
                max_bytes=max_bytes,
            )
            return DetectedStatementResult(
                detected_format="mt5_statement",
                broker_id=ledger.broker_id,
                ledger=ledger,
                origin_assurance=OriginAssurance.SELF_REPORTED,
                warnings=list(ledger.parser_warnings),
            )

        # 3f. MetaTrader 4 CSV (Closed Transactions)
        if (
            "ticket" in hdr_set
            and "open time" in hdr_set
            and "type" in hdr_set
            and "profit" in hdr_set
            and bool(hdr_set & {"close time", "size", "lots", "item", "swap"})
        ) or ("metatrader 4" in banner_lower and "profit" in hdr_set):
            ledger = parse_mt4_statement(
                raw_bytes,
                blinding_salt_hex=blinding_salt_hex,
                base_currency=base_currency,
                reject_demo=reject_demo,
                max_bytes=max_bytes,
            )
            return DetectedStatementResult(
                detected_format="mt4_statement",
                broker_id=ledger.broker_id,
                ledger=ledger,
                origin_assurance=OriginAssurance.SELF_REPORTED,
                warnings=list(ledger.parser_warnings),
            )

        # 3g. TradeZella Journal CSV
        tz_markers = {
            "net p&l",
            "gross p&l",
            "playbook",
            "mistake tags",
            "custom tags",
            "zella scale",
            "r-multiple",
            "realized r",
            "trade rating",
        }
        has_journal_symbol = bool(hdr_set & {"symbol", "ticker", "instrument"})
        if has_journal_symbol and (
            "tradezella" in fname_lower
            or bool(hdr_set & tz_markers)
        ):
            mig = parse_journal_migration_csv(
                raw_bytes,
                source_hint="tradezella",
                blinding_salt_hex=blinding_salt_hex,
                base_currency=base_currency,
                max_bytes=max_bytes,
            )
            return DetectedStatementResult(
                detected_format="tradezella_journal",
                broker_id=mig.broker_id,
                ledger=mig.ledger,
                origin_assurance=OriginAssurance.SELF_REPORTED,
                reconciliation_status_override=ReconciliationStatus.INSUFFICIENT_SECTIONS,
                imported_journal_tags=list(mig.imported_journal_tags),
                warnings=list(mig.warnings),
            )

        # 3h. TraderSync Journal CSV
        ts_markers = {
            "setups",
            "setup",
            "mistakes",
            "mistake",
            "return $",
            "return %",
            "net return",
        }
        if has_journal_symbol and (
            "tradersync" in fname_lower
            or bool(hdr_set & ts_markers)
            or ("open date" in hdr_set and "entry price" in hdr_set and "exit price" in hdr_set)
        ):
            mig = parse_journal_migration_csv(
                raw_bytes,
                source_hint="tradersync",
                blinding_salt_hex=blinding_salt_hex,
                base_currency=base_currency,
                max_bytes=max_bytes,
            )
            return DetectedStatementResult(
                detected_format=mig.detected_format,
                broker_id=mig.broker_id,
                ledger=mig.ledger,
                origin_assurance=OriginAssurance.SELF_REPORTED,
                reconciliation_status_override=ReconciliationStatus.INSUFFICIENT_SECTIONS,
                imported_journal_tags=list(mig.imported_journal_tags),
                warnings=list(mig.warnings),
            )

    raise ValueError(
        "Unrecognized statement format: input did not match IBKR Flex XML, DEGIRO, Robinhood, "
        "Charles Schwab, MetaTrader 4, MetaTrader 5, Tradovate, TraderSync, or TradeZella schemas"
    )


class OfflineExportAdapterBase(ReadOnlyBrokerAdapter):
    """Shared base class for offline statement/CSV import adapters (`OFFLINE_EXPORT_ONLY`)."""

    approval_state = ProviderApprovalState.OFFLINE_EXPORT_ONLY
    default_origin_assurance = OriginAssurance.SELF_REPORTED
    supports_subaccount_enumeration = False
    allowed_capabilities = ("parse_statement_export",)

    def __init__(self, **kwargs: Any) -> None:
        reject_unofficial_scraper_credentials(**kwargs)
        if kwargs:
            raise ValueError(f"Unexpected arguments for {type(self).__name__}: {sorted(kwargs)}")
        super().__init__()


class DegiroOfflineCsvAdapter(OfflineExportAdapterBase):
    """Offline multi-locale (EN/NL/DE) DEGIRO CSV statement adapter (`OFFLINE_EXPORT_ONLY`)."""

    broker_id = "degiro_csv"
    display_name = "DEGIRO Offline CSV Import (EN/NL/DE)"

    def parse_export(self, *, environment_tier: EnvironmentTier | str = EnvironmentTier.UNVERIFIED_OFFLINE, **kwargs: Any) -> CanonicalPortfolioLedger:
        return parse_degiro_csv_bundle(environment_tier=environment_tier, **kwargs)


class RobinhoodOfflineCsvAdapter(OfflineExportAdapterBase):
    """Offline Robinhood Activity CSV adapter (`OFFLINE_EXPORT_ONLY`; scraping hard-blocked)."""

    broker_id = "robinhood_csv"
    display_name = "Robinhood Offline Activity CSV Import"

    def parse_export(
        self,
        csv_source: bytes | str,
        *,
        blinding_salt_hex: str = "ab" * 32,
        **kwargs: Any,
    ) -> CanonicalPortfolioLedger:
        return parse_robinhood_csv(csv_source, blinding_salt_hex=blinding_salt_hex, **kwargs)


class SchwabOfflineCsvAdapter(OfflineExportAdapterBase):
    """Offline Charles Schwab Transactions CSV adapter (`OFFLINE_EXPORT_ONLY`)."""

    broker_id = "schwab_csv"
    display_name = "Charles Schwab Offline Transactions CSV Import"

    def parse_export(
        self,
        csv_source: bytes | str,
        *,
        blinding_salt_hex: str = "ab" * 32,
        **kwargs: Any,
    ) -> CanonicalPortfolioLedger:
        return parse_schwab_csv(csv_source, blinding_salt_hex=blinding_salt_hex, **kwargs)


__all__ = [
    "ALLOWED_DETECTED_FORMATS",
    "DegiroOfflineCsvAdapter",
    "DetectedStatementResult",
    "MAX_STATEMENT_BYTES",
    "OfflineExportAdapterBase",
    "RobinhoodOfflineCsvAdapter",
    "SchwabOfflineCsvAdapter",
    "StatementSizeLimitExceededError",
    "StatementXmlHtmlSecurityError",
    "decode_statement_bytes",
    "detect_and_parse_statement",
    "enforce_statement_size_limit",
    "parse_degiro_csv_bundle",
    "parse_robinhood_csv",
    "parse_schwab_csv",
    "reject_unofficial_scraper_credentials",
    "reject_xxe_and_dtd_declarations",
    "sanitize_csv_text_field",
]
