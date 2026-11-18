"""SEC EDGAR submissions client with America/New_York 'Z'-quirk normalization and +180s lag."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone
import os
import re
from typing import Any
from zoneinfo import ZoneInfo

from n170_verify.catalysts.eodhd_events import execute_http_get_json
from n170_verify.contracts import format_utc_timestamp, parse_utc_timestamp


SEC_EASTERN_TZ = ZoneInfo("America/New_York")
DEFAULT_SEC_SUBMISSIONS_BASE_URL: str = "https://data.sec.gov"
DEFAULT_SEC_TICKERS_URL: str = "https://www.sec.gov/files/company_tickers.json"
DEFAULT_SEC_USER_AGENT: str = "N170VerifyResearch/0.3 (research-compliance@example.com)"
SEC_PUBLIC_DISSEMINATION_LAG_SECONDS: int = 180
REG_ST_CUTOFF_ET = time(17, 30, 0)

MATERIAL_CATALYST_FORMS: frozenset[str] = frozenset(
    {
        "8-K",
        "8-K/A",
        "6-K",
        "6-K/A",
        "10-Q",
        "10-Q/A",
        "10-K",
        "10-K/A",
        "SC 13D",
        "SC 13D/A",
        "SC TO-T",
        "425",
        "S-3",
        "S-1",
    }
)

_COMPACT_14D_RE = re.compile(r"^\d{14}$")
_GENERIC_UA_PREFIXES: tuple[str, ...] = (
    "python-urllib",
    "python-requests",
    "python-httpx",
    "curl/",
    "wget/",
)


class SecEdgarApiError(RuntimeError):
    """SEC EDGAR submissions retrieval error."""


def validate_sec_user_agent(user_agent: str) -> str:
    """Validate mandatory SEC Fair Access ``User-Agent`` header with contact email."""
    if not isinstance(user_agent, str) or not user_agent.strip():
        raise ValueError("SEC EDGAR requires a non-empty User-Agent header with contact email")
    cleaned = user_agent.strip()
    lower = cleaned.lower()
    if any(lower.startswith(prefix) for prefix in _GENERIC_UA_PREFIXES):
        raise ValueError(
            "SEC EDGAR rejects generic HTTP library User-Agent strings; include app name and email"
        )
    if "@" not in cleaned or len(cleaned) < 10:
        raise ValueError(
            "SEC EDGAR User-Agent must include an organizational contact email (e.g. 'App/1.0 (ops@example.com)')"
        )
    return cleaned


def format_cik_10d(cik: str | int) -> str:
    """Zero-pad a numeric SEC Central Index Key to 10 digits (for ``CIK{10d}.json``)."""
    if isinstance(cik, int):
        if cik <= 0:
            raise ValueError("CIK must be a positive integer")
        digits = str(cik)
    elif isinstance(cik, str):
        cleaned = cik.strip().upper()
        if cleaned.startswith("CIK"):
            cleaned = cleaned[3:].strip()
        if not cleaned.isdigit() or int(cleaned) <= 0:
            raise ValueError(f"CIK must contain positive digits (got {cik!r})")
        digits = str(int(cleaned))
    else:
        raise ValueError(f"Unsupported CIK type: {type(cik).__name__}")

    if len(digits) > 10:
        raise ValueError(f"CIK exceeds 10 digits: {cik!r}")
    return digits.zfill(10)


def parse_sec_acceptance_datetime_et(raw_acceptance_datetime: str) -> datetime:
    """Parse SEC ``acceptanceDateTime`` in true ``America/New_York`` time, stripping SEC's bogus 'Z'.

    SEC ``submissions/CIK{10d}.json`` appends a literal ``"Z"`` to ``acceptanceDateTime``
    (e.g. ``"2026-01-15T18:05:12.000Z"``) or emits 14-digit ``"20260715163005"`` even though
    the EDGAR acceptance clock runs in US Eastern Time (EST ``-05:00`` / EDT ``-04:00``).
    """
    if not isinstance(raw_acceptance_datetime, str) or not raw_acceptance_datetime.strip():
        raise ValueError("SEC acceptanceDateTime must be a non-empty string")

    cleaned = raw_acceptance_datetime.strip()
    if cleaned.endswith("Z") or cleaned.endswith("z"):
        cleaned = cleaned[:-1].strip()

    if _COMPACT_14D_RE.match(cleaned):
        naive_dt = datetime.strptime(cleaned, "%Y%m%d%H%M%S")
    else:
        try:
            parsed = datetime.fromisoformat(cleaned)
        except ValueError as exc:
            raise ValueError(
                f"Invalid SEC acceptanceDateTime format: {raw_acceptance_datetime!r}"
            ) from exc
        if parsed.tzinfo is not None:
            # If an already-normalized offset was explicitly supplied without SEC's trailing 'Z', convert to ET.
            return parsed.astimezone(SEC_EASTERN_TZ)
        naive_dt = parsed

    return naive_dt.replace(tzinfo=SEC_EASTERN_TZ)


def parse_sec_acceptance_datetime_utc(raw_acceptance_datetime: str) -> datetime:
    """Convert SEC ``acceptanceDateTime`` (Eastern wall-clock with bogus 'Z') to aware UTC."""
    et_dt = parse_sec_acceptance_datetime_et(raw_acceptance_datetime)
    return et_dt.astimezone(timezone.utc)


def normalize_sec_acceptance_timestamp_utc(raw_acceptance_datetime: str) -> str:
    """Format normalized SEC ``acceptanceDateTime`` as canonical ISO-8601 UTC string."""
    return format_utc_timestamp(parse_sec_acceptance_datetime_utc(raw_acceptance_datetime))


def _execute_sec_get_json(
    url: str,
    *,
    user_agent: str,
    timeout_seconds: float,
    transport: Callable[[str, Mapping[str, str], float], Any] | Any | None = None,
    prefer_httpx: bool = False,
) -> Any:
    return execute_http_get_json(
        url,
        headers={"User-Agent": validate_sec_user_agent(user_agent), "Accept": "application/json"},
        timeout_seconds=timeout_seconds,
        transport=transport,
        prefer_httpx=prefer_httpx,
        error_cls=SecEdgarApiError,
        error_prefix="SEC EDGAR request failed",
    )


@dataclass(slots=True)
class SecEdgarFiling:
    """Normalized SEC EDGAR filing anchored strictly on ``acceptanceDateTime`` (never ``filingDate``)."""

    symbol: str
    cik_10d: str
    accession_number: str
    form: str
    acceptance_timestamp_utc: str
    confirmed_public_utc: str
    raw_acceptance_datetime: str
    filing_date: str = ""
    reg_st_filing_date_rolled: bool = False
    items: list[str] = field(default_factory=list)
    primary_doc_description: str = ""

    @property
    def headline(self) -> str:
        items_suffix = f" (Items {', '.join(self.items)})" if self.items else ""
        desc = f" - {self.primary_doc_description}" if self.primary_doc_description else ""
        return f"SEC Form {self.form}{items_suffix}{desc}"


def parse_submissions_payload(
    payload: Mapping[str, Any],
    *,
    symbol: str | None = None,
    cik_10d: str | None = None,
    forms: Sequence[str] | frozenset[str] | None = MATERIAL_CATALYST_FORMS,
    from_utc: str | datetime | None = None,
    to_utc: str | datetime | None = None,
    dissemination_lag_seconds: int = SEC_PUBLIC_DISSEMINATION_LAG_SECONDS,
) -> list[SecEdgarFiling]:
    """Parse ``submissions/CIK{10d}.json`` payload into UTC-normalized ``SecEdgarFiling`` records."""
    if dissemination_lag_seconds < 0:
        raise ValueError("dissemination_lag_seconds must be >= 0")

    resolved_cik = format_cik_10d(cik_10d or str(payload.get("cik") or "0000000001"))
    tickers = payload.get("tickers")
    resolved_sym = (
        symbol.strip().upper()
        if symbol and symbol.strip()
        else (
            str(tickers[0]).strip().upper()
            if isinstance(tickers, list) and tickers
            else f"CIK{resolved_cik}"
        )
    )

    filings_obj = payload.get("filings")
    recent = filings_obj.get("recent") if isinstance(filings_obj, Mapping) else None
    if not isinstance(recent, Mapping):
        return []

    accessions = recent.get("accessionNumber") or []
    filing_dates = recent.get("filingDate") or []
    acceptance_dts = recent.get("acceptanceDateTime") or []
    form_list = recent.get("form") or []
    items_list = recent.get("items") or []
    descriptions = recent.get("primaryDocDescription") or []

    if not isinstance(acceptance_dts, list) or not isinstance(form_list, list):
        return []

    allowed_forms = {f.strip().upper() for f in forms} if forms is not None else None
    from_dt = parse_utc_timestamp(from_utc) if from_utc is not None else None
    to_dt = parse_utc_timestamp(to_utc) if to_utc is not None else None

    row_count = min(len(acceptance_dts), len(form_list))
    parsed_filings: list[SecEdgarFiling] = []

    for idx in range(row_count):
        raw_form = str(form_list[idx] or "").strip().upper()
        if not raw_form:
            continue
        if allowed_forms is not None and raw_form not in allowed_forms:
            continue

        raw_acc_dt = str(acceptance_dts[idx] or "").strip()
        if not raw_acc_dt:
            # Never fabricate point timestamps from Reg S-T filingDate alone.
            continue

        try:
            et_dt = parse_sec_acceptance_datetime_et(raw_acc_dt)
        except ValueError:
            continue

        utc_dt = et_dt.astimezone(timezone.utc)
        if from_dt is not None and utc_dt < from_dt:
            continue
        if to_dt is not None and utc_dt > to_dt:
            continue

        fdate = str(filing_dates[idx] or "").strip() if idx < len(filing_dates) else ""
        et_date_str = et_dt.strftime("%Y-%m-%d")
        rolled = bool(
            (fdate and fdate > et_date_str) or et_dt.timetz().replace(tzinfo=None) > REG_ST_CUTOFF_ET
        )

        raw_items = items_list[idx] if idx < len(items_list) else []
        if isinstance(raw_items, list):
            norm_items = [str(x).strip() for x in raw_items if str(x).strip()]
        elif isinstance(raw_items, str) and raw_items.strip():
            norm_items = [s.strip() for s in raw_items.split(",") if s.strip()]
        else:
            norm_items = []

        acc_num = str(accessions[idx] or "").strip() if idx < len(accessions) else ""
        desc = str(descriptions[idx] or "").strip() if idx < len(descriptions) else ""
        confirmed_dt = utc_dt + timedelta(seconds=dissemination_lag_seconds)

        parsed_filings.append(
            SecEdgarFiling(
                symbol=resolved_sym,
                cik_10d=resolved_cik,
                accession_number=acc_num,
                form=raw_form,
                acceptance_timestamp_utc=format_utc_timestamp(utc_dt),
                confirmed_public_utc=format_utc_timestamp(confirmed_dt),
                raw_acceptance_datetime=raw_acc_dt,
                filing_date=fdate,
                reg_st_filing_date_rolled=rolled,
                items=norm_items,
                primary_doc_description=desc,
            )
        )

    parsed_filings.sort(key=lambda f: f.acceptance_timestamp_utc)
    return parsed_filings


class SecEdgarClient:
    """Read-only SEC EDGAR submissions client enforcing ``User-Agent`` and ET->UTC normalization."""

    def __init__(
        self,
        user_agent: str | None = None,
        *,
        cik_map: Mapping[str, str | int] | None = None,
        submissions_base_url: str = DEFAULT_SEC_SUBMISSIONS_BASE_URL,
        tickers_url: str = DEFAULT_SEC_TICKERS_URL,
        dissemination_lag_seconds: int = SEC_PUBLIC_DISSEMINATION_LAG_SECONDS,
        timeout_seconds: float = 10.0,
        transport: Callable[[str, Mapping[str, str], float], Any] | Any | None = None,
        prefer_httpx: bool = False,
    ) -> None:
        raw_ua = (
            user_agent
            if user_agent is not None
            else os.environ.get("SEC_EDGAR_USER_AGENT", DEFAULT_SEC_USER_AGENT)
        )
        self.user_agent: str = validate_sec_user_agent(raw_ua)
        self._submissions_base_url: str = submissions_base_url.rstrip("/")
        self._tickers_url: str = tickers_url
        self.dissemination_lag_seconds: int = int(dissemination_lag_seconds)
        self._timeout_seconds: float = float(timeout_seconds)
        self._transport = transport
        self._prefer_httpx = prefer_httpx
        self._cik_cache: dict[str, str] = {}
        if cik_map:
            for sym, cik_val in cik_map.items():
                self._cik_cache[sym.strip().upper()] = format_cik_10d(cik_val)

    def register_cik(self, symbol: str, cik: str | int) -> None:
        """Register a local ``symbol -> CIK{10d}`` mapping."""
        self._cik_cache[symbol.strip().upper()] = format_cik_10d(cik)

    def resolve_cik_10d(self, symbol: str) -> str | None:
        """Resolve an equity ticker symbol to a 10-digit SEC CIK."""
        sym_norm = symbol.strip().upper().split(".")[0]
        if sym_norm in self._cik_cache:
            return self._cik_cache[sym_norm]

        payload = _execute_sec_get_json(
            self._tickers_url,
            user_agent=self.user_agent,
            timeout_seconds=self._timeout_seconds,
            transport=self._transport,
            prefer_httpx=self._prefer_httpx,
        )
        if isinstance(payload, Mapping):
            for entry in payload.values():
                if not isinstance(entry, Mapping):
                    continue
                ticker = str(entry.get("ticker") or "").strip().upper()
                cik_num = entry.get("cik_str")
                if ticker and cik_num is not None:
                    try:
                        self._cik_cache[ticker] = format_cik_10d(cik_num)
                    except ValueError:
                        continue
        return self._cik_cache.get(sym_norm)

    def fetch_company_filings(
        self,
        symbol: str,
        *,
        cik: str | int | None = None,
        forms: Sequence[str] | frozenset[str] | None = MATERIAL_CATALYST_FORMS,
        from_utc: str | datetime | None = None,
        to_utc: str | datetime | None = None,
    ) -> list[SecEdgarFiling]:
        """Fetch and normalize ``submissions/CIK{10d}.json`` filings for ``symbol``."""
        cik_10d = format_cik_10d(cik) if cik is not None else self.resolve_cik_10d(symbol)
        if cik_10d is None:
            return []

        url = f"{self._submissions_base_url}/submissions/CIK{cik_10d}.json"
        payload = _execute_sec_get_json(
            url,
            user_agent=self.user_agent,
            timeout_seconds=self._timeout_seconds,
            transport=self._transport,
            prefer_httpx=self._prefer_httpx,
        )
        if not isinstance(payload, Mapping):
            return []

        return parse_submissions_payload(
            payload,
            symbol=symbol.strip().upper().split(".")[0],
            cik_10d=cik_10d,
            forms=forms,
            from_utc=from_utc,
            to_utc=to_utc,
            dissemination_lag_seconds=self.dissemination_lag_seconds,
        )


__all__ = [
    "DEFAULT_SEC_SUBMISSIONS_BASE_URL",
    "DEFAULT_SEC_TICKERS_URL",
    "DEFAULT_SEC_USER_AGENT",
    "MATERIAL_CATALYST_FORMS",
    "SEC_EASTERN_TZ",
    "SEC_PUBLIC_DISSEMINATION_LAG_SECONDS",
    "SecEdgarApiError",
    "SecEdgarClient",
    "SecEdgarFiling",
    "format_cik_10d",
    "normalize_sec_acceptance_timestamp_utc",
    "parse_sec_acceptance_datetime_et",
    "parse_sec_acceptance_datetime_utc",
    "parse_submissions_payload",
    "validate_sec_user_agent",
]
