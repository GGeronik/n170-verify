"""EODHD company news & macro economic-events client with token redaction and injectable HTTP."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
import re
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from n170_verify.contracts import format_utc_timestamp, parse_utc_timestamp


DEFAULT_EODHD_BASE_URL: str = "https://eodhd.com"
EODHD_NEWS_CALL_WEIGHT: int = 5
EODHD_ECONOMIC_EVENTS_CALL_WEIGHT: int = 5

_QUERY_SECRET_RE = re.compile(
    r"((?:api_token|api_key|apikey|access_token|token)=)([^&\s'\"]+)",
    re.IGNORECASE,
)

_PRESS_WIRE_MARKERS: tuple[str, ...] = (
    "business wire",
    "businesswire",
    "pr newswire",
    "prnewswire",
    "globenewswire",
    "globe newswire",
    "accesswire",
    "newsfile",
    "eqs newswire",
    "rns",
    "press release",
)

_EXCHANGE_SUFFIX_MAP: dict[str, str] = {
    "US": "US",
    "NASDAQ": "US",
    "NMS": "US",
    "NGS": "US",
    "NYSE": "US",
    "ARCA": "US",
    "NYSEARCA": "US",
    "AMEX": "US",
    "BATS": "US",
    "IEX": "US",
    "OTC": "US",
    "LSE": "LSE",
    "LON": "LSE",
    "XETRA": "XETRA",
    "IBIS": "XETRA",
    "TSX": "TO",
    "TSE": "TSE",
    "HKEX": "HK",
    "SEHK": "HK",
    "ASX": "AU",
    "SIX": "SW",
    "SWX": "SW",
    "EURONEXT": "PA",
    "FOREX": "FOREX",
    "CC": "CC",
}


class EodhdApiError(RuntimeError):
    """Sanitized EODHD API error guaranteed never to expose ``api_token``."""


def redact_url_secrets(text: str, *, extra_secrets: Sequence[str] = ()) -> str:
    """Scrub ``api_token=...``, ``api_key=...``, and explicit secret strings from URLs/errors."""
    scrubbed = _QUERY_SECRET_RE.sub(r"\1[REDACTED]", text)
    for secret in extra_secrets:
        if secret and len(secret) >= 4:
            scrubbed = scrubbed.replace(secret, "[REDACTED]")
            encoded = urllib.parse.quote(secret, safe="")
            if encoded and encoded != secret:
                scrubbed = scrubbed.replace(encoded, "[REDACTED]")
    return scrubbed


def format_eodhd_symbol(symbol: str, exchange: str | None = None) -> str:
    """Format an instrument ticker into EODHD ``{CODE}.{EXCHANGE}`` notation."""
    cleaned = symbol.strip().upper()
    if not cleaned:
        raise ValueError("symbol must not be empty")

    if "." in cleaned:
        left, right = cleaned.rsplit(".", 1)
        # Single-letter US share class suffixes (e.g. BRK.B, BF.A) map to BRK-B.US.
        if len(right) == 1 and right.isalpha() and (exchange is None or exchange.upper() in _EXCHANGE_SUFFIX_MAP):
            ex_code = _EXCHANGE_SUFFIX_MAP.get((exchange or "US").strip().upper(), "US")
            return f"{left}-{right}.{ex_code}"
        if len(right) >= 2 and right.isalnum():
            return f"{left}.{right}"

    ex_norm = _EXCHANGE_SUFFIX_MAP.get((exchange or "US").strip().upper(), (exchange or "US").strip().upper())
    return f"{cleaned}.{ex_norm}"


def _parse_eodhd_datetime_utc(raw_value: str) -> str:
    cleaned = raw_value.strip()
    if not cleaned:
        raise ValueError("Empty EODHD event timestamp")
    # EODHD returns ISO-8601 ('2026-01-29T21:05:00+00:00') or space-separated UTC ('2026-01-29 21:05:00').
    if " " in cleaned and "T" not in cleaned:
        cleaned = cleaned.replace(" ", "T", 1)
    return format_utc_timestamp(parse_utc_timestamp(cleaned, field_name="eodhd_timestamp"))


def normalize_iso_date(value: str | datetime, *, field_name: str = "date_param") -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d")
    cleaned = value.strip()
    if len(cleaned) >= 10 and cleaned[4] == "-" and cleaned[7] == "-":
        return cleaned[:10]
    return parse_utc_timestamp(cleaned, field_name=field_name).strftime("%Y-%m-%d")


def _detect_press_wire(title: str, content: str, link: str, tags: Sequence[str]) -> tuple[str, bool]:
    combined = f"{title} {content[:400]} {link} {' '.join(tags)}".lower()
    if "business wire" in combined or "businesswire" in combined:
        return "businesswire", True
    if "pr newswire" in combined or "prnewswire" in combined:
        return "prnewswire", True
    if "globenewswire" in combined or "globe newswire" in combined:
        return "globenewswire", True
    if "accesswire" in combined:
        return "accesswire", True
    if "newsfile" in combined:
        return "newsfile", True
    for marker in _PRESS_WIRE_MARKERS:
        if marker in combined:
            return "eodhd_press_wire", True
    return "eodhd_news", False


def execute_http_get_json(
    url: str,
    *,
    headers: Mapping[str, str],
    timeout_seconds: float,
    transport: Callable[[str, Mapping[str, str], float], Any] | Any | None = None,
    prefer_httpx: bool = False,
    secrets_to_redact: Sequence[str] = (),
    error_cls: type[Exception] = EodhdApiError,
    error_prefix: str = "EODHD request failed",
) -> Any:
    try:
        if transport is not None:
            if hasattr(transport, "get") and callable(transport.get):
                resp = transport.get(url, headers=dict(headers), timeout=timeout_seconds)
                if hasattr(resp, "raise_for_status"):
                    resp.raise_for_status()
                if hasattr(resp, "json") and callable(resp.json):
                    return resp.json()
                raw_payload = getattr(resp, "text", getattr(resp, "content", resp))
            elif callable(transport):
                raw_payload = transport(url, dict(headers), timeout_seconds)
            else:
                raise TypeError("Unsupported HTTP transport object")
        elif prefer_httpx:
            try:
                import httpx  # type: ignore[import-not-found]
            except ImportError:
                req = urllib.request.Request(url, headers=dict(headers), method="GET")
                with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                    raw_payload = resp.read()
            else:
                resp = httpx.get(url, headers=dict(headers), timeout=timeout_seconds)
                resp.raise_for_status()
                return resp.json()
        else:
            req = urllib.request.Request(url, headers=dict(headers), method="GET")
            with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                raw_payload = resp.read()

        if isinstance(raw_payload, (dict, list)):
            return raw_payload
        if isinstance(raw_payload, bytes):
            return json.loads(raw_payload.decode("utf-8"))
        if isinstance(raw_payload, str):
            return json.loads(raw_payload)
        raise ValueError(f"Unexpected HTTP response payload type: {type(raw_payload).__name__}")
    except Exception as exc:
        safe_msg = redact_url_secrets(str(exc), extra_secrets=secrets_to_redact)
        safe_url = redact_url_secrets(url, extra_secrets=secrets_to_redact)
        raise error_cls(f"{error_prefix} for {safe_url}: {safe_msg}") from None


@dataclass(slots=True)
class EodhdNewsEvent:
    """Normalized EODHD news / press-wire item."""

    symbol: str
    eodhd_symbol: str
    published_utc: str
    title: str
    source_wire: str = "eodhd_news"
    is_press_wire: bool = False
    tags: list[str] = field(default_factory=list)
    link: str = ""


@dataclass(slots=True)
class EodhdEconomicEvent:
    """Normalized EODHD macro economic calendar event."""

    event_type: str
    country: str
    released_utc: str
    comparison: str | None = None
    actual: float | None = None
    estimate: float | None = None
    previous: float | None = None


class EodhdEventsClient:
    """Read-only EODHD News and Macro Economic Events client (weight 5 per call)."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = DEFAULT_EODHD_BASE_URL,
        timeout_seconds: float = 10.0,
        transport: Callable[[str, Mapping[str, str], float], Any] | Any | None = None,
        prefer_httpx: bool = False,
    ) -> None:
        resolved_key = api_key if api_key is not None else os.environ.get("EODHD_API_KEY", "")
        self._api_key: str = resolved_key.strip()
        self._base_url: str = base_url.rstrip("/")
        self._timeout_seconds: float = float(timeout_seconds)
        self._transport = transport
        self._prefer_httpx = prefer_httpx
        self.consumed_api_weight: int = 0

    @property
    def is_configured(self) -> bool:
        return bool(self._api_key)

    def fetch_company_news(
        self,
        symbol: str,
        from_date: str | datetime,
        to_date: str | datetime,
        *,
        exchange: str | None = None,
        limit: int = 100,
    ) -> list[EodhdNewsEvent]:
        """Fetch ``/api/news?s={code}.{ex}&from=...&to=...&fmt=json`` (API weight = 5)."""
        if not self._api_key:
            return []

        eodhd_sym = format_eodhd_symbol(symbol, exchange=exchange)
        base_sym = symbol.strip().upper().split(".")[0]
        params = urllib.parse.urlencode(
            {
                "s": eodhd_sym,
                "from": normalize_iso_date(from_date),
                "to": normalize_iso_date(to_date),
                "limit": max(1, int(limit)),
                "fmt": "json",
                "api_token": self._api_key,
            }
        )
        url = f"{self._base_url}/api/news?{params}"
        self.consumed_api_weight += EODHD_NEWS_CALL_WEIGHT

        payload = execute_http_get_json(
            url,
            headers={"Accept": "application/json", "User-Agent": "N170Verify/0.3"},
            timeout_seconds=self._timeout_seconds,
            transport=self._transport,
            prefer_httpx=self._prefer_httpx,
            secrets_to_redact=(self._api_key,),
        )
        if not isinstance(payload, list):
            return []

        events: list[EodhdNewsEvent] = []
        for item in payload:
            if not isinstance(item, Mapping):
                continue
            raw_date = item.get("date")
            raw_title = item.get("title")
            if not isinstance(raw_date, str) or not isinstance(raw_title, str) or not raw_title.strip():
                continue
            try:
                pub_utc = _parse_eodhd_datetime_utc(raw_date)
            except ValueError:
                continue

            raw_content = str(item.get("content") or "")
            raw_link = str(item.get("link") or "")
            raw_tags = item.get("tags")
            tags = [str(t) for t in raw_tags] if isinstance(raw_tags, list) else []
            wire_source, is_wire = _detect_press_wire(raw_title, raw_content, raw_link, tags)
            events.append(
                EodhdNewsEvent(
                    symbol=base_sym,
                    eodhd_symbol=eodhd_sym,
                    published_utc=pub_utc,
                    title=raw_title.strip(),
                    source_wire=wire_source,
                    is_press_wire=is_wire,
                    tags=tags,
                    link=raw_link,
                )
            )

        events.sort(key=lambda ev: ev.published_utc)
        return events

    def fetch_economic_events(
        self,
        from_date: str | datetime,
        to_date: str | datetime,
        *,
        country: str = "US",
        limit: int = 100,
    ) -> list[EodhdEconomicEvent]:
        """Fetch ``/api/economic-events?from=...&to=...&fmt=json`` (API weight = 5)."""
        if not self._api_key:
            return []

        params_dict: dict[str, str | int] = {
            "from": normalize_iso_date(from_date),
            "to": normalize_iso_date(to_date),
            "limit": max(1, int(limit)),
            "fmt": "json",
            "api_token": self._api_key,
        }
        if country.strip():
            params_dict["country"] = country.strip().upper()

        url = f"{self._base_url}/api/economic-events?{urllib.parse.urlencode(params_dict)}"
        self.consumed_api_weight += EODHD_ECONOMIC_EVENTS_CALL_WEIGHT

        payload = execute_http_get_json(
            url,
            headers={"Accept": "application/json", "User-Agent": "N170Verify/0.3"},
            timeout_seconds=self._timeout_seconds,
            transport=self._transport,
            prefer_httpx=self._prefer_httpx,
            secrets_to_redact=(self._api_key,),
        )
        if not isinstance(payload, list):
            return []

        results: list[EodhdEconomicEvent] = []
        for item in payload:
            if not isinstance(item, Mapping):
                continue
            raw_date = item.get("date")
            ev_type = item.get("type") or item.get("event")
            if not isinstance(raw_date, str) or not isinstance(ev_type, str) or not ev_type.strip():
                continue
            try:
                rel_utc = _parse_eodhd_datetime_utc(raw_date)
            except ValueError:
                continue

            def _opt_float(val: Any) -> float | None:
                if isinstance(val, (int, float)) and not isinstance(val, bool):
                    return float(val)
                if isinstance(val, str) and val.strip():
                    try:
                        return float(val.strip())
                    except ValueError:
                        return None
                return None

            results.append(
                EodhdEconomicEvent(
                    event_type=ev_type.strip(),
                    country=str(item.get("country") or country).strip().upper(),
                    released_utc=rel_utc,
                    comparison=str(item["comparison"]) if item.get("comparison") is not None else None,
                    actual=_opt_float(item.get("actual")),
                    estimate=_opt_float(item.get("estimate")),
                    previous=_opt_float(item.get("previous")),
                )
            )

        results.sort(key=lambda ev: ev.released_utc)
        return results


__all__ = [
    "DEFAULT_EODHD_BASE_URL",
    "EODHD_ECONOMIC_EVENTS_CALL_WEIGHT",
    "EODHD_NEWS_CALL_WEIGHT",
    "EodhdApiError",
    "EodhdEconomicEvent",
    "EodhdEventsClient",
    "EodhdNewsEvent",
    "execute_http_get_json",
    "format_eodhd_symbol",
    "normalize_iso_date",
    "redact_url_secrets",
]
