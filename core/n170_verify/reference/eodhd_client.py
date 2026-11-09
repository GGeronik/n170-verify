"""Production-hardened EODHD market reference client with quota guards and 4-stage resolution."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Mapping, Sequence
from datetime import date, timedelta
import json
import logging
import math
import os
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
import urllib.error
from urllib.request import HTTPRedirectHandler, Request, build_opener

from n170_verify.reference.base import (
    DailyPriceEnvelope,
    DerivedBenchmarkSeries,
    DividendEvent,
    EodhdQuotaGuardError,
    EodhdRateLimitError,
    IntradayPriceEnvelope,
    NullReferenceProvider,
    ReferenceDataProvider,
    ReferenceProviderError,
    ResolvedSecurity,
    SplitEvent,
    normalize_uk_currency_and_scale,
    parse_eodhd_split_ratio,
    redact_eodhd_secrets,
)


logger = logging.getLogger(__name__)

DEFAULT_EODHD_BASE_URL = "https://eodhd.com"
EODHD_ENV_VAR = "EODHD_API_KEY"

TransportCallable = Callable[[str, Mapping[str, str]], Any]

_US_EXCHANGE_ALIASES: frozenset[str] = frozenset(
    {
        "US",
        "NASDAQ",
        "NYSE",
        "AMEX",
        "ARCA",
        "NYSEARCA",
        "NYSEMKT",
        "BATS",
        "CBOE",
        "IEX",
        "ISLAND",
        "SMART",
        "OTC",
        "PINK",
        "NMFQS",
    }
)

_EXCHANGE_ALIAS_MAP: dict[str, str] = {
    **{alias: "US" for alias in _US_EXCHANGE_ALIASES},
    "LSE": "LSE",
    "LON": "LSE",
    "XLON": "LSE",
    "XETRA": "XETRA",
    "IBIS": "XETRA",
    "ETR": "XETRA",
    "FWB": "XETRA",
    "PA": "PA",
    "SBF": "PA",
    "EPA": "PA",
    "AS": "AS",
    "AEB": "AS",
    "AMS": "AS",
    "TO": "TO",
    "TSX": "TO",
    "TSE": "TO",
    "HK": "HK",
    "SEHK": "HK",
    "HKEX": "HK",
    "SW": "SW",
    "EBS": "SW",
    "SWX": "SW",
    "AU": "AU",
    "ASX": "AU",
    "FOREX": "FOREX",
    "CC": "CC",
}

_ISIN_COUNTRY_TO_EXCHANGE: dict[str, str] = {
    "US": "US",
    "GB": "LSE",
    "JE": "LSE",
    "GG": "LSE",
    "IM": "LSE",
    "DE": "XETRA",
    "FR": "PA",
    "NL": "AS",
    "CA": "TO",
    "CH": "SW",
    "AU": "AU",
    "HK": "HK",
}

_KNOWN_EODHD_SUFFIXES: frozenset[str] = frozenset(
    {
        "US",
        "LSE",
        "XETRA",
        "PA",
        "AS",
        "TO",
        "HK",
        "SW",
        "AU",
        "FOREX",
        "CC",
        "INDX",
        "COMM",
    }
)


def endpoint_call_weight(path: str) -> int:
    """Return EODHD quota weight for a normalized API path."""
    lowered = path.strip().lower()
    if "/api/eod-bulk-last-day" in lowered:
        return 100
    if "/api/intraday/" in lowered or lowered.endswith("/api/intraday"):
        return 5
    return 1


def normalize_eodhd_exchange(
    exchange: str | None,
    *,
    isin: str | None = None,
    currency: str | None = None,
) -> str:
    """Map broker venue/exchange codes, ISIN prefixes, or currency hints onto EODHD exchange codes."""
    if exchange and exchange.strip():
        upper = exchange.strip().upper()
        if upper == "SMART" and currency:
            ccy = currency.strip().upper()
            if ccy in {"GBP", "GBX"}:
                return "LSE"
            if ccy == "EUR":
                return "XETRA"
            if ccy == "CAD":
                return "TO"
        if upper in _EXCHANGE_ALIAS_MAP:
            return _EXCHANGE_ALIAS_MAP[upper]
        return upper

    if isin and len(isin.strip()) >= 2:
        prefix = isin.strip()[:2].upper()
        if prefix in _ISIN_COUNTRY_TO_EXCHANGE:
            return _ISIN_COUNTRY_TO_EXCHANGE[prefix]

    if currency and currency.strip():
        ccy = currency.strip().upper()
        if ccy in {"GBP", "GBX"}:
            return "LSE"
        if ccy == "EUR":
            return "XETRA"
        if ccy == "CAD":
            return "TO"
        if ccy == "CHF":
            return "SW"
        if ccy == "AUD":
            return "AU"
        if ccy == "HKD":
            return "HK"

    return "US"


def split_eodhd_ticker(
    symbol_or_ticker: str,
    *,
    default_exchange: str = "US",
) -> tuple[str, str]:
    """Split ``'AAPL.US'`` or ``'BRK B'`` into ``(normalized_symbol, normalized_exchange)``."""
    cleaned = symbol_or_ticker.strip().upper()
    if not cleaned:
        raise ValueError("Ticker symbol must not be empty")

    if "." in cleaned:
        stem, suffix = cleaned.rsplit(".", 1)
        if suffix in _KNOWN_EODHD_SUFFIXES or suffix in _EXCHANGE_ALIAS_MAP:
            norm_ex = _EXCHANGE_ALIAS_MAP.get(suffix, suffix)
            norm_sym = stem.replace(" ", "-")
            return norm_sym, norm_ex

    norm_sym = cleaned.replace(" ", "-").replace(".", "-")
    norm_ex = _EXCHANGE_ALIAS_MAP.get(default_exchange.strip().upper(), default_exchange.strip().upper())
    return norm_sym, norm_ex


class QuotaBudgetTracker:
    """Enforces EODHD's ``1,000 req/min`` sliding window and ``100,000 weighted calls/day`` budget."""

    def __init__(
        self,
        *,
        max_requests_per_minute: int = 1_000,
        max_calls_per_day: int = 100_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_requests_per_minute <= 0:
            raise ValueError("max_requests_per_minute must be > 0")
        if max_calls_per_day <= 0:
            raise ValueError("max_calls_per_day must be > 0")
        self.max_requests_per_minute = max_requests_per_minute
        self.max_calls_per_day = max_calls_per_day
        self._clock = clock
        self._request_timestamps: deque[float] = deque()
        self._daily_calls_used: int = 0
        self._call_log: list[tuple[str, int]] = []

    def _prune_minute_window(self, now: float) -> None:
        cutoff = now - 60.0
        while self._request_timestamps and self._request_timestamps[0] <= cutoff:
            self._request_timestamps.popleft()

    @property
    def daily_calls_used(self) -> int:
        return self._daily_calls_used

    @property
    def remaining_daily_calls(self) -> int:
        return max(0, self.max_calls_per_day - self._daily_calls_used)

    @property
    def requests_in_last_minute(self) -> int:
        self._prune_minute_window(self._clock())
        return len(self._request_timestamps)

    @property
    def call_log(self) -> tuple[tuple[str, int], ...]:
        return tuple(self._call_log)

    def acquire(self, redacted_path: str, weight: int) -> None:
        """Reserve ``weight`` calls for ``redacted_path`` or raise ``EodhdRateLimitError``."""
        if weight <= 0:
            raise ValueError("Quota weight must be > 0")
        now = self._clock()
        self._prune_minute_window(now)
        if len(self._request_timestamps) >= self.max_requests_per_minute:
            raise EodhdRateLimitError(
                f"EODHD per-minute rate limit ({self.max_requests_per_minute} req/min) exceeded on {redacted_path}"
            )
        if self._daily_calls_used + weight > self.max_calls_per_day:
            raise EodhdRateLimitError(
                f"EODHD daily weighted call budget ({self.max_calls_per_day} calls/day) exceeded "
                f"attempting weight={weight} on {redacted_path} (used={self._daily_calls_used})"
            )
        self._request_timestamps.append(now)
        self._daily_calls_used += weight
        self._call_log.append((redacted_path, weight))


class _NoRedirectHandler(HTTPRedirectHandler):
    """Reject HTTP redirects on pinned EODHD reference endpoints."""

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        hdrs: Any,
        newurl: str,
    ) -> Request | None:
        del msg, newurl
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"HTTP {code} redirect forbidden for pinned reference endpoint",
            hdrs,
            fp,
        )


def _default_urllib_transport(
    url: str,
    params: Mapping[str, str],
    *,
    timeout_seconds: float = 15.0,
) -> Any:
    """Stdlib ``urllib.request`` JSON transport with optional ``httpx`` fallback if configured."""
    query = urlencode(params)
    full_url = f"{url}?{query}" if query else url
    req = Request(
        full_url,
        headers={
            "Accept": "application/json",
            "User-Agent": "n170-verify/3.0",
        },
        method="GET",
    )
    opener = build_opener(_NoRedirectHandler())
    with opener.open(req, timeout=timeout_seconds) as resp:  # noqa: S310
        raw_bytes = resp.read()
    if not raw_bytes:
        return []
    return json.loads(raw_bytes.decode("utf-8"))


def build_httpx_transport(*, timeout_seconds: float = 15.0) -> TransportCallable:
    """Optional ``httpx`` transport builder when ``httpx`` is installed in the runtime."""
    try:
        import httpx  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("httpx is not installed; use default urllib transport") from exc

    def _transport(url: str, params: Mapping[str, str]) -> Any:
        resp = httpx.get(
            url,
            params=dict(params),
            headers={"Accept": "application/json", "User-Agent": "n170-verify/3.0"},
            timeout=timeout_seconds,
            follow_redirects=False,
        )
        if resp.is_redirect or (300 <= resp.status_code < 400):
            raise RuntimeError(f"HTTP {resp.status_code} redirect forbidden for pinned reference endpoint")
        resp.raise_for_status()
        if not resp.content:
            return []
        return resp.json()

    return _transport


class EodhdReferenceProvider(ReferenceDataProvider):
    """Production-hardened EODHD reference client with 4-stage resolution and quota enforcement."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = DEFAULT_EODHD_BASE_URL,
        transport: TransportCallable | None = None,
        quota_tracker: QuotaBudgetTracker | None = None,
        max_requests_per_minute: int = 1_000,
        max_calls_per_day: int = 100_000,
        timeout_seconds: float = 15.0,
    ) -> None:
        resolved_key = api_key if api_key is not None else os.environ.get(EODHD_ENV_VAR, "")
        cleaned_key = resolved_key.strip()
        if not cleaned_key:
            raise ValueError(
                "EodhdReferenceProvider requires a non-empty API key "
                "(use build_reference_provider() for NullReferenceProvider fallback)"
            )
        try:
            from n170_verify.connectors.ccxt_crypto import validate_ssrf_safe_https_url
        except ImportError:
            import ipaddress
            import urllib.parse as _urlparse

            def validate_ssrf_safe_https_url(
                url: str,
                *,
                allowed_hosts: set[str] | None = None,
                require_live: bool = True,
                label: str = "connector",
            ) -> str:
                cleaned = (url or "").strip().rstrip("/")
                if not cleaned or any(ord(ch) < 33 or ord(ch) == 127 for ch in cleaned):
                    raise ValueError(f"{label} base_url must be a clean https:// URL")
                parsed = _urlparse.urlsplit(cleaned)
                if parsed.scheme.lower() != "https" or parsed.username or parsed.password or "@" in parsed.netloc:
                    raise ValueError(f"{label} adapter requires credential-free https:// transport")
                if parsed.query or parsed.fragment:
                    raise ValueError(f"{label} base_url must not contain query or fragment")
                host = (parsed.hostname or "").strip().lower().rstrip(".")
                if (
                    not host
                    or host in {"localhost", "metadata.google.internal", "instance-data"}
                    or host.endswith((".localhost", ".local", ".internal", ".home.arpa"))
                    or host.startswith("0x")
                    or host.replace(".", "").isdigit()
                ):
                    raise ValueError(f"{label} SSRF/local host {host!r} is forbidden")
                try:
                    ipaddress.ip_address(host.split("%", 1)[0])
                    is_ip = True
                except ValueError:
                    is_ip = False
                if is_ip:
                    raise ValueError(f"{label} IP-literal host {host!r} is forbidden")
                if require_live:
                    if any(tok in host or tok in parsed.path.lower() for tok in ("sandbox", "demo", "testnet", "paper")):
                        raise ValueError(f"{label} non-live endpoint {host!r} rejected")
                    if allowed_hosts is not None and host not in {h.strip().lower().rstrip(".") for h in allowed_hosts}:
                        raise ValueError(f"{label} host {host!r} not in allowed_hosts")
                return cleaned

        self._api_key = cleaned_key
        try:
            self._base_url = validate_ssrf_safe_https_url(
                base_url or DEFAULT_EODHD_BASE_URL,
                allowed_hosts={"eodhd.com", "www.eodhd.com"},
                require_live=True,
                label="EODHD",
            )
        except Exception as exc:
            raise ValueError(f"Invalid or disallowed EODHD base_url: {exc}") from exc
        self._timeout_seconds = timeout_seconds
        self._transport: TransportCallable = (
            transport
            if transport is not None
            else (lambda u, p: _default_urllib_transport(u, p, timeout_seconds=self._timeout_seconds))
        )
        self.quota_tracker = (
            quota_tracker
            if quota_tracker is not None
            else QuotaBudgetTracker(
                max_requests_per_minute=max_requests_per_minute,
                max_calls_per_day=max_calls_per_day,
            )
        )

        # Session caches preventing redundant reference calls.
        self._search_cache: dict[str, list[dict[str, Any]]] = {}
        self._delisted_exchange_cache: dict[str, list[dict[str, Any]]] = {}
        self._symbol_change_history_cache: list[dict[str, Any]] | None = None
        self._splits_cache: dict[str, list[SplitEvent]] = {}
        self._dividends_cache: dict[tuple[str, str | None, str | None], list[DividendEvent]] = {}
        self._eod_raw_cache: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        self._security_currency_cache: dict[str, str] = {}
        self._resolved_renames: dict[str, str] = {}

    def __repr__(self) -> str:
        return f"EodhdReferenceProvider(base_url={self._base_url!r}, api_token='[REDACTED]')"

    def __str__(self) -> str:
        return self.__repr__()

    @property
    def provider_name(self) -> str:
        return "eodhd"

    @property
    def is_available(self) -> bool:
        return True

    @property
    def resolved_renames(self) -> dict[str, str]:
        """Return map of ``old_ticker -> current_ticker`` resolved via ``/api/symbol-change-history``."""
        return dict(self._resolved_renames)

    def _request_json(
        self,
        path: str,
        params: Mapping[str, str | int] | None = None,
    ) -> Any:
        """Execute a rate-limited JSON request with mandatory ``fmt=json`` and secret redaction."""
        norm_path = "/" + path.lstrip("/")
        redacted_path = redact_eodhd_secrets(norm_path, self._api_key)

        if "symbols=" in norm_path.lower() and "/api/eod-bulk-last-day" in norm_path.lower():
            raise EodhdQuotaGuardError(
                "Passing 'symbols=' to /api/eod-bulk-last-day/ is blocked because EODHD bills 100 + K calls."
            )

        merged_params: dict[str, str] = {}
        if params:
            for raw_k, raw_v in params.items():
                key = str(raw_k).strip()
                if "/api/eod-bulk-last-day" in norm_path.lower() and key.lower() == "symbols":
                    raise EodhdQuotaGuardError(
                        "Passing 'symbols=' to /api/eod-bulk-last-day/ is blocked because EODHD bills 100 + K calls."
                    )
                if key.lower() == "fmt" and str(raw_v).strip().lower() != "json":
                    raise EodhdQuotaGuardError(
                        f"EODHD requests must use fmt=json (got fmt={raw_v!r} on {redacted_path})"
                    )
                merged_params[key] = str(raw_v)

        # Mandatory fmt=json on every endpoint (EODHD defaults to CSV on /eod, /splits, /div).
        merged_params["fmt"] = "json"
        merged_params["api_token"] = self._api_key

        weight = endpoint_call_weight(norm_path)
        self.quota_tracker.acquire(redacted_path, weight)

        endpoint_url = f"{self._base_url}{norm_path}"
        try:
            raw_payload = self._transport(endpoint_url, merged_params)
            if isinstance(raw_payload, bytes):
                text = raw_payload.decode("utf-8")
                return json.loads(text) if text.strip() else []
            if isinstance(raw_payload, str):
                return json.loads(raw_payload) if raw_payload.strip() else []
            return raw_payload
        except (EodhdQuotaGuardError, EodhdRateLimitError):
            raise
        except HTTPError as exc:
            status_code = exc.code
            reason_text = str(exc.reason)
            try:
                exc.close()
            except Exception:
                pass
            safe_msg = redact_eodhd_secrets(
                f"EODHD HTTP {status_code} on {redacted_path}: {reason_text}",
                self._api_key,
            )
            logger.warning("%s", safe_msg)
            raise ReferenceProviderError(safe_msg, status_code=status_code) from None
        except URLError as exc:
            safe_msg = redact_eodhd_secrets(
                f"EODHD network error on {redacted_path}: {exc.reason}",
                self._api_key,
            )
            logger.warning("%s", safe_msg)
            raise ReferenceProviderError(safe_msg) from None
        except Exception as exc:
            safe_msg = redact_eodhd_secrets(
                f"EODHD request failed on {redacted_path}: {exc}",
                self._api_key,
            )
            logger.warning("%s", safe_msg)
            raise ReferenceProviderError(safe_msg) from None

    def get_bulk_last_day(
        self,
        exchange: str,
        *,
        date_str: str | None = None,
        extra_params: Mapping[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch full exchange bulk last day (100 calls); explicitly blocks ``symbols=``."""
        norm_ex = normalize_eodhd_exchange(exchange)
        params: dict[str, str] = {}
        if date_str:
            params["date"] = date_str
        if extra_params:
            for k, v in extra_params.items():
                params[k] = v
        data = self._request_json(f"/api/eod-bulk-last-day/{norm_ex}", params)
        return list(data) if isinstance(data, list) else []

    def _search_query(self, query: str) -> list[dict[str, Any]]:
        cleaned = query.strip()
        if cleaned in self._search_cache:
            return self._search_cache[cleaned]
        safe_segment = quote(cleaned, safe="")
        payload = self._request_json(f"/api/search/{safe_segment}")
        rows = [item for item in payload if isinstance(item, Mapping)] if isinstance(payload, list) else []
        cached = [dict(r) for r in rows]
        self._search_cache[cleaned] = cached
        for row in cached:
            code = str(row.get("Code") or "").strip().upper()
            ex = normalize_eodhd_exchange(str(row.get("Exchange") or ""))
            ccy = str(row.get("Currency") or "").strip()
            if code and ex and ccy:
                self._security_currency_cache[f"{code}.{ex}"] = ccy
        return cached

    def _get_delisted_exchange_symbols(self, exchange: str) -> list[dict[str, Any]]:
        norm_ex = normalize_eodhd_exchange(exchange)
        if norm_ex in self._delisted_exchange_cache:
            return self._delisted_exchange_cache[norm_ex]
        payload = self._request_json(
            f"/api/exchange-symbol-list/{norm_ex}",
            {"delisted": "1"},
        )
        rows = [dict(item) for item in payload if isinstance(item, Mapping)] if isinstance(payload, list) else []
        self._delisted_exchange_cache[norm_ex] = rows
        for row in rows:
            code = str(row.get("Code") or "").strip().upper()
            row_ccy = str(row.get("Currency") or "").strip()
            if code and row_ccy:
                self._security_currency_cache.setdefault(f"{code}.{norm_ex}", row_ccy)
        return rows

    def _get_symbol_change_history(self) -> list[dict[str, Any]]:
        if self._symbol_change_history_cache is None:
            payload = self._request_json("/api/symbol-change-history")
            self._symbol_change_history_cache = (
                [dict(item) for item in payload if isinstance(item, Mapping)]
                if isinstance(payload, list)
                else []
            )
        return self._symbol_change_history_cache

    def _resolve_renamed_symbol(self, symbol: str, exchange: str) -> str | None:
        """Follow ``/api/symbol-change-history`` chain (e.g. ``FB`` -> ``META`` on ``US``)."""
        history = self._get_symbol_change_history()
        current_sym = symbol.strip().upper()
        norm_ex = normalize_eodhd_exchange(exchange)
        visited = {current_sym}
        changed = False

        for _ in range(5):
            candidates: list[tuple[str, str]] = []
            for row in history:
                old_sym = str(row.get("old_symbol") or row.get("OldSymbol") or "").strip().upper()
                new_sym = str(row.get("new_symbol") or row.get("NewSymbol") or "").strip().upper()
                row_ex_raw = str(row.get("exchange") or row.get("Exchange") or norm_ex).strip()
                row_ex = normalize_eodhd_exchange(row_ex_raw)
                eff_date = str(row.get("effective") or row.get("Effective") or "")
                if old_sym == current_sym and new_sym and row_ex == norm_ex:
                    candidates.append((eff_date, new_sym))
            if not candidates:
                break
            # Pick the most recent effective rename if multiple historical entries exist.
            candidates.sort(key=lambda item: item[0])
            next_sym = candidates[-1][1]
            if next_sym in visited:
                break
            visited.add(next_sym)
            current_sym = next_sym
            changed = True

        return current_sym if changed else None

    def resolve_security(
        self,
        symbol: str,
        *,
        exchange: str | None = None,
        isin: str | None = None,
        currency: str | None = None,
    ) -> ResolvedSecurity | None:
        """Resolve an instrument via 4-stage pipeline: ISIN search -> delisted list -> direct/rename."""
        default_ex = normalize_eodhd_exchange(exchange, isin=isin, currency=currency)
        base_sym, target_ex = split_eodhd_ticker(symbol, default_exchange=default_ex)
        cleaned_isin = isin.strip().upper() if isin and isin.strip() else None

        # Stage 1: ISIN lookup via /api/search/{isin}
        if cleaned_isin:
            search_rows = self._search_query(cleaned_isin)
            isin_matches = [
                row
                for row in search_rows
                if str(row.get("ISIN") or row.get("Isin") or "").strip().upper() == cleaned_isin
            ]
            if isin_matches:
                preferred = [
                    row
                    for row in isin_matches
                    if normalize_eodhd_exchange(str(row.get("Exchange") or "")) == target_ex
                ]
                chosen = preferred[0] if preferred else isin_matches[0]
                code = str(chosen.get("Code") or base_sym).strip().upper()
                resolved_ex = normalize_eodhd_exchange(str(chosen.get("Exchange") or target_ex))
                raw_ccy, norm_ccy, scale = normalize_uk_currency_and_scale(
                    str(chosen.get("Currency") or currency or "USD")
                )
                canonical = f"{code}.{resolved_ex}"
                self._security_currency_cache[canonical] = raw_ccy
                return ResolvedSecurity(
                    canonical_ticker=canonical,
                    symbol=code,
                    exchange=resolved_ex,
                    raw_currency=raw_ccy,
                    normalized_currency=norm_ccy,
                    currency_scale_factor=scale,
                    isin=cleaned_isin,
                    is_delisted=False,
                    resolution_source="search_isin",
                )

            # Stage 2: /api/search/ omits delisted securities (e.g. ATVI.US) -> fallback to
            # cached /api/exchange-symbol-list/{EX}?delisted=1&fmt=json
            delisted_rows = self._get_delisted_exchange_symbols(target_ex)
            delisted_matches = [
                row
                for row in delisted_rows
                if str(row.get("Isin") or row.get("ISIN") or "").strip().upper() == cleaned_isin
            ]
            if not delisted_matches:
                delisted_matches = [
                    row
                    for row in delisted_rows
                    if str(row.get("Code") or "").strip().upper() == base_sym
                ]
            if delisted_matches:
                chosen = delisted_matches[0]
                code = str(chosen.get("Code") or base_sym).strip().upper()
                raw_ccy, norm_ccy, scale = normalize_uk_currency_and_scale(
                    str(chosen.get("Currency") or currency or "USD")
                )
                canonical = f"{code}.{target_ex}"
                self._security_currency_cache[canonical] = raw_ccy
                return ResolvedSecurity(
                    canonical_ticker=canonical,
                    symbol=code,
                    exchange=target_ex,
                    raw_currency=raw_ccy,
                    normalized_currency=norm_ccy,
                    currency_scale_factor=scale,
                    isin=cleaned_isin,
                    is_delisted=True,
                    resolution_source="delisted_exchange_list",
                )

        canonical = f"{base_sym}.{target_ex}"
        if canonical in self._resolved_renames:
            renamed_target = self._resolved_renames[canonical]
            ren_sym, ren_ex = split_eodhd_ticker(renamed_target, default_exchange=target_ex)
            cached_ccy = self._security_currency_cache.get(renamed_target, currency or "USD")
            raw_ccy, norm_ccy, scale = normalize_uk_currency_and_scale(cached_ccy)
            return ResolvedSecurity(
                canonical_ticker=renamed_target,
                symbol=ren_sym,
                exchange=ren_ex,
                raw_currency=raw_ccy,
                normalized_currency=norm_ccy,
                currency_scale_factor=scale,
                isin=cleaned_isin,
                renamed_from=canonical,
                resolution_source="symbol_change_history",
            )

        # For UK .LSE tickers without cached quote currency, check /api/search/{symbol} so GBX vs GBP
        # is deterministically established before price envelope construction.
        if target_ex == "LSE" and canonical not in self._security_currency_cache:
            if currency and (currency.strip() == "GBp" or currency.strip().upper() == "GBX"):
                self._security_currency_cache[canonical] = "GBX"
            else:
                search_rows = self._search_query(base_sym)
                lse_matches = [
                    row
                    for row in search_rows
                    if str(row.get("Code") or "").strip().upper() == base_sym
                    and normalize_eodhd_exchange(str(row.get("Exchange") or "")) == "LSE"
                ]
                if lse_matches and lse_matches[0].get("Currency"):
                    self._security_currency_cache[canonical] = str(lse_matches[0]["Currency"]).strip()

        known_ccy = self._security_currency_cache.get(
            canonical,
            currency or ("GBP" if target_ex == "LSE" else "USD"),
        )
        raw_ccy, norm_ccy, scale = normalize_uk_currency_and_scale(known_ccy)
        return ResolvedSecurity(
            canonical_ticker=canonical,
            symbol=base_sym,
            exchange=target_ex,
            raw_currency=raw_ccy,
            normalized_currency=norm_ccy,
            currency_scale_factor=scale,
            isin=cleaned_isin,
            resolution_source="direct",
        )

    def _determine_quote_currency(
        self,
        canonical_ticker: str,
        *,
        quote_currency_hint: str | None = None,
    ) -> tuple[str, str, float]:
        base_sym, ex = split_eodhd_ticker(canonical_ticker)
        if canonical_ticker in self._security_currency_cache:
            return normalize_uk_currency_and_scale(self._security_currency_cache[canonical_ticker])
        if quote_currency_hint and (
            quote_currency_hint.strip() == "GBp" or quote_currency_hint.strip().upper() == "GBX"
        ):
            self._security_currency_cache[canonical_ticker] = "GBX"
            return "GBX", "GBP", 0.01
        if ex == "LSE":
            search_rows = self._search_query(base_sym)
            for row in search_rows:
                if (
                    str(row.get("Code") or "").strip().upper() == base_sym
                    and normalize_eodhd_exchange(str(row.get("Exchange") or "")) == "LSE"
                    and row.get("Currency")
                ):
                    ccy_val = str(row["Currency"]).strip()
                    self._security_currency_cache[canonical_ticker] = ccy_val
                    return normalize_uk_currency_and_scale(ccy_val)
        return normalize_uk_currency_and_scale(
            quote_currency_hint,
            default_currency="GBP" if ex == "LSE" else "USD",
        )

    def get_splits(
        self,
        ticker: str,
        *,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> list[SplitEvent]:
        """Fetch and parse ``/api/splits/{ticker}`` (cached full history per canonical ticker)."""
        sym, ex = split_eodhd_ticker(ticker)
        canonical = self._resolved_renames.get(f"{sym}.{ex}", f"{sym}.{ex}")

        if canonical not in self._splits_cache:
            payload = self._request_json(f"/api/splits/{canonical}")
            events: list[SplitEvent] = []
            if isinstance(payload, list):
                for row in payload:
                    if not isinstance(row, Mapping):
                        continue
                    eff_date = str(row.get("date") or "").strip()
                    split_raw = row.get("split")
                    if not eff_date or split_raw is None:
                        continue
                    ratio = parse_eodhd_split_ratio(split_raw)
                    events.append(
                        SplitEvent(
                            effective_date=eff_date,
                            ratio=ratio,
                            raw_split_text=str(split_raw),
                        )
                    )
            events.sort(key=lambda item: item.effective_date)
            self._splits_cache[canonical] = events

        all_events = self._splits_cache[canonical]
        return [
            ev
            for ev in all_events
            if (start_date is None or ev.effective_date >= start_date)
            and (end_date is None or ev.effective_date <= end_date)
        ]

    def _fetch_eod_bars_with_rename_fallback(
        self,
        canonical_ticker: str,
        *,
        start_date: str,
        end_date: str,
    ) -> tuple[str, list[dict[str, Any]]]:
        """Fetch raw ``/api/eod/`` bars, resolving HTTP 200 ``[]`` via ``/api/symbol-change-history``."""
        target = self._resolved_renames.get(canonical_ticker, canonical_ticker)
        cache_key = (target, start_date, end_date)
        if cache_key in self._eod_raw_cache:
            return target, self._eod_raw_cache[cache_key]

        payload = self._request_json(
            f"/api/eod/{target}",
            {"from": start_date, "to": end_date, "period": "d"},
        )
        rows = [dict(item) for item in payload if isinstance(item, Mapping)] if isinstance(payload, list) else []

        # Stage 3: HTTP 200 empty array [] on /api/eod/ -> resolve renamed ticker (e.g. FB.US -> META.US)
        if not rows:
            sym, ex = split_eodhd_ticker(target)
            renamed_sym = self._resolve_renamed_symbol(sym, ex)
            if renamed_sym and f"{renamed_sym}.{ex}" != target:
                new_ticker = f"{renamed_sym}.{ex}"
                self._resolved_renames[canonical_ticker] = new_ticker
                self._resolved_renames[target] = new_ticker
                alt_key = (new_ticker, start_date, end_date)
                if alt_key in self._eod_raw_cache:
                    return new_ticker, self._eod_raw_cache[alt_key]
                alt_payload = self._request_json(
                    f"/api/eod/{new_ticker}",
                    {"from": start_date, "to": end_date, "period": "d"},
                )
                alt_rows = (
                    [dict(item) for item in alt_payload if isinstance(item, Mapping)]
                    if isinstance(alt_payload, list)
                    else []
                )
                self._eod_raw_cache[alt_key] = alt_rows
                return new_ticker, alt_rows

        self._eod_raw_cache[cache_key] = rows
        return target, rows

    def get_daily_envelopes(
        self,
        ticker: str,
        *,
        start_date: str,
        end_date: str,
        quote_currency_hint: str | None = None,
    ) -> list[DailyPriceEnvelope]:
        """Return daily price envelopes with GBX normalization and pure ``/api/splits/`` factors."""
        sym, ex = split_eodhd_ticker(ticker)
        initial_canonical = f"{sym}.{ex}"
        effective_ticker, raw_bars = self._fetch_eod_bars_with_rename_fallback(
            initial_canonical,
            start_date=start_date,
            end_date=end_date,
        )
        if not raw_bars:
            return []

        raw_ccy, norm_ccy, ccy_scale = self._determine_quote_currency(
            effective_ticker,
            quote_currency_hint=quote_currency_hint,
        )
        splits = self.get_splits(effective_ticker)

        envelopes: list[DailyPriceEnvelope] = []
        for bar in raw_bars:
            trade_date = str(bar.get("date") or "").strip()
            if not trade_date:
                continue
            raw_open = float(bar["open"]) * ccy_scale
            raw_high = float(bar["high"]) * ccy_scale
            raw_low = float(bar["low"]) * ccy_scale
            raw_close = float(bar["close"]) * ccy_scale

            # Pure cumulative split factor strictly from /api/splits/ (NEVER adjusted_close / close!).
            cum_split = 1.0
            for sp in splits:
                if sp.effective_date > trade_date:
                    cum_split *= sp.ratio

            adj_close_raw = bar.get("adjusted_close")
            tr_adj_close = (
                float(adj_close_raw) * ccy_scale if adj_close_raw is not None else None
            )
            vol_raw = bar.get("volume")
            eod_split_vol = float(vol_raw) if vol_raw is not None else None
            unadj_vol = (eod_split_vol / cum_split) if eod_split_vol is not None else None

            envelopes.append(
                DailyPriceEnvelope(
                    ticker=effective_ticker,
                    trade_date=trade_date,
                    currency=norm_ccy,
                    raw_currency=raw_ccy,
                    currency_scale_factor=ccy_scale,
                    raw_open=raw_open,
                    raw_high=raw_high,
                    raw_low=raw_low,
                    raw_close=raw_close,
                    cumulative_split_factor=cum_split,
                    split_adjusted_open=raw_open / cum_split,
                    split_adjusted_high=raw_high / cum_split,
                    split_adjusted_low=raw_low / cum_split,
                    split_adjusted_close=raw_close / cum_split,
                    total_return_adjusted_close=tr_adj_close,
                    eodhd_split_adjusted_volume=eod_split_vol,
                    raw_unadjusted_volume=unadj_vol,
                )
            )

        envelopes.sort(key=lambda item: item.trade_date)
        return envelopes

    def get_dividends(
        self,
        ticker: str,
        *,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> list[DividendEvent]:
        """Return dividends from ``/api/div/`` using ``unadjustedValue`` and declaration currency."""
        sym, ex = split_eodhd_ticker(ticker)
        canonical = self._resolved_renames.get(f"{sym}.{ex}", f"{sym}.{ex}")
        cache_key = (canonical, start_date, end_date)
        if cache_key in self._dividends_cache:
            return list(self._dividends_cache[cache_key])

        params: dict[str, str] = {}
        if start_date:
            params["from"] = start_date
        if end_date:
            params["to"] = end_date

        payload = self._request_json(f"/api/div/{canonical}", params)
        events: list[DividendEvent] = []
        if isinstance(payload, list):
            for row in payload:
                if not isinstance(row, Mapping):
                    continue
                ex_dt = str(row.get("date") or "").strip()
                if not ex_dt:
                    continue
                unadj_raw = row.get("unadjustedValue")
                adj_raw = row.get("value")
                val_source = unadj_raw if unadj_raw is not None else adj_raw
                if val_source is None:
                    continue
                decl_ccy_raw = str(row.get("currency") or ("GBP" if ex == "LSE" else "USD")).strip()
                raw_ccy, norm_ccy, scale = normalize_uk_currency_and_scale(decl_ccy_raw)
                unadj_val = float(val_source) * scale
                adj_val = float(adj_raw) * scale if adj_raw is not None else None
                events.append(
                    DividendEvent(
                        ex_date=ex_dt,
                        unadjusted_value=unadj_val,
                        currency=norm_ccy,
                        raw_currency=raw_ccy,
                        adjusted_value=adj_val,
                        declaration_date=str(row["declarationDate"]) if row.get("declarationDate") else None,
                        record_date=str(row["recordDate"]) if row.get("recordDate") else None,
                        payment_date=str(row["paymentDate"]) if row.get("paymentDate") else None,
                    )
                )

        events.sort(key=lambda item: item.ex_date)
        self._dividends_cache[cache_key] = events
        return list(events)

    def get_intraday_envelope(
        self,
        ticker: str,
        *,
        start_unix: int,
        end_unix: int,
        interval: str = "1m",
        trade_date: str | None = None,
        quote_currency_hint: str | None = None,
    ) -> IntradayPriceEnvelope | None:
        """Query ``/api/intraday/{ticker}`` (weight 5) and return aggregated ``[Low, High]``."""
        if interval not in {"1m", "5m", "1h"}:
            raise ValueError(f"Unsupported EODHD intraday interval {interval!r}")
        sym, ex = split_eodhd_ticker(ticker)
        canonical = self._resolved_renames.get(f"{sym}.{ex}", f"{sym}.{ex}")

        payload = self._request_json(
            f"/api/intraday/{canonical}",
            {
                "interval": interval,
                "from": int(start_unix),
                "to": int(end_unix),
            },
        )
        if not isinstance(payload, list) or not payload:
            return None

        raw_ccy, norm_ccy, ccy_scale = self._determine_quote_currency(
            canonical,
            quote_currency_hint=quote_currency_hint,
        )
        lows: list[float] = []
        highs: list[float] = []
        for bar in payload:
            if not isinstance(bar, Mapping):
                continue
            low_v = bar.get("low")
            high_v = bar.get("high")
            if low_v is None or high_v is None:
                continue
            fl = float(low_v) * ccy_scale
            fh = float(high_v) * ccy_scale
            if math.isfinite(fl) and math.isfinite(fh):
                lows.append(fl)
                highs.append(fh)

        if not lows or not highs:
            return None

        cum_split = 1.0
        if trade_date:
            for sp in self.get_splits(canonical):
                if sp.effective_date > trade_date:
                    cum_split *= sp.ratio

        sess_low = min(lows)
        sess_high = max(highs)
        return IntradayPriceEnvelope(
            ticker=canonical,
            interval=interval,
            currency=norm_ccy,
            bar_count=len(lows),
            session_low=sess_low,
            session_high=sess_high,
            split_adjusted_low=sess_low / cum_split,
            split_adjusted_high=sess_high / cum_split,
            cumulative_split_factor=cum_split,
        )

    def get_fx_rate(
        self,
        from_currency: str,
        to_currency: str,
        *,
        date_str: str,
    ) -> float | None:
        """Fetch closing FOREX conversion rate ``1 from_currency -> X to_currency`` on or before ``date_str``."""
        _, norm_from, scale_from = normalize_uk_currency_and_scale(from_currency)
        _, norm_to, scale_to = normalize_uk_currency_and_scale(to_currency)
        cross_scale = scale_from / scale_to
        if norm_from == norm_to:
            return cross_scale

        end_dt = date.fromisoformat(date_str[:10])
        start_dt = end_dt - timedelta(days=5)
        start_s = start_dt.isoformat()
        end_s = end_dt.isoformat()

        direct_ticker = f"{norm_from}{norm_to}.FOREX"
        _, direct_bars = self._fetch_eod_bars_with_rename_fallback(
            direct_ticker,
            start_date=start_s,
            end_date=end_s,
        )
        if direct_bars:
            direct_bars.sort(key=lambda b: str(b.get("date") or ""))
            close_val = float(direct_bars[-1]["close"])
            if close_val > 0.0 and math.isfinite(close_val):
                return close_val * cross_scale

        inverse_ticker = f"{norm_to}{norm_from}.FOREX"
        _, inv_bars = self._fetch_eod_bars_with_rename_fallback(
            inverse_ticker,
            start_date=start_s,
            end_date=end_s,
        )
        if inv_bars:
            inv_bars.sort(key=lambda b: str(b.get("date") or ""))
            inv_close = float(inv_bars[-1]["close"])
            if inv_close > 0.0 and math.isfinite(inv_close):
                return (1.0 / inv_close) * cross_scale

        return None

    def get_derived_benchmark_series(
        self,
        benchmark_symbol: str,
        *,
        dates: Sequence[str],
    ) -> DerivedBenchmarkSeries | None:
        """Compute licensing-safe rebased-100 benchmark index and TWR (zero raw OHLCV emitted)."""
        clean_dates = sorted({d[:10] for d in dates if d and len(d) >= 10})
        if len(clean_dates) < 2:
            return None

        start_dt = date.fromisoformat(clean_dates[0]) - timedelta(days=5)
        envelopes = self.get_daily_envelopes(
            benchmark_symbol,
            start_date=start_dt.isoformat(),
            end_date=clean_dates[-1],
        )
        if not envelopes:
            return None

        # Use total-return adjusted_close for total-return benchmark indexing when available,
        # otherwise split_adjusted_close. Emit ONLY rebased 100.0 index values!
        series_marks: list[tuple[str, float]] = []
        for env in envelopes:
            mark = (
                env.total_return_adjusted_close
                if env.total_return_adjusted_close is not None and env.total_return_adjusted_close > 0.0
                else env.split_adjusted_close
            )
            if mark > 0.0 and math.isfinite(mark):
                series_marks.append((env.trade_date, mark))

        if len(series_marks) < 2:
            return None

        # Align each target date to the latest benchmark mark on or before that date.
        aligned: dict[str, float] = {}
        idx = 0
        last_mark: float | None = None
        for target_d in clean_dates:
            while idx < len(series_marks) and series_marks[idx][0] <= target_d:
                last_mark = series_marks[idx][1]
                idx += 1
            if last_mark is None:
                last_mark = series_marks[0][1]
            aligned[target_d] = last_mark

        base_mark = aligned[clean_dates[0]]
        if base_mark <= 0.0:
            return None

        indexed_by_date = {
            d: round((mark / base_mark) * 100.0, 8)
            for d, mark in aligned.items()
        }
        twr_decimal = (aligned[clean_dates[-1]] / base_mark) - 1.0
        return DerivedBenchmarkSeries(
            benchmark_symbol=envelopes[0].ticker,
            twr_decimal=twr_decimal,
            indexed_values_by_date=indexed_by_date,
        )


def build_reference_provider(
    api_key: str | None = None,
    *,
    transport: TransportCallable | None = None,
    base_url: str = DEFAULT_EODHD_BASE_URL,
    quota_tracker: QuotaBudgetTracker | None = None,
) -> ReferenceDataProvider:
    """Return ``EodhdReferenceProvider`` when ``EODHD_API_KEY`` is configured, else ``NullReferenceProvider``."""
    resolved = api_key if api_key is not None else os.environ.get(EODHD_ENV_VAR, "")
    if not resolved or not resolved.strip():
        return NullReferenceProvider()
    return EodhdReferenceProvider(
        api_key=resolved,
        base_url=base_url,
        transport=transport,
        quota_tracker=quota_tracker,
    )


__all__ = [
    "DEFAULT_EODHD_BASE_URL",
    "EODHD_ENV_VAR",
    "EodhdReferenceProvider",
    "QuotaBudgetTracker",
    "TransportCallable",
    "build_httpx_transport",
    "build_reference_provider",
    "endpoint_call_weight",
    "normalize_eodhd_exchange",
    "split_eodhd_ticker",
]
