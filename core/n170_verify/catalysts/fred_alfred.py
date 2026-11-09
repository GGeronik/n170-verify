"""ALFRED point-in-time macro vintage client and GDELT DOC 2.0 (<90d) news fallback."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
import os
import re
from typing import Any
import urllib.parse
from zoneinfo import ZoneInfo

from n170_verify.catalysts.eodhd_events import execute_http_get_json, normalize_iso_date
from n170_verify.contracts import format_utc_timestamp, parse_utc_timestamp


EASTERN_TZ = ZoneInfo("America/New_York")
DEFAULT_ALFRED_BASE_URL: str = "https://api.stlouisfed.org"
DEFAULT_GDELT_DOC_URL: str = "https://api.gdeltproject.org/api/v2/doc/doc"
GDELT_MAX_LOOKBACK_DAYS: int = 90

# Canonical US Eastern Time release clocks for primary ALFRED macro series.
SERIES_RELEASE_TIME_ET: dict[str, time] = {
    "CPIAUCSL": time(8, 30, 0),
    "CPILFESL": time(8, 30, 0),
    "PAYEMS": time(8, 30, 0),
    "UNRATE": time(8, 30, 0),
    "GDP": time(8, 30, 0),
    "GDPC1": time(8, 30, 0),
    "PCEPI": time(8, 30, 0),
    "PCEPILFE": time(8, 30, 0),
    "RSAFS": time(8, 30, 0),
    "ICSA": time(8, 30, 0),
    "PPIACO": time(8, 30, 0),
    "INDPRO": time(9, 15, 0),
    "NAPM": time(10, 0, 0),
    "DFF": time(14, 0, 0),
    "DFEDTARU": time(14, 0, 0),
    "DFEDTARL": time(14, 0, 0),
}
DEFAULT_MACRO_RELEASE_TIME_ET = time(8, 30, 0)
MACRO_CONFIRMATION_LAG_SECONDS: int = 120

_GDELT_TS_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})T?(\d{2})(\d{2})(\d{2})Z?$")


class FredAlfredApiError(RuntimeError):
    """Sanitized FRED/ALFRED or GDELT retrieval error."""


def _execute_get_json(
    url: str,
    *,
    headers: Mapping[str, str],
    timeout_seconds: float,
    transport: Callable[[str, Mapping[str, str], float], Any] | Any | None = None,
    prefer_httpx: bool = False,
    secrets_to_redact: Sequence[str] = (),
) -> Any:
    return execute_http_get_json(
        url,
        headers=headers,
        timeout_seconds=timeout_seconds,
        transport=transport,
        prefer_httpx=prefer_httpx,
        secrets_to_redact=secrets_to_redact,
        error_cls=FredAlfredApiError,
        error_prefix="Macro/news request failed",
    )


def _vintage_date_to_utc_window(
    series_id: str,
    vintage_date_str: str,
    *,
    confirmation_lag_seconds: int = MACRO_CONFIRMATION_LAG_SECONDS,
) -> tuple[str, str]:
    rel_clock = SERIES_RELEASE_TIME_ET.get(series_id.strip().upper(), DEFAULT_MACRO_RELEASE_TIME_ET)
    year, month, day = (int(part) for part in vintage_date_str[:10].split("-"))
    et_dt = datetime(
        year,
        month,
        day,
        rel_clock.hour,
        rel_clock.minute,
        rel_clock.second,
        tzinfo=EASTERN_TZ,
    )
    earliest_utc = et_dt.astimezone(timezone.utc)
    confirmed_utc = earliest_utc + timedelta(seconds=max(0, confirmation_lag_seconds))
    return format_utc_timestamp(earliest_utc), format_utc_timestamp(confirmed_utc)


@dataclass(slots=True)
class MacroReleaseObservation:
    """Point-in-time ALFRED macro release anchored on ``realtime_start`` (never reference ``date``)."""

    series_id: str
    observation_period_date: str
    vintage_release_date: str
    earliest_public_utc: str
    confirmed_public_utc: str
    unrevised_value: float | None = None
    is_initial_release: bool = True
    headline: str = ""


@dataclass(slots=True)
class GdeltArticleEvent:
    """GDELT DOC 2.0 public news article observation (<90d rolling window fallback)."""

    symbol: str
    published_utc: str
    title: str
    domain: str = ""
    url: str = ""
    is_press_wire: bool = False


def parse_alfred_observations_payload(
    series_id: str,
    payload: Mapping[str, Any],
    *,
    from_release_date: str | datetime | None = None,
    to_release_date: str | datetime | None = None,
    initial_releases_only: bool = True,
    confirmation_lag_seconds: int = MACRO_CONFIRMATION_LAG_SECONDS,
) -> list[MacroReleaseObservation]:
    """Extract unrevised point-in-time macro release dates from ALFRED ``observations`` JSON."""
    norm_series = series_id.strip().upper()
    raw_obs = payload.get("observations")
    if not isinstance(raw_obs, list):
        return []

    # Group vintages by observation reference period to isolate initial unrevised releases.
    earliest_realtime_by_obs_date: dict[str, str] = {}
    valid_rows: list[tuple[str, str, float | None]] = []

    for row in raw_obs:
        if not isinstance(row, Mapping):
            continue
        obs_date = str(row.get("date") or "").strip()[:10]
        rt_start = str(row.get("realtime_start") or "").strip()[:10]
        raw_val = str(row.get("value") or "").strip()
        if len(obs_date) != 10 or len(rt_start) != 10:
            continue
        # ALFRED marks missing values with '.'
        if raw_val == ".":
            continue
        parsed_val: float | None = None
        if raw_val:
            try:
                parsed_val = float(raw_val)
            except ValueError:
                parsed_val = None

        prev_min = earliest_realtime_by_obs_date.get(obs_date)
        if prev_min is None or rt_start < prev_min:
            earliest_realtime_by_obs_date[obs_date] = rt_start
        valid_rows.append((obs_date, rt_start, parsed_val))

    from_str = normalize_iso_date(from_release_date) if from_release_date is not None else None
    to_str = normalize_iso_date(to_release_date) if to_release_date is not None else None

    seen_keys: set[tuple[str, str]] = set()
    releases: list[MacroReleaseObservation] = []
    for obs_date, rt_start, val in valid_rows:
        is_initial = rt_start == earliest_realtime_by_obs_date.get(obs_date)
        if initial_releases_only and not is_initial:
            continue
        if from_str is not None and rt_start < from_str:
            continue
        if to_str is not None and rt_start > to_str:
            continue
        dedup_key = (obs_date, rt_start)
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        earliest_utc, confirmed_utc = _vintage_date_to_utc_window(
            norm_series,
            rt_start,
            confirmation_lag_seconds=confirmation_lag_seconds,
        )
        kind_tag = "Initial Release" if is_initial else "Vintage Revision"
        releases.append(
            MacroReleaseObservation(
                series_id=norm_series,
                observation_period_date=obs_date,
                vintage_release_date=rt_start,
                earliest_public_utc=earliest_utc,
                confirmed_public_utc=confirmed_utc,
                unrevised_value=val,
                is_initial_release=is_initial,
                headline=f"ALFRED {norm_series} {kind_tag} (period {obs_date}, vintage {rt_start})",
            )
        )

    releases.sort(key=lambda r: (r.earliest_public_utc, r.observation_period_date))
    return releases


class FredAlfredClient:
    """Point-in-time FRED/ALFRED macro release client using ``realtime_start`` and ``vintagedates``."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = DEFAULT_ALFRED_BASE_URL,
        confirmation_lag_seconds: int = MACRO_CONFIRMATION_LAG_SECONDS,
        timeout_seconds: float = 10.0,
        transport: Callable[[str, Mapping[str, str], float], Any] | Any | None = None,
        prefer_httpx: bool = False,
    ) -> None:
        resolved = api_key if api_key is not None else os.environ.get("FRED_API_KEY", "")
        self._api_key: str = resolved.strip()
        self._base_url: str = base_url.rstrip("/")
        self.confirmation_lag_seconds: int = int(confirmation_lag_seconds)
        self._timeout_seconds: float = float(timeout_seconds)
        self._transport = transport
        self._prefer_httpx = prefer_httpx

    @property
    def is_configured(self) -> bool:
        return bool(self._api_key)

    def fetch_vintage_dates(
        self,
        series_id: str,
        *,
        realtime_start: str | datetime | None = None,
        realtime_end: str | datetime | None = None,
    ) -> list[str]:
        """Fetch ALFRED ``/fred/series/vintagedates`` point-in-time calendar dates."""
        if not self._api_key:
            return []
        params: dict[str, str] = {
            "series_id": series_id.strip().upper(),
            "file_type": "json",
            "api_key": self._api_key,
        }
        if realtime_start is not None:
            params["realtime_start"] = normalize_iso_date(realtime_start)
        if realtime_end is not None:
            params["realtime_end"] = normalize_iso_date(realtime_end)

        url = f"{self._base_url}/fred/series/vintagedates?{urllib.parse.urlencode(params)}"
        payload = _execute_get_json(
            url,
            headers={"Accept": "application/json", "User-Agent": "N170Verify/0.3"},
            timeout_seconds=self._timeout_seconds,
            transport=self._transport,
            prefer_httpx=self._prefer_httpx,
            secrets_to_redact=(self._api_key,),
        )
        if not isinstance(payload, Mapping):
            return []
        vdates = payload.get("vintage_dates")
        if not isinstance(vdates, list):
            return []
        return sorted(str(d).strip()[:10] for d in vdates if isinstance(d, str) and len(d.strip()) >= 10)

    def fetch_point_in_time_releases(
        self,
        series_id: str,
        *,
        from_release_date: str | datetime | None = None,
        to_release_date: str | datetime | None = None,
        initial_releases_only: bool = True,
    ) -> list[MacroReleaseObservation]:
        """Fetch unrevised point-in-time macro releases via ALFRED ``realtime_start``."""
        if not self._api_key:
            return []

        params = {
            "series_id": series_id.strip().upper(),
            "realtime_start": "1776-07-04",
            "realtime_end": "9999-12-31",
            "file_type": "json",
            "api_key": self._api_key,
        }
        url = f"{self._base_url}/fred/series/observations?{urllib.parse.urlencode(params)}"
        payload = _execute_get_json(
            url,
            headers={"Accept": "application/json", "User-Agent": "N170Verify/0.3"},
            timeout_seconds=self._timeout_seconds,
            transport=self._transport,
            prefer_httpx=self._prefer_httpx,
            secrets_to_redact=(self._api_key,),
        )
        if not isinstance(payload, Mapping):
            return []

        return parse_alfred_observations_payload(
            series_id,
            payload,
            from_release_date=from_release_date,
            to_release_date=to_release_date,
            initial_releases_only=initial_releases_only,
            confirmation_lag_seconds=self.confirmation_lag_seconds,
        )


def parse_gdelt_seendate_utc(raw_seendate: str) -> str:
    """Parse GDELT DOC 2.0 ``seendate`` (e.g. ``'20260129T210200Z'``) into ISO-8601 UTC."""
    cleaned = raw_seendate.strip()
    m = _GDELT_TS_RE.match(cleaned)
    if m:
        yr, mo, dy, hh, mm, ss = (int(g) for g in m.groups())
        return format_utc_timestamp(datetime(yr, mo, dy, hh, mm, ss, tzinfo=timezone.utc))
    return format_utc_timestamp(parse_utc_timestamp(cleaned, field_name="gdelt_seendate"))


class GdeltDocFallbackClient:
    """Optional GDELT DOC 2.0 news fallback (<90d rolling retention) when EODHD is unset."""

    def __init__(
        self,
        *,
        doc_url: str = DEFAULT_GDELT_DOC_URL,
        max_lookback_days: int = GDELT_MAX_LOOKBACK_DAYS,
        timeout_seconds: float = 10.0,
        transport: Callable[[str, Mapping[str, str], float], Any] | Any | None = None,
        prefer_httpx: bool = False,
    ) -> None:
        self._doc_url: str = doc_url
        self.max_lookback_days: int = int(max_lookback_days)
        self._timeout_seconds: float = float(timeout_seconds)
        self._transport = transport
        self._prefer_httpx = prefer_httpx

    def fetch_recent_articles(
        self,
        symbol: str,
        from_utc: str | datetime,
        to_utc: str | datetime,
        *,
        reference_now_utc: str | datetime | None = None,
        max_records: int = 75,
    ) -> tuple[list[GdeltArticleEvent], bool]:
        """Fetch GDELT DOC 2.0 articles within the ``<90d`` rolling window.

        Returns ``(articles, retention_truncated)`` where ``retention_truncated`` is True
        when the requested range fell partially or wholly outside GDELT's <90d horizon.
        """
        start_dt = parse_utc_timestamp(from_utc, field_name="from_utc")
        end_dt = parse_utc_timestamp(to_utc, field_name="to_utc")
        now_dt = (
            parse_utc_timestamp(reference_now_utc, field_name="reference_now_utc")
            if reference_now_utc is not None
            else datetime.now(timezone.utc)
        )

        # Strict <90d guard (leave a 1-hour margin inside 90.0 days).
        retention_floor = now_dt - timedelta(days=self.max_lookback_days) + timedelta(hours=1)
        if end_dt <= retention_floor:
            return [], True

        retention_truncated = False
        if start_dt < retention_floor:
            start_dt = retention_floor
            retention_truncated = True

        sym_clean = symbol.strip().upper().split(".")[0]
        params = urllib.parse.urlencode(
            {
                "query": f'"{sym_clean}"',
                "mode": "ArtList",
                "format": "json",
                "maxrecords": max(1, min(250, int(max_records))),
                "startdatetime": start_dt.strftime("%Y%m%d%H%M%S"),
                "enddatetime": end_dt.strftime("%Y%m%d%H%M%S"),
            }
        )
        url = f"{self._doc_url}?{params}"
        payload = _execute_get_json(
            url,
            headers={"Accept": "application/json", "User-Agent": "N170Verify/0.3"},
            timeout_seconds=self._timeout_seconds,
            transport=self._transport,
            prefer_httpx=self._prefer_httpx,
        )
        if not isinstance(payload, Mapping):
            return [], retention_truncated

        raw_articles = payload.get("articles")
        if not isinstance(raw_articles, list):
            return [], retention_truncated

        events: list[GdeltArticleEvent] = []
        for item in raw_articles:
            if not isinstance(item, Mapping):
                continue
            raw_seen = item.get("seendate")
            raw_title = item.get("title")
            if not isinstance(raw_seen, str) or not isinstance(raw_title, str) or not raw_title.strip():
                continue
            try:
                pub_utc = parse_gdelt_seendate_utc(raw_seen)
            except ValueError:
                continue
            domain = str(item.get("domain") or "").strip().lower()
            art_url = str(item.get("url") or "").strip()
            is_wire = any(
                w in domain or w in raw_title.lower()
                for w in ("businesswire", "prnewswire", "globenewswire", "accesswire", "newsfile")
            )
            events.append(
                GdeltArticleEvent(
                    symbol=sym_clean,
                    published_utc=pub_utc,
                    title=raw_title.strip(),
                    domain=domain,
                    url=art_url,
                    is_press_wire=is_wire,
                )
            )

        events.sort(key=lambda ev: ev.published_utc)
        return events, retention_truncated


__all__ = [
    "DEFAULT_ALFRED_BASE_URL",
    "DEFAULT_GDELT_DOC_URL",
    "GDELT_MAX_LOOKBACK_DAYS",
    "MACRO_CONFIRMATION_LAG_SECONDS",
    "SERIES_RELEASE_TIME_ET",
    "FredAlfredApiError",
    "FredAlfredClient",
    "GdeltArticleEvent",
    "GdeltDocFallbackClient",
    "MacroReleaseObservation",
    "parse_alfred_observations_payload",
    "parse_gdelt_seendate_utc",
]
