"""Base interfaces, internal envelopes, and secret-redaction utilities for market reference data.

Licensing invariant:
    Raw reference OHLCV bars are strictly internal verification inputs and MUST NEVER be attached
    to ``VerifyProofBundle``, ``PerformanceSummary``, or ``ReconciliationReport`` payloads.
    Publicly serializable outputs carry only derived benchmark return indices (rebased to 100.0)
    and check outcomes / residuals.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
import math
import re
from urllib.parse import quote


_API_TOKEN_QUERY_RE = re.compile(r"(?i)(api_token=)([^&\s\"']+)")


class ReferenceProviderError(RuntimeError):
    """Sanitized error raised by a market reference provider (never exposes API tokens)."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class EodhdQuotaGuardError(ReferenceProviderError, ValueError):
    """Raised when a request violates EODHD quota-amplification or mandatory format guards."""


class EodhdRateLimitError(ReferenceProviderError):
    """Raised when a request would exceed the minute request rate or daily weighted call budget."""


def redact_eodhd_secrets(text: str, secret: str | None = None) -> str:
    """Strip ``api_token`` query parameters and literal API key substrings from any string."""
    if not text:
        return text
    sanitized = _API_TOKEN_QUERY_RE.sub(r"\1[REDACTED]", text)
    if secret:
        cleaned = secret.strip()
        if cleaned:
            sanitized = sanitized.replace(cleaned, "[REDACTED]")
            encoded = quote(cleaned, safe="")
            if encoded and encoded != cleaned:
                sanitized = sanitized.replace(encoded, "[REDACTED]")
    return sanitized


def normalize_uk_currency_and_scale(
    currency: str | None,
    *,
    default_currency: str = "USD",
) -> tuple[str, str, float]:
    """Normalize UK ``GBX`` / ``GBp`` pence quotes (``0.01 GBP``) vs ``GBP`` pounds.

    Returns ``(raw_currency, normalized_currency, scale_factor)`` where multiplying a raw price
    by ``scale_factor`` converts it into ``normalized_currency``.
    """
    if currency is None or not currency.strip():
        fallback = default_currency.strip().upper() or "USD"
        return fallback, fallback, 1.0

    stripped = currency.strip()
    if stripped == "GBp" or stripped.upper() == "GBX":
        return "GBX", "GBP", 0.01

    upper = stripped.upper()
    return upper, upper, 1.0


def parse_eodhd_split_ratio(split_spec: str | float | int) -> float:
    """Parse an EODHD split ratio such as ``'4.000000/1.000000'`` into ``4.0``."""
    if isinstance(split_spec, (int, float)) and not isinstance(split_spec, bool):
        ratio = float(split_spec)
        if not math.isfinite(ratio) or ratio <= 0.0:
            raise ValueError(f"Split ratio must be finite and > 0 (got {split_spec!r})")
        return ratio

    if not isinstance(split_spec, str) or not split_spec.strip():
        raise ValueError(f"Unsupported split specification: {split_spec!r}")

    cleaned = split_spec.strip()
    if "/" in cleaned:
        parts = cleaned.split("/")
        if len(parts) != 2:
            raise ValueError(f"Malformed split ratio {split_spec!r}")
        num = float(parts[0].strip())
        den = float(parts[1].strip())
        if not (math.isfinite(num) and math.isfinite(den)) or num <= 0.0 or den <= 0.0:
            raise ValueError(f"Split numerator/denominator must be > 0 (got {split_spec!r})")
        return num / den

    if ":" in cleaned:
        parts = cleaned.split(":")
        if len(parts) != 2:
            raise ValueError(f"Malformed split ratio {split_spec!r}")
        num = float(parts[0].strip())
        den = float(parts[1].strip())
        if not (math.isfinite(num) and math.isfinite(den)) or num <= 0.0 or den <= 0.0:
            raise ValueError(f"Split numerator/denominator must be > 0 (got {split_spec!r})")
        return num / den

    ratio = float(cleaned)
    if not math.isfinite(ratio) or ratio <= 0.0:
        raise ValueError(f"Split ratio must be > 0 (got {split_spec!r})")
    return ratio


@dataclass(frozen=True, slots=True)
class ResolvedSecurity:
    """Canonicalized instrument identifier resolved across search, delisted, and rename tables."""

    canonical_ticker: str
    symbol: str
    exchange: str
    raw_currency: str = "USD"
    normalized_currency: str = "USD"
    currency_scale_factor: float = 1.0
    isin: str | None = None
    is_delisted: bool = False
    renamed_from: str | None = None
    resolution_source: str = "direct"


@dataclass(frozen=True, slots=True)
class SplitEvent:
    """Historical stock split event from ``/api/splits/``."""

    effective_date: str
    ratio: float
    raw_split_text: str = ""


@dataclass(frozen=True, slots=True)
class DividendEvent:
    """Historical cash dividend event from ``/api/div/`` using ``unadjustedValue``."""

    ex_date: str
    unadjusted_value: float
    currency: str = "USD"
    raw_currency: str = "USD"
    adjusted_value: float | None = None
    declaration_date: str | None = None
    record_date: str | None = None
    payment_date: str | None = None


@dataclass(frozen=True, slots=True)
class DailyPriceEnvelope:
    """Internal daily OHLC envelope with pure ``/api/splits/`` split reconstruction.

    EODHD ``/api/eod/`` provides raw unadjusted ``open/high/low/close`` alongside already
    split-adjusted ``volume`` and dividend-contaminated ``adjusted_close``. Split-adjusted OHLC
    values here are reconstructed exclusively from ``/api/splits/`` cumulative factors.
    """

    ticker: str
    trade_date: str
    currency: str
    raw_currency: str
    currency_scale_factor: float
    raw_open: float
    raw_high: float
    raw_low: float
    raw_close: float
    cumulative_split_factor: float
    split_adjusted_open: float
    split_adjusted_high: float
    split_adjusted_low: float
    split_adjusted_close: float
    total_return_adjusted_close: float | None = None
    eodhd_split_adjusted_volume: float | None = None
    raw_unadjusted_volume: float | None = None


@dataclass(frozen=True, slots=True)
class IntradayPriceEnvelope:
    """Internal aggregated intraday ``[Low, High]`` envelope for Stage-2 fill bound checks."""

    ticker: str
    interval: str
    currency: str
    bar_count: int
    session_low: float
    session_high: float
    split_adjusted_low: float
    split_adjusted_high: float
    cumulative_split_factor: float = 1.0


@dataclass(frozen=True, slots=True)
class DerivedBenchmarkSeries:
    """Licensing-safe derived benchmark return series rebased to 100.0 (zero raw OHLCV)."""

    benchmark_symbol: str
    twr_decimal: float
    indexed_values_by_date: dict[str, float]


class ReferenceDataProvider(ABC):
    """Abstract interface for external market reference data verification."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Canonical provider identifier (``'eodhd'`` or ``'none'``)."""

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Return True when live/mocked reference data lookups are active."""

    @abstractmethod
    def resolve_security(
        self,
        symbol: str,
        *,
        exchange: str | None = None,
        isin: str | None = None,
        currency: str | None = None,
    ) -> ResolvedSecurity | None:
        """Resolve an instrument symbol/ISIN to a canonical provider ticker and currency."""

    @abstractmethod
    def get_daily_envelopes(
        self,
        ticker: str,
        *,
        start_date: str,
        end_date: str,
        quote_currency_hint: str | None = None,
    ) -> list[DailyPriceEnvelope]:
        """Return pure split-reconstructed and GBX-normalized daily OHLC envelopes."""

    @abstractmethod
    def get_splits(
        self,
        ticker: str,
        *,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> list[SplitEvent]:
        """Return historical split events for ``ticker``."""

    @abstractmethod
    def get_dividends(
        self,
        ticker: str,
        *,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> list[DividendEvent]:
        """Return historical cash dividends using ``unadjustedValue`` and declaration currency."""

    @abstractmethod
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
        """Return aggregated intraday ``[Low, High]`` envelope over ``[start_unix, end_unix]``."""

    @abstractmethod
    def get_fx_rate(
        self,
        from_currency: str,
        to_currency: str,
        *,
        date_str: str,
    ) -> float | None:
        """Return closing FX conversion rate ``1 from_currency -> X to_currency`` on ``date_str``."""

    @abstractmethod
    def get_derived_benchmark_series(
        self,
        benchmark_symbol: str,
        *,
        dates: Sequence[str],
    ) -> DerivedBenchmarkSeries | None:
        """Return licensing-safe benchmark return index rebased to 100.0 across ``dates``."""


class NullReferenceProvider(ReferenceDataProvider):
    """Graceful offline degradation provider when ``EODHD_API_KEY`` is unset."""

    @property
    def provider_name(self) -> str:
        return "none"

    @property
    def is_available(self) -> bool:
        return False

    def resolve_security(
        self,
        symbol: str,
        *,
        exchange: str | None = None,
        isin: str | None = None,
        currency: str | None = None,
    ) -> ResolvedSecurity | None:
        del symbol, exchange, isin, currency
        return None

    def get_daily_envelopes(
        self,
        ticker: str,
        *,
        start_date: str,
        end_date: str,
        quote_currency_hint: str | None = None,
    ) -> list[DailyPriceEnvelope]:
        del ticker, start_date, end_date, quote_currency_hint
        return []

    def get_splits(
        self,
        ticker: str,
        *,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> list[SplitEvent]:
        del ticker, start_date, end_date
        return []

    def get_dividends(
        self,
        ticker: str,
        *,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> list[DividendEvent]:
        del ticker, start_date, end_date
        return []

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
        del ticker, start_unix, end_unix, interval, trade_date, quote_currency_hint
        return None

    def get_fx_rate(
        self,
        from_currency: str,
        to_currency: str,
        *,
        date_str: str,
    ) -> float | None:
        if from_currency.strip().upper() == to_currency.strip().upper():
            return 1.0
        del date_str
        return None

    def get_derived_benchmark_series(
        self,
        benchmark_symbol: str,
        *,
        dates: Sequence[str],
    ) -> DerivedBenchmarkSeries | None:
        del benchmark_symbol, dates
        return None


__all__ = [
    "DailyPriceEnvelope",
    "DerivedBenchmarkSeries",
    "DividendEvent",
    "EodhdQuotaGuardError",
    "EodhdRateLimitError",
    "IntradayPriceEnvelope",
    "NullReferenceProvider",
    "ReferenceDataProvider",
    "ReferenceProviderError",
    "ResolvedSecurity",
    "SplitEvent",
    "normalize_uk_currency_and_scale",
    "parse_eodhd_split_ratio",
    "redact_eodhd_secrets",
]
