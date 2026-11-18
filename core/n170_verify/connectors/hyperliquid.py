"""Permissionless read-only Hyperliquid L1 clearinghouse adapter (`POST /info`).

Queries public read-only Hyperliquid L1 clearinghouse state for a validated
``0x[0-9a-fA-F]{40}`` EVM wallet address with zero API keys, zero private keys,
SSRF-safe pinned ``https://api.hyperliquid.xyz/info`` transport, bounded
timeouts and response byte limits, and strict testnet rejection.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import json
import math
import re
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from n170_verify.connectors.ccxt_crypto import (
    ConnectorHttpError,
    DisallowedCapabilityError,
    HttpExchangeResponse,
    HttpTransportCallable,
    MutatingCredentialRejectedError,
    PaperOrSandboxAccountRejectedError,
    _NoRedirectHandler,
    validate_ssrf_safe_https_url,
)
from n170_verify.connectors.mcp_allowlist_firewall import redact_sensitive_text
from n170_verify.connectors.statement_csv import reject_unofficial_scraper_credentials
from n170_verify.performance.calculator import CAPITAL_FLOW_KINDS_FOR_TWR
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    BrokerAdapterDescriptor,
    CanonicalPortfolioLedger,
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
    parse_utc_timestamp,
)

HYPERLIQUID_LIVE_BASE_URL: str = "https://api.hyperliquid.xyz"
HYPERLIQUID_INFO_PATH: str = "/info"
DEFAULT_HYPERLIQUID_USER_AGENT: str = "N170-Verify-Hyperliquid-ReadOnly/1.0"
DEFAULT_HYPERLIQUID_TIMEOUT_SECONDS: float = 15.0
MAX_HYPERLIQUID_TIMEOUT_SECONDS: float = 30.0
MAX_HYPERLIQUID_RESPONSE_BYTES: int = 10 * 1024 * 1024
HYPERLIQUID_LEDGER_PAGE_SIZE: int = 2000
# Ledger history is read up to this many entries; more withholds the record.
MAX_HYPERLIQUID_LEDGER_ENTRIES: int = 10_000
# Safety bound on calls; with the documented 500-element responses it allows twice the entry ceiling.
MAX_HYPERLIQUID_LEDGER_PAGES: int = 40
HYPERLIQUID_FILLS_PAGE_SIZE: int = 2000
# Safety bound on calls; with the documented 500-element responses it allows twice the 10,000-fill limit.
MAX_HYPERLIQUID_FILL_PAGES: int = 40
# `userFillsByTime` serves only the 10,000 most recent fills (documented service limit).
HYPERLIQUID_FILLS_BY_TIME_AVAILABLE: int = 10_000
# Documented minimum number of elements a time-range response returns before it is cut.
HYPERLIQUID_MIN_DOCUMENTED_RESPONSE_ELEMENTS: int = 500
_USD_EQUIVALENT_TOKENS: frozenset[str] = frozenset(
    {"", "USD", "USDC", "USDH", "USDE", "USDT", "USDT0"}
)
# Ledger delta fields that carry a moved amount; an unknown entry type with any of them
# non-zero withholds the record.
_VALUE_MOVING_DELTA_FIELDS: tuple[str, ...] = ("usdc", "usdcValue", "amount", "netWithdrawnUsd")

HYPERLIQUID_ALLOWED_INFO_TYPES: frozenset[str] = frozenset(
    {
        "portfolio",
        "userNonFundingLedgerUpdates",
        "userFills",
        "userFillsByTime",
        "clearinghouseState",
        "spotClearinghouseState",
        "subAccounts",
    }
)

HYPERLIQUID_BLOCKED_ENDPOINTS: tuple[str, ...] = (
    "/exchange",
    "/ws",
)

_BLOCKED_MUTATING_ACTIONS: frozenset[str] = frozenset(
    {
        "order",
        "place_order",
        "cancel",
        "cancel_order",
        "cancel_by_cloid",
        "modify",
        "modify_order",
        "batch_modify",
        "schedule_cancel",
        "update_leverage",
        "update_isolated_margin",
        "usd_send",
        "spot_send",
        "withdraw",
        "withdraw3",
        "usd_class_transfer",
        "sub_account_transfer",
        "vault_transfer",
        "approve_agent",
        "approve_builder_fee",
        "exchange",
    }
)

_FORBIDDEN_SECRET_KWARGS: frozenset[str] = frozenset(
    {
        "private_key",
        "secret_key",
        "api_secret",
        "wallet_private_key",
        "agent_private_key",
        "agent_key",
        "mnemonic",
        "seed_phrase",
        "signing_key",
    }
)

_EVM_ADDRESS_RE: re.Pattern[str] = re.compile(r"^0x[0-9a-fA-F]{40}$")
_INLINE_EVM_ADDRESS_RE: re.Pattern[str] = re.compile(r"0x[0-9a-fA-F]{40}")


def _redact_hyperliquid_error(text: str, extra_secrets: Sequence[str] = ()) -> str:
    redacted = _INLINE_EVM_ADDRESS_RE.sub("[REDACTED]", text or "")
    return redact_sensitive_text(redacted, extra_secrets=list(extra_secrets))


class HyperliquidError(Exception):
    """Base error for Hyperliquid read-only public connector operations."""


class HyperliquidValidationError(HyperliquidError, ValueError):
    """Raised when a Hyperliquid wallet address or payload fails domain validation."""


class HyperliquidServiceError(HyperliquidError, RuntimeError):
    """Raised when Hyperliquid /info upstream fails, times out, or exceeds byte bounds."""


def validate_hyperliquid_wallet_address(address: Any) -> str:
    """Validate an EVM ``0x[0-9a-fA-F]{40}`` wallet address and return canonical lowercase form."""
    if not isinstance(address, str):
        raise HyperliquidValidationError(
            "Hyperliquid wallet_address must be a 0x-prefixed 40-hex-character EVM address string"
        )
    cleaned = address.strip()
    if not _EVM_ADDRESS_RE.fullmatch(cleaned):
        raise HyperliquidValidationError(
            "Invalid Hyperliquid wallet_address; expected 0x followed by 40 hexadecimal characters"
        )
    return cleaned.lower()


def _normalize_hyperliquid_base_url(raw_url: str | None, *, require_live: bool = True) -> str:
    candidate = (raw_url or HYPERLIQUID_LIVE_BASE_URL).strip().rstrip("/")
    if candidate.lower().endswith("/info"):
        candidate = candidate[:-5].rstrip("/")
    lower_candidate = candidate.lower()
    if "hyperliquid-testnet" in lower_candidate or "testnet" in lower_candidate:
        raise PaperOrSandboxAccountRejectedError(
            "Hyperliquid testnet endpoint rejected for live verification"
        )
    return validate_ssrf_safe_https_url(
        candidate,
        allowed_hosts={"api.hyperliquid.xyz"},
        require_live=require_live,
        label="hyperliquid",
    )


def _format_epoch_or_iso_utc(raw_ts: Any, *, field_name: str = "timestamp") -> str:
    if isinstance(raw_ts, bool) or raw_ts is None:
        raise HyperliquidValidationError(f"Missing or invalid Hyperliquid {field_name}")
    if isinstance(raw_ts, (int, float)):
        f_val = float(raw_ts)
        if not math.isfinite(f_val) or f_val <= 0.0:
            raise HyperliquidValidationError(f"Non-positive or non-finite Hyperliquid {field_name}")
        epoch_sec = f_val / 1000.0 if f_val > 1e11 else f_val
        dt = datetime.fromtimestamp(epoch_sec, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(raw_ts, str):
        text = raw_ts.strip()
        if not text:
            raise HyperliquidValidationError(f"Empty Hyperliquid {field_name}")
        if text.isdigit():
            val_int = int(text)
            epoch_sec = val_int / 1000.0 if val_int > 100_000_000_000 else float(val_int)
            return datetime.fromtimestamp(epoch_sec, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        dt = parse_utc_timestamp(text, field_name=field_name)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    raise HyperliquidValidationError(f"Unsupported Hyperliquid {field_name} type")


def _raw_time_ms(raw_ts: Any) -> int | None:
    """Millisecond epoch of a Hyperliquid time (timestamps are formatted to whole seconds)."""
    if isinstance(raw_ts, bool) or raw_ts is None:
        return None
    if isinstance(raw_ts, (int, float)) and math.isfinite(float(raw_ts)):
        f_val = float(raw_ts)
        return int(f_val) if f_val > 1e11 else int(round(f_val * 1000))
    if isinstance(raw_ts, str) and raw_ts.strip().isdigit():
        val = int(raw_ts.strip())
        return val if val > 100_000_000_000 else val * 1000
    if isinstance(raw_ts, str) and raw_ts.strip():
        try:
            return int(round(parse_utc_timestamp(raw_ts.strip(), field_name="time").timestamp() * 1000))
        except Exception:
            return None
    return None


def _parse_finite_float(raw_val: Any, *, field_name: str, default: float | None = None) -> float:
    if raw_val is None or raw_val == "":
        if default is not None:
            return default
        raise HyperliquidValidationError(f"Missing numeric field {field_name}")
    if isinstance(raw_val, bool):
        raise HyperliquidValidationError(f"Boolean is not valid for numeric field {field_name}")
    try:
        parsed = float(raw_val)
    except (TypeError, ValueError) as exc:
        raise HyperliquidValidationError(f"Malformed numeric value in {field_name}") from exc
    if not math.isfinite(parsed):
        raise HyperliquidValidationError(f"Non-finite numeric value in {field_name}")
    return parsed


def _normalize_date_bound(value: str | None, *, end_of_day: bool, field_name: str) -> datetime | None:
    if value is None or not str(value).strip():
        return None
    cleaned = str(value).strip()
    if len(cleaned) == 10 and cleaned[4] == "-" and cleaned[7] == "-":
        suffix = "T23:59:59Z" if end_of_day else "T00:00:00Z"
        return parse_utc_timestamp(f"{cleaned}{suffix}", field_name=field_name)
    return parse_utc_timestamp(cleaned, field_name=field_name)


def _normalize_usd_currency(raw_token: Any) -> str:
    if isinstance(raw_token, str):
        cleaned = raw_token.strip().upper()
        if cleaned in {"USD", "USDC", "USDH", "USDE", "USDT", ""}:
            return "USD"
        if 2 <= len(cleaned) <= 12 and cleaned.isalnum():
            return cleaned
    return "USD"


def _extract_portfolio_windows(raw_portfolio: Any) -> dict[str, Mapping[str, Any]]:
    windows: dict[str, Mapping[str, Any]] = {}
    if isinstance(raw_portfolio, list):
        for entry in raw_portfolio:
            if (
                isinstance(entry, (list, tuple))
                and len(entry) == 2
                and isinstance(entry[0], str)
                and isinstance(entry[1], Mapping)
            ):
                windows[entry[0].strip()] = entry[1]
    elif isinstance(raw_portfolio, Mapping):
        if "accountValueHistory" in raw_portfolio:
            windows["allTime"] = raw_portfolio
        else:
            for k, v in raw_portfolio.items():
                if isinstance(k, str) and isinstance(v, Mapping):
                    windows[k.strip()] = v
    return windows


def _extract_nav_points_from_history(
    raw_history: Any,
    *,
    start_bound: datetime | None = None,
    end_bound: datetime | None = None,
    complete_before: datetime | None = None,
    ms_out: dict[str, int] | None = None,
) -> list[NormalizedNavPoint]:
    """Return one close per completed UTC date (plus any wipe-out point), oldest first.

    Snapshots at or after ``complete_before`` (the start of the current, unfinished UTC date,
    or of a date the end bound cuts short) contribute no point.
    """
    if not isinstance(raw_history, list):
        return []
    all_by_ts: dict[str, float] = {}
    for item in raw_history:
        raw_t: Any = None
        raw_v: Any = None
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            raw_t, raw_v = item[0], item[1]
        elif isinstance(item, Mapping):
            raw_t = item.get("time") or item.get("timestamp") or item.get("timestamp_utc")
            raw_v = (
                item.get("accountValue")
                if item.get("accountValue") is not None
                else (item.get("nav_base") if item.get("nav_base") is not None else item.get("value"))
            )
        else:
            continue

        ts_iso = _format_epoch_or_iso_utc(raw_t, field_name="accountValueHistory.time")
        ts_dt = parse_utc_timestamp(ts_iso, field_name="accountValueHistory.time")
        if start_bound is not None and ts_dt < start_bound:
            continue
        if end_bound is not None and ts_dt > end_bound:
            continue
        if complete_before is not None and ts_dt >= complete_before:
            continue

        val = _parse_finite_float(raw_v, field_name="accountValueHistory.value", default=0.0)
        all_by_ts[ts_iso] = val
        if ms_out is not None:
            raw_ms = _raw_time_ms(raw_t)
            if raw_ms is not None:
                ms_out[ts_iso] = raw_ms

    ordered_ts = sorted(all_by_ts.keys())
    pos_indices = [idx for idx, ts_key in enumerate(ordered_ts) if all_by_ts[ts_key] > 0.0]
    if not pos_indices:
        return []

    first_pos_idx = pos_indices[0]
    last_pos_idx = pos_indices[-1]
    # Daily closes cover every day between the first and the last positive snapshot, zero
    # equity days included, so a wipe-out followed by a new deposit keeps daily spacing.
    last_idx_by_day: dict[str, int] = {}
    for idx in range(first_pos_idx, last_pos_idx + 1):
        last_idx_by_day[ordered_ts[idx][:10]] = idx

    # Every scored interval runs from one UTC date's close to the next date's close: the
    # last snapshot of each date is its close, and an opening snapshot followed by a later
    # snapshot on the same date is not a scored point.
    kept_indices: list[int] = list(last_idx_by_day.values())

    # Keep every transition from positive equity to <= 0.0 between positive snapshots, even
    # inside a date, so a 100% wipe-out stays a -100% interval (and withholds the record)
    # when a later deposit brings equity back. After the last positive snapshot only the
    # close of the date equity first reached zero is kept. (A full withdrawal is a cash flow
    # of 100% of the opening value inside one interval, so the calculator withholds it too.)
    for idx in range(first_pos_idx + 1, last_pos_idx + 1):
        if all_by_ts[ordered_ts[idx]] <= 0.0 and all_by_ts[ordered_ts[idx - 1]] > 0.0:
            kept_indices.append(idx)
    if last_pos_idx + 1 < len(ordered_ts):
        zero_date = ordered_ts[last_pos_idx + 1][:10]
        terminal_idx = last_pos_idx + 1
        while terminal_idx + 1 < len(ordered_ts) and ordered_ts[terminal_idx + 1][:10] == zero_date:
            terminal_idx += 1
        if zero_date == ordered_ts[last_pos_idx][:10]:
            # The date's close is the zero, not the earlier positive snapshot on that date.
            kept_indices.remove(last_idx_by_day[zero_date])
        kept_indices.append(terminal_idx)

    return [
        NormalizedNavPoint(timestamp_utc=ordered_ts[idx], nav_base=all_by_ts[ordered_ts[idx]])
        for idx in sorted(set(kept_indices))
    ]


def _unvalued_inbound_warning(token_name: str) -> str:
    return (
        f"An unvalued inbound {token_name or 'token'} transfer from another address (no USD value "
        "reported) was recorded at $0 because the perp-only return series does not hold spot tokens."
    )


def _restrict_to_daily_closes(
    points: list[NormalizedNavPoint],
) -> tuple[list[NormalizedNavPoint], bool, str | None]:
    """Return the NAV points to score, whether earlier points were dropped, and a warning.

    Every return interval is scored as one daily period, so a scored series contains only
    closes on consecutive UTC dates. When the series ends in such a run, only that run is
    kept and the excluded snapshots are named in a parser warning. When it does not, the
    record is withheld: Hyperliquid reports daily account history only for about the most
    recent month, and older history is too coarse to score as days.
    """
    if len(points) < 2:
        return points, False, None
    dates = [datetime.fromisoformat(p.timestamp_utc[:10]).date() for p in points]
    multi_day = [i for i in range(1, len(points)) if (dates[i] - dates[i - 1]).days > 1]
    if not multi_day:
        return points, False, None
    run_start = multi_day[-1]
    if len(points) - run_start >= 2:
        return (
            points[run_start:],
            True,
            (
                f"Hyperliquid return series starts at {points[run_start].timestamp_utc}: "
                f"{run_start} earlier snapshot(s) are not daily closes (spaced more than one day "
                "apart) and were excluded so every scored interval is one day."
            ),
        )
    raise HyperliquidValidationError(
        "Hyperliquid reports daily account history only for about the most recent month, and the "
        "requested period has no run of daily closes; the record is withheld rather than scoring "
        "steps of several days as single days"
    )


def _require_list_page(raw_page: Any, query_type: str) -> list[Any]:
    """A page whose body is not a list is an upstream failure, never an empty page."""
    if not isinstance(raw_page, list):
        raise HyperliquidServiceError(
            f"Hyperliquid POST /info ({query_type}) returned a body that is not a list"
        )
    return raw_page


def _entry_time_ms(entry: Mapping[str, Any]) -> int | None:
    t_raw = entry.get("time")
    if not isinstance(t_raw, bool) and isinstance(t_raw, (int, float)):
        return int(t_raw)
    if isinstance(t_raw, str) and t_raw.strip().isdigit():
        return int(t_raw.strip())
    return None


def _page_cannot_be_paged(page: list[Any], cursor_ms: int, new_entries: int) -> bool:
    """True when a page adds new entries but every entry on it sits at the cursor's millisecond.

    The next query would start at the same millisecond and return the same entries, so any
    further entries sharing that millisecond cannot be reached, whatever the page length.
    """
    if new_entries == 0:
        return False
    times = [t for t in (_entry_time_ms(e) for e in page if isinstance(e, Mapping)) if t is not None]
    return bool(times) and min(times) == cursor_ms and max(times) == cursor_ms


def _page_repeats_a_cut_block(page: list[Any], cursor_ms: int) -> bool:
    """True when a page that adds nothing is a block of at least the documented response size
    sitting at the cursor's millisecond: the response cap may have cut that block."""
    times = [t for t in (_entry_time_ms(e) for e in page if isinstance(e, Mapping)) if t is not None]
    return (
        bool(times)
        and min(times) == cursor_ms
        and max(times) == cursor_ms
        and len(page) >= HYPERLIQUID_MIN_DOCUMENTED_RESPONSE_ELEMENTS
    )


def _completed_dates_before(as_of: datetime, end_bound: datetime | None) -> datetime:
    """Start of the first UTC date whose close is not yet known (today, or a cut end date)."""
    cutoff = as_of.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    if end_bound is not None:
        end_day_start = end_bound.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        if end_bound < end_day_start.replace(hour=23, minute=59, second=59):
            cutoff = min(cutoff, end_day_start)
    return cutoff


def _select_scored_nav_series(
    raw_portfolio: Any,
    *,
    start_bound: datetime | None,
    end_bound: datetime | None,
    as_of: datetime | None = None,
) -> tuple[str, list[NormalizedNavPoint], bool, str | None, dict[str, int]]:
    """Select the portfolio window and return (window, scored NAV points, truncated, warning,
    millisecond time of each scored point).

    `allTime` is preferred and enriched with the finer `month`/`week`/`day` snapshots from
    the same response; the merged series is then restricted to daily closes.
    """
    windows = _extract_portfolio_windows(raw_portfolio)
    complete_before = _completed_dates_before(as_of or datetime.now(timezone.utc), end_bound)
    selected_window = "allTime"
    nav_points: list[NormalizedNavPoint] = []
    selected_ms: dict[str, int] = {}
    window_groups: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("allTime", ("day", "week", "month", "allTime")),
        ("perpAllTime", ("perpDay", "perpWeek", "perpMonth", "perpAllTime")),
        ("month", ("day", "week", "month")),
        ("perpMonth", ("perpDay", "perpWeek", "perpMonth")),
        ("week", ("day", "week")),
        ("day", ("day",)),
    )
    for primary_win, merge_order in window_groups:
        if primary_win not in windows:
            continue
        merged_history: list[Any] = []
        for sub_win in merge_order:
            sub_obj = windows.get(sub_win)
            if sub_obj is not None and isinstance(sub_obj.get("accountValueHistory"), list):
                merged_history.extend(sub_obj["accountValueHistory"])
        ms_by_ts: dict[str, int] = {}
        pts = _extract_nav_points_from_history(
            merged_history,
            start_bound=start_bound,
            end_bound=end_bound,
            complete_before=complete_before,
            ms_out=ms_by_ts,
        )
        if len(pts) >= 2:
            selected_window = primary_win
            nav_points = pts
            selected_ms = ms_by_ts
            break
        if pts and not nav_points:
            selected_window = primary_win
            nav_points = pts
            selected_ms = ms_by_ts

    if len(nav_points) < 2:
        raise HyperliquidValidationError(
            "Hyperliquid wallet has fewer than 2 completed daily closes in the requested window; a record "
            "needs at least one full UTC day between two closes"
        )

    nav_points, truncated, spacing_warning = _restrict_to_daily_closes(nav_points)
    return selected_window, nav_points, truncated, spacing_warning, selected_ms


class HyperliquidPublicReadOnlyAdapter(ReadOnlyBrokerAdapter):
    """Permissionless read-only Hyperliquid L1 adapter (`POST https://api.hyperliquid.xyz/info`)."""

    broker_id = "hyperliquid"
    display_name = "Hyperliquid Public Read-Only L1 Clearinghouse"
    approval_state = ProviderApprovalState.PUBLIC_API_PERMISSIONLESS
    default_origin_assurance = OriginAssurance.OPERATOR_RETRIEVED
    supports_subaccount_enumeration = True
    allowed_capabilities = (
        "read_account_profile",
        "list_subaccounts",
        "fetch_nav_history",
        "fetch_fills",
        "fetch_cash_flows",
    )

    def __init__(
        self,
        *,
        wallet_address: str | None = None,
        address: str | None = None,
        user: str | None = None,
        base_url: str | None = None,
        http_transport: HttpTransportCallable | Any | None = None,
        timeout_seconds: float = DEFAULT_HYPERLIQUID_TIMEOUT_SECONDS,
        max_response_bytes: int = MAX_HYPERLIQUID_RESPONSE_BYTES,
        require_live: bool = True,
        **extra_kwargs: Any,
    ) -> None:
        reject_unofficial_scraper_credentials(**extra_kwargs)
        for bad_key in _FORBIDDEN_SECRET_KWARGS:
            if extra_kwargs.get(bad_key) is not None:
                raise MutatingCredentialRejectedError(
                    f"Hyperliquid public read-only adapter forbids secret/signing parameter {bad_key!r}; "
                    "only a public 0x EVM wallet address is accepted."
                )
        super().__init__()

        resolved_addr = wallet_address if wallet_address is not None else (address if address is not None else user)
        self.wallet_address: str | None = (
            validate_hyperliquid_wallet_address(resolved_addr)
            if resolved_addr is not None and str(resolved_addr).strip() != ""
            else None
        )
        self.require_live = bool(require_live)
        self.base_url = _normalize_hyperliquid_base_url(base_url, require_live=self.require_live)

        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or float(timeout_seconds) <= 0.0
            or float(timeout_seconds) > MAX_HYPERLIQUID_TIMEOUT_SECONDS
        ):
            raise HyperliquidValidationError(
                f"timeout_seconds must be between 0 and {MAX_HYPERLIQUID_TIMEOUT_SECONDS}"
            )
        self.timeout_seconds = float(timeout_seconds)

        if (
            isinstance(max_response_bytes, bool)
            or not isinstance(max_response_bytes, int)
            or max_response_bytes < 1024
            or max_response_bytes > MAX_HYPERLIQUID_RESPONSE_BYTES
        ):
            raise HyperliquidValidationError(
                f"max_response_bytes must be an integer between 1024 and {MAX_HYPERLIQUID_RESPONSE_BYTES}"
            )
        self.max_response_bytes = int(max_response_bytes)
        self._transport = http_transport

    def describe_adapter(self) -> BrokerAdapterDescriptor:
        return BrokerAdapterDescriptor(
            broker_id=self.broker_id,
            display_name=self.display_name,
            approval_state=self.approval_state,
            default_origin_assurance=self.default_origin_assurance,
            supports_subaccount_enumeration=self.supports_subaccount_enumeration,
            allowed_capabilities=self.allowed_capabilities,
        )

    def assert_action_permitted(self, action: str) -> None:
        """Enforce read-only policy: block /exchange, order routing, transfers, and withdrawals."""
        clean_action = (action or "").strip().lower()
        if clean_action in _BLOCKED_MUTATING_ACTIONS or any(
            bad in clean_action
            for bad in ("order", "cancel", "withdraw", "transfer", "exchange", "approve", "leverage")
        ):
            raise DisallowedCapabilityError(
                f"Action {action!r} is strictly disallowed in Hyperliquid public read-only adapter."
            )

    def _execute_bounded_post(
        self,
        api_path: str,
        payload: Mapping[str, Any],
        *,
        redact_tokens: Sequence[str] = (),
    ) -> Any:
        norm_path = "/" + (api_path or "").strip().lstrip("/")
        if norm_path.lower() in HYPERLIQUID_BLOCKED_ENDPOINTS or norm_path != HYPERLIQUID_INFO_PATH:
            raise DisallowedCapabilityError(
                f"Hyperliquid endpoint {norm_path!r} is disallowed; only POST /info is permitted"
            )

        query_type = str(payload.get("type") or "").strip()
        if query_type not in HYPERLIQUID_ALLOWED_INFO_TYPES:
            raise DisallowedCapabilityError(
                f"Hyperliquid info query type {query_type!r} is not on the read-only allowlist"
            )

        url = f"{self.base_url}{HYPERLIQUID_INFO_PATH}"
        body_bytes = json.dumps(dict(payload), separators=(",", ":"), sort_keys=True).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": DEFAULT_HYPERLIQUID_USER_AGENT,
        }

        try:
            resp = self._dispatch_http("POST", url, headers, body_bytes)
        except (
            DisallowedCapabilityError,
            PaperOrSandboxAccountRejectedError,
            HyperliquidError,
        ):
            raise
        except Exception as exc:
            safe_err = _redact_hyperliquid_error(str(exc), redact_tokens)
            raise HyperliquidServiceError(
                f"Hyperliquid POST /info ({query_type}) transport failed: {safe_err}"
            ) from None

        if len(resp.body) > self.max_response_bytes:
            raise HyperliquidServiceError(
                f"Hyperliquid POST /info ({query_type}) exceeded {self.max_response_bytes}-byte safety cap"
            )

        if resp.status_code != 200:
            snippet = resp.body[:240].decode("utf-8", errors="replace").strip()
            safe_snippet = _redact_hyperliquid_error(snippet, redact_tokens)
            msg = f"Hyperliquid POST /info ({query_type}) failed with HTTP {resp.status_code}"
            if safe_snippet:
                msg = f"{msg}: {safe_snippet}"
            raise HyperliquidServiceError(msg)

        if not resp.body or not resp.body.strip():
            raise HyperliquidServiceError(
                f"Hyperliquid POST /info ({query_type}) returned an empty body"
            )

        try:
            return json.loads(resp.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HyperliquidServiceError(
                f"Hyperliquid POST /info ({query_type}) returned malformed JSON"
            ) from exc

    def _dispatch_http(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> HttpExchangeResponse:
        hdr_dict = {str(k): str(v) for k, v in headers.items()}
        if self._transport is None:
            req = urllib.request.Request(url=url, data=body, headers=hdr_dict, method=method)
            opener = urllib.request.build_opener(_NoRedirectHandler())
            try:
                with opener.open(req, timeout=self.timeout_seconds) as raw_resp:
                    status_code = int(raw_resp.status)
                    if 300 <= status_code < 400:
                        raise ConnectorHttpError(
                            status_code,
                            f"HTTP {status_code} redirect forbidden for pinned Hyperliquid endpoint",
                        )
                    chunk = raw_resp.read(self.max_response_bytes + 1)
                    if len(chunk) > self.max_response_bytes:
                        raise HyperliquidServiceError(
                            f"Hyperliquid response exceeded {self.max_response_bytes}-byte safety cap"
                        )
                    resp_hdrs = {k.lower(): v for k, v in raw_resp.headers.items()}
                    return HttpExchangeResponse(
                        status_code=status_code,
                        headers=resp_hdrs,
                        body=chunk,
                    )
            except urllib.error.HTTPError as http_exc:
                code_int = int(http_exc.code)
                if 300 <= code_int < 400:
                    raise ConnectorHttpError(
                        code_int,
                        f"HTTP {code_int} redirect forbidden for pinned Hyperliquid endpoint",
                    ) from None
                err_bytes = http_exc.read(65536) if http_exc.fp is not None else b""
                resp_hdrs = (
                    {k.lower(): v for k, v in http_exc.headers.items()}
                    if http_exc.headers is not None
                    else {}
                )
                return HttpExchangeResponse(
                    status_code=code_int,
                    headers=resp_hdrs,
                    body=err_bytes,
                )

        if hasattr(self._transport, "request") and callable(self._transport.request):
            out = self._transport.request(method, url, headers=hdr_dict, content=body)
            raw_b = (
                bytes(out.body)
                if hasattr(out, "body")
                else (
                    bytes(out.content)
                    if hasattr(out, "content")
                    else str(out.text).encode("utf-8")
                )
            )
            return HttpExchangeResponse(
                status_code=int(out.status_code),
                headers={str(k).lower(): str(v) for k, v in (getattr(out, "headers", None) or {}).items()},
                body=raw_b,
            )

        if callable(self._transport):
            raw_out = self._transport(method, url, hdr_dict, body)
            if isinstance(raw_out, HttpExchangeResponse):
                return raw_out
            if hasattr(raw_out, "status_code"):
                raw_b = (
                    bytes(raw_out.body)
                    if hasattr(raw_out, "body")
                    else (
                        bytes(raw_out.content)
                        if hasattr(raw_out, "content")
                        else str(raw_out.text).encode("utf-8")
                    )
                )
                return HttpExchangeResponse(
                    status_code=int(raw_out.status_code),
                    headers={
                        str(k).lower(): str(v)
                        for k, v in (getattr(raw_out, "headers", None) or {}).items()
                    },
                    body=raw_b,
                )
            status, out_hdrs, out_payload = raw_out
            if isinstance(out_payload, bytes):
                payload_bytes = out_payload
            elif isinstance(out_payload, str):
                payload_bytes = out_payload.encode("utf-8")
            else:
                payload_bytes = json.dumps(out_payload, separators=(",", ":")).encode("utf-8")
            return HttpExchangeResponse(
                status_code=int(status),
                headers={str(k).lower(): str(v) for k, v in (out_hdrs or {}).items()},
                body=payload_bytes,
            )

        raise TypeError(f"Unsupported http_transport type: {type(self._transport).__name__}")

    def parse_payload(
        self,
        payload: Mapping[str, Any],
        *,
        wallet_address: str,
        blinding_salt_hex: str,
        start_date: str | None = None,
        end_date: str | None = None,
        require_live: bool = True,
        as_of_utc: str | None = None,
    ) -> CanonicalPortfolioLedger:
        """Normalize Hyperliquid ``portfolio``, ``userNonFundingLedgerUpdates``, and ``userFills`` into ``CanonicalPortfolioLedger``."""
        norm_address = validate_hyperliquid_wallet_address(wallet_address)
        if not self.require_live and require_live:
            pass
        env_tier = EnvironmentTier.LIVE_PRODUCTION

        start_bound = _normalize_date_bound(start_date, end_of_day=False, field_name="start_date")
        end_bound = _normalize_date_bound(end_date, end_of_day=True, field_name="end_date")
        if start_bound is not None and end_bound is not None and end_bound < start_bound:
            raise HyperliquidValidationError("end_date must be >= start_date")

        raw_portfolio = payload.get("portfolio")
        raw_ledger_updates = (
            payload.get("ledger_updates")
            if payload.get("ledger_updates") is not None
            else payload.get("userNonFundingLedgerUpdates")
        )
        raw_fills = (
            payload.get("fills")
            if payload.get("fills") is not None
            else payload.get("userFills")
        )
        raw_clearinghouse = (
            payload.get("clearinghouse_state")
            if payload.get("clearinghouse_state") is not None
            else payload.get("clearinghouseState")
        )

        source_canonical = json.dumps(
            {
                "portfolio": raw_portfolio,
                "ledger_updates": raw_ledger_updates,
                "fills": raw_fills,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        source_sha256 = hashlib.sha256(source_canonical).hexdigest()
        blinded_tag = compute_blinded_account_tag("hyperliquid", norm_address, blinding_salt_hex)

        # 1. Extract the scored NAV curve from `portfolio` (daily closes only)
        as_of = parse_utc_timestamp(as_of_utc, field_name="as_of_utc") if as_of_utc else None
        selected_window, nav_points, _, spacing_warning, nav_ms = _select_scored_nav_series(
            raw_portfolio, start_bound=start_bound, end_bound=end_bound, as_of=as_of
        )
        parser_warnings: list[str] = [spacing_warning] if spacing_warning else []
        # The ledger describes one period, the span of the scored closes: ledger entries and
        # fills dated before the first scored close or after the last one are dropped.
        entry_start_bound = parse_utc_timestamp(nav_points[0].timestamp_utc, field_name="nav_points.timestamp_utc")
        entry_end_bound = parse_utc_timestamp(nav_points[-1].timestamp_utc, field_name="nav_points.timestamp_utc")
        # Timestamps are formatted to whole seconds, so a capital flow in the same second as a
        # scored close but after it (at millisecond precision) would be read as on the wrong side
        # of that close: its interval cannot be computed and the record is refused.
        boundary_close_ms = {
            nav_points[0].timestamp_utc: nav_ms.get(nav_points[0].timestamp_utc),
            nav_points[-1].timestamp_utc: nav_ms.get(nav_points[-1].timestamp_utc),
        }

        perp_only_window = selected_window.startswith("perp")

        # 2. Separate non-funding ledger cash flows from trading PnL
        flows: list[NormalizedFlow] = []
        updates_list = raw_ledger_updates if isinstance(raw_ledger_updates, list) else []
        for item in updates_list:
            if not isinstance(item, Mapping):
                continue
            delta = item.get("delta") if isinstance(item.get("delta"), Mapping) else item
            if not isinstance(delta, Mapping):
                continue

            delta_type = str(delta.get("type") or "").strip()
            if not delta_type:
                continue
            lower_type = delta_type.lower()

            raw_time = item.get("time") if item.get("time") is not None else delta.get("time")
            if raw_time is None:
                continue
            ts_iso = _format_epoch_or_iso_utc(raw_time, field_name="ledgerUpdate.time")
            ts_dt = parse_utc_timestamp(ts_iso, field_name="ledgerUpdate.time")
            if ts_dt < entry_start_bound:
                continue
            if ts_dt > entry_end_bound:
                continue

            flows_before_entry = len(flows)
            explicit_usdc_raw = (
                delta.get("usdc")
                if delta.get("usdc") is not None
                else delta.get("usdcValue")
            )
            token_name = str(delta.get("token") or "").strip().upper()
            raw_usdc = (
                explicit_usdc_raw
                if explicit_usdc_raw is not None
                else (
                    delta.get("amount")
                    if token_name in _USD_EQUIVALENT_TOKENS
                    and lower_type not in {"spottransfer"}
                    else None
                )
            )
            usdc_val = _parse_finite_float(raw_usdc, field_name=f"delta.{delta_type}.usdc", default=0.0)
            fee_val = abs(
                _parse_finite_float(delta.get("fee"), field_name=f"delta.{delta_type}.fee", default=0.0)
            )

            sender = str(delta.get("user") or "").strip().lower()
            destination = str(delta.get("destination") or "").strip().lower()
            is_self_transfer = bool(sender and destination and sender == norm_address and destination == norm_address)
            # An unvalued token that another address sends into spot is outside a perp-only
            # return series, so it is recorded at $0 with a warning instead of withholding.
            # On the combined window the token is part of NAV and its value is unknown, so it
            # stays an unvalued in-kind flow and the record is withheld.
            dst_dex_raw = delta.get("destinationDex")
            unvalued_inbound_outside_series = bool(
                perp_only_window
                and sender
                and sender != norm_address
                and destination == norm_address
                and (dst_dex_raw is None or str(dst_dex_raw).strip().lower() == "spot")
            )

            if lower_type == "deposit":
                if abs(usdc_val) > 0.0:
                    flows.append(
                        NormalizedFlow(
                            timestamp_utc=ts_iso,
                            kind=FlowKind.DEPOSIT,
                            amount=abs(usdc_val),
                            currency="USD",
                            transfer_type="deposit",
                            description="Hyperliquid L1 USDC deposit",
                        )
                    )
            elif lower_type == "withdraw":
                if abs(usdc_val) > 0.0:
                    flows.append(
                        NormalizedFlow(
                            timestamp_utc=ts_iso,
                            kind=FlowKind.WITHDRAWAL,
                            amount=-abs(usdc_val),
                            currency="USD",
                            transfer_type="withdraw",
                            description="Hyperliquid L1 USDC withdrawal",
                        )
                    )
                if fee_val > 0.0:
                    flows.append(
                        NormalizedFlow(
                            timestamp_utc=ts_iso,
                            kind=FlowKind.COMMISSION_FEE,
                            amount=-fee_val,
                            currency="USD",
                            transfer_type="withdraw_fee",
                            description="Hyperliquid L1 bridge withdrawal fee",
                        )
                    )
            elif lower_type in {"accountclasstransfer", "usdclasstransfer"}:
                if abs(usdc_val) > 0.0:
                    to_perp_raw = delta.get("toPerp")
                    if isinstance(to_perp_raw, bool):
                        signed_amt = abs(usdc_val) if to_perp_raw else -abs(usdc_val)
                    else:
                        signed_amt = usdc_val
                    # On `allTime` (combined Perp + Spot), Spot<->Perp reclassifications stay inside
                    # the wallet (`OTHER_INTERNAL`); on `perp*` windows they cross the Perp boundary.
                    cls_kind = (
                        FlowKind.INTERNAL_SUBACCOUNT_TRANSFER
                        if perp_only_window
                        else FlowKind.OTHER_INTERNAL
                    )
                    flows.append(
                        NormalizedFlow(
                            timestamp_utc=ts_iso,
                            kind=cls_kind,
                            amount=signed_amt,
                            currency="USD",
                            transfer_type="accountClassTransfer",
                            description="Hyperliquid Spot/Perp class transfer",
                        )
                    )
            elif lower_type == "subaccounttransfer":
                if abs(usdc_val) > 0.0:
                    if is_self_transfer:
                        flows.append(
                            NormalizedFlow(
                                timestamp_utc=ts_iso,
                                kind=FlowKind.OTHER_INTERNAL,
                                amount=0.0,
                                currency="USD",
                                transfer_type="subAccountTransfer",
                                description="Hyperliquid self subaccount reclassification",
                            )
                        )
                    else:
                        if destination == norm_address and sender != norm_address:
                            signed_amt = abs(usdc_val)
                        elif sender == norm_address and destination != norm_address:
                            signed_amt = -abs(usdc_val)
                        else:
                            signed_amt = usdc_val
                        flows.append(
                            NormalizedFlow(
                                timestamp_utc=ts_iso,
                                kind=FlowKind.INTERNAL_SUBACCOUNT_TRANSFER,
                                amount=signed_amt,
                                currency="USD",
                                transfer_type="subAccountTransfer",
                                description="Hyperliquid subaccount transfer",
                            )
                        )
            elif lower_type in {"internaltransfer", "send", "spotsend"}:
                token_amt = _parse_finite_float(
                    delta.get("amount"), field_name=f"delta.{delta_type}.amount", default=0.0
                )
                if is_self_transfer:
                    src_dex = str(delta.get("sourceDex") or "").strip().lower()
                    dst_dex = str(delta.get("destinationDex") or "").strip().lower()
                    crosses_perp_boundary = src_dex != dst_dex and "" in (src_dex, dst_dex)
                    if (
                        perp_only_window
                        and crosses_perp_boundary
                        and explicit_usdc_raw is None
                        and abs(usdc_val) == 0.0
                        and abs(token_amt) > 0.0
                    ):
                        # An unvalued token crossing into or out of a perp-only return series
                        # changes that series by an unknown amount, so the record is withheld.
                        flows.append(
                            NormalizedFlow(
                                timestamp_utc=ts_iso,
                                kind=(
                                    FlowKind.TRANSFER_IN_KIND
                                    if dst_dex == ""
                                    else FlowKind.TRANSFER_OUT_KIND
                                ),
                                amount=0.0,
                                amount_base=0.0,
                                currency="USD",
                                symbol=token_name,
                                quantity=abs(token_amt),
                                transfer_type="internalTransfer",
                                description="Hyperliquid unvalued token crossing the perp boundary",
                            )
                        )
                        self_kind, self_amt = None, 0.0
                    elif perp_only_window and abs(usdc_val) > 0.0 and src_dex != dst_dex:
                        if dst_dex == "":
                            self_kind = FlowKind.INTERNAL_SUBACCOUNT_TRANSFER
                            self_amt = abs(usdc_val)
                        elif src_dex == "":
                            self_kind = FlowKind.INTERNAL_SUBACCOUNT_TRANSFER
                            self_amt = -abs(usdc_val)
                        else:
                            self_kind = FlowKind.OTHER_INTERNAL
                            self_amt = usdc_val
                    else:
                        self_kind = FlowKind.OTHER_INTERNAL
                        self_amt = abs(usdc_val)
                    if self_kind is not None and (abs(self_amt) > 0.0 or abs(token_amt) > 0.0):
                        flows.append(
                            NormalizedFlow(
                                timestamp_utc=ts_iso,
                                kind=self_kind,
                                amount=self_amt,
                                currency="USD",
                                transfer_type="internalTransfer",
                                description="Hyperliquid self-wallet DEX transfer",
                            )
                        )
                elif abs(usdc_val) > 0.0:
                    if destination == norm_address and sender != norm_address:
                        flow_kind = FlowKind.DEPOSIT
                        signed_amt = abs(usdc_val)
                    elif sender == norm_address and destination != norm_address:
                        flow_kind = FlowKind.WITHDRAWAL
                        signed_amt = -abs(usdc_val)
                    elif usdc_val >= 0.0:
                        flow_kind = FlowKind.DEPOSIT
                        signed_amt = abs(usdc_val)
                    else:
                        flow_kind = FlowKind.WITHDRAWAL
                        signed_amt = -abs(usdc_val)
                    flows.append(
                        NormalizedFlow(
                            timestamp_utc=ts_iso,
                            kind=flow_kind,
                            amount=signed_amt,
                            currency="USD",
                            transfer_type="internalTransfer",
                            description="Hyperliquid L1 wallet transfer",
                        )
                    )
                elif token_name not in _USD_EQUIVALENT_TOKENS and abs(token_amt) > 0.0:
                    if explicit_usdc_raw is not None:
                        # Hyperliquid explicitly valued this dust/spam airdrop token at $0.00 USD;
                        # classify as $0 internal dust so spam airdrops cannot grief/withhold TWR.
                        flows.append(
                            NormalizedFlow(
                                timestamp_utc=ts_iso,
                                kind=FlowKind.OTHER_INTERNAL,
                                amount=0.0,
                                currency="USD",
                                symbol=token_name,
                                quantity=abs(token_amt),
                                transfer_type="internalTransfer",
                                description="Hyperliquid zero-USD dust token transfer",
                            )
                        )
                    elif unvalued_inbound_outside_series:
                        parser_warnings.append(_unvalued_inbound_warning(token_name))
                        flows.append(
                            NormalizedFlow(
                                timestamp_utc=ts_iso,
                                kind=FlowKind.OTHER_INTERNAL,
                                amount=0.0,
                                currency="USD",
                                symbol=token_name,
                                quantity=abs(token_amt),
                                transfer_type="internalTransfer",
                                description="Hyperliquid unvalued inbound token outside perp series",
                            )
                        )
                    else:
                        inbound = (destination == norm_address and sender != norm_address) or (
                            not sender and not destination and token_amt >= 0.0
                        )
                        flows.append(
                            NormalizedFlow(
                                timestamp_utc=ts_iso,
                                kind=FlowKind.TRANSFER_IN_KIND if inbound else FlowKind.TRANSFER_OUT_KIND,
                                amount=0.0,
                                amount_base=0.0,
                                currency="USD",
                                symbol=token_name,
                                quantity=abs(token_amt),
                                transfer_type="internalTransfer",
                                description="Hyperliquid unvalued token transfer",
                            )
                        )
                if fee_val > 0.0 and sender in {"", norm_address}:
                    flows.append(
                        NormalizedFlow(
                            timestamp_utc=ts_iso,
                            kind=FlowKind.COMMISSION_FEE,
                            amount=-fee_val,
                            currency="USD",
                            transfer_type="internalTransfer_fee",
                            description="Hyperliquid L1 transfer fee",
                        )
                    )
            elif lower_type == "spottransfer":
                token_amt = _parse_finite_float(
                    delta.get("amount"), field_name="delta.spotTransfer.amount", default=0.0
                )
                usd_equiv = (
                    abs(usdc_val)
                    if explicit_usdc_raw is not None and abs(usdc_val) > 0.0
                    else (abs(token_amt) if token_name in _USD_EQUIVALENT_TOKENS else 0.0)
                )
                if is_self_transfer:
                    if usd_equiv > 0.0 or abs(token_amt) > 0.0:
                        flows.append(
                            NormalizedFlow(
                                timestamp_utc=ts_iso,
                                kind=FlowKind.OTHER_INTERNAL,
                                amount=usd_equiv,
                                currency="USD",
                                transfer_type="spotTransfer",
                                description="Hyperliquid self-wallet spot reclassification",
                            )
                        )
                else:
                    inbound = (destination == norm_address and sender != norm_address) or (
                        not sender and not destination and token_amt >= 0.0
                    )
                    if token_name in _USD_EQUIVALENT_TOKENS and usd_equiv > 0.0:
                        flows.append(
                            NormalizedFlow(
                                timestamp_utc=ts_iso,
                                kind=FlowKind.DEPOSIT if inbound else FlowKind.WITHDRAWAL,
                                amount=usd_equiv if inbound else -usd_equiv,
                                currency="USD",
                                transfer_type="spotTransfer",
                                description="Hyperliquid spot USDC transfer",
                            )
                        )
                    elif token_name not in _USD_EQUIVALENT_TOKENS and abs(token_amt) > 0.0:
                        if usd_equiv > 0.0:
                            flows.append(
                                NormalizedFlow(
                                    timestamp_utc=ts_iso,
                                    kind=FlowKind.TRANSFER_IN_KIND if inbound else FlowKind.TRANSFER_OUT_KIND,
                                    amount=usd_equiv if inbound else -usd_equiv,
                                    amount_base=usd_equiv if inbound else -usd_equiv,
                                    currency="USD",
                                    symbol=token_name,
                                    quantity=abs(token_amt),
                                    transfer_type="spotTransfer",
                                    description="Hyperliquid spot token transfer",
                                )
                            )
                        elif explicit_usdc_raw is not None:
                            # Hyperliquid explicitly valued this unsolicited airdrop/dust token at $0.00 USD.
                            flows.append(
                                NormalizedFlow(
                                    timestamp_utc=ts_iso,
                                    kind=FlowKind.OTHER_INTERNAL,
                                    amount=0.0,
                                    currency="USD",
                                    symbol=token_name,
                                    quantity=abs(token_amt),
                                    transfer_type="spotTransfer",
                                    description="Hyperliquid zero-USD dust spot transfer",
                                )
                            )
                        elif unvalued_inbound_outside_series:
                            parser_warnings.append(_unvalued_inbound_warning(token_name))
                            flows.append(
                                NormalizedFlow(
                                    timestamp_utc=ts_iso,
                                    kind=FlowKind.OTHER_INTERNAL,
                                    amount=0.0,
                                    currency="USD",
                                    symbol=token_name,
                                    quantity=abs(token_amt),
                                    transfer_type="spotTransfer",
                                    description="Hyperliquid unvalued inbound token outside perp series",
                                )
                            )
                        else:
                            flows.append(
                                NormalizedFlow(
                                    timestamp_utc=ts_iso,
                                    kind=FlowKind.TRANSFER_IN_KIND if inbound else FlowKind.TRANSFER_OUT_KIND,
                                    amount=0.0,
                                    amount_base=0.0,
                                    currency="USD",
                                    symbol=token_name,
                                    quantity=abs(token_amt),
                                    transfer_type="spotTransfer",
                                    description="Hyperliquid unvalued spot token transfer",
                                )
                            )
            elif lower_type in {"vaultdeposit", "vaultwithdraw"}:
                # The combined account value already includes equity held in vaults (checked
                # against the service on 2026-11-18: the combined windows show no change at a vault
                # withdrawal, the perp-only windows show the money arriving in the perp account).
                # So on the combined window a vault move is internal and carries no external flow;
                # on a perp-only window the money leaves or enters the perp account.
                vault_amt = (
                    _parse_finite_float(
                        delta.get("netWithdrawnUsd"),
                        field_name="delta.vaultWithdraw.netWithdrawnUsd",
                        default=usdc_val,
                    )
                    if lower_type == "vaultwithdraw"
                    else usdc_val
                )
                if abs(vault_amt) > 0.0:
                    into_vault = lower_type == "vaultdeposit"
                    if perp_only_window:
                        flows.append(
                            NormalizedFlow(
                                timestamp_utc=ts_iso,
                                kind=FlowKind.WITHDRAWAL if into_vault else FlowKind.DEPOSIT,
                                amount=-abs(vault_amt) if into_vault else abs(vault_amt),
                                currency="USD",
                                transfer_type=delta_type,
                                description="Hyperliquid vault move across the perp account",
                            )
                        )
                    else:
                        flows.append(
                            NormalizedFlow(
                                timestamp_utc=ts_iso,
                                kind=FlowKind.OTHER_INTERNAL,
                                amount=-abs(vault_amt) if into_vault else abs(vault_amt),
                                currency="USD",
                                transfer_type=delta_type,
                                description="Hyperliquid vault move inside the combined account value",
                            )
                        )
            elif lower_type == "rewardsclaim":
                if abs(usdc_val) > 0.0:
                    flows.append(
                        NormalizedFlow(
                            timestamp_utc=ts_iso,
                            kind=FlowKind.INTEREST,
                            amount=abs(usdc_val),
                            currency="USD",
                            transfer_type="rewardsClaim",
                            description="Hyperliquid protocol rewards claim",
                        )
                    )
            else:
                # A ledger entry type this parser does not know, and that moves value, has an
                # effect on returns that cannot be computed, so the record is withheld.
                moves_value = any(
                    abs(
                        _parse_finite_float(
                            delta.get(value_key),
                            field_name=f"delta.{delta_type}.{value_key}",
                            default=0.0,
                        )
                    )
                    > 0.0
                    for value_key in _VALUE_MOVING_DELTA_FIELDS
                )
                if moves_value:
                    raise HyperliquidValidationError(
                        f"Hyperliquid ledger entry type {delta_type!r} is not recognised and moves value; "
                        "the record is withheld because its effect on returns cannot be computed"
                    )

            close_ms = boundary_close_ms.get(ts_iso)
            entry_ms = _raw_time_ms(raw_time)
            if (
                close_ms is not None
                and entry_ms is not None
                and entry_ms > close_ms
                and any(f.kind in CAPITAL_FLOW_KINDS_FOR_TWR for f in flows[flows_before_entry:])
            ):
                raise HyperliquidValidationError(
                    f"A Hyperliquid cash flow falls in the same second as the scored close at {ts_iso} but "
                    "after it; the record is withheld because that interval cannot be computed"
                )

        # 3. Normalize `userFills` into `NormalizedTrade` records (7-day embargo enforced downstream)
        trades: list[NormalizedTrade] = []
        seen_fill_ids: set[str] = set()
        fills_list = raw_fills if isinstance(raw_fills, list) else []
        # A coin whose position may already be open at the first scored close has none of its
        # fills in the ledger: closing fills without their opening fills would be matched as
        # round trips that never happened. That is a coin with any fill before the first close,
        # or whose first fill inside the period reports a non-zero starting position.
        first_fill_in_period: dict[str, tuple[int, Any]] = {}
        coins_open_at_start: set[str] = set()
        for fill in fills_list:
            if not isinstance(fill, Mapping):
                continue
            coin_key = str(fill.get("coin") or fill.get("symbol") or "").strip().upper()
            raw_t = fill.get("time") if fill.get("time") is not None else fill.get("timestamp")
            if not coin_key or raw_t is None:
                continue
            f_dt = parse_utc_timestamp(
                _format_epoch_or_iso_utc(raw_t, field_name="userFills.time"), field_name="userFills.time"
            )
            if f_dt < entry_start_bound:
                coins_open_at_start.add(coin_key)
            elif f_dt <= entry_end_bound:
                f_ms = _raw_time_ms(raw_t) or 0
                if coin_key not in first_fill_in_period or f_ms < first_fill_in_period[coin_key][0]:
                    first_fill_in_period[coin_key] = (f_ms, fill.get("startPosition"))
        for coin_key, (_, start_pos) in first_fill_in_period.items():
            if abs(_parse_finite_float(start_pos, field_name="userFills.startPosition", default=0.0)) > 0.0:
                coins_open_at_start.add(coin_key)
        if coins_open_at_start:
            parser_warnings.append(
                "Fills in "
                + ", ".join(sorted(coins_open_at_start))
                + " are left out of the ledger: a position in each may be open at the start of the "
                "period, so its trades cannot be matched into round trips."
            )
        for idx, fill in enumerate(fills_list):
            if not isinstance(fill, Mapping):
                continue
            coin_raw = str(fill.get("coin") or fill.get("symbol") or "").strip()
            if not coin_raw or coin_raw.upper() in coins_open_at_start:
                continue
            raw_time = fill.get("time") if fill.get("time") is not None else fill.get("timestamp")
            if raw_time is None:
                continue
            ts_iso = _format_epoch_or_iso_utc(raw_time, field_name="userFills.time")
            ts_dt = parse_utc_timestamp(ts_iso, field_name="userFills.time")
            if ts_dt < entry_start_bound:
                continue
            if ts_dt > entry_end_bound:
                continue

            sz = abs(_parse_finite_float(fill.get("sz") if fill.get("sz") is not None else fill.get("quantity"), field_name="userFills.sz", default=0.0))
            px = _parse_finite_float(fill.get("px") if fill.get("px") is not None else fill.get("price"), field_name="userFills.px", default=0.0)
            if sz <= 0.0 or px < 0.0:
                continue

            side_raw = str(fill.get("side") or "").strip().lower()
            if side_raw in {"b", "buy", "bid", "long"}:
                norm_side = "buy"
            elif side_raw in {"a", "sell", "ask", "short"}:
                norm_side = "sell"
            else:
                dir_raw = str(fill.get("dir") or "").strip().lower()
                if (
                    ("long" in dir_raw and "open" in dir_raw)
                    or "close short" in dir_raw
                    or "short > long" in dir_raw
                    or ("liquidat" in dir_raw and "short" in dir_raw)
                ):
                    norm_side = "buy"
                elif (
                    ("short" in dir_raw and "open" in dir_raw)
                    or "close long" in dir_raw
                    or "long > short" in dir_raw
                    or ("liquidat" in dir_raw and "long" in dir_raw)
                ):
                    norm_side = "sell"
                else:
                    raise HyperliquidValidationError(f"Unrecognized Hyperliquid fill side {side_raw!r}")

            raw_fee = _parse_finite_float(fill.get("fee"), field_name="userFills.fee", default=0.0)
            builder_fee = _parse_finite_float(
                fill.get("builderFee"), field_name="userFills.builderFee", default=0.0
            )
            # Maker rebates (negative fee) reduce net fee drag rather than inflating cost drag.
            commission = max(0.0, raw_fee) + max(0.0, builder_fee)

            is_spot = coin_raw.startswith("@") or "/" in coin_raw
            asset_cls = AssetClass.CRYPTO_SPOT if is_spot else AssetClass.CRYPTO_PERP
            symbol_clean = coin_raw.upper()

            raw_tid = fill.get("tid")
            raw_oid = fill.get("oid")
            entry_id = (
                f"hl-tid-{raw_tid}"
                if raw_tid is not None and str(raw_tid).strip() != ""
                else (
                    f"hl-oid-{raw_oid}-{idx}"
                    if raw_oid is not None and str(raw_oid).strip() != ""
                    else f"hl-fill-{idx + 1}"
                )
            )
            if entry_id in seen_fill_ids:
                continue
            seen_fill_ids.add(entry_id)

            fee_ccy = _normalize_usd_currency(fill.get("feeToken"))
            fx_rate = 1.0

            trades.append(
                NormalizedTrade(
                    venue="HYPERLIQUID_L1",
                    native_entry_id=entry_id,
                    symbol=symbol_clean,
                    asset_class=asset_cls,
                    side=norm_side,
                    quantity=sz,
                    price=px,
                    timestamp_utc=ts_iso,
                    currency=fee_ccy if fee_ccy == "USD" else "USD",
                    fx_rate_to_base=fx_rate,
                    multiplier=1.0,
                    commission=commission,
                )
            )

        # 4. Optional ending positions when `clearinghouseState` is supplied
        ending_positions: list[NormalizedPosition] = []
        enabled_sections = [
            "hyperliquid_portfolio",
            "hyperliquid_ledger_updates",
            "hyperliquid_fills",
        ]
        if isinstance(raw_clearinghouse, Mapping):
            enabled_sections.extend(["hyperliquid_clearinghouse_state", "Transfers", "CorporateActions"])
            asset_positions = raw_clearinghouse.get("assetPositions")
            if isinstance(asset_positions, list):
                for ap in asset_positions:
                    if not isinstance(ap, Mapping):
                        continue
                    pos_obj = ap.get("position") if isinstance(ap.get("position"), Mapping) else ap
                    if not isinstance(pos_obj, Mapping):
                        continue
                    coin_sym = str(pos_obj.get("coin") or "").strip().upper()
                    szi = _parse_finite_float(pos_obj.get("szi"), field_name="position.szi", default=0.0)
                    if not coin_sym or abs(szi) <= 1e-12:
                        continue
                    entry_px = _parse_finite_float(
                        pos_obj.get("entryPx"), field_name="position.entryPx", default=0.0
                    )
                    pos_val = _parse_finite_float(
                        pos_obj.get("positionValue"),
                        field_name="position.positionValue",
                        default=abs(szi) * entry_px,
                    )
                    signed_mv = pos_val if szi >= 0.0 else -abs(pos_val)
                    ending_positions.append(
                        NormalizedPosition(
                            prior_period_or_ending="ending",
                            symbol=coin_sym,
                            asset_class=AssetClass.CRYPTO_PERP,
                            quantity=szi,
                            cost_basis=szi * entry_px,
                            market_value=signed_mv,
                            currency="USD",
                            multiplier=1.0,
                        )
                    )

        # The record covers exactly the span of the scored closes.
        period_start_utc = nav_points[0].timestamp_utc
        period_end_utc = nav_points[-1].timestamp_utc

        return CanonicalPortfolioLedger(
            blinded_account_tag=blinded_tag,
            broker_id=self.broker_id,
            account_scope=AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED,
            claimed_origin_assurance=self.default_origin_assurance,
            provider_approval_state=self.approval_state,
            environment_tier=env_tier,
            source_body_sha256=source_sha256,
            base_currency="USD",
            period_start_utc=period_start_utc,
            period_end_utc=period_end_utc,
            ending_positions=ending_positions,
            nav_points=nav_points,
            trades=sorted(trades, key=lambda t: (t.timestamp_utc, t.native_entry_id)),
            flows=sorted(flows, key=lambda f: f.timestamp_utc),
            conversion_rates={"USDC/USD": 1.0},
            enabled_sections=enabled_sections,
            parser_warnings=list(dict.fromkeys(parser_warnings)),
        )

    def fetch_canonical_ledger(
        self,
        *,
        blinding_salt_hex: str,
        wallet_address: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        require_live: bool = True,
        as_of_utc: str | None = None,
    ) -> CanonicalPortfolioLedger:
        """Fetch read-only Hyperliquid L1 portfolio, non-funding ledger updates, and fills."""
        raw_addr = wallet_address if wallet_address is not None else self.wallet_address
        norm_address = validate_hyperliquid_wallet_address(raw_addr)
        if require_live and not self.require_live:
            _normalize_hyperliquid_base_url(self.base_url, require_live=True)

        start_bound = _normalize_date_bound(start_date, end_of_day=False, field_name="start_date")
        end_bound = _normalize_date_bound(end_date, end_of_day=True, field_name="end_date")
        if start_bound is not None and end_bound is not None and end_bound < start_bound:
            raise HyperliquidValidationError("end_date must be >= start_date")

        redact_list = (norm_address, str(raw_addr or "").strip())

        portfolio_data = self._execute_bounded_post(
            HYPERLIQUID_INFO_PATH,
            {"type": "portfolio", "user": norm_address},
            redact_tokens=redact_list,
        )

        # The scored series decides where paging starts: ledger entries and fills before the
        # first scored close are not needed (and are dropped by `parse_payload`). A portfolio
        # without a scorable series is withheld here, before any ledger call.
        as_of = parse_utc_timestamp(as_of_utc, field_name="as_of_utc") if as_of_utc else None
        _, scored_nav, _, _, _ = _select_scored_nav_series(
            portfolio_data, start_bound=start_bound, end_bound=end_bound, as_of=as_of
        )
        scored_start_ms = int(parse_utc_timestamp(scored_nav[0].timestamp_utc).timestamp() * 1000)

        cursor_ms = scored_start_ms
        if start_bound is not None:
            cursor_ms = max(cursor_ms, int(start_bound.timestamp() * 1000))
        end_ms = int(end_bound.timestamp() * 1000) if end_bound is not None else None
        ledger_updates_data: list[Any] = []
        seen_ledger_keys: set[tuple[str, str, str, int]] = set()
        # A page is final only when it adds no new entries: the service's page size is not
        # contractual, so a short page is not taken as the end of the history. The ceiling
        # counts entries read, not pages.
        for _ in range(MAX_HYPERLIQUID_LEDGER_PAGES):
            ledger_query: dict[str, Any] = {
                "type": "userNonFundingLedgerUpdates",
                "user": norm_address,
                "startTime": cursor_ms,
            }
            if end_ms is not None:
                ledger_query["endTime"] = end_ms
            page_raw = self._execute_bounded_post(
                HYPERLIQUID_INFO_PATH,
                ledger_query,
                redact_tokens=redact_list,
            )
            page_items = _require_list_page(page_raw, "userNonFundingLedgerUpdates")
            max_page_ms = cursor_ms
            page_fp_counts: dict[tuple[str, str, str], int] = {}
            new_unique_count = 0
            for entry in page_items:
                if isinstance(entry, Mapping):
                    t_ms = _entry_time_ms(entry)
                    h_raw = str(entry.get("hash") or "")
                    fp = (
                        str(t_ms if t_ms is not None else entry.get("time")),
                        h_raw,
                        json.dumps(entry.get("delta"), sort_keys=True, default=str),
                    )
                    occ_idx = page_fp_counts.get(fp, 0)
                    page_fp_counts[fp] = occ_idx + 1
                    dedup_key = (fp[0], fp[1], fp[2], occ_idx)
                    if dedup_key not in seen_ledger_keys:
                        seen_ledger_keys.add(dedup_key)
                        ledger_updates_data.append(entry)
                        new_unique_count += 1
                    if t_ms is not None and t_ms > max_page_ms:
                        max_page_ms = t_ms
                else:
                    ledger_updates_data.append(entry)
                    new_unique_count += 1
            if _page_cannot_be_paged(page_items, cursor_ms, new_unique_count) or (
                new_unique_count == 0 and _page_repeats_a_cut_block(page_items, cursor_ms)
            ):
                raise HyperliquidValidationError(
                    "Hyperliquid ledger history could not be paged past entries sharing one timestamp; "
                    "the record is withheld because the ledger is incomplete"
                )
            if len(ledger_updates_data) >= MAX_HYPERLIQUID_LEDGER_ENTRIES:
                raise HyperliquidValidationError(
                    f"Hyperliquid ledger history reaches {MAX_HYPERLIQUID_LEDGER_ENTRIES} entries in the "
                    "period; the record is withheld because the ledger may be incomplete"
                )
            if new_unique_count == 0:
                break
            cursor_ms = max_page_ms if max_page_ms > cursor_ms else cursor_ms + 1
        else:
            raise HyperliquidValidationError(
                f"Hyperliquid ledger history needs more than {MAX_HYPERLIQUID_LEDGER_PAGES} pages; "
                "the record is withheld because the ledger is incomplete"
            )

        fills_data = self._execute_bounded_post(
            HYPERLIQUID_INFO_PATH,
            {"type": "userFills", "user": norm_address},
            redact_tokens=redact_list,
        )
        merged_fills: list[Any] = list(_require_list_page(fills_data, "userFills"))

        fill_cursor_ms = scored_start_ms
        if start_bound is not None:
            fill_cursor_ms = max(scored_start_ms, int(start_bound.timestamp() * 1000))
        recent_times = [
            t for t in (_entry_time_ms(f) for f in merged_fills if isinstance(f, Mapping)) if t is not None
        ]

        # `userFills` returns only the most recent fills. Whenever the oldest of them is later
        # than the start of the scored period, whatever their count, older fills are paged with
        # `userFillsByTime`; a record is never built from the most recent fills alone. Paging
        # runs without an end time, so a wallet whose fills reach the service's availability
        # limit is refused whatever window is asked for (`parse_payload` applies the end bound).
        if recent_times and min(recent_times) > fill_cursor_ms:

            def _fill_fp(item: Mapping[str, Any]) -> tuple[str, str, str, str, str, str]:
                return (
                    str(item.get("tid") or ""),
                    str(item.get("oid") or ""),
                    str(item.get("time") or ""),
                    str(item.get("coin") or item.get("symbol") or ""),
                    str(item.get("side") or item.get("dir") or ""),
                    f"{item.get('px')}:{item.get('sz')}",
                )

            seen_fill_keys: set[tuple[str, str, str, str, str, str, int]] = set()
            base_counts: dict[tuple[str, str, str, str, str, str], int] = {}
            paged_fills: list[Any] = []
            # A failed fills page propagates as HyperliquidServiceError.
            for _ in range(MAX_HYPERLIQUID_FILL_PAGES):
                fill_query: dict[str, Any] = {
                    "type": "userFillsByTime",
                    "user": norm_address,
                    "startTime": fill_cursor_ms,
                    "aggregateByTime": False,
                }
                fill_page_raw = self._execute_bounded_post(
                    HYPERLIQUID_INFO_PATH,
                    fill_query,
                    redact_tokens=redact_list,
                )
                fill_page = _require_list_page(fill_page_raw, "userFillsByTime")
                max_fill_ms = fill_cursor_ms
                page_counts: dict[tuple[str, str, str, str, str, str], int] = {}
                new_fills = 0
                for f_entry in fill_page:
                    if not isinstance(f_entry, Mapping):
                        continue
                    t_ms = _entry_time_ms(f_entry)
                    ffp = _fill_fp(f_entry)
                    occ = page_counts.get(ffp, 0)
                    page_counts[ffp] = occ + 1
                    dkey = (*ffp, occ)
                    if dkey not in seen_fill_keys:
                        seen_fill_keys.add(dkey)
                        paged_fills.append(f_entry)
                        new_fills += 1
                    if t_ms is not None and t_ms > max_fill_ms:
                        max_fill_ms = t_ms
                if len(paged_fills) >= HYPERLIQUID_FILLS_BY_TIME_AVAILABLE:
                    raise HyperliquidValidationError(
                        f"Hyperliquid serves only the {HYPERLIQUID_FILLS_BY_TIME_AVAILABLE} most recent fills "
                        "and this wallet's fills since the period start reach that limit; the record is "
                        "withheld because older fills are unreachable"
                    )
                if _page_cannot_be_paged(fill_page, fill_cursor_ms, new_fills) or (
                    new_fills == 0 and _page_repeats_a_cut_block(fill_page, fill_cursor_ms)
                ):
                    raise HyperliquidValidationError(
                        "Hyperliquid fill history could not be paged past fills sharing one timestamp; "
                        "the record is withheld because the fills are incomplete"
                    )
                if new_fills == 0:
                    break
                fill_cursor_ms = max_fill_ms if max_fill_ms > fill_cursor_ms else fill_cursor_ms + 1
            else:
                raise HyperliquidValidationError(
                    f"Hyperliquid fill history needs more than {MAX_HYPERLIQUID_FILL_PAGES} pages; "
                    "the record is withheld because the fills are incomplete"
                )

            if not paged_fills:
                raise HyperliquidValidationError(
                    "Hyperliquid returned recent fills but no earlier fills could be paged; "
                    "the record is withheld because the fills are incomplete"
                )
            for f_entry in merged_fills:
                if isinstance(f_entry, Mapping):
                    ffp = _fill_fp(f_entry)
                    occ = base_counts.get(ffp, 0)
                    base_counts[ffp] = occ + 1
                    dkey = (*ffp, occ)
                    if dkey not in seen_fill_keys:
                        seen_fill_keys.add(dkey)
                        paged_fills.append(f_entry)
            merged_fills = paged_fills

        return self.parse_payload(
            {
                "portfolio": portfolio_data,
                "ledger_updates": ledger_updates_data,
                "fills": merged_fills,
            },
            wallet_address=norm_address,
            blinding_salt_hex=blinding_salt_hex,
            start_date=start_date,
            end_date=end_date,
            require_live=require_live,
            as_of_utc=as_of_utc,
        )


__all__ = [
    "DEFAULT_HYPERLIQUID_TIMEOUT_SECONDS",
    "DEFAULT_HYPERLIQUID_USER_AGENT",
    "HYPERLIQUID_ALLOWED_INFO_TYPES",
    "HYPERLIQUID_BLOCKED_ENDPOINTS",
    "HYPERLIQUID_INFO_PATH",
    "HYPERLIQUID_LIVE_BASE_URL",
    "HyperliquidError",
    "HyperliquidPublicReadOnlyAdapter",
    "HyperliquidServiceError",
    "HyperliquidValidationError",
    "MAX_HYPERLIQUID_RESPONSE_BYTES",
    "MAX_HYPERLIQUID_TIMEOUT_SECONDS",
    "validate_hyperliquid_wallet_address",
]
