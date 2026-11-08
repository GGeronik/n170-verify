"""Fail-closed MCP Streamable HTTP (2025-11-25) & stdio allowlist firewall.

Inspects JSON-RPC 2.0 payloads over ``HTTP POST`` and ``stdio`` transports rather
than naively blocking ``HTTP POST`` at the transport layer (since legitimate MCP
Streamable HTTP ``2025-11-25`` uses ``POST`` for ``initialize``, ``tools/list``,
``tools/call``, and ``resources/read``).

Security invariants:
1. Default-deny server identity pinning (only reviewed MIT profiles are permitted;
   community CCXT MCP servers ``pcriadoperez/ccxt-mcp``, ``lazy-dinosaur/ccxt-mcp``,
   and ``doggybee/mcp-server-ccxt`` are hard-blocked).
2. Explicit blocklist + default-deny allowlist on ``tools/list`` and ``tools/call``:
   - Strips/blocks all 18 mutating tools in ``alpacahq/alpaca-mcp-server`` without
     relying on ``ALPACA_TOOLSETS``.
   - Strips/blocks all 10 mutating tools in ``trading212-mcp-server`` (including
     state-mutating ``request_csv_export``) and forbids persistent
     ``TRADING212_CACHE_DIR`` disk writes.
3. Strict per-tool JSON Schema validation (``additionalProperties: false``),
   bounded ``limit`` and ISO date ranges, zero credential/secret acceptance in
   tool arguments, zero filesystem path acceptance, and secret-redacted errors.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
import json
import re
import subprocess
from typing import Any
import urllib.error
import urllib.request

from n170_verify.contracts import ReadOnlyCapabilityViolationError


MCP_PROTOCOL_VERSION = "2025-11-25"
COMPATIBLE_MCP_PROTOCOL_VERSIONS: frozenset[str] = frozenset(
    {
        "2025-11-25",
        "2025-06-18",
        "2025-03-26",
        "2024-11-05",
    }
)

ALLOWED_JSONRPC_METHODS: frozenset[str] = frozenset(
    {
        "initialize",
        "notifications/initialized",
        "ping",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/read",
    }
)

ALPACA_BLOCKED_MUTATING_TOOLS: frozenset[str] = frozenset(
    {
        "update_account_config",
        "place_stock_order",
        "place_crypto_order",
        "place_option_order",
        "exercise_options_position",
        "cancel_order_by_id",
        "cancel_all_orders",
        "close_position",
        "close_all_positions",
        "create_watchlist",
        "update_watchlist_by_id",
        "update_watchlist_by_name",
        "add_asset_to_watchlist_by_id",
        "add_asset_to_watchlist_by_name",
        "remove_asset_from_watchlist_by_id",
        "remove_asset_from_watchlist_by_name",
        "delete_watchlist_by_id",
        "delete_watchlist_by_name",
    }
)

TRADING212_BLOCKED_MUTATING_TOOLS: frozenset[str] = frozenset(
    {
        "place_market_order",
        "place_limit_order",
        "place_stop_order",
        "place_stop_limit_order",
        "cancel_order",
        "create_pie",
        "update_pie",
        "delete_pie",
        "duplicate_pie",
        "request_csv_export",
    }
)

REJECTED_MCP_SERVERS: dict[str, str] = {
    "pcriadoperez/ccxt-mcp": (
        "Rejected by N170 Verify policy: unverified upstream license; route crypto "
        "exclusively through vault-bound n170_verify.connectors.ccxt_crypto."
    ),
    "lazy-dinosaur/ccxt-mcp": (
        "Rejected by N170 Verify policy: lacks programmatic read-only API key scope "
        "introspection; route crypto exclusively through vault-bound ccxt_crypto."
    ),
    "doggybee/mcp-server-ccxt": (
        "Rejected by N170 Verify policy: passes raw apiKey/secret in MCP tool arguments, "
        "exposing exchange secrets to LLM transcripts; use vault-bound ccxt_crypto."
    ),
    "ccxt-mcp": (
        "Rejected by N170 Verify policy: community CCXT MCP servers are disallowed; "
        "route crypto exclusively through vault-bound ccxt_crypto."
    ),
    "mcp-server-ccxt": (
        "Rejected by N170 Verify policy: community CCXT MCP servers are disallowed; "
        "route crypto exclusively through vault-bound ccxt_crypto."
    ),
}

_FORBIDDEN_ARGUMENT_KEYS: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "secret",
        "api_secret",
        "secret_key",
        "passphrase",
        "password",
        "token",
        "access_token",
        "refresh_token",
        "client_secret",
        "client_assertion",
        "live_session_token",
        "oauth_token",
        "oauth_signature",
        "bearer",
        "authorization",
        "cookie",
        "cookies",
        "session_cookie",
        "session_id",
        "private_key",
        "totp",
        "totp_secret",
        "mfa_code",
        "file",
        "filepath",
        "file_path",
        "path",
        "cache_dir",
        "trading212_cache_dir",
        "output_dir",
        "export_path",
        "base_url",
        "endpoint",
        "url",
    }
)

_SENSITIVE_QUERY_RE = re.compile(
    r"([?&](?:t|q|token|api_token|eodhd_api_key|access_token|refresh_token|api_key|apikey|"
    r"api_secret|client_secret|flex_token|secret|signature|passphrase|session|cookie|"
    r"client_assertion|oauth_token|oauth_signature)=)([^&#\s'\"]*)",
    re.IGNORECASE,
)
_KEY_VALUE_SECRET_RE = re.compile(
    r"((?:['\"]?(?:api_token|eodhd_api_key|access_token|refresh_token|client_secret|"
    r"api_key|apikey|api_secret|secret_key|flex_token|live_session_token|live_session_token_b64|"
    r"client_assertion|client_assertion_jwt|oauth_token|oauth_signature|passphrase|password)"
    r"['\"]?\s*[:=]\s*['\"]?))([^'\"\s,;}{)\]]+)",
    re.IGNORECASE,
)
_TRADIER_OR_GENERIC_ACCOUNTS_RE = re.compile(
    r"(/(?:trader/)?v\d+/accounts/|(?<!/portfolio)/accounts/)([^/?#\s'\"]+)",
    re.IGNORECASE,
)
_IBKR_PORTFOLIO_ACCT_RE = re.compile(
    r"(/portfolio/)([^/?#\s'\"]+)(?=/|$)",
    re.IGNORECASE,
)
_AUTH_HEADER_VALUE_RE = re.compile(
    r"\b((?:authorization|proxy-authorization)\s*:\s*(?:bearer|basic)\s+)([^\s,;'\"]+)",
    re.IGNORECASE,
)
_AUTH_OAUTH_HEADER_RE = re.compile(
    r"\b((?:authorization|proxy-authorization)\s*:\s*oauth\s+)(?:[A-Za-z0-9_.-]+\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;'\"]+)(?:\s*,\s*)?)+",
    re.IGNORECASE,
)
_AUTH_BARE_SCHEME_RE = re.compile(
    r"\b((?:bearer|basic)\s+)([A-Za-z0-9._~+/=-]{8,})",
    re.IGNORECASE,
)
_NAMED_SECRET_HEADER_RE = re.compile(
    r"\b((?:apca-api-key-id|apca-api-secret-key|x-mbx-apikey|cb-access-key|"
    r"cb-access-sign|cb-access-passphrase|x-bapi-api-key|x-bapi-sign|"
    r"x-api-key|api-key|api-sign)\s*:\s*)([^\s,;'\"]+)",
    re.IGNORECASE,
)
_COOKIE_HEADER_RE = re.compile(
    r"\b((?:cookie|set-cookie)\s*:\s*)(?:[^\s;,'\"]+=[^\s;,'\"]+(?:;\s*)?)+|\b((?:cookie|set-cookie)\s*:\s*)([^\s,;'\"]+)",
    re.IGNORECASE,
)
_ALLOWED_STATIC_ACCOUNT_SEGMENTS: frozenset[str] = frozenset(
    {
        "accountnumbers",
        "subaccounts",
        "subaccounts2",
        "summary",
        "accounts",
        "[redacted]",
        "<redacted>",
        "redacted",
        "***",
        "*",
    }
)
_PATH_TRAVERSAL_OR_FS_RE = re.compile(
    r"(?:^file://|^\.\./|/\.\./|^[A-Za-z]:\\|^~[/\\]|^/(?:etc|var|tmp|opt|private|proc|sys|root|Users|home)(?:/|$))"
)
_MAX_DATE_RANGE_DAYS = 3_660  # ~10 years maximum bounded query window


class McpFirewallError(ReadOnlyCapabilityViolationError):
    """Base fail-closed exception raised by the N170 Verify MCP allowlist firewall."""


class DisallowedMcpServerError(McpFirewallError):
    """Raised when an unapproved, mutating, or credential-leaking MCP server is requested."""


class McpServerIdentityError(McpFirewallError):
    """Raised when an MCP server's initialize response fails pinned identity verification."""


class McpToolDisallowedError(McpFirewallError):
    """Raised when a mutating or non-allowlisted MCP tool is invoked."""


class McpArgumentValidationError(McpFirewallError):
    """Raised when MCP tool arguments fail strict JSON Schema or secret/path checks."""


def redact_sensitive_text(text: str, extra_secrets: Sequence[str] = ()) -> str:
    """Redact tokens, query params, auth headers, and raw account path segments."""
    if not isinstance(text, str) or not text:
        return ""
    sanitized = text

    # Explicit caller-known secrets first (longest first to avoid partial prefix leftovers).
    valid_secrets = sorted(
        {s for s in extra_secrets if isinstance(s, str) and len(s.strip()) >= 4},
        key=len,
        reverse=True,
    )
    for secret in valid_secrets:
        sanitized = sanitized.replace(secret, "[REDACTED]")
        sanitized = sanitized.replace(secret.strip(), "[REDACTED]")

    sanitized = _SENSITIVE_QUERY_RE.sub(r"\1[REDACTED]", sanitized)

    def _replace_kv_secret(match: re.Match[str]) -> str:
        prefix, secret_val = match.group(1), match.group(2)
        lowered_val = secret_val.strip().lower()
        if lowered_val in _ALLOWED_STATIC_ACCOUNT_SEGMENTS or lowered_val.startswith(
            ("[redacted", "<redacted")
        ):
            return match.group(0)
        return f"{prefix}[REDACTED]"

    sanitized = _KEY_VALUE_SECRET_RE.sub(_replace_kv_secret, sanitized)
    sanitized = _AUTH_HEADER_VALUE_RE.sub(r"\1[REDACTED]", sanitized)
    sanitized = _AUTH_OAUTH_HEADER_RE.sub(r"\1[REDACTED]", sanitized)
    sanitized = _NAMED_SECRET_HEADER_RE.sub(r"\1[REDACTED]", sanitized)

    def _replace_cookie_header(match: re.Match[str]) -> str:
        hdr_prefix = match.group(1) or match.group(2)
        return f"{hdr_prefix}[REDACTED]"

    sanitized = _COOKIE_HEADER_RE.sub(_replace_cookie_header, sanitized)

    def _replace_bare_scheme(match: re.Match[str]) -> str:
        prefix, token = match.group(1), match.group(2)
        if token.strip().lower() in _ALLOWED_STATIC_ACCOUNT_SEGMENTS:
            return match.group(0)
        return f"{prefix}[REDACTED]"

    sanitized = _AUTH_BARE_SCHEME_RE.sub(_replace_bare_scheme, sanitized)

    def _replace_acct_seg(match: re.Match[str]) -> str:
        prefix, seg = match.group(1), match.group(2)
        if seg.strip().lower() in _ALLOWED_STATIC_ACCOUNT_SEGMENTS:
            return match.group(0)
        return f"{prefix}[REDACTED]"

    sanitized = _TRADIER_OR_GENERIC_ACCOUNTS_RE.sub(_replace_acct_seg, sanitized)
    sanitized = _IBKR_PORTFOLIO_ACCT_RE.sub(_replace_acct_seg, sanitized)
    return sanitized


def _parse_bounded_iso_date(raw: str, *, field_name: str) -> date:
    cleaned = raw.strip()
    if not cleaned or len(cleaned) > 64:
        raise McpArgumentValidationError(f"{field_name} must be a valid bounded ISO-8601 date")
    if cleaned.endswith(("Z", "z")):
        cleaned = cleaned[:-1] + "+00:00"
    parsed_date: date | None = None
    if len(cleaned) == 10 and cleaned[4] == "-" and cleaned[7] == "-":
        try:
            parsed_date = date.fromisoformat(cleaned)
        except ValueError:
            parsed_date = None
    if parsed_date is None:
        try:
            parsed_date = datetime.fromisoformat(cleaned).date()
        except ValueError as exc:
            raise McpArgumentValidationError(
                f"{field_name} must be an ISO-8601 date or timestamp"
            ) from exc
    if not (1990 <= parsed_date.year <= 2100):
        raise McpArgumentValidationError(
            f"{field_name} year {parsed_date.year} is outside bounded range [1990, 2100]"
        )
    return parsed_date


def _inspect_no_credentials_or_paths(value: Any, *, path_label: str = "arguments") -> None:
    """Recursively reject smuggled credentials, tokens, URLs, or filesystem paths."""
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return
        if _PATH_TRAVERSAL_OR_FS_RE.search(stripped):
            raise McpArgumentValidationError(
                f"Filesystem path or URI disallowed in MCP tool argument {path_label}"
            )
        lowered = stripped.lower()
        if lowered.startswith(("http://", "https://", "ws://", "wss://")):
            raise McpArgumentValidationError(
                f"Arbitrary network URL disallowed in MCP tool argument {path_label}"
            )
        if "private key-----" in lowered or _AUTH_BARE_SCHEME_RE.search(stripped):
            raise McpArgumentValidationError(
                f"Embedded credential material disallowed in MCP tool argument {path_label}"
            )
        if _SENSITIVE_QUERY_RE.search(stripped):
            raise McpArgumentValidationError(
                f"Query credential parameter disallowed in MCP tool argument {path_label}"
            )
        return
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                raise McpArgumentValidationError(f"{path_label} keys must be strings")
            norm_key = re.sub(r"[^a-z0-9]+", "_", raw_key.strip().lower()).strip("_")
            if norm_key in _FORBIDDEN_ARGUMENT_KEYS or raw_key.strip().lower() in _FORBIDDEN_ARGUMENT_KEYS:
                raise McpArgumentValidationError(
                    f"Credential, URL, or filesystem key {raw_key!r} is forbidden in MCP tool arguments"
                )
            _inspect_no_credentials_or_paths(item, path_label=f"{path_label}.{raw_key}")
        return
    if isinstance(value, (list, tuple)):
        if len(value) > 200:
            raise McpArgumentValidationError(f"{path_label} exceeds maximum array length 200")
        for idx, item in enumerate(value):
            _inspect_no_credentials_or_paths(item, path_label=f"{path_label}[{idx}]")
        return
    raise McpArgumentValidationError(
        f"Unsupported MCP argument type at {path_label}: {type(value).__name__}"
    )


def validate_strict_tool_schema(schema: Mapping[str, Any], arguments: Any) -> dict[str, Any]:
    """Validate ``arguments`` against a strict ``additionalProperties: false`` JSON Schema."""
    if schema.get("additionalProperties", True) is not False:
        raise McpFirewallError("Firewall tool schema must enforce additionalProperties: false")

    args = {} if arguments is None else arguments
    if not isinstance(args, Mapping) or isinstance(args, (list, tuple)):
        raise McpArgumentValidationError("Tool arguments must be a JSON object")

    _inspect_no_credentials_or_paths(args, path_label="arguments")

    properties = schema.get("properties", {})
    required = set(schema.get("required", ()))

    unknown_keys = sorted(set(args.keys()) - set(properties.keys()))
    if unknown_keys:
        raise McpArgumentValidationError(
            f"Unexpected argument(s) rejected by additionalProperties=false: {unknown_keys}"
        )

    missing_keys = sorted(required - set(args.keys()))
    if missing_keys:
        raise McpArgumentValidationError(f"Missing required tool argument(s): {missing_keys}")

    parsed_dates: dict[str, date] = {}
    validated: dict[str, Any] = {}

    for key, val in args.items():
        prop_spec = properties[key]
        _validate_property_value(key, val, prop_spec, parsed_dates)
        validated[key] = val

    # Enforce bounded date window when start/after/since and end/until pairs are present.
    start_candidates = [
        parsed_dates[k] for k in ("start", "after", "since", "from") if k in parsed_dates
    ]
    end_candidates = [
        parsed_dates[k] for k in ("end", "until", "to") if k in parsed_dates
    ]
    if start_candidates and end_candidates:
        span_days = (end_candidates[0] - start_candidates[0]).days
        if span_days < 0:
            raise McpArgumentValidationError("Date range end/until must be >= start/after")
        if span_days > _MAX_DATE_RANGE_DAYS:
            raise McpArgumentValidationError(
                f"Date range ({span_days} days) exceeds maximum bounded window ({_MAX_DATE_RANGE_DAYS} days)"
            )

    return validated


def _validate_property_value(
    key: str,
    val: Any,
    spec: Mapping[str, Any],
    parsed_dates: dict[str, date],
) -> None:
    if "anyOf" in spec:
        errors: list[str] = []
        for sub in spec["anyOf"]:
            try:
                _validate_property_value(key, val, sub, parsed_dates)
                return
            except McpArgumentValidationError as exc:
                errors.append(str(exc))
        raise McpArgumentValidationError(f"Invalid {key!r}: {'; '.join(errors)}")

    expected_type = spec.get("type")
    if expected_type == "string":
        if not isinstance(val, str):
            raise McpArgumentValidationError(f"Argument {key!r} must be a string")
        min_len = spec.get("minLength", 1)
        max_len = spec.get("maxLength", 128)
        if not (min_len <= len(val) <= max_len):
            raise McpArgumentValidationError(
                f"Argument {key!r} length must be within [{min_len}, {max_len}]"
            )
        if "enum" in spec and val not in spec["enum"]:
            raise McpArgumentValidationError(
                f"Argument {key!r} must be one of {list(spec['enum'])}"
            )
        if "pattern" in spec and not re.fullmatch(spec["pattern"], val):
            raise McpArgumentValidationError(f"Argument {key!r} violates allowed format pattern")
        if spec.get("format") == "iso_date":
            parsed_dates[key] = _parse_bounded_iso_date(val, field_name=key)
    elif expected_type == "integer":
        if isinstance(val, bool) or not isinstance(val, int):
            raise McpArgumentValidationError(f"Argument {key!r} must be an integer")
        minimum = spec.get("minimum")
        maximum = spec.get("maximum")
        if minimum is not None and val < minimum:
            raise McpArgumentValidationError(f"Argument {key!r} must be >= {minimum}")
        if maximum is not None and val > maximum:
            raise McpArgumentValidationError(f"Argument {key!r} must be <= {maximum}")
    elif expected_type == "number":
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            raise McpArgumentValidationError(f"Argument {key!r} must be a number")
        minimum = spec.get("minimum")
        maximum = spec.get("maximum")
        if minimum is not None and val < minimum:
            raise McpArgumentValidationError(f"Argument {key!r} must be >= {minimum}")
        if maximum is not None and val > maximum:
            raise McpArgumentValidationError(f"Argument {key!r} must be <= {maximum}")
    elif expected_type == "boolean":
        if not isinstance(val, bool):
            raise McpArgumentValidationError(f"Argument {key!r} must be a boolean")
    elif expected_type == "array":
        if not isinstance(val, (list, tuple)) or isinstance(val, (str, bytes)):
            raise McpArgumentValidationError(f"Argument {key!r} must be an array")
        max_items = spec.get("maxItems", 100)
        if len(val) > max_items:
            raise McpArgumentValidationError(f"Argument {key!r} exceeds maxItems={max_items}")
        item_spec = spec.get("items", {"type": "string"})
        for idx, item in enumerate(val):
            _validate_property_value(f"{key}[{idx}]", item, item_spec, parsed_dates)
    else:
        raise McpFirewallError(f"Unsupported schema property type {expected_type!r} for {key!r}")


def _empty_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {},
    }


_SYMBOL_PROP: dict[str, Any] = {
    "type": "string",
    "minLength": 1,
    "maxLength": 32,
    "pattern": r"^[A-Za-z0-9./_-]{1,32}$",
}
_ID_PROP: dict[str, Any] = {
    "type": "string",
    "minLength": 1,
    "maxLength": 64,
    "pattern": r"^[A-Za-z0-9._:-]{1,64}$",
}
_ISO_DATE_PROP: dict[str, Any] = {
    "type": "string",
    "minLength": 10,
    "maxLength": 40,
    "format": "iso_date",
}


ALPACA_ALLOWED_TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "get_account_info": _empty_schema(),
    "get_positions": _empty_schema(),
    "get_open_position": {
        "type": "object",
        "additionalProperties": False,
        "required": ["symbol"],
        "properties": {"symbol": _SYMBOL_PROP},
    },
    "get_orders": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "status": {"type": "string", "enum": ["open", "closed", "all"]},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500},
            "after": _ISO_DATE_PROP,
            "until": _ISO_DATE_PROP,
            "direction": {"type": "string", "enum": ["asc", "desc"]},
            "nested": {"type": "boolean"},
            "symbols": {"type": "array", "maxItems": 50, "items": _SYMBOL_PROP},
        },
    },
    "get_order_by_id": {
        "type": "object",
        "additionalProperties": False,
        "required": ["order_id"],
        "properties": {"order_id": _ID_PROP},
    },
    "get_portfolio_history": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "period": {
                "type": "string",
                "pattern": r"^[0-9]{1,3}(?:D|W|M|A)|all|intraday$",
                "maxLength": 16,
            },
            "timeframe": {
                "type": "string",
                "enum": ["1Min", "5Min", "15Min", "1H", "1D"],
            },
            "start": _ISO_DATE_PROP,
            "end": _ISO_DATE_PROP,
            "intraday_reporting": {
                "type": "string",
                "enum": ["market_hours", "extended_hours", "continuous"],
            },
            "pnl_reset": {"type": "string", "enum": ["per_day", "no_reset"]},
        },
    },
    "get_account_activities": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "activity_types": {
                "anyOf": [
                    {"type": "string", "maxLength": 64, "pattern": r"^[A-Z_,]{1,64}$"},
                    {
                        "type": "array",
                        "maxItems": 30,
                        "items": {"type": "string", "maxLength": 16, "pattern": r"^[A-Z_]{1,16}$"},
                    },
                ]
            },
            "date": _ISO_DATE_PROP,
            "after": _ISO_DATE_PROP,
            "until": _ISO_DATE_PROP,
            "direction": {"type": "string", "enum": ["asc", "desc"]},
            "page_size": {"type": "integer", "minimum": 1, "maximum": 100},
            "page_token": _ID_PROP,
        },
    },
    "get_corporate_announcements": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "ca_types": {
                "type": "array",
                "maxItems": 10,
                "items": {
                    "type": "string",
                    "enum": ["dividend", "merger", "spinoff", "split"],
                },
            },
            "since": _ISO_DATE_PROP,
            "until": _ISO_DATE_PROP,
            "symbol": _SYMBOL_PROP,
        },
    },
    "get_watchlists": _empty_schema(),
    "get_watchlist_by_id": {
        "type": "object",
        "additionalProperties": False,
        "required": ["watchlist_id"],
        "properties": {"watchlist_id": _ID_PROP},
    },
    "get_watchlist_by_name": {
        "type": "object",
        "additionalProperties": False,
        "required": ["name"],
        "properties": {"name": {"type": "string", "minLength": 1, "maxLength": 64}},
    },
    "get_clock": _empty_schema(),
    "get_calendar": {
        "type": "object",
        "additionalProperties": False,
        "properties": {"start": _ISO_DATE_PROP, "end": _ISO_DATE_PROP},
    },
    "get_asset_info": {
        "type": "object",
        "additionalProperties": False,
        "required": ["symbol"],
        "properties": {"symbol": _SYMBOL_PROP},
    },
    "get_all_assets": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "status": {"type": "string", "enum": ["active", "inactive"]},
            "asset_class": {"type": "string", "enum": ["us_equity", "us_option", "crypto"]},
        },
    },
    "get_stock_bars": {
        "type": "object",
        "additionalProperties": False,
        "required": ["symbol_or_symbols"],
        "properties": {
            "symbol_or_symbols": {
                "anyOf": [
                    _SYMBOL_PROP,
                    {"type": "array", "maxItems": 50, "items": _SYMBOL_PROP},
                ]
            },
            "timeframe": {"type": "string", "maxLength": 16, "pattern": r"^[0-9A-Za-z]{1,16}$"},
            "start": _ISO_DATE_PROP,
            "end": _ISO_DATE_PROP,
            "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
        },
    },
    "get_stock_latest_quote": {
        "type": "object",
        "additionalProperties": False,
        "required": ["symbol_or_symbols"],
        "properties": {
            "symbol_or_symbols": {
                "anyOf": [
                    _SYMBOL_PROP,
                    {"type": "array", "maxItems": 50, "items": _SYMBOL_PROP},
                ]
            }
        },
    },
    "get_crypto_bars": {
        "type": "object",
        "additionalProperties": False,
        "required": ["symbol_or_symbols"],
        "properties": {
            "symbol_or_symbols": {
                "anyOf": [
                    _SYMBOL_PROP,
                    {"type": "array", "maxItems": 50, "items": _SYMBOL_PROP},
                ]
            },
            "timeframe": {"type": "string", "maxLength": 16, "pattern": r"^[0-9A-Za-z]{1,16}$"},
            "start": _ISO_DATE_PROP,
            "end": _ISO_DATE_PROP,
            "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
        },
    },
}


TRADING212_ALLOWED_TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "get_account_cash": _empty_schema(),
    "get_account_metadata": _empty_schema(),
    "get_account_summary": _empty_schema(),
    "get_open_positions": {
        "type": "object",
        "additionalProperties": False,
        "properties": {"ticker": _SYMBOL_PROP},
    },
    "get_position": {
        "type": "object",
        "additionalProperties": False,
        "required": ["ticker"],
        "properties": {"ticker": _SYMBOL_PROP},
    },
    "get_historical_orders": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "cursor": {"anyOf": [{"type": "integer", "minimum": 0}, _ID_PROP]},
            "ticker": _SYMBOL_PROP,
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
        },
    },
    "get_dividends": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "cursor": {"anyOf": [{"type": "integer", "minimum": 0}, _ID_PROP]},
            "ticker": _SYMBOL_PROP,
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
        },
    },
    "get_transactions": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "cursor": _ID_PROP,
            "time": _ISO_DATE_PROP,
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
        },
    },
    "get_exports": _empty_schema(),
    "get_pies": _empty_schema(),
    "get_pie": {
        "type": "object",
        "additionalProperties": False,
        "required": ["pie_id"],
        "properties": {
            "pie_id": {"anyOf": [{"type": "integer", "minimum": 1}, _ID_PROP]},
        },
    },
    "get_instruments": _empty_schema(),
    "get_exchanges": _empty_schema(),
}


@dataclass(frozen=True, slots=True)
class McpServerFirewallProfile:
    """Immutable allowlist/blocklist security profile for a pinned upstream MCP server."""

    profile_id: str
    canonical_repo: str
    spdx_license: str
    pinned_server_names: frozenset[str]
    allowed_tool_schemas: Mapping[str, dict[str, Any]]
    blocked_mutating_tools: frozenset[str]
    allowed_resource_uri_prefixes: tuple[str, ...] = ()
    forbidden_env_keys: frozenset[str] = frozenset()
    ignored_untrusted_env_keys: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        overlap = set(self.allowed_tool_schemas.keys()) & set(self.blocked_mutating_tools)
        if overlap:
            raise ValueError(
                f"Profile {self.profile_id!r} cannot allow blocked mutating tools: {sorted(overlap)}"
            )


ALPACA_MCP_PROFILE = McpServerFirewallProfile(
    profile_id="alpaca",
    canonical_repo="alpacahq/alpaca-mcp-server",
    spdx_license="MIT",
    pinned_server_names=frozenset(
        {
            "alpaca-mcp-server",
            "alpacahq/alpaca-mcp-server",
            "alpaca",
        }
    ),
    allowed_tool_schemas=ALPACA_ALLOWED_TOOL_SCHEMAS,
    blocked_mutating_tools=ALPACA_BLOCKED_MUTATING_TOOLS,
    allowed_resource_uri_prefixes=("alpaca://",),
    ignored_untrusted_env_keys=frozenset({"ALPACA_TOOLSETS"}),
)

TRADING212_MCP_PROFILE = McpServerFirewallProfile(
    profile_id="trading212",
    canonical_repo="trading212-mcp-server",
    spdx_license="MIT",
    pinned_server_names=frozenset(
        {
            "trading212-mcp-server",
            "trading212/trading212-mcp-server",
            "trading212",
        }
    ),
    allowed_tool_schemas=TRADING212_ALLOWED_TOOL_SCHEMAS,
    blocked_mutating_tools=TRADING212_BLOCKED_MUTATING_TOOLS,
    allowed_resource_uri_prefixes=("trading212://",),
    forbidden_env_keys=frozenset({"TRADING212_CACHE_DIR"}),
)

PINNED_MCP_PROFILES: dict[str, McpServerFirewallProfile] = {
    "alpaca": ALPACA_MCP_PROFILE,
    "alpaca-mcp-server": ALPACA_MCP_PROFILE,
    "alpacahq/alpaca-mcp-server": ALPACA_MCP_PROFILE,
    "trading212": TRADING212_MCP_PROFILE,
    "trading212-mcp-server": TRADING212_MCP_PROFILE,
    "trading212/trading212-mcp-server": TRADING212_MCP_PROFILE,
}


def resolve_mcp_firewall_profile(server_id: str) -> McpServerFirewallProfile:
    """Resolve a pinned MCP firewall profile or fail closed for unapproved/CCXT servers."""
    if not isinstance(server_id, str) or not server_id.strip():
        raise DisallowedMcpServerError("MCP server identifier must be a non-empty string")
    normalized = server_id.strip().lower()
    if normalized in REJECTED_MCP_SERVERS:
        raise DisallowedMcpServerError(REJECTED_MCP_SERVERS[normalized])
    if "ccxt" in normalized:
        raise DisallowedMcpServerError(
            f"MCP server {server_id!r} rejected: crypto venues must route exclusively through "
            "vault-bound n170_verify.connectors.ccxt_crypto with API key scope introspection."
        )
    profile = PINNED_MCP_PROFILES.get(normalized)
    if profile is None:
        raise DisallowedMcpServerError(
            f"Unrecognized MCP server {server_id!r}: fail-closed policy permits only pinned MIT profiles."
        )
    return profile


@dataclass(slots=True)
class McpAllowlistFirewall:
    """Stateful JSON-RPC 2.0 firewall enforcing pinned identity, tool allowlists, and env safety."""

    profile: McpServerFirewallProfile
    require_live_environment: bool = True
    extra_secrets: tuple[str, ...] = ()
    _initialized_server_name: str | None = field(default=None, init=False, repr=False)

    @classmethod
    def for_server(
        cls,
        server_id: str,
        *,
        require_live_environment: bool = True,
        extra_secrets: Sequence[str] = (),
    ) -> McpAllowlistFirewall:
        profile = resolve_mcp_firewall_profile(server_id)
        return cls(
            profile=profile,
            require_live_environment=require_live_environment,
            extra_secrets=tuple(extra_secrets),
        )

    def validate_and_sanitize_env(self, env: Mapping[str, str]) -> dict[str, str]:
        """Validate launch environment variables and strip untrusted toolset/cache overrides."""
        if not isinstance(env, Mapping):
            raise McpFirewallError("MCP launch environment must be a mapping")

        sanitized: dict[str, str] = {}
        for key, val in env.items():
            if not isinstance(key, str) or not isinstance(val, str):
                raise McpFirewallError("Environment keys and values must be strings")

            if key in self.profile.forbidden_env_keys and val.strip():
                raise McpFirewallError(
                    f"Environment variable {key!r} is forbidden by profile "
                    f"{self.profile.profile_id!r} (persistent disk cache writes disallowed)"
                )
            if key in self.profile.ignored_untrusted_env_keys:
                # Never rely on ALPACA_TOOLSETS; strip and enforce firewall-level schema allowlist.
                continue

            if self.require_live_environment:
                upper_k = key.strip().upper()
                lower_v = val.strip().lower()
                if upper_k == "ALPACA_PAPER_TRADE" and lower_v in {"true", "1", "yes"}:
                    raise McpFirewallError(
                        "ALPACA_PAPER_TRADE=true is rejected when live production provenance is required"
                    )
                if upper_k in {"APCA_API_BASE_URL", "ALPACA_BASE_URL", "ALPACA_API_BASE_URL"}:
                    if "paper-api.alpaca.markets" in lower_v or "sandbox" in lower_v:
                        raise McpFirewallError(
                            "Paper/sandbox Alpaca API URL rejected by MCP firewall"
                        )
                if upper_k in {"TRADING212_ENVIRONMENT", "T212_ENV"} and lower_v in {
                    "demo",
                    "paper",
                    "sandbox",
                }:
                    raise McpFirewallError(
                        "Trading 212 demo/paper environment rejected by MCP firewall"
                    )
                if "demo.trading212.com" in lower_v:
                    raise McpFirewallError("demo.trading212.com rejected by MCP firewall")

            sanitized[key] = val

        if self.profile.profile_id == "trading212":
            sanitized["TRADING212_CACHE_ENABLED"] = "false"
        return sanitized

    def inspect_outgoing_request(
        self,
        payload: Mapping[str, Any] | bytes | str,
        *,
        transport: str = "streamable_http",
        http_method: str = "POST",
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        """Validate an outbound MCP JSON-RPC message over Streamable HTTP POST or stdio."""
        if transport not in {"streamable_http", "stdio"}:
            raise McpFirewallError(f"Unsupported MCP transport {transport!r}")

        if transport == "streamable_http":
            method_upper = http_method.strip().upper()
            if method_upper != "POST":
                raise McpFirewallError(
                    f"MCP Streamable HTTP (2025-11-25) firewall permits only JSON-RPC HTTP POST; "
                    f"blocked HTTP {method_upper}"
                )
            if headers is not None:
                lower_headers = {k.strip().lower(): v.strip() for k, v in headers.items()}
                proto_ver = lower_headers.get("mcp-protocol-version")
                if proto_ver is not None and proto_ver not in COMPATIBLE_MCP_PROTOCOL_VERSIONS:
                    raise McpFirewallError(
                        f"Unsupported MCP-Protocol-Version header: {proto_ver!r}"
                    )

        parsed = self._decode_jsonrpc_object(payload)
        if parsed.get("jsonrpc") != "2.0":
            raise McpFirewallError("MCP payload must be a JSON-RPC 2.0 object")

        rpc_method = parsed.get("method")
        if not isinstance(rpc_method, str) or rpc_method not in ALLOWED_JSONRPC_METHODS:
            raise McpFirewallError(
                f"JSON-RPC method {rpc_method!r} is disallowed by fail-closed MCP firewall"
            )

        params = parsed.get("params")
        if params is not None and not isinstance(params, Mapping):
            raise McpFirewallError("JSON-RPC params must be an object when present")

        if rpc_method == "initialize":
            req_proto = (params or {}).get("protocolVersion", MCP_PROTOCOL_VERSION)
            if req_proto not in COMPATIBLE_MCP_PROTOCOL_VERSIONS:
                raise McpFirewallError(f"Unsupported MCP initialize protocolVersion {req_proto!r}")
        elif rpc_method in {"notifications/initialized", "ping", "tools/list", "resources/list"}:
            if params:
                _inspect_no_credentials_or_paths(params, path_label="params")
        elif rpc_method == "tools/call":
            if not isinstance(params, Mapping):
                raise McpArgumentValidationError("tools/call requires params object")
            tool_name = params.get("name")
            if not isinstance(tool_name, str) or not tool_name.strip():
                raise McpArgumentValidationError("tools/call requires non-empty tool name")
            normalized_tool = tool_name.strip()
            self._assert_tool_allowed(normalized_tool)
            schema = self.profile.allowed_tool_schemas[normalized_tool]
            validated_args = validate_strict_tool_schema(schema, params.get("arguments"))
            updated = dict(parsed)
            updated["params"] = {"name": normalized_tool, "arguments": validated_args}
            return updated
        elif rpc_method == "resources/read":
            if not isinstance(params, Mapping):
                raise McpArgumentValidationError("resources/read requires params object")
            uri = params.get("uri")
            if not isinstance(uri, str) or not uri.strip():
                raise McpArgumentValidationError("resources/read requires non-empty uri")
            cleaned_uri = uri.strip()
            if _PATH_TRAVERSAL_OR_FS_RE.search(cleaned_uri) or ".." in cleaned_uri:
                raise McpArgumentValidationError(
                    "Filesystem or traversal URI blocked in resources/read"
                )
            if not any(
                cleaned_uri.startswith(prefix)
                for prefix in self.profile.allowed_resource_uri_prefixes
            ):
                raise McpArgumentValidationError(
                    f"Resource URI {redact_sensitive_text(cleaned_uri, self.extra_secrets)!r} is "
                    f"not allowlisted for profile {self.profile.profile_id!r}"
                )

        return dict(parsed)

    def _assert_tool_allowed(self, tool_name: str) -> None:
        if tool_name in self.profile.blocked_mutating_tools:
            raise McpToolDisallowedError(
                f"Mutating MCP tool {tool_name!r} is explicitly blocked on profile "
                f"{self.profile.profile_id!r}"
            )
        if tool_name not in self.profile.allowed_tool_schemas:
            raise McpToolDisallowedError(
                f"Unlisted MCP tool {tool_name!r} is denied by default-deny allowlist on profile "
                f"{self.profile.profile_id!r}"
            )

    def inspect_incoming_response(
        self,
        rpc_method: str,
        response: Mapping[str, Any] | bytes | str,
    ) -> dict[str, Any]:
        """Inspect and sanitize an upstream MCP JSON-RPC response (`initialize`, `tools/list`, etc.)."""
        parsed = self._decode_jsonrpc_object(response)
        if "error" in parsed and parsed["error"] is not None:
            err_obj = parsed["error"]
            if isinstance(err_obj, Mapping):
                redacted_err = dict(err_obj)
                if isinstance(redacted_err.get("message"), str):
                    redacted_err["message"] = redact_sensitive_text(
                        redacted_err["message"], self.extra_secrets
                    )
                if "data" in redacted_err:
                    redacted_err["data"] = redact_sensitive_text(
                        json.dumps(redacted_err["data"]), self.extra_secrets
                    )
                parsed = dict(parsed)
                parsed["error"] = redacted_err
            return dict(parsed)

        result = parsed.get("result")
        if rpc_method == "initialize":
            if not isinstance(result, Mapping):
                raise McpServerIdentityError("MCP initialize response missing result object")
            server_info = result.get("serverInfo")
            if not isinstance(server_info, Mapping):
                raise McpServerIdentityError("MCP initialize response missing serverInfo")
            srv_name = str(server_info.get("name", "")).strip().lower()
            if srv_name not in self.profile.pinned_server_names:
                raise McpServerIdentityError(
                    f"Upstream MCP serverInfo.name {srv_name!r} does not match pinned identity "
                    f"{sorted(self.profile.pinned_server_names)} for profile {self.profile.profile_id!r}"
                )
            self._initialized_server_name = srv_name
            return dict(parsed)

        if rpc_method == "tools/list":
            if not isinstance(result, Mapping):
                raise McpFirewallError("MCP tools/list response missing result object")
            raw_tools = result.get("tools", [])
            if not isinstance(raw_tools, list):
                raise McpFirewallError("MCP tools/list result.tools must be a list")
            filtered_tools: list[dict[str, Any]] = []
            for entry in raw_tools:
                if not isinstance(entry, Mapping):
                    continue
                name = str(entry.get("name", "")).strip()
                if name in self.profile.blocked_mutating_tools:
                    continue
                if name not in self.profile.allowed_tool_schemas:
                    continue
                sanitized_tool = dict(entry)
                sanitized_tool["inputSchema"] = self.profile.allowed_tool_schemas[name]
                sanitized_tool["annotations"] = {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "openWorldHint": False,
                }
                filtered_tools.append(sanitized_tool)
            updated = dict(parsed)
            updated_result = dict(result)
            updated_result["tools"] = filtered_tools
            updated["result"] = updated_result
            return updated

        return dict(parsed)

    def _decode_jsonrpc_object(self, raw: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
        if isinstance(raw, Mapping):
            return dict(raw)
        try:
            if isinstance(raw, bytes):
                text = raw.decode("utf-8")
            elif isinstance(raw, str):
                text = raw
            else:
                raise McpFirewallError(f"Unsupported JSON-RPC payload type: {type(raw).__name__}")
            decoded = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise McpFirewallError(
                f"Invalid JSON-RPC payload: {redact_sensitive_text(str(exc), self.extra_secrets)}"
            ) from exc
        if isinstance(decoded, list):
            raise McpFirewallError(
                "JSON-RPC batch arrays are disallowed by fail-closed MCP firewall"
            )
        if not isinstance(decoded, Mapping):
            raise McpFirewallError("JSON-RPC payload must decode to a JSON object")
        return dict(decoded)


HttpPostTransportFn = Callable[
    [str, str, bytes, Mapping[str, str]],
    tuple[int, Mapping[str, str], bytes],
]


def _default_urllib_post_transport(
    method: str,
    url: str,
    body: bytes,
    headers: Mapping[str, str],
) -> tuple[int, Mapping[str, str], bytes]:
    req = urllib.request.Request(url=url, data=body, headers=dict(headers), method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return int(resp.status), resp_headers, resp.read()
    except urllib.error.HTTPError as exc:
        err_body = exc.read() if exc.fp is not None else b""
        resp_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return int(exc.code), resp_headers, err_body


def _decode_streamable_http_body(raw_body: bytes, content_type: str) -> dict[str, Any]:
    """Decode either `application/json` or `text/event-stream` (`data:` SSE) MCP response."""
    text = raw_body.decode("utf-8")
    if "text/event-stream" in content_type.lower():
        data_lines: list[str] = []
        last_json: dict[str, Any] | None = None
        for line in text.splitlines():
            if line.startswith("data:"):
                data_lines.append(line[5:].strip())
            elif not line.strip() and data_lines:
                joined = "\n".join(data_lines)
                data_lines.clear()
                candidate = json.loads(joined)
                if isinstance(candidate, dict):
                    last_json = candidate
        if data_lines:
            candidate = json.loads("\n".join(data_lines))
            if isinstance(candidate, dict):
                last_json = candidate
        if last_json is None:
            raise McpFirewallError("Empty text/event-stream response from MCP server")
        return last_json
    decoded = json.loads(text)
    if not isinstance(decoded, dict):
        raise McpFirewallError("MCP HTTP response body must be a JSON object")
    return decoded


class StreamableHttpMcpFirewallClient:
    """MCP Streamable HTTP (`2025-11-25`) client guarded by `McpAllowlistFirewall`."""

    def __init__(
        self,
        *,
        server_id: str,
        endpoint_url: str,
        firewall: McpAllowlistFirewall | None = None,
        auth_headers: Mapping[str, str] | None = None,
        http_transport: HttpPostTransportFn | Any | None = None,
        extra_secrets: Sequence[str] = (),
    ) -> None:
        if not endpoint_url.startswith("https://"):
            raise McpFirewallError("Streamable HTTP MCP endpoint must use https://")
        lower_url = endpoint_url.lower()
        if "paper-api.alpaca.markets" in lower_url or "demo.trading212.com" in lower_url:
            raise McpFirewallError("Paper/demo MCP endpoint URLs are rejected")

        secrets_list = list(extra_secrets)
        if auth_headers:
            secrets_list.extend(v for v in auth_headers.values() if isinstance(v, str))

        self.firewall = firewall or McpAllowlistFirewall.for_server(
            server_id,
            extra_secrets=secrets_list,
        )
        self._endpoint_url = endpoint_url
        self._auth_headers = dict(auth_headers or {})
        self._transport = http_transport or _default_urllib_post_transport
        self._session_id: str | None = None
        self._next_id = 1
        self._secrets = tuple(secrets_list)

    def send_jsonrpc(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        *,
        is_notification: bool = False,
        http_method: str = "POST",
    ) -> dict[str, Any] | None:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if not is_notification:
            msg["id"] = self._next_id
            self._next_id += 1
        if params is not None:
            msg["params"] = dict(params)

        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        headers.update(self._auth_headers)

        checked_msg = self.firewall.inspect_outgoing_request(
            msg,
            transport="streamable_http",
            http_method=http_method,
            headers=headers,
        )
        encoded = json.dumps(checked_msg, separators=(",", ":"), allow_nan=False).encode("utf-8")

        try:
            status, resp_headers, resp_body = self._invoke_transport(
                http_method, self._endpoint_url, encoded, headers
            )
        except Exception as exc:
            if isinstance(exc, McpFirewallError):
                raise
            raise McpFirewallError(
                f"MCP transport failed: {redact_sensitive_text(str(exc), self._secrets)}"
            ) from None

        lower_resp_headers = {k.lower(): v for k, v in resp_headers.items()}
        if "mcp-session-id" in lower_resp_headers:
            self._session_id = lower_resp_headers["mcp-session-id"]

        if status == 202 or (is_notification and not resp_body.strip()):
            return None
        if status < 200 or status >= 300:
            snippet = redact_sensitive_text(
                resp_body.decode("utf-8", errors="replace")[:256], self._secrets
            )
            raise McpFirewallError(f"MCP server returned HTTP {status}: {snippet}")

        ctype = lower_resp_headers.get("content-type", "application/json")
        decoded = _decode_streamable_http_body(resp_body, ctype)
        return self.firewall.inspect_incoming_response(method, decoded)

    def _invoke_transport(
        self,
        method: str,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
    ) -> tuple[int, Mapping[str, str], bytes]:
        if hasattr(self._transport, "request") and callable(self._transport.request):
            resp = self._transport.request(method, url, content=body, headers=dict(headers))
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return int(resp.status_code), resp_headers, bytes(resp.content)
        return self._transport(method, url, body, headers)

    def initialize(self) -> dict[str, Any]:
        init_resp = self.send_jsonrpc(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "n170-verify-firewall", "version": "0.3.0"},
            },
        )
        self.send_jsonrpc("notifications/initialized", is_notification=True)
        assert init_resp is not None
        return init_resp

    def list_tools(self) -> list[dict[str, Any]]:
        resp = self.send_jsonrpc("tools/list", {})
        assert resp is not None
        return list(resp.get("result", {}).get("tools", []))

    def call_tool(self, name: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        resp = self.send_jsonrpc(
            "tools/call",
            {"name": name, "arguments": dict(arguments or {})},
        )
        assert resp is not None
        return resp


class StdioMcpFirewallClient:
    """Stdio newline-delimited JSON-RPC MCP client guarded by `McpAllowlistFirewall`."""

    def __init__(
        self,
        *,
        server_id: str,
        command: Sequence[str] | None = None,
        env: Mapping[str, str] | None = None,
        line_exchange: Callable[[str], str] | None = None,
        firewall: McpAllowlistFirewall | None = None,
        extra_secrets: Sequence[str] = (),
    ) -> None:
        secrets_list = list(extra_secrets)
        if env:
            secrets_list.extend(v for v in env.values() if isinstance(v, str) and len(v) >= 6)

        self.firewall = firewall or McpAllowlistFirewall.for_server(
            server_id,
            extra_secrets=secrets_list,
        )
        self.sanitized_env = self.firewall.validate_and_sanitize_env(env or {})
        self._command = list(command) if command is not None else None
        self._line_exchange = line_exchange
        self._proc: subprocess.Popen[str] | None = None
        self._next_id = 1
        self._secrets = tuple(secrets_list)

    def start(self) -> None:
        if self._line_exchange is not None or self._proc is not None:
            return
        if not self._command:
            raise McpFirewallError("StdioMcpFirewallClient requires command or line_exchange")
        self._proc = subprocess.Popen(
            self._command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=self.sanitized_env,
        )

    def close(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            self._proc.wait(timeout=5)
            self._proc = None

    def send_jsonrpc(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        *,
        is_notification: bool = False,
    ) -> dict[str, Any] | None:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if not is_notification:
            msg["id"] = self._next_id
            self._next_id += 1
        if params is not None:
            msg["params"] = dict(params)

        checked_msg = self.firewall.inspect_outgoing_request(msg, transport="stdio")
        serialized = json.dumps(checked_msg, separators=(",", ":"), allow_nan=False)

        if self._line_exchange is not None:
            raw_reply = self._line_exchange(serialized)
            if is_notification and not raw_reply.strip():
                return None
            return self.firewall.inspect_incoming_response(method, raw_reply)

        self.start()
        assert self._proc is not None and self._proc.stdin is not None and self._proc.stdout is not None
        self._proc.stdin.write(serialized + "\n")
        self._proc.stdin.flush()
        if is_notification:
            return None
        reply_line = self._proc.stdout.readline()
        if not reply_line:
            raise McpFirewallError("Upstream stdio MCP server closed stdout unexpectedly")
        return self.firewall.inspect_incoming_response(method, reply_line)

    def initialize(self) -> dict[str, Any]:
        resp = self.send_jsonrpc(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "n170-verify-firewall", "version": "0.3.0"},
            },
        )
        self.send_jsonrpc("notifications/initialized", is_notification=True)
        assert resp is not None
        return resp

    def list_tools(self) -> list[dict[str, Any]]:
        resp = self.send_jsonrpc("tools/list", {})
        assert resp is not None
        return list(resp.get("result", {}).get("tools", []))

    def call_tool(self, name: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        resp = self.send_jsonrpc(
            "tools/call",
            {"name": name, "arguments": dict(arguments or {})},
        )
        assert resp is not None
        return resp


__all__ = [
    "ALLOWED_JSONRPC_METHODS",
    "ALPACA_ALLOWED_TOOL_SCHEMAS",
    "ALPACA_BLOCKED_MUTATING_TOOLS",
    "ALPACA_MCP_PROFILE",
    "COMPATIBLE_MCP_PROTOCOL_VERSIONS",
    "DisallowedMcpServerError",
    "MCP_PROTOCOL_VERSION",
    "McpAllowlistFirewall",
    "McpArgumentValidationError",
    "McpFirewallError",
    "McpServerFirewallProfile",
    "McpServerIdentityError",
    "McpToolDisallowedError",
    "PINNED_MCP_PROFILES",
    "REJECTED_MCP_SERVERS",
    "StdioMcpFirewallClient",
    "StreamableHttpMcpFirewallClient",
    "TRADING212_ALLOWED_TOOL_SCHEMAS",
    "TRADING212_BLOCKED_MUTATING_TOOLS",
    "TRADING212_MCP_PROFILE",
    "redact_sensitive_text",
    "resolve_mcp_firewall_profile",
    "validate_strict_tool_schema",
]
