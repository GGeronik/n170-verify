"""Cryptographic holder-signed trader profiles (/@<handle>) keyed by Ed25519 public key."""

from __future__ import annotations

from collections.abc import Mapping
import ipaddress
import re
from typing import Any
import unicodedata
import urllib.parse

from app.badges import (
    extract_verified_capital_bracket,
    finite_real_number,
    return_not_computed,
    verified_leaf_payload,
)
from app.config import utc_now_iso
from app.privacy_scanner import OutboundPrivacyScanner
from app.routes_proofs import parse_strict_bool, refuse_caller_clock
from app.store import (
    GovernanceBlockedError,
    ProfileInvalidError,
    ProfileNotFoundError,
    ProfileOwnershipError,
    ProfileSequenceError,
    ProofStore,
    StoredHolderProfile,
)
from n170_verify.contracts import parse_utc_timestamp, validate_hex_digest
from n170_verify.contracts.proof import (
    _BLANK_FILLER_LETTERS,
    _FORBIDDEN_HOLDER_CHARS_RE,
    _is_forbidden_holder_char,
)
from n170_verify.crypto import (
    derive_public_key_hex,
    ed25519_sign_domain,
    ed25519_verify_domain,
    jcs_canonicalize,
)


HOLDER_PROFILE_SCHEMA_VERSION = "n170-holder-profile-v1"
HOLDER_PROFILE_SIGNING_DOMAIN = b"n170.verify.holder.profile.v1"

HOLDER_LEADERBOARD_SCHEMA_VERSION = "n170-holder-leaderboard-v1"
HOLDER_LEADERBOARD_SIGNING_DOMAIN = b"n170.verify.holder.leaderboard.v1"

_PROFILE_HANDLE_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-]{1,30}[a-z0-9]\Z")
_TICKER_SYMBOL_RE = re.compile(r"^[A-Z0-9][A-Z0-9.\-^=/]{0,15}\Z")

RESERVED_HANDLES: frozenset[str] = frozenset(
    {
        "about",
        "admin",
        "api",
        "assets",
        "badges",
        "benchmarks",
        "by-key",
        "chains",
        "challenge",
        "commit",
        "connect",
        "docs",
        "edit",
        "embed",
        "explore",
        "favicon.ico",
        "health",
        "healthz",
        "leaderboard",
        "login",
        "logout",
        "me",
        "methods",
        "new",
        "null",
        "p",
        "privacy",
        "profile",
        "profiles",
        "proof",
        "proofs",
        "record",
        "records",
        "robots.txt",
        "root",
        "search",
        "settings",
        "signup",
        "sitemap.xml",
        "static",
        "status",
        "sync",
        "system",
        "terms",
        "tools",
        "u",
        "undefined",
        "verify",
        "vs",
        "well-known",
    }
)

_WATCHLIST_ALLOWED_KEYS = frozenset({"symbol", "thesis", "conviction", "status", "added_at_utc"})
_CONVICTION_ALLOWED_KEYS = frozenset({"symbol", "thesis", "conviction", "horizon"})
_ALLOWED_CONVICTIONS = frozenset({"high", "medium", "low"})
_ALLOWED_WATCHLIST_STATUSES = frozenset({"core", "watching", "research", "exited"})
_FORBIDDEN_BALANCE_KEYS = frozenset(
    {
        "account_id",
        "amount",
        "balance",
        "cost_basis",
        "dollar_value",
        "dollars",
        "market_value",
        "nav",
        "notional",
        "pnl_usd",
        "position_size",
        "quantity",
        "shares",
        "usd_value",
    }
)

MAX_WATCHLIST_ITEMS = 50
MAX_CONVICTION_ITEMS = 25
MAX_BIO_CHARS = 280
MAX_STRATEGY_NOTES_CHARS = 4000
MAX_THESIS_CHARS = 400


def _has_forbidden_text(text: str, *, allow_newlines: bool) -> bool:
    for ch in text:
        if ch in {"<", ">"}:
            return True
        if allow_newlines and ch == "\n":
            continue
        if _is_forbidden_holder_char(ch):
            return True
    return False


def normalize_profile_handle(raw: str) -> str:
    """Validate and normalize a trader profile handle (lowercase without leading '@')."""
    if not isinstance(raw, str):
        raise ValueError("handle must be a string")
    cleaned = raw.strip()
    if cleaned.startswith("@"):
        cleaned = cleaned[1:]
    cleaned = cleaned.lower()
    if not _PROFILE_HANDLE_RE.match(cleaned) or ".." in cleaned:
        raise ValueError(
            "handle must be 3-32 characters of lowercase letters, digits, '.', '_' or '-', "
            "starting and ending with a letter or digit"
        )
    if cleaned in RESERVED_HANDLES:
        raise ValueError(f"handle '@{cleaned}' is reserved")
    return cleaned


def _validate_display_name(raw: Any) -> str:
    if not isinstance(raw, str):
        raise ValueError("display_name must be a string")
    name = raw.strip(" \t\r\n")
    if (
        not name
        or len(name) > 64
        or _FORBIDDEN_HOLDER_CHARS_RE.search(name)
        or any(_is_forbidden_holder_char(ch) for ch in name)
    ):
        raise ValueError("display_name is invalid or contains forbidden characters")
    if not any(
        unicodedata.category(ch)[0] in {"L", "N"} and ord(ch) not in _BLANK_FILLER_LETTERS
        for ch in name
    ):
        raise ValueError("display_name must contain at least one letter or digit")
    return name


def _validate_profile_url(raw: Any) -> str | None:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError("profile_url must be a string or null")
    url = raw.strip()
    if not url:
        return None
    if (
        not url.startswith("https://")
        or len(url) > 180
        or _FORBIDDEN_HOLDER_CHARS_RE.search(url)
        or any(ch.isspace() or _is_forbidden_holder_char(ch) for ch in url)
    ):
        raise ValueError("profile_url must be a clean https:// URL (max 180 chars)")
    try:
        unquoted = urllib.parse.unquote(url, errors="strict")
    except UnicodeError:
        raise ValueError("profile_url has invalid percent-encoding") from None
    if any(_is_forbidden_holder_char(ch) for ch in unquoted):
        raise ValueError("profile_url contains forbidden characters")
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        raise ValueError("profile_url is malformed") from None
    if (
        parts.scheme != "https"
        or parts.username is not None
        or parts.password is not None
        or "@" in parts.netloc
        or port is not None
        or ":" in parts.netloc
    ):
        raise ValueError("profile_url must not include credentials or explicit ports")
    host = parts.hostname
    if (
        not host
        or "." not in host
        or host.startswith(".")
        or host.endswith(".")
        or host.lower() == "localhost"
    ):
        raise ValueError("profile_url must use a public domain name")
    is_ip = False
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        raise ValueError("profile_url must not use a literal IP address")
    if all(seg.isdigit() for seg in host.split(".")):
        raise ValueError("profile_url must use a public domain name")
    return url


def _validate_free_text(
    raw: Any,
    *,
    field_name: str,
    max_len: int,
    allow_newlines: bool,
) -> str:
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raise ValueError(f"{field_name} must be a string")
    normalized = raw.replace("\r\n", "\n").replace("\r", "\n").strip()
    if len(normalized) > max_len:
        raise ValueError(f"{field_name} exceeds maximum length ({max_len} chars)")
    if _has_forbidden_text(normalized, allow_newlines=allow_newlines):
        raise ValueError(f"{field_name} contains forbidden control, HTML, or format characters")
    return normalized


def _validate_ticker_symbol(raw: Any, *, field_name: str) -> str:
    if not isinstance(raw, str):
        raise ValueError(f"{field_name} must be a ticker string")
    sym = raw.strip().upper()
    if not _TICKER_SYMBOL_RE.match(sym):
        raise ValueError(f"{field_name} has invalid symbol {raw!r}")
    return sym


def _validate_watchlist(raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("watchlist must be a list of objects")
    if len(raw) > MAX_WATCHLIST_ITEMS:
        raise ValueError(f"watchlist supports at most {MAX_WATCHLIST_ITEMS} items")
    items: list[dict[str, Any]] = []
    seen_symbols: set[str] = set()
    for idx, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            raise ValueError(f"watchlist[{idx}] must be an object")
        for k in entry:
            lk = str(k).lower()
            if lk in _FORBIDDEN_BALANCE_KEYS:
                raise ValueError(
                    f"watchlist[{idx}] must not include share counts or dollar balances ({k!r})"
                )
            if k not in _WATCHLIST_ALLOWED_KEYS:
                raise ValueError(f"watchlist[{idx}] has unsupported key {k!r}")
        sym = _validate_ticker_symbol(entry.get("symbol"), field_name=f"watchlist[{idx}].symbol")
        if sym in seen_symbols:
            raise ValueError(f"watchlist contains duplicate symbol {sym!r}")
        seen_symbols.add(sym)

        thesis = _validate_free_text(
            entry.get("thesis", ""),
            field_name=f"watchlist[{idx}].thesis",
            max_len=280,
            allow_newlines=False,
        )
        conviction_raw = entry.get("conviction", "medium")
        if not isinstance(conviction_raw, str) or conviction_raw.strip().lower() not in _ALLOWED_CONVICTIONS:
            raise ValueError(
                f"watchlist[{idx}].conviction must be one of {sorted(_ALLOWED_CONVICTIONS)}"
            )
        conviction = conviction_raw.strip().lower()

        status_raw = entry.get("status", "watching")
        if not isinstance(status_raw, str) or status_raw.strip().lower() not in _ALLOWED_WATCHLIST_STATUSES:
            raise ValueError(
                f"watchlist[{idx}].status must be one of {sorted(_ALLOWED_WATCHLIST_STATUSES)}"
            )
        status = status_raw.strip().lower()

        added_at_raw = entry.get("added_at_utc")
        added_at_utc: str | None = None
        if added_at_raw is not None:
            if not isinstance(added_at_raw, str) or not added_at_raw.strip():
                raise ValueError(f"watchlist[{idx}].added_at_utc must be an ISO UTC string or null")
            parse_utc_timestamp(added_at_raw.strip(), field_name=f"watchlist[{idx}].added_at_utc")
            added_at_utc = added_at_raw.strip()

        items.append(
            {
                "added_at_utc": added_at_utc,
                "conviction": conviction,
                "status": status,
                "symbol": sym,
                "thesis": thesis,
            }
        )
    return items


def _validate_conviction_list(raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("conviction_list must be a list of objects")
    if len(raw) > MAX_CONVICTION_ITEMS:
        raise ValueError(f"conviction_list supports at most {MAX_CONVICTION_ITEMS} items")
    items: list[dict[str, Any]] = []
    seen_symbols: set[str] = set()
    for idx, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            raise ValueError(f"conviction_list[{idx}] must be an object")
        for k in entry:
            lk = str(k).lower()
            if lk in _FORBIDDEN_BALANCE_KEYS:
                raise ValueError(
                    f"conviction_list[{idx}] must not include share counts or dollar balances ({k!r})"
                )
            if k not in _CONVICTION_ALLOWED_KEYS:
                raise ValueError(f"conviction_list[{idx}] has unsupported key {k!r}")
        sym = _validate_ticker_symbol(
            entry.get("symbol"), field_name=f"conviction_list[{idx}].symbol"
        )
        if sym in seen_symbols:
            raise ValueError(f"conviction_list contains duplicate symbol {sym!r}")
        seen_symbols.add(sym)

        thesis = _validate_free_text(
            entry.get("thesis", ""),
            field_name=f"conviction_list[{idx}].thesis",
            max_len=MAX_THESIS_CHARS,
            allow_newlines=False,
        )
        conviction_raw = entry.get("conviction", "high")
        if not isinstance(conviction_raw, str) or conviction_raw.strip().lower() not in _ALLOWED_CONVICTIONS:
            raise ValueError(
                f"conviction_list[{idx}].conviction must be one of {sorted(_ALLOWED_CONVICTIONS)}"
            )
        conviction = conviction_raw.strip().lower()

        horizon = _validate_free_text(
            entry.get("horizon", ""),
            field_name=f"conviction_list[{idx}].horizon",
            max_len=64,
            allow_newlines=False,
        )
        items.append(
            {
                "conviction": conviction,
                "horizon": horizon,
                "symbol": sym,
                "thesis": thesis,
            }
        )
    return items


def build_profile_signable_claim(
    *,
    holder_public_key_hex: str,
    handle: str,
    display_name: str,
    bio: str = "",
    profile_url: str | None = None,
    strategy_notes: str = "",
    watchlist: list[dict[str, Any]] | None = None,
    conviction_list: list[dict[str, Any]] | None = None,
    list_on_leaderboard: bool = False,
    pinned_proof_id: str | None = None,
    sequence_number: int = 1,
    claimed_at_utc: str,
) -> dict[str, Any]:
    """Build the canonical JCS signable dictionary for ``HolderProfileClaim``."""
    norm_pubkey = validate_hex_digest(
        holder_public_key_hex, field_name="holder_public_key_hex", num_bytes=32
    )
    norm_handle = normalize_profile_handle(handle)
    norm_name = _validate_display_name(display_name)
    norm_bio = _validate_free_text(
        bio, field_name="bio", max_len=MAX_BIO_CHARS, allow_newlines=False
    )
    norm_url = _validate_profile_url(profile_url)
    norm_notes = _validate_free_text(
        strategy_notes,
        field_name="strategy_notes",
        max_len=MAX_STRATEGY_NOTES_CHARS,
        allow_newlines=True,
    )
    norm_watchlist = _validate_watchlist(watchlist)
    norm_conviction = _validate_conviction_list(conviction_list)
    if not isinstance(list_on_leaderboard, bool):
        raise ValueError("list_on_leaderboard must be a boolean")
    norm_pinned: str | None = None
    if pinned_proof_id is not None:
        if not isinstance(pinned_proof_id, str) or not pinned_proof_id.strip():
            raise ValueError("pinned_proof_id must be a non-empty string or null")
        norm_pinned = pinned_proof_id.strip()
        if len(norm_pinned) > 128 or _has_forbidden_text(norm_pinned, allow_newlines=False):
            raise ValueError("pinned_proof_id is invalid")
    if isinstance(sequence_number, bool) or not isinstance(sequence_number, int) or sequence_number < 1:
        raise ValueError("sequence_number must be a positive integer")
    if not isinstance(claimed_at_utc, str) or not claimed_at_utc.strip():
        raise ValueError("claimed_at_utc must be an ISO UTC timestamp")
    parse_utc_timestamp(claimed_at_utc.strip(), field_name="claimed_at_utc")

    return {
        "bio": norm_bio,
        "claimed_at_utc": claimed_at_utc.strip(),
        "conviction_list": norm_conviction,
        "display_name": norm_name,
        "handle": norm_handle,
        "holder_public_key_hex": norm_pubkey,
        "list_on_leaderboard": list_on_leaderboard,
        "pinned_proof_id": norm_pinned,
        "profile_url": norm_url,
        "schema_version": HOLDER_PROFILE_SCHEMA_VERSION,
        "sequence_number": sequence_number,
        "strategy_notes": norm_notes,
        "watchlist": norm_watchlist,
    }


def sign_holder_profile_claim(
    *,
    holder_private_key_hex: str,
    handle: str,
    display_name: str,
    bio: str = "",
    profile_url: str | None = None,
    strategy_notes: str = "",
    watchlist: list[dict[str, Any]] | None = None,
    conviction_list: list[dict[str, Any]] | None = None,
    list_on_leaderboard: bool = False,
    pinned_proof_id: str | None = None,
    sequence_number: int = 1,
    claimed_at_utc: str | None = None,
) -> dict[str, Any]:
    """Create an Ed25519-signed holder profile payload ready for ``POST /api/v1/profiles``."""
    pubkey = derive_public_key_hex(holder_private_key_hex)
    claim = build_profile_signable_claim(
        holder_public_key_hex=pubkey,
        handle=handle,
        display_name=display_name,
        bio=bio,
        profile_url=profile_url,
        strategy_notes=strategy_notes,
        watchlist=watchlist,
        conviction_list=conviction_list,
        list_on_leaderboard=list_on_leaderboard,
        pinned_proof_id=pinned_proof_id,
        sequence_number=sequence_number,
        claimed_at_utc=claimed_at_utc or utc_now_iso(),
    )
    sig_hex = ed25519_sign_domain(
        holder_private_key_hex,
        HOLDER_PROFILE_SIGNING_DOMAIN,
        jcs_canonicalize(claim),
    )
    return {**claim, "signature_hex": sig_hex}


def build_leaderboard_signable_claim(
    *,
    holder_public_key_hex: str,
    handle: str,
    list_on_leaderboard: bool,
    sequence_number: int,
    claimed_at_utc: str,
) -> dict[str, Any]:
    """Build the canonical JCS signable dictionary for a holder leaderboard list/unlist toggle."""
    norm_pubkey = validate_hex_digest(
        holder_public_key_hex, field_name="holder_public_key_hex", num_bytes=32
    )
    norm_handle = normalize_profile_handle(handle)
    if not isinstance(list_on_leaderboard, bool):
        raise ValueError("list_on_leaderboard must be a boolean")
    if isinstance(sequence_number, bool) or not isinstance(sequence_number, int) or sequence_number < 1:
        raise ValueError("sequence_number must be a positive integer")
    if not isinstance(claimed_at_utc, str) or not claimed_at_utc.strip():
        raise ValueError("claimed_at_utc must be an ISO UTC timestamp")
    parse_utc_timestamp(claimed_at_utc.strip(), field_name="claimed_at_utc")
    return {
        "claimed_at_utc": claimed_at_utc.strip(),
        "handle": norm_handle,
        "holder_public_key_hex": norm_pubkey,
        "list_on_leaderboard": list_on_leaderboard,
        "schema_version": HOLDER_LEADERBOARD_SCHEMA_VERSION,
        "sequence_number": sequence_number,
    }


def sign_holder_leaderboard_claim(
    *,
    holder_private_key_hex: str,
    handle: str,
    list_on_leaderboard: bool,
    sequence_number: int,
    claimed_at_utc: str | None = None,
) -> dict[str, Any]:
    """Create an Ed25519-signed leaderboard toggle payload for ``POST /api/v1/profiles/{handle}/leaderboard``."""
    pubkey = derive_public_key_hex(holder_private_key_hex)
    claim = build_leaderboard_signable_claim(
        holder_public_key_hex=pubkey,
        handle=handle,
        list_on_leaderboard=list_on_leaderboard,
        sequence_number=sequence_number,
        claimed_at_utc=claimed_at_utc or utc_now_iso(),
    )
    sig_hex = ed25519_sign_domain(
        holder_private_key_hex,
        HOLDER_LEADERBOARD_SIGNING_DOMAIN,
        jcs_canonicalize(claim),
    )
    return {**claim, "signature_hex": sig_hex}


def _count_disclosed_delayed_trades(bundle: Any) -> int | None:
    payload = verified_leaf_payload(bundle, "delayed_closed_trades")
    if isinstance(payload, Mapping):
        trades = payload.get("trades")
        if isinstance(trades, list):
            return len(trades)
        return None
    if isinstance(payload, list):
        return len(payload)
    return None


def _build_profile_response(
    profile: StoredHolderProfile,
    *,
    store: ProofStore,
    now_utc: str | None = None,
) -> dict[str, Any]:
    entries = store.list_proofs_for_holder_key(profile.holder_public_key_hex)
    registry_doc = store.build_registry_document()
    continuity_leaves = store.list_all_continuity_leaves()

    active_entry = entries[0] if entries else None
    if profile.pinned_proof_id is not None:
        for item in entries:
            if item.bundle.proof_id == profile.pinned_proof_id:
                active_entry = item
                break

    active_proof_payload: dict[str, Any] | None = None
    release_history: list[dict[str, Any]] = []

    for entry in entries:
        bundle = entry.bundle
        verification = store.verify_bundle_against_live_state(
            bundle,
            now_utc=now_utc,
            registry_doc=registry_doc,
            continuity_leaves=continuity_leaves,
        )
        is_active = active_entry is not None and bundle.proof_id == active_entry.bundle.proof_id
        if is_active:
            active_proof_payload = {
                "proof_id": bundle.proof_id,
                "proof_hash": entry.proof_hash,
                "opt_in_leaderboard": entry.opt_in_leaderboard,
                "stored_at_utc": entry.stored_at_utc,
                "proof_bundle": bundle.to_dict(),
                "verification": verification.to_dict(),
            }

        core = verified_leaf_payload(bundle, "core_metrics")
        core_map = core if isinstance(core, Mapping) else {}
        withheld = return_not_computed(core_map)
        proven_bracket = extract_verified_capital_bracket(bundle)
        obs_raw = core_map.get("observation_count")
        obs_count = (
            int(obs_raw)
            if isinstance(obs_raw, int) and not isinstance(obs_raw, bool) and obs_raw >= 0
            else None
        )
        if withheld:
            twr_dec = None
            twr_pct = None
            max_dd_dec = None
            sharpe_val = None
            psr_val = None
        else:
            twr_dec = finite_real_number(core_map.get("twr_decimal"))
            twr_pct = finite_real_number(core_map.get("twr_pct"))
            max_dd_dec = finite_real_number(core_map.get("max_drawdown_decimal"))
            sharpe_raw = (
                core_map.get("unsmoothed_sharpe_ratio")
                if core_map.get("unsmoothed_sharpe_ratio") is not None
                else core_map.get("sharpe_ratio")
            )
            sharpe_val = finite_real_number(sharpe_raw)
            elig_raw = core_map.get("psr_sample_eligible")
            psr_eligible = (
                bool(elig_raw)
                if isinstance(elig_raw, bool)
                else (obs_count is not None and obs_count >= 30)
            )
            psr_raw = (
                core_map.get("psr_glm_unsmoothed")
                if core_map.get("psr_glm_unsmoothed") is not None
                else core_map.get("probabilistic_sharpe_ratio")
            )
            psr_cand = finite_real_number(psr_raw)
            psr_val = (
                psr_cand
                if psr_eligible
                and obs_count is not None
                and obs_count >= 30
                and psr_cand is not None
                and 0.0 <= psr_cand <= 1.0
                else None
            )
        release_history.append(
            {
                "proof_id": bundle.proof_id,
                "proof_hash": entry.proof_hash,
                "broker_id": bundle.broker_id,
                "base_currency": bundle.base_currency,
                "period_start_utc": bundle.period_start_utc,
                "period_end_utc": bundle.period_end_utc,
                "issued_at_utc": bundle.issued_at_utc,
                "stored_at_utc": entry.stored_at_utc,
                "opt_in_leaderboard": entry.opt_in_leaderboard,
                "is_active": is_active,
                "verification_valid": verification.valid,
                "performance_withheld": withheld,
                "effective_origin_assurance": verification.effective_origin_assurance.value,
                "signer_trust_status": verification.signer_trust_status.value,
                "capital_bracket": proven_bracket.value if proven_bracket is not None else "undisclosed",
                "twr_decimal": twr_dec,
                "twr_pct": twr_pct,
                "max_drawdown_decimal": max_dd_dec,
                "sharpe_ratio": sharpe_val,
                "probabilistic_sharpe_ratio": psr_val,
                "observation_count": obs_count,
                "delayed_trades_count": _count_disclosed_delayed_trades(bundle),
                "badge_url": f"/api/v1/badges/{bundle.proof_id}.svg",
                "record_url": f"/p/{bundle.proof_id}",
            }
        )

    return {
        "profile": {
            "holder_public_key_hex": profile.holder_public_key_hex,
            "handle": profile.handle,
            "handle_at": f"@{profile.handle}",
            "profile_path": f"/@{profile.handle}",
            "display_name": profile.display_name,
            "bio": profile.bio,
            "profile_url": profile.profile_url,
            "strategy_notes": profile.strategy_notes,
            "watchlist": profile.watchlist,
            "conviction_list": profile.conviction_list,
            "list_on_leaderboard": profile.list_on_leaderboard,
            "pinned_proof_id": profile.pinned_proof_id,
            "sequence_number": profile.sequence_number,
            "signed_claim": profile.signed_claim,
            "leaderboard_signed_claim": profile.leaderboard_signed_claim,
            "created_at_utc": profile.created_at_utc,
            "updated_at_utc": profile.updated_at_utc,
        },
        "active_proof_id": active_entry.bundle.proof_id if active_entry is not None else None,
        "active_proof": active_proof_payload,
        "release_count": len(release_history),
        "release_history": release_history,
    }


def _validate_optional_now_utc(raw: Any) -> str | None:
    if raw is None:
        return None
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("now_utc must be a valid ISO-8601 UTC timestamp")
    cleaned = raw.strip()
    parse_utc_timestamp(cleaned, field_name="now_utc")
    return cleaned


def handle_post_profile(
    payload: Mapping[str, Any],
    *,
    store: ProofStore,
) -> tuple[int, dict[str, Any]]:
    """Claim or update a cryptographic holder profile via ``POST /api/v1/profiles``."""
    if not isinstance(payload, Mapping):
        return 400, {"error": "invalid_request", "detail": "Request body must be a JSON object"}
    clock_refusal = refuse_caller_clock(store.config, payload)
    if clock_refusal is not None:
        return clock_refusal

    schema_ver = payload.get("schema_version", HOLDER_PROFILE_SCHEMA_VERSION)
    if schema_ver != HOLDER_PROFILE_SCHEMA_VERSION:
        return 422, {
            "error": "validation_error",
            "detail": f"schema_version must be {HOLDER_PROFILE_SCHEMA_VERSION!r}",
        }

    list_on_lb, bool_err = parse_strict_bool(payload, "list_on_leaderboard", default=False)
    if bool_err is not None:
        return bool_err

    try:
        validated_now_utc = _validate_optional_now_utc(payload.get("now_utc"))
        claim = build_profile_signable_claim(
            holder_public_key_hex=str(payload.get("holder_public_key_hex") or ""),
            handle=payload.get("handle"),  # type: ignore[arg-type]
            display_name=payload.get("display_name"),
            bio=payload.get("bio", ""),
            profile_url=payload.get("profile_url"),
            strategy_notes=payload.get("strategy_notes", ""),
            watchlist=payload.get("watchlist"),
            conviction_list=payload.get("conviction_list"),
            list_on_leaderboard=list_on_lb,
            pinned_proof_id=payload.get("pinned_proof_id"),
            sequence_number=payload.get("sequence_number"),  # type: ignore[arg-type]
            claimed_at_utc=payload.get("claimed_at_utc"),  # type: ignore[arg-type]
        )
        sig_hex = validate_hex_digest(
            str(payload.get("signature_hex") or ""),
            field_name="signature_hex",
            num_bytes=64,
        )
    except (ValueError, TypeError) as exc:
        return 422, {"error": "validation_error", "detail": str(exc)}

    if not ed25519_verify_domain(
        claim["holder_public_key_hex"],
        HOLDER_PROFILE_SIGNING_DOMAIN,
        jcs_canonicalize(claim),
        sig_hex,
    ):
        return 422, {
            "error": "invalid_profile_signature",
            "detail": "Ed25519 holder signature failed verification for this profile claim",
        }

    signed_claim = {**claim, "signature_hex": sig_hex}
    if OutboundPrivacyScanner().scan_payload(signed_claim):
        return 422, {
            "error": "privacy_content_refused",
            "detail": (
                "Profile text contains patterns that look like an account number, credential, "
                "or raw statement excerpt; remove them and re-sign"
            ),
        }

    try:
        stored, created = store.upsert_holder_profile(
            holder_public_key_hex=claim["holder_public_key_hex"],
            handle=claim["handle"],
            display_name=claim["display_name"],
            bio=claim["bio"],
            profile_url=claim["profile_url"],
            strategy_notes=claim["strategy_notes"],
            watchlist=claim["watchlist"],
            conviction_list=claim["conviction_list"],
            list_on_leaderboard=claim["list_on_leaderboard"],
            pinned_proof_id=claim["pinned_proof_id"],
            sequence_number=claim["sequence_number"],
            signed_claim=signed_claim,
        )
    except ProfileOwnershipError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    except ProfileSequenceError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    except ProfileInvalidError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc), "errors": exc.errors}
    except GovernanceBlockedError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}

    body = _build_profile_response(stored, store=store, now_utc=validated_now_utc)
    return (201 if created else 200), body


def handle_get_profile(
    handle: str,
    query_params: Mapping[str, str],
    *,
    store: ProofStore,
) -> tuple[int, dict[str, Any]]:
    """Fetch a holder profile, its latest active proof, and release history via ``GET /api/v1/profiles/{handle}``."""
    clock_refusal = refuse_caller_clock(store.config, query_params)
    if clock_refusal is not None:
        return clock_refusal
    try:
        validated_now_utc = _validate_optional_now_utc(query_params.get("now_utc"))
    except ValueError as exc:
        return 422, {"error": "validation_error", "detail": str(exc)}
    try:
        norm_handle = normalize_profile_handle(handle)
    except ValueError:
        return 404, {"error": "profile_not_found", "detail": "Profile not found"}

    try:
        profile = store.get_holder_profile_by_handle(norm_handle)
    except ProfileNotFoundError:
        return 404, {"error": "profile_not_found", "detail": f"Profile '@{norm_handle}' not found"}

    return 200, _build_profile_response(profile, store=store, now_utc=validated_now_utc)


def handle_get_profile_by_key(
    holder_public_key_hex: str,
    query_params: Mapping[str, str],
    *,
    store: ProofStore,
) -> tuple[int, dict[str, Any]]:
    """Lookup a holder profile by Ed25519 public key via ``GET /api/v1/profiles/by-key/{holder_public_key_hex}``."""
    clock_refusal = refuse_caller_clock(store.config, query_params)
    if clock_refusal is not None:
        return clock_refusal
    try:
        validated_now_utc = _validate_optional_now_utc(query_params.get("now_utc"))
        norm_key = validate_hex_digest(
            holder_public_key_hex, field_name="holder_public_key_hex", num_bytes=32
        )
    except ValueError as exc:
        return 422, {"error": "validation_error", "detail": str(exc)}

    try:
        profile = store.get_holder_profile_by_key(norm_key)
    except ProfileNotFoundError:
        return 404, {"error": "profile_not_found", "detail": "Profile not found for this holder key"}

    return 200, _build_profile_response(profile, store=store, now_utc=validated_now_utc)


def handle_post_profile_leaderboard(
    handle: str,
    payload: Mapping[str, Any],
    *,
    store: ProofStore,
) -> tuple[int, dict[str, Any]]:
    """Apply an Ed25519-signed leaderboard list/unlist toggle via ``POST /api/v1/profiles/{handle}/leaderboard``."""
    if not isinstance(payload, Mapping):
        return 400, {"error": "invalid_request", "detail": "Request body must be a JSON object"}
    clock_refusal = refuse_caller_clock(store.config, payload)
    if clock_refusal is not None:
        return clock_refusal

    schema_ver = payload.get("schema_version", HOLDER_LEADERBOARD_SCHEMA_VERSION)
    if schema_ver != HOLDER_LEADERBOARD_SCHEMA_VERSION:
        return 422, {
            "error": "validation_error",
            "detail": f"schema_version must be {HOLDER_LEADERBOARD_SCHEMA_VERSION!r}",
        }

    if "list_on_leaderboard" not in payload:
        return 422, {
            "error": "validation_error",
            "detail": "list_on_leaderboard is required and must be a boolean",
        }
    list_on_lb, bool_err = parse_strict_bool(payload, "list_on_leaderboard", default=False)
    if bool_err is not None:
        return bool_err

    try:
        validated_now_utc = _validate_optional_now_utc(payload.get("now_utc"))
        path_handle = normalize_profile_handle(handle)
        body_handle = normalize_profile_handle(payload.get("handle", path_handle))  # type: ignore[arg-type]
        if body_handle != path_handle:
            return 422, {
                "error": "validation_error",
                "detail": "Payload handle does not match URL handle",
            }
        claim = build_leaderboard_signable_claim(
            holder_public_key_hex=str(payload.get("holder_public_key_hex") or ""),
            handle=path_handle,
            list_on_leaderboard=list_on_lb,
            sequence_number=payload.get("sequence_number"),  # type: ignore[arg-type]
            claimed_at_utc=payload.get("claimed_at_utc"),  # type: ignore[arg-type]
        )
        sig_hex = validate_hex_digest(
            str(payload.get("signature_hex") or ""),
            field_name="signature_hex",
            num_bytes=64,
        )
    except (ValueError, TypeError) as exc:
        return 422, {"error": "validation_error", "detail": str(exc)}

    if not ed25519_verify_domain(
        claim["holder_public_key_hex"],
        HOLDER_LEADERBOARD_SIGNING_DOMAIN,
        jcs_canonicalize(claim),
        sig_hex,
    ):
        return 422, {
            "error": "invalid_profile_signature",
            "detail": "Ed25519 holder signature failed verification for this leaderboard toggle",
        }

    signed_claim = {**claim, "signature_hex": sig_hex}
    try:
        updated = store.set_holder_leaderboard_listing(
            holder_public_key_hex=claim["holder_public_key_hex"],
            handle=path_handle,
            list_on_leaderboard=claim["list_on_leaderboard"],
            sequence_number=claim["sequence_number"],
            signed_claim=signed_claim,
        )
    except ProfileNotFoundError:
        return 404, {"error": "profile_not_found", "detail": f"Profile '@{path_handle}' not found"}
    except ProfileOwnershipError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    except ProfileSequenceError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    except GovernanceBlockedError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}

    return 200, _build_profile_response(updated, store=store, now_utc=validated_now_utc)


__all__ = [
    "HOLDER_LEADERBOARD_SCHEMA_VERSION",
    "HOLDER_LEADERBOARD_SIGNING_DOMAIN",
    "HOLDER_PROFILE_SCHEMA_VERSION",
    "HOLDER_PROFILE_SIGNING_DOMAIN",
    "RESERVED_HANDLES",
    "build_leaderboard_signable_claim",
    "build_profile_signable_claim",
    "handle_get_profile",
    "handle_get_profile_by_key",
    "handle_post_profile",
    "handle_post_profile_leaderboard",
    "normalize_profile_handle",
    "sign_holder_leaderboard_claim",
    "sign_holder_profile_claim",
]
