#!/usr/bin/env python3
"""Zero-secret CLI for claiming and updating Ed25519-signed /@<handle> Trader Profiles.

Reads a local holder Ed25519 key JSON file (mode 0600 recommended), signs a
canonical JCS ``HolderProfileClaim`` or ``HolderLeaderboardClaim``, and submits
it to ``POST /api/v1/profiles`` or ``POST /api/v1/profiles/{handle}/leaderboard``.
Private key material is never logged or printed.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any
from urllib import error as url_error
from urllib import request as url_request


_REPO_ROOT = Path(__file__).resolve().parents[2]
for _sub in (_REPO_ROOT / "core", _REPO_ROOT / "api"):
    _sub_str = str(_sub)
    if _sub_str not in sys.path:
        sys.path.insert(0, _sub_str)

from app.routes_profiles import (  # noqa: E402
    normalize_profile_handle,
    sign_holder_leaderboard_claim,
    sign_holder_profile_claim,
)
from n170_verify.crypto import derive_public_key_hex  # noqa: E402


def _b64url_to_hex(raw: str) -> str:
    padded = raw.strip() + "=" * ((4 - len(raw.strip()) % 4) % 4)
    decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    if len(decoded) != 32:
        raise ValueError("Ed25519 private seed must be 32 bytes")
    return decoded.hex()


def load_holder_private_key_hex(key_path: Path, *, strict_perms: bool = False) -> str:
    """Load a 32-byte Ed25519 private key hex from a local JSON file without printing secrets."""
    if not key_path.is_file():
        raise FileNotFoundError(f"Holder key file not found: {key_path}")
    if os.name == "posix":
        mode = stat.S_IMODE(key_path.stat().st_mode)
        if mode & 0o077:
            msg = f"Warning: holder key file {key_path} has permissive mode {oct(mode)} (expected 0o600)"
            if strict_perms:
                raise PermissionError(msg)
            print(msg, file=sys.stderr)

    data = json.loads(key_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Holder key JSON must be an object")

    for hex_field in ("private_key_hex", "privateKeyHex", "seed_hex", "seedHex"):
        val = data.get(hex_field)
        if isinstance(val, str) and len(val.strip()) == 64:
            bytes.fromhex(val.strip())
            return val.strip().lower()

    # Support Ed25519 JWK format ({"kty": "OKP", "crv": "Ed25519", "d": "<b64url>"})
    jwk_obj = data.get("private_jwk") if isinstance(data.get("private_jwk"), dict) else data
    if isinstance(jwk_obj, dict) and isinstance(jwk_obj.get("d"), str):
        return _b64url_to_hex(jwk_obj["d"])

    raise ValueError(
        "Holder key JSON must contain a 32-byte Ed25519 key in "
        "'private_key_hex', 'seed_hex', or JWK 'd'"
    )


def _http_json(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    *,
    timeout: float = 20.0,
) -> tuple[int, dict[str, Any]]:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = url_request.Request(url, data=body, headers=headers, method=method)
    try:
        with url_request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return int(resp.status), json.loads(raw) if raw else {}
    except url_error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"detail": raw}
        return int(exc.code), parsed


def _fetch_existing_profile(api_url: str, pubkey_hex: str) -> dict[str, Any] | None:
    status, data = _http_json(
        "GET",
        f"{api_url.rstrip('/')}/api/v1/profiles/by-key/{pubkey_hex}",
    )
    if status == 404:
        return None
    if status != 200:
        raise RuntimeError(f"Failed to query current profile state (HTTP {status}): {data}")
    prof = data.get("profile")
    return prof if isinstance(prof, dict) else None


def _load_json_list_file(path_str: str | None) -> list[dict[str, Any]]:
    if not path_str:
        return []
    parsed = json.loads(Path(path_str).read_text(encoding="utf-8"))
    if not isinstance(parsed, list):
        raise ValueError(f"{path_str} must contain a JSON array")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sign and submit Ed25519 holder profile claims (zero passwords, zero secret output)."
    )
    parser.add_argument(
        "--key-file",
        required=True,
        help="Path to local holder Ed25519 key JSON file (recommended mode 0600)",
    )
    parser.add_argument(
        "--strict-perms",
        action="store_true",
        help="Refuse to run if --key-file is readable by group/other",
    )
    parser.add_argument(
        "--api-url",
        default="http://127.0.0.1:8080",
        help="Base API URL (default: http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the signed public claim JSON without sending an HTTP POST",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_upsert = sub.add_parser("upsert", help="Claim or update /@<handle> profile")
    p_upsert.add_argument("--handle", required=True, help="Profile handle (with or without leading @)")
    p_upsert.add_argument("--display-name", required=True, help="Public trader display name")
    p_upsert.add_argument("--bio", default=None, help="Short trader bio (max 280 chars)")
    url_grp = p_upsert.add_mutually_exclusive_group()
    url_grp.add_argument("--profile-url", default=None, help="Optional https:// website/X/GitHub URL")
    url_grp.add_argument("--clear-profile-url", action="store_true", help="Clear existing profile_url")
    p_upsert.add_argument("--strategy-notes", default=None, help="Strategy notes text")
    p_upsert.add_argument("--strategy-notes-file", default=None, help="Path to text/markdown file for strategy notes")
    p_upsert.add_argument("--watchlist-json", default=None, help="Path to JSON file containing watchlist array")
    p_upsert.add_argument("--conviction-json", default=None, help="Path to JSON file containing conviction_list array")
    lb_grp = p_upsert.add_mutually_exclusive_group()
    lb_grp.add_argument("--list-on-leaderboard", action="store_true", help="Opt active record onto /leaderboard")
    lb_grp.add_argument("--unlist-from-leaderboard", action="store_true", help="Remove records from /leaderboard")
    pin_grp = p_upsert.add_mutually_exclusive_group()
    pin_grp.add_argument("--pinned-proof-id", default=None, help="Optional proof_id to pin as active snapshot")
    pin_grp.add_argument("--unpin", action="store_true", help="Clear pinned_proof_id to auto-track latest record")
    p_upsert.add_argument(
        "--replace",
        action="store_true",
        help="Replace all omitted optional fields with empty defaults instead of preserving existing profile values",
    )
    p_upsert.add_argument("--sequence", type=int, default=None, help="Explicit monotonic sequence_number")

    p_lb = sub.add_parser("leaderboard", help="Sign a lightweight leaderboard list/unlist toggle")
    p_lb.add_argument("--handle", required=True, help="Profile handle (with or without leading @)")
    toggle_grp = p_lb.add_mutually_exclusive_group(required=True)
    toggle_grp.add_argument("--list", dest="list_flag", action="store_true", help="List active record on /leaderboard")
    toggle_grp.add_argument("--unlist", dest="list_flag", action="store_false", help="Unlist from /leaderboard")
    p_lb.add_argument("--sequence", type=int, default=None, help="Explicit monotonic sequence_number")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    priv_hex = load_holder_private_key_hex(Path(args.key_file), strict_perms=args.strict_perms)
    pubkey_hex = derive_public_key_hex(priv_hex)

    existing_profile: dict[str, Any] | None = None
    if not args.dry_run:
        if args.sequence is None or (args.command == "upsert" and not args.replace):
            existing_profile = _fetch_existing_profile(args.api_url, pubkey_hex)

    seq = args.sequence
    if seq is None:
        if existing_profile is not None:
            seq = max(1, int(existing_profile.get("sequence_number", 0)) + 1)
        else:
            seq = 1

    if args.command == "upsert":
        base = existing_profile if (existing_profile is not None and not args.replace) else {}

        bio = args.bio if args.bio is not None else str(base.get("bio") or "")

        if args.clear_profile_url:
            profile_url: str | None = None
        elif args.profile_url is not None:
            profile_url = args.profile_url
        else:
            raw_url = base.get("profile_url")
            profile_url = str(raw_url) if isinstance(raw_url, str) and raw_url.strip() else None

        if args.strategy_notes_file is not None:
            notes = Path(args.strategy_notes_file).read_text(encoding="utf-8")
        elif args.strategy_notes is not None:
            notes = args.strategy_notes
        else:
            notes = str(base.get("strategy_notes") or "")

        if args.watchlist_json is not None:
            watchlist = _load_json_list_file(args.watchlist_json)
        else:
            prev_wl = base.get("watchlist")
            watchlist = list(prev_wl) if isinstance(prev_wl, list) else []

        if args.conviction_json is not None:
            conviction = _load_json_list_file(args.conviction_json)
        else:
            prev_cv = base.get("conviction_list")
            conviction = list(prev_cv) if isinstance(prev_cv, list) else []

        if args.list_on_leaderboard:
            list_on_lb = True
        elif args.unlist_from_leaderboard:
            list_on_lb = False
        else:
            list_on_lb = bool(base.get("list_on_leaderboard", False))

        if args.unpin:
            pinned_proof_id: str | None = None
        elif args.pinned_proof_id is not None:
            pinned_proof_id = args.pinned_proof_id
        else:
            raw_pin = base.get("pinned_proof_id")
            pinned_proof_id = str(raw_pin) if isinstance(raw_pin, str) and raw_pin.strip() else None

        signed = sign_holder_profile_claim(
            holder_private_key_hex=priv_hex,
            handle=args.handle,
            display_name=args.display_name,
            bio=bio,
            profile_url=profile_url,
            strategy_notes=notes,
            watchlist=watchlist,
            conviction_list=conviction,
            list_on_leaderboard=list_on_lb,
            pinned_proof_id=pinned_proof_id,
            sequence_number=seq,
        )
        if args.dry_run:
            print(json.dumps(signed, indent=2, sort_keys=True))
            return 0
        status, resp = _http_json("POST", f"{args.api_url.rstrip('/')}/api/v1/profiles", signed)
    else:
        norm_handle = normalize_profile_handle(args.handle)
        signed = sign_holder_leaderboard_claim(
            holder_private_key_hex=priv_hex,
            handle=norm_handle,
            list_on_leaderboard=bool(args.list_flag),
            sequence_number=seq,
        )
        if args.dry_run:
            print(json.dumps(signed, indent=2, sort_keys=True))
            return 0
        status, resp = _http_json(
            "POST",
            f"{args.api_url.rstrip('/')}/api/v1/profiles/{norm_handle}/leaderboard",
            signed,
        )

    print(json.dumps({"http_status": status, "response": resp}, indent=2, sort_keys=True))
    return 0 if 200 <= status < 300 else 1


if __name__ == "__main__":
    raise SystemExit(main())
