"""Command-line interface for N170 Verify v3 (`python3 -m n170_verify.cli` / `n170-verify`).

Security & privacy invariants:
- Never creates temporary files or writes unencrypted artifacts to disk unless ``--output`` is
  explicitly requested for the redacted proof bundle.
- Never prints raw account identifiers, trade/order IDs, share quantities, or dollar NAV balances
  to ``stdout`` or ``stderr``.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
import os
from pathlib import Path
import sys
from typing import Any

from n170_verify.connectors import (
    CONNECTOR_CLASS_MAP,
    PaperOrSandboxAccountRejectedError,
    list_connector_descriptors,
)
from n170_verify.contracts import (
    AccountScope,
    ChainContinuityMode,
    EnvironmentTier,
    OriginAssurance,
    ProviderApprovalState,
    SignerTrustStatus,
    VERIFY_SCHEMA_VERSION,
    VerifyProofBundle,
    verify_proof_bundle,
)
from n170_verify.crypto import (
    CANONICAL_LEAF_NAMES,
    PublisherKeyRecord,
    PublisherKeyRegistryDocument,
    active_ed25519_backend,
    compute_key_id,
    generate_ed25519_keypair,
)
from n170_verify.pipeline import _utc_now_iso, verify_portfolio


def _read_bytes_arg(path_or_dash: str) -> bytes:
    if path_or_dash == "-":
        return sys.stdin.buffer.read()
    return Path(path_or_dash).read_bytes()


def _resolve_disclose_leaves(
    disclose_arg: str | None,
    redact_arg: str | None,
) -> list[str]:
    if disclose_arg:
        selected = [item.strip() for item in disclose_arg.split(",") if item.strip()]
        unknown = set(selected) - set(CANONICAL_LEAF_NAMES)
        if unknown:
            raise ValueError(f"Unknown canonical leaf name(s): {sorted(unknown)}")
    else:
        selected = list(CANONICAL_LEAF_NAMES)

    if redact_arg:
        to_hide = {item.strip() for item in redact_arg.split(",") if item.strip()}
        unknown_hide = to_hide - set(CANONICAL_LEAF_NAMES)
        if unknown_hide:
            raise ValueError(f"Unknown canonical leaf name(s) in --redact: {sorted(unknown_hide)}")
        selected = [leaf for leaf in selected if leaf not in to_hide]

    return selected


def _resolve_signing_key_hex(args: argparse.Namespace) -> str | None:
    if getattr(args, "signing_key_hex", None):
        return str(args.signing_key_hex).strip()
    env_name = getattr(args, "signing_key_env", None)
    if env_name:
        val = os.environ.get(str(env_name), "").strip()
        if not val:
            raise ValueError(f"Signing key environment variable {env_name!r} is empty or unset")
        return val
    return None


def _emit_json(payload: Any, output_path: str | None = None) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    if output_path:
        Path(output_path).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


def _add_common_verify_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional output path for the signed .verify.json proof bundle (defaults to stdout)",
    )
    parser.add_argument(
        "--disclose",
        default=None,
        help="Comma-separated canonical leaf names to disclose (defaults to all 7 leaves)",
    )
    parser.add_argument(
        "--redact",
        default=None,
        help="Comma-separated canonical leaf names to keep undisclosed behind salted SHA-256 hashes",
    )
    parser.add_argument(
        "--benchmark",
        default=None,
        help="Optional benchmark ticker (e.g. SPY.US) when EODHD_API_KEY is configured",
    )
    parser.add_argument(
        "--cash-flow-timing",
        choices=("end_of_day", "start_of_day", "modified_dietz"),
        default="end_of_day",
        help="External capital flow timing convention for daily TWR",
    )
    parser.add_argument(
        "--publisher-kid",
        default="self-hosted-cli",
        help="Publisher key identifier recorded in the signed proof header",
    )
    parser.add_argument(
        "--signing-key-hex",
        default=None,
        help="Optional 64-char hex Ed25519 private seed (defaults to ephemeral in-memory keypair)",
    )
    parser.add_argument(
        "--signing-key-env",
        default=None,
        help="Optional environment variable name holding the 64-char hex Ed25519 private seed",
    )
    parser.add_argument(
        "--blinding-salt-hex",
        default=None,
        help="Optional 64-char hex salt for blinded_account_tag (defaults to random 256-bit salt)",
    )
    parser.add_argument(
        "--proof-id",
        default=None,
        help="Optional explicit proof_id",
    )
    parser.add_argument(
        "--issued-at",
        default=None,
        help="Optional ISO-8601 UTC issuance timestamp",
    )
    parser.add_argument(
        "--envelope",
        action="store_true",
        help="Emit {proof_bundle, verification} envelope instead of standalone .verify.json bundle",
    )


def _cmd_verify_flex(args: argparse.Namespace) -> int:
    source_path = args.input or args.input_file
    if not source_path:
        raise ValueError("verify-flex requires an input XML file path (or '-' for stdin)")
    raw_xml = _read_bytes_arg(source_path)
    disclose_leaves = _resolve_disclose_leaves(args.disclose, args.redact)
    priv_hex = _resolve_signing_key_hex(args)

    result = verify_portfolio(
        flex_xml=raw_xml,
        blinding_salt_hex=args.blinding_salt_hex,
        benchmark_symbol=args.benchmark,
        cash_flow_timing=args.cash_flow_timing,
        publisher_kid=args.publisher_kid,
        publisher_private_key_hex=priv_hex,
        disclose_leaf_names=disclose_leaves,
        proof_id=args.proof_id,
        issued_at_utc=args.issued_at,
        require_live=True,
    )

    payload: dict[str, Any]
    if args.envelope:
        payload = {
            "proof_bundle": result.proof_bundle.to_dict(),
            "verification": result.verification.to_dict(),
        }
    else:
        payload = result.proof_bundle.to_dict()

    _emit_json(payload, args.output)
    valid_csv = (
        result.verification.valid
        or (
            result.proof_bundle.environment_tier == EnvironmentTier.UNVERIFIED_OFFLINE
            and result.verification.signature_valid
            and result.verification.merkle_valid
        )
    )
    return 0 if valid_csv else 1


def _cmd_verify_csv(args: argparse.Namespace) -> int:
    disclose_leaves = _resolve_disclose_leaves(args.disclose, args.redact)
    priv_hex = _resolve_signing_key_hex(args)
    fmt = None if args.format == "auto" else args.format

    degiro_acct = _read_bytes_arg(args.degiro_account_csv) if args.degiro_account_csv else None
    degiro_tx = (
        _read_bytes_arg(args.degiro_transactions_csv) if args.degiro_transactions_csv else None
    )
    degiro_port = _read_bytes_arg(args.degiro_portfolio_csv) if args.degiro_portfolio_csv else None

    csv_bytes: bytes | None = None
    source_path = args.input or args.input_file
    if source_path:
        csv_bytes = _read_bytes_arg(source_path)
    elif degiro_acct is None and degiro_tx is None and degiro_port is None:
        raise ValueError(
            "verify-csv requires either a positional CSV path ('-' for stdin) or --degiro-*-csv options"
        )

    result = verify_portfolio(
        csv_source=csv_bytes,
        csv_format=fmt,
        degiro_account_csv=degiro_acct,
        degiro_transactions_csv=degiro_tx,
        degiro_portfolio_csv=degiro_port,
        base_currency=args.base_currency,
        blinding_salt_hex=args.blinding_salt_hex,
        benchmark_symbol=args.benchmark,
        cash_flow_timing=args.cash_flow_timing,
        publisher_kid=args.publisher_kid,
        publisher_private_key_hex=priv_hex,
        disclose_leaf_names=disclose_leaves,
        proof_id=args.proof_id,
        issued_at_utc=args.issued_at,
        require_live=True,
    )

    if args.envelope:
        payload: dict[str, Any] = {
            "proof_bundle": result.proof_bundle.to_dict(),
            "verification": result.verification.to_dict(),
        }
    else:
        payload = result.proof_bundle.to_dict()

    _emit_json(payload, args.output)
    valid_csv = (
        result.verification.valid
        or (
            result.proof_bundle.environment_tier == EnvironmentTier.UNVERIFIED_OFFLINE
            and result.verification.signature_valid
            and result.verification.merkle_valid
        )
    )
    return 0 if valid_csv else 1


def _cmd_check_bundle(args: argparse.Namespace) -> int:
    raw_bytes = _read_bytes_arg(args.bundle_file)
    parsed = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("Bundle JSON must be an object")

    bundle_dict = parsed["proof_bundle"] if "proof_bundle" in parsed and isinstance(parsed["proof_bundle"], dict) else parsed
    bundle = VerifyProofBundle.from_dict(bundle_dict)

    registry_doc: PublisherKeyRegistryDocument | None = None
    if args.registry:
        reg_bytes = Path(args.registry).read_bytes()
        registry_doc = PublisherKeyRegistryDocument.from_dict(json.loads(reg_bytes.decode("utf-8")))

    verification = verify_proof_bundle(
        bundle,
        registry_doc=registry_doc,
        now_utc=args.now_utc,
    )
    _emit_json(verification.to_dict(), args.output)
    return 0 if verification.valid else 1


def _cmd_keygen(args: argparse.Namespace) -> int:
    kp = generate_ed25519_keypair()
    now_iso = _utc_now_iso()
    kid = args.kid or f"self-hosted-{compute_key_id(kp.public_key_hex)}"
    rec = PublisherKeyRecord(
        publisher_kid=kid,
        public_key_hex=kp.public_key_hex,
        status="active",
        not_before_utc=now_iso,
        issuer_org=args.issuer_org,
    )
    out: dict[str, Any] = {
        "publisher_kid": kid,
        "public_key_hex": kp.public_key_hex,
        "ed25519_backend": active_ed25519_backend(),
        "registry_record": rec.to_dict(),
    }
    if not args.public_only:
        out["private_key_hex"] = kp.private_key_hex
    _emit_json(out, args.output)
    return 0


def _cmd_capabilities(args: argparse.Namespace) -> int:
    descriptors = [
        d.to_dict() if hasattr(d, "to_dict") else d for d in list_connector_descriptors()
    ]
    payload = {
        "schema_version": VERIFY_SCHEMA_VERSION,
        "ed25519_backend": active_ed25519_backend(),
        "canonical_leaf_names": list(CANONICAL_LEAF_NAMES),
        "connectors": descriptors,
        "connector_ids": sorted(CONNECTOR_CLASS_MAP.keys()),
        "assurance_axes": {
            "origin_assurance": [e.value for e in OriginAssurance],
            "account_scope": [e.value for e in AccountScope],
            "provider_approval_state": [e.value for e in ProviderApprovalState],
            "environment_tier": [e.value for e in EnvironmentTier],
            "signer_trust_status": [e.value for e in SignerTrustStatus],
            "chain_continuity_mode": [e.value for e in ChainContinuityMode],
        },
        "privacy_guarantees": {
            "raw_account_ids_emitted": False,
            "dollar_nav_balances_emitted": False,
            "raw_share_quantities_emitted": False,
            "raw_reference_ohlcv_emitted": False,
            "closed_trade_embargo_days": 7,
            "temporary_files_written": False,
        },
    }
    _emit_json(payload, args.output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="n170-verify",
        description="N170 Verify - Privacy-preserving brokerage performance proof generator & verifier",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_flex = sub.add_parser(
        "verify-flex",
        help="Verify an offline IBKR Flex XML statement and emit a signed .verify.json proof bundle",
    )
    p_flex.add_argument(
        "input_file",
        nargs="?",
        default=None,
        help="Path to IBKR Flex XML export or '-' for stdin",
    )
    p_flex.add_argument(
        "-i",
        "--input",
        default=None,
        help="Optional alias for IBKR Flex XML export path",
    )
    _add_common_verify_options(p_flex)
    p_flex.set_defaults(handler=_cmd_verify_flex)

    p_csv = sub.add_parser(
        "verify-csv",
        help="Verify an offline brokerage CSV export (DEGIRO, Robinhood, or Charles Schwab)",
    )
    p_csv.add_argument(
        "input_file",
        nargs="?",
        default=None,
        help="Path to offline CSV export or '-' for stdin",
    )
    p_csv.add_argument(
        "-i",
        "--input",
        default=None,
        help="Optional alias for offline CSV export path",
    )
    p_csv.add_argument(
        "--format",
        choices=("auto", "degiro", "robinhood", "schwab"),
        default="auto",
        help="CSV statement format (defaults to auto-detect)",
    )
    p_csv.add_argument(
        "--base-currency",
        default=None,
        help="Optional base currency code override (e.g. EUR or USD)",
    )
    p_csv.add_argument("--degiro-account-csv", default=None, help="DEGIRO Account.csv path")
    p_csv.add_argument(
        "--degiro-transactions-csv", default=None, help="DEGIRO Transactions.csv path"
    )
    p_csv.add_argument("--degiro-portfolio-csv", default=None, help="DEGIRO Portfolio.csv path")
    _add_common_verify_options(p_csv)
    p_csv.set_defaults(handler=_cmd_verify_csv)

    p_check = sub.add_parser(
        "check-bundle",
        help="Cryptographically verify a .verify.json proof bundle offline",
    )
    p_check.add_argument("bundle_file", help="Path to .verify.json bundle or '-' for stdin")
    p_check.add_argument(
        "--registry",
        default=None,
        help="Optional path to n170-specimen-keys.json publisher & notary registry",
    )
    p_check.add_argument(
        "--now-utc",
        default=None,
        help="Optional ISO-8601 UTC reference timestamp for chain freshness checks",
    )
    p_check.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional path to write verification report JSON (defaults to stdout)",
    )
    p_check.set_defaults(handler=_cmd_check_bundle)

    p_keygen = sub.add_parser(
        "keygen",
        help="Generate an Ed25519 publisher signing keypair in memory without writing disk files",
    )
    p_keygen.add_argument("--kid", default=None, help="Optional publisher_kid label")
    p_keygen.add_argument("--issuer-org", default="Self-Hosted", help="Issuer organization label")
    p_keygen.add_argument(
        "--public-only",
        action="store_true",
        help="Omit private_key_hex from JSON output",
    )
    p_keygen.add_argument("-o", "--output", default=None, help="Optional JSON output path")
    p_keygen.set_defaults(handler=_cmd_keygen)

    p_caps = sub.add_parser(
        "capabilities",
        help="Print supported connectors, Merkle leaves, assurance axes, and crypto backend",
    )
    p_caps.add_argument("-o", "--output", default=None, help="Optional JSON output path")
    p_caps.set_defaults(handler=_cmd_capabilities)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2

    try:
        return int(args.handler(args))
    except PaperOrSandboxAccountRejectedError as exc:
        sys.stderr.write(
            json.dumps({"error": "paper_or_sandbox_rejected", "detail": str(exc)}) + "\n"
        )
        return 2
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(json.dumps({"error": "cli_error", "detail": str(exc)}) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
