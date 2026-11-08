"""Proof registry, dynamic verification, prospective chains, and continuity log routes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.store import (
    ChainResetConflictError,
    ChainViolationError,
    GovernanceBlockedError,
    PaperOrSandboxRejectedError,
    ProofBundleInvalidError,
    ProofNotFoundError,
    ProofStore,
)
from n170_verify.contracts import VerifyProofBundle, validate_hex_digest
from n170_verify.crypto import verify_prospective_chain


def _parse_bundle_from_payload(payload: Mapping[str, Any]) -> VerifyProofBundle:
    raw = payload.get("proof_bundle", payload)
    if not isinstance(raw, Mapping):
        raise ValueError("proof_bundle must be a JSON object")
    return VerifyProofBundle.from_dict(raw)


def handle_post_proof(
    payload: Mapping[str, Any],
    *,
    store: ProofStore,
) -> tuple[int, dict[str, Any]]:
    """Publish an opt-in redacted ``VerifyProofBundle`` via ``POST /api/v1/proofs``."""
    if not isinstance(payload, Mapping):
        return 400, {"error": "invalid_request", "detail": "Request body must be a JSON object"}
    try:
        bundle = _parse_bundle_from_payload(payload)
    except (ValueError, TypeError) as exc:
        return 422, {"error": "validation_error", "detail": str(exc)}

    opt_in_leaderboard = bool(payload.get("opt_in_leaderboard", False))
    now_utc = payload.get("now_utc")
    try:
        stored_bundle, verification = store.store_proof(
            bundle,
            opt_in_leaderboard=opt_in_leaderboard,
            now_utc=now_utc,
        )
    except PaperOrSandboxRejectedError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    except GovernanceBlockedError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    except ProofBundleInvalidError as exc:
        return 422, {"error": "invalid_proof_bundle", "errors": exc.errors}

    return 201, {
        "proof_id": stored_bundle.proof_id,
        "proof_hash": stored_bundle.proof_hash(),
        "proof_bundle": stored_bundle.to_dict(),
        "verification": verification.to_dict(),
    }


def handle_get_proof(
    proof_id: str,
    *,
    store: ProofStore,
) -> tuple[int, dict[str, Any]]:
    """Fetch stored proof and dynamically evaluate assurance via ``GET /api/v1/proofs/{proof_id}``."""
    try:
        entry = store.get_proof_entry(proof_id)
    except ProofNotFoundError:
        return 404, {"error": "proof_not_found", "detail": f"Proof {proof_id!r} not found"}

    verification = store.verify_bundle_against_live_state(entry.bundle)
    return 200, {
        "proof_bundle": entry.bundle.to_dict(),
        "proof_hash": entry.proof_hash,
        "opt_in_leaderboard": entry.opt_in_leaderboard,
        "stored_at_utc": entry.stored_at_utc,
        "verification": verification.to_dict(),
    }


def handle_post_verify_proof(
    payload: Mapping[str, Any],
    *,
    store: ProofStore,
) -> tuple[int, dict[str, Any]]:
    """Dynamically verify a ``VerifyProofBundle`` against registry & continuity log via ``POST /api/v1/proofs/verify``."""
    if not isinstance(payload, Mapping):
        return 400, {"error": "invalid_request", "detail": "Request body must be a JSON object"}

    try:
        bundle = _parse_bundle_from_payload(payload)
        history_raw = payload.get("chain_history")
        chain_history = (
            [VerifyProofBundle.from_dict(item) for item in history_raw]
            if isinstance(history_raw, list)
            else None
        )
        now_utc = payload.get("now_utc")
        result = store.verify_bundle_against_live_state(
            bundle,
            chain_history=chain_history,
            now_utc=now_utc,
        )
    except (ValueError, TypeError) as exc:
        return 422, {"error": "validation_error", "detail": str(exc)}

    return 200, result.to_dict()


def handle_post_enroll_chain(
    payload: Mapping[str, Any],
    *,
    store: ProofStore,
) -> tuple[int, dict[str, Any]]:
    """Enroll genesis prospective chain link via ``POST /api/v1/chains``."""
    if not isinstance(payload, Mapping):
        return 400, {"error": "invalid_request", "detail": "Request body must be a JSON object"}

    try:
        bundle = _parse_bundle_from_payload(payload)
    except (ValueError, TypeError) as exc:
        return 422, {"error": "validation_error", "detail": str(exc)}

    opt_in_leaderboard = bool(payload.get("opt_in_leaderboard", False))
    allow_backfill = bool(payload.get("allow_retrospective_backfill", False))
    now_utc = payload.get("now_utc")

    try:
        stored_bundle, log_leaf, chain_res = store.enroll_chain(
            bundle,
            opt_in_leaderboard=opt_in_leaderboard,
            allow_retrospective_backfill=allow_backfill,
            now_utc=now_utc,
        )
    except PaperOrSandboxRejectedError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    except GovernanceBlockedError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    except ChainResetConflictError as exc:
        return exc.http_status, {
            "error": "parallel_chain_reset_detected",
            "continuity_mode": exc.chain_result.continuity_mode.value,
            "violation_codes": [c.value for c in exc.chain_result.violation_codes],
            "details": exc.chain_result.details,
        }
    except ChainViolationError as exc:
        return exc.http_status, {
            "error": "chain_invariant_violation",
            "continuity_mode": exc.chain_result.continuity_mode.value,
            "violation_codes": [c.value for c in exc.chain_result.violation_codes],
            "details": exc.chain_result.details,
        }
    except ProofBundleInvalidError as exc:
        return 422, {"error": "invalid_proof_bundle", "errors": exc.errors}

    checkpoint = store.build_signed_checkpoint()
    return 201, {
        "chain_id": log_leaf.chain_id,
        "sequence_number": log_leaf.sequence_number,
        "proof_id": stored_bundle.proof_id,
        "proof_hash": log_leaf.proof_hash,
        "continuity_mode": chain_res.continuity_mode.value,
        "chain_verification": chain_res.to_dict(),
        "log_leaf": log_leaf.to_dict(),
        "checkpoint": checkpoint.to_dict(),
    }


def handle_post_append_chain(
    chain_id: str,
    payload: Mapping[str, Any],
    *,
    store: ProofStore,
) -> tuple[int, dict[str, Any]]:
    """Append next link to an enrolled chain via ``POST /api/v1/chains/{chain_id}/append``."""
    if not isinstance(payload, Mapping):
        return 400, {"error": "invalid_request", "detail": "Request body must be a JSON object"}

    try:
        bundle = _parse_bundle_from_payload(payload)
    except (ValueError, TypeError) as exc:
        return 422, {"error": "validation_error", "detail": str(exc)}

    opt_in_raw = payload.get("opt_in_leaderboard")
    opt_in_val = None if opt_in_raw is None else bool(opt_in_raw)
    now_utc = payload.get("now_utc")

    try:
        stored_bundle, log_leaf, chain_res = store.append_chain(
            chain_id,
            bundle,
            opt_in_leaderboard=opt_in_val,
            now_utc=now_utc,
        )
    except ProofNotFoundError as exc:
        return 404, {"error": "chain_not_found", "detail": str(exc)}
    except PaperOrSandboxRejectedError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    except GovernanceBlockedError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    except ChainResetConflictError as exc:
        return exc.http_status, {
            "error": "parallel_chain_reset_detected",
            "continuity_mode": exc.chain_result.continuity_mode.value,
            "violation_codes": [c.value for c in exc.chain_result.violation_codes],
            "details": exc.chain_result.details,
        }
    except ChainViolationError as exc:
        return exc.http_status, {
            "error": "chain_invariant_violation",
            "continuity_mode": exc.chain_result.continuity_mode.value,
            "violation_codes": [c.value for c in exc.chain_result.violation_codes],
            "details": exc.chain_result.details,
        }
    except ProofBundleInvalidError as exc:
        return 422, {"error": "invalid_proof_bundle", "errors": exc.errors}

    checkpoint = store.build_signed_checkpoint()
    return 200, {
        "chain_id": log_leaf.chain_id,
        "sequence_number": log_leaf.sequence_number,
        "proof_id": stored_bundle.proof_id,
        "proof_hash": log_leaf.proof_hash,
        "continuity_mode": chain_res.continuity_mode.value,
        "chain_verification": chain_res.to_dict(),
        "log_leaf": log_leaf.to_dict(),
        "checkpoint": checkpoint.to_dict(),
    }


def handle_get_chain(
    chain_id: str,
    *,
    store: ProofStore,
    now_utc: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """Retrieve enrolled chain sequence and live ``ChainVerificationResult`` via ``GET /api/v1/chains/{chain_id}``."""
    try:
        bundles = store.get_chain_bundles(chain_id)
    except ProofNotFoundError as exc:
        return 404, {"error": "chain_not_found", "detail": str(exc)}

    all_leaves = store.list_all_continuity_leaves()
    chain_res = verify_prospective_chain(
        bundles,
        continuity_log_leaves=all_leaves,
        now_utc=now_utc,
    )
    return 200, {
        "chain_id": chain_id,
        "length": len(bundles),
        "proof_ids": [b.proof_id for b in bundles],
        "proof_hashes": [b.proof_hash() for b in bundles],
        "chain_verification": chain_res.to_dict(),
    }


def handle_get_continuity_for_account(
    blinded_account_tag: str,
    *,
    store: ProofStore,
) -> tuple[int, dict[str, Any]]:
    """Serve append-only ``ContinuityLogLeaf`` entries for ``blinded_account_tag`` via ``GET /api/v1/continuity/{blinded_account_tag}``."""
    try:
        norm_tag = validate_hex_digest(
            blinded_account_tag, field_name="blinded_account_tag", num_bytes=32
        )
    except ValueError as exc:
        return 422, {"error": "validation_error", "detail": str(exc)}

    acct_leaves = store.get_continuity_leaves_for_account(norm_tag)
    checkpoint = store.build_signed_checkpoint()
    return 200, {
        "blinded_account_tag": norm_tag,
        "entry_count": len(acct_leaves),
        "entries": [leaf.to_dict() for leaf in acct_leaves],
        "checkpoint": checkpoint.to_dict(),
    }


__all__ = [
    "handle_get_chain",
    "handle_get_continuity_for_account",
    "handle_get_proof",
    "handle_post_append_chain",
    "handle_post_enroll_chain",
    "handle_post_proof",
    "handle_post_verify_proof",
]
