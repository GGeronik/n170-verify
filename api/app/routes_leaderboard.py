"""Opt-in verified performance leaderboard filtered by Merkle-proven capital brackets."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from app.badges import (
    extract_verified_capital_bracket,
    extract_verified_reconciliation_status,
    finite_real_number,
    verified_leaf_payload,
)
from app.store import ProofStore
from n170_verify.contracts import (
    AccountScope,
    CapitalBracket,
    ChainContinuityMode,
    OriginAssurance,
    ReconciliationStatus,
    VerifyProofBundle,
)


_EnumT = TypeVar("_EnumT")

CAPITAL_BRACKET_RANK: dict[CapitalBracket, int] = {
    CapitalBracket.UNDER_1K: 0,
    CapitalBracket.BRACKET_1K_10K: 1,
    CapitalBracket.BRACKET_10K_100K: 2,
    CapitalBracket.BRACKET_100K_1M: 3,
    CapitalBracket.OVER_1M: 4,
}

_EXCLUDED_SIMULATION_METRIC_KEYS = frozenset(
    {"counterfactual_twin", "bootstrap_summary", "is_hypothetical_simulation"}
)


def _extract_merkle_proven_core_metrics(bundle: VerifyProofBundle) -> dict[str, Any]:
    payload = verified_leaf_payload(bundle, "core_metrics")
    if not isinstance(payload, Mapping):
        return {}
    return {k: v for k, v in payload.items() if k not in _EXCLUDED_SIMULATION_METRIC_KEYS}


def _parse_enum_csv_filter(
    query_params: Mapping[str, str], key: str, enum_cls: type[_EnumT]
) -> set[_EnumT] | None:
    raw = query_params.get(key)
    if not raw:
        return None
    return {enum_cls(part.strip()) for part in raw.split(",") if part.strip()}


def handle_get_leaderboard(
    query_params: Mapping[str, str],
    *,
    store: ProofStore,
) -> tuple[int, dict[str, Any]]:
    """Serve ``GET /api/v1/leaderboard`` filtered by verifier-computed assurance & Merkle-proven capital bracket."""
    min_bracket_str = query_params.get(
        "min_capital_bracket", CapitalBracket.BRACKET_10K_100K.value
    ).strip()
    try:
        min_bracket = CapitalBracket(min_bracket_str)
    except ValueError:
        return 422, {
            "error": "validation_error",
            "detail": f"Invalid min_capital_bracket: {min_bracket_str!r}",
        }

    try:
        origin_filter = _parse_enum_csv_filter(query_params, "origin_assurance", OriginAssurance)
        scope_filter = _parse_enum_csv_filter(query_params, "account_scope", AccountScope)
        continuity_filter = _parse_enum_csv_filter(
            query_params, "continuity_mode", ChainContinuityMode
        )
        recon_filter = _parse_enum_csv_filter(
            query_params, "reconciliation_status", ReconciliationStatus
        )
    except ValueError as exc:
        return 422, {"error": "validation_error", "detail": str(exc)}

    broker_filter = query_params.get("broker_id", "").strip().lower() or None
    now_utc = query_params.get("now_utc")
    try:
        limit = max(1, min(int(query_params.get("limit", "50")), 200))
    except ValueError:
        return 422, {"error": "validation_error", "detail": "limit must be an integer"}

    candidates = store.list_leaderboard_candidates()
    entries: list[dict[str, Any]] = []

    for cand in candidates:
        bundle = cand.bundle
        if broker_filter and bundle.broker_id != broker_filter:
            continue

        verification = store.verify_bundle_against_live_state(bundle, now_utc=now_utc)
        if not verification.valid:
            continue

        # Filter strictly on verifier-computed assurance axes (never raw claimed_origin_assurance)
        if origin_filter and verification.effective_origin_assurance not in origin_filter:
            continue
        if scope_filter and verification.assurance_profile.account_scope not in scope_filter:
            continue
        if (
            continuity_filter
            and verification.effective_chain_continuity_mode not in continuity_filter
        ):
            continue

        proven_bracket = extract_verified_capital_bracket(bundle)
        if proven_bracket is None:
            continue
        if CAPITAL_BRACKET_RANK[proven_bracket] < CAPITAL_BRACKET_RANK[min_bracket]:
            continue

        recon_str = extract_verified_reconciliation_status(bundle)
        recon_status = (
            ReconciliationStatus(recon_str)
            if recon_str not in {"undisclosed", "invalid_status"}
            else None
        )
        if recon_filter and recon_status not in recon_filter:
            continue

        metrics = _extract_merkle_proven_core_metrics(bundle)
        twr_dec = finite_real_number(metrics.get("twr_decimal"))
        twr_pct = finite_real_number(metrics.get("twr_pct"))
        obs_raw = metrics.get("observation_count")
        obs_count = (
            int(obs_raw)
            if isinstance(obs_raw, int) and not isinstance(obs_raw, bool) and obs_raw >= 0
            else 0
        )
        elig_raw = metrics.get("psr_sample_eligible")
        psr_eligible = bool(elig_raw) if isinstance(elig_raw, bool) else (obs_count >= 30)
        raw_psr = (
            metrics.get("psr_glm_unsmoothed")
            if metrics.get("psr_glm_unsmoothed") is not None
            else metrics.get("probabilistic_sharpe_ratio")
        )
        psr_cand = finite_real_number(raw_psr)
        psr_val = (
            psr_cand
            if psr_eligible and obs_count >= 30 and psr_cand is not None and 0.0 <= psr_cand <= 1.0
            else None
        )
        max_dd_dec = finite_real_number(metrics.get("max_drawdown_decimal"))

        entries.append(
            {
                "proof_id": bundle.proof_id,
                "proof_hash": cand.proof_hash,
                "broker_id": bundle.broker_id,
                "blinded_account_tag": bundle.blinded_account_tag,
                "period_start_utc": bundle.period_start_utc,
                "period_end_utc": bundle.period_end_utc,
                "issued_at_utc": bundle.issued_at_utc,
                "effective_origin_assurance": verification.effective_origin_assurance.value,
                "account_scope": verification.assurance_profile.account_scope.value,
                "effective_chain_continuity_mode": (
                    verification.effective_chain_continuity_mode.value
                ),
                "signer_trust_status": verification.signer_trust_status.value,
                "reconciliation_status": recon_status.value if recon_status is not None else None,
                "capital_bracket": proven_bracket.value,
                "twr_decimal": twr_dec,
                "twr_pct": twr_pct,
                "probabilistic_sharpe_ratio": psr_val,
                "max_drawdown_decimal": max_dd_dec,
                "badge_url": f"/api/v1/badges/{bundle.proof_id}.svg",
            }
        )

    entries.sort(
        key=lambda item: (
            item["probabilistic_sharpe_ratio"]
            if item["probabilistic_sharpe_ratio"] is not None
            else -1.0,
            item["twr_decimal"] if item["twr_decimal"] is not None else float("-inf"),
            item["proof_id"],
        ),
        reverse=True,
    )

    sliced = entries[:limit]
    return 200, {
        "filters": {
            "min_capital_bracket": min_bracket.value,
            "origin_assurance": sorted(x.value for x in origin_filter) if origin_filter else None,
            "account_scope": sorted(x.value for x in scope_filter) if scope_filter else None,
            "continuity_mode": (
                sorted(x.value for x in continuity_filter) if continuity_filter else None
            ),
        },
        "count": len(sliced),
        "entries": sliced,
    }


__all__ = [
    "CAPITAL_BRACKET_RANK",
    "handle_get_leaderboard",
]
