"""Viral distribution, stateless claim plausibility, head-to-head comparison, and auto-detect routes."""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from email.parser import BytesParser
from email.policy import HTTP as EMAIL_HTTP_POLICY
import hashlib
import html
import json
import math
import re
import secrets
from typing import Any
from urllib.parse import quote

from app.badges import (
    extract_verified_capital_bracket,
    extract_verified_reconciliation_status,
    finite_real_number,
    is_safe_xml_char,
    verified_leaf_payload,
)
from app.config import ApiConfig, utc_now_iso
from app.store import (
    GovernanceBlockedError,
    PaperOrSandboxRejectedError,
    ProofBundleInvalidError,
    ProofConflictError,
    ProofNotFoundError,
    ProofStore,
)
from app.worker_isolation import (
    WorkerIsolationError,
    WorkerValidationError,
    run_isolated_one_shot_verification,
)
from n170_verify.coaching import TraderCoachingEngine, match_fifo_round_trips
from n170_verify.connectors import (
    PaperOrSandboxAccountRejectedError,
    detect_and_parse_statement,
    get_ibkr_flex_setup_guide,
)
from n170_verify.contracts import (
    BundleVerificationResult,
    CanonicalPortfolioLedger,
    EnvironmentTier,
    IndexedCurvePoint,
    OriginAssurance,
    ProviderApprovalState,
    ReadOnlyCapabilityViolationError,
    ReconciliationReport,
    ReconciliationStatus,
    VERIFY_SCHEMA_VERSION,
    VerifyProofBundle,
    create_signed_proof_bundle,
    parse_utc_timestamp,
)
from n170_verify.crypto import (
    CANONICAL_LEAF_NAMES,
    build_salted_merkle_tree,
    generate_ed25519_keypair,
)
from n170_verify.performance import (
    calculate_portfolio_performance_detailed,
    evaluate_claim_plausibility,
)
from n170_verify.pipeline import build_canonical_leaf_payloads
from n170_verify.reconciliation import reconcile_portfolio_ledger
from n170_verify.reference import build_reference_provider


MAX_PLAUSIBILITY_BODY_BYTES = 65_536
MAX_STATEMENT_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_MULTIPART_PARTS = 16

EMBED_METADATA_HEADERS: dict[str, str] = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors *",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store, max-age=0",
    "Access-Control-Allow-Origin": "*",
}

_VALID_VS_PROOF_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DANGEROUS_SCHEME_RE = re.compile(r"(?:javascript|vbscript|data)\s*:", re.IGNORECASE)
_DANGEROUS_EVENT_ATTR_RE = re.compile(r"\bon[a-z0-9_]+\s*=", re.IGNORECASE)
_HTML_TAG_RE = re.compile(r"<[^>]*>")
_DISCORD_MASS_MENTION_RE = re.compile(r"@(everyone|here)\b", re.IGNORECASE)
_CURRENCY_AMOUNT_TOKEN_RE = re.compile(
    r"(?:[$€£¥]\s*[-+]?\d[\d,.]*|\b(?:USD|EUR|GBP|CAD|CHF|JPY|AUD)\s*[-+]?\d[\d,.]*)",
    re.IGNORECASE,
)
_LONG_DIGIT_RUN_RE = re.compile(r"\b\d{5,}\b")


class _PlausibilityInputError(ValueError):
    """Raised when plausibility calculator inputs violate bounds or type rules."""

    def __init__(self, message: str, *, status_code: int = 422) -> None:
        super().__init__(message)
        self.status_code = status_code


def sanitize_public_label(raw: Any, *, max_len: int = 64) -> str:
    """Strip XSS vectors, HTML delimiters, quotes, and control chars, then HTML-escape."""
    if raw is None:
        return ""
    cleaned = "".join(ch for ch in str(raw) if is_safe_xml_char(ch))
    cleaned = _HTML_TAG_RE.sub(" ", cleaned)
    cleaned = _DANGEROUS_SCHEME_RE.sub("", cleaned)
    cleaned = _DANGEROUS_EVENT_ATTR_RE.sub("", cleaned)
    cleaned = _DISCORD_MASS_MENTION_RE.sub(r"\1", cleaned)
    for forbidden_ch in ("<", ">", '"', "'", "`", "\\"):
        cleaned = cleaned.replace(forbidden_ch, "")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len].rstrip()
    return html.escape(cleaned, quote=True)


def sanitize_markdown_text(raw: Any, *, max_len: int = 96) -> str:
    """Sanitize free-text strings for Discord/Telegram embeds (zero XSS or link injection)."""
    base = sanitize_public_label(raw, max_len=max_len)
    for md_ch in ("[", "]", "(", ")", "*", "_", "~", "|"):
        base = base.replace(md_ch, "")
    return base.strip()


def sanitize_journal_tag(raw: Any, *, max_len: int = 48) -> str | None:
    """Sanitize an imported trade-journal setup/mistake tag (zero $ amounts or account IDs)."""
    if raw is None:
        return None
    text = "".join(ch for ch in str(raw) if is_safe_xml_char(ch))
    text = _CURRENCY_AMOUNT_TOKEN_RE.sub("", text)
    text = _LONG_DIGIT_RUN_RE.sub("", text)
    text = text.replace("$", "").replace("€", "").replace("£", "")
    safe = sanitize_public_label(text, max_len=max_len)
    safe = safe.lstrip("=+-@'| \t\r\n").strip()
    return safe if safe else None


def _reject_json_nonfinite_constant(token: str) -> Any:
    raise _PlausibilityInputError(
        f"Non-finite JSON numeric constant {token!r} is prohibited",
        status_code=422,
    )


def _parse_strict_int(
    payload: Mapping[str, Any],
    keys: Sequence[str],
    *,
    required: bool,
    default: int | None = None,
    low: int,
    high: int,
    label: str,
) -> int:
    found_vals: list[tuple[str, Any]] = [
        (k, payload[k]) for k in keys if k in payload and payload[k] is not None
    ]
    if not found_vals:
        if required or default is None:
            raise _PlausibilityInputError(f"{label} is required", status_code=422)
        return default

    primary_key, raw_val = found_vals[0]
    if isinstance(raw_val, bool) or not isinstance(raw_val, int):
        raise _PlausibilityInputError(
            f"{primary_key} must be an integer (booleans, floats, and strings are rejected)",
            status_code=422,
        )
    for other_key, other_val in found_vals[1:]:
        if isinstance(other_val, bool) or not isinstance(other_val, int) or other_val != raw_val:
            raise _PlausibilityInputError(
                f"Conflicting or invalid alias {other_key} alongside {primary_key}",
                status_code=422,
            )

    if raw_val < low or raw_val > high:
        raise _PlausibilityInputError(
            f"{label} must be in [{low}, {high}] (got {raw_val})",
            status_code=422,
        )
    return int(raw_val)


def _parse_strict_float(
    payload: Mapping[str, Any],
    key: str,
    *,
    required: bool,
    default: float | None = None,
    low: float,
    high: float,
) -> float:
    if key not in payload or payload[key] is None:
        if required or default is None:
            raise _PlausibilityInputError(f"{key} is required", status_code=422)
        return default

    raw_val = payload[key]
    if isinstance(raw_val, bool) or not isinstance(raw_val, (int, float)):
        raise _PlausibilityInputError(
            f"{key} must be a finite number (booleans and non-numeric values are rejected)",
            status_code=422,
        )
    try:
        fval = float(raw_val)
    except OverflowError as exc:
        raise _PlausibilityInputError(
            f"{key} overflows IEEE-754 floating-point range",
            status_code=422,
        ) from exc

    if not math.isfinite(fval) or abs(fval) >= 1e308:
        raise _PlausibilityInputError(
            f"{key} must be finite and within bounds",
            status_code=422,
        )
    if fval < low or fval > high:
        raise _PlausibilityInputError(
            f"{key} must be in [{low}, {high}] (got {fval})",
            status_code=422,
        )
    return 0.0 if fval == 0.0 else fval


# ---------------------------------------------------------------------------
# 1. POST /api/v1/tools/plausibility
# ---------------------------------------------------------------------------


def handle_post_plausibility(
    raw_body_or_payload: bytes | Mapping[str, Any],
) -> tuple[int, dict[str, Any]]:
    """Stateless public claim plausibility endpoint with strict DoS & numeric bounds."""
    if isinstance(raw_body_or_payload, (bytes, bytearray)):
        raw_bytes = bytes(raw_body_or_payload)
        if len(raw_bytes) > MAX_PLAUSIBILITY_BODY_BYTES:
            return 400, {
                "error": "payload_too_large",
                "detail": f"Request body exceeds {MAX_PLAUSIBILITY_BODY_BYTES} bytes",
            }
        if not raw_bytes.strip():
            return 400, {
                "error": "invalid_request",
                "detail": "JSON object body is required",
            }
        try:
            parsed = json.loads(
                raw_bytes.decode("utf-8"),
                parse_constant=_reject_json_nonfinite_constant,
            )
        except _PlausibilityInputError as exc:
            return exc.status_code, {"error": "validation_error", "detail": str(exc)}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return 400, {"error": "invalid_json", "detail": f"Malformed JSON body: {exc}"}
    else:
        parsed = raw_body_or_payload

    if not isinstance(parsed, Mapping):
        return 400, {
            "error": "invalid_request",
            "detail": "Request body must be a JSON object",
        }
    if len(parsed) > 32:
        return 400, {
            "error": "invalid_request",
            "detail": "Too many fields in plausibility request object",
        }

    try:
        observed_periods = _parse_strict_int(
            parsed,
            ("observed_periods", "T"),
            required=True,
            low=2,
            high=25_000,
            label="observed_periods",
        )
        claimed_sharpe = _parse_strict_float(
            parsed,
            "claimed_sharpe",
            required=True,
            low=-20.0,
            high=50.0,
        )
        benchmark_sharpe = _parse_strict_float(
            parsed,
            "benchmark_sharpe",
            required=False,
            default=0.0,
            low=-10.0,
            high=20.0,
        )
        skewness = _parse_strict_float(
            parsed,
            "skewness",
            required=False,
            default=0.0,
            low=-10.0,
            high=10.0,
        )
        excess_kurtosis = _parse_strict_float(
            parsed,
            "excess_kurtosis",
            required=False,
            default=3.0,
            low=-2.0,
            high=50.0,
        )
        annualization_factor = _parse_strict_int(
            parsed,
            ("annualization_factor",),
            required=False,
            default=252,
            low=1,
            high=10_000,
            label="annualization_factor",
        )
        analysis = evaluate_claim_plausibility(
            claimed_sharpe,
            observed_periods,
            annualization_factor=annualization_factor,
            skewness=skewness,
            excess_kurtosis=excess_kurtosis,
            benchmark_sharpe=benchmark_sharpe,
        )
    except _PlausibilityInputError as exc:
        return exc.status_code, {"error": "validation_error", "detail": str(exc)}
    except (ValueError, TypeError, ArithmeticError, OverflowError) as exc:
        return 422, {"error": "validation_error", "detail": str(exc)}

    return 200, analysis.to_dict()


# ---------------------------------------------------------------------------
# Verified Leaf Extraction Helpers (Strictly Realized Metrics Only!)
# ---------------------------------------------------------------------------


def _extract_realized_metrics_strict(bundle: VerifyProofBundle) -> dict[str, Any]:
    """Extract strictly realized verified metrics from ``core_metrics`` leaf.

    Explicitly ignores ``bootstrap_summary``, ``counterfactual_twin``, and any
    hypothetical/simulated fields so simulated curves can NEVER masquerade as realized returns.
    """
    payload = verified_leaf_payload(bundle, "core_metrics")
    if not isinstance(payload, Mapping):
        return {
            "disclosed": False,
            "twr": None,
            "twr_decimal": None,
            "twr_pct": None,
            "xirr": None,
            "xirr_decimal": None,
            "cagr": None,
            "cagr_decimal": None,
            "cagr_pct": None,
            "max_drawdown": None,
            "max_drawdown_decimal": None,
            "max_drawdown_pct": None,
            "sharpe_ratio": None,
            "psr": None,
            "psr_display": "Undisclosed",
            "psr_sample_eligible": False,
            "observation_count": 0,
        }

    # Guard: strip/ignore any hypothetical or bootstrap sub-objects if present in leaf dict
    twr_dec = finite_real_number(payload.get("twr_decimal"))
    twr_pct = finite_real_number(payload.get("twr_pct"))
    if twr_dec is None and twr_pct is not None:
        twr_dec = round(twr_pct / 100.0, 8)
    elif twr_pct is None and twr_dec is not None:
        twr_pct = round(twr_dec * 100.0, 8)

    xirr_dec = finite_real_number(payload.get("xirr_decimal"))
    cagr_dec = finite_real_number(payload.get("cagr_decimal"))
    cagr_pct = finite_real_number(payload.get("cagr_pct"))
    if cagr_pct is None and cagr_dec is not None:
        cagr_pct = round(cagr_dec * 100.0, 8)

    max_dd_dec = finite_real_number(payload.get("max_drawdown_decimal"))
    max_dd_pct = finite_real_number(payload.get("max_drawdown_pct"))
    if max_dd_dec is None and max_dd_pct is not None:
        max_dd_dec = round(max_dd_pct / 100.0, 8)
    elif max_dd_pct is None and max_dd_dec is not None:
        max_dd_pct = round(max_dd_dec * 100.0, 8)

    obs_raw = payload.get("observation_count")
    obs_count = (
        int(obs_raw)
        if isinstance(obs_raw, int) and not isinstance(obs_raw, bool) and obs_raw >= 0
        else 0
    )
    eligible_raw = payload.get("psr_sample_eligible")
    psr_eligible = bool(eligible_raw) if isinstance(eligible_raw, bool) else (obs_count >= 30)
    if obs_count < 30:
        psr_eligible = False

    psr_candidate = (
        payload.get("psr_glm_unsmoothed")
        if payload.get("psr_glm_unsmoothed") is not None
        else payload.get("probabilistic_sharpe_ratio")
    )
    psr_num = finite_real_number(psr_candidate)
    if psr_eligible and obs_count >= 30 and psr_num is not None and 0.0 <= psr_num <= 1.0:
        psr_val: float | None = psr_num
        psr_display = f"{psr_num * 100.0:.1f}%"
    elif obs_count < 30:
        psr_val = None
        psr_display = "Insufficient N (<30)"
    else:
        psr_val = None
        psr_display = "Undisclosed"

    sharpe_val = finite_real_number(payload.get("unsmoothed_sharpe_ratio"))
    if sharpe_val is None:
        sharpe_val = finite_real_number(payload.get("sharpe_ratio"))

    return {
        "disclosed": True,
        "twr": twr_dec,
        "twr_decimal": twr_dec,
        "twr_pct": twr_pct,
        "xirr": xirr_dec,
        "xirr_decimal": xirr_dec,
        "cagr": cagr_dec,
        "cagr_decimal": cagr_dec,
        "cagr_pct": cagr_pct,
        "max_drawdown": max_dd_dec,
        "max_drawdown_decimal": max_dd_dec,
        "max_drawdown_pct": max_dd_pct,
        "sharpe_ratio": sharpe_val,
        "psr": psr_val,
        "psr_display": psr_display,
        "psr_sample_eligible": psr_eligible,
        "observation_count": obs_count,
    }


def _extract_verified_curve_points(bundle: VerifyProofBundle) -> list[IndexedCurvePoint]:
    """Extract verified 100-rebased wealth & underwater points from ``indexed_curve`` leaf."""
    payload = verified_leaf_payload(bundle, "indexed_curve")
    raw_points: Sequence[Any] | None = None
    if isinstance(payload, list):
        raw_points = payload
    elif isinstance(payload, Mapping) and isinstance(payload.get("points"), list):
        raw_points = payload["points"]
    if not raw_points:
        return []

    points: list[IndexedCurvePoint] = []
    for item in raw_points:
        if not isinstance(item, Mapping):
            continue
        # Reject any hypothetical twin curve object if ever mis-placed
        if "zero_friction_ending_index" in item or "is_hypothetical_simulation" in item:
            continue
        try:
            points.append(IndexedCurvePoint.from_dict(item))
        except (ValueError, TypeError):
            continue

    points.sort(key=lambda pt: parse_utc_timestamp(pt.timestamp_utc))
    if points and abs(points[0].index_value - 100.0) > 1e-4:
        return []
    return points


def _build_synchronized_series(
    points_a: Sequence[IndexedCurvePoint],
    points_b: Sequence[IndexedCurvePoint],
) -> dict[str, Any]:
    """Synchronize two disclosed wealth curves onto their overlapping UTC window (rebased to 100.0)."""
    if len(points_a) < 2 or len(points_b) < 2:
        return {
            "disclosed": False,
            "overlap": False,
            "overlap_start_utc": None,
            "overlap_end_utc": None,
            "points": [],
            "wealth_series": [],
            "underwater_series": [],
        }

    dated_a = [(parse_utc_timestamp(p.timestamp_utc), p) for p in points_a]
    dated_b = [(parse_utc_timestamp(p.timestamp_utc), p) for p in points_b]
    overlap_start = max(dated_a[0][0], dated_b[0][0])
    overlap_end = min(dated_a[-1][0], dated_b[-1][0])

    if overlap_end <= overlap_start:
        return {
            "disclosed": True,
            "overlap": False,
            "overlap_start_utc": None,
            "overlap_end_utc": None,
            "points": [],
            "wealth_series": [],
            "underwater_series": [],
        }

    in_a = [(dt, p) for dt, p in dated_a if overlap_start <= dt <= overlap_end]
    in_b = [(dt, p) for dt, p in dated_b if overlap_start <= dt <= overlap_end]
    if not in_a or not in_b:
        return {
            "disclosed": True,
            "overlap": False,
            "overlap_start_utc": None,
            "overlap_end_utc": None,
            "points": [],
            "wealth_series": [],
            "underwater_series": [],
        }

    # Build date-keyed lookup (YYYY-MM-DD) preserving latest observation per day
    by_day_a: dict[str, tuple[str, float]] = {}
    for dt, p in in_a:
        day_key = dt.strftime("%Y-%m-%d")
        by_day_a[day_key] = (p.timestamp_utc, p.index_value)

    by_day_b: dict[str, tuple[str, float]] = {}
    for dt, p in in_b:
        day_key = dt.strftime("%Y-%m-%d")
        by_day_b[day_key] = (p.timestamp_utc, p.index_value)

    all_days = sorted(set(by_day_a.keys()) | set(by_day_b.keys()))
    first_val_a = in_a[0][1].index_value
    first_val_b = in_b[0][1].index_value
    last_a = first_val_a
    last_b = first_val_b
    peak_a = 100.0
    peak_b = 100.0

    combined_points: list[dict[str, Any]] = []
    wealth_series: list[dict[str, Any]] = []
    underwater_series: list[dict[str, Any]] = []

    for day in all_days:
        ts_iso = f"{day}T00:00:00Z"
        if day in by_day_a:
            ts_iso, last_a = by_day_a[day]
        if day in by_day_b:
            ts_b, last_b = by_day_b[day]
            if day not in by_day_a:
                ts_iso = ts_b

        reb_a = round(100.0 * (last_a / first_val_a), 6)
        reb_b = round(100.0 * (last_b / first_val_b), 6)
        peak_a = max(peak_a, reb_a)
        peak_b = max(peak_b, reb_b)
        dd_a = min(0.0, round(((reb_a - peak_a) / peak_a) * 100.0, 6))
        dd_b = min(0.0, round(((reb_b - peak_b) / peak_b) * 100.0, 6))

        combined_points.append(
            {
                "date": day,
                "timestamp_utc": ts_iso,
                "wealth_a": reb_a,
                "wealth_b": reb_b,
                "underwater_pct_a": dd_a,
                "underwater_pct_b": dd_b,
            }
        )
        wealth_series.append(
            {
                "date": day,
                "timestamp_utc": ts_iso,
                "proof_a_index": reb_a,
                "proof_b_index": reb_b,
            }
        )
        underwater_series.append(
            {
                "date": day,
                "timestamp_utc": ts_iso,
                "proof_a_drawdown_pct": dd_a,
                "proof_b_drawdown_pct": dd_b,
            }
        )

    return {
        "disclosed": True,
        "overlap": True,
        "overlap_start_utc": overlap_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "overlap_end_utc": overlap_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "points": combined_points,
        "wealth_series": wealth_series,
        "underwater_series": underwater_series,
    }


def _build_vs_summary_card(
    bundle: VerifyProofBundle,
    verification: BundleVerificationResult,
) -> tuple[dict[str, Any], list[IndexedCurvePoint]]:
    recon_status = extract_verified_reconciliation_status(bundle)
    cap_bracket_enum = extract_verified_capital_bracket(bundle)
    cap_bracket = cap_bracket_enum.value if cap_bracket_enum is not None else None
    metrics = _extract_realized_metrics_strict(bundle)
    curve_pts = _extract_verified_curve_points(bundle)

    card = {
        "bundle_id": bundle.proof_id,
        "proof_id": bundle.proof_id,
        "proof_hash": verification.proof_hash,
        "merkle_root": bundle.merkle_root,
        "broker_id": bundle.broker_id,
        "base_currency": bundle.base_currency,
        "period_start_utc": bundle.period_start_utc,
        "period_end_utc": bundle.period_end_utc,
        "issued_at_utc": bundle.issued_at_utc,
        # Dynamically verified 4+1 orthogonal trust axes (NEVER self-asserted claimed_origin_assurance)
        "origin_assurance": verification.effective_origin_assurance.value,
        "signer_trust": verification.signer_trust_status.value,
        "reconciliation_status": recon_status,
        "account_scope": verification.assurance_profile.account_scope.value,
        "continuity_mode": verification.effective_chain_continuity_mode.value,
        "capital_bracket": cap_bracket,
        # Strictly realized verified metrics
        "twr": metrics["twr"],
        "twr_decimal": metrics["twr_decimal"],
        "twr_pct": metrics["twr_pct"],
        "xirr": metrics["xirr"],
        "xirr_decimal": metrics["xirr_decimal"],
        "cagr": metrics["cagr"],
        "cagr_decimal": metrics["cagr_decimal"],
        "cagr_pct": metrics["cagr_pct"],
        "max_drawdown": metrics["max_drawdown"],
        "max_drawdown_decimal": metrics["max_drawdown_decimal"],
        "max_drawdown_pct": metrics["max_drawdown_pct"],
        "sharpe_ratio": metrics["sharpe_ratio"],
        "psr": metrics["psr"],
        "psr_display": metrics["psr_display"],
        "psr_sample_eligible": metrics["psr_sample_eligible"],
        "observation_count": metrics["observation_count"],
        "wealth_series": [pt.to_dict() for pt in curve_pts] if curve_pts else None,
    }
    return card, curve_pts


# ---------------------------------------------------------------------------
# 2. GET /api/v1/vs/{proof_a}/{proof_b}
# ---------------------------------------------------------------------------


def validate_comparison_proof_id(proof_id: str) -> bool:
    """Validate path-segment proof IDs for ``/api/v1/vs/{proof_a}/{proof_b}``."""
    if not isinstance(proof_id, str) or not proof_id:
        return False
    if ".." in proof_id or not _VALID_VS_PROOF_ID_RE.match(proof_id):
        return False
    return True


def handle_get_head_to_head(
    proof_a_id: str,
    proof_b_id: str,
    *,
    store: ProofStore,
    now_utc: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """Serve ``GET /api/v1/vs/{proof_a}/{proof_b}`` with live C2SP re-verification on both sides."""
    if not validate_comparison_proof_id(proof_a_id):
        return 400, {
            "error": "invalid_proof_id",
            "detail": "proof_a contains invalid or unsafe characters",
        }
    if not validate_comparison_proof_id(proof_b_id):
        return 400, {
            "error": "invalid_proof_id",
            "detail": "proof_b contains invalid or unsafe characters",
        }

    try:
        entry_a = store.get_proof_entry(proof_a_id)
    except ProofNotFoundError:
        return 404, {
            "error": "proof_not_found",
            "detail": f"Proof {proof_a_id!r} not found",
        }
    try:
        entry_b = store.get_proof_entry(proof_b_id)
    except ProofNotFoundError:
        return 404, {
            "error": "proof_not_found",
            "detail": f"Proof {proof_b_id!r} not found",
        }

    ver_a = store.verify_bundle_against_live_state(entry_a.bundle, now_utc=now_utc)
    ver_b = store.verify_bundle_against_live_state(entry_b.bundle, now_utc=now_utc)
    if not ver_a.valid or not ver_b.valid:
        failed_ids: list[str] = []
        if not ver_a.valid:
            failed_ids.append(entry_a.bundle.proof_id)
        if not ver_b.valid:
            failed_ids.append(entry_b.bundle.proof_id)
        return 422, {
            "error": "proof_verification_failed",
            "detail": "One or both proofs failed live cryptographic or continuity verification",
            "failed_proof_ids": failed_ids,
            "proof_a_errors": ver_a.errors,
            "proof_b_errors": ver_b.errors,
        }

    card_a, curve_a = _build_vs_summary_card(entry_a.bundle, ver_a)
    card_b, curve_b = _build_vs_summary_card(entry_b.bundle, ver_b)
    sync_series = _build_synchronized_series(curve_a, curve_b)

    warnings: list[str] = []
    if (
        card_a["period_start_utc"] != card_b["period_start_utc"]
        or card_a["period_end_utc"] != card_b["period_end_utc"]
    ):
        if not sync_series["overlap"] and curve_a and curve_b:
            warnings.append(
                f"Non-overlapping measurement periods ({card_a['period_start_utc']}..{card_a['period_end_utc']} "
                f"vs {card_b['period_start_utc']}..{card_b['period_end_utc']}); "
                "market regime differences prevent direct head-to-head return comparison."
            )
        else:
            warnings.append(
                f"Measurement periods differ ({card_a['period_start_utc']}..{card_a['period_end_utc']} "
                f"vs {card_b['period_start_utc']}..{card_b['period_end_utc']})."
            )

    for field_key, label in (
        ("origin_assurance", "Asymmetric origin assurance"),
        ("account_scope", "Asymmetric subaccount survivorship scope"),
        ("reconciliation_status", "Different accounting reconciliation statuses"),
        ("signer_trust", "Different publisher signer trust tiers"),
        ("continuity_mode", "Different prospective continuity modes"),
        ("base_currency", "Different valuation base currencies"),
    ):
        if card_a[field_key] != card_b[field_key]:
            warnings.append(f"{label}: {card_a[field_key]} vs {card_b[field_key]}.")
    if card_a["capital_bracket"] != card_b["capital_bracket"]:
        warnings.append(
            f"Different disclosed capital brackets: {card_a['capital_bracket'] or 'undisclosed'} "
            f"vs {card_b['capital_bracket'] or 'undisclosed'}."
        )
    if not card_a["psr_sample_eligible"] or not card_b["psr_sample_eligible"]:
        warnings.append(
            "Probabilistic Sharpe Ratio (PSR) is withheld for one or both proofs under the T >= 30 observation gate."
        )

    return 200, {
        "schema_version": VERIFY_SCHEMA_VERSION,
        "realized_metrics_only": True,
        "proof_a": card_a,
        "proof_b": card_b,
        "synchronized_series": sync_series,
        "comparability_warnings": warnings,
    }


# ---------------------------------------------------------------------------
# 3. GET /api/v1/challenge-card
# ---------------------------------------------------------------------------


def _parse_optional_query_float(
    query_params: Mapping[str, str],
    key: str,
    *,
    low: float,
    high: float,
) -> float | None:
    raw = query_params.get(key)
    if raw is None or not raw.strip():
        return None
    try:
        val = float(raw.strip())
    except ValueError as exc:
        raise _PlausibilityInputError(f"{key} must be a finite number", status_code=422) from exc
    if not math.isfinite(val) or val < low or val > high:
        raise _PlausibilityInputError(
            f"{key} must be finite and within [{low}, {high}]",
            status_code=422,
        )
    return round(0.0 if val == 0.0 else val, 4)


def handle_get_challenge_card(
    query_params: Mapping[str, str],
) -> tuple[int, dict[str, Any], dict[str, str]]:
    """Serve polite, XSS-escaped zero-NAV-leakage verification invitation payload."""
    try:
        claimed_ret = _parse_optional_query_float(
            query_params,
            "claimed_return_pct",
            low=-100.0,
            high=1_000_000.0,
        )
        claimed_sr = _parse_optional_query_float(
            query_params,
            "claimed_sharpe",
            low=-20.0,
            high=50.0,
        )
    except _PlausibilityInputError as exc:
        return exc.status_code, {"error": "validation_error", "detail": str(exc)}, dict(EMBED_METADATA_HEADERS)

    safe_handle = sanitize_public_label(query_params.get("handle"), max_len=64)
    safe_period = sanitize_public_label(query_params.get("period_label"), max_len=64)

    display_target = safe_handle if safe_handle else "Trader"
    claim_fragments: list[str] = []
    if claimed_ret is not None:
        claim_fragments.append(f"{claimed_ret:+.2f}% return")
    if claimed_sr is not None:
        claim_fragments.append(f"{claimed_sr:.2f} Sharpe")
    if safe_period:
        claim_fragments.append(f"({safe_period})")
    claim_clause = f" for {' '.join(claim_fragments)}" if claim_fragments else ""

    headline = f"Polite Verification Invite for {display_target}"
    invitation_message = (
        f"Hi {display_target} - impressive track record{claim_clause}! "
        "If you'd like to share a cryptographic percentage-only proof, you can generate an "
        "Ed25519-signed N170 Verify bundle in under 60 seconds while keeping your exact dollar "
        "NAV (salted RFC 6962 Merkle leaves & 100-rebased curve), raw account_id (HMAC-SHA256 "
        "blinded), and live open positions (7-day delayed disclosure guard) private."
    )
    social_reply_text = (
        f"Nice run {display_target}{claim_clause}! Want to mint a 60-second cryptographic % TWR "
        "proof on N170 Verify? Exact $ NAV, raw account_id (HMAC-SHA256 blinded), and live open "
        "positions (7-day delayed guard) stay private via salted RFC 6962 Merkle leaves."
    )

    payload: dict[str, Any] = {
        "handle": safe_handle or None,
        "period_label": safe_period or None,
        "claimed_return_pct": claimed_ret,
        "claimed_sharpe": claimed_sr,
        "headline": headline,
        "invitation_message": invitation_message,
        "social_reply_text": social_reply_text,
        "estimated_verification_seconds": 60,
        "non_defamatory": True,
        "verify_url": "https://verify.example.org/verify",
        "privacy_guarantees": {
            "dollar_nav_private": (
                "Private by design: raw dollar balances never leave the ephemeral worker; "
                "curves rebase to 100.0 and optional leaves use 256-bit salted RFC 6962 Merkle commitments."
            ),
            "account_id_private": (
                "Private by design: raw brokerage account_id is blinded via domain-separated HMAC-SHA256."
            ),
            "open_positions_private": (
                "Private by design: live open positions are excluded and closed trades younger than "
                "7 days are stripped by the delayed disclosure front-running guard."
            ),
        },
    }
    return 200, payload, dict(EMBED_METADATA_HEADERS)


# ---------------------------------------------------------------------------
# 4. GET /api/v1/proofs/{proof_id}/discord-embed & /qr-payload
# ---------------------------------------------------------------------------


def _has_unsafe_control_chars(value: str) -> bool:
    return any(not is_safe_xml_char(ch) for ch in value)


def _embed_color_int(origin: OriginAssurance) -> int:
    if origin == OriginAssurance.BROKER_SIGNED:
        return 0x047857
    if origin == OriginAssurance.INDEPENDENTLY_WITNESSED_TLS:
        return 0x0F766E
    if origin == OriginAssurance.OPERATOR_RETRIEVED:
        return 0x1D4ED8
    return 0x475569


def _load_and_verify_stored_proof(
    proof_id: str,
    *,
    store: ProofStore,
    now_utc: str | None = None,
) -> tuple[
    tuple[VerifyProofBundle, BundleVerificationResult] | None,
    tuple[int, dict[str, Any], dict[str, str]] | None,
]:
    if not proof_id or _has_unsafe_control_chars(proof_id) or len(proof_id) > 256:
        return None, (
            400,
            {"error": "invalid_proof_id", "detail": "Invalid proof_id"},
            dict(EMBED_METADATA_HEADERS),
        )
    try:
        entry = store.get_proof_entry(proof_id)
    except ProofNotFoundError:
        return None, (
            404,
            {"error": "proof_not_found", "detail": f"Proof {sanitize_public_label(proof_id)!r} not found"},
            dict(EMBED_METADATA_HEADERS),
        )
    verification = store.verify_bundle_against_live_state(entry.bundle, now_utc=now_utc)
    if not verification.valid:
        return None, (
            422,
            {
                "error": "proof_verification_failed",
                "detail": "Stored proof failed live cryptographic or continuity verification",
                "errors": verification.errors,
            },
            dict(EMBED_METADATA_HEADERS),
        )
    return (entry.bundle, verification), None


def handle_get_discord_embed(
    proof_id: str,
    *,
    store: ProofStore,
    now_utc: str | None = None,
) -> tuple[int, dict[str, Any], dict[str, str]]:
    """Serve dynamically re-verified Discord/Telegram rich embed payload."""
    verified_pair, err_resp = _load_and_verify_stored_proof(proof_id, store=store, now_utc=now_utc)
    if err_resp is not None or verified_pair is None:
        return err_resp  # type: ignore[return-value]
    bundle, verification = verified_pair

    recon_status = extract_verified_reconciliation_status(bundle)
    metrics = _extract_realized_metrics_strict(bundle)

    twr_str = (
        f"{metrics['twr_pct']:+.2f}%"
        if metrics["twr_pct"] is not None
        else "Undisclosed"
    )
    psr_str = str(metrics["psr_display"])

    origin_val = verification.effective_origin_assurance.value
    signer_val = verification.signer_trust_status.value
    scope_val = verification.assurance_profile.account_scope.value
    continuity_val = verification.effective_chain_continuity_mode.value

    safe_proof_label = sanitize_markdown_text(bundle.proof_id, max_len=64)
    safe_broker_label = sanitize_markdown_text(bundle.broker_id, max_len=32)
    encoded_id = quote(bundle.proof_id, safe="")
    proof_url = f"https://verify.example.org/p/{encoded_id}"

    trust_chips = {
        "origin_assurance": origin_val,
        "signer_trust": signer_val,
        "reconciliation_status": recon_status,
        "account_scope": scope_val,
        "continuity_mode": continuity_val,
    }

    discord_embed = {
        "title": f"N170 Verified Track Record - {safe_broker_label}",
        "url": proof_url,
        "color": _embed_color_int(verification.effective_origin_assurance),
        "description": (
            f"Cryptographically verified realized TWR **{twr_str}** | PSR **{psr_str}** "
            f"({bundle.period_start_utc[:10]} to {bundle.period_end_utc[:10]})"
        ),
        "fields": [
            {"name": "Realized TWR", "value": twr_str, "inline": True},
            {"name": "Probabilistic Sharpe (PSR)", "value": psr_str, "inline": True},
            {"name": "OriginAssurance", "value": origin_val, "inline": True},
            {"name": "SignerTrust", "value": signer_val, "inline": True},
            {"name": "ReconciliationStatus", "value": recon_status, "inline": True},
            {"name": "AccountScope", "value": scope_val, "inline": True},
        ],
        "footer": {
            "text": f"N170 Verify v3 | id: {safe_proof_label} | merkle: {bundle.merkle_root[:16]}..."
        },
        "timestamp": bundle.issued_at_utc,
    }

    telegram_markdown = (
        f"*N170 Verified Performance* ({safe_broker_label})\n"
        f"• Realized TWR: `{twr_str}`\n"
        f"• PSR: `{psr_str}`\n"
        f"• OriginAssurance: `{origin_val}`\n"
        f"• SignerTrust: `{signer_val}`\n"
        f"• ReconciliationStatus: `{recon_status}`\n"
        f"• AccountScope: `{scope_val}`\n"
        f"• Verify: {proof_url}"
    )

    return (
        200,
        {
            "proof_id": safe_proof_label,
            "verified": True,
            "proof_url": proof_url,
            "trust_chips": trust_chips,
            "metrics": {
                "twr": twr_str,
                "twr_decimal": metrics["twr_decimal"],
                "twr_pct": metrics["twr_pct"],
                "psr": psr_str,
                "psr_numeric": metrics["psr"],
                "observation_count": metrics["observation_count"],
                "psr_sample_eligible": metrics["psr_sample_eligible"],
            },
            "embeds": [discord_embed],
            "allowed_mentions": {"parse": []},
            "telegram_markdown": telegram_markdown,
        },
        dict(EMBED_METADATA_HEADERS),
    )


def handle_get_qr_payload(
    proof_id: str,
    *,
    store: ProofStore,
    now_utc: str | None = None,
) -> tuple[int, dict[str, Any], dict[str, str]]:
    """Serve compact offline QR verification payload and 16:9 / 9:16 share-card metadata."""
    verified_pair, err_resp = _load_and_verify_stored_proof(proof_id, store=store, now_utc=now_utc)
    if err_resp is not None or verified_pair is None:
        return err_resp  # type: ignore[return-value]
    bundle, verification = verified_pair

    recon_status = extract_verified_reconciliation_status(bundle)
    metrics = _extract_realized_metrics_strict(bundle)
    origin_val = verification.effective_origin_assurance.value
    signer_val = verification.signer_trust_status.value
    scope_val = verification.assurance_profile.account_scope.value
    continuity_val = verification.effective_chain_continuity_mode.value

    sig_fp = hashlib.sha256(bytes.fromhex(bundle.signature_hex)).hexdigest()[:32]
    encoded_id = quote(bundle.proof_id, safe="")
    encoded_kid = quote(bundle.publisher_kid, safe="")

    offline_uri = (
        f"n170verify://v3/{encoded_id}"
        f"?mr={bundle.merkle_root}"
        f"&kid={encoded_kid}"
        f"&sig={sig_fp}"
        f"&oa={origin_val}"
        f"&st={signer_val}"
        f"&rs={recon_status}"
        f"&as={scope_val}"
    )
    https_url = f"https://verify.example.org/p/{encoded_id}"
    relative_path = f"/p/{encoded_id}"

    trust_enums = {
        "origin_assurance": origin_val,
        "signer_trust": signer_val,
        "reconciliation_status": recon_status,
        "account_scope": scope_val,
    }

    twr_str = (
        f"{metrics['twr_pct']:+.2f}%"
        if metrics["twr_pct"] is not None
        else "Undisclosed"
    )
    psr_str = str(metrics["psr_display"])
    safe_broker = sanitize_public_label(bundle.broker_id, max_len=32)

    card_common = {
        "broker_id": safe_broker,
        "period_start_utc": bundle.period_start_utc,
        "period_end_utc": bundle.period_end_utc,
        "twr": twr_str,
        "psr": psr_str,
        "merkle_root": bundle.merkle_root,
        "ed25519_key_id": bundle.publisher_kid,
        "signature_fingerprint": sig_fp,
        "qr_target_url": https_url,
        "offline_verification_uri": offline_uri,
        "trust_enums": dict(trust_enums),
    }

    return (
        200,
        {
            "schema_version": VERIFY_SCHEMA_VERSION,
            "proof_id": sanitize_public_label(bundle.proof_id, max_len=128),
            "offline_verification_uri": offline_uri,
            "public_proof_url": https_url,
            "proof_path": relative_path,
            "merkle_root": bundle.merkle_root,
            "ed25519_key_id": bundle.publisher_kid,
            "publisher_public_key_hex": bundle.publisher_public_key_hex,
            "signature_fingerprint": sig_fp,
            "origin_assurance": origin_val,
            "signer_trust": signer_val,
            "reconciliation_status": recon_status,
            "account_scope": scope_val,
            "continuity_mode": continuity_val,
            "trust_enums": trust_enums,
            "share_cards": {
                "16:9": {
                    "aspect_ratio": "16:9",
                    "width": 1600,
                    "height": 900,
                    **card_common,
                },
                "9:16": {
                    "aspect_ratio": "9:16",
                    "width": 1080,
                    "height": 1920,
                    **card_common,
                },
            },
        },
        dict(EMBED_METADATA_HEADERS),
    )


# ---------------------------------------------------------------------------
# 5. POST /api/v1/verify/auto-detect & GET /api/v1/connect/ibkr-flex-guide
# ---------------------------------------------------------------------------


def build_and_sign_proof_bundle(
    ledger: CanonicalPortfolioLedger,
    *,
    detected_format: str,
    issued_at_utc: str,
    embargo_days: int = 7,
    eodhd_api_key: str | None = None,
    reconciliation_status_override: ReconciliationStatus | None = None,
    origin_assurance: OriginAssurance = OriginAssurance.SELF_REPORTED,
    imported_journal_tags: Sequence[str] = (),
    include_journal_tags: bool = True,
    disclose_leaf_names: Sequence[str] | None = None,
    publisher_kid: str = "ephemeral-worker-auto-detect",
    publisher_private_key_hex: str | None = None,
) -> tuple[VerifyProofBundle, dict[str, Any], int]:
    """Compute performance/reconciliation/coaching leaves and sign a redacted ``VerifyProofBundle``."""
    ref_provider = build_reference_provider(api_key=eodhd_api_key)
    perf_calc = calculate_portfolio_performance_detailed(
        ledger,
        reference_provider=ref_provider,
    )
    perf_summary = perf_calc.summary

    recon_report = reconcile_portfolio_ledger(
        ledger,
        reference_provider=ref_provider,
        performance_summary=perf_summary,
        reference_now_utc=issued_at_utc,
    )
    if reconciliation_status_override is not None:
        recon_dict = recon_report.to_dict()
        recon_dict["status"] = reconciliation_status_override.value
        if reconciliation_status_override == ReconciliationStatus.INSUFFICIENT_SECTIONS:
            recon_dict["ledger_completeness_ok"] = False
        recon_report = ReconciliationReport.from_dict(recon_dict)

    all_trips = match_fifo_round_trips(ledger)
    coaching_engine = TraderCoachingEngine(
        min_trade_disclosure_delay_days=float(embargo_days),
    )
    coaching_out = coaching_engine.evaluate(
        ledger,
        as_of_utc=issued_at_utc,
        enable_llm_narrative=False,
    )
    delayed_trades = coaching_out.delayed_closed_trades
    stripped_count = max(0, len(all_trips) - len(delayed_trades))

    sanitized_tags: list[str] = []
    if include_journal_tags:
        existing_tags = list(coaching_out.report.imported_journal_tags or [])
        for raw_t in [*existing_tags, *imported_journal_tags]:
            clean_t = sanitize_journal_tag(raw_t)
            if clean_t and clean_t not in sanitized_tags and len(sanitized_tags) < 50:
                sanitized_tags.append(clean_t)

    coaching_report = coaching_out.report
    coaching_dict = coaching_report.to_dict()
    coaching_dict["imported_journal_tags"] = sanitized_tags
    coaching_report = coaching_report.from_dict(coaching_dict)

    leaf_payloads = build_canonical_leaf_payloads(
        performance=perf_summary,
        reconciliation=recon_report,
        coaching=coaching_report,
        delayed_closed_trades=delayed_trades,
        base_currency=ledger.base_currency,
        embargo_days=embargo_days,
        stripped_recent_closed_trades_count=stripped_count,
    )
    # Persist non-sensitive detected_format token inside the salted reconciliation leaf
    leaf_payloads["reconciliation"]["detected_format"] = sanitize_public_label(
        detected_format, max_len=64
    )

    merkle_tree = build_salted_merkle_tree(leaf_payloads)
    priv_hex = (
        publisher_private_key_hex
        if publisher_private_key_hex is not None
        else generate_ed25519_keypair().private_key_hex
    )
    disclose_list = (
        list(CANONICAL_LEAF_NAMES)
        if disclose_leaf_names is None
        else [str(n) for n in disclose_leaf_names]
    )

    bundle = create_signed_proof_bundle(
        proof_id=f"prf-{secrets.token_hex(10)}",
        issued_at_utc=issued_at_utc,
        publisher_kid=publisher_kid,
        publisher_private_key_hex=priv_hex,
        broker_id=ledger.broker_id,
        blinded_account_tag=ledger.blinded_account_tag,
        account_scope=ledger.account_scope,
        provider_approval_state=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
        environment_tier=ledger.environment_tier,
        claimed_origin_assurance=origin_assurance,
        source_body_sha256=ledger.source_body_sha256,
        period_start_utc=ledger.period_start_utc,
        period_end_utc=ledger.period_end_utc,
        base_currency=ledger.base_currency,
        merkle_tree=merkle_tree,
        disclose_leaf_names=disclose_list,
        retention_mode="no_persistent_storage",
        schema_version=VERIFY_SCHEMA_VERSION,
    )
    return bundle, leaf_payloads, stripped_count


def auto_detect_worker_pipeline(job: Mapping[str, Any]) -> dict[str, Any]:
    """Top-level picklable worker pipeline executed strictly inside single-use ``spawn`` worker.

    Parses the uploaded statement, strips raw dollar NAVs & raw account IDs inside transient
    child memory, and emits only salted Merkle leaves + redacted metadata.
    """
    raw_bytes: bytes | None = None
    if job.get("raw_statement_b64"):
        try:
            raw_bytes = base64.b64decode(str(job["raw_statement_b64"]), validate=True)
        except Exception as exc:
            raise WorkerValidationError("raw_statement_b64 must be valid base64") from exc
    elif job.get("raw_statement_text") is not None:
        raw_bytes = str(job["raw_statement_text"]).encode("utf-8")

    if raw_bytes is None or not raw_bytes.strip():
        raise WorkerValidationError("Uploaded statement payload must not be empty")
    if len(raw_bytes) > MAX_STATEMENT_UPLOAD_BYTES:
        raise WorkerValidationError("Uploaded statement exceeds 25 MB maximum size")

    filename = str(job["filename"]).strip() if job.get("filename") else None
    blinding_salt_hex = str(job["account_blinding_salt_hex"])
    base_currency = str(job.get("base_currency") or "USD").strip().upper()
    issued_at_utc = str(job.get("issued_at_utc") or utc_now_iso())
    embargo_days = int(job.get("delayed_trade_guard_days", 7))
    include_journal_tags = bool(job.get("include_journal_tags", True))

    det = detect_and_parse_statement(
        raw_bytes,
        filename=filename,
        blinding_salt_hex=blinding_salt_hex,
        base_currency=base_currency,
        require_live=True,
    )
    ledger = det.ledger
    detected_format = det.detected_format
    if ledger.environment_tier == EnvironmentTier.PAPER_OR_SANDBOX_REJECTED:
        raise PaperOrSandboxAccountRejectedError(
            f"Paper, demo, or sandbox statement rejected (broker_id={ledger.broker_id!r})"
        )

    recon_override = det.reconciliation_status_override
    if recon_override is None and any(
        j_tok in detected_format.lower() or j_tok in ledger.broker_id.lower()
        for j_tok in ("tradersync", "tradezella", "journal")
    ):
        recon_override = ReconciliationStatus.INSUFFICIENT_SECTIONS

    bundle, leaf_payloads, stripped_count = build_and_sign_proof_bundle(
        ledger,
        detected_format=detected_format,
        issued_at_utc=issued_at_utc,
        embargo_days=embargo_days,
        eodhd_api_key=job.get("eodhd_api_key"),
        reconciliation_status_override=recon_override,
        origin_assurance=OriginAssurance.SELF_REPORTED,
        imported_journal_tags=det.imported_journal_tags,
        include_journal_tags=include_journal_tags,
        disclose_leaf_names=job.get("disclose_leaf_names"),
    )

    final_recon_status = str(leaf_payloads["reconciliation"]["status"])
    final_tags = list(leaf_payloads["coaching_and_context"].get("imported_journal_tags") or [])
    safe_format = sanitize_public_label(detected_format, max_len=64)

    return {
        "detected_format": safe_format,
        "broker_id": bundle.broker_id,
        "blinded_account_tag": bundle.blinded_account_tag,
        "account_scope": bundle.account_scope.value,
        "provider_approval_state": bundle.provider_approval_state.value,
        "environment_tier": bundle.environment_tier.value,
        "claimed_origin_assurance": OriginAssurance.SELF_REPORTED.value,
        "origin_assurance": OriginAssurance.SELF_REPORTED.value,
        "reconciliation_status": final_recon_status,
        "imported_journal_tags": final_tags,
        "source_body_sha256": bundle.source_body_sha256,
        "period_start_utc": bundle.period_start_utc,
        "period_end_utc": bundle.period_end_utc,
        "base_currency": bundle.base_currency,
        "merkle_root": bundle.merkle_root,
        "disclosed_leaves": [leaf.to_dict() for leaf in bundle.disclosed_leaves],
        "undisclosed_leaf_hashes": dict(bundle.undisclosed_leaf_hashes),
        "stripped_recent_closed_trades_count": stripped_count,
        "bundle": bundle.to_dict(),
    }


def _extract_multipart_upload(
    raw_body: bytes,
    content_type: str,
) -> tuple[bytes, dict[str, str]]:
    """Parse ``multipart/form-data`` via stdlib ``email.parser.BytesParser``."""
    header_bytes = (
        b"Content-Type: "
        + content_type.encode("latin-1", errors="replace")
        + b"\r\nMIME-Version: 1.0\r\n\r\n"
    )
    msg = BytesParser(policy=EMAIL_HTTP_POLICY).parsebytes(header_bytes + raw_body)
    if not msg.is_multipart():
        raise ValueError("Malformed multipart/form-data request")

    fields_map: dict[str, str] = {}
    file_bytes: bytes | None = None
    part_count = 0

    for part in msg.iter_parts():
        part_count += 1
        if part_count > MAX_MULTIPART_PARTS:
            raise ValueError("Too many multipart parts")
        disp = part.get_content_disposition()
        if disp != "form-data":
            continue
        name = part.get_param("name", header="content-disposition")
        filename = part.get_filename()
        payload = part.get_payload(decode=True)
        part_bytes = payload if isinstance(payload, (bytes, bytearray)) else b""
        if len(part_bytes) > MAX_STATEMENT_UPLOAD_BYTES:
            raise BufferError("Uploaded file part exceeds 25 MB limit")

        if filename is not None or name in {"file", "statement", "upload", "raw_statement"}:
            if file_bytes is None:
                file_bytes = bytes(part_bytes)
            if filename and "filename" not in fields_map:
                fields_map["filename"] = str(filename)
        elif name:
            fields_map[str(name)] = bytes(part_bytes).decode("utf-8", errors="replace").strip()

    if file_bytes is None:
        raise ValueError("multipart/form-data upload missing 'file' or 'statement' part")
    return file_bytes, fields_map


def handle_post_verify_auto_detect(
    raw_body: bytes,
    *,
    headers: Mapping[str, str] | None = None,
    query_params: Mapping[str, str] | None = None,
    config: ApiConfig,
    store: ProofStore,
) -> tuple[int, dict[str, Any]]:
    """Accept statement upload (<= 25 MB) and verify inside single-use ``spawn`` worker."""
    if len(raw_body) > MAX_STATEMENT_UPLOAD_BYTES:
        return 413, {
            "error": "payload_too_large",
            "detail": f"Uploaded statement exceeds maximum 25 MB ({MAX_STATEMENT_UPLOAD_BYTES} bytes) limit",
        }
    if not raw_body or not raw_body.strip():
        return 400, {
            "error": "empty_upload",
            "detail": "Statement upload body must not be empty",
        }

    hdrs = headers or {}
    q_map = query_params or {}
    content_type = str(hdrs.get("Content-Type") or hdrs.get("content-type") or "").strip()
    ct_lower = content_type.lower()

    stmt_bytes: bytes | None = None
    filename: str | None = q_map.get("filename") or hdrs.get("X-Filename") or hdrs.get("x-filename")
    base_currency = (q_map.get("base_currency") or "USD").strip().upper()
    include_journal_tags = q_map.get("include_journal_tags", "true").strip().lower() not in {
        "0",
        "false",
        "no",
    }
    publish_proof = q_map.get("publish_proof", "false").strip().lower() in {"1", "true", "yes"}
    opt_in_leaderboard = q_map.get("opt_in_leaderboard", "false").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    issued_at_utc: str | None = q_map.get("issued_at_utc")
    disclose_leaf_names: Sequence[str] | None = None

    if ct_lower.startswith("multipart/form-data"):
        try:
            stmt_bytes, form_fields = _extract_multipart_upload(raw_body, content_type)
        except BufferError as exc:
            return 413, {"error": "payload_too_large", "detail": str(exc)}
        except ValueError as exc:
            return 400, {"error": "invalid_multipart", "detail": str(exc)}

        if form_fields.get("filename"):
            filename = form_fields["filename"]
        if form_fields.get("base_currency"):
            base_currency = form_fields["base_currency"].upper()
        if "include_journal_tags" in form_fields:
            include_journal_tags = form_fields["include_journal_tags"].lower() not in {
                "0",
                "false",
                "no",
            }
        if "publish_proof" in form_fields:
            publish_proof = form_fields["publish_proof"].lower() in {"1", "true", "yes"}
        if "opt_in_leaderboard" in form_fields:
            opt_in_leaderboard = form_fields["opt_in_leaderboard"].lower() in {"1", "true", "yes"}
        if form_fields.get("issued_at_utc"):
            issued_at_utc = form_fields["issued_at_utc"]
    elif "application/json" in ct_lower or (not ct_lower and raw_body.lstrip().startswith(b"{")):
        try:
            parsed_json = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return 400, {"error": "invalid_json", "detail": f"Malformed JSON body: {exc}"}
        if not isinstance(parsed_json, Mapping):
            return 400, {"error": "invalid_request", "detail": "JSON body must be an object"}

        if bool(parsed_json.get("is_paper", False)) or bool(parsed_json.get("is_sandbox", False)):
            return 422, {
                "error": "paper_or_sandbox_rejected",
                "detail": "Paper, demo, and sandbox accounts are rejected",
            }
        if str(parsed_json.get("account_type", "")).strip().lower() in {
            "paper",
            "sandbox",
            "demo",
            "simulated",
            "testnet",
        }:
            return 422, {
                "error": "paper_or_sandbox_rejected",
                "detail": "Paper, demo, and sandbox accounts are rejected",
            }

        if parsed_json.get("filename"):
            filename = str(parsed_json["filename"])
        if parsed_json.get("base_currency"):
            base_currency = str(parsed_json["base_currency"]).strip().upper()
        if "include_journal_tags" in parsed_json:
            include_journal_tags = bool(parsed_json["include_journal_tags"])
        elif "forward_journal_tags" in parsed_json:
            include_journal_tags = bool(parsed_json["forward_journal_tags"])
        if "publish_proof" in parsed_json:
            publish_proof = bool(parsed_json["publish_proof"])
        if "opt_in_leaderboard" in parsed_json:
            opt_in_leaderboard = bool(parsed_json["opt_in_leaderboard"])
        if parsed_json.get("issued_at_utc"):
            issued_at_utc = str(parsed_json["issued_at_utc"])
        if isinstance(parsed_json.get("disclose_leaf_names"), list):
            disclose_leaf_names = [str(x) for x in parsed_json["disclose_leaf_names"]]

        if parsed_json.get("raw_statement_b64") is not None:
            b64_str = str(parsed_json["raw_statement_b64"]).strip()
            try:
                stmt_bytes = base64.b64decode(b64_str, validate=True)
            except Exception:
                return 422, {
                    "error": "validation_error",
                    "detail": "raw_statement_b64 must be valid base64",
                }
        elif parsed_json.get("raw_statement_text") is not None:
            if not isinstance(parsed_json["raw_statement_text"], str):
                return 422, {
                    "error": "validation_error",
                    "detail": "raw_statement_text must be a string",
                }
            stmt_bytes = parsed_json["raw_statement_text"].encode("utf-8")
        elif parsed_json.get("statement") is not None:
            if not isinstance(parsed_json["statement"], str):
                return 422, {
                    "error": "validation_error",
                    "detail": "statement must be a string",
                }
            stmt_bytes = parsed_json["statement"].encode("utf-8")
        else:
            return 422, {
                "error": "validation_error",
                "detail": "JSON body must provide raw_statement_text or raw_statement_b64",
            }
    else:
        stmt_bytes = bytes(raw_body)

    if stmt_bytes is None or not stmt_bytes.strip():
        return 422, {
            "error": "validation_error",
            "detail": "Uploaded statement content must not be empty",
        }
    if len(stmt_bytes) > MAX_STATEMENT_UPLOAD_BYTES:
        return 413, {
            "error": "payload_too_large",
            "detail": f"Decoded statement exceeds maximum 25 MB ({MAX_STATEMENT_UPLOAD_BYTES} bytes) limit",
        }
    if not (2 <= len(base_currency) <= 12) or not base_currency.isalnum():
        return 422, {
            "error": "validation_error",
            "detail": "base_currency must be a 2-12 character alphanumeric currency code",
        }

    worker_request: dict[str, Any] = {
        "broker_id": "auto_detect",
        "provider_approval_state": ProviderApprovalState.OFFLINE_EXPORT_ONLY.value,
        "environment_tier": EnvironmentTier.LIVE_PRODUCTION.value,
        "raw_statement_b64": base64.b64encode(stmt_bytes).decode("ascii"),
        "filename": sanitize_public_label(filename, max_len=128) if filename else None,
        "base_currency": base_currency,
        "include_journal_tags": include_journal_tags,
    }
    if issued_at_utc:
        worker_request["issued_at_utc"] = issued_at_utc
    if disclose_leaf_names is not None:
        worker_request["disclose_leaf_names"] = list(disclose_leaf_names)

    try:
        bundle, receipt, stripped_trades = run_isolated_one_shot_verification(
            worker_request,
            config=config,
            pipeline_spec="app.routes_viral:auto_detect_worker_pipeline",
            retention_mode="no_persistent_storage",
            persistent_rows_written=0,
        )
    except PaperOrSandboxRejectedError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    except GovernanceBlockedError as exc:
        return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
    except ReadOnlyCapabilityViolationError as exc:
        return 422, {"error": "read_only_capability_violation", "detail": str(exc)}
    except (WorkerValidationError, ValueError) as exc:
        return 422, {"error": "validation_error", "detail": str(exc)}
    except WorkerIsolationError as exc:
        return 500, {"error": "worker_isolation_error", "detail": str(exc)}

    rows_written = 0
    if publish_proof:
        try:
            bundle, verification = store.store_proof(
                bundle, opt_in_leaderboard=opt_in_leaderboard
            )
            rows_written = 1
        except ProofConflictError as exc:
            return exc.http_status, {"error": exc.error_code, "detail": str(exc)}
        except ProofBundleInvalidError as exc:
            return 422, {"error": "invalid_proof_bundle", "errors": exc.errors}
    else:
        verification = store.verify_bundle_against_live_state(bundle)

    receipt.persistent_rows_written = rows_written

    recon_payload = verified_leaf_payload(bundle, "reconciliation")
    detected_format = bundle.broker_id
    reconciliation_status = extract_verified_reconciliation_status(bundle)
    if isinstance(recon_payload, Mapping) and recon_payload.get("detected_format"):
        detected_format = sanitize_public_label(recon_payload["detected_format"], max_len=64)

    coaching_payload = verified_leaf_payload(bundle, "coaching_and_context")
    imported_tags: list[str] = []
    if isinstance(coaching_payload, Mapping) and isinstance(
        coaching_payload.get("imported_journal_tags"), list
    ):
        for t in coaching_payload["imported_journal_tags"]:
            clean_t = sanitize_journal_tag(t)
            if clean_t:
                imported_tags.append(clean_t)

    bundle_dict = bundle.to_dict()
    return 200, {
        "detected_format": detected_format,
        "broker_id": bundle.broker_id,
        "origin_assurance": verification.effective_origin_assurance.value,
        "reconciliation_status": reconciliation_status,
        "imported_journal_tags": imported_tags,
        "bundle": bundle_dict,
        "proof_bundle": bundle_dict,
        "verification": verification.to_dict(),
        "isolation_receipt": receipt.to_dict(),
        "stripped_recent_closed_trades_count": stripped_trades,
    }


def handle_get_ibkr_flex_guide() -> tuple[int, dict[str, Any]]:
    """Serve ``GET /api/v1/connect/ibkr-flex-guide`` delegating directly to core."""
    return 200, get_ibkr_flex_setup_guide().to_dict()


__all__ = [
    "EMBED_METADATA_HEADERS",
    "MAX_PLAUSIBILITY_BODY_BYTES",
    "MAX_STATEMENT_UPLOAD_BYTES",
    "auto_detect_worker_pipeline",
    "build_and_sign_proof_bundle",
    "handle_get_challenge_card",
    "handle_get_discord_embed",
    "handle_get_head_to_head",
    "handle_get_ibkr_flex_guide",
    "handle_get_qr_payload",
    "handle_post_plausibility",
    "handle_post_verify_auto_detect",
    "sanitize_journal_tag",
    "sanitize_markdown_text",
    "sanitize_public_label",
    "validate_comparison_proof_id",
]
