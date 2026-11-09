"""Strict XML/XSS-escaped SVG badge renderer using verifier-computed assurance axes."""

from __future__ import annotations

from collections.abc import Mapping
import html
import math
import re
from typing import Any

from app.store import ProofNotFoundError, ProofStore
from n170_verify.contracts import (
    BundleVerificationResult,
    CapitalBracket,
    OriginAssurance,
    ReconciliationStatus,
    VerifyProofBundle,
)
from n170_verify.crypto import verify_disclosed_leaf


SVG_RESPONSE_HEADERS: dict[str, str] = {
    "Content-Type": "image/svg+xml; charset=utf-8",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store, max-age=0",
    "Access-Control-Allow-Origin": "*",
}

_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


def is_safe_xml_char(ch: str) -> bool:
    code = ord(ch)
    return not (
        code < 0x20
        or 0x7F <= code <= 0x9F
        or 0xD800 <= code <= 0xDFFF
        or code in {0x2028, 0x2029, 0xFFFE, 0xFFFF}
    )


def svg_escape(value: Any) -> str:
    """Strictly escape arbitrary text for XML/SVG text & attribute contexts."""
    raw = "" if value is None else str(value)
    sanitized = "".join(ch for ch in raw if is_safe_xml_char(ch))
    return html.escape(sanitized, quote=True)


def finite_real_number(raw: Any) -> float | None:
    """Coerce strict JSON int/float (excluding bool) to finite float."""
    if raw is None or isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    val = float(raw)
    return (0.0 if val == 0.0 else val) if math.isfinite(val) else None


def _safe_finite_float(raw: Any) -> float | None:
    if raw is None or isinstance(raw, bool):
        return None
    try:
        val = float(raw)
    except (ValueError, TypeError, OverflowError):
        return None
    return val if math.isfinite(val) else None


def _safe_nonneg_int(raw: Any, default: int = 0) -> int:
    if raw is None or isinstance(raw, bool):
        return default
    try:
        val = int(raw)
    except (ValueError, TypeError, OverflowError):
        return default
    return val if val >= 0 else default


def verified_leaf_payload(bundle: VerifyProofBundle, leaf_name: str) -> Any | None:
    """Return disclosed leaf payload iff its salted Merkle audit path verifies against ``bundle.merkle_root``."""
    for leaf in bundle.disclosed_leaves:
        if leaf.leaf_name == leaf_name:
            return leaf.payload if verify_disclosed_leaf(leaf, bundle.merkle_root) else None
    return None


def extract_verified_capital_bracket(bundle: VerifyProofBundle) -> CapitalBracket | None:
    """Verify the disclosed ``capital_bracket`` Merkle leaf against ``bundle.merkle_root``."""
    payload = verified_leaf_payload(bundle, "capital_bracket")
    raw_val = (
        payload.get("capital_bracket")
        if isinstance(payload, Mapping)
        else (payload if isinstance(payload, str) else None)
    )
    if raw_val is None:
        return None
    try:
        return CapitalBracket(str(raw_val))
    except ValueError:
        return None


def extract_verified_reconciliation_status(bundle: VerifyProofBundle) -> str:
    """Verify the disclosed ``reconciliation`` Merkle leaf and return its status string."""
    payload = verified_leaf_payload(bundle, "reconciliation")
    if isinstance(payload, Mapping) and "status" in payload:
        try:
            return ReconciliationStatus(str(payload["status"])).value
        except ValueError:
            return "invalid_status"
    return "undisclosed"


def _extract_reconciliation_label(
    bundle: VerifyProofBundle, verification: BundleVerificationResult
) -> str:
    if not (verification.valid and verification.signature_valid and verification.merkle_valid):
        return "unverified"
    return extract_verified_reconciliation_status(bundle)


def _extract_twr_and_psr_labels(
    bundle: VerifyProofBundle, verification: BundleVerificationResult
) -> tuple[str, str]:
    if not (verification.valid and verification.signature_valid and verification.merkle_valid):
        return "unverified", "unverified"
    payload = verified_leaf_payload(bundle, "core_metrics")
    if not isinstance(payload, Mapping):
        return "undisclosed", "undisclosed"
    twr_label = "undisclosed"
    twr_pct_val = _safe_finite_float(payload.get("twr_pct"))
    twr_dec_val = _safe_finite_float(payload.get("twr_decimal"))
    if twr_pct_val is not None:
        twr_label = f"{twr_pct_val:+.2f}%"
    elif twr_dec_val is not None:
        twr_label = f"{twr_dec_val * 100.0:+.2f}%"

    obs_count = _safe_nonneg_int(payload.get("observation_count"), default=0)
    has_obs_key = "observation_count" in payload
    psr_eligible_flag = payload.get("psr_sample_eligible")
    psr_eligible = bool(psr_eligible_flag) if isinstance(psr_eligible_flag, bool) else (obs_count >= 30)
    if has_obs_key and obs_count < 30:
        psr_eligible = False

    psr_raw = (
        payload.get("psr_glm_unsmoothed")
        if payload.get("psr_glm_unsmoothed") is not None
        else payload.get("probabilistic_sharpe_ratio")
    )
    if psr_raw is not None and psr_eligible and (not has_obs_key or obs_count >= 30):
        p_val = _safe_finite_float(psr_raw)
        if p_val is not None and 0.0 <= p_val <= 1.0:
            psr_label = f"{p_val * 100.0:.1f}%"
        else:
            psr_label = "invalid"
    elif (has_obs_key and obs_count < 30) or ("psr_sample_eligible" in payload and not psr_eligible):
        psr_label = "gated (<30 obs)"
    else:
        psr_label = "undisclosed"

    return twr_label, psr_label


def _accent_hex_for(verification: BundleVerificationResult) -> str:
    candidate = "#475569"
    if not verification.valid:
        candidate = "#b91c1c"
    else:
        origin = verification.effective_origin_assurance
        if origin == OriginAssurance.BROKER_SIGNED:
            candidate = "#047857"
        elif origin == OriginAssurance.INDEPENDENTLY_WITNESSED_TLS:
            candidate = "#0f766e"
        elif origin == OriginAssurance.OPERATOR_RETRIEVED:
            candidate = "#1d4ed8"
    return candidate if _HEX_COLOR_RE.match(candidate) else "#475569"


def render_proof_badge_svg(
    bundle: VerifyProofBundle,
    verification: BundleVerificationResult,
    *,
    label: str | None = None,
) -> str:
    """Render XSS-safe SVG badge strictly from verifier-computed ``BundleVerificationResult``.

    Never reads ``bundle.claimed_origin_assurance``; always renders
    ``verification.effective_origin_assurance``.
    """
    status_headline = "N170 VERIFIED" if verification.valid else "N170 INVALID PROOF"
    accent_color = _accent_hex_for(verification)

    # Strictly verifier-computed assurance fields
    effective_origin = svg_escape(verification.effective_origin_assurance.value)
    effective_continuity = svg_escape(verification.effective_chain_continuity_mode.value)
    signer_trust = svg_escape(verification.signer_trust_status.value)
    recon_label = svg_escape(_extract_reconciliation_label(bundle, verification))
    twr_raw, psr_raw = _extract_twr_and_psr_labels(bundle, verification)
    twr_label = svg_escape(twr_raw)
    psr_label = svg_escape(psr_raw)

    safe_proof_id = svg_escape(bundle.proof_id[:48])
    safe_broker = svg_escape(bundle.broker_id[:24])
    safe_headline = svg_escape(status_headline)
    safe_custom_label = svg_escape(str(label)[:32]) if label else ""

    title_text = (
        f"{safe_headline} | origin={effective_origin} | recon={recon_label} | "
        f"continuity={effective_continuity} | TWR={twr_label} | PSR={psr_label}"
    )
    if safe_custom_label:
        title_text = f"{title_text} | label={safe_custom_label}"

    signer_footer = f"signer: {signer_trust}"
    if safe_custom_label:
        signer_footer = f"{signer_footer} &#183; {safe_custom_label}"

    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="640" height="92" '
        'viewBox="0 0 640 92" role="img" aria-label="N170 Verify Proof Badge">'
        f"<title>{title_text}</title>"
        '<rect x="0" y="0" width="640" height="92" rx="8" fill="#0f172a"/>'
        f'<rect x="0" y="0" width="640" height="28" rx="8" fill="{accent_color}"/>'
        f'<rect x="0" y="20" width="640" height="8" fill="{accent_color}"/>'
        '<g font-family="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace" '
        'font-size="11" fill="#f8fafc">'
        f'<text x="12" y="18" font-weight="700">{safe_headline} &#183; {safe_broker}</text>'
        f'<text x="628" y="18" text-anchor="end" fill="#e2e8f0">id: {safe_proof_id}</text>'
        f'<text x="12" y="48" fill="#cbd5e1">origin: <tspan fill="#ffffff" font-weight="600">{effective_origin}</tspan></text>'
        f'<text x="320" y="48" fill="#cbd5e1">recon: <tspan fill="#ffffff" font-weight="600">{recon_label}</tspan></text>'
        f'<text x="12" y="68" fill="#cbd5e1">continuity: <tspan fill="#ffffff" font-weight="600">{effective_continuity}</tspan></text>'
        f'<text x="320" y="68" fill="#cbd5e1">TWR: <tspan fill="#38bdf8" font-weight="700">{twr_label}</tspan>'
        f' &#183; PSR: <tspan fill="#38bdf8" font-weight="700">{psr_label}</tspan></text>'
        f'<text x="12" y="84" font-size="9.5" fill="#94a3b8">{signer_footer}</text>'
        "</g>"
        "</svg>"
    )


def handle_get_badge_svg(
    proof_id: str,
    *,
    store: ProofStore,
    query_params: Mapping[str, str] | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    """HTTP handler logic for ``GET /api/v1/badges/{proof_id}.svg``."""
    raw_label = query_params.get("label") if query_params else None
    try:
        entry = store.get_proof_entry(proof_id)
    except ProofNotFoundError:
        safe_missing = svg_escape(proof_id[:48])
        safe_q_label = svg_escape(str(raw_label)[:32]) if raw_label else ""
        title_suffix = f" ({safe_q_label})" if safe_q_label else ""
        not_found_svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" width="420" height="40" role="img">'
            f"<title>Proof Not Found: {safe_missing}{title_suffix}</title>"
            '<rect width="420" height="40" rx="6" fill="#334155"/>'
            '<text x="12" y="25" font-family="monospace" font-size="12" fill="#f8fafc">'
            f"N170 Verify: proof not found ({safe_missing})"
            "</text></svg>"
        )
        return 404, not_found_svg.encode("utf-8"), dict(SVG_RESPONSE_HEADERS)

    verification = store.verify_bundle_against_live_state(entry.bundle)
    svg_str = render_proof_badge_svg(entry.bundle, verification, label=raw_label)
    return 200, svg_str.encode("utf-8"), dict(SVG_RESPONSE_HEADERS)


__all__ = [
    "SVG_RESPONSE_HEADERS",
    "extract_verified_capital_bracket",
    "extract_verified_reconciliation_status",
    "finite_real_number",
    "handle_get_badge_svg",
    "is_safe_xml_char",
    "render_proof_badge_svg",
    "svg_escape",
    "verified_leaf_payload",
]
