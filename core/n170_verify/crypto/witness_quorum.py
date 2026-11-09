"""Dynamic TLS witness quorum evaluation and side-channel/secret-safe transcript checks."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import re
from typing import Any
import urllib.parse

from n170_verify.contracts.assurance import (
    ContractModelMixin,
    EnvironmentTier,
    OriginAssurance,
    ProviderApprovalState,
    SignerTrustStatus,
    parse_utc_timestamp,
    validate_hex_digest,
)
from n170_verify.crypto.canonical import jcs_canonicalize
from n170_verify.crypto.signing import (
    SIGNING_DOMAIN_BROKER,
    SIGNING_DOMAIN_WITNESS,
    ed25519_sign_domain,
    ed25519_verify_domain,
)


REQUIRED_TLSN_PROTOCOL = "tlsn-v0.1.0-alpha.15"
REQUIRED_TLS_VERSION = "1.2"
DEFAULT_MAX_WITNESS_SKEW_SECONDS = 600

_IBKR_WITNESS_SNIS: frozenset[str] = frozenset(
    {
        "api.ibkr.com",
        "ndcdyn.interactivebrokers.com",
        "gdcdyn.interactivebrokers.com",
        "www.interactivebrokers.com",
    }
)
_SCHWAB_WITNESS_SNIS: frozenset[str] = frozenset({"api.schwabapi.com"})
_CTRADER_WITNESS_SNIS: frozenset[str] = frozenset(
    {"openapi.ctrader.com", "live.ctraderapi.com"}
)
_COINBASE_WITNESS_SNIS: frozenset[str] = frozenset(
    {"api.coinbase.com", "api.exchange.coinbase.com"}
)

BROKER_WITNESS_SNI_ALLOWLIST: dict[str, frozenset[str]] = {
    "ibkr": _IBKR_WITNESS_SNIS,
    "ibkr_flex": _IBKR_WITNESS_SNIS,
    "ibkr_flex_offline": _IBKR_WITNESS_SNIS,
    "ibkr_flex_web": _IBKR_WITNESS_SNIS,
    "ibkr_oauth": _IBKR_WITNESS_SNIS,
    "interactive_brokers": _IBKR_WITNESS_SNIS,
    "schwab": _SCHWAB_WITNESS_SNIS,
    "schwab_csv": _SCHWAB_WITNESS_SNIS,
    "alpaca": frozenset({"api.alpaca.markets"}),
    "tradier": frozenset({"api.tradier.com"}),
    "trading212": frozenset({"live.trading212.com"}),
    "ctrader": _CTRADER_WITNESS_SNIS,
    "ctrader_oauth": _CTRADER_WITNESS_SNIS,
    "coinbase": _COINBASE_WITNESS_SNIS,
    "coinbaseadvanced": _COINBASE_WITNESS_SNIS,
    "coinbase_advanced": _COINBASE_WITNESS_SNIS,
    "binance": frozenset({"api.binance.com"}),
    "kraken": frozenset({"api.kraken.com"}),
    "bybit": frozenset({"api.bybit.com"}),
}

_REDACTED_PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "[redacted]",
        "<redacted>",
        "redacted",
        "***",
        "*",
    }
)

_ALLOWED_STATIC_ACCOUNT_SEGMENTS: frozenset[str] = _REDACTED_PLACEHOLDERS | frozenset(
    {
        "accountnumbers",
        "subaccounts",
        "summary",
    }
)

_SENSITIVE_HEADER_NAMES: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "apca-api-key-id",
        "apca-api-secret-key",
        "cookie",
        "set-cookie",
        "x-api-key",
        "cb-access-key",
        "cb-access-sign",
        "cb-access-passphrase",
        "api-key",
        "api-sign",
    }
)

_SENSITIVE_QUERY_PARAM_RE = re.compile(
    r"(?:^|[?&])(t|q|token|access_token|refresh_token|api_key|apikey|secret|signature)=([^&#\s]*)",
    re.IGNORECASE,
)
_ACCOUNT_PATH_RE = re.compile(
    r"(?:/v\d+)?/accounts/([^/?#\s]+)",
    re.IGNORECASE,
)
_EMBEDDED_HEADER_LEAK_RE = re.compile(
    r"\b(authorization|apca-api-key-id|apca-api-secret-key|cookie|set-cookie|cb-access-key|x-api-key|api-key|api-sign)\s*:",
    re.IGNORECASE,
)
_AUTH_SCHEME_LEAK_RE = re.compile(
    r"\b(bearer|basic)\s+([^\s,;]+)",
    re.IGNORECASE,
)


class TranscriptCommitmentKind(str, Enum):
    """TLS transcript response commitment granularity."""

    WHOLE_BODY_SHA256 = "whole_body_sha256"
    FIXED_64B_PADDED_WINDOW = "fixed_64b_padded_window"
    UNPADDED_VARIABLE_SPAN_REJECTED = "unpadded_variable_span_rejected"


def _normalize_asn(asn: str) -> str:
    cleaned = asn.strip().upper()
    if cleaned.startswith("AS"):
        cleaned = cleaned[2:].strip()
    if not cleaned:
        raise ValueError("NotaryNodeInfo.asn must not be empty")
    return f"AS{cleaned}"


@dataclass(slots=True)
class NotaryNodeInfo(ContractModelMixin):
    """Registered MPC-TLS notary node identity, operator organization, and network ASN."""

    notary_id: str
    operator_org: str
    asn: str
    public_key_hex: str
    is_debug_build: bool = False
    attestation_type: str = "production"

    def _validate(self) -> None:
        if not self.notary_id.strip():
            raise ValueError("NotaryNodeInfo.notary_id must not be empty")
        if not self.operator_org.strip():
            raise ValueError("NotaryNodeInfo.operator_org must not be empty")
        object.__setattr__(self, "asn", _normalize_asn(self.asn))
        object.__setattr__(
            self,
            "public_key_hex",
            validate_hex_digest(
                self.public_key_hex, field_name="NotaryNodeInfo.public_key_hex", num_bytes=32
            ),
        )
        if not self.attestation_type.strip():
            raise ValueError("NotaryNodeInfo.attestation_type must not be empty")


@dataclass(slots=True)
class WitnessAttestation(ContractModelMixin):
    """Signed MPC-TLS notary attestation over a sanitized broker HTTPS exchange."""

    protocol: str
    tls_version: str
    defer_decryption_from_start: bool
    notary_id: str
    server_sni: str
    sanitized_request_target: str
    redacted_headers: list[str]
    commitment_kind: TranscriptCommitmentKind
    response_body_sha256: str
    session_timestamp_utc: str
    signature_hex: str

    def _validate(self) -> None:
        if not self.notary_id.strip():
            raise ValueError("WitnessAttestation.notary_id must not be empty")
        if not self.server_sni.strip():
            raise ValueError("WitnessAttestation.server_sni must not be empty")
        if not self.sanitized_request_target.strip():
            raise ValueError("WitnessAttestation.sanitized_request_target must not be empty")
        object.__setattr__(
            self,
            "response_body_sha256",
            validate_hex_digest(
                self.response_body_sha256,
                field_name="WitnessAttestation.response_body_sha256",
                num_bytes=32,
            ),
        )
        parse_utc_timestamp(
            self.session_timestamp_utc, field_name="WitnessAttestation.session_timestamp_utc"
        )
        object.__setattr__(
            self,
            "signature_hex",
            validate_hex_digest(
                self.signature_hex,
                field_name="WitnessAttestation.signature_hex",
                num_bytes=64,
            ),
        )

    def signable_dict(self) -> dict[str, Any]:
        """Return canonical signable payload dictionary excluding ``signature_hex``."""
        return {
            "commitment_kind": self.commitment_kind.value,
            "defer_decryption_from_start": self.defer_decryption_from_start,
            "notary_id": self.notary_id,
            "protocol": self.protocol,
            "redacted_headers": list(self.redacted_headers),
            "response_body_sha256": self.response_body_sha256,
            "sanitized_request_target": self.sanitized_request_target,
            "server_sni": self.server_sni,
            "session_timestamp_utc": self.session_timestamp_utc,
            "tls_version": self.tls_version,
        }

    def signable_bytes(self) -> bytes:
        return jcs_canonicalize(self.signable_dict())

    def verify_signature(self, notary_public_key_hex: str) -> bool:
        return ed25519_verify_domain(
            notary_public_key_hex,
            SIGNING_DOMAIN_WITNESS,
            self.signable_bytes(),
            self.signature_hex,
        )


def create_signed_witness_attestation(
    *,
    notary_private_key_hex: str,
    notary_id: str,
    server_sni: str,
    sanitized_request_target: str,
    redacted_headers: Sequence[str],
    commitment_kind: TranscriptCommitmentKind = TranscriptCommitmentKind.WHOLE_BODY_SHA256,
    response_body_sha256: str,
    session_timestamp_utc: str,
    protocol: str = REQUIRED_TLSN_PROTOCOL,
    tls_version: str = REQUIRED_TLS_VERSION,
    defer_decryption_from_start: bool = True,
) -> WitnessAttestation:
    """Create and Ed25519-sign a ``WitnessAttestation``."""
    norm_body = validate_hex_digest(
        response_body_sha256, field_name="response_body_sha256", num_bytes=32
    )
    payload_dict: dict[str, Any] = {
        "commitment_kind": TranscriptCommitmentKind(commitment_kind).value,
        "defer_decryption_from_start": defer_decryption_from_start,
        "notary_id": notary_id,
        "protocol": protocol,
        "redacted_headers": list(redacted_headers),
        "response_body_sha256": norm_body,
        "sanitized_request_target": sanitized_request_target,
        "server_sni": server_sni,
        "session_timestamp_utc": session_timestamp_utc,
        "tls_version": tls_version,
    }
    sig_hex = ed25519_sign_domain(
        notary_private_key_hex,
        SIGNING_DOMAIN_WITNESS,
        jcs_canonicalize(payload_dict),
    )
    return WitnessAttestation(
        protocol=protocol,
        tls_version=tls_version,
        defer_decryption_from_start=defer_decryption_from_start,
        notary_id=notary_id,
        server_sni=server_sni,
        sanitized_request_target=sanitized_request_target,
        redacted_headers=list(redacted_headers),
        commitment_kind=TranscriptCommitmentKind(commitment_kind),
        response_body_sha256=norm_body,
        session_timestamp_utc=session_timestamp_utc,
        signature_hex=sig_hex,
    )


@dataclass(slots=True)
class BrokerNativeSignature(ContractModelMixin):
    """First-party cryptographic signature issued directly by a broker over statement bytes."""

    broker_id: str
    key_id: str
    algorithm: str
    signed_payload_sha256: str
    signature_hex: str

    def _validate(self) -> None:
        if not self.broker_id.strip():
            raise ValueError("BrokerNativeSignature.broker_id must not be empty")
        object.__setattr__(self, "broker_id", self.broker_id.strip().lower())
        if not self.key_id.strip():
            raise ValueError("BrokerNativeSignature.key_id must not be empty")
        if not self.algorithm.strip():
            raise ValueError("BrokerNativeSignature.algorithm must not be empty")
        object.__setattr__(
            self,
            "signed_payload_sha256",
            validate_hex_digest(
                self.signed_payload_sha256,
                field_name="BrokerNativeSignature.signed_payload_sha256",
                num_bytes=32,
            ),
        )
        object.__setattr__(
            self,
            "signature_hex",
            validate_hex_digest(
                self.signature_hex,
                field_name="BrokerNativeSignature.signature_hex",
                num_bytes=64,
            ),
        )

    def signable_dict(self) -> dict[str, str]:
        return {
            "algorithm": self.algorithm,
            "broker_id": self.broker_id,
            "key_id": self.key_id,
            "signed_payload_sha256": self.signed_payload_sha256,
        }

    def signable_bytes(self) -> bytes:
        return jcs_canonicalize(self.signable_dict())

    def verify_signature(self, broker_public_key_hex: str) -> bool:
        if self.algorithm.strip().lower() != "ed25519":
            return False
        return ed25519_verify_domain(
            broker_public_key_hex,
            SIGNING_DOMAIN_BROKER,
            self.signable_bytes(),
            self.signature_hex,
        )


def create_signed_broker_signature(
    *,
    broker_private_key_hex: str,
    broker_id: str,
    key_id: str,
    signed_payload_sha256: str,
    algorithm: str = "Ed25519",
) -> BrokerNativeSignature:
    """Create and sign a ``BrokerNativeSignature`` with a broker's Ed25519 key."""
    norm_broker = broker_id.strip().lower()
    norm_sha = validate_hex_digest(
        signed_payload_sha256, field_name="signed_payload_sha256", num_bytes=32
    )
    payload_dict = {
        "algorithm": algorithm,
        "broker_id": norm_broker,
        "key_id": key_id,
        "signed_payload_sha256": norm_sha,
    }
    sig_hex = ed25519_sign_domain(
        broker_private_key_hex,
        SIGNING_DOMAIN_BROKER,
        jcs_canonicalize(payload_dict),
    )
    return BrokerNativeSignature(
        broker_id=norm_broker,
        key_id=key_id,
        algorithm=algorithm,
        signed_payload_sha256=norm_sha,
        signature_hex=sig_hex,
    )


def verify_broker_native_signature(
    broker_sig: BrokerNativeSignature | None,
    expected_source_body_sha256: str,
    pinned_broker_keys: Mapping[str, Mapping[str, str]] | None,
) -> bool:
    """Verify a first-party broker signature against pinned broker Ed25519 public keys."""
    if broker_sig is None or not pinned_broker_keys:
        return False
    try:
        norm_expected = validate_hex_digest(
            expected_source_body_sha256, field_name="expected_source_body_sha256", num_bytes=32
        )
    except ValueError:
        return False
    if broker_sig.signed_payload_sha256 != norm_expected:
        return False
    broker_keys = pinned_broker_keys.get(broker_sig.broker_id.lower())
    if not broker_keys:
        return False
    pub_hex = broker_keys.get(broker_sig.key_id)
    if not pub_hex:
        return False
    return broker_sig.verify_signature(pub_hex)


def inspect_transcript_safety(attestation: WitnessAttestation) -> tuple[bool, list[str]]:
    """Enforce whole-body/fixed-64B commitment and secret/account-ID transcript redaction."""
    violations: list[str] = []

    if attestation.protocol != REQUIRED_TLSN_PROTOCOL:
        violations.append(
            f"Unsupported TLSNotary protocol {attestation.protocol!r}; expected {REQUIRED_TLSN_PROTOCOL!r}"
        )
    if attestation.tls_version != REQUIRED_TLS_VERSION:
        violations.append(
            f"Unsupported witnessed TLS version {attestation.tls_version!r}; expected {REQUIRED_TLS_VERSION!r}"
        )
    if not attestation.defer_decryption_from_start:
        violations.append("defer_decryption_from_start must be True to prevent selective forgery")

    if attestation.commitment_kind == TranscriptCommitmentKind.UNPADDED_VARIABLE_SPAN_REJECTED:
        violations.append(
            "Variable-span transcript commitments leak NAV digit counts; "
            "require whole_body_sha256 or fixed_64b_padded_window"
        )

    target = attestation.sanitized_request_target
    for match in _SENSITIVE_QUERY_PARAM_RE.finditer(target):
        param_name, param_val = match.group(1), match.group(2).strip().lower()
        if param_val not in _REDACTED_PLACEHOLDERS:
            violations.append(
                f"Unredacted sensitive query parameter {param_name!r} in sanitized_request_target"
            )

    for match in _ACCOUNT_PATH_RE.finditer(target):
        acct_seg = match.group(1).strip().lower()
        if acct_seg not in _ALLOWED_STATIC_ACCOUNT_SEGMENTS:
            violations.append(
                "Unredacted raw account identifier in /accounts/<id> path of sanitized_request_target"
            )

    if _EMBEDDED_HEADER_LEAK_RE.search(target):
        violations.append("Sensitive HTTP header leaked inside sanitized_request_target")

    for match in _AUTH_SCHEME_LEAK_RE.finditer(target):
        scheme, token = match.group(1), match.group(2).strip().lower()
        if token not in _REDACTED_PLACEHOLDERS:
            violations.append(f"Unredacted {scheme} credential leaked in sanitized_request_target")

    if not attestation.redacted_headers:
        violations.append("redacted_headers must list at least one redacted credential header")

    for entry in attestation.redacted_headers:
        stripped = entry.strip()
        if ":" in stripped:
            hdr_name, hdr_val = stripped.split(":", 1)
            norm_name = hdr_name.strip().lower()
            norm_val = hdr_val.strip().lower()
            if norm_name in _SENSITIVE_HEADER_NAMES and norm_val not in _REDACTED_PLACEHOLDERS:
                violations.append(
                    f"Unredacted sensitive header value for {hdr_name.strip()!r} in redacted_headers"
                )
        for match in _AUTH_SCHEME_LEAK_RE.finditer(stripped):
            scheme, token = match.group(1), match.group(2).strip().lower()
            if token not in _REDACTED_PLACEHOLDERS:
                violations.append(f"Unredacted {scheme} token in redacted_headers")

    return len(violations) == 0, violations


def _max_mutually_disjoint_quorum(
    candidates: list[tuple[NotaryNodeInfo, datetime]],
    max_skew_seconds: int,
) -> tuple[int, int, int]:
    """Find the largest subset within ``max_skew_seconds`` with pairwise distinct org, ASN, pubkey, and ID."""
    if not candidates:
        return 0, 0, 0

    sorted_cands = sorted(candidates, key=lambda item: item[1])
    best_clique: list[NotaryNodeInfo] = []

    for start_idx in range(len(sorted_cands)):
        t0 = sorted_cands[start_idx][1]
        window_nodes = [
            node
            for node, ts in sorted_cands[start_idx:]
            if (ts - t0).total_seconds() <= max_skew_seconds
        ]

        # Backtrack for exact maximum mutually disjoint set over (notary_id, pubkey, org, asn).
        def _search(
            idx: int,
            chosen: list[NotaryNodeInfo],
            used_ids: set[str],
            used_pubs: set[str],
            used_orgs: set[str],
            used_asns: set[str],
        ) -> None:
            nonlocal best_clique
            if len(chosen) > len(best_clique):
                best_clique = list(chosen)
            if len(chosen) + (len(window_nodes) - idx) <= len(best_clique):
                return
            for pos in range(idx, len(window_nodes)):
                cand = window_nodes[pos]
                nid = cand.notary_id.strip().lower()
                pub = cand.public_key_hex.lower()
                org = cand.operator_org.strip().lower()
                asn = cand.asn.strip().upper()
                if (
                    nid not in used_ids
                    and pub not in used_pubs
                    and org not in used_orgs
                    and asn not in used_asns
                ):
                    used_ids.add(nid)
                    used_pubs.add(pub)
                    used_orgs.add(org)
                    used_asns.add(asn)
                    chosen.append(cand)
                    _search(pos + 1, chosen, used_ids, used_pubs, used_orgs, used_asns)
                    chosen.pop()
                    used_asns.remove(asn)
                    used_orgs.remove(org)
                    used_pubs.remove(pub)
                    used_ids.remove(nid)

        _search(0, [], set(), set(), set(), set())

    all_orgs = {node.operator_org.strip().lower() for node, _ in sorted_cands}
    all_asns = {node.asn.strip().upper() for node, _ in sorted_cands}
    return len(best_clique), len(all_orgs), len(all_asns)


@dataclass(slots=True)
class WitnessQuorumEvaluation(ContractModelMixin):
    """Detailed dynamic origin-assurance evaluation result."""

    effective_origin_assurance: OriginAssurance
    valid_witness_count: int
    disjoint_quorum_size: int
    distinct_org_count: int
    distinct_asn_count: int
    broker_signature_valid: bool
    downgrade_reasons: list[str] = field(default_factory=list)


def evaluate_origin_assurance(
    *,
    source_body_sha256: str,
    broker_id: str | None = None,
    signer_trust: SignerTrustStatus = SignerTrustStatus.OFFICIAL_N170_HOSTED,
    publisher_kid: str = "",
    publisher_public_key_hex: str = "",
    publisher_org: str = "N170",
    environment_tier: EnvironmentTier = EnvironmentTier.LIVE_PRODUCTION,
    provider_approval_state: ProviderApprovalState = ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    claimed_origin_assurance: OriginAssurance | None = None,
    witness_attestations: Sequence[WitnessAttestation] = (),
    notary_registry: Sequence[NotaryNodeInfo] = (),
    broker_native_signature: BrokerNativeSignature | None = None,
    pinned_broker_keys: Mapping[str, Mapping[str, str]] | None = None,
    max_witness_skew_seconds: int = DEFAULT_MAX_WITNESS_SKEW_SECONDS,
) -> WitnessQuorumEvaluation:
    """Dynamically derive ``OriginAssurance`` from cryptographic evidence (never trusting claims)."""
    reasons: list[str] = []
    norm_source_sha = validate_hex_digest(
        source_body_sha256, field_name="source_body_sha256", num_bytes=32
    )

    if environment_tier == EnvironmentTier.PAPER_OR_SANDBOX_REJECTED:
        reasons.append("Paper or sandbox environment tier rejected; downgraded to self_reported")
        return WitnessQuorumEvaluation(
            effective_origin_assurance=OriginAssurance.SELF_REPORTED,
            valid_witness_count=0,
            disjoint_quorum_size=0,
            distinct_org_count=0,
            distinct_asn_count=0,
            broker_signature_valid=False,
            downgrade_reasons=reasons,
        )

    if signer_trust in {
        SignerTrustStatus.REVOKED_KEY,
        SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER,
    }:
        reasons.append(
            f"Publisher signer trust is {signer_trust.value}; downgraded to self_reported"
        )
        return WitnessQuorumEvaluation(
            effective_origin_assurance=OriginAssurance.SELF_REPORTED,
            valid_witness_count=0,
            disjoint_quorum_size=0,
            distinct_org_count=0,
            distinct_asn_count=0,
            broker_signature_valid=False,
            downgrade_reasons=reasons,
        )

    broker_id_norm = broker_id.strip().lower() if broker_id is not None else None
    if (
        broker_native_signature is not None
        and broker_id_norm is not None
        and broker_native_signature.broker_id.strip().lower() != broker_id_norm
    ):
        broker_sig_ok = False
        reasons.append(
            f"BrokerNativeSignature broker_id {broker_native_signature.broker_id!r} "
            f"mismatches bundle broker_id {broker_id!r}"
        )
    else:
        broker_sig_ok = verify_broker_native_signature(
            broker_native_signature,
            norm_source_sha,
            pinned_broker_keys,
        )
        if broker_sig_ok:
            return WitnessQuorumEvaluation(
                effective_origin_assurance=OriginAssurance.BROKER_SIGNED,
                valid_witness_count=0,
                disjoint_quorum_size=0,
                distinct_org_count=0,
                distinct_asn_count=0,
                broker_signature_valid=True,
                downgrade_reasons=[],
            )
        if broker_native_signature is not None:
            reasons.append("BrokerNativeSignature failed verification against pinned broker keys")

    notary_map: dict[str, NotaryNodeInfo] = {n.notary_id: n for n in notary_registry}
    pub_key_norm = publisher_public_key_hex.strip().lower()
    pub_kid_norm = publisher_kid.strip().lower()
    pub_org_norm = publisher_org.strip().lower()

    valid_by_sni: dict[str, list[tuple[NotaryNodeInfo, datetime]]] = defaultdict(list)
    total_valid_witnesses = 0

    for att in witness_attestations:
        notary = notary_map.get(att.notary_id)
        if notary is None:
            reasons.append(f"Notary {att.notary_id!r} is not present in trusted notary registry")
            continue
        if notary.is_debug_build or notary.attestation_type.strip().lower() == "debug":
            reasons.append(f"Notary {att.notary_id!r} uses a debug build/attestation")
            continue
        if pub_kid_norm and notary.notary_id.strip().lower() == pub_kid_norm:
            reasons.append(f"Notary {att.notary_id!r} shares key ID with bundle publisher")
            continue
        if pub_key_norm and notary.public_key_hex.lower() == pub_key_norm:
            reasons.append(f"Notary {att.notary_id!r} shares public key with bundle publisher")
            continue
        if pub_org_norm and notary.operator_org.strip().lower() == pub_org_norm:
            reasons.append(
                f"Notary {att.notary_id!r} is operated by publisher org ({notary.operator_org!r})"
            )
            continue
        if att.response_body_sha256 != norm_source_sha:
            reasons.append(
                f"Notary {att.notary_id!r} response_body_sha256 does not match source_body_sha256"
            )
            continue
        safe_ok, safety_violations = inspect_transcript_safety(att)
        if not safe_ok:
            reasons.extend(safety_violations)
            continue
        if not att.verify_signature(notary.public_key_hex):
            reasons.append(f"Notary {att.notary_id!r} Ed25519 signature verification failed")
            continue

        sni_norm = att.server_sni.strip().lower().rstrip(".")
        target_raw = att.sanitized_request_target.strip()
        if target_raw.lower().startswith(("http://", "https://")) or target_raw.startswith("//"):
            parsed_host = (urllib.parse.urlsplit(target_raw).hostname or "").strip().lower().rstrip(".")
            if parsed_host != sni_norm:
                reasons.append(
                    f"Notary {att.notary_id!r} sanitized_request_target host mismatches server_sni {sni_norm!r}"
                )
                continue
        if broker_id_norm is not None:
            allowed_snis = BROKER_WITNESS_SNI_ALLOWLIST.get(broker_id_norm)
            if not allowed_snis or sni_norm not in allowed_snis:
                reasons.append(
                    f"Notary {att.notary_id!r} server_sni {sni_norm!r} is not an official TLS endpoint for broker_id={broker_id!r}"
                )
                continue

        ts = parse_utc_timestamp(att.session_timestamp_utc)
        valid_by_sni[sni_norm].append((notary, ts))
        total_valid_witnesses += 1

    best_quorum = 0
    best_orgs = 0
    best_asns = 0
    for sni_candidates in valid_by_sni.values():
        q_size, org_cnt, asn_cnt = _max_mutually_disjoint_quorum(
            sni_candidates, max_witness_skew_seconds
        )
        if (q_size, org_cnt, asn_cnt) > (best_quorum, best_orgs, best_asns):
            best_quorum, best_orgs, best_asns = q_size, org_cnt, asn_cnt

    if best_quorum >= 2:
        return WitnessQuorumEvaluation(
            effective_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
            valid_witness_count=total_valid_witnesses,
            disjoint_quorum_size=best_quorum,
            distinct_org_count=best_orgs,
            distinct_asn_count=best_asns,
            broker_signature_valid=False,
            downgrade_reasons=reasons,
        )

    if total_valid_witnesses >= 1:
        reasons.append(
            f"Insufficient org/ASN-disjoint notary quorum (disjoint_quorum_size={best_quorum} < 2); "
            "downgraded to operator_retrieved"
        )
        return WitnessQuorumEvaluation(
            effective_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            valid_witness_count=total_valid_witnesses,
            disjoint_quorum_size=best_quorum,
            distinct_org_count=best_orgs,
            distinct_asn_count=best_asns,
            broker_signature_valid=False,
            downgrade_reasons=reasons,
        )

    if (
        provider_approval_state != ProviderApprovalState.OFFLINE_EXPORT_ONLY
        and claimed_origin_assurance != OriginAssurance.SELF_REPORTED
    ):
        if claimed_origin_assurance in {
            OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
            OriginAssurance.BROKER_SIGNED,
        }:
            reasons.append(
                f"Claimed {claimed_origin_assurance.value} without valid quorum/broker signature; "
                "downgraded to operator_retrieved"
            )
        return WitnessQuorumEvaluation(
            effective_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            valid_witness_count=0,
            disjoint_quorum_size=0,
            distinct_org_count=0,
            distinct_asn_count=0,
            broker_signature_valid=False,
            downgrade_reasons=reasons,
        )

    if claimed_origin_assurance is not None and claimed_origin_assurance != OriginAssurance.SELF_REPORTED:
        reasons.append(
            f"Offline export without valid witness quorum or broker signature; "
            f"downgraded from {claimed_origin_assurance.value} to self_reported"
        )
    return WitnessQuorumEvaluation(
        effective_origin_assurance=OriginAssurance.SELF_REPORTED,
        valid_witness_count=0,
        disjoint_quorum_size=0,
        distinct_org_count=0,
        distinct_asn_count=0,
        broker_signature_valid=False,
        downgrade_reasons=reasons,
    )


def compute_effective_origin_assurance(
    *,
    source_body_sha256: str,
    broker_id: str | None = None,
    signer_trust: SignerTrustStatus = SignerTrustStatus.OFFICIAL_N170_HOSTED,
    publisher_kid: str = "",
    publisher_public_key_hex: str = "",
    publisher_org: str = "N170",
    environment_tier: EnvironmentTier = EnvironmentTier.LIVE_PRODUCTION,
    provider_approval_state: ProviderApprovalState = ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    claimed_origin_assurance: OriginAssurance | None = None,
    witness_attestations: Sequence[WitnessAttestation] = (),
    notary_registry: Sequence[NotaryNodeInfo] = (),
    broker_native_signature: BrokerNativeSignature | None = None,
    pinned_broker_keys: Mapping[str, Mapping[str, str]] | None = None,
    max_witness_skew_seconds: int = DEFAULT_MAX_WITNESS_SKEW_SECONDS,
) -> OriginAssurance:
    """Return the dynamically verified ``OriginAssurance`` enum."""
    return evaluate_origin_assurance(
        source_body_sha256=source_body_sha256,
        broker_id=broker_id,
        signer_trust=signer_trust,
        publisher_kid=publisher_kid,
        publisher_public_key_hex=publisher_public_key_hex,
        publisher_org=publisher_org,
        environment_tier=environment_tier,
        provider_approval_state=provider_approval_state,
        claimed_origin_assurance=claimed_origin_assurance,
        witness_attestations=witness_attestations,
        notary_registry=notary_registry,
        broker_native_signature=broker_native_signature,
        pinned_broker_keys=pinned_broker_keys,
        max_witness_skew_seconds=max_witness_skew_seconds,
    ).effective_origin_assurance


__all__ = [
    "BROKER_WITNESS_SNI_ALLOWLIST",
    "BrokerNativeSignature",
    "DEFAULT_MAX_WITNESS_SKEW_SECONDS",
    "NotaryNodeInfo",
    "REQUIRED_TLSN_PROTOCOL",
    "REQUIRED_TLS_VERSION",
    "TranscriptCommitmentKind",
    "WitnessAttestation",
    "WitnessQuorumEvaluation",
    "compute_effective_origin_assurance",
    "create_signed_broker_signature",
    "create_signed_witness_attestation",
    "evaluate_origin_assurance",
    "inspect_transcript_safety",
    "verify_broker_native_signature",
]
