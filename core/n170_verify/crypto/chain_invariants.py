"""Five formal prospective chain invariants for LP due-diligence continuity verification."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import math
from typing import Any

from n170_verify.contracts.assurance import (
    ChainContinuityMode,
    ContractModelMixin,
    parse_utc_timestamp,
    validate_hex_digest,
)
from n170_verify.crypto.canonical import jcs_sha256_hex


GENESIS_ENROLLMENT_WINDOW_SECONDS = 86_400
INDEX_CONTINUITY_TOLERANCE = 1e-4


class ChainInvariantViolationCode(str, Enum):
    """Specific prospective continuity invariant violation codes."""

    GENESIS_BACKFILL_WINDOW_EXCEEDED = "genesis_backfill_window_exceeded"
    NON_MONOTONIC_SEQUENCE = "non_monotonic_sequence"
    PREV_HASH_MISMATCH = "prev_hash_mismatch"
    CADENCE_POLICY_MUTATED = "cadence_policy_mutated"
    ACCOUNT_CONTINUITY_VIOLATION = "account_continuity_violation"
    MISSED_INTERVAL_DETECTED = "missed_interval_detected"
    STALE_OR_TRUNCATED_TAIL = "stale_or_truncated_tail"
    PARALLEL_CHAIN_RESET_DETECTED = "parallel_chain_reset_detected"


@dataclass(slots=True)
class ChainCadencePolicy(ContractModelMixin):
    """Immutable reporting cadence and issuance grace window committed at chain genesis."""

    expected_interval_seconds: int
    grace_window_seconds: int

    def _validate(self) -> None:
        if self.expected_interval_seconds <= 0:
            raise ValueError("ChainCadencePolicy.expected_interval_seconds must be > 0")
        if self.grace_window_seconds < 0:
            raise ValueError("ChainCadencePolicy.grace_window_seconds must be >= 0")


@dataclass(slots=True)
class ProspectiveChainLink(ContractModelMixin):
    """Single sequence link inside an enrolled prospective performance chain."""

    chain_id: str
    sequence_number: int
    prev_proof_hash: str | None
    blinded_account_tag: str
    enrolled_at_utc: str
    period_start_utc: str
    period_end_utc: str
    issued_at_utc: str
    cadence_policy: ChainCadencePolicy
    beginning_index_value: float
    ending_index_value: float
    period_twr_decimal: float

    def _validate(self) -> None:
        if not self.chain_id.strip():
            raise ValueError("ProspectiveChainLink.chain_id must not be empty")
        if self.sequence_number < 0:
            raise ValueError("ProspectiveChainLink.sequence_number must be >= 0")
        if self.prev_proof_hash is not None:
            object.__setattr__(
                self,
                "prev_proof_hash",
                validate_hex_digest(
                    self.prev_proof_hash,
                    field_name="ProspectiveChainLink.prev_proof_hash",
                    num_bytes=32,
                ),
            )
        object.__setattr__(
            self,
            "blinded_account_tag",
            validate_hex_digest(
                self.blinded_account_tag,
                field_name="ProspectiveChainLink.blinded_account_tag",
                num_bytes=32,
            ),
        )
        parse_utc_timestamp(self.enrolled_at_utc, field_name="ProspectiveChainLink.enrolled_at_utc")
        parse_utc_timestamp(
            self.period_start_utc, field_name="ProspectiveChainLink.period_start_utc"
        )
        parse_utc_timestamp(self.period_end_utc, field_name="ProspectiveChainLink.period_end_utc")
        parse_utc_timestamp(self.issued_at_utc, field_name="ProspectiveChainLink.issued_at_utc")
        if (
            isinstance(self.beginning_index_value, bool)
            or isinstance(self.ending_index_value, bool)
            or isinstance(self.period_twr_decimal, bool)
            or not math.isfinite(self.beginning_index_value)
            or not math.isfinite(self.ending_index_value)
            or not math.isfinite(self.period_twr_decimal)
        ):
            raise ValueError("ProspectiveChainLink numeric fields must be finite numbers")
        if self.beginning_index_value <= 0.0 or self.ending_index_value <= 0.0:
            raise ValueError("ProspectiveChainLink index values must be > 0")


@dataclass(slots=True)
class ContinuityLogLeaf(ContractModelMixin):
    """Append-only transparency log entry committing ``(blinded_account_tag, sequence_number, proof_hash)``."""

    log_index: int
    chain_id: str
    blinded_account_tag: str
    sequence_number: int
    proof_hash: str
    logged_at_utc: str

    def _validate(self) -> None:
        if self.log_index < 0:
            raise ValueError("ContinuityLogLeaf.log_index must be >= 0")
        if not self.chain_id.strip():
            raise ValueError("ContinuityLogLeaf.chain_id must not be empty")
        object.__setattr__(
            self,
            "blinded_account_tag",
            validate_hex_digest(
                self.blinded_account_tag,
                field_name="ContinuityLogLeaf.blinded_account_tag",
                num_bytes=32,
            ),
        )
        if self.sequence_number < 0:
            raise ValueError("ContinuityLogLeaf.sequence_number must be >= 0")
        object.__setattr__(
            self,
            "proof_hash",
            validate_hex_digest(
                self.proof_hash,
                field_name="ContinuityLogLeaf.proof_hash",
                num_bytes=32,
            ),
        )
        parse_utc_timestamp(self.logged_at_utc, field_name="ContinuityLogLeaf.logged_at_utc")


@dataclass(slots=True)
class ChainVerificationResult(ContractModelMixin):
    """Outcome of verifying the 5 formal prospective chain invariants."""

    valid: bool
    continuity_mode: ChainContinuityMode
    verified_length: int
    violation_codes: list[ChainInvariantViolationCode] = field(default_factory=list)
    details: list[str] = field(default_factory=list)


def compute_chain_element_hash(proof_or_link: Any) -> str:
    """Compute canonical ``SHA256(JCS(signable_header))`` for a bundle or link."""
    if hasattr(proof_or_link, "signable_header") and callable(proof_or_link.signable_header):
        return jcs_sha256_hex(proof_or_link.signable_header())
    if isinstance(proof_or_link, ProspectiveChainLink):
        return jcs_sha256_hex(proof_or_link.to_dict())
    raise TypeError(
        f"Unsupported chain element type {type(proof_or_link).__name__}; "
        "expected VerifyProofBundle or ProspectiveChainLink"
    )


def _extract_link_and_hash(item: Any) -> tuple[ProspectiveChainLink | None, str, str | None]:
    """Return ``(link, element_hash, outer_blinded_account_tag)``."""
    if isinstance(item, ProspectiveChainLink):
        return item, compute_chain_element_hash(item), None
    if hasattr(item, "prospective_chain_link"):
        link = getattr(item, "prospective_chain_link")
        outer_tag = getattr(item, "blinded_account_tag", None)
        return link, compute_chain_element_hash(item), outer_tag
    raise TypeError(
        f"Expected ProspectiveChainLink or VerifyProofBundle, got {type(item).__name__}"
    )


def verify_prospective_chain(
    proofs: Sequence[Any],
    continuity_log_leaves: Sequence[ContinuityLogLeaf] | None = None,
    now_utc: str | datetime | None = None,
) -> ChainVerificationResult:
    """Verify all 5 formal LP due-diligence prospective chain invariants."""
    if not proofs:
        return ChainVerificationResult(
            valid=True,
            continuity_mode=ChainContinuityMode.UNENROLLED_SINGLE_SNAPSHOT,
            verified_length=0,
            violation_codes=[],
            details=["No prospective chain elements provided; single unenrolled snapshot."],
        )

    extracted = [_extract_link_and_hash(item) for item in proofs]
    if len(extracted) == 1 and extracted[0][0] is None:
        return ChainVerificationResult(
            valid=True,
            continuity_mode=ChainContinuityMode.UNENROLLED_SINGLE_SNAPSHOT,
            verified_length=0,
            violation_codes=[],
            details=["Proof bundle is an unenrolled single snapshot."],
        )

    violations: list[ChainInvariantViolationCode] = []
    details: list[str] = []

    def _record(code: ChainInvariantViolationCode, message: str) -> None:
        if code not in violations:
            violations.append(code)
        details.append(message)

    links: list[ProspectiveChainLink] = []
    elem_hashes: list[str] = []
    for idx, (link, digest, outer_tag) in enumerate(extracted):
        if link is None:
            _record(
                ChainInvariantViolationCode.NON_MONOTONIC_SEQUENCE,
                f"Element {idx} in multi-element chain is missing prospective_chain_link",
            )
            return ChainVerificationResult(
                valid=False,
                continuity_mode=ChainContinuityMode.CONTINUITY_BROKEN,
                verified_length=idx,
                violation_codes=violations,
                details=details,
            )
        if outer_tag is not None and outer_tag != link.blinded_account_tag:
            _record(
                ChainInvariantViolationCode.ACCOUNT_CONTINUITY_VIOLATION,
                f"Element {idx} bundle blinded_account_tag mismatches chain link blinded_account_tag",
            )
        links.append(link)
        elem_hashes.append(digest)

    genesis = links[0]

    # Invariant 1: 24h Genesis Enrollment Window & Genesis Boundary
    if genesis.sequence_number != 0:
        _record(
            ChainInvariantViolationCode.NON_MONOTONIC_SEQUENCE,
            f"Genesis link sequence_number must be 0 (got {genesis.sequence_number})",
        )
    if genesis.prev_proof_hash is not None:
        _record(
            ChainInvariantViolationCode.PREV_HASH_MISMATCH,
            "Genesis link prev_proof_hash must be None",
        )

    g_enrolled = parse_utc_timestamp(genesis.enrolled_at_utc)
    g_start = parse_utc_timestamp(genesis.period_start_utc)
    g_end = parse_utc_timestamp(genesis.period_end_utc)
    g_issued = parse_utc_timestamp(genesis.issued_at_utc)

    if g_end <= g_start:
        _record(
            ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
            "Genesis period_end_utc must be strictly after period_start_utc",
        )
    if g_issued < g_end:
        _record(
            ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
            "Genesis issued_at_utc cannot precede period_end_utc",
        )

    enrollment_delta = abs((g_enrolled - g_start).total_seconds())
    genesis_issue_lag = (g_issued - g_end).total_seconds()
    if (
        enrollment_delta > GENESIS_ENROLLMENT_WINDOW_SECONDS
        or genesis_issue_lag > genesis.cadence_policy.grace_window_seconds
    ):
        _record(
            ChainInvariantViolationCode.GENESIS_BACKFILL_WINDOW_EXCEEDED,
            f"Genesis enrollment delta ({enrollment_delta:.0f}s) or issuance lag "
            f"({genesis_issue_lag:.0f}s) exceeds prospective window; classified as retrospective backfill",
        )

    # Check internal index math on every link + Invariants 2, 3, 4 across consecutive links
    intact_prefix = 0
    structural_broken = any(
        c != ChainInvariantViolationCode.GENESIS_BACKFILL_WINDOW_EXCEEDED for c in violations
    )

    expected_end_0 = genesis.beginning_index_value * (1.0 + genesis.period_twr_decimal)
    if abs(genesis.ending_index_value - expected_end_0) > INDEX_CONTINUITY_TOLERANCE:
        _record(
            ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
            "Genesis ending_index_value does not match beginning_index_value * (1 + period_twr_decimal)",
        )
        structural_broken = True

    if not structural_broken:
        intact_prefix = 1

    for idx in range(1, len(links)):
        prev_link = links[idx - 1]
        curr_link = links[idx]
        link_ok = True

        # Invariant 2: Monotonic sequence_number, prev_proof_hash == SHA256(JCS(P_{i-1}.signable_header)), immutable cadence_policy
        if curr_link.sequence_number != prev_link.sequence_number + 1:
            _record(
                ChainInvariantViolationCode.NON_MONOTONIC_SEQUENCE,
                f"Link {idx} sequence_number={curr_link.sequence_number} expected {prev_link.sequence_number + 1}",
            )
            link_ok = False

        if curr_link.prev_proof_hash != elem_hashes[idx - 1] or curr_link.chain_id != genesis.chain_id:
            _record(
                ChainInvariantViolationCode.PREV_HASH_MISMATCH,
                f"Link {idx} prev_proof_hash or chain_id does not match previous proof digest",
            )
            link_ok = False

        if curr_link.cadence_policy != genesis.cadence_policy:
            _record(
                ChainInvariantViolationCode.CADENCE_POLICY_MUTATED,
                f"Link {idx} mutated cadence_policy from genesis commitment",
            )
            link_ok = False

        # Invariant 3: blinded_account_tag pinning
        if curr_link.blinded_account_tag != genesis.blinded_account_tag:
            _record(
                ChainInvariantViolationCode.ACCOUNT_CONTINUITY_VIOLATION,
                f"Link {idx} blinded_account_tag switched mid-chain",
            )
            link_ok = False

        # Invariant 4: Contiguous period boundaries + timely issuance + flow-adjusted index continuity
        prev_end_dt = parse_utc_timestamp(prev_link.period_end_utc)
        curr_start_dt = parse_utc_timestamp(curr_link.period_start_utc)
        curr_end_dt = parse_utc_timestamp(curr_link.period_end_utc)
        curr_issued_dt = parse_utc_timestamp(curr_link.issued_at_utc)

        if curr_start_dt != prev_end_dt:
            _record(
                ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
                f"Link {idx} period_start_utc ({curr_link.period_start_utc}) != "
                f"prev.period_end_utc ({prev_link.period_end_utc})",
            )
            link_ok = False

        if curr_end_dt <= curr_start_dt:
            _record(
                ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
                f"Link {idx} period_end_utc must be strictly after period_start_utc",
            )
            link_ok = False

        issue_lag = (curr_issued_dt - curr_end_dt).total_seconds()
        if issue_lag < 0 or issue_lag > genesis.cadence_policy.grace_window_seconds:
            _record(
                ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
                f"Link {idx} issued_at_utc violates [period_end_utc, period_end_utc + grace_window_seconds]",
            )
            link_ok = False

        if abs(curr_link.beginning_index_value - prev_link.ending_index_value) > INDEX_CONTINUITY_TOLERANCE:
            _record(
                ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
                f"Link {idx} beginning_index_value ({curr_link.beginning_index_value}) "
                f"discontinuous with prev.ending_index_value ({prev_link.ending_index_value})",
            )
            link_ok = False

        expected_curr_end = curr_link.beginning_index_value * (1.0 + curr_link.period_twr_decimal)
        if abs(curr_link.ending_index_value - expected_curr_end) > INDEX_CONTINUITY_TOLERANCE:
            _record(
                ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
                f"Link {idx} ending_index_value inconsistent with period_twr_decimal",
            )
            link_ok = False

        if not link_ok:
            structural_broken = True
        elif not structural_broken:
            intact_prefix += 1

    # Invariant 5: Transparency Log Monotonicity & Tail Freshness
    if continuity_log_leaves is not None:
        acct_leaves = [
            leaf
            for leaf in continuity_log_leaves
            if leaf.blinded_account_tag == genesis.blinded_account_tag
        ]
        genesis_leaves = [leaf for leaf in acct_leaves if leaf.sequence_number == 0]
        if len(genesis_leaves) > 1:
            _record(
                ChainInvariantViolationCode.PARALLEL_CHAIN_RESET_DETECTED,
                "Continuity log contains multiple sequence_number == 0 entries for blinded_account_tag",
            )
            structural_broken = True

        distinct_chains = {leaf.chain_id for leaf in acct_leaves}
        if distinct_chains and (len(distinct_chains) > 1 or genesis.chain_id not in distinct_chains):
            _record(
                ChainInvariantViolationCode.PARALLEL_CHAIN_RESET_DETECTED,
                "Continuity log records a conflicting chain_id for blinded_account_tag",
            )
            structural_broken = True

        logged_by_seq: dict[int, str] = {}
        for leaf in acct_leaves:
            existing = logged_by_seq.get(leaf.sequence_number)
            if existing is not None and existing != leaf.proof_hash:
                _record(
                    ChainInvariantViolationCode.PARALLEL_CHAIN_RESET_DETECTED,
                    f"Continuity log contains conflicting proof_hash entries at sequence {leaf.sequence_number}",
                )
                structural_broken = True
            logged_by_seq[leaf.sequence_number] = leaf.proof_hash

        for link, digest in zip(links, elem_hashes):
            logged_hash = logged_by_seq.get(link.sequence_number)
            if logged_hash is not None and logged_hash != digest:
                _record(
                    ChainInvariantViolationCode.PARALLEL_CHAIN_RESET_DETECTED,
                    f"Presented proof hash at sequence {link.sequence_number} conflicts with transparency log",
                )
                structural_broken = True

        max_presented_seq = links[-1].sequence_number
        if any(leaf.sequence_number > max_presented_seq for leaf in acct_leaves):
            _record(
                ChainInvariantViolationCode.STALE_OR_TRUNCATED_TAIL,
                "Continuity log contains newer sequence_number(s) omitted from presented chain tail",
            )
            structural_broken = True

    if now_utc is not None:
        now_dt = parse_utc_timestamp(now_utc, field_name="now_utc")
        last_link = links[-1]
        last_end_dt = parse_utc_timestamp(last_link.period_end_utc)
        freshness_deadline = last_end_dt + timedelta(
            seconds=(
                last_link.cadence_policy.expected_interval_seconds
                + last_link.cadence_policy.grace_window_seconds
            )
        )
        if now_dt > freshness_deadline:
            _record(
                ChainInvariantViolationCode.STALE_OR_TRUNCATED_TAIL,
                f"Chain tail period_end_utc ({last_link.period_end_utc}) is stale at {now_dt.isoformat()}",
            )
            structural_broken = True

    if structural_broken:
        mode = ChainContinuityMode.CONTINUITY_BROKEN
    elif ChainInvariantViolationCode.GENESIS_BACKFILL_WINDOW_EXCEEDED in violations:
        mode = ChainContinuityMode.RETROSPECTIVE_BACKFILL
    else:
        mode = ChainContinuityMode.PROSPECTIVE_CONTINUOUS

    return ChainVerificationResult(
        valid=len(violations) == 0,
        continuity_mode=mode,
        verified_length=intact_prefix,
        violation_codes=violations,
        details=details,
    )


__all__ = [
    "ChainCadencePolicy",
    "ChainInvariantViolationCode",
    "ChainVerificationResult",
    "ContinuityLogLeaf",
    "GENESIS_ENROLLMENT_WINDOW_SECONDS",
    "INDEX_CONTINUITY_TOLERANCE",
    "ProspectiveChainLink",
    "compute_chain_element_hash",
    "verify_prospective_chain",
]
