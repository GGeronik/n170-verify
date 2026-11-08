"""Salted Merkle tree construction and selective disclosure with 0x00/0x01 domain separation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import secrets
from typing import Any

from n170_verify.contracts.assurance import ContractModelMixin, validate_hex_digest
from n170_verify.crypto.canonical import jcs_canonicalize


CANONICAL_LEAF_NAMES: tuple[str, ...] = (
    "core_metrics",
    "indexed_curve",
    "reconciliation",
    "coaching_and_context",
    "capital_bracket",
    "benchmark_alpha",
    "delayed_closed_trades",
)

LEAF_DOMAIN_PREFIX = b"n170.verify.leaf.v3\x00"
NODE_DOMAIN_PREFIX = b"n170.verify.node.v3\x01"


def generate_leaf_salt_hex() -> str:
    """Generate a cryptographically random 256-bit (32-byte / 64-hex-char) leaf salt."""
    return secrets.token_hex(32)


def compute_salted_leaf_hash(leaf_name: str, salt_32b_hex: str, payload: Any) -> str:
    """Compute domain-separated salted Merkle leaf digest.

    Formula:
        SHA256(b"n170.verify.leaf.v3\\x00" + leaf_name_utf8 + b"\\x00" + salt_32b + b"\\x00" + jcs_bytes)
    """
    if not isinstance(leaf_name, str) or not leaf_name.strip() or "\x00" in leaf_name:
        raise ValueError("leaf_name must be a non-empty string without NUL bytes")
    norm_salt = validate_hex_digest(salt_32b_hex, field_name="salt_32b_hex", num_bytes=32)
    salt_bytes = bytes.fromhex(norm_salt)
    jcs_bytes = jcs_canonicalize(payload)
    preimage = (
        LEAF_DOMAIN_PREFIX
        + leaf_name.encode("utf-8")
        + b"\x00"
        + salt_bytes
        + b"\x00"
        + jcs_bytes
    )
    return hashlib.sha256(preimage).hexdigest()


def compute_internal_node_hash(left_hash_hex: str, right_hash_hex: str) -> str:
    """Compute domain-separated internal node digest.

    Formula:
        SHA256(b"n170.verify.node.v3\\x01" + left_32b + right_32b)
    """
    left_norm = validate_hex_digest(left_hash_hex, field_name="left_hash_hex", num_bytes=32)
    right_norm = validate_hex_digest(right_hash_hex, field_name="right_hash_hex", num_bytes=32)
    preimage = NODE_DOMAIN_PREFIX + bytes.fromhex(left_norm) + bytes.fromhex(right_norm)
    return hashlib.sha256(preimage).hexdigest()


def _build_tree_layers(ordered_leaf_hashes: Sequence[str]) -> list[list[str]]:
    if not ordered_leaf_hashes:
        raise ValueError("Cannot construct Merkle tree from empty leaf sequence")
    current = [
        validate_hex_digest(h, field_name=f"leaf_hash[{idx}]", num_bytes=32)
        for idx, h in enumerate(ordered_leaf_hashes)
    ]
    layers: list[list[str]] = [current]
    while len(current) > 1:
        next_layer: list[str] = []
        idx = 0
        while idx < len(current):
            if idx + 1 < len(current):
                next_layer.append(compute_internal_node_hash(current[idx], current[idx + 1]))
                idx += 2
            else:
                # Odd trailing node promotes directly without duplication; leaf/node
                # 0x00 vs 0x01 domain separation prevents tree-depth second preimages.
                next_layer.append(current[idx])
                idx += 1
        layers.append(next_layer)
        current = next_layer
    return layers


def compute_merkle_root_from_leaf_hashes(ordered_leaf_hashes: Sequence[str]) -> str:
    """Compute canonical Merkle root from ordered 32-byte hex leaf hashes."""
    return _build_tree_layers(ordered_leaf_hashes)[-1][0]


@dataclass(slots=True)
class MerkleAuditStep(ContractModelMixin):
    """Single directional sibling hash in a Merkle inclusion proof."""

    side: str
    sibling_hash_hex: str

    def _validate(self) -> None:
        cleaned_side = self.side.strip().lower()
        if cleaned_side not in {"left", "right"}:
            raise ValueError("MerkleAuditStep.side must be 'left' or 'right'")
        object.__setattr__(self, "side", cleaned_side)
        object.__setattr__(
            self,
            "sibling_hash_hex",
            validate_hex_digest(
                self.sibling_hash_hex,
                field_name="MerkleAuditStep.sibling_hash_hex",
                num_bytes=32,
            ),
        )


@dataclass(slots=True)
class DisclosedLeaf(ContractModelMixin):
    """Selectively disclosed Merkle leaf carrying its 256-bit salt, payload, and audit path."""

    leaf_name: str
    salt_hex: str
    payload: Any
    leaf_hash_hex: str
    audit_path: list[MerkleAuditStep] = field(default_factory=list)

    def _validate(self) -> None:
        if not self.leaf_name.strip() or "\x00" in self.leaf_name:
            raise ValueError("DisclosedLeaf.leaf_name must be a valid non-empty string")
        object.__setattr__(
            self,
            "salt_hex",
            validate_hex_digest(self.salt_hex, field_name="DisclosedLeaf.salt_hex", num_bytes=32),
        )
        object.__setattr__(
            self,
            "leaf_hash_hex",
            validate_hex_digest(
                self.leaf_hash_hex, field_name="DisclosedLeaf.leaf_hash_hex", num_bytes=32
            ),
        )
        # Ensure payload is JCS-serializable at construction time.
        jcs_canonicalize(self.payload)


def verify_merkle_audit_path(
    leaf_hash_hex: str,
    audit_path: Sequence[MerkleAuditStep],
    expected_root_hex: str,
) -> bool:
    """Walk ``audit_path`` from ``leaf_hash_hex`` and compare against ``expected_root_hex``."""
    try:
        current = validate_hex_digest(leaf_hash_hex, field_name="leaf_hash_hex", num_bytes=32)
        target = validate_hex_digest(expected_root_hex, field_name="expected_root_hex", num_bytes=32)
    except ValueError:
        return False

    for step in audit_path:
        if not isinstance(step, MerkleAuditStep):
            try:
                step = MerkleAuditStep.from_dict(step)
            except ValueError:
                return False
        if step.side == "left":
            current = compute_internal_node_hash(step.sibling_hash_hex, current)
        elif step.side == "right":
            current = compute_internal_node_hash(current, step.sibling_hash_hex)
        else:
            return False
    return current == target


def verify_disclosed_leaf(leaf: DisclosedLeaf, expected_root_hex: str) -> bool:
    """Verify both the salted JCS leaf commitment and its Merkle inclusion path to ``expected_root_hex``."""
    try:
        recomputed_leaf_hash = compute_salted_leaf_hash(
            leaf.leaf_name,
            leaf.salt_hex,
            leaf.payload,
        )
    except (ValueError, TypeError):
        return False
    if recomputed_leaf_hash != leaf.leaf_hash_hex:
        return False
    return verify_merkle_audit_path(recomputed_leaf_hash, leaf.audit_path, expected_root_hex)


@dataclass(slots=True)
class SaltedMerkleTree:
    """Complete pre-redaction salted Merkle commitment tree over canonical disclosure leaves."""

    leaf_order: tuple[str, ...]
    leaf_salts_hex: dict[str, str]
    leaf_payloads: dict[str, Any]
    leaf_hashes_hex: dict[str, str]
    layers: list[list[str]]

    @property
    def merkle_root(self) -> str:
        return self.layers[-1][0]

    def audit_path_for(self, leaf_name: str) -> list[MerkleAuditStep]:
        if leaf_name not in self.leaf_order:
            raise KeyError(f"Unknown leaf_name: {leaf_name!r}")
        idx = self.leaf_order.index(leaf_name)
        steps: list[MerkleAuditStep] = []
        for layer in self.layers[:-1]:
            if idx % 2 == 0:
                if idx + 1 < len(layer):
                    steps.append(MerkleAuditStep(side="right", sibling_hash_hex=layer[idx + 1]))
            else:
                steps.append(MerkleAuditStep(side="left", sibling_hash_hex=layer[idx - 1]))
            idx //= 2
        return steps

    def selectively_disclose(
        self,
        disclose_leaf_names: Iterable[str] | None = None,
    ) -> tuple[list[DisclosedLeaf], dict[str, str]]:
        """Produce ``(disclosed_leaves, undisclosed_leaf_hashes)`` omitting salts & payloads for hidden leaves."""
        if disclose_leaf_names is None:
            chosen = set(self.leaf_order)
        else:
            chosen = set(disclose_leaf_names)
            unknown = chosen - set(self.leaf_order)
            if unknown:
                raise ValueError(f"Unknown leaf name(s) requested for disclosure: {sorted(unknown)}")

        disclosed: list[DisclosedLeaf] = []
        undisclosed: dict[str, str] = {}
        for name in self.leaf_order:
            if name in chosen:
                disclosed.append(
                    DisclosedLeaf(
                        leaf_name=name,
                        salt_hex=self.leaf_salts_hex[name],
                        payload=self.leaf_payloads[name],
                        leaf_hash_hex=self.leaf_hashes_hex[name],
                        audit_path=self.audit_path_for(name),
                    )
                )
            else:
                undisclosed[name] = self.leaf_hashes_hex[name]
        return disclosed, undisclosed


def build_salted_merkle_tree(
    leaf_payloads: Mapping[str, Any],
    leaf_salts_hex: Mapping[str, str] | None = None,
    *,
    leaf_order: Sequence[str] = CANONICAL_LEAF_NAMES,
) -> SaltedMerkleTree:
    """Build a salted Merkle tree across ``leaf_order`` (defaulting to the 7 canonical Verify v3 leaves)."""
    order_tuple = tuple(leaf_order)
    if len(set(order_tuple)) != len(order_tuple) or not order_tuple:
        raise ValueError("leaf_order must be non-empty with unique leaf names")
    expected_set = set(order_tuple)
    provided_set = set(leaf_payloads.keys())
    if provided_set != expected_set:
        missing = sorted(expected_set - provided_set)
        extra = sorted(provided_set - expected_set)
        raise ValueError(
            f"leaf_payloads keys must match canonical leaf_order (missing={missing}, extra={extra})"
        )

    salts: dict[str, str] = {}
    hashes: dict[str, str] = {}
    ordered_hashes: list[str] = []
    for name in order_tuple:
        if leaf_salts_hex is not None and name in leaf_salts_hex:
            salt = validate_hex_digest(
                leaf_salts_hex[name], field_name=f"leaf_salts_hex[{name!r}]", num_bytes=32
            )
        else:
            salt = generate_leaf_salt_hex()
        salts[name] = salt
        leaf_hash = compute_salted_leaf_hash(name, salt, leaf_payloads[name])
        hashes[name] = leaf_hash
        ordered_hashes.append(leaf_hash)

    layers = _build_tree_layers(ordered_hashes)
    return SaltedMerkleTree(
        leaf_order=order_tuple,
        leaf_salts_hex=salts,
        leaf_payloads=dict(leaf_payloads),
        leaf_hashes_hex=hashes,
        layers=layers,
    )


def verify_selective_disclosure(
    merkle_root_hex: str,
    disclosed_leaves: Sequence[DisclosedLeaf],
    undisclosed_leaf_hashes: Mapping[str, str],
    *,
    expected_leaf_order: Sequence[str] = CANONICAL_LEAF_NAMES,
) -> tuple[bool, list[str]]:
    """Verify disclosed leaves (salts + payloads + audit paths) and canonical 7-leaf partition."""
    errors: list[str] = []
    try:
        norm_root = validate_hex_digest(merkle_root_hex, field_name="merkle_root_hex", num_bytes=32)
    except ValueError as exc:
        return False, [str(exc)]

    seen_disclosed: dict[str, str] = {}
    for leaf in disclosed_leaves:
        if leaf.leaf_name in seen_disclosed:
            errors.append(f"Duplicate disclosed leaf: {leaf.leaf_name!r}")
            continue
        if not verify_disclosed_leaf(leaf, norm_root):
            errors.append(f"Merkle disclosure verification failed for leaf {leaf.leaf_name!r}")
        seen_disclosed[leaf.leaf_name] = leaf.leaf_hash_hex

    overlap = set(seen_disclosed.keys()) & set(undisclosed_leaf_hashes.keys())
    if overlap:
        errors.append(f"Leaves present in both disclosed and undisclosed sets: {sorted(overlap)}")

    combined_hashes: dict[str, str] = dict(seen_disclosed)
    for name, digest in undisclosed_leaf_hashes.items():
        try:
            combined_hashes[name] = validate_hex_digest(
                digest, field_name=f"undisclosed_leaf_hashes[{name!r}]", num_bytes=32
            )
        except ValueError as exc:
            errors.append(str(exc))

    expected_set = set(expected_leaf_order)
    if set(combined_hashes.keys()) != expected_set:
        missing = sorted(expected_set - set(combined_hashes.keys()))
        extra = sorted(set(combined_hashes.keys()) - expected_set)
        errors.append(
            f"Canonical leaf partition mismatch (missing={missing}, extra={extra})"
        )
    elif not errors:
        rebuilt_root = compute_merkle_root_from_leaf_hashes(
            [combined_hashes[name] for name in expected_leaf_order]
        )
        if rebuilt_root != norm_root:
            errors.append(
                "Reconstructed canonical 7-leaf Merkle root does not match bundle merkle_root"
            )

    return len(errors) == 0, errors


__all__ = [
    "CANONICAL_LEAF_NAMES",
    "DisclosedLeaf",
    "LEAF_DOMAIN_PREFIX",
    "MerkleAuditStep",
    "NODE_DOMAIN_PREFIX",
    "SaltedMerkleTree",
    "build_salted_merkle_tree",
    "compute_internal_node_hash",
    "compute_merkle_root_from_leaf_hashes",
    "compute_salted_leaf_hash",
    "generate_leaf_salt_hex",
    "verify_disclosed_leaf",
    "verify_merkle_audit_path",
    "verify_selective_disclosure",
]
