"""Deterministic specimen generator for N170 Verify truth specimens."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from n170_verify.contracts import (
    AccountScope,
    EnvironmentTier,
    OriginAssurance,
    ProviderApprovalState,
    VERIFY_SCHEMA_VERSION,
    VerifyProofBundle,
    compute_blinded_account_tag,
    create_signed_proof_bundle,
    verify_proof_bundle,
)
from n170_verify.crypto import (
    CANONICAL_LEAF_NAMES,
    NotaryNodeInfo,
    PublisherKeyRecord,
    PublisherKeyRegistryDocument,
    TranscriptCommitmentKind,
    build_salted_merkle_tree,
    create_signed_c2sp_checkpoint,
    create_signed_witness_attestation,
    generate_ed25519_keypair,
)

DEFAULT_SPECIMEN_SEED_HEX: str = (
    "4e31373053706563696d656e5365656432303236547275746853756974653031"
)


@dataclass(frozen=True, slots=True)
class SpecimenGenerationResult:
    """Result of generating deterministic specimens and key registry."""

    seed_hex: str
    registry: PublisherKeyRegistryDocument
    bundle_s1: VerifyProofBundle
    bundle_offline: VerifyProofBundle


def derive_keypairs_from_seed(seed_hex: str) -> dict[str, Any]:
    """Deterministically derive Ed25519 keypairs from a 64-hex seed."""
    seed_bytes = bytes.fromhex(seed_hex)

    def derive(tag: bytes):
        raw_seed = hashlib.sha256(seed_bytes + b":" + tag).digest()
        return generate_ed25519_keypair(raw_seed)

    return {
        "pub_active": derive(b"publisher:2026-q1"),
        "pub_retired": derive(b"publisher:2025-h2"),
        "pub_revoked": derive(b"publisher:revoked"),
        "notary_pse": derive(b"notary:pse"),
        "notary_swiss": derive(b"notary:swiss"),
        "notary_nordic": derive(b"notary:nordic"),
        "notary_colocated": derive(b"notary:colocated"),
        "witness_sigsum": derive(b"witness:sigsum"),
        "witness_c2sp": derive(b"witness:c2sp"),
        "broker_prime": derive(b"broker:prime"),
    }


def build_specimen_registry(seed_hex: str, keys: Mapping[str, Any]) -> PublisherKeyRegistryDocument:
    """Build canonical PublisherKeyRegistryDocument with C2SP checkpoint cosignatures."""
    seed_bytes = bytes.fromhex(seed_hex)
    root_hash = hashlib.sha256(seed_bytes + b":c2sp-checkpoint-tree-root").hexdigest()

    ckpt = create_signed_c2sp_checkpoint(
        origin="n170.verify/transparency/v3",
        size=1284,
        root_hash_hex=root_hash,
        publisher_kid="n170-pub-2026-q1",
        publisher_private_key_hex=keys["pub_active"].private_key_hex,
        witness_signers=[
            (
                "witness-sigsum-se",
                keys["witness_sigsum"].private_key_hex,
                keys["witness_sigsum"].public_key_hex,
                "2026-04-01T11:58:10Z",
            ),
            (
                "witness-c2sp-ch",
                keys["witness_c2sp"].private_key_hex,
                keys["witness_c2sp"].public_key_hex,
                "2026-04-01T11:58:24Z",
            ),
        ],
    )

    return PublisherKeyRegistryDocument(
        updated_at_utc="2026-04-01T12:00:00Z",
        keys=[
            PublisherKeyRecord(
                publisher_kid="n170-pub-2026-q1",
                public_key_hex=keys["pub_active"].public_key_hex,
                status="active",
                not_before_utc="2026-01-01T00:00:00Z",
                not_after_utc="2027-01-01T00:00:00Z",
                issuer_org="N170",
            ),
            PublisherKeyRecord(
                publisher_kid="n170-pub-2025-h2",
                public_key_hex=keys["pub_retired"].public_key_hex,
                status="retired",
                not_before_utc="2025-07-01T00:00:00Z",
                not_after_utc="2025-12-31T23:59:59Z",
                issuer_org="N170",
            ),
            PublisherKeyRecord(
                publisher_kid="n170-pub-compromised-test",
                public_key_hex=keys["pub_revoked"].public_key_hex,
                status="revoked",
                not_before_utc="2025-01-01T00:00:00Z",
                not_after_utc=None,
                revoked_after_utc="2025-06-01T00:00:00Z",
                issuer_org="N170",
            ),
        ],
        notaries=[
            NotaryNodeInfo(
                notary_id="notary-pse-eu",
                operator_org="PSE TLSNotary Foundation",
                asn="AS24940",
                public_key_hex=keys["notary_pse"].public_key_hex,
                is_debug_build=False,
                attestation_type="aws_nitro_enclave",
            ),
            NotaryNodeInfo(
                notary_id="notary-swiss-ch",
                operator_org="Zurich Independent Attestations AG",
                asn="AS13030",
                public_key_hex=keys["notary_swiss"].public_key_hex,
                is_debug_build=False,
                attestation_type="amd_sev_snp",
            ),
            NotaryNodeInfo(
                notary_id="notary-nordic-is",
                operator_org="Reykjavik Transparency Lab",
                asn="AS44530",
                public_key_hex=keys["notary_nordic"].public_key_hex,
                is_debug_build=False,
                attestation_type="aws_nitro_enclave",
            ),
            NotaryNodeInfo(
                notary_id="notary-colocated-eu2",
                operator_org="Berlin Notary Guild",
                asn="AS24940",
                public_key_hex=keys["notary_colocated"].public_key_hex,
                is_debug_build=False,
                attestation_type="production",
            ),
        ],
        checkpoint=ckpt,
        pinned_broker_keys={
            "prime_custody_ed25519": {
                "prime-custody-k1": keys["broker_prime"].public_key_hex
            }
        },
    )


def build_specimen_s1(keys: Mapping[str, Any], seed_bytes: bytes) -> VerifyProofBundle:
    """Build canonical specimen-s1 proof bundle with 3-way disjoint witness quorum."""
    source_bytes = b"n170-specimen-s1-raw-statement-source-bytes"
    source_sha = hashlib.sha256(source_bytes).hexdigest()
    salt_hex = hashlib.sha256(seed_bytes + b":blinded-salt:s1").hexdigest()
    blinded_acct = compute_blinded_account_tag("ibkr", "U1234567", salt_hex)

    leaf_payloads = {
        "core_metrics": {
            "twr_decimal": 0.285,
            "twr_pct": 28.5,
            "cagr_decimal": 1.42,
            "cagr_pct": 142.0,
            "xirr_decimal": 1.38,
            "annualized_volatility": 0.182,
            "max_drawdown_decimal": 0.064,
            "max_drawdown_pct": 6.4,
            "sharpe_ratio": 2.14,
            "sortino_ratio": 3.25,
            "calmar_ratio": 4.45,
            "observation_count": 63,
            "trading_days": 63,
            "start_date": "2026-01-01",
            "end_date": "2026-03-31",
            "base_currency": "USD",
            "psr_sample_eligible": True,
            "probabilistic_sharpe_ratio": 0.982,
            "psr_glm_unsmoothed": 0.975,
            "min_track_record_length_days": 42.5,
            "unconditional_monthly_var_95": 0.041,
            "unconditional_monthly_cvar_95": 0.058,
            "benchmark_symbol": "SPY",
            "benchmark_twr_decimal": 0.082,
            "alpha_decimal": 0.203,
        },
        "indexed_curve": {
            "base_index": 100.0,
            "points": [
                {
                    "timestamp_utc": "2026-01-01T00:00:00Z",
                    "index_value": 100.0,
                    "drawdown_decimal": 0.0,
                    "benchmark_index_value": 100.0,
                },
                {
                    "timestamp_utc": "2026-02-15T00:00:00Z",
                    "index_value": 114.2,
                    "drawdown_decimal": 0.015,
                    "benchmark_index_value": 104.1,
                },
                {
                    "timestamp_utc": "2026-03-31T23:59:59Z",
                    "index_value": 128.5,
                    "drawdown_decimal": 0.021,
                    "benchmark_index_value": 108.2,
                },
            ],
        },
        "reconciliation": {
            "status": "reconciled_clean",
            "discrepancy_count": 0,
            "evaluated_at_utc": "2026-04-01T12:00:00Z",
            "tolerance_bps": 5.0,
            "sections_checked": [
                "nav_continuity",
                "cash_flow_timing",
                "corporate_actions",
                "market_envelope",
            ],
            "findings": [
                {
                    "category": "nav_continuity_bridge",
                    "outcome": "pass",
                    "residual_bps": 0.0,
                    "technical_explanation": (
                        "Period NAV continuity verified with zero residual across valuation points."
                    ),
                }
            ],
        },
        "coaching_and_context": {
            "cost_drag": {
                "commission_and_fee_drag_bps": 12.4,
                "margin_and_funding_drag_bps": 15.6,
                "fx_conversion_drag_bps": 6.2,
                "withholding_tax_drag_bps": 2.1,
                "total_friction_drag_bps": 36.3,
                "annualized_total_drag_bps": 145.2,
            },
            "behaviour": {
                "sample_eligible": True,
                "min_trades_gate": 30,
                "observed_trades": 84,
                "observed_days": 63,
                "median_holding_hours": 18.5,
                "holding_horizon_label": "swing_momentum",
                "win_rate": 0.655,
                "profit_factor": 2.12,
                "winner_vs_loser_hold_ratio": 1.45,
                "odean_pgr_plr_spread": 0.042,
                "post_drawdown_sizing_discipline_atr": 0.92,
                "atr_normalized": True,
                "return_concentration_top5_pct": 28.4,
                "actionable_improvements": [
                    "Discipline score within target: post-drawdown risk sizing maintained at 0.92x baseline ATR."
                ],
            },
            "catalyst_regime_win_rate": 0.725,
            "quiet_regime_win_rate": 0.612,
            "event_window_share_pct": 24.5,
            "event_observations": [],
        },
        "capital_bracket": {
            "capital_bracket": "100k_to_1m",
            "valuation_currency": "USD",
        },
        "benchmark_alpha": {
            "benchmark_symbol": "SPY",
            "benchmark_twr_decimal": 0.082,
            "alpha_decimal": 0.203,
            "information_ratio": 1.84,
            "beta": 0.94,
        },
        "delayed_closed_trades": {
            "embargo_days": 7,
            "trades": [
                {
                    "symbol": "AAPL",
                    "asset_class": "equity",
                    "entry_timestamp_utc": "2026-01-15T14:35:00Z",
                    "exit_timestamp_utc": "2026-01-22T20:45:00Z",
                    "holding_duration_hours": 174.1,
                    "realized_pnl_bps": 340.0,
                    "return_decimal": 0.034,
                    "was_short": False,
                    "atr_multiple_at_exit": 2.1,
                }
            ],
            "stripped_recent_count": 3,
        },
    }

    salts_s1 = {
        name: hashlib.sha256(seed_bytes + b":merkle:s1:" + name.encode("utf-8")).hexdigest()
        for name in CANONICAL_LEAF_NAMES
    }
    merkle_tree = build_salted_merkle_tree(leaf_payloads, leaf_salts_hex=salts_s1)

    w_pse = create_signed_witness_attestation(
        notary_private_key_hex=keys["notary_pse"].private_key_hex,
        notary_id="notary-pse-eu",
        server_sni="ndcdyn.interactivebrokers.com",
        sanitized_request_target=(
            "/AccountManagement/FlexWebService/GetStatement?t=[REDACTED]&q=[REDACTED]&v=3"
        ),
        redacted_headers=["Authorization: [REDACTED]"],
        commitment_kind=TranscriptCommitmentKind.WHOLE_BODY_SHA256,
        response_body_sha256=source_sha,
        session_timestamp_utc="2026-04-01T03:10:00Z",
    )
    w_swiss = create_signed_witness_attestation(
        notary_private_key_hex=keys["notary_swiss"].private_key_hex,
        notary_id="notary-swiss-ch",
        server_sni="ndcdyn.interactivebrokers.com",
        sanitized_request_target=(
            "/AccountManagement/FlexWebService/GetStatement?t=[REDACTED]&q=[REDACTED]&v=3"
        ),
        redacted_headers=["Authorization: [REDACTED]"],
        commitment_kind=TranscriptCommitmentKind.WHOLE_BODY_SHA256,
        response_body_sha256=source_sha,
        session_timestamp_utc="2026-04-01T03:10:12Z",
    )
    w_nordic = create_signed_witness_attestation(
        notary_private_key_hex=keys["notary_nordic"].private_key_hex,
        notary_id="notary-nordic-is",
        server_sni="ndcdyn.interactivebrokers.com",
        sanitized_request_target=(
            "/AccountManagement/FlexWebService/GetStatement?t=[REDACTED]&q=[REDACTED]&v=3"
        ),
        redacted_headers=["Authorization: [REDACTED]"],
        commitment_kind=TranscriptCommitmentKind.WHOLE_BODY_SHA256,
        response_body_sha256=source_sha,
        session_timestamp_utc="2026-04-01T03:10:25Z",
    )

    return create_signed_proof_bundle(
        proof_id="specimen-s1",
        issued_at_utc="2026-04-01T12:00:00Z",
        publisher_kid="n170-pub-2026-q1",
        publisher_private_key_hex=keys["pub_active"].private_key_hex,
        broker_id="ibkr",
        blinded_account_tag=blinded_acct,
        account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
        provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
        environment_tier=EnvironmentTier.LIVE_PRODUCTION,
        claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
        source_body_sha256=source_sha,
        period_start_utc="2026-01-01T00:00:00Z",
        period_end_utc="2026-03-31T23:59:59Z",
        base_currency="USD",
        merkle_tree=merkle_tree,
        disclose_leaf_names=list(CANONICAL_LEAF_NAMES),
        witness_attestations=[w_pse, w_swiss, w_nordic],
        retention_mode="no_persistent_storage",
        schema_version=VERIFY_SCHEMA_VERSION,
    )


def build_specimen_offline(keys: Mapping[str, Any], seed_bytes: bytes) -> VerifyProofBundle:
    """Build specimen for EnvironmentTier.UNVERIFIED_OFFLINE."""
    source_bytes = b"degiro-offline-csv-export-body-bytes"
    source_sha = hashlib.sha256(source_bytes).hexdigest()
    salt_hex = hashlib.sha256(seed_bytes + b":blinded-salt:offline").hexdigest()
    blinded_acct = compute_blinded_account_tag("degiro", "DEGIRO-9988", salt_hex)

    leaf_payloads = {
        "core_metrics": {
            "twr_decimal": 0.152,
            "twr_pct": 15.2,
            "cagr_decimal": 1.15,
            "cagr_pct": 115.0,
            "xirr_decimal": 1.12,
            "annualized_volatility": 0.145,
            "max_drawdown_decimal": 0.048,
            "max_drawdown_pct": 4.8,
            "sharpe_ratio": 1.85,
            "sortino_ratio": 2.45,
            "calmar_ratio": 3.16,
            "observation_count": 45,
            "trading_days": 45,
            "start_date": "2026-01-01",
            "end_date": "2026-03-31",
            "base_currency": "EUR",
            "psr_sample_eligible": True,
            "probabilistic_sharpe_ratio": 0.941,
            "psr_glm_unsmoothed": 0.932,
            "min_track_record_length_days": 38.0,
            "unconditional_monthly_var_95": 0.035,
            "unconditional_monthly_cvar_95": 0.048,
            "benchmark_symbol": "IWDA",
            "benchmark_twr_decimal": 0.065,
            "alpha_decimal": 0.087,
        },
        "indexed_curve": {
            "base_index": 100.0,
            "points": [
                {"timestamp_utc": "2026-01-01T00:00:00Z", "index_value": 100.0},
                {"timestamp_utc": "2026-03-31T23:59:59Z", "index_value": 115.2},
            ],
        },
        "reconciliation": {
            "status": "reconciled_offline_export",
            "discrepancy_count": 0,
            "evaluated_at_utc": "2026-04-01T12:00:00Z",
            "tolerance_bps": 10.0,
            "sections_checked": ["cash_balance", "transactions", "portfolio"],
            "findings": [],
        },
        "coaching_and_context": {
            "cost_drag": {
                "commission_and_fee_drag_bps": 8.5,
                "margin_and_funding_drag_bps": 0.0,
                "fx_conversion_drag_bps": 3.2,
                "withholding_tax_drag_bps": 1.5,
                "total_friction_drag_bps": 13.2,
                "annualized_total_drag_bps": 52.8,
            },
            "behaviour": {
                "sample_eligible": True,
                "min_trades_gate": 30,
                "observed_trades": 38,
                "observed_days": 45,
                "median_holding_hours": 72.0,
                "holding_horizon_label": "position_investing",
                "win_rate": 0.684,
                "profit_factor": 2.45,
                "winner_vs_loser_hold_ratio": 1.82,
                "odean_pgr_plr_spread": 0.015,
                "post_drawdown_sizing_discipline_atr": 0.88,
                "atr_normalized": True,
                "return_concentration_top5_pct": 22.1,
                "actionable_improvements": [],
            },
            "catalyst_regime_win_rate": None,
            "quiet_regime_win_rate": None,
            "event_window_share_pct": 0.0,
            "event_observations": [],
        },
        "capital_bracket": {
            "capital_bracket": "10k_to_100k",
            "valuation_currency": "EUR",
        },
        "benchmark_alpha": {
            "benchmark_symbol": "IWDA",
            "benchmark_twr_decimal": 0.065,
            "alpha_decimal": 0.087,
            "information_ratio": 1.45,
            "beta": 0.88,
        },
        "delayed_closed_trades": {
            "embargo_days": 7,
            "trades": [],
            "stripped_recent_count": 0,
        },
    }

    salts_offline = {
        name: hashlib.sha256(seed_bytes + b":merkle:offline:" + name.encode("utf-8")).hexdigest()
        for name in CANONICAL_LEAF_NAMES
    }
    merkle_tree = build_salted_merkle_tree(leaf_payloads, leaf_salts_hex=salts_offline)

    return create_signed_proof_bundle(
        proof_id="specimen-offline-unverified",
        issued_at_utc="2026-04-01T12:00:00Z",
        publisher_kid="n170-pub-2026-q1",
        publisher_private_key_hex=keys["pub_active"].private_key_hex,
        broker_id="degiro",
        blinded_account_tag=blinded_acct,
        account_scope=AccountScope.UNKNOWN_OFFLINE_SCOPE,
        provider_approval_state=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
        environment_tier=EnvironmentTier.UNVERIFIED_OFFLINE,
        claimed_origin_assurance=OriginAssurance.SELF_REPORTED,
        source_body_sha256=source_sha,
        period_start_utc="2026-01-01T00:00:00Z",
        period_end_utc="2026-03-31T23:59:59Z",
        base_currency="EUR",
        merkle_tree=merkle_tree,
        disclose_leaf_names=list(CANONICAL_LEAF_NAMES),
        witness_attestations=[],
        retention_mode="no_persistent_storage",
        schema_version=VERIFY_SCHEMA_VERSION,
    )


def generate_specimens(
    seed_hex: str | None = None,
    output_repo_root: Path | str | None = None,
) -> SpecimenGenerationResult:
    """Generate truth specimens deterministically from seed and optionally write to repo."""
    effective_seed = seed_hex or os.environ.get(
        "N170_VERIFY_SPECIMEN_SEED_HEX", DEFAULT_SPECIMEN_SEED_HEX
    )
    seed_bytes = bytes.fromhex(effective_seed)
    keys = derive_keypairs_from_seed(effective_seed)
    registry = build_specimen_registry(effective_seed, keys)
    bundle_s1 = build_specimen_s1(keys, seed_bytes)
    bundle_offline = build_specimen_offline(keys, seed_bytes)

    # Self-verify s1
    res_s1 = verify_proof_bundle(bundle_s1, registry_doc=registry, now_utc="2026-04-02T00:00:00Z")
    if not res_s1.valid:
        raise ValueError(f"Self-verification of specimen-s1 failed: {res_s1.errors}")

    if output_repo_root is not None:
        root = Path(output_repo_root)

        # 1. examples/specimen-s1.verify.json
        ex_dir = root / "examples"
        ex_dir.mkdir(parents=True, exist_ok=True)
        (ex_dir / "specimen-s1.verify.json").write_text(
            json.dumps(bundle_s1.to_dict(), indent=2) + "\n", encoding="utf-8"
        )

        # 2. web/public/specimens/n170-specimen-keys.json
        pub_dir = root / "web" / "public" / "specimens"
        pub_dir.mkdir(parents=True, exist_ok=True)
        (pub_dir / "n170-specimen-keys.json").write_text(
            json.dumps(registry.to_dict(), indent=2) + "\n", encoding="utf-8"
        )

        # 3. web/tests/fixtures/*
        fix_dir = root / "web" / "tests" / "fixtures"
        fix_dir.mkdir(parents=True, exist_ok=True)
        (fix_dir / "specimen-s1.verify.json").write_text(
            json.dumps(bundle_s1.to_dict(), indent=2) + "\n", encoding="utf-8"
        )
        (fix_dir / "specimen-offline-unverified.verify.json").write_text(
            json.dumps(bundle_offline.to_dict(), indent=2) + "\n", encoding="utf-8"
        )
        (fix_dir / "registry.json").write_text(
            json.dumps(registry.to_dict(), indent=2) + "\n", encoding="utf-8"
        )

    return SpecimenGenerationResult(
        seed_hex=effective_seed,
        registry=registry,
        bundle_s1=bundle_s1,
        bundle_offline=bundle_offline,
    )
