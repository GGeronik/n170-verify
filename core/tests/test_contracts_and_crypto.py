"""Comprehensive unit test suite for n170_verify.contracts and n170_verify.crypto."""

from __future__ import annotations

import hashlib
import json
import math
import shutil
import subprocess
import sys
import unittest
from typing import Any

from n170_verify import VERIFY_SCHEMA_VERSION, create_signed_proof_bundle, verify_proof_bundle
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    BehaviouralCoachingMetrics,
    CanonicalPortfolioLedger,
    CapitalBracket,
    CatalystAlignmentClass,
    ChainContinuityMode,
    CheckOutcome,
    CorporateActionRecord,
    CorporateActionType,
    CostAndDragBreakdown,
    EnvironmentTier,
    EventWindowObservation,
    FlowKind,
    IndexedCurvePoint,
    NormalizedFlow,
    NormalizedNavPoint,
    NormalizedPosition,
    NormalizedTrade,
    OriginAssurance,
    PerformanceSummary,
    ProviderApprovalState,
    ReadOnlyBrokerAdapter,
    ReadOnlyCapabilityViolationError,
    ReconciliationFinding,
    ReconciliationReport,
    ReconciliationStatus,
    RedactedClosedTrade,
    SignerTrustStatus,
    StatisticalDiagnostic,
    TraderCoachingAndContextReport,
    classify_capital_bracket,
    compute_blinded_account_tag,
    is_external_capital_flow,
)
from n170_verify.crypto import (
    CANONICAL_LEAF_NAMES,
    ChainCadencePolicy,
    ChainInvariantViolationCode,
    ContinuityLogLeaf,
    DisclosedLeaf,
    Ed25519KeyPair,
    L2BatchAnchor,
    MerkleAuditStep,
    NotaryNodeInfo,
    ProspectiveChainLink,
    PublisherKeyRecord,
    PublisherKeyRegistryDocument,
    TranscriptCommitmentKind,
    build_salted_merkle_tree,
    compute_effective_origin_assurance,
    compute_internal_node_hash,
    compute_salted_leaf_hash,
    create_signed_broker_signature,
    create_signed_c2sp_checkpoint,
    create_signed_witness_attestation,
    derive_public_key_hex,
    ed25519_sign,
    ed25519_verify,
    evaluate_signer_trust,
    generate_ed25519_keypair,
    inspect_transcript_safety,
    jcs_canonicalize,
    jcs_canonicalize_str,
    jcs_sha256_hex,
    verify_c2sp_checkpoint,
    verify_disclosed_leaf,
    verify_prospective_chain,
    verify_selective_disclosure,
)


def _sample_seven_leaves() -> dict[str, Any]:
    """Construct realistic privacy-preserving payloads for all 7 canonical Merkle leaves."""
    curve = [
        IndexedCurvePoint(timestamp_utc="2026-01-01T00:00:00Z", index_value=100.0, drawdown_pct=0.0),
        IndexedCurvePoint(timestamp_utc="2026-01-15T00:00:00Z", index_value=106.5, drawdown_pct=0.0),
        IndexedCurvePoint(timestamp_utc="2026-01-31T00:00:00Z", index_value=105.0, drawdown_pct=-1.40845),
    ]
    perf = PerformanceSummary(
        twr_decimal=0.05,
        cagr_decimal=0.7958,
        xirr_decimal=0.781,
        annualized_volatility=0.142,
        smoothing_index_xi=0.94,
        lag1_autocorrelation=0.06,
        unsmoothed_volatility=0.146,
        unsmoothed_sharpe_ratio=1.88,
        sharpe_ratio=1.93,
        sortino_ratio=2.75,
        probabilistic_sharpe_ratio=0.972,
        psr_glm_unsmoothed=None,
        min_track_record_length_periods=18.4,
        psr_sample_eligible=True,
        observation_count=35,
        psr_benchmark_sr=0.0,
        max_drawdown_decimal=-0.0140845,
        skewness=0.12,
        excess_kurtosis=0.45,
        capital_bracket=CapitalBracket.BRACKET_100K_1M,
        benchmark_symbol="SPY",
        benchmark_twr_decimal=0.028,
        alpha_decimal=0.022,
        indexed_curve=curve,
    )
    recon = ReconciliationReport(
        status=ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE,
        reference_provider="eodhd",
        ledger_completeness_ok=True,
        checks_evaluated=14,
        discrepancy_count=0,
        explained_convention_count=1,
        findings=[
            ReconciliationFinding(
                category="nav_bridge",
                outcome=CheckOutcome.EXPLAINED_CONVENTION,
                date_or_timestamp="2026-01-15T00:00:00Z",
                expected_value=106.50,
                observed_value=106.49,
                residual_bps=0.94,
                residual_base_currency=11.2,
                math_identity="NAV_t = NAV_{t-1} + PnL_t + Flows_t",
                technical_explanation="Within ex-dividend accrual rounding convention.",
                benign_causes_considered=["dividend_accrual_timing", "fx_closing_snap"],
            )
        ],
        statistical_diagnostics=[
            StatisticalDiagnostic(
                metric_name="return_autocorrelation_lag1",
                observed_value=0.06,
                interpretation="Consistent with liquid daily-marked instruments.",
                caveats=["35 daily observations have wide confidence intervals."],
            )
        ],
        summary_text="All accounting identities reconciled within tolerance.",
    )
    coaching = TraderCoachingAndContextReport(
        cost_drag=CostAndDragBreakdown(
            commission_and_fee_drag_bps=8.4,
            margin_and_funding_drag_bps=3.1,
            fx_conversion_drag_bps=1.2,
            withholding_tax_drag_bps=0.5,
            total_friction_drag_bps=13.2,
            annualized_total_drag_bps=158.4,
        ),
        behaviour=BehaviouralCoachingMetrics(
            sample_eligible=True,
            min_trades_gate=30,
            observed_trades=42,
            observed_days=31,
            median_holding_hours=38.5,
            holding_horizon_label="multi_day_swing",
            win_rate=0.57,
            profit_factor=1.64,
            winner_vs_loser_hold_ratio=1.35,
            odean_pgr_plr_spread=-0.04,
            post_drawdown_sizing_discipline_atr=0.92,
            atr_normalized=True,
            return_concentration_top5_pct=41.0,
            actionable_improvements=["Consolidate odd-lot FX conversions to reduce spread drag."],
        ),
        catalyst_regime_win_rate=0.62,
        quiet_regime_win_rate=0.55,
        event_window_share_pct=23.8,
        event_observations=[
            EventWindowObservation(
                symbol="AAPL",
                trade_timestamp_utc="2026-01-29T21:40:00Z",
                earliest_public_utc="2026-01-29T21:30:00Z",
                confirmed_public_utc="2026-01-29T21:31:12Z",
                event_sources=["sec_edgar_8k", "eodhd_earnings"],
                headline_or_event="Q1 FY26 Form 8-K Earnings Release",
                alignment_class=CatalystAlignmentClass.POST_CONFIRMED_CATALYST,
                timestamp_uncertainty_note="SEC EDGAR acceptance timestamp has 1-second resolution.",
            )
        ],
        style_summary="Multi-day liquid equity swing profile with disciplined post-drawdown sizing.",
        coaching_takeaways=["Maintain current post-drawdown sizing discipline."],
        uncertainty_disclosures=["Public feed arrival times can vary by vendor."],
    )
    closed_trades = [
        RedactedClosedTrade(
            symbol="AAPL",
            asset_class=AssetClass.EQUITY,
            side="long",
            entry_timestamp_utc="2026-01-29T21:40:00Z",
            exit_timestamp_utc="2026-01-30T19:10:00Z",
            return_pct=3.45,
            holding_hours=21.5,
        ).to_dict()
    ]
    perf_dict = perf.to_dict()
    return {
        "core_metrics": {
            k: perf_dict[k]
            for k in (
                "twr_decimal",
                "twr_pct",
                "cagr_decimal",
                "xirr_decimal",
                "annualized_volatility",
                "sharpe_ratio",
                "sortino_ratio",
                "probabilistic_sharpe_ratio",
                "max_drawdown_decimal",
                "observation_count",
                "psr_sample_eligible",
                "non_iid_caveat",
            )
        },
        "indexed_curve": [pt.to_dict() for pt in curve],
        "reconciliation": recon.to_dict(),
        "coaching_and_context": coaching.to_dict(),
        "capital_bracket": {"capital_bracket": CapitalBracket.BRACKET_100K_1M.value},
        "benchmark_alpha": {
            "benchmark_symbol": "SPY",
            "benchmark_twr_decimal": 0.028,
            "alpha_decimal": 0.022,
        },
        "delayed_closed_trades": closed_trades,
    }


class TestEd25519AndRFC8032(unittest.TestCase):
    """RFC 8032 test vectors, OpenSSL ctypes path, and Node.js WebCrypto cross-verification."""

    RFC8032_VECTORS = (
        # Test Vector 1 (empty message)
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            b"",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
            "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        # Test Vector 2 (1-byte message 0x72)
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            bytes.fromhex("72"),
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        # Test Vector 3 (2-byte message 0xaf82)
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            bytes.fromhex("af82"),
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    )

    def test_rfc8032_vectors_default_and_forced_openssl(self) -> None:
        for priv_hex, expected_pub_hex, msg, expected_sig_hex in self.RFC8032_VECTORS:
            for force_openssl in (False, True):
                derived_pub = derive_public_key_hex(priv_hex, force_openssl=force_openssl)
                self.assertEqual(derived_pub, expected_pub_hex)

                sig = ed25519_sign(priv_hex, msg, force_openssl=force_openssl)
                self.assertEqual(sig, expected_sig_hex)
                self.assertTrue(
                    ed25519_verify(expected_pub_hex, msg, sig, force_openssl=force_openssl)
                )

                # Flip one bit in signature -> must reject
                flipped_first_byte = f"{int(sig[:2], 16) ^ 0x01:02x}" + sig[2:]
                self.assertFalse(
                    ed25519_verify(
                        expected_pub_hex, msg, flipped_first_byte, force_openssl=force_openssl
                    )
                )
                # Mutated message -> must reject
                self.assertFalse(
                    ed25519_verify(
                        expected_pub_hex, msg + b"\x00", sig, force_openssl=force_openssl
                    )
                )

    def test_keypair_validation_and_roundtrip(self) -> None:
        kp = generate_ed25519_keypair()
        self.assertEqual(len(kp.private_key_hex), 64)
        self.assertEqual(len(kp.public_key_hex), 64)
        self.assertIsNotNone(kp.key_id)
        self.assertEqual(Ed25519KeyPair.model_validate(kp.model_dump()), kp)

        other_kp = generate_ed25519_keypair()
        with self.assertRaises(ValueError):
            Ed25519KeyPair(
                private_key_hex=kp.private_key_hex,
                public_key_hex=other_kp.public_key_hex,
            )

    def test_nodejs_webcrypto_ed25519_cross_verification(self) -> None:
        node_bin = shutil.which("node")
        if node_bin is None:
            self.skipTest("node binary not available")

        kp = generate_ed25519_keypair()
        message = b"n170-verify-cross-language-ed25519-check"
        py_sig_hex = ed25519_sign(kp.private_key_hex, message)

        node_script = """
const { subtle } = require('node:crypto').webcrypto;
(async () => {
  const pubHex = process.argv[1];
  const msgHex = process.argv[2];
  const sigHex = process.argv[3];
  const pyPub = await subtle.importKey(
    'raw',
    Buffer.from(pubHex, 'hex'),
    { name: 'Ed25519' },
    false,
    ['verify']
  );
  const verifiedByNode = await subtle.verify(
    'Ed25519',
    pyPub,
    Buffer.from(sigHex, 'hex'),
    Buffer.from(msgHex, 'hex')
  );

  const nodeKp = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const nodePubRaw = Buffer.from(await subtle.exportKey('raw', nodeKp.publicKey)).toString('hex');
  const nodeMsg = Buffer.from('node-webcrypto-to-python-openssl-check', 'utf8');
  const nodeSig = Buffer.from(await subtle.sign('Ed25519', nodeKp.privateKey, nodeMsg)).toString('hex');
  console.log(JSON.stringify({
    verifiedByNode,
    nodePubRaw,
    nodeMsgHex: nodeMsg.toString('hex'),
    nodeSig
  }));
})();
"""
        proc = subprocess.run(
            [node_bin, "-e", node_script, kp.public_key_hex, message.hex(), py_sig_hex],
            check=True,
            capture_output=True,
            text=True,
        )
        result = json.loads(proc.stdout.strip())
        self.assertTrue(result["verifiedByNode"])
        self.assertTrue(
            ed25519_verify(
                result["nodePubRaw"],
                bytes.fromhex(result["nodeMsgHex"]),
                result["nodeSig"],
            )
        )


class TestJCSCanonicalization(unittest.TestCase):
    """RFC 8785 UTF-16 key ordering, ES6 float serialization, and rejection edge cases."""

    def test_utf16_code_unit_key_sorting_astral_vs_bmp_private_use(self) -> None:
        # U+1F600 encodes in UTF-16 as 0xD83D 0xDE00, whereas U+E000 encodes as 0xE000.
        # Code-point sort wrongly orders U+E000 before U+1F600; RFC 8785 UTF-16 code-unit
        # sort MUST order U+1F600 (0xD83D) before U+E000 (0xE000) and U+FB33 (0xFB33).
        obj = {
            "\ufb33": "hebrew",
            "\U0001f600": "grinning",
            "\ue000": "bmp_pua",
            "\u20ac": "euro",
            "\r": "cr",
            "10": "ten",
            "1": "one",
            "\u0080": "c1",
            "\u00f6": "umlaut",
        }
        canon = jcs_canonicalize_str(obj)
        expected = (
            '{"\\r":"cr","1":"one","10":"ten","\u0080":"c1","\u00f6":"umlaut",'
            '"\u20ac":"euro","\U0001f600":"grinning","\ue000":"bmp_pua","\ufb33":"hebrew"}'
        )
        self.assertEqual(canon, expected)

    def test_es6_number_serialization_and_negative_zero(self) -> None:
        payload = {
            "neg_zero": -0.0,
            "zero": 0.0,
            "int_float": 1.0,
            "boundary_fixed_hi": 1e20,
            "boundary_exp_hi": 1e21,
            "boundary_fixed_lo": 1e-6,
            "boundary_exp_lo": 1e-7,
            "repeating": 333333333.3333333,
        }
        canon = jcs_canonicalize_str(payload)
        self.assertEqual(
            canon,
            '{"boundary_exp_hi":1e+21,"boundary_exp_lo":1e-7,'
            '"boundary_fixed_hi":100000000000000000000,"boundary_fixed_lo":0.000001,'
            '"int_float":1,"neg_zero":0,"repeating":333333333.3333333,"zero":0}',
        )

    def test_rejects_nan_infinity_and_lone_surrogates(self) -> None:
        for bad in (math.nan, math.inf, -math.inf):
            with self.assertRaises(ValueError):
                jcs_canonicalize({"x": bad})
        with self.assertRaises(ValueError):
            jcs_canonicalize({"s": "\ud800"})
        with self.assertRaises(ValueError):
            jcs_canonicalize({"\udfff": 1})

    def test_control_character_lowercase_hex_escaping(self) -> None:
        raw = {"ctrl": "\x00\x07\x08\x09\x0a\x0c\x0d\x1f/\"\\"}
        self.assertEqual(
            jcs_canonicalize_str(raw),
            r'{"ctrl":"\u0000\u0007\b\t\n\f\r\u001f/\"\\"}',
        )


class TestContractsAndReadOnlyBoundary(unittest.TestCase):
    """Contract validation, Pydantic-compatible methods, blinded tags, and read-only adapter ABC."""

    def test_ledger_blinded_account_tag_and_roundtrip(self) -> None:
        salt = "aa" * 32
        tag1 = compute_blinded_account_tag("IBKR", "U1234567", salt)
        tag2 = compute_blinded_account_tag("ibkr", "U1234567", salt)
        tag_diff_salt = compute_blinded_account_tag("ibkr", "U1234567", "bb" * 32)
        self.assertEqual(tag1, tag2)
        self.assertNotEqual(tag1, tag_diff_salt)
        self.assertEqual(len(tag1), 64)

        # Raw account ID in blinded_account_tag must be rejected immediately
        with self.assertRaises(ValueError):
            CanonicalPortfolioLedger(
                blinded_account_tag="U1234567",
                broker_id="ibkr",
                account_scope=AccountScope.UNKNOWN_OFFLINE_SCOPE,
                claimed_origin_assurance=OriginAssurance.SELF_REPORTED,
                provider_approval_state=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
                environment_tier=EnvironmentTier.LIVE_PRODUCTION,
                source_body_sha256="11" * 32,
                base_currency="USD",
                period_start_utc="2026-01-01T00:00:00Z",
                period_end_utc="2026-01-31T00:00:00Z",
            )

        opt_trade = NormalizedTrade(
            venue="ibkr",
            native_entry_id="exec-001",
            symbol="AAPL 260220C00200000",
            asset_class=AssetClass.OPTION,
            side="BUY",
            quantity=2.0,
            price=4.5,
            timestamp_utc="2026-01-10T15:30:00Z",
            option_right="call",
            strike=200.0,
            expiry="2026-02-20",
            underlying_symbol="AAPL",
        )
        self.assertEqual(opt_trade.multiplier, 100.0)
        self.assertEqual(opt_trade.option_right, "C")
        self.assertAlmostEqual(opt_trade.notional_base, 900.0)

        acats_in = NormalizedFlow(
            timestamp_utc="2026-01-05T00:00:00Z",
            kind=FlowKind.TRANSFER_IN_KIND,
            amount=15000.0,
            symbol="MSFT",
            quantity=35.0,
            transfer_type="ACATS",
        )
        dividend_flow = NormalizedFlow(
            timestamp_utc="2026-01-12T00:00:00Z",
            kind=FlowKind.DIVIDEND,
            amount=120.0,
        )
        self.assertTrue(acats_in.is_external_capital_flow)
        self.assertTrue(is_external_capital_flow(acats_in))
        self.assertFalse(dividend_flow.is_external_capital_flow)
        self.assertFalse(is_external_capital_flow(FlowKind.PERP_FUNDING))

        ledger = CanonicalPortfolioLedger(
            blinded_account_tag=tag1,
            broker_id="ibkr",
            account_scope=AccountScope.UNKNOWN_OFFLINE_SCOPE,
            enumerated_subaccount_count=None,
            connected_subaccount_count=1,
            claimed_origin_assurance=OriginAssurance.SELF_REPORTED,
            provider_approval_state=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            source_body_sha256="22" * 32,
            base_currency="USD",
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            prior_positions=[
                NormalizedPosition(
                    prior_period_or_ending="prior",
                    symbol="SPY",
                    asset_class=AssetClass.ETF,
                    quantity=100.0,
                    cost_basis=47000.0,
                    market_value=50000.0,
                )
            ],
            nav_points=[NormalizedNavPoint(timestamp_utc="2026-01-01T00:00:00Z", nav_base=100000.0)],
            trades=[opt_trade],
            flows=[acats_in, dividend_flow],
            corporate_actions=[
                CorporateActionRecord(
                    action_type=CorporateActionType.SPLIT,
                    timestamp_utc="2026-01-20T00:00:00Z",
                    symbol="NVDA",
                    ratio_numerator=10.0,
                    ratio_denominator=1.0,
                    quantity_delta=90.0,
                )
            ],
            conversion_rates={"EURUSD": 1.085},
            enabled_sections=["nav", "trades", "flows", "positions", "corporate_actions"],
        )
        dumped = ledger.model_dump()
        restored = CanonicalPortfolioLedger.model_validate(dumped)
        self.assertEqual(restored, ledger)
        self.assertEqual(CanonicalPortfolioLedger.from_dict(ledger.to_dict()), ledger)

    def test_performance_summary_privacy_and_psr_gates(self) -> None:
        self.assertEqual(classify_capital_bracket(500.0), CapitalBracket.UNDER_1K)
        self.assertEqual(classify_capital_bracket(5_000.0), CapitalBracket.BRACKET_1K_10K)
        self.assertEqual(classify_capital_bracket(50_000.0), CapitalBracket.BRACKET_10K_100K)
        self.assertEqual(classify_capital_bracket(500_000.0), CapitalBracket.BRACKET_100K_1M)
        self.assertEqual(classify_capital_bracket(2_500_000.0), CapitalBracket.OVER_1M)

        # Raw dollar NAV curve not starting at 100.0 must fail validation
        with self.assertRaises(ValueError):
            PerformanceSummary(
                twr_decimal=0.10,
                indexed_curve=[
                    IndexedCurvePoint(
                        timestamp_utc="2026-01-01T00:00:00Z",
                        index_value=250_000.0,
                        drawdown_pct=0.0,
                    )
                ],
            )

        # PSR sample gate T >= 30 enforced
        with self.assertRaises(ValueError):
            PerformanceSummary(
                twr_decimal=0.10,
                observation_count=15,
                psr_sample_eligible=True,
            )

    def test_read_only_broker_adapter_enforces_capability_allowlist(self) -> None:
        with self.assertRaises(TypeError):
            ReadOnlyBrokerAdapter()

        class ValidSchwabAdapter(ReadOnlyBrokerAdapter):
            broker_id = "schwab"
            display_name = "Charles Schwab Trader API"
            approval_state = ProviderApprovalState.APPROVED_LIVE
            default_origin_assurance = OriginAssurance.OPERATOR_RETRIEVED
            supports_subaccount_enumeration = True
            allowed_capabilities = ("read_accounts", "read_balances", "read_positions", "read_trades")

        adapter = ValidSchwabAdapter()
        desc = adapter.describe_adapter()
        self.assertEqual(desc.broker_id, "schwab")
        self.assertTrue(desc.supports_subaccount_enumeration)

        for bad_cap in ("place_order", "cancel_order", "withdraw_funds", "read_orders", "write_ledger"):
            class BadAdapter(ReadOnlyBrokerAdapter):
                broker_id = "bad"
                display_name = "Bad"
                allowed_capabilities = ("read_balances", bad_cap)

            with self.assertRaises(ReadOnlyCapabilityViolationError):
                BadAdapter()


class TestSaltedMerkleSelectiveDisclosure(unittest.TestCase):
    """Salted Merkle commitments, selective redaction, small-domain hiding, and 0x00/0x01 separation."""

    def test_selective_disclosure_and_salt_privacy(self) -> None:
        leaves = _sample_seven_leaves()
        tree = build_salted_merkle_tree(leaves)
        self.assertEqual(len(tree.merkle_root), 64)

        # Disclose only core_metrics, indexed_curve, reconciliation; hide capital_bracket & closed_trades
        disclosed, undisclosed = tree.selectively_disclose(
            ["core_metrics", "indexed_curve", "reconciliation"]
        )
        self.assertEqual(len(disclosed), 3)
        self.assertEqual(len(undisclosed), 4)
        self.assertIn("capital_bracket", undisclosed)
        self.assertIn("delayed_closed_trades", undisclosed)

        ok, errs = verify_selective_disclosure(tree.merkle_root, disclosed, undisclosed)
        self.assertTrue(ok, errs)

        # Verify undisclosed representation contains ONLY 64-char hex hashes (no salt, no payload)
        for name, digest in undisclosed.items():
            self.assertIn(name, CANONICAL_LEAF_NAMES)
            self.assertEqual(len(digest), 64)

        # Identical small-domain CapitalBracket payload under two distinct salts produces unrelated hashes
        payload = {"capital_bracket": CapitalBracket.OVER_1M.value}
        h1 = compute_salted_leaf_hash("capital_bracket", "01" * 32, payload)
        h2 = compute_salted_leaf_hash("capital_bracket", "02" * 32, payload)
        self.assertNotEqual(h1, h2)

        # Tampering with a disclosed payload or salt invalidates verification
        tampered = DisclosedLeaf(
            leaf_name=disclosed[0].leaf_name,
            salt_hex=disclosed[0].salt_hex,
            payload={**disclosed[0].payload, "twr_decimal": 0.99},
            leaf_hash_hex=disclosed[0].leaf_hash_hex,
            audit_path=disclosed[0].audit_path,
        )
        self.assertFalse(verify_disclosed_leaf(tampered, tree.merkle_root))

    def test_second_preimage_leaf_vs_internal_node_domain_separation(self) -> None:
        leaves = _sample_seven_leaves()
        tree = build_salted_merkle_tree(leaves)
        full_disclosed, _ = tree.selectively_disclose(CANONICAL_LEAF_NAMES)

        # Leaf 0 and Leaf 1 combine into internal node N01 = H(0x01 || L0 || L1).
        l0 = full_disclosed[0]
        l1 = full_disclosed[1]
        internal_n01 = compute_internal_node_hash(l0.leaf_hash_hex, l1.leaf_hash_hex)

        # Attempt tree-depth truncation attack: claim N01 is itself a leaf hash with shortened path
        shortened_path = l0.audit_path[1:]
        forged_leaf = DisclosedLeaf(
            leaf_name="core_metrics",
            salt_hex=l0.salt_hex,
            payload={"left": l0.leaf_hash_hex, "right": l1.leaf_hash_hex},
            leaf_hash_hex=internal_n01,
            audit_path=shortened_path,
        )
        # Fails because verify_disclosed_leaf recomputes H(0x00 || ...) != H(0x01 || L0 || L1)
        self.assertFalse(verify_disclosed_leaf(forged_leaf, tree.merkle_root))

        # Swapping leaf_name with same salt + payload also changes leaf hash (leaf_name is bound!)
        h_a = compute_salted_leaf_hash("capital_bracket", "ab" * 32, {"v": 1})
        h_b = compute_salted_leaf_hash("benchmark_alpha", "ab" * 32, {"v": 1})
        self.assertNotEqual(h_a, h_b)


class TestPublisherRegistryWitnessQuorumAndBundle(unittest.TestCase):
    """C2SP checkpoints, key rotation/revocation, dynamic k>=2 org/ASN quorum, and transcript safety."""

    def setUp(self) -> None:
        self.pub_active = generate_ed25519_keypair(b"\x11" * 32)
        self.pub_retired = generate_ed25519_keypair(b"\x22" * 32)
        self.pub_revoked = generate_ed25519_keypair(b"\x33" * 32)
        self.pub_unrecognized = generate_ed25519_keypair(b"\x44" * 32)

        self.notary_cf = generate_ed25519_keypair(b"\x51" * 32)
        self.notary_pse = generate_ed25519_keypair(b"\x52" * 32)
        self.notary_same_org = generate_ed25519_keypair(b"\x53" * 32)
        self.notary_same_asn = generate_ed25519_keypair(b"\x54" * 32)
        self.notary_debug = generate_ed25519_keypair(b"\x55" * 32)

        self.broker_kp = generate_ed25519_keypair(b"\x61" * 32)
        self.ckpt_witness_kp = generate_ed25519_keypair(b"\x71" * 32)

        self.checkpoint = create_signed_c2sp_checkpoint(
            origin="n170.io/verify/continuity-log/v3",
            size=128,
            root_hash_hex="99" * 32,
            publisher_kid="n170-active-2026",
            publisher_private_key_hex=self.pub_active.private_key_hex,
            witness_signers=[
                (
                    "witness-alpha",
                    self.ckpt_witness_kp.private_key_hex,
                    self.ckpt_witness_kp.public_key_hex,
                    "2026-02-01T00:05:00Z",
                )
            ],
        )

        self.registry = PublisherKeyRegistryDocument(
            updated_at_utc="2026-02-01T00:10:00Z",
            keys=[
                PublisherKeyRecord(
                    publisher_kid="n170-active-2026",
                    public_key_hex=self.pub_active.public_key_hex,
                    status="active",
                    not_before_utc="2026-01-01T00:00:00Z",
                    issuer_org="N170",
                ),
                PublisherKeyRecord(
                    publisher_kid="n170-retired-2025",
                    public_key_hex=self.pub_retired.public_key_hex,
                    status="retired",
                    not_before_utc="2025-01-01T00:00:00Z",
                    not_after_utc="2025-12-31T23:59:59Z",
                    issuer_org="N170",
                ),
                PublisherKeyRecord(
                    publisher_kid="n170-revoked-key",
                    public_key_hex=self.pub_revoked.public_key_hex,
                    status="revoked",
                    not_before_utc="2025-06-01T00:00:00Z",
                    revoked_after_utc="2025-11-01T00:00:00Z",
                    issuer_org="N170",
                ),
            ],
            notaries=[
                NotaryNodeInfo(
                    notary_id="notary-cf-1",
                    operator_org="Cloudflare Research",
                    asn="AS13335",
                    public_key_hex=self.notary_cf.public_key_hex,
                ),
                NotaryNodeInfo(
                    notary_id="notary-pse-1",
                    operator_org="PSE TLSNotary",
                    asn="AS24940",
                    public_key_hex=self.notary_pse.public_key_hex,
                ),
                NotaryNodeInfo(
                    notary_id="notary-cf-colocated-org",
                    operator_org="Cloudflare Research",
                    asn="AS16509",
                    public_key_hex=self.notary_same_org.public_key_hex,
                ),
                NotaryNodeInfo(
                    notary_id="notary-other-colocated-asn",
                    operator_org="Independent Audit Guild",
                    asn="13335",  # Normalizes to AS13335 -> same ASN as notary-cf-1!
                    public_key_hex=self.notary_same_asn.public_key_hex,
                ),
                NotaryNodeInfo(
                    notary_id="notary-debug-enclave",
                    operator_org="Debug Lab",
                    asn="AS396982",
                    public_key_hex=self.notary_debug.public_key_hex,
                    is_debug_build=True,
                ),
            ],
            checkpoint=self.checkpoint,
            l2_anchor=L2BatchAnchor(
                chain_id=8453,
                contract_address="0x" + "12" * 20,
                tx_hash="0x" + "ab" * 32,
                batch_merkle_root="99" * 32,
                block_number=18_500_000,
                anchored_at_utc="2026-02-01T00:06:00Z",
            ),
            pinned_broker_keys={
                "schwab": {"schwab-stmt-ed25519-v1": self.broker_kp.public_key_hex},
            },
        )
        self.source_sha = hashlib.sha256(b"canonical-broker-response-bytes").hexdigest()
        self.account_tag = compute_blinded_account_tag("schwab", "ACCT-889900", "cc" * 32)

    def test_c2sp_checkpoint_format_and_cosignatures(self) -> None:
        lines = self.checkpoint.body_text().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[0], "n170.io/verify/continuity-log/v3")
        self.assertEqual(lines[1], "128")
        ok, errs = verify_c2sp_checkpoint(
            self.checkpoint,
            publisher_public_key_hex=self.pub_active.public_key_hex,
            trusted_witness_keys={"witness-alpha": self.ckpt_witness_kp.public_key_hex},
            min_witness_cosignatures=1,
        )
        self.assertTrue(ok, errs)

        # Requiring 2 witnesses when only 1 signed fails
        ok2, _ = verify_c2sp_checkpoint(
            self.checkpoint,
            publisher_public_key_hex=self.pub_active.public_key_hex,
            min_witness_cosignatures=2,
        )
        self.assertFalse(ok2)

    def test_k_ge_2_disjoint_quorum_upgrades_and_selective_redaction_preserves_validity(self) -> None:
        w1 = create_signed_witness_attestation(
            notary_private_key_hex=self.notary_cf.private_key_hex,
            notary_id="notary-cf-1",
            server_sni="api.schwabapi.com",
            sanitized_request_target="/trader/v1/accounts/accountNumbers",
            redacted_headers=["Authorization", "Cookie"],
            commitment_kind=TranscriptCommitmentKind.WHOLE_BODY_SHA256,
            response_body_sha256=self.source_sha,
            session_timestamp_utc="2026-02-01T00:00:10Z",
        )
        w2 = create_signed_witness_attestation(
            notary_private_key_hex=self.notary_pse.private_key_hex,
            notary_id="notary-pse-1",
            server_sni="api.schwabapi.com",
            sanitized_request_target="/trader/v1/accounts/accountNumbers",
            redacted_headers=["Authorization: [REDACTED]"],
            commitment_kind=TranscriptCommitmentKind.FIXED_64B_PADDED_WINDOW,
            response_body_sha256=self.source_sha,
            session_timestamp_utc="2026-02-01T00:02:00Z",
        )
        bundle = create_signed_proof_bundle(
            proof_id="prf-witnessed-001",
            issued_at_utc="2026-02-01T00:05:00Z",
            publisher_kid="n170-active-2026",
            publisher_private_key_hex=self.pub_active.private_key_hex,
            broker_id="schwab",
            blinded_account_tag=self.account_tag,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
            source_body_sha256=self.source_sha,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T23:59:59Z",
            base_currency="USD",
            leaf_payloads=_sample_seven_leaves(),
            witness_attestations=[w1, w2],
        )
        res = verify_proof_bundle(bundle, registry_doc=self.registry)
        self.assertTrue(res.valid, res.errors)
        self.assertEqual(res.signer_trust_status, SignerTrustStatus.OFFICIAL_N170_HOSTED)
        self.assertEqual(
            res.effective_origin_assurance, OriginAssurance.INDEPENDENTLY_WITNESSED_TLS
        )
        self.assertEqual(
            res.effective_chain_continuity_mode, ChainContinuityMode.UNENROLLED_SINGLE_SNAPSHOT
        )

        # Offline selective redaction without publisher private key!
        redacted = bundle.redact_leaves(["capital_bracket", "delayed_closed_trades"])
        self.assertEqual(len(redacted.disclosed_leaves), 5)
        self.assertIn("capital_bracket", redacted.undisclosed_leaf_hashes)
        with self.assertRaises(KeyError):
            redacted.get_disclosed_payload("capital_bracket")

        res_redacted = verify_proof_bundle(redacted, registry_doc=self.registry)
        self.assertTrue(res_redacted.valid, res_redacted.errors)
        self.assertEqual(res_redacted.proof_hash, res.proof_hash)
        self.assertEqual(
            res_redacted.effective_origin_assurance,
            OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
        )

    def test_single_colocated_debug_and_skewed_notaries_downgrade_to_operator_retrieved(self) -> None:
        w_cf = create_signed_witness_attestation(
            notary_private_key_hex=self.notary_cf.private_key_hex,
            notary_id="notary-cf-1",
            server_sni="api.schwabapi.com",
            sanitized_request_target="/trader/v1/accounts",
            redacted_headers=["Authorization"],
            response_body_sha256=self.source_sha,
            session_timestamp_utc="2026-02-01T00:00:00Z",
        )
        w_same_org = create_signed_witness_attestation(
            notary_private_key_hex=self.notary_same_org.private_key_hex,
            notary_id="notary-cf-colocated-org",
            server_sni="api.schwabapi.com",
            sanitized_request_target="/trader/v1/accounts",
            redacted_headers=["Authorization"],
            response_body_sha256=self.source_sha,
            session_timestamp_utc="2026-02-01T00:00:05Z",
        )
        w_same_asn = create_signed_witness_attestation(
            notary_private_key_hex=self.notary_same_asn.private_key_hex,
            notary_id="notary-other-colocated-asn",
            server_sni="api.schwabapi.com",
            sanitized_request_target="/trader/v1/accounts",
            redacted_headers=["Authorization"],
            response_body_sha256=self.source_sha,
            session_timestamp_utc="2026-02-01T00:00:05Z",
        )
        w_debug = create_signed_witness_attestation(
            notary_private_key_hex=self.notary_debug.private_key_hex,
            notary_id="notary-debug-enclave",
            server_sni="api.schwabapi.com",
            sanitized_request_target="/trader/v1/accounts",
            redacted_headers=["Authorization"],
            response_body_sha256=self.source_sha,
            session_timestamp_utc="2026-02-01T00:00:05Z",
        )
        w_skewed = create_signed_witness_attestation(
            notary_private_key_hex=self.notary_pse.private_key_hex,
            notary_id="notary-pse-1",
            server_sni="api.schwabapi.com",
            sanitized_request_target="/trader/v1/accounts",
            redacted_headers=["Authorization"],
            response_body_sha256=self.source_sha,
            session_timestamp_utc="2026-02-01T00:15:00Z",  # 900s > 600s max skew
        )

        for label, witnesses in (
            ("single_notary", [w_cf]),
            ("same_org", [w_cf, w_same_org]),
            ("same_asn", [w_cf, w_same_asn]),
            ("debug_second_notary", [w_cf, w_debug]),
            ("excessive_clock_skew", [w_cf, w_skewed]),
        ):
            with self.subTest(case=label):
                origin = compute_effective_origin_assurance(
                    source_body_sha256=self.source_sha,
                    signer_trust=SignerTrustStatus.OFFICIAL_N170_HOSTED,
                    publisher_kid="n170-active-2026",
                    publisher_public_key_hex=self.pub_active.public_key_hex,
                    provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
                    claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
                    witness_attestations=witnesses,
                    notary_registry=self.registry.notaries,
                )
                self.assertEqual(origin, OriginAssurance.OPERATOR_RETRIEVED)

    def test_broker_signed_retired_revoked_and_self_hosted_trust_levels(self) -> None:
        # 1. Valid BrokerNativeSignature -> BROKER_SIGNED
        broker_sig = create_signed_broker_signature(
            broker_private_key_hex=self.broker_kp.private_key_hex,
            broker_id="schwab",
            key_id="schwab-stmt-ed25519-v1",
            signed_payload_sha256=self.source_sha,
        )
        b_broker = create_signed_proof_bundle(
            proof_id="prf-broker-sig",
            issued_at_utc="2026-02-01T00:05:00Z",
            publisher_kid="n170-active-2026",
            publisher_private_key_hex=self.pub_active.private_key_hex,
            broker_id="schwab",
            blinded_account_tag=self.account_tag,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.BROKER_SIGNED,
            source_body_sha256=self.source_sha,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T23:59:59Z",
            base_currency="USD",
            leaf_payloads=_sample_seven_leaves(),
            broker_native_signature=broker_sig,
        )
        r_broker = verify_proof_bundle(b_broker, registry_doc=self.registry)
        self.assertTrue(r_broker.valid)
        self.assertEqual(r_broker.effective_origin_assurance, OriginAssurance.BROKER_SIGNED)

        # 2. Retired historical key within window -> RETIRED_HISTORICAL_VALID
        b_retired = create_signed_proof_bundle(
            proof_id="prf-retired-2025",
            issued_at_utc="2025-10-15T12:00:00Z",
            publisher_kid="n170-retired-2025",
            publisher_private_key_hex=self.pub_retired.private_key_hex,
            broker_id="schwab",
            blinded_account_tag=self.account_tag,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256=self.source_sha,
            period_start_utc="2025-09-01T00:00:00Z",
            period_end_utc="2025-09-30T23:59:59Z",
            base_currency="USD",
            leaf_payloads=_sample_seven_leaves(),
        )
        self.assertEqual(
            evaluate_signer_trust(b_retired, self.registry),
            SignerTrustStatus.RETIRED_HISTORICAL_VALID,
        )

        # 3. Revoked key -> REVOKED_KEY, valid=False, effective_origin_assurance=SELF_REPORTED
        b_revoked = create_signed_proof_bundle(
            proof_id="prf-revoked",
            issued_at_utc="2026-02-01T00:05:00Z",
            publisher_kid="n170-revoked-key",
            publisher_private_key_hex=self.pub_revoked.private_key_hex,
            broker_id="schwab",
            blinded_account_tag=self.account_tag,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.BROKER_SIGNED,
            source_body_sha256=self.source_sha,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T23:59:59Z",
            base_currency="USD",
            leaf_payloads=_sample_seven_leaves(),
            broker_native_signature=broker_sig,
        )
        r_revoked = verify_proof_bundle(b_revoked, registry_doc=self.registry)
        self.assertFalse(r_revoked.valid)
        self.assertEqual(r_revoked.signer_trust_status, SignerTrustStatus.REVOKED_KEY)
        self.assertEqual(r_revoked.effective_origin_assurance, OriginAssurance.SELF_REPORTED)

        # 4. Self-hosted unrecognized signer claiming INDEPENDENTLY_WITNESSED_TLS -> downgraded to SELF_REPORTED
        b_self = create_signed_proof_bundle(
            proof_id="prf-self-hosted",
            issued_at_utc="2026-02-01T00:05:00Z",
            publisher_kid="custom-local-node",
            publisher_private_key_hex=self.pub_unrecognized.private_key_hex,
            broker_id="ibkr",
            blinded_account_tag=self.account_tag,
            account_scope=AccountScope.UNKNOWN_OFFLINE_SCOPE,
            provider_approval_state=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
            source_body_sha256=self.source_sha,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T23:59:59Z",
            base_currency="USD",
            leaf_payloads=_sample_seven_leaves(),
        )
        r_self = verify_proof_bundle(b_self, registry_doc=self.registry)
        self.assertTrue(r_self.valid)
        self.assertEqual(
            r_self.signer_trust_status, SignerTrustStatus.UNRECOGNIZED_SELF_HOSTED_SIGNER
        )
        self.assertEqual(r_self.effective_origin_assurance, OriginAssurance.SELF_REPORTED)

    def test_variable_span_and_leaked_secret_transcript_rejections(self) -> None:
        bad_cases = [
            (
                "variable_span_side_channel",
                dict(
                    server_sni="api.alpaca.markets",
                    sanitized_request_target="/v2/account",
                    redacted_headers=["APCA-API-KEY-ID"],
                    commitment_kind=TranscriptCommitmentKind.UNPADDED_VARIABLE_SPAN_REJECTED,
                ),
            ),
            (
                "defer_decryption_disabled",
                dict(
                    server_sni="api.alpaca.markets",
                    sanitized_request_target="/v2/account",
                    redacted_headers=["APCA-API-KEY-ID"],
                    defer_decryption_from_start=False,
                ),
            ),
            (
                "leaked_authorization_bearer",
                dict(
                    server_sni="api.schwabapi.com",
                    sanitized_request_target="/trader/v1/accounts",
                    redacted_headers=["Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret"],
                ),
            ),
            (
                "leaked_alpaca_key_header",
                dict(
                    server_sni="api.alpaca.markets",
                    sanitized_request_target="/v2/account",
                    redacted_headers=["APCA-API-KEY-ID: PKLIVE9988776655"],
                ),
            ),
            (
                "leaked_cookie_header",
                dict(
                    server_sni="ndcdyn.interactivebrokers.com",
                    sanitized_request_target="/Universal/servlet/FlexStatementService.GetStatement",
                    redacted_headers=["Cookie: sessionid=xyz987654"],
                ),
            ),
            (
                "leaked_ibkr_query_token",
                dict(
                    server_sni="ndcdyn.interactivebrokers.com",
                    sanitized_request_target="/Universal/servlet/FlexStatementService.SendRequest?t=99887766&q=112233",
                    redacted_headers=["Cookie"],
                ),
            ),
            (
                "leaked_tradier_account_id_in_path",
                dict(
                    server_sni="api.tradier.com",
                    sanitized_request_target="/v1/accounts/VA12345678/balances",
                    redacted_headers=["Authorization"],
                ),
            ),
        ]

        for label, kwargs in bad_cases:
            with self.subTest(case=label):
                att = create_signed_witness_attestation(
                    notary_private_key_hex=self.notary_cf.private_key_hex,
                    notary_id="notary-cf-1",
                    response_body_sha256=self.source_sha,
                    session_timestamp_utc="2026-02-01T00:00:10Z",
                    **kwargs,
                )
                safe, reasons = inspect_transcript_safety(att)
                self.assertFalse(safe, f"Expected {label} to fail transcript safety")
                self.assertTrue(len(reasons) >= 1)

                bundle = create_signed_proof_bundle(
                    proof_id=f"prf-bad-{label}",
                    issued_at_utc="2026-02-01T00:05:00Z",
                    publisher_kid="n170-active-2026",
                    publisher_private_key_hex=self.pub_active.private_key_hex,
                    broker_id="schwab",
                    blinded_account_tag=self.account_tag,
                    account_scope=AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED,
                    provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
                    environment_tier=EnvironmentTier.LIVE_PRODUCTION,
                    claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
                    source_body_sha256=self.source_sha,
                    period_start_utc="2026-01-01T00:00:00Z",
                    period_end_utc="2026-01-31T23:59:59Z",
                    base_currency="USD",
                    leaf_payloads=_sample_seven_leaves(),
                    witness_attestations=[att],
                )
                res = verify_proof_bundle(bundle, registry_doc=self.registry)
                self.assertFalse(res.transcript_safety_ok)
                self.assertFalse(res.valid)

        # Redacted Tradier account placeholder in path MUST pass
        clean_tradier = create_signed_witness_attestation(
            notary_private_key_hex=self.notary_cf.private_key_hex,
            notary_id="notary-cf-1",
            server_sni="api.tradier.com",
            sanitized_request_target="/v1/accounts/[REDACTED]/balances",
            redacted_headers=["Authorization"],
            response_body_sha256=self.source_sha,
            session_timestamp_utc="2026-02-01T00:00:10Z",
        )
        safe_ok, clean_reasons = inspect_transcript_safety(clean_tradier)
        self.assertTrue(safe_ok, clean_reasons)


class TestProspectiveChainInvariants(unittest.TestCase):
    """Tests for all 5 formal LP due-diligence prospective chain invariants."""

    def setUp(self) -> None:
        self.pub_kp = generate_ed25519_keypair(b"\x81" * 32)
        self.account_tag = compute_blinded_account_tag("alpaca", "PA-LIVE-001", "dd" * 32)
        self.other_account_tag = compute_blinded_account_tag("alpaca", "PA-LIVE-002", "dd" * 32)
        self.policy = ChainCadencePolicy(
            expected_interval_seconds=86_400,
            grace_window_seconds=14_400,
        )

    def _make_three_bundle_chain(self) -> tuple[list[Any], list[ContinuityLogLeaf]]:
        leaves = _sample_seven_leaves()

        link0 = ProspectiveChainLink(
            chain_id="chain-alpaca-001",
            sequence_number=0,
            prev_proof_hash=None,
            blinded_account_tag=self.account_tag,
            enrolled_at_utc="2026-03-01T00:10:00Z",
            period_start_utc="2026-03-01T00:00:00Z",
            period_end_utc="2026-03-02T00:00:00Z",
            issued_at_utc="2026-03-02T01:00:00Z",
            cadence_policy=self.policy,
            beginning_index_value=100.0,
            ending_index_value=102.0,
            period_twr_decimal=0.02,
        )
        p0 = create_signed_proof_bundle(
            proof_id="p0",
            issued_at_utc=link0.issued_at_utc,
            publisher_kid="n170-active-2026",
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            broker_id="alpaca",
            blinded_account_tag=self.account_tag,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="31" * 32,
            period_start_utc=link0.period_start_utc,
            period_end_utc=link0.period_end_utc,
            base_currency="USD",
            leaf_payloads=leaves,
            prospective_chain_link=link0,
        )

        link1 = ProspectiveChainLink(
            chain_id="chain-alpaca-001",
            sequence_number=1,
            prev_proof_hash=p0.proof_hash(),
            blinded_account_tag=self.account_tag,
            enrolled_at_utc="2026-03-01T00:10:00Z",
            period_start_utc="2026-03-02T00:00:00Z",
            period_end_utc="2026-03-03T00:00:00Z",
            issued_at_utc="2026-03-03T01:00:00Z",
            cadence_policy=self.policy,
            beginning_index_value=102.0,
            ending_index_value=100.98,
            period_twr_decimal=-0.01,
        )
        p1 = create_signed_proof_bundle(
            proof_id="p1",
            issued_at_utc=link1.issued_at_utc,
            publisher_kid="n170-active-2026",
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            broker_id="alpaca",
            blinded_account_tag=self.account_tag,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="32" * 32,
            period_start_utc=link1.period_start_utc,
            period_end_utc=link1.period_end_utc,
            base_currency="USD",
            leaf_payloads=leaves,
            prospective_chain_link=link1,
        )

        link2 = ProspectiveChainLink(
            chain_id="chain-alpaca-001",
            sequence_number=2,
            prev_proof_hash=p1.proof_hash(),
            blinded_account_tag=self.account_tag,
            enrolled_at_utc="2026-03-01T00:10:00Z",
            period_start_utc="2026-03-03T00:00:00Z",
            period_end_utc="2026-03-04T00:00:00Z",
            issued_at_utc="2026-03-04T01:00:00Z",
            cadence_policy=self.policy,
            beginning_index_value=100.98,
            ending_index_value=106.029,
            period_twr_decimal=0.05,
        )
        p2 = create_signed_proof_bundle(
            proof_id="p2",
            issued_at_utc=link2.issued_at_utc,
            publisher_kid="n170-active-2026",
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            broker_id="alpaca",
            blinded_account_tag=self.account_tag,
            account_scope=AccountScope.SUBACCOUNT_COMPLETENESS_UNSUPPORTED,
            provider_approval_state=ProviderApprovalState.USER_KEY_SELF_ATTESTED,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="33" * 32,
            period_start_utc=link2.period_start_utc,
            period_end_utc=link2.period_end_utc,
            base_currency="USD",
            leaf_payloads=leaves,
            prospective_chain_link=link2,
        )

        log_leaves = [
            ContinuityLogLeaf(
                log_index=i,
                chain_id="chain-alpaca-001",
                blinded_account_tag=self.account_tag,
                sequence_number=i,
                proof_hash=b.proof_hash(),
                logged_at_utc=b.issued_at_utc,
            )
            for i, b in enumerate((p0, p1, p2))
        ]
        return [p0, p1, p2], log_leaves

    def test_valid_prospective_chain_and_selective_disclosure_invariance(self) -> None:
        chain, log_leaves = self._make_three_bundle_chain()
        # Redacting leaves on p0 does NOT break prev_proof_hash in p1!
        chain[0] = chain[0].redact_leaves(["capital_bracket", "delayed_closed_trades"])
        res = verify_prospective_chain(
            chain,
            continuity_log_leaves=log_leaves,
            now_utc="2026-03-04T12:00:00Z",
        )
        self.assertTrue(res.valid, res.details)
        self.assertEqual(res.continuity_mode, ChainContinuityMode.PROSPECTIVE_CONTINUOUS)
        self.assertEqual(res.verified_length, 3)

    def test_invariant_1_genesis_backfill_window_exceeded(self) -> None:
        backfill_link = ProspectiveChainLink(
            chain_id="chain-backfill",
            sequence_number=0,
            prev_proof_hash=None,
            blinded_account_tag=self.account_tag,
            enrolled_at_utc="2026-03-15T00:00:00Z",  # 14 days after period_start_utc (> 86,400s)
            period_start_utc="2026-03-01T00:00:00Z",
            period_end_utc="2026-03-15T00:00:00Z",
            issued_at_utc="2026-03-15T01:00:00Z",
            cadence_policy=self.policy,
            beginning_index_value=100.0,
            ending_index_value=104.0,
            period_twr_decimal=0.04,
        )
        res = verify_prospective_chain([backfill_link])
        self.assertFalse(res.valid)
        self.assertEqual(res.continuity_mode, ChainContinuityMode.RETROSPECTIVE_BACKFILL)
        self.assertIn(
            ChainInvariantViolationCode.GENESIS_BACKFILL_WINDOW_EXCEEDED,
            res.violation_codes,
        )

    def test_invariants_2_3_4_and_5_failure_modes(self) -> None:
        chain, log_leaves = self._make_three_bundle_chain()

        # Invariant 2a: Non-monotonic sequence (skip p1 -> p0, p2)
        res_seq = verify_prospective_chain([chain[0], chain[2]])
        self.assertFalse(res_seq.valid)
        self.assertEqual(res_seq.continuity_mode, ChainContinuityMode.CONTINUITY_BROKEN)
        self.assertIn(ChainInvariantViolationCode.NON_MONOTONIC_SEQUENCE, res_seq.violation_codes)

        # Invariant 2b: Tampered prev_proof_hash
        bad_prev = ProspectiveChainLink.from_dict(
            {**chain[1].prospective_chain_link.to_dict(), "prev_proof_hash": "ff" * 32}
        )
        res_hash = verify_prospective_chain([chain[0].prospective_chain_link, bad_prev])
        self.assertFalse(res_hash.valid)
        self.assertIn(ChainInvariantViolationCode.PREV_HASH_MISMATCH, res_hash.violation_codes)

        # Invariant 2c: Mutated cadence_policy
        mutated_policy_link = ProspectiveChainLink.from_dict(
            {
                **chain[1].prospective_chain_link.to_dict(),
                "prev_proof_hash": jcs_sha256_hex(chain[0].prospective_chain_link.to_dict()),
                "cadence_policy": {"expected_interval_seconds": 604_800, "grace_window_seconds": 3600},
            }
        )
        res_pol = verify_prospective_chain([chain[0].prospective_chain_link, mutated_policy_link])
        self.assertFalse(res_pol.valid)
        self.assertIn(ChainInvariantViolationCode.CADENCE_POLICY_MUTATED, res_pol.violation_codes)

        # Invariant 3: Switched blinded_account_tag mid-chain
        switched_acct_link = ProspectiveChainLink.from_dict(
            {
                **chain[1].prospective_chain_link.to_dict(),
                "prev_proof_hash": jcs_sha256_hex(chain[0].prospective_chain_link.to_dict()),
                "blinded_account_tag": self.other_account_tag,
            }
        )
        res_acct = verify_prospective_chain([chain[0].prospective_chain_link, switched_acct_link])
        self.assertFalse(res_acct.valid)
        self.assertIn(
            ChainInvariantViolationCode.ACCOUNT_CONTINUITY_VIOLATION, res_acct.violation_codes
        )

        # Invariant 4: Gap in period_start_utc / discontinuous index
        gapped_link = ProspectiveChainLink.from_dict(
            {
                **chain[1].prospective_chain_link.to_dict(),
                "prev_proof_hash": jcs_sha256_hex(chain[0].prospective_chain_link.to_dict()),
                "period_start_utc": "2026-03-02T12:00:00Z",
                "beginning_index_value": 95.0,
                "ending_index_value": 94.05,
            }
        )
        res_gap = verify_prospective_chain([chain[0].prospective_chain_link, gapped_link])
        self.assertFalse(res_gap.valid)
        self.assertIn(
            ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED, res_gap.violation_codes
        )

        # Invariant 5a: Omitted bad tail (presenting only [p0, p1] while log contains seq=2)
        res_trunc = verify_prospective_chain(chain[:2], continuity_log_leaves=log_leaves)
        self.assertFalse(res_trunc.valid)
        self.assertIn(
            ChainInvariantViolationCode.STALE_OR_TRUNCATED_TAIL, res_trunc.violation_codes
        )

        # Invariant 5b: Stale tail relative to now_utc
        res_stale = verify_prospective_chain(
            chain,
            continuity_log_leaves=log_leaves,
            now_utc="2026-03-10T00:00:00Z",
        )
        self.assertFalse(res_stale.valid)
        self.assertIn(
            ChainInvariantViolationCode.STALE_OR_TRUNCATED_TAIL, res_stale.violation_codes
        )

        # Invariant 5c: Parallel chain reset (second sequence_number == 0 for same blinded_account_tag)
        reset_log = [
            *log_leaves,
            ContinuityLogLeaf(
                log_index=99,
                chain_id="chain-alpaca-reset-002",
                blinded_account_tag=self.account_tag,
                sequence_number=0,
                proof_hash="ee" * 32,
                logged_at_utc="2026-03-05T00:00:00Z",
            ),
        ]
        res_reset = verify_prospective_chain(chain, continuity_log_leaves=reset_log)
        self.assertFalse(res_reset.valid)
        self.assertIn(
            ChainInvariantViolationCode.PARALLEL_CHAIN_RESET_DETECTED,
            res_reset.violation_codes,
        )


class TestStandalonePackageIsolation(unittest.TestCase):
    """Ensure n170_verify is self-contained with zero unreviewed external runtime coupling."""

    def test_standalone_package_namespace_isolation(self) -> None:
        loaded = [
            name
            for name in sys.modules
            if name == "n170" or name.startswith("n170.")
        ]
        self.assertEqual(loaded, [])
        self.assertEqual(VERIFY_SCHEMA_VERSION, "n170-verify-v3")


if __name__ == "__main__":
    unittest.main()
