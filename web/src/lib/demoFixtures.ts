/**
 * N170 Verify v3 — Cryptographically Signed Public Demo Fixtures.
 *
 * Every bundle, salted 7-leaf Merkle tree, MPC-TLS witness attestation,
 * C2SP tlog-checkpoint cosignature, and prospective chain link in this module
 * is genuinely Ed25519-signed using deterministic public demo seeds and
 * verifies 100% end-to-end under both Python `verify_proof_bundle` and
 * browser `crypto.subtle` (`verifyProofBundle`).
 */

import type {
  ContinuityLogLeaf,
  PublisherKeyRegistryDocument,
  VerifyProofBundle,
} from "./contracts.ts";

export interface ShowcaseProfileMeta {
  proofId: string;
  handle: string;
  strategyTitle: string;
  subtitle: string;
  assetFocus: string;
  brokerDisplay: string;
  previewMode:
    | "institutional_fund"
    | "discrepancy_xray"
    | "coaching_studio"
    | "custody_feed"
    | "historical_archive"
    | "full_studio";
  bundle: VerifyProofBundle;
  fullUnredactedBundle?: VerifyProofBundle;
  chainHistory: VerifyProofBundle[];
}

export const DEMO_REGISTRY_DOCUMENT: PublisherKeyRegistryDocument = {
  "updated_at_utc": "2026-04-01T12:00:00Z",
  "keys": [
    {
      "publisher_kid": "n170-pub-2026-q1",
      "public_key_hex": "519749abe49eaf67bff092d850c243df38be8697b84a2dde4b8fad150d08ff78",
      "status": "active",
      "not_before_utc": "2026-01-01T00:00:00Z",
      "not_after_utc": "2027-01-01T00:00:00Z",
      "revoked_after_utc": null,
      "issuer_org": "N170"
    },
    {
      "publisher_kid": "n170-pub-2025-h2",
      "public_key_hex": "01080b646c2f518909f7766c30229aecdfe6894e5c7757f71c828c8ef8841703",
      "status": "retired",
      "not_before_utc": "2025-07-01T00:00:00Z",
      "not_after_utc": "2025-12-31T23:59:59Z",
      "revoked_after_utc": null,
      "issuer_org": "N170"
    },
    {
      "publisher_kid": "n170-pub-compromised-test",
      "public_key_hex": "9641f1e0f3e858410a22ce94888e9fb87e0ad34fc33c1b6815a1330a8ba10144",
      "status": "revoked",
      "not_before_utc": "2025-01-01T00:00:00Z",
      "not_after_utc": null,
      "revoked_after_utc": "2025-06-01T00:00:00Z",
      "issuer_org": "N170"
    }
  ],
  "notaries": [
    {
      "notary_id": "notary-pse-eu",
      "operator_org": "PSE TLSNotary Foundation",
      "asn": "AS24940",
      "public_key_hex": "e62531931eaf8b085d1965fc220a085e607dfc76f99f732c9a48c192776cb6d1",
      "is_debug_build": false,
      "attestation_type": "aws_nitro_enclave"
    },
    {
      "notary_id": "notary-swiss-ch",
      "operator_org": "Zurich Independent Attestations AG",
      "asn": "AS13030",
      "public_key_hex": "96fe1168f097e664807fff68d82257ea3d6dd2421b43cb30be36a121cfd2954d",
      "is_debug_build": false,
      "attestation_type": "amd_sev_snp"
    },
    {
      "notary_id": "notary-nordic-is",
      "operator_org": "Reykjavik Transparency Lab",
      "asn": "AS44530",
      "public_key_hex": "b340c6a8ab3890078c08632043eb7ae3c015d6ccfcc56f28d691202a376f2d2e",
      "is_debug_build": false,
      "attestation_type": "aws_nitro_enclave"
    },
    {
      "notary_id": "notary-colocated-eu2",
      "operator_org": "Berlin Notary Guild",
      "asn": "AS24940",
      "public_key_hex": "016d30f3cc956561e7e433df41d5780a701c847229b1d5d95f35704907cfdd7b",
      "is_debug_build": false,
      "attestation_type": "production"
    }
  ],
  "checkpoint": {
    "origin": "n170.verify/transparency/v3",
    "size": 1284,
    "hash_b64": "qNNnSPvOdC6EhQHaf9Sde2shsaF31ZkYhq6t+UD+xPo=",
    "publisher_kid": "n170-pub-2026-q1",
    "publisher_signature_hex": "f6f9b5508a8a084dcb7b18f604abe81d1d9ca213a865ee2e391b575fb9f8dff2d2735bfe6da79181097bf55af08f819272c0a04269284d45a0d071360df94606",
    "witness_cosignatures": [
      {
        "witness_id": "witness-sigsum-se",
        "public_key_hex": "6372809b80fcc875762401d4dd49ae2cb54b27f9ee380b2d09d70fa52f117c71",
        "timestamp_utc": "2026-04-01T11:58:10Z",
        "signature_hex": "5f945f7d86283bf96ec4d9562b19a6d470713bc74ce4d37935ac0f972dfdcc9177193f16d9cc58fad72b4d07630348b3f7382a1a4b5020290392abb7c247770e"
      },
      {
        "witness_id": "witness-c2sp-ch",
        "public_key_hex": "925535d2102e6131037ede85da7db604c256e4b548ce800decb16641b4d4a57e",
        "timestamp_utc": "2026-04-01T11:58:24Z",
        "signature_hex": "10da8360575d44225f3f857ba7c6b60c9c03cd18770b0a98b38ea8b1c8bbd695e9ce23462944582de66895bb63565cef808ce974698a2cb475bf3528ab622408"
      }
    ]
  },
  "l2_anchor": {
    "contract_address": "0x4e313730566572696679416e63686f7256333031",
    "tx_hash": "0x3c4e57a2aff05bd7388d359a6782052d28a9d984b9bd42152f3f85e962220048",
    "batch_merkle_root": "a8d36748fbce742e848501da7fd49d7b6b21b1a177d5991886aeadf940fec4fa",
    "chain_id": 8453,
    "block_number": 28419022,
    "anchored_at_utc": "2026-04-01T11:55:00Z"
  },
  "pinned_broker_keys": {
    "prime_custody_ed25519": {
      "prime-custody-k1": "66bd4c45dcd977122a0667dd304f140570e6af266afa88ac575435396b5f4c67"
    }
  },
  "schema_version": "n170-verify-keys-v3"
};

export const DEMO_CONTINUITY_LOG_LEAVES: ContinuityLogLeaf[] = [
  {
    "log_index": 1201,
    "chain_id": "chain-meridian-2026",
    "blinded_account_tag": "17bad5d847162a4aae8550221f68eac6b563ac019290bfd83c9945dff4f8d462",
    "sequence_number": 0,
    "proof_hash": "79ae579aaccc4059ac55cec5b9e13af9dc63afcc4f4de2558a6b2d3abd4aec82",
    "logged_at_utc": "2026-02-01T02:15:12Z"
  },
  {
    "log_index": 1244,
    "chain_id": "chain-meridian-2026",
    "blinded_account_tag": "17bad5d847162a4aae8550221f68eac6b563ac019290bfd83c9945dff4f8d462",
    "sequence_number": 1,
    "proof_hash": "a0b2ea961a90110ee5d8125fa5168a7bc05bb961f2feca91e3877b87ae7ee6ce",
    "logged_at_utc": "2026-03-01T01:45:09Z"
  },
  {
    "log_index": 1283,
    "chain_id": "chain-meridian-2026",
    "blinded_account_tag": "17bad5d847162a4aae8550221f68eac6b563ac019290bfd83c9945dff4f8d462",
    "sequence_number": 2,
    "proof_hash": "beec255251447a3b35edca1de99872264a43a7208a26451eba3ea606d361dfd6",
    "logged_at_utc": "2026-04-01T03:12:05Z"
  }
];

export const BUNDLE_INSTITUTIONAL_SEQ0: VerifyProofBundle = {
  "proof_id": "prf-inst-alpha-010",
  "issued_at_utc": "2026-02-01T02:15:00Z",
  "publisher_kid": "n170-pub-2026-q1",
  "publisher_public_key_hex": "519749abe49eaf67bff092d850c243df38be8697b84a2dde4b8fad150d08ff78",
  "broker_id": "interactive_brokers",
  "blinded_account_tag": "17bad5d847162a4aae8550221f68eac6b563ac019290bfd83c9945dff4f8d462",
  "account_scope": "all_enumerated_subaccounts",
  "provider_approval_state": "approved_live",
  "environment_tier": "live_production",
  "claimed_origin_assurance": "independently_witnessed_tls",
  "source_body_sha256": "3ac0eeec8bd51b95812b7c0e2fa1f486fa612095eef7707edbeedfc06c862557",
  "period_start_utc": "2026-01-01T00:00:00Z",
  "period_end_utc": "2026-01-31T23:59:59Z",
  "base_currency": "USD",
  "merkle_root": "b29643daafb23c567c7f1bd37412c01803a4ae9e91f68686fcd9b94fb09aa09a",
  "signature_hex": "193f4d61aaaf6f81e38e409bda845a37064c002f1c77f6b7fd334dcc3b3a483db5d3412c372883c08f36607aff7c8dc9ca59fa72cc2d2ac2438bb6d65082840b",
  "schema_version": "n170-verify-v3",
  "disclosed_leaves": [
    {
      "leaf_name": "core_metrics",
      "salt_hex": "8c1d04aaa6eee43bcb969e9a0b8c967aa8b856022f21e8dd053d765469af4ee6",
      "payload": {
        "twr_decimal": 0.41877,
        "twr_pct": 41.877,
        "cagr_decimal": 3.048,
        "cagr_pct": 304.8,
        "xirr_decimal": 2.982,
        "annualized_volatility": 0.148,
        "smoothing_index_xi": 0.76,
        "lag1_autocorrelation": 0.24,
        "unsmoothed_volatility": 0.171,
        "unsmoothed_sharpe_ratio": 2.45,
        "sharpe_ratio": 2.84,
        "sortino_ratio": 4.12,
        "probabilistic_sharpe_ratio": 0.996,
        "psr_glm_unsmoothed": 0.984,
        "min_track_record_length_periods": 19.4,
        "psr_sample_eligible": true,
        "observation_count": 63,
        "psr_benchmark_sr": 0.0,
        "non_iid_caveat": "PSR accounts for skewness and excess kurtosis under stationary returns; GLM unsmoothing adjusts for first-order serial correlation, and unobserved multi-account selection trials cannot be ruled out without subaccount enumeration.",
        "max_drawdown_decimal": -0.0462,
        "max_drawdown_pct": -4.62,
        "skewness": 0.34,
        "excess_kurtosis": 0.82,
        "capital_bracket": "over_1m",
        "benchmark_symbol": "SPY",
        "benchmark_twr_decimal": 0.0612,
        "alpha_decimal": 0.35757,
        "indexed_curve": [
          {
            "timestamp_utc": "2026-01-01T00:00:00Z",
            "index_value": 100.0,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.0
          },
          {
            "timestamp_utc": "2026-01-09T21:00:00Z",
            "index_value": 104.2,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 101.1
          },
          {
            "timestamp_utc": "2026-01-19T21:00:00Z",
            "index_value": 102.8,
            "drawdown_pct": -1.34,
            "benchmark_index_value": 100.4
          },
          {
            "timestamp_utc": "2026-01-31T23:59:59Z",
            "index_value": 112.4,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 102.3
          },
          {
            "timestamp_utc": "2026-02-10T21:00:00Z",
            "index_value": 118.9,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 103.5
          },
          {
            "timestamp_utc": "2026-02-18T21:00:00Z",
            "index_value": 113.41,
            "drawdown_pct": -4.62,
            "benchmark_index_value": 101.9
          },
          {
            "timestamp_utc": "2026-02-28T23:59:59Z",
            "index_value": 126.45,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.1
          },
          {
            "timestamp_utc": "2026-03-09T21:00:00Z",
            "index_value": 131.8,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.8
          },
          {
            "timestamp_utc": "2026-03-17T21:00:00Z",
            "index_value": 129.4,
            "drawdown_pct": -1.82,
            "benchmark_index_value": 103.9
          },
          {
            "timestamp_utc": "2026-03-24T21:00:00Z",
            "index_value": 137.6,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 105.4
          },
          {
            "timestamp_utc": "2026-03-31T23:59:59Z",
            "index_value": 141.877,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 106.12
          }
        ],
        "methodology": "daily_flow_adjusted_twr_v3",
        "warnings": []
      },
      "leaf_hash_hex": "15102dae24b655841f16122be234def38d02f47234e7f43ed1f7e34a0323ddb1",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "bd835c19e1f5c34a7973e24a4f97e7ed25c05081e2fafe3b77fb00955078827f"
        },
        {
          "side": "right",
          "sibling_hash_hex": "f56910f1ccec71a8e94238a05139112e21c4b11e7745a6b9a5b3098d600273c6"
        },
        {
          "side": "right",
          "sibling_hash_hex": "877247217715c9048bb4a34d5592691645260b14ed062c47fe84f82592455f71"
        }
      ]
    },
    {
      "leaf_name": "indexed_curve",
      "salt_hex": "cbbdc045424a1276e1e9d9794e836e3fd578e9dffc86d16b3dd0e7a9b3a56b40",
      "payload": {
        "base_index": 100.0,
        "points": [
          {
            "timestamp_utc": "2026-01-01T00:00:00Z",
            "index_value": 100.0,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.0
          },
          {
            "timestamp_utc": "2026-01-09T21:00:00Z",
            "index_value": 104.2,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 101.1
          },
          {
            "timestamp_utc": "2026-01-19T21:00:00Z",
            "index_value": 102.8,
            "drawdown_pct": -1.34,
            "benchmark_index_value": 100.4
          },
          {
            "timestamp_utc": "2026-01-31T23:59:59Z",
            "index_value": 112.4,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 102.3
          },
          {
            "timestamp_utc": "2026-02-10T21:00:00Z",
            "index_value": 118.9,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 103.5
          },
          {
            "timestamp_utc": "2026-02-18T21:00:00Z",
            "index_value": 113.41,
            "drawdown_pct": -4.62,
            "benchmark_index_value": 101.9
          },
          {
            "timestamp_utc": "2026-02-28T23:59:59Z",
            "index_value": 126.45,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.1
          },
          {
            "timestamp_utc": "2026-03-09T21:00:00Z",
            "index_value": 131.8,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.8
          },
          {
            "timestamp_utc": "2026-03-17T21:00:00Z",
            "index_value": 129.4,
            "drawdown_pct": -1.82,
            "benchmark_index_value": 103.9
          },
          {
            "timestamp_utc": "2026-03-24T21:00:00Z",
            "index_value": 137.6,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 105.4
          },
          {
            "timestamp_utc": "2026-03-31T23:59:59Z",
            "index_value": 141.877,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 106.12
          }
        ]
      },
      "leaf_hash_hex": "bd835c19e1f5c34a7973e24a4f97e7ed25c05081e2fafe3b77fb00955078827f",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "15102dae24b655841f16122be234def38d02f47234e7f43ed1f7e34a0323ddb1"
        },
        {
          "side": "right",
          "sibling_hash_hex": "f56910f1ccec71a8e94238a05139112e21c4b11e7745a6b9a5b3098d600273c6"
        },
        {
          "side": "right",
          "sibling_hash_hex": "877247217715c9048bb4a34d5592691645260b14ed062c47fe84f82592455f71"
        }
      ]
    },
    {
      "leaf_name": "reconciliation",
      "salt_hex": "468e31f6a02f3190110e27aabe0c1334ad698b88fadb24c8d15fe4714ec16177",
      "payload": {
        "status": "reconciled_within_tolerance",
        "reference_provider": "eodhd",
        "ledger_completeness_ok": true,
        "missing_sections": [],
        "checks_evaluated": 184,
        "discrepancy_count": 0,
        "explained_convention_count": 2,
        "findings": [
          {
            "category": "daily_nav_continuity_identity",
            "outcome": "pass",
            "date_or_timestamp": "2026-01-01..2026-03-31",
            "symbol": "PORTFOLIO",
            "expected_value": 141.877,
            "observed_value": 141.878,
            "residual_bps": 0.07,
            "residual_base_currency": null,
            "math_identity": "NAV_t = NAV_{t-1} + Realized_t + Unrealized_t + NetFlows_t - Fees_t",
            "technical_explanation": "All 63 daily valuation intervals reconcile within 0.4 bps tolerance across all enumerated subaccounts.",
            "benign_causes_considered": [
              "Sub-penny multi-currency mark rounding"
            ]
          },
          {
            "category": "fx_t1_settlement_accrual",
            "outcome": "explained_convention",
            "date_or_timestamp": "2026-02-13T17:00:00Z",
            "symbol": "EUR.USD",
            "expected_value": 1.0418,
            "observed_value": 1.0421,
            "residual_bps": 2.88,
            "residual_base_currency": null,
            "math_identity": "Cash_Base(t) = Spot_FX(t) * Settled_Cash + Forward_Accrual(T+1)",
            "technical_explanation": "3 bps transient variance between trade-date and settlement-date FX translation resolved automatically on T+1 settlement.",
            "benign_causes_considered": [
              "WM/Refinitiv 16:00 London fix vs NY 17:00 broker FX mark",
              "T+1 spot FX value-date interest differential"
            ]
          },
          {
            "category": "dividend_ex_date_receivable",
            "outcome": "explained_convention",
            "date_or_timestamp": "2026-03-13T20:00:00Z",
            "symbol": "MSFT",
            "expected_value": 100.0,
            "observed_value": 100.0,
            "residual_bps": 0.0,
            "residual_base_currency": null,
            "math_identity": "NavExDate = SharePrice_Ex * Qty + DividendAccrualReceivable",
            "technical_explanation": "Ex-dividend price drop matched exact ChangeInDividendAccruals entry net of 15% treaty withholding.",
            "benign_causes_considered": [
              "Ex-date vs pay-date accrual accounting"
            ]
          },
          {
            "category": "eodhd_two_stage_fill_envelope",
            "outcome": "pass",
            "date_or_timestamp": "2026-03-24T14:32:18Z",
            "symbol": "NVDA",
            "expected_value": 138.4,
            "observed_value": 138.52,
            "residual_bps": 0.0,
            "residual_base_currency": null,
            "math_identity": "Low_1m(t) - SpreadTol <= FillPrice <= High_1m(t) + SpreadTol",
            "technical_explanation": "184 of 184 equity, ETF, and index futures executions fell strictly inside EODHD Stage-1 daily and Stage-2 1-minute market envelopes.",
            "benign_causes_considered": [
              "Odd-lot NBBO midpoint print",
              "Extended-hours auction cross"
            ]
          }
        ],
        "statistical_diagnostics": [
          {
            "metric_name": "Getmansky-Lo-Makarov Smoothing Index (xi)",
            "observed_value": 0.76,
            "interpretation": "Mild lag-1 return autocorrelation (rho_1 = 0.24) consistent with liquid swing overnight momentum exposure; PSR_GLM (98.4%) remains statistically significant after unsmoothing.",
            "caveats": [
              "GLM MA(2) unsmoothing assumes locally stationary return innovations.",
              "Reported alongside raw annualized volatility (14.8% raw vs 17.1% GLM unsmoothed)."
            ]
          },
          {
            "metric_name": "Execution Midpoint Slippage Asymmetry",
            "observed_value": -1.4,
            "interpretation": "Mean fill execution realized 1.4 bps adverse to 1-minute VWAP, consistent with realistic institutional limit/marketable-limit order routing.",
            "caveats": [
              "Does not accuse or clear off-exchange internalized flow advantages."
            ]
          }
        ],
        "summary_text": "All 5 canonical ledger sections verified across all enumerated subaccounts; 0 unexplained residuals across 63 trading days."
      },
      "leaf_hash_hex": "bc9e0f6881ca41155992fd225b1ec5c77c92667067a6df04098ab8a04e3c688b",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "80cb37f13d329d2bacacb4dfbe1c255a51b7a982adb495a2b58966b454761106"
        },
        {
          "side": "left",
          "sibling_hash_hex": "8973b7f9a09c65702594877c010f8f83efbef7accc73735d5f28ea4da95e7c9b"
        },
        {
          "side": "right",
          "sibling_hash_hex": "877247217715c9048bb4a34d5592691645260b14ed062c47fe84f82592455f71"
        }
      ]
    },
    {
      "leaf_name": "coaching_and_context",
      "salt_hex": "2131f6c0d37a7b9e398573bb5aa5cd74ed7e8994911c9a20e27f351e69d9797f",
      "payload": {
        "cost_drag": {
          "commission_and_fee_drag_bps": 14.2,
          "margin_and_funding_drag_bps": 19.8,
          "fx_conversion_drag_bps": 4.1,
          "withholding_tax_drag_bps": 3.4,
          "total_friction_drag_bps": 41.5,
          "annualized_total_drag_bps": 168.0
        },
        "behaviour": {
          "sample_eligible": true,
          "min_trades_gate": 30,
          "observed_trades": 142,
          "observed_days": 63,
          "median_holding_hours": 54.6,
          "holding_horizon_label": "multi_day_institutional_swing",
          "win_rate": 0.563,
          "profit_factor": 2.18,
          "winner_vs_loser_hold_ratio": 2.38,
          "odean_pgr_plr_spread": -0.082,
          "post_drawdown_sizing_discipline_atr": 0.94,
          "atr_normalized": true,
          "return_concentration_top5_pct": 28.4,
          "actionable_improvements": [
            "Overnight margin financing accounts for 47.7% of total friction (19.8 bps in Q1); sweeping idle EUR/CHF balances via FX swap box reduces annualized drag by ~38 bps.",
            "Post-drawdown ATR risk discipline is exemplary (0.94x baseline ATR risk following the Feb -4.62% drawdown), avoiding convex drawdown escalation.",
            "Negative Odean PGR-PLR spread (-0.082) confirms winners are systematically held 2.38x longer than stopped-out losers."
          ]
        },
        "catalyst_regime_win_rate": 0.642,
        "quiet_regime_win_rate": 0.538,
        "event_window_share_pct": 24.6,
        "event_observations": [
          {
            "symbol": "NVDA",
            "trade_timestamp_utc": "2026-02-25T21:24:11Z",
            "earliest_public_utc": "2026-02-25T21:20:04Z",
            "confirmed_public_utc": "2026-02-25T21:21:30Z",
            "event_sources": [
              "SEC EDGAR Form 8-K",
              "BusinessWire Feed"
            ],
            "headline_or_event": "Q4 Fiscal 2026 Earnings Release & Data-Center Guidance",
            "alignment_class": "post_confirmed_catalyst",
            "timestamp_uncertainty_note": "Execution occurred +2m41s after confirmed EDGAR/wire dissemination [21:20:04Z, 21:21:30Z]."
          },
          {
            "symbol": "SAP",
            "trade_timestamp_utc": "2026-01-28T06:01:19Z",
            "earliest_public_utc": "2026-01-28T06:00:00Z",
            "confirmed_public_utc": "2026-01-28T06:03:12Z",
            "event_sources": [
              "EQS Ad-Hoc Disclosure",
              "Consolidated News Aggregator"
            ],
            "headline_or_event": "Cloud Backlog Acceleration & FY26 Operating Profit Outlook",
            "alignment_class": "ambiguous_public_window",
            "timestamp_uncertainty_note": "Trade falls inside I_e = [06:00:00Z, 06:03:12Z] due to ~3m aggregator indexing lag behind primary EQS wire."
          },
          {
            "symbol": "MSFT",
            "trade_timestamp_utc": "2026-03-11T15:10:44Z",
            "earliest_public_utc": null,
            "confirmed_public_utc": null,
            "event_sources": [
              "EODHD Corporate Calendar"
            ],
            "headline_or_event": "No scheduled macro or issuer-specific catalyst within +-24h",
            "alignment_class": "quiet_non_catalyst_regime",
            "timestamp_uncertainty_note": "Classified as quiet regime liquidity execution."
          }
        ],
        "llm_narrative_used": false,
        "llm_model_id": null,
        "style_summary": "Multi-day liquid equity & index-futures swing strategy with disciplined ATR volatility targeting and low disposition bias.",
        "coaching_takeaways": [
          "Positive post-catalyst drift capture (64.2% win rate in confirmed post-release windows vs 53.8% in quiet regimes).",
          "Top-5 winners contribute 28.4% of cumulative TWR \u2014 well-diversified across 142 closed round-trips."
        ],
        "uncertainty_disclosures": [
          "Public news wire timestamps carry +-30s to +-180s ingestion latency across secondary aggregators; catalyst intervals I_e = [t_earliest, t_confirmed] are descriptive context and never imply non-public information."
        ]
      },
      "leaf_hash_hex": "80cb37f13d329d2bacacb4dfbe1c255a51b7a982adb495a2b58966b454761106",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "bc9e0f6881ca41155992fd225b1ec5c77c92667067a6df04098ab8a04e3c688b"
        },
        {
          "side": "left",
          "sibling_hash_hex": "8973b7f9a09c65702594877c010f8f83efbef7accc73735d5f28ea4da95e7c9b"
        },
        {
          "side": "right",
          "sibling_hash_hex": "877247217715c9048bb4a34d5592691645260b14ed062c47fe84f82592455f71"
        }
      ]
    },
    {
      "leaf_name": "capital_bracket",
      "salt_hex": "6ccb4f9f660c6f18b565d704879a98b47f2f9e2b8aa7f66b9f63e0e543bd764c",
      "payload": {
        "capital_bracket": "over_1m",
        "valuation_currency": "USD"
      },
      "leaf_hash_hex": "56e826475959918bf784dd91dafd88041151385926ed24ae3435e2aea576b144",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "b99a08b971af1f635185d0f6b453e360e74c971dd48873731579b05b7d0d24e1"
        },
        {
          "side": "right",
          "sibling_hash_hex": "2d493660044d5a761b5a2c243c3b419b74007258ea85695737dc2988c50ccbb8"
        },
        {
          "side": "left",
          "sibling_hash_hex": "e8684e2524da4f7d35b9e2ffdaf5f5a208604a111f7bf0ab2ee730dff36c2d99"
        }
      ]
    },
    {
      "leaf_name": "benchmark_alpha",
      "salt_hex": "00e594d9904f6ddec8bda9737e635a7c816e963a467898f7ebc5afae6ca03323",
      "payload": {
        "benchmark_symbol": "SPY",
        "benchmark_twr_decimal": 0.0612,
        "alpha_decimal": 0.35757,
        "information_ratio": 2.31,
        "beta": 0.42
      },
      "leaf_hash_hex": "b99a08b971af1f635185d0f6b453e360e74c971dd48873731579b05b7d0d24e1",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "56e826475959918bf784dd91dafd88041151385926ed24ae3435e2aea576b144"
        },
        {
          "side": "right",
          "sibling_hash_hex": "2d493660044d5a761b5a2c243c3b419b74007258ea85695737dc2988c50ccbb8"
        },
        {
          "side": "left",
          "sibling_hash_hex": "e8684e2524da4f7d35b9e2ffdaf5f5a208604a111f7bf0ab2ee730dff36c2d99"
        }
      ]
    },
    {
      "leaf_name": "delayed_closed_trades",
      "salt_hex": "ba6f6ed721b6c147259961a81273dcc7d63d508d1021d06bd5fbb31321ac0538",
      "payload": {
        "embargo_days": 7,
        "trades": [
          {
            "symbol": "NVDA",
            "asset_class": "equity",
            "side": "long",
            "entry_timestamp_utc": "2026-02-25T21:24:11Z",
            "exit_timestamp_utc": "2026-03-04T19:45:00Z",
            "return_pct": 9.84,
            "holding_hours": 166.3
          },
          {
            "symbol": "ES_FUT",
            "asset_class": "future",
            "side": "short",
            "entry_timestamp_utc": "2026-02-17T14:35:00Z",
            "exit_timestamp_utc": "2026-02-19T20:10:00Z",
            "return_pct": 2.41,
            "holding_hours": 53.6
          },
          {
            "symbol": "SAP",
            "asset_class": "equity",
            "side": "long",
            "entry_timestamp_utc": "2026-01-28T06:01:19Z",
            "exit_timestamp_utc": "2026-02-03T16:20:00Z",
            "return_pct": 6.12,
            "holding_hours": 154.3
          },
          {
            "symbol": "MSFT",
            "asset_class": "equity",
            "side": "long",
            "entry_timestamp_utc": "2026-03-11T15:10:44Z",
            "exit_timestamp_utc": "2026-03-13T19:55:00Z",
            "return_pct": -1.48,
            "holding_hours": 52.7
          }
        ]
      },
      "leaf_hash_hex": "2d493660044d5a761b5a2c243c3b419b74007258ea85695737dc2988c50ccbb8",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "5d067ecf2678095c312e8d0f72eb21db766c08a5b80fa7cb304ea7f826dfa78e"
        },
        {
          "side": "left",
          "sibling_hash_hex": "e8684e2524da4f7d35b9e2ffdaf5f5a208604a111f7bf0ab2ee730dff36c2d99"
        }
      ]
    }
  ],
  "undisclosed_leaf_hashes": {},
  "witness_attestations": [
    {
      "protocol": "tlsn-v0.1.0-alpha.15",
      "tls_version": "1.2",
      "defer_decryption_from_start": true,
      "notary_id": "notary-pse-eu",
      "server_sni": "api.ibkr.com",
      "sanitized_request_target": "/v1/api/portfolio/subaccounts?token=[REDACTED]",
      "redacted_headers": [
        "Authorization: [REDACTED]",
        "Cookie: [REDACTED]"
      ],
      "commitment_kind": "whole_body_sha256",
      "response_body_sha256": "3ac0eeec8bd51b95812b7c0e2fa1f486fa612095eef7707edbeedfc06c862557",
      "session_timestamp_utc": "2026-02-01T02:10:00Z",
      "signature_hex": "33b4b487c2a19549f70978320c3e29f91fe8107e9bd9836b6f95db0913cbada1b32f4b4c46e82cf578fffdc146562cc9ee75dfe01ae23cb53fcc9a35126d5609"
    },
    {
      "protocol": "tlsn-v0.1.0-alpha.15",
      "tls_version": "1.2",
      "defer_decryption_from_start": true,
      "notary_id": "notary-swiss-ch",
      "server_sni": "api.ibkr.com",
      "sanitized_request_target": "/v1/api/portfolio/subaccounts?token=[REDACTED]",
      "redacted_headers": [
        "Authorization: [REDACTED]",
        "Cookie: [REDACTED]"
      ],
      "commitment_kind": "whole_body_sha256",
      "response_body_sha256": "3ac0eeec8bd51b95812b7c0e2fa1f486fa612095eef7707edbeedfc06c862557",
      "session_timestamp_utc": "2026-02-01T02:10:00Z",
      "signature_hex": "c52e3740dd454ceade522bd86646cd1de81e6c080f8c448d1e2032e3507d40d8b30327804616770650ebe6e720debe564dd8ca6a0972d7c5f8b7a10f8c784a09"
    },
    {
      "protocol": "tlsn-v0.1.0-alpha.15",
      "tls_version": "1.2",
      "defer_decryption_from_start": true,
      "notary_id": "notary-nordic-is",
      "server_sni": "api.ibkr.com",
      "sanitized_request_target": "/v1/api/portfolio/subaccounts?token=[REDACTED]",
      "redacted_headers": [
        "Authorization: [REDACTED]",
        "Cookie: [REDACTED]"
      ],
      "commitment_kind": "whole_body_sha256",
      "response_body_sha256": "3ac0eeec8bd51b95812b7c0e2fa1f486fa612095eef7707edbeedfc06c862557",
      "session_timestamp_utc": "2026-02-01T02:10:00Z",
      "signature_hex": "b562945c152beb31f2029c3d2e234e3406c9d1ece8a478f2cd2420a11344b2956ab71165fcae58f261cafc07846ce57083200ccd6fbd1e05da401369057d4501"
    }
  ],
  "broker_native_signature": null,
  "prospective_chain_link": {
    "chain_id": "chain-meridian-2026",
    "sequence_number": 0,
    "prev_proof_hash": null,
    "blinded_account_tag": "17bad5d847162a4aae8550221f68eac6b563ac019290bfd83c9945dff4f8d462",
    "enrolled_at_utc": "2026-01-01T06:00:00Z",
    "period_start_utc": "2026-01-01T00:00:00Z",
    "period_end_utc": "2026-01-31T23:59:59Z",
    "issued_at_utc": "2026-02-01T02:15:00Z",
    "cadence_policy": {
      "expected_interval_seconds": 2764800,
      "grace_window_seconds": 172800
    },
    "beginning_index_value": 100.0,
    "ending_index_value": 112.4,
    "period_twr_decimal": 0.124
  },
  "retention_mode": "no_persistent_storage"
};

export const BUNDLE_INSTITUTIONAL_SEQ1: VerifyProofBundle = {
  "proof_id": "prf-inst-alpha-011",
  "issued_at_utc": "2026-03-01T01:45:00Z",
  "publisher_kid": "n170-pub-2026-q1",
  "publisher_public_key_hex": "519749abe49eaf67bff092d850c243df38be8697b84a2dde4b8fad150d08ff78",
  "broker_id": "interactive_brokers",
  "blinded_account_tag": "17bad5d847162a4aae8550221f68eac6b563ac019290bfd83c9945dff4f8d462",
  "account_scope": "all_enumerated_subaccounts",
  "provider_approval_state": "approved_live",
  "environment_tier": "live_production",
  "claimed_origin_assurance": "independently_witnessed_tls",
  "source_body_sha256": "fe208976cbf3916b39e2c331c607fcf56acaaa0329d145beeeb3c74dbfc6d189",
  "period_start_utc": "2026-01-31T23:59:59Z",
  "period_end_utc": "2026-02-28T23:59:59Z",
  "base_currency": "USD",
  "merkle_root": "435680f330a4cb3d3700246716e2dd6d365ba38355f38ef04ebeb27fd6b5577b",
  "signature_hex": "c2acbc9c05ac9eb8b672c11162c13ad58b7c437d9b515f273a3510ce4fa2ef5e143e40af67b0c1ba8cb27108b58bf315da5b19ea9f734bc5613a88de9b2c3205",
  "schema_version": "n170-verify-v3",
  "disclosed_leaves": [
    {
      "leaf_name": "core_metrics",
      "salt_hex": "e230069b9b9ddff6ba4b0dd9855ad825a627cf5e46450154f4a3c14fe38994e0",
      "payload": {
        "twr_decimal": 0.41877,
        "twr_pct": 41.877,
        "cagr_decimal": 3.048,
        "cagr_pct": 304.8,
        "xirr_decimal": 2.982,
        "annualized_volatility": 0.148,
        "smoothing_index_xi": 0.76,
        "lag1_autocorrelation": 0.24,
        "unsmoothed_volatility": 0.171,
        "unsmoothed_sharpe_ratio": 2.45,
        "sharpe_ratio": 2.84,
        "sortino_ratio": 4.12,
        "probabilistic_sharpe_ratio": 0.996,
        "psr_glm_unsmoothed": 0.984,
        "min_track_record_length_periods": 19.4,
        "psr_sample_eligible": true,
        "observation_count": 63,
        "psr_benchmark_sr": 0.0,
        "non_iid_caveat": "PSR accounts for skewness and excess kurtosis under stationary returns; GLM unsmoothing adjusts for first-order serial correlation, and unobserved multi-account selection trials cannot be ruled out without subaccount enumeration.",
        "max_drawdown_decimal": -0.0462,
        "max_drawdown_pct": -4.62,
        "skewness": 0.34,
        "excess_kurtosis": 0.82,
        "capital_bracket": "over_1m",
        "benchmark_symbol": "SPY",
        "benchmark_twr_decimal": 0.0612,
        "alpha_decimal": 0.35757,
        "indexed_curve": [
          {
            "timestamp_utc": "2026-01-01T00:00:00Z",
            "index_value": 100.0,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.0
          },
          {
            "timestamp_utc": "2026-01-09T21:00:00Z",
            "index_value": 104.2,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 101.1
          },
          {
            "timestamp_utc": "2026-01-19T21:00:00Z",
            "index_value": 102.8,
            "drawdown_pct": -1.34,
            "benchmark_index_value": 100.4
          },
          {
            "timestamp_utc": "2026-01-31T23:59:59Z",
            "index_value": 112.4,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 102.3
          },
          {
            "timestamp_utc": "2026-02-10T21:00:00Z",
            "index_value": 118.9,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 103.5
          },
          {
            "timestamp_utc": "2026-02-18T21:00:00Z",
            "index_value": 113.41,
            "drawdown_pct": -4.62,
            "benchmark_index_value": 101.9
          },
          {
            "timestamp_utc": "2026-02-28T23:59:59Z",
            "index_value": 126.45,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.1
          },
          {
            "timestamp_utc": "2026-03-09T21:00:00Z",
            "index_value": 131.8,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.8
          },
          {
            "timestamp_utc": "2026-03-17T21:00:00Z",
            "index_value": 129.4,
            "drawdown_pct": -1.82,
            "benchmark_index_value": 103.9
          },
          {
            "timestamp_utc": "2026-03-24T21:00:00Z",
            "index_value": 137.6,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 105.4
          },
          {
            "timestamp_utc": "2026-03-31T23:59:59Z",
            "index_value": 141.877,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 106.12
          }
        ],
        "methodology": "daily_flow_adjusted_twr_v3",
        "warnings": []
      },
      "leaf_hash_hex": "dda05462f693d364b4dd0719d854b1dcfd5660f8f9ace3810f3984b8c820c6ef",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "d1d55550a026dfd0927f64057c3f0eec25b4a4886c3426c7c4d67ab2d1e5fd7f"
        },
        {
          "side": "right",
          "sibling_hash_hex": "257d0824c1d7d07c0716b7284912c999f2e48f206c894ed8978cd1422e4f47aa"
        },
        {
          "side": "right",
          "sibling_hash_hex": "08483821c0822c43dc353b1c09da7f62907c9c90c081c9731bb77c7865f44278"
        }
      ]
    },
    {
      "leaf_name": "indexed_curve",
      "salt_hex": "53cd330b06f6a13735a742b999d50e40c280f6e420706102f6cf9526e6fcecad",
      "payload": {
        "base_index": 100.0,
        "points": [
          {
            "timestamp_utc": "2026-01-01T00:00:00Z",
            "index_value": 100.0,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.0
          },
          {
            "timestamp_utc": "2026-01-09T21:00:00Z",
            "index_value": 104.2,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 101.1
          },
          {
            "timestamp_utc": "2026-01-19T21:00:00Z",
            "index_value": 102.8,
            "drawdown_pct": -1.34,
            "benchmark_index_value": 100.4
          },
          {
            "timestamp_utc": "2026-01-31T23:59:59Z",
            "index_value": 112.4,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 102.3
          },
          {
            "timestamp_utc": "2026-02-10T21:00:00Z",
            "index_value": 118.9,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 103.5
          },
          {
            "timestamp_utc": "2026-02-18T21:00:00Z",
            "index_value": 113.41,
            "drawdown_pct": -4.62,
            "benchmark_index_value": 101.9
          },
          {
            "timestamp_utc": "2026-02-28T23:59:59Z",
            "index_value": 126.45,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.1
          },
          {
            "timestamp_utc": "2026-03-09T21:00:00Z",
            "index_value": 131.8,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.8
          },
          {
            "timestamp_utc": "2026-03-17T21:00:00Z",
            "index_value": 129.4,
            "drawdown_pct": -1.82,
            "benchmark_index_value": 103.9
          },
          {
            "timestamp_utc": "2026-03-24T21:00:00Z",
            "index_value": 137.6,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 105.4
          },
          {
            "timestamp_utc": "2026-03-31T23:59:59Z",
            "index_value": 141.877,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 106.12
          }
        ]
      },
      "leaf_hash_hex": "d1d55550a026dfd0927f64057c3f0eec25b4a4886c3426c7c4d67ab2d1e5fd7f",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "dda05462f693d364b4dd0719d854b1dcfd5660f8f9ace3810f3984b8c820c6ef"
        },
        {
          "side": "right",
          "sibling_hash_hex": "257d0824c1d7d07c0716b7284912c999f2e48f206c894ed8978cd1422e4f47aa"
        },
        {
          "side": "right",
          "sibling_hash_hex": "08483821c0822c43dc353b1c09da7f62907c9c90c081c9731bb77c7865f44278"
        }
      ]
    },
    {
      "leaf_name": "reconciliation",
      "salt_hex": "7bdc15c9be7cb44f9e93e60faa3b5018962717fe6f45981cd0c5dc4db3e01ebf",
      "payload": {
        "status": "reconciled_within_tolerance",
        "reference_provider": "eodhd",
        "ledger_completeness_ok": true,
        "missing_sections": [],
        "checks_evaluated": 184,
        "discrepancy_count": 0,
        "explained_convention_count": 2,
        "findings": [
          {
            "category": "daily_nav_continuity_identity",
            "outcome": "pass",
            "date_or_timestamp": "2026-01-01..2026-03-31",
            "symbol": "PORTFOLIO",
            "expected_value": 141.877,
            "observed_value": 141.878,
            "residual_bps": 0.07,
            "residual_base_currency": null,
            "math_identity": "NAV_t = NAV_{t-1} + Realized_t + Unrealized_t + NetFlows_t - Fees_t",
            "technical_explanation": "All 63 daily valuation intervals reconcile within 0.4 bps tolerance across all enumerated subaccounts.",
            "benign_causes_considered": [
              "Sub-penny multi-currency mark rounding"
            ]
          },
          {
            "category": "fx_t1_settlement_accrual",
            "outcome": "explained_convention",
            "date_or_timestamp": "2026-02-13T17:00:00Z",
            "symbol": "EUR.USD",
            "expected_value": 1.0418,
            "observed_value": 1.0421,
            "residual_bps": 2.88,
            "residual_base_currency": null,
            "math_identity": "Cash_Base(t) = Spot_FX(t) * Settled_Cash + Forward_Accrual(T+1)",
            "technical_explanation": "3 bps transient variance between trade-date and settlement-date FX translation resolved automatically on T+1 settlement.",
            "benign_causes_considered": [
              "WM/Refinitiv 16:00 London fix vs NY 17:00 broker FX mark",
              "T+1 spot FX value-date interest differential"
            ]
          },
          {
            "category": "dividend_ex_date_receivable",
            "outcome": "explained_convention",
            "date_or_timestamp": "2026-03-13T20:00:00Z",
            "symbol": "MSFT",
            "expected_value": 100.0,
            "observed_value": 100.0,
            "residual_bps": 0.0,
            "residual_base_currency": null,
            "math_identity": "NavExDate = SharePrice_Ex * Qty + DividendAccrualReceivable",
            "technical_explanation": "Ex-dividend price drop matched exact ChangeInDividendAccruals entry net of 15% treaty withholding.",
            "benign_causes_considered": [
              "Ex-date vs pay-date accrual accounting"
            ]
          },
          {
            "category": "eodhd_two_stage_fill_envelope",
            "outcome": "pass",
            "date_or_timestamp": "2026-03-24T14:32:18Z",
            "symbol": "NVDA",
            "expected_value": 138.4,
            "observed_value": 138.52,
            "residual_bps": 0.0,
            "residual_base_currency": null,
            "math_identity": "Low_1m(t) - SpreadTol <= FillPrice <= High_1m(t) + SpreadTol",
            "technical_explanation": "184 of 184 equity, ETF, and index futures executions fell strictly inside EODHD Stage-1 daily and Stage-2 1-minute market envelopes.",
            "benign_causes_considered": [
              "Odd-lot NBBO midpoint print",
              "Extended-hours auction cross"
            ]
          }
        ],
        "statistical_diagnostics": [
          {
            "metric_name": "Getmansky-Lo-Makarov Smoothing Index (xi)",
            "observed_value": 0.76,
            "interpretation": "Mild lag-1 return autocorrelation (rho_1 = 0.24) consistent with liquid swing overnight momentum exposure; PSR_GLM (98.4%) remains statistically significant after unsmoothing.",
            "caveats": [
              "GLM MA(2) unsmoothing assumes locally stationary return innovations.",
              "Reported alongside raw annualized volatility (14.8% raw vs 17.1% GLM unsmoothed)."
            ]
          },
          {
            "metric_name": "Execution Midpoint Slippage Asymmetry",
            "observed_value": -1.4,
            "interpretation": "Mean fill execution realized 1.4 bps adverse to 1-minute VWAP, consistent with realistic institutional limit/marketable-limit order routing.",
            "caveats": [
              "Does not accuse or clear off-exchange internalized flow advantages."
            ]
          }
        ],
        "summary_text": "All 5 canonical ledger sections verified across all enumerated subaccounts; 0 unexplained residuals across 63 trading days."
      },
      "leaf_hash_hex": "0ae575e1c4bc17588f22c34bb87445c24484508d42cc17d5e40f4c6fc4b46304",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "8fcfe10ab5b6ff8ca77d6a1bc5faac7aaa9ee1781bff132111ae73c8132836e7"
        },
        {
          "side": "left",
          "sibling_hash_hex": "fcd6bbd6d8c5a594f26ebe5c9ad23d666fc8efdf438ccfc53fb8cbb258234b0f"
        },
        {
          "side": "right",
          "sibling_hash_hex": "08483821c0822c43dc353b1c09da7f62907c9c90c081c9731bb77c7865f44278"
        }
      ]
    },
    {
      "leaf_name": "coaching_and_context",
      "salt_hex": "f1b15cec289c1990b1d527cb9f25309900f8851944cd598d73d72e9ad33ec022",
      "payload": {
        "cost_drag": {
          "commission_and_fee_drag_bps": 14.2,
          "margin_and_funding_drag_bps": 19.8,
          "fx_conversion_drag_bps": 4.1,
          "withholding_tax_drag_bps": 3.4,
          "total_friction_drag_bps": 41.5,
          "annualized_total_drag_bps": 168.0
        },
        "behaviour": {
          "sample_eligible": true,
          "min_trades_gate": 30,
          "observed_trades": 142,
          "observed_days": 63,
          "median_holding_hours": 54.6,
          "holding_horizon_label": "multi_day_institutional_swing",
          "win_rate": 0.563,
          "profit_factor": 2.18,
          "winner_vs_loser_hold_ratio": 2.38,
          "odean_pgr_plr_spread": -0.082,
          "post_drawdown_sizing_discipline_atr": 0.94,
          "atr_normalized": true,
          "return_concentration_top5_pct": 28.4,
          "actionable_improvements": [
            "Overnight margin financing accounts for 47.7% of total friction (19.8 bps in Q1); sweeping idle EUR/CHF balances via FX swap box reduces annualized drag by ~38 bps.",
            "Post-drawdown ATR risk discipline is exemplary (0.94x baseline ATR risk following the Feb -4.62% drawdown), avoiding convex drawdown escalation.",
            "Negative Odean PGR-PLR spread (-0.082) confirms winners are systematically held 2.38x longer than stopped-out losers."
          ]
        },
        "catalyst_regime_win_rate": 0.642,
        "quiet_regime_win_rate": 0.538,
        "event_window_share_pct": 24.6,
        "event_observations": [
          {
            "symbol": "NVDA",
            "trade_timestamp_utc": "2026-02-25T21:24:11Z",
            "earliest_public_utc": "2026-02-25T21:20:04Z",
            "confirmed_public_utc": "2026-02-25T21:21:30Z",
            "event_sources": [
              "SEC EDGAR Form 8-K",
              "BusinessWire Feed"
            ],
            "headline_or_event": "Q4 Fiscal 2026 Earnings Release & Data-Center Guidance",
            "alignment_class": "post_confirmed_catalyst",
            "timestamp_uncertainty_note": "Execution occurred +2m41s after confirmed EDGAR/wire dissemination [21:20:04Z, 21:21:30Z]."
          },
          {
            "symbol": "SAP",
            "trade_timestamp_utc": "2026-01-28T06:01:19Z",
            "earliest_public_utc": "2026-01-28T06:00:00Z",
            "confirmed_public_utc": "2026-01-28T06:03:12Z",
            "event_sources": [
              "EQS Ad-Hoc Disclosure",
              "Consolidated News Aggregator"
            ],
            "headline_or_event": "Cloud Backlog Acceleration & FY26 Operating Profit Outlook",
            "alignment_class": "ambiguous_public_window",
            "timestamp_uncertainty_note": "Trade falls inside I_e = [06:00:00Z, 06:03:12Z] due to ~3m aggregator indexing lag behind primary EQS wire."
          },
          {
            "symbol": "MSFT",
            "trade_timestamp_utc": "2026-03-11T15:10:44Z",
            "earliest_public_utc": null,
            "confirmed_public_utc": null,
            "event_sources": [
              "EODHD Corporate Calendar"
            ],
            "headline_or_event": "No scheduled macro or issuer-specific catalyst within +-24h",
            "alignment_class": "quiet_non_catalyst_regime",
            "timestamp_uncertainty_note": "Classified as quiet regime liquidity execution."
          }
        ],
        "llm_narrative_used": false,
        "llm_model_id": null,
        "style_summary": "Multi-day liquid equity & index-futures swing strategy with disciplined ATR volatility targeting and low disposition bias.",
        "coaching_takeaways": [
          "Positive post-catalyst drift capture (64.2% win rate in confirmed post-release windows vs 53.8% in quiet regimes).",
          "Top-5 winners contribute 28.4% of cumulative TWR \u2014 well-diversified across 142 closed round-trips."
        ],
        "uncertainty_disclosures": [
          "Public news wire timestamps carry +-30s to +-180s ingestion latency across secondary aggregators; catalyst intervals I_e = [t_earliest, t_confirmed] are descriptive context and never imply non-public information."
        ]
      },
      "leaf_hash_hex": "8fcfe10ab5b6ff8ca77d6a1bc5faac7aaa9ee1781bff132111ae73c8132836e7",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "0ae575e1c4bc17588f22c34bb87445c24484508d42cc17d5e40f4c6fc4b46304"
        },
        {
          "side": "left",
          "sibling_hash_hex": "fcd6bbd6d8c5a594f26ebe5c9ad23d666fc8efdf438ccfc53fb8cbb258234b0f"
        },
        {
          "side": "right",
          "sibling_hash_hex": "08483821c0822c43dc353b1c09da7f62907c9c90c081c9731bb77c7865f44278"
        }
      ]
    },
    {
      "leaf_name": "capital_bracket",
      "salt_hex": "65f50dca9a3c82c654d84bdcf65bb3cf6f1cf892e9534004a1b2a3de62c366ac",
      "payload": {
        "capital_bracket": "over_1m",
        "valuation_currency": "USD"
      },
      "leaf_hash_hex": "411ebb4c2ca01af67077099e49806516c3b3e3432d2027ac0e456df46b7a68cc",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "702cdb6b1761d14c4223bd68d60aa7cc07d7ebc07c8b3b100898bbbbc3aed64d"
        },
        {
          "side": "right",
          "sibling_hash_hex": "9b6c0e4535a826b3edeed361c0c0ae32aab500b34310f7c077586476d8f090bd"
        },
        {
          "side": "left",
          "sibling_hash_hex": "1050d4e038b3743718494fd3f6241e82168bd7e72627d089f731d31351983c21"
        }
      ]
    },
    {
      "leaf_name": "benchmark_alpha",
      "salt_hex": "d82f6a8985288bb5b7088c59854cbf0a07291a232e6fd6fd0b23d43ec00fb288",
      "payload": {
        "benchmark_symbol": "SPY",
        "benchmark_twr_decimal": 0.0612,
        "alpha_decimal": 0.35757,
        "information_ratio": 2.31,
        "beta": 0.42
      },
      "leaf_hash_hex": "702cdb6b1761d14c4223bd68d60aa7cc07d7ebc07c8b3b100898bbbbc3aed64d",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "411ebb4c2ca01af67077099e49806516c3b3e3432d2027ac0e456df46b7a68cc"
        },
        {
          "side": "right",
          "sibling_hash_hex": "9b6c0e4535a826b3edeed361c0c0ae32aab500b34310f7c077586476d8f090bd"
        },
        {
          "side": "left",
          "sibling_hash_hex": "1050d4e038b3743718494fd3f6241e82168bd7e72627d089f731d31351983c21"
        }
      ]
    },
    {
      "leaf_name": "delayed_closed_trades",
      "salt_hex": "c4e18908537133231c2e90fc52517652337ad5478682ef9990fe042418b7c357",
      "payload": {
        "embargo_days": 7,
        "trades": [
          {
            "symbol": "NVDA",
            "asset_class": "equity",
            "side": "long",
            "entry_timestamp_utc": "2026-02-25T21:24:11Z",
            "exit_timestamp_utc": "2026-03-04T19:45:00Z",
            "return_pct": 9.84,
            "holding_hours": 166.3
          },
          {
            "symbol": "ES_FUT",
            "asset_class": "future",
            "side": "short",
            "entry_timestamp_utc": "2026-02-17T14:35:00Z",
            "exit_timestamp_utc": "2026-02-19T20:10:00Z",
            "return_pct": 2.41,
            "holding_hours": 53.6
          },
          {
            "symbol": "SAP",
            "asset_class": "equity",
            "side": "long",
            "entry_timestamp_utc": "2026-01-28T06:01:19Z",
            "exit_timestamp_utc": "2026-02-03T16:20:00Z",
            "return_pct": 6.12,
            "holding_hours": 154.3
          },
          {
            "symbol": "MSFT",
            "asset_class": "equity",
            "side": "long",
            "entry_timestamp_utc": "2026-03-11T15:10:44Z",
            "exit_timestamp_utc": "2026-03-13T19:55:00Z",
            "return_pct": -1.48,
            "holding_hours": 52.7
          }
        ]
      },
      "leaf_hash_hex": "9b6c0e4535a826b3edeed361c0c0ae32aab500b34310f7c077586476d8f090bd",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "cdc0bef03ce729b0ab06fd5483cf35e3205be16555ac2374e446d5a6240bd04f"
        },
        {
          "side": "left",
          "sibling_hash_hex": "1050d4e038b3743718494fd3f6241e82168bd7e72627d089f731d31351983c21"
        }
      ]
    }
  ],
  "undisclosed_leaf_hashes": {},
  "witness_attestations": [
    {
      "protocol": "tlsn-v0.1.0-alpha.15",
      "tls_version": "1.2",
      "defer_decryption_from_start": true,
      "notary_id": "notary-pse-eu",
      "server_sni": "api.ibkr.com",
      "sanitized_request_target": "/v1/api/portfolio/subaccounts?token=[REDACTED]",
      "redacted_headers": [
        "Authorization: [REDACTED]",
        "Cookie: [REDACTED]"
      ],
      "commitment_kind": "whole_body_sha256",
      "response_body_sha256": "fe208976cbf3916b39e2c331c607fcf56acaaa0329d145beeeb3c74dbfc6d189",
      "session_timestamp_utc": "2026-03-01T01:40:00Z",
      "signature_hex": "ec27caaa722da39274f12800d0004a92e03daba82b0c6a484d96b84137bde0698468ac07efd505edbcab9b86f58de4a9f96f3147393a5ae9f9b201097a689500"
    },
    {
      "protocol": "tlsn-v0.1.0-alpha.15",
      "tls_version": "1.2",
      "defer_decryption_from_start": true,
      "notary_id": "notary-swiss-ch",
      "server_sni": "api.ibkr.com",
      "sanitized_request_target": "/v1/api/portfolio/subaccounts?token=[REDACTED]",
      "redacted_headers": [
        "Authorization: [REDACTED]",
        "Cookie: [REDACTED]"
      ],
      "commitment_kind": "whole_body_sha256",
      "response_body_sha256": "fe208976cbf3916b39e2c331c607fcf56acaaa0329d145beeeb3c74dbfc6d189",
      "session_timestamp_utc": "2026-03-01T01:40:00Z",
      "signature_hex": "4b6599acc2d373c7808969cd3ed48684fd897630b1a45be842adfa41e9a28028468a8fe77533f53f1439b053a33dac9a8923c03175ab12b9c4c4e45852375f09"
    },
    {
      "protocol": "tlsn-v0.1.0-alpha.15",
      "tls_version": "1.2",
      "defer_decryption_from_start": true,
      "notary_id": "notary-nordic-is",
      "server_sni": "api.ibkr.com",
      "sanitized_request_target": "/v1/api/portfolio/subaccounts?token=[REDACTED]",
      "redacted_headers": [
        "Authorization: [REDACTED]",
        "Cookie: [REDACTED]"
      ],
      "commitment_kind": "whole_body_sha256",
      "response_body_sha256": "fe208976cbf3916b39e2c331c607fcf56acaaa0329d145beeeb3c74dbfc6d189",
      "session_timestamp_utc": "2026-03-01T01:40:00Z",
      "signature_hex": "56689bdc166b22741bb7b92167ed5ba86de69225e7b8c4a1c04b1197028878bb5db66b474465a123f724d018489e72981029ffd97b8032d7d66c99cf1cca5009"
    }
  ],
  "broker_native_signature": null,
  "prospective_chain_link": {
    "chain_id": "chain-meridian-2026",
    "sequence_number": 1,
    "prev_proof_hash": "79ae579aaccc4059ac55cec5b9e13af9dc63afcc4f4de2558a6b2d3abd4aec82",
    "blinded_account_tag": "17bad5d847162a4aae8550221f68eac6b563ac019290bfd83c9945dff4f8d462",
    "enrolled_at_utc": "2026-01-01T06:00:00Z",
    "period_start_utc": "2026-01-31T23:59:59Z",
    "period_end_utc": "2026-02-28T23:59:59Z",
    "issued_at_utc": "2026-03-01T01:45:00Z",
    "cadence_policy": {
      "expected_interval_seconds": 2764800,
      "grace_window_seconds": 172800
    },
    "beginning_index_value": 112.4,
    "ending_index_value": 126.45,
    "period_twr_decimal": 0.125
  },
  "retention_mode": "no_persistent_storage"
};

export const BUNDLE_INSTITUTIONAL_FUND: VerifyProofBundle = {
  "proof_id": "prf-inst-alpha-012",
  "issued_at_utc": "2026-04-01T03:12:00Z",
  "publisher_kid": "n170-pub-2026-q1",
  "publisher_public_key_hex": "519749abe49eaf67bff092d850c243df38be8697b84a2dde4b8fad150d08ff78",
  "broker_id": "interactive_brokers",
  "blinded_account_tag": "17bad5d847162a4aae8550221f68eac6b563ac019290bfd83c9945dff4f8d462",
  "account_scope": "all_enumerated_subaccounts",
  "provider_approval_state": "approved_live",
  "environment_tier": "live_production",
  "claimed_origin_assurance": "independently_witnessed_tls",
  "source_body_sha256": "43fcd398b30e7c195b54fb744da346a8ed0c1ab3ede2e0b348e06dace49dc34e",
  "period_start_utc": "2026-01-01T00:00:00Z",
  "period_end_utc": "2026-03-31T23:59:59Z",
  "base_currency": "USD",
  "merkle_root": "23ebb56a58ea11667c51583170493891025e249c95dce67eec5a08fe87277df1",
  "signature_hex": "307bb8cde79eca8c2d23298c5c7144febe3d2280100da41c291060e25fffb1178062a2106c25c75fb46cb0878f12b83ab25bed432dcdbcbbded30007ff949508",
  "schema_version": "n170-verify-v3",
  "disclosed_leaves": [
    {
      "leaf_name": "core_metrics",
      "salt_hex": "ffec8af08edbfd941213b7a14c78639317dde0232509740ef92eb7c3c3dff58e",
      "payload": {
        "twr_decimal": 0.41877,
        "twr_pct": 41.877,
        "cagr_decimal": 3.048,
        "cagr_pct": 304.8,
        "xirr_decimal": 2.982,
        "annualized_volatility": 0.148,
        "smoothing_index_xi": 0.76,
        "lag1_autocorrelation": 0.24,
        "unsmoothed_volatility": 0.171,
        "unsmoothed_sharpe_ratio": 2.45,
        "sharpe_ratio": 2.84,
        "sortino_ratio": 4.12,
        "probabilistic_sharpe_ratio": 0.996,
        "psr_glm_unsmoothed": 0.984,
        "min_track_record_length_periods": 19.4,
        "psr_sample_eligible": true,
        "observation_count": 63,
        "psr_benchmark_sr": 0.0,
        "non_iid_caveat": "PSR accounts for skewness and excess kurtosis under stationary returns; GLM unsmoothing adjusts for first-order serial correlation, and unobserved multi-account selection trials cannot be ruled out without subaccount enumeration.",
        "max_drawdown_decimal": -0.0462,
        "max_drawdown_pct": -4.62,
        "skewness": 0.34,
        "excess_kurtosis": 0.82,
        "capital_bracket": "over_1m",
        "benchmark_symbol": "SPY",
        "benchmark_twr_decimal": 0.0612,
        "alpha_decimal": 0.35757,
        "indexed_curve": [
          {
            "timestamp_utc": "2026-01-01T00:00:00Z",
            "index_value": 100.0,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.0
          },
          {
            "timestamp_utc": "2026-01-09T21:00:00Z",
            "index_value": 104.2,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 101.1
          },
          {
            "timestamp_utc": "2026-01-19T21:00:00Z",
            "index_value": 102.8,
            "drawdown_pct": -1.34,
            "benchmark_index_value": 100.4
          },
          {
            "timestamp_utc": "2026-01-31T23:59:59Z",
            "index_value": 112.4,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 102.3
          },
          {
            "timestamp_utc": "2026-02-10T21:00:00Z",
            "index_value": 118.9,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 103.5
          },
          {
            "timestamp_utc": "2026-02-18T21:00:00Z",
            "index_value": 113.41,
            "drawdown_pct": -4.62,
            "benchmark_index_value": 101.9
          },
          {
            "timestamp_utc": "2026-02-28T23:59:59Z",
            "index_value": 126.45,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.1
          },
          {
            "timestamp_utc": "2026-03-09T21:00:00Z",
            "index_value": 131.8,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.8
          },
          {
            "timestamp_utc": "2026-03-17T21:00:00Z",
            "index_value": 129.4,
            "drawdown_pct": -1.82,
            "benchmark_index_value": 103.9
          },
          {
            "timestamp_utc": "2026-03-24T21:00:00Z",
            "index_value": 137.6,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 105.4
          },
          {
            "timestamp_utc": "2026-03-31T23:59:59Z",
            "index_value": 141.877,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 106.12
          }
        ],
        "methodology": "daily_flow_adjusted_twr_v3",
        "warnings": []
      },
      "leaf_hash_hex": "279d10afc63831de8af49ce0d38fa820d866e8ef65ef4566f9f0fff764cb0147",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "5dea33f2c9826fe87a1acd748412f1c1107193e2c851b345d3e75895784cba19"
        },
        {
          "side": "right",
          "sibling_hash_hex": "f1359c4f0eb5b7bafe37c39c47e852202fde5eeebc56fb6d31cecc49f7f48268"
        },
        {
          "side": "right",
          "sibling_hash_hex": "9218d3922f156198b36c21573195bd18c1f407464e089ef6d49b50c6ce03a142"
        }
      ]
    },
    {
      "leaf_name": "indexed_curve",
      "salt_hex": "b8ed444993e6cdffc501a44eb44704be3749f41231f3a3328912b151226fe090",
      "payload": {
        "base_index": 100.0,
        "points": [
          {
            "timestamp_utc": "2026-01-01T00:00:00Z",
            "index_value": 100.0,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.0
          },
          {
            "timestamp_utc": "2026-01-09T21:00:00Z",
            "index_value": 104.2,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 101.1
          },
          {
            "timestamp_utc": "2026-01-19T21:00:00Z",
            "index_value": 102.8,
            "drawdown_pct": -1.34,
            "benchmark_index_value": 100.4
          },
          {
            "timestamp_utc": "2026-01-31T23:59:59Z",
            "index_value": 112.4,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 102.3
          },
          {
            "timestamp_utc": "2026-02-10T21:00:00Z",
            "index_value": 118.9,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 103.5
          },
          {
            "timestamp_utc": "2026-02-18T21:00:00Z",
            "index_value": 113.41,
            "drawdown_pct": -4.62,
            "benchmark_index_value": 101.9
          },
          {
            "timestamp_utc": "2026-02-28T23:59:59Z",
            "index_value": 126.45,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.1
          },
          {
            "timestamp_utc": "2026-03-09T21:00:00Z",
            "index_value": 131.8,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.8
          },
          {
            "timestamp_utc": "2026-03-17T21:00:00Z",
            "index_value": 129.4,
            "drawdown_pct": -1.82,
            "benchmark_index_value": 103.9
          },
          {
            "timestamp_utc": "2026-03-24T21:00:00Z",
            "index_value": 137.6,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 105.4
          },
          {
            "timestamp_utc": "2026-03-31T23:59:59Z",
            "index_value": 141.877,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 106.12
          }
        ]
      },
      "leaf_hash_hex": "5dea33f2c9826fe87a1acd748412f1c1107193e2c851b345d3e75895784cba19",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "279d10afc63831de8af49ce0d38fa820d866e8ef65ef4566f9f0fff764cb0147"
        },
        {
          "side": "right",
          "sibling_hash_hex": "f1359c4f0eb5b7bafe37c39c47e852202fde5eeebc56fb6d31cecc49f7f48268"
        },
        {
          "side": "right",
          "sibling_hash_hex": "9218d3922f156198b36c21573195bd18c1f407464e089ef6d49b50c6ce03a142"
        }
      ]
    },
    {
      "leaf_name": "reconciliation",
      "salt_hex": "047ded1311ffb4b933501ca9c2c3f01bd87d4d9e2f88939a76361536fa319daa",
      "payload": {
        "status": "reconciled_within_tolerance",
        "reference_provider": "eodhd",
        "ledger_completeness_ok": true,
        "missing_sections": [],
        "checks_evaluated": 184,
        "discrepancy_count": 0,
        "explained_convention_count": 2,
        "findings": [
          {
            "category": "daily_nav_continuity_identity",
            "outcome": "pass",
            "date_or_timestamp": "2026-01-01..2026-03-31",
            "symbol": "PORTFOLIO",
            "expected_value": 141.877,
            "observed_value": 141.878,
            "residual_bps": 0.07,
            "residual_base_currency": null,
            "math_identity": "NAV_t = NAV_{t-1} + Realized_t + Unrealized_t + NetFlows_t - Fees_t",
            "technical_explanation": "All 63 daily valuation intervals reconcile within 0.4 bps tolerance across all enumerated subaccounts.",
            "benign_causes_considered": [
              "Sub-penny multi-currency mark rounding"
            ]
          },
          {
            "category": "fx_t1_settlement_accrual",
            "outcome": "explained_convention",
            "date_or_timestamp": "2026-02-13T17:00:00Z",
            "symbol": "EUR.USD",
            "expected_value": 1.0418,
            "observed_value": 1.0421,
            "residual_bps": 2.88,
            "residual_base_currency": null,
            "math_identity": "Cash_Base(t) = Spot_FX(t) * Settled_Cash + Forward_Accrual(T+1)",
            "technical_explanation": "3 bps transient variance between trade-date and settlement-date FX translation resolved automatically on T+1 settlement.",
            "benign_causes_considered": [
              "WM/Refinitiv 16:00 London fix vs NY 17:00 broker FX mark",
              "T+1 spot FX value-date interest differential"
            ]
          },
          {
            "category": "dividend_ex_date_receivable",
            "outcome": "explained_convention",
            "date_or_timestamp": "2026-03-13T20:00:00Z",
            "symbol": "MSFT",
            "expected_value": 100.0,
            "observed_value": 100.0,
            "residual_bps": 0.0,
            "residual_base_currency": null,
            "math_identity": "NavExDate = SharePrice_Ex * Qty + DividendAccrualReceivable",
            "technical_explanation": "Ex-dividend price drop matched exact ChangeInDividendAccruals entry net of 15% treaty withholding.",
            "benign_causes_considered": [
              "Ex-date vs pay-date accrual accounting"
            ]
          },
          {
            "category": "eodhd_two_stage_fill_envelope",
            "outcome": "pass",
            "date_or_timestamp": "2026-03-24T14:32:18Z",
            "symbol": "NVDA",
            "expected_value": 138.4,
            "observed_value": 138.52,
            "residual_bps": 0.0,
            "residual_base_currency": null,
            "math_identity": "Low_1m(t) - SpreadTol <= FillPrice <= High_1m(t) + SpreadTol",
            "technical_explanation": "184 of 184 equity, ETF, and index futures executions fell strictly inside EODHD Stage-1 daily and Stage-2 1-minute market envelopes.",
            "benign_causes_considered": [
              "Odd-lot NBBO midpoint print",
              "Extended-hours auction cross"
            ]
          }
        ],
        "statistical_diagnostics": [
          {
            "metric_name": "Getmansky-Lo-Makarov Smoothing Index (xi)",
            "observed_value": 0.76,
            "interpretation": "Mild lag-1 return autocorrelation (rho_1 = 0.24) consistent with liquid swing overnight momentum exposure; PSR_GLM (98.4%) remains statistically significant after unsmoothing.",
            "caveats": [
              "GLM MA(2) unsmoothing assumes locally stationary return innovations.",
              "Reported alongside raw annualized volatility (14.8% raw vs 17.1% GLM unsmoothed)."
            ]
          },
          {
            "metric_name": "Execution Midpoint Slippage Asymmetry",
            "observed_value": -1.4,
            "interpretation": "Mean fill execution realized 1.4 bps adverse to 1-minute VWAP, consistent with realistic institutional limit/marketable-limit order routing.",
            "caveats": [
              "Does not accuse or clear off-exchange internalized flow advantages."
            ]
          }
        ],
        "summary_text": "All 5 canonical ledger sections verified across all enumerated subaccounts; 0 unexplained residuals across 63 trading days."
      },
      "leaf_hash_hex": "c449e554c5a888f2741c933205c46acfa7564f871b5c27d4eae4b9afa8a1785e",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "569b20c7c7072afa569867b786792e2f814a9df7d0222f62a5cc328d8226bf38"
        },
        {
          "side": "left",
          "sibling_hash_hex": "5ee712e256684c8b0ca4addcf716f4a7f59cb3c3e4886bc7a58d2cf1c07d6374"
        },
        {
          "side": "right",
          "sibling_hash_hex": "9218d3922f156198b36c21573195bd18c1f407464e089ef6d49b50c6ce03a142"
        }
      ]
    },
    {
      "leaf_name": "coaching_and_context",
      "salt_hex": "35e5e61e39881e9c5e83aa92e057858fdac74f3436da9c3472ce58d4272ecf81",
      "payload": {
        "cost_drag": {
          "commission_and_fee_drag_bps": 14.2,
          "margin_and_funding_drag_bps": 19.8,
          "fx_conversion_drag_bps": 4.1,
          "withholding_tax_drag_bps": 3.4,
          "total_friction_drag_bps": 41.5,
          "annualized_total_drag_bps": 168.0
        },
        "behaviour": {
          "sample_eligible": true,
          "min_trades_gate": 30,
          "observed_trades": 142,
          "observed_days": 63,
          "median_holding_hours": 54.6,
          "holding_horizon_label": "multi_day_institutional_swing",
          "win_rate": 0.563,
          "profit_factor": 2.18,
          "winner_vs_loser_hold_ratio": 2.38,
          "odean_pgr_plr_spread": -0.082,
          "post_drawdown_sizing_discipline_atr": 0.94,
          "atr_normalized": true,
          "return_concentration_top5_pct": 28.4,
          "actionable_improvements": [
            "Overnight margin financing accounts for 47.7% of total friction (19.8 bps in Q1); sweeping idle EUR/CHF balances via FX swap box reduces annualized drag by ~38 bps.",
            "Post-drawdown ATR risk discipline is exemplary (0.94x baseline ATR risk following the Feb -4.62% drawdown), avoiding convex drawdown escalation.",
            "Negative Odean PGR-PLR spread (-0.082) confirms winners are systematically held 2.38x longer than stopped-out losers."
          ]
        },
        "catalyst_regime_win_rate": 0.642,
        "quiet_regime_win_rate": 0.538,
        "event_window_share_pct": 24.6,
        "event_observations": [
          {
            "symbol": "NVDA",
            "trade_timestamp_utc": "2026-02-25T21:24:11Z",
            "earliest_public_utc": "2026-02-25T21:20:04Z",
            "confirmed_public_utc": "2026-02-25T21:21:30Z",
            "event_sources": [
              "SEC EDGAR Form 8-K",
              "BusinessWire Feed"
            ],
            "headline_or_event": "Q4 Fiscal 2026 Earnings Release & Data-Center Guidance",
            "alignment_class": "post_confirmed_catalyst",
            "timestamp_uncertainty_note": "Execution occurred +2m41s after confirmed EDGAR/wire dissemination [21:20:04Z, 21:21:30Z]."
          },
          {
            "symbol": "SAP",
            "trade_timestamp_utc": "2026-01-28T06:01:19Z",
            "earliest_public_utc": "2026-01-28T06:00:00Z",
            "confirmed_public_utc": "2026-01-28T06:03:12Z",
            "event_sources": [
              "EQS Ad-Hoc Disclosure",
              "Consolidated News Aggregator"
            ],
            "headline_or_event": "Cloud Backlog Acceleration & FY26 Operating Profit Outlook",
            "alignment_class": "ambiguous_public_window",
            "timestamp_uncertainty_note": "Trade falls inside I_e = [06:00:00Z, 06:03:12Z] due to ~3m aggregator indexing lag behind primary EQS wire."
          },
          {
            "symbol": "MSFT",
            "trade_timestamp_utc": "2026-03-11T15:10:44Z",
            "earliest_public_utc": null,
            "confirmed_public_utc": null,
            "event_sources": [
              "EODHD Corporate Calendar"
            ],
            "headline_or_event": "No scheduled macro or issuer-specific catalyst within +-24h",
            "alignment_class": "quiet_non_catalyst_regime",
            "timestamp_uncertainty_note": "Classified as quiet regime liquidity execution."
          }
        ],
        "llm_narrative_used": false,
        "llm_model_id": null,
        "style_summary": "Multi-day liquid equity & index-futures swing strategy with disciplined ATR volatility targeting and low disposition bias.",
        "coaching_takeaways": [
          "Positive post-catalyst drift capture (64.2% win rate in confirmed post-release windows vs 53.8% in quiet regimes).",
          "Top-5 winners contribute 28.4% of cumulative TWR \u2014 well-diversified across 142 closed round-trips."
        ],
        "uncertainty_disclosures": [
          "Public news wire timestamps carry +-30s to +-180s ingestion latency across secondary aggregators; catalyst intervals I_e = [t_earliest, t_confirmed] are descriptive context and never imply non-public information."
        ]
      },
      "leaf_hash_hex": "569b20c7c7072afa569867b786792e2f814a9df7d0222f62a5cc328d8226bf38",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "c449e554c5a888f2741c933205c46acfa7564f871b5c27d4eae4b9afa8a1785e"
        },
        {
          "side": "left",
          "sibling_hash_hex": "5ee712e256684c8b0ca4addcf716f4a7f59cb3c3e4886bc7a58d2cf1c07d6374"
        },
        {
          "side": "right",
          "sibling_hash_hex": "9218d3922f156198b36c21573195bd18c1f407464e089ef6d49b50c6ce03a142"
        }
      ]
    },
    {
      "leaf_name": "capital_bracket",
      "salt_hex": "d353f93efd1830ff0b50b67793c1a374c7c18366ba7114c73be7b93787613363",
      "payload": {
        "capital_bracket": "over_1m",
        "valuation_currency": "USD"
      },
      "leaf_hash_hex": "f8afabbcd4854379f0ea232270b0d685dde5aaa44529269a21823b0b0f91dbd4",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "514229de63465454a1d4d2cbece712617ff460f15f724847908add6c70f4f010"
        },
        {
          "side": "right",
          "sibling_hash_hex": "f8dbc38253a3c9053bb233cce2705fc2c9668d6ba112d4a314c77198d389e0a6"
        },
        {
          "side": "left",
          "sibling_hash_hex": "212f62bbb4ea0a5f9d109c2fb6c16b3538bdbf9a2826ec94569b25c04e84b8b1"
        }
      ]
    },
    {
      "leaf_name": "benchmark_alpha",
      "salt_hex": "10c52d8b0fc2931c58f6925a822d721aa397a825c9eaaa2888ee71c0b14e7949",
      "payload": {
        "benchmark_symbol": "SPY",
        "benchmark_twr_decimal": 0.0612,
        "alpha_decimal": 0.35757,
        "information_ratio": 2.31,
        "beta": 0.42
      },
      "leaf_hash_hex": "514229de63465454a1d4d2cbece712617ff460f15f724847908add6c70f4f010",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "f8afabbcd4854379f0ea232270b0d685dde5aaa44529269a21823b0b0f91dbd4"
        },
        {
          "side": "right",
          "sibling_hash_hex": "f8dbc38253a3c9053bb233cce2705fc2c9668d6ba112d4a314c77198d389e0a6"
        },
        {
          "side": "left",
          "sibling_hash_hex": "212f62bbb4ea0a5f9d109c2fb6c16b3538bdbf9a2826ec94569b25c04e84b8b1"
        }
      ]
    },
    {
      "leaf_name": "delayed_closed_trades",
      "salt_hex": "9aaeb900bd55eb16176b5ce04fa904bb4cf4ccf55d390749f9343b0bcee8c223",
      "payload": {
        "embargo_days": 7,
        "trades": [
          {
            "symbol": "NVDA",
            "asset_class": "equity",
            "side": "long",
            "entry_timestamp_utc": "2026-02-25T21:24:11Z",
            "exit_timestamp_utc": "2026-03-04T19:45:00Z",
            "return_pct": 9.84,
            "holding_hours": 166.3
          },
          {
            "symbol": "ES_FUT",
            "asset_class": "future",
            "side": "short",
            "entry_timestamp_utc": "2026-02-17T14:35:00Z",
            "exit_timestamp_utc": "2026-02-19T20:10:00Z",
            "return_pct": 2.41,
            "holding_hours": 53.6
          },
          {
            "symbol": "SAP",
            "asset_class": "equity",
            "side": "long",
            "entry_timestamp_utc": "2026-01-28T06:01:19Z",
            "exit_timestamp_utc": "2026-02-03T16:20:00Z",
            "return_pct": 6.12,
            "holding_hours": 154.3
          },
          {
            "symbol": "MSFT",
            "asset_class": "equity",
            "side": "long",
            "entry_timestamp_utc": "2026-03-11T15:10:44Z",
            "exit_timestamp_utc": "2026-03-13T19:55:00Z",
            "return_pct": -1.48,
            "holding_hours": 52.7
          }
        ]
      },
      "leaf_hash_hex": "f8dbc38253a3c9053bb233cce2705fc2c9668d6ba112d4a314c77198d389e0a6",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "ad989049cec786948518f93566d502601b4393267291e99f173c330d95b29d3f"
        },
        {
          "side": "left",
          "sibling_hash_hex": "212f62bbb4ea0a5f9d109c2fb6c16b3538bdbf9a2826ec94569b25c04e84b8b1"
        }
      ]
    }
  ],
  "undisclosed_leaf_hashes": {},
  "witness_attestations": [
    {
      "protocol": "tlsn-v0.1.0-alpha.15",
      "tls_version": "1.2",
      "defer_decryption_from_start": true,
      "notary_id": "notary-pse-eu",
      "server_sni": "api.ibkr.com",
      "sanitized_request_target": "/v1/api/portfolio/subaccounts?token=[REDACTED]",
      "redacted_headers": [
        "Authorization: [REDACTED]",
        "Cookie: [REDACTED]"
      ],
      "commitment_kind": "whole_body_sha256",
      "response_body_sha256": "43fcd398b30e7c195b54fb744da346a8ed0c1ab3ede2e0b348e06dace49dc34e",
      "session_timestamp_utc": "2026-04-01T03:08:00Z",
      "signature_hex": "093e1edf866d88c5d061350d634bc648ef44ac1fbf711eedfedfec3ebefb6a99cbbebbad2ce0775fa049d75c137a155050e676bb6793285cee3cd6c489b83d01"
    },
    {
      "protocol": "tlsn-v0.1.0-alpha.15",
      "tls_version": "1.2",
      "defer_decryption_from_start": true,
      "notary_id": "notary-swiss-ch",
      "server_sni": "api.ibkr.com",
      "sanitized_request_target": "/v1/api/portfolio/subaccounts?token=[REDACTED]",
      "redacted_headers": [
        "Authorization: [REDACTED]",
        "Cookie: [REDACTED]"
      ],
      "commitment_kind": "whole_body_sha256",
      "response_body_sha256": "43fcd398b30e7c195b54fb744da346a8ed0c1ab3ede2e0b348e06dace49dc34e",
      "session_timestamp_utc": "2026-04-01T03:08:00Z",
      "signature_hex": "51942376cf4dfb3fa1e644390501625a8c487f9237a6b2b3b58dff557ba0e8d287b578493981d0ed4e73ca0a612d5f717178a0bacf9817341b0d820e3804c000"
    },
    {
      "protocol": "tlsn-v0.1.0-alpha.15",
      "tls_version": "1.2",
      "defer_decryption_from_start": true,
      "notary_id": "notary-nordic-is",
      "server_sni": "api.ibkr.com",
      "sanitized_request_target": "/v1/api/portfolio/subaccounts?token=[REDACTED]",
      "redacted_headers": [
        "Authorization: [REDACTED]",
        "Cookie: [REDACTED]"
      ],
      "commitment_kind": "whole_body_sha256",
      "response_body_sha256": "43fcd398b30e7c195b54fb744da346a8ed0c1ab3ede2e0b348e06dace49dc34e",
      "session_timestamp_utc": "2026-04-01T03:08:00Z",
      "signature_hex": "c41315d58e5a34ea2125a2ae098f6652f015706e58146cd07e8c1182898a7d11aac386b27c8fee6573a99efc61fe3508fdbd529d307cc151e00834c4a58f0404"
    }
  ],
  "broker_native_signature": null,
  "prospective_chain_link": {
    "chain_id": "chain-meridian-2026",
    "sequence_number": 2,
    "prev_proof_hash": "a0b2ea961a90110ee5d8125fa5168a7bc05bb961f2feca91e3877b87ae7ee6ce",
    "blinded_account_tag": "17bad5d847162a4aae8550221f68eac6b563ac019290bfd83c9945dff4f8d462",
    "enrolled_at_utc": "2026-01-01T06:00:00Z",
    "period_start_utc": "2026-02-28T23:59:59Z",
    "period_end_utc": "2026-03-31T23:59:59Z",
    "issued_at_utc": "2026-04-01T03:12:00Z",
    "cadence_policy": {
      "expected_interval_seconds": 2764800,
      "grace_window_seconds": 172800
    },
    "beginning_index_value": 126.45,
    "ending_index_value": 141.8769,
    "period_twr_decimal": 0.122
  },
  "retention_mode": "no_persistent_storage"
};

export const BUNDLE_DISCREPANCY_XRAY: VerifyProofBundle = {
  "proof_id": "prf-xray-residual-004",
  "issued_at_utc": "2026-04-01T04:02:00Z",
  "publisher_kid": "n170-pub-2026-q1",
  "publisher_public_key_hex": "519749abe49eaf67bff092d850c243df38be8697b84a2dde4b8fad150d08ff78",
  "broker_id": "interactive_brokers",
  "blinded_account_tag": "91e77e036a7f2848bf3eea81dc2a2aff5b781049b73ccc01c6f975c8b1cc957d",
  "account_scope": "single_account_survivorship_unverified",
  "provider_approval_state": "user_key_self_attested",
  "environment_tier": "live_production",
  "claimed_origin_assurance": "independently_witnessed_tls",
  "source_body_sha256": "310a1585bbda6bd6b44e1f2cd1f39485155aae06f8127566ba6ad6fb928300e7",
  "period_start_utc": "2026-03-02T00:00:00Z",
  "period_end_utc": "2026-03-31T23:59:59Z",
  "base_currency": "USD",
  "merkle_root": "1508815c69f0cd334e0a4a4c4811a704c76f54207086ed12c8d69339d944eff0",
  "signature_hex": "78f6c8fde1bba8187baaa2f9af1aabdd3d7bdebd8942ad72c43e655088d97ba347e440e4621bb393db0047fcc23e3f5b6fd1d8d815f622d6f92b41ca9ed9460c",
  "schema_version": "n170-verify-v3",
  "disclosed_leaves": [
    {
      "leaf_name": "core_metrics",
      "salt_hex": "af8a9f424d553a1d954720b1b336d067e24cc6eea746693b747a46b3a76e82e4",
      "payload": {
        "twr_decimal": 0.114,
        "twr_pct": 11.4,
        "cagr_decimal": 2.74,
        "cagr_pct": 274.0,
        "xirr_decimal": 2.61,
        "annualized_volatility": 0.264,
        "smoothing_index_xi": 0.92,
        "lag1_autocorrelation": 0.06,
        "unsmoothed_volatility": 0.278,
        "unsmoothed_sharpe_ratio": 2.01,
        "sharpe_ratio": 2.12,
        "sortino_ratio": 2.95,
        "probabilistic_sharpe_ratio": null,
        "psr_glm_unsmoothed": null,
        "min_track_record_length_periods": 34.0,
        "psr_sample_eligible": false,
        "observation_count": 22,
        "psr_benchmark_sr": 0.0,
        "non_iid_caveat": "PSR accounts for skewness and excess kurtosis under stationary returns; GLM unsmoothing adjusts for first-order serial correlation, and unobserved multi-account selection trials cannot be ruled out without subaccount enumeration.",
        "max_drawdown_decimal": -0.0455,
        "max_drawdown_pct": -4.55,
        "skewness": 0.18,
        "excess_kurtosis": 0.41,
        "capital_bracket": "bracket_100k_1m",
        "benchmark_symbol": "QQQ",
        "benchmark_twr_decimal": 0.021,
        "alpha_decimal": 0.093,
        "indexed_curve": [
          {
            "timestamp_utc": "2026-03-02T00:00:00Z",
            "index_value": 100.0,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.0
          },
          {
            "timestamp_utc": "2026-03-06T21:00:00Z",
            "index_value": 103.4,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.8
          },
          {
            "timestamp_utc": "2026-03-11T21:00:00Z",
            "index_value": 98.7,
            "drawdown_pct": -4.55,
            "benchmark_index_value": 99.6
          },
          {
            "timestamp_utc": "2026-03-14T21:00:00Z",
            "index_value": 106.9,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 101.2
          },
          {
            "timestamp_utc": "2026-03-20T21:00:00Z",
            "index_value": 105.1,
            "drawdown_pct": -1.68,
            "benchmark_index_value": 100.9
          },
          {
            "timestamp_utc": "2026-03-26T21:00:00Z",
            "index_value": 109.8,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 101.7
          },
          {
            "timestamp_utc": "2026-03-31T23:59:59Z",
            "index_value": 111.4,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 102.1
          }
        ],
        "methodology": "daily_flow_adjusted_twr_v3",
        "warnings": [
          "PSR and PSR_GLM suppressed: observation_count=22 is below the mandatory T >= 30 statistical reliability gate.",
          "Statement reconciliation flagged an unexplained +64.8 bps NAV jump on 2026-03-14 while <Transfers> and <CorporateActions> XML sections were omitted."
        ]
      },
      "leaf_hash_hex": "505dd2cba14b892b45fbb50ce9eecb5832ad26f68d7386d776ec431b6fb0acef",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "57123fcb82c4ae6f4b5ea371a861e8e786e9cb3585f11206f55cedaa0af9a7d0"
        },
        {
          "side": "right",
          "sibling_hash_hex": "f61e02e8f91260c31d2034466af6aece389404fc4a1912eb24469d689bd3497f"
        },
        {
          "side": "right",
          "sibling_hash_hex": "e64914e656cb5f5c9d9452c78629295e33ab155278516609007ecadc36524fed"
        }
      ]
    },
    {
      "leaf_name": "indexed_curve",
      "salt_hex": "4a891181f31ccc189b99d592cc29cf7c2e267fe62fc93a6b90250731db888a71",
      "payload": {
        "base_index": 100.0,
        "points": [
          {
            "timestamp_utc": "2026-03-02T00:00:00Z",
            "index_value": 100.0,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.0
          },
          {
            "timestamp_utc": "2026-03-06T21:00:00Z",
            "index_value": 103.4,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.8
          },
          {
            "timestamp_utc": "2026-03-11T21:00:00Z",
            "index_value": 98.7,
            "drawdown_pct": -4.55,
            "benchmark_index_value": 99.6
          },
          {
            "timestamp_utc": "2026-03-14T21:00:00Z",
            "index_value": 106.9,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 101.2
          },
          {
            "timestamp_utc": "2026-03-20T21:00:00Z",
            "index_value": 105.1,
            "drawdown_pct": -1.68,
            "benchmark_index_value": 100.9
          },
          {
            "timestamp_utc": "2026-03-26T21:00:00Z",
            "index_value": 109.8,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 101.7
          },
          {
            "timestamp_utc": "2026-03-31T23:59:59Z",
            "index_value": 111.4,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 102.1
          }
        ]
      },
      "leaf_hash_hex": "57123fcb82c4ae6f4b5ea371a861e8e786e9cb3585f11206f55cedaa0af9a7d0",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "505dd2cba14b892b45fbb50ce9eecb5832ad26f68d7386d776ec431b6fb0acef"
        },
        {
          "side": "right",
          "sibling_hash_hex": "f61e02e8f91260c31d2034466af6aece389404fc4a1912eb24469d689bd3497f"
        },
        {
          "side": "right",
          "sibling_hash_hex": "e64914e656cb5f5c9d9452c78629295e33ab155278516609007ecadc36524fed"
        }
      ]
    },
    {
      "leaf_name": "reconciliation",
      "salt_hex": "b0a0855071b4ac8ad7871c0cabd18fbeeba41ff89b7004a9be4371b2a2f8a25a",
      "payload": {
        "status": "unexplained_residual",
        "reference_provider": "eodhd",
        "ledger_completeness_ok": false,
        "missing_sections": [
          "Transfers",
          "CorporateActions"
        ],
        "checks_evaluated": 41,
        "discrepancy_count": 1,
        "explained_convention_count": 1,
        "findings": [
          {
            "category": "daily_nav_continuity_identity",
            "outcome": "discrepancy",
            "date_or_timestamp": "2026-03-14T21:00:00Z",
            "symbol": "NVDA / PORTFOLIO",
            "expected_value": 106.21,
            "observed_value": 106.9,
            "residual_bps": 64.8,
            "residual_base_currency": null,
            "math_identity": "Residual_t = Observed_NAV_t - (NAV_{t-1} + TradePnL_t + CashFlows_t) = +64.8 bps",
            "technical_explanation": "Observed ending equity exceeds trade-explained mark-to-market change by +64.8 bps on 2026-03-14. Statement query omitted <Transfers> and <CorporateActions> sections.",
            "benign_causes_considered": [
              "Unexported internal ACATS or subaccount share transfer (<Transfers> section unchecked in query config)",
              "Unexported stock split, spin-off, or special dividend adjustment (<CorporateActions> section unchecked)",
              "Prior-period option assignment cost-basis carry adjustment"
            ]
          },
          {
            "category": "option_expiration_settlement_timing",
            "outcome": "explained_convention",
            "date_or_timestamp": "2026-03-20T20:00:00Z",
            "symbol": "QQQ 260320C510",
            "expected_value": 105.1,
            "observed_value": 105.1,
            "residual_bps": 0.4,
            "residual_base_currency": null,
            "math_identity": "OptionExerciseCash = (SpotClose - Strike) * Multiplier * Contracts",
            "technical_explanation": "Friday OCC option expiration cash settlement booked on Saturday clearing batch; reconciled across T+1 weekend boundary.",
            "benign_causes_considered": [
              "OCC Friday 23:59 ET clearing batch vs UTC midnight cutoff"
            ]
          },
          {
            "category": "eodhd_two_stage_fill_envelope",
            "outcome": "pass",
            "date_or_timestamp": "2026-03-02..2026-03-31",
            "symbol": "ALL_TRADES",
            "expected_value": 100.0,
            "observed_value": 100.0,
            "residual_bps": 0.0,
            "residual_base_currency": null,
            "math_identity": "Low_1m(t) - SpreadTol <= FillPrice <= High_1m(t) + SpreadTol",
            "technical_explanation": "All 39 reported trade fills fall inside EODHD 1-minute OHLC envelopes; discrepancy is isolated to non-trade position continuity on 2026-03-14.",
            "benign_causes_considered": [
              "Normal exchange execution"
            ]
          }
        ],
        "statistical_diagnostics": [
          {
            "metric_name": "Sample Horizon Reliability Gate (T = 22 < 30)",
            "observed_value": 22.0,
            "interpretation": "Track record spans 22 daily observations; Probabilistic Sharpe Ratio requires T >= 30 to bound fourth-moment standard-error estimation noise.",
            "caveats": [
              "Re-export with >= 30 trading days and enable <Transfers> + <CorporateActions> to resolve accounting residual."
            ]
          }
        ],
        "summary_text": "1 unexplained +64.8 bps NAV continuity residual on 2026-03-14; <Transfers> and <CorporateActions> sections missing from statement export."
      },
      "leaf_hash_hex": "5b8cf87a51ae20d2d1bf8b3f83dc6c0101f050aa11c301999bf98c0a9bc38db0",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "66cb957ad8bafc6f772af524c115207a41c906e5b2a56776c9237d26cf115500"
        },
        {
          "side": "left",
          "sibling_hash_hex": "50d1ea5ca419eaa2fb17be7da8543bfc3c13d250389377f02bc3c47e38c7e8a7"
        },
        {
          "side": "right",
          "sibling_hash_hex": "e64914e656cb5f5c9d9452c78629295e33ab155278516609007ecadc36524fed"
        }
      ]
    },
    {
      "leaf_name": "coaching_and_context",
      "salt_hex": "e769f7b0e8975fcff0251467784a3509bc43d3614cf75be28e06d58500ae0578",
      "payload": {
        "cost_drag": {
          "commission_and_fee_drag_bps": 8.4,
          "margin_and_funding_drag_bps": 11.2,
          "fx_conversion_drag_bps": 0.0,
          "withholding_tax_drag_bps": 1.1,
          "total_friction_drag_bps": 20.7,
          "annualized_total_drag_bps": 248.4
        },
        "behaviour": {
          "sample_eligible": true,
          "min_trades_gate": 30,
          "observed_trades": 39,
          "observed_days": 22,
          "median_holding_hours": 18.5,
          "holding_horizon_label": "intraday_to_2d_swing",
          "win_rate": 0.513,
          "profit_factor": 1.44,
          "winner_vs_loser_hold_ratio": 1.12,
          "odean_pgr_plr_spread": 0.041,
          "post_drawdown_sizing_discipline_atr": 1.08,
          "atr_normalized": true,
          "return_concentration_top5_pct": 61.2,
          "actionable_improvements": [
            "Enable <Transfers> and <CorporateActions> in your query template so verifiers can distinguish capital inflows from trading alpha.",
            "Top-5 trades represent 61.2% of net return over 22 days; extend prospective enrollment beyond 30 trading days to unlock PSR_GLM."
          ]
        },
        "catalyst_regime_win_rate": 0.55,
        "quiet_regime_win_rate": 0.48,
        "event_window_share_pct": 38.5,
        "event_observations": [
          {
            "symbol": "AMD",
            "trade_timestamp_utc": "2026-03-10T13:31:05Z",
            "earliest_public_utc": "2026-03-10T13:30:00Z",
            "confirmed_public_utc": "2026-03-10T13:32:10Z",
            "event_sources": [
              "Macro Economic Calendar",
              "Issuer PR Feed"
            ],
            "headline_or_event": "US CPI Macro Print & AI Accelerator Supply Update",
            "alignment_class": "ambiguous_public_window",
            "timestamp_uncertainty_note": "Executed +65s after 13:30:00Z macro release inside secondary wire confirmation band."
          }
        ],
        "llm_narrative_used": false,
        "llm_model_id": null,
        "style_summary": "Concentrated short-horizon tech & options swing account with incomplete non-cash ledger sections.",
        "coaching_takeaways": [
          "Reconciliation X-Ray pinpoints exact date (2026-03-14) and missing XML checkboxes without accusatory fraud scoring."
        ],
        "uncertainty_disclosures": [
          "Accounting residuals often arise from omitted corporate action or transfer sections rather than statement tampering."
        ]
      },
      "leaf_hash_hex": "66cb957ad8bafc6f772af524c115207a41c906e5b2a56776c9237d26cf115500",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "5b8cf87a51ae20d2d1bf8b3f83dc6c0101f050aa11c301999bf98c0a9bc38db0"
        },
        {
          "side": "left",
          "sibling_hash_hex": "50d1ea5ca419eaa2fb17be7da8543bfc3c13d250389377f02bc3c47e38c7e8a7"
        },
        {
          "side": "right",
          "sibling_hash_hex": "e64914e656cb5f5c9d9452c78629295e33ab155278516609007ecadc36524fed"
        }
      ]
    },
    {
      "leaf_name": "capital_bracket",
      "salt_hex": "8e4816b6c0bfab94953ee01a4bf2138a3afc5e3b3e2759a8fd7f08755c78dcf0",
      "payload": {
        "capital_bracket": "bracket_100k_1m",
        "valuation_currency": "USD"
      },
      "leaf_hash_hex": "8768863417359ae08e115ac4fa707b8fd236b170e785d6a691d21970a5b43ca7",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "a9da47d403e5c11a9436f7559fc91b97bf3e70b7eafdc85f3ef85d8203db0020"
        },
        {
          "side": "right",
          "sibling_hash_hex": "d02e5588076f6cb2ff2aa3c195c24081c1e82765e2008b9d3ee0b3f983b590c2"
        },
        {
          "side": "left",
          "sibling_hash_hex": "59b88a47a014d18386c66fcacb72834f6a184b679b40f60a803c59aeec7800f2"
        }
      ]
    },
    {
      "leaf_name": "benchmark_alpha",
      "salt_hex": "d61401a8dc4516229a90ef3c5024884b2dd55a687a4fd87ce0810179f3dc3d0d",
      "payload": {
        "benchmark_symbol": "QQQ",
        "benchmark_twr_decimal": 0.021,
        "alpha_decimal": 0.093,
        "information_ratio": 1.48,
        "beta": 1.15
      },
      "leaf_hash_hex": "a9da47d403e5c11a9436f7559fc91b97bf3e70b7eafdc85f3ef85d8203db0020",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "8768863417359ae08e115ac4fa707b8fd236b170e785d6a691d21970a5b43ca7"
        },
        {
          "side": "right",
          "sibling_hash_hex": "d02e5588076f6cb2ff2aa3c195c24081c1e82765e2008b9d3ee0b3f983b590c2"
        },
        {
          "side": "left",
          "sibling_hash_hex": "59b88a47a014d18386c66fcacb72834f6a184b679b40f60a803c59aeec7800f2"
        }
      ]
    },
    {
      "leaf_name": "delayed_closed_trades",
      "salt_hex": "0debbcbc23f91aff41f2a0b4e006a8c3905d10ef0c71ba057e4af5b57f67b01c",
      "payload": {
        "embargo_days": 7,
        "trades": []
      },
      "leaf_hash_hex": "d02e5588076f6cb2ff2aa3c195c24081c1e82765e2008b9d3ee0b3f983b590c2",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "c44570607d24dbc95d26f301bd988e4ed8cbb885834dfefe46b4ca01f177b011"
        },
        {
          "side": "left",
          "sibling_hash_hex": "59b88a47a014d18386c66fcacb72834f6a184b679b40f60a803c59aeec7800f2"
        }
      ]
    }
  ],
  "undisclosed_leaf_hashes": {},
  "witness_attestations": [
    {
      "protocol": "tlsn-v0.1.0-alpha.15",
      "tls_version": "1.2",
      "defer_decryption_from_start": true,
      "notary_id": "notary-pse-eu",
      "server_sni": "ndcdyn.interactivebrokers.com",
      "sanitized_request_target": "/AccountManagement/FlexWebService/GetStatement?t=[REDACTED]&q=[REDACTED]&v=3",
      "redacted_headers": [
        "Authorization: [REDACTED]"
      ],
      "commitment_kind": "whole_body_sha256",
      "response_body_sha256": "310a1585bbda6bd6b44e1f2cd1f39485155aae06f8127566ba6ad6fb928300e7",
      "session_timestamp_utc": "2026-04-01T04:00:00Z",
      "signature_hex": "9e190611f946bc03d9b5d1e2b8b23c7c6124267b218ff4ed55d709f33ce4d14cd189d54f79e7f92087feb931395dfcd2c9321167bcf840d08cbaa4960d32c408"
    }
  ],
  "broker_native_signature": null,
  "prospective_chain_link": null,
  "retention_mode": "no_persistent_storage"
};

export const BUNDLE_COACHING_STUDIO: VerifyProofBundle = {
  "proof_id": "prf-coach-studio-009",
  "issued_at_utc": "2026-04-01T05:12:00Z",
  "publisher_kid": "n170-pub-2026-q1",
  "publisher_public_key_hex": "519749abe49eaf67bff092d850c243df38be8697b84a2dde4b8fad150d08ff78",
  "broker_id": "alpaca",
  "blinded_account_tag": "95ab2fb18fe573dd0981889339788152c1acadd7960825c1c8d1f70c39ec525d",
  "account_scope": "all_enumerated_subaccounts",
  "provider_approval_state": "approved_live",
  "environment_tier": "live_production",
  "claimed_origin_assurance": "independently_witnessed_tls",
  "source_body_sha256": "2d755857a20ab146c1a170570400a564188d810079b0dece8757c3f17b555a93",
  "period_start_utc": "2026-01-02T00:00:00Z",
  "period_end_utc": "2026-03-31T23:59:59Z",
  "base_currency": "USD",
  "merkle_root": "095cf796c52e20664093f7c91a06de650d67fc1185e92f1a7a03275f72d497b5",
  "signature_hex": "444e97a9ca1ea65a056a1b877d73c3d2c422f5b3095c12698dc9246dd57d10c7648949b1c7550afbf6dedd1445e5a5294ea1a7f35ab37c417f318696bc111705",
  "schema_version": "n170-verify-v3",
  "disclosed_leaves": [
    {
      "leaf_name": "core_metrics",
      "salt_hex": "1bd0048ff507c2592e38dbd9648480880ae13c1cee19e9f2e00e48ff01abb849",
      "payload": {
        "twr_decimal": 0.226,
        "twr_pct": 22.6,
        "cagr_decimal": 1.298,
        "cagr_pct": 129.8,
        "xirr_decimal": 1.264,
        "annualized_volatility": 0.194,
        "smoothing_index_xi": 0.95,
        "lag1_autocorrelation": 0.03,
        "unsmoothed_volatility": 0.199,
        "unsmoothed_sharpe_ratio": 2.08,
        "sharpe_ratio": 2.14,
        "sortino_ratio": 2.89,
        "probabilistic_sharpe_ratio": 0.972,
        "psr_glm_unsmoothed": 0.968,
        "min_track_record_length_periods": 24.8,
        "psr_sample_eligible": true,
        "observation_count": 61,
        "psr_benchmark_sr": 0.0,
        "non_iid_caveat": "PSR accounts for skewness and excess kurtosis under stationary returns; GLM unsmoothing adjusts for first-order serial correlation, and unobserved multi-account selection trials cannot be ruled out without subaccount enumeration.",
        "max_drawdown_decimal": -0.0524,
        "max_drawdown_pct": -5.24,
        "skewness": -0.22,
        "excess_kurtosis": 1.14,
        "capital_bracket": null,
        "benchmark_symbol": "SPY",
        "benchmark_twr_decimal": 0.061,
        "alpha_decimal": 0.165,
        "indexed_curve": [
          {
            "timestamp_utc": "2026-01-02T00:00:00Z",
            "index_value": 100.0,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.0
          },
          {
            "timestamp_utc": "2026-01-16T21:00:00Z",
            "index_value": 106.8,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 101.4
          },
          {
            "timestamp_utc": "2026-01-30T21:00:00Z",
            "index_value": 101.2,
            "drawdown_pct": -5.24,
            "benchmark_index_value": 102.1
          },
          {
            "timestamp_utc": "2026-02-13T21:00:00Z",
            "index_value": 109.5,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 103.6
          },
          {
            "timestamp_utc": "2026-02-27T21:00:00Z",
            "index_value": 114.2,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.0
          },
          {
            "timestamp_utc": "2026-03-13T21:00:00Z",
            "index_value": 111.8,
            "drawdown_pct": -2.1,
            "benchmark_index_value": 103.8
          },
          {
            "timestamp_utc": "2026-03-31T23:59:59Z",
            "index_value": 122.6,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 106.1
          }
        ],
        "methodology": "daily_flow_adjusted_twr_v3",
        "warnings": []
      },
      "leaf_hash_hex": "7ee58ee153994c819ea8a5f5cf26b047f284815e8311d9a7e3c8d0ac8e76af9d",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "a4133c045b5c1e285444673f2366a2dea5e344f8357c77cba5872e7b56ad2d27"
        },
        {
          "side": "right",
          "sibling_hash_hex": "cc70d2a8ae37760ec33c8424936a0c132ab7a11bd5de2e4cd9472463cec58c6b"
        },
        {
          "side": "right",
          "sibling_hash_hex": "d537c818ce4f407fbf789f0c639c360cea261b3566660f2396e43ed704a04143"
        }
      ]
    },
    {
      "leaf_name": "indexed_curve",
      "salt_hex": "d12dc61111b9f9ffad86cffafbb76254dd5ad57f3fce25c7ae5e602790fae23d",
      "payload": {
        "base_index": 100.0,
        "points": [
          {
            "timestamp_utc": "2026-01-02T00:00:00Z",
            "index_value": 100.0,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.0
          },
          {
            "timestamp_utc": "2026-01-16T21:00:00Z",
            "index_value": 106.8,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 101.4
          },
          {
            "timestamp_utc": "2026-01-30T21:00:00Z",
            "index_value": 101.2,
            "drawdown_pct": -5.24,
            "benchmark_index_value": 102.1
          },
          {
            "timestamp_utc": "2026-02-13T21:00:00Z",
            "index_value": 109.5,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 103.6
          },
          {
            "timestamp_utc": "2026-02-27T21:00:00Z",
            "index_value": 114.2,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.0
          },
          {
            "timestamp_utc": "2026-03-13T21:00:00Z",
            "index_value": 111.8,
            "drawdown_pct": -2.1,
            "benchmark_index_value": 103.8
          },
          {
            "timestamp_utc": "2026-03-31T23:59:59Z",
            "index_value": 122.6,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 106.1
          }
        ]
      },
      "leaf_hash_hex": "a4133c045b5c1e285444673f2366a2dea5e344f8357c77cba5872e7b56ad2d27",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "7ee58ee153994c819ea8a5f5cf26b047f284815e8311d9a7e3c8d0ac8e76af9d"
        },
        {
          "side": "right",
          "sibling_hash_hex": "cc70d2a8ae37760ec33c8424936a0c132ab7a11bd5de2e4cd9472463cec58c6b"
        },
        {
          "side": "right",
          "sibling_hash_hex": "d537c818ce4f407fbf789f0c639c360cea261b3566660f2396e43ed704a04143"
        }
      ]
    },
    {
      "leaf_name": "reconciliation",
      "salt_hex": "2dfd9d99b269f210a3cb4e3b1c74f38a3cc0917610a0d496effca1337a0ebc7e",
      "payload": {
        "status": "reconciled_within_tolerance",
        "reference_provider": "eodhd",
        "ledger_completeness_ok": true,
        "missing_sections": [],
        "checks_evaluated": 218,
        "discrepancy_count": 0,
        "explained_convention_count": 1,
        "findings": [
          {
            "category": "daily_nav_continuity_identity",
            "outcome": "pass",
            "date_or_timestamp": "2026-01-02..2026-03-31",
            "symbol": "PORTFOLIO",
            "expected_value": 122.6,
            "observed_value": 122.6,
            "residual_bps": 0.12,
            "residual_base_currency": null,
            "math_identity": "NAV_t = NAV_{t-1} + Realized_t + Unrealized_t + NetFlows_t - Fees_t",
            "technical_explanation": "61 daily live Alpaca portfolio equity snapshots reconcile within 0.2 bps.",
            "benign_causes_considered": [
              "SEC/FINRA TAF sub-cent fee rounding"
            ]
          }
        ],
        "statistical_diagnostics": [
          {
            "metric_name": "Left-Tail Skewness Check (Skew = -0.22)",
            "observed_value": -0.22,
            "interpretation": "Slight negative daily return skewness caused by holding losing intraday positions longer than winners (Odean PGR-PLR = +0.214).",
            "caveats": [
              "Directly addressable via symmetrical ATR hard-stop automation."
            ]
          }
        ],
        "summary_text": "Reconciled within 0.2 bps across 61 live trading days on Alpaca Production API (`paper-api` rejected)."
      },
      "leaf_hash_hex": "02c68c3ee75f5d731a306c15fe51f945504f63e541345783489e89aaf7a1d307",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "b7d6822fd8cdf214cb1f985981a0b9e3a49023e46d07a0a7b15f78690f088410"
        },
        {
          "side": "left",
          "sibling_hash_hex": "3d3e43323e58cfda01f661b50cd1946ca248b589117ecd0cd8726d59594d90f1"
        },
        {
          "side": "right",
          "sibling_hash_hex": "d537c818ce4f407fbf789f0c639c360cea261b3566660f2396e43ed704a04143"
        }
      ]
    },
    {
      "leaf_name": "coaching_and_context",
      "salt_hex": "ce14d160eb834db9ef27d6b51ccb1fb56c6238d2d66c775e745464d51a9652f9",
      "payload": {
        "cost_drag": {
          "commission_and_fee_drag_bps": 31.0,
          "margin_and_funding_drag_bps": 42.6,
          "fx_conversion_drag_bps": 14.8,
          "withholding_tax_drag_bps": 4.0,
          "total_friction_drag_bps": 92.4,
          "annualized_total_drag_bps": 284.0
        },
        "behaviour": {
          "sample_eligible": true,
          "min_trades_gate": 30,
          "observed_trades": 214,
          "observed_days": 61,
          "median_holding_hours": 5.8,
          "holding_horizon_label": "active_intraday_and_overnight_momentum",
          "win_rate": 0.631,
          "profit_factor": 1.67,
          "winner_vs_loser_hold_ratio": 0.58,
          "odean_pgr_plr_spread": 0.214,
          "post_drawdown_sizing_discipline_atr": 1.31,
          "atr_normalized": true,
          "return_concentration_top5_pct": 34.2,
          "actionable_improvements": [
            "Disposition Effect Alert (Odean PGR - PLR = +0.214): You realize winning positions 21.4% more frequently than open losers, holding winners a median 4.2h vs 7.3h on losers (0.58x hold ratio). Trailing 1.5-ATR partial exits on top momentum breakouts would have added ~+410 bps net.",
            "Post-Drawdown Revenge Sizing (SDI_DD^ATR = 1.31x): In the 5 trades immediately following your Jan 30 -5.24% drawdown, ATR-normalized position risk expanded +31% above your baseline risk budget. Cap post-drawdown risk at <= 0.85x baseline ATR until 50% drawdown recovery.",
            "Friction Waterfall Drag (284 bps annualized): Overnight margin borrow (42.6 bps) + ad-hoc CAD/EUR FX auto-conversions (14.8 bps) consumed 29% of gross edge. Closing flat before 16:00 ET on non-catalyst days cuts margin drag by ~65%."
          ]
        },
        "catalyst_regime_win_rate": 0.714,
        "quiet_regime_win_rate": 0.579,
        "event_window_share_pct": 32.7,
        "event_observations": [
          {
            "symbol": "PLTR",
            "trade_timestamp_utc": "2026-02-03T21:08:42Z",
            "earliest_public_utc": "2026-02-03T21:05:11Z",
            "confirmed_public_utc": "2026-02-03T21:06:02Z",
            "event_sources": [
              "SEC EDGAR 8-K",
              "BusinessWire"
            ],
            "headline_or_event": "FY2026 Commercial Revenue Guidance & Earnings Beat",
            "alignment_class": "post_confirmed_catalyst",
            "timestamp_uncertainty_note": "Entered +2m40s after confirmed EDGAR 8-K acceptance timestamp."
          },
          {
            "symbol": "TSLA",
            "trade_timestamp_utc": "2026-03-02T14:00:18Z",
            "earliest_public_utc": "2026-03-02T14:00:00Z",
            "confirmed_public_utc": "2026-03-02T14:02:45Z",
            "event_sources": [
              "European Fleet Registration Release",
              "News Wire"
            ],
            "headline_or_event": "Monthly Regional Delivery & Registration Bulletin",
            "alignment_class": "ambiguous_public_window",
            "timestamp_uncertainty_note": "Executed inside I_e = [14:00:00Z, 14:02:45Z] between primary agency bulletin and secondary wire headline."
          },
          {
            "symbol": "SMCI",
            "trade_timestamp_utc": "2026-02-18T19:42:10Z",
            "earliest_public_utc": "2026-02-18T19:48:00Z",
            "confirmed_public_utc": "2026-02-18T19:50:12Z",
            "event_sources": [
              "After-Hours Filing Feed"
            ],
            "headline_or_event": "Late-Session Supply Chain Partner Filing",
            "alignment_class": "prior_to_earliest_recorded_catalyst",
            "timestamp_uncertainty_note": "Order filled 5m50s prior to earliest indexed secondary headline; aligns with high-volume sector sympathy breakout at 19:40Z (descriptive window note, never an MNPI claim)."
          },
          {
            "symbol": "META",
            "trade_timestamp_utc": "2026-03-19T15:22:05Z",
            "earliest_public_utc": null,
            "confirmed_public_utc": null,
            "event_sources": [
              "EODHD Event Feed"
            ],
            "headline_or_event": "Quiet intraday VWAP mean-reversion session",
            "alignment_class": "quiet_non_catalyst_regime",
            "timestamp_uncertainty_note": "No issuer or macro catalyst within +-24h."
          }
        ],
        "llm_narrative_used": false,
        "llm_model_id": null,
        "style_summary": "High-hit-rate catalyst & intraday momentum trader leaving alpha on the table via premature winner exits (Odean disposition spread +0.214) and overnight margin drag.",
        "coaching_takeaways": [
          "Strongest edge is confirmed post-catalyst momentum (71.4% win rate vs 57.9% in quiet regimes).",
          "Fixing premature winner exits and post-drawdown +31% ATR oversizing offers the highest immediate Sharpe improvement \u2014 zero $80/mo journal paywall required."
        ],
        "uncertainty_disclosures": [
          "Catalyst interval I_e = [t_earliest, t_confirmed] explicitly models wire/EDGAR clock skew and feed latency; alignment classes are purely descriptive regime context."
        ]
      },
      "leaf_hash_hex": "b7d6822fd8cdf214cb1f985981a0b9e3a49023e46d07a0a7b15f78690f088410",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "02c68c3ee75f5d731a306c15fe51f945504f63e541345783489e89aaf7a1d307"
        },
        {
          "side": "left",
          "sibling_hash_hex": "3d3e43323e58cfda01f661b50cd1946ca248b589117ecd0cd8726d59594d90f1"
        },
        {
          "side": "right",
          "sibling_hash_hex": "d537c818ce4f407fbf789f0c639c360cea261b3566660f2396e43ed704a04143"
        }
      ]
    },
    {
      "leaf_name": "benchmark_alpha",
      "salt_hex": "f0bba7afae38596cb13cd693bef24db5f842e8a30be0de8fd2dab5b2a016b98f",
      "payload": {
        "benchmark_symbol": "SPY",
        "benchmark_twr_decimal": 0.061,
        "alpha_decimal": 0.165,
        "information_ratio": 1.92,
        "beta": 0.78
      },
      "leaf_hash_hex": "2509d6db43330ebf1a9bba70570b4fea5e0bdf4b20281ac242685eff85cc7e48",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "322b4057ed1fdd15fffcb6305a9a7911c4cbacd953f3a9066adf5865439cc43b"
        },
        {
          "side": "right",
          "sibling_hash_hex": "c64838d31e6f1c7c4b727e463128703399fb511a4fd7016ffadac26b32b56d18"
        },
        {
          "side": "left",
          "sibling_hash_hex": "fb70731cc3e1f7057099f5ecc89df460f068cf978f1179e3d80fb8a0d62d673e"
        }
      ]
    }
  ],
  "undisclosed_leaf_hashes": {
    "capital_bracket": "322b4057ed1fdd15fffcb6305a9a7911c4cbacd953f3a9066adf5865439cc43b",
    "delayed_closed_trades": "c64838d31e6f1c7c4b727e463128703399fb511a4fd7016ffadac26b32b56d18"
  },
  "witness_attestations": [
    {
      "protocol": "tlsn-v0.1.0-alpha.15",
      "tls_version": "1.2",
      "defer_decryption_from_start": true,
      "notary_id": "notary-pse-eu",
      "server_sni": "api.alpaca.markets",
      "sanitized_request_target": "/v2/accounts/[REDACTED]/portfolio/history",
      "redacted_headers": [
        "APCA-API-KEY-ID: [REDACTED]",
        "APCA-API-SECRET-KEY: [REDACTED]"
      ],
      "commitment_kind": "whole_body_sha256",
      "response_body_sha256": "2d755857a20ab146c1a170570400a564188d810079b0dece8757c3f17b555a93",
      "session_timestamp_utc": "2026-04-01T05:10:00Z",
      "signature_hex": "b2020e830333c2dddc7120520717b4a36b98bd178691f556e84dee66f574f6b2d97ea85d174aed863b699b463a95a753bb17aefe7f41c7b737db5a5207eb3b02"
    },
    {
      "protocol": "tlsn-v0.1.0-alpha.15",
      "tls_version": "1.2",
      "defer_decryption_from_start": true,
      "notary_id": "notary-swiss-ch",
      "server_sni": "api.alpaca.markets",
      "sanitized_request_target": "/v2/accounts/[REDACTED]/portfolio/history",
      "redacted_headers": [
        "APCA-API-KEY-ID: [REDACTED]",
        "APCA-API-SECRET-KEY: [REDACTED]"
      ],
      "commitment_kind": "whole_body_sha256",
      "response_body_sha256": "2d755857a20ab146c1a170570400a564188d810079b0dece8757c3f17b555a93",
      "session_timestamp_utc": "2026-04-01T05:10:08Z",
      "signature_hex": "ce68f9eb40f29c27418cad243df8827a59c54efc2273969b05390c0ed536b66c0eeb4a1adadea817778c01d0e12f3d597cbf7a47ccf72c4b108892ab3decea07"
    }
  ],
  "broker_native_signature": null,
  "prospective_chain_link": null,
  "retention_mode": "opt_in_encrypted_sync"
};

export const BUNDLE_COACHING_STUDIO_FULL: VerifyProofBundle = {
  "proof_id": "prf-coach-studio-009",
  "issued_at_utc": "2026-04-01T05:12:00Z",
  "publisher_kid": "n170-pub-2026-q1",
  "publisher_public_key_hex": "519749abe49eaf67bff092d850c243df38be8697b84a2dde4b8fad150d08ff78",
  "broker_id": "alpaca",
  "blinded_account_tag": "95ab2fb18fe573dd0981889339788152c1acadd7960825c1c8d1f70c39ec525d",
  "account_scope": "all_enumerated_subaccounts",
  "provider_approval_state": "approved_live",
  "environment_tier": "live_production",
  "claimed_origin_assurance": "independently_witnessed_tls",
  "source_body_sha256": "2d755857a20ab146c1a170570400a564188d810079b0dece8757c3f17b555a93",
  "period_start_utc": "2026-01-02T00:00:00Z",
  "period_end_utc": "2026-03-31T23:59:59Z",
  "base_currency": "USD",
  "merkle_root": "095cf796c52e20664093f7c91a06de650d67fc1185e92f1a7a03275f72d497b5",
  "signature_hex": "444e97a9ca1ea65a056a1b877d73c3d2c422f5b3095c12698dc9246dd57d10c7648949b1c7550afbf6dedd1445e5a5294ea1a7f35ab37c417f318696bc111705",
  "schema_version": "n170-verify-v3",
  "disclosed_leaves": [
    {
      "leaf_name": "core_metrics",
      "salt_hex": "1bd0048ff507c2592e38dbd9648480880ae13c1cee19e9f2e00e48ff01abb849",
      "payload": {
        "twr_decimal": 0.226,
        "twr_pct": 22.6,
        "cagr_decimal": 1.298,
        "cagr_pct": 129.8,
        "xirr_decimal": 1.264,
        "annualized_volatility": 0.194,
        "smoothing_index_xi": 0.95,
        "lag1_autocorrelation": 0.03,
        "unsmoothed_volatility": 0.199,
        "unsmoothed_sharpe_ratio": 2.08,
        "sharpe_ratio": 2.14,
        "sortino_ratio": 2.89,
        "probabilistic_sharpe_ratio": 0.972,
        "psr_glm_unsmoothed": 0.968,
        "min_track_record_length_periods": 24.8,
        "psr_sample_eligible": true,
        "observation_count": 61,
        "psr_benchmark_sr": 0.0,
        "non_iid_caveat": "PSR accounts for skewness and excess kurtosis under stationary returns; GLM unsmoothing adjusts for first-order serial correlation, and unobserved multi-account selection trials cannot be ruled out without subaccount enumeration.",
        "max_drawdown_decimal": -0.0524,
        "max_drawdown_pct": -5.24,
        "skewness": -0.22,
        "excess_kurtosis": 1.14,
        "capital_bracket": null,
        "benchmark_symbol": "SPY",
        "benchmark_twr_decimal": 0.061,
        "alpha_decimal": 0.165,
        "indexed_curve": [
          {
            "timestamp_utc": "2026-01-02T00:00:00Z",
            "index_value": 100.0,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.0
          },
          {
            "timestamp_utc": "2026-01-16T21:00:00Z",
            "index_value": 106.8,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 101.4
          },
          {
            "timestamp_utc": "2026-01-30T21:00:00Z",
            "index_value": 101.2,
            "drawdown_pct": -5.24,
            "benchmark_index_value": 102.1
          },
          {
            "timestamp_utc": "2026-02-13T21:00:00Z",
            "index_value": 109.5,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 103.6
          },
          {
            "timestamp_utc": "2026-02-27T21:00:00Z",
            "index_value": 114.2,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.0
          },
          {
            "timestamp_utc": "2026-03-13T21:00:00Z",
            "index_value": 111.8,
            "drawdown_pct": -2.1,
            "benchmark_index_value": 103.8
          },
          {
            "timestamp_utc": "2026-03-31T23:59:59Z",
            "index_value": 122.6,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 106.1
          }
        ],
        "methodology": "daily_flow_adjusted_twr_v3",
        "warnings": []
      },
      "leaf_hash_hex": "7ee58ee153994c819ea8a5f5cf26b047f284815e8311d9a7e3c8d0ac8e76af9d",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "a4133c045b5c1e285444673f2366a2dea5e344f8357c77cba5872e7b56ad2d27"
        },
        {
          "side": "right",
          "sibling_hash_hex": "cc70d2a8ae37760ec33c8424936a0c132ab7a11bd5de2e4cd9472463cec58c6b"
        },
        {
          "side": "right",
          "sibling_hash_hex": "d537c818ce4f407fbf789f0c639c360cea261b3566660f2396e43ed704a04143"
        }
      ]
    },
    {
      "leaf_name": "indexed_curve",
      "salt_hex": "d12dc61111b9f9ffad86cffafbb76254dd5ad57f3fce25c7ae5e602790fae23d",
      "payload": {
        "base_index": 100.0,
        "points": [
          {
            "timestamp_utc": "2026-01-02T00:00:00Z",
            "index_value": 100.0,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.0
          },
          {
            "timestamp_utc": "2026-01-16T21:00:00Z",
            "index_value": 106.8,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 101.4
          },
          {
            "timestamp_utc": "2026-01-30T21:00:00Z",
            "index_value": 101.2,
            "drawdown_pct": -5.24,
            "benchmark_index_value": 102.1
          },
          {
            "timestamp_utc": "2026-02-13T21:00:00Z",
            "index_value": 109.5,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 103.6
          },
          {
            "timestamp_utc": "2026-02-27T21:00:00Z",
            "index_value": 114.2,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.0
          },
          {
            "timestamp_utc": "2026-03-13T21:00:00Z",
            "index_value": 111.8,
            "drawdown_pct": -2.1,
            "benchmark_index_value": 103.8
          },
          {
            "timestamp_utc": "2026-03-31T23:59:59Z",
            "index_value": 122.6,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 106.1
          }
        ]
      },
      "leaf_hash_hex": "a4133c045b5c1e285444673f2366a2dea5e344f8357c77cba5872e7b56ad2d27",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "7ee58ee153994c819ea8a5f5cf26b047f284815e8311d9a7e3c8d0ac8e76af9d"
        },
        {
          "side": "right",
          "sibling_hash_hex": "cc70d2a8ae37760ec33c8424936a0c132ab7a11bd5de2e4cd9472463cec58c6b"
        },
        {
          "side": "right",
          "sibling_hash_hex": "d537c818ce4f407fbf789f0c639c360cea261b3566660f2396e43ed704a04143"
        }
      ]
    },
    {
      "leaf_name": "reconciliation",
      "salt_hex": "2dfd9d99b269f210a3cb4e3b1c74f38a3cc0917610a0d496effca1337a0ebc7e",
      "payload": {
        "status": "reconciled_within_tolerance",
        "reference_provider": "eodhd",
        "ledger_completeness_ok": true,
        "missing_sections": [],
        "checks_evaluated": 218,
        "discrepancy_count": 0,
        "explained_convention_count": 1,
        "findings": [
          {
            "category": "daily_nav_continuity_identity",
            "outcome": "pass",
            "date_or_timestamp": "2026-01-02..2026-03-31",
            "symbol": "PORTFOLIO",
            "expected_value": 122.6,
            "observed_value": 122.6,
            "residual_bps": 0.12,
            "residual_base_currency": null,
            "math_identity": "NAV_t = NAV_{t-1} + Realized_t + Unrealized_t + NetFlows_t - Fees_t",
            "technical_explanation": "61 daily live Alpaca portfolio equity snapshots reconcile within 0.2 bps.",
            "benign_causes_considered": [
              "SEC/FINRA TAF sub-cent fee rounding"
            ]
          }
        ],
        "statistical_diagnostics": [
          {
            "metric_name": "Left-Tail Skewness Check (Skew = -0.22)",
            "observed_value": -0.22,
            "interpretation": "Slight negative daily return skewness caused by holding losing intraday positions longer than winners (Odean PGR-PLR = +0.214).",
            "caveats": [
              "Directly addressable via symmetrical ATR hard-stop automation."
            ]
          }
        ],
        "summary_text": "Reconciled within 0.2 bps across 61 live trading days on Alpaca Production API (`paper-api` rejected)."
      },
      "leaf_hash_hex": "02c68c3ee75f5d731a306c15fe51f945504f63e541345783489e89aaf7a1d307",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "b7d6822fd8cdf214cb1f985981a0b9e3a49023e46d07a0a7b15f78690f088410"
        },
        {
          "side": "left",
          "sibling_hash_hex": "3d3e43323e58cfda01f661b50cd1946ca248b589117ecd0cd8726d59594d90f1"
        },
        {
          "side": "right",
          "sibling_hash_hex": "d537c818ce4f407fbf789f0c639c360cea261b3566660f2396e43ed704a04143"
        }
      ]
    },
    {
      "leaf_name": "coaching_and_context",
      "salt_hex": "ce14d160eb834db9ef27d6b51ccb1fb56c6238d2d66c775e745464d51a9652f9",
      "payload": {
        "cost_drag": {
          "commission_and_fee_drag_bps": 31.0,
          "margin_and_funding_drag_bps": 42.6,
          "fx_conversion_drag_bps": 14.8,
          "withholding_tax_drag_bps": 4.0,
          "total_friction_drag_bps": 92.4,
          "annualized_total_drag_bps": 284.0
        },
        "behaviour": {
          "sample_eligible": true,
          "min_trades_gate": 30,
          "observed_trades": 214,
          "observed_days": 61,
          "median_holding_hours": 5.8,
          "holding_horizon_label": "active_intraday_and_overnight_momentum",
          "win_rate": 0.631,
          "profit_factor": 1.67,
          "winner_vs_loser_hold_ratio": 0.58,
          "odean_pgr_plr_spread": 0.214,
          "post_drawdown_sizing_discipline_atr": 1.31,
          "atr_normalized": true,
          "return_concentration_top5_pct": 34.2,
          "actionable_improvements": [
            "Disposition Effect Alert (Odean PGR - PLR = +0.214): You realize winning positions 21.4% more frequently than open losers, holding winners a median 4.2h vs 7.3h on losers (0.58x hold ratio). Trailing 1.5-ATR partial exits on top momentum breakouts would have added ~+410 bps net.",
            "Post-Drawdown Revenge Sizing (SDI_DD^ATR = 1.31x): In the 5 trades immediately following your Jan 30 -5.24% drawdown, ATR-normalized position risk expanded +31% above your baseline risk budget. Cap post-drawdown risk at <= 0.85x baseline ATR until 50% drawdown recovery.",
            "Friction Waterfall Drag (284 bps annualized): Overnight margin borrow (42.6 bps) + ad-hoc CAD/EUR FX auto-conversions (14.8 bps) consumed 29% of gross edge. Closing flat before 16:00 ET on non-catalyst days cuts margin drag by ~65%."
          ]
        },
        "catalyst_regime_win_rate": 0.714,
        "quiet_regime_win_rate": 0.579,
        "event_window_share_pct": 32.7,
        "event_observations": [
          {
            "symbol": "PLTR",
            "trade_timestamp_utc": "2026-02-03T21:08:42Z",
            "earliest_public_utc": "2026-02-03T21:05:11Z",
            "confirmed_public_utc": "2026-02-03T21:06:02Z",
            "event_sources": [
              "SEC EDGAR 8-K",
              "BusinessWire"
            ],
            "headline_or_event": "FY2026 Commercial Revenue Guidance & Earnings Beat",
            "alignment_class": "post_confirmed_catalyst",
            "timestamp_uncertainty_note": "Entered +2m40s after confirmed EDGAR 8-K acceptance timestamp."
          },
          {
            "symbol": "TSLA",
            "trade_timestamp_utc": "2026-03-02T14:00:18Z",
            "earliest_public_utc": "2026-03-02T14:00:00Z",
            "confirmed_public_utc": "2026-03-02T14:02:45Z",
            "event_sources": [
              "European Fleet Registration Release",
              "News Wire"
            ],
            "headline_or_event": "Monthly Regional Delivery & Registration Bulletin",
            "alignment_class": "ambiguous_public_window",
            "timestamp_uncertainty_note": "Executed inside I_e = [14:00:00Z, 14:02:45Z] between primary agency bulletin and secondary wire headline."
          },
          {
            "symbol": "SMCI",
            "trade_timestamp_utc": "2026-02-18T19:42:10Z",
            "earliest_public_utc": "2026-02-18T19:48:00Z",
            "confirmed_public_utc": "2026-02-18T19:50:12Z",
            "event_sources": [
              "After-Hours Filing Feed"
            ],
            "headline_or_event": "Late-Session Supply Chain Partner Filing",
            "alignment_class": "prior_to_earliest_recorded_catalyst",
            "timestamp_uncertainty_note": "Order filled 5m50s prior to earliest indexed secondary headline; aligns with high-volume sector sympathy breakout at 19:40Z (descriptive window note, never an MNPI claim)."
          },
          {
            "symbol": "META",
            "trade_timestamp_utc": "2026-03-19T15:22:05Z",
            "earliest_public_utc": null,
            "confirmed_public_utc": null,
            "event_sources": [
              "EODHD Event Feed"
            ],
            "headline_or_event": "Quiet intraday VWAP mean-reversion session",
            "alignment_class": "quiet_non_catalyst_regime",
            "timestamp_uncertainty_note": "No issuer or macro catalyst within +-24h."
          }
        ],
        "llm_narrative_used": false,
        "llm_model_id": null,
        "style_summary": "High-hit-rate catalyst & intraday momentum trader leaving alpha on the table via premature winner exits (Odean disposition spread +0.214) and overnight margin drag.",
        "coaching_takeaways": [
          "Strongest edge is confirmed post-catalyst momentum (71.4% win rate vs 57.9% in quiet regimes).",
          "Fixing premature winner exits and post-drawdown +31% ATR oversizing offers the highest immediate Sharpe improvement \u2014 zero $80/mo journal paywall required."
        ],
        "uncertainty_disclosures": [
          "Catalyst interval I_e = [t_earliest, t_confirmed] explicitly models wire/EDGAR clock skew and feed latency; alignment classes are purely descriptive regime context."
        ]
      },
      "leaf_hash_hex": "b7d6822fd8cdf214cb1f985981a0b9e3a49023e46d07a0a7b15f78690f088410",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "02c68c3ee75f5d731a306c15fe51f945504f63e541345783489e89aaf7a1d307"
        },
        {
          "side": "left",
          "sibling_hash_hex": "3d3e43323e58cfda01f661b50cd1946ca248b589117ecd0cd8726d59594d90f1"
        },
        {
          "side": "right",
          "sibling_hash_hex": "d537c818ce4f407fbf789f0c639c360cea261b3566660f2396e43ed704a04143"
        }
      ]
    },
    {
      "leaf_name": "capital_bracket",
      "salt_hex": "cfe4f9935e17772b72f6a02adc195f3ef756feb9aac66b280896a98e674fb6e9",
      "payload": {
        "capital_bracket": "bracket_10k_100k",
        "valuation_currency": "USD"
      },
      "leaf_hash_hex": "322b4057ed1fdd15fffcb6305a9a7911c4cbacd953f3a9066adf5865439cc43b",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "2509d6db43330ebf1a9bba70570b4fea5e0bdf4b20281ac242685eff85cc7e48"
        },
        {
          "side": "right",
          "sibling_hash_hex": "c64838d31e6f1c7c4b727e463128703399fb511a4fd7016ffadac26b32b56d18"
        },
        {
          "side": "left",
          "sibling_hash_hex": "fb70731cc3e1f7057099f5ecc89df460f068cf978f1179e3d80fb8a0d62d673e"
        }
      ]
    },
    {
      "leaf_name": "benchmark_alpha",
      "salt_hex": "f0bba7afae38596cb13cd693bef24db5f842e8a30be0de8fd2dab5b2a016b98f",
      "payload": {
        "benchmark_symbol": "SPY",
        "benchmark_twr_decimal": 0.061,
        "alpha_decimal": 0.165,
        "information_ratio": 1.92,
        "beta": 0.78
      },
      "leaf_hash_hex": "2509d6db43330ebf1a9bba70570b4fea5e0bdf4b20281ac242685eff85cc7e48",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "322b4057ed1fdd15fffcb6305a9a7911c4cbacd953f3a9066adf5865439cc43b"
        },
        {
          "side": "right",
          "sibling_hash_hex": "c64838d31e6f1c7c4b727e463128703399fb511a4fd7016ffadac26b32b56d18"
        },
        {
          "side": "left",
          "sibling_hash_hex": "fb70731cc3e1f7057099f5ecc89df460f068cf978f1179e3d80fb8a0d62d673e"
        }
      ]
    },
    {
      "leaf_name": "delayed_closed_trades",
      "salt_hex": "180d973e894c97d757fea72d310b77cfde35bf215ef970507a97b3d29af5b86d",
      "payload": {
        "embargo_days": 7,
        "trades": [
          {
            "symbol": "PLTR",
            "asset_class": "equity",
            "side": "long",
            "entry_timestamp_utc": "2026-02-03T21:08:42Z",
            "exit_timestamp_utc": "2026-02-04T15:20:00Z",
            "return_pct": 5.42,
            "holding_hours": 18.2
          }
        ]
      },
      "leaf_hash_hex": "c64838d31e6f1c7c4b727e463128703399fb511a4fd7016ffadac26b32b56d18",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "c76cba9bcd11a3dc7e349a7f83ddac752f23732bd7c3c3ed083f5aae58c14307"
        },
        {
          "side": "left",
          "sibling_hash_hex": "fb70731cc3e1f7057099f5ecc89df460f068cf978f1179e3d80fb8a0d62d673e"
        }
      ]
    }
  ],
  "undisclosed_leaf_hashes": {},
  "witness_attestations": [
    {
      "protocol": "tlsn-v0.1.0-alpha.15",
      "tls_version": "1.2",
      "defer_decryption_from_start": true,
      "notary_id": "notary-pse-eu",
      "server_sni": "api.alpaca.markets",
      "sanitized_request_target": "/v2/accounts/[REDACTED]/portfolio/history",
      "redacted_headers": [
        "APCA-API-KEY-ID: [REDACTED]",
        "APCA-API-SECRET-KEY: [REDACTED]"
      ],
      "commitment_kind": "whole_body_sha256",
      "response_body_sha256": "2d755857a20ab146c1a170570400a564188d810079b0dece8757c3f17b555a93",
      "session_timestamp_utc": "2026-04-01T05:10:00Z",
      "signature_hex": "b2020e830333c2dddc7120520717b4a36b98bd178691f556e84dee66f574f6b2d97ea85d174aed863b699b463a95a753bb17aefe7f41c7b737db5a5207eb3b02"
    },
    {
      "protocol": "tlsn-v0.1.0-alpha.15",
      "tls_version": "1.2",
      "defer_decryption_from_start": true,
      "notary_id": "notary-swiss-ch",
      "server_sni": "api.alpaca.markets",
      "sanitized_request_target": "/v2/accounts/[REDACTED]/portfolio/history",
      "redacted_headers": [
        "APCA-API-KEY-ID: [REDACTED]",
        "APCA-API-SECRET-KEY: [REDACTED]"
      ],
      "commitment_kind": "whole_body_sha256",
      "response_body_sha256": "2d755857a20ab146c1a170570400a564188d810079b0dece8757c3f17b555a93",
      "session_timestamp_utc": "2026-04-01T05:10:08Z",
      "signature_hex": "ce68f9eb40f29c27418cad243df8827a59c54efc2273969b05390c0ed536b66c0eeb4a1adadea817778c01d0e12f3d597cbf7a47ccf72c4b108892ab3decea07"
    }
  ],
  "broker_native_signature": null,
  "prospective_chain_link": null,
  "retention_mode": "opt_in_encrypted_sync"
};

export const BUNDLE_CUSTODY_SIGNED: VerifyProofBundle = {
  "proof_id": "prf-custody-signed-001",
  "issued_at_utc": "2026-04-01T01:20:00Z",
  "publisher_kid": "n170-pub-2026-q1",
  "publisher_public_key_hex": "519749abe49eaf67bff092d850c243df38be8697b84a2dde4b8fad150d08ff78",
  "broker_id": "prime_custody_ed25519",
  "blinded_account_tag": "a00361ea2259d5eb75718e7a2c5763532d9a52539f6d04e054d96bb4df1d79e8",
  "account_scope": "all_enumerated_subaccounts",
  "provider_approval_state": "approved_live",
  "environment_tier": "live_production",
  "claimed_origin_assurance": "broker_signed",
  "source_body_sha256": "d5a3966b021f66757d2846230e1aa242d56f9bab3d4082f79b3e251ed245dc17",
  "period_start_utc": "2026-01-01T00:00:00Z",
  "period_end_utc": "2026-03-31T23:59:59Z",
  "base_currency": "USD",
  "merkle_root": "00dee8c65e19242ff4d3f7b793fc7f60a7b4a835caa0382efd6b86550c1afd54",
  "signature_hex": "fd58b4e7ef6f57a8112b08efdcb7c7ec4ed9b86d2eb186ee576c8dfcecbf4a44cfef85166dff5c1d896b9e8c7907b6d3de6357ba56f205c28036321ce8380f06",
  "schema_version": "n170-verify-v3",
  "disclosed_leaves": [
    {
      "leaf_name": "core_metrics",
      "salt_hex": "3338f7c87286813227b245672072925baebba7e49deb57469e71540f0d818601",
      "payload": {
        "twr_decimal": 0.1864,
        "twr_pct": 18.64,
        "cagr_decimal": 0.984,
        "cagr_pct": 98.4,
        "xirr_decimal": 0.971,
        "annualized_volatility": 0.068,
        "smoothing_index_xi": 0.91,
        "lag1_autocorrelation": 0.07,
        "unsmoothed_volatility": 0.072,
        "unsmoothed_sharpe_ratio": 3.41,
        "sharpe_ratio": 3.62,
        "sortino_ratio": 5.4,
        "probabilistic_sharpe_ratio": 0.994,
        "psr_glm_unsmoothed": 0.991,
        "min_track_record_length_periods": 14.2,
        "psr_sample_eligible": true,
        "observation_count": 90,
        "psr_benchmark_sr": 0.0,
        "non_iid_caveat": "PSR accounts for skewness and excess kurtosis under stationary returns; GLM unsmoothing adjusts for first-order serial correlation, and unobserved multi-account selection trials cannot be ruled out without subaccount enumeration.",
        "max_drawdown_decimal": -0.0085,
        "max_drawdown_pct": -0.85,
        "skewness": 0.12,
        "excess_kurtosis": 0.35,
        "capital_bracket": "bracket_100k_1m",
        "benchmark_symbol": "BTC_BASIS",
        "benchmark_twr_decimal": 0.038,
        "alpha_decimal": 0.1484,
        "indexed_curve": [
          {
            "timestamp_utc": "2026-01-01T00:00:00Z",
            "index_value": 100.0,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.0
          },
          {
            "timestamp_utc": "2026-01-31T23:59:59Z",
            "index_value": 105.8,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 101.2
          },
          {
            "timestamp_utc": "2026-02-28T23:59:59Z",
            "index_value": 111.9,
            "drawdown_pct": -0.85,
            "benchmark_index_value": 102.4
          },
          {
            "timestamp_utc": "2026-03-31T23:59:59Z",
            "index_value": 118.64,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 103.8
          }
        ],
        "methodology": "daily_flow_adjusted_twr_v3",
        "warnings": []
      },
      "leaf_hash_hex": "34e8836c1310b30f4b3f91dec777b08104058f74c292d80aa08d25a5ef8c8011",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "e830fbe9b571f3d54475a2c90d92e772ef47fc09ac516ec8761e5ea1e3062da8"
        },
        {
          "side": "right",
          "sibling_hash_hex": "a0401e27b8651c1c8713abbc8cfd7fb179ef5f794aef3b9e1bef666e6de37c03"
        },
        {
          "side": "right",
          "sibling_hash_hex": "4b27c787e36b8c19235e5744ec3f47ef0ebc56f7ca6383302a887717955fa0b2"
        }
      ]
    },
    {
      "leaf_name": "indexed_curve",
      "salt_hex": "3333889c602f226011078fe3d307a3070a7e340de774dd10cd638a29f28b547e",
      "payload": {
        "base_index": 100.0,
        "points": [
          {
            "timestamp_utc": "2026-01-01T00:00:00Z",
            "index_value": 100.0,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.0
          },
          {
            "timestamp_utc": "2026-01-31T23:59:59Z",
            "index_value": 105.8,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 101.2
          },
          {
            "timestamp_utc": "2026-02-28T23:59:59Z",
            "index_value": 111.9,
            "drawdown_pct": -0.85,
            "benchmark_index_value": 102.4
          },
          {
            "timestamp_utc": "2026-03-31T23:59:59Z",
            "index_value": 118.64,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 103.8
          }
        ]
      },
      "leaf_hash_hex": "e830fbe9b571f3d54475a2c90d92e772ef47fc09ac516ec8761e5ea1e3062da8",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "34e8836c1310b30f4b3f91dec777b08104058f74c292d80aa08d25a5ef8c8011"
        },
        {
          "side": "right",
          "sibling_hash_hex": "a0401e27b8651c1c8713abbc8cfd7fb179ef5f794aef3b9e1bef666e6de37c03"
        },
        {
          "side": "right",
          "sibling_hash_hex": "4b27c787e36b8c19235e5744ec3f47ef0ebc56f7ca6383302a887717955fa0b2"
        }
      ]
    },
    {
      "leaf_name": "reconciliation",
      "salt_hex": "e101f7433295d4dd5fd5dfe55e045f17db7bea5923b3b4655ec51a2032450583",
      "payload": {
        "status": "reconciled_within_tolerance",
        "reference_provider": "eodhd",
        "ledger_completeness_ok": true,
        "missing_sections": [],
        "checks_evaluated": 184,
        "discrepancy_count": 0,
        "explained_convention_count": 2,
        "findings": [
          {
            "category": "daily_nav_continuity_identity",
            "outcome": "pass",
            "date_or_timestamp": "2026-01-01..2026-03-31",
            "symbol": "PORTFOLIO",
            "expected_value": 141.877,
            "observed_value": 141.878,
            "residual_bps": 0.07,
            "residual_base_currency": null,
            "math_identity": "NAV_t = NAV_{t-1} + Realized_t + Unrealized_t + NetFlows_t - Fees_t",
            "technical_explanation": "All 63 daily valuation intervals reconcile within 0.4 bps tolerance across all enumerated subaccounts.",
            "benign_causes_considered": [
              "Sub-penny multi-currency mark rounding"
            ]
          },
          {
            "category": "fx_t1_settlement_accrual",
            "outcome": "explained_convention",
            "date_or_timestamp": "2026-02-13T17:00:00Z",
            "symbol": "EUR.USD",
            "expected_value": 1.0418,
            "observed_value": 1.0421,
            "residual_bps": 2.88,
            "residual_base_currency": null,
            "math_identity": "Cash_Base(t) = Spot_FX(t) * Settled_Cash + Forward_Accrual(T+1)",
            "technical_explanation": "3 bps transient variance between trade-date and settlement-date FX translation resolved automatically on T+1 settlement.",
            "benign_causes_considered": [
              "WM/Refinitiv 16:00 London fix vs NY 17:00 broker FX mark",
              "T+1 spot FX value-date interest differential"
            ]
          },
          {
            "category": "dividend_ex_date_receivable",
            "outcome": "explained_convention",
            "date_or_timestamp": "2026-03-13T20:00:00Z",
            "symbol": "MSFT",
            "expected_value": 100.0,
            "observed_value": 100.0,
            "residual_bps": 0.0,
            "residual_base_currency": null,
            "math_identity": "NavExDate = SharePrice_Ex * Qty + DividendAccrualReceivable",
            "technical_explanation": "Ex-dividend price drop matched exact ChangeInDividendAccruals entry net of 15% treaty withholding.",
            "benign_causes_considered": [
              "Ex-date vs pay-date accrual accounting"
            ]
          },
          {
            "category": "eodhd_two_stage_fill_envelope",
            "outcome": "pass",
            "date_or_timestamp": "2026-03-24T14:32:18Z",
            "symbol": "NVDA",
            "expected_value": 138.4,
            "observed_value": 138.52,
            "residual_bps": 0.0,
            "residual_base_currency": null,
            "math_identity": "Low_1m(t) - SpreadTol <= FillPrice <= High_1m(t) + SpreadTol",
            "technical_explanation": "184 of 184 equity, ETF, and index futures executions fell strictly inside EODHD Stage-1 daily and Stage-2 1-minute market envelopes.",
            "benign_causes_considered": [
              "Odd-lot NBBO midpoint print",
              "Extended-hours auction cross"
            ]
          }
        ],
        "statistical_diagnostics": [
          {
            "metric_name": "Getmansky-Lo-Makarov Smoothing Index (xi)",
            "observed_value": 0.76,
            "interpretation": "Mild lag-1 return autocorrelation (rho_1 = 0.24) consistent with liquid swing overnight momentum exposure; PSR_GLM (98.4%) remains statistically significant after unsmoothing.",
            "caveats": [
              "GLM MA(2) unsmoothing assumes locally stationary return innovations.",
              "Reported alongside raw annualized volatility (14.8% raw vs 17.1% GLM unsmoothed)."
            ]
          },
          {
            "metric_name": "Execution Midpoint Slippage Asymmetry",
            "observed_value": -1.4,
            "interpretation": "Mean fill execution realized 1.4 bps adverse to 1-minute VWAP, consistent with realistic institutional limit/marketable-limit order routing.",
            "caveats": [
              "Does not accuse or clear off-exchange internalized flow advantages."
            ]
          }
        ],
        "summary_text": "All 5 canonical ledger sections verified across all enumerated subaccounts; 0 unexplained residuals across 63 trading days."
      },
      "leaf_hash_hex": "14a7738dedb044074317336f74883dcf47ad946b1d7a54fd70012db013121f3b",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "bb91332cf08167a661bbb77a6a98ef7ef6f73d52d7322b02c1c304cc6c6e02b4"
        },
        {
          "side": "left",
          "sibling_hash_hex": "d2ef6863d22fcc70477c903a24fe3246011e2d88d0c611126bcef33ec1a1861e"
        },
        {
          "side": "right",
          "sibling_hash_hex": "4b27c787e36b8c19235e5744ec3f47ef0ebc56f7ca6383302a887717955fa0b2"
        }
      ]
    },
    {
      "leaf_name": "coaching_and_context",
      "salt_hex": "3fefe9150357a434b7355ea0daaa7f5b4c9a1645be5726bbc23278543e6d9cb7",
      "payload": {
        "cost_drag": {
          "commission_and_fee_drag_bps": 14.2,
          "margin_and_funding_drag_bps": 19.8,
          "fx_conversion_drag_bps": 4.1,
          "withholding_tax_drag_bps": 3.4,
          "total_friction_drag_bps": 41.5,
          "annualized_total_drag_bps": 168.0
        },
        "behaviour": {
          "sample_eligible": true,
          "min_trades_gate": 30,
          "observed_trades": 142,
          "observed_days": 63,
          "median_holding_hours": 54.6,
          "holding_horizon_label": "multi_day_institutional_swing",
          "win_rate": 0.563,
          "profit_factor": 2.18,
          "winner_vs_loser_hold_ratio": 2.38,
          "odean_pgr_plr_spread": -0.082,
          "post_drawdown_sizing_discipline_atr": 0.94,
          "atr_normalized": true,
          "return_concentration_top5_pct": 28.4,
          "actionable_improvements": [
            "Overnight margin financing accounts for 47.7% of total friction (19.8 bps in Q1); sweeping idle EUR/CHF balances via FX swap box reduces annualized drag by ~38 bps.",
            "Post-drawdown ATR risk discipline is exemplary (0.94x baseline ATR risk following the Feb -4.62% drawdown), avoiding convex drawdown escalation.",
            "Negative Odean PGR-PLR spread (-0.082) confirms winners are systematically held 2.38x longer than stopped-out losers."
          ]
        },
        "catalyst_regime_win_rate": 0.642,
        "quiet_regime_win_rate": 0.538,
        "event_window_share_pct": 24.6,
        "event_observations": [
          {
            "symbol": "NVDA",
            "trade_timestamp_utc": "2026-02-25T21:24:11Z",
            "earliest_public_utc": "2026-02-25T21:20:04Z",
            "confirmed_public_utc": "2026-02-25T21:21:30Z",
            "event_sources": [
              "SEC EDGAR Form 8-K",
              "BusinessWire Feed"
            ],
            "headline_or_event": "Q4 Fiscal 2026 Earnings Release & Data-Center Guidance",
            "alignment_class": "post_confirmed_catalyst",
            "timestamp_uncertainty_note": "Execution occurred +2m41s after confirmed EDGAR/wire dissemination [21:20:04Z, 21:21:30Z]."
          },
          {
            "symbol": "SAP",
            "trade_timestamp_utc": "2026-01-28T06:01:19Z",
            "earliest_public_utc": "2026-01-28T06:00:00Z",
            "confirmed_public_utc": "2026-01-28T06:03:12Z",
            "event_sources": [
              "EQS Ad-Hoc Disclosure",
              "Consolidated News Aggregator"
            ],
            "headline_or_event": "Cloud Backlog Acceleration & FY26 Operating Profit Outlook",
            "alignment_class": "ambiguous_public_window",
            "timestamp_uncertainty_note": "Trade falls inside I_e = [06:00:00Z, 06:03:12Z] due to ~3m aggregator indexing lag behind primary EQS wire."
          },
          {
            "symbol": "MSFT",
            "trade_timestamp_utc": "2026-03-11T15:10:44Z",
            "earliest_public_utc": null,
            "confirmed_public_utc": null,
            "event_sources": [
              "EODHD Corporate Calendar"
            ],
            "headline_or_event": "No scheduled macro or issuer-specific catalyst within +-24h",
            "alignment_class": "quiet_non_catalyst_regime",
            "timestamp_uncertainty_note": "Classified as quiet regime liquidity execution."
          }
        ],
        "llm_narrative_used": false,
        "llm_model_id": null,
        "style_summary": "Multi-day liquid equity & index-futures swing strategy with disciplined ATR volatility targeting and low disposition bias.",
        "coaching_takeaways": [
          "Positive post-catalyst drift capture (64.2% win rate in confirmed post-release windows vs 53.8% in quiet regimes).",
          "Top-5 winners contribute 28.4% of cumulative TWR \u2014 well-diversified across 142 closed round-trips."
        ],
        "uncertainty_disclosures": [
          "Public news wire timestamps carry +-30s to +-180s ingestion latency across secondary aggregators; catalyst intervals I_e = [t_earliest, t_confirmed] are descriptive context and never imply non-public information."
        ]
      },
      "leaf_hash_hex": "bb91332cf08167a661bbb77a6a98ef7ef6f73d52d7322b02c1c304cc6c6e02b4",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "14a7738dedb044074317336f74883dcf47ad946b1d7a54fd70012db013121f3b"
        },
        {
          "side": "left",
          "sibling_hash_hex": "d2ef6863d22fcc70477c903a24fe3246011e2d88d0c611126bcef33ec1a1861e"
        },
        {
          "side": "right",
          "sibling_hash_hex": "4b27c787e36b8c19235e5744ec3f47ef0ebc56f7ca6383302a887717955fa0b2"
        }
      ]
    },
    {
      "leaf_name": "capital_bracket",
      "salt_hex": "c413418f11e08a07f537c75d2b29e45ff027fbffe50d57e1304b57a281be61b0",
      "payload": {
        "capital_bracket": "bracket_100k_1m",
        "valuation_currency": "USD"
      },
      "leaf_hash_hex": "ee0e7f6f1b908b70f0c8f7bc5a37ca35109cc4bc5f516a9eec7e34d9d0ad5589",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "c4ddee9b2a0888e9d2fab6608a04814db68250af49805657bf094586cd3d225e"
        },
        {
          "side": "right",
          "sibling_hash_hex": "43fe4a1a69ab147764d926f1e8503eaf5e28222fe990eff96b4ac3cdef8033ae"
        },
        {
          "side": "left",
          "sibling_hash_hex": "dd15362a34f61d599e870634c83b775149936f43b402bf5e511840023c328dc7"
        }
      ]
    },
    {
      "leaf_name": "benchmark_alpha",
      "salt_hex": "e0fee08fab652566cb2d3deb094ae3dd471308e00119efd18150a0fab2b70706",
      "payload": {
        "benchmark_symbol": "BTC_BASIS",
        "benchmark_twr_decimal": 0.038,
        "alpha_decimal": 0.1484,
        "information_ratio": 3.12,
        "beta": 0.04
      },
      "leaf_hash_hex": "c4ddee9b2a0888e9d2fab6608a04814db68250af49805657bf094586cd3d225e",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "ee0e7f6f1b908b70f0c8f7bc5a37ca35109cc4bc5f516a9eec7e34d9d0ad5589"
        },
        {
          "side": "right",
          "sibling_hash_hex": "43fe4a1a69ab147764d926f1e8503eaf5e28222fe990eff96b4ac3cdef8033ae"
        },
        {
          "side": "left",
          "sibling_hash_hex": "dd15362a34f61d599e870634c83b775149936f43b402bf5e511840023c328dc7"
        }
      ]
    },
    {
      "leaf_name": "delayed_closed_trades",
      "salt_hex": "8e76078b2a639e26c84ef3f05dfadadeb541b7609d06663a15bb5d0cc18c0d06",
      "payload": {
        "embargo_days": 7,
        "trades": []
      },
      "leaf_hash_hex": "43fe4a1a69ab147764d926f1e8503eaf5e28222fe990eff96b4ac3cdef8033ae",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "19a7e41ab53e552a6fbf88bdb79716696930840239c0fe2b7635b9d0c29bdb44"
        },
        {
          "side": "left",
          "sibling_hash_hex": "dd15362a34f61d599e870634c83b775149936f43b402bf5e511840023c328dc7"
        }
      ]
    }
  ],
  "undisclosed_leaf_hashes": {},
  "witness_attestations": [],
  "broker_native_signature": {
    "broker_id": "prime_custody_ed25519",
    "key_id": "prime-custody-k1",
    "algorithm": "Ed25519",
    "signed_payload_sha256": "d5a3966b021f66757d2846230e1aa242d56f9bab3d4082f79b3e251ed245dc17",
    "signature_hex": "a14c7056619bb072990fdc8e1ea0d868a6c9cbe8df142c4959760a021f99e84b1186dd800df1f426924a42cb28cda5f2e7b955834d8432fbe81e9bb43e36140c"
  },
  "prospective_chain_link": {
    "chain_id": "chain-helvetia-2026",
    "sequence_number": 0,
    "prev_proof_hash": null,
    "blinded_account_tag": "a00361ea2259d5eb75718e7a2c5763532d9a52539f6d04e054d96bb4df1d79e8",
    "enrolled_at_utc": "2026-01-01T02:00:00Z",
    "period_start_utc": "2026-01-01T00:00:00Z",
    "period_end_utc": "2026-03-31T23:59:59Z",
    "issued_at_utc": "2026-04-01T01:20:00Z",
    "cadence_policy": {
      "expected_interval_seconds": 8208000,
      "grace_window_seconds": 172800
    },
    "beginning_index_value": 100.0,
    "ending_index_value": 118.64,
    "period_twr_decimal": 0.1864
  },
  "retention_mode": "no_persistent_storage"
};

export const BUNDLE_RETIRED_HISTORICAL: VerifyProofBundle = {
  "proof_id": "prf-retired-hist-2025",
  "issued_at_utc": "2025-12-31T20:15:00Z",
  "publisher_kid": "n170-pub-2025-h2",
  "publisher_public_key_hex": "01080b646c2f518909f7766c30229aecdfe6894e5c7757f71c828c8ef8841703",
  "broker_id": "kraken",
  "blinded_account_tag": "af5d400a717ecf6beb71e4c5b6bcf69aab7c9cb5cccabe47f36f6a2a8cef0984",
  "account_scope": "all_enumerated_subaccounts",
  "provider_approval_state": "user_key_self_attested",
  "environment_tier": "live_production",
  "claimed_origin_assurance": "operator_retrieved",
  "source_body_sha256": "1b57b7d85342a8e8eec53cc584f08ff87cbe0ad714bd3751e2914d972bc4ad14",
  "period_start_utc": "2025-07-01T00:00:00Z",
  "period_end_utc": "2025-12-31T18:00:00Z",
  "base_currency": "USD",
  "merkle_root": "e99e873fe77426f7858fe8f7339a39198f52badcb0c2193d66fac614a39a4788",
  "signature_hex": "32129378affeb43d20313867f73fcad357e380c2b07e75ca90c81da3f3ce5ccf8018b8c6cb77289e68d30ff3bc55670c13b4b510f58770cdbbd578e43b3ff106",
  "schema_version": "n170-verify-v3",
  "disclosed_leaves": [
    {
      "leaf_name": "core_metrics",
      "salt_hex": "f6d37970fb0da40858b7bd0dc4af06c65d7f9950e32395a6b81b748d9c70da98",
      "payload": {
        "twr_decimal": 0.241,
        "twr_pct": 24.1,
        "cagr_decimal": 0.54,
        "cagr_pct": 54.0,
        "xirr_decimal": 0.532,
        "annualized_volatility": 0.112,
        "smoothing_index_xi": 0.88,
        "lag1_autocorrelation": 0.1,
        "unsmoothed_volatility": 0.121,
        "unsmoothed_sharpe_ratio": 2.3,
        "sharpe_ratio": 2.48,
        "sortino_ratio": 3.61,
        "probabilistic_sharpe_ratio": 0.988,
        "psr_glm_unsmoothed": 0.981,
        "min_track_record_length_periods": 18.0,
        "psr_sample_eligible": true,
        "observation_count": 126,
        "psr_benchmark_sr": 0.0,
        "non_iid_caveat": "PSR accounts for skewness and excess kurtosis under stationary returns; GLM unsmoothing adjusts for first-order serial correlation, and unobserved multi-account selection trials cannot be ruled out without subaccount enumeration.",
        "max_drawdown_decimal": -0.024,
        "max_drawdown_pct": -2.4,
        "skewness": -0.08,
        "excess_kurtosis": 0.52,
        "capital_bracket": "bracket_10k_100k",
        "benchmark_symbol": "DXY",
        "benchmark_twr_decimal": 0.042,
        "alpha_decimal": 0.199,
        "indexed_curve": [
          {
            "timestamp_utc": "2025-07-01T00:00:00Z",
            "index_value": 100.0,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.0
          },
          {
            "timestamp_utc": "2025-09-30T23:59:59Z",
            "index_value": 111.2,
            "drawdown_pct": -2.4,
            "benchmark_index_value": 101.8
          },
          {
            "timestamp_utc": "2025-12-31T18:00:00Z",
            "index_value": 124.1,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.2
          }
        ],
        "methodology": "daily_flow_adjusted_twr_v3",
        "warnings": []
      },
      "leaf_hash_hex": "aec14f55199f147a1a54ea837715bd5d8b55b0e6c31b5d069abaddd32c7a532e",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "af17abeff2b54de5242163b0e9e130dff4f7888f5b703fe18c5e5030baaa0fe2"
        },
        {
          "side": "right",
          "sibling_hash_hex": "a892b6317319f647b58f47205e0da14fd2b48cfe90aaa3d80f656997772bdfdc"
        },
        {
          "side": "right",
          "sibling_hash_hex": "37fd52048aad351f4bf5a624ef7255ce7e601fbccd1926300278003951568399"
        }
      ]
    },
    {
      "leaf_name": "indexed_curve",
      "salt_hex": "df8384f95a00c67f02771cb238eeefd85ece262c8b67dc5208564caa26f8f482",
      "payload": {
        "base_index": 100.0,
        "points": [
          {
            "timestamp_utc": "2025-07-01T00:00:00Z",
            "index_value": 100.0,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 100.0
          },
          {
            "timestamp_utc": "2025-09-30T23:59:59Z",
            "index_value": 111.2,
            "drawdown_pct": -2.4,
            "benchmark_index_value": 101.8
          },
          {
            "timestamp_utc": "2025-12-31T18:00:00Z",
            "index_value": 124.1,
            "drawdown_pct": 0.0,
            "benchmark_index_value": 104.2
          }
        ]
      },
      "leaf_hash_hex": "af17abeff2b54de5242163b0e9e130dff4f7888f5b703fe18c5e5030baaa0fe2",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "aec14f55199f147a1a54ea837715bd5d8b55b0e6c31b5d069abaddd32c7a532e"
        },
        {
          "side": "right",
          "sibling_hash_hex": "a892b6317319f647b58f47205e0da14fd2b48cfe90aaa3d80f656997772bdfdc"
        },
        {
          "side": "right",
          "sibling_hash_hex": "37fd52048aad351f4bf5a624ef7255ce7e601fbccd1926300278003951568399"
        }
      ]
    },
    {
      "leaf_name": "reconciliation",
      "salt_hex": "0c2ab5e1821613e51a4ee6674a8596ac143f17956290a952544f7ed339a8f00c",
      "payload": {
        "status": "reconciled_within_tolerance",
        "reference_provider": "eodhd",
        "ledger_completeness_ok": true,
        "missing_sections": [],
        "checks_evaluated": 184,
        "discrepancy_count": 0,
        "explained_convention_count": 2,
        "findings": [
          {
            "category": "daily_nav_continuity_identity",
            "outcome": "pass",
            "date_or_timestamp": "2026-01-01..2026-03-31",
            "symbol": "PORTFOLIO",
            "expected_value": 141.877,
            "observed_value": 141.878,
            "residual_bps": 0.07,
            "residual_base_currency": null,
            "math_identity": "NAV_t = NAV_{t-1} + Realized_t + Unrealized_t + NetFlows_t - Fees_t",
            "technical_explanation": "All 63 daily valuation intervals reconcile within 0.4 bps tolerance across all enumerated subaccounts.",
            "benign_causes_considered": [
              "Sub-penny multi-currency mark rounding"
            ]
          },
          {
            "category": "fx_t1_settlement_accrual",
            "outcome": "explained_convention",
            "date_or_timestamp": "2026-02-13T17:00:00Z",
            "symbol": "EUR.USD",
            "expected_value": 1.0418,
            "observed_value": 1.0421,
            "residual_bps": 2.88,
            "residual_base_currency": null,
            "math_identity": "Cash_Base(t) = Spot_FX(t) * Settled_Cash + Forward_Accrual(T+1)",
            "technical_explanation": "3 bps transient variance between trade-date and settlement-date FX translation resolved automatically on T+1 settlement.",
            "benign_causes_considered": [
              "WM/Refinitiv 16:00 London fix vs NY 17:00 broker FX mark",
              "T+1 spot FX value-date interest differential"
            ]
          },
          {
            "category": "dividend_ex_date_receivable",
            "outcome": "explained_convention",
            "date_or_timestamp": "2026-03-13T20:00:00Z",
            "symbol": "MSFT",
            "expected_value": 100.0,
            "observed_value": 100.0,
            "residual_bps": 0.0,
            "residual_base_currency": null,
            "math_identity": "NavExDate = SharePrice_Ex * Qty + DividendAccrualReceivable",
            "technical_explanation": "Ex-dividend price drop matched exact ChangeInDividendAccruals entry net of 15% treaty withholding.",
            "benign_causes_considered": [
              "Ex-date vs pay-date accrual accounting"
            ]
          },
          {
            "category": "eodhd_two_stage_fill_envelope",
            "outcome": "pass",
            "date_or_timestamp": "2026-03-24T14:32:18Z",
            "symbol": "NVDA",
            "expected_value": 138.4,
            "observed_value": 138.52,
            "residual_bps": 0.0,
            "residual_base_currency": null,
            "math_identity": "Low_1m(t) - SpreadTol <= FillPrice <= High_1m(t) + SpreadTol",
            "technical_explanation": "184 of 184 equity, ETF, and index futures executions fell strictly inside EODHD Stage-1 daily and Stage-2 1-minute market envelopes.",
            "benign_causes_considered": [
              "Odd-lot NBBO midpoint print",
              "Extended-hours auction cross"
            ]
          }
        ],
        "statistical_diagnostics": [
          {
            "metric_name": "Getmansky-Lo-Makarov Smoothing Index (xi)",
            "observed_value": 0.76,
            "interpretation": "Mild lag-1 return autocorrelation (rho_1 = 0.24) consistent with liquid swing overnight momentum exposure; PSR_GLM (98.4%) remains statistically significant after unsmoothing.",
            "caveats": [
              "GLM MA(2) unsmoothing assumes locally stationary return innovations.",
              "Reported alongside raw annualized volatility (14.8% raw vs 17.1% GLM unsmoothed)."
            ]
          },
          {
            "metric_name": "Execution Midpoint Slippage Asymmetry",
            "observed_value": -1.4,
            "interpretation": "Mean fill execution realized 1.4 bps adverse to 1-minute VWAP, consistent with realistic institutional limit/marketable-limit order routing.",
            "caveats": [
              "Does not accuse or clear off-exchange internalized flow advantages."
            ]
          }
        ],
        "summary_text": "All 5 canonical ledger sections verified across all enumerated subaccounts; 0 unexplained residuals across 63 trading days."
      },
      "leaf_hash_hex": "1b3fb2da72bfeb25100a5a1ada22f578b84c987408fe859e91754ff832233a2f",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "d63802284191cd58e23d9a91c280e8af35a54e49c62d3a60e3216705fed25930"
        },
        {
          "side": "left",
          "sibling_hash_hex": "7b3ee674eeeff60cccd7a9b73a02f1bc728983b015806ef83f2a760a84facdea"
        },
        {
          "side": "right",
          "sibling_hash_hex": "37fd52048aad351f4bf5a624ef7255ce7e601fbccd1926300278003951568399"
        }
      ]
    },
    {
      "leaf_name": "coaching_and_context",
      "salt_hex": "d98ec4aa4594a2b59668f89629636c1e3dcab19f83de795fb71aae8800466284",
      "payload": {
        "cost_drag": {
          "commission_and_fee_drag_bps": 14.2,
          "margin_and_funding_drag_bps": 19.8,
          "fx_conversion_drag_bps": 4.1,
          "withholding_tax_drag_bps": 3.4,
          "total_friction_drag_bps": 41.5,
          "annualized_total_drag_bps": 168.0
        },
        "behaviour": {
          "sample_eligible": true,
          "min_trades_gate": 30,
          "observed_trades": 142,
          "observed_days": 63,
          "median_holding_hours": 54.6,
          "holding_horizon_label": "multi_day_institutional_swing",
          "win_rate": 0.563,
          "profit_factor": 2.18,
          "winner_vs_loser_hold_ratio": 2.38,
          "odean_pgr_plr_spread": -0.082,
          "post_drawdown_sizing_discipline_atr": 0.94,
          "atr_normalized": true,
          "return_concentration_top5_pct": 28.4,
          "actionable_improvements": [
            "Overnight margin financing accounts for 47.7% of total friction (19.8 bps in Q1); sweeping idle EUR/CHF balances via FX swap box reduces annualized drag by ~38 bps.",
            "Post-drawdown ATR risk discipline is exemplary (0.94x baseline ATR risk following the Feb -4.62% drawdown), avoiding convex drawdown escalation.",
            "Negative Odean PGR-PLR spread (-0.082) confirms winners are systematically held 2.38x longer than stopped-out losers."
          ]
        },
        "catalyst_regime_win_rate": 0.642,
        "quiet_regime_win_rate": 0.538,
        "event_window_share_pct": 24.6,
        "event_observations": [
          {
            "symbol": "NVDA",
            "trade_timestamp_utc": "2026-02-25T21:24:11Z",
            "earliest_public_utc": "2026-02-25T21:20:04Z",
            "confirmed_public_utc": "2026-02-25T21:21:30Z",
            "event_sources": [
              "SEC EDGAR Form 8-K",
              "BusinessWire Feed"
            ],
            "headline_or_event": "Q4 Fiscal 2026 Earnings Release & Data-Center Guidance",
            "alignment_class": "post_confirmed_catalyst",
            "timestamp_uncertainty_note": "Execution occurred +2m41s after confirmed EDGAR/wire dissemination [21:20:04Z, 21:21:30Z]."
          },
          {
            "symbol": "SAP",
            "trade_timestamp_utc": "2026-01-28T06:01:19Z",
            "earliest_public_utc": "2026-01-28T06:00:00Z",
            "confirmed_public_utc": "2026-01-28T06:03:12Z",
            "event_sources": [
              "EQS Ad-Hoc Disclosure",
              "Consolidated News Aggregator"
            ],
            "headline_or_event": "Cloud Backlog Acceleration & FY26 Operating Profit Outlook",
            "alignment_class": "ambiguous_public_window",
            "timestamp_uncertainty_note": "Trade falls inside I_e = [06:00:00Z, 06:03:12Z] due to ~3m aggregator indexing lag behind primary EQS wire."
          },
          {
            "symbol": "MSFT",
            "trade_timestamp_utc": "2026-03-11T15:10:44Z",
            "earliest_public_utc": null,
            "confirmed_public_utc": null,
            "event_sources": [
              "EODHD Corporate Calendar"
            ],
            "headline_or_event": "No scheduled macro or issuer-specific catalyst within +-24h",
            "alignment_class": "quiet_non_catalyst_regime",
            "timestamp_uncertainty_note": "Classified as quiet regime liquidity execution."
          }
        ],
        "llm_narrative_used": false,
        "llm_model_id": null,
        "style_summary": "Multi-day liquid equity & index-futures swing strategy with disciplined ATR volatility targeting and low disposition bias.",
        "coaching_takeaways": [
          "Positive post-catalyst drift capture (64.2% win rate in confirmed post-release windows vs 53.8% in quiet regimes).",
          "Top-5 winners contribute 28.4% of cumulative TWR \u2014 well-diversified across 142 closed round-trips."
        ],
        "uncertainty_disclosures": [
          "Public news wire timestamps carry +-30s to +-180s ingestion latency across secondary aggregators; catalyst intervals I_e = [t_earliest, t_confirmed] are descriptive context and never imply non-public information."
        ]
      },
      "leaf_hash_hex": "d63802284191cd58e23d9a91c280e8af35a54e49c62d3a60e3216705fed25930",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "1b3fb2da72bfeb25100a5a1ada22f578b84c987408fe859e91754ff832233a2f"
        },
        {
          "side": "left",
          "sibling_hash_hex": "7b3ee674eeeff60cccd7a9b73a02f1bc728983b015806ef83f2a760a84facdea"
        },
        {
          "side": "right",
          "sibling_hash_hex": "37fd52048aad351f4bf5a624ef7255ce7e601fbccd1926300278003951568399"
        }
      ]
    },
    {
      "leaf_name": "capital_bracket",
      "salt_hex": "e96b4f82ddfaf9a12090b78d4b8020365a7329fc09c2e52a81d7b5b545e321da",
      "payload": {
        "capital_bracket": "bracket_10k_100k",
        "valuation_currency": "USD"
      },
      "leaf_hash_hex": "1aa2048c8edadcda03eefba569ee752ed9b55045e6973d6473dad5a7dbe19cf5",
      "audit_path": [
        {
          "side": "right",
          "sibling_hash_hex": "d223e81ce5ea1be3dc57d2efb6e3894f176713b71e0899499f84caf5b7246c8c"
        },
        {
          "side": "right",
          "sibling_hash_hex": "c066d4e53cc3ad6ea36594c1a1aa40c3d18d7469fed9663acf2f77aa6ac08f81"
        },
        {
          "side": "left",
          "sibling_hash_hex": "de5256cdf0bcbb5b32ae850601b6e8e65f18067aa70caf35fc475e492c533771"
        }
      ]
    },
    {
      "leaf_name": "benchmark_alpha",
      "salt_hex": "85cb2fd1adb6d19823c507082ad6eeed151beb2f890d2788e7413c2ef6442cfd",
      "payload": {
        "benchmark_symbol": "DXY",
        "benchmark_twr_decimal": 0.042,
        "alpha_decimal": 0.199,
        "information_ratio": 2.15,
        "beta": 0.18
      },
      "leaf_hash_hex": "d223e81ce5ea1be3dc57d2efb6e3894f176713b71e0899499f84caf5b7246c8c",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "1aa2048c8edadcda03eefba569ee752ed9b55045e6973d6473dad5a7dbe19cf5"
        },
        {
          "side": "right",
          "sibling_hash_hex": "c066d4e53cc3ad6ea36594c1a1aa40c3d18d7469fed9663acf2f77aa6ac08f81"
        },
        {
          "side": "left",
          "sibling_hash_hex": "de5256cdf0bcbb5b32ae850601b6e8e65f18067aa70caf35fc475e492c533771"
        }
      ]
    },
    {
      "leaf_name": "delayed_closed_trades",
      "salt_hex": "2de62d486a97fbb1e829e509909d988eea898a6feb5bb4cf1ab12c187179c5ef",
      "payload": {
        "embargo_days": 7,
        "trades": []
      },
      "leaf_hash_hex": "c066d4e53cc3ad6ea36594c1a1aa40c3d18d7469fed9663acf2f77aa6ac08f81",
      "audit_path": [
        {
          "side": "left",
          "sibling_hash_hex": "e1c1a47008c1a421ba68db2ac21e0073c75c117b931975923f08d01d8ea273ed"
        },
        {
          "side": "left",
          "sibling_hash_hex": "de5256cdf0bcbb5b32ae850601b6e8e65f18067aa70caf35fc475e492c533771"
        }
      ]
    }
  ],
  "undisclosed_leaf_hashes": {},
  "witness_attestations": [],
  "broker_native_signature": null,
  "prospective_chain_link": {
    "chain_id": "chain-nordic-2025",
    "sequence_number": 0,
    "prev_proof_hash": null,
    "blinded_account_tag": "af5d400a717ecf6beb71e4c5b6bcf69aab7c9cb5cccabe47f36f6a2a8cef0984",
    "enrolled_at_utc": "2025-10-01T00:00:00Z",
    "period_start_utc": "2025-07-01T00:00:00Z",
    "period_end_utc": "2025-12-31T18:00:00Z",
    "issued_at_utc": "2025-12-31T20:15:00Z",
    "cadence_policy": {
      "expected_interval_seconds": 16416000,
      "grace_window_seconds": 172800
    },
    "beginning_index_value": 100.0,
    "ending_index_value": 124.1,
    "period_twr_decimal": 0.241
  },
  "retention_mode": "no_persistent_storage"
};

export const SHOWCASE_PROFILES: ShowcaseProfileMeta[] = [
  {
    proofId: BUNDLE_INSTITUTIONAL_FUND.proof_id,
    handle: "@meridian-systematic",
    strategyTitle: "Meridian Systematic Multi-Asset Master",
    subtitle: "k=3 Org/ASN-Disjoint MPC-TLS Notaries • Prospective Chain #2 • All Sub-Accounts Enumerated",
    assetFocus: "Equities & Index Futures",
    brokerDisplay: "Interactive Brokers (Approved Live Feed)",
    previewMode: "institutional_fund",
    bundle: BUNDLE_INSTITUTIONAL_FUND,
    chainHistory: [BUNDLE_INSTITUTIONAL_SEQ0, BUNDLE_INSTITUTIONAL_SEQ1],
  },
  {
    proofId: BUNDLE_COACHING_STUDIO.proof_id,
    handle: "@apex-momentum-lab",
    strategyTitle: "Apex Discretionary Momentum & Catalyst Studio",
    subtitle: "k=2 Disjoint Notaries • Salted Merkle Redacted Size Tier • Full Odean & ATR Coaching",
    assetFocus: "US Equities Momentum",
    brokerDisplay: "Alpaca Live API (Paper Blocked)",
    previewMode: "coaching_studio",
    bundle: BUNDLE_COACHING_STUDIO,
    fullUnredactedBundle: BUNDLE_COACHING_STUDIO_FULL,
    chainHistory: [],
  },
  {
    proofId: BUNDLE_CUSTODY_SIGNED.proof_id,
    handle: "@helvetia-treasury",
    strategyTitle: "Helvetia Digital Delta-Neutral Basis",
    subtitle: "First-Party Pinned Broker Ed25519 Signature • Prospective Genesis #0 • 0.85% Max DD",
    assetFocus: "Crypto Spot/Perp Basis",
    brokerDisplay: "Prime Custody Native Ed25519",
    previewMode: "custody_feed",
    bundle: BUNDLE_CUSTODY_SIGNED,
    chainHistory: [],
  },
  {
    proofId: BUNDLE_DISCREPANCY_XRAY.proof_id,
    handle: "@swing-xray-audit",
    strategyTitle: "Event-Driven Tech Swing (Discrepancy X-Ray)",
    subtitle: "Single-Notary Dynamic Downgrade • +64.8 bps Missing-Section Residual • T=22 PSR Gate",
    assetFocus: "Equities & Options",
    brokerDisplay: "Interactive Brokers (Flex v3 User Token)",
    previewMode: "discrepancy_xray",
    bundle: BUNDLE_DISCREPANCY_XRAY,
    chainHistory: [],
  },
  {
    proofId: BUNDLE_RETIRED_HISTORICAL.proof_id,
    handle: "@nordic-fx-archive",
    strategyTitle: "Nordic Systematic G10 Carry (2025 H2 Archive)",
    subtitle: "Retired 2025-H2 N170 Key (Valid Window) • >24h Genesis Lag Classified as Backfill",
    assetFocus: "FX & Macro",
    brokerDisplay: "Kraken Read-Only API",
    previewMode: "historical_archive",
    bundle: BUNDLE_RETIRED_HISTORICAL,
    chainHistory: [],
  },
];

export const DEMO_PROOF_ALIASES: Readonly<Record<string, string>> = {
  "demo-tls-alpha": BUNDLE_INSTITUTIONAL_FUND.proof_id,
  "demo-ibkr-flex": BUNDLE_DISCREPANCY_XRAY.proof_id,
  "demo-coaching-studio": BUNDLE_COACHING_STUDIO.proof_id,
  "demo-custody-ed25519": BUNDLE_CUSTODY_SIGNED.proof_id,
  "demo-retired-key": BUNDLE_RETIRED_HISTORICAL.proof_id,
};

export interface ArenaPresetMatchup {
  slugA: string;
  slugB: string;
  label: string;
  tagline: string;
}

export const ARENA_PRESET_MATCHUPS: readonly ArenaPresetMatchup[] = [
  {
    slugA: "demo-tls-alpha",
    slugB: "demo-ibkr-flex",
    label: "k=3 Witnessed TLS Master vs Single-Notary IBKR Flex",
    tagline: "Prospective Chain #2 (T=63) vs Dynamic Downgrade & Missing-Section X-Ray (T=22)",
  },
  {
    slugA: BUNDLE_INSTITUTIONAL_FUND.proof_id,
    slugB: BUNDLE_COACHING_STUDIO.proof_id,
    label: "Meridian Systematic Master vs Apex Momentum Lab",
    tagline: "Full Disclosure >$1M Multi-Asset vs Salted-Redacted Tier US Equities",
  },
  {
    slugA: BUNDLE_CUSTODY_SIGNED.proof_id,
    slugB: BUNDLE_RETIRED_HISTORICAL.proof_id,
    label: "Helvetia Pinned Custody Ed25519 vs Nordic G10 FX Archive",
    tagline: "First-Party Broker Custody Signature vs Retired 2025-H2 Key Backfill",
  },
];

export function findShowcaseProfile(proofId: string): ShowcaseProfileMeta | undefined {
  const canonicalId = DEMO_PROOF_ALIASES[proofId] ?? proofId;
  return SHOWCASE_PROFILES.find((item) => item.proofId === canonicalId);
}
