/**
 * N170 Verify v3 — Strict TypeScript Contracts & Cryptographic Constants.
 *
 * Mirrors Wave-1 Python `n170_verify.contracts` and `n170_verify.crypto` 1:1
 * with zero external runtime dependencies so modules execute identically in
 * modern browsers (`crypto.subtle`) and Node.js v25 native TypeScript.
 */

export const VERIFY_SCHEMA_VERSION = "n170-verify-v3" as const;

export const SIGNING_DOMAIN_BUNDLE = "n170.verify.bundle.v3" as const;
export const SIGNING_DOMAIN_CHECKPOINT = "n170.verify.checkpoint.v3" as const;
export const SIGNING_DOMAIN_WITNESS = "n170.verify.witness.v3" as const;
export const SIGNING_DOMAIN_BROKER = "n170.verify.broker.v3" as const;

const UTF8_ENCODER = new TextEncoder();

/** UTF-8 bytes `"n170.verify.leaf.v3\x00"` (20 bytes ending in 0x00). */
export const LEAF_DOMAIN_PREFIX_STR = "n170.verify.leaf.v3\x00" as const;
export const LEAF_DOMAIN_PREFIX: Uint8Array = UTF8_ENCODER.encode(LEAF_DOMAIN_PREFIX_STR);

/** Bytes `"n170.verify.node.v3\x01"` (20 bytes ending in 0x01). */
export const NODE_DOMAIN_PREFIX_STR = "n170.verify.node.v3\x01" as const;
export const NODE_DOMAIN_PREFIX: Uint8Array = UTF8_ENCODER.encode(NODE_DOMAIN_PREFIX_STR);

export const CANONICAL_LEAF_NAMES = [
  "core_metrics",
  "indexed_curve",
  "reconciliation",
  "coaching_and_context",
  "capital_bracket",
  "benchmark_alpha",
  "delayed_closed_trades",
] as const;

export type CanonicalLeafName = (typeof CANONICAL_LEAF_NAMES)[number];

export const REQUIRED_TLSN_PROTOCOL = "tlsn-v0.1.0-alpha.15" as const;
export const REQUIRED_TLS_VERSION = "1.2" as const;
export const DEFAULT_MAX_WITNESS_SKEW_SECONDS = 600 as const;

export const GENESIS_ENROLLMENT_WINDOW_SECONDS = 86_400 as const;
export const INDEX_CONTINUITY_TOLERANCE = 1e-4 as const;

export const ALLOWED_RETENTION_MODES = [
  "no_persistent_storage",
  "opt_in_encrypted_sync",
] as const;

export type RetentionMode = (typeof ALLOWED_RETENTION_MODES)[number];

// ---------------------------------------------------------------------------
// Orthogonal Six-Axis Assurance Enums
// ---------------------------------------------------------------------------

export const OriginAssurance = {
  BROKER_SIGNED: "broker_signed",
  INDEPENDENTLY_WITNESSED_TLS: "independently_witnessed_tls",
  OPERATOR_RETRIEVED: "operator_retrieved",
  SELF_REPORTED: "self_reported",
} as const;
export type OriginAssurance = (typeof OriginAssurance)[keyof typeof OriginAssurance];

export const AccountScope = {
  ALL_ENUMERATED_SUBACCOUNTS: "all_enumerated_subaccounts",
  SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED: "single_account_survivorship_unverified",
  SUBACCOUNT_COMPLETENESS_UNSUPPORTED: "subaccount_completeness_unsupported",
  UNKNOWN_OFFLINE_SCOPE: "unknown_offline_scope",
} as const;
export type AccountScope = (typeof AccountScope)[keyof typeof AccountScope];

export const ProviderApprovalState = {
  APPROVED_LIVE: "approved_live",
  USER_KEY_SELF_ATTESTED: "user_key_self_attested",
  PENDING_PROVIDER_APPROVAL: "pending_provider_approval",
  OFFLINE_EXPORT_ONLY: "offline_export_only",
  AGGREGATOR_RELAYED: "aggregator_relayed",
  PUBLIC_API_PERMISSIONLESS: "public_api_permissionless",
} as const;
export type ProviderApprovalState =
  (typeof ProviderApprovalState)[keyof typeof ProviderApprovalState];

export const EnvironmentTier = {
  LIVE_PRODUCTION: "live_production",
  PAPER_OR_SANDBOX_REJECTED: "paper_or_sandbox_rejected",
  UNVERIFIED_OFFLINE: "unverified_offline",
} as const;
export type EnvironmentTier = (typeof EnvironmentTier)[keyof typeof EnvironmentTier];

export const SignerTrustStatus = {
  OFFICIAL_N170_HOSTED: "official_n170_hosted",
  RETIRED_HISTORICAL_VALID: "retired_historical_valid",
  REVOKED_KEY: "revoked_key",
  UNRECOGNIZED_SELF_HOSTED_SIGNER: "unrecognized_self_hosted_signer",
} as const;
export type SignerTrustStatus = (typeof SignerTrustStatus)[keyof typeof SignerTrustStatus];

export const ChainContinuityMode = {
  PROSPECTIVE_CONTINUOUS: "prospective_continuous",
  RETROSPECTIVE_BACKFILL: "retrospective_backfill",
  UNENROLLED_SINGLE_SNAPSHOT: "unenrolled_single_snapshot",
  CONTINUITY_BROKEN: "continuity_broken",
} as const;
export type ChainContinuityMode =
  (typeof ChainContinuityMode)[keyof typeof ChainContinuityMode];

export interface AssuranceProfile {
  effective_origin_assurance: OriginAssurance;
  account_scope: AccountScope;
  provider_approval_state: ProviderApprovalState;
  environment_tier: EnvironmentTier;
  signer_trust_status: SignerTrustStatus;
  chain_continuity_mode: ChainContinuityMode;
}

// ---------------------------------------------------------------------------
// Witness Quorum, Transcript Commitment & Chain Invariants
// ---------------------------------------------------------------------------

export const TranscriptCommitmentKind = {
  WHOLE_BODY_SHA256: "whole_body_sha256",
  FIXED_64B_PADDED_WINDOW: "fixed_64b_padded_window",
  UNPADDED_VARIABLE_SPAN_REJECTED: "unpadded_variable_span_rejected",
} as const;
export type TranscriptCommitmentKind =
  (typeof TranscriptCommitmentKind)[keyof typeof TranscriptCommitmentKind];

export const ChainInvariantViolationCode = {
  GENESIS_BACKFILL_WINDOW_EXCEEDED: "genesis_backfill_window_exceeded",
  NON_MONOTONIC_SEQUENCE: "non_monotonic_sequence",
  PREV_HASH_MISMATCH: "prev_hash_mismatch",
  CADENCE_POLICY_MUTATED: "cadence_policy_mutated",
  ACCOUNT_CONTINUITY_VIOLATION: "account_continuity_violation",
  MISSED_INTERVAL_DETECTED: "missed_interval_detected",
  STALE_OR_TRUNCATED_TAIL: "stale_or_truncated_tail",
  PARALLEL_CHAIN_RESET_DETECTED: "parallel_chain_reset_detected",
} as const;
export type ChainInvariantViolationCode =
  (typeof ChainInvariantViolationCode)[keyof typeof ChainInvariantViolationCode];

export interface MerkleAuditStep {
  side: "left" | "right";
  sibling_hash_hex: string;
}

export interface DisclosedLeaf<TPayload = unknown> {
  leaf_name: string;
  salt_hex: string;
  payload: TPayload;
  leaf_hash_hex: string;
  audit_path: MerkleAuditStep[];
}

export interface NotaryNodeInfo {
  notary_id: string;
  operator_org: string;
  asn: string;
  public_key_hex: string;
  is_debug_build?: boolean;
  attestation_type?: string;
}

export interface WitnessAttestation {
  protocol: string;
  tls_version: string;
  defer_decryption_from_start: boolean;
  notary_id: string;
  server_sni: string;
  sanitized_request_target: string;
  redacted_headers: string[];
  commitment_kind: TranscriptCommitmentKind;
  response_body_sha256: string;
  session_timestamp_utc: string;
  signature_hex: string;
}

export interface BrokerNativeSignature {
  broker_id: string;
  key_id: string;
  algorithm: string;
  signed_payload_sha256: string;
  signature_hex: string;
}

export interface WitnessQuorumEvaluation {
  effective_origin_assurance: OriginAssurance;
  valid_witness_count: number;
  disjoint_quorum_size: number;
  distinct_org_count: number;
  distinct_asn_count: number;
  broker_signature_valid: boolean;
  downgrade_reasons: string[];
}

export interface ChainCadencePolicy {
  expected_interval_seconds: number;
  grace_window_seconds: number;
}

export interface ProspectiveChainLink {
  chain_id: string;
  sequence_number: number;
  prev_proof_hash: string | null;
  blinded_account_tag: string;
  enrolled_at_utc: string;
  period_start_utc: string;
  period_end_utc: string;
  issued_at_utc: string;
  cadence_policy: ChainCadencePolicy;
  beginning_index_value: number;
  ending_index_value: number;
  period_twr_decimal: number;
}

export interface ContinuityLogLeaf {
  log_index: number;
  chain_id: string;
  blinded_account_tag: string;
  sequence_number: number;
  proof_hash: string;
  logged_at_utc: string;
}

export interface ChainVerificationResult {
  valid: boolean;
  continuity_mode: ChainContinuityMode;
  verified_length: number;
  violation_codes: ChainInvariantViolationCode[];
  details: string[];
}

// ---------------------------------------------------------------------------
// Publisher Registry & C2SP Checkpoint
// ---------------------------------------------------------------------------

export interface PublisherKeyRecord {
  publisher_kid: string;
  public_key_hex: string;
  status: "active" | "retired" | "revoked";
  not_before_utc: string;
  not_after_utc?: string | null;
  revoked_after_utc?: string | null;
  issuer_org?: string;
}

export interface WitnessCheckpointCosignature {
  witness_id: string;
  public_key_hex: string;
  timestamp_utc: string;
  signature_hex: string;
}

export interface C2SPCheckpoint {
  origin: string;
  size: number;
  hash_b64: string;
  publisher_kid: string;
  publisher_signature_hex: string;
  witness_cosignatures: WitnessCheckpointCosignature[];
}

export interface L2BatchAnchor {
  contract_address: string;
  tx_hash: string;
  batch_merkle_root: string;
  chain_id: number;
  block_number?: number | null;
  anchored_at_utc?: string | null;
}

export interface PublisherKeyRegistryDocument {
  updated_at_utc: string;
  keys: PublisherKeyRecord[];
  notaries: NotaryNodeInfo[];
  checkpoint?: C2SPCheckpoint | null;
  l2_anchor?: L2BatchAnchor | null;
  pinned_broker_keys?: Record<string, Record<string, string>>;
  schema_version?: string;
}

// ---------------------------------------------------------------------------
// Performance, Reconciliation & Coaching Leaf Contracts
// ---------------------------------------------------------------------------

export const CapitalBracket = {
  UNDER_1K: "under_1k",
  BRACKET_1K_10K: "bracket_1k_10k",
  BRACKET_10K_100K: "bracket_10k_100k",
  BRACKET_100K_1M: "bracket_100k_1m",
  OVER_1M: "over_1m",
} as const;
export type CapitalBracket = (typeof CapitalBracket)[keyof typeof CapitalBracket];

export interface IndexedCurvePoint {
  timestamp_utc: string;
  index_value: number;
  drawdown_pct: number;
  benchmark_index_value?: number | null;
}

export interface DailyCalendarCell {
  date: string;
  return_pct: number;
  trade_count: number;
}

export interface BootstrapConePoint {
  step: number;
  p05: number;
  p25: number;
  p50: number;
  p75: number;
  p95: number;
}

export interface BootstrapRiskSummary {
  horizon_periods: number;
  num_simulations: number;
  block_length: number;
  prob_drawdown_10pct: number;
  prob_drawdown_20pct: number;
  prob_positive_terminal: number;
  cone: BootstrapConePoint[];
}

export interface ClaimPlausibilityAnalysis {
  claimed_sharpe: number;
  annualization_factor: number;
  observed_periods: number;
  skewness: number;
  excess_kurtosis: number;
  benchmark_sharpe: number;
  implied_psr: number;
  required_min_trl_periods_95pct: number | null;
  sufficiency_tier: string;
  bell_curve_points: { sharpe: number; density: number }[];
  plain_english_summary: string;
}

export interface PerformanceSummary {
  twr_decimal: number;
  twr_pct?: number | null;
  cagr_decimal?: number | null;
  cagr_pct?: number | null;
  xirr_decimal?: number | null;
  annualized_volatility?: number | null;
  smoothing_index_xi?: number | null;
  lag1_autocorrelation?: number | null;
  unsmoothed_volatility?: number | null;
  unsmoothed_sharpe_ratio?: number | null;
  sharpe_ratio?: number | null;
  sortino_ratio?: number | null;
  probabilistic_sharpe_ratio?: number | null;
  psr_glm_unsmoothed?: number | null;
  min_track_record_length_periods?: number | null;
  psr_sample_eligible: boolean;
  observation_count: number;
  psr_benchmark_sr: number;
  non_iid_caveat: string;
  max_drawdown_decimal: number;
  max_drawdown_pct?: number | null;
  skewness?: number | null;
  excess_kurtosis?: number | null;
  capital_bracket?: CapitalBracket | null;
  benchmark_symbol?: string | null;
  benchmark_twr_decimal?: number | null;
  alpha_decimal?: number | null;
  indexed_curve?: IndexedCurvePoint[];
  methodology?: string;
  warnings?: string[];
  daily_calendar_cells?: DailyCalendarCell[];
  bootstrap_summary?: BootstrapRiskSummary | null;
}

export const ReconciliationStatus = {
  RECONCILED_WITHIN_TOLERANCE: "reconciled_within_tolerance",
  UNEXPLAINED_RESIDUAL: "unexplained_residual",
  INSUFFICIENT_SECTIONS: "insufficient_sections",
  REFERENCE_DATA_UNAVAILABLE: "reference_data_unavailable",
} as const;
export type ReconciliationStatus =
  (typeof ReconciliationStatus)[keyof typeof ReconciliationStatus];

export const CheckOutcome = {
  PASS: "pass",
  EXPLAINED_CONVENTION: "explained_convention",
  DISCREPANCY: "discrepancy",
  NOT_EVALUATED: "not_evaluated",
} as const;
export type CheckOutcome = (typeof CheckOutcome)[keyof typeof CheckOutcome];

export interface ReconciliationFinding {
  category: string;
  outcome: CheckOutcome;
  date_or_timestamp: string;
  symbol?: string | null;
  expected_value?: number | null;
  observed_value?: number | null;
  residual_bps?: number | null;
  residual_base_currency?: number | null;
  math_identity: string;
  technical_explanation: string;
  benign_causes_considered: string[];
}

export interface StatisticalDiagnostic {
  metric_name: string;
  observed_value: number | null;
  interpretation: string;
  caveats: string[];
}

export interface ReconciliationReport {
  status: ReconciliationStatus;
  reference_provider: "eodhd" | "none";
  ledger_completeness_ok: boolean;
  missing_sections: string[];
  checks_evaluated: number;
  discrepancy_count: number;
  explained_convention_count: number;
  findings: ReconciliationFinding[];
  statistical_diagnostics: StatisticalDiagnostic[];
  summary_text: string;
}

export const CatalystAlignmentClass = {
  PRIOR_TO_EARLIEST_RECORDED_CATALYST: "prior_to_earliest_recorded_catalyst",
  AMBIGUOUS_PUBLIC_WINDOW: "ambiguous_public_window",
  POST_CONFIRMED_CATALYST: "post_confirmed_catalyst",
  QUIET_NON_CATALYST_REGIME: "quiet_non_catalyst_regime",
} as const;
export type CatalystAlignmentClass =
  (typeof CatalystAlignmentClass)[keyof typeof CatalystAlignmentClass];

export const AssetClass = {
  EQUITY: "equity",
  ETF: "etf",
  OPTION: "option",
  FUTURE: "future",
  FX: "fx",
  CRYPTO_SPOT: "crypto_spot",
  CRYPTO_PERP: "crypto_perp",
  CASH: "cash",
} as const;
export type AssetClass = (typeof AssetClass)[keyof typeof AssetClass];

export interface CostAndDragBreakdown {
  commission_and_fee_drag_bps: number;
  margin_and_funding_drag_bps: number;
  fx_conversion_drag_bps: number;
  withholding_tax_drag_bps: number;
  total_friction_drag_bps: number;
  annualized_total_drag_bps: number;
}

export interface BehaviouralCoachingMetrics {
  sample_eligible: boolean;
  min_trades_gate: number;
  observed_trades: number;
  observed_days: number;
  median_holding_hours?: number | null;
  holding_horizon_label: string;
  win_rate?: number | null;
  profit_factor?: number | null;
  winner_vs_loser_hold_ratio?: number | null;
  odean_pgr_plr_spread?: number | null;
  post_drawdown_sizing_discipline_atr?: number | null;
  atr_normalized: boolean;
  return_concentration_top5_pct?: number | null;
  actionable_improvements: string[];
}

export interface EventWindowObservation {
  symbol: string;
  trade_timestamp_utc: string;
  earliest_public_utc: string | null;
  confirmed_public_utc: string | null;
  event_sources: string[];
  headline_or_event: string;
  alignment_class: CatalystAlignmentClass;
  timestamp_uncertainty_note: string;
}

export const DEFAULT_COUNTERFACTUAL_DISCLAIMER =
  "Hypothetical simulation. Not actual trading results." as const;

export interface SessionExpectancyCell {
  weekday: number;
  hour_utc: number;
  trade_count: number;
  win_rate: number;
  expectancy_bps: number;
}

export interface CounterfactualTwinCurvePoint {
  step: number;
  date?: string;
  timestamp_utc?: string;
  actual: number;
  zero_friction: number;
  disciplined_sizing: number;
  capped_tail_loss: number;
}

export interface CounterfactualTwinReport {
  is_hypothetical_simulation: true;
  compliance_disclaimer: string;
  actual_ending_index: number;
  zero_friction_ending_index: number;
  disciplined_post_dd_sizing_ending_index: number;
  capped_tail_loss_ending_index: number;
  curve_points: CounterfactualTwinCurvePoint[];
}

export interface QuantDnaProfile {
  archetype_label: string;
  consistency_score: number;
  drawdown_resilience_score: number;
  cost_efficiency_score: number;
  sizing_discipline_score: number;
  exit_symmetry_score: number;
  catalyst_alignment_score: number;
}

export interface TraderCoachingAndContextReport {
  cost_drag: CostAndDragBreakdown;
  behaviour: BehaviouralCoachingMetrics;
  catalyst_regime_win_rate?: number | null;
  quiet_regime_win_rate?: number | null;
  event_window_share_pct: number;
  event_observations: EventWindowObservation[];
  llm_narrative_used: boolean;
  llm_model_id?: string | null;
  style_summary: string;
  coaching_takeaways: string[];
  uncertainty_disclosures: string[];
  session_heatmap?: SessionExpectancyCell[];
  counterfactual_twin?: CounterfactualTwinReport | null;
  quant_dna?: QuantDnaProfile | null;
  imported_journal_tags?: string[];
}

export interface RedactedClosedTrade {
  symbol: string;
  asset_class: AssetClass;
  side: "long" | "short" | "buy" | "sell";
  entry_timestamp_utc: string;
  exit_timestamp_utc: string;
  return_pct: number;
  holding_hours: number;
}

export interface CapitalBracketLeafPayload {
  capital_bracket: CapitalBracket;
  valuation_currency: string;
}

export interface BenchmarkAlphaLeafPayload {
  benchmark_symbol: string;
  benchmark_twr_decimal: number | null;
  alpha_decimal: number | null;
  information_ratio?: number | null;
  beta?: number | null;
}

export interface IndexedCurveLeafPayload {
  base_index: number;
  points: IndexedCurvePoint[];
}

export interface DelayedClosedTradesLeafPayload {
  embargo_days: number;
  trades: RedactedClosedTrade[];
}

// ---------------------------------------------------------------------------
// Complete VerifyProofBundle v3 & Verification Outcome
// ---------------------------------------------------------------------------

export interface VerifyProofBundle {
  proof_id: string;
  schema_version: string;
  issued_at_utc: string;
  publisher_kid: string;
  publisher_public_key_hex: string;
  broker_id: string;
  blinded_account_tag: string;
  account_scope: AccountScope;
  provider_approval_state: ProviderApprovalState;
  environment_tier: EnvironmentTier;
  claimed_origin_assurance: OriginAssurance;
  source_body_sha256: string;
  period_start_utc: string;
  period_end_utc: string;
  base_currency: string;
  merkle_root: string;
  disclosed_leaves: DisclosedLeaf[];
  undisclosed_leaf_hashes: Record<string, string>;
  witness_attestations: WitnessAttestation[];
  broker_native_signature: BrokerNativeSignature | null;
  prospective_chain_link: ProspectiveChainLink | null;
  retention_mode: RetentionMode | string;
  signature_hex: string;
}

export interface BundleVerificationResult {
  valid: boolean;
  proof_id: string;
  proof_hash: string;
  signature_valid: boolean;
  merkle_valid: boolean;
  transcript_safety_ok: boolean;
  signer_trust_status: SignerTrustStatus;
  effective_origin_assurance: OriginAssurance;
  effective_chain_continuity_mode: ChainContinuityMode;
  assurance_profile: AssuranceProfile;
  disclosed_leaf_names: string[];
  undisclosed_leaf_names: string[];
  witness_quorum: WitnessQuorumEvaluation;
  chain_verification: ChainVerificationResult | null;
  checkpoint_verified: boolean;
  checkpoint_witness_count: number;
  errors: string[];
  warnings: string[];
}

// ---------------------------------------------------------------------------
// UI Metadata &Typed Leaf Extraction Helpers
// ---------------------------------------------------------------------------

export type BadgeTone = "emerald" | "cyan" | "amber" | "rose" | "slate";

export const ORIGIN_ASSURANCE_META: Record<
  OriginAssurance,
  { label: string; shortLabel: string; tone: BadgeTone; summary: string }
> = {
  broker_signed: {
    label: "Broker-Signed Native Feed",
    shortLabel: "Broker-Signed",
    tone: "emerald",
    summary:
      "First-party Ed25519 signature issued directly by a pinned brokerage custody key over raw statement bytes.",
  },
  independently_witnessed_tls: {
    label: "Independently Witnessed TLS (k>=2 Disjoint Notaries)",
    shortLabel: "Witnessed TLS (k>=2)",
    tone: "emerald",
    summary:
      "Verified MPC-TLS quorum across >=2 organization- and ASN-disjoint production TLSNotary nodes with deferred decryption.",
  },
  operator_retrieved: {
    label: "Operator-Retrieved Live API",
    shortLabel: "Operator-Retrieved",
    tone: "cyan",
    summary:
      "Retrieved directly from live broker API by publisher operator without an independent >=2 disjoint notary quorum.",
  },
  self_reported: {
    label: "Self-Reported / Offline Statement",
    shortLabel: "Self-Reported",
    tone: "amber",
    summary:
      "Offline statement upload, unpinned self-hosted signer, or unverified provenance; origin relies on holder assertion.",
  },
};

export const SIGNER_TRUST_META: Record<
  SignerTrustStatus,
  { label: string; shortLabel: string; tone: BadgeTone; summary: string }
> = {
  official_n170_hosted: {
    label: "Official N170 Key + C2SP Checkpoint",
    shortLabel: "Official + C2SP",
    tone: "emerald",
    summary:
      "Active Ed25519 signing key verified against /.well-known/n170-verify-keys.json and witness-cosigned C2SP tlog-checkpoint.",
  },
  retired_historical_valid: {
    label: "Retired Historical Key (Valid Window)",
    shortLabel: "Retired Valid Key",
    tone: "cyan",
    summary:
      "Bundle was issued inside the active validity window of an officially retired N170 historical signing key.",
  },
  revoked_key: {
    label: "Revoked Signing Key (Rejected)",
    shortLabel: "Revoked Key",
    tone: "rose",
    summary:
      "Signing key has been cryptographically revoked or bundle timestamp falls at/after revocation cutoff.",
  },
  unrecognized_self_hosted_signer: {
    label: "Unrecognized Self-Hosted Key",
    shortLabel: "Self-Hosted Key",
    tone: "amber",
    summary:
      "Valid Ed25519 math or custom key not present in the official N170 registry; treated as self-hosted.",
  },
};

export const RECONCILIATION_STATUS_META: Record<
  ReconciliationStatus,
  { label: string; shortLabel: string; tone: BadgeTone; summary: string }
> = {
  reconciled_within_tolerance: {
    label: "Reconciled Within Tolerance",
    shortLabel: "Reconciled",
    tone: "emerald",
    summary:
      "Period-by-period NAV accounting identities and 2-stage EODHD market execution bounds reconcile within tolerance.",
  },
  unexplained_residual: {
    label: "Unexplained Accounting Residual",
    shortLabel: "Unexplained Residual",
    tone: "amber",
    summary:
      "Mathematical NAV or execution-bound residual exceeds tolerance after evaluating standard settlement conventions.",
  },
  insufficient_sections: {
    label: "Insufficient Non-Cash Sections",
    shortLabel: "Insufficient Sections",
    tone: "amber",
    summary:
      "Statement omits one or more required ledger sections (PriorPeriodPositions, Transfers, CorporateActions, or OptionEAE).",
  },
  reference_data_unavailable: {
    label: "Reference Market Data Unavailable",
    shortLabel: "Ref Data Unavailable",
    tone: "slate",
    summary:
      "Internal ledger identities checked, but external reference price bars were unavailable for one or more symbols.",
  },
};

export const ACCOUNT_SCOPE_META: Record<
  AccountScope,
  { label: string; shortLabel: string; tone: BadgeTone }
> = {
  all_enumerated_subaccounts: {
    label: "All Enumerated Sub-Accounts",
    shortLabel: "All Sub-Accounts",
    tone: "emerald",
  },
  single_account_survivorship_unverified: {
    label: "Single Account (Survivorship Unverified)",
    shortLabel: "Single Account",
    tone: "amber",
  },
  subaccount_completeness_unsupported: {
    label: "Sub-Account Enumeration Unsupported by Broker",
    shortLabel: "Sub-Accounts Unsupported",
    tone: "slate",
  },
  unknown_offline_scope: {
    label: "Unknown Offline Export Scope",
    shortLabel: "Offline Scope",
    tone: "amber",
  },
};

export const CHAIN_CONTINUITY_META: Record<
  ChainContinuityMode,
  { label: string; shortLabel: string; tone: BadgeTone }
> = {
  prospective_continuous: {
    label: "Prospective Continuous Chain",
    shortLabel: "Prospective Chain",
    tone: "emerald",
  },
  retrospective_backfill: {
    label: "Retroactive Backfill (>24h Genesis Lag)",
    shortLabel: "Retroactive Backfill",
    tone: "amber",
  },
  unenrolled_single_snapshot: {
    label: "Unenrolled Single Snapshot",
    shortLabel: "Single Snapshot",
    tone: "slate",
  },
  continuity_broken: {
    label: "Chain Continuity Broken",
    shortLabel: "Continuity Broken",
    tone: "rose",
  },
};

export const CAPITAL_BRACKET_LABELS: Record<CapitalBracket, string> = {
  under_1k: "< $1K USD",
  bracket_1k_10k: "$1K – $10K USD",
  bracket_10k_100k: "$10K – $100K USD",
  bracket_100k_1m: "$100K – $1M USD",
  over_1m: "> $1M USD",
};

export const LEAF_DISPLAY_META: Record<
  CanonicalLeafName,
  { title: string; optional: boolean; description: string }
> = {
  core_metrics: {
    title: "Core Econometrics & PSR",
    optional: false,
    description: "TWR, CAGR, XIRR (ACT/365), GLM unsmoothed volatility, PSR/PSR_GLM, and MinTRL.",
  },
  indexed_curve: {
    title: "Indexed-100 Wealth & Drawdown Curve",
    optional: false,
    description: "Daily flow-adjusted TWR curve strictly rebased to 100.0 (zero dollar NAV leak).",
  },
  reconciliation: {
    title: "Ledger & Market Reconciliation",
    optional: false,
    description: "Period NAV accounting identities, 2-stage fill bounds, and benign-cause checks.",
  },
  coaching_and_context: {
    title: "Coaching, Friction Drag & Catalyst Context",
    optional: false,
    description: "5-part bps drag waterfall, Odean PGR/PLR, ATR drawdown sizing, and catalyst intervals.",
  },
  capital_bracket: {
    title: "Coarse Capital Tier Bracket",
    optional: true,
    description: "Logarithmic USD size tier (e.g. $100K–$1M or >$1M) without exact dollar balances.",
  },
  benchmark_alpha: {
    title: "Benchmark Relative Alpha",
    optional: true,
    description: "Flow-matched benchmark comparison, excess return alpha, and beta.",
  },
  delayed_closed_trades: {
    title: "7-Day Delayed Closed Round-Trips",
    optional: true,
    description: "Percentage-only closed trade round-trips after 7-day embargo (zero share/dollar sizes).",
  },
};

export interface ExtractedBundleLeaves {
  coreMetrics: PerformanceSummary | null;
  indexedCurve: IndexedCurvePoint[];
  reconciliation: ReconciliationReport | null;
  coaching: TraderCoachingAndContextReport | null;
  capitalBracket: CapitalBracket | null;
  benchmarkAlpha: BenchmarkAlphaLeafPayload | null;
  delayedClosedTrades: DelayedClosedTradesLeafPayload | null;
}

export function extractTypedLeaves(bundle: VerifyProofBundle): ExtractedBundleLeaves {
  const map = new Map<string, unknown>();
  for (const leaf of bundle.disclosed_leaves) {
    map.set(leaf.leaf_name, leaf.payload);
  }

  const coreMetrics = (map.get("core_metrics") as PerformanceSummary | undefined) ?? null;

  const rawCurve = map.get("indexed_curve");
  let indexedCurve: IndexedCurvePoint[] = [];
  if (Array.isArray(rawCurve)) {
    indexedCurve = rawCurve as IndexedCurvePoint[];
  } else if (
    rawCurve &&
    typeof rawCurve === "object" &&
    Array.isArray((rawCurve as IndexedCurveLeafPayload).points)
  ) {
    indexedCurve = (rawCurve as IndexedCurveLeafPayload).points;
  } else if (coreMetrics?.indexed_curve?.length) {
    indexedCurve = coreMetrics.indexed_curve;
  }

  const reconciliation = (map.get("reconciliation") as ReconciliationReport | undefined) ?? null;
  const coaching =
    (map.get("coaching_and_context") as TraderCoachingAndContextReport | undefined) ?? null;

  const rawBracket = map.get("capital_bracket");
  let capitalBracket: CapitalBracket | null = null;
  if (typeof rawBracket === "string") {
    capitalBracket = rawBracket as CapitalBracket;
  } else if (
    rawBracket &&
    typeof rawBracket === "object" &&
    typeof (rawBracket as CapitalBracketLeafPayload).capital_bracket === "string"
  ) {
    capitalBracket = (rawBracket as CapitalBracketLeafPayload).capital_bracket;
  } else if (coreMetrics?.capital_bracket) {
    capitalBracket = coreMetrics.capital_bracket;
  }

  const benchmarkAlpha =
    (map.get("benchmark_alpha") as BenchmarkAlphaLeafPayload | undefined) ?? null;

  const rawTrades = map.get("delayed_closed_trades");
  let delayedClosedTrades: DelayedClosedTradesLeafPayload | null = null;
  if (Array.isArray(rawTrades)) {
    delayedClosedTrades = { embargo_days: 7, trades: rawTrades as RedactedClosedTrade[] };
  } else if (
    rawTrades &&
    typeof rawTrades === "object" &&
    Array.isArray((rawTrades as DelayedClosedTradesLeafPayload).trades)
  ) {
    delayedClosedTrades = rawTrades as DelayedClosedTradesLeafPayload;
  }

  return {
    coreMetrics,
    indexedCurve,
    reconciliation,
    coaching,
    capitalBracket,
    benchmarkAlpha,
    delayedClosedTrades,
  };
}
