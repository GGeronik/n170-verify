"""N170 Verify v3 core library — privacy-preserving brokerage performance verification."""

from n170_verify.coaching import (
    TraderCoachingEngine,
    build_trader_coaching_report,
    extract_delayed_closed_trades,
    match_fifo_round_trips,
)
from n170_verify.contracts import (
    AccountScope,
    AssuranceProfile,
    BundleVerificationResult,
    CanonicalPortfolioLedger,
    CapitalBracket,
    ChainContinuityMode,
    EnvironmentTier,
    OriginAssurance,
    PerformanceSummary,
    ProviderApprovalState,
    ReconciliationReport,
    ReconciliationStatus,
    SignerTrustStatus,
    TraderCoachingAndContextReport,
    VERIFY_SCHEMA_VERSION,
    VerifyProofBundle,
    compute_blinded_account_tag,
    create_signed_proof_bundle,
    verify_proof_bundle,
)
from n170_verify.crypto import (
    CANONICAL_LEAF_NAMES,
    PublisherKeyRegistryDocument,
    build_salted_merkle_tree,
    generate_ed25519_keypair,
    jcs_canonicalize,
)
from n170_verify.performance import (
    calculate_portfolio_performance,
    calculate_portfolio_performance_detailed,
    evaluate_econometric_diagnostics,
)
from n170_verify.reconciliation import (
    ReconciliationEngine,
    reconcile_portfolio_ledger,
)
from n170_verify.reference import (
    EodhdReferenceProvider,
    NullReferenceProvider,
    ReferenceDataProvider,
    build_reference_provider,
)

__version__ = "0.3.0"

__all__ = [
    "AccountScope",
    "AssuranceProfile",
    "BundleVerificationResult",
    "CANONICAL_LEAF_NAMES",
    "CanonicalPortfolioLedger",
    "CapitalBracket",
    "ChainContinuityMode",
    "EnvironmentTier",
    "EodhdReferenceProvider",
    "NullReferenceProvider",
    "OriginAssurance",
    "PerformanceSummary",
    "ProviderApprovalState",
    "PublisherKeyRegistryDocument",
    "ReconciliationEngine",
    "ReconciliationReport",
    "ReconciliationStatus",
    "ReferenceDataProvider",
    "SignerTrustStatus",
    "TraderCoachingAndContextReport",
    "TraderCoachingEngine",
    "VERIFY_SCHEMA_VERSION",
    "VerifyProofBundle",
    "__version__",
    "build_reference_provider",
    "build_salted_merkle_tree",
    "build_trader_coaching_report",
    "calculate_portfolio_performance",
    "calculate_portfolio_performance_detailed",
    "compute_blinded_account_tag",
    "create_signed_proof_bundle",
    "evaluate_econometric_diagnostics",
    "extract_delayed_closed_trades",
    "generate_ed25519_keypair",
    "jcs_canonicalize",
    "match_fifo_round_trips",
    "reconcile_portfolio_ledger",
    "verify_proof_bundle",
]
