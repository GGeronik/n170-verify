"""Unified end-to-end verification pipeline for N170 Verify v3.

Orchestrates:
1. Connector or pre-normalized ``CanonicalPortfolioLedger`` ingestion across IBKR Flex
   (offline XML & Web Service v3), IBKR OAuth, Alpaca, Trading 212, Tradier, Charles Schwab,
   read-only crypto exchanges (Binance, Coinbase, Kraken, Bybit), and offline CSV exports
   (DEGIRO EN/NL/DE, Robinhood, Charles Schwab),
2. Optional ``ReferenceDataProvider`` (``EodhdReferenceProvider`` / ``NullReferenceProvider``)
   emitting strictly derived rebased-100 benchmark curves & TWR (zero raw OHLCV bars),
3. Cash- and in-kind-flow-adjusted TWR, CAGR, ACT/365 XIRR, Getmansky-Lo-Makarov AR(1)
   unsmoothing, and sample-gated Probabilistic Sharpe Ratio (``T >= 30``, zero single-account multiple-testing Sharpe deflation),
4. Multi-section ledger completeness & calibrated EODHD market-envelope reconciliation,
5. Friction-waterfall cost drag, behavioural coaching, public catalyst interval context, and
   7-day embargoed closed trade extraction,
6. Salted 7-leaf Merkle tree selective disclosure, Ed25519 signing, and dynamic six-axis
   ``verify_proof_bundle`` evaluation.
"""

from __future__ import annotations

import base64
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
import inspect
import math
from pathlib import Path
import secrets
from statistics import mean, stdev
from typing import Any

from n170_verify.catalysts import (
    CatalystAvailabilityInterval,
    EodhdEconomicEvent,
    EodhdEventsClient,
    EodhdNewsEvent,
    FredAlfredClient,
    GdeltArticleEvent,
    GdeltDocFallbackClient,
    MacroReleaseObservation,
    SecEdgarClient,
    SecEdgarFiling,
)
from n170_verify.coaching import (
    SmallLlmCoachClient,
    TraderCoachingEngine,
    match_fifo_round_trips,
)
from n170_verify.connectors import (
    PaperOrSandboxAccountRejectedError,
    create_connector,
    parse_degiro_csv_bundle,
    parse_ibkr_flex_xml,
    parse_robinhood_csv,
    parse_schwab_csv,
)
from n170_verify.contracts import (
    ALLOWED_RETENTION_MODES,
    BundleVerificationResult,
    CanonicalPortfolioLedger,
    CapitalBracket,
    ContractModelMixin,
    EnvironmentTier,
    IndexedCurvePoint,
    PerformanceSummary,
    ReadOnlyBrokerAdapter,
    ReconciliationReport,
    RedactedClosedTrade,
    TraderCoachingAndContextReport,
    VERIFY_SCHEMA_VERSION,
    VerifyProofBundle,
    compute_blinded_account_tag,
    create_signed_proof_bundle,
    verify_proof_bundle,
)
from n170_verify.crypto import (
    BrokerNativeSignature,
    CANONICAL_LEAF_NAMES,
    ContinuityLogLeaf,
    ProspectiveChainLink,
    PublisherKeyRegistryDocument,
    WitnessAttestation,
    build_salted_merkle_tree,
    generate_ed25519_keypair,
)
from n170_verify.performance import calculate_portfolio_performance_detailed
from n170_verify.reconciliation import reconcile_portfolio_ledger
from n170_verify.reference import (
    ReferenceDataProvider,
    build_reference_provider,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _coerce_source_bytes(source: str | bytes | Path, *, treat_xml: bool = False) -> bytes:
    if isinstance(source, bytes):
        return source
    if isinstance(source, Path):
        return source.read_bytes()
    if isinstance(source, str):
        stripped = source.lstrip()
        if treat_xml and stripped.startswith("<"):
            return source.encode("utf-8")
        if "\n" not in source and "\r" not in source and len(source) < 1024:
            candidate = Path(source)
            if candidate.is_file():
                return candidate.read_bytes()
        return source.encode("utf-8")
    raise TypeError(f"Unsupported statement source type: {type(source).__name__}")


def _detect_csv_format(csv_bytes: bytes, broker_id: str | None, csv_format: str | None) -> str:
    if csv_format:
        norm = csv_format.strip().lower()
        if norm in {"degiro", "degiro_csv"}:
            return "degiro"
        if norm in {"robinhood", "robinhood_csv"}:
            return "robinhood"
        if norm in {"schwab", "schwab_csv"}:
            return "schwab"
        raise ValueError(f"Unsupported csv_format {csv_format!r}; expected degiro, robinhood, or schwab")

    if broker_id:
        bid = broker_id.strip().lower()
        if bid in {"degiro", "degiro_csv"}:
            return "degiro"
        if bid in {"robinhood", "robinhood_csv"}:
            return "robinhood"
        if bid in {"schwab", "schwab_csv"}:
            return "schwab"

    header_sample = csv_bytes[:2048].decode("utf-8-sig", errors="replace").lower()
    if "trans code" in header_sample and "activity date" in header_sample:
        return "robinhood"
    if "fees & comm" in header_sample or ("action" in header_sample and "symbol" in header_sample):
        return "schwab"
    if any(tok in header_sample for tok in ("isin", "mutatie", "änderung", "waehrung", "koers")):
        return "degiro"
    raise ValueError(
        "Unable to infer CSV broker format automatically; specify csv_format='degiro'|'robinhood'|'schwab'"
    )


def _call_adapter_fetch(
    adapter: ReadOnlyBrokerAdapter,
    *,
    blinding_salt_hex: str,
    period_start_utc: str | None,
    period_end_utc: str | None,
    base_currency: str | None,
    extra_fetch_kwargs: Mapping[str, Any] | None = None,
) -> CanonicalPortfolioLedger:
    fetch_fn = getattr(adapter, "fetch_canonical_ledger", None) or getattr(
        adapter, "parse_export", None
    )
    if not callable(fetch_fn):
        raise TypeError(
            f"Connector {type(adapter).__name__} does not implement fetch_canonical_ledger() or parse_export()"
        )

    sig = inspect.signature(fetch_fn)
    params = sig.parameters
    accepts_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())

    call_kwargs: dict[str, Any] = {}
    if "blinding_salt_hex" in params or accepts_var_kw:
        call_kwargs["blinding_salt_hex"] = blinding_salt_hex

    default_start = period_start_utc or "2026-01-01T00:00:00Z"
    default_end = period_end_utc or _utc_now_iso()
    if "period_start_utc" in params:
        call_kwargs["period_start_utc"] = default_start
    if "period_end_utc" in params:
        call_kwargs["period_end_utc"] = default_end
    if base_currency is not None and "base_currency" in params:
        call_kwargs["base_currency"] = base_currency

    if extra_fetch_kwargs:
        for key, value in extra_fetch_kwargs.items():
            if key in params or accepts_var_kw:
                call_kwargs[key] = value

    ledger = fetch_fn(**call_kwargs)
    if not isinstance(ledger, CanonicalPortfolioLedger):
        raise TypeError(
            f"Connector {type(adapter).__name__}.fetch_canonical_ledger() must return CanonicalPortfolioLedger"
        )
    return ledger


def ingest_portfolio_ledger(
    *,
    ledger: CanonicalPortfolioLedger | Mapping[str, Any] | None = None,
    flex_xml: str | bytes | Path | None = None,
    csv_source: str | bytes | Path | None = None,
    csv_format: str | None = None,
    degiro_account_csv: str | bytes | Path | None = None,
    degiro_transactions_csv: str | bytes | Path | None = None,
    degiro_portfolio_csv: str | bytes | Path | None = None,
    connector: ReadOnlyBrokerAdapter | None = None,
    broker_id: str | None = None,
    connector_kwargs: Mapping[str, Any] | None = None,
    connector_fetch_kwargs: Mapping[str, Any] | None = None,
    blinding_salt_hex: str | None = None,
    raw_account_id_override: str | None = None,
    period_start_utc: str | None = None,
    period_end_utc: str | None = None,
    base_currency: str | None = None,
    require_live: bool = True,
) -> CanonicalPortfolioLedger:
    """Normalize supported offline statements or live read-only connectors into ``CanonicalPortfolioLedger``."""
    salt_hex = (blinding_salt_hex or secrets.token_hex(32)).strip().lower()

    resolved_ledger: CanonicalPortfolioLedger | None = None
    if ledger is not None:
        resolved_ledger = (
            ledger
            if isinstance(ledger, CanonicalPortfolioLedger)
            else CanonicalPortfolioLedger.from_dict(ledger)
        )
    elif connector is not None:
        resolved_ledger = _call_adapter_fetch(
            connector,
            blinding_salt_hex=salt_hex,
            period_start_utc=period_start_utc,
            period_end_utc=period_end_utc,
            base_currency=base_currency,
            extra_fetch_kwargs=connector_fetch_kwargs,
        )
    elif flex_xml is not None:
        raw_xml = _coerce_source_bytes(flex_xml, treat_xml=True)
        resolved_ledger = parse_ibkr_flex_xml(
            raw_xml,
            blinding_salt_hex=salt_hex,
            require_live=require_live,
        )
    elif any(
        item is not None
        for item in (csv_source, degiro_account_csv, degiro_transactions_csv, degiro_portfolio_csv)
    ):
        if any(
            item is not None
            for item in (degiro_account_csv, degiro_transactions_csv, degiro_portfolio_csv)
        ):
            resolved_ledger = parse_degiro_csv_bundle(
                account_csv=(
                    _coerce_source_bytes(degiro_account_csv)
                    if degiro_account_csv is not None
                    else None
                ),
                transactions_csv=(
                    _coerce_source_bytes(degiro_transactions_csv)
                    if degiro_transactions_csv is not None
                    else None
                ),
                portfolio_csv=(
                    _coerce_source_bytes(degiro_portfolio_csv)
                    if degiro_portfolio_csv is not None
                    else None
                ),
                blinding_salt_hex=salt_hex,
                base_currency=base_currency or "EUR",
            )
        else:
            assert csv_source is not None
            raw_csv = _coerce_source_bytes(csv_source)
            detected = _detect_csv_format(raw_csv, broker_id, csv_format)
            if detected == "degiro":
                resolved_ledger = parse_degiro_csv_bundle(
                    account_csv=raw_csv,
                    blinding_salt_hex=salt_hex,
                    base_currency=base_currency or "EUR",
                )
            elif detected == "robinhood":
                resolved_ledger = parse_robinhood_csv(raw_csv, blinding_salt_hex=salt_hex)
            else:
                resolved_ledger = parse_schwab_csv(raw_csv, blinding_salt_hex=salt_hex)
    elif broker_id is not None:
        init_kw = dict(connector_kwargs or {})
        norm_bid = broker_id.strip().lower()
        if norm_bid == "ibkr_flex":
            norm_bid = "ibkr_flex_offline"
        elif norm_bid == "degiro":
            norm_bid = "degiro_csv"
        elif norm_bid == "robinhood":
            norm_bid = "robinhood_csv"
        adapter_inst = create_connector(norm_bid, **init_kw)
        resolved_ledger = _call_adapter_fetch(
            adapter_inst,
            blinding_salt_hex=salt_hex,
            period_start_utc=period_start_utc,
            period_end_utc=period_end_utc,
            base_currency=base_currency,
            extra_fetch_kwargs=connector_fetch_kwargs,
        )
    else:
        raise ValueError(
            "verify_portfolio requires one of: ledger, flex_xml, csv_source/degiro_*_csv, "
            "connector, or broker_id + connector_kwargs"
        )

    if require_live and resolved_ledger.environment_tier == EnvironmentTier.PAPER_OR_SANDBOX_REJECTED:
        raise PaperOrSandboxAccountRejectedError(
            f"Paper, demo, or sandbox account rejected for live verification (broker_id={resolved_ledger.broker_id!r})"
        )

    # Apply optional non-secret metadata overrides without mutating original input instance.
    updates: dict[str, Any] = {}
    if broker_id and resolved_ledger.broker_id != broker_id.strip().lower():
        # Preserve canonical broker_id unless caller explicitly aliased e.g. ibkr_flex
        pass
    if raw_account_id_override:
        updates["blinded_account_tag"] = compute_blinded_account_tag(
            resolved_ledger.broker_id,
            raw_account_id_override,
            salt_hex,
        )
    if period_start_utc is not None:
        updates["period_start_utc"] = period_start_utc
    if period_end_utc is not None:
        updates["period_end_utc"] = period_end_utc
    if base_currency is not None:
        updates["base_currency"] = base_currency.strip().upper()

    if updates:
        ledger_dict = resolved_ledger.to_dict()
        ledger_dict.update(updates)
        resolved_ledger = CanonicalPortfolioLedger.from_dict(ledger_dict)

    return resolved_ledger


def _compute_benchmark_beta_and_ir(
    indexed_curve: Sequence[IndexedCurvePoint],
    *,
    periods_per_year: int = 252,
) -> tuple[float | None, float | None]:
    """Derive portfolio beta and annualized information ratio strictly from rebased-100 index points."""
    if len(indexed_curve) < 3:
        return None, None

    port_rets: list[float] = []
    bench_rets: list[float] = []
    for prev_pt, curr_pt in zip(indexed_curve, indexed_curve[1:]):
        if (
            prev_pt.index_value <= 0.0
            or curr_pt.index_value <= 0.0
            or prev_pt.benchmark_index_value is None
            or curr_pt.benchmark_index_value is None
            or prev_pt.benchmark_index_value <= 0.0
            or curr_pt.benchmark_index_value <= 0.0
        ):
            continue
        p_r = (curr_pt.index_value / prev_pt.index_value) - 1.0
        b_r = (curr_pt.benchmark_index_value / prev_pt.benchmark_index_value) - 1.0
        if math.isfinite(p_r) and math.isfinite(b_r):
            port_rets.append(p_r)
            bench_rets.append(b_r)

    if len(port_rets) < 2:
        return None, None

    mean_p = mean(port_rets)
    mean_b = mean(bench_rets)
    var_b = sum((b - mean_b) ** 2 for b in bench_rets) / (len(bench_rets) - 1)
    beta: float | None = None
    if var_b > 1e-16:
        cov_pb = sum((p - mean_p) * (b - mean_b) for p, b in zip(port_rets, bench_rets)) / (
            len(port_rets) - 1
        )
        beta = round(cov_pb / var_b, 6)

    active_rets = [p - b for p, b in zip(port_rets, bench_rets)]
    tracking_err = stdev(active_rets) if len(active_rets) >= 2 else 0.0
    ir: float | None = None
    if tracking_err > 1e-12:
        ir = round((mean(active_rets) / tracking_err) * math.sqrt(periods_per_year), 6)

    return beta, ir


def _redact_reconciliation_for_public_leaf(reconciliation: ReconciliationReport) -> dict[str, Any]:
    """Strip raw base-currency NAV balances from public Merkle reconciliation findings while preserving bps."""
    recon_dict = reconciliation.to_dict()
    sanitized_findings: list[dict[str, Any]] = []
    for raw_f in recon_dict.get("findings", []):
        f_copy = dict(raw_f)
        f_copy["expected_value"] = None
        f_copy["observed_value"] = None
        f_copy["residual_base_currency"] = None
        res_bps = f_copy.get("residual_bps")
        cat = f_copy.get("category")
        outcome = f_copy.get("outcome")
        if isinstance(res_bps, (int, float)):
            if cat == "nav_continuity_bridge":
                f_copy["technical_explanation"] = (
                    f"Period NAV continuity check recorded a residual of {float(res_bps):+.1f} bps "
                    "relative to double-entry ledger conservation (dollar balances redacted)."
                )
            elif cat == "nav_component_identity" and outcome != "pass":
                f_copy["technical_explanation"] = (
                    f"Snapshot NAV component identity recorded a residual of {float(res_bps):+.1f} bps "
                    "relative to Cash + Positions + Accruals (dollar balances redacted)."
                )
            elif cat == "ending_positions_valuation_identity" and outcome != "pass":
                f_copy["technical_explanation"] = (
                    f"Ending positions valuation check recorded a residual of {float(res_bps):+.1f} bps "
                    "relative to sum of open positions (dollar balances redacted)."
                )
            elif cat in {"dividend_accrual_check", "margin_interest_reasonableness", "option_eae_basis_link"} and outcome != "pass":
                f_copy["technical_explanation"] = (
                    f"Reconciliation check ({cat}) recorded a residual of {float(res_bps):+.1f} bps "
                    "(currency amounts redacted)."
                )
        sanitized_findings.append(f_copy)
    recon_dict["findings"] = sanitized_findings
    return recon_dict


def build_canonical_leaf_payloads(
    *,
    performance: PerformanceSummary,
    reconciliation: ReconciliationReport,
    coaching: TraderCoachingAndContextReport,
    delayed_closed_trades: Sequence[RedactedClosedTrade],
    base_currency: str,
    embargo_days: int = 7,
    stripped_recent_closed_trades_count: int = 0,
    periods_per_year: int = 252,
) -> dict[str, Any]:
    """Assemble the 7 canonical Merkle leaf payloads with strict zero-leakage leaf separation."""
    core_dict = performance.to_dict()
    # Keep optional-disclosure fields isolated inside their dedicated salted Merkle leaves
    # so redacting capital_bracket, indexed_curve, or benchmark_alpha leaks zero side-channel data.
    core_dict["capital_bracket"] = None
    core_dict["indexed_curve"] = []
    core_dict["benchmark_symbol"] = None
    core_dict["benchmark_twr_decimal"] = None
    core_dict["alpha_decimal"] = None

    beta, info_ratio = _compute_benchmark_beta_and_ir(
        performance.indexed_curve,
        periods_per_year=periods_per_year,
    )

    bracket_value = (
        performance.capital_bracket.value
        if performance.capital_bracket is not None
        else CapitalBracket.UNDER_1K.value
    )

    return {
        "core_metrics": core_dict,
        "indexed_curve": {
            "base_index": 100.0,
            "points": [pt.to_dict() for pt in performance.indexed_curve],
        },
        "reconciliation": _redact_reconciliation_for_public_leaf(reconciliation),
        "coaching_and_context": coaching.to_dict(),
        "capital_bracket": {
            "capital_bracket": bracket_value,
            "valuation_currency": base_currency.strip().upper(),
        },
        "benchmark_alpha": {
            "benchmark_symbol": performance.benchmark_symbol or "NONE",
            "benchmark_twr_decimal": performance.benchmark_twr_decimal,
            "alpha_decimal": performance.alpha_decimal,
            "information_ratio": info_ratio,
            "beta": beta,
        },
        "delayed_closed_trades": {
            "embargo_days": int(embargo_days),
            "trades": [tr.to_dict() for tr in delayed_closed_trades],
            "stripped_recent_count": int(stripped_recent_closed_trades_count),
        },
    }


@dataclass(slots=True)
class PortfolioVerificationOutput(ContractModelMixin):
    """Privacy-preserving output of ``verify_portfolio`` (zero raw account IDs or dollar NAVs)."""

    proof_bundle: VerifyProofBundle
    verification: BundleVerificationResult
    performance: PerformanceSummary
    reconciliation: ReconciliationReport
    coaching: TraderCoachingAndContextReport
    delayed_closed_trades: list[RedactedClosedTrade] = field(default_factory=list)
    stripped_recent_closed_trades_count: int = 0
    broker_id: str = ""
    blinded_account_tag: str = ""
    base_currency: str = "USD"
    period_start_utc: str = ""
    period_end_utc: str = ""
    source_body_sha256: str = ""
    parser_warnings: list[str] = field(default_factory=list)


def verify_portfolio(
    *,
    ledger: CanonicalPortfolioLedger | Mapping[str, Any] | None = None,
    flex_xml: str | bytes | Path | None = None,
    csv_source: str | bytes | Path | None = None,
    csv_format: str | None = None,
    degiro_account_csv: str | bytes | Path | None = None,
    degiro_transactions_csv: str | bytes | Path | None = None,
    degiro_portfolio_csv: str | bytes | Path | None = None,
    connector: ReadOnlyBrokerAdapter | None = None,
    broker_id: str | None = None,
    connector_kwargs: Mapping[str, Any] | None = None,
    connector_fetch_kwargs: Mapping[str, Any] | None = None,
    blinding_salt_hex: str | None = None,
    raw_account_id_override: str | None = None,
    period_start_utc: str | None = None,
    period_end_utc: str | None = None,
    base_currency: str | None = None,
    require_live: bool = True,
    reference_provider: ReferenceDataProvider | None = None,
    eodhd_api_key: str | None = None,
    benchmark_symbol: str | None = None,
    annual_risk_free_rate: float = 0.0,
    periods_per_year: int = 252,
    cash_flow_timing: str = "end_of_day",
    psr_benchmark_sr: float = 0.0,
    embargo_days: int = 7,
    catalyst_intervals: Sequence[CatalystAvailabilityInterval] | None = None,
    sec_filings: Sequence[SecEdgarFiling] = (),
    eodhd_news: Sequence[EodhdNewsEvent] = (),
    gdelt_articles: Sequence[GdeltArticleEvent] = (),
    eodhd_macro_events: Sequence[EodhdEconomicEvent] = (),
    alfred_macro_releases: Sequence[MacroReleaseObservation] = (),
    eodhd_events_client: EodhdEventsClient | None = None,
    sec_client: SecEdgarClient | None = None,
    fred_client: FredAlfredClient | None = None,
    gdelt_client: GdeltDocFallbackClient | None = None,
    llm_client: SmallLlmCoachClient | None = None,
    enable_llm_narrative: bool = False,
    imported_journal_tags: Sequence[str] | None = None,
    proof_id: str | None = None,
    issued_at_utc: str | None = None,
    publisher_kid: str = "self-hosted-ephemeral",
    publisher_private_key_hex: str | None = None,
    disclose_leaf_names: Iterable[str] | None = None,
    leaf_salts: Mapping[str, str] | None = None,
    witness_attestations: Sequence[WitnessAttestation] = (),
    broker_native_signature: BrokerNativeSignature | None = None,
    prospective_chain_link: ProspectiveChainLink | None = None,
    retention_mode: str = "no_persistent_storage",
    registry_doc: PublisherKeyRegistryDocument | None = None,
    chain_history: Sequence[VerifyProofBundle] | None = None,
    continuity_log_leaves: Sequence[ContinuityLogLeaf] | None = None,
) -> PortfolioVerificationOutput:
    """Execute the full N170 Verify v3 pipeline from statement/connector input to verified proof bundle."""
    if retention_mode not in ALLOWED_RETENTION_MODES:
        raise ValueError(
            f"Invalid retention_mode {retention_mode!r}; expected one of {ALLOWED_RETENTION_MODES}"
        )

    issued_iso = issued_at_utc or _utc_now_iso()
    resolved_proof_id = proof_id or f"prf-{secrets.token_hex(8)}"

    # 1. Ingest & normalize portfolio ledger
    canonical_ledger = ingest_portfolio_ledger(
        ledger=ledger,
        flex_xml=flex_xml,
        csv_source=csv_source,
        csv_format=csv_format,
        degiro_account_csv=degiro_account_csv,
        degiro_transactions_csv=degiro_transactions_csv,
        degiro_portfolio_csv=degiro_portfolio_csv,
        connector=connector,
        broker_id=broker_id,
        connector_kwargs=connector_kwargs,
        connector_fetch_kwargs=connector_fetch_kwargs,
        blinding_salt_hex=blinding_salt_hex,
        raw_account_id_override=raw_account_id_override,
        period_start_utc=period_start_utc,
        period_end_utc=period_end_utc,
        base_currency=base_currency,
        require_live=require_live,
    )

    # 2. Resolve optional market reference provider (EODHD when configured, else NullReferenceProvider)
    ref_provider = (
        reference_provider
        if reference_provider is not None
        else build_reference_provider(api_key=eodhd_api_key)
    )

    # 3. Compute flow-adjusted performance, GLM AR(1) unsmoothing, and sample-gated PSR (T >= 30)
    perf_calc = calculate_portfolio_performance_detailed(
        canonical_ledger,
        reference_provider=ref_provider,
        benchmark_symbol=benchmark_symbol,
        annual_risk_free_rate=annual_risk_free_rate,
        periods_per_year=periods_per_year,
        cash_flow_timing=cash_flow_timing,
        psr_benchmark_sr=psr_benchmark_sr,
    )
    performance_summary = perf_calc.summary

    # 4. Run ledger completeness gate, NAV identity, 2-stage EODHD fill bounds & statistical diagnostics
    reconciliation_report = reconcile_portfolio_ledger(
        canonical_ledger,
        reference_provider=ref_provider,
        performance_summary=performance_summary,
        reference_now_utc=issued_iso,
    )

    # 5. Run friction waterfall, behavioural coaching, catalyst intervals & 7-day delayed closed trades
    all_round_trips = match_fifo_round_trips(canonical_ledger)
    coaching_engine = TraderCoachingEngine(
        llm_client=llm_client,
        eodhd_client=eodhd_events_client,
        sec_client=sec_client,
        fred_client=fred_client,
        gdelt_client=gdelt_client,
        min_trade_disclosure_delay_days=float(embargo_days),
    )
    coaching_out = coaching_engine.evaluate(
        canonical_ledger,
        as_of_utc=issued_iso,
        catalyst_intervals=catalyst_intervals,
        sec_filings=sec_filings,
        eodhd_news=eodhd_news,
        gdelt_articles=gdelt_articles,
        eodhd_macro_events=eodhd_macro_events,
        alfred_macro_releases=alfred_macro_releases,
        enable_llm_narrative=enable_llm_narrative,
        imported_journal_tags=imported_journal_tags,
        max_drawdown_decimal=performance_summary.max_drawdown_decimal,
    )
    delayed_trades = coaching_out.delayed_closed_trades
    stripped_recent_count = max(0, len(all_round_trips) - len(delayed_trades))

    # 6. Build 7 salted Merkle leaves, Ed25519-sign VerifyProofBundle, and run dynamic verifier
    leaf_payloads = build_canonical_leaf_payloads(
        performance=performance_summary,
        reconciliation=reconciliation_report,
        coaching=coaching_out.report,
        delayed_closed_trades=delayed_trades,
        base_currency=canonical_ledger.base_currency,
        embargo_days=embargo_days,
        stripped_recent_closed_trades_count=stripped_recent_count,
        periods_per_year=periods_per_year,
    )
    merkle_tree = build_salted_merkle_tree(leaf_payloads, leaf_salts_hex=leaf_salts)

    signing_priv_hex = (
        publisher_private_key_hex
        if publisher_private_key_hex is not None
        else generate_ed25519_keypair().private_key_hex
    )

    disclose_names = (
        list(CANONICAL_LEAF_NAMES)
        if disclose_leaf_names is None
        else [str(name) for name in disclose_leaf_names]
    )

    bundle = create_signed_proof_bundle(
        proof_id=resolved_proof_id,
        issued_at_utc=issued_iso,
        publisher_kid=publisher_kid,
        publisher_private_key_hex=signing_priv_hex,
        broker_id=canonical_ledger.broker_id,
        blinded_account_tag=canonical_ledger.blinded_account_tag,
        account_scope=canonical_ledger.account_scope,
        provider_approval_state=canonical_ledger.provider_approval_state,
        environment_tier=canonical_ledger.environment_tier,
        claimed_origin_assurance=canonical_ledger.claimed_origin_assurance,
        source_body_sha256=canonical_ledger.source_body_sha256,
        period_start_utc=canonical_ledger.period_start_utc,
        period_end_utc=canonical_ledger.period_end_utc,
        base_currency=canonical_ledger.base_currency,
        merkle_tree=merkle_tree,
        disclose_leaf_names=disclose_names,
        witness_attestations=witness_attestations,
        broker_native_signature=broker_native_signature,
        prospective_chain_link=prospective_chain_link,
        retention_mode=retention_mode,
        schema_version=VERIFY_SCHEMA_VERSION,
    )

    verification_result = verify_proof_bundle(
        bundle,
        registry_doc=registry_doc,
        chain_history=chain_history,
        continuity_log_leaves=continuity_log_leaves,
        now_utc=issued_iso,
    )

    return PortfolioVerificationOutput(
        proof_bundle=bundle,
        verification=verification_result,
        performance=performance_summary,
        reconciliation=reconciliation_report,
        coaching=coaching_out.report,
        delayed_closed_trades=list(delayed_trades),
        stripped_recent_closed_trades_count=stripped_recent_count,
        broker_id=canonical_ledger.broker_id,
        blinded_account_tag=canonical_ledger.blinded_account_tag,
        base_currency=canonical_ledger.base_currency,
        period_start_utc=canonical_ledger.period_start_utc,
        period_end_utc=canonical_ledger.period_end_utc,
        source_body_sha256=canonical_ledger.source_body_sha256,
        parser_warnings=list(canonical_ledger.parser_warnings),
    )


def has_real_pipeline_input(job_payload: Mapping[str, Any]) -> bool:
    """Return True when an API worker job carries real statement, ledger, or connector inputs."""
    if any(
        job_payload.get(key) is not None
        for key in (
            "ledger",
            "flex_xml",
            "flex_xml_b64",
            "csv_source",
            "csv_b64",
            "degiro_account_csv",
            "degiro_transactions_csv",
            "degiro_portfolio_csv",
            "connector_kwargs",
            "connector_credentials",
        )
    ):
        return True

    # Inspect raw_statement_text / raw_statement_b64 when synthetic nav_points/leaf_payloads are absent.
    if job_payload.get("leaf_payloads") is not None or job_payload.get("nav_points") is not None:
        return False

    raw_text = (
        job_payload.get("raw_statement_text")
        if job_payload.get("raw_statement_text") is not None
        else job_payload.get("raw_statement")
    )
    if isinstance(raw_text, str) and raw_text.strip():
        stripped = raw_text.lstrip()
        if stripped.startswith("<"):
            return True
        if job_payload.get("csv_format") or str(job_payload.get("broker_id", "")).lower() in {
            "degiro",
            "degiro_csv",
            "robinhood",
            "robinhood_csv",
            "schwab_csv",
        }:
            return True

    raw_b64 = job_payload.get("raw_statement_b64")
    if isinstance(raw_b64, str) and raw_b64.strip():
        try:
            decoded = base64.b64decode(raw_b64)
        except Exception:
            return False
        probe = decoded[:256].lstrip()
        if probe.startswith(b"<") or job_payload.get("csv_format") or str(
            job_payload.get("broker_id", "")
        ).lower() in {"degiro", "degiro_csv", "robinhood", "robinhood_csv", "schwab_csv"}:
            return True

    return False


def api_worker_pipeline_entrypoint(job_payload: Mapping[str, Any]) -> dict[str, Any]:
    """Top-level picklable entrypoint executed inside the isolated ``spawn`` worker subprocess.

    Accepts raw statement/connector/ledger fields inside ``job_payload``, executes the full
    ``verify_portfolio`` pipeline in-memory, and returns ONLY redacted Merkle commitments
    and metadata so raw statements, account IDs, and dollar NAVs never cross the pipe back
    to the parent API process.
    """
    broker_id = str(job_payload.get("broker_id") or "").strip().lower() or None
    salt_hex = str(job_payload.get("account_blinding_salt_hex") or secrets.token_hex(32))
    issued_at_utc = str(job_payload.get("issued_at_utc") or _utc_now_iso())
    embargo_days = int(job_payload.get("delayed_trade_guard_days", 7))

    period_start = (
        str(job_payload["period_start_utc"])
        if job_payload.get("period_start_utc_explicit") and job_payload.get("period_start_utc")
        else None
    )
    period_end = (
        str(job_payload["period_end_utc"])
        if job_payload.get("period_end_utc_explicit") and job_payload.get("period_end_utc")
        else None
    )
    base_ccy = (
        str(job_payload["base_currency"]).strip().upper()
        if job_payload.get("base_currency_explicit") and job_payload.get("base_currency")
        else None
    )

    flex_xml: bytes | str | None = None
    if job_payload.get("flex_xml_b64"):
        flex_xml = base64.b64decode(str(job_payload["flex_xml_b64"]))
    elif job_payload.get("flex_xml") is not None:
        raw_fx = job_payload["flex_xml"]
        flex_xml = raw_fx if isinstance(raw_fx, bytes) else str(raw_fx).encode("utf-8")

    csv_source: bytes | str | None = None
    if job_payload.get("csv_b64"):
        csv_source = base64.b64decode(str(job_payload["csv_b64"]))
    elif job_payload.get("csv_source") is not None:
        raw_c = job_payload["csv_source"]
        csv_source = raw_c if isinstance(raw_c, bytes) else str(raw_c).encode("utf-8")

    # Support raw_statement / raw_statement_text / raw_statement_b64 when real XML or CSV is submitted
    if flex_xml is None and csv_source is None:
        raw_bytes: bytes | None = None
        if job_payload.get("raw_statement_b64"):
            raw_bytes = base64.b64decode(str(job_payload["raw_statement_b64"]))
        elif isinstance(job_payload.get("raw_statement_text"), str):
            raw_bytes = job_payload["raw_statement_text"].encode("utf-8")
        elif isinstance(job_payload.get("raw_statement"), str):
            raw_bytes = job_payload["raw_statement"].encode("utf-8")
        if raw_bytes is not None:
            if raw_bytes.lstrip().startswith(b"<"):
                flex_xml = raw_bytes
            else:
                csv_source = raw_bytes

    connector_kw = dict(
        job_payload.get("connector_kwargs") or job_payload.get("connector_credentials") or {}
    )
    connector_fetch_kw = dict(job_payload.get("connector_fetch_kwargs") or {})
    if period_start is None and job_payload.get("period_start_utc"):
        connector_fetch_kw.setdefault("period_start_utc", str(job_payload["period_start_utc"]))
    if period_end is None and job_payload.get("period_end_utc"):
        connector_fetch_kw.setdefault("period_end_utc", str(job_payload["period_end_utc"]))

    raw_acct_override = (
        str(job_payload["raw_account_id"]).strip()
        if job_payload.get("raw_account_id")
        else None
    )

    output = verify_portfolio(
        ledger=job_payload.get("ledger"),
        flex_xml=flex_xml,
        csv_source=csv_source,
        csv_format=job_payload.get("csv_format"),
        degiro_account_csv=job_payload.get("degiro_account_csv"),
        degiro_transactions_csv=job_payload.get("degiro_transactions_csv"),
        degiro_portfolio_csv=job_payload.get("degiro_portfolio_csv"),
        broker_id=broker_id,
        connector_kwargs=connector_kw if connector_kw else None,
        connector_fetch_kwargs=connector_fetch_kw if connector_fetch_kw else None,
        blinding_salt_hex=salt_hex,
        raw_account_id_override=raw_acct_override,
        period_start_utc=period_start,
        period_end_utc=period_end,
        base_currency=base_ccy,
        require_live=True,
        eodhd_api_key=job_payload.get("eodhd_api_key"),
        benchmark_symbol=job_payload.get("benchmark_symbol"),
        annual_risk_free_rate=float(job_payload.get("annual_risk_free_rate", 0.0)),
        periods_per_year=int(job_payload.get("periods_per_year", 252)),
        cash_flow_timing=str(job_payload.get("cash_flow_timing", "end_of_day")),
        psr_benchmark_sr=float(job_payload.get("psr_benchmark_sr", 0.0)),
        embargo_days=embargo_days,
        issued_at_utc=issued_at_utc,
        disclose_leaf_names=job_payload.get("disclose_leaf_names"),
        enable_llm_narrative=False,
        imported_journal_tags=job_payload.get("imported_journal_tags"),
    )

    bundle = output.proof_bundle
    resolved_broker_id = broker_id if broker_id else bundle.broker_id
    return {
        "broker_id": resolved_broker_id,
        "blinded_account_tag": bundle.blinded_account_tag,
        "account_scope": bundle.account_scope.value,
        "provider_approval_state": bundle.provider_approval_state.value,
        "environment_tier": bundle.environment_tier.value,
        "claimed_origin_assurance": bundle.claimed_origin_assurance.value,
        "source_body_sha256": bundle.source_body_sha256,
        "period_start_utc": bundle.period_start_utc,
        "period_end_utc": bundle.period_end_utc,
        "base_currency": bundle.base_currency,
        "merkle_root": bundle.merkle_root,
        "disclosed_leaves": [leaf.to_dict() for leaf in bundle.disclosed_leaves],
        "undisclosed_leaf_hashes": dict(bundle.undisclosed_leaf_hashes),
        "stripped_recent_closed_trades_count": output.stripped_recent_closed_trades_count,
    }


__all__ = [
    "PortfolioVerificationOutput",
    "api_worker_pipeline_entrypoint",
    "build_canonical_leaf_payloads",
    "has_real_pipeline_input",
    "ingest_portfolio_ledger",
    "verify_portfolio",
]
