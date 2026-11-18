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
import os
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
    sanitize_journal_tags,
)
from n170_verify.connectors import (
    CONNECTOR_CLASS_MAP,
    PaperOrSandboxAccountRejectedError,
    create_connector,
    parse_degiro_csv_bundle,
    parse_ibkr_flex_xml,
    parse_robinhood_csv,
    parse_schwab_csv,
)
from n170_verify.connectors.statement_csv import detect_and_parse_statement
from n170_verify.contracts import (
    ALLOWED_RETENTION_MODES,
    BundleVerificationResult,
    CanonicalPortfolioLedger,
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
    parse_utc_timestamp,
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


def _coerce_source_bytes(
    source: str | bytes | Path,
    *,
    treat_xml: bool = False,
    allow_filesystem_paths: bool = True,
) -> bytes:
    if isinstance(source, bytes):
        return source
    if isinstance(source, (Path, os.PathLike)):
        if not allow_filesystem_paths:
            raise ValueError("Filesystem path inputs are forbidden in isolated worker mode")
        return Path(source).read_bytes()
    if isinstance(source, str):
        if not allow_filesystem_paths:
            return source.encode("utf-8")
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
    require_live: bool = True,
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

    if period_start_utc is not None:
        if "period_start_utc" in params:
            call_kwargs["period_start_utc"] = period_start_utc
        elif "start_date" in params:
            call_kwargs["start_date"] = period_start_utc
    elif (
        "period_start_utc" in params
        and params["period_start_utc"].default is inspect.Parameter.empty
    ):
        call_kwargs["period_start_utc"] = "2026-01-01T00:00:00Z"

    if period_end_utc is not None:
        if "period_end_utc" in params:
            call_kwargs["period_end_utc"] = period_end_utc
        elif "end_date" in params:
            call_kwargs["end_date"] = period_end_utc
    elif (
        "period_end_utc" in params
        and params["period_end_utc"].default is inspect.Parameter.empty
    ):
        call_kwargs["period_end_utc"] = _utc_now_iso()
    if base_currency is not None and "base_currency" in params:
        call_kwargs["base_currency"] = base_currency
    if "require_live" in params:
        call_kwargs["require_live"] = require_live

    if extra_fetch_kwargs:
        if any(str(key).strip().lower() == "blinding_salt_hex" for key in extra_fetch_kwargs):
            # The account-tag salt is chosen by the operator, never by fetch options.
            raise ValueError("connector_fetch_kwargs may not set blinding_salt_hex")
        for key, value in extra_fetch_kwargs.items():
            if key == "require_live" and require_live:
                continue
            if key in params or accepts_var_kw:
                call_kwargs[key] = value

    ledger = fetch_fn(**call_kwargs)
    if not isinstance(ledger, CanonicalPortfolioLedger):
        raise TypeError(
            f"Connector {type(adapter).__name__}.fetch_canonical_ledger() must return CanonicalPortfolioLedger"
        )
    return ledger


def _activity_inside_scored_span(
    ledger: CanonicalPortfolioLedger, first_ts: str, last_ts: str
) -> dict[str, Any]:
    """Ledger updates that keep only activity inside the span of the scored valuations.

    Activity dated outside the record's period is left out, so no trade, cost or behaviour
    figure describes a time the record does not state. A position opened before the period
    cannot be matched inside it, so every trade in an instrument that also traded before the
    period is left out too.
    """
    start_dt, end_dt = parse_utc_timestamp(first_ts), parse_utc_timestamp(last_ts)

    def _inside(ts: str) -> bool:
        return start_dt <= parse_utc_timestamp(ts) <= end_dt

    def _instrument(t: Any) -> tuple[Any, ...]:
        return (t.symbol.strip().upper(), t.asset_class, t.option_right, t.strike, t.expiry)

    held_into = {
        _instrument(t) for t in ledger.trades if parse_utc_timestamp(t.timestamp_utc) < start_dt
    }
    in_span = [t for t in ledger.trades if _inside(t.timestamp_utc)]
    kept_trades = [t for t in in_span if _instrument(t) not in held_into]
    kept_flows = [f for f in ledger.flows if _inside(f.timestamp_utc)]
    kept_actions = [c for c in ledger.corporate_actions if _inside(c.timestamp_utc)]

    updates: dict[str, Any] = {}
    warnings = list(ledger.parser_warnings)
    if len(kept_trades) != len(ledger.trades):
        updates["trades"] = [t.to_dict() for t in kept_trades]
        if len(kept_trades) != len(in_span):
            dropped = {_instrument(t) for t in in_span} & held_into
            warnings.append(
                f"Trades in {len(dropped)} instrument(s) held into the valuation series from "
                "earlier are not in the ledger, so no round trip is matched against an opening "
                "trade outside the record's period."
            )
        if len(in_span) != len(ledger.trades):
            warnings.append(
                f"{len(ledger.trades) - len(in_span)} trade(s) dated outside the record's period "
                "are not in the ledger."
            )
    if len(kept_flows) != len(ledger.flows):
        updates["flows"] = [f.to_dict() for f in kept_flows]
        warnings.append(
            f"{len(ledger.flows) - len(kept_flows)} cash or transfer flow(s) dated outside the "
            "record's period are not in the ledger."
        )
    if len(kept_actions) != len(ledger.corporate_actions):
        updates["corporate_actions"] = [c.to_dict() for c in kept_actions]
    if warnings != list(ledger.parser_warnings):
        updates["parser_warnings"] = warnings
    return updates


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
    allow_filesystem_paths: bool = True,
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
            require_live=require_live,
            extra_fetch_kwargs=connector_fetch_kwargs,
        )
    elif flex_xml is not None:
        raw_xml = _coerce_source_bytes(
            flex_xml,
            treat_xml=True,
            allow_filesystem_paths=allow_filesystem_paths,
        )
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
                    _coerce_source_bytes(
                        degiro_account_csv, allow_filesystem_paths=allow_filesystem_paths
                    )
                    if degiro_account_csv is not None
                    else None
                ),
                transactions_csv=(
                    _coerce_source_bytes(
                        degiro_transactions_csv, allow_filesystem_paths=allow_filesystem_paths
                    )
                    if degiro_transactions_csv is not None
                    else None
                ),
                portfolio_csv=(
                    _coerce_source_bytes(
                        degiro_portfolio_csv, allow_filesystem_paths=allow_filesystem_paths
                    )
                    if degiro_portfolio_csv is not None
                    else None
                ),
                blinding_salt_hex=salt_hex,
                base_currency=base_currency or "EUR",
            )
        else:
            assert csv_source is not None
            raw_csv = _coerce_source_bytes(
                csv_source, allow_filesystem_paths=allow_filesystem_paths
            )
            norm_cf = (csv_format or "").strip().lower()
            norm_bid_hint = (broker_id or "").strip().lower()
            extended_offline_hints = {
                "mt4",
                "mt4_statement",
                "mt5",
                "mt5_statement",
                "tradovate",
                "tradovate_csv",
                "tradersync",
                "tradersync_journal",
                "tradezella",
                "tradezella_journal",
                "journal_migration",
                "auto_detect",
            }
            if norm_cf in extended_offline_hints or (
                not norm_cf and norm_bid_hint in extended_offline_hints
            ):
                resolved_ledger = detect_and_parse_statement(
                    raw_csv,
                    blinding_salt_hex=salt_hex,
                    base_currency=base_currency or "USD",
                    reject_demo=require_live,
                    require_live=require_live,
                ).ledger
            else:
                try:
                    detected = _detect_csv_format(raw_csv, broker_id, csv_format)
                except ValueError:
                    if norm_cf:
                        raise
                    resolved_ledger = detect_and_parse_statement(
                        raw_csv,
                        blinding_salt_hex=salt_hex,
                        base_currency=base_currency or "USD",
                        reject_demo=require_live,
                        require_live=require_live,
                    ).ledger
                else:
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
        kw_req_live = init_kw.pop("require_live", None)
        effective_req_live = True if require_live else (True if kw_req_live is None else bool(kw_req_live))
        target_cls = CONNECTOR_CLASS_MAP.get(norm_bid)
        if target_cls is not None:
            init_params = inspect.signature(target_cls.__init__).parameters
            if "require_live" in init_params:
                init_kw["require_live"] = effective_req_live
        elif kw_req_live is not None:
            init_kw["require_live"] = effective_req_live
        adapter_inst = create_connector(norm_bid, **init_kw)
        resolved_ledger = _call_adapter_fetch(
            adapter_inst,
            blinding_salt_hex=salt_hex,
            period_start_utc=period_start_utc,
            period_end_utc=period_end_utc,
            base_currency=base_currency,
            require_live=effective_req_live,
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
    # Whenever the ledger has valuations, the signed period is exactly the span of the
    # valuations that are scored, whatever the request or the connector stated. A requested
    # period that would leave out a scored valuation is refused: the caller must supply input
    # for that period instead. A ledger without valuations keeps its stated period.
    if resolved_ledger.nav_points:
        nav_sorted = sorted(
            resolved_ledger.nav_points, key=lambda pt: parse_utc_timestamp(pt.timestamp_utc)
        )
        first_ts, last_ts = nav_sorted[0].timestamp_utc, nav_sorted[-1].timestamp_utc
        if period_start_utc is not None and parse_utc_timestamp(period_start_utc) > parse_utc_timestamp(first_ts):
            raise ValueError(
                f"The requested period starts at {period_start_utc}, after the first scored valuation "
                f"({first_ts}); supply input for the requested period instead"
            )
        if period_end_utc is not None and parse_utc_timestamp(period_end_utc) < parse_utc_timestamp(last_ts):
            raise ValueError(
                f"The requested period ends at {period_end_utc}, before the last scored valuation "
                f"({last_ts}); supply input for the requested period instead"
            )
        if resolved_ledger.period_start_utc != first_ts:
            updates["period_start_utc"] = first_ts
        if resolved_ledger.period_end_utc != last_ts:
            updates["period_end_utc"] = last_ts
        updates.update(_activity_inside_scored_span(resolved_ledger, first_ts, last_ts))
    else:
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
    periods_per_year: float | None = 252,
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
    if tracking_err > 1e-12 and periods_per_year is not None:
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
    periods_per_year: float | None = 252,
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

    # A bracket is signed only when it was measured; otherwise the leaf states null.
    bracket_value = (
        performance.capital_bracket.value
        if performance.capital_bracket is not None
        else None
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
    performance_withheld: bool = False
    withheld_reasons: list[str] = field(default_factory=list)


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
    allow_filesystem_paths: bool = True,
    reference_provider: ReferenceDataProvider | None = None,
    eodhd_api_key: str | None = None,
    benchmark_symbol: str | None = None,
    annual_risk_free_rate: float = 0.0,
    periods_per_year: float | None = None,
    cash_flow_timing: str | None = None,
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
        allow_filesystem_paths=allow_filesystem_paths,
    )

    # 2. Resolve optional market reference provider (EODHD when configured, else NullReferenceProvider)
    ref_provider = (
        reference_provider
        if reference_provider is not None
        else build_reference_provider(api_key=eodhd_api_key)
    )

    # 3. Compute flow-adjusted performance, GLM AR(1) unsmoothing, and sample-gated PSR (T >= 30)
    resolved_cash_flow_timing = (
        cash_flow_timing
        if cash_flow_timing is not None
        else ("modified_dietz" if canonical_ledger.broker_id == "hyperliquid" else "end_of_day")
    )
    perf_calc = calculate_portfolio_performance_detailed(
        canonical_ledger,
        reference_provider=ref_provider,
        benchmark_symbol=benchmark_symbol,
        annual_risk_free_rate=annual_risk_free_rate,
        periods_per_year=periods_per_year,
        cash_flow_timing=resolved_cash_flow_timing,
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
        # Journal tags are cleaned once here, so every route signs the same cleaned tags.
        imported_journal_tags=(
            sanitize_journal_tags(imported_journal_tags)
            if imported_journal_tags is not None
            else None
        ),
        # A withheld return has no drawdown: pass none rather than the 0.0 placeholder.
        max_drawdown_decimal=(
            None if perf_calc.withheld else performance_summary.max_drawdown_decimal
        ),
        scored_period_returns=(
            None
            if perf_calc.withheld
            else [obs.period_return for obs in perf_calc.return_observations]
        ),
        performance_withheld=perf_calc.withheld,
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
        periods_per_year=perf_calc.annualization_periods_per_year,
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
    if perf_calc.withheld and "core_metrics" not in disclose_names:
        # A withheld return is always stated: the leaf carrying the flag cannot be hidden.
        disclose_names.append("core_metrics")

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
        performance_withheld=bool(performance_summary.performance_withheld),
        withheld_reasons=list(performance_summary.withheld_reasons),
    )


_OFFLINE_STATEMENT_BROKER_IDS: frozenset[str] = frozenset(
    {
        "ibkr_flex",
        "ibkr_flex_offline",
        "degiro",
        "degiro_csv",
        "robinhood",
        "robinhood_csv",
        "schwab",
        "schwab_csv",
        "mt4",
        "mt4_statement",
        "mt5",
        "mt5_statement",
        "tradovate",
        "tradovate_csv",
        "tradersync",
        "tradersync_journal",
        "tradezella",
        "tradezella_journal",
        "journal_migration",
        "auto_detect",
    }
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

    norm_broker = str(job_payload.get("broker_id") or "").strip().lower()
    if norm_broker == "hyperliquid":
        for addr_key in ("wallet_address", "address", "user"):
            raw_addr = job_payload.get(addr_key)
            if isinstance(raw_addr, str) and raw_addr.strip():
                return True

    raw_text = (
        job_payload.get("raw_statement_text")
        if job_payload.get("raw_statement_text") is not None
        else job_payload.get("raw_statement")
    )
    if isinstance(raw_text, str) and raw_text.strip():
        stripped = raw_text.lstrip()
        if stripped.startswith("<"):
            return True
        if job_payload.get("csv_format") or norm_broker in _OFFLINE_STATEMENT_BROKER_IDS:
            return True

    raw_b64 = job_payload.get("raw_statement_b64")
    if isinstance(raw_b64, str) and raw_b64.strip():
        try:
            decoded = base64.b64decode(raw_b64)
        except Exception:
            return False
        probe = decoded[:256].lstrip()
        if (
            probe.startswith(b"<")
            or job_payload.get("csv_format")
            or norm_broker in _OFFLINE_STATEMENT_BROKER_IDS
        ):
            return True

    return False


_WORKER_CUSTOM_URL_KEYS: tuple[str, ...] = (
    "base_url",
    "api_url",
    "endpoint",
    "auth_base_url",
    "token_url",
    "api_base_url",
    "flex_base_url",
    "oauth_base_url",
)

_WORKER_STRIPPED_CONNECTOR_KEYS: frozenset[str] = frozenset(
    {
        *_WORKER_CUSTOM_URL_KEYS,
        "transport",
        "http_transport",
        "http_client",
        "message_transport",
        "ccxt_exchange",
        "opener",
        "require_live",
        "env",
        "hosted_mode",
    }
)

_PAPER_OR_SANDBOX_URL_TOKENS: tuple[str, ...] = ("paper", "sandbox", "demo", "testnet")

# The account-tag salt and the queried account identity come from the server and the
# connector credentials; fetch options may only narrow what is read.
_WORKER_SERVER_ONLY_FETCH_KEYS: frozenset[str] = frozenset(
    {"blinding_salt_hex", "wallet_address", "address", "user"}
)


def _coerce_worker_inline_bytes(val: Any, field_name: str) -> bytes | None:
    if val is None:
        return None
    if isinstance(val, (Path, os.PathLike)):
        raise ValueError(f"Filesystem path inputs are forbidden in isolated worker mode ({field_name})")
    if isinstance(val, bytes):
        return val
    if isinstance(val, str):
        return val.encode("utf-8")
    raise TypeError(f"Unsupported {field_name} type in worker payload: {type(val).__name__}")


def _is_forbidden_path_key(key: str) -> bool:
    norm = key.strip().lower()
    return norm in {"path", "file", "source", "csv_source", "flex_xml"} or norm.endswith(
        ("_path", "_file")
    )


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

    for b64_key in ("flex_xml_b64", "csv_b64", "raw_statement_b64", "raw_statement_text", "raw_statement"):
        if isinstance(job_payload.get(b64_key), (Path, os.PathLike)):
            raise ValueError(
                f"Filesystem path inputs are forbidden in isolated worker mode ({b64_key})"
            )

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
    # The currency label comes from the input: the file, or the parser that read it. No
    # request field (base_currency, broker_id) relabels a record.
    base_ccy = None

    flex_xml: bytes | None = None
    if job_payload.get("flex_xml_b64"):
        flex_xml = base64.b64decode(str(job_payload["flex_xml_b64"]))
    elif job_payload.get("flex_xml") is not None:
        flex_xml = _coerce_worker_inline_bytes(job_payload["flex_xml"], "flex_xml")

    csv_source: bytes | None = None
    if job_payload.get("csv_b64"):
        csv_source = base64.b64decode(str(job_payload["csv_b64"]))
    elif job_payload.get("csv_source") is not None:
        csv_source = _coerce_worker_inline_bytes(job_payload["csv_source"], "csv_source")

    degiro_account_bytes = _coerce_worker_inline_bytes(
        job_payload.get("degiro_account_csv"), "degiro_account_csv"
    )
    degiro_tx_bytes = _coerce_worker_inline_bytes(
        job_payload.get("degiro_transactions_csv"), "degiro_transactions_csv"
    )
    degiro_port_bytes = _coerce_worker_inline_bytes(
        job_payload.get("degiro_portfolio_csv"), "degiro_portfolio_csv"
    )

    # Support raw_statement / raw_statement_text / raw_statement_b64 across XML, HTML, and CSV formats
    detected_offline_ledger: CanonicalPortfolioLedger | None = None
    detected_offline_broker_id: str | None = None
    detected_journal_tags: list[str] | None = None
    if flex_xml is None and csv_source is None and job_payload.get("ledger") is None:
        raw_bytes: bytes | None = None
        if job_payload.get("raw_statement_b64"):
            raw_bytes = base64.b64decode(str(job_payload["raw_statement_b64"]))
        elif isinstance(job_payload.get("raw_statement_text"), str):
            raw_bytes = job_payload["raw_statement_text"].encode("utf-8")
        elif isinstance(job_payload.get("raw_statement"), str):
            raw_bytes = job_payload["raw_statement"].encode("utf-8")
        if raw_bytes is not None:
            head_low = raw_bytes[:16384].decode("utf-8-sig", errors="replace").lstrip().lower()
            explicit_cf = str(job_payload.get("csv_format") or "").strip().lower()
            if head_low.startswith("<") and (
                "<flexqueryresponse" in head_low
                or "<flexstatement" in head_low
                or broker_id in {"ibkr_flex", "ibkr_flex_offline"}
            ):
                flex_xml = raw_bytes
            elif not head_low.startswith("<") and explicit_cf in {
                "degiro",
                "degiro_csv",
                "robinhood",
                "robinhood_csv",
            }:
                csv_source = raw_bytes
            else:
                det = detect_and_parse_statement(
                    raw_bytes,
                    blinding_salt_hex=salt_hex,
                    reject_demo=True,
                    require_live=True,
                )
                detected_offline_ledger = det.ledger
                detected_offline_broker_id = det.broker_id
                if det.imported_journal_tags:
                    detected_journal_tags = list(det.imported_journal_tags)

    raw_conn_kw = job_payload.get("connector_kwargs") or job_payload.get("connector_credentials")
    has_connector_input = raw_conn_kw is not None
    connector_kw = dict(raw_conn_kw or {})

    if broker_id == "hyperliquid":
        for addr_key in ("wallet_address", "address", "user"):
            top_addr = job_payload.get(addr_key)
            if top_addr is not None and str(top_addr).strip():
                connector_kw.setdefault("wallet_address", str(top_addr).strip())
                has_connector_input = True
                break

    # Inspect custom URL fields for paper/sandbox/demo/testnet tokens before stripping overrides
    for scope_map in (job_payload, connector_kw):
        for url_key in _WORKER_CUSTOM_URL_KEYS:
            raw_url_val = scope_map.get(url_key)
            if raw_url_val is not None and str(raw_url_val).strip():
                lower_url = str(raw_url_val).strip().lower()
                if any(tok in lower_url for tok in _PAPER_OR_SANDBOX_URL_TOKENS):
                    raise PaperOrSandboxAccountRejectedError(
                        f"Paper, sandbox, demo, or testnet endpoint rejected in {url_key}"
                    )

    for k in list(connector_kw.keys()):
        k_str = str(k)
        v_val = connector_kw[k]
        if isinstance(v_val, (Path, os.PathLike)) or _is_forbidden_path_key(k_str):
            raise ValueError(
                f"Filesystem path inputs are forbidden in isolated worker mode (connector_kwargs.{k_str})"
            )
        if k_str.strip().lower() in _WORKER_STRIPPED_CONNECTOR_KEYS:
            connector_kw.pop(k, None)

    has_offline_or_ledger = any(
        item is not None
        for item in (
            job_payload.get("ledger"),
            detected_offline_ledger,
            flex_xml,
            csv_source,
            degiro_account_bytes,
            degiro_tx_bytes,
            degiro_port_bytes,
        )
    )
    if has_connector_input or (broker_id is not None and not has_offline_or_ledger):
        connector_kw["require_live"] = True

    if broker_id == "hyperliquid" and job_payload.get("_internal_hyperliquid_transport") is not None:
        internal_transport = job_payload["_internal_hyperliquid_transport"]
        if isinstance(internal_transport, str) and ":" in internal_transport:
            import importlib

            mod_name, attr_name = internal_transport.split(":", 1)
            internal_transport = getattr(importlib.import_module(mod_name), attr_name)
        connector_kw["http_transport"] = internal_transport

    if (
        broker_id in {"snaptrade", "snaptrade_relay", "snaptrade_poc"}
        and job_payload.get("_internal_snaptrade_transport") is not None
    ):
        internal_st_transport = job_payload["_internal_snaptrade_transport"]
        if isinstance(internal_st_transport, str) and ":" in internal_st_transport:
            import importlib

            mod_name, attr_name = internal_st_transport.split(":", 1)
            internal_st_transport = getattr(importlib.import_module(mod_name), attr_name)
        connector_kw["http_transport"] = internal_st_transport

    raw_fetch_kw = dict(job_payload.get("connector_fetch_kwargs") or {})
    connector_fetch_kw: dict[str, Any] = {}
    for k, v in raw_fetch_kw.items():
        k_str = str(k)
        if isinstance(v, (Path, os.PathLike)) or _is_forbidden_path_key(k_str):
            raise ValueError(
                f"Filesystem path inputs are forbidden in isolated worker mode (connector_fetch_kwargs.{k_str})"
            )
        if k_str.strip().lower() == "require_live":
            continue
        if k_str.strip().lower() in _WORKER_SERVER_ONLY_FETCH_KEYS:
            raise ValueError(
                f"connector_fetch_kwargs.{k_str} is set by the server, not by fetch options"
            )
        if isinstance(v, (list, tuple)):
            if len(v) > 256 or any(not isinstance(item, (str, int, float, bool)) for item in v):
                raise ValueError(
                    f"Non-primitive sequence value rejected in connector_fetch_kwargs.{k_str}"
                )
            connector_fetch_kw[k_str] = list(v)
            continue
        if v is not None and not isinstance(v, (str, int, float, bool)):
            raise ValueError(
                f"Non-primitive value rejected in connector_fetch_kwargs.{k_str}: {type(v).__name__}"
            )
        connector_fetch_kw[k_str] = v

    if broker_id not in {"hyperliquid", "snaptrade", "snaptrade_relay", "snaptrade_poc"}:
        if period_start is None and job_payload.get("period_start_utc"):
            connector_fetch_kw.setdefault("period_start_utc", str(job_payload["period_start_utc"]))
        if period_end is None and job_payload.get("period_end_utc"):
            connector_fetch_kw.setdefault("period_end_utc", str(job_payload["period_end_utc"]))

    if broker_id in {"hyperliquid", "snaptrade", "snaptrade_relay", "snaptrade_poc"}:
        if job_payload.get("start_date") is not None and str(job_payload["start_date"]).strip():
            connector_fetch_kw.setdefault("start_date", str(job_payload["start_date"]).strip())
        elif period_start is not None:
            connector_fetch_kw.setdefault("start_date", period_start)
        if job_payload.get("end_date") is not None and str(job_payload["end_date"]).strip():
            connector_fetch_kw.setdefault("end_date", str(job_payload["end_date"]).strip())
        elif period_end is not None:
            connector_fetch_kw.setdefault("end_date", period_end)

    raw_acct_override = (
        str(job_payload["raw_account_id"]).strip()
        if job_payload.get("raw_account_id")
        else None
    )
    if raw_acct_override and not has_offline_or_ledger:
        # A live connector derives the account identity from what it reads, not from the request.
        raise ValueError("raw_account_id is not accepted for live connector input")

    explicit_tags = job_payload.get("imported_journal_tags")
    merged_journal_tags: list[str] | None = None
    if explicit_tags is not None or detected_journal_tags is not None:
        merged_journal_tags = []
        for tag_src in (detected_journal_tags or (), explicit_tags or ()):
            for t_val in tag_src:
                t_str = str(t_val).strip()
                if t_str and t_str not in merged_journal_tags:
                    merged_journal_tags.append(t_str)

    output = verify_portfolio(
        ledger=job_payload.get("ledger") if job_payload.get("ledger") is not None else detected_offline_ledger,
        flex_xml=flex_xml,
        csv_source=csv_source,
        csv_format=job_payload.get("csv_format"),
        degiro_account_csv=degiro_account_bytes,
        degiro_transactions_csv=degiro_tx_bytes,
        degiro_portfolio_csv=degiro_port_bytes,
        broker_id=broker_id,
        connector_kwargs=connector_kw if connector_kw else None,
        connector_fetch_kwargs=connector_fetch_kw if connector_fetch_kw else None,
        blinding_salt_hex=salt_hex,
        raw_account_id_override=raw_acct_override,
        period_start_utc=period_start,
        period_end_utc=period_end,
        base_currency=base_ccy,
        require_live=True,
        allow_filesystem_paths=False,
        eodhd_api_key=job_payload.get("eodhd_api_key"),
        benchmark_symbol=job_payload.get("benchmark_symbol"),
        annual_risk_free_rate=float(job_payload.get("annual_risk_free_rate", 0.0)),
        periods_per_year=(
            float(job_payload["periods_per_year"])
            if job_payload.get("periods_per_year") is not None
            else None
        ),
        cash_flow_timing=(
            str(job_payload["cash_flow_timing"])
            if job_payload.get("cash_flow_timing")
            else None
        ),
        psr_benchmark_sr=float(job_payload.get("psr_benchmark_sr", 0.0)),
        embargo_days=embargo_days,
        issued_at_utc=issued_at_utc,
        disclose_leaf_names=job_payload.get("disclose_leaf_names"),
        enable_llm_narrative=False,
        imported_journal_tags=merged_journal_tags,
    )

    bundle = output.proof_bundle
    alias_preserve_pairs = {
        ("ibkr_flex", "ibkr_flex_offline"),
        ("degiro", "degiro_csv"),
        ("robinhood", "robinhood_csv"),
        ("schwab", "schwab_csv"),
        ("mt4", "mt4_statement"),
        ("mt5", "mt5_statement"),
        ("tradovate", "tradovate_csv"),
        ("tradersync", "tradersync_journal"),
        ("tradezella", "tradezella_journal"),
    }
    if detected_offline_broker_id is not None:
        if (broker_id, detected_offline_broker_id) in alias_preserve_pairs and broker_id:
            resolved_broker_id = broker_id
        else:
            resolved_broker_id = detected_offline_broker_id
    elif broker_id in {None, "", "auto_detect", "journal_migration"}:
        resolved_broker_id = bundle.broker_id
    else:
        resolved_broker_id = broker_id
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
        "performance_withheld": output.performance_withheld,
        "withheld_reasons": list(output.withheld_reasons),
    }


__all__ = [
    "PortfolioVerificationOutput",
    "api_worker_pipeline_entrypoint",
    "build_canonical_leaf_payloads",
    "has_real_pipeline_input",
    "ingest_portfolio_ledger",
    "verify_portfolio",
]
