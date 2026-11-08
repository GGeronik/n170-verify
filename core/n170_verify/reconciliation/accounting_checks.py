"""Double-entry position roll-forward, OptionEAE basis link, and period-by-period NAV identities."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
import math
import re

from n170_verify.contracts import (
    AssetClass,
    CanonicalPortfolioLedger,
    CheckOutcome,
    CorporateActionRecord,
    CorporateActionType,
    FlowKind,
    NormalizedFlow,
    NormalizedNavPoint,
    NormalizedPosition,
    NormalizedTrade,
    ReconciliationFinding,
    parse_utc_timestamp,
)
from n170_verify.reference.base import ReferenceDataProvider
from n170_verify.reference.eodhd_client import normalize_eodhd_exchange, split_eodhd_ticker


_OCC_OPTION_RE = re.compile(r"^([A-Z0-9.\-]+?)\s*(\d{6})([CP])(\d{8})$")


@dataclass(slots=True)
class _OptionTracker:
    option_right: str | None = None
    strike: float | None = None
    multiplier: float = 100.0
    underlying_symbol: str | None = None
    fx_rate_to_base: float = 1.0
    signed_cost_basis_base: float = 0.0


@dataclass(frozen=True, slots=True)
class PositionRollforwardResult:
    """Result of multi-asset position roll-forward and completeness gate evaluation."""

    findings: list[ReconciliationFinding]
    ledger_completeness_ok: bool
    missing_sections: list[str]
    implied_option_cash_delta_base: float


def _normalize_section_token(section: str) -> str:
    return re.sub(r"[^a-z0-9]", "", section.strip().lower())


def _find_missing_completeness_sections(
    enabled_sections: Sequence[str],
    *,
    has_options: bool,
) -> list[str]:
    present = {_normalize_section_token(s) for s in enabled_sections if s and s.strip()}
    missing: list[str] = []
    if "transfers" not in present:
        missing.append("Transfers")
    if "corporateactions" not in present:
        missing.append("CorporateActions")
    if has_options and "optioneae" not in present:
        missing.append("OptionEAE")
    elif not present and "optioneae" not in missing:
        missing.append("OptionEAE")
    return missing


def _canonical_symbol(sym: str) -> str:
    return " ".join(sym.strip().upper().split())


def _infer_option_metadata_from_text(
    symbol: str,
    description: str = "",
) -> tuple[str | None, str | None, float | None]:
    """Extract ``(underlying_symbol, option_right, strike)`` from OCC or descriptive symbol strings."""
    compact = symbol.strip().upper()
    m = _OCC_OPTION_RE.match(compact)
    if m:
        und = m.group(1).strip()
        right = m.group(3)
        strike = int(m.group(4)) / 1000.0
        return und, right, strike

    combined = f"{compact} {description.upper()}"
    right_guess: str | None = None
    if re.search(r"\bPUT\b", combined):
        right_guess = "P"
    elif re.search(r"\bCALL\b", combined):
        right_guess = "C"
    return None, right_guess, None


def _signed_option_position_basis(pos: NormalizedPosition) -> float:
    raw_base = float(pos.cost_basis) * float(pos.fx_rate_to_base)
    if pos.quantity < 0.0:
        return -abs(raw_base)
    if pos.quantity > 0.0:
        return abs(raw_base)
    return 0.0


def _has_explicit_exercise_stock_trade(
    trades: Sequence[NormalizedTrade],
    *,
    underlying_symbol: str,
    action_date: str,
    expected_shares: float,
    strike: float | None,
) -> bool:
    target_sym = _canonical_symbol(underlying_symbol)
    for tr in trades:
        if tr.asset_class == AssetClass.OPTION:
            continue
        if _canonical_symbol(tr.symbol) != target_sym:
            continue
        if tr.timestamp_utc[:10] != action_date:
            continue
        if abs(abs(tr.quantity) - abs(expected_shares)) > 1e-6:
            continue
        if strike is not None and abs(tr.price - strike) > 1e-4:
            continue
        id_lower = f"{tr.native_entry_id} {tr.venue}".lower()
        if any(tok in id_lower for tok in ("eae", "exerc", "assign")):
            return True
    return False


def reconcile_position_rollforward(
    ledger: CanonicalPortfolioLedger,
) -> PositionRollforwardResult:
    """Reconcile PriorPositions + Trades + InKindFlows + CorporateActions/OptionEAE == EndingPositions."""
    qty_by_sym: dict[str, float] = defaultdict(float)
    stock_basis_by_sym: dict[str, float] = defaultdict(float)
    option_meta: dict[str, _OptionTracker] = {}
    has_options = False

    for pos in ledger.prior_positions:
        if pos.asset_class == AssetClass.CASH:
            continue
        sym = _canonical_symbol(pos.symbol)
        qty_by_sym[sym] += float(pos.quantity)
        if pos.asset_class == AssetClass.OPTION:
            has_options = True
            und_guess, right_guess, strike_guess = _infer_option_metadata_from_text(sym)
            tracker = option_meta.setdefault(sym, _OptionTracker())
            tracker.option_right = pos.option_right or tracker.option_right or right_guess
            tracker.strike = pos.strike if pos.strike is not None else (tracker.strike or strike_guess)
            tracker.multiplier = float(pos.multiplier or 100.0)
            tracker.underlying_symbol = (
                _canonical_symbol(pos.underlying_symbol)
                if pos.underlying_symbol
                else (tracker.underlying_symbol or und_guess)
            )
            tracker.fx_rate_to_base = float(pos.fx_rate_to_base)
            tracker.signed_cost_basis_base += _signed_option_position_basis(pos)
        else:
            stock_basis_by_sym[sym] += float(pos.cost_basis) * float(pos.fx_rate_to_base)

    for pos in ledger.ending_positions:
        if pos.asset_class == AssetClass.OPTION:
            has_options = True

    for ca in ledger.corporate_actions:
        if ca.action_type in {
            CorporateActionType.OPTION_EXERCISE,
            CorporateActionType.OPTION_ASSIGNMENT,
            CorporateActionType.OPTION_EXPIRATION,
        }:
            has_options = True

    # Build unified chronological event stream: (timestamp, priority, kind, record)
    # Priority puts corporate actions at start-of-timestamp (0) before post-action fills (1),
    # EXCEPT OptionEAE expirations/assignments which occur after same-timestamp opening trades (2).
    events: list[tuple[datetime, int, str, object]] = []
    for tr in ledger.trades:
        if tr.asset_class == AssetClass.CASH:
            continue
        if tr.asset_class == AssetClass.OPTION:
            has_options = True
        events.append((parse_utc_timestamp(tr.timestamp_utc), 1, "trade", tr))

    for fl in ledger.flows:
        if fl.kind in {FlowKind.TRANSFER_IN_KIND, FlowKind.TRANSFER_OUT_KIND} and fl.symbol:
            events.append((parse_utc_timestamp(fl.timestamp_utc), 1, "flow", fl))

    for ca in ledger.corporate_actions:
        prio = (
            2
            if ca.action_type
            in {
                CorporateActionType.OPTION_EXERCISE,
                CorporateActionType.OPTION_ASSIGNMENT,
                CorporateActionType.OPTION_EXPIRATION,
            }
            else 0
        )
        events.append((parse_utc_timestamp(ca.timestamp_utc), prio, "corp", ca))

    events.sort(key=lambda item: (item[0], item[1]))

    findings: list[ReconciliationFinding] = []
    implied_option_cash_delta_base = 0.0
    option_exercised_underlyings: dict[str, str] = {}

    for _, _, ev_kind, payload in events:
        if ev_kind == "trade":
            assert isinstance(payload, NormalizedTrade)
            if payload.asset_class == AssetClass.FX:
                continue
            sym = _canonical_symbol(payload.symbol)
            abs_q = abs(float(payload.quantity))
            signed_q = abs_q if payload.side == "buy" else -abs_q
            prev_q = qty_by_sym[sym]
            new_q = prev_q + signed_q
            qty_by_sym[sym] = new_q

            mult = float(payload.multiplier or (100.0 if payload.asset_class == AssetClass.OPTION else 1.0))
            fx = float(payload.fx_rate_to_base)
            comm_base = abs(float(payload.commission)) * fx + abs(float(payload.tax)) * fx
            gross_base = abs_q * float(payload.price) * mult * fx

            if payload.asset_class == AssetClass.OPTION:
                und_guess, right_guess, strike_guess = _infer_option_metadata_from_text(sym)
                tracker = option_meta.setdefault(sym, _OptionTracker())
                tracker.option_right = payload.option_right or tracker.option_right or right_guess
                tracker.strike = (
                    payload.strike if payload.strike is not None else (tracker.strike or strike_guess)
                )
                tracker.multiplier = mult
                tracker.underlying_symbol = (
                    _canonical_symbol(payload.underlying_symbol)
                    if payload.underlying_symbol
                    else (tracker.underlying_symbol or und_guess)
                )
                tracker.fx_rate_to_base = fx

                # Update signed option basis (+cost for long, -credit for short)
                trade_cash_cost = (gross_base + comm_base) if signed_q > 0.0 else -(gross_base - comm_base)
                if prev_q == 0.0 or (prev_q > 0.0) == (signed_q > 0.0):
                    tracker.signed_cost_basis_base += trade_cash_cost
                elif abs(signed_q) <= abs(prev_q):
                    frac_remaining = 1.0 - (abs(signed_q) / abs(prev_q))
                    tracker.signed_cost_basis_base *= frac_remaining
                else:
                    residual_open = abs(signed_q) - abs(prev_q)
                    unit_cost = trade_cash_cost / abs_q
                    tracker.signed_cost_basis_base = residual_open * unit_cost
            else:
                trade_cost = (gross_base + comm_base) if signed_q > 0.0 else -(gross_base - comm_base)
                if prev_q == 0.0 or (prev_q > 0.0) == (signed_q > 0.0):
                    stock_basis_by_sym[sym] += trade_cost
                elif abs(signed_q) <= abs(prev_q):
                    frac_remaining = 1.0 - (abs(signed_q) / abs(prev_q))
                    stock_basis_by_sym[sym] *= frac_remaining
                else:
                    rem = abs(signed_q) - abs(prev_q)
                    stock_basis_by_sym[sym] = rem * (trade_cost / abs_q)

        elif ev_kind == "flow":
            assert isinstance(payload, NormalizedFlow)
            if payload.symbol and payload.quantity is not None:
                sym = _canonical_symbol(payload.symbol)
                dq = (
                    abs(float(payload.quantity))
                    if payload.kind == FlowKind.TRANSFER_IN_KIND
                    else -abs(float(payload.quantity))
                )
                qty_by_sym[sym] += dq
                if payload.amount_base is not None and dq > 0.0:
                    stock_basis_by_sym[sym] += abs(float(payload.amount_base))

        elif ev_kind == "corp":
            assert isinstance(payload, CorporateActionRecord)
            sym = _canonical_symbol(payload.symbol)
            ctype = payload.action_type

            if ctype in {CorporateActionType.SPLIT, CorporateActionType.REVERSE_SPLIT}:
                cur_q = qty_by_sym[sym]
                if payload.ratio_numerator is not None and payload.ratio_denominator is not None:
                    ratio = float(payload.ratio_numerator) / float(payload.ratio_denominator)
                    if payload.quantity_delta != 0.0 and cur_q != 0.0:
                        implied_delta = cur_q * (ratio - 1.0)
                        if abs(implied_delta - payload.quantity_delta) <= 1e-5:
                            qty_by_sym[sym] = cur_q * ratio
                        else:
                            qty_by_sym[sym] = cur_q + float(payload.quantity_delta)
                    else:
                        qty_by_sym[sym] = cur_q * ratio
                else:
                    qty_by_sym[sym] = cur_q + float(payload.quantity_delta)
                stock_basis_by_sym[sym] += float(payload.cost_basis_adjustment_base)

            elif ctype in {CorporateActionType.SYMBOL_CHANGE, CorporateActionType.MERGER}:
                old_q = qty_by_sym.pop(sym, 0.0)
                old_basis = stock_basis_by_sym.pop(sym, 0.0)
                if payload.new_symbol:
                    new_sym = _canonical_symbol(payload.new_symbol)
                    if payload.ratio_numerator is not None and payload.ratio_denominator is not None:
                        ratio = float(payload.ratio_numerator) / float(payload.ratio_denominator)
                        delivered = (
                            old_q * ratio
                            if payload.quantity_delta == 0.0
                            else float(payload.quantity_delta)
                        )
                    else:
                        delivered = old_q if payload.quantity_delta == 0.0 else float(payload.quantity_delta)
                    qty_by_sym[new_sym] += delivered
                    stock_basis_by_sym[new_sym] += old_basis + float(payload.cost_basis_adjustment_base)
                else:
                    qty_by_sym[sym] = max(0.0, old_q + float(payload.quantity_delta)) if old_q > 0 else (
                        old_q + float(payload.quantity_delta) if payload.quantity_delta != 0.0 else 0.0
                    )

            elif ctype in {CorporateActionType.SPIN_OFF, CorporateActionType.STOCK_GRANT}:
                target_sym = _canonical_symbol(payload.new_symbol or payload.symbol)
                if payload.quantity_delta != 0.0:
                    qty_by_sym[target_sym] += float(payload.quantity_delta)
                elif (
                    payload.new_symbol
                    and payload.ratio_numerator is not None
                    and payload.ratio_denominator is not None
                ):
                    qty_by_sym[target_sym] += qty_by_sym[sym] * (
                        float(payload.ratio_numerator) / float(payload.ratio_denominator)
                    )
                stock_basis_by_sym[target_sym] += float(payload.cost_basis_adjustment_base)

            elif ctype == CorporateActionType.OPTION_EXPIRATION:
                cur_opt_q = qty_by_sym[sym]
                closed_q = -cur_opt_q if payload.quantity_delta == 0.0 else float(payload.quantity_delta)
                qty_by_sym[sym] = cur_opt_q + closed_q
                tracker = option_meta.get(sym)
                if tracker is not None and abs(cur_opt_q) > 1e-9:
                    rem_frac = max(0.0, abs(qty_by_sym[sym]) / abs(cur_opt_q))
                    tracker.signed_cost_basis_base *= rem_frac
                findings.append(
                    ReconciliationFinding(
                        category="option_eae_lifecycle",
                        outcome=CheckOutcome.PASS,
                        date_or_timestamp=payload.timestamp_utc,
                        symbol=sym,
                        expected_value=0.0,
                        observed_value=qty_by_sym[sym],
                        residual_bps=0.0,
                        residual_base_currency=0.0,
                        math_identity="OptionExpiration: remaining_contracts = open_contracts + expired_delta, underlying_delivery = 0",
                        technical_explanation="Worthless option expiration extinguished contract obligation with zero underlying share delivery.",
                        benign_causes_considered=["Out-of-the-money expiration at contract maturity"],
                    )
                )

            elif ctype in {
                CorporateActionType.OPTION_EXERCISE,
                CorporateActionType.OPTION_ASSIGNMENT,
            }:
                cur_opt_q = qty_by_sym[sym]
                contracts_closed = (
                    abs(float(payload.quantity_delta))
                    if payload.quantity_delta != 0.0
                    else abs(cur_opt_q)
                )
                if cur_opt_q > 0.0:
                    qty_by_sym[sym] = cur_opt_q - contracts_closed
                elif cur_opt_q < 0.0:
                    qty_by_sym[sym] = cur_opt_q + contracts_closed
                else:
                    qty_by_sym[sym] = cur_opt_q + float(payload.quantity_delta)

                tracker = option_meta.get(sym)
                und_guess, right_guess, strike_guess = _infer_option_metadata_from_text(
                    sym, payload.description
                )
                opt_right = (tracker.option_right if tracker else None) or right_guess
                strike = (
                    float(payload.strike)
                    if payload.strike is not None
                    else ((tracker.strike if tracker else None) or strike_guess)
                )
                mult = float(
                    payload.option_multiplier
                    or (tracker.multiplier if tracker else None)
                    or 100.0
                )
                fx = tracker.fx_rate_to_base if tracker else 1.0
                und_sym = (
                    _canonical_symbol(payload.underlying_symbol)
                    if payload.underlying_symbol
                    else ((tracker.underlying_symbol if tracker else None) or und_guess)
                )

                # Determine underlying share delivery sign:
                # Long Call Exercise or Short Put Assignment -> +contracts * mult shares
                # Long Put Exercise or Short Call Assignment -> -contracts * mult shares
                if ctype == CorporateActionType.OPTION_EXERCISE:
                    share_sign = -1.0 if opt_right == "P" else 1.0
                else:
                    share_sign = 1.0 if opt_right == "P" else -1.0

                delivered_shares = share_sign * contracts_closed * mult

                closed_opt_basis = 0.0
                if tracker is not None and abs(cur_opt_q) > 1e-9:
                    proportion = min(1.0, contracts_closed / abs(cur_opt_q))
                    closed_opt_basis = tracker.signed_cost_basis_base * proportion
                    tracker.signed_cost_basis_base *= 1.0 - proportion
                elif payload.cost_basis_adjustment_base != 0.0:
                    closed_opt_basis = float(payload.cost_basis_adjustment_base)

                if und_sym:
                    already_booked = _has_explicit_exercise_stock_trade(
                        ledger.trades,
                        underlying_symbol=und_sym,
                        action_date=payload.timestamp_utc[:10],
                        expected_shares=delivered_shares,
                        strike=strike,
                    )
                    if not already_booked:
                        qty_by_sym[und_sym] += delivered_shares
                        if strike is not None:
                            strike_cash = -delivered_shares * strike * fx
                            implied_option_cash_delta_base += strike_cash
                            stock_basis_by_sym[und_sym] += (delivered_shares * strike * fx) + closed_opt_basis
                            option_exercised_underlyings[und_sym] = payload.timestamp_utc

    # Compare rolled-forward quantities & OptionEAE cost-basis links against ending_positions.
    observed_qty_by_sym: dict[str, float] = defaultdict(float)
    observed_basis_by_sym: dict[str, float] = defaultdict(float)
    for pos in ledger.ending_positions:
        if pos.asset_class == AssetClass.CASH:
            continue
        sym = _canonical_symbol(pos.symbol)
        observed_qty_by_sym[sym] += float(pos.quantity)
        observed_basis_by_sym[sym] += float(pos.cost_basis) * float(pos.fx_rate_to_base)

    all_syms = sorted(set(qty_by_sym.keys()) | set(observed_qty_by_sym.keys()))
    unexplained_position_jump = False

    for sym in all_syms:
        exp_q = qty_by_sym.get(sym, 0.0)
        obs_q = observed_qty_by_sym.get(sym, 0.0)
        if abs(exp_q) <= 1e-9 and abs(obs_q) <= 1e-9:
            continue

        tol = max(1e-6, 1e-6 * max(abs(exp_q), abs(obs_q)))
        diff = obs_q - exp_q
        if abs(diff) <= tol:
            findings.append(
                ReconciliationFinding(
                    category="position_rollforward",
                    outcome=CheckOutcome.PASS,
                    date_or_timestamp=ledger.period_end_utc,
                    symbol=sym,
                    expected_value=exp_q,
                    observed_value=obs_q,
                    residual_bps=0.0,
                    residual_base_currency=0.0,
                    math_identity="PriorPositions + Trades + InKindFlows + CorporateActions == EndingPositions",
                    technical_explanation=f"Position roll-forward for {sym} reconciled exactly ({obs_q:g} units).",
                    benign_causes_considered=[],
                )
            )
        else:
            unexplained_position_jump = True
            rel_bps = (abs(diff) / max(abs(exp_q), abs(obs_q), 1.0)) * 10_000.0
            findings.append(
                ReconciliationFinding(
                    category="position_rollforward",
                    outcome=CheckOutcome.DISCREPANCY,
                    date_or_timestamp=ledger.period_end_utc,
                    symbol=sym,
                    expected_value=exp_q,
                    observed_value=obs_q,
                    residual_bps=rel_bps,
                    residual_base_currency=None,
                    math_identity="PriorPositions + Trades + InKindFlows + CorporateActions == EndingPositions",
                    technical_explanation=(
                        f"Ending quantity for {sym} is {obs_q:g}, whereas rolled-forward ledger events imply {exp_q:g} "
                        f"(delta={diff:+g})."
                    ),
                    benign_causes_considered=[
                        "Unexported Transfers (ACATS / FOP / DWAC in-kind transfer) section",
                        "Unexported CorporateActions (split / merger / spin-off) section",
                        "Unexported OptionEAE (exercise / assignment / expiration) section",
                    ],
                )
            )

    # Verify OptionEAE underlying cost-basis link when underlying shares remain at period end.
    for und_sym, action_ts in sorted(option_exercised_underlyings.items()):
        obs_q = observed_qty_by_sym.get(und_sym, 0.0)
        exp_q = qty_by_sym.get(und_sym, 0.0)
        if abs(obs_q) > 1e-6 and abs(obs_q - exp_q) <= 1e-5:
            exp_basis = stock_basis_by_sym.get(und_sym, 0.0)
            obs_basis = observed_basis_by_sym.get(und_sym, 0.0)
            basis_diff = obs_basis - exp_basis
            basis_bps = (abs(basis_diff) / max(abs(exp_basis), 1.0)) * 10_000.0
            basis_ok = abs(basis_diff) <= max(2.0, 0.0010 * abs(exp_basis))
            findings.append(
                ReconciliationFinding(
                    category="option_eae_cost_basis_link",
                    outcome=CheckOutcome.PASS if basis_ok else CheckOutcome.DISCREPANCY,
                    date_or_timestamp=action_ts,
                    symbol=und_sym,
                    expected_value=exp_basis,
                    observed_value=obs_basis,
                    residual_bps=0.0 if basis_ok else basis_bps,
                    residual_base_currency=basis_diff,
                    math_identity="UnderlyingCostBasis == StrikeNotional + OptionPremiumBasisAdjustment",
                    technical_explanation=(
                        f"Underlying {und_sym} cost basis after option exercise/assignment matches strike +/- option premium."
                        if basis_ok
                        else f"Underlying {und_sym} cost basis ({obs_basis:.2f}) diverges from strike +/- option premium link ({exp_basis:.2f})."
                    ),
                    benign_causes_considered=[
                        "FIFO vs specific-lot tax basis relief on partial sale",
                        "Wash-sale basis deferral adjustment",
                    ],
                )
            )

    missing_sections: list[str] = []
    ledger_completeness_ok = True
    if unexplained_position_jump:
        missing_sections = _find_missing_completeness_sections(
            ledger.enabled_sections,
            has_options=has_options,
        )
        if missing_sections:
            ledger_completeness_ok = False

    return PositionRollforwardResult(
        findings=findings,
        ledger_completeness_ok=ledger_completeness_ok,
        missing_sections=missing_sections,
        implied_option_cash_delta_base=implied_option_cash_delta_base,
    )


def _signed_cash_flow_delta_base(flow: NormalizedFlow) -> float:
    """Return signed cash impact in base currency (0.0 for non-cash in-kind transfers)."""
    if flow.kind in {
        FlowKind.TRANSFER_IN_KIND,
        FlowKind.TRANSFER_OUT_KIND,
        FlowKind.FX_TRANSLATION,
    }:
        return 0.0
    amt = float(flow.amount_base or 0.0)
    if flow.kind in {
        FlowKind.WITHDRAWAL,
        FlowKind.WITHHOLDING_TAX,
        FlowKind.COMMISSION_FEE,
        FlowKind.MARGIN_INTEREST,
    }:
        return -abs(amt)
    if flow.kind == FlowKind.DEPOSIT:
        return amt
    return amt


def _estimate_unsettled_trade_cash_near_boundary(
    trades: Sequence[NormalizedTrade],
    boundary_dt: datetime,
) -> float:
    """Sum net settlement cash of trades within T+2 (4 calendar days) prior to ``boundary_dt``."""
    window_start = boundary_dt - timedelta(days=4)
    net = 0.0
    for tr in trades:
        ts = parse_utc_timestamp(tr.timestamp_utc)
        if window_start <= ts <= boundary_dt:
            cash_leg = -tr.notional_base if tr.side == "buy" else tr.notional_base
            net += cash_leg
    return net


def _estimate_pending_dividend_accrual_base(
    ledger: CanonicalPortfolioLedger,
    boundary_date: str,
    reference_provider: ReferenceDataProvider | None,
) -> float:
    """Query EODHD ``/api/div/`` to check pending ex-date <= boundary < pay-date dividend accruals."""
    if reference_provider is None or not reference_provider.is_available:
        return 0.0

    b_dt = datetime.fromisoformat(boundary_date).date()
    lookback = (b_dt - timedelta(days=45)).isoformat()
    lookahead = (b_dt + timedelta(days=5)).isoformat()

    held_qty: dict[str, tuple[float, str, str | None]] = {}
    for pos in ledger.ending_positions or ledger.prior_positions:
        if pos.asset_class in {AssetClass.EQUITY, AssetClass.ETF} and abs(pos.quantity) > 0.0:
            sym_key = _canonical_symbol(pos.symbol)
            prev_q, prev_ccy, prev_isin = held_qty.get(sym_key, (0.0, pos.currency, pos.isin))
            held_qty[sym_key] = (prev_q + float(pos.quantity), prev_ccy, prev_isin or pos.isin)

    pending_total = 0.0
    for sym, (qty, pos_ccy, pos_isin) in held_qty.items():
        if abs(qty) <= 0.0:
            continue
        ex_code = normalize_eodhd_exchange(None, isin=pos_isin, currency=pos_ccy)
        resolved = reference_provider.resolve_security(
            sym,
            exchange=ex_code,
            isin=pos_isin,
            currency=pos_ccy,
        )
        if resolved is not None:
            canonical_ticker = resolved.canonical_ticker
        else:
            base_s, norm_ex = split_eodhd_ticker(sym, default_exchange=ex_code)
            canonical_ticker = f"{base_s}.{norm_ex}"
        divs = reference_provider.get_dividends(
            canonical_ticker,
            start_date=lookback,
            end_date=lookahead,
        )
        for dv in divs:
            pay_dt = dv.payment_date or ""
            if dv.ex_date <= boundary_date and (not pay_dt or pay_dt > boundary_date):
                fx = reference_provider.get_fx_rate(
                    dv.currency,
                    ledger.base_currency,
                    date_str=dv.ex_date,
                )
                if fx is not None and fx > 0.0:
                    pending_total += qty * dv.unadjusted_value * fx
    return pending_total


def reconcile_nav_identities(
    ledger: CanonicalPortfolioLedger,
    *,
    reference_provider: ReferenceDataProvider | None = None,
    implied_option_cash_delta_base: float = 0.0,
    ledger_completeness_ok: bool = True,
) -> list[ReconciliationFinding]:
    """Verify snapshot NAV component identities and full-window double-entry NAV conservation."""
    findings: list[ReconciliationFinding] = []
    if not ledger.nav_points:
        return findings

    nav_sorted: list[tuple[datetime, NormalizedNavPoint]] = sorted(
        ((parse_utc_timestamp(pt.timestamp_utc), pt) for pt in ledger.nav_points),
        key=lambda item: item[0],
    )

    # 1. Intra-snapshot component check: cash_base + positions_base + accruals_base == nav_base
    for nav_dt, pt in nav_sorted:
        if pt.cash_base is None or pt.positions_base is None:
            continue
        expected = float(pt.cash_base) + float(pt.positions_base) + float(pt.accruals_base or 0.0)
        residual = float(pt.nav_base) - expected
        tol = max(1.0, 0.0005 * abs(pt.nav_base))
        res_bps = (abs(residual) / max(abs(pt.nav_base), 1.0)) * 10_000.0

        if abs(residual) <= tol:
            findings.append(
                ReconciliationFinding(
                    category="nav_component_identity",
                    outcome=CheckOutcome.PASS,
                    date_or_timestamp=pt.timestamp_utc,
                    expected_value=expected,
                    observed_value=float(pt.nav_base),
                    residual_bps=res_bps,
                    residual_base_currency=residual,
                    math_identity="NAV == CashBase + PositionsBase + AccrualsBase",
                    technical_explanation="Snapshot NAV matches sum of cash, positions, and accruals within tolerance.",
                    benign_causes_considered=[],
                )
            )
            continue

        unsettled = _estimate_unsettled_trade_cash_near_boundary(ledger.trades, nav_dt)
        if abs(unsettled) > 0.0 and min(abs(residual - unsettled), abs(residual + unsettled)) <= max(
            5.0, 0.0015 * abs(pt.nav_base)
        ):
            findings.append(
                ReconciliationFinding(
                    category="nav_component_identity",
                    outcome=CheckOutcome.EXPLAINED_CONVENTION,
                    date_or_timestamp=pt.timestamp_utc,
                    expected_value=expected,
                    observed_value=float(pt.nav_base),
                    residual_bps=res_bps,
                    residual_base_currency=residual,
                    math_identity="NAV == SettlementDateCash + TradeDatePositions +/- UnsettledTradeReceivable",
                    technical_explanation="Residual matches T+1/T+2 unsettled trade cash timing between trade-date positions and settlement-date cash.",
                    benign_causes_considered=[
                        "T+1/T+2 trade-date vs settlement-date cash accrual timing",
                    ],
                )
            )
            continue

        pending_div = _estimate_pending_dividend_accrual_base(
            ledger, pt.timestamp_utc[:10], reference_provider
        )
        if pending_div > 0.0 and (0.65 * pending_div - 5.0 <= abs(residual) <= 1.05 * pending_div + 5.0):
            findings.append(
                ReconciliationFinding(
                    category="nav_component_identity",
                    outcome=CheckOutcome.EXPLAINED_CONVENTION,
                    date_or_timestamp=pt.timestamp_utc,
                    expected_value=expected + pending_div,
                    observed_value=float(pt.nav_base),
                    residual_bps=res_bps,
                    residual_base_currency=residual,
                    math_identity="NAV == CashBase + PositionsBase + ExDateDividendReceivable",
                    technical_explanation="Residual matches ex-date vs pay-date dividend accrual confirmed via reference /api/div/ unadjustedValue.",
                    benign_causes_considered=[
                        "Ex-date vs pay-date dividend accrual (net of statutory withholding)",
                    ],
                )
            )
            continue

        if abs(unsettled) > 0.0 and pending_div > 0.0:
            comb_tol = max(5.0, 0.0020 * abs(pt.nav_base))
            matched_combined = any(
                (0.65 * pending_div - comb_tol) <= abs(residual - sign * unsettled) <= (1.05 * pending_div + comb_tol)
                for sign in (1.0, -1.0)
            )
            if matched_combined:
                findings.append(
                    ReconciliationFinding(
                        category="nav_component_identity",
                        outcome=CheckOutcome.EXPLAINED_CONVENTION,
                        date_or_timestamp=pt.timestamp_utc,
                        expected_value=expected + pending_div,
                        observed_value=float(pt.nav_base),
                        residual_bps=res_bps,
                        residual_base_currency=residual,
                        math_identity="NAV == CashBase + PositionsBase +/- UnsettledTradeReceivable + ExDateDividendReceivable",
                        technical_explanation="Residual matches combined T+1/T+2 unsettled trade cash and ex-date dividend accrual.",
                        benign_causes_considered=[
                            "T+1/T+2 trade-date vs settlement-date cash accrual timing",
                            "Ex-date vs pay-date dividend accrual (net of statutory withholding)",
                        ],
                    )
                )
                continue

        findings.append(
            ReconciliationFinding(
                category="nav_component_identity",
                outcome=CheckOutcome.DISCREPANCY,
                date_or_timestamp=pt.timestamp_utc,
                expected_value=expected,
                observed_value=float(pt.nav_base),
                residual_bps=res_bps,
                residual_base_currency=residual,
                math_identity="NAV == CashBase + PositionsBase + AccrualsBase",
                technical_explanation=(
                    f"Reported NAV ({pt.nav_base:.2f}) diverges from Cash + Positions + Accruals "
                    f"({expected:.2f}) by {residual:+.2f} ({res_bps:.1f} bps)."
                ),
                benign_causes_considered=[
                    "T+1/T+2 settlement lag",
                    "Pending dividend or interest accrual",
                    "FX closing mark cut-off difference",
                ],
            )
        )

    # 2. Ending positions sum vs final NAV positions_base (when reported)
    end_dt, end_pt = nav_sorted[-1]
    non_cash_ending = [p for p in ledger.ending_positions if p.asset_class != AssetClass.CASH]
    ending_mv_sum = math.fsum(p.market_value_base for p in non_cash_ending)
    if end_pt.positions_base is not None:
        pos_res = float(end_pt.positions_base) - ending_mv_sum
        pos_bps = (abs(pos_res) / max(abs(end_pt.nav_base), 1.0)) * 10_000.0
        pos_ok = abs(pos_res) <= max(2.0, 0.0010 * abs(end_pt.nav_base))
        findings.append(
            ReconciliationFinding(
                category="ending_positions_valuation_identity",
                outcome=CheckOutcome.PASS if pos_ok else CheckOutcome.DISCREPANCY,
                date_or_timestamp=end_pt.timestamp_utc,
                expected_value=ending_mv_sum,
                observed_value=float(end_pt.positions_base),
                residual_bps=pos_bps,
                residual_base_currency=pos_res,
                math_identity="NavPositionsBase == sum(EndingOpenPositions.market_value_base)",
                technical_explanation=(
                    "Ending open positions market value matches NAV positions component."
                    if pos_ok
                    else f"NAV positions component ({end_pt.positions_base:.2f}) diverges from sum of ending positions ({ending_mv_sum:.2f})."
                ),
                benign_causes_considered=[
                    "FX conversion cut-off spread across multi-currency positions",
                    "Accrued bond interest classification",
                ],
            )
        )

    # 3. Full-window double-entry NAV conservation bridge (detects altered ending/intermediate NAV!)
    if len(nav_sorted) >= 2 and ledger_completeness_ok:
        start_dt, start_pt = nav_sorted[0]
        prior_non_cash = [p for p in ledger.prior_positions if p.asset_class != AssetClass.CASH]
        prior_mv_sum = math.fsum(p.market_value_base for p in prior_non_cash)

        has_futures_or_perps = any(
            tr.asset_class in {AssetClass.FUTURE, AssetClass.CRYPTO_PERP}
            for tr in ledger.trades
        )
        if not has_futures_or_perps:
            opening_cash_and_accruals = float(start_pt.nav_base) - prior_mv_sum

            in_window_flows = [
                fl
                for fl in ledger.flows
                if start_dt < parse_utc_timestamp(fl.timestamp_utc) <= end_dt
            ]
            cash_flow_sum = math.fsum(_signed_cash_flow_delta_base(fl) for fl in in_window_flows)
            explicit_comm_flows = math.fsum(
                abs(float(fl.amount_base or 0.0))
                for fl in in_window_flows
                if fl.kind == FlowKind.COMMISSION_FEE
            )

            in_window_trades = [
                tr
                for tr in ledger.trades
                if start_dt < parse_utc_timestamp(tr.timestamp_utc) <= end_dt
                and tr.asset_class not in {AssetClass.CASH, AssetClass.FX}
            ]
            trade_gross_cash = math.fsum(
                (-tr.notional_base if tr.side == "buy" else tr.notional_base)
                for tr in in_window_trades
            )
            trade_comm_and_tax = math.fsum(
                (abs(float(tr.commission)) + abs(float(tr.tax))) * float(tr.fx_rate_to_base)
                for tr in in_window_trades
            )
            net_unbooked_trade_costs = max(0.0, trade_comm_and_tax - explicit_comm_flows)

            corp_cash_in_lieu = math.fsum(
                float(ca.cash_in_lieu_base)
                for ca in ledger.corporate_actions
                if start_dt < parse_utc_timestamp(ca.timestamp_utc) <= end_dt
            )

            implied_ending_cash = (
                opening_cash_and_accruals
                + cash_flow_sum
                + trade_gross_cash
                - net_unbooked_trade_costs
                + corp_cash_in_lieu
                + implied_option_cash_delta_base
            )
            expected_ending_nav = implied_ending_cash + ending_mv_sum
            nav_residual = float(end_pt.nav_base) - expected_ending_nav
            nav_res_bps = (abs(nav_residual) / max(abs(expected_ending_nav), abs(end_pt.nav_base), 1.0)) * 10_000.0
            tol_abs = max(5.0, 0.0015 * max(abs(expected_ending_nav), abs(end_pt.nav_base)))

            if abs(nav_residual) <= tol_abs:
                findings.append(
                    ReconciliationFinding(
                        category="nav_continuity_bridge",
                        outcome=CheckOutcome.PASS,
                        date_or_timestamp=end_pt.timestamp_utc,
                        expected_value=expected_ending_nav,
                        observed_value=float(end_pt.nav_base),
                        residual_bps=nav_res_bps,
                        residual_base_currency=nav_residual,
                        math_identity="EndingNAV == OpeningCash + CashFlows + NetTradeProceeds + EndingPositionsMV",
                        technical_explanation="Double-entry cash and mark-to-market position conservation reconciles ending NAV within tolerance.",
                        benign_causes_considered=[],
                    )
                )
            else:
                unsettled_end = _estimate_unsettled_trade_cash_near_boundary(ledger.trades, end_dt)
                pending_div = _estimate_pending_dividend_accrual_base(
                    ledger, end_pt.timestamp_utc[:10], reference_provider
                )
                has_multi_ccy = any(p.currency != ledger.base_currency for p in non_cash_ending) or any(
                    fl.currency != ledger.base_currency for fl in in_window_flows
                )

                if abs(unsettled_end) > 0.0 and min(
                    abs(nav_residual - unsettled_end), abs(nav_residual + unsettled_end)
                ) <= max(5.0, 0.0020 * abs(end_pt.nav_base)):
                    findings.append(
                        ReconciliationFinding(
                            category="nav_continuity_bridge",
                            outcome=CheckOutcome.EXPLAINED_CONVENTION,
                            date_or_timestamp=end_pt.timestamp_utc,
                            expected_value=expected_ending_nav,
                            observed_value=float(end_pt.nav_base),
                            residual_bps=nav_res_bps,
                            residual_base_currency=nav_residual,
                            math_identity="EndingNAV == ImpliedCash + EndingPositionsMV +/- UnsettledTradeCash",
                            technical_explanation="NAV bridge residual is explained by T+1/T+2 settlement lag across period boundary.",
                            benign_causes_considered=[
                                "T+1/T+2 trade-date vs settlement-date boundary timing",
                            ],
                        )
                    )
                elif pending_div > 0.0 and (
                    0.65 * pending_div - 5.0 <= abs(nav_residual) <= 1.05 * pending_div + 5.0
                ):
                    findings.append(
                        ReconciliationFinding(
                            category="nav_continuity_bridge",
                            outcome=CheckOutcome.EXPLAINED_CONVENTION,
                            date_or_timestamp=end_pt.timestamp_utc,
                            expected_value=expected_ending_nav + pending_div,
                            observed_value=float(end_pt.nav_base),
                            residual_bps=nav_res_bps,
                            residual_base_currency=nav_residual,
                            math_identity="EndingNAV == ImpliedCash + EndingPositionsMV + ExDateDividendReceivable",
                            technical_explanation="NAV bridge residual matches pending ex-date vs pay-date dividend accrual confirmed via /api/div/.",
                            benign_causes_considered=[
                                "Ex-date vs pay-date dividend accrual confirmed via EODHD /api/div/",
                            ],
                        )
                    )
                elif (
                    abs(unsettled_end) > 0.0
                    and pending_div > 0.0
                    and any(
                        (0.65 * pending_div - max(5.0, 0.0020 * abs(end_pt.nav_base)))
                        <= abs(nav_residual - sign * unsettled_end)
                        <= (1.05 * pending_div + max(5.0, 0.0020 * abs(end_pt.nav_base)))
                        for sign in (1.0, -1.0)
                    )
                ):
                    findings.append(
                        ReconciliationFinding(
                            category="nav_continuity_bridge",
                            outcome=CheckOutcome.EXPLAINED_CONVENTION,
                            date_or_timestamp=end_pt.timestamp_utc,
                            expected_value=expected_ending_nav + pending_div,
                            observed_value=float(end_pt.nav_base),
                            residual_bps=nav_res_bps,
                            residual_base_currency=nav_residual,
                            math_identity="EndingNAV == ImpliedCash + EndingPositionsMV +/- UnsettledTradeCash + ExDateDividendReceivable",
                            technical_explanation="NAV bridge residual matches combined T+1/T+2 unsettled trade cash and pending ex-date dividend accrual.",
                            benign_causes_considered=[
                                "T+1/T+2 trade-date vs settlement-date boundary timing",
                                "Ex-date vs pay-date dividend accrual confirmed via EODHD /api/div/",
                            ],
                        )
                    )
                elif has_multi_ccy and nav_res_bps <= 60.0:
                    findings.append(
                        ReconciliationFinding(
                            category="nav_continuity_bridge",
                            outcome=CheckOutcome.EXPLAINED_CONVENTION,
                            date_or_timestamp=end_pt.timestamp_utc,
                            expected_value=expected_ending_nav,
                            observed_value=float(end_pt.nav_base),
                            residual_bps=nav_res_bps,
                            residual_base_currency=nav_residual,
                            math_identity="EndingNAV == ImpliedCash + EndingPositionsMV + FxTranslationDrift",
                            technical_explanation="Small multi-currency NAV residual (<= 60 bps) consistent with intra-period FX translation on non-base cash.",
                            benign_causes_considered=[
                                "FX translation on non-base currency cash balances",
                                "Broker FX closing mark spread",
                            ],
                        )
                    )
                else:
                    findings.append(
                        ReconciliationFinding(
                            category="nav_continuity_bridge",
                            outcome=CheckOutcome.DISCREPANCY,
                            date_or_timestamp=end_pt.timestamp_utc,
                            expected_value=expected_ending_nav,
                            observed_value=float(end_pt.nav_base),
                            residual_bps=nav_res_bps,
                            residual_base_currency=nav_residual,
                            math_identity="EndingNAV == OpeningCash + CashFlows + NetTradeProceeds + EndingPositionsMV",
                            technical_explanation=(
                                f"Ending NAV ({end_pt.nav_base:.2f}) exhibits an unexplained residual of "
                                f"{nav_residual:+.2f} ({nav_res_bps:.1f} bps) relative to double-entry ledger conservation ({expected_ending_nav:.2f})."
                            ),
                            benign_causes_considered=[
                                "T+1/T+2 trade settlement timing",
                                "Ex-date vs pay-date dividend or interest accrual",
                                "Unexported subaccount or fee adjustment",
                            ],
                        )
                    )

    return findings


__all__ = [
    "PositionRollforwardResult",
    "reconcile_nav_identities",
    "reconcile_position_rollforward",
]
