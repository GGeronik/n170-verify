"""Double-entry position roll-forward, OptionEAE basis link, and period-by-period NAV identities."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
import math
import re

from n170_verify.coaching.cost_and_drag import normalize_fx_pair, resolve_forex_midpoint
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
    OriginAssurance,
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


_IBKR_FLEX_BROKER_IDS = frozenset({"ibkr", "ibkr_flex", "ibkr_flex_web", "ibkr_flex_offline"})
_ENDING_POSITIONS_SECTION_TOKENS = frozenset({"openpositions", "positions", "endingpositions"})


def _normalize_section_token(section: str) -> str:
    return re.sub(r"[^a-z0-9]", "", section.strip().lower())


def _ibkr_omitted_open_positions(ledger: CanonicalPortfolioLedger) -> bool:
    if (ledger.broker_id or "").strip().lower() not in _IBKR_FLEX_BROKER_IDS:
        return False
    if ledger.ending_positions:
        return False
    present = {_normalize_section_token(s) for s in ledger.enabled_sections if s and s.strip()}
    if not present:
        return False
    return not bool(present & _ENDING_POSITIONS_SECTION_TOKENS)


def _find_missing_completeness_sections(
    enabled_sections: Sequence[str],
    *,
    has_options: bool,
    omitted_open_positions: bool = False,
) -> list[str]:
    present = {_normalize_section_token(s) for s in enabled_sections if s and s.strip()}
    missing: list[str] = []
    if omitted_open_positions:
        missing.append("OpenPositions")
        if "priorperiodpositions" not in present:
            missing.append("PriorPeriodPositions")
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
    omitted_open_pos = _ibkr_omitted_open_positions(ledger)

    if omitted_open_pos:
        nonzero_syms = [
            sym
            for sym in all_syms
            if abs(qty_by_sym.get(sym, 0.0)) > 1e-9 or abs(observed_qty_by_sym.get(sym, 0.0)) > 1e-9
        ]
        if nonzero_syms:
            findings.append(
                ReconciliationFinding(
                    category="position_rollforward",
                    outcome=CheckOutcome.NOT_EVALUATED,
                    date_or_timestamp=ledger.period_end_utc,
                    expected_value=None,
                    observed_value=None,
                    residual_bps=None,
                    residual_base_currency=None,
                    math_identity="PriorPositions + Trades + InKindFlows + CorporateActions == EndingPositions",
                    technical_explanation=(
                        "OpenPositions section was not included in the IBKR Flex query; "
                        "ending position roll-forward was not evaluated."
                    ),
                    benign_causes_considered=[
                        "Minimal IBKR Activity Flex Query omitting OpenPositions / PriorPeriodPositions",
                    ],
                )
            )
        missing_sections = _find_missing_completeness_sections(
            ledger.enabled_sections,
            has_options=has_options,
            omitted_open_positions=True,
        )
        return PositionRollforwardResult(
            findings=findings,
            ledger_completeness_ok=False,
            missing_sections=missing_sections,
            implied_option_cash_delta_base=implied_option_cash_delta_base,
        )

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
        if tr.asset_class in {AssetClass.CASH, AssetClass.FX}:
            continue
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
        if _ibkr_omitted_open_positions(ledger):
            findings.append(
                ReconciliationFinding(
                    category="ending_positions_valuation_identity",
                    outcome=CheckOutcome.NOT_EVALUATED,
                    date_or_timestamp=end_pt.timestamp_utc,
                    expected_value=None,
                    observed_value=float(end_pt.positions_base),
                    residual_bps=None,
                    residual_base_currency=None,
                    math_identity="NavPositionsBase == sum(EndingOpenPositions.market_value_base)",
                    technical_explanation=(
                        "OpenPositions section was not included in the IBKR Flex query; "
                        "ending positions valuation identity was not evaluated."
                    ),
                    benign_causes_considered=[
                        "Minimal IBKR Activity Flex Query omitting OpenPositions",
                    ],
                )
            )
        else:
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
            is_cfd_fx_broker = ledger.broker_id in {"mt4", "mt5", "ctrader"}
            pre_start_flows = [
                fl
                for fl in ledger.flows
                if parse_utc_timestamp(fl.timestamp_utc) <= start_dt
            ]
            pre_start_all_trades = [
                tr
                for tr in ledger.trades
                if parse_utc_timestamp(tr.timestamp_utc) <= start_dt
            ]
            pre_start_non_fx_trades = [
                tr
                for tr in pre_start_all_trades
                if tr.asset_class not in {AssetClass.CASH, AssetClass.FX}
            ]
            pre_start_comm_trades = [
                tr
                for tr in pre_start_all_trades
                if tr.asset_class != AssetClass.FX or not is_cfd_fx_broker
            ]
            pre_start_explicit_comm = math.fsum(
                abs(float(fl.amount_base or 0.0))
                for fl in pre_start_flows
                if fl.kind == FlowKind.COMMISSION_FEE
            )
            pre_start_trade_comm = math.fsum(
                (abs(float(tr.commission)) + abs(float(tr.tax))) * float(tr.fx_rate_to_base)
                for tr in pre_start_comm_trades
            )
            pre_start_unbooked_comm = max(0.0, pre_start_trade_comm - pre_start_explicit_comm)
            pre_start_trade_gross_cash = math.fsum(
                (-tr.notional_base if tr.side == "buy" else tr.notional_base)
                for tr in pre_start_non_fx_trades
            )

            start_comp_consistent = (
                start_pt.cash_base is not None
                and start_pt.positions_base is not None
                and abs(
                    float(start_pt.nav_base)
                    - (
                        float(start_pt.cash_base)
                        + float(start_pt.positions_base)
                        + float(start_pt.accruals_base or 0.0)
                    )
                )
                <= max(2.0, 0.0010 * abs(start_pt.nav_base))
            )
            if start_comp_consistent and (
                pre_start_all_trades
                or abs(float(start_pt.positions_base or 0.0) - prior_mv_sum)
                > max(2.0, 0.0010 * abs(start_pt.nav_base))
            ):
                opening_cash_and_accruals = float(start_pt.cash_base or 0.0) + float(
                    start_pt.accruals_base or 0.0
                )
            elif pre_start_non_fx_trades:
                opening_cash_and_accruals = (
                    float(start_pt.nav_base)
                    - prior_mv_sum
                    + pre_start_trade_gross_cash
                    - pre_start_unbooked_comm
                )
            else:
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

            in_window_all_trades = [
                tr
                for tr in ledger.trades
                if start_dt < parse_utc_timestamp(tr.timestamp_utc) <= end_dt
            ]
            in_window_trades = [
                tr
                for tr in in_window_all_trades
                if tr.asset_class not in {AssetClass.CASH, AssetClass.FX}
            ]
            comm_eligible_trades = [
                tr
                for tr in in_window_all_trades
                if tr.asset_class != AssetClass.FX or not is_cfd_fx_broker
            ]
            trade_gross_cash = math.fsum(
                (-tr.notional_base if tr.side == "buy" else tr.notional_base)
                for tr in in_window_trades
            )
            trade_comm_and_tax = math.fsum(
                (abs(float(tr.commission)) + abs(float(tr.tax))) * float(tr.fx_rate_to_base)
                for tr in comm_eligible_trades
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
                all_flows_le_end = [*pre_start_flows, *in_window_flows]
                all_trades_le_end = [*pre_start_all_trades, *in_window_all_trades]
                has_multi_ccy = (
                    any(p.currency != ledger.base_currency for p in [*ledger.prior_positions, *non_cash_ending])
                    or any(fl.currency != ledger.base_currency for fl in all_flows_le_end)
                    or any(
                        tr.currency != ledger.base_currency or tr.asset_class == AssetClass.CASH
                        for tr in all_trades_le_end
                    )
                    or bool(ledger.conversion_rates)
                )

                # Multi-currency cash conservation sub-ledger: tracks non-base cash balances
                # across spot FX conversions (e.g. IBKR EUR.USD), foreign trades, and flows,
                # then marks closing foreign cash at closing FX rates.
                multiccy_candidates: list[float] = []
                opening_fx_drift_ok = False
                if has_multi_ccy and not is_cfd_fx_broker:
                    open_or_prior_fx_pairs = {
                        pair
                        for pos in [*ledger.prior_positions, *ledger.ending_positions]
                        if pos.asset_class == AssetClass.FX
                        for pair in (normalize_fx_pair(pos.symbol),)
                        if pair is not None
                    }
                    prior_cash_pos = [p for p in ledger.prior_positions if p.asset_class == AssetClass.CASH]
                    earliest_fx_by_ccy: dict[str, float] = {}
                    latest_fx_by_ccy: dict[str, float] = {}
                    latest_fx_date_by_ccy: dict[str, str] = {}
                    for pos in ledger.prior_positions:
                        if pos.currency != ledger.base_currency and pos.fx_rate_to_base > 0.0:
                            earliest_fx_by_ccy.setdefault(pos.currency, float(pos.fx_rate_to_base))

                    def _record_event_fx(ccy_code: str, rate_val: float, date_s: str) -> None:
                        if ccy_code == ledger.base_currency or rate_val <= 0.0:
                            return
                        earliest_fx_by_ccy.setdefault(ccy_code, rate_val)
                        prev_d = latest_fx_date_by_ccy.get(ccy_code, "")
                        if date_s >= prev_d:
                            latest_fx_date_by_ccy[ccy_code] = date_s
                            latest_fx_by_ccy[ccy_code] = rate_val

                    def _replay_cash_maps(
                        seed_cash: dict[str, float],
                        flows_seq: Sequence[NormalizedFlow],
                        trades_seq: Sequence[NormalizedTrade],
                        comm_scale: float,
                        extra_base_cash: float,
                    ) -> tuple[dict[str, float], dict[str, float]]:
                        c_map: dict[str, float] = defaultdict(float, seed_cash)
                        afx_map: dict[str, float] = defaultdict(float, seed_cash)
                        ev_list: list[tuple[datetime, int, int, object]] = []
                        for idx_f, fl_item in enumerate(flows_seq):
                            ev_list.append((parse_utc_timestamp(fl_item.timestamp_utc), 0, idx_f, fl_item))
                        for idx_t, tr_item in enumerate(trades_seq):
                            ev_list.append((parse_utc_timestamp(tr_item.timestamp_utc), 1, idx_t, tr_item))
                        ev_list.sort(key=lambda item: (item[0], item[1], item[2]))

                        for _, ev_kind, _, ev_obj in ev_list:
                            if ev_kind == 0:
                                assert isinstance(ev_obj, NormalizedFlow)
                                _record_event_fx(
                                    ev_obj.currency,
                                    float(ev_obj.fx_rate_to_base),
                                    ev_obj.timestamp_utc[:10],
                                )
                                if ev_obj.kind in {
                                    FlowKind.TRANSFER_IN_KIND,
                                    FlowKind.TRANSFER_OUT_KIND,
                                    FlowKind.FX_TRANSLATION,
                                }:
                                    continue
                                raw_a = float(ev_obj.amount)
                                if ev_obj.kind in {
                                    FlowKind.WITHDRAWAL,
                                    FlowKind.WITHHOLDING_TAX,
                                    FlowKind.COMMISSION_FEE,
                                    FlowKind.MARGIN_INTEREST,
                                }:
                                    amt_ccy = -abs(raw_a)
                                else:
                                    amt_ccy = raw_a
                                c_map[ev_obj.currency] += amt_ccy
                                afx_map[ev_obj.currency] += amt_ccy
                                if (
                                    ev_obj.currency != ledger.base_currency
                                    and afx_map[ev_obj.currency] < -1e-9
                                ):
                                    deficit = -afx_map[ev_obj.currency]
                                    afx_map[ev_obj.currency] = 0.0
                                    afx_map[ledger.base_currency] -= deficit * float(ev_obj.fx_rate_to_base)
                            else:
                                assert isinstance(ev_obj, NormalizedTrade)
                                d_s = ev_obj.timestamp_utc[:10]
                                _record_event_fx(ev_obj.currency, float(ev_obj.fx_rate_to_base), d_s)
                                comm_ccy = (
                                    (abs(float(ev_obj.commission)) + abs(float(ev_obj.tax))) * comm_scale
                                )
                                pair = normalize_fx_pair(ev_obj.symbol)
                                is_spot_fx = ev_obj.asset_class == AssetClass.CASH or (
                                    ev_obj.asset_class == AssetClass.FX and pair not in open_or_prior_fx_pairs
                                )
                                if is_spot_fx:
                                    if pair is not None:
                                        fx_b, fx_q = pair
                                        mult = float(ev_obj.multiplier) if ev_obj.multiplier is not None else 1.0
                                        qty_b = abs(float(ev_obj.quantity)) * mult
                                        qty_q = qty_b * float(ev_obj.price)
                                        if ev_obj.side == "buy":
                                            c_map[fx_b] += qty_b
                                            c_map[fx_q] -= qty_q
                                            afx_map[fx_b] += qty_b
                                            afx_map[fx_q] -= qty_q
                                        else:
                                            c_map[fx_b] -= qty_b
                                            c_map[fx_q] += qty_q
                                            afx_map[fx_b] -= qty_b
                                            afx_map[fx_q] += qty_q
                                        if fx_b == ledger.base_currency and fx_q != ledger.base_currency and ev_obj.price > 0.0:
                                            _record_event_fx(fx_q, 1.0 / float(ev_obj.price), d_s)
                                        elif fx_q == ledger.base_currency and fx_b != ledger.base_currency and ev_obj.price > 0.0:
                                            _record_event_fx(fx_b, float(ev_obj.price), d_s)
                                    c_map[ev_obj.currency] -= comm_ccy
                                    afx_map[ev_obj.currency] -= comm_ccy
                                elif ev_obj.asset_class not in {AssetClass.CASH, AssetClass.FX}:
                                    mult = float(ev_obj.multiplier) if ev_obj.multiplier is not None else 1.0
                                    gross_ccy = abs(float(ev_obj.quantity)) * float(ev_obj.price) * mult
                                    delta_ccy = (-gross_ccy if ev_obj.side == "buy" else gross_ccy) - comm_ccy
                                    c_map[ev_obj.currency] += delta_ccy
                                    afx_map[ev_obj.currency] += delta_ccy
                                    if (
                                        ev_obj.currency != ledger.base_currency
                                        and afx_map[ev_obj.currency] < -1e-9
                                    ):
                                        deficit = -afx_map[ev_obj.currency]
                                        afx_map[ev_obj.currency] = 0.0
                                        afx_map[ledger.base_currency] -= deficit * float(
                                            ev_obj.fx_rate_to_base
                                        )

                        c_map[ledger.base_currency] += extra_base_cash
                        afx_map[ledger.base_currency] += extra_base_cash
                        return c_map, afx_map

                    seed_in_window: dict[str, float] = defaultdict(float)
                    if prior_cash_pos:
                        for p in prior_cash_pos:
                            seed_in_window[p.currency] += float(p.market_value)
                        seed_in_window[ledger.base_currency] += opening_cash_and_accruals - math.fsum(
                            p.market_value_base for p in prior_cash_pos
                        )
                    else:
                        seed_in_window[ledger.base_currency] = opening_cash_and_accruals

                    unbooked_comm_scale = (
                        max(0.0, (trade_comm_and_tax - explicit_comm_flows) / trade_comm_and_tax)
                        if trade_comm_and_tax > 1e-9
                        else 0.0
                    )
                    cash_by_ccy, autofx_cash_by_ccy = _replay_cash_maps(
                        seed_in_window,
                        in_window_flows,
                        in_window_all_trades,
                        unbooked_comm_scale,
                        corp_cash_in_lieu + implied_option_cash_delta_base,
                    )
                    candidate_maps: list[dict[str, float]] = [cash_by_ccy, autofx_cash_by_ccy]

                    # When flows or trades occurred on/before start_dt (e.g. Day-1 deposit +
                    # EUR.USD conversion + USD stock buy before Day-1 EOD valuation), also replay
                    # from pre-Day-1 cash so Day-1 currency conversions split EUR/USD cash accurately.
                    if (pre_start_flows or pre_start_all_trades) and not prior_cash_pos:
                        pre_flow_sum_base = math.fsum(
                            _signed_cash_flow_delta_base(fl) for fl in pre_start_flows
                        )
                        pre_spot_fx_base_delta = 0.0
                        for tr_pre in pre_start_all_trades:
                            pair_pre = normalize_fx_pair(tr_pre.symbol)
                            is_spot_pre = tr_pre.asset_class == AssetClass.CASH or (
                                tr_pre.asset_class == AssetClass.FX
                                and pair_pre not in open_or_prior_fx_pairs
                            )
                            if is_spot_pre and pair_pre is not None:
                                fb, fq = pair_pre
                                mult_p = float(tr_pre.multiplier) if tr_pre.multiplier is not None else 1.0
                                qb = abs(float(tr_pre.quantity)) * mult_p
                                qq = qb * float(tr_pre.price)
                                r_q = float(tr_pre.fx_rate_to_base) if tr_pre.currency == fq else None
                                r_b = (
                                    1.0
                                    if fb == ledger.base_currency
                                    else (
                                        float(tr_pre.price) * r_q
                                        if r_q is not None and fq != ledger.base_currency
                                        else (float(tr_pre.price) if fq == ledger.base_currency else None)
                                    )
                                )
                                if r_q is None:
                                    r_q = 1.0 if fq == ledger.base_currency else None
                                if r_b is not None and r_q is not None:
                                    leg_b = qb * r_b
                                    leg_q = qq * r_q
                                    pre_spot_fx_base_delta += (
                                        (leg_b - leg_q) if tr_pre.side == "buy" else (leg_q - leg_b)
                                    )
                        pre_corp_lieu = math.fsum(
                            float(ca.cash_in_lieu_base)
                            for ca in ledger.corporate_actions
                            if parse_utc_timestamp(ca.timestamp_utc) <= start_dt
                        )
                        pre_net_cash_base = (
                            pre_flow_sum_base
                            + pre_start_trade_gross_cash
                            + pre_spot_fx_base_delta
                            - pre_start_unbooked_comm
                            + pre_corp_lieu
                        )
                        pre_period_base_cash = opening_cash_and_accruals - pre_net_cash_base
                        total_comm = pre_start_trade_comm + trade_comm_and_tax
                        total_exp_comm = pre_start_explicit_comm + explicit_comm_flows
                        full_comm_scale = (
                            max(0.0, (total_comm - total_exp_comm) / total_comm)
                            if total_comm > 1e-9
                            else 0.0
                        )
                        full_c_map, full_afx_map = _replay_cash_maps(
                            {ledger.base_currency: pre_period_base_cash},
                            all_flows_le_end,
                            all_trades_le_end,
                            full_comm_scale,
                            pre_corp_lieu + corp_cash_in_lieu + implied_option_cash_delta_base,
                        )
                        candidate_maps.extend([full_c_map, full_afx_map])

                    end_date_str = end_pt.timestamp_utc[:10]
                    ending_fx_by_ccy: dict[str, float] = {ledger.base_currency: 1.0}
                    for pos in ledger.ending_positions:
                        if pos.currency != ledger.base_currency and pos.fx_rate_to_base > 0.0:
                            ending_fx_by_ccy[pos.currency] = float(pos.fx_rate_to_base)

                    def _closing_fx(ccy_code: str) -> float | None:
                        if ccy_code == ledger.base_currency:
                            return 1.0
                        if ccy_code in ending_fx_by_ccy:
                            return ending_fx_by_ccy[ccy_code]
                        if latest_fx_date_by_ccy.get(ccy_code) == end_date_str:
                            return latest_fx_by_ccy[ccy_code]
                        if reference_provider is not None and reference_provider.is_available:
                            ref_fx = reference_provider.get_fx_rate(
                                ccy_code, ledger.base_currency, date_str=end_date_str
                            )
                            if ref_fx is not None and ref_fx > 0.0:
                                return float(ref_fx)
                        conv_fx = resolve_forex_midpoint(
                            ccy_code,
                            ledger.base_currency,
                            base_currency=ledger.base_currency,
                            date_str=end_date_str,
                            conversion_rates=ledger.conversion_rates,
                        )
                        if conv_fx is not None and conv_fx > 0.0:
                            return float(conv_fx)
                        return latest_fx_by_ccy.get(ccy_code)

                    for candidate_map in candidate_maps:
                        ok_all = True
                        total_c_base = 0.0
                        for c_code, c_amt in candidate_map.items():
                            if abs(c_amt) <= 1e-9:
                                continue
                            c_fx = _closing_fx(c_code)
                            if c_fx is None or c_fx <= 0.0:
                                ok_all = False
                                break
                            total_c_base += c_amt * c_fx
                        if ok_all:
                            multiccy_candidates.append(total_c_base + ending_mv_sum)

                best_multiccy_expected = (
                    min(multiccy_candidates, key=lambda v: abs(float(end_pt.nav_base) - v))
                    if multiccy_candidates
                    else None
                )
                multiccy_residual = (
                    float(end_pt.nav_base) - best_multiccy_expected
                    if best_multiccy_expected is not None
                    else None
                )
                multiccy_tol = (
                    max(5.0, 0.0015 * max(abs(best_multiccy_expected), abs(end_pt.nav_base)))
                    if best_multiccy_expected is not None
                    else tol_abs
                )

                # Strictly for broker-retrieved origins (never SELF_REPORTED!) when opening
                # per-currency CashReport was omitted: check directional FX drift on opening cash.
                if (
                    has_multi_ccy
                    and not is_cfd_fx_broker
                    and not [p for p in ledger.prior_positions if p.asset_class == AssetClass.CASH]
                    and ledger.claimed_origin_assurance
                    in {
                        OriginAssurance.OPERATOR_RETRIEVED,
                        OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
                        OriginAssurance.BROKER_SIGNED,
                    }
                ):
                    same_day_base_deposits = math.fsum(
                        float(fl.amount_base or 0.0)
                        for fl in ledger.flows
                        if fl.kind == FlowKind.DEPOSIT
                        and fl.currency == ledger.base_currency
                        and float(fl.amount_base or 0.0) > 0.0
                        and parse_utc_timestamp(fl.timestamp_utc) <= start_dt
                        and fl.timestamp_utc[:10] == start_pt.timestamp_utc[:10]
                    )
                    opening_cash_signed = (
                        float(start_pt.cash_base)
                        if start_pt.cash_base is not None
                        else opening_cash_and_accruals
                    )
                    unattrib_mag = max(0.0, abs(opening_cash_signed) - same_day_base_deposits)
                    res_to_check = (
                        multiccy_residual if multiccy_residual is not None else nav_residual
                    )
                    if unattrib_mag > 0.0:
                        min_rel = 0.0
                        max_rel = 0.0
                        for c_key, r_open in earliest_fx_by_ccy.items():
                            r_close = _closing_fx(c_key)
                            if r_open > 0.0 and r_close is not None and r_close > 0.0:
                                rel = max(-0.25, min(0.25, (r_close - r_open) / r_open))
                                if opening_cash_signed < 0.0:
                                    rel = -rel
                                min_rel = min(min_rel, rel)
                                max_rel = max(max_rel, rel)
                        lower_bound = unattrib_mag * min_rel - multiccy_tol
                        upper_bound = unattrib_mag * max_rel + multiccy_tol
                        if (min_rel < 0.0 or max_rel > 0.0) and (
                            lower_bound <= res_to_check <= upper_bound
                        ):
                            opening_fx_drift_ok = True

                if multiccy_residual is not None and abs(multiccy_residual) <= multiccy_tol:
                    assert best_multiccy_expected is not None
                    mc_bps = (
                        abs(multiccy_residual)
                        / max(abs(best_multiccy_expected), abs(end_pt.nav_base), 1.0)
                    ) * 10_000.0
                    findings.append(
                        ReconciliationFinding(
                            category="nav_continuity_bridge",
                            outcome=CheckOutcome.EXPLAINED_CONVENTION,
                            date_or_timestamp=end_pt.timestamp_utc,
                            expected_value=best_multiccy_expected,
                            observed_value=float(end_pt.nav_base),
                            residual_bps=mc_bps,
                            residual_base_currency=multiccy_residual,
                            math_identity="EndingNAV == sum_ccy(EndingCash_ccy * ClosingFX_ccy) + EndingPositionsMV",
                            technical_explanation=(
                                "Multi-currency cash sub-ledger (accounting for FX cash conversions and "
                                "closing FX re-marking on non-base cash) reconciles ending NAV within tolerance."
                            ),
                            benign_causes_considered=[
                                "FX translation on non-base currency cash balances",
                                "Explicit spot FX cash conversion legs",
                            ],
                        )
                    )
                elif abs(unsettled_end) > 0.0 and min(
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
                elif has_multi_ccy and (nav_res_bps <= 60.0 or opening_fx_drift_ok):
                    findings.append(
                        ReconciliationFinding(
                            category="nav_continuity_bridge",
                            outcome=CheckOutcome.EXPLAINED_CONVENTION,
                            date_or_timestamp=end_pt.timestamp_utc,
                            expected_value=(
                                best_multiccy_expected
                                if best_multiccy_expected is not None
                                else expected_ending_nav
                            ),
                            observed_value=float(end_pt.nav_base),
                            residual_bps=nav_res_bps,
                            residual_base_currency=nav_residual,
                            math_identity="EndingNAV == ImpliedCash + EndingPositionsMV + FxTranslationDrift",
                            technical_explanation="Multi-currency NAV residual consistent with FX translation on non-base currency cash balances.",
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
