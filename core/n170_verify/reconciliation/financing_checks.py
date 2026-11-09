"""FX closing mark spread, cross-currency dividend accrual, and margin financing checks."""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, timedelta
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
    NormalizedTrade,
    ReconciliationFinding,
    parse_utc_timestamp,
)
from n170_verify.reference.base import (
    ReferenceDataProvider,
    normalize_uk_currency_and_scale,
)
from n170_verify.reference.eodhd_client import normalize_eodhd_exchange, split_eodhd_ticker


MAJOR_FX_CURRENCIES: frozenset[str] = frozenset(
    {"USD", "EUR", "GBP", "JPY", "CHF", "CAD", "AUD", "NZD"}
)
MAJOR_FX_SPREAD_LIMIT_BPS = 25.0
CROSS_FX_SPREAD_LIMIT_BPS = 60.0
EXACT_FX_PASS_BPS = 5.0


def is_major_fx_pair(from_ccy: str, to_ccy: str) -> bool:
    """Return True for G10 USD-leg major pairs (<= 25 bps tolerance); False for crosses (<= 60 bps)."""
    _, norm_a, _ = normalize_uk_currency_and_scale(from_ccy)
    _, norm_b, _ = normalize_uk_currency_and_scale(to_ccy)
    if norm_a == norm_b:
        return True
    return ("USD" in {norm_a, norm_b}) and (norm_a in MAJOR_FX_CURRENCIES) and (
        norm_b in MAJOR_FX_CURRENCIES
    )


def _parse_fx_pair_key(raw_key: str, base_currency: str) -> tuple[str, str] | None:
    cleaned = raw_key.strip().upper()
    if "/" in cleaned:
        parts = cleaned.split("/")
        if len(parts) == 2 and len(parts[0]) >= 3 and len(parts[1]) >= 3:
            return parts[0], parts[1]
        return None
    if len(cleaned) == 6 and cleaned.isalpha():
        return cleaned[:3], cleaned[3:]
    if len(cleaned) == 3 and cleaned.isalpha():
        return cleaned, base_currency
    return None


def reconcile_fx_conversion_marks(
    ledger: CanonicalPortfolioLedger,
    *,
    reference_provider: ReferenceDataProvider | None = None,
) -> list[ReconciliationFinding]:
    """Compare ledger FX closing conversion rates against reference FOREX marks (25 bps major / 60 bps cross)."""
    findings: list[ReconciliationFinding] = []
    end_date = ledger.period_end_utc[:10]

    candidate_pairs: dict[tuple[str, str], float] = {}
    for key, rate in sorted(ledger.conversion_rates.items()):
        parsed = _parse_fx_pair_key(key, ledger.base_currency)
        if parsed is not None and parsed[0] != parsed[1]:
            candidate_pairs[parsed] = float(rate)

    for pos in ledger.ending_positions:
        _, norm_pos_ccy, pos_scale = normalize_uk_currency_and_scale(pos.currency)
        if norm_pos_ccy != ledger.base_currency:
            # Normalize GBX fx_rate_to_base (0.01x of GBP) onto canonical GBP->base scale.
            effective_fx = float(pos.fx_rate_to_base) / pos_scale
            candidate_pairs.setdefault((norm_pos_ccy, ledger.base_currency), effective_fx)

    if not candidate_pairs:
        return findings

    if reference_provider is None or not reference_provider.is_available:
        for (from_c, to_c), obs_rate in sorted(candidate_pairs.items()):
            findings.append(
                ReconciliationFinding(
                    category="fx_closing_mark_spread",
                    outcome=CheckOutcome.NOT_EVALUATED,
                    date_or_timestamp=ledger.period_end_utc,
                    symbol=f"{from_c}/{to_c}",
                    expected_value=None,
                    observed_value=obs_rate,
                    math_identity="|ObservedFX - ReferenceFX| / ReferenceFX <= 25 bps (major) / 60 bps (cross)",
                    technical_explanation="External FOREX reference data unavailable; FX mark spread not evaluated.",
                    benign_causes_considered=["Offline verification without EODHD API key"],
                )
            )
        return findings

    for (from_c, to_c), obs_rate in sorted(candidate_pairs.items()):
        ref_rate = reference_provider.get_fx_rate(from_c, to_c, date_str=end_date)
        pair_label = f"{from_c}/{to_c}"
        if ref_rate is None or ref_rate <= 0.0:
            findings.append(
                ReconciliationFinding(
                    category="fx_closing_mark_spread",
                    outcome=CheckOutcome.NOT_EVALUATED,
                    date_or_timestamp=ledger.period_end_utc,
                    symbol=pair_label,
                    expected_value=None,
                    observed_value=obs_rate,
                    math_identity="|ObservedFX - ReferenceFX| / ReferenceFX <= SpreadLimit",
                    technical_explanation=f"Reference closing FX mark unavailable for {pair_label} on {end_date}.",
                    benign_causes_considered=["Holiday or exotic currency pair"],
                )
            )
            continue

        spread_bps = (abs(obs_rate - ref_rate) / ref_rate) * 10_000.0
        major = is_major_fx_pair(from_c, to_c)
        limit_bps = MAJOR_FX_SPREAD_LIMIT_BPS if major else CROSS_FX_SPREAD_LIMIT_BPS
        tier_label = "G10 major (<= 25 bps)" if major else "FX cross (<= 60 bps)"

        if spread_bps <= EXACT_FX_PASS_BPS:
            outcome = CheckOutcome.PASS
            explanation = (
                f"Closing FX mark for {pair_label} ({obs_rate:.6f}) matches reference ({ref_rate:.6f}) "
                f"within {spread_bps:.2f} bps."
            )
        elif spread_bps <= limit_bps:
            outcome = CheckOutcome.EXPLAINED_CONVENTION
            explanation = (
                f"Closing FX mark for {pair_label} ({obs_rate:.6f} vs {ref_rate:.6f}, {spread_bps:.2f} bps) "
                f"lies within standard {tier_label} fixing cut-off convention."
            )
        else:
            outcome = CheckOutcome.DISCREPANCY
            explanation = (
                f"Closing FX mark for {pair_label} ({obs_rate:.6f}) deviates by {spread_bps:.2f} bps from "
                f"reference ({ref_rate:.6f}), exceeding {tier_label} bound."
            )

        findings.append(
            ReconciliationFinding(
                category="fx_closing_mark_spread",
                outcome=outcome,
                date_or_timestamp=ledger.period_end_utc,
                symbol=pair_label,
                expected_value=ref_rate,
                observed_value=obs_rate,
                residual_bps=spread_bps,
                residual_base_currency=None,
                math_identity=f"|ObservedFX - ReferenceFX| / ReferenceFX <= {limit_bps:.0f} bps",
                technical_explanation=explanation,
                benign_causes_considered=[
                    "WM/Refinitiv 16:00 London vs 17:00 New York FX fixing cut-off",
                    "ECB 14:15 CET reference rate vs EOD composite close",
                    "Broker retail FX translation spread",
                ],
            )
        )

    return findings


_OCC_OPTION_RE = re.compile(r"^([A-Z0-9.\-]+?)\s*(\d{6})([CP])(\d{8})$")


def _canon_sym(sym: str) -> str:
    return " ".join(sym.strip().upper().split())


def _infer_opt_meta(symbol: str, description: str = "") -> tuple[str | None, str | None]:
    compact = symbol.strip().upper()
    m = _OCC_OPTION_RE.match(compact)
    if m:
        return m.group(1).strip(), m.group(3)
    combined = f"{compact} {description.upper()}"
    if re.search(r"\bPUT\b", combined):
        return None, "P"
    if re.search(r"\bCALL\b", combined):
        return None, "C"
    return None, None


def _has_explicit_eae_stock_trade(
    trades: list[NormalizedTrade] | tuple[NormalizedTrade, ...],
    *,
    underlying_symbol: str,
    action_date: str,
    expected_shares: float,
) -> bool:
    target = _canon_sym(underlying_symbol)
    for tr in trades:
        if tr.asset_class == AssetClass.OPTION:
            continue
        if _canon_sym(tr.symbol) != target:
            continue
        if tr.timestamp_utc[:10] != action_date:
            continue
        if abs(abs(float(tr.quantity)) - abs(expected_shares)) > 1e-6:
            continue
        id_lower = f"{tr.native_entry_id} {tr.venue}".lower()
        if any(tok in id_lower for tok in ("eae", "exerc", "assign")):
            return True
    return False


def _held_shares_on_date(ledger: CanonicalPortfolioLedger, symbol: str, target_date: str) -> float | None:
    """Reconstruct held share count for ``symbol`` prior to ``target_date`` (including splits & OptionEAE)."""
    sym_upper = _canon_sym(symbol)
    qty_by_sym: dict[str, float] = defaultdict(float)
    opt_meta: dict[str, tuple[str | None, str | None, float]] = {}
    saw_any = False

    for p in ledger.prior_positions:
        psym = _canon_sym(p.symbol)
        if p.asset_class in {AssetClass.EQUITY, AssetClass.ETF}:
            qty_by_sym[psym] += float(p.quantity)
            if psym == sym_upper:
                saw_any = True
        elif p.asset_class == AssetClass.OPTION:
            qty_by_sym[psym] += float(p.quantity)
            und_g, right_g = _infer_opt_meta(psym)
            opt_meta[psym] = (
                _canon_sym(p.underlying_symbol) if p.underlying_symbol else und_g,
                p.option_right or right_g,
                float(p.multiplier or 100.0),
            )

    events: list[tuple[datetime, int, str, object]] = []
    for tr in ledger.trades:
        if tr.asset_class == AssetClass.CASH:
            continue
        events.append((parse_utc_timestamp(tr.timestamp_utc), 1, "trade", tr))
    for fl in ledger.flows:
        if (
            fl.symbol
            and fl.kind in {FlowKind.TRANSFER_IN_KIND, FlowKind.TRANSFER_OUT_KIND}
            and fl.quantity is not None
        ):
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

    for _, _, ev_kind, payload in events:
        if ev_kind == "trade":
            assert isinstance(payload, NormalizedTrade)
            if payload.asset_class == AssetClass.FX:
                continue
            tsym = _canon_sym(payload.symbol)
            if tsym == sym_upper and payload.asset_class in {AssetClass.EQUITY, AssetClass.ETF}:
                saw_any = True
            if payload.timestamp_utc[:10] >= target_date:
                continue
            if payload.asset_class in {AssetClass.EQUITY, AssetClass.ETF}:
                qty_by_sym[tsym] += (
                    abs(float(payload.quantity)) if payload.side == "buy" else -abs(float(payload.quantity))
                )
            elif payload.asset_class == AssetClass.OPTION:
                qty_by_sym[tsym] += (
                    abs(float(payload.quantity)) if payload.side == "buy" else -abs(float(payload.quantity))
                )
                prev_und, prev_right, prev_mult = opt_meta.get(tsym, (None, None, 100.0))
                und_g, right_g = _infer_opt_meta(tsym)
                opt_meta[tsym] = (
                    _canon_sym(payload.underlying_symbol)
                    if payload.underlying_symbol
                    else (prev_und or und_g),
                    payload.option_right or prev_right or right_g,
                    float(payload.multiplier or prev_mult or 100.0),
                )

        elif ev_kind == "flow":
            assert isinstance(payload, NormalizedFlow)
            assert payload.symbol is not None and payload.quantity is not None
            fsym = _canon_sym(payload.symbol)
            if fsym == sym_upper:
                saw_any = True
            if payload.timestamp_utc[:10] >= target_date:
                continue
            qty_by_sym[fsym] += (
                abs(float(payload.quantity))
                if payload.kind == FlowKind.TRANSFER_IN_KIND
                else -abs(float(payload.quantity))
            )

        elif ev_kind == "corp":
            assert isinstance(payload, CorporateActionRecord)
            csym = _canon_sym(payload.symbol)
            new_csym = _canon_sym(payload.new_symbol) if payload.new_symbol else None
            und_csym = _canon_sym(payload.underlying_symbol) if payload.underlying_symbol else None
            if sym_upper in {csym, new_csym, und_csym}:
                saw_any = True
            if payload.timestamp_utc[:10] >= target_date:
                continue
            ctype = payload.action_type
            if ctype in {CorporateActionType.SPLIT, CorporateActionType.REVERSE_SPLIT}:
                cur_q = qty_by_sym[csym]
                if payload.ratio_numerator is not None and payload.ratio_denominator is not None:
                    ratio = float(payload.ratio_numerator) / float(payload.ratio_denominator)
                    if payload.quantity_delta != 0.0 and cur_q != 0.0:
                        implied_delta = cur_q * (ratio - 1.0)
                        qty_by_sym[csym] = (
                            cur_q * ratio
                            if abs(implied_delta - payload.quantity_delta) <= 1e-5
                            else cur_q + float(payload.quantity_delta)
                        )
                    else:
                        qty_by_sym[csym] = cur_q * ratio
                else:
                    qty_by_sym[csym] = cur_q + float(payload.quantity_delta)
            elif ctype in {CorporateActionType.SYMBOL_CHANGE, CorporateActionType.MERGER}:
                old_q = qty_by_sym.pop(csym, 0.0)
                if new_csym:
                    if payload.ratio_numerator is not None and payload.ratio_denominator is not None:
                        ratio = float(payload.ratio_numerator) / float(payload.ratio_denominator)
                        delivered = (
                            old_q * ratio if payload.quantity_delta == 0.0 else float(payload.quantity_delta)
                        )
                    else:
                        delivered = old_q if payload.quantity_delta == 0.0 else float(payload.quantity_delta)
                    qty_by_sym[new_csym] += delivered
                    if new_csym == sym_upper:
                        saw_any = True
            elif ctype in {CorporateActionType.SPIN_OFF, CorporateActionType.STOCK_GRANT}:
                tgt = new_csym or csym
                if payload.quantity_delta != 0.0:
                    qty_by_sym[tgt] += float(payload.quantity_delta)
                elif (
                    new_csym
                    and payload.ratio_numerator is not None
                    and payload.ratio_denominator is not None
                ):
                    qty_by_sym[tgt] += qty_by_sym[csym] * (
                        float(payload.ratio_numerator) / float(payload.ratio_denominator)
                    )
            elif ctype in {CorporateActionType.OPTION_EXERCISE, CorporateActionType.OPTION_ASSIGNMENT}:
                cur_opt_q = qty_by_sym[csym]
                contracts_closed = (
                    abs(float(payload.quantity_delta))
                    if payload.quantity_delta != 0.0
                    else abs(cur_opt_q)
                )
                if cur_opt_q > 0.0:
                    qty_by_sym[csym] = cur_opt_q - contracts_closed
                elif cur_opt_q < 0.0:
                    qty_by_sym[csym] = cur_opt_q + contracts_closed
                else:
                    qty_by_sym[csym] = cur_opt_q + float(payload.quantity_delta)

                prev_und, prev_right, prev_mult = opt_meta.get(csym, (None, None, 100.0))
                und_g, right_g = _infer_opt_meta(csym, payload.description)
                opt_right = prev_right or right_g
                mult = float(payload.option_multiplier or prev_mult or 100.0)
                und_target = und_csym or prev_und or und_g
                if und_target:
                    if und_target == sym_upper:
                        saw_any = True
                    share_sign = (
                        (-1.0 if opt_right == "P" else 1.0)
                        if ctype == CorporateActionType.OPTION_EXERCISE
                        else (1.0 if opt_right == "P" else -1.0)
                    )
                    delivered_shares = share_sign * contracts_closed * mult
                    if not _has_explicit_eae_stock_trade(
                        ledger.trades,
                        underlying_symbol=und_target,
                        action_date=payload.timestamp_utc[:10],
                        expected_shares=delivered_shares,
                    ):
                        qty_by_sym[und_target] += delivered_shares

    if not saw_any:
        end_match = [
            float(p.quantity)
            for p in ledger.ending_positions
            if _canon_sym(p.symbol) == sym_upper and p.asset_class in {AssetClass.EQUITY, AssetClass.ETF}
        ]
        if end_match:
            return sum(end_match)
        return None
    return qty_by_sym[sym_upper]


def reconcile_dividend_flows(
    ledger: CanonicalPortfolioLedger,
    *,
    reference_provider: ReferenceDataProvider | None = None,
) -> list[ReconciliationFinding]:
    """Verify ledger dividend flows against EODHD ``/api/div/`` ``unadjustedValue`` + declaration FX."""
    findings: list[ReconciliationFinding] = []
    div_flows = [fl for fl in ledger.flows if fl.kind == FlowKind.DIVIDEND and fl.symbol]
    if not div_flows:
        return findings

    if reference_provider is None or not reference_provider.is_available:
        for fl in div_flows:
            findings.append(
                ReconciliationFinding(
                    category="dividend_accrual_check",
                    outcome=CheckOutcome.NOT_EVALUATED,
                    date_or_timestamp=fl.timestamp_utc,
                    symbol=fl.symbol,
                    observed_value=float(fl.amount_base or 0.0),
                    math_identity="DividendBase == HeldSharesOnExDate * unadjustedValue * DeclarationFX",
                    technical_explanation="Reference dividend schedule unavailable in offline mode.",
                    benign_causes_considered=["Offline verification without EODHD API key"],
                )
            )
        return findings

    # Map withholding tax flows by (symbol, date) if split out separately.
    wht_by_sym: dict[str, float] = defaultdict(float)
    for fl in ledger.flows:
        if fl.kind == FlowKind.WITHHOLDING_TAX and fl.symbol:
            wht_by_sym[fl.symbol.strip().upper()] += abs(float(fl.amount_base or 0.0))

    for fl in div_flows:
        assert fl.symbol is not None
        sym_upper = fl.symbol.strip().upper()
        fl_date = fl.timestamp_utc[:10]
        fl_dt = date.fromisoformat(fl_date)

        ex_hint = normalize_eodhd_exchange(None, isin=fl.isin, currency=fl.currency)
        resolved = reference_provider.resolve_security(
            sym_upper,
            exchange=ex_hint,
            isin=fl.isin,
            currency=fl.currency,
        )
        ticker = resolved.canonical_ticker if resolved is not None else f"{split_eodhd_ticker(sym_upper, default_exchange=ex_hint)[0]}.{ex_hint}"

        divs = reference_provider.get_dividends(
            ticker,
            start_date=(fl_dt - timedelta(days=60)).isoformat(),
            end_date=(fl_dt + timedelta(days=10)).isoformat(),
        )
        if not divs:
            findings.append(
                ReconciliationFinding(
                    category="dividend_accrual_check",
                    outcome=CheckOutcome.NOT_EVALUATED,
                    date_or_timestamp=fl.timestamp_utc,
                    symbol=sym_upper,
                    observed_value=float(fl.amount_base or 0.0),
                    math_identity="DividendBase == HeldSharesOnExDate * unadjustedValue * DeclarationFX",
                    technical_explanation=f"No matching EODHD /api/div/ event found near {fl_date} for {ticker}.",
                    benign_causes_considered=["Money-market ETF / ADR pass-through fee / special distribution"],
                )
            )
            continue

        # Match closest dividend by paymentDate == fl_date or ex_date <= fl_date.
        pay_matches = [d for d in divs if d.payment_date == fl_date]
        ex_matches = [d for d in divs if d.ex_date == fl_date]
        prior_ex = [d for d in divs if d.ex_date <= fl_date]
        matched_div = (
            pay_matches[-1]
            if pay_matches
            else (ex_matches[-1] if ex_matches else (prior_ex[-1] if prior_ex else divs[-1]))
        )

        shares = _held_shares_on_date(ledger, sym_upper, matched_div.ex_date)
        fx_to_base = reference_provider.get_fx_rate(
            matched_div.currency,
            ledger.base_currency,
            date_str=fl_date,
        )
        if shares is None or shares <= 0.0 or fx_to_base is None or fx_to_base <= 0.0:
            continue

        expected_gross_base = shares * matched_div.unadjusted_value * fx_to_base
        observed_base = float(fl.amount_base or 0.0)
        separate_wht = wht_by_sym.get(sym_upper, 0.0)

        diff = observed_base - expected_gross_base
        rel_bps = (abs(diff) / max(expected_gross_base, 1.0)) * 10_000.0
        booked_on_pay_date = (
            matched_div.payment_date is not None
            and matched_div.payment_date != matched_div.ex_date
            and fl_date == matched_div.payment_date
        )

        # Exact gross match
        if abs(diff) <= max(1.0, 0.02 * expected_gross_base):
            outcome = CheckOutcome.EXPLAINED_CONVENTION if booked_on_pay_date else CheckOutcome.PASS
            explanation = (
                f"Pay-date dividend cash receipt ({fl_date}, ex-date {matched_div.ex_date}) matches "
                f"/api/div/ unadjustedValue ({matched_div.unadjusted_value:g} {matched_div.currency})."
                if booked_on_pay_date
                else f"Dividend matches /api/div/ unadjustedValue ({matched_div.unadjusted_value:g} {matched_div.currency})."
            )
        # Net-of-withholding booking (typically 10%-35% statutory treaty tax when WHT isn't a separate line)
        elif separate_wht == 0.0 and (0.60 * expected_gross_base <= observed_base <= 0.95 * expected_gross_base):
            outcome = CheckOutcome.EXPLAINED_CONVENTION
            explanation = (
                f"Dividend flow ({observed_base:.2f} {ledger.base_currency}) reflects net-of-withholding payout "
                f"on gross {expected_gross_base:.2f} {ledger.base_currency} (/api/div/ unadjustedValue)."
            )
        else:
            fx_ex = (
                reference_provider.get_fx_rate(
                    matched_div.currency,
                    ledger.base_currency,
                    date_str=matched_div.ex_date,
                )
                if matched_div.currency != ledger.base_currency and matched_div.ex_date != fl_date
                else None
            )
            ex_expected = (
                shares * matched_div.unadjusted_value * fx_ex
                if fx_ex is not None and fx_ex > 0.0
                else None
            )
            if ex_expected is not None and (
                abs(observed_base - ex_expected) <= max(1.0, 0.02 * ex_expected)
                or (separate_wht == 0.0 and (0.60 * ex_expected <= observed_base <= 0.95 * ex_expected))
            ):
                outcome = CheckOutcome.EXPLAINED_CONVENTION
                expected_gross_base = ex_expected
                diff = observed_base - expected_gross_base
                rel_bps = (abs(diff) / max(expected_gross_base, 1.0)) * 10_000.0
                explanation = (
                    f"Cross-currency dividend flow ({observed_base:.2f} {ledger.base_currency}) matches "
                    f"ex-date ({matched_div.ex_date}) FX valuation of /api/div/ unadjustedValue."
                )
            else:
                outcome = CheckOutcome.DISCREPANCY
                explanation = (
                    f"Dividend flow ({observed_base:.2f} {ledger.base_currency}) diverges from expected "
                    f"{expected_gross_base:.2f} {ledger.base_currency} derived from /api/div/ unadjustedValue."
                )

        findings.append(
            ReconciliationFinding(
                category="dividend_accrual_check",
                outcome=outcome,
                date_or_timestamp=fl.timestamp_utc,
                symbol=sym_upper,
                expected_value=expected_gross_base,
                observed_value=observed_base,
                residual_bps=rel_bps,
                residual_base_currency=diff,
                math_identity="DividendBase == HeldShares * unadjustedValue * DeclarationCurrencyFX",
                technical_explanation=explanation,
                benign_causes_considered=[
                    "Ex-date accrual vs pay-date cash settlement convention",
                    "Net-of-withholding dividend booking without separate tax row",
                    "ADR depositary pass-through fee deduction",
                    "Cross-currency FX rate on pay-date vs ex-date",
                ],
            )
        )

    return findings


def reconcile_financing_accruals(
    ledger: CanonicalPortfolioLedger,
) -> list[ReconciliationFinding]:
    """Check margin interest and perpetual funding flow sign and settlement timing conventions."""
    findings: list[ReconciliationFinding] = []
    nav_scale = max(
        (abs(float(pt.nav_base)) for pt in ledger.nav_points),
        default=1.0,
    )
    min_cash = min(
        (float(pt.cash_base) for pt in ledger.nav_points if pt.cash_base is not None),
        default=0.0,
    )

    for fl in ledger.flows:
        if fl.kind != FlowKind.MARGIN_INTEREST:
            continue
        amt = float(fl.amount_base or 0.0)
        ts = parse_utc_timestamp(fl.timestamp_utc)
        # Positive margin interest inflow > $10 and > 10 bps while account carries debit cash is anomalous.
        if amt > max(10.0, 0.0010 * nav_scale) and min_cash <= 0.0:
            findings.append(
                ReconciliationFinding(
                    category="margin_financing_check",
                    outcome=CheckOutcome.DISCREPANCY,
                    date_or_timestamp=fl.timestamp_utc,
                    expected_value=0.0,
                    observed_value=amt,
                    residual_bps=(amt / max(nav_scale, 1.0)) * 10_000.0,
                    residual_base_currency=amt,
                    math_identity="MarginDebitInterest <= 0",
                    technical_explanation=f"Margin interest entry reported as positive inflow ({amt:+.2f} {ledger.base_currency}).",
                    benign_causes_considered=[
                        "Prior-month broker interest rebate / adjustment reversal",
                        "Misclassified credit interest or securities-lending fee",
                    ],
                )
            )
        elif ts.day <= 7 and amt < 0.0:
            findings.append(
                ReconciliationFinding(
                    category="margin_financing_check",
                    outcome=CheckOutcome.EXPLAINED_CONVENTION,
                    date_or_timestamp=fl.timestamp_utc,
                    observed_value=amt,
                    residual_bps=0.0,
                    residual_base_currency=0.0,
                    math_identity="MonthlyMarginInterestSettlement in BusinessDays[1..5]",
                    technical_explanation="Prior-month accrued margin interest settled in early-month cash cycle.",
                    benign_causes_considered=[
                        "Monthly broker interest accrual vs early-next-month cash debit convention",
                    ],
                )
            )
        elif math.isfinite(amt):
            findings.append(
                ReconciliationFinding(
                    category="margin_financing_check",
                    outcome=CheckOutcome.PASS,
                    date_or_timestamp=fl.timestamp_utc,
                    observed_value=amt,
                    residual_bps=0.0,
                    residual_base_currency=0.0,
                    math_identity="MarginDebitInterest <= 0",
                    technical_explanation="Margin financing debit consistent with leverage convention.",
                    benign_causes_considered=[],
                )
            )

    return findings


__all__ = [
    "CROSS_FX_SPREAD_LIMIT_BPS",
    "EXACT_FX_PASS_BPS",
    "MAJOR_FX_CURRENCIES",
    "MAJOR_FX_SPREAD_LIMIT_BPS",
    "is_major_fx_pair",
    "reconcile_dividend_flows",
    "reconcile_financing_accruals",
    "reconcile_fx_conversion_marks",
]
