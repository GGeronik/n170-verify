"""MetaTrader 4/5 (FX/CFD/Prop) and Tradovate (CME/NYMEX/COMEX Futures) offline statement importers.

Guarantees:
- Strictly assigns ``OriginAssurance.SELF_REPORTED``, ``AccountScope.UNKNOWN_OFFLINE_SCOPE``,
  and ``ProviderApprovalState.OFFLINE_EXPORT_ONLY``.
- Enforces ``MAX_STATEMENT_BYTES`` (``25 MB``), ``reject_xxe_and_dtd_declarations`` before
  any HTML parsing, and ``sanitize_csv_text_field`` across all text/symbol/comment cells.
- Rejects MetaTrader Demo/Contest servers and Tradovate Sim/Demo accounts with
  ``PaperOrSandboxAccountRejectedError`` when ``reject_demo=True`` (or marks
  ``EnvironmentTier.PAPER_OR_SANDBOX_REJECTED`` when ``reject_demo=False``).
- Resolves CME/NYMEX/COMEX root futures contract multipliers accurately across month-coded
  contracts (e.g. ``ESH6`` -> ``ES`` ``50.0``, ``MESZ5`` -> ``MES`` ``5.0``, ``NQM26`` -> ``NQ`` ``20.0``).
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
from html.parser import HTMLParser
import re
from typing import Any

from n170_verify.connectors.ccxt_crypto import PaperOrSandboxAccountRejectedError
from n170_verify.connectors.statement_csv import (
    MAX_STATEMENT_BYTES,
    OfflineExportAdapterBase,
    StatementSizeLimitExceededError,
    _cell,
    _find_col,
    _parse_localized_float,
    _parse_multi_format_timestamp,
    _read_csv_rows,
    decode_statement_bytes,
    enforce_statement_size_limit,
    reject_unofficial_scraper_credentials,
    reject_xxe_and_dtd_declarations,
    sanitize_csv_text_field,
)
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    CanonicalPortfolioLedger,
    EnvironmentTier,
    FlowKind,
    NormalizedFlow,
    NormalizedNavPoint,
    NormalizedPosition,
    NormalizedTrade,
    OriginAssurance,
    ProviderApprovalState,
    ReadOnlyBrokerAdapter,
    compute_blinded_account_tag,
)


FUTURES_POINT_MULTIPLIERS: dict[str, float] = {
    "ES": 50.0,
    "MES": 5.0,
    "NQ": 20.0,
    "MNQ": 2.0,
    "CL": 1000.0,
    "MCL": 100.0,
    "GC": 100.0,
    "MGC": 10.0,
    "YM": 5.0,
    "MYM": 0.5,
    "RTY": 50.0,
    "M2K": 5.0,
}

_CME_CONTRACT_RE = re.compile(r"^([A-Z0-9]{1,5}?)[FGHJKMNQUVXZ](\d{1,4})$")

_ISO_FX_CURRENCIES: frozenset[str] = frozenset(
    {
        "USD",
        "EUR",
        "GBP",
        "JPY",
        "CHF",
        "CAD",
        "AUD",
        "NZD",
        "SEK",
        "NOK",
        "DKK",
        "SGD",
        "HKD",
        "MXN",
        "ZAR",
        "TRY",
        "PLN",
        "CNH",
    }
)

_DEMO_SERVER_RE = re.compile(
    r"(?:\b(?:demo|contest|practice|trial|simulated|paper|playmoney)\b|-demo\d*\b)",
    re.IGNORECASE,
)
_MT_ACCOUNT_RE = re.compile(r"\baccount\s*[:#]?\s*([0-9]{4,20})\b", re.IGNORECASE)
_MT_CURRENCY_RE = re.compile(r"\bcurrency\s*[:#]?\s*([A-Z]{3})\b", re.IGNORECASE)
_MT_PAREN_CCY_RE = re.compile(r"\(([A-Z]{3})\s*,", re.IGNORECASE)
_TRADOVATE_DEMO_ACCT_RE = re.compile(r"^(?:demo|sim|paper|practice)[a-z0-9_-]*$", re.IGNORECASE)


def resolve_futures_root_and_multiplier(symbol: str) -> tuple[str, float]:
    """Strip futures contract month/year codes (e.g. ``ESH6``, ``MESZ5``, ``NQM26``) and resolve point multiplier."""
    cleaned = sanitize_csv_text_field(symbol).lstrip("/").strip().upper()
    if not cleaned:
        return "", 1.0

    # Strip venue suffix if present (e.g. "ESH6.CME" or "NQM26:XCME")
    primary = re.split(r"[.:#]", cleaned)[0].strip()
    if primary in FUTURES_POINT_MULTIPLIERS:
        return primary, FUTURES_POINT_MULTIPLIERS[primary]

    # Space/hyphen separated contract e.g. "ES 03-26" or "MES MAR26"
    first_tok = re.split(r"[\s_-]+", primary)[0].strip()
    if first_tok in FUTURES_POINT_MULTIPLIERS:
        return first_tok, FUTURES_POINT_MULTIPLIERS[first_tok]

    m = _CME_CONTRACT_RE.match(first_tok)
    if m:
        root = m.group(1)
        if root in FUTURES_POINT_MULTIPLIERS:
            return root, FUTURES_POINT_MULTIPLIERS[root]
        return root, 1.0

    return first_tok, FUTURES_POINT_MULTIPLIERS.get(first_tok, 1.0)


def compute_futures_roundtrip_pnl(
    symbol: str,
    buy_price: float,
    sell_price: float,
    quantity: float,
) -> float:
    """Compute gross base-currency PnL using CME/NYMEX/COMEX point multipliers."""
    _, mult = resolve_futures_root_and_multiplier(symbol)
    val = (float(sell_price) - float(buy_price)) * abs(float(quantity)) * mult
    return 0.0 if val == 0.0 else val


def _infer_mt_instrument_spec(
    raw_symbol: str,
    base_currency: str,
    *,
    open_price: float | None = None,
    close_price: float | None = None,
    lots: float | None = None,
    reported_profit_base: float | None = None,
) -> tuple[str, AssetClass, str, float, float]:
    """Return ``(sanitized_symbol, asset_class, trade_ccy, multiplier, fx_rate_to_base)``."""
    sym = sanitize_csv_text_field(raw_symbol)
    if not sym:
        return "UNKNOWN", AssetClass.FX, base_currency, 1.0, 1.0

    alpha_prefix = re.sub(r"[^A-Za-z0-9]", "", sym).upper()

    # 1. Known CME/NYMEX/COMEX futures root or contract
    fut_root, fut_mult = resolve_futures_root_and_multiplier(sym)
    if fut_root in FUTURES_POINT_MULTIPLIERS:
        return sym, AssetClass.FUTURE, base_currency, fut_mult, 1.0

    # 2. Precious metals spot CFDs (XAUUSD = 100 oz/lot, XAGUSD = 5000 oz/lot)
    if alpha_prefix.startswith("XAU") and len(alpha_prefix) >= 6:
        quote = alpha_prefix[3:6]
        trade_ccy = quote if quote in _ISO_FX_CURRENCIES else base_currency
        fx = 1.0
        if (
            trade_ccy != base_currency
            and open_price is not None
            and close_price is not None
            and lots
            and reported_profit_base
            and abs(close_price - open_price) > 1e-9
        ):
            cand = abs(reported_profit_base) / (abs(close_price - open_price) * abs(lots) * 100.0)
            if cand > 0.0:
                fx = cand
        return sym, AssetClass.FUTURE, trade_ccy, 100.0, fx

    if alpha_prefix.startswith("XAG") and len(alpha_prefix) >= 6:
        quote = alpha_prefix[3:6]
        trade_ccy = quote if quote in _ISO_FX_CURRENCIES else base_currency
        return sym, AssetClass.FUTURE, trade_ccy, 5000.0, 1.0

    # 3. 6-letter ISO FX pair (with optional broker suffix like EURUSD.pro / EURUSDm)
    if len(alpha_prefix) >= 6:
        ccy1, ccy2 = alpha_prefix[:3], alpha_prefix[3:6]
        if ccy1 in _ISO_FX_CURRENCIES and ccy2 in _ISO_FX_CURRENCIES and ccy1 != ccy2:
            lot_units = 100_000.0
            if ccy2 == base_currency:
                return sym, AssetClass.FX, base_currency, lot_units, 1.0
            fx = 1.0
            if (
                open_price is not None
                and close_price is not None
                and lots
                and reported_profit_base
                and abs(close_price - open_price) > 1e-9
            ):
                cand = abs(reported_profit_base) / (
                    abs(close_price - open_price) * abs(lots) * lot_units
                )
                if cand > 0.0:
                    fx = cand
            elif ccy1 == base_currency and (close_price or open_price):
                ref_px = close_price or open_price or 1.0
                if ref_px > 0.0:
                    fx = 1.0 / ref_px
            return sym, AssetClass.FX, ccy2, lot_units, fx

    # 4. Crypto CFDs
    if any(alpha_prefix.startswith(c) for c in ("BTC", "ETH", "SOL", "XRP")):
        return sym, AssetClass.CRYPTO_SPOT, base_currency, 1.0, 1.0

    # 5. Index / Commodity CFDs — infer effective contract size if round-trip profit is present
    inferred_mult = 1.0
    if (
        open_price is not None
        and close_price is not None
        and lots
        and reported_profit_base
        and abs(close_price - open_price) > 1e-9
        and abs(lots) > 0.0
    ):
        cand_mult = abs(reported_profit_base) / (abs(close_price - open_price) * abs(lots))
        if cand_mult > 0.0:
            inferred_mult = round(cand_mult, 6)
    return sym, AssetClass.FUTURE, base_currency, inferred_mult, 1.0


class _HtmlTableExtractor(HTMLParser):
    """Zero-dependency HTML table and title extractor for MT4 & MT5 statements."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.rows: list[list[tuple[str, int]]] = []
        self._in_title = False
        self._in_ignored_tag = 0
        self._current_row: list[tuple[str, int]] | None = None
        self._current_cell: list[str] | None = None
        self._current_colspan = 1

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        if t in {"script", "style"}:
            self._in_ignored_tag += 1
            return
        if self._in_ignored_tag:
            return
        if t == "title":
            self._in_title = True
        elif t == "tr":
            self._current_row = []
        elif t in {"td", "th"} and self._current_row is not None:
            self._current_cell = []
            colspan = 1
            for k, v in attrs:
                if k.lower() == "colspan" and v:
                    m = re.match(r"^\s*(\d+)", v)
                    if m:
                        colspan = max(1, min(32, int(m.group(1))))
            self._current_colspan = colspan
        elif t == "br" and self._current_cell is not None:
            self._current_cell.append(" ")

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in {"script", "style"} and self._in_ignored_tag > 0:
            self._in_ignored_tag -= 1
            return
        if self._in_ignored_tag:
            return
        if t == "title":
            self._in_title = False
        elif t in {"td", "th"} and self._current_row is not None and self._current_cell is not None:
            text = " ".join("".join(self._current_cell).split())
            self._current_row.append((text, self._current_colspan))
            self._current_cell = None
            self._current_colspan = 1
        elif t == "tr" and self._current_row is not None:
            if any(c[0] for c in self._current_row):
                self.rows.append(self._current_row)
            self._current_row = None

    def handle_data(self, data: str) -> None:
        if self._in_ignored_tag:
            return
        if self._in_title:
            self.title_parts.append(data)
        if self._current_cell is not None:
            self._current_cell.append(data)


def _extract_html_rows(html_text: str) -> tuple[str, list[list[str]], list[list[tuple[str, int]]]]:
    parser = _HtmlTableExtractor()
    parser.feed(html_text)
    parser.close()
    title = " ".join("".join(parser.title_parts).split())
    plain_rows = [[cell_text for cell_text, _ in row] for row in parser.rows]
    return title, plain_rows, parser.rows


def _parse_mt_volume(raw: str | None) -> float | None:
    if not raw:
        return None
    # MT5 Orders/Deals sometimes render volume as "1.00 / 1.00" or "0.50 / 0.50"
    cleaned = raw.strip()
    if "/" in cleaned:
        parts = [p.strip() for p in cleaned.split("/") if p.strip()]
        if len(parts) == 2:
            filled = _parse_localized_float(parts[1])
            ordered = _parse_localized_float(parts[0])
            if filled is not None and filled > 0:
                return filled
            return ordered
    return _parse_localized_float(cleaned)


def _detect_mt_metadata(
    title: str,
    rows: list[list[str]],
    default_currency: str,
) -> tuple[str | None, str, bool]:
    """Return ``(raw_account_id, base_currency, is_demo)`` from MT4/MT5 header rows."""
    header_texts = [title] + [" | ".join(r) for r in rows[:15]]
    combined_header = "\n".join(header_texts)

    acct_id: str | None = None
    m_acct = _MT_ACCOUNT_RE.search(combined_header)
    if m_acct:
        acct_id = m_acct.group(1)

    base_ccy = default_currency.strip().upper() or "USD"
    m_ccy = _MT_CURRENCY_RE.search(combined_header)
    if m_ccy:
        cand = m_ccy.group(1).upper()
        if cand in _ISO_FX_CURRENCIES:
            base_ccy = cand
    else:
        m_pccy = _MT_PAREN_CCY_RE.search(combined_header)
        if m_pccy and m_pccy.group(1).upper() in _ISO_FX_CURRENCIES:
            base_ccy = m_pccy.group(1).upper()

    is_demo = bool(_DEMO_SERVER_RE.search(combined_header))
    return acct_id, base_ccy, is_demo


def parse_mt4_statement(
    source: bytes | str,
    *,
    blinding_salt_hex: str = "ab" * 32,
    base_currency: str = "USD",
    reject_demo: bool = True,
    max_bytes: int = MAX_STATEMENT_BYTES,
    **extra_kwargs: Any,
) -> CanonicalPortfolioLedger:
    """Parse a MetaTrader 4 HTML or CSV statement (`Closed Transactions`, `Summary`, `Open Trades`)."""
    reject_unofficial_scraper_credentials(**extra_kwargs)
    text, raw_bytes = decode_statement_bytes(source, max_bytes=max_bytes)
    if not text.strip():
        raise ValueError("MT4 statement payload is empty")
    reject_xxe_and_dtd_declarations(raw_bytes)

    is_html = "<table" in text.lower() or "<tr" in text.lower() or "<html" in text.lower()
    if is_html:
        title, rows, _ = _extract_html_rows(text)
    else:
        title = ""
        rows = _read_csv_rows(text)

    if not rows:
        raise ValueError("MT4 statement contains no table or CSV rows")

    raw_acct_id, resolved_ccy, is_demo = _detect_mt_metadata(title, rows, base_currency)
    env_tier = EnvironmentTier.LIVE_PRODUCTION
    if is_demo:
        if reject_demo:
            raise PaperOrSandboxAccountRejectedError(
                "MetaTrader 4 Demo/Contest server or account rejected for live verification"
            )
        env_tier = EnvironmentTier.PAPER_OR_SANDBOX_REJECTED

    trades: list[NormalizedTrade] = []
    flows: list[NormalizedFlow] = []
    ending_positions: list[NormalizedPosition] = []
    enabled_sections: list[str] = []
    cash_deltas: list[tuple[str, float]] = []
    summary_equity: float | None = None

    section = "closed_transactions" if not is_html else "header"
    col_map: dict[str, int] = {}

    for r_idx, row in enumerate(rows):
        lowered = [c.strip().lower() for c in row]
        joined_low = " ".join(lowered).strip()

        # Section switches in MT4 HTML reports
        if len(row) <= 3:
            if "closed transactions" in joined_low:
                section = "closed_transactions"
                if "mt4_closed_transactions" not in enabled_sections:
                    enabled_sections.append("mt4_closed_transactions")
                continue
            if "open trades" in joined_low:
                section = "open_trades"
                if "mt4_open_trades" not in enabled_sections:
                    enabled_sections.append("mt4_open_trades")
                continue
            if "working orders" in joined_low:
                section = "working_orders"
                continue
            if joined_low.startswith("summary"):
                section = "summary"
                if "mt4_summary" not in enabled_sections:
                    enabled_sections.append("mt4_summary")
                continue

        # Summary key/value extraction (e.g. "Equity: 12 450.00")
        if section == "summary":
            for i, cell_low in enumerate(lowered):
                if cell_low.startswith("equity") and (i + 1) < len(row):
                    eq_val = _parse_localized_float(row[i + 1])
                    if eq_val is not None and eq_val > 0.0:
                        summary_equity = eq_val
            continue

        # Detect header row for Closed Transactions or Open Trades
        if "ticket" in lowered and "open time" in lowered and "type" in lowered:
            if section == "header":
                section = "closed_transactions"
            if section == "closed_transactions" and "mt4_closed_transactions" not in enabled_sections:
                enabled_sections.append("mt4_closed_transactions")
            price_cols = [i for i, h in enumerate(lowered) if h == "price"]
            col_map = {
                "ticket": lowered.index("ticket"),
                "open_time": lowered.index("open time"),
                "type": lowered.index("type"),
                "size": _find_col(lowered, ("size", "lots", "volume")) or 3,
                "item": _find_col(lowered, ("item", "symbol")) or 4,
                "open_price": price_cols[0] if price_cols else 5,
                "close_time": _find_col(lowered, ("close time",)) or 8,
                "close_price": price_cols[1] if len(price_cols) >= 2 else 9,
                "commission": _find_col(lowered, ("commission",)) or 10,
                "taxes": _find_col(lowered, ("taxes", "tax")) or 11,
                "swap": _find_col(lowered, ("swap",)) or 12,
                "profit": _find_col(lowered, ("profit",)) or (len(lowered) - 1),
            }
            continue

        if section == "working_orders" or not col_map:
            continue

        ticket = sanitize_csv_text_field(_cell(row, col_map.get("ticket", 0)))
        if not ticket or not any(ch.isdigit() for ch in ticket):
            continue
        open_ts = _parse_multi_format_timestamp(_cell(row, col_map.get("open_time", 1)))
        if open_ts is None:
            continue
        row_type = sanitize_csv_text_field(_cell(row, col_map.get("type", 2))).lower()

        if section == "closed_transactions":
            if row_type in {"balance", "credit"}:
                # MT4 HTML uses colspan=10 on balance rows -> comment is cell 3 and amount is last cell!
                amt = _parse_localized_float(row[-1])
                if amt is None or amt == 0.0:
                    continue
                middle_cells = [
                    sanitize_csv_text_field(c)
                    for c in row[3:-1]
                    if c.strip() and _parse_localized_float(c) != amt
                ]
                comment = " ".join(c for c in middle_cells if c) or f"MT4 {row_type}"
                kind = FlowKind.DEPOSIT if amt >= 0.0 else FlowKind.WITHDRAWAL
                flows.append(
                    NormalizedFlow(
                        timestamp_utc=open_ts,
                        kind=kind,
                        amount=amt,
                        currency=resolved_ccy,
                        description=comment,
                    )
                )
                cash_deltas.append((open_ts, amt))
                continue

            if row_type not in {"buy", "sell"}:
                # Skip canceled/expired pending orders ("buy limit", "sell stop", etc.)
                continue

            lots = _parse_mt_volume(_cell(row, col_map.get("size", 3)))
            raw_sym = _cell(row, col_map.get("item", 4))
            open_px = _parse_localized_float(_cell(row, col_map.get("open_price", 5)))
            close_ts = _parse_multi_format_timestamp(_cell(row, col_map.get("close_time", 8))) or open_ts
            close_px = _parse_localized_float(_cell(row, col_map.get("close_price", 9)))
            comm = _parse_localized_float(_cell(row, col_map.get("commission", 10)), default=0.0) or 0.0
            taxes = _parse_localized_float(_cell(row, col_map.get("taxes", 11)), default=0.0) or 0.0
            swap = _parse_localized_float(_cell(row, col_map.get("swap", 12)), default=0.0) or 0.0
            profit = _parse_localized_float(_cell(row, col_map.get("profit", len(row) - 1)), default=0.0) or 0.0

            if lots is None or lots <= 0.0 or open_px is None or close_px is None:
                continue

            sym, ac, trade_ccy, mult, fx_to_base = _infer_mt_instrument_spec(
                raw_sym,
                resolved_ccy,
                open_price=open_px,
                close_price=close_px,
                lots=lots,
                reported_profit_base=profit,
            )
            half_comm = abs(comm) / 2.0
            close_side = "sell" if row_type == "buy" else "buy"

            trades.append(
                NormalizedTrade(
                    venue="mt4",
                    native_entry_id=f"mt4-{ticket}-open-{r_idx}",
                    symbol=sym,
                    asset_class=ac,
                    side=row_type,
                    quantity=abs(lots),
                    price=abs(open_px),
                    timestamp_utc=open_ts,
                    currency=trade_ccy,
                    fx_rate_to_base=fx_to_base,
                    multiplier=mult,
                    commission=half_comm,
                )
            )
            trades.append(
                NormalizedTrade(
                    venue="mt4",
                    native_entry_id=f"mt4-{ticket}-close-{r_idx}",
                    symbol=sym,
                    asset_class=ac,
                    side=close_side,
                    quantity=abs(lots),
                    price=abs(close_px),
                    timestamp_utc=close_ts,
                    currency=trade_ccy,
                    fx_rate_to_base=fx_to_base,
                    multiplier=mult,
                    commission=half_comm,
                    tax=abs(taxes),
                )
            )
            if swap != 0.0:
                flows.append(
                    NormalizedFlow(
                        timestamp_utc=close_ts,
                        kind=FlowKind.MARGIN_INTEREST if swap < 0.0 else FlowKind.INTEREST,
                        amount=swap,
                        currency=resolved_ccy,
                        symbol=sym,
                        description=sanitize_csv_text_field(f"MT4 swap ticket {ticket}"),
                    )
                )
            net_trade_delta = profit - abs(comm) - abs(taxes) + swap
            cash_deltas.append((close_ts, net_trade_delta))

        elif section == "open_trades" and row_type in {"buy", "sell"}:
            lots = _parse_mt_volume(_cell(row, col_map.get("size", 3)))
            raw_sym = _cell(row, col_map.get("item", 4))
            open_px = _parse_localized_float(_cell(row, col_map.get("open_price", 5)))
            mkt_px = _parse_localized_float(_cell(row, col_map.get("close_price", 8))) or open_px
            floating_pl = _parse_localized_float(row[-1], default=0.0) or 0.0
            if lots is None or lots <= 0.0 or open_px is None:
                continue
            sym, ac, trade_ccy, mult, fx_to_base = _infer_mt_instrument_spec(
                raw_sym,
                resolved_ccy,
                open_price=open_px,
                close_price=mkt_px,
                lots=lots,
                reported_profit_base=floating_pl,
            )
            signed_qty = abs(lots) if row_type == "buy" else -abs(lots)
            cost_b = abs(lots) * open_px * mult
            mv = cost_b + (floating_pl / fx_to_base if fx_to_base > 0 else floating_pl)
            ending_positions.append(
                NormalizedPosition(
                    prior_period_or_ending="ending",
                    symbol=sym,
                    asset_class=ac,
                    quantity=signed_qty,
                    cost_basis=cost_b,
                    market_value=mv,
                    currency=trade_ccy,
                    fx_rate_to_base=fx_to_base,
                    multiplier=mult,
                )
            )

    if not trades and not flows and not ending_positions:
        raise ValueError("MT4 statement contained no recognizable closed transactions, flows, or open trades")

    # Reconstruct chronological running-balance NAV points when positive
    nav_by_ts: dict[str, NormalizedNavPoint] = {}
    running_bal = 0.0
    for ts, delta in sorted(cash_deltas, key=lambda item: item[0]):
        running_bal += delta
        if running_bal > 0.0:
            nav_by_ts[ts] = NormalizedNavPoint(
                timestamp_utc=ts,
                nav_base=round(running_bal, 6),
                cash_base=round(running_bal, 6),
            )

    source_sha = hashlib.sha256(raw_bytes).hexdigest()
    all_ts = [t.timestamp_utc for t in trades] + [f.timestamp_utc for f in flows] + list(nav_by_ts)
    start_ts = min(all_ts) if all_ts else "2025-01-01T00:00:00Z"
    end_ts = max(all_ts) if all_ts else start_ts

    if summary_equity is not None and summary_equity > 0.0:
        nav_by_ts[end_ts] = NormalizedNavPoint(
            timestamp_utc=end_ts,
            nav_base=summary_equity,
            cash_base=round(running_bal, 6) if running_bal > 0.0 else None,
        )

    tag_seed = raw_acct_id or f"offline:{source_sha[:16]}"
    return CanonicalPortfolioLedger(
        blinded_account_tag=compute_blinded_account_tag("mt4", tag_seed, blinding_salt_hex),
        broker_id="mt4",
        account_scope=AccountScope.UNKNOWN_OFFLINE_SCOPE,
        claimed_origin_assurance=OriginAssurance.SELF_REPORTED,
        provider_approval_state=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
        environment_tier=env_tier,
        source_body_sha256=source_sha,
        base_currency=resolved_ccy,
        period_start_utc=start_ts,
        period_end_utc=end_ts,
        ending_positions=ending_positions,
        nav_points=[nav_by_ts[k] for k in sorted(nav_by_ts)],
        trades=sorted(trades, key=lambda t: (t.timestamp_utc, t.native_entry_id)),
        flows=sorted(flows, key=lambda f: f.timestamp_utc),
        enabled_sections=enabled_sections or ["mt4_closed_transactions"],
    )


def parse_mt5_statement(
    source: bytes | str,
    *,
    blinding_salt_hex: str = "ab" * 32,
    base_currency: str = "USD",
    reject_demo: bool = True,
    max_bytes: int = MAX_STATEMENT_BYTES,
    **extra_kwargs: Any,
) -> CanonicalPortfolioLedger:
    """Parse a MetaTrader 5 HTML or UTF-8/UTF-16 CSV statement (`Deals`, `Positions`, `Orders`)."""
    reject_unofficial_scraper_credentials(**extra_kwargs)
    text, raw_bytes = decode_statement_bytes(source, max_bytes=max_bytes)
    if not text.strip():
        raise ValueError("MT5 statement payload is empty")
    reject_xxe_and_dtd_declarations(raw_bytes)

    is_html = "<table" in text.lower() or "<tr" in text.lower() or "<html" in text.lower()
    if is_html:
        title, rows, _ = _extract_html_rows(text)
    else:
        title = ""
        rows = _read_csv_rows(text)

    if not rows:
        raise ValueError("MT5 statement contains no table or CSV rows")

    raw_acct_id, resolved_ccy, is_demo = _detect_mt_metadata(title, rows, base_currency)
    env_tier = EnvironmentTier.LIVE_PRODUCTION
    if is_demo:
        if reject_demo:
            raise PaperOrSandboxAccountRejectedError(
                "MetaTrader 5 Demo/Contest server or account rejected for live verification"
            )
        env_tier = EnvironmentTier.PAPER_OR_SANDBOX_REJECTED

    deals_trades: list[NormalizedTrade] = []
    positions_fallback_trades: list[NormalizedTrade] = []
    flows: list[NormalizedFlow] = []
    positions_fallback_flows: list[NormalizedFlow] = []
    ending_positions: list[NormalizedPosition] = []
    enabled_sections: list[str] = []
    nav_by_ts: dict[str, NormalizedNavPoint] = {}
    fallback_cash_deltas: list[tuple[str, float]] = []
    summary_equity: float | None = None

    section = "auto"
    col_map: dict[str, int] = {}

    for r_idx, row in enumerate(rows):
        lowered = [c.strip().lower() for c in row]
        non_empty_low = [c for c in lowered if c]
        joined_low = " ".join(non_empty_low)

        # Detect MT5 section banners ("Positions", "Orders", "Deals", "Open Positions", "Working Orders", "Results")
        if len(non_empty_low) == 1:
            banner = non_empty_low[0].rstrip(":")
            if banner == "deals":
                section = "deals"
                col_map = {}
                if "mt5_deals" not in enabled_sections:
                    enabled_sections.append("mt5_deals")
                continue
            if banner == "positions":
                section = "positions"
                col_map = {}
                if "mt5_positions" not in enabled_sections:
                    enabled_sections.append("mt5_positions")
                continue
            if banner == "open positions":
                section = "open_positions"
                col_map = {}
                if "mt5_open_positions" not in enabled_sections:
                    enabled_sections.append("mt5_open_positions")
                continue
            if banner in {"orders", "working orders"}:
                section = "orders"
                col_map = {}
                if "mt5_orders" not in enabled_sections:
                    enabled_sections.append("mt5_orders")
                continue
            if banner in {"results", "summary"}:
                section = "summary"
                col_map = {}
                continue

        # Capture Equity from MT5 Summary block if present
        for i, cell_low in enumerate(lowered):
            if cell_low in {"equity:", "equity"} and (i + 1) < len(row):
                eq_v = _parse_localized_float(row[i + 1])
                if eq_v is not None and eq_v > 0.0:
                    summary_equity = eq_v

        # Detect Deals header row
        if "deal" in lowered and "type" in lowered and "profit" in lowered:
            section = "deals"
            if "mt5_deals" not in enabled_sections:
                enabled_sections.append("mt5_deals")
            col_map = {
                "time": _find_col(lowered, ("time", "date")) or 0,
                "deal": lowered.index("deal"),
                "symbol": _find_col(lowered, ("symbol", "item")),
                "type": lowered.index("type"),
                "direction": _find_col(lowered, ("direction", "entry")),
                "volume": _find_col(lowered, ("volume", "lots", "size")),
                "price": _find_col(lowered, ("price",)),
                "order": _find_col(lowered, ("order",)),
                "commission": _find_col(lowered, ("commission",)),
                "fee": _find_col(lowered, ("fee",)),
                "swap": _find_col(lowered, ("swap",)),
                "profit": lowered.index("profit"),
                "balance": _find_col(lowered, ("balance",)),
                "comment": _find_col(lowered, ("comment",)),
            }
            continue

        # Detect Positions / Open Positions header row
        if "position" in lowered and "type" in lowered and "volume" in lowered and "profit" in lowered:
            if section not in {"positions", "open_positions"}:
                section = "positions"
            if f"mt5_{section}" not in enabled_sections:
                enabled_sections.append(f"mt5_{section}")
            time_cols = [i for i, h in enumerate(lowered) if h == "time"]
            price_cols = [i for i, h in enumerate(lowered) if h in {"price", "market price"}]
            col_map = {
                "open_time": time_cols[0] if time_cols else 0,
                "position": lowered.index("position"),
                "symbol": _find_col(lowered, ("symbol",)) or 2,
                "type": lowered.index("type"),
                "volume": lowered.index("volume"),
                "open_price": price_cols[0] if price_cols else 5,
                "close_time": time_cols[1] if len(time_cols) >= 2 else (time_cols[0] if time_cols else 0),
                "close_price": price_cols[1] if len(price_cols) >= 2 else (price_cols[0] if price_cols else 5),
                "commission": _find_col(lowered, ("commission",)),
                "swap": _find_col(lowered, ("swap",)),
                "profit": lowered.index("profit"),
            }
            continue

        if section in {"orders", "summary", "auto"} or not col_map:
            continue

        if section == "deals":
            ts = _parse_multi_format_timestamp(_cell(row, col_map.get("time")))
            if ts is None:
                continue
            deal_id = sanitize_csv_text_field(_cell(row, col_map.get("deal"))) or f"deal-{r_idx}"
            raw_sym = _cell(row, col_map.get("symbol"))
            deal_type = sanitize_csv_text_field(_cell(row, col_map.get("type"))).lower()
            vol = _parse_mt_volume(_cell(row, col_map.get("volume")))
            px = _parse_localized_float(_cell(row, col_map.get("price")))
            comm = _parse_localized_float(_cell(row, col_map.get("commission")), default=0.0) or 0.0
            fee = _parse_localized_float(_cell(row, col_map.get("fee")), default=0.0) or 0.0
            swap = _parse_localized_float(_cell(row, col_map.get("swap")), default=0.0) or 0.0
            profit = _parse_localized_float(_cell(row, col_map.get("profit")), default=0.0) or 0.0
            bal = _parse_localized_float(_cell(row, col_map.get("balance")))
            comment = sanitize_csv_text_field(_cell(row, col_map.get("comment")))

            if deal_type in {"balance", "credit", "bonus"}:
                if profit != 0.0:
                    flows.append(
                        NormalizedFlow(
                            timestamp_utc=ts,
                            kind=FlowKind.DEPOSIT if profit >= 0.0 else FlowKind.WITHDRAWAL,
                            amount=profit,
                            currency=resolved_ccy,
                            description=comment or f"MT5 {deal_type}",
                        )
                    )
                    fallback_cash_deltas.append((ts, profit))
                if bal is not None and bal > 0.0:
                    nav_by_ts[ts] = NormalizedNavPoint(
                        timestamp_utc=ts, nav_base=bal, cash_base=bal
                    )
                continue

            if "dividend" in deal_type and profit != 0.0:
                sym_clean = sanitize_csv_text_field(raw_sym) or None
                flows.append(
                    NormalizedFlow(
                        timestamp_utc=ts,
                        kind=FlowKind.DIVIDEND,
                        amount=profit,
                        currency=resolved_ccy,
                        symbol=sym_clean,
                        description=comment or "MT5 dividend",
                    )
                )
                fallback_cash_deltas.append((ts, profit))
                if bal is not None and bal > 0.0:
                    nav_by_ts[ts] = NormalizedNavPoint(
                        timestamp_utc=ts, nav_base=bal, cash_base=bal
                    )
                continue

            if ("commission" in deal_type or deal_type == "charge") and (profit != 0.0 or comm != 0.0 or fee != 0.0):
                amt_fee = profit if profit != 0.0 else -(abs(comm) + abs(fee))
                flows.append(
                    NormalizedFlow(
                        timestamp_utc=ts,
                        kind=FlowKind.COMMISSION_FEE,
                        amount=amt_fee,
                        currency=resolved_ccy,
                        description=comment or f"MT5 {deal_type}",
                    )
                )
                fallback_cash_deltas.append((ts, amt_fee))
                if bal is not None and bal > 0.0:
                    nav_by_ts[ts] = NormalizedNavPoint(
                        timestamp_utc=ts, nav_base=bal, cash_base=bal
                    )
                continue

            if deal_type in {"buy", "sell"} and raw_sym and vol and vol > 0.0 and px is not None:
                sym, ac, trade_ccy, mult, fx_to_base = _infer_mt_instrument_spec(
                    raw_sym,
                    resolved_ccy,
                    close_price=px,
                    lots=vol,
                )
                total_comm_fee = abs(comm) + abs(fee)
                deals_trades.append(
                    NormalizedTrade(
                        venue="mt5",
                        native_entry_id=f"mt5-deal-{deal_id}",
                        symbol=sym,
                        asset_class=ac,
                        side=deal_type,
                        quantity=abs(vol),
                        price=abs(px),
                        timestamp_utc=ts,
                        currency=trade_ccy,
                        fx_rate_to_base=fx_to_base,
                        multiplier=mult,
                        commission=total_comm_fee,
                    )
                )
                if swap != 0.0:
                    swap_desc = f"MT5 swap deal {deal_id}" + (f" ({comment})" if comment else "")
                    flows.append(
                        NormalizedFlow(
                            timestamp_utc=ts,
                            kind=FlowKind.MARGIN_INTEREST if swap < 0.0 else FlowKind.INTEREST,
                            amount=swap,
                            currency=resolved_ccy,
                            symbol=sym,
                            description=sanitize_csv_text_field(swap_desc),
                        )
                    )
                net_delta = profit - abs(comm) - abs(fee) + swap
                fallback_cash_deltas.append((ts, net_delta))
                if bal is not None and bal > 0.0:
                    nav_by_ts[ts] = NormalizedNavPoint(
                        timestamp_utc=ts, nav_base=bal, cash_base=bal
                    )

        elif section == "positions":
            open_ts = _parse_multi_format_timestamp(_cell(row, col_map.get("open_time")))
            if open_ts is None:
                continue
            pos_id = sanitize_csv_text_field(_cell(row, col_map.get("position"))) or f"pos-{r_idx}"
            raw_sym = _cell(row, col_map.get("symbol"))
            pos_type = sanitize_csv_text_field(_cell(row, col_map.get("type"))).lower()
            vol = _parse_mt_volume(_cell(row, col_map.get("volume")))
            open_px = _parse_localized_float(_cell(row, col_map.get("open_price")))
            close_ts = _parse_multi_format_timestamp(_cell(row, col_map.get("close_time"))) or open_ts
            close_px = _parse_localized_float(_cell(row, col_map.get("close_price")))
            comm = _parse_localized_float(_cell(row, col_map.get("commission")), default=0.0) or 0.0
            swap = _parse_localized_float(_cell(row, col_map.get("swap")), default=0.0) or 0.0
            profit = _parse_localized_float(_cell(row, col_map.get("profit")), default=0.0) or 0.0
            if pos_type not in {"buy", "sell"} or not raw_sym or not vol or open_px is None or close_px is None:
                continue

            sym, ac, trade_ccy, mult, fx_to_base = _infer_mt_instrument_spec(
                raw_sym,
                resolved_ccy,
                open_price=open_px,
                close_price=close_px,
                lots=vol,
                reported_profit_base=profit,
            )
            half_comm = abs(comm) / 2.0
            close_side = "sell" if pos_type == "buy" else "buy"
            positions_fallback_trades.append(
                NormalizedTrade(
                    venue="mt5",
                    native_entry_id=f"mt5-pos-{pos_id}-open",
                    symbol=sym,
                    asset_class=ac,
                    side=pos_type,
                    quantity=abs(vol),
                    price=abs(open_px),
                    timestamp_utc=open_ts,
                    currency=trade_ccy,
                    fx_rate_to_base=fx_to_base,
                    multiplier=mult,
                    commission=half_comm,
                )
            )
            positions_fallback_trades.append(
                NormalizedTrade(
                    venue="mt5",
                    native_entry_id=f"mt5-pos-{pos_id}-close",
                    symbol=sym,
                    asset_class=ac,
                    side=close_side,
                    quantity=abs(vol),
                    price=abs(close_px),
                    timestamp_utc=close_ts,
                    currency=trade_ccy,
                    fx_rate_to_base=fx_to_base,
                    multiplier=mult,
                    commission=half_comm,
                )
            )
            if swap != 0.0:
                positions_fallback_flows.append(
                    NormalizedFlow(
                        timestamp_utc=close_ts,
                        kind=FlowKind.MARGIN_INTEREST if swap < 0.0 else FlowKind.INTEREST,
                        amount=swap,
                        currency=resolved_ccy,
                        symbol=sym,
                        description=sanitize_csv_text_field(f"MT5 swap position {pos_id}"),
                    )
                )

        elif section == "open_positions":
            open_ts = _parse_multi_format_timestamp(_cell(row, col_map.get("open_time")))
            raw_sym = _cell(row, col_map.get("symbol"))
            pos_type = sanitize_csv_text_field(_cell(row, col_map.get("type"))).lower()
            vol = _parse_mt_volume(_cell(row, col_map.get("volume")))
            open_px = _parse_localized_float(_cell(row, col_map.get("open_price")))
            mkt_px = _parse_localized_float(_cell(row, col_map.get("close_price"))) or open_px
            floating_pl = _parse_localized_float(_cell(row, col_map.get("profit")), default=0.0) or 0.0
            if open_ts is None or pos_type not in {"buy", "sell"} or not raw_sym or not vol or open_px is None:
                continue
            sym, ac, trade_ccy, mult, fx_to_base = _infer_mt_instrument_spec(
                raw_sym,
                resolved_ccy,
                open_price=open_px,
                close_price=mkt_px,
                lots=vol,
                reported_profit_base=floating_pl,
            )
            signed_qty = abs(vol) if pos_type == "buy" else -abs(vol)
            cost_b = abs(vol) * open_px * mult
            mv = cost_b + (floating_pl / fx_to_base if fx_to_base > 0 else floating_pl)
            ending_positions.append(
                NormalizedPosition(
                    prior_period_or_ending="ending",
                    symbol=sym,
                    asset_class=ac,
                    quantity=signed_qty,
                    cost_basis=cost_b,
                    market_value=mv,
                    currency=trade_ccy,
                    fx_rate_to_base=fx_to_base,
                    multiplier=mult,
                )
            )

    final_trades = deals_trades if deals_trades else positions_fallback_trades
    final_flows = flows if deals_trades or flows else positions_fallback_flows
    if not final_trades and not final_flows and not ending_positions:
        raise ValueError("MT5 statement contained no recognizable deals, positions, or balance flows")

    if not nav_by_ts and fallback_cash_deltas:
        running_bal = 0.0
        for ts, delta in sorted(fallback_cash_deltas, key=lambda item: item[0]):
            running_bal += delta
            if running_bal > 0.0:
                nav_by_ts[ts] = NormalizedNavPoint(
                    timestamp_utc=ts,
                    nav_base=round(running_bal, 6),
                    cash_base=round(running_bal, 6),
                )

    source_sha = hashlib.sha256(raw_bytes).hexdigest()
    all_ts = (
        [t.timestamp_utc for t in final_trades]
        + [f.timestamp_utc for f in final_flows]
        + list(nav_by_ts)
    )
    start_ts = min(all_ts) if all_ts else "2025-01-01T00:00:00Z"
    end_ts = max(all_ts) if all_ts else start_ts

    if summary_equity is not None and summary_equity > 0.0:
        nav_by_ts[end_ts] = NormalizedNavPoint(timestamp_utc=end_ts, nav_base=summary_equity)

    tag_seed = raw_acct_id or f"offline:{source_sha[:16]}"
    return CanonicalPortfolioLedger(
        blinded_account_tag=compute_blinded_account_tag("mt5", tag_seed, blinding_salt_hex),
        broker_id="mt5",
        account_scope=AccountScope.UNKNOWN_OFFLINE_SCOPE,
        claimed_origin_assurance=OriginAssurance.SELF_REPORTED,
        provider_approval_state=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
        environment_tier=env_tier,
        source_body_sha256=source_sha,
        base_currency=resolved_ccy,
        period_start_utc=start_ts,
        period_end_utc=end_ts,
        ending_positions=ending_positions,
        nav_points=[nav_by_ts[k] for k in sorted(nav_by_ts)],
        trades=sorted(final_trades, key=lambda t: (t.timestamp_utc, t.native_entry_id)),
        flows=sorted(final_flows, key=lambda f: f.timestamp_utc),
        enabled_sections=enabled_sections or ["mt5_deals"],
    )


def parse_tradovate_csv(
    csv_source: bytes | str | Mapping[str, bytes | str] | None = None,
    *,
    performance_csv: bytes | str | None = None,
    orders_csv: bytes | str | None = None,
    cash_history_csv: bytes | str | None = None,
    blinding_salt_hex: str = "ab" * 32,
    base_currency: str = "USD",
    reject_demo: bool = True,
    max_bytes: int = MAX_STATEMENT_BYTES,
    **extra_kwargs: Any,
) -> CanonicalPortfolioLedger:
    """Parse Tradovate ``Performance``, ``Orders``, and/or ``Cash History`` CSV exports."""
    reject_unofficial_scraper_credentials(**extra_kwargs)

    parts_raw: list[bytes | str] = []
    if isinstance(csv_source, Mapping):
        for k, v in csv_source.items():
            if v is None:
                continue
            kl = str(k).strip().lower()
            if "perf" in kl:
                performance_csv = v
            elif "order" in kl:
                orders_csv = v
            elif "cash" in kl:
                cash_history_csv = v
            else:
                parts_raw.append(v)
    elif csv_source is not None:
        parts_raw.append(csv_source)

    for explicit in (performance_csv, orders_csv, cash_history_csv):
        if explicit is not None:
            parts_raw.append(explicit)

    if not parts_raw:
        raise ValueError("Tradovate CSV input is empty")

    decoded_parts: list[tuple[str, bytes]] = []
    total_len = 0
    for p in parts_raw:
        raw_b = enforce_statement_size_limit(p, max_bytes=max_bytes)
        reject_xxe_and_dtd_declarations(raw_b)
        total_len += len(raw_b)
        if total_len > max_bytes:
            raise StatementSizeLimitExceededError(
                f"Tradovate CSV bundle ({total_len} bytes) exceeds {max_bytes}-byte safety limit"
            )
        txt, _ = decode_statement_bytes(raw_b, max_bytes=max_bytes)
        if txt.strip():
            decoded_parts.append((txt, raw_b))

    if not decoded_parts:
        raise ValueError("Tradovate CSV contains no non-empty content")

    resolved_ccy = base_currency.strip().upper() or "USD"
    perf_trades: list[NormalizedTrade] = []
    order_trades: list[NormalizedTrade] = []
    flows: list[NormalizedFlow] = []
    nav_by_ts: dict[str, NormalizedNavPoint] = {}
    enabled_sections: list[str] = []
    warnings: list[str] = []
    seen_accounts: list[str] = []
    is_demo = False

    def _record_account(raw_acct: str) -> None:
        nonlocal is_demo
        cleaned_acct = sanitize_csv_text_field(raw_acct)
        if not cleaned_acct:
            return
        if cleaned_acct not in seen_accounts:
            seen_accounts.append(cleaned_acct)
        if _TRADOVATE_DEMO_ACCT_RE.match(cleaned_acct) or "demo" in cleaned_acct.lower():
            is_demo = True

    for part_idx, (txt, _) in enumerate(decoded_parts):
        rows = _read_csv_rows(txt)
        if len(rows) < 2:
            continue
        hdrs = [c.strip().lower() for c in rows[0]]
        hdr_set = set(hdrs)

        # 1. Tradovate Performance CSV (paired round-trips)
        if "buyprice" in hdr_set and "sellprice" in hdr_set:
            if "tradovate_performance_csv" not in enabled_sections:
                enabled_sections.append("tradovate_performance_csv")
            c_sym = _find_col(hdrs, ("symbol", "contract"))
            c_acct = _find_col(hdrs, ("account",))
            c_qty = _find_col(hdrs, ("qty", "quantity", "filledqty"))
            c_bpx = _find_col(hdrs, ("buyprice",))
            c_spx = _find_col(hdrs, ("sellprice",))
            c_bts = _find_col(hdrs, ("boughttimestamp", "buytime"))
            c_sts = _find_col(hdrs, ("soldtimestamp", "selltime"))
            c_pnl = _find_col(hdrs, ("pnl", "p&l", "grosspnl"))
            c_fee = _find_col(hdrs, ("commission", "fees", "fee"))
            c_bfid = _find_col(hdrs, ("buyfillid",))
            c_sfid = _find_col(hdrs, ("sellfillid",))

            for r_idx, row in enumerate(rows[1:]):
                _record_account(_cell(row, c_acct))
                sym = sanitize_csv_text_field(_cell(row, c_sym))
                qty = _parse_localized_float(_cell(row, c_qty))
                buy_px = _parse_localized_float(_cell(row, c_bpx))
                sell_px = _parse_localized_float(_cell(row, c_spx))
                buy_ts = _parse_multi_format_timestamp(_cell(row, c_bts))
                sell_ts = _parse_multi_format_timestamp(_cell(row, c_sts))
                if not sym or not qty or qty <= 0.0 or buy_px is None or sell_px is None:
                    continue
                if buy_ts is None and sell_ts is None:
                    continue
                b_ts = buy_ts or sell_ts or "2025-01-01T00:00:00Z"
                s_ts = sell_ts or buy_ts or b_ts

                root, mult = resolve_futures_root_and_multiplier(sym)
                fee_total = abs(_parse_localized_float(_cell(row, c_fee), default=0.0) or 0.0)
                reported_pnl = _parse_localized_float(_cell(row, c_pnl))
                expected_gross = compute_futures_roundtrip_pnl(sym, buy_px, sell_px, qty)
                if (
                    reported_pnl is not None
                    and fee_total == 0.0
                    and abs(expected_gross - reported_pnl) > 0.05
                ):
                    diff = expected_gross - reported_pnl
                    # If reported PnL is slightly lower than gross by typical per-contract fees, note warning
                    warnings.append(
                        f"Tradovate row {r_idx} ({sym}): gross multiplier PnL={expected_gross:.2f} vs CSV pnl={reported_pnl:.2f} (delta={diff:.2f})."
                    )

                bfid = sanitize_csv_text_field(_cell(row, c_bfid)) or f"tv-p{part_idx}-{r_idx}-buy"
                sfid = sanitize_csv_text_field(_cell(row, c_sfid)) or f"tv-p{part_idx}-{r_idx}-sell"
                half_fee = fee_total / 2.0

                buy_leg = NormalizedTrade(
                    venue="tradovate",
                    native_entry_id=bfid,
                    symbol=sym,
                    asset_class=AssetClass.FUTURE,
                    side="buy",
                    quantity=abs(qty),
                    price=abs(buy_px),
                    timestamp_utc=b_ts,
                    currency=resolved_ccy,
                    multiplier=mult,
                    commission=half_fee,
                    underlying_symbol=root or None,
                )
                sell_leg = NormalizedTrade(
                    venue="tradovate",
                    native_entry_id=sfid,
                    symbol=sym,
                    asset_class=AssetClass.FUTURE,
                    side="sell",
                    quantity=abs(qty),
                    price=abs(sell_px),
                    timestamp_utc=s_ts,
                    currency=resolved_ccy,
                    multiplier=mult,
                    commission=half_fee,
                    underlying_symbol=root or None,
                )
                # Append in chronological fill order (supports both long and short futures trades!)
                if s_ts < b_ts:
                    perf_trades.extend([sell_leg, buy_leg])
                else:
                    perf_trades.extend([buy_leg, sell_leg])
            continue

        # 2. Tradovate Orders CSV (execution fills)
        if bool(hdr_set & {"b/s", "orderid", "order id"}) and bool(
            hdr_set & {"avgprice", "filledqty", "fill time", "filltime", "contract"}
        ):
            if "tradovate_orders_csv" not in enabled_sections:
                enabled_sections.append("tradovate_orders_csv")
            c_oid = _find_col(hdrs, ("orderid", "order id", "id"))
            c_acct = _find_col(hdrs, ("account",))
            c_side = _find_col(hdrs, ("b/s", "side", "action"))
            c_sym = _find_col(hdrs, ("contract", "symbol", "product"))
            c_px = _find_col(hdrs, ("avgprice", "avg fill price", "price"))
            c_qty = _find_col(hdrs, ("filledqty", "qty", "quantity"))
            c_ts = _find_col(hdrs, ("fill time", "filltime", "timestamp", "time"))
            c_status = _find_col(hdrs, ("status",))
            c_fee = _find_col(hdrs, ("commission", "fees", "fee"))

            for r_idx, row in enumerate(rows[1:]):
                _record_account(_cell(row, c_acct))
                status_low = sanitize_csv_text_field(_cell(row, c_status)).lower()
                if status_low and status_low in {
                    "canceled",
                    "cancelled",
                    "rejected",
                    "working",
                    "expired",
                    "pending",
                }:
                    continue
                sym = sanitize_csv_text_field(_cell(row, c_sym))
                raw_side = sanitize_csv_text_field(_cell(row, c_side)).lower()
                qty = _parse_localized_float(_cell(row, c_qty))
                px = _parse_localized_float(_cell(row, c_px))
                ts = _parse_multi_format_timestamp(_cell(row, c_ts))
                if not sym or not qty or qty <= 0.0 or px is None or ts is None:
                    continue
                side = "buy" if raw_side.startswith(("b", "long")) else "sell"
                root, mult = resolve_futures_root_and_multiplier(sym)
                oid = sanitize_csv_text_field(_cell(row, c_oid)) or f"tv-ord-{part_idx}-{r_idx}"
                fee = abs(_parse_localized_float(_cell(row, c_fee), default=0.0) or 0.0)
                order_trades.append(
                    NormalizedTrade(
                        venue="tradovate",
                        native_entry_id=oid,
                        symbol=sym,
                        asset_class=AssetClass.FUTURE,
                        side=side,
                        quantity=abs(qty),
                        price=abs(px),
                        timestamp_utc=ts,
                        currency=resolved_ccy,
                        multiplier=mult,
                        commission=fee,
                        underlying_symbol=root or None,
                    )
                )
            continue

        # 3. Tradovate Cash History CSV
        if "cash change type" in hdr_set or ("cash balance" in hdr_set and "delta" in hdr_set):
            if "tradovate_cash_history_csv" not in enabled_sections:
                enabled_sections.append("tradovate_cash_history_csv")
            c_acct = _find_col(hdrs, ("account",))
            c_ts = _find_col(hdrs, ("timestamp", "trade date", "date"))
            c_ccy = _find_col(hdrs, ("currency",))
            c_type = _find_col(hdrs, ("cash change type", "type"))
            c_delta = _find_col(hdrs, ("delta", "amount", "change"))
            c_bal = _find_col(hdrs, ("cash balance", "balance"))
            c_comm = _find_col(hdrs, ("comment", "description"))

            for row in rows[1:]:
                _record_account(_cell(row, c_acct))
                ts = _parse_multi_format_timestamp(_cell(row, c_ts))
                if ts is None:
                    continue
                row_ccy = sanitize_csv_text_field(_cell(row, c_ccy)).upper()
                if len(row_ccy) == 3 and row_ccy.isalpha():
                    resolved_ccy = row_ccy
                chg_type = sanitize_csv_text_field(_cell(row, c_type))
                chg_low = chg_type.lower()
                delta = _parse_localized_float(_cell(row, c_delta), default=0.0) or 0.0
                bal = _parse_localized_float(_cell(row, c_bal))
                comment = sanitize_csv_text_field(_cell(row, c_comm))

                if bal is not None and bal > 0.0:
                    nav_by_ts[ts] = NormalizedNavPoint(
                        timestamp_utc=ts, nav_base=bal, cash_base=bal
                    )

                if delta == 0.0:
                    continue
                # Skip realized trade PnL lines so trade P&L is not misclassified as external deposit/withdrawal
                if any(tok in chg_low for tok in ("trade paired", "realized", "mark to market", "mtm")):
                    continue

                if any(tok in chg_low for tok in ("deposit", "wire in", "ach in", "funding")):
                    kind = FlowKind.DEPOSIT if delta >= 0.0 else FlowKind.WITHDRAWAL
                elif any(tok in chg_low for tok in ("withdraw", "wire out", "ach out", "payout")):
                    kind = FlowKind.WITHDRAWAL
                elif any(tok in chg_low for tok in ("commission", "clearing", "exchange fee", "nfa", "fee")):
                    kind = FlowKind.COMMISSION_FEE
                elif "interest" in chg_low:
                    kind = FlowKind.INTEREST if delta >= 0.0 else FlowKind.MARGIN_INTEREST
                else:
                    kind = FlowKind.OTHER_INTERNAL

                flows.append(
                    NormalizedFlow(
                        timestamp_utc=ts,
                        kind=kind,
                        amount=delta,
                        currency=resolved_ccy,
                        description=comment or chg_type or "Tradovate cash entry",
                    )
                )

    env_tier = EnvironmentTier.LIVE_PRODUCTION
    if is_demo:
        if reject_demo:
            raise PaperOrSandboxAccountRejectedError(
                "Tradovate Demo/Sim account rejected for live verification"
            )
        env_tier = EnvironmentTier.PAPER_OR_SANDBOX_REJECTED

    # Prefer paired Performance trades when both Performance and Orders CSVs are supplied to avoid double-counting fills
    final_trades = perf_trades if perf_trades else order_trades
    if not final_trades and not flows and not nav_by_ts:
        raise ValueError("Tradovate CSV contained no recognizable Performance, Orders, or Cash History rows")

    source_sha = hashlib.sha256(b"\n--TRADOVATE-PART--\n".join(b for _, b in decoded_parts)).hexdigest()
    all_ts = (
        [t.timestamp_utc for t in final_trades]
        + [f.timestamp_utc for f in flows]
        + list(nav_by_ts)
    )
    start_ts = min(all_ts) if all_ts else "2025-01-01T00:00:00Z"
    end_ts = max(all_ts) if all_ts else start_ts
    tag_seed = ",".join(sorted(seen_accounts)) if seen_accounts else f"offline:{source_sha[:16]}"

    return CanonicalPortfolioLedger(
        blinded_account_tag=compute_blinded_account_tag("tradovate", tag_seed, blinding_salt_hex),
        broker_id="tradovate",
        account_scope=AccountScope.UNKNOWN_OFFLINE_SCOPE,
        claimed_origin_assurance=OriginAssurance.SELF_REPORTED,
        provider_approval_state=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
        environment_tier=env_tier,
        source_body_sha256=source_sha,
        base_currency=resolved_ccy,
        period_start_utc=start_ts,
        period_end_utc=end_ts,
        nav_points=[nav_by_ts[k] for k in sorted(nav_by_ts)],
        trades=sorted(final_trades, key=lambda t: (t.timestamp_utc, t.native_entry_id)),
        flows=sorted(flows, key=lambda f: f.timestamp_utc),
        enabled_sections=enabled_sections,
        parser_warnings=warnings,
    )


class Mt4OfflineStatementAdapter(OfflineExportAdapterBase):
    """Offline MetaTrader 4 HTML/CSV statement adapter (`OFFLINE_EXPORT_ONLY`)."""

    broker_id = "mt4_statement"
    display_name = "MetaTrader 4 Offline Statement Import (HTML/CSV)"

    def parse_export(
        self,
        source: bytes | str,
        *,
        blinding_salt_hex: str = "ab" * 32,
        **kwargs: Any,
    ) -> CanonicalPortfolioLedger:
        return parse_mt4_statement(source, blinding_salt_hex=blinding_salt_hex, **kwargs)


class Mt5OfflineStatementAdapter(OfflineExportAdapterBase):
    """Offline MetaTrader 5 (and MT4 auto-fallback) HTML/CSV statement adapter (`OFFLINE_EXPORT_ONLY`)."""

    broker_id = "mt5_statement"
    display_name = "MetaTrader 4/5 Offline Statement Import (HTML/CSV)"

    def parse_export(
        self,
        source: bytes | str,
        *,
        blinding_salt_hex: str = "ab" * 32,
        platform: str = "auto",
        **kwargs: Any,
    ) -> CanonicalPortfolioLedger:
        plat = platform.strip().lower()
        if plat == "mt4":
            return parse_mt4_statement(source, blinding_salt_hex=blinding_salt_hex, **kwargs)
        if plat == "mt5":
            return parse_mt5_statement(source, blinding_salt_hex=blinding_salt_hex, **kwargs)
        text, _ = decode_statement_bytes(source, max_bytes=kwargs.get("max_bytes", MAX_STATEMENT_BYTES))
        low = text.lower()
        if "metatrader 4" in low or ("closed transactions" in low and "deals" not in low):
            return parse_mt4_statement(source, blinding_salt_hex=blinding_salt_hex, **kwargs)
        return parse_mt5_statement(source, blinding_salt_hex=blinding_salt_hex, **kwargs)


class TradovateOfflineCsvAdapter(OfflineExportAdapterBase):
    """Offline Tradovate Futures CSV adapter (`OFFLINE_EXPORT_ONLY`)."""

    broker_id = "tradovate_csv"
    display_name = "Tradovate Futures Offline CSV Import"

    def parse_export(
        self,
        csv_source: bytes | str | Mapping[str, bytes | str] | None = None,
        *,
        blinding_salt_hex: str = "ab" * 32,
        **kwargs: Any,
    ) -> CanonicalPortfolioLedger:
        return parse_tradovate_csv(csv_source, blinding_salt_hex=blinding_salt_hex, **kwargs)


__all__ = [
    "FUTURES_POINT_MULTIPLIERS",
    "Mt4OfflineStatementAdapter",
    "Mt5OfflineStatementAdapter",
    "TradovateOfflineCsvAdapter",
    "compute_futures_roundtrip_pnl",
    "parse_mt4_statement",
    "parse_mt5_statement",
    "parse_tradovate_csv",
    "resolve_futures_root_and_multiplier",
]
