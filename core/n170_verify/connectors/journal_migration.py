"""1-Click TraderSync & TradeZella journal backup migration importer.

Migrates historical trades, setup/playbook tags, mistake tags, and coaching notes
from TraderSync and TradeZella CSV backups while enforcing strict assurance boundaries:
- ``OriginAssurance.SELF_REPORTED``
- ``AccountScope.UNKNOWN_OFFLINE_SCOPE``
- ``reconciliation_status_override = ReconciliationStatus.INSUFFICIENT_SECTIONS``
  (trade-journal CSV exports lack verified broker cash/NAV snapshots until paired
  with an official broker statement or read-only API connection).
- Full spreadsheet formula-injection neutralization via ``sanitize_csv_text_field``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import Any

from n170_verify.connectors.mt5_tradovate import (
    FUTURES_POINT_MULTIPLIERS,
    resolve_futures_root_and_multiplier,
)
from n170_verify.connectors.statement_csv import (
    MAX_STATEMENT_BYTES,
    OfflineExportAdapterBase,
    _cell,
    _find_col,
    _parse_localized_float,
    _parse_multi_format_timestamp,
    _read_csv_rows,
    decode_statement_bytes,
    reject_unofficial_scraper_credentials,
    reject_xxe_and_dtd_declarations,
    sanitize_csv_text_field,
)
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    CanonicalPortfolioLedger,
    ContractModelMixin,
    EnvironmentTier,
    NormalizedPosition,
    NormalizedTrade,
    OriginAssurance,
    ProviderApprovalState,
    ReadOnlyBrokerAdapter,
    ReconciliationStatus,
    compute_blinded_account_tag,
)


_TAG_SPLIT_RE = re.compile(r"[;,]+|\s+\|\s+")


@dataclass(slots=True)
class JournalMigrationEntryMetadata(ContractModelMixin):
    """Sanitized coaching tags and notes preserved from a migrated journal trade row."""

    trade_key: str
    symbol: str
    setup_tags: list[str] = field(default_factory=list)
    mistake_tags: list[str] = field(default_factory=list)
    custom_tags: list[str] = field(default_factory=list)
    sanitized_note: str = ""

    def _validate(self) -> None:
        if not self.trade_key.strip():
            raise ValueError("JournalMigrationEntryMetadata.trade_key must not be empty")
        if not self.symbol.strip():
            raise ValueError("JournalMigrationEntryMetadata.symbol must not be empty")


@dataclass(slots=True)
class JournalMigrationResult(ContractModelMixin):
    """Structured output of ``parse_journal_migration_csv``."""

    detected_format: str
    broker_id: str
    ledger: CanonicalPortfolioLedger
    origin_assurance: OriginAssurance = OriginAssurance.SELF_REPORTED
    account_scope: AccountScope = AccountScope.UNKNOWN_OFFLINE_SCOPE
    reconciliation_status_override: ReconciliationStatus = (
        ReconciliationStatus.INSUFFICIENT_SECTIONS
    )
    imported_journal_tags: list[str] = field(default_factory=list)
    sanitized_trade_notes: list[str] = field(default_factory=list)
    entries_metadata: list[JournalMigrationEntryMetadata] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def _validate(self) -> None:
        if self.detected_format not in {"tradersync_journal", "tradezella_journal"}:
            raise ValueError(
                f"JournalMigrationResult.detected_format must be 'tradersync_journal' or "
                f"'tradezella_journal', got {self.detected_format!r}"
            )
        if self.origin_assurance != OriginAssurance.SELF_REPORTED:
            raise ValueError("Journal migrations must carry OriginAssurance.SELF_REPORTED")
        if self.account_scope != AccountScope.UNKNOWN_OFFLINE_SCOPE:
            raise ValueError("Journal migrations must carry AccountScope.UNKNOWN_OFFLINE_SCOPE")
        if self.reconciliation_status_override != ReconciliationStatus.INSUFFICIENT_SECTIONS:
            raise ValueError(
                "Journal migrations must enforce ReconciliationStatus.INSUFFICIENT_SECTIONS"
            )


def _extract_sanitized_tags(raw_cell: str) -> list[str]:
    cleaned_whole = sanitize_csv_text_field(raw_cell)
    if not cleaned_whole:
        return []
    out: list[str] = []
    seen_low: set[str] = set()
    for part in _TAG_SPLIT_RE.split(cleaned_whole):
        tok = sanitize_csv_text_field(part)
        if tok and tok.lower() not in {"none", "n/a", "--", "-"} and tok.lower() not in seen_low:
            seen_low.add(tok.lower())
            out.append(tok)
    return out


def _resolve_journal_asset_and_multiplier(
    symbol: str,
    raw_asset_type: str,
) -> tuple[AssetClass, float, str | None]:
    at = sanitize_csv_text_field(raw_asset_type).lower()
    if "opt" in at:
        return AssetClass.OPTION, 100.0, None
    if "fut" in at:
        root, mult = resolve_futures_root_and_multiplier(symbol)
        return AssetClass.FUTURE, mult, root or None
    if "forex" in at or at == "fx":
        return AssetClass.FX, 100_000.0, None
    if "crypto" in at:
        return AssetClass.CRYPTO_SPOT, 1.0, None
    if "etf" in at:
        return AssetClass.ETF, 1.0, None

    # Symbol-based fallback when asset type column is omitted
    fut_root, fut_mult = resolve_futures_root_and_multiplier(symbol)
    if fut_root in FUTURES_POINT_MULTIPLIERS and symbol.upper() != fut_root:
        return AssetClass.FUTURE, fut_mult, fut_root
    return AssetClass.EQUITY, 1.0, None


def _detect_journal_platform(headers_lower: list[str], source_hint: str | None) -> tuple[str, str]:
    if source_hint:
        h = source_hint.strip().lower()
        if "zella" in h:
            return "tradezella_journal", "tradezella"
        if "sync" in h:
            return "tradersync_journal", "tradersync"
        raise ValueError(
            f"Unsupported journal source_hint {source_hint!r} (expected 'tradersync' or 'tradezella')"
        )

    hdr_set = set(headers_lower)
    tz_markers = {
        "net p&l",
        "gross p&l",
        "playbook",
        "mistake tags",
        "custom tags",
        "zella scale",
        "r-multiple",
        "realized r",
        "trade rating",
    }
    if hdr_set & tz_markers:
        return "tradezella_journal", "tradezella"

    ts_markers = {
        "setups",
        "setup",
        "mistakes",
        "mistake",
        "return $",
        "return %",
        "net return",
    }
    if hdr_set & ts_markers or ("open date" in hdr_set and "entry price" in hdr_set):
        return "tradersync_journal", "tradersync"

    raise ValueError(
        "Unrecognized journal CSV header: expected TraderSync or TradeZella export columns"
    )


def parse_journal_migration_csv(
    csv_source: bytes | str,
    *,
    source_hint: str | None = None,
    blinding_salt_hex: str = "ab" * 32,
    base_currency: str = "USD",
    max_bytes: int = MAX_STATEMENT_BYTES,
    environment_tier: EnvironmentTier | str = EnvironmentTier.UNVERIFIED_OFFLINE,
    **extra_kwargs: Any,
) -> JournalMigrationResult:
    """Import a TraderSync or TradeZella CSV journal backup with sanitized tags and notes."""
    reject_unofficial_scraper_credentials(**extra_kwargs)
    text, raw_bytes = decode_statement_bytes(csv_source, max_bytes=max_bytes)
    if not text.strip():
        raise ValueError("Journal migration CSV is empty")
    reject_xxe_and_dtd_declarations(raw_bytes)

    rows = _read_csv_rows(text)
    if len(rows) < 2:
        raise ValueError("Journal migration CSV must contain a header and at least one trade row")

    hdrs = [c.strip().lower() for c in rows[0]]
    detected_format, broker_id = _detect_journal_platform(hdrs, source_hint)
    resolved_ccy = base_currency.strip().upper() or "USD"

    c_status = _find_col(hdrs, ("status",))
    c_sym = _find_col(hdrs, ("symbol", "ticker", "instrument"))
    c_side = _find_col(hdrs, ("side", "direction", "position", "type"))
    c_qty = _find_col(hdrs, ("size", "volume", "quantity", "qty", "shares", "contracts"))
    c_open_date = _find_col(hdrs, ("open date", "entry date", "date"))
    c_open_time = _find_col(hdrs, ("open time", "entry time"))
    c_close_date = _find_col(hdrs, ("close date", "exit date"))
    c_close_time = _find_col(hdrs, ("close time", "exit time"))
    c_entry_px = _find_col(hdrs, ("entry price", "avg buy", "avg entry", "open price"))
    c_exit_px = _find_col(hdrs, ("exit price", "avg sell", "avg exit", "close price"))
    c_comm = _find_col(hdrs, ("commission", "commissions", "fees", "fee"))
    c_asset = _find_col(hdrs, ("asset type", "instrument type", "asset class", "market"))
    c_setup = _find_col(hdrs, ("setups", "playbook", "setup", "strategy"))
    c_mistake = _find_col(hdrs, ("mistakes", "mistake tags", "mistake", "error tags"))
    c_tags = _find_col(hdrs, ("custom tags", "tags"))
    c_notes = _find_col(hdrs, ("notes", "trade notes", "journal notes", "note", "comment"))

    if c_sym is None or c_entry_px is None:
        raise ValueError("Journal CSV missing required Symbol or Entry Price column")

    trades: list[NormalizedTrade] = []
    ending_positions: list[NormalizedPosition] = []
    entries_meta: list[JournalMigrationEntryMetadata] = []
    all_tags: list[str] = []
    seen_tags_low: set[str] = set()
    sanitized_notes: list[str] = []

    def _register_tags(items: list[str]) -> None:
        for item in items:
            low = item.lower()
            if low not in seen_tags_low:
                seen_tags_low.add(low)
                all_tags.append(item)

    for r_idx, row in enumerate(rows[1:]):
        sym = sanitize_csv_text_field(_cell(row, c_sym))
        if not sym:
            continue
        open_ts = _parse_multi_format_timestamp(
            _cell(row, c_open_date), _cell(row, c_open_time)
        )
        if open_ts is None:
            continue

        close_ts = _parse_multi_format_timestamp(
            _cell(row, c_close_date), _cell(row, c_close_time)
        )
        qty = _parse_localized_float(_cell(row, c_qty))
        entry_px = _parse_localized_float(_cell(row, c_entry_px))
        exit_px = _parse_localized_float(_cell(row, c_exit_px))
        if qty is None or abs(qty) == 0.0 or entry_px is None or entry_px < 0.0:
            continue

        raw_side = sanitize_csv_text_field(_cell(row, c_side)).lower()
        is_short = raw_side in {"short", "sell", "sld", "s"} or (not raw_side and qty < 0.0)
        open_side = "sell" if is_short else "buy"
        close_side = "buy" if is_short else "sell"

        status_low = sanitize_csv_text_field(_cell(row, c_status)).lower()
        is_open = status_low == "open" or exit_px is None

        ac, mult, underlying = _resolve_journal_asset_and_multiplier(sym, _cell(row, c_asset))
        comm_total = abs(_parse_localized_float(_cell(row, c_comm), default=0.0) or 0.0)
        trade_key = f"{broker_id}-{r_idx}"

        setup_tags = _extract_sanitized_tags(_cell(row, c_setup))
        mistake_tags = _extract_sanitized_tags(_cell(row, c_mistake))
        custom_tags = _extract_sanitized_tags(_cell(row, c_tags))
        _register_tags(setup_tags)
        _register_tags(mistake_tags)
        _register_tags(custom_tags)

        clean_note = sanitize_csv_text_field(_cell(row, c_notes))
        if clean_note:
            sanitized_notes.append(clean_note)

        entries_meta.append(
            JournalMigrationEntryMetadata(
                trade_key=trade_key,
                symbol=sym,
                setup_tags=setup_tags,
                mistake_tags=mistake_tags,
                custom_tags=custom_tags,
                sanitized_note=clean_note,
            )
        )

        if is_open:
            trades.append(
                NormalizedTrade(
                    venue=broker_id,
                    native_entry_id=f"{trade_key}-open",
                    symbol=sym,
                    asset_class=ac,
                    side=open_side,
                    quantity=abs(qty),
                    price=abs(entry_px),
                    timestamp_utc=open_ts,
                    currency=resolved_ccy,
                    multiplier=mult,
                    commission=comm_total,
                    underlying_symbol=underlying,
                )
            )
            signed_qty = -abs(qty) if is_short else abs(qty)
            cost_val = abs(qty) * abs(entry_px) * mult
            ending_positions.append(
                NormalizedPosition(
                    prior_period_or_ending="ending",
                    symbol=sym,
                    asset_class=ac,
                    quantity=signed_qty,
                    cost_basis=cost_val,
                    market_value=cost_val,
                    currency=resolved_ccy,
                    multiplier=mult,
                    underlying_symbol=underlying,
                )
            )
        else:
            eff_close_ts = close_ts if (close_ts and close_ts >= open_ts) else open_ts
            half_comm = comm_total / 2.0
            trades.append(
                NormalizedTrade(
                    venue=broker_id,
                    native_entry_id=f"{trade_key}-open",
                    symbol=sym,
                    asset_class=ac,
                    side=open_side,
                    quantity=abs(qty),
                    price=abs(entry_px),
                    timestamp_utc=open_ts,
                    currency=resolved_ccy,
                    multiplier=mult,
                    commission=half_comm,
                    underlying_symbol=underlying,
                )
            )
            trades.append(
                NormalizedTrade(
                    venue=broker_id,
                    native_entry_id=f"{trade_key}-close",
                    symbol=sym,
                    asset_class=ac,
                    side=close_side,
                    quantity=abs(qty),
                    price=abs(exit_px or 0.0),
                    timestamp_utc=eff_close_ts,
                    currency=resolved_ccy,
                    multiplier=mult,
                    commission=half_comm,
                    underlying_symbol=underlying,
                )
            )

    if not trades:
        raise ValueError("Journal migration CSV contained no valid trade rows")

    warnings = [
        f"Migrated {broker_id} trade-journal backup lacks verified cash/NAV snapshots "
        f"(ReconciliationStatus.INSUFFICIENT_SECTIONS until paired with a broker statement)."
    ]
    source_sha = hashlib.sha256(raw_bytes).hexdigest()
    all_ts = [t.timestamp_utc for t in trades]
    start_ts = min(all_ts)
    end_ts = max(all_ts)

    ledger = CanonicalPortfolioLedger(
        blinded_account_tag=compute_blinded_account_tag(
            broker_id, f"journal:{source_sha[:16]}", blinding_salt_hex
        ),
        broker_id=broker_id,
        account_scope=AccountScope.UNKNOWN_OFFLINE_SCOPE,
        claimed_origin_assurance=OriginAssurance.SELF_REPORTED,
        provider_approval_state=ProviderApprovalState.OFFLINE_EXPORT_ONLY,
        environment_tier=EnvironmentTier(environment_tier),
        source_body_sha256=source_sha,
        base_currency=resolved_ccy,
        period_start_utc=start_ts,
        period_end_utc=end_ts,
        ending_positions=ending_positions,
        nav_points=[],
        trades=sorted(trades, key=lambda t: (t.timestamp_utc, t.native_entry_id)),
        enabled_sections=[f"{detected_format}_csv"],
        parser_warnings=list(warnings),
    )

    return JournalMigrationResult(
        detected_format=detected_format,
        broker_id=broker_id,
        ledger=ledger,
        origin_assurance=OriginAssurance.SELF_REPORTED,
        account_scope=AccountScope.UNKNOWN_OFFLINE_SCOPE,
        reconciliation_status_override=ReconciliationStatus.INSUFFICIENT_SECTIONS,
        imported_journal_tags=all_tags,
        sanitized_trade_notes=sanitized_notes,
        entries_metadata=entries_meta,
        warnings=warnings,
    )


class JournalMigrationOfflineAdapter(OfflineExportAdapterBase):
    """Offline TraderSync / TradeZella journal backup migration adapter (`OFFLINE_EXPORT_ONLY`)."""

    broker_id = "journal_migration"
    display_name = "TraderSync & TradeZella Offline Journal Migration Adapter"

    def __init__(self, *, source_hint: str | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._source_hint = source_hint

    def migrate_export(
        self,
        csv_source: bytes | str,
        *,
        source_hint: str | None = None,
        blinding_salt_hex: str = "ab" * 32,
        **kwargs: Any,
    ) -> JournalMigrationResult:
        return parse_journal_migration_csv(
            csv_source,
            source_hint=source_hint or self._source_hint,
            blinding_salt_hex=blinding_salt_hex,
            **kwargs,
        )

    def parse_export(
        self,
        csv_source: bytes | str,
        *,
        source_hint: str | None = None,
        blinding_salt_hex: str = "ab" * 32,
        **kwargs: Any,
    ) -> CanonicalPortfolioLedger:
        return self.migrate_export(
            csv_source,
            source_hint=source_hint,
            blinding_salt_hex=blinding_salt_hex,
            **kwargs,
        ).ledger


__all__ = [
    "JournalMigrationEntryMetadata",
    "JournalMigrationOfflineAdapter",
    "JournalMigrationResult",
    "parse_journal_migration_csv",
]
