"""Central read-only broker & exchange connector registry and governance router."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from n170_verify.connectors.alpaca import AlpacaReadOnlyAdapter
from n170_verify.connectors.ccxt_crypto import (
    CcxtExchangeReadOnlyAdapter,
    UnsupportedScraperPolicyError,
)
from n170_verify.connectors.ctrader_oauth import CTraderReadOnlyOAuthAdapter
from n170_verify.connectors.ibkr_flex import (
    IbkrFlexOfflineAdapter,
    IbkrFlexWebServiceAdapter,
)
from n170_verify.connectors.ibkr_oauth import IbkrOAuthReadOnlyAdapter
from n170_verify.connectors.journal_migration import JournalMigrationOfflineAdapter
from n170_verify.connectors.mcp_allowlist_firewall import (
    DisallowedMcpServerError,
    REJECTED_MCP_SERVERS,
)
from n170_verify.connectors.mt5_tradovate import (
    Mt4OfflineStatementAdapter,
    Mt5OfflineStatementAdapter,
    TradovateOfflineCsvAdapter,
)
from n170_verify.connectors.statement_csv import (
    DegiroOfflineCsvAdapter,
    RobinhoodOfflineCsvAdapter,
    SchwabOfflineCsvAdapter,
    reject_unofficial_scraper_credentials,
)
from n170_verify.connectors.tradier_schwab import (
    SchwabReadOnlyAdapter,
    TradierReadOnlyAdapter,
)
from n170_verify.connectors.snaptrade import SnapTradeReadOnlyAdapter
from n170_verify.connectors.trading212 import Trading212ReadOnlyAdapter
from n170_verify.contracts import BrokerAdapterDescriptor, ReadOnlyBrokerAdapter


CONNECTOR_CLASS_MAP: dict[str, type[ReadOnlyBrokerAdapter]] = {
    "ibkr_oauth": IbkrOAuthReadOnlyAdapter,
    "ibkr_flex_web": IbkrFlexWebServiceAdapter,
    "ibkr_flex_offline": IbkrFlexOfflineAdapter,
    "alpaca": AlpacaReadOnlyAdapter,
    "trading212": Trading212ReadOnlyAdapter,
    "tradier": TradierReadOnlyAdapter,
    "schwab": SchwabReadOnlyAdapter,
    "schwab_csv": SchwabOfflineCsvAdapter,
    "degiro": DegiroOfflineCsvAdapter,
    "degiro_csv": DegiroOfflineCsvAdapter,
    "robinhood": RobinhoodOfflineCsvAdapter,
    "robinhood_csv": RobinhoodOfflineCsvAdapter,
    "binance": CcxtExchangeReadOnlyAdapter,
    "coinbase": CcxtExchangeReadOnlyAdapter,
    "kraken": CcxtExchangeReadOnlyAdapter,
    "bybit": CcxtExchangeReadOnlyAdapter,
    "mt4": Mt4OfflineStatementAdapter,
    "mt4_statement": Mt4OfflineStatementAdapter,
    "mt5": Mt5OfflineStatementAdapter,
    "mt5_statement": Mt5OfflineStatementAdapter,
    "tradovate": TradovateOfflineCsvAdapter,
    "tradovate_csv": TradovateOfflineCsvAdapter,
    "ctrader": CTraderReadOnlyOAuthAdapter,
    "ctrader_oauth": CTraderReadOnlyOAuthAdapter,
    "journal_migration": JournalMigrationOfflineAdapter,
    "tradersync": JournalMigrationOfflineAdapter,
    "tradersync_journal": JournalMigrationOfflineAdapter,
    "tradezella": JournalMigrationOfflineAdapter,
    "tradezella_journal": JournalMigrationOfflineAdapter,
    "snaptrade": SnapTradeReadOnlyAdapter,
    "snaptrade_relay": SnapTradeReadOnlyAdapter,
    "snaptrade_poc": SnapTradeReadOnlyAdapter,
}


def create_connector(
    broker_id: str,
    *,
    env: Mapping[str, str] | None = None,
    **kwargs: Any,
) -> ReadOnlyBrokerAdapter:
    """Instantiate a validated ``ReadOnlyBrokerAdapter`` by ``broker_id``."""
    if not isinstance(broker_id, str) or not broker_id.strip():
        raise ValueError("broker_id must be a non-empty string")
    norm = broker_id.strip().lower()

    if norm in REJECTED_MCP_SERVERS or "ccxt-mcp" in norm or "mcp-server-ccxt" in norm:
        raise DisallowedMcpServerError(
            REJECTED_MCP_SERVERS.get(
                norm,
                f"Community CCXT MCP server {broker_id!r} is disallowed; use binance/coinbase/kraken/bybit.",
            )
        )

    if norm in {"robinhood", "robinhood_csv", "degiro", "degiro_csv"}:
        reject_unofficial_scraper_credentials(**kwargs)
        if kwargs:
            raise UnsupportedScraperPolicyError(
                f"{norm} supports only offline CSV import (OFFLINE_EXPORT_ONLY); "
                "live API/scraper parameters are rejected"
            )

    if norm in {"binance", "coinbase", "kraken", "bybit"}:
        return CcxtExchangeReadOnlyAdapter(norm, **kwargs)
    if norm == "ibkr_oauth":
        return IbkrOAuthReadOnlyAdapter(env=env, **kwargs)
    if norm == "ibkr_flex_web":
        return IbkrFlexWebServiceAdapter(**kwargs)
    if norm == "ibkr_flex_offline":
        return IbkrFlexOfflineAdapter()
    if norm == "alpaca":
        return AlpacaReadOnlyAdapter(env=env, **kwargs)
    if norm == "trading212":
        return Trading212ReadOnlyAdapter(**kwargs)
    if norm == "tradier":
        return TradierReadOnlyAdapter(**kwargs)
    if norm == "schwab":
        return SchwabReadOnlyAdapter(env=env, **kwargs)
    if norm in {"schwab_csv"}:
        return SchwabOfflineCsvAdapter(**kwargs)
    if norm in {"degiro", "degiro_csv"}:
        return DegiroOfflineCsvAdapter()
    if norm in {"robinhood", "robinhood_csv"}:
        return RobinhoodOfflineCsvAdapter()
    if norm in {"mt4", "mt4_statement"}:
        return Mt4OfflineStatementAdapter(**kwargs)
    if norm in {"mt5", "mt5_statement"}:
        return Mt5OfflineStatementAdapter(**kwargs)
    if norm in {"tradovate", "tradovate_csv"}:
        return TradovateOfflineCsvAdapter(**kwargs)
    if norm in {"ctrader", "ctrader_oauth"}:
        return CTraderReadOnlyOAuthAdapter(env=env, **kwargs)
    if norm in {"journal_migration"}:
        return JournalMigrationOfflineAdapter(**kwargs)
    if norm in {"tradersync", "tradersync_journal"}:
        return JournalMigrationOfflineAdapter(source_hint="tradersync", **kwargs)
    if norm in {"tradezella", "tradezella_journal"}:
        return JournalMigrationOfflineAdapter(source_hint="tradezella", **kwargs)
    if norm in {"snaptrade", "snaptrade_relay", "snaptrade_poc"}:
        return SnapTradeReadOnlyAdapter(env=env, **kwargs)

    raise KeyError(f"Unknown broker_id {broker_id!r}; registered={sorted(CONNECTOR_CLASS_MAP)}")


def list_connector_descriptors(
    *,
    env: Mapping[str, str] | None = None,
    include_extended: bool = False,
    include_poc: bool = False,
) -> list[BrokerAdapterDescriptor]:
    """Return validated ``BrokerAdapterDescriptor`` records across canonical connectors."""
    sample_instances: list[ReadOnlyBrokerAdapter] = [
        IbkrOAuthReadOnlyAdapter(env=env or {}),
        IbkrFlexWebServiceAdapter(),
        IbkrFlexOfflineAdapter(),
        AlpacaReadOnlyAdapter(
            api_key_id="placeholder", api_secret_key="placeholder", env=env or {}
        ),
        Trading212ReadOnlyAdapter(api_key="placeholder", api_secret="placeholder"),
        TradierReadOnlyAdapter(access_token="placeholder"),
        SchwabReadOnlyAdapter(env=env or {}),
        SchwabOfflineCsvAdapter(),
        DegiroOfflineCsvAdapter(),
        RobinhoodOfflineCsvAdapter(),
        CcxtExchangeReadOnlyAdapter("binance"),
        CcxtExchangeReadOnlyAdapter("coinbase"),
        CcxtExchangeReadOnlyAdapter("kraken"),
        CcxtExchangeReadOnlyAdapter("bybit"),
    ]
    if include_extended:
        sample_instances.extend(
            [
                Mt4OfflineStatementAdapter(),
                Mt5OfflineStatementAdapter(),
                TradovateOfflineCsvAdapter(),
                CTraderReadOnlyOAuthAdapter(env=env or {}),
                JournalMigrationOfflineAdapter(),
            ]
        )
    if include_poc:
        sample_instances.append(SnapTradeReadOnlyAdapter(env=env or {}))
    return [inst.describe_adapter() for inst in sample_instances]


def list_all_connector_descriptors(
    *,
    env: Mapping[str, str] | None = None,
    include_poc: bool = False,
) -> list[BrokerAdapterDescriptor]:
    """Return validated ``BrokerAdapterDescriptor`` records including FX, Futures & Migration adapters."""
    return list_connector_descriptors(env=env, include_extended=True, include_poc=include_poc)


def get_connector_descriptor(
    broker_id: str,
    *,
    env: Mapping[str, str] | None = None,
) -> BrokerAdapterDescriptor:
    """Lookup a single ``BrokerAdapterDescriptor`` by ``broker_id``."""
    norm = broker_id.strip().lower()
    alias_map = {
        "degiro": "degiro_csv",
        "robinhood": "robinhood_csv",
        "mt4": "mt4_statement",
        "mt5": "mt5_statement",
        "tradovate": "tradovate_csv",
        "ctrader": "ctrader_oauth",
        "tradersync": "journal_migration",
        "tradersync_journal": "journal_migration",
        "tradezella": "journal_migration",
        "tradezella_journal": "journal_migration",
        "snaptrade_relay": "snaptrade",
        "snaptrade_poc": "snaptrade",
    }
    target = alias_map.get(norm, norm)
    if target == "snaptrade":
        return SnapTradeReadOnlyAdapter(env=env or {}).describe_adapter()
    for desc in list_connector_descriptors(env=env, include_extended=True):
        if desc.broker_id == target:
            return desc
    raise KeyError(f"Unknown broker_id {broker_id!r}")


__all__ = [
    "CONNECTOR_CLASS_MAP",
    "create_connector",
    "get_connector_descriptor",
    "list_all_connector_descriptors",
    "list_connector_descriptors",
]
