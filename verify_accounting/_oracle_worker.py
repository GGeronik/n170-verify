"""Original worker; runs only in an explicitly selected external Beancount env.

No N170 accounting implementation is imported. Beancount is separately licensed.
"""

from decimal import Decimal, localcontext
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import sys

REVISION = "9747213802acb733ce53acc6e963f5961f47d6cd"
SOURCE_URL = f"https://github.com/beancount/beancount/archive/{REVISION}.tar.gz"


def decimal_text(value):
    if value == 0:
        return "0"
    rendered = format(value, "f")
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered


def execute(ledger_path):
    # Set before importing the external loader. -I and -B isolate Python paths
    # and disable bytecode; no input-controlled plugin/include is generated.
    os.environ["BEANCOUNT_DISABLE_LOAD_CACHE"] = "1"
    dist = metadata.distribution("beancount")
    direct = json.loads(dist.read_text("direct_url.json") or "{}")
    if dist.version != "3.2.3" or direct.get("url") != SOURCE_URL:
        return {"status": "UNAVAILABLE", "reason_codes": ["PINNED_INSTALL_NOT_ESTABLISHED"]}, 2
    from beancount import loader
    from beancount.core import convert, data, prices, realization
    from beancount.ops import validation
    loader.initialize(use_cache=False)
    with localcontext() as context:
        context.prec = 80
        entries, errors, _ = loader.load_file(ledger_path, extra_validations=validation.HARDCORE_VALIDATIONS)
        book = realization.realize(entries)
        def units(account, commodity):
            node = realization.get(book, account)
            return node.balance.get_currency_units(commodity).number if node is not None else Decimal(0)
        price_entries = [entry for entry in entries if isinstance(entry, data.Price)]
        if len(price_entries) != 1:
            return {"status": "UNAVAILABLE", "reason_codes": ["EXPECTED_SINGLE_CLOSING_PRICE"]}, 2
        mark = price_entries[0]
        asset, cash_currency = mark.currency, mark.amount.currency
        position = realization.get(book, "Assets:Position")
        basis = position.balance.reduce(convert.get_cost).get_currency_units(cash_currency).number if position is not None else Decimal(0)
        value = position.balance.reduce(convert.get_value, prices.build_price_map(entries), mark.date).get_currency_units(cash_currency).number if position is not None else Decimal(0)
        cash = units("Assets:Cash", cash_currency)
        quantity = units("Assets:Position", asset)
        fees = units("Expenses:Fees", cash_currency)
        realized = -units("Income:Trading", cash_currency)
        flows = -units("Equity:Flows", cash_currency)
        unrealized = value - basis
        computed = {"cash": cash, "quantity": quantity, "cost_basis": basis, "fees": fees, "realized_pnl": realized, "unrealized_pnl": unrealized, "external_flows": flows, "net_pnl": realized + unrealized - fees, "nav": cash + value}
        inventory = []
        for file in sorted(dist.files or (), key=str):
            if str(file).startswith("beancount/") and str(file).endswith((".py", ".so", ".pyd")):
                raw = Path(dist.locate_file(file)).read_bytes()
                inventory.append({"path": str(file), "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        result = {
            "status": "EXECUTED", "engine": "beancount", "version": dist.version,
            "declared_install_source": direct, "source_revision": REVISION,
            "installed_code_inventory": inventory,
            "installed_code_inventory_sha256": hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "python": sys.version.split()[0], "packages": sorted([{"name": item.metadata["Name"], "version": item.version} for item in metadata.distributions()], key=lambda item: item["name"].lower()),
            "validation_error_count": len(errors), "validation_error_types": sorted(set(type(error).__name__ for error in errors)),
            "computed": {key: decimal_text(value) for key, value in computed.items()},
            "limits": ["Supplied events and marks remain unverified", "Local process, toolchain and installation metadata are trusted; this is not remote attestation"],
        }
        return result, 1 if errors else 0


if __name__ == "__main__":
    try:
        output, code = execute(sys.argv[1])
    except Exception:
        output, code = {"status": "UNAVAILABLE", "reason_codes": ["ORACLE_WORKER_FAILURE"]}, 2
    print(json.dumps(output, sort_keys=True, allow_nan=False))
    raise SystemExit(code)
