"""Generate a fixed ledger and invoke a separately installed Beancount process."""

from __future__ import annotations

from datetime import timedelta
from decimal import localcontext
import json
import os
from pathlib import Path
import subprocess

from .core import AccountingError, assess_bytes, canonical, create_private_directory, digest, number, parse_bytes, read_bytes, text_decimal, timestamp, validate_document, write_new_file

BEANCOUNT_REVISION = "9747213802acb733ce53acc6e963f5961f47d6cd"
BEANCOUNT_SOURCE_URL = f"https://github.com/beancount/beancount/archive/{BEANCOUNT_REVISION}.tar.gz"


def generate_ledger(document):
    """No raw descriptions, code, plugins, includes or document paths are emitted.

    Only the fixed Income:Trading posting is interpolated: Beancount independently
    determines FIFO realized gain rather than receiving N170's calculated gain.
    """
    validate_document(document)
    asset, cash = document["asset"], document["cash_currency"]
    start = timestamp(document["opening"]["timestamp"]).date().isoformat()
    end = timestamp(document["closing"]["timestamp"]).date()
    assertion_date = (end + timedelta(days=1)).isoformat()
    lines = [
        '; Original generated accounting fixture. Never an arbitrary user-authored ledger.',
        'option "tolerance_multiplier" "0"',
        'option "infer_tolerance_from_cost" "FALSE"',
        f'{start} open Assets:Cash {cash}',
        f'{start} open Assets:Position {asset} "FIFO"',
        f'{start} open Equity:Opening {cash}',
        f'{start} open Equity:Flows {cash}',
        f'{start} open Expenses:Fees {cash}',
        f'{start} open Income:Trading {cash}',
        f'{start} * "Opening cash"',
        f'  Assets:Cash {document["opening"]["cash"]} {cash}',
        f'  Equity:Opening -{document["opening"]["cash"]} {cash}',
    ]
    with localcontext() as context:
        context.prec = 80
        for sequence, event in enumerate(document["events"], start=1):
            date = timestamp(event["timestamp"]).date().isoformat()
            lines.append(f'{date} * "Event {sequence}"')
            kind = event["type"]
            if kind in ("DEPOSIT", "WITHDRAWAL"):
                amount = number(event["amount"]) * (1 if kind == "DEPOSIT" else -1)
                lines.extend([f'  Assets:Cash {text_decimal(amount)} {cash}', f'  Equity:Flows {text_decimal(-amount)} {cash}'])
            else:
                quantity, price, fee = (number(event[k]) for k in ("quantity", "price", "fee"))
                if kind == "BUY":
                    lines.extend([
                        f'  Assets:Position {text_decimal(quantity)} {asset} {{{text_decimal(price)} {cash}, "event-{sequence}"}}',
                        f'  Assets:Cash {text_decimal(-(quantity * price + fee))} {cash}',
                        f'  Expenses:Fees {text_decimal(fee)} {cash}',
                    ])
                else:
                    lines.extend([
                        f'  Assets:Position {text_decimal(-quantity)} {asset} {{}} @ {text_decimal(price)} {cash}',
                        f'  Assets:Cash {text_decimal(quantity * price - fee)} {cash}',
                        f'  Expenses:Fees {text_decimal(fee)} {cash}',
                        '  Income:Trading',
                    ])
        lines.append(f'{end.isoformat()} price {asset} {document["closing"]["mark_price"]} {cash}')
        accounts = {"cash": ("Assets:Cash", cash, 1), "quantity": ("Assets:Position", asset, 1), "fees": ("Expenses:Fees", cash, 1), "realized_pnl": ("Income:Trading", cash, -1), "external_flows": ("Equity:Flows", cash, -1)}
        for name, (account, commodity, sign) in accounts.items():
            if name in document["closing"]["reported"]:
                amount = number(document["closing"]["reported"][name], reported=True) * sign
                lines.append(f'{assertion_date} balance {account} {text_decimal(amount)} ~ 0 {commodity}')
    return ("\n".join(lines) + "\n").encode()


def run_beancount(raw, *, python_executable, output_directory):
    """Run a trusted, explicitly selected interpreter; never install automatically.

    This is a local process check, not an OS sandbox or remote attestation.
    """
    report = assess_bytes(raw)
    report["oracle"] = {"status": "NOT_RUN", "reason_codes": []}
    if report["computed"] is None:
        report["oracle"]["reason_codes"] = ["SUPPORTED_ACCOUNTING_INPUT_REQUIRED"]
        return report
    document = parse_bytes(raw)
    ledger = generate_ledger(document)
    output = Path(output_directory).absolute()
    create_private_directory(output)
    worker = read_bytes(Path(__file__).with_name("_oracle_worker.py"))
    for name, value in (("events.json", raw), ("ledger.beancount", ledger), ("oracle-worker.py", worker)):
        write_new_file(output / name, value)
    command = [str(Path(python_executable).absolute()), "-I", "-B", str(output / "oracle-worker.py"), str(output / "ledger.beancount")]
    evidence = {
        "engine": "beancount", "expected_revision": BEANCOUNT_REVISION,
        "input_sha256": digest(raw), "ledger_sha256": digest(ledger), "worker_sha256": digest(worker),
        "execution_trust": "locally selected interpreter and installed packages; no independent observer or hardware attestation",
        "network_policy": "no network operation requested; no OS network isolation claimed",
    }
    try:
        completed = subprocess.run(command, cwd=output, env={"PATH": os.defpath, "BEANCOUNT_DISABLE_LOAD_CACHE": "1", "TZ": "UTC", "LC_ALL": "C"}, capture_output=True, timeout=45, check=False)
        if len(completed.stdout) + len(completed.stderr) > 4 * 1024 * 1024:
            raise AccountingError("ORACLE_OUTPUT_LIMIT_EXCEEDED")
        evidence["exit_code"] = completed.returncode
        evidence["stdout_sha256"] = digest(completed.stdout)
        evidence["stderr_sha256"] = digest(completed.stderr)
        write_new_file(output / "oracle.stdout.json", completed.stdout)
        write_new_file(output / "oracle.stderr.txt", completed.stderr)
        observed = json.loads(completed.stdout)
        evidence["observation"] = observed
        if observed.get("status") != "EXECUTED":
            evidence.update(status="UNAVAILABLE", reason_codes=["ORACLE_DID_NOT_COMPLETE"])
        else:
            independent = observed["computed"]
            differences = [key for key in report["computed"] if independent.get(key) != report["computed"][key]]
            evidence["different_metrics"] = differences
            if differences or observed["validation_error_count"] or completed.returncode:
                evidence.update(status="DISCREPANCIES_FOUND", reason_codes=["ORACLE_DIFFERENCE_OR_VALIDATION_ERROR"])
            else:
                evidence.update(status="MATCHED", reason_codes=["BEANCOUNT_EXECUTED_AND_MATCHED"])
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError) as exc:
        evidence.update(status="UNAVAILABLE", reason_codes=[str(exc) if isinstance(exc, AccountingError) else "ORACLE_EXECUTION_OR_OUTPUT_FAILURE"])
    report["oracle"] = evidence
    write_new_file(output / "report.json", canonical(report))
    return report
