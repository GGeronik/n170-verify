"""Optional real Beancount check of the exact modeled ledger, separately reported.

No native rounded claims or invented reported metrics become ledger assertions.
The generated ledger is fixed, data-only, and omits all closing supplied claims.
The unchanged v1 worker executes only in an explicitly selected pinned interpreter.
"""
import json
from pathlib import Path
import os
import re
import subprocess

from .core import AccountingError, METRICS, canonical, create_private_directory, digest, keys, parse_bytes, read_bytes, reject, text_decimal, timestamp, write_new_file
from .oracle import BEANCOUNT_REVISION, BEANCOUNT_SOURCE_URL
from .v2 import assess_bytes, exact_context, number, validate_document

INSTALLED_INVENTORY_SHA256 = "e8613933996e605176913722520851dc65b61f479a94f5da0589facb9a829bc9"
MAX_OUTPUT = 2 * 1024 * 1024


def generate_ledger(document):
    validate_document(document)
    asset, cash = document["asset"], document["cash_currency"]
    start = timestamp(document["opening"]["timestamp"]).date().isoformat()
    end = timestamp(document["closing"]["timestamp"]).date().isoformat()
    opening = number(document["opening"]["cash"])
    lines = ['; Original exact modeled ledger. Native float claims are not assertions.', 'option "tolerance_multiplier" "0"', 'option "infer_tolerance_from_cost" "FALSE"', f'{start} open Assets:Cash {cash}', f'{start} open Assets:Position {asset} "FIFO"', f'{start} open Equity:Opening {cash}', f'{start} open Equity:Flows {cash}', f'{start} open Expenses:Fees {cash}', f'{start} open Income:Trading {cash}', f'{start} * "Opening cash"', f'  Assets:Cash {text_decimal(opening)} {cash}', f'  Equity:Opening {text_decimal(opening.copy_negate())} {cash}']
    with exact_context():
        for sequence, event in enumerate(document["events"], 1):
            day = timestamp(event["timestamp"]).date().isoformat()
            lines.append(f'{day} * "Event {sequence}"')
            kind = event["type"]
            if kind in ("DEPOSIT", "WITHDRAWAL"):
                amount = number(event["amount"]) * (1 if kind == "DEPOSIT" else -1)
                lines.extend([f'  Assets:Cash {text_decimal(amount)} {cash}', f'  Equity:Flows {text_decimal(-amount)} {cash}'])
            else:
                quantity, price, fee = number(event["quantity"]), number(event["price"]), number(event["fee"], kind="fee")
                if kind == "BUY":
                    lines.extend([f'  Assets:Position {text_decimal(quantity)} {asset} {{{text_decimal(price)} {cash}, "event-{sequence}"}}', f'  Assets:Cash {text_decimal(-(quantity * price + fee))} {cash}', f'  Expenses:Fees {text_decimal(fee)} {cash}'])
                else:
                    lines.extend([f'  Assets:Position {text_decimal(-quantity)} {asset} {{}} @ {text_decimal(price)} {cash}', f'  Assets:Cash {text_decimal(quantity * price - fee)} {cash}', f'  Expenses:Fees {text_decimal(fee)} {cash}', '  Income:Trading'])
        lines.append(f'{end} price {asset} {text_decimal(number(document["closing"]["mark_price"]))} {cash}')
    return ("\n".join(lines) + "\n").encode()


def _validate_observation(observed):
    keys(observed, ("status", "engine", "version", "declared_install_source", "source_revision", "installed_code_inventory", "installed_code_inventory_sha256", "python", "packages", "validation_error_count", "validation_error_types", "computed", "limits"))
    if observed["status"] != "EXECUTED" or observed["engine"] != "beancount" or observed["version"] != "3.2.3" or observed["source_revision"] != BEANCOUNT_REVISION:
        reject("ORACLE_IDENTITY_MISMATCH")
    if type(observed["declared_install_source"]) is not dict or observed["declared_install_source"].get("url") != BEANCOUNT_SOURCE_URL:
        reject("ORACLE_IDENTITY_MISMATCH")
    if type(observed["python"]) is not str or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", observed["python"]):
        reject("INVALID_ORACLE_RUNTIME_METADATA")
    packages = observed["packages"]
    if type(packages) is not list or not 1 <= len(packages) <= 2000:
        reject("INVALID_ORACLE_RUNTIME_METADATA")
    names = []
    for package in packages:
        keys(package, ("name", "version"))
        if any(type(package[key]) is not str or not 1 <= len(package[key]) <= 128 for key in ("name", "version")):
            reject("INVALID_ORACLE_RUNTIME_METADATA")
        names.append(package["name"].lower())
    if names != sorted(set(names)) or {"name": "beancount", "version": "3.2.3"} not in packages:
        reject("INVALID_ORACLE_RUNTIME_METADATA")
    if type(observed["limits"]) is not list or not 1 <= len(observed["limits"]) <= 32 or any(type(value) is not str or not 1 <= len(value) <= 1024 for value in observed["limits"]):
        reject("INVALID_ORACLE_RUNTIME_METADATA")
    inventory = observed["installed_code_inventory"]
    if type(inventory) is not list or not 1 <= len(inventory) <= 2000:
        reject("ORACLE_INVENTORY_MISMATCH")
    calculated = digest(json.dumps(inventory, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())
    if calculated != observed["installed_code_inventory_sha256"] or calculated != INSTALLED_INVENTORY_SHA256:
        reject("ORACLE_INVENTORY_MISMATCH")
    if type(observed["validation_error_count"]) is not int or observed["validation_error_count"] < 0 or type(observed["validation_error_types"]) is not list or any(type(v) is not str for v in observed["validation_error_types"]):
        reject("INVALID_ORACLE_VALIDATION_RESULT")
    if bool(observed["validation_error_count"]) != bool(observed["validation_error_types"]) or observed["validation_error_types"] != sorted(set(observed["validation_error_types"])):
        reject("INVALID_ORACLE_VALIDATION_RESULT")
    keys(observed["computed"], METRICS)
    for value in observed["computed"].values():
        if text_decimal(number(value, kind="result")) != value:
            reject("NONCANONICAL_ORACLE_METRIC")


def run_beancount(raw, *, python_executable, output_directory):
    report = assess_bytes(raw)
    report["oracle"] = {"status": "NOT_RUN", "reason_codes": []}
    if report["computed"] is None:
        report["oracle"]["reason_codes"] = ["SUPPORTED_ACCOUNTING_INPUT_REQUIRED"]
        return report
    ledger = generate_ledger(parse_bytes(raw))
    output = Path(output_directory).absolute()
    create_private_directory(output)
    worker = read_bytes(Path(__file__).with_name("_oracle_worker.py"))
    for name, data in (("events.json", raw), ("ledger.beancount", ledger), ("oracle-worker.py", worker)):
        write_new_file(output / name, data)
    command = [str(Path(python_executable).absolute()), "-I", "-B", str(output / "oracle-worker.py"), str(output / "ledger.beancount")]
    evidence = {"engine": "beancount", "expected_revision": BEANCOUNT_REVISION, "expected_installed_inventory_sha256": INSTALLED_INVENTORY_SHA256, "input_sha256": digest(raw), "ledger_sha256": digest(ledger), "worker_sha256": digest(worker), "purpose": "independent exact modeled-ledger calculation; all supplied closing claims omitted from generated ledger assertions", "execution_trust": "trusted locally selected interpreter; installation inventory checked against accepted local build; no attestation", "network_policy": "no network operation requested; no OS network isolation claimed", "output_policy": "stdout/stderr bounded after collection from trusted interpreter; originals hashed, retained prefixes explicitly marked when oversized"}
    stdout = stderr = b""
    try:
        completed = subprocess.run(command, cwd=output, env={"PATH": os.defpath, "BEANCOUNT_DISABLE_LOAD_CACHE": "1", "TZ": "UTC", "LC_ALL": "C"}, capture_output=True, timeout=45, check=False)
        stdout, stderr = completed.stdout, completed.stderr
        evidence["exit_code"] = completed.returncode
        if len(stdout) > MAX_OUTPUT or len(stderr) > MAX_OUTPUT:
            reject("ORACLE_OUTPUT_LIMIT_EXCEEDED")
        observed = parse_bytes(stdout)
        evidence["observation"] = observed
        _validate_observation(observed)
        differences = [key for key in METRICS if observed["computed"][key] != report["computed"][key]]
        evidence["different_metrics"] = differences
        if completed.returncode not in (0, 1):
            reject("ORACLE_EXIT_FAILURE")
        if differences or observed["validation_error_count"] or completed.returncode:
            evidence.update(status="DISCREPANCIES_FOUND", reason_codes=["ORACLE_DIFFERENCE_OR_VALIDATION_ERROR"])
        else:
            evidence.update(status="MATCHED", reason_codes=["BEANCOUNT_EXECUTED_AND_MATCHED_EXACT_MODEL"])
    except subprocess.TimeoutExpired as error:
        stdout, stderr = error.stdout or b"", error.stderr or b""
        evidence.update(status="UNAVAILABLE", reason_codes=["ORACLE_TIMEOUT"])
    except (OSError, AccountingError, ValueError, KeyError, TypeError, AttributeError) as error:
        evidence.update(status="UNAVAILABLE", reason_codes=[str(error) if isinstance(error, AccountingError) else "ORACLE_EXECUTION_OR_OUTPUT_FAILURE"])
    for name, data in (("oracle.stdout.json", stdout), ("oracle.stderr.txt", stderr)):
        evidence[name] = {"observed_bytes": len(data), "sha256": digest(data), "retained_bytes": min(len(data), MAX_OUTPUT), "truncated": len(data) > MAX_OUTPUT}
        write_new_file(output / name, data[:MAX_OUTPUT])
    report["oracle"] = evidence
    write_new_file(output / "report.json", canonical(report))
    return report
