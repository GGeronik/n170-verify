"""Explicit local accounting v2 CLI; offline review never executes captured code."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from . import run_contract_v2 as contract
from . import run_review_v2 as review


ORACLE_FILES = ("events.json", "ledger.beancount", "oracle-worker.py", "oracle.stdout.json", "oracle.stderr.txt", "report.json")


def _write(path, raw):
    from verify_accounting.core import write_new_file
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_new_file(path, raw)


def attach_oracle(source, destination, python_executable):
    """Keep the original receipt intact; write a new receipt with oracle evidence."""
    from verify_accounting.core import canonical, create_private_directory
    from verify_accounting.oracle_v2 import run_beancount
    package = review.export_run_review(source)
    report, manifest, buffers = review._inspect(contract.json_bytes(package))
    assessments = report["accounting"]["attempts"]
    selected = [item for item in assessments if item["capture"]["status"] == "SUPPORTED"]
    if not selected:
        raise ValueError("NO_SUPPORTED_CAPTURE_FOR_ORACLE")
    if any("/accounting/" in name for name in buffers):
        raise ValueError("ORACLE_EVIDENCE_ALREADY_PRESENT")
    if len(buffers) + len(selected) * len(ORACLE_FILES) > review.MAX_ARTIFACTS:
        raise ValueError("ORACLE_ARTIFACT_COUNT_LIMIT")
    root = Path(destination).absolute()
    create_private_directory(root)
    for path, raw in buffers.items():
        _write(root / path, raw)
    for item in selected:
        output = root / "attempts" / item["id"] / "accounting"
        run_beancount(canonical(item["events"]), python_executable=python_executable, output_directory=output)
    paths = contract._files(root)
    manifest["artifacts"] = [contract.inventory_entry(path, contract.read_file(root / path)) for path in paths]
    for attempt in manifest["attempts"]:
        prefix = "attempts/" + attempt["id"] + "/"
        attempt["artifacts"] = [entry for entry in manifest["artifacts"] if entry["path"].startswith(prefix)]
    _write(root / "manifest.json", contract.json_bytes(manifest))
    return review.verify_run_review(contract.json_bytes(review.export_run_review(root)))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    execute = sub.add_parser("run", help="Run explicitly trusted local strategies in the pinned installed container")
    execute.add_argument("destination")
    execute.add_argument("--strategy", action="append", required=True, metavar="NAME=PATH")
    execute.add_argument("--data", required=True)
    execute.add_argument("--acknowledge-local-code", action="store_true")
    execute.add_argument("--timeout-seconds", type=int, default=120)
    execute.add_argument("--minimum-trade-amount", type=int, default=5)
    execute.add_argument("--targeted-trade-amount", type=int, default=10)
    execute.add_argument("--timerange", default="20260101-20260103")
    export = sub.add_parser("export", help="Export complete v2 run bytes without executing them")
    export.add_argument("directory")
    export.add_argument("--output", required=True)
    verify = sub.add_parser("verify", help="Verify and recompute a portable v2 receipt, offline and data-only")
    verify.add_argument("package")
    verify.add_argument("--manifest-sha256")
    verify.add_argument("--report")
    oracle = sub.add_parser("oracle", help="Explicitly invoke a separately installed trusted Beancount interpreter")
    oracle.add_argument("directory")
    oracle.add_argument("--output", required=True, help="New directory; original receipt remains intact")
    oracle.add_argument("--python", required=True, help="Trusted explicitly selected interpreter with pinned Beancount installed")
    compare = sub.add_parser("compare", help="Conservative comparison of two supplied v2 receipts")
    compare.add_argument("left")
    compare.add_argument("right")
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            from .runner_v2 import run_freqtrade
            strategies = {}
            for entry in args.strategy:
                name, separator, path = entry.partition("=")
                if not separator or not name or not path or name in strategies:
                    raise ValueError("UNIQUE_NAME_EQUALS_PATH_REQUIRED")
                strategies[name] = path
            run_freqtrade(args.destination, strategies=strategies, data=args.data,
                          acknowledge_local_code=args.acknowledge_local_code, timeout_seconds=args.timeout_seconds,
                          minimum_trade_amount=args.minimum_trade_amount, targeted_trade_amount=args.targeted_trade_amount,
                          timerange=args.timerange)
            result = review.verify_run_review(contract.json_bytes(review.export_run_review(args.destination)))
        elif args.command == "export":
            package = review.export_run_review(args.directory)
            _write(Path(args.output).absolute(), contract.json_bytes(package))
            result = {"schema": review.SCHEMA, "status": "EXPORTED", "manifest_sha256": package["manifest"]["sha256"]}
        elif args.command == "verify":
            result = review.verify_run_review(contract.read_file(args.package, review.MAX_ENVELOPE), args.manifest_sha256)
            if args.report:
                _write(Path(args.report).absolute(), contract.json_bytes(result))
        elif args.command == "oracle":
            result = attach_oracle(args.directory, args.output, args.python)
        else:
            result = review.compare_run_reviews(contract.read_file(args.left, review.MAX_ENVELOPE), contract.read_file(args.right, review.MAX_ENVELOPE))
        sys.stdout.buffer.write(contract.json_bytes(result))
        # Financial completeness is intentionally never inferred from detector success.
        return 0 if args.command == "export" else 2
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, "Accounting operation did not complete: " + str(error) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
