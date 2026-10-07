"""Local accounting CLI. No installations or account connections."""

import argparse
import sys
from pathlib import Path

from .core import AccountingError, assess_bytes, canonical, read_bytes, write_new_file
from .oracle import run_beancount


def main(argv=None):
    parser = argparse.ArgumentParser(description="Reconcile supplied single-asset spot events; authenticity and completeness remain unknown.")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="Original exact-decimal FIFO calculation")
    check.add_argument("input", type=Path)
    check.add_argument("--output", type=Path, help="Create a new report file, without overwriting")
    oracle = commands.add_parser("oracle", help="Run separately installed, pinned Beancount on a generated ledger")
    oracle.add_argument("input", type=Path)
    oracle.add_argument("--python", required=True, type=Path, help="Trusted isolated Beancount interpreter")
    oracle.add_argument("--output-dir", required=True, type=Path, help="New evidence directory")
    args = parser.parse_args(argv)
    try:
        raw = read_bytes(args.input)
        report = run_beancount(raw, python_executable=args.python, output_directory=args.output_dir) if args.command == "oracle" else assess_bytes(raw)
        rendered = canonical(report)
        if args.command == "check" and args.output:
            write_new_file(args.output, rendered)
        sys.stdout.buffer.write(rendered)
        if args.command == "oracle":
            if report["oracle"]["status"] in ("NOT_RUN", "UNAVAILABLE"):
                return 2
            if report["oracle"]["status"] == "DISCREPANCIES_FOUND":
                return 1
        return {"RECONCILED_UNDER_ASSUMPTIONS": 0, "DISCREPANCIES_FOUND": 1, "NOT_ASSESSABLE": 2}[report["status"]]
    except (OSError, AccountingError):
        sys.stderr.write("Accounting input or output unavailable; use bounded regular input and new output paths.\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
