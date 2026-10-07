"""Local evidence CLI; execution requires the explicit isolated-runner opt-in."""
import argparse
import json
import os
from pathlib import Path
import stat
import sys

from .freqtrade import MAX_CSV_BYTES, assess_lookahead
from .reporting import render_html, report_for_sharing


def read_regular(path, limit=MAX_CSV_BYTES):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("Regular file required")
        raw = source.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("Input too large")
    return raw.decode("utf-8")


def strict_context(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate context field")
            result[key] = value
        return result
    def invalid(value):
        raise ValueError("Non-finite context value")
    return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid)


def write_new(path, text):
    # Explicit export only; preserve prior evidence and use private permissions.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as destination:
        destination.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect supplied tool evidence locally; no trading or authentication.")
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("freqtrade-lookahead", help="Interpret a Freqtrade lookahead CSV, with explicit evidence limits")
    inspect.add_argument("csv", type=Path)
    inspect.add_argument("--context", type=Path, help="Optional unverified run declarations")
    inspect.add_argument("--output", type=Path, help="Write a new structured report")
    inspect.add_argument("--html", type=Path, help="Write a new static reading copy")
    inspect.add_argument("--include-labels", action="store_true", help="Explicitly include private strategy/file/indicator labels")
    inspect.add_argument("--synthetic-example", action="store_true", help="Label an explicitly supplied synthetic demonstration")
    commands.add_parser("self-test", help="Run synthetic parser/claim-boundary controls; not an engine benchmark")
    package = commands.add_parser("package", help="Prepare an allowlisted source archive; no publication")
    package.add_argument("--output", type=Path, required=True)
    run = commands.add_parser("run-freqtrade", help="Opt-in offline execution of explicitly selected trusted local strategies")
    run.add_argument("--output", type=Path, required=True, help="Fresh nonexistent run directory")
    run.add_argument("--data", type=Path, required=True, help="BTC_USDT-5m.json local spot candles")
    run.add_argument("--strategy", action="append", required=True, help="Explicit NAME=local-file.py; repeat up to eight times")
    run.add_argument("--acknowledge-local-code", action="store_true", help="Confirm reviewed local executable code; never use uploads")
    run.add_argument("--image", help="Separately installed immutable Docker image reference")
    run.add_argument("--timeout-seconds", type=int, default=120)
    run.add_argument("--minimum-trade-amount", type=int, default=5)
    run.add_argument("--targeted-trade-amount", type=int, default=10)
    run.add_argument("--timerange", default="20260101-20260103")
    verify = commands.add_parser("verify-run", help="Check exact run artifacts and complete attempt accounting; no execution")
    verify.add_argument("directory", type=Path)
    verify.add_argument("--manifest-sha256")
    export = commands.add_parser("export-run", help="Export exact local run bytes as a bounded data-only review package")
    export.add_argument("directory", type=Path)
    export.add_argument("--output", type=Path, required=True, help="New package file; includes selected source, data, configuration and logs")
    review = commands.add_parser("verify-review", help="Verify a portable run package without executing or extracting its contents")
    review.add_argument("file", type=Path)
    review.add_argument("--manifest-sha256", help="Optional independently obtained exact manifest digest")
    compare = commands.add_parser("compare-runs", help="Compare two supplied packages; does not establish independent execution")
    compare.add_argument("left", type=Path)
    compare.add_argument("right", type=Path)
    fixture = commands.add_parser("synthetic-fixture", help="Create original synthetic engineering inputs in a new directory")
    fixture.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    review_error_types = ()
    try:
        if args.command == "self-test":
            from .conformance import run_conformance
            result = run_conformance()
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if not result["unexpected_results"] else 1
        if args.command == "package":
            from .packaging import package_source
            print(json.dumps(package_source(args.output), indent=2, sort_keys=True))
            return 0
        if args.command == "synthetic-fixture":
            from .synthetic import generate_fixture
            generate_fixture(args.output)
            print(json.dumps({"created": True, "scope": "original_synthetic_engineering_inputs; not real-market performance"}))
            return 0
        if args.command in {"export-run", "verify-review", "compare-runs"}:
            from .run_review import MAX_ENVELOPE, ReviewError, compare_run_reviews, export_run_review, verify_run_review
            review_error_types = (ReviewError,)
            from .run_contract import digest, json_bytes, read_file
            if args.command == "export-run":
                package_raw = json_bytes(export_run_review(args.directory))
                result = verify_run_review(package_raw)
                write_new(args.output, package_raw.decode("utf-8"))
                result["package_sha256"] = digest(package_raw)
                result["exported"] = True
                print(json.dumps(result, indent=2, sort_keys=True))
                return 0
            if args.command == "compare-runs":
                result = compare_run_reviews(read_file(args.left, MAX_ENVELOPE), read_file(args.right, MAX_ENVELOPE))
                print(json.dumps(result, indent=2, sort_keys=True))
                return {"SAME": 0, "DIFFERENT": 1}.get(result["status"], 2)
            result = verify_run_review(read_file(args.file, MAX_ENVELOPE), args.manifest_sha256)
            print(json.dumps(result, indent=2, sort_keys=True))
            return {"NO_FINDINGS_REPORTED": 0, "FINDINGS_REPORTED": 1}.get(result["status"], 2)
        if args.command == "verify-run":
            from .run_contract import verify_run
            result = verify_run(args.directory, args.manifest_sha256)
            print(json.dumps(result, indent=2, sort_keys=True))
            return {"NO_FINDINGS_REPORTED": 0, "FINDINGS_REPORTED": 1}.get(result["status"], 2)
        if args.command == "run-freqtrade":
            import signal
            from .runner import DEFAULT_IMAGE, run_freqtrade
            from .run_contract import verify_run
            selected = {}
            for selection in args.strategy:
                name, path = selection.split("=", 1)
                if name in selected:
                    raise ValueError("Duplicate selected strategy")
                selected[name] = Path(path)
            def cancel(_signum, _frame):
                raise KeyboardInterrupt()
            previous = signal.signal(signal.SIGTERM, cancel)
            try:
                run_freqtrade(args.output, image=args.image or DEFAULT_IMAGE, strategies=selected,
                              data=args.data, acknowledge_local_code=args.acknowledge_local_code,
                              timeout_seconds=args.timeout_seconds, minimum_trade_amount=args.minimum_trade_amount,
                              targeted_trade_amount=args.targeted_trade_amount, timerange=args.timerange)
            finally:
                signal.signal(signal.SIGTERM, previous)
            result = verify_run(args.output)
            print(json.dumps(result, indent=2, sort_keys=True))
            return {"NO_FINDINGS_REPORTED": 0, "FINDINGS_REPORTED": 1}.get(result["status"], 2)
        context = strict_context(read_regular(args.context, 16_384)) if args.context else None
        result = report_for_sharing(assess_lookahead(read_regular(args.csv), context=context),
                                    include_labels=args.include_labels)
        result["example_declaration"] = "synthetic" if args.synthetic_example else "not_declared"
        text = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
        if args.output:
            write_new(args.output, text)
        if args.html:
            write_new(args.html, render_html(result))
        print(text, end="")
        return {"NO_FINDINGS_REPORTED": 0, "FINDINGS_REPORTED": 1}.get(result["status"], 2)
    except review_error_types as error:
        print(json.dumps({"schema": "n170.tool-evidence.error.v1", "status": "NOT_ASSESSABLE",
                          "reason_codes": [str(error)],
                          "message": "Portable export was not completed. Retain the original evidence; no bytes were pruned or authenticated."}))
        return 2
    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        # Do not echo paths, source values or hostile parser content to stdout.
        print(json.dumps({"schema": "n170.tool-evidence.error.v1", "status": "NOT_ASSESSABLE",
                          "reason_codes": ["INPUT_OR_OUTPUT_ERROR"],
                          "message": "Check UTF-8 input, supported context, file limits and unused output paths. No report was authenticated."}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
