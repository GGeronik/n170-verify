"""Independent hand expectations plus unsupported/adversarial accounting cases."""

import copy
from decimal import localcontext
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from verify_accounting.core import AccountingError, MAX_BYTES, MAX_EVENTS, assess_bytes, assess_document, canonical, create_private_directory, number, read_bytes, write_new_file

FIXTURES = Path(__file__).resolve().parents[1] / "verify_accounting" / "fixtures"


def fixture(name="gain"):
    return json.loads((FIXTURES / f"{name}.json").read_text())


class AccountingTests(unittest.TestCase):
    def test_frozen_hand_answers(self):
        self.assertEqual(hashlib.sha256((FIXTURES / "EXPECTED.json").read_bytes()).hexdigest(), "f593cca4075eca132a97b4831676e1106b65c1259fff4cc19ff9883624053f79")
        for file in ("EXPECTED.json", "EXPECTED_ADDITIONAL.json"):
            for name, expected in json.loads((FIXTURES / file).read_text()).items():
                if name in ("schema", "basis"):
                    continue
                with self.subTest(name=name):
                    report = assess_document(fixture(name))
                    self.assertEqual(report["status"], "RECONCILED_UNDER_ASSUMPTIONS")
                    self.assertEqual(report["computed"], {k: v for k, v in expected.items() if k != "calculation"})
                    self.assertEqual(report["selected_source_completeness"], "unknown")
                    self.assertEqual(report["source_authenticity"], "not_established")
                    self.assertEqual(report["oracle"]["status"], "NOT_RUN")

    def test_every_reported_metric_discrepancy(self):
        for metric in fixture()["closing"]["reported"]:
            d = fixture()
            d["closing"]["reported"][metric] = "999"
            r = assess_document(d)
            self.assertEqual(r["status"], "DISCREPANCIES_FOUND", metric)
            self.assertEqual(r["checks"][metric]["status"], "DISCREPANCY")

    def test_missing_metric_is_not_reconciled(self):
        d = fixture()
        del d["closing"]["reported"]["fees"]
        r = assess_document(d)
        self.assertEqual(r["status"], "NOT_ASSESSABLE")
        self.assertEqual(r["checks"]["fees"]["status"], "NOT_SUPPLIED")
        d["closing"]["reported"]["nav"] = "10"
        self.assertEqual(assess_document(d)["status"], "DISCREPANCIES_FOUND")

    def test_required_zero_is_distinct_from_missing(self):
        d = fixture("depletion")
        del d["closing"]["mark_price"]
        self.assertEqual(assess_document(d)["reason_codes"], ["MISSING_REQUIRED_FIELD"])

    def test_unsupported_inputs(self):
        mutations = [
            (lambda d: d["events"][0].update(type="SPLIT"), "UNSUPPORTED_EVENT"),
            (lambda d: d["events"][0].update(fee_currency="BTC"), "UNSUPPORTED_FEE_CURRENCY"),
            (lambda d: d["events"][0].update(quantity="0"), "INVALID_AMOUNT_SIGN"),
            (lambda d: d["events"][0].update(price="0"), "INVALID_AMOUNT_SIGN"),
            (lambda d: d["events"][0].update(fee="-1"), "INVALID_AMOUNT_SIGN"),
            (lambda d: d["events"][0].update(fee=2), "INVALID_DECIMAL"),
            (lambda d: d["events"][0].update(price="NaN"), "INVALID_DECIMAL"),
            (lambda d: d["events"][0].update(price="1e2"), "INVALID_DECIMAL"),
            (lambda d: d["events"][0].update(price="1.000000001"), "INVALID_DECIMAL"),
            (lambda d: d["events"][0].update(price="1000000000001"), "AMOUNT_LIMIT_EXCEEDED"),
            (lambda d: d["events"][1].update(event_id="buy-1"), "DUPLICATE_EVENT"),
            (lambda d: d["events"].reverse(), "EVENT_CHRONOLOGY_MISMATCH"),
            (lambda d: d["opening"].update(quantity="1"), "UNSUPPORTED_FIELD"),
            (lambda d: d.update(plugin="evil"), "UNSUPPORTED_FIELD"),
            (lambda d: d.update(asset='BTC\nplugin "evil"'), "INVALID_COMMODITY"),
            (lambda d: d["opening"].update(cash="1"), "NEGATIVE_CASH_UNSUPPORTED"),
            (lambda d: d["events"][1].update(quantity="5"), "SELL_EXCEEDS_POSITION"),
        ]
        for mutation, code in mutations:
            d = fixture()
            mutation(d)
            with self.subTest(code=code):
                r = assess_document(d)
                self.assertEqual(r["status"], "NOT_ASSESSABLE")
                self.assertEqual(r["reason_codes"], [code])
                self.assertIsNone(r["computed"])

    def test_withdrawal_excludes_external_flow_from_profit(self):
        d = fixture()
        d["events"].append({"event_id": "withdraw", "timestamp": "2026-01-04T00:00:00Z", "type": "WITHDRAWAL", "amount": "100"})
        d["closing"]["reported"].update(cash="617", external_flows="-100", nav="947")
        r = assess_document(d)
        self.assertEqual(r["status"], "RECONCILED_UNDER_ASSUMPTIONS")
        self.assertEqual(r["computed"]["net_pnl"], "47")

    def test_no_event_zero_account(self):
        d = fixture()
        d["opening"]["cash"] = "0"
        d["events"] = []
        d["closing"]["reported"] = {key: "0" for key in d["closing"]["reported"]}
        r = assess_document(d)
        self.assertEqual(r["status"], "RECONCILED_UNDER_ASSUMPTIONS")
        self.assertEqual(r["scope"]["selected_event_count"], 0)

    def test_selected_sources_cannot_establish_completeness(self):
        d = fixture("contribution")
        d["events"] = d["events"][:-1]
        self.assertEqual(assess_document(d)["status"], "DISCREPANCIES_FOUND")
        # Consistently omitting both the event and its balance effect is not detectable.
        d["closing"]["reported"] = fixture()["closing"]["reported"]
        r = assess_document(d)
        self.assertEqual(r["status"], "RECONCILED_UNDER_ASSUMPTIONS")
        self.assertEqual(r["selected_source_completeness"], "unknown")

    def test_raw_inventory_binds_bytes_and_events(self):
        raw = (FIXTURES / "gain.json").read_bytes()
        r = assess_bytes(raw)
        self.assertEqual(r["source_inventory"][0]["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertNotEqual(assess_bytes(raw + b" ")["source_inventory"], r["source_inventory"])
        self.assertEqual(r["event_inventory"][0]["sha256"], hashlib.sha256(canonical(fixture()["events"][0])).hexdigest())

    def test_input_limits_and_ambiguous_json(self):
        for raw in (b'{"schema":"a","schema":"b"}', b'{"x":NaN}', b"\xff", b"[" * 1200, b" " * (MAX_BYTES + 1)):
            self.assertEqual(assess_bytes(raw)["status"], "NOT_ASSESSABLE")
        d = fixture()
        d["events"] *= MAX_EVENTS
        self.assertEqual(assess_document(d)["status"], "NOT_ASSESSABLE")

    def test_timestamp_utc_overflow_is_not_assessable(self):
        d = fixture()
        d["opening"]["timestamp"] = "0001-01-01T00:00:00+23:59"
        self.assertEqual(assess_document(d)["reason_codes"], ["INVALID_TIMESTAMP"])

    def test_numeric_bound_is_independent_of_ambient_precision(self):
        with localcontext() as context:
            context.prec = 2
            for value in ("1000000000000000000000000000000.0000000000000001", "-1000000000000000000000000000000.0000000000000001"):
                with self.assertRaises(AccountingError):
                    number(value, reported=True)
            self.assertEqual(assess_document(fixture("fractional"))["status"], "RECONCILED_UNDER_ASSUMPTIONS")

    def test_private_output_modes_and_no_symlink_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            old = os.umask(0)
            try:
                create_private_directory(base / "private")
                write_new_file(base / "private" / "report", b"{}")
            finally:
                os.umask(old)
            self.assertEqual((base / "private").stat().st_mode & 0o777, 0o700)
            self.assertEqual((base / "private" / "report").stat().st_mode & 0o777, 0o600)
            (base / "link").symlink_to(base / "private", target_is_directory=True)
            with self.assertRaises(OSError):
                write_new_file(base / "link" / "other", b"{}")
            with self.assertRaises(OSError):
                create_private_directory(base / "link" / "new")
            with self.assertRaises(OSError):
                write_new_file(base / "private" / "report", b"replacement")
            self.assertEqual((base / "private" / "report").read_bytes(), b"{}")

    def test_bounded_file_read_refuses_symlinks_and_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            (base / "input").write_bytes(b"{}")
            (base / "link").symlink_to(base / "input")
            (base / "dirlink").symlink_to(base, target_is_directory=True)
            os.mkfifo(base / "fifo")
            for path in (base / "link", base / "dirlink" / "input", base / "fifo"):
                with self.assertRaises((OSError, AccountingError)):
                    read_bytes(path)

    def test_cli_success_failure_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / "report.json"
            command = [sys.executable, "-B", "-m", "verify_accounting", "check", str(FIXTURES / "gain.json"), "--output", str(output)]
            result = subprocess.run(command, capture_output=True)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(output.read_bytes())["computed"]["net_pnl"], "47")
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 2)


if __name__ == "__main__":
    unittest.main()
