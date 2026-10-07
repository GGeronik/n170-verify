"""Actual external-engine tests are explicitly skipped without its pinned env."""

import json
import os
from pathlib import Path
import tempfile
import unittest

from verify_accounting.core import AccountingError, assess_document, canonical
from verify_accounting.oracle import generate_ledger, run_beancount

FIXTURES = Path(__file__).resolve().parents[1] / "verify_accounting" / "fixtures"
PYTHON = os.environ.get("N170_BEANCOUNT_PYTHON")


class LedgerGenerationTests(unittest.TestCase):
    def test_raw_lots_without_calculated_gain_or_lot_selection(self):
        d = json.loads((FIXTURES / "fifo.json").read_bytes())
        d["closing"]["reported"] = {}
        ledger = generate_ledger(d).decode()
        self.assertIn('Assets:Position -3 BTC {} @ 120 USDT', ledger)
        self.assertIn('Assets:Position 2 BTC {100 USDT, "event-1"}', ledger)
        self.assertIn('Assets:Position 2 BTC {150 USDT, "event-2"}', ledger)
        self.assertIn('\n  Income:Trading\n', ledger)
        for directive in ("plugin ", "include ", " pad "):
            self.assertNotIn(directive, ledger)

    def test_unsafe_directives_never_emitted(self):
        d = json.loads((FIXTURES / "gain.json").read_bytes())
        d["asset"] = 'BTC\ninclude "private.bean"'
        with self.assertRaises(AccountingError):
            generate_ledger(d)

    def test_missing_interpreter_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            r = run_beancount((FIXTURES / "gain.json").read_bytes(), python_executable="/nonexistent/n170-test-python", output_directory=Path(directory).resolve() / "evidence")
            self.assertEqual(r["oracle"]["status"], "UNAVAILABLE")

    def test_unsupported_data_never_executes(self):
        r = run_beancount(b"{}", python_executable="/nonexistent", output_directory="/nonexistent")
        self.assertEqual(r["oracle"]["status"], "NOT_RUN")


@unittest.skipUnless(PYTHON, "Set N170_BEANCOUNT_PYTHON to an explicitly installed pinned oracle; no simulated oracle success")
class ActualBeancountTests(unittest.TestCase):
    def test_eight_independent_hand_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ("gain", "loss", "contribution", "fifo", "depletion", "funded", "fractional", "same_day_fifo"):
                with self.subTest(name=name):
                    r = run_beancount((FIXTURES / f"{name}.json").read_bytes(), python_executable=PYTHON, output_directory=Path(directory).resolve() / name)
                    self.assertEqual(r["oracle"]["status"], "MATCHED", r["oracle"])
                    self.assertEqual(r["oracle"]["observation"]["validation_error_count"], 0)

    def test_exact_assertion_tampering_fails(self):
        d = json.loads((FIXTURES / "gain.json").read_bytes())
        d["closing"]["reported"]["cash"] = "717.0000000000000001"
        with tempfile.TemporaryDirectory() as directory:
            r = run_beancount(canonical(d), python_executable=PYTHON, output_directory=Path(directory).resolve() / "tampered")
            self.assertEqual(r["status"], "DISCREPANCIES_FOUND")
            self.assertEqual(r["oracle"]["status"], "DISCREPANCIES_FOUND")
            self.assertIn("BalanceError", r["oracle"]["observation"]["validation_error_types"])


if __name__ == "__main__":
    unittest.main()
