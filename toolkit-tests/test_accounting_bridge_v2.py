"""Integration challenges against retained actual captures, never substituted mocks.

Set N170_ACCOUNTING_EVIDENCE to the isolated evidence directory. These tests never
run received source/commands or the external engine. Mutations are adversarial
supplied receipts, not additional engine executions.
"""
import base64
import copy
import json
import math
import os
from pathlib import Path
import unittest

from verify_toolkit import run_review_v2 as review, run_contract_v2 as contract
from verify_accounting.native_numeric import dto

EVIDENCE = os.environ.get("N170_ACCOUNTING_EVIDENCE")


@unittest.skipUnless(EVIDENCE, "retained actual accounting evidence path required")
class AccountingBridgeIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packages = {case: json.loads((Path(EVIDENCE) / "packages" / (case + ".json")).read_bytes())
                        for case in ("flat-02", "smooth", "gain", "loss", "forced", "insufficient", "failure")}

    def report(self, package):
        return review.verify_run_review(contract.json_bytes(package))

    def mutate_capture(self, change, case="smooth"):
        package = copy.deepcopy(self.packages[case])
        _, manifest, buffers = review._decode(contract.json_bytes(package))
        prefix = "attempts/000/"
        capture = json.loads(buffers[prefix + "output/baseline-capture.json"])
        change(capture)
        raw = contract.json_bytes(capture)
        buffers[prefix + "output/baseline-capture.json"] = raw
        worker = json.loads(buffers[prefix + "output/worker-result.json"])
        worker["capture"].update(size=len(raw), sha256=contract.digest(raw), status=capture["capture"]["status"], reason_codes=capture["capture"]["reason_codes"])
        manifest["attempts"][0]["capture"] = worker["capture"]
        buffers[prefix + "output/worker-result.json"] = contract.json_bytes(worker)
        emitted = {path[len(prefix + "output/"):]: base64.b64encode(data).decode() for path, data in buffers.items() if path.startswith(prefix + "output/")}
        transport = review.BUNDLE_PREFIX + base64.b64encode(json.dumps(emitted, sort_keys=True, separators=(",", ":")).encode())
        buffers[prefix + "stdout.log"] = b"\n".join(transport if line.startswith(review.BUNDLE_PREFIX) else line for line in buffers[prefix + "stdout.log"].split(b"\n"))
        return self.repack(manifest, buffers)

    def repack(self, manifest, buffers):
        manifest["artifacts"] = [contract.inventory_entry(path, data) for path, data in sorted(buffers.items())]
        manifest["inputs"] = [item for item in manifest["artifacts"] if "/input/" in item["path"]]
        for attempt in manifest["attempts"]:
            attempt["artifacts"] = [item for item in manifest["artifacts"] if item["path"].startswith("attempts/" + attempt["id"] + "/")]
        def descriptor(path, data):
            return dict(contract.inventory_entry(path, data), base64=base64.b64encode(data).decode())
        return {"schema": review.SCHEMA, "manifest": descriptor("manifest.json", contract.json_bytes(manifest)),
                "artifacts": [descriptor(path, data) for path, data in sorted(buffers.items())]}

    def accounting(self, package):
        result = self.report(package)
        self.assertEqual(result["integrity"], "VALID", result["reason_codes"])
        return result["accounting"]["attempts"][0]

    def assert_capture_rejected(self, change):
        assessed = self.accounting(self.mutate_capture(change))
        self.assertNotEqual(assessed["capture"]["status"], "SUPPORTED")
        self.assertIsNone(assessed["exact_model"])
        self.assertNotEqual(assessed["oracle"]["status"], "SUPPLIED_MATCHED")

    def test_actual_closed_controls_and_external_oracle(self):
        for case, expected in (("flat-02", "-960"), ("gain", "46992"), ("loss", "-48912"), ("smooth", "-1063.93749652147178202")):
            with self.subTest(case=case):
                a = self.accounting(self.packages[case])
                self.assertEqual(a["capture"]["status"], "SUPPORTED")
                self.assertEqual(a["exact_model"]["computed"]["net_pnl"], expected)
                self.assertEqual(a["native_compatibility"]["status"], "MATCHES_ENGINE_NUMERIC_POLICY")
                self.assertEqual(a["oracle"]["status"], "SUPPLIED_MATCHED")
                self.assertEqual(a["status"], "NOT_ASSESSABLE")
                self.assertEqual(sum(x["status"] == "NOT_SUPPLIED" for x in a["native_metrics"].values()), 6)

    def test_actual_unsupported_and_failed_controls(self):
        for case in ("forced", "insufficient", "failure"):
            a = self.accounting(self.packages[case])
            self.assertEqual(a["status"], "NOT_ASSESSABLE")
            self.assertNotEqual(a["capture"]["status"], "SUPPORTED")
            self.assertIsNone(a["exact_model"])

    def test_missing_field(self):
        self.assert_capture_rejected(lambda c: c["completions"][0]["order"].pop("filled"))

    def test_drop_fill(self):
        self.assert_capture_rejected(lambda c: c["completions"].pop())

    def test_duplicate_fill(self):
        self.assert_capture_rejected(lambda c: c["completions"].append(copy.deepcopy(c["completions"][0])))

    def test_reorder_fills(self):
        self.assert_capture_rejected(lambda c: c["completions"].reverse())

    def test_boolean_count(self):
        self.assert_capture_rejected(lambda c: c["capture"].update(completion_count=True))

    def test_truncation_is_not_a_valid_prefix(self):
        self.assert_capture_rejected(lambda c: c["capture"].update(truncated=True))

    def test_partial_fill(self):
        self.assert_capture_rejected(lambda c: c["completions"][0]["order"].update(remaining=1))

    def test_base_fee(self):
        self.assert_capture_rejected(lambda c: c["completions"][0]["order"].update(fee_base=dto(0.001)))

    def test_fee_rate_not_fixed(self):
        self.assert_capture_rejected(lambda c: c["completions"][0]["trade_fee_rates"].update(open=dto(0.002)))

    def test_float_hex_disagrees_with_repr(self):
        self.assert_capture_rejected(lambda c: c["completions"][0]["order"]["safe_price"].update(hex=(100.0).hex()))

    def test_same_bits_longer_decimal_cannot_change_model(self):
        self.assert_capture_rejected(lambda c: c["completions"][0]["order"]["safe_price"].update(repr=c["completions"][0]["order"]["safe_price"]["repr"] + "0"))

    def test_numpy_wrapper_not_evaluated(self):
        self.assert_capture_rejected(lambda c: c["completions"][0]["order"]["safe_price"].update(repr="np.float64(100.0)"))

    def test_unknown_runtime(self):
        self.assert_capture_rejected(lambda c: c["runtime"].update(python_version="3.14.8"))

    def test_trade_table_contradicts_closed_trade(self):
        def change(c):
            index = c["final"]["trade_rows"]["columns"].index("profit_abs")
            c["final"]["trade_rows"]["rows"][0][index] = dto(-999.0)
        self.assert_capture_rejected(change)

    def test_wallet_query_without_balance(self):
        self.assert_capture_rejected(lambda c: c["final"]["wallets"].update(balances=[]))

    def test_reserved_cash_in_closed_wallet(self):
        self.assert_capture_rejected(lambda c: c["final"]["wallets"]["balances"][0].update(used=dto(123.0)))

    def test_resolved_opening_capital_contradiction(self):
        self.assert_capture_rejected(lambda c: c["resolved"]["config"].update(dry_run_wallet=42))

    def test_failed_attempt_with_parseable_capture_has_no_assessed_metrics(self):
        _, manifest, buffers = review._decode(contract.json_bytes(self.packages["gain"]))
        manifest["attempts"][0]["outcome"] = "FAILED"
        assessed = review._accounting(manifest, buffers)["attempts"][0]
        self.assertIsNone(assessed["exact_model"])
        self.assertTrue(all(value["status"] == "NOT_SUPPLIED" for value in assessed["native_metrics"].values()))
        self.assertNotEqual(assessed["oracle"]["status"], "SUPPLIED_MATCHED")

    def test_one_ulp_cash_change(self):
        def change(c):
            original = float(c["final"]["wallets"]["cash"]["repr"])
            changed = dto(math.nextafter(original, math.inf))
            c["final"]["native_final_balance"] = changed
            for stage in ("final", "pre_force_exit"):
                c[stage]["wallets"]["cash"] = changed
                for row in c[stage]["wallets"]["balances"]:
                    if row["currency"] == "USDT":
                        row["free"] = row["total"] = changed
        a = self.accounting(self.mutate_capture(change))
        self.assertEqual(a["capture"]["status"], "SUPPORTED")
        self.assertEqual(a["native_compatibility"]["status"], "MISMATCH")
        self.assertEqual(a["status"], "NOT_ASSESSABLE")

    def test_order_cost_is_not_cash_credit(self):
        def change(c):
            for fill in c["completions"]:
                fill["order"]["cost"] = dto(1.0)
            for trade in c["final"]["closed_trades"]:
                for order in trade["orders"]:
                    order["cost"] = dto(1.0)
            column = c["final"]["trade_rows"]["columns"].index("orders")
            for row in c["final"]["trade_rows"]["rows"]:
                for order in row[column]:
                    order["cost"] = dto(1.0)
        a = self.accounting(self.mutate_capture(change))
        self.assertEqual(a["capture"]["status"], "SUPPORTED")
        self.assertEqual(a["exact_model"]["computed"]["cash"], "999998936.06250347852821798")

    def test_manifest_pin(self):
        result = review.verify_run_review(contract.json_bytes(self.packages["smooth"]), "0" * 64)
        self.assertEqual(result["integrity"], "INVALID")
        self.assertEqual(result["reason_codes"], ["MANIFEST_PIN_MISMATCH"])

    def test_tampered_bytes(self):
        package = copy.deepcopy(self.packages["smooth"])
        package["artifacts"][0]["base64"] = base64.b64encode(b"altered").decode()
        self.assertEqual(self.report(package)["integrity"], "INVALID")

    def test_oracle_missing_and_tampered_evidence(self):
        _, manifest, buffers = review._decode(contract.json_bytes(self.packages["smooth"]))
        for filename in ("oracle.stdout.json", "ledger.beancount", "events.json", "oracle-worker.py"):
            with self.subTest(filename=filename):
                changed = dict(buffers)
                changed["attempts/000/accounting/" + filename] = b"altered"
                self.assertEqual(self.accounting(self.repack(copy.deepcopy(manifest), changed))["oracle"]["status"], "INVALID")
        del buffers["attempts/000/accounting/oracle.stdout.json"]
        self.assertEqual(self.accounting(self.repack(manifest, buffers))["oracle"]["status"], "MISSING")


if __name__ == "__main__":
    unittest.main()
