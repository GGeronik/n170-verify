"""Independent arithmetic and evidence challenges for the original ledger.

Expected numbers use literal hand cases and Fraction, not the ledger or its
Beancount exporter. This does not authenticate supplied events or fills.
"""
from copy import deepcopy
from fractions import Fraction
import hashlib
import json
import unittest

from verify_accounting.core import assess_bytes, assess_document


def decimal_text(value):
    value = Fraction(value)
    scale = 0
    while 10 ** scale % value.denominator:
        scale += 1
        if scale > 32:
            raise AssertionError("Nonterminating fixture amount")
    integer = value.numerator * (10 ** scale // value.denominator)
    if not scale:
        return str(integer)
    sign = "-" if integer < 0 else ""
    digits = str(abs(integer)).zfill(scale + 1)
    return (sign + digits[:-scale] + "." + digits[-scale:]).rstrip("0").rstrip(".")


def trade(kind, event_id, quantity, price, fee="0", minute=0):
    return {"event_id": event_id, "timestamp": f"2026-01-02T12:{minute:02d}:00Z",
            "type": kind, "quantity": quantity, "price": price,
            "fee": fee, "fee_currency": "USDT"}


def cash_event(kind, amount, minute=0):
    return {"event_id": kind.lower(), "timestamp": f"2026-01-02T12:{minute:02d}:00Z",
            "type": kind, "amount": amount}


def document(opening, events, mark, expected):
    return {"schema": "n170.accounting.events.v1", "evidence_class": "synthetic_fixture",
            "asset": "BTC", "cash_currency": "USDT",
            "opening": {"timestamp": "2026-01-01T00:00:00Z", "cash": opening},
            "events": events,
            "closing": {"timestamp": "2026-01-03T00:00:00Z", "mark_price": mark,
                        "reported": dict(expected)}}


GAIN = {"cash": "717", "quantity": "3", "cost_basis": "300", "fees": "3",
        "realized_pnl": "20", "unrealized_pnl": "30", "external_flows": "0",
        "net_pnl": "47", "nav": "1047"}


def gain():
    return document("1000", [trade("BUY", "buy", "4", "100", "2"),
                             trade("SELL", "sell", "1", "120", "1", 1)], "110", GAIN)


class IndependentAccountingChallenges(unittest.TestCase):
    def assert_reconciled(self, value):
        result = assess_document(value)
        self.assertEqual(result["status"], "RECONCILED_UNDER_ASSUMPTIONS", result)
        self.assertEqual(result["computed"], value["closing"]["reported"])
        self.assertEqual(result["source_authenticity"], "not_established")
        self.assertEqual(result["selected_source_completeness"], "unknown")
        self.assertEqual(result["oracle"]["status"], "NOT_RUN")
        return result

    def test_hand_calculated_gain_and_loss(self):
        self.assert_reconciled(gain())
        loss = gain()
        loss["events"][1]["price"] = "80"
        loss["closing"]["mark_price"] = "90"
        loss["closing"]["reported"].update(cash="677", realized_pnl="-20",
            unrealized_pnl="-30", net_pnl="-53", nav="947")
        self.assert_reconciled(loss)

    def test_fractional_fills_preserve_all_sixteen_product_decimals(self):
        q, sold = Fraction("0.12345678"), Fraction("0.01234567")
        entry, exit_price, mark = map(Fraction, ("0.87654321", "1.23456789", "0.98765432"))
        first_fee, second_fee = Fraction("0.00000001"), Fraction("0.00000002")
        remaining = q - sold
        cash = 1000 - q * entry - first_fee + sold * exit_price - second_fee
        nav = cash + remaining * mark
        expected = {k: decimal_text(v) for k, v in {
            "cash": cash, "quantity": remaining, "cost_basis": remaining * entry,
            "fees": first_fee + second_fee, "realized_pnl": sold * (exit_price - entry),
            "unrealized_pnl": remaining * (mark - entry), "external_flows": 0,
            "net_pnl": nav - 1000, "nav": nav}.items()}
        value = document("1000", [trade("BUY", "buy", "0.12345678", "0.87654321", "0.00000001"),
            trade("SELL", "sell", "0.01234567", "1.23456789", "0.00000002", 1)],
            "0.98765432", expected)
        self.assert_reconciled(value)

    def test_fifo_crosses_lot_boundary(self):
        expected = {"cash": "955", "quantity": "3", "cost_basis": "60", "fees": "0",
                    "realized_pnl": "15", "unrealized_pnl": "0", "external_flows": "0",
                    "net_pnl": "15", "nav": "1015"}
        self.assert_reconciled(document("1000", [trade("BUY", "a", "5", "10"),
            trade("BUY", "b", "5", "20", minute=1),
            trade("SELL", "c", "7", "15", minute=2)], "20", expected))

    def test_deposit_and_withdrawal_are_not_profit(self):
        for kind, signed in (("DEPOSIT", 100), ("WITHDRAWAL", -100)):
            with self.subTest(kind=kind):
                value = gain()
                value["events"].append(cash_event(kind, "100", 2))
                value["closing"]["reported"].update(cash=str(717 + signed),
                    external_flows=str(signed), nav=str(1047 + signed))
                self.assert_reconciled(value)

    def test_total_depletion_is_a_real_accounting_loss(self):
        expected = {"cash": "0", "quantity": "1", "cost_basis": "100", "fees": "0",
                    "realized_pnl": "0", "unrealized_pnl": "-100", "external_flows": "0",
                    "net_pnl": "-100", "nav": "0"}
        self.assert_reconciled(document("100", [trade("BUY", "buy", "1", "100")], "0", expected))

    def test_funding_an_empty_account_does_not_become_profit(self):
        expected = {"cash": "0", "quantity": "1", "cost_basis": "100", "fees": "0",
                    "realized_pnl": "0", "unrealized_pnl": "10", "external_flows": "100",
                    "net_pnl": "10", "nav": "110"}
        self.assert_reconciled(document("0", [cash_event("DEPOSIT", "100"),
            trade("BUY", "buy", "1", "100", minute=1)], "110", expected))

    def test_a_one_unit_reported_cash_residual_is_not_clean(self):
        value = gain()
        value["closing"]["reported"]["cash"] = "718"
        result = assess_document(value)
        self.assertEqual(result["status"], "DISCREPANCIES_FOUND")
        self.assertEqual(result["checks"]["cash"]["difference_reported_minus_computed"], "1")

    def test_missing_mark_or_metric_is_not_reconciled(self):
        missing_mark = gain()
        del missing_mark["closing"]["mark_price"]
        self.assertEqual(assess_document(missing_mark)["status"], "NOT_ASSESSABLE")
        missing_metric = gain()
        del missing_metric["closing"]["reported"]["nav"]
        self.assertEqual(assess_document(missing_metric)["status"], "NOT_ASSESSABLE")

    def test_duplicate_or_omitted_fill_cannot_reconcile_original_balances(self):
        repeated = gain()
        repeated["events"].insert(1, deepcopy(repeated["events"][0]))
        self.assertEqual(assess_document(repeated)["status"], "NOT_ASSESSABLE")
        omitted = gain()
        omitted["events"].pop()
        self.assertEqual(assess_document(omitted)["status"], "DISCREPANCIES_FOUND")

    def test_false_authentication_and_unsupported_fee_currency_are_rejected(self):
        for mutate in (lambda d: d.update(source_authenticated=True),
                       lambda d: d["events"][0].update(fee_currency="BTC")):
            value = gain()
            mutate(value)
            self.assertEqual(assess_document(value)["status"], "NOT_ASSESSABLE")

    def test_source_inventory_binds_original_bytes_not_pretty_printing(self):
        compact = json.dumps(gain(), separators=(",", ":")).encode()
        pretty = json.dumps(gain(), indent=2).encode()
        first, second = assess_bytes(compact), assess_bytes(pretty)
        self.assertEqual(first["computed"], second["computed"])
        self.assertEqual(first["source_inventory"][0]["sha256"], hashlib.sha256(compact).hexdigest())
        self.assertNotEqual(first["source_inventory"], second["source_inventory"])

    def test_duplicate_json_fields_are_not_last_value_wins(self):
        raw = json.dumps(gain()).encode()
        duplicate = raw[:-1] + b',"evidence_class":"synthetic_fixture"}'
        result = assess_bytes(duplicate)
        self.assertEqual(result["status"], "NOT_ASSESSABLE")
        self.assertEqual(result["reason_codes"], ["DUPLICATE_JSON_FIELD"])


if __name__ == "__main__":
    unittest.main()
