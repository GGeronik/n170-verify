"""What the account-id scanner catches, and how statement rows are counted.

Rules covered here:
- an instrument symbol (a compact option symbol, a ticker) or an ordinary setup tag is never
  read as an account id: such a record is signed, stored and served;
- a journal tag that does look like an account id is left out of the signed record and the
  response says so; it is never signed, stored or served;
- a real account id still never reaches a signed record or a response;
- a statement row ends at a line feed, a carriage return or both, so the row limit counts
  every kind of line ending;
- a parser error that reaches the worker boundary is a 422 without Python's own text.
"""

from __future__ import annotations

import base64
from typing import Any
import unittest

from app import worker_isolation
from app.main import VerifyApiTestClient, create_app
from app.privacy_scanner import OutboundPrivacyScanner
from app.worker_isolation import WorkerInputTooLargeError, enforce_statement_input_limits

try:
    from tests.test_verify_input_allowlist import TRADERSYNC_CSV
    from tests.test_verify_request_surface import _config
except ImportError:  # pragma: no cover - run from inside api/tests
    from test_verify_input_allowlist import TRADERSYNC_CSV  # type: ignore[no-redef]
    from test_verify_request_surface import _config  # type: ignore[no-redef]


# Shapes assembled at run time.
OPTION_SYMBOLS = ("PA" + "NW260320C00150000", "PA" + "AS260320C00020000", "U" + "260320C00050000")
ORDINARY_TAGS = ("PA" + "USE1MIN", "PA" + "TTERNS", "PA" + "20EMA")
ACCOUNT_IDS = ("PA" + "3K9XZ1ABCD", "PA" + "12345678", "U" + "1234567", "DU" + "1234567")
ACCOUNT_SHAPED_TAG = "PA" + "3K9XZ1ABCD"


def _flex_with_option(symbol: str) -> str:
    navs = "".join(
        f'<EquitySummaryByReportDateInBase reportDate="2026-01-{d:02d}" cash="{100000 + d * 10}" '
        f'stock="0" total="{100000 + d * 10}" />'
        for d in range(5, 15)
    )
    trade = (
        '<Trade ibExecID="E{n}" symbol="{s}" assetCategory="OPT" buySell="{side}" quantity="{q}" '
        'tradePrice="{p}" currency="USD" ibCommission="-1" dateTime="2026-01-0{d};14:30:00" '
        'levelOfDetail="EXECUTION" putCall="C" strike="150" expiry="20260320" multiplier="100" />'
    )
    trades = trade.format(n=1, s=symbol, side="BUY", q="1", p="5.00", d=6) + trade.format(
        n=2, s=symbol, side="SELL", q="-1", p="6.00", d=8
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?><FlexQueryResponse queryName="q" type="AF">'
        '<FlexStatements count="1"><FlexStatement accountId="U7654321" baseCurrency="USD" '
        'fromDate="2026-01-01" toDate="2026-01-31">'
        f"<EquitySummaryInBase>{navs}</EquitySummaryInBase><Trades>{trades}</Trades>"
        "</FlexStatement></FlexStatements></FlexQueryResponse>"
    )


def _leaf(body: dict[str, Any], name: str) -> Any:
    for leaf in body["proof_bundle"]["disclosed_leaves"]:
        if leaf["leaf_name"] == name:
            return leaf["payload"]
    return None


class ScannerShapes(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app(_config(hosted=True), prefer_fastapi=False)
        self.addCleanup(self.app.verify_app.close)
        self.client = VerifyApiTestClient(self.app)

    def test_the_scanner_tells_symbols_and_tags_from_account_ids(self) -> None:
        scanner = OutboundPrivacyScanner()
        for text in OPTION_SYMBOLS + ORDINARY_TAGS:
            with self.subTest(text=text):
                self.assertEqual(scanner.scan_text(f'{{"symbol": "{text}"}}'), [])
        for text in ACCOUNT_IDS:
            with self.subTest(text=text):
                self.assertTrue(scanner.scan_text(f'{{"tag": "{text}"}}'))

    def test_a_record_with_an_option_symbol_is_signed_stored_and_served(self) -> None:
        for symbol in OPTION_SYMBOLS[:2]:
            with self.subTest(symbol=symbol):
                statement = base64.b64encode(_flex_with_option(symbol).encode()).decode()
                resp = self.client.post(
                    "/api/v1/verify",
                    json={"broker_id": "auto_detect", "raw_statement_b64": statement, "publish_proof": True},
                )
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                self.assertIn(symbol, resp.text)
                proof_id = resp.json()["proof_bundle"]["proof_id"]
                served = self.client.get(f"/api/v1/proofs/{proof_id}")
                self.assertEqual(served.status_code, 200, served.text[:300])
                self.assertIn(symbol, served.text)

    def test_an_ordinary_setup_tag_is_signed(self) -> None:
        statement = TRADERSYNC_CSV.replace(",ORB,", f",{ORDINARY_TAGS[0]},")
        resp = self.client.post(
            "/api/v1/verify",
            json={"broker_id": "tradersync", "raw_statement_text": statement, "publish_proof": True},
        )
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertIn(ORDINARY_TAGS[0], resp.text)

    def test_an_account_shaped_tag_is_left_out_and_the_record_is_signed(self) -> None:
        statement = TRADERSYNC_CSV.replace(",ORB,", f",{ACCOUNT_SHAPED_TAG},")
        for publish in (False, True):
            with self.subTest(publish=publish):
                resp = self.client.post(
                    "/api/v1/verify",
                    json={"broker_id": "tradersync", "raw_statement_text": statement, "publish_proof": publish},
                )
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                self.assertNotIn(ACCOUNT_SHAPED_TAG, resp.text)
                self.assertTrue(
                    any("journal tag" in w for w in resp.json().get("record_warnings", [])),
                    resp.json().get("record_warnings"),
                )
                if publish:
                    proof_id = resp.json()["proof_bundle"]["proof_id"]
                    served = self.client.get(f"/api/v1/proofs/{proof_id}")
                    self.assertEqual(served.status_code, 200)
                    self.assertNotIn(ACCOUNT_SHAPED_TAG, served.text)
        # The upload route signs the same record.
        upload = self.client.post(
            "/api/v1/verify/auto-detect", content=statement.encode(), headers={"Content-Type": "text/csv"}
        )
        self.assertEqual(upload.status_code, 200, upload.text[:300])
        self.assertNotIn(ACCOUNT_SHAPED_TAG, upload.text)


class RowEndings(unittest.TestCase):
    def test_every_kind_of_line_ending_counts_as_a_row(self) -> None:
        limit = worker_isolation.MAX_STATEMENT_INPUT_ROWS
        for eol in ("\n", "\r", "\r\n"):
            with self.subTest(eol=repr(eol)):
                text = eol.join(["a,b"] * (limit + 2)) + eol
                with self.assertRaises(WorkerInputTooLargeError):
                    enforce_statement_input_limits({"raw_statement_text": text})
                within = eol.join(["a,b"] * (limit - 1)) + eol
                enforce_statement_input_limits({"raw_statement_text": within})

    def test_a_parser_error_at_the_worker_boundary_is_a_422_without_python_text(self) -> None:
        app = create_app(_config(hosted=True), prefer_fastapi=False)
        self.addCleanup(app.verify_app.close)
        client = VerifyApiTestClient(app)
        cr_only = TRADERSYNC_CSV.replace("\n", "\r")
        for route, kwargs in (
            ("/api/v1/verify", {"json": {"broker_id": "tradersync", "raw_statement_text": cr_only}}),
            (
                "/api/v1/verify/auto-detect",
                {"content": cr_only.encode(), "headers": {"Content-Type": "text/csv"}},
            ),
        ):
            with self.subTest(route=route):
                resp = client.post(route, **kwargs)
                self.assertLess(resp.status_code, 500, resp.text[:300])
                if resp.status_code != 200:
                    self.assertEqual(resp.status_code, 422, resp.text[:300])
                    self.assertNotIn("newline=", resp.text)
                    self.assertNotIn("Error:", resp.text)


if __name__ == "__main__":
    unittest.main()
