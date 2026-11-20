"""Fail-first API tests for hosted IBKR Flex Web v3, SnapTrade session-status, and /proofs/.../badge.svg."""

from __future__ import annotations

from datetime import date, timedelta
import json
import os
from pathlib import Path
import tempfile
from typing import Any
import unittest
import urllib.parse

from app.config import ApiConfig
from app.main import VerifyApiApplication, VerifyApiTestClient
from n170_verify.connectors import HttpExchangeResponse
from n170_verify.connectors.ibkr_flex import (
    IBKR_FLEX_GET_STATEMENT_URL,
    IBKR_FLEX_SEND_REQUEST_URL,
)
from n170_verify.crypto import generate_ed25519_keypair


_SIGNING_KEY = generate_ed25519_keypair(bytes.fromhex("11" * 32))
_SALT = "22" * 32
_KEK = "33" * 32

def _sync_flag_path(pid: int) -> Path:
    return Path(tempfile.gettempdir()) / f"n170_test_st_sync_{pid}.flag"


def _overflow_flag_path(pid: int) -> Path:
    return Path(tempfile.gettempdir()) / f"n170_test_st_overflow_{pid}.flag"


def _set_tx_done(done: bool) -> None:
    p = _sync_flag_path(os.getpid())
    if done:
        p.write_text("1", encoding="utf-8")
    else:
        p.unlink(missing_ok=True)


def _set_overflow_activities(overflow: bool) -> None:
    p = _overflow_flag_path(os.getpid())
    if overflow:
        p.write_text("1", encoding="utf-8")
    else:
        p.unlink(missing_ok=True)


def _is_tx_done() -> bool:
    return _sync_flag_path(os.getpid()).exists() or _sync_flag_path(os.getppid()).exists()


def _is_overflow_activities() -> bool:
    return _overflow_flag_path(os.getpid()).exists() or _overflow_flag_path(os.getppid()).exists()


def fake_ibkr_flex_transport(
    method: str, url: str, headers: dict[str, str], body: bytes | None
) -> HttpExchangeResponse:
    parsed = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qs(parsed.query)
    tok = qs.get("t", [""])[0]
    if tok == "TIMEOUT-FLEX-TOKEN":
        from n170_verify.connectors.ccxt_crypto import ConnectorHttpError

        raise ConnectorHttpError(0, f"Socket timeout calling {url}")
    if tok == "BAD-FLEX-TOKEN":
        err = (
            "<FlexStatementResponse><Status>Fail</Status>"
            "<ErrorCode>1012</ErrorCode>"
            "<ErrorMessage>Token BAD-FLEX-TOKEN has expired.</ErrorMessage>"
            "</FlexStatementResponse>"
        ).encode("utf-8")
        return HttpExchangeResponse(status_code=200, headers={}, body=err)

    if url.startswith(IBKR_FLEX_SEND_REQUEST_URL):
        fd = qs.get("fd", ["20250102"])[0]
        td = qs.get("td", ["20250331"])[0]
        ref = f"REF-{fd}-{td}"
        env = (
            f"<FlexStatementResponse><Status>Success</Status>"
            f"<ReferenceCode>{ref}</ReferenceCode></FlexStatementResponse>"
        ).encode("utf-8")
        return HttpExchangeResponse(status_code=200, headers={}, body=env)

    if url.startswith(IBKR_FLEX_GET_STATEMENT_URL):
        ref = qs["q"][0]
        _, fd_s, td_s = ref.split("-")
        d0 = date(int(fd_s[:4]), int(fd_s[4:6]), int(fd_s[6:8]))
        d1 = date(int(td_s[:4]), int(td_s[4:6]), int(td_s[6:8]))
        cur = d0
        nav = 20000.0 if d0.year == 2024 else (22500.0 if d0.year == 2025 else 26000.0)
        rows: list[str] = []
        while cur <= d1:
            if cur.weekday() < 5:
                nav = round(nav * 1.0007, 2)
                rows.append(
                    f'<EquitySummaryByReportDateInBase accountId="U8899001" '
                    f'reportDate="{cur.isoformat()}" cash="{nav:.2f}" stock="0.00" total="{nav:.2f}" />'
                )
            cur += timedelta(days=1)
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<FlexQueryResponse queryName="HostedAF" type="AF"><FlexStatements count="1">'
            f'<FlexStatement accountId="U8899001" baseCurrency="EUR" '
            f'fromDate="{d0.isoformat()}" toDate="{d1.isoformat()}">'
            f'<EquitySummaryInBase>{"".join(rows)}</EquitySummaryInBase>'
            '<ConversionRates><ConversionRate reportDate="2025-01-02" fromCurrency="USD" toCurrency="EUR" rate="0.92" /></ConversionRates>'
            '</FlexStatement></FlexStatements></FlexQueryResponse>'
        ).encode("utf-8")
        return HttpExchangeResponse(status_code=200, headers={}, body=xml)

    raise AssertionError(f"Unexpected IBKR URL: {url}")


def fake_snaptrade_transport(
    method: str, url: str, headers: dict[str, str], body: bytes | None
) -> HttpExchangeResponse:
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path
    if path == "/api/v1/snapTrade/listUsers":
        return HttpExchangeResponse(status_code=200, headers={}, body=b"[]")
    if path == "/api/v1/snapTrade/registerUser":
        req = json.loads((body or b"{}").decode("utf-8"))
        out = json.dumps({"userId": req["userId"], "userSecret": "st-secret-xyz-9876"}).encode("utf-8")
        return HttpExchangeResponse(status_code=200, headers={}, body=out)
    if path == "/api/v1/snapTrade/login":
        return HttpExchangeResponse(
            status_code=200,
            headers={},
            body=b'{"redirectURI":"https://app.snaptrade.com/ blade/connect-1"}'.replace(b" ", b""),
        )
    if path == "/api/v1/snapTrade/deleteUser":
        return HttpExchangeResponse(status_code=200, headers={}, body=b'{"status":"deleted"}')
    if path == "/api/v1/authorizations":
        return HttpExchangeResponse(
            status_code=200,
            headers={},
            body=b'[{"id":"auth-ibkr-1","brokerage":{"slug":"INTERACTIVE-BROKERS-FLEX"},"disabled":false}]',
        )
    if path == "/api/v1/accounts":
        tx_done = "true" if _is_tx_done() else "false"
        payload = (
            '[{"id":"acct-private-777","number":"U8899001",'
            '"balance":{"total":{"amount":31000.0,"currency":"EUR"},"updated_at":"2026-11-18T21:00:00Z"},'
            '"sync_status":{"holdings":{"initial_sync_completed":true},'
            f'"transactions":{{"initial_sync_completed":{tx_done},"first_transaction_date":"2024-09-02"}}'
            "}}]"
        ).encode("utf-8")
        return HttpExchangeResponse(status_code=200, headers={}, body=payload)
    if path == "/api/v1/holdings":
        return HttpExchangeResponse(
            status_code=200,
            headers={},
            body=(
                b'[{"account":{"id":"acct-private-777","number":"U8899001","currency":"EUR"},'
                b'"total_value":{"value":31000.0,"currency":"EUR"},'
                b'"balances":[{"cash":31000.0,"currency":{"code":"EUR"}}],"positions":[]}]'
            ),
        )
    if path.endswith("/activities") or path == "/api/v1/activities":
        if _is_overflow_activities():
            qs = urllib.parse.parse_qs(parsed.query)
            off = int(qs.get("offset", ["0"])[0])
            items = [
                {
                    "id": f"act-{off + i}",
                    "account": {"id": "acct-private-777"},
                    "type": "DIVIDEND",
                    "amount": 1.0,
                    "currency": {"code": "EUR"},
                    "trade_date": "2026-11-18T12:00:00Z",
                }
                for i in range(1000)
            ]
            return HttpExchangeResponse(status_code=200, headers={}, body=json.dumps(items).encode())
        return HttpExchangeResponse(status_code=200, headers={}, body=b"[]")
    if path == "/api/v1/currencies/rates" or path.startswith("/api/v1/currencies/rates/"):
        return HttpExchangeResponse(
            status_code=200,
            headers={},
            body=b'[{"src":{"code":"EUR"},"dst":{"code":"USD"},"exchange_rate":1.08}]',
        )
    if path.endswith("/returnRates"):
        return HttpExchangeResponse(status_code=200, headers={}, body=b'{"data":[]}')
    raise AssertionError(f"Unexpected SnapTrade request: {method} {path}")


class HostedIbkrFlexWebAndSnapTradeSyncTests(unittest.TestCase):
    def setUp(self) -> None:
        _set_tx_done(False)
        _set_overflow_activities(False)
        self.cfg = ApiConfig(
            publisher_keypair=_SIGNING_KEY,
            hosted_multi_user_mode=True,
            allow_hosted_signing=False,
            allow_caller_clock_for_tests=True,
            vault_master_kek_hex=_KEK,
            account_blinding_salt_hex=_SALT,
            snaptrade_client_id="N170-BUILD-ID",
            snaptrade_consumer_key="build-consumer-secret-key",
            site_origin="https://verify.example.org",
        )
        self.app = VerifyApiApplication(
            self.cfg,
            snaptrade_http_transport=f"{__name__}:fake_snaptrade_transport",
            ibkr_flex_http_transport=f"{__name__}:fake_ibkr_flex_transport",
        )
        self.client = VerifyApiTestClient(self.app)

    def tearDown(self) -> None:
        _set_tx_done(False)
        _set_overflow_activities(False)
        self.app.close()

    def test_hosted_ibkr_flex_web_verifies_multiyear_and_serves_proof_badge_svg(self) -> None:
        resp = self.client.post(
            "/api/v1/verify",
            json={
                "broker_id": "ibkr_flex_web",
                "connector_fetch_kwargs": {
                    "flex_token": "VALID-FLEX-TOKEN-1234",
                    "query_id": "998877",
                    "start_date": "2024-09-02",
                    "end_date": "2026-11-18",
                },
                "issued_at_utc": "2026-11-19T12:00:00Z",
                "publish_proof": True,
                "opt_in_leaderboard": False,
            },
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertFalse(body["performance_withheld"])
        self.assertEqual(
            body["verification"]["effective_origin_assurance"],
            "operator_retrieved",
        )
        proof_id = body["proof_bundle"]["proof_id"]

        # Both /api/v1/badges/{id}.svg and /api/v1/proofs/{id}/badge.svg resolve 200 SVG
        b1 = self.client.get(f"/api/v1/badges/{proof_id}.svg")
        b2 = self.client.get(f"/api/v1/proofs/{proof_id}/badge.svg")
        self.assertEqual(b1.status_code, 200)
        self.assertEqual(b2.status_code, 200)
        self.assertIn("image/svg+xml", b2.headers.get("Content-Type", ""))
        self.assertEqual(b1.text, b2.text)
        self.assertNotIn("withheld", b2.text.lower())

        # Upstream Flex token error returns 502 and never leaks the token
        bad = self.client.post(
            "/api/v1/verify",
            json={
                "broker_id": "ibkr_flex_web",
                "connector_fetch_kwargs": {
                    "flex_token": "BAD-FLEX-TOKEN",
                    "query_id": "998877",
                },
                "issued_at_utc": "2026-11-19T12:00:00Z",
            },
        )
        self.assertEqual(bad.status_code, 502, bad.text)
        self.assertNotIn("BAD-FLEX-TOKEN", bad.text)
        self.assertNotIn("998877", bad.text)

    def test_snaptrade_session_status_polls_readiness_and_early_verify_keeps_session(self) -> None:
        portal = self.client.post(
            "/api/v1/connect/snaptrade/portal",
            json={"redirect_url": "https://verify.example.org/connect?snaptrade=connected"},
        )
        self.assertEqual(portal.status_code, 200, portal.text)
        token = portal.json()["session_token"]

        # Poll while transactions initial sync is still running
        st1 = self.client.post(
            "/api/v1/connect/snaptrade/session-status",
            json={"session_token": token},
        )
        self.assertEqual(st1.status_code, 200, st1.text)
        d1 = st1.json()
        self.assertTrue(d1["session_active"])
        self.assertEqual(d1["accounts_count"], 1)
        self.assertTrue(d1["holdings_synced"])
        self.assertFalse(d1["transactions_synced"])
        self.assertFalse(d1["ready_to_verify"])
        self.assertEqual(d1["first_transaction_date"], "2024-09-02")
        self.assertNotIn("acct-private-777", st1.text)
        self.assertNotIn("st-secret-xyz-9876", st1.text)

        # Early verify attempt while initial sync is running must be retryable (session kept!)
        early = self.client.post(
            "/api/v1/connect/snaptrade/verify",
            json={"session_token": token},
        )
        self.assertEqual(early.status_code, 422, early.text)
        self.assertNotEqual(early.json().get("session_ended"), True)

        # Once sync finishes, session-status reports ready_to_verify=True and verify succeeds!
        _set_tx_done(True)
        st2 = self.client.post(
            "/api/v1/connect/snaptrade/session-status",
            json={"session_token": token},
        )
        self.assertEqual(st2.status_code, 200, st2.text)
        self.assertTrue(st2.json()["ready_to_verify"])

        ok_ver = self.client.post(
            "/api/v1/connect/snaptrade/verify",
            json={"session_token": token},
        )
        self.assertEqual(ok_ver.status_code, 200, ok_ver.text)

        # Pagination overflow (10 full pages) must return 422 validation_error and free the public slot!
        portal2 = self.client.post(
            "/api/v1/connect/snaptrade/portal",
            json={"redirect_url": "https://verify.example.org/connect?snaptrade=connected"},
        )
        self.assertEqual(portal2.status_code, 200, portal2.text)
        token2 = portal2.json()["session_token"]
        _set_overflow_activities(True)
        ov_resp = self.client.post(
            "/api/v1/connect/snaptrade/verify",
            json={"session_token": token2},
        )
        self.assertEqual(ov_resp.status_code, 422, ov_resp.text)
        ov_data = ov_resp.json()
        self.assertEqual(ov_data["error"], "validation_error")
        self.assertIn("pagination", ov_data["detail"].lower())
        self.assertEqual(ov_data.get("session_ended"), True)
        status_after = self.client.get("/api/v1/connect/snaptrade/status").json()
        self.assertEqual(status_after["active_slots"], 0)

    def test_multiyear_ibkr_flex_xml_above_legacy_2mb_5000_tag_cap_verifies_while_50k_cap_holds(
        self,
    ) -> None:
        from app import worker_isolation

        self.assertGreaterEqual(worker_isolation.MAX_STATEMENT_INPUT_BYTES, 16 * 1024 * 1024)
        self.assertGreaterEqual(worker_isolation.MAX_STATEMENT_INPUT_ROWS, 50_000)

        # Build a genuine 3-year Flex XML with >6,000 XML elements and >2.1 MiB payload
        d0 = date(2024, 1, 2)
        d1 = date(2026, 11, 18)
        cur = d0
        nav = 25_000.0
        eq_rows: list[str] = []
        conv_rows: list[str] = []
        pad_desc = "Dividend reinvestment / custody settlement note " * 8
        while cur <= d1:
            if cur.weekday() < 5:
                nav = round(nav * 1.0003, 2)
                eq_rows.append(
                    f'<EquitySummaryByReportDateInBase accountId="U7711223" '
                    f'reportDate="{cur.isoformat()}" cash="{nav:.2f}" stock="0.00" '
                    f'options="0.00" dividendAccruals="0.00" interestAccruals="0.00" total="{nav:.2f}" />'
                )
                for ccy, rate in (
                    ("USD", "0.9200"),
                    ("GBP", "1.1700"),
                    ("CHF", "1.0600"),
                    ("JPY", "0.0061"),
                    ("CAD", "0.6700"),
                    ("AUD", "0.6000"),
                    ("SEK", "0.0880"),
                ):
                    conv_rows.append(
                        f'<ConversionRate reportDate="{cur.isoformat()}" fromCurrency="{ccy}" '
                        f'toCurrency="EUR" rate="{rate}" note="{pad_desc}" />'
                    )
            cur += timedelta(days=1)

        xml_str = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<FlexQueryResponse queryName="MultiYearLarge" type="AF"><FlexStatements count="1">'
            f'<FlexStatement accountId="U7711223" baseCurrency="EUR" fromDate="{d0.isoformat()}" toDate="{d1.isoformat()}">'
            '<AccountInformation accountId="U7711223" currency="EUR" />'
            f'<EquitySummaryInBase>{"".join(eq_rows)}</EquitySummaryInBase>'
            '<PriorPeriodPositions /><OpenPositions /><Trades /><CashTransactions />'
            '<Transfers /><CorporateActions /><OptionEAE />'
            f'<ConversionRates>{"".join(conv_rows)}</ConversionRates>'
            '</FlexStatement></FlexStatements></FlexQueryResponse>'
        )
        self.assertGreater(len(xml_str.encode("utf-8")), 2 * 1024 * 1024)

        ok_resp = self.client.post(
            "/api/v1/verify",
            json={
                "broker_id": "ibkr_flex",
                "raw_statement": xml_str,
                "issued_at_utc": "2026-11-19T12:00:00Z",
            },
        )
        self.assertEqual(ok_resp.status_code, 200, ok_resp.text)
        self.assertFalse(ok_resp.json()["performance_withheld"])

    def test_round3_transport_error_502_snaptrade_no_store_cors_and_worker_timeout_validation(
        self,
    ) -> None:
        from app.main import DEFAULT_JSON_HEADERS

        self.assertEqual(
            DEFAULT_JSON_HEADERS["Access-Control-Allow-Headers"],
            "Accept, Content-Type, X-N170-Dev-Key",
        )

        # 1. ConnectorHttpError inside ibkr_flex_web worker returns 502 broker_upstream_error (not 422/500)
        to_resp = self.client.post(
            "/api/v1/verify",
            json={
                "broker_id": "ibkr_flex_web",
                "connector_fetch_kwargs": {
                    "flex_token": "TIMEOUT-FLEX-TOKEN",
                    "query_id": "998877",
                },
                "issued_at_utc": "2026-11-19T12:00:00Z",
            },
        )
        self.assertEqual(to_resp.status_code, 502, to_resp.text)
        self.assertNotIn("TIMEOUT-FLEX-TOKEN", to_resp.text)
        self.assertNotIn("998877", to_resp.text)

        # 2. All /api/v1/connect/snaptrade/* responses carry Cache-Control: no-store
        st_get = self.client.get("/api/v1/connect/snaptrade/status")
        self.assertEqual(st_get.headers.get("Cache-Control"), "no-store")
        st_portal = self.client.post(
            "/api/v1/connect/snaptrade/portal",
            json={"redirect_url": "https://verify.example.org/connect?snaptrade=connected"},
        )
        self.assertEqual(st_portal.headers.get("Cache-Control"), "no-store")
        tok = st_portal.json()["session_token"]
        st_sess = self.client.post(
            "/api/v1/connect/snaptrade/session-status",
            json={"session_token": tok},
        )
        self.assertEqual(st_sess.headers.get("Cache-Control"), "no-store")
        st_rel = self.client.post(
            "/api/v1/connect/snaptrade/release",
            json={"session_token": tok},
        )
        self.assertEqual(st_rel.headers.get("Cache-Control"), "no-store")
        st_opt = self.client.options("/api/v1/connect/snaptrade/portal")
        self.assertEqual(st_opt.headers.get("Cache-Control"), "no-store")
        st_404 = self.client.get("/api/v1/connect/snaptrade/nonexistent")
        self.assertEqual(st_404.status_code, 404)
        self.assertEqual(st_404.headers.get("Cache-Control"), "no-store")
        sync_404 = self.client.post("/api/v1/sync/unknown/extra", json={})
        self.assertEqual(sync_404.status_code, 404)
        self.assertEqual(sync_404.headers.get("Cache-Control"), "no-store")
        self.assertIsNone(sync_404.headers.get("Access-Control-Allow-Origin"))

        # 3. ApiConfig rejects NaN / Inf / non-positive / bool worker_timeout_seconds
        for bad_timeout in (float("nan"), float("inf"), -float("inf"), 0.0, -5.0, True):
            with self.assertRaises(ValueError):
                ApiConfig(
                    publisher_keypair=_SIGNING_KEY,
                    vault_master_kek_hex=_KEK,
                    account_blinding_salt_hex=_SALT,
                    worker_timeout_seconds=bad_timeout,  # type: ignore[arg-type]
                )


if __name__ == "__main__":
    unittest.main()
