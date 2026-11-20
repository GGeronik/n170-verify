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


def _snaptrade_counters_path(pid: int) -> Path:
    return Path(tempfile.gettempdir()) / f"n170_test_st_counters_{pid}.json"


def _reset_snaptrade_counters() -> None:
    _snaptrade_counters_path(os.getpid()).write_text(
        json.dumps({"register_calls": 0, "login_calls": 0}),
        encoding="utf-8",
    )


def _bump_snaptrade_counter(field: str) -> int:
    p = _snaptrade_counters_path(os.getpid())
    if not p.exists():
        alt = _snaptrade_counters_path(os.getppid())
        if alt.exists():
            p = alt
    data = (
        json.loads(p.read_text(encoding="utf-8"))
        if p.exists()
        else {"register_calls": 0, "login_calls": 0}
    )
    data[field] = int(data.get(field, 0)) + 1
    p.write_text(json.dumps(data), encoding="utf-8")
    return int(data[field])


def _read_snaptrade_counters() -> dict[str, int]:
    p = _snaptrade_counters_path(os.getpid())
    if not p.exists():
        return {"register_calls": 0, "login_calls": 0}
    return json.loads(p.read_text(encoding="utf-8"))


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
        big_suffix = "-BIG" if tok == "BIG-FLEX-TOKEN-3MB" else ""
        ref = f"REF-{fd}-{td}{big_suffix}"
        env = (
            f"<FlexStatementResponse><Status>Success</Status>"
            f"<ReferenceCode>{ref}</ReferenceCode></FlexStatementResponse>"
        ).encode("utf-8")
        return HttpExchangeResponse(status_code=200, headers={}, body=env)

    if url.startswith(IBKR_FLEX_GET_STATEMENT_URL):
        ref = qs["q"][0]
        parts = ref.split("-")
        fd_s, td_s = parts[1], parts[2]
        is_big = len(parts) > 3 and parts[3] == "BIG"
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
        extra_padding = ""
        if is_big:
            pad_note = "IBKR verbose statement padding for >2MB GetStatement envelope test " * 8
            extra_padding = (
                "<UnbundledCommissionDetails>"
                + "".join(
                    f'<UnbundledCommissionDetail accountId="U8899001" tradeID="T-{i}" note="{pad_note}" />'
                    for i in range(4200)
                )
                + "</UnbundledCommissionDetails>"
            )
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<FlexQueryResponse queryName="HostedAF" type="AF"><FlexStatements count="1">'
            f'<FlexStatement accountId="U8899001" baseCurrency="EUR" '
            f'fromDate="{d0.isoformat()}" toDate="{d1.isoformat()}">'
            f'<EquitySummaryInBase>{"".join(rows)}</EquitySummaryInBase>'
            '<ConversionRates><ConversionRate reportDate="2025-01-02" fromCurrency="USD" toCurrency="EUR" rate="0.92" /></ConversionRates>'
            f"{extra_padding}"
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
        _bump_snaptrade_counter("register_calls")
        req = json.loads((body or b"{}").decode("utf-8"))
        out = json.dumps({"userId": req["userId"], "userSecret": "st-secret-xyz-9876"}).encode("utf-8")
        return HttpExchangeResponse(status_code=200, headers={}, body=out)
    if path == "/api/v1/snapTrade/login":
        seq = _bump_snaptrade_counter("login_calls")
        out = json.dumps(
            {"redirectURI": f"https://app.snaptrade.com/blade/connect-{seq}"}
        ).encode("utf-8")
        return HttpExchangeResponse(
            status_code=200,
            headers={},
            body=out,
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
        _reset_snaptrade_counters()
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
        _snaptrade_counters_path(os.getpid()).unlink(missing_ok=True)
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

    def test_snaptrade_portal_reissues_fresh_portal_url_for_existing_session_token_without_new_slot(
        self,
    ) -> None:
        p1 = self.client.post(
            "/api/v1/connect/snaptrade/portal",
            json={"redirect_url": "https://verify.example.org/connect?snaptrade=connected"},
        )
        self.assertEqual(p1.status_code, 200, p1.text)
        b1 = p1.json()
        tok = b1["session_token"]
        url1 = b1["portal_url"]
        self.assertEqual(b1["active_slots"], 1)
        self.assertEqual(_read_snaptrade_counters()["register_calls"], 1)
        self.assertEqual(_read_snaptrade_counters()["login_calls"], 1)

        # Re-requesting portal with existing session_token mints a FRESH single-use SnapTrade
        # login URL without registering a second user or consuming a second slot!
        p2 = self.client.post(
            "/api/v1/connect/snaptrade/portal",
            json={
                "session_token": tok,
                "redirect_url": "https://verify.example.org/connect?snaptrade=connected",
            },
        )
        self.assertEqual(p2.status_code, 200, p2.text)
        b2 = p2.json()
        self.assertEqual(b2["session_token"], tok)
        self.assertEqual(b2["slot_id"], b1["slot_id"])
        self.assertEqual(b2["active_slots"], 1)
        self.assertNotEqual(b2["portal_url"], url1)
        self.assertEqual(_read_snaptrade_counters()["register_calls"], 1)
        self.assertEqual(_read_snaptrade_counters()["login_calls"], 2)

        # Unknown/expired session_token on /portal fails closed with 404 session_not_found
        bad_p = self.client.post(
            "/api/v1/connect/snaptrade/portal",
            json={"session_token": "expired-or-unknown-session-token"},
        )
        self.assertEqual(bad_p.status_code, 404, bad_p.text)
        self.assertEqual(bad_p.json()["error"], "session_not_found")
        self.assertEqual(_read_snaptrade_counters()["register_calls"], 1)

        # Non-string / blank session_token rejected with 422
        for bad_tok in (123, "   "):
            bad_val = self.client.post(
                "/api/v1/connect/snaptrade/portal",
                json={"session_token": bad_tok},
            )
            self.assertEqual(bad_val.status_code, 422, bad_val.text)

    def test_hosted_ibkr_flex_web_verifies_over_2mb_get_statement_payload_and_guide_ai_prompt(
        self,
    ) -> None:
        resp = self.client.post(
            "/api/v1/verify",
            json={
                "broker_id": "ibkr_flex_web",
                "connector_fetch_kwargs": {
                    "flex_token": "BIG-FLEX-TOKEN-3MB",
                    "query_id": "998877",
                    "start_date": "2025-01-02",
                    "end_date": "2025-03-31",
                },
                "issued_at_utc": "2026-11-19T12:00:00Z",
            },
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertFalse(resp.json()["performance_withheld"])

        guide_resp = self.client.get("/api/v1/connect/ibkr-flex-guide")
        self.assertEqual(guide_resp.status_code, 200, guide_resp.text)
        g_body = guide_resp.json()
        self.assertIn("ai_builder_prompt", g_body)
        self.assertLessEqual(len(g_body["ai_builder_prompt"]), 200)
        self.assertIn("minimal_sections", g_body)

    def test_snaptrade_portal_refresh_race_against_concurrent_release_and_max_ttl_and_active_sync_extension(
        self,
    ) -> None:
        import threading
        from app import worker_isolation
        from app.routes_snaptrade import SnapTradeRelayCoordinator

        self.assertGreaterEqual(worker_isolation.MAX_STATEMENT_INPUT_BYTES, 24 * 1024 * 1024)
        self.assertGreaterEqual(worker_isolation.MAX_STATEMENT_INPUT_ROWS, 250_000)

        # 1. Concurrent /portal (session_token) racing against /release (session_token) MUST
        # return 404 session_not_found instead of 200 with a dead portal_url after finish_use deletes user!
        login_entered = threading.Event()
        allow_login_exit = threading.Event()
        race_login_calls = 0

        def racing_transport(
            method: str, url: str, headers: dict[str, str], body: bytes | None
        ) -> HttpExchangeResponse:
            nonlocal race_login_calls
            if "/api/v1/snapTrade/login" in url:
                race_login_calls += 1
                if race_login_calls == 2:
                    login_entered.set()
                    allow_login_exit.wait(timeout=5.0)
            return fake_snaptrade_transport(method, url, headers, body)

        race_app = VerifyApiApplication(
            ApiConfig(
                publisher_keypair=_SIGNING_KEY,
                vault_master_kek_hex=_KEK,
                account_blinding_salt_hex=_SALT,
                hosted_multi_user_mode=True,
                allow_hosted_signing=False,
                site_origin="https://verify.example.org",
                snaptrade_client_id="N170-BUILD-ID",
                snaptrade_consumer_key="build-consumer-secret-key",
                snaptrade_session_ttl_seconds=300.0,
            ),
            snaptrade_relay=SnapTradeRelayCoordinator(
                http_transport=racing_transport,
                session_ttl_seconds=300.0,
            ),
        )
        self.addCleanup(race_app.close)
        race_client = VerifyApiTestClient(race_app)

        init_p = race_client.post(
            "/api/v1/connect/snaptrade/portal",
            json={"redirect_url": "https://verify.example.org/connect?snaptrade=connected"},
        )
        self.assertEqual(init_p.status_code, 200, init_p.text)
        race_tok = init_p.json()["session_token"]

        portal_race_out: list[Any] = []

        def run_portal_refresh() -> None:
            portal_race_out.append(
                race_client.post(
                    "/api/v1/connect/snaptrade/portal",
                    json={
                        "session_token": race_tok,
                        "redirect_url": "https://verify.example.org/connect?snaptrade=connected",
                    },
                )
            )

        t_refresh = threading.Thread(target=run_portal_refresh)
        t_refresh.start()
        self.assertTrue(login_entered.wait(timeout=5.0))
        rel_resp = race_client.post(
            "/api/v1/connect/snaptrade/release",
            json={"session_token": race_tok},
        )
        self.assertEqual(rel_resp.status_code, 200, rel_resp.text)
        allow_login_exit.set()
        t_refresh.join(timeout=5.0)

        self.assertEqual(len(portal_race_out), 1)
        self.assertEqual(
            portal_race_out[0].status_code,
            404,
            f"Released session must not return 200 with dead portal_url: {portal_race_out[0].text}",
        )
        self.assertEqual(portal_race_out[0].json()["error"], "session_not_found")

        # 2. Hard 30-minute S3 cap on /portal refresh + active mid-sync extension under 300s TTL
        _set_tx_done(False)
        fake_now = [1000.0]
        ttl_app = VerifyApiApplication(
            ApiConfig(
                publisher_keypair=_SIGNING_KEY,
                vault_master_kek_hex=_KEK,
                account_blinding_salt_hex=_SALT,
                hosted_multi_user_mode=True,
                allow_hosted_signing=False,
                site_origin="https://verify.example.org",
                snaptrade_client_id="N170-BUILD-ID",
                snaptrade_consumer_key="build-consumer-secret-key",
                snaptrade_session_ttl_seconds=300.0,
            ),
            snaptrade_relay=SnapTradeRelayCoordinator(
                http_transport=fake_snaptrade_transport,
                session_ttl_seconds=300.0,
                monotonic_clock=lambda: fake_now[0],
            ),
        )
        self.addCleanup(ttl_app.close)
        ttl_client = VerifyApiTestClient(ttl_app)

        p_sync = ttl_client.post(
            "/api/v1/connect/snaptrade/portal",
            json={"redirect_url": "https://verify.example.org/connect?snaptrade=connected"},
        )
        self.assertEqual(p_sync.status_code, 200, p_sync.text)
        sync_tok = p_sync.json()["session_token"]

        # At t = +250s (within 300s TTL), /session-status sees accounts_count == 1 (mid-sync)
        # and extends the session so it survives past 300s!
        fake_now[0] = 1250.0
        st_250 = ttl_client.post(
            "/api/v1/connect/snaptrade/session-status",
            json={"session_token": sync_tok},
        )
        self.assertEqual(st_250.status_code, 200, st_250.text)
        self.assertFalse(st_250.json()["ready_to_verify"])

        fake_now[0] = 1400.0  # +400s (> 300s initial TTL): still alive thanks to active sync poll!
        st_400 = ttl_client.post(
            "/api/v1/connect/snaptrade/session-status",
            json={"session_token": sync_tok},
        )
        self.assertEqual(st_400.status_code, 200, st_400.text)

        # Past hard 1800s (30m) ceiling from creation (t = 1000 + 1801 = 2801), /portal refresh is refused 404!
        for poll_t in (1950.0, 2450.0):
            fake_now[0] = poll_t
            self.assertEqual(
                ttl_client.post(
                    "/api/v1/connect/snaptrade/session-status",
                    json={"session_token": sync_tok},
                ).status_code,
                200,
            )
        fake_now[0] = 2700.0
        p_2700 = ttl_client.post(
            "/api/v1/connect/snaptrade/portal",
            json={
                "session_token": sync_tok,
                "redirect_url": "https://verify.example.org/connect?snaptrade=connected",
            },
        )
        self.assertEqual(p_2700.status_code, 200, p_2700.text)
        fake_now[0] = 2801.0
        p_expired_cap = ttl_client.post(
            "/api/v1/connect/snaptrade/portal",
            json={
                "session_token": sync_tok,
                "redirect_url": "https://verify.example.org/connect?snaptrade=connected",
            },
        )
        self.assertEqual(p_expired_cap.status_code, 404, p_expired_cap.text)


if __name__ == "__main__":
    unittest.main()
