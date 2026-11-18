"""Regression tests for Round 4 API findings (F5, F6b, F8, F9, F10, SEC-03, SEC-07, SEC-13b, SEC-15, SEC-16)."""

from __future__ import annotations

import base64
from datetime import date, timedelta
import os
import tempfile
import time
from typing import Any
import unittest
from unittest import mock
import urllib.parse

from app import store as store_module
from app import worker_isolation
from app.badges import is_safe_xml_char, svg_escape
from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from app.privacy_scanner import OutboundPrivacyScanner
from app.routes_snaptrade import (
    SnapTradeRelayCoordinator,
    validate_snaptrade_redirect_url,
)
from app.routes_viral import (
    handle_get_challenge_card,
    sanitize_markdown_text,
    sanitize_public_label,
)
from app.worker_isolation import (
    WorkerInputTooLargeError,
    default_standalone_worker_pipeline,
    enforce_statement_input_limits,
)
from n170_verify.contracts import (
    AccountScope,
    EnvironmentTier,
    OriginAssurance,
    ProviderApprovalState,
    create_signed_proof_bundle,
)
from n170_verify.crypto import generate_ed25519_keypair

try:
    from tests.test_api_lifecycle_and_security import _build_leaf_payloads
    from tests.test_snaptrade_relay import _make_mock_snaptrade_transport
    from tests.test_verify_input_allowlist import (
        DUMMY_WALLET,
        SERVER_SALT_HEX,
        picklable_dummy_hyperliquid_transport,
    )
except ImportError:  # pragma: no cover - run from inside api/tests
    from test_api_lifecycle_and_security import _build_leaf_payloads  # type: ignore[no-redef]
    from test_snaptrade_relay import _make_mock_snaptrade_transport  # type: ignore[no-redef]
    from test_verify_input_allowlist import (  # type: ignore[no-redef]
        DUMMY_WALLET,
        SERVER_SALT_HEX,
        picklable_dummy_hyperliquid_transport,
    )


_HL_TRANSPORT_SPEC = (
    f"{picklable_dummy_hyperliquid_transport.__module__}:{picklable_dummy_hyperliquid_transport.__name__}"
)

PORTAL = "/api/v1/connect/snaptrade/portal"
VERIFY_ST = "/api/v1/connect/snaptrade/verify"
RELEASE_ST = "/api/v1/connect/snaptrade/release"
STATUS_ST = "/api/v1/connect/snaptrade/status"
LEADERBOARD_ALL = "/api/v1/leaderboard?min_capital_bracket=under_1k&include_private_bracket=true"


def _make_mt5_html(n_deals: int) -> str:
    head = (
        "<html><body><table>\n"
        "<tr><td>Account: 77441122 (USD, Live, Hedge)</td><td>Company: Broker Live</td>"
        "<td>Server: Broker-Live3</td></tr>\n"
        "<tr><td>Deals</td></tr>\n"
        "<tr><td>Time</td><td>Deal</td><td>Symbol</td><td>Type</td><td>Direction</td>"
        "<td>Volume</td><td>Price</td><td>Order</td><td>Commission</td><td>Fee</td>"
        "<td>Swap</td><td>Profit</td><td>Balance</td><td>Comment</td></tr>\n"
        "<tr><td>2025.01.02 09:00:00</td><td>1</td><td></td><td>balance</td><td></td>"
        "<td></td><td></td><td></td><td>0.00</td><td>0.00</td><td>0.00</td>"
        "<td>10 000.00</td><td>10 000.00</td><td>Funding</td></tr>\n"
    )
    rows: list[str] = []
    bal = 10000.0
    d0 = date(2025, 1, 3)
    for i in range(n_deals):
        d = d0 + timedelta(days=i // 2)
        did = 100 + i
        if i % 2 == 0:
            rows.append(
                f"<tr><td>{d:%Y.%m.%d} 09:00:00</td><td>{did}</td><td>EURUSD</td><td>buy</td>"
                f"<td>in</td><td>0.10</td><td>1.10000</td><td>{did}</td><td>0</td><td>0</td>"
                f"<td>0</td><td>0.00</td><td>{bal:.2f}</td><td></td></tr>"
            )
        else:
            bal += 10.0
            rows.append(
                f"<tr><td>{d:%Y.%m.%d} 15:00:00</td><td>{did}</td><td>EURUSD</td><td>sell</td>"
                f"<td>out</td><td>0.10</td><td>1.10100</td><td>{did}</td><td>0</td><td>0</td>"
                f"<td>0</td><td>10.00</td><td>{bal:.2f}</td><td></td></tr>"
            )
    return head + "\n".join(rows) + "\n</table></body></html>"


def _clean_env_case(case: unittest.TestCase) -> None:
    patcher = mock.patch.dict(os.environ, {}, clear=False)
    patcher.start()
    case.addCleanup(patcher.stop)
    for key in (
        "N170_VERIFY_SITE_ORIGIN",
        "N170_SNAPTRADE_DEV_KEY",
        "SNAPTRADE_CLIENT_ID",
        "SNAPTRADE_CONSUMER_KEY",
        "SNAPTRADE_AUTH_MODE",
    ):
        os.environ.pop(key, None)


class TestWorkerStatementLimitsCostDragAndWarnings(unittest.TestCase):
    """F5, F6b, and F10 in api/app/worker_isolation.py."""

    def setUp(self) -> None:
        _clean_env_case(self)
        self.kp = generate_ed25519_keypair(bytes.fromhex("42" * 32))
        self.cfg = ApiConfig(
            publisher_keypair=self.kp,
            publisher_kid="r4-worker-test-kid",
            hosted_multi_user_mode=True,
            allow_hosted_signing=False,
            account_blinding_salt_hex=SERVER_SALT_HEX,
        )
        self.app = create_app(self.cfg, prefer_fastapi=False)
        self.addCleanup(self.app.verify_app.close)
        self.client = VerifyApiTestClient(self.app)

    def test_f5_mt5_html_utf16_and_utf8_pass_while_oversized_csv_html_and_xml_return_413(
        self,
    ) -> None:
        html_175 = _make_mt5_html(175)
        html_350 = _make_mt5_html(350)
        for label, blob in (
            ("utf16_bom", html_175.encode("utf-16")),
            ("utf16_le_nobom", html_175.encode("utf-16-le")),
            ("utf16_be_nobom", html_175.encode("utf-16-be")),
            ("utf8_350", html_350.encode("utf-8")),
        ):
            with self.subTest(valid_case=label):
                b64 = base64.b64encode(blob).decode("ascii")
                enforce_statement_input_limits({"raw_statement_b64": b64})

        for label, blob in (
            ("utf16_175_verify", html_175.encode("utf-16")),
            ("utf8_350_verify", html_350.encode("utf-8")),
        ):
            with self.subTest(verify_route=label):
                b64 = base64.b64encode(blob).decode("ascii")
                resp = self.client.post(
                    "/api/v1/verify",
                    json={"broker_id": "auto_detect", "raw_statement_b64": b64},
                )
                self.assertEqual(resp.status_code, 200, resp.text[:300])

        limit = worker_isolation.MAX_STATEMENT_INPUT_ROWS
        for eol in ("\n", "\r", "\r\n"):
            with self.subTest(oversized_csv=repr(eol)):
                csv_blob = (eol.join(["a,b"] * (limit + 2)) + eol).encode("utf-8")
                with self.assertRaises(WorkerInputTooLargeError):
                    enforce_statement_input_limits(
                        {"raw_statement_b64": base64.b64encode(csv_blob).decode("ascii")}
                    )
        with self.subTest(oversized_utf16_csv=True):
            u16_csv = ("\n".join(["a,b"] * (limit + 2)) + "\n").encode("utf-16-le")
            with self.assertRaises(WorkerInputTooLargeError):
                enforce_statement_input_limits(
                    {"raw_statement_b64": base64.b64encode(u16_csv).decode("ascii")}
                )

        oversized_html = (
            "<html><body><table>"
            + "".join("<tr><td>1</td></tr>" for _ in range(limit + 2))
            + "</table></body></html>"
        )
        r_html = self.client.post(
            "/api/v1/verify",
            json={"broker_id": "auto_detect", "raw_statement_text": oversized_html},
        )
        self.assertEqual(r_html.status_code, 413, r_html.text[:300])

        oversized_xml = (
            "<FlexQueryResponse><FlexStatements><FlexStatement>"
            + "".join(f'<Trade id="{i}" />' for i in range(limit + 2))
            + "</FlexStatement></FlexStatements></FlexQueryResponse>"
        )
        r_xml = self.client.post(
            "/api/v1/verify",
            json={"broker_id": "auto_detect", "raw_statement_text": oversized_xml},
        )
        self.assertEqual(r_xml.status_code, 413, r_xml.text[:300])

    def test_f6b_standalone_pipeline_emits_null_cost_drag_when_withheld(self) -> None:
        out = default_standalone_worker_pipeline(
            {
                "broker_id": "ibkr_flex_offline",
                "account_blinding_salt_hex": SERVER_SALT_HEX,
                "issued_at_utc": "2026-02-01T00:00:00Z",
                "period_start_utc": "2026-01-01T00:00:00Z",
                "period_end_utc": "2026-01-31T00:00:00Z",
                "blinded_account_tag": "ba" * 32,
                "performance_withheld": True,
                "withheld_reasons": ["Insufficient valuation points"],
            }
        )
        coaching = next(
            lf["payload"]
            for lf in out["disclosed_leaves"]
            if lf["leaf_name"] == "coaching_and_context"
        )
        drag = coaching["cost_drag"]
        for key in (
            "commission_and_fee_drag_bps",
            "margin_and_funding_drag_bps",
            "fx_conversion_drag_bps",
            "withholding_tax_drag_bps",
            "total_friction_drag_bps",
            "annualized_total_drag_bps",
        ):
            self.assertIsNone(drag[key], f"{key}={drag[key]!r}")

    def test_f10_dropped_journal_tag_warning_preserved_after_withheld_rerun(self) -> None:
        stmt = (
            "Status,Symbol,Size,Open Date,Open Time,Close Date,Close Time,Entry Price,"
            "Exit Price,Return $,Side,Setups,Mistakes,Commission,Notes\n"
            "WIN,NVDA,50,2026-01-08,09:35:00,2026-01-08,10:20:00,140.00,145.00,248.00,"
            "LONG,PA3K9XZ1ABCD,,2.00,\n"
        ).encode("utf-8")
        b64 = base64.b64encode(stmt).decode("ascii")

        for route, body in (
            (
                "/api/v1/verify/auto-detect",
                {"raw_statement_b64": b64, "disclose_leaf_names": ["coaching_and_context"]},
            ),
            (
                "/api/v1/verify",
                {
                    "broker_id": "tradersync",
                    "raw_statement_b64": b64,
                    "disclose_leaf_names": ["coaching_and_context"],
                },
            ),
        ):
            with self.subTest(route=route):
                resp = self.client.post(route, json=body)
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                warnings = resp.json().get("record_warnings") or []
                self.assertTrue(
                    any("journal tag" in w for w in warnings),
                    f"Missing dropped-tag warning on {route}: {resp.json()}",
                )


class TestHostedLeaderboardRequiresProvenOwnership(unittest.TestCase):
    """SEC-03 in api/app/store.py and api/app/routes_leaderboard.py."""

    def setUp(self) -> None:
        _clean_env_case(self)
        self.kp = generate_ed25519_keypair(bytes.fromhex("42" * 32))

    def _config(self, *, hosted: bool, db_path: str = ":memory:") -> ApiConfig:
        return ApiConfig(
            publisher_keypair=self.kp,
            publisher_kid="r4-sec03-kid",
            publisher_key_not_before_utc="2025-01-01T00:00:00Z",
            hosted_multi_user_mode=hosted,
            allow_hosted_signing=False,
            db_path=db_path,
            sync_db_path=":memory:",
            vault_master_kek_hex="aa" * 32,
            account_blinding_salt_hex=SERVER_SALT_HEX,
        )

    def _bundle(self, proof_id: str, *, approval: ProviderApprovalState, twr: float = 0.12):
        return create_signed_proof_bundle(
            proof_id=proof_id,
            issued_at_utc="2026-02-10T12:00:00Z",
            publisher_kid="r4-sec03-kid",
            publisher_private_key_hex=self.kp.private_key_hex,
            broker_id="hyperliquid"
            if approval == ProviderApprovalState.PUBLIC_API_PERMISSIONLESS
            else "schwab",
            blinded_account_tag="ab" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=approval,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="34" * 32,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-02-10T00:00:00Z",
            base_currency="USD",
            leaf_payloads=_build_leaf_payloads(twr_decimal=twr),
        )

    def test_sec03_hosted_refuses_leaderboard_opt_in_for_public_wallet_but_allows_share_link(
        self,
    ) -> None:
        self.assertTrue(hasattr(store_module, "LeaderboardRequiresProvenOwnershipError"))
        app = create_app(
            self._config(hosted=True),
            hyperliquid_http_transport=_HL_TRANSPORT_SPEC,
            prefer_fastapi=False,
        )
        self.addCleanup(app.verify_app.close)
        client = VerifyApiTestClient(app)

        # 1. /api/v1/verify with publish_proof=True, opt_in_leaderboard=True -> 403
        r_ver_opt = client.post(
            "/api/v1/verify",
            json={
                "broker_id": "hyperliquid",
                "wallet_address": DUMMY_WALLET,
                "connector_fetch_kwargs": {"start_date": "2026-01-02", "end_date": "2026-02-05"},
                "publish_proof": True,
                "opt_in_leaderboard": True,
            },
        )
        self.assertEqual(r_ver_opt.status_code, 403, r_ver_opt.text)
        self.assertEqual(r_ver_opt.json()["error"], "leaderboard_requires_proven_ownership")
        self.assertEqual(app.verify_app.store.total_row_counts()["proofs"], 0)

        # 2. /api/v1/verify with publish_proof=True, opt_in_leaderboard=False -> 200
        r_ver_link = client.post(
            "/api/v1/verify",
            json={
                "broker_id": "hyperliquid",
                "wallet_address": DUMMY_WALLET,
                "connector_fetch_kwargs": {"start_date": "2026-01-02", "end_date": "2026-02-05"},
                "publish_proof": True,
                "opt_in_leaderboard": False,
            },
        )
        self.assertEqual(r_ver_link.status_code, 200, r_ver_link.text)
        ver_pid = r_ver_link.json()["proof_bundle"]["proof_id"]
        self.assertEqual(client.get(f"/api/v1/proofs/{ver_pid}").status_code, 200)

        # 3. Direct POST /api/v1/proofs on PUBLIC_API_PERMISSIONLESS: opt_in=True -> 403, opt_in=False -> 201
        pub_bundle = self._bundle(
            "prf-public-wallet-direct",
            approval=ProviderApprovalState.PUBLIC_API_PERMISSIONLESS,
        )
        r_post_opt = client.post(
            "/api/v1/proofs",
            json={"proof_bundle": pub_bundle.to_dict(), "opt_in_leaderboard": True},
        )
        self.assertEqual(r_post_opt.status_code, 403, r_post_opt.text)
        self.assertEqual(r_post_opt.json()["error"], "leaderboard_requires_proven_ownership")

        r_post_link = client.post(
            "/api/v1/proofs",
            json={"proof_bundle": pub_bundle.to_dict(), "opt_in_leaderboard": False},
        )
        self.assertEqual(r_post_link.status_code, 201, r_post_link.text)
        self.assertEqual(client.get(LEADERBOARD_ALL).json()["count"], 0)

    def test_sec03_leaderboard_defense_in_depth_skips_preexisting_public_wallet_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "proofs_store")
            sh_app = create_app(self._config(hosted=False, db_path=db_path), prefer_fastapi=False)
            sh_client = VerifyApiTestClient(sh_app)
            proven = self._bundle(
                "prf-proven-owner", approval=ProviderApprovalState.APPROVED_LIVE, twr=0.25
            )
            unproven = create_signed_proof_bundle(
                proof_id="prf-preexisting-public",
                issued_at_utc="2026-02-15T12:00:00Z",
                publisher_kid="r4-sec03-kid",
                publisher_private_key_hex=self.kp.private_key_hex,
                broker_id="hyperliquid",
                blinded_account_tag="ab" * 32,
                account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
                provider_approval_state=ProviderApprovalState.PUBLIC_API_PERMISSIONLESS,
                environment_tier=EnvironmentTier.LIVE_PRODUCTION,
                claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
                source_body_sha256="56" * 32,
                period_start_utc="2026-01-20T00:00:00Z",
                period_end_utc="2026-02-15T00:00:00Z",
                base_currency="USD",
                leaf_payloads=_build_leaf_payloads(twr_decimal=0.01),
            )
            self.assertEqual(
                sh_client.post(
                    "/api/v1/proofs",
                    json={"proof_bundle": proven.to_dict(), "opt_in_leaderboard": True},
                ).status_code,
                201,
            )
            self.assertEqual(
                sh_client.post(
                    "/api/v1/proofs",
                    json={"proof_bundle": unproven.to_dict(), "opt_in_leaderboard": True},
                ).status_code,
                201,
            )
            sh_app.verify_app.close()

            hosted_app = create_app(
                self._config(hosted=True, db_path=db_path), prefer_fastapi=False
            )
            try:
                lb = VerifyApiTestClient(hosted_app).get(LEADERBOARD_ALL).json()
            finally:
                hosted_app.verify_app.close()
            self.assertEqual([e["proof_id"] for e in lb["entries"]], ["prf-proven-owner"])


class TestSnapTradeRelayLifecycleRedirectsAnd502(unittest.TestCase):
    """F8 and SEC-16 in api/app/routes_snaptrade.py."""

    def setUp(self) -> None:
        _clean_env_case(self)
        self.kp = generate_ed25519_keypair(bytes.fromhex("42" * 32))

    def _app(
        self,
        transport: Any = None,
        *,
        hosted: bool = True,
        site_origin: str = "https://verify.example.org",
    ) -> tuple[Any, VerifyApiTestClient, SnapTradeRelayCoordinator, list[dict[str, Any]]]:
        if transport is None:
            transport, recorded = _make_mock_snaptrade_transport()
        else:
            recorded = []
        relay = SnapTradeRelayCoordinator(http_transport=transport)
        cfg = ApiConfig(
            publisher_keypair=self.kp,
            publisher_kid="r4-snap-kid",
            snaptrade_client_id="N170-SNAP-DEV-CLIENT",
            snaptrade_consumer_key="snap-hmac-consumer-secret-xyz-12345",
            account_blinding_salt_hex=SERVER_SALT_HEX,
            hosted_multi_user_mode=hosted,
            site_origin=site_origin,
        )
        app = create_app(cfg, snaptrade_relay=relay, prefer_fastapi=False)
        self.addCleanup(app.close)
        return app, VerifyApiTestClient(app), relay, recorded

    def test_f8_finish_use_runs_queued_delete_keeps_slot_reserved_and_reports_token_disposal(
        self,
    ) -> None:
        _, client, relay, recorded = self._app()
        tok = client.post(PORTAL, json={"slot_label": "v1"}).json()["session_token"]
        concurrent_sess = relay.get_session_for_use(tok)
        self.assertIsNotNone(concurrent_sess)
        assert concurrent_sess is not None

        r = client.post(VERIFY_ST, json={"session_token": tok, "release_slot_after": True})
        self.assertEqual(r.status_code, 200, r.text[:300])
        body = r.json()
        deletes_during = [x for x in recorded if "deleteUser" in x["path"]]
        self.assertEqual(deletes_during, [])
        self.assertEqual(
            body["isolation"]["token_disposal"],
            "queued_for_upstream_delete_and_purged_from_memory",
        )
        self.assertEqual(body["slot_status"]["active_slots"], 1)

        relay.finish_use(concurrent_sess.user_id)
        deletes_after = [x for x in recorded if "deleteUser" in x["path"]]
        self.assertEqual(len(deletes_after), 1)
        self.assertEqual(len(relay._pending_upstream_deletes), 0)
        self.assertEqual(relay.slot_status_dict()["active_slots"], 0)

    def test_f8_verify_finally_passes_adapter_to_finish_use_for_concurrent_release(self) -> None:
        inner, recorded = _make_mock_snaptrade_transport()
        holder: dict[str, Any] = {}

        def transport(
            method: str, url: str, headers: dict[str, str], body: bytes | None
        ) -> Any:
            if urllib.parse.urlsplit(url).path == "/api/v1/accounts" and not holder.get("released"):
                holder["released"] = True
                holder["rel_resp"] = holder["client"].post(
                    RELEASE_ST, json={"session_token": holder["tok"]}
                )
                holder["during_slots"] = holder["relay"].slot_status_dict()["active_slots"]
            return inner(method, url, headers, body)

        _, client, relay, _ = self._app(transport)
        tok = client.post(PORTAL, json={}).json()["session_token"]
        holder.update(client=client, relay=relay, tok=tok)

        # Verify with release_slot_after=False while RELEASE ran mid-flight:
        # finish_use in verify's finally must immediately delete upstream and free the slot!
        v_resp = client.post(VERIFY_ST, json={"session_token": tok, "release_slot_after": False})
        self.assertEqual(v_resp.status_code, 200, v_resp.text[:300])
        self.assertEqual(holder["rel_resp"].status_code, 200)
        self.assertFalse(holder["rel_resp"].json()["upstream_deleted"])
        self.assertEqual(holder["during_slots"], 1)
        deletes_after = [x for x in recorded if "deleteUser" in x["path"]]
        self.assertEqual(len(deletes_after), 1)
        self.assertEqual(relay.slot_status_dict()["active_slots"], 0)

    def test_sec16c_end_user_purges_and_checks_in_use_under_one_lock_And_keeps_slot_on_fail(
        self,
    ) -> None:
        base, recorded = _make_mock_snaptrade_transport()
        fail_delete = {"on": True}

        def flaky(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
            if "deleteUser" in url and fail_delete["on"]:
                raise OSError("connection reset by peer")
            return base(method, url, headers, body)

        _, client, relay, _ = self._app(flaky)
        tok = client.post(PORTAL, json={}).json()["session_token"]
        sess = relay.get_session(tok)
        assert sess is not None

        # Attempt to interleave via purge_user_sessions_and_release_local hook (must not allow mid-release claim)
        got: dict[str, Any] = {}
        orig_purge = relay.purge_user_sessions_and_release_local

        def interleaved(user_id: str, *, is_personal: bool = False) -> bool:
            got["claimed"] = relay.get_session_for_use(tok)
            return orig_purge(user_id, is_personal=is_personal)

        relay.purge_user_sessions_and_release_local = interleaved  # type: ignore[method-assign]
        r_rel = client.post(RELEASE_ST, json={"session_token": tok})
        self.assertEqual(r_rel.status_code, 200)
        self.assertIsNone(got.get("claimed"))
        # Because deleteUser failed, local slot stays reserved until reap succeeds!
        self.assertEqual(r_rel.json()["active_slots"], 1)
        self.assertIn(sess.user_id, relay._pending_upstream_deletes)

        fail_delete["on"] = False
        st = client.get(STATUS_ST).json()
        self.assertEqual(st["active_slots"], 0)
        self.assertEqual(len(relay._pending_upstream_deletes), 0)
        self.assertTrue(any(x["path"] == "/api/v1/snapTrade/deleteUser" for x in recorded))

    def test_sec16b_redirect_url_rejects_double_slash_backslash_and_hosted_loopback(self) -> None:
        site = "https://verify.example.org"
        _, hosted_client, _, _ = self._app(hosted=True, site_origin=site)
        for bad in (
            "https://verify.example.org//evil.com/",
            "https://verify.example.org/\\evil.com",
            "https://verify.example.org/%5cevil.com",
            "https://verify.example.org/%2f%2fevil.com",
            "http://127.0.0.1:3000/connect",
            "http://127.0.0.1:9/x",
        ):
            with self.subTest(hosted_portal_bad=bad):
                resp = hosted_client.post(PORTAL, json={"redirect_url": bad})
                self.assertEqual(resp.status_code, 422, f"Expected 422 in hosted mode: {bad!r}")

        for good in (
            "https://verify.example.org/connect/done",
            "https://VERIFY.example.org:443/connect?snaptrade=ok",
            "https://verify.example.org?next=1",
        ):
            with self.subTest(hosted_good=good):
                ok, _, _ = validate_snaptrade_redirect_url(good, allowed_origin=site)
                self.assertTrue(ok, f"Expected accept: {good!r}")

        # Loopback allowed when self-hosted OR when site_origin itself is loopback
        _, sh_client, _, _ = self._app(hosted=False, site_origin=site)
        self.assertEqual(
            sh_client.post(PORTAL, json={"redirect_url": "http://127.0.0.1:3000/connect"}).status_code,
            200,
        )
        for loop_site in ("http://localhost:3000", "http://127.0.0.1:3000"):
            _, loop_client, _, _ = self._app(hosted=True, site_origin=loop_site)
            self.assertEqual(
                loop_client.post(
                    PORTAL, json={"redirect_url": "http://127.0.0.1:3000/connect"}
                ).status_code,
                200,
            )

    def test_sec16a_portal_and_verify_502_never_echo_raw_upstream_error_body(self) -> None:
        base, _ = _make_mock_snaptrade_transport()
        leaked_body = b'{"detail":"internal: db=pg://snap:hunter2@db.upstream.invalid/prod trace=abc"}'

        def noisy_register(
            method: str, url: str, headers: dict[str, str], body: bytes | None
        ) -> Any:
            if "registerUser" in url:
                return 500, {"Content-Type": "application/json"}, leaked_body
            return base(method, url, headers, body)

        _, client, _, _ = self._app(noisy_register)
        r_portal = client.post(PORTAL, json={})
        self.assertEqual(r_portal.status_code, 502)
        self.assertEqual(r_portal.json()["error"], "snaptrade_upstream_error")
        self.assertNotIn("hunter2", r_portal.text)
        self.assertNotIn("db.upstream.invalid", r_portal.text)
        self.assertIn("HTTP 500", r_portal.json()["detail"])


class TestSanitizersBadgesStrictBooleansAndScannerIsins(unittest.TestCase):
    """SEC-07, SEC-13b, SEC-15, SEC-17, and F9."""

    def setUp(self) -> None:
        _clean_env_case(self)
        self.kp = generate_ed25519_keypair(bytes.fromhex("42" * 32))

    def test_sec07_and_sec17_sanitizer_bounds_redos_reforming_and_challenge_card_422(
        self,
    ) -> None:
        t0 = time.perf_counter()
        sanitize_public_label("<" * 32_000, max_len=64)
        sanitize_public_label("on" + "a" * 64_000, max_len=64)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 0.05, f"Sanitizer took {elapsed:.3f}s")

        for raw in (
            "@everyone",
            "@every'one",
            "@@everyone",
            "@every`one",
            "@here\\",
            "@her<b>e",
        ):
            with self.subTest(mention=raw):
                pub = sanitize_public_label(raw).lower()
                md = sanitize_markdown_text(raw).lower()
                self.assertNotIn("@everyone", pub)
                self.assertNotIn("@here", pub)
                self.assertNotIn("@everyone", md)
                self.assertNotIn("@here", md)

        for raw in ("@every_one", "@ever*yone", "@he[r]e"):
            with self.subTest(md_mention=raw):
                md = sanitize_markdown_text(raw).lower()
                self.assertNotIn("@everyone", md)
                self.assertNotIn("@here", md)

        for raw in (
            "javajavascript:script:alert(1)",
            "jav'ascript:alert(1)",
            "o'nload=x",
            "data\u200b:text/html",
        ):
            with self.subTest(scheme=raw):
                out = sanitize_public_label(raw).lower()
                self.assertNotIn("javascript:", out)
                self.assertNotIn("data:", out)
                self.assertNotIn("onload=", out)

        for params in (
            {"handle": "U1234567"},
            {"period_label": "sk_live_" + "A" * 20},
            {"handle": "pa3k9xz1abcd"},
        ):
            with self.subTest(challenge_leak=params):
                st, body, _ = handle_get_challenge_card(params)
                self.assertEqual(st, 422, body)
                self.assertEqual(body["error"], "validation_error")
                for secret_val in params.values():
                    self.assertNotIn(secret_val.lower(), str(body).lower())

    def test_sec13b_badges_is_safe_xml_char_rejects_cf_cc_zl_zp_cs_co_cn(self) -> None:
        for ch in ("\u202e", "\u200b", "\u2066", "\u2069", "\ufeff", "\u00ad", "\u061c", "\x85", "\x9b", "\u2028", "\u2029"):
            with self.subTest(code=hex(ord(ch))):
                self.assertFalse(is_safe_xml_char(ch))
                self.assertEqual(svg_escape(f"a{ch}b"), "ab")

    def test_sec15_strict_boolean_flags_on_json_routes_while_keeping_environment_tier(
        self,
    ) -> None:
        transport, _ = _make_mock_snaptrade_transport()
        relay = SnapTradeRelayCoordinator(http_transport=transport)
        cfg = ApiConfig(
            publisher_keypair=self.kp,
            publisher_kid="r4-bool-kid",
            publisher_key_not_before_utc="2025-01-01T00:00:00Z",
            snaptrade_client_id="N170-SNAP-DEV-CLIENT",
            snaptrade_consumer_key="snap-hmac-consumer-secret-xyz-12345",
            account_blinding_salt_hex=SERVER_SALT_HEX,
            hosted_multi_user_mode=True,
        )
        app = create_app(
            cfg,
            snaptrade_relay=relay,
            hyperliquid_http_transport=_HL_TRANSPORT_SPEC,
            prefer_fastapi=False,
        )
        self.addCleanup(app.close)
        client = VerifyApiTestClient(app)

        # 1. SnapTrade /verify rejects string booleans
        tok = client.post(PORTAL, json={}).json()["session_token"]
        for bad_flags in (
            {"publish_proof": "false"},
            {"opt_in_leaderboard": "false"},
            {"publish_proof": "0", "opt_in_leaderboard": "no"},
            {"publish_proof": 0},
        ):
            with self.subTest(snaptrade_flags=bad_flags):
                r = client.post(VERIFY_ST, json={"session_token": tok, **bad_flags})
                self.assertEqual(r.status_code, 422, r.text)
                self.assertEqual(r.json()["error"], "validation_error")
        self.assertEqual(app.store.total_row_counts()["proofs"], 0)

        # 2. /api/v1/verify rejects string booleans AND keeps environment_tier accepted
        for bad_flags in ({"publish_proof": "false"}, {"opt_in_leaderboard": "false"}):
            with self.subTest(verify_flags=bad_flags):
                r = client.post(
                    "/api/v1/verify",
                    json={"broker_id": "hyperliquid", "wallet_address": DUMMY_WALLET, **bad_flags},
                )
                self.assertEqual(r.status_code, 422, r.text)
                self.assertEqual(r.json()["error"], "validation_error")

        r_tier = client.post(
            "/api/v1/verify",
            json={
                "broker_id": "hyperliquid",
                "wallet_address": DUMMY_WALLET,
                "environment_tier": "live_production",
                "publish_proof": False,
                "opt_in_leaderboard": False,
            },
        )
        self.assertEqual(r_tier.status_code, 200, r_tier.text[:300])

        # 3. /api/v1/proofs & /api/v1/chains reject string opt_in_leaderboard
        bundle = create_signed_proof_bundle(
            proof_id="prf-strict-bool-01",
            issued_at_utc="2026-02-10T12:00:00Z",
            publisher_kid="r4-bool-kid",
            publisher_private_key_hex=self.kp.private_key_hex,
            broker_id="schwab",
            blinded_account_tag="cd" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="78" * 32,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-02-10T00:00:00Z",
            base_currency="USD",
            leaf_payloads=_build_leaf_payloads(),
        )
        r_proofs = client.post(
            "/api/v1/proofs",
            json={"proof_bundle": bundle.to_dict(), "opt_in_leaderboard": "false"},
        )
        self.assertEqual(r_proofs.status_code, 422, r_proofs.text)
        self.assertEqual(r_proofs.json()["error"], "validation_error")

        r_chains = client.post(
            "/api/v1/chains",
            json={"proof_bundle": bundle.to_dict(), "opt_in_leaderboard": "false"},
        )
        self.assertEqual(r_chains.status_code, 422, r_chains.text)
        self.assertEqual(r_chains.json()["error"], "validation_error")
        self.assertEqual(app.store.total_row_counts()["proofs"], 0)

    def test_f9_privacy_scanner_case_insensitive_account_ids_and_isin_exemption(self) -> None:
        scanner = OutboundPrivacyScanner()
        for valid_isin in ("PA1436583006", "PAP310761054", "PA21986M1051"):
            with self.subTest(valid_isin=valid_isin):
                self.assertEqual(scanner.scan_text(valid_isin), [])

        for blocked in (
            "PA3K9XZ1ABCD",
            "pa3k9xz1abcd",
            "PA1436583007",
            "pa1436583006",
            "u1234567",
            "U1234567",
            "du1234567",
            "DU1234567",
            "6ya123456",
            "6YA123456",
        ):
            with self.subTest(blocked=blocked):
                self.assertTrue(scanner.scan_text(blocked), f"Expected scanner hit on {blocked!r}")

        cfg = ApiConfig(
            publisher_keypair=self.kp,
            publisher_kid="r4-isin-kid",
            hosted_multi_user_mode=True,
            allow_hosted_signing=False,
            account_blinding_salt_hex=SERVER_SALT_HEX,
        )
        app = create_app(cfg, prefer_fastapi=False)
        self.addCleanup(app.verify_app.close)
        client = VerifyApiTestClient(app)

        ts_isin = (
            "Status,Symbol,Size,Open Date,Open Time,Close Date,Close Time,Entry Price,"
            "Exit Price,Return $,Side,Setups,Mistakes,Commission,Notes\n"
            "WIN,PA1436583006,50,2026-01-08,09:35:00,2026-01-08,10:20:00,20.00,21.00,"
            "50.00,LONG,,,0,\n"
        ).encode("utf-8")
        r_isin = client.post(
            "/api/v1/verify",
            json={
                "broker_id": "auto_detect",
                "raw_statement_b64": base64.b64encode(ts_isin).decode("ascii"),
            },
        )
        self.assertEqual(r_isin.status_code, 200, r_isin.text[:300])


if __name__ == "__main__":
    unittest.main()
