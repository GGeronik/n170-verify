"""What a caller of ``POST /api/v1/verify`` may set, and which values the server keeps for itself.

Rules covered here:
- callers may set only the reporting window (and, where the adapter supports it, an
  account subset) of a live connector through ``connector_fetch_kwargs``; the server's
  blinding salt and the queried wallet are never caller-controlled;
- statement or ledger input is accepted only under an offline broker id, and the
  approval state signed into a bundle never exceeds what the worker's input supports;
- in hosted mode the account scope and origin assurance come from the worker, not the
  request.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any
import unittest

from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from app.worker_isolation import WorkerValidationError, run_isolated_one_shot_verification
from n170_verify.connectors import HYPERLIQUID_LIVE_BASE_URL
from n170_verify.contracts import (
    AccountScope,
    OriginAssurance,
    ProviderApprovalState,
    VerifyProofBundle,
    verify_proof_bundle,
)
from n170_verify.crypto import generate_ed25519_keypair


DUMMY_WALLET = "0x" + "ab" * 20
SERVER_SALT_HEX = "cd" * 32
ISSUED_AT = "2026-03-01T00:00:00Z"

TRADERSYNC_CSV = (
    "Status,Symbol,Size,Open Date,Open Time,Close Date,Close Time,Entry Price,Exit Price,"
    "Return $,Side,Setups,Mistakes,Commission,Notes\n"
    "WIN,NVDA,50,2026-01-08,09:35:00,2026-01-08,10:20:00,140.00,145.00,248.00,LONG,ORB,FOMO,2.00,x\n"
)

SCHWAB_CSV = (
    '"Date","Action","Symbol","Description","Quantity","Price","Fees & Comm","Amount"\n'
    '"01/04/2026","MoneyLink Deposit","","Deposit","","","","$15,000.00"\n'
    '"01/18/2026","Buy","VTI","VANGUARD TOTAL STOCK MKT","20","$290.00","$0.00","-$5,800.00"\n'
)


def picklable_dummy_hyperliquid_transport(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
) -> tuple[int, dict[str, str], Any]:
    """Fake Hyperliquid info endpoint that answers only for the dummy wallet."""
    if method != "POST" or url != f"{HYPERLIQUID_LIVE_BASE_URL}/info":
        return 400, {"Content-Type": "application/json"}, {"error": "unexpected_request"}
    query = json.loads(body.decode("utf-8"))
    if str(query.get("user") or "") != DUMMY_WALLET:
        return 400, {"Content-Type": "application/json"}, {"error": "unexpected_user"}
    base = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    q_type = query.get("type")
    if q_type == "portfolio":
        nav = 10000.0
        history = []
        for i in range(40):
            history.append([int((base + dt.timedelta(days=i)).timestamp() * 1000), f"{nav:.2f}"])
            nav = round(nav * (1.004 if i % 3 else 0.997), 2)
        return 200, {"Content-Type": "application/json"}, [["allTime", {"accountValueHistory": history}]]
    if q_type in {"userNonFundingLedgerUpdates", "userFills"}:
        return 200, {"Content-Type": "application/json"}, []
    return 400, {"Content-Type": "application/json"}, {"error": "unexpected_query"}


def picklable_offline_origin_worker_pipeline(job: dict[str, Any]) -> dict[str, Any]:
    """Worker stand-in whose input was a self-reported file, whatever broker id was requested."""
    from n170_verify.crypto import CANONICAL_LEAF_NAMES, build_salted_merkle_tree

    tree = build_salted_merkle_tree({name: {"placeholder": name} for name in CANONICAL_LEAF_NAMES})
    disclosed, undisclosed = tree.selectively_disclose(["core_metrics"])
    return {
        "broker_id": str(job["broker_id"]),
        "blinded_account_tag": "ef" * 32,
        "account_scope": AccountScope.UNKNOWN_OFFLINE_SCOPE.value,
        "provider_approval_state": ProviderApprovalState.OFFLINE_EXPORT_ONLY.value,
        "environment_tier": "live_production",
        "claimed_origin_assurance": OriginAssurance.SELF_REPORTED.value,
        "source_body_sha256": "12" * 32,
        "period_start_utc": "2026-01-01T00:00:00Z",
        "period_end_utc": "2026-01-31T00:00:00Z",
        "base_currency": "USD",
        "merkle_root": tree.merkle_root,
        "disclosed_leaves": [leaf.to_dict() for leaf in disclosed],
        "undisclosed_leaf_hashes": dict(undisclosed),
        "stripped_recent_closed_trades_count": 0,
    }


class VerifyInputAllowlistTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = ApiConfig(
            publisher_keypair=generate_ed25519_keypair(bytes.fromhex("42" * 32)),
            publisher_kid="allowlist-test-kid",
            hosted_multi_user_mode=True,
            allow_hosted_signing=False,
            account_blinding_salt_hex=SERVER_SALT_HEX,
        )
        self.app = create_app(
            self.cfg,
            hyperliquid_http_transport=f"{__name__}:picklable_dummy_hyperliquid_transport",
            prefer_fastapi=False,
        )
        self.client = VerifyApiTestClient(self.app)
        self.base = {"broker_id": "hyperliquid", "wallet_address": DUMMY_WALLET, "issued_at_utc": ISSUED_AT}

    def tearDown(self) -> None:
        self.app.verify_app.close()

    # H2 -------------------------------------------------------------------------------
    def test_callers_may_set_only_the_reporting_window_of_a_live_connector(self) -> None:
        r_base = self.client.post("/api/v1/verify", json=self.base)
        self.assertEqual(r_base.status_code, 200, r_base.text)
        base_tag = r_base.json()["proof_bundle"]["blinded_account_tag"]

        r_window = self.client.post(
            "/api/v1/verify",
            json={**self.base, "connector_fetch_kwargs": {"start_date": "2026-01-10", "end_date": "2026-02-05"}},
        )
        self.assertEqual(r_window.status_code, 200, r_window.text)
        self.assertEqual(r_window.json()["proof_bundle"]["blinded_account_tag"], base_tag)

        for refused in (
            {"blinding_salt_hex": "11" * 32},
            {"wallet_address": "0x" + "bb" * 20},
            {"address": "0x" + "bb" * 20},
            {"user": "0x" + "bb" * 20},
            {"require_live": False},
            {"some_unknown_option": 1},
            {"start_date": "2026-01-10", "Blinding_Salt_Hex": "22" * 32},
        ):
            with self.subTest(refused=sorted(refused)):
                resp = self.client.post("/api/v1/verify", json={**self.base, "connector_fetch_kwargs": refused})
                self.assertEqual(resp.status_code, 422, resp.text)
                self.assertEqual(resp.json()["error"], "validation_error")
                self.assertIn("connector_fetch_kwargs", resp.json()["detail"])

        r_not_object = self.client.post("/api/v1/verify", json={**self.base, "connector_fetch_kwargs": ["start_date"]})
        self.assertEqual(r_not_object.status_code, 422, r_not_object.text)

    def test_worker_never_lets_fetch_options_replace_the_server_salt_or_wallet(self) -> None:
        from n170_verify.pipeline import api_worker_pipeline_entrypoint

        job = {
            "broker_id": "hyperliquid",
            "wallet_address": DUMMY_WALLET,
            "account_blinding_salt_hex": SERVER_SALT_HEX,
            "issued_at_utc": ISSUED_AT,
            "_internal_hyperliquid_transport": picklable_dummy_hyperliquid_transport,
        }
        baseline = api_worker_pipeline_entrypoint(dict(job))
        self.assertTrue(baseline["blinded_account_tag"])
        for refused in ({"blinding_salt_hex": "11" * 32}, {"wallet_address": "0x" + "bb" * 20}):
            with self.subTest(refused=sorted(refused)):
                with self.assertRaises(ValueError):
                    api_worker_pipeline_entrypoint({**job, "connector_fetch_kwargs": refused})
        with self.assertRaises(ValueError):
            api_worker_pipeline_entrypoint({**job, "raw_account_id": "dummy-account-1"})

    # H3 -------------------------------------------------------------------------------
    def test_statement_input_is_refused_under_a_live_connector_broker_id(self) -> None:
        for broker_id, stmt, extra in (
            ("hyperliquid", TRADERSYNC_CSV, {"csv_format": "auto_detect"}),
            ("hyperliquid", TRADERSYNC_CSV, {}),
            ("schwab", SCHWAB_CSV, {}),
        ):
            with self.subTest(broker_id=broker_id, extra=sorted(extra)):
                resp = self.client.post(
                    "/api/v1/verify",
                    json={"broker_id": broker_id, "raw_statement_text": stmt, "issued_at_utc": ISSUED_AT, **extra},
                )
                self.assertEqual(resp.status_code, 422, resp.text)
                self.assertEqual(resp.json()["error"], "validation_error")

        # The same file under its own offline broker id still verifies, as offline export.
        honest = self.client.post(
            "/api/v1/verify",
            json={"broker_id": "tradersync", "raw_statement_text": TRADERSYNC_CSV, "issued_at_utc": ISSUED_AT},
        )
        self.assertEqual(honest.status_code, 200, honest.text)
        self.assertEqual(
            honest.json()["proof_bundle"]["provider_approval_state"],
            ProviderApprovalState.OFFLINE_EXPORT_ONLY.value,
        )

    def test_signed_approval_never_exceeds_what_the_worker_input_supports(self) -> None:
        request = {
            "broker_id": "hyperliquid",
            "provider_approval_state": ProviderApprovalState.PUBLIC_API_PERMISSIONLESS.value,
            "environment_tier": "live_production",
            "issued_at_utc": ISSUED_AT,
        }
        with self.assertRaises(WorkerValidationError):
            run_isolated_one_shot_verification(
                request,
                config=self.cfg,
                pipeline_spec=f"{__name__}:picklable_offline_origin_worker_pipeline",
            )

        # Unhosted: the signed state is lowered to the worker's, never kept above it.
        unhosted = ApiConfig(
            publisher_keypair=self.cfg.publisher_keypair,
            publisher_kid="allowlist-test-kid",
            hosted_multi_user_mode=False,
            account_blinding_salt_hex=SERVER_SALT_HEX,
        )
        bundle, _receipt, _stripped = run_isolated_one_shot_verification(
            request,
            config=unhosted,
            pipeline_spec=f"{__name__}:picklable_offline_origin_worker_pipeline",
        )
        self.assertEqual(bundle.provider_approval_state, ProviderApprovalState.OFFLINE_EXPORT_ONLY)

    # Withheld performance --------------------------------------------------------------
    def test_response_states_whether_the_return_was_withheld(self) -> None:
        computed = self.client.post("/api/v1/verify", json=self.base)
        self.assertEqual(computed.status_code, 200, computed.text)
        self.assertIs(computed.json().get("performance_withheld"), False)
        self.assertNotIn("withheld_reasons", computed.json())

        trade_only = self.client.post(
            "/api/v1/verify",
            json={"broker_id": "tradersync", "raw_statement_text": TRADERSYNC_CSV, "issued_at_utc": ISSUED_AT},
        )
        self.assertEqual(trade_only.status_code, 200, trade_only.text)
        body = trade_only.json()
        self.assertIs(body.get("performance_withheld"), True)
        self.assertTrue(body.get("withheld_reasons"))
        core = next(
            lf["payload"] for lf in body["proof_bundle"]["disclosed_leaves"] if lf["leaf_name"] == "core_metrics"
        )
        self.assertIs(core.get("performance_withheld"), True)

    # O6 -------------------------------------------------------------------------------
    def test_hosted_bundle_scope_and_origin_come_from_the_worker(self) -> None:
        resp = self.client.post(
            "/api/v1/verify",
            json={
                **self.base,
                "account_scope": AccountScope.ALL_ENUMERATED_SUBACCOUNTS.value,
                "claimed_origin_assurance": OriginAssurance.BROKER_SIGNED.value,
            },
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        bundle = VerifyProofBundle.from_dict(resp.json()["proof_bundle"])
        self.assertEqual(bundle.account_scope, AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED)
        self.assertEqual(bundle.claimed_origin_assurance, OriginAssurance.OPERATOR_RETRIEVED)
        self.assertTrue(verify_proof_bundle(bundle).signature_valid)


if __name__ == "__main__":
    unittest.main()
