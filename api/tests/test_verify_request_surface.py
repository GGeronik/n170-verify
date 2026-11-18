"""Which top-level request fields ``POST /api/v1/verify`` accepts on a hosted deployment.

Rules covered here:
- in hosted mode the worker job is built from a fixed list of request fields; any other
  top-level field is refused with 422 naming it, and the host chooses the record id;
- in hosted mode a broker id is lower-case ASCII letters, digits and underscores and is one
  the host has configured; a record made from a statement is signed under an offline id;
- a malformed value for a field the route or the parent process reads is a 422, not a 500.
"""

from __future__ import annotations

from typing import Any
import unittest

from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from app.worker_isolation import WorkerValidationError, run_isolated_one_shot_verification
from n170_verify.contracts import ProviderApprovalState
from n170_verify.crypto import generate_ed25519_keypair

try:
    from tests.test_verify_input_allowlist import (
        DUMMY_WALLET,
        SCHWAB_CSV,
        SERVER_SALT_HEX,
        picklable_dummy_hyperliquid_transport,
    )
except ImportError:  # pragma: no cover - run from inside api/tests
    from test_verify_input_allowlist import (  # type: ignore[no-redef]
        DUMMY_WALLET,
        SCHWAB_CSV,
        SERVER_SALT_HEX,
        picklable_dummy_hyperliquid_transport,
    )


_HL_TRANSPORT_SPEC = (
    f"{picklable_dummy_hyperliquid_transport.__module__}:{picklable_dummy_hyperliquid_transport.__name__}"
)

_STAND_IN_STATES = {
    "hyperliquid": (ProviderApprovalState.PUBLIC_API_PERMISSIONLESS.value, "operator_retrieved"),
    "alpaca": (ProviderApprovalState.APPROVED_LIVE.value, "operator_retrieved"),
    "schwab": (ProviderApprovalState.APPROVED_LIVE.value, "operator_retrieved"),
    "snaptrade": (ProviderApprovalState.AGGREGATOR_RELAYED.value, "operator_retrieved"),
    "tradier": (ProviderApprovalState.USER_KEY_SELF_ATTESTED.value, "operator_retrieved"),
}


def picklable_fixed_result_pipeline(job: dict[str, Any]) -> dict[str, Any]:
    """Worker stand-in: returns a fixed record and never reads any network source."""
    from n170_verify.crypto import CANONICAL_LEAF_NAMES, build_salted_merkle_tree

    broker_id = str(job["broker_id"])
    state, origin = _STAND_IN_STATES.get(
        broker_id, (ProviderApprovalState.OFFLINE_EXPORT_ONLY.value, "self_reported")
    )
    tree = build_salted_merkle_tree({name: {"placeholder": name} for name in CANONICAL_LEAF_NAMES})
    disclosed, undisclosed = tree.selectively_disclose(["core_metrics"])
    return {
        "broker_id": broker_id,
        "blinded_account_tag": "ef" * 32,
        "account_scope": "single_account_survivorship_unverified",
        "provider_approval_state": state,
        "environment_tier": "live_production",
        "claimed_origin_assurance": origin,
        "source_body_sha256": "12" * 32,
        "period_start_utc": "2026-01-01T00:00:00Z",
        "period_end_utc": "2026-01-31T00:00:00Z",
        "base_currency": "USD",
        "merkle_root": tree.merkle_root,
        "disclosed_leaves": [leaf.to_dict() for leaf in disclosed],
        "undisclosed_leaf_hashes": dict(undisclosed),
        "stripped_recent_closed_trades_count": 0,
    }


_STAND_IN_SPEC = f"{__name__}:picklable_fixed_result_pipeline"

_DUMMY_CHAIN_LINK = {
    "chain_id": "dummy-chain",
    "sequence_number": 0,
    "previous_proof_hash": None,
    "issued_at_utc": "2026-01-01T00:00:00Z",
}


def _config(*, hosted: bool) -> ApiConfig:
    return ApiConfig(
        publisher_keypair=generate_ed25519_keypair(bytes.fromhex("43" * 32)),
        publisher_kid="request-surface-test-kid",
        hosted_multi_user_mode=hosted,
        allow_hosted_signing=False,
        account_blinding_salt_hex=SERVER_SALT_HEX,
    )


class HostedVerifyRequestSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = _config(hosted=True)
        self.stand_in_app = create_app(
            self.cfg,
            pipeline_spec=_STAND_IN_SPEC,
            hyperliquid_http_transport=_HL_TRANSPORT_SPEC,
            prefer_fastapi=False,
        )
        self.stand_in = VerifyApiTestClient(self.stand_in_app)
        self.real_app = create_app(
            self.cfg,
            hyperliquid_http_transport=_HL_TRANSPORT_SPEC,
            prefer_fastapi=False,
        )
        self.real = VerifyApiTestClient(self.real_app)
        self.base = {"broker_id": "hyperliquid", "wallet_address": DUMMY_WALLET}

    def tearDown(self) -> None:
        self.stand_in_app.verify_app.close()
        self.real_app.verify_app.close()

    def test_fields_outside_the_hosted_request_list_are_refused_by_name(self) -> None:
        refused_fields: dict[str, Any] = {
            "psr_benchmark_sr": -100,
            "periods_per_year": 8760,
            "annual_risk_free_rate": 0.5,
            "benchmark_symbol": "SPY",
            "cash_flow_timing": "end_of_day",
            "eodhd_api_key": "dummy-not-a-key",
            "imported_journal_tags": ["dummy tag"],
            "base_currency": "JPY",
            "proof_id": "prf-chosen-by-caller",
            "prospective_chain_link": _DUMMY_CHAIN_LINK,
            "witness_attestations": [],
            "broker_native_signature": {"algorithm": "dummy"},
            "account_scope": "all_enumerated_subaccounts",
            "claimed_origin_assurance": "broker_signed",
            "period_start_utc": "2025-01-01T00:00:00Z",
            "period_end_utc": "2026-01-31T00:00:00Z",
            "raw_account_id": "dummy-account",
            "blinded_account_tag": "aa" * 32,
            "some_unlisted_field": 1,
        }
        for field_name, value in refused_fields.items():
            with self.subTest(field=field_name):
                resp = self.stand_in.post("/api/v1/verify", json={**self.base, field_name: value})
                self.assertEqual(resp.status_code, 422, resp.text)
                self.assertEqual(resp.json()["error"], "validation_error")
                self.assertIn(field_name, resp.json()["detail"])

        # Refused even when the value is null: the field itself is not part of the request.
        resp = self.stand_in.post("/api/v1/verify", json={**self.base, "proof_id": None})
        self.assertEqual(resp.status_code, 422, resp.text)

    def test_the_web_client_request_shapes_keep_working(self) -> None:
        live = {
            "broker_id": "hyperliquid",
            "raw_statement": None,
            "csv_format": None,
            "wallet_address": DUMMY_WALLET,
            "connector_fetch_kwargs": {"start_date": "2026-01-02", "end_date": "2026-02-05"},
            "disclose_leaf_names": ["core_metrics"],
            "publish_proof": True,
            "opt_in_leaderboard": True,
        }
        resp = self.real.post("/api/v1/verify", json=live)
        self.assertEqual(resp.status_code, 200, resp.text)
        bundle = resp.json()["proof_bundle"]
        self.assertEqual(bundle["broker_id"], "hyperliquid")
        self.assertRegex(bundle["proof_id"], r"^prf-[0-9a-f]{20}$")

        statement = {
            "broker_id": "auto_detect",
            "raw_statement": SCHWAB_CSV,
            "csv_format": "auto_detect",
            "wallet_address": None,
            "connector_fetch_kwargs": None,
            "disclose_leaf_names": ["core_metrics"],
            "publish_proof": False,
            "opt_in_leaderboard": False,
        }
        resp = self.real.post("/api/v1/verify", json=statement)
        self.assertEqual(resp.status_code, 200, resp.text)

    def test_hosted_worker_refuses_caller_chain_and_attestation_fields(self) -> None:
        for field_name, value in (
            ("prospective_chain_link", _DUMMY_CHAIN_LINK),
            ("witness_attestations", [{"notary_id": "dummy"}]),
            ("broker_native_signature", {"algorithm": "dummy"}),
        ):
            with self.subTest(field=field_name):
                with self.assertRaises(WorkerValidationError) as ctx:
                    run_isolated_one_shot_verification(
                        {**self.base, field_name: value},
                        config=self.cfg,
                        pipeline_spec=_STAND_IN_SPEC,
                    )
                self.assertIn(field_name, str(ctx.exception))

    def test_hosted_route_offers_only_permissionless_reads_and_statements(self) -> None:
        dummy_kwargs = {"api_key_id": "dummy-key-id", "api_secret_key": "dummy-secret"}
        for broker_id in ("alpaca", "schwab", "snaptrade", "tradier"):
            for extra in ({"connector_kwargs": dummy_kwargs}, {}):
                with self.subTest(broker_id=broker_id, extra=sorted(extra)):
                    resp = self.stand_in.post("/api/v1/verify", json={"broker_id": broker_id, **extra})
                    self.assertEqual(resp.status_code, 422, resp.text)
                    self.assertEqual(resp.json()["error"], "connector_not_offered")
                    self.assertIn(broker_id, resp.json()["detail"])

        resp = self.stand_in.post("/api/v1/verify", json={**self.base, "connector_kwargs": dummy_kwargs})
        self.assertEqual(resp.status_code, 422, resp.text)
        self.assertIn("connector_kwargs", resp.json()["detail"])

        pending = self.stand_in.post("/api/v1/verify", json={"broker_id": "ibkr_oauth", "connector_kwargs": dummy_kwargs})
        self.assertEqual(pending.status_code, 403, pending.text)
        self.assertEqual(pending.json()["error"], "provider_approval_pending")

        # The two offered inputs still verify.
        self.assertEqual(self.stand_in.post("/api/v1/verify", json=self.base).status_code, 200)
        stmt = self.stand_in.post("/api/v1/verify", json={"broker_id": "schwab_csv", "raw_statement_text": SCHWAB_CSV})
        self.assertEqual(stmt.status_code, 200, stmt.text)

    # Finding 2 ---------------------------------------------------------------------------
    def test_hosted_broker_id_must_be_a_configured_plain_identifier(self) -> None:
        for broker_id in (
            "hyperliquid​",
            "snaptrade-relay",
            "alpaca_live",
            "HyperliquidK",
            "hyperliquid\n",
            "",
        ):
            with self.subTest(broker_id=repr(broker_id)):
                resp = self.stand_in.post(
                    "/api/v1/verify", json={"broker_id": broker_id, "raw_statement_text": SCHWAB_CSV}
                )
                self.assertEqual(resp.status_code, 422, resp.text)
                self.assertEqual(resp.json()["error"], "validation_error")
        resp = self.stand_in.post("/api/v1/verify", json={"broker_id": 7, "raw_statement_text": SCHWAB_CSV})
        self.assertEqual(resp.status_code, 422, resp.text)

    def test_a_record_made_from_a_statement_is_signed_under_an_offline_id(self) -> None:
        for requested in ("auto_detect", "schwab_csv"):
            with self.subTest(requested=requested):
                resp = self.real.post(
                    "/api/v1/verify", json={"broker_id": requested, "raw_statement_text": SCHWAB_CSV}
                )
                self.assertEqual(resp.status_code, 200, resp.text)
                bundle = resp.json()["proof_bundle"]
                signed_id = bundle["broker_id"]
                self.assertEqual(
                    self.cfg.connector_approval_states.get(signed_id),
                    ProviderApprovalState.OFFLINE_EXPORT_ONLY,
                    f"statement signed under {signed_id!r}",
                )
                self.assertEqual(signed_id, "schwab_csv")
                self.assertEqual(bundle["provider_approval_state"], ProviderApprovalState.OFFLINE_EXPORT_ONLY.value)


class HostedMalformedListedFieldsTests(unittest.TestCase):
    """A malformed value in a field the hosted list accepts is a client error, never a 500."""

    def setUp(self) -> None:
        import dataclasses

        self.cfg = dataclasses.replace(_config(hosted=True), allow_caller_clock_for_tests=True)
        self.app = create_app(self.cfg, hyperliquid_http_transport=_HL_TRANSPORT_SPEC, prefer_fastapi=False)
        self.client = VerifyApiTestClient(self.app)

    def tearDown(self) -> None:
        self.app.verify_app.close()

    def test_malformed_listed_values_are_client_errors(self) -> None:
        live = {"broker_id": "hyperliquid", "wallet_address": DUMMY_WALLET}
        stmt = {"broker_id": "auto_detect", "raw_statement_text": SCHWAB_CSV}
        cases: list[dict[str, Any]] = [
            {**live, "wallet_address": {"nested": 1}},
            {**live, "wallet_address": 12345},
            {**live, "wallet_address": "not-an-address"},
            {**live, "connector_fetch_kwargs": {"start_date": "garbage"}},
            {**live, "connector_kwargs": 5},
            {**live, "connector_kwargs": [1, 2]},
            {**live, "disclose_leaf_names": 5},
            {**live, "disclose_leaf_names": ["no_such_leaf"]},
            {**live, "issued_at_utc": "garbage"},
            {**live, "environment_tier": "not_a_tier"},
            {**stmt, "raw_statement_text": 12345},
            {"broker_id": "auto_detect", "raw_statement": ["a", "b"]},
            {"broker_id": "auto_detect", "raw_statement_b64": "!!!not-base64!!!"},
            {"broker_id": "auto_detect", "csv_b64": "!!!not-base64!!!"},
            {"broker_id": "auto_detect", "flex_xml": 5},
            {**stmt, "csv_format": 5},
            {**stmt, "csv_format": "no_such_format"},
        ]
        for body in cases:
            with self.subTest(body=sorted((k, repr(v)[:40]) for k, v in body.items() if k != "raw_statement_text")):
                resp = self.client.post("/api/v1/verify", json=body)
                self.assertLess(resp.status_code, 500, resp.text)


class WithheldAndSeriesRulesTests(unittest.TestCase):
    """A withheld return is always visible; a client-supplied series is test-only."""

    def test_a_withheld_return_always_discloses_core_metrics(self) -> None:
        try:
            from tests.test_verify_input_allowlist import TRADERSYNC_CSV
        except ImportError:  # pragma: no cover
            from test_verify_input_allowlist import TRADERSYNC_CSV  # type: ignore[no-redef]

        app = create_app(_config(hosted=True), prefer_fastapi=False)
        self.addCleanup(app.verify_app.close)
        resp = VerifyApiTestClient(app).post(
            "/api/v1/verify",
            json={
                "broker_id": "tradersync",
                "raw_statement_text": TRADERSYNC_CSV,
                "disclose_leaf_names": ["capital_bracket"],
            },
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertIs(body["performance_withheld"], True)
        disclosed = {leaf["leaf_name"]: leaf["payload"] for leaf in body["proof_bundle"]["disclosed_leaves"]}
        self.assertIn("core_metrics", disclosed)
        self.assertIs(disclosed["core_metrics"].get("performance_withheld"), True)
        self.assertIn("capital_bracket", disclosed)

    def test_a_client_supplied_series_is_signed_only_in_test_configurations(self) -> None:
        request = {
            "broker_id": "schwab",
            "raw_account_id": "dummy-account",
            "nav_points": [
                {"timestamp_utc": "2026-01-01T00:00:00Z", "nav_base": 100_000.0},
                {"timestamp_utc": "2026-01-31T00:00:00Z", "nav_base": 160_000.0},
            ],
        }
        import dataclasses

        for overrides in ({}, {"allow_hosted_signing": True}):
            with self.subTest(overrides=sorted(overrides)):
                app = create_app(dataclasses.replace(_config(hosted=False), **overrides), prefer_fastapi=False)
                self.addCleanup(app.verify_app.close)
                resp = VerifyApiTestClient(app).post("/api/v1/verify", json=request)
                self.assertEqual(resp.status_code, 403, resp.text)
                self.assertEqual(resp.json()["error"], "signing_oracle_disabled")

        test_cfg = dataclasses.replace(_config(hosted=False), allow_client_supplied_series_for_tests=True)
        app = create_app(test_cfg, prefer_fastapi=False)
        self.addCleanup(app.verify_app.close)
        self.assertEqual(VerifyApiTestClient(app).post("/api/v1/verify", json=request).status_code, 200)


class MalformedVerifyFieldsTests(unittest.TestCase):
    """Self-hosted deployments still accept these fields; a malformed value is a 422."""

    def setUp(self) -> None:
        self.app = create_app(_config(hosted=False), pipeline_spec=_STAND_IN_SPEC, prefer_fastapi=False)
        self.client = VerifyApiTestClient(self.app)

    def tearDown(self) -> None:
        self.app.verify_app.close()

    def test_malformed_parent_read_fields_are_a_422(self) -> None:
        base = {"broker_id": "auto_detect", "raw_statement_text": SCHWAB_CSV}
        for field_name, value in (
            ("account_scope", "not_a_scope"),
            ("claimed_origin_assurance", "not_an_origin"),
            ("witness_attestations", 5),
            ("witness_attestations", [{"unexpected": True}]),
            ("witness_attestations", ["not-an-object"]),
            ("broker_native_signature", "not-an-object"),
            ("prospective_chain_link", {"unexpected": True}),
            ("period_start_utc", "not-a-time"),
            ("provider_approval_state", "not_a_state"),
            ("environment_tier", "not_a_tier"),
        ):
            with self.subTest(field=field_name, value=repr(value)):
                resp = self.client.post("/api/v1/verify", json={**base, field_name: value})
                self.assertEqual(resp.status_code, 422, resp.text)
                self.assertEqual(resp.json()["error"], "validation_error")


if __name__ == "__main__":
    unittest.main()
