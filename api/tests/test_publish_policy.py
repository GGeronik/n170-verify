"""Publishing policy of the hosted store, the verification clock, and start-up keys.

* The hosted store publishes only records signed by a key in its own registry.
  A self-hosted store (hosted mode off) keeps accepting other signers.
* The host sets the verification clock itself. A caller-supplied ``now_utc``
  (or issue time on the statement upload) is refused unless the test-only
  setting ``allow_caller_clock_for_tests`` is on.
* A configured signing seed file that yields no seed stops start-up, and hosted
  mode requires the account salt instead of inventing one.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from n170_verify.contracts import (
    AccountScope,
    CapitalBracket,
    EnvironmentTier,
    OriginAssurance,
    ProviderApprovalState,
    VerifyProofBundle,
    create_signed_proof_bundle,
)
from n170_verify.crypto import (
    ChainCadencePolicy,
    ProspectiveChainLink,
    PublisherKeyRecord,
    generate_ed25519_keypair,
)

try:
    from tests.test_api_lifecycle_and_security import _build_leaf_payloads
except ImportError:  # run with api/tests on the path, as CI does
    from test_api_lifecycle_and_security import _build_leaf_payloads

HOST_KID = "n170-active-2026"
EXTRA_KID = "n170-second-2026"
TAG_A = "12" * 32
TAG_B = "13" * 32
TAG_C = "14" * 32


def _leaderboard_counts(client: VerifyApiTestClient) -> dict[str, int]:
    counts: dict[str, int] = {}
    for bracket in CapitalBracket:
        resp = client.get(
            "/api/v1/leaderboard?include_private_bracket=1&min_capital_bracket=" + bracket.value
        )
        assert resp.status_code == 200, resp.text
        counts[bracket.value] = int(resp.json()["count"])
    return counts


class _Base(unittest.TestCase):
    hosted = True
    allow_clock = False

    def setUp(self) -> None:
        self.host_kp = generate_ed25519_keypair(bytes.fromhex("11" * 32))
        self.extra_kp = generate_ed25519_keypair(bytes.fromhex("22" * 32))
        self.outside_kp = generate_ed25519_keypair(bytes.fromhex("33" * 32))
        self.config = ApiConfig(
            publisher_keypair=self.host_kp,
            publisher_kid=HOST_KID,
            publisher_key_not_before_utc="2025-01-01T00:00:00Z",
            additional_registry_keys=[
                PublisherKeyRecord(
                    publisher_kid=EXTRA_KID,
                    public_key_hex=self.extra_kp.public_key_hex,
                    status="active",
                    not_before_utc="2025-01-01T00:00:00Z",
                )
            ],
            hosted_multi_user_mode=self.hosted,
            allow_caller_clock_for_tests=self.allow_clock,
            db_path=":memory:",
            sync_db_path=":memory:",
            vault_master_kek_hex="aa" * 32,
            account_blinding_salt_hex="bb" * 32,
        )
        self.app = create_app(self.config, prefer_fastapi=False)
        self.client = VerifyApiTestClient(self.app)

    def tearDown(self) -> None:
        self.app.verify_app.close()

    def _bundle(
        self,
        proof_id: str,
        *,
        kid: str,
        private_key_hex: str,
        tag: str = TAG_A,
        link: ProspectiveChainLink | None = None,
        issued_at_utc: str = "2026-02-10T12:00:00Z",
        period_start_utc: str = "2026-01-01T00:00:00Z",
        period_end_utc: str = "2026-02-10T00:00:00Z",
    ) -> VerifyProofBundle:
        return create_signed_proof_bundle(
            proof_id=proof_id,
            issued_at_utc=issued_at_utc,
            publisher_kid=kid,
            publisher_private_key_hex=private_key_hex,
            broker_id="schwab",
            blinded_account_tag=tag,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="34" * 32,
            period_start_utc=period_start_utc,
            period_end_utc=period_end_utc,
            base_currency="USD",
            leaf_payloads=_build_leaf_payloads(),
            prospective_chain_link=link,
        )

    def _outside(self, proof_id: str, **kw) -> VerifyProofBundle:
        return self._bundle(
            proof_id, kid="self-hosted-kid", private_key_hex=self.outside_kp.private_key_hex, **kw
        )

    def _host(self, proof_id: str, **kw) -> VerifyProofBundle:
        return self._bundle(proof_id, kid=HOST_KID, private_key_hex=self.host_kp.private_key_hex, **kw)

    @staticmethod
    def _genesis_link(chain_id: str, tag: str) -> ProspectiveChainLink:
        return ProspectiveChainLink(
            chain_id=chain_id,
            sequence_number=0,
            prev_proof_hash=None,
            blinded_account_tag=tag,
            enrolled_at_utc="2026-01-01T06:00:00Z",
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            issued_at_utc="2026-01-31T12:00:00Z",
            cadence_policy=ChainCadencePolicy(
                expected_interval_seconds=30 * 86400, grace_window_seconds=5 * 86400
            ),
            beginning_index_value=100.0,
            ending_index_value=110.0,
            period_twr_decimal=0.10,
        )

    @staticmethod
    def _next_link(chain_id: str, tag: str, prev_hash: str) -> ProspectiveChainLink:
        return ProspectiveChainLink(
            chain_id=chain_id,
            sequence_number=1,
            prev_proof_hash=prev_hash,
            blinded_account_tag=tag,
            enrolled_at_utc="2026-01-01T06:00:00Z",
            period_start_utc="2026-01-31T00:00:00Z",
            period_end_utc="2026-03-02T00:00:00Z",
            issued_at_utc="2026-03-02T12:00:00Z",
            cadence_policy=ChainCadencePolicy(
                expected_interval_seconds=30 * 86400, grace_window_seconds=5 * 86400
            ),
            beginning_index_value=110.0,
            ending_index_value=121.0,
            period_twr_decimal=0.10,
        )

    def _chain_bundle(self, proof_id: str, link: ProspectiveChainLink, *, outside: bool) -> VerifyProofBundle:
        make = self._outside if outside else self._host
        return make(
            proof_id,
            tag=link.blinded_account_tag,
            link=link,
            issued_at_utc=link.issued_at_utc,
            period_start_utc=link.period_start_utc,
            period_end_utc=link.period_end_utc,
        )


class TestHostedStorePublishesOnlyRegistrySigners(_Base):
    hosted = True
    allow_clock = True  # chain timing below needs a fixed clock

    def test_record_signed_by_a_key_outside_the_registry_is_refused_and_never_listed(self) -> None:
        bundle = self._outside("prf-outside-signer")
        resp = self.client.post(
            "/api/v1/proofs", json={"proof_bundle": bundle.to_dict(), "opt_in_leaderboard": True}
        )
        self.assertEqual(resp.status_code, 403, resp.text)
        self.assertEqual(resp.json()["error"], "publisher_key_not_in_registry")
        self.assertEqual(self.client.get("/api/v1/proofs/prf-outside-signer").status_code, 404)
        self.assertEqual(self.app.verify_app.store.total_row_counts()["proofs"], 0)
        self.assertEqual(set(_leaderboard_counts(self.client).values()), {0})

    def test_records_signed_by_the_host_key_or_another_registry_key_still_publish(self) -> None:
        own = self._host("prf-host-signed", tag=TAG_A)
        extra = self._bundle(
            "prf-extra-signed", kid=EXTRA_KID, private_key_hex=self.extra_kp.private_key_hex, tag=TAG_B
        )
        for bundle in (own, extra):
            resp = self.client.post(
                "/api/v1/proofs", json={"proof_bundle": bundle.to_dict(), "opt_in_leaderboard": True}
            )
            self.assertEqual(resp.status_code, 201, resp.text)
            self.assertEqual(resp.json()["verification"]["signer_trust_status"], "official_n170_hosted")
        self.assertEqual(_leaderboard_counts(self.client)["under_1k"], 2)

    def test_chain_enrolment_by_a_key_outside_the_registry_is_refused(self) -> None:
        b0 = self._chain_bundle("prf-outside-chain-0", self._genesis_link("chn-outside", TAG_C), outside=True)
        resp = self.client.post(
            "/api/v1/chains",
            json={"proof_bundle": b0.to_dict(), "opt_in_leaderboard": True, "now_utc": "2026-01-31T12:05:00Z"},
        )
        self.assertEqual(resp.status_code, 403, resp.text)
        self.assertEqual(resp.json()["error"], "publisher_key_not_in_registry")
        self.assertEqual(
            self.app.verify_app.store.total_row_counts(), {"proofs": 0, "chains": 0, "continuity_log": 0}
        )

    def test_chain_append_by_a_key_outside_the_registry_is_refused(self) -> None:
        b0 = self._chain_bundle("prf-mixed-chain-0", self._genesis_link("chn-mixed", TAG_C), outside=False)
        enrol = self.client.post(
            "/api/v1/chains",
            json={"proof_bundle": b0.to_dict(), "now_utc": "2026-01-31T12:05:00Z"},
        )
        self.assertEqual(enrol.status_code, 201, enrol.text)
        b1 = self._chain_bundle(
            "prf-mixed-chain-1", self._next_link("chn-mixed", TAG_C, b0.proof_hash()), outside=True
        )
        resp = self.client.post(
            "/api/v1/chains/chn-mixed/append",
            json={"proof_bundle": b1.to_dict(), "opt_in_leaderboard": True, "now_utc": "2026-03-02T12:05:00Z"},
        )
        self.assertEqual(resp.status_code, 403, resp.text)
        self.assertEqual(resp.json()["error"], "publisher_key_not_in_registry")
        self.assertEqual(
            self.app.verify_app.store.total_row_counts(), {"proofs": 1, "chains": 1, "continuity_log": 1}
        )

    def test_checking_a_record_from_another_signer_still_reports_it(self) -> None:
        bundle = self._outside("prf-outside-check")
        resp = self.client.post("/api/v1/proofs/verify", json={"proof_bundle": bundle.to_dict()})
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["signer_trust_status"], "unrecognized_self_hosted_signer")


class TestSelfHostedStoreKeepsAcceptingOtherSigners(_Base):
    hosted = False

    def test_self_hosted_store_publishes_a_record_from_another_signer(self) -> None:
        bundle = self._outside("prf-self-hosted-outside")
        resp = self.client.post(
            "/api/v1/proofs", json={"proof_bundle": bundle.to_dict(), "opt_in_leaderboard": True}
        )
        self.assertEqual(resp.status_code, 201, resp.text)
        self.assertEqual(
            resp.json()["verification"]["signer_trust_status"], "unrecognized_self_hosted_signer"
        )


class TestHostSetsTheVerificationClock(_Base):
    hosted = True
    allow_clock = False

    def _assert_clock_refused(self, resp) -> None:
        self.assertEqual(resp.status_code, 400, resp.text)
        self.assertEqual(resp.json()["error"], "caller_clock_not_accepted")

    def test_flag_is_off_by_default_and_not_read_from_the_environment(self) -> None:
        self.assertFalse(ApiConfig().allow_caller_clock_for_tests)
        with mock.patch.dict(
            os.environ,
            {"N170_VERIFY_ACCOUNT_SALT_HEX": "cd" * 32, "ALLOW_CALLER_CLOCK_FOR_TESTS": "true"},
            clear=True,
        ):
            self.assertFalse(ApiConfig.from_env().allow_caller_clock_for_tests)

    def test_json_routes_refuse_a_caller_clock_and_store_nothing(self) -> None:
        bundle = self._host("prf-clock-post")
        link_bundle = self._chain_bundle("prf-clock-chain-0", self._genesis_link("chn-clock", TAG_C), outside=False)
        self._assert_clock_refused(
            self.client.post(
                "/api/v1/proofs",
                json={"proof_bundle": bundle.to_dict(), "now_utc": "2026-02-10T12:05:00Z"},
            )
        )
        self._assert_clock_refused(
            self.client.post(
                "/api/v1/proofs/verify",
                json={"proof_bundle": bundle.to_dict(), "now_utc": "2026-02-10T12:05:00Z"},
            )
        )
        self._assert_clock_refused(
            self.client.post(
                "/api/v1/chains",
                json={"proof_bundle": link_bundle.to_dict(), "now_utc": "2026-01-31T12:05:00Z"},
            )
        )
        self._assert_clock_refused(
            self.client.post(
                "/api/v1/chains/chn-clock/append",
                json={"proof_bundle": link_bundle.to_dict(), "now_utc": "2026-01-31T12:05:00Z"},
            )
        )
        self.assertEqual(
            self.app.verify_app.store.total_row_counts(), {"proofs": 0, "chains": 0, "continuity_log": 0}
        )

    def test_query_routes_refuse_a_caller_clock(self) -> None:
        bundle = self._host("prf-clock-get")
        stored = self.client.post("/api/v1/proofs", json={"proof_bundle": bundle.to_dict()})
        self.assertEqual(stored.status_code, 201, stored.text)
        q = "now_utc=2030-01-01T00:00:00Z"
        for path in (
            f"/api/v1/leaderboard?{q}",
            f"/api/v1/chains/chn-none?{q}",
            f"/api/v1/vs/prf-clock-get/prf-clock-get?{q}",
            f"/api/v1/proofs/prf-clock-get/discord-embed?{q}",
            f"/api/v1/proofs/prf-clock-get/qr-payload?{q}",
        ):
            with self.subTest(path=path):
                self._assert_clock_refused(self.client.get(path))

    def test_statement_upload_refuses_a_caller_issue_time(self) -> None:
        resp = self.client.post(
            "/api/v1/verify/auto-detect",
            json={"raw_statement_text": "date,symbol\n", "issued_at_utc": "2030-01-01T00:00:00Z"},
        )
        self._assert_clock_refused(resp)

    def test_requests_without_a_caller_clock_are_unaffected(self) -> None:
        bundle = self._host("prf-clock-none")
        self.assertEqual(
            self.client.post("/api/v1/proofs", json={"proof_bundle": bundle.to_dict()}).status_code, 201
        )
        self.assertEqual(self.client.get("/api/v1/leaderboard").status_code, 200)


class TestCallerClockWithTestFlagOn(_Base):
    hosted = True
    allow_clock = True

    def test_flag_on_accepts_a_caller_clock(self) -> None:
        bundle = self._host("prf-clock-flag-on")
        resp = self.client.post(
            "/api/v1/proofs/verify",
            json={"proof_bundle": bundle.to_dict(), "now_utc": "2026-02-10T12:05:00Z"},
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(self.client.get("/api/v1/leaderboard?now_utc=2026-02-10T12:05:00Z").status_code, 200)


class TestStartUpKeysAndSalt(unittest.TestCase):
    SALT = {"N170_VERIFY_ACCOUNT_SALT_HEX": "cd" * 32}

    def test_configured_seed_file_that_does_not_exist_stops_start_up(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = os.path.join(tmpdir, "no_such_seed.hex")
            with mock.patch.dict(
                os.environ, {**self.SALT, "N170_VERIFY_SIGNING_SEED_FILE": missing}, clear=True
            ):
                with self.assertRaises(RuntimeError) as ctx:
                    ApiConfig.from_env()
        self.assertIn("N170_VERIFY_SIGNING_SEED_FILE", str(ctx.exception))

    def test_configured_seed_file_that_is_empty_stops_start_up(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            empty = os.path.join(tmpdir, "empty_seed.hex")
            with open(empty, "w", encoding="utf-8") as fh:
                fh.write("\n")
            with mock.patch.dict(
                os.environ, {**self.SALT, "N170_VERIFY_SIGNING_SEED_FILE": empty}, clear=True
            ):
                with self.assertRaises(RuntimeError):
                    ApiConfig.from_env()

    def test_configured_seed_file_is_used(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            seed = os.path.join(tmpdir, "seed.hex")
            with open(seed, "w", encoding="utf-8") as fh:
                fh.write("ab" * 32 + "\n")
            with mock.patch.dict(
                os.environ, {**self.SALT, "N170_VERIFY_SIGNING_SEED_FILE": seed}, clear=True
            ):
                cfg = ApiConfig.from_env()
        expected = generate_ed25519_keypair(bytes.fromhex("ab" * 32)).public_key_hex
        self.assertEqual(cfg.publisher_keypair.public_key_hex, expected)

    def test_hosted_mode_without_account_salt_stops_start_up(self) -> None:
        for env in ({}, {"N170_VERIFY_HOSTED_MODE": "true"}):
            with self.subTest(env=env):
                with mock.patch.dict(os.environ, env, clear=True):
                    with self.assertRaises(RuntimeError) as ctx:
                        ApiConfig.from_env()
                self.assertIn("N170_VERIFY_ACCOUNT_SALT_HEX", str(ctx.exception))

    def test_hosted_mode_uses_the_configured_salt(self) -> None:
        with mock.patch.dict(os.environ, self.SALT, clear=True):
            cfg = ApiConfig.from_env()
        self.assertEqual(cfg.account_blinding_salt_hex, "cd" * 32)

    def test_self_hosted_mode_without_salt_still_starts(self) -> None:
        with mock.patch.dict(os.environ, {"N170_VERIFY_HOSTED_MODE": "false"}, clear=True):
            cfg = ApiConfig.from_env()
        self.assertFalse(cfg.hosted_multi_user_mode)
        self.assertEqual(len(cfg.account_blinding_salt_hex), 64)


if __name__ == "__main__":
    unittest.main()
