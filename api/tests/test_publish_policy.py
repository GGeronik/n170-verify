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
        leaf_payloads: dict | None = None,
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
            leaf_payloads=leaf_payloads if leaf_payloads is not None else _build_leaf_payloads(),
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
            # The signed return matches the link's period return.
            leaf_payloads=_build_leaf_payloads(twr_decimal=link.period_twr_decimal),
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
            {**TestStartUpKeysAndSalt.HOSTED, "ALLOW_CALLER_CLOCK_FOR_TESTS": "true"},
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


def _tampered(bundle: VerifyProofBundle) -> dict:
    data = bundle.to_dict()
    sig = data["signature_hex"]
    data["signature_hex"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    return data


class TestBadSignatureIsReportedAsInvalid(_Base):
    hosted = True
    allow_clock = True

    def test_bad_signature_claiming_the_host_key_is_refused_as_invalid(self) -> None:
        bundle = self._host("prf-bad-signature")
        resp = self.client.post(
            "/api/v1/proofs", json={"proof_bundle": _tampered(bundle), "opt_in_leaderboard": True}
        )
        self.assertEqual(resp.status_code, 422, resp.text)
        self.assertEqual(resp.json()["error"], "invalid_proof_bundle")
        self.assertEqual(self.app.verify_app.store.total_row_counts()["proofs"], 0)

    def test_bad_signature_from_an_outside_key_is_still_refused(self) -> None:
        bundle = self._outside("prf-bad-signature-outside")
        resp = self.client.post(
            "/api/v1/proofs", json={"proof_bundle": _tampered(bundle), "opt_in_leaderboard": True}
        )
        self.assertEqual(resp.status_code, 422, resp.text)
        self.assertEqual(self.app.verify_app.store.total_row_counts()["proofs"], 0)

    def test_bad_signature_on_chain_enrolment_is_refused_as_invalid(self) -> None:
        b0 = self._chain_bundle("prf-bad-sig-chain-0", self._genesis_link("chn-bad-sig", TAG_C), outside=False)
        resp = self.client.post(
            "/api/v1/chains",
            json={"proof_bundle": _tampered(b0), "now_utc": "2026-01-31T12:05:00Z"},
        )
        self.assertEqual(resp.status_code, 422, resp.text)
        self.assertEqual(resp.json()["error"], "invalid_proof_bundle")
        self.assertEqual(
            self.app.verify_app.store.total_row_counts(), {"proofs": 0, "chains": 0, "continuity_log": 0}
        )


def _holder_claim(bundle: VerifyProofBundle, name: str, *, break_signature: bool = False) -> dict:
    from n170_verify.contracts.proof import HOLDER_SCHEMA_VERSION, SIGNING_DOMAIN_HOLDER
    from n170_verify.crypto.canonical import jcs_canonicalize
    from n170_verify.crypto.signing import ed25519_sign_domain

    kp = generate_ed25519_keypair(bytes.fromhex("41" * 32))
    claim = {
        "claimed_at_utc": "2026-02-10T12:00:00Z",
        "display_name": name,
        "handle": None,
        "holder_public_key_hex": kp.public_key_hex,
        "merkle_root": bundle.merkle_root,
        "profile_url": None,
        "proof_hash": bundle.proof_hash(),
        "proof_id": bundle.proof_id,
        "schema_version": HOLDER_SCHEMA_VERSION,
    }
    claim["signature_hex"] = ed25519_sign_domain(
        kp.private_key_hex, SIGNING_DOMAIN_HOLDER, jcs_canonicalize(claim)
    )
    if break_signature:
        sig = claim["signature_hex"]
        claim["signature_hex"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    return claim


class TestInvalidHolderClaimIsNotPublished(_Base):
    hosted = True
    allow_clock = True

    def test_record_with_an_invalid_holder_claim_is_refused(self) -> None:
        bundle = self._host("prf-holder-invalid")
        data = bundle.to_dict()
        data["holder_identity"] = _holder_claim(bundle, "Someone", break_signature=True)
        resp = self.client.post("/api/v1/proofs", json={"proof_bundle": data, "opt_in_leaderboard": True})
        self.assertEqual(resp.status_code, 422, resp.text)
        self.assertEqual(resp.json()["error"], "invalid_proof_bundle")
        self.assertTrue(any("holder" in e.lower() for e in resp.json()["errors"]), resp.text)
        self.assertEqual(self.app.verify_app.store.total_row_counts()["proofs"], 0)

    def test_a_holder_name_with_a_format_character_is_refused(self) -> None:
        # A right-to-left override and a zero-width space, assembled at run time.
        for n, name in enumerate(("‮" + "deifirev", "Ana Trader" + "‮", "Ana" + "​" + "Trader")):
            with self.subTest(name=repr(name)):
                bundle = self._host(f"prf-holder-format-{n}")
                data = bundle.to_dict()
                data["holder_identity"] = _holder_claim(bundle, name)
                resp = self.client.post("/api/v1/proofs", json={"proof_bundle": data, "opt_in_leaderboard": True})
                self.assertEqual(resp.status_code, 422, resp.text)
                self.assertEqual(resp.json()["error"], "invalid_proof_bundle")
        self.assertEqual(self.app.verify_app.store.total_row_counts()["proofs"], 0)

    def test_chain_enrolment_with_an_invalid_holder_claim_is_refused(self) -> None:
        b0 = self._chain_bundle("prf-holder-chain-0", self._genesis_link("chn-holder", TAG_C), outside=False)
        data = b0.to_dict()
        data["holder_identity"] = _holder_claim(b0, "Someone", break_signature=True)
        resp = self.client.post(
            "/api/v1/chains", json={"proof_bundle": data, "now_utc": "2026-01-31T12:05:00Z"}
        )
        self.assertEqual(resp.status_code, 422, resp.text)
        self.assertEqual(resp.json()["error"], "invalid_proof_bundle")
        self.assertEqual(
            self.app.verify_app.store.total_row_counts(), {"proofs": 0, "chains": 0, "continuity_log": 0}
        )

    def test_chain_append_with_an_invalid_holder_claim_is_refused(self) -> None:
        b0 = self._chain_bundle("prf-holder-app-0", self._genesis_link("chn-holder-app", TAG_C), outside=False)
        enrol = self.client.post(
            "/api/v1/chains", json={"proof_bundle": b0.to_dict(), "now_utc": "2026-01-31T12:05:00Z"}
        )
        self.assertEqual(enrol.status_code, 201, enrol.text)
        b1 = self._chain_bundle(
            "prf-holder-app-1", self._next_link("chn-holder-app", TAG_C, b0.proof_hash()), outside=False
        )
        data = b1.to_dict()
        data["holder_identity"] = _holder_claim(b1, "Someone", break_signature=True)
        resp = self.client.post(
            "/api/v1/chains/chn-holder-app/append",
            json={"proof_bundle": data, "now_utc": "2026-03-02T12:05:00Z"},
        )
        self.assertEqual(resp.status_code, 422, resp.text)
        self.assertEqual(resp.json()["error"], "invalid_proof_bundle")
        self.assertEqual(self.app.verify_app.store.total_row_counts()["proofs"], 1)

    def test_record_with_no_or_a_self_asserted_holder_claim_publishes(self) -> None:
        plain = self._host("prf-holder-none", tag=TAG_A)
        named = self._host("prf-holder-named", tag=TAG_B)
        named_data = named.to_dict()
        named_data["holder_identity"] = _holder_claim(named, "Alice Owner")
        for data, status in ((plain.to_dict(), "absent"), (named_data, "self_asserted")):
            resp = self.client.post("/api/v1/proofs", json={"proof_bundle": data})
            self.assertEqual(resp.status_code, 201, resp.text)
            self.assertEqual(resp.json()["verification"]["holder_claim_status"], status)


def _withheld_leaves(**core_overrides) -> dict:
    leaves = _build_leaf_payloads()
    leaves["core_metrics"] = {**leaves["core_metrics"], **core_overrides}
    return leaves


class TestCohortListRanksOnlyComputedReturns(_Base):
    hosted = True

    def _publish(self, bundle: VerifyProofBundle) -> None:
        resp = self.client.post(
            "/api/v1/proofs", json={"proof_bundle": bundle.to_dict(), "opt_in_leaderboard": True}
        )
        self.assertEqual(resp.status_code, 201, resp.text)

    def _listed_ids(self) -> set[str]:
        resp = self.client.get("/api/v1/leaderboard?include_private_bracket=1&min_capital_bracket=under_1k")
        self.assertEqual(resp.status_code, 200, resp.text)
        return {row["proof_id"] for row in resp.json()["entries"]}

    def test_withheld_or_zero_observation_returns_are_not_listed(self) -> None:
        self._publish(self._host("prf-computed", tag=TAG_A))
        self._publish(
            self._host(
                "prf-withheld",
                tag=TAG_B,
                leaf_payloads=_withheld_leaves(
                    twr_decimal=0.0, twr_pct=0.0, observation_count=0, performance_withheld=True
                ),
            )
        )
        self._publish(
            self._host("prf-zero-observations", tag=TAG_C, leaf_payloads=_withheld_leaves(observation_count=0))
        )
        self._publish(
            self._host(
                "prf-withheld-flag-only",
                tag="15" * 32,
                leaf_payloads=_withheld_leaves(performance_withheld=True),
            )
        )
        self.assertEqual(self._listed_ids(), {"prf-computed"})


class TestHostedListingShowsOnlyRegistrySigners(unittest.TestCase):
    def _config(self, db_path: str, *, hosted: bool) -> ApiConfig:
        return ApiConfig(
            publisher_keypair=generate_ed25519_keypair(bytes.fromhex("11" * 32)),
            publisher_kid=HOST_KID,
            publisher_key_not_before_utc="2025-01-01T00:00:00Z",
            hosted_multi_user_mode=hosted,
            db_path=db_path,
            sync_db_path=":memory:",
            vault_master_kek_hex="aa" * 32,
            account_blinding_salt_hex="bb" * 32,
        )

    def test_rows_from_other_signers_already_stored_are_not_listed_in_hosted_mode(self) -> None:
        outside_kp = generate_ed25519_keypair(bytes.fromhex("33" * 32))
        host_kp = generate_ed25519_keypair(bytes.fromhex("11" * 32))

        def make(proof_id: str, kid: str, key_hex: str, tag: str) -> dict:
            return create_signed_proof_bundle(
                proof_id=proof_id,
                issued_at_utc="2026-02-10T12:00:00Z",
                publisher_kid=kid,
                publisher_private_key_hex=key_hex,
                broker_id="schwab",
                blinded_account_tag=tag,
                account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
                provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
                environment_tier=EnvironmentTier.LIVE_PRODUCTION,
                claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
                source_body_sha256="34" * 32,
                period_start_utc="2026-01-01T00:00:00Z",
                period_end_utc="2026-02-10T00:00:00Z",
                base_currency="USD",
                leaf_payloads=_build_leaf_payloads(),
            ).to_dict()

        path = "/api/v1/leaderboard?include_private_bracket=1&min_capital_bracket=under_1k"
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "proofs.sqlite3")
            # Rows written while the store ran self-hosted (or before the publish rule).
            self_hosted = create_app(self._config(db_path, hosted=False), prefer_fastapi=False)
            sh_client = VerifyApiTestClient(self_hosted)
            for proof_id, kid, key_hex, tag in (
                ("prf-stored-outside", "self-hosted-kid", outside_kp.private_key_hex, TAG_A),
                ("prf-stored-host", HOST_KID, host_kp.private_key_hex, TAG_B),
            ):
                resp = sh_client.post(
                    "/api/v1/proofs",
                    json={"proof_bundle": make(proof_id, kid, key_hex, tag), "opt_in_leaderboard": True},
                )
                self.assertEqual(resp.status_code, 201, resp.text)
            sh_ids = {row["proof_id"] for row in sh_client.get(path).json()["entries"]}
            self.assertEqual(sh_ids, {"prf-stored-outside", "prf-stored-host"})
            self_hosted.verify_app.close()

            hosted = create_app(self._config(db_path, hosted=True), prefer_fastapi=False)
            try:
                rows = VerifyApiTestClient(hosted).get(path).json()["entries"]
            finally:
                hosted.verify_app.close()
        self.assertEqual([row["proof_id"] for row in rows], ["prf-stored-host"])
        self.assertEqual(rows[0]["signer_trust_status"], "official_n170_hosted")


class TestStatementUploadPublishRefusalKeepsItsStatus(unittest.TestCase):
    def test_upload_publish_refused_by_the_registry_rule_answers_with_its_own_status(self) -> None:
        try:
            from tests.test_viral_routes import SYNTHETIC_LIVE_IBKR_FLEX_XML
        except ImportError:
            from test_viral_routes import SYNTHETIC_LIVE_IBKR_FLEX_XML
        cfg = ApiConfig(
            publisher_keypair=generate_ed25519_keypair(bytes.fromhex("11" * 32)),
            publisher_kid=HOST_KID,
            # The host key is valid only from 2027-01-01, so a record issued
            # earlier (after the statement it describes) is not one this registry recognises.
            publisher_key_not_before_utc="2027-01-01T00:00:00Z",
            hosted_multi_user_mode=True,
            allow_caller_clock_for_tests=True,
            db_path=":memory:",
            sync_db_path=":memory:",
            vault_master_kek_hex="aa" * 32,
            account_blinding_salt_hex="bb" * 32,
        )
        app = create_app(cfg, prefer_fastapi=False)
        try:
            resp = VerifyApiTestClient(app).post(
                "/api/v1/verify/auto-detect",
                json={
                    "raw_statement_text": SYNTHETIC_LIVE_IBKR_FLEX_XML,
                    "filename": "ibkr_activity_2026.xml",
                    "issued_at_utc": "2026-12-31T12:00:00Z",
                    "publish_proof": True,
                    "opt_in_leaderboard": True,
                },
            )
            self.assertEqual(resp.status_code, 403, resp.text)
            self.assertEqual(resp.json()["error"], "publisher_key_not_in_registry")
            self.assertEqual(app.verify_app.store.total_row_counts()["proofs"], 0)
        finally:
            app.verify_app.close()


class TestStartUpKeysAndSalt(unittest.TestCase):
    # Hosted start-up needs the account salt, the vault key and a signing seed.
    SALT = {"N170_VERIFY_ACCOUNT_SALT_HEX": "cd" * 32, "N170_VERIFY_VAULT_KEK_HEX": "ef" * 32}
    HOSTED = {**SALT, "N170_VERIFY_SIGNING_SEED_HEX": "42" * 32}

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
        no_salt = {k: v for k, v in self.HOSTED.items() if k != "N170_VERIFY_ACCOUNT_SALT_HEX"}
        for env in (no_salt, {**no_salt, "N170_VERIFY_HOSTED_MODE": "true"}):
            with self.subTest(env=sorted(env)):
                with mock.patch.dict(os.environ, env, clear=True):
                    with self.assertRaises(RuntimeError) as ctx:
                        ApiConfig.from_env()
                self.assertIn("N170_VERIFY_ACCOUNT_SALT_HEX", str(ctx.exception))

    def test_hosted_mode_uses_the_configured_salt(self) -> None:
        with mock.patch.dict(os.environ, self.HOSTED, clear=True):
            cfg = ApiConfig.from_env()
        self.assertEqual(cfg.account_blinding_salt_hex, "cd" * 32)

    def test_hosted_mode_without_a_signing_seed_stops_start_up(self) -> None:
        env = {k: v for k, v in self.HOSTED.items() if k != "N170_VERIFY_SIGNING_SEED_HEX"}
        for extra in ({}, {"N170_VERIFY_HOSTED_MODE": "true"}):
            with self.subTest(extra=extra):
                with mock.patch.dict(os.environ, {**env, **extra}, clear=True):
                    with self.assertRaises(RuntimeError) as ctx:
                        ApiConfig.from_env()
                self.assertIn("N170_VERIFY_SIGNING_SEED", str(ctx.exception))

    def test_hosted_mode_without_the_vault_key_stops_start_up(self) -> None:
        env = {k: v for k, v in self.HOSTED.items() if k != "N170_VERIFY_VAULT_KEK_HEX"}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(RuntimeError) as ctx:
                ApiConfig.from_env()
        self.assertIn("N170_VERIFY_VAULT_KEK_HEX", str(ctx.exception))

    def test_hosted_mode_setting_accepts_only_true_or_false(self) -> None:
        for raw, expected in (("true", True), (" TRUE ", True), ("False", False), ("false", False)):
            with self.subTest(raw=raw):
                with mock.patch.dict(os.environ, {**self.HOSTED, "N170_VERIFY_HOSTED_MODE": raw}, clear=True):
                    self.assertIs(ApiConfig.from_env().hosted_multi_user_mode, expected)
        for raw in ("ture", "1", "yes", "on", "0", "off", "no"):
            with self.subTest(raw=raw):
                with mock.patch.dict(os.environ, {**self.HOSTED, "N170_VERIFY_HOSTED_MODE": raw}, clear=True):
                    with self.assertRaises(ValueError) as ctx:
                        ApiConfig.from_env()
                self.assertIn("N170_VERIFY_HOSTED_MODE", str(ctx.exception))

    def test_site_origin_is_read_and_validated(self) -> None:
        with mock.patch.dict(os.environ, self.HOSTED, clear=True):
            self.assertEqual(ApiConfig.from_env().site_origin, "")
        for good in ("https://verify.example.org", "http://localhost:3000", "https://verify.example.org/"):
            with self.subTest(good=good):
                with mock.patch.dict(os.environ, {**self.HOSTED, "N170_VERIFY_SITE_ORIGIN": good}, clear=True):
                    self.assertEqual(ApiConfig.from_env().site_origin, good.rstrip("/"))
        for bad in (
            "verify.example.org",
            "ftp://verify.example.org",
            "https://verify.example.org/path",
            "https://verify.example.org?x=1",
            "https://verify.example.org#frag",
            "https://someone@verify.example.org",
            "https://",
        ):
            with self.subTest(bad=bad):
                with mock.patch.dict(os.environ, {**self.HOSTED, "N170_VERIFY_SITE_ORIGIN": bad}, clear=True):
                    with self.assertRaises(ValueError) as ctx:
                        ApiConfig.from_env()
                self.assertIn("N170_VERIFY_SITE_ORIGIN", str(ctx.exception))

    def test_a_personal_snaptrade_client_id_with_a_build_mode_override_stops_start_up(self) -> None:
        try:
            from tests.test_snaptrade_session_binding import PERSONAL_CLIENT_ID
        except ImportError:
            from test_snaptrade_session_binding import PERSONAL_CLIENT_ID
        for client_id in (PERSONAL_CLIENT_ID, PERSONAL_CLIENT_ID.lower()):
            for mode in ("commercial", "build", "developer_5_slot", " Build "):
                with self.subTest(client_id=client_id, mode=mode):
                    env = {**self.HOSTED, "SNAPTRADE_CLIENT_ID": client_id, "SNAPTRADE_AUTH_MODE": mode}
                    with mock.patch.dict(os.environ, env, clear=True):
                        with self.assertRaises(RuntimeError) as ctx:
                            ApiConfig.from_env()
                    self.assertIn("SNAPTRADE_AUTH_MODE", str(ctx.exception))
        for mode in ("auto", "personal"):
            env = {**self.HOSTED, "SNAPTRADE_CLIENT_ID": PERSONAL_CLIENT_ID, "SNAPTRADE_AUTH_MODE": mode}
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(ApiConfig.from_env().snaptrade_client_id, PERSONAL_CLIENT_ID)

    def test_self_hosted_mode_without_salt_still_starts(self) -> None:
        with mock.patch.dict(os.environ, {"N170_VERIFY_HOSTED_MODE": "false"}, clear=True):
            cfg = ApiConfig.from_env()
        self.assertFalse(cfg.hosted_multi_user_mode)
        self.assertEqual(len(cfg.account_blinding_salt_hex), 64)


if __name__ == "__main__":
    unittest.main()
