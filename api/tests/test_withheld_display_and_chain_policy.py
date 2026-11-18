"""Withheld returns are never shown as numbers, and continuity chains hold only links tied to their record.

* Every surface that renders a stored record (badge, Discord and Telegram text,
  QR share cards, head-to-head) says the return is withheld when it was not
  computed, and never shows a number for it. The cohort list ranks only a
  disclosed, Merkle-proven, computed return.
* A chain link must agree with the record that carries it (issue time, period,
  account tag, return), and in hosted mode a record from a public address
  without proof of ownership is not enrolled in a chain.
* A repeated post of a published record answers with the stored record and its
  own verification; publishing a chain-linked record and then enrolling it is a
  conflict, not a server error.
* The statement upload says when the return was withheld.
"""

from __future__ import annotations

import unittest

from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from app.store import ProofStore
from n170_verify.contracts import (
    AccountScope,
    EnvironmentTier,
    OriginAssurance,
    ProviderApprovalState,
    VerifyProofBundle,
    create_signed_proof_bundle,
)
from n170_verify.crypto import (
    ChainCadencePolicy,
    ProspectiveChainLink,
    generate_ed25519_keypair,
)

try:
    from tests.test_api_lifecycle_and_security import _build_leaf_payloads
    from tests.test_publish_policy import _holder_claim
    from tests.test_viral_routes import SYNTHETIC_LIVE_IBKR_FLEX_XML
except ImportError:  # run with api/tests on the path, as CI does
    from test_api_lifecycle_and_security import _build_leaf_payloads
    from test_publish_policy import _holder_claim
    from test_viral_routes import SYNTHETIC_LIVE_IBKR_FLEX_XML

HOST_KID = "n170-active-2026"
LEADERBOARD_ALL = "/api/v1/leaderboard?include_private_bracket=1&min_capital_bracket=under_1k"
ALL_LEAVES = [
    "core_metrics",
    "indexed_curve",
    "reconciliation",
    "coaching_and_context",
    "capital_bracket",
    "benchmark_alpha",
    "delayed_closed_trades",
]
WITHHELD_REASON = "At least two NAV observations are required to compute portfolio returns."


def _tag(n: int) -> str:
    return f"{n:064x}"


def _withheld_core(**extra) -> dict:
    leaves = _build_leaf_payloads()
    leaves["core_metrics"] = {
        **leaves["core_metrics"],
        "twr_decimal": 0.0,
        "twr_pct": 0.0,
        "observation_count": 0,
        **extra,
    }
    return leaves


class _Case(unittest.TestCase):
    hosted = True

    def setUp(self) -> None:
        self.kp = generate_ed25519_keypair(bytes.fromhex("11" * 32))
        self.config = ApiConfig(
            publisher_keypair=self.kp,
            publisher_kid=HOST_KID,
            publisher_key_not_before_utc="2025-01-01T00:00:00Z",
            hosted_multi_user_mode=self.hosted,
            allow_caller_clock_for_tests=True,
            db_path=":memory:",
            sync_db_path=":memory:",
            vault_master_kek_hex="aa" * 32,
            account_blinding_salt_hex="bb" * 32,
        )
        self.app = create_app(self.config, prefer_fastapi=False)
        self.client = VerifyApiTestClient(self.app)

    def tearDown(self) -> None:
        self.app.verify_app.close()

    def _counts(self) -> dict[str, int]:
        return self.app.verify_app.store.total_row_counts()

    def _bundle(
        self,
        proof_id: str,
        *,
        tag: str,
        leaves: dict | None = None,
        disclose: list[str] | None = None,
        link: ProspectiveChainLink | None = None,
        issued_at_utc: str = "2026-02-10T12:00:00Z",
        period_start_utc: str = "2026-01-01T00:00:00Z",
        period_end_utc: str = "2026-02-10T00:00:00Z",
        approval: ProviderApprovalState = ProviderApprovalState.APPROVED_LIVE,
    ) -> VerifyProofBundle:
        return create_signed_proof_bundle(
            proof_id=proof_id,
            issued_at_utc=issued_at_utc,
            publisher_kid=HOST_KID,
            publisher_private_key_hex=self.kp.private_key_hex,
            broker_id="schwab",
            blinded_account_tag=tag,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=approval,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="34" * 32,
            period_start_utc=period_start_utc,
            period_end_utc=period_end_utc,
            base_currency="USD",
            leaf_payloads=leaves if leaves is not None else _build_leaf_payloads(),
            disclose_leaf_names=disclose,
            prospective_chain_link=link,
        )

    def _publish(self, bundle: VerifyProofBundle, *, opt_in: bool = True):
        resp = self.client.post(
            "/api/v1/proofs", json={"proof_bundle": bundle.to_dict(), "opt_in_leaderboard": opt_in}
        )
        self.assertEqual(resp.status_code, 201, resp.text)
        return resp


class TestWithheldReturnIsNeverShownAsANumber(_Case):
    def setUp(self) -> None:
        super().setUp()
        self._publish(
            self._bundle(
                "prf-withheld",
                tag=_tag(1),
                leaves=_withheld_core(performance_withheld=True, withheld_reasons=[WITHHELD_REASON]),
            )
        )
        self._publish(self._bundle("prf-zero-obs", tag=_tag(2), leaves=_withheld_core()))
        self._publish(self._bundle("prf-computed", tag=_tag(3)))

    def test_badge_says_withheld(self) -> None:
        for pid in ("prf-withheld", "prf-zero-obs"):
            with self.subTest(pid=pid):
                resp = self.client.get(f"/api/v1/badges/{pid}.svg")
                self.assertEqual(resp.status_code, 200)
                self.assertNotIn("+0.00%", resp.text)
                self.assertIn("withheld", resp.text.lower())
        self.assertIn("+8.00%", self.client.get("/api/v1/badges/prf-computed.svg").text)

    def test_discord_and_telegram_text_say_withheld_without_a_number(self) -> None:
        for pid in ("prf-withheld", "prf-zero-obs"):
            with self.subTest(pid=pid):
                resp = self.client.get(f"/api/v1/proofs/{pid}/discord-embed")
                self.assertEqual(resp.status_code, 200, resp.text)
                body = resp.json()
                self.assertNotIn("+0.00%", resp.text)
                self.assertNotIn("verified realized", resp.text.lower())
                self.assertIn("withheld", body["embeds"][0]["description"].lower())
                self.assertIn("withheld", body["telegram_markdown"].lower())
                self.assertTrue(body["metrics"]["performance_withheld"])
                self.assertIsNone(body["metrics"]["twr_decimal"])
                self.assertIsNone(body["metrics"]["twr_pct"])
        computed = self.client.get("/api/v1/proofs/prf-computed/discord-embed").json()
        self.assertFalse(computed["metrics"]["performance_withheld"])
        self.assertIn("+8.00%", computed["embeds"][0]["description"])

    def test_qr_share_cards_say_withheld(self) -> None:
        for pid in ("prf-withheld", "prf-zero-obs"):
            with self.subTest(pid=pid):
                resp = self.client.get(f"/api/v1/proofs/{pid}/qr-payload")
                self.assertEqual(resp.status_code, 200, resp.text)
                self.assertNotIn("+0.00%", resp.text)
                for card in resp.json()["share_cards"].values():
                    self.assertEqual(card["twr"], "Withheld")

    def test_head_to_head_refuses_a_withheld_return(self) -> None:
        for pair in (("prf-withheld", "prf-computed"), ("prf-computed", "prf-zero-obs")):
            with self.subTest(pair=pair):
                resp = self.client.get(f"/api/v1/vs/{pair[0]}/{pair[1]}")
                self.assertEqual(resp.status_code, 422, resp.text)
                body = resp.json()
                self.assertEqual(body["error"], "performance_withheld")
                self.assertEqual(len(body["withheld_proof_ids"]), 1)

    def test_cohort_list_does_not_rank_a_withheld_return(self) -> None:
        ids = {row["proof_id"] for row in self.client.get(LEADERBOARD_ALL).json()["entries"]}
        self.assertEqual(ids, {"prf-computed"})


class TestCohortListNeedsADisclosedComputedReturn(_Case):
    def test_only_a_disclosed_proven_finite_return_with_observations_is_listed(self) -> None:
        no_core = [n for n in ALL_LEAVES if n != "core_metrics"]
        self._publish(self._bundle("prf-core-hidden", tag=_tag(11), disclose=no_core))
        no_twr = _build_leaf_payloads()
        no_twr["core_metrics"] = {**no_twr["core_metrics"], "twr_decimal": None, "twr_pct": None}
        self._publish(self._bundle("prf-no-return", tag=_tag(12), leaves=no_twr))
        no_obs = _build_leaf_payloads()
        no_obs["core_metrics"] = {
            k: v for k, v in no_obs["core_metrics"].items() if k != "observation_count"
        }
        self._publish(self._bundle("prf-no-observations", tag=_tag(13), leaves=no_obs))
        self._publish(self._bundle("prf-listed", tag=_tag(14)))
        ids = {row["proof_id"] for row in self.client.get(LEADERBOARD_ALL).json()["entries"]}
        self.assertEqual(ids, {"prf-listed"})

    def test_the_list_builds_the_registry_document_once_per_request(self) -> None:
        for i in range(5):
            self._publish(self._bundle(f"prf-cost-{i}", tag=_tag(20 + i)))
        calls = {"n": 0}
        original = ProofStore.build_registry_document

        def counted(store_self):
            calls["n"] += 1
            return original(store_self)

        ProofStore.build_registry_document = counted  # type: ignore[method-assign]
        try:
            resp = self.client.get(LEADERBOARD_ALL)
        finally:
            ProofStore.build_registry_document = original  # type: ignore[method-assign]
        self.assertEqual(resp.json()["count"], 5)
        self.assertEqual(calls["n"], 1)


def _cadence() -> ChainCadencePolicy:
    return ChainCadencePolicy(expected_interval_seconds=30 * 86400, grace_window_seconds=5 * 86400)


def _genesis(tag: str, **overrides) -> ProspectiveChainLink:
    fields = dict(
        chain_id="chn-tied",
        sequence_number=0,
        prev_proof_hash=None,
        blinded_account_tag=tag,
        enrolled_at_utc="2026-01-01T06:00:00Z",
        period_start_utc="2026-01-01T00:00:00Z",
        period_end_utc="2026-01-31T00:00:00Z",
        issued_at_utc="2026-01-31T12:00:00Z",
        cadence_policy=_cadence(),
        beginning_index_value=100.0,
        ending_index_value=110.0,
        period_twr_decimal=0.10,
    )
    fields.update(overrides)
    return ProspectiveChainLink(**fields)


def _second(tag: str, prev_hash: str, **overrides) -> ProspectiveChainLink:
    fields = dict(
        chain_id="chn-tied",
        sequence_number=1,
        prev_proof_hash=prev_hash,
        blinded_account_tag=tag,
        enrolled_at_utc="2026-01-01T06:00:00Z",
        period_start_utc="2026-01-31T00:00:00Z",
        period_end_utc="2026-03-02T00:00:00Z",
        issued_at_utc="2026-03-02T12:00:00Z",
        cadence_policy=_cadence(),
        beginning_index_value=110.0,
        ending_index_value=121.0,
        period_twr_decimal=0.10,
    )
    fields.update(overrides)
    return ProspectiveChainLink(**fields)


class TestChainLinkMustMatchItsRecord(_Case):
    TAG = _tag(40)

    def _record_for(self, proof_id: str, link: ProspectiveChainLink, **kw) -> VerifyProofBundle:
        params = dict(
            tag=self.TAG,
            leaves=_build_leaf_payloads(twr_decimal=0.10),
            link=link,
            issued_at_utc="2026-01-31T12:00:00Z" if link.sequence_number == 0 else "2026-03-02T12:00:00Z",
            period_start_utc="2026-01-01T00:00:00Z" if link.sequence_number == 0 else "2026-01-31T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z" if link.sequence_number == 0 else "2026-03-02T00:00:00Z",
        )
        params.update(kw)
        return self._bundle(proof_id, **params)

    def _enrol(self, bundle: VerifyProofBundle):
        return self.client.post(
            "/api/v1/chains", json={"proof_bundle": bundle.to_dict(), "now_utc": "2026-01-31T12:05:00Z"}
        )

    def test_a_link_that_matches_its_record_enrols(self) -> None:
        resp = self._enrol(self._record_for("prf-tied-0", _genesis(self.TAG)))
        self.assertEqual(resp.status_code, 201, resp.text)

    def test_a_link_that_disagrees_with_its_record_is_refused_and_nothing_is_written(self) -> None:
        cases = {
            "issued_at_utc": _genesis(self.TAG, issued_at_utc="2026-01-31T13:00:00Z"),
            "period_start_utc": _genesis(self.TAG, period_start_utc="2025-12-31T00:00:00Z"),
            "period_end_utc": _genesis(self.TAG, period_end_utc="2026-01-30T00:00:00Z"),
            "blinded_account_tag": _genesis(_tag(41)),
            "period_twr_decimal": _genesis(self.TAG, period_twr_decimal=0.5, ending_index_value=150.0),
            "index values": _genesis(self.TAG, ending_index_value=130.0),
        }
        for name, link in cases.items():
            with self.subTest(field=name):
                resp = self._enrol(self._record_for(f"prf-mismatch-{len(name)}", link))
                self.assertEqual(resp.status_code, 422, resp.text)
                self.assertEqual(resp.json()["error"], "chain_link_mismatch")
                self.assertEqual(self._counts(), {"proofs": 0, "chains": 0, "continuity_log": 0})

    def test_a_link_on_a_record_whose_return_is_hidden_or_withheld_is_refused(self) -> None:
        hidden = self._record_for(
            "prf-link-hidden", _genesis(self.TAG), disclose=[n for n in ALL_LEAVES if n != "core_metrics"]
        )
        withheld = self._record_for(
            "prf-link-withheld",
            _genesis(self.TAG),
            leaves=_withheld_core(performance_withheld=True, withheld_reasons=[WITHHELD_REASON]),
        )
        for bundle in (hidden, withheld):
            with self.subTest(proof_id=bundle.proof_id):
                resp = self._enrol(bundle)
                self.assertEqual(resp.status_code, 422, resp.text)
                self.assertEqual(resp.json()["error"], "chain_link_mismatch")
        self.assertEqual(self._counts(), {"proofs": 0, "chains": 0, "continuity_log": 0})

    def test_an_append_whose_link_disagrees_with_its_record_is_refused(self) -> None:
        b0 = self._record_for("prf-app-0", _genesis(self.TAG))
        self.assertEqual(self._enrol(b0).status_code, 201)
        b1 = self._record_for("prf-app-1", _second(self.TAG, b0.proof_hash(), period_twr_decimal=0.3, ending_index_value=143.0))
        resp = self.client.post(
            "/api/v1/chains/chn-tied/append",
            json={"proof_bundle": b1.to_dict(), "now_utc": "2026-03-02T12:05:00Z"},
        )
        self.assertEqual(resp.status_code, 422, resp.text)
        self.assertEqual(resp.json()["error"], "chain_link_mismatch")
        self.assertEqual(self._counts(), {"proofs": 1, "chains": 1, "continuity_log": 1})
        good = self._record_for("prf-app-1b", _second(self.TAG, b0.proof_hash()))
        ok = self.client.post(
            "/api/v1/chains/chn-tied/append",
            json={"proof_bundle": good.to_dict(), "now_utc": "2026-03-02T12:05:00Z"},
        )
        self.assertEqual(ok.status_code, 200, ok.text)

    def test_hosted_mode_does_not_enrol_a_record_without_proof_of_ownership(self) -> None:
        bundle = self._record_for(
            "prf-public-address", _genesis(self.TAG), approval=ProviderApprovalState.PUBLIC_API_PERMISSIONLESS
        )
        resp = self._enrol(bundle)
        self.assertEqual(resp.status_code, 403, resp.text)
        self.assertEqual(resp.json()["error"], "chain_requires_proven_ownership")
        self.assertEqual(self._counts(), {"proofs": 0, "chains": 0, "continuity_log": 0})

    def test_publishing_a_chain_linked_record_then_enrolling_it_is_a_conflict(self) -> None:
        bundle = self._record_for("prf-published-first", _genesis(self.TAG))
        self._publish(bundle, opt_in=False)
        resp = self._enrol(bundle)
        self.assertEqual(resp.status_code, 409, resp.text)
        self.assertEqual(resp.json()["error"], "proof_already_published")
        self.assertEqual(self._counts(), {"proofs": 1, "chains": 0, "continuity_log": 0})


class TestRepostAnswersWithTheStoredRecord(_Case):
    def test_repost_answers_200_with_the_stored_record_and_its_verification(self) -> None:
        bundle = self._bundle("prf-repost", tag=_tag(60))
        first = bundle.to_dict()
        first["holder_identity"] = _holder_claim(bundle, "Alice Owner")
        self.assertEqual(
            self.client.post("/api/v1/proofs", json={"proof_bundle": first}).status_code, 201
        )
        second = bundle.to_dict()  # no holder claim this time
        resp = self.client.post("/api/v1/proofs", json={"proof_bundle": second})
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertEqual(body["proof_bundle"]["holder_identity"]["display_name"], "Alice Owner")
        self.assertEqual(body["verification"]["holder_claim_status"], "self_asserted")
        self.assertEqual(body["verification"]["holder_display_name"], "Alice Owner")

        # A second poster attaches their own self-asserted name: nothing changes,
        # and the answer describes the stored record, not the posted one.
        other = bundle.to_dict()
        other["holder_identity"] = _holder_claim(bundle, "Mallory")
        again = self.client.post("/api/v1/proofs", json={"proof_bundle": other})
        self.assertEqual(again.status_code, 200, again.text)
        self.assertEqual(again.json()["proof_bundle"]["holder_identity"]["display_name"], "Alice Owner")
        self.assertEqual(again.json()["verification"]["holder_display_name"], "Alice Owner")


class TestUploadSaysWhenTheReturnWasWithheld(_Case):
    def _upload(self, text: str):
        return self.client.post(
            "/api/v1/verify/auto-detect",
            json={"raw_statement_text": text, "filename": "ibkr.xml", "issued_at_utc": "2026-02-10T00:00:00Z"},
        )

    def test_upload_states_performance_withheld(self) -> None:
        computed = self._upload(SYNTHETIC_LIVE_IBKR_FLEX_XML)
        self.assertEqual(computed.status_code, 200, computed.text)
        self.assertIs(computed.json()["performance_withheld"], False)
        self.assertNotIn("withheld_reasons", computed.json())

        one_nav = "\n".join(
            line
            for line in SYNTHETIC_LIVE_IBKR_FLEX_XML.splitlines()
            if 'reportDate="20260115"' not in line and 'reportDate="20260130"' not in line
        )
        withheld = self._upload(one_nav)
        self.assertEqual(withheld.status_code, 200, withheld.text)
        self.assertIs(withheld.json()["performance_withheld"], True)
        self.assertTrue(withheld.json()["withheld_reasons"])


if __name__ == "__main__":
    unittest.main()
