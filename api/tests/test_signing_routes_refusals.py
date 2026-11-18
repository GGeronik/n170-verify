"""Every route that signs a record answers the shared worker refusals the same way.

Rules covered here:
- a busy host or a worker that runs out of time answers 503 with its own code, a
  ``retry_after_seconds`` field and a ``Retry-After`` header; a statement over the stated
  size answers 413; on the statement upload, on POST /api/v1/verify and on the relay;
- a journal tag the outbound privacy scanner would block is left out of the signed record;
  other text it would block is refused with 422 before a record is signed, whether or not
  it is published, and the reason does not repeat the text;
- the relay ends a user in one place: the seat is freed, the upstream user is deleted, and
  a failed delete is retried later, a few per request; a user another read is using is
  deleted upstream only after the last read has finished;
- a relay session with no linked account yet keeps its seat for a retry.
"""

from __future__ import annotations

import json
from typing import Any
import unittest
from unittest import mock
import urllib.parse

from app import worker_isolation
from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from app.routes_snaptrade import SnapTradeRelayCoordinator
from app.worker_isolation import (
    WorkerInputTooLargeError,
    WorkerTimeoutError,
)
from n170_verify.crypto import generate_ed25519_keypair

try:
    from tests.test_snaptrade_session_binding import (
        BUILD_CLIENT_ID,
        CONSUMER_KEY,
        PORTAL,
        RELEASE,
        STATUS,
        TEST_SALT_HEX,
        VERIFY,
        _AppCase,
        _deleted_user_ids,
        _make_mock_snaptrade_transport,
    )
    from tests.test_verify_input_allowlist import SCHWAB_CSV, TRADERSYNC_CSV
    from tests.test_verify_request_surface import _config
except ImportError:  # pragma: no cover - run from inside api/tests
    from test_snaptrade_session_binding import (  # type: ignore[no-redef]
        BUILD_CLIENT_ID,
        CONSUMER_KEY,
        PORTAL,
        RELEASE,
        STATUS,
        TEST_SALT_HEX,
        VERIFY,
        _AppCase,
        _deleted_user_ids,
        _make_mock_snaptrade_transport,
    )
    from test_verify_input_allowlist import SCHWAB_CSV, TRADERSYNC_CSV  # type: ignore[no-redef]
    from test_verify_request_surface import _config  # type: ignore[no-redef]


UPLOAD = "/api/v1/verify/auto-detect"
# A paper-account id, assembled at run time.
ACCOUNT_SHAPED_TAG = "PA" + "3K9XZ" + "1ABCD"


def _scanner_tagged_tradersync() -> str:
    return TRADERSYNC_CSV.replace(",ORB,", f",{ACCOUNT_SHAPED_TAG},")


def picklable_relay_record_with_tag(job: dict[str, Any]) -> dict[str, Any]:
    """Worker stand-in for the relay: a record whose disclosed leaf carries the tag."""
    from n170_verify.crypto import CANONICAL_LEAF_NAMES, build_salted_merkle_tree

    leaves = {name: {"placeholder": name} for name in CANONICAL_LEAF_NAMES}
    leaves["coaching_and_context"] = {"journal_tags": [ACCOUNT_SHAPED_TAG]}
    tree = build_salted_merkle_tree(leaves)
    disclosed, undisclosed = tree.selectively_disclose(["coaching_and_context"])
    return {
        "broker_id": str(job["broker_id"]),
        "blinded_account_tag": "ef" * 32,
        "account_scope": "single_account_survivorship_unverified",
        "provider_approval_state": str(job["provider_approval_state"]),
        "environment_tier": "live_production",
        "claimed_origin_assurance": "operator_retrieved",
        "source_body_sha256": "12" * 32,
        "period_start_utc": "2026-01-01T00:00:00Z",
        "period_end_utc": "2026-01-31T00:00:00Z",
        "base_currency": "USD",
        "merkle_root": tree.merkle_root,
        "disclosed_leaves": [leaf.to_dict() for leaf in disclosed],
        "undisclosed_leaf_hashes": dict(undisclosed),
        "stripped_recent_closed_trades_count": 0,
    }


def picklable_no_linked_account_transport(
    method: str, url: str, headers: dict[str, str], body: bytes | None
) -> tuple[int, dict[str, str], Any]:
    """Fake aggregator: a registered user that has not linked any brokerage account yet."""
    path = urllib.parse.urlsplit(url).path
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    payload = json.loads(body.decode("utf-8")) if body else {}
    if path == "/api/v1/snapTrade/registerUser":
        return 200, {"Content-Type": "application/json"}, {
            "userId": str(payload.get("userId", "")),
            "userSecret": "dummy-user-secret-for-tests-0001",
        }
    if path == "/api/v1/snapTrade/login":
        return 200, {"Content-Type": "application/json"}, {"redirectURI": "https://portal.example.invalid/s"}
    if path == "/api/v1/snapTrade/deleteUser":
        return 200, {"Content-Type": "application/json"}, {"status": "deleted", "userId": query["userId"][0]}
    if path == "/api/v1/snapTrade/listUsers":
        return 200, {"Content-Type": "application/json"}, []
    if path == "/api/v1/accounts":
        return 200, {"Content-Type": "application/json"}, []
    return 404, {"Content-Type": "application/json"}, {"detail": "unexpected"}


class _SlotsHeld:
    """Hold every verification worker slot for the duration of a ``with`` block."""

    def __enter__(self) -> "_SlotsHeld":
        self.held = 0
        for _ in range(worker_isolation.MAX_CONCURRENT_VERIFICATION_WORKERS):
            self.assertion = worker_isolation._VERIFICATION_WORKER_SLOTS.acquire(blocking=False)
            if self.assertion:
                self.held += 1
        return self

    def __exit__(self, *exc: Any) -> None:
        for _ in range(self.held):
            worker_isolation._VERIFICATION_WORKER_SLOTS.release()


def _assert_retry(case: unittest.TestCase, resp: Any, code: str) -> None:
    case.assertEqual(resp.status_code, 503, resp.text)
    body = resp.json()
    case.assertEqual(body["error"], code)
    case.assertGreater(int(body["retry_after_seconds"]), 0)
    retry_header = {k.lower(): v for k, v in resp.headers.items()}.get("retry-after")
    case.assertEqual(retry_header, str(body["retry_after_seconds"]))


class UploadAndVerifyRouteRefusals(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app(_config(hosted=True), prefer_fastapi=False)
        self.addCleanup(self.app.verify_app.close)
        self.client = VerifyApiTestClient(self.app)

    def _upload(self, text: str, *, publish: bool = False) -> Any:
        url = UPLOAD + ("?publish_proof=true" if publish else "")
        return self.client.post(url, content=text.encode("utf-8"), headers={"Content-Type": "text/csv"})

    def test_a_busy_host_answers_503_with_a_retry_delay_on_every_route(self) -> None:
        with _SlotsHeld():
            _assert_retry(self, self._upload(SCHWAB_CSV), "verification_busy")
            _assert_retry(
                self,
                self.client.post("/api/v1/verify", json={"broker_id": "schwab_csv", "raw_statement_text": SCHWAB_CSV}),
                "verification_busy",
            )

    def test_a_worker_that_runs_out_of_time_answers_503_on_the_upload(self) -> None:
        with mock.patch(
            "app.routes_viral.run_isolated_one_shot_verification",
            side_effect=WorkerTimeoutError("Verification did not finish in time on this host; try again shortly"),
        ):
            _assert_retry(self, self._upload(SCHWAB_CSV), "verification_timed_out")

    def test_a_statement_over_the_stated_size_answers_413_on_the_upload(self) -> None:
        header, row = SCHWAB_CSV.splitlines()[:2]
        too_long = "\n".join([header] + [row] * (worker_isolation.MAX_STATEMENT_INPUT_ROWS + 1)) + "\n"
        resp = self._upload(too_long)
        self.assertEqual(resp.status_code, 413, resp.text[:300])
        self.assertEqual(resp.json()["error"], "statement_too_large")

    def test_an_account_id_in_a_journal_tag_never_reaches_a_signed_record(self) -> None:
        # The tag is left out of the record and the response says so; the record is signed.
        statement = _scanner_tagged_tradersync()
        for publish in (False, True):
            with self.subTest(route="verify", publish=publish):
                resp = self.client.post(
                    "/api/v1/verify",
                    json={"broker_id": "tradersync", "raw_statement_text": statement, "publish_proof": publish},
                )
                self.assertEqual(resp.status_code, 200, resp.text[:400])
                self.assertNotIn(ACCOUNT_SHAPED_TAG, resp.text)
                self.assertTrue(resp.json().get("record_warnings"))
            with self.subTest(route="upload", publish=publish):
                resp = self._upload(statement, publish=publish)
                self.assertEqual(resp.status_code, 200, resp.text[:400])
                self.assertNotIn(ACCOUNT_SHAPED_TAG, resp.text)
                self.assertTrue(resp.json().get("record_warnings"))


class RelayRouteRefusals(_AppCase):
    def _relay_app(self, transport: Any, *, pipeline_spec: Any = None, clock: Any = None) -> tuple[Any, Any, Any]:
        relay = (
            SnapTradeRelayCoordinator(http_transport=transport, monotonic_clock=clock)
            if clock is not None
            else SnapTradeRelayCoordinator(http_transport=transport)
        )
        cfg = ApiConfig(
            publisher_keypair=self.kp,
            publisher_kid="n170-relay-refusal-kid",
            snaptrade_client_id=BUILD_CLIENT_ID,
            snaptrade_consumer_key=CONSUMER_KEY,
            account_blinding_salt_hex=TEST_SALT_HEX,
            hosted_multi_user_mode=True,
        )
        app = create_app(cfg, snaptrade_relay=relay, pipeline_spec=pipeline_spec, prefer_fastapi=False)
        self.addCleanup(app.close)
        return app, VerifyApiTestClient(app), relay

    def _open(self, transport: Any, **kw: Any) -> tuple[Any, Any, Any, str]:
        app, client, relay = self._relay_app(transport, **kw)
        portal = client.post(PORTAL, json={})
        self.assertEqual(portal.status_code, 200, portal.text)
        return app, client, relay, portal.json()["session_token"]

    def test_busy_and_timed_out_keep_the_seat_and_answer_503(self) -> None:
        transport, recorded = _make_mock_snaptrade_transport()
        _, client, relay, token = self._open(transport)
        with _SlotsHeld():
            _assert_retry(self, client.post(VERIFY, json={"session_token": token}), "verification_busy")
        with mock.patch(
            "app.routes_snaptrade.run_isolated_one_shot_verification",
            side_effect=WorkerTimeoutError("Verification did not finish in time on this host; try again shortly"),
        ):
            _assert_retry(self, client.post(VERIFY, json={"session_token": token}), "verification_timed_out")
        self.assertIsNotNone(relay.get_session(token))
        self.assertEqual(_deleted_user_ids(recorded), [])

    def test_input_over_the_stated_size_answers_413_and_ends_the_session(self) -> None:
        transport, recorded = _make_mock_snaptrade_transport()
        _, client, relay, token = self._open(transport)
        with mock.patch(
            "app.routes_snaptrade.run_isolated_one_shot_verification",
            side_effect=WorkerInputTooLargeError("The statement is over this host's limit of 10,000 rows."),
        ):
            resp = client.post(VERIFY, json={"session_token": token})
        self.assertEqual(resp.status_code, 413, resp.text)
        self.assertEqual(resp.json()["error"], "statement_too_large")
        self.assertIsNone(relay.get_session(token))

    def test_text_the_scanner_blocks_is_refused_before_signing_on_the_relay(self) -> None:
        spec = f"{__name__}:picklable_relay_record_with_tag"
        for publish in (False, True):
            with self.subTest(publish=publish):
                transport, _ = _make_mock_snaptrade_transport()
                app, client, _, token = self._open(transport, pipeline_spec=spec)
                resp = client.post(VERIFY, json={"session_token": token, "publish_proof": publish})
                self.assertEqual(resp.status_code, 422, resp.text[:400])
                self.assertNotIn(ACCOUNT_SHAPED_TAG, resp.text)
                self.assertEqual(app.store.total_row_counts()["proofs"], 0)

    def test_a_failed_upstream_delete_after_verify_or_release_is_retried(self) -> None:
        for how in ("verify", "release"):
            with self.subTest(how=how):
                inner, recorded = _make_mock_snaptrade_transport()
                failures = {"left": 1}

                def transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
                    if urllib.parse.urlsplit(url).path == "/api/v1/snapTrade/deleteUser" and failures["left"]:
                        failures["left"] -= 1
                        inner(method, url, headers, body)  # recorded as an attempt
                        return 500, {"Content-Type": "application/json"}, {"detail": "unavailable"}
                    return inner(method, url, headers, body)

                _, client, relay, token = self._open(transport)
                if how == "verify":
                    resp = client.post(VERIFY, json={"session_token": token})
                else:
                    resp = client.post(RELEASE, json={"session_token": token})
                self.assertEqual(resp.status_code, 200, resp.text[:300])
                self.assertEqual(len(_deleted_user_ids(recorded)), 1)
                self.assertEqual(client.get(STATUS).json()["active_slots"], 0)
                client.get(STATUS)  # the next request retries the queued delete
                deleted = _deleted_user_ids(recorded)
                self.assertEqual(len(deleted), 2, deleted)
                self.assertEqual(deleted[0], deleted[1])

    def test_a_session_that_expires_during_its_own_verify_is_not_ended_mid_read(self) -> None:
        now = {"t": 1000.0}
        inner, recorded = _make_mock_snaptrade_transport()
        holder: dict[str, Any] = {}
        deletes_during_read: list[list[str]] = []

        def transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
            if urllib.parse.urlsplit(url).path == "/api/v1/accounts" and "client" in holder:
                now["t"] += 10 * 3600.0  # the session's lifetime passes while its read runs
                holder["client"].get(STATUS)
                deletes_during_read.append(list(_deleted_user_ids(recorded)))
            return inner(method, url, headers, body)

        _, client, _, token = self._open(transport, clock=lambda: now["t"])
        holder["client"] = client
        resp = client.post(VERIFY, json={"session_token": token})
        self.assertEqual(deletes_during_read, [[]])
        self.assertEqual(resp.status_code, 200, resp.text[:300])
        self.assertEqual(len(_deleted_user_ids(recorded)), 1)

    def test_a_user_another_read_is_using_is_not_deleted_upstream_until_that_read_ends(self) -> None:
        for second in ("verify", "release"):
            with self.subTest(second=second):
                inner, recorded = _make_mock_snaptrade_transport()
                holder: dict[str, Any] = {}
                deletes_during_read: list[list[str]] = []

                def transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
                    if urllib.parse.urlsplit(url).path == "/api/v1/accounts" and not holder.get("nested"):
                        holder["nested"] = True
                        path = VERIFY if second == "verify" else RELEASE
                        holder["second"] = holder["client"].post(path, json={"session_token": holder["token"]})
                        deletes_during_read.append(list(_deleted_user_ids(recorded)))
                    return inner(method, url, headers, body)

                _, client, _, token = self._open(transport)
                holder.update(client=client, token=token)
                first = client.post(VERIFY, json={"session_token": token})
                self.assertEqual(holder["second"].status_code, 200, holder["second"].text[:300])
                self.assertEqual(deletes_during_read, [[]])
                self.assertEqual(first.status_code, 200, first.text[:300])
                client.get(STATUS)  # a queued delete runs once no read is using the user
                deleted = _deleted_user_ids(recorded)
                self.assertGreaterEqual(len(deleted), 1)
                self.assertEqual(len(set(deleted)), 1)

    def test_one_request_retries_only_a_few_queued_deletes(self) -> None:
        from app.routes_snaptrade import MAX_QUEUED_DELETES_PER_REQUEST

        transport, recorded = _make_mock_snaptrade_transport()
        _, client, relay = self._relay_app(transport)
        client.get(STATUS)
        with relay._lock:
            for n in range(MAX_QUEUED_DELETES_PER_REQUEST + 3):
                relay._pending_upstream_deletes.add(f"n170-st-queued-{n:02d}")
        before = len(_deleted_user_ids(recorded))
        client.get(STATUS)
        self.assertEqual(len(_deleted_user_ids(recorded)) - before, MAX_QUEUED_DELETES_PER_REQUEST)
        with relay._lock:
            self.assertEqual(len(relay._pending_upstream_deletes), 3)

    def test_no_linked_account_keeps_the_seat_through_the_real_connector(self) -> None:
        for transport in (f"{__name__}:picklable_no_linked_account_transport", picklable_no_linked_account_transport):
            with self.subTest(in_worker=isinstance(transport, str)):
                _, client, relay, token = self._open(transport)
                resp = client.post(VERIFY, json={"session_token": token})
                self.assertEqual(resp.status_code, 422, resp.text[:300])
                self.assertNotIn("session_ended", resp.json())
                self.assertIsNotNone(relay.get_session(token))
                self.assertEqual(client.get(STATUS).json()["active_slots"], 1)


if __name__ == "__main__":
    unittest.main()
