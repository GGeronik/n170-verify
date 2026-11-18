"""SnapTrade relay sessions belong to the caller that created them.

Rules covered here:
- every portal call gets its own random upstream user; a label never selects or reuses one,
  and the public status lists no labels;
- in hosted mode a personal key is served only to callers presenting a configured dev key;
- a slot is released only with the caller's own session token (operator targeting needs the
  dev key), one session holds one slot, and a successful verify frees the slot by default;
- redirect_url is limited to the configured site origin and local http://127.0.0.1;
- relay users left upstream by an earlier process are deleted once, before first use.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
from typing import Any
import unittest
from unittest import mock
import urllib.parse

from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from app.routes_snaptrade import SnapTradeRelayCoordinator
from n170_verify.crypto import generate_ed25519_keypair

try:
    from tests.test_snaptrade_relay import _make_mock_snaptrade_transport
except ImportError:
    from test_snaptrade_relay import _make_mock_snaptrade_transport


BUILD_CLIENT_ID = "N170-SNAP-DEV-CLIENT"
PERSONAL_CLIENT_ID = "PERS-DUMMY-OWNER-01"
CONSUMER_KEY = "snap-hmac-consumer-secret-xyz-12345"
DEV_KEY = "dummy-operator-dev-key"
SITE_ORIGIN_ENV = "N170_VERIFY_SITE_ORIGIN"

PORTAL = "/api/v1/connect/snaptrade/portal"
VERIFY = "/api/v1/connect/snaptrade/verify"
RELEASE = "/api/v1/connect/snaptrade/release"
STATUS = "/api/v1/connect/snaptrade/status"

TEST_SALT_HEX = "5a" * 32
# This deployment's part of an upstream user id: a short keyed hash of the account salt.
OWN_TAG = hmac.new(
    bytes.fromhex(TEST_SALT_HEX), b"n170.snaptrade.deployment.v1", hashlib.sha256
).hexdigest()[:8]
OWN_PREFIX = f"n170-st-{OWN_TAG}-"


def _registered_user_ids(recorded: list[dict[str, Any]]) -> list[str]:
    return [
        str((r["body"] or {}).get("userId"))
        for r in recorded
        if r["path"] == "/api/v1/snapTrade/registerUser"
    ]


def _deleted_user_ids(recorded: list[dict[str, Any]]) -> list[str]:
    return [
        r["query"]["userId"][0]
        for r in recorded
        if r["path"] == "/api/v1/snapTrade/deleteUser"
    ]


class _AppCase(unittest.TestCase):
    def setUp(self) -> None:
        self.kp = generate_ed25519_keypair(bytes.fromhex("42" * 32))
        env_patch = mock.patch.dict(os.environ, {}, clear=False)
        env_patch.start()
        self.addCleanup(env_patch.stop)
        for name in (
            SITE_ORIGIN_ENV,
            "N170_SNAPTRADE_DEV_KEY",
            "SNAPTRADE_CLIENT_ID",
            "SNAPTRADE_CONSUMER_KEY",
            "SNAPTRADE_AUTH_MODE",
        ):
            os.environ.pop(name, None)

    def _client(
        self,
        transport: Any,
        *,
        client_id: str = BUILD_CLIENT_ID,
        dev_key: str = "",
        hosted: bool = True,
        allow_caller_clock: bool = False,
        clock: Any = None,
        site_origin: str = "",
        client_secret: str = CONSUMER_KEY,
    ) -> tuple[Any, VerifyApiTestClient, SnapTradeRelayCoordinator]:
        relay = (
            SnapTradeRelayCoordinator(http_transport=transport, monotonic_clock=clock)
            if clock is not None
            else SnapTradeRelayCoordinator(http_transport=transport)
        )
        cfg = ApiConfig(
            publisher_keypair=self.kp,
            publisher_kid="n170-binding-test-kid",
            snaptrade_client_id=client_id,
            snaptrade_consumer_key=client_secret,
            snaptrade_dev_key=dev_key,
            site_origin=site_origin,
            account_blinding_salt_hex=TEST_SALT_HEX,
            hosted_multi_user_mode=hosted,
            allow_caller_clock_for_tests=allow_caller_clock,
        )
        app = create_app(cfg, snaptrade_relay=relay, prefer_fastapi=False)
        self.addCleanup(app.close)
        return app, VerifyApiTestClient(app), relay


class TestRelaySessionBelongsToItsCreator(_AppCase):
    def test_each_portal_call_gets_its_own_upstream_user_regardless_of_label(self) -> None:
        transport, recorded = _make_mock_snaptrade_transport()
        _, client, _ = self._client(transport)

        first = client.post(PORTAL, json={"slot_label": "alice"})
        self.assertEqual(first.status_code, 200, first.text)

        status = client.get(STATUS).json()
        for slot in status["slots"]:
            self.assertNotIn("slot_label", slot)
        self.assertNotIn("alice", str(status))

        second = client.post(PORTAL, json={"slot_label": "alice"})
        self.assertEqual(second.status_code, 200, second.text)
        self.assertNotEqual(first.json()["slot_id"], second.json()["slot_id"])

        user_ids = _registered_user_ids(recorded)
        self.assertEqual(len(user_ids), 2, user_ids)
        self.assertNotEqual(user_ids[0], user_ids[1])
        for uid in user_ids:
            self.assertTrue(uid.startswith(OWN_PREFIX), uid)
            self.assertEqual(len(uid), len(OWN_PREFIX) + 24, uid)


class TestPersonalKeyIsOperatorOnlyWhenHosted(_AppCase):
    def test_hosted_personal_key_without_configured_dev_key_is_refused(self) -> None:
        transport, recorded = _make_mock_snaptrade_transport(expected_client_id=PERSONAL_CLIENT_ID)
        _, client, _ = self._client(transport, client_id=PERSONAL_CLIENT_ID)

        portal = client.post(PORTAL, json={"slot_label": "visitor"})
        self.assertEqual(portal.status_code, 403, portal.text)
        self.assertEqual(portal.json()["error"], "personal_key_requires_dev_key")

        verify = client.post(VERIFY, json={"session_token": "x" * 43})
        self.assertEqual(verify.status_code, 403, verify.text)
        self.assertEqual(verify.json()["error"], "personal_key_requires_dev_key")
        self.assertFalse(any(r["path"] == "/api/v1/snapTrade/login" for r in recorded))

    def test_hosted_personal_key_serves_a_caller_presenting_the_dev_key(self) -> None:
        transport, _ = _make_mock_snaptrade_transport(expected_client_id=PERSONAL_CLIENT_ID)
        _, client, _ = self._client(transport, client_id=PERSONAL_CLIENT_ID, dev_key=DEV_KEY)

        refused = client.post(PORTAL, json={})
        self.assertEqual(refused.status_code, 403, refused.text)
        self.assertEqual(refused.json()["error"], "dev_key_required")

        allowed = client.post(PORTAL, json={}, headers={"X-N170-Dev-Key": DEV_KEY})
        self.assertEqual(allowed.status_code, 200, allowed.text)
        self.assertEqual(allowed.json()["mode"], "personal_1_slot")

    def test_self_hosted_personal_key_needs_no_dev_key(self) -> None:
        transport, _ = _make_mock_snaptrade_transport(expected_client_id=PERSONAL_CLIENT_ID)
        _, client, _ = self._client(transport, client_id=PERSONAL_CLIENT_ID, hosted=False)
        portal = client.post(PORTAL, json={})
        self.assertEqual(portal.status_code, 200, portal.text)


class TestReleaseNeedsTheCallersOwnSession(_AppCase):
    def test_release_without_dev_key_accepts_only_the_callers_session_token(self) -> None:
        transport, recorded = _make_mock_snaptrade_transport()
        _, client, _ = self._client(transport)

        owner = client.post(PORTAL, json={"slot_label": "owner"})
        self.assertEqual(owner.status_code, 200, owner.text)
        owner_token = owner.json()["session_token"]
        owner_slot = owner.json()["slot_id"]

        for body in (
            {"release_all": True},
            {"slot_id": owner_slot},
            {"slot_label": "owner"},
        ):
            r = client.post(RELEASE, json=body)
            self.assertEqual(r.status_code, 403, f"{body} -> {r.text}")
            self.assertEqual(r.json()["error"], "session_token_required")
        self.assertEqual(_deleted_user_ids(recorded), [])
        self.assertEqual(client.get(STATUS).json()["active_slots"], 1)

        unknown = client.post(RELEASE, json={"session_token": "y" * 43})
        self.assertEqual(unknown.status_code, 404, unknown.text)
        self.assertEqual(unknown.json()["error"], "session_not_found")

        missing = client.post(RELEASE, json={})
        self.assertEqual(missing.status_code, 422, missing.text)

        own = client.post(RELEASE, json={"session_token": owner_token})
        self.assertEqual(own.status_code, 200, own.text)
        self.assertEqual(own.json()["released_slot_ids"], [owner_slot])
        self.assertEqual(own.json()["active_slots"], 0)
        self.assertEqual(len(_deleted_user_ids(recorded)), 1)

        gone = client.post(VERIFY, json={"session_token": owner_token})
        self.assertEqual(gone.status_code, 404, gone.text)

    def test_operator_with_dev_key_may_still_target_slots(self) -> None:
        transport, _ = _make_mock_snaptrade_transport()
        _, client, _ = self._client(transport, dev_key=DEV_KEY)
        hdr = {"X-N170-Dev-Key": DEV_KEY}
        for _ in range(2):
            self.assertEqual(client.post(PORTAL, json={}, headers=hdr).status_code, 200)
        rel = client.post(RELEASE, json={"release_all": True}, headers=hdr)
        self.assertEqual(rel.status_code, 200, rel.text)
        self.assertEqual(rel.json()["active_slots"], 0)

    def test_successful_verify_frees_the_slot_by_default(self) -> None:
        transport, recorded = _make_mock_snaptrade_transport()
        _, client, _ = self._client(transport)
        portal = client.post(PORTAL, json={})
        self.assertEqual(portal.status_code, 200, portal.text)
        verify = client.post(VERIFY, json={"session_token": portal.json()["session_token"]})
        self.assertEqual(verify.status_code, 200, verify.text)
        self.assertTrue(verify.json()["isolation"]["slot_released"])
        self.assertEqual(verify.json()["slot_status"]["active_slots"], 0)
        self.assertEqual(len(_deleted_user_ids(recorded)), 1)

    def test_one_session_holds_one_slot(self) -> None:
        transport, _ = _make_mock_snaptrade_transport(expected_client_id=PERSONAL_CLIENT_ID)
        _, client, relay = self._client(transport, client_id=PERSONAL_CLIENT_ID, dev_key=DEV_KEY)
        hdr = {"X-N170-Dev-Key": DEV_KEY}
        first = client.post(PORTAL, json={}, headers=hdr)
        second = client.post(PORTAL, json={}, headers=hdr)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual(first.json()["slot_id"], second.json()["slot_id"])
        self.assertIsNone(relay.get_session(first.json()["session_token"]))
        self.assertIsNotNone(relay.get_session(second.json()["session_token"]))


class TestRelayVerifyIssueTimeAndPublishRefusals(_AppCase):
    def test_caller_may_not_set_the_issue_time_of_a_signed_record(self) -> None:
        transport, _ = _make_mock_snaptrade_transport()
        app, client, relay = self._client(transport)
        portal = client.post(PORTAL, json={})
        self.assertEqual(portal.status_code, 200, portal.text)
        token = portal.json()["session_token"]

        r = client.post(
            VERIFY,
            json={"session_token": token, "issued_at_utc": "2026-02-10T12:00:00Z", "publish_proof": True},
        )
        self.assertEqual(r.status_code, 400, r.text)
        self.assertEqual(r.json()["error"], "caller_clock_not_accepted")
        self.assertEqual(app.store.total_row_counts()["proofs"], 0)
        self.assertIsNotNone(relay.get_session(token))

    def test_test_only_setting_still_accepts_an_issue_time(self) -> None:
        transport, _ = _make_mock_snaptrade_transport()
        _, client, _ = self._client(transport, allow_caller_clock=True)
        portal = client.post(PORTAL, json={})
        r = client.post(
            VERIFY,
            json={"session_token": portal.json()["session_token"], "issued_at_utc": "2026-02-10T12:00:00Z"},
        )
        self.assertEqual(r.status_code, 200, r.text)

    def test_a_record_the_host_may_not_publish_returns_its_own_refusal(self) -> None:
        from app.store import PublisherKeyNotInRegistryError

        transport, _ = _make_mock_snaptrade_transport()
        app, client, _ = self._client(transport)

        def refuse(*_a: Any, **_k: Any) -> Any:
            raise PublisherKeyNotInRegistryError("signing key is not in this host's registry")

        app.store.store_proof = refuse  # type: ignore[method-assign]
        portal = client.post(PORTAL, json={})
        r = client.post(
            VERIFY,
            json={"session_token": portal.json()["session_token"], "publish_proof": True},
        )
        self.assertEqual(r.status_code, 403, r.text)
        self.assertEqual(r.json()["error"], "publisher_key_not_in_registry")


class TestOperatorSetsRelaySessionLifetime(unittest.TestCase):
    """The operator may shorten the relay session lifetime; a bad value stops start-up."""

    NAME = "N170_SNAPTRADE_SESSION_TTL_SECONDS"

    def _env(self, **extra: str) -> dict[str, str]:
        base = {
            "N170_VERIFY_HOSTED_MODE": "false",
            "N170_VERIFY_SIGNING_SEED_HEX": "42" * 32,
            "N170_VERIFY_ACCOUNT_SALT_HEX": "5a" * 32,
        }
        base.update(extra)
        return base

    def test_unset_keeps_the_thirty_minute_lifetime(self) -> None:
        with mock.patch.dict(os.environ, self._env(), clear=True):
            app = create_app(ApiConfig.from_env(), prefer_fastapi=False)
        self.addCleanup(app.close)
        self.assertEqual(app.snaptrade_relay.session_ttl_seconds, 1800.0)

    def test_a_shorter_lifetime_frees_an_unfinished_session_when_it_expires(self) -> None:
        transport, _ = _make_mock_snaptrade_transport()
        env = self._env(
            **{
                self.NAME: "120",
                "SNAPTRADE_CLIENT_ID": BUILD_CLIENT_ID,
                "SNAPTRADE_CONSUMER_KEY": CONSUMER_KEY,
            }
        )
        with mock.patch.dict(os.environ, env, clear=True):
            app = create_app(
                ApiConfig.from_env(), snaptrade_http_transport=transport, prefer_fastapi=False
            )
            self.addCleanup(app.close)
            relay = app.snaptrade_relay
            self.assertEqual(relay.session_ttl_seconds, 120.0)
            now = [5000.0]
            relay._clock = lambda: now[0]
            client = VerifyApiTestClient(app)
            portal = client.post(PORTAL, json={})
            self.assertEqual(portal.status_code, 200, portal.text)
            now[0] += 119.0
            self.assertEqual(client.get(STATUS).json()["active_slots"], 1)
            now[0] += 2.0
            self.assertEqual(client.get(STATUS).json()["active_slots"], 0)
            self.assertIsNone(relay.get_session(portal.json()["session_token"]))

    def test_a_value_that_is_not_a_number_or_out_of_range_stops_start_up(self) -> None:
        for bad in ("abc", "", " ", "nan", "inf", "59", "1801", "-5", "0"):
            if not bad.strip():
                continue  # empty means unset
            with mock.patch.dict(os.environ, self._env(**{self.NAME: bad}), clear=True):
                with self.assertRaises(ValueError, msg=bad) as ctx:
                    ApiConfig.from_env()
                self.assertIn(self.NAME, str(ctx.exception))
        for bad_value in (59.0, 1801.0, float("nan")):
            with self.assertRaises(ValueError):
                ApiConfig(snaptrade_session_ttl_seconds=bad_value)  # type: ignore[call-arg]

    def test_bounds_are_accepted(self) -> None:
        for ok in ("60", "1800", "900.5"):
            with mock.patch.dict(os.environ, self._env(**{self.NAME: ok}), clear=True):
                self.assertEqual(ApiConfig.from_env().snaptrade_session_ttl_seconds, float(ok))


class TestRedirectLimitedToSiteOrigin(_AppCase):
    def _portal(self, client: VerifyApiTestClient, url: str) -> Any:
        return client.post(PORTAL, json={"redirect_url": url})

    def test_redirect_must_match_the_configured_origin_or_local_loopback(self) -> None:
        transport, _ = _make_mock_snaptrade_transport()
        _, client, _ = self._client(transport, site_origin="https://verify.example.org")

        for bad in (
            "https://evil.example.com/connect",
            "https://verify.example.org.evil.example/connect",
            "https://verify.example.org:8443/connect",
            "http://verify.example.org/connect",
            "http://localhost:3000/connect",
        ):
            r = self._portal(client, bad)
            self.assertEqual(r.status_code, 422, f"{bad} -> {r.text}")
            self.assertEqual(r.json()["error"], "invalid_redirect_url")

        for good in (
            "https://verify.example.org/connect?snaptrade=connected",
            "https://VERIFY.example.org:443/connect",
            "http://127.0.0.1:3000/connect",
        ):
            r = self._portal(client, good)
            self.assertEqual(r.status_code, 200, f"{good} -> {r.text}")

    def test_without_configured_origin_only_local_loopback_is_accepted(self) -> None:
        transport, _ = _make_mock_snaptrade_transport()
        _, client, _ = self._client(transport)
        r = self._portal(client, "https://verify.example.org/connect")
        self.assertEqual(r.status_code, 422, r.text)
        ok = self._portal(client, "http://127.0.0.1:3000/connect")
        self.assertEqual(ok.status_code, 200, ok.text)

    def test_the_origin_comes_only_from_configuration(self) -> None:
        # An environment value is never consulted at request time.
        os.environ[SITE_ORIGIN_ENV] = "https://verify.example.org"
        transport, _ = _make_mock_snaptrade_transport()
        _, client, _ = self._client(transport)
        r = self._portal(client, "https://verify.example.org/connect")
        self.assertEqual(r.status_code, 422, r.text)

    def test_a_configured_origin_holds_while_the_environment_is_empty(self) -> None:
        # A verification worker start briefly empties the process environment.
        transport, _ = _make_mock_snaptrade_transport()
        _, client, _ = self._client(transport, site_origin="https://verify.example.org")
        with mock.patch.dict(os.environ, {}, clear=True):
            r = self._portal(client, "https://verify.example.org/connect")
        self.assertEqual(r.status_code, 200, r.text)

    def test_a_configured_http_origin_is_matched_exactly(self) -> None:
        transport, _ = _make_mock_snaptrade_transport()
        _, client, _ = self._client(transport, site_origin="http://verify.example.org:8080")
        self.assertEqual(self._portal(client, "http://verify.example.org:8080/cb").status_code, 200)
        self.assertEqual(self._portal(client, "http://verify.example.org/cb").status_code, 422)
        self.assertEqual(self._portal(client, "https://verify.example.org:8080/cb").status_code, 422)


class TestRelayCredentialsComeOnlyFromConfiguration(_AppCase):
    def test_credentials_in_the_environment_alone_do_not_configure_the_relay(self) -> None:
        os.environ["SNAPTRADE_CLIENT_ID"] = BUILD_CLIENT_ID
        os.environ["SNAPTRADE_CONSUMER_KEY"] = CONSUMER_KEY
        os.environ["N170_SNAPTRADE_DEV_KEY"] = DEV_KEY
        transport, recorded = _make_mock_snaptrade_transport()
        _, client, _ = self._client(transport, client_id="", client_secret="")
        status = client.get(STATUS).json()
        self.assertFalse(status["configured"], status)
        self.assertFalse(status["requires_dev_key"], status)
        self.assertEqual(client.post(PORTAL, json={}).status_code, 503)
        self.assertEqual(recorded, [])


def _with_list_users(inner: Any, listed: Any, status: int = 200) -> tuple[Any, list[str]]:
    seen: list[str] = []

    def transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
        path = urllib.parse.urlsplit(url).path
        if method == "GET" and path == "/api/v1/snapTrade/listUsers":
            seen.append(path)
            return (status, {"Content-Type": "application/json"}, listed)
        return inner(method, url, headers, body)

    return transport, seen


class TestLeftoverUpstreamUsersAreCleanedOnce(_AppCase):
    def test_first_use_deletes_only_prefixed_leftover_users(self) -> None:
        inner, recorded = _make_mock_snaptrade_transport()
        leftover = OWN_PREFIX + "a" * 24
        transport, seen = _with_list_users(inner, [leftover, "someone-else", 42])
        _, client, _ = self._client(transport)

        self.assertEqual(client.get(STATUS).status_code, 200)
        self.assertEqual(_deleted_user_ids(recorded), [leftover])

        self.assertEqual(client.get(STATUS).status_code, 200)
        self.assertEqual(len(seen), 1)
        self.assertEqual(_deleted_user_ids(recorded), [leftover])

    def test_sweep_keeps_a_user_registered_while_it_runs(self) -> None:
        inner, recorded = _make_mock_snaptrade_transport()
        leftover = OWN_PREFIX + "c" * 24
        state: dict[str, Any] = {}

        def transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
            path = urllib.parse.urlsplit(url).path
            if method == "GET" and path == "/api/v1/snapTrade/listUsers":
                # A portal session is created after the sweep started and before the
                # upstream list comes back, so the list already contains its user.
                portal = state["client"].post(PORTAL, json={})
                state["portal"] = portal
                new_ids = _registered_user_ids(recorded)
                return (200, {"Content-Type": "application/json"}, [leftover, *new_ids])
            return inner(method, url, headers, body)

        _, client, relay = self._client(transport)
        state["client"] = client

        self.assertEqual(client.get(STATUS).status_code, 200)
        self.assertEqual(state["portal"].status_code, 200, state["portal"].text)
        live_user = _registered_user_ids(recorded)[0]
        self.assertEqual(_deleted_user_ids(recorded), [leftover])
        self.assertNotIn(live_user, _deleted_user_ids(recorded))
        self.assertIsNotNone(relay.get_session(state["portal"].json()["session_token"]))
        self.assertEqual(client.get(STATUS).json()["active_slots"], 1)

    def test_upstream_error_is_recorded_and_the_relay_keeps_working(self) -> None:
        inner, _ = _make_mock_snaptrade_transport()
        transport, seen = _with_list_users(inner, {"detail": "unavailable"}, status=503)
        _, client, relay = self._client(transport)

        self.assertEqual(client.get(STATUS).status_code, 200)
        self.assertEqual(len(seen), 1)
        self.assertTrue(relay.startup_cleanup_warnings)
        self.assertEqual(client.post(PORTAL, json={}).status_code, 200)

    def test_personal_key_never_lists_or_deletes_upstream_users(self) -> None:
        inner, recorded = _make_mock_snaptrade_transport(expected_client_id=PERSONAL_CLIENT_ID)
        transport, seen = _with_list_users(inner, ["n170-st-" + "b" * 24])
        _, client, _ = self._client(transport, client_id=PERSONAL_CLIENT_ID, dev_key=DEV_KEY)
        self.assertEqual(client.get(STATUS).status_code, 200)
        self.assertEqual(seen, [])
        self.assertEqual(_deleted_user_ids(recorded), [])


def _session_ids(relay: SnapTradeRelayCoordinator) -> list[str]:
    with relay._lock:
        return [s.user_id for s in relay._sessions.values()]


class TestRefusalThatRetryCannotFixFreesTheSeat(_AppCase):
    """A refusal a retry cannot fix ends the session; an upstream failure keeps it."""

    def _open(self) -> tuple[Any, VerifyApiTestClient, SnapTradeRelayCoordinator, list, str]:
        transport, recorded = _make_mock_snaptrade_transport()
        app, client, relay = self._client(transport)
        portal = client.post(PORTAL, json={})
        self.assertEqual(portal.status_code, 200, portal.text)
        return app, client, relay, recorded, portal.json()["session_token"]

    def _assert_seat_freed(self, client: VerifyApiTestClient, relay: Any, recorded: list, token: str) -> None:
        self.assertIsNone(relay.get_session(token))
        self.assertEqual(client.get(STATUS).json()["active_slots"], 0)
        self.assertEqual(len(_deleted_user_ids(recorded)), 1)

    def _assert_seat_kept(self, client: VerifyApiTestClient, relay: Any, recorded: list, token: str) -> None:
        self.assertIsNotNone(relay.get_session(token))
        self.assertEqual(client.get(STATUS).json()["active_slots"], 1)
        self.assertEqual(_deleted_user_ids(recorded), [])

    def test_missing_conversion_rate_frees_the_seat(self) -> None:
        from app.worker_isolation import WorkerValidationError

        _, client, relay, recorded, token = self._open()
        with mock.patch(
            "app.routes_snaptrade.run_isolated_one_shot_verification",
            side_effect=WorkerValidationError("No conversion rate from CAD to USD is available"),
        ):
            r = client.post(VERIFY, json={"session_token": token, "release_slot_after": False})
        self.assertEqual(r.status_code, 422, r.text)
        self._assert_seat_freed(client, relay, recorded, token)

    def test_governance_refusal_frees_the_seat(self) -> None:
        from app.store import GovernanceBlockedError

        _, client, relay, recorded, token = self._open()
        with mock.patch(
            "app.routes_snaptrade.run_isolated_one_shot_verification",
            side_effect=GovernanceBlockedError("connector not approved"),
        ):
            r = client.post(VERIFY, json={"session_token": token})
        self.assertEqual(r.status_code, 403, r.text)
        self._assert_seat_freed(client, relay, recorded, token)

    def test_publish_refusal_frees_the_seat(self) -> None:
        from app.store import PublisherKeyNotInRegistryError

        app, client, relay, recorded, token = self._open()

        def refuse(*_a: Any, **_k: Any) -> Any:
            raise PublisherKeyNotInRegistryError("signing key is not in this host's registry")

        app.store.store_proof = refuse  # type: ignore[method-assign]
        r = client.post(
            VERIFY, json={"session_token": token, "publish_proof": True, "release_slot_after": False}
        )
        self.assertEqual(r.status_code, 403, r.text)
        self._assert_seat_freed(client, relay, recorded, token)

    def test_no_linked_account_yet_keeps_the_seat_for_a_retry(self) -> None:
        from app.worker_isolation import WorkerValidationError

        _, client, relay, recorded, token = self._open()
        with mock.patch(
            "app.routes_snaptrade.run_isolated_one_shot_verification",
            side_effect=WorkerValidationError(
                "No brokerage accounts are connected to this SnapTrade session yet"
            ),
        ):
            r = client.post(VERIFY, json={"session_token": token})
        self.assertEqual(r.status_code, 422, r.text)
        self._assert_seat_kept(client, relay, recorded, token)

    def test_upstream_failure_keeps_the_seat_for_a_retry(self) -> None:
        inner, recorded = _make_mock_snaptrade_transport()

        def transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
            if urllib.parse.urlsplit(url).path == "/api/v1/accounts":
                return (503, {"Content-Type": "application/json"}, {"detail": "busy"})
            return inner(method, url, headers, body)

        _, client, relay = self._client(transport)
        token = client.post(PORTAL, json={}).json()["session_token"]
        r = client.post(VERIFY, json={"session_token": token})
        self.assertEqual(r.status_code, 502, r.text)
        self._assert_seat_kept(client, relay, recorded, token)


class TestNoUpstreamCallHoldsTheRelayLock(_AppCase):
    """A slow aggregator delays only the request waiting on it, never other relay requests."""

    def _run_in_thread(self, fn: Any) -> tuple[threading.Thread, dict[str, Any]]:
        out: dict[str, Any] = {}

        def target() -> None:
            out["result"] = fn()

        t = threading.Thread(target=target, daemon=True)
        t.start()
        return t, out

    def test_status_is_answered_while_a_portal_call_waits_on_upstream(self) -> None:
        inner, _ = _make_mock_snaptrade_transport()
        entered, release = threading.Event(), threading.Event()

        def transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
            if urllib.parse.urlsplit(url).path == "/api/v1/snapTrade/registerUser":
                entered.set()
                release.wait(10)
            return inner(method, url, headers, body)

        _, client, _ = self._client(transport)
        client.get(STATUS)  # first-use sweep happens here
        slow, slow_out = self._run_in_thread(lambda: client.post(PORTAL, json={}))
        try:
            self.assertTrue(entered.wait(5))
            fast, fast_out = self._run_in_thread(lambda: client.get(STATUS))
            fast.join(2.0)
            self.assertFalse(fast.is_alive(), "status waited behind an upstream call")
            self.assertEqual(fast_out["result"].status_code, 200)
            # The pending seat is already counted while its upstream call is in flight.
            self.assertEqual(fast_out["result"].json()["active_slots"], 1)
        finally:
            release.set()
            slow.join(10)
        self.assertEqual(slow_out["result"].status_code, 200, slow_out["result"].text)

    def test_a_portal_call_is_answered_while_the_sweep_waits_on_the_listing(self) -> None:
        inner, _ = _make_mock_snaptrade_transport()
        entered, release = threading.Event(), threading.Event()

        def transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
            if urllib.parse.urlsplit(url).path == "/api/v1/snapTrade/listUsers":
                entered.set()
                release.wait(10)
                return (200, {"Content-Type": "application/json"}, [])
            return inner(method, url, headers, body)

        _, client, _ = self._client(transport)
        sweep, _ = self._run_in_thread(lambda: client.get(STATUS))
        try:
            self.assertTrue(entered.wait(5))
            fast, fast_out = self._run_in_thread(lambda: client.post(PORTAL, json={}))
            fast.join(2.0)
            self.assertFalse(fast.is_alive(), "portal waited behind the sweep's upstream listing")
            self.assertEqual(fast_out["result"].status_code, 200, fast_out["result"].text)
        finally:
            release.set()
            sweep.join(10)

    def test_a_failed_portal_call_frees_its_reserved_seat(self) -> None:
        inner, recorded = _make_mock_snaptrade_transport()

        def transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
            if urllib.parse.urlsplit(url).path == "/api/v1/snapTrade/login":
                return (503, {"Content-Type": "application/json"}, {"detail": "busy"})
            return inner(method, url, headers, body)

        _, client, relay = self._client(transport)
        r = client.post(PORTAL, json={})
        self.assertEqual(r.status_code, 502, r.text)
        self.assertEqual(client.get(STATUS).json()["active_slots"], 0)
        self.assertEqual(_session_ids(relay), [])
        self.assertEqual(_deleted_user_ids(recorded), _registered_user_ids(recorded))

    def test_sweep_keeps_a_user_reserved_between_listing_and_deleting(self) -> None:
        inner, recorded = _make_mock_snaptrade_transport()
        first_leftover = OWN_PREFIX + "d" * 24
        reserved_id = OWN_PREFIX + "e" * 24
        state: dict[str, Any] = {}

        def transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
            parsed = urllib.parse.urlsplit(url)
            if method == "GET" and parsed.path == "/api/v1/snapTrade/listUsers":
                return (200, {"Content-Type": "application/json"}, [first_leftover, reserved_id])
            if parsed.path == "/api/v1/snapTrade/deleteUser" and "portal" not in state:
                # After the listing, before the sweep reaches the second id, a portal call
                # reserves exactly that id.
                with mock.patch("app.routes_snaptrade.secrets.token_hex", return_value="e" * 24):
                    state["portal"] = state["client"].post(PORTAL, json={})
            return inner(method, url, headers, body)

        _, client, relay = self._client(transport)
        state["client"] = client
        self.assertEqual(client.get(STATUS).status_code, 200)
        self.assertEqual(state["portal"].status_code, 200, state["portal"].text)
        self.assertIn(reserved_id, _registered_user_ids(recorded))
        self.assertEqual(_deleted_user_ids(recorded), [first_leftover])
        self.assertIn(reserved_id, _session_ids(relay))


class TestSweepTouchesOnlyThisDeployment(_AppCase):
    def test_user_ids_carry_this_deployments_tag_and_the_sweep_keeps_others(self) -> None:
        inner, recorded = _make_mock_snaptrade_transport()
        own_leftover = OWN_PREFIX + "a" * 24
        other_deployment = "n170-st-0123abcd-" + "a" * 24
        old_shape = "n170-st-" + "a" * 24
        transport, _ = _with_list_users(inner, [own_leftover, other_deployment, old_shape])
        _, client, _ = self._client(transport)

        self.assertEqual(client.get(STATUS).status_code, 200)
        self.assertEqual(_deleted_user_ids(recorded), [own_leftover])
        self.assertNotIn(TEST_SALT_HEX, OWN_PREFIX)
        client.post(PORTAL, json={})
        self.assertTrue(_registered_user_ids(recorded)[0].startswith(OWN_PREFIX))

    def test_a_failed_listing_is_retried_after_a_bounded_wait(self) -> None:
        inner, recorded = _make_mock_snaptrade_transport()
        now = [1000.0]
        leftover = OWN_PREFIX + "f" * 24
        replies = [(503, {"detail": "down"}), (200, [leftover])]
        seen: list[int] = []

        def transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
            if urllib.parse.urlsplit(url).path == "/api/v1/snapTrade/listUsers":
                seen.append(1)
                status, payload = replies[min(len(seen) - 1, len(replies) - 1)]
                return (status, {"Content-Type": "application/json"}, payload)
            return inner(method, url, headers, body)

        _, client, _ = self._client(transport, clock=lambda: now[0])
        client.get(STATUS)
        client.get(STATUS)
        self.assertEqual(len(seen), 1, "a failing listing must not be retried on every request")
        now[0] += 61.0
        client.get(STATUS)
        self.assertEqual(len(seen), 2)
        self.assertEqual(_deleted_user_ids(recorded), [leftover])
        now[0] += 10_000.0
        client.get(STATUS)
        self.assertEqual(len(seen), 2, "after a successful listing the sweep is done")


class TestRelayVerifyReportsWithheldReturn(_AppCase):
    def test_a_single_snapshot_reports_the_return_as_withheld(self) -> None:
        transport, _ = _make_mock_snaptrade_transport()
        _, client, _ = self._client(transport)
        token = client.post(PORTAL, json={}).json()["session_token"]
        r = client.post(VERIFY, json={"session_token": token})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertIs(body.get("performance_withheld"), True, sorted(body))
        self.assertTrue(body.get("withheld_reasons"))


if __name__ == "__main__":
    unittest.main()
