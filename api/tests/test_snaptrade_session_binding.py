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

import os
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
        for name in (SITE_ORIGIN_ENV, "N170_SNAPTRADE_DEV_KEY"):
            os.environ.pop(name, None)

    def _client(
        self,
        transport: Any,
        *,
        client_id: str = BUILD_CLIENT_ID,
        dev_key: str = "",
        hosted: bool = True,
    ) -> tuple[Any, VerifyApiTestClient, SnapTradeRelayCoordinator]:
        relay = SnapTradeRelayCoordinator(http_transport=transport)
        cfg = ApiConfig(
            publisher_keypair=self.kp,
            publisher_kid="n170-binding-test-kid",
            snaptrade_client_id=client_id,
            snaptrade_consumer_key=CONSUMER_KEY,
            snaptrade_dev_key=dev_key,
            account_blinding_salt_hex="5a" * 32,
            hosted_multi_user_mode=hosted,
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
            self.assertTrue(uid.startswith("n170-st-"), uid)
            self.assertEqual(len(uid), len("n170-st-") + 24, uid)


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


class TestRedirectLimitedToSiteOrigin(_AppCase):
    def _portal(self, client: VerifyApiTestClient, url: str) -> Any:
        return client.post(PORTAL, json={"redirect_url": url})

    def test_redirect_must_match_the_configured_origin_or_local_loopback(self) -> None:
        os.environ[SITE_ORIGIN_ENV] = "https://verify.example.org"
        transport, _ = _make_mock_snaptrade_transport()
        _, client, _ = self._client(transport)

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
        leftover = "n170-st-" + "a" * 24
        transport, seen = _with_list_users(inner, [leftover, "someone-else", 42])
        _, client, _ = self._client(transport)

        self.assertEqual(client.get(STATUS).status_code, 200)
        self.assertEqual(_deleted_user_ids(recorded), [leftover])

        self.assertEqual(client.get(STATUS).status_code, 200)
        self.assertEqual(len(seen), 1)
        self.assertEqual(_deleted_user_ids(recorded), [leftover])

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


if __name__ == "__main__":
    unittest.main()
