"""N170 Verify v3 ASGI/FastAPI application, stdlib HTTP server, and zero-dep TestClient."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
from typing import Any
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

from app import __version__
from app.badges import handle_get_badge_svg
from app.config import ApiConfig
from app.privacy_scanner import OutboundPrivacyScanner
from app.routes_keys import (
    handle_get_well_known_keys,
    handle_options_well_known_keys,
)
from app.routes_leaderboard import handle_get_leaderboard
from app.routes_proofs import (
    handle_get_chain,
    handle_get_continuity_for_account,
    handle_get_proof,
    handle_post_append_chain,
    handle_post_enroll_chain,
    handle_post_proof,
    handle_post_verify_proof,
)
from app.routes_sync import (
    handle_delete_sync,
    handle_get_sync,
    handle_post_sync,
)
from app.routes_verify import handle_post_verify
from app.routes_viral import (
    MAX_STATEMENT_UPLOAD_BYTES,
    handle_get_challenge_card,
    handle_get_discord_embed,
    handle_get_head_to_head,
    handle_get_ibkr_flex_guide,
    handle_get_qr_payload,
    handle_post_plausibility,
    handle_post_verify_auto_detect,
)
from app.store import ProofStore
from app.sync_vault import (
    OAuthRevocationCallback,
    SyncVault,
    active_aes_gcm_backend,
)
from app.worker_isolation import WorkerPipelineSpec
from n170_verify.contracts import VERIFY_SCHEMA_VERSION
from n170_verify.crypto import active_ed25519_backend


try:
    from fastapi import FastAPI as _FastAPI
    from fastapi import Request as _FastAPIRequest
    from fastapi import Response as _FastAPIResponse

    _HAS_FASTAPI = True
except ImportError:  # pragma: no cover - exercised in zero-wheel stdlib sandbox
    _HAS_FASTAPI = False


DEFAULT_JSON_HEADERS: dict[str, str] = {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Accept, Content-Type",
}


class CaseInsensitiveHeaders(Mapping[str, str]):
    """Case-insensitive HTTP header mapping preserving original casing for serialization."""

    def __init__(self, initial: Mapping[str, str] | None = None) -> None:
        self._store: dict[str, tuple[str, str]] = {}
        if initial:
            for k, v in initial.items():
                self._store[k.lower()] = (k, str(v))

    def __getitem__(self, key: str) -> str:
        return self._store[key.lower()][1]

    def __iter__(self) -> Iterator[str]:
        for orig_k, _ in self._store.values():
            yield orig_k

    def __len__(self) -> int:
        return len(self._store)

    def get(self, key: str, default: Any = None) -> Any:
        entry = self._store.get(key.lower())
        return entry[1] if entry is not None else default

    def to_dict(self) -> dict[str, str]:
        return {orig_k: val for orig_k, val in self._store.values()}


@dataclass(slots=True)
class ApiResponse:
    """Normalized HTTP response returned by ``VerifyApiApplication.dispatch``."""

    status_code: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        cookie_keys = [k for k in list(self.headers.keys()) if k.lower() == "set-cookie"]
        for k in cookie_keys:
            del self.headers[k]

    @classmethod
    def json_response(
        cls,
        status_code: int,
        payload: Any,
        headers: Mapping[str, str] | None = None,
    ) -> ApiResponse:
        merged = dict(DEFAULT_JSON_HEADERS)
        if headers:
            merged.update(headers)
        if "frame-ancestors *" not in merged.get("Content-Security-Policy", "").lower():
            merged.setdefault("X-Frame-Options", "DENY")
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return cls(status_code=status_code, body=encoded, headers=merged)


def _parse_json_body(raw_body: bytes) -> tuple[bool, Any]:
    if not raw_body or not raw_body.strip():
        return True, {}
    try:
        parsed = json.loads(raw_body.decode("utf-8"))
        return True, parsed
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return False, f"Malformed JSON request body: {exc}"


def _flatten_query_params(query_string: str) -> dict[str, str]:
    if not query_string:
        return {}
    parsed = parse_qs(query_string, keep_blank_values=False)
    return {k: vals[-1] for k, vals in parsed.items() if vals}


def _is_sync_route(path: str) -> bool:
    return path == "/api/v1/sync" or path.startswith("/api/v1/sync/")


def _sync_json_response(status_code: int, payload: Any) -> ApiResponse:
    resp = ApiResponse.json_response(
        status_code,
        payload,
        headers={"Cache-Control": "no-store"},
    )
    resp.headers.pop("Access-Control-Allow-Origin", None)
    resp.headers.pop("Access-Control-Allow-Methods", None)
    resp.headers.pop("Access-Control-Allow-Headers", None)
    return resp


_ROUTE_BADGE_RE = re.compile(r"^/api/v1/badges/(?P<proof_id>.+)\.svg$")
_ROUTE_SYNC_ITEM_RE = re.compile(r"^/api/v1/sync/(?P<connection_id>[^/]+)$")
_ROUTE_PROOF_DISCORD_EMBED_RE = re.compile(r"^/api/v1/proofs/(?P<proof_id>.+)/discord-embed$")
_ROUTE_PROOF_QR_PAYLOAD_RE = re.compile(r"^/api/v1/proofs/(?P<proof_id>.+)/qr-payload$")
_ROUTE_PROOF_ITEM_RE = re.compile(r"^/api/v1/proofs/(?P<proof_id>[^/]+)$")
_ROUTE_CHAIN_APPEND_RE = re.compile(r"^/api/v1/chains/(?P<chain_id>[^/]+)/append$")
_ROUTE_CHAIN_ITEM_RE = re.compile(r"^/api/v1/chains/(?P<chain_id>[^/]+)$")
_ROUTE_CONTINUITY_RE = re.compile(r"^/api/v1/continuity/(?P<blinded_account_tag>[^/]+)$")
_ROUTE_VS_RE = re.compile(r"^/api/v1/vs/(?P<proof_a>[^/]+)/(?P<proof_b>[^/]+)$")
_ROUTE_VS_PREFIX_RE = re.compile(r"^/api/v1/vs(?:/.*)?$")


class VerifyApiApplication:
    """Zero-dependency ASGI 3.0 & synchronous router for N170 Verify v3."""

    def __init__(
        self,
        config: ApiConfig | None = None,
        *,
        store: ProofStore | None = None,
        sync_vault: SyncVault | None = None,
        pipeline_spec: WorkerPipelineSpec = None,
        oauth_revocation_callbacks: Mapping[str, OAuthRevocationCallback] | None = None,
    ) -> None:
        self.config = config or ApiConfig()
        self.store = store or ProofStore(self.config)
        self.sync_vault = sync_vault or SyncVault(
            db_path=self.config.sync_db_path,
            master_kek_hex=self.config.vault_master_kek_hex,
            publisher_keypair=self.config.publisher_keypair,
            publisher_kid=self.config.publisher_kid,
            account_blinding_salt_hex=self.config.account_blinding_salt_hex,
            backup_retention_hours=self.config.sync_backup_retention_hours,
            oauth_revocation_callbacks=oauth_revocation_callbacks,
        )
        self.pipeline_spec = pipeline_spec

    @property
    def verify_app(self) -> VerifyApiApplication:
        return self

    def close(self) -> None:
        self.store.close()
        self.sync_vault.close()

    def dispatch(
        self,
        method: str,
        raw_path: str,
        *,
        query_string: str = "",
        headers: Mapping[str, str] | None = None,
        body: bytes = b"",
    ) -> ApiResponse:
        """Dispatch an HTTP request synchronously to N170 Verify route handlers."""
        resp = self._dispatch_internal(
            method, raw_path, query_string=query_string, headers=headers, body=body
        )
        for k in list(resp.headers.keys()):
            if k.lower() == "set-cookie":
                del resp.headers[k]
        path = raw_path or "/"
        if not _is_sync_route(path) and resp.status_code < 500:
            scanner = OutboundPrivacyScanner()
            body_text = resp.body.decode("utf-8", errors="replace")
            violations = scanner.scan_text(body_text)
            if violations:
                return ApiResponse.json_response(
                    500,
                    {
                        "error": "privacy_leak_blocked",
                        "detail": "Outbound privacy scanner blocked response containing sensitive data",
                        "violations": violations,
                    },
                )
        return resp

    def _dispatch_internal(
        self,
        method: str,
        raw_path: str,
        *,
        query_string: str = "",
        headers: Mapping[str, str] | None = None,
        body: bytes = b"",
    ) -> ApiResponse:
        req_headers = CaseInsensitiveHeaders(headers)
        verb = method.strip().upper()
        path = raw_path or "/"

        # 1. Health check
        if path == "/healthz":
            if verb != "GET":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            return ApiResponse.json_response(
                200,
                {
                    "status": "ok",
                    "version": __version__,
                    "schema_version": VERIFY_SCHEMA_VERSION,
                    "hosted_multi_user_mode": self.config.hosted_multi_user_mode,
                    "allow_hosted_signing": self.config.allow_hosted_signing,
                    "ed25519_backend": active_ed25519_backend(),
                    "aes_gcm_backend": active_aes_gcm_backend(),
                },
            )

        # 2. Public C2SP Key Registry (/.well-known/n170-verify-keys.json)
        if path == "/.well-known/n170-verify-keys.json":
            if verb == "OPTIONS":
                st, raw_b, hdrs = handle_options_well_known_keys()
                return ApiResponse(status_code=st, body=raw_b, headers=hdrs)
            if verb == "GET":
                st, payload, hdrs = handle_get_well_known_keys(store=self.store)
                return ApiResponse.json_response(st, payload, headers=hdrs)
            return ApiResponse.json_response(405, {"error": "method_not_allowed"})

        # Refusal of signing oracle in hosted mode (allow_hosted_signing=False by default)
        if path in {"/api/v1/sign", "/api/v1/proofs/sign"}:
            if verb == "OPTIONS":
                return ApiResponse(
                    status_code=204,
                    body=b"",
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Accept, Content-Type",
                        "X-Content-Type-Options": "nosniff",
                    },
                )
            if verb != "POST":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            if self.config.hosted_multi_user_mode and not self.config.allow_hosted_signing:
                return ApiResponse.json_response(
                    403,
                    {
                        "error": "signing_oracle_disabled",
                        "detail": "Hosted mode refuses to sign payloads with server private keys",
                    },
                )

        if verb == "OPTIONS" and _is_sync_route(path):
            return ApiResponse(
                status_code=204,
                body=b"",
                headers={
                    "Cache-Control": "no-store",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                },
            )

        if verb == "OPTIONS" and (path == "/healthz" or path.startswith("/api/v1/")):
            return ApiResponse(
                status_code=204,
                body=b"",
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
                    "Access-Control-Allow-Headers": "Accept, Content-Type",
                    "X-Content-Type-Options": "nosniff",
                },
            )

        # 3. Subprocess-isolated one-shot verification (POST /api/v1/verify & /api/v1/verify/auto-detect)
        if path == "/api/v1/verify":
            if verb != "POST":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            ok, parsed = _parse_json_body(body)
            if not ok:
                return ApiResponse.json_response(400, {"error": "invalid_json", "detail": parsed})
            st, resp = handle_post_verify(
                parsed,
                config=self.config,
                store=self.store,
                sync_vault=self.sync_vault,
                pipeline_spec=self.pipeline_spec,
                headers=req_headers,
            )
            if isinstance(parsed, Mapping) and bool(parsed.get("persist_sync", False)):
                return _sync_json_response(st, resp)
            return ApiResponse.json_response(st, resp)

        if path == "/api/v1/verify/auto-detect":
            if verb != "POST":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            q_map = _flatten_query_params(query_string)
            st, resp = handle_post_verify_auto_detect(
                body,
                headers=req_headers,
                query_params=q_map,
                config=self.config,
                store=self.store,
            )
            return ApiResponse.json_response(st, resp)

        if path == "/api/v1/connect/ibkr-flex-guide":
            if verb != "GET":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            st, resp = handle_get_ibkr_flex_guide()
            return ApiResponse.json_response(st, resp)

        # 3b. Viral tools: Claim Plausibility, Challenge Card, and Head-to-Head Comparison
        if path == "/api/v1/tools/plausibility":
            if verb != "POST":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            st, resp = handle_post_plausibility(body)
            return ApiResponse.json_response(st, resp)

        if path == "/api/v1/challenge-card":
            if verb != "GET":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            q_map = _flatten_query_params(query_string)
            st, resp, hdrs = handle_get_challenge_card(q_map)
            return ApiResponse.json_response(st, resp, headers=hdrs)

        vs_match = _ROUTE_VS_RE.match(path)
        if vs_match is not None:
            if verb != "GET":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            proof_a = unquote(vs_match.group("proof_a"))
            proof_b = unquote(vs_match.group("proof_b"))
            q_map = _flatten_query_params(query_string)
            st, resp = handle_get_head_to_head(
                proof_a,
                proof_b,
                store=self.store,
                now_utc=q_map.get("now_utc"),
            )
            return ApiResponse.json_response(st, resp)

        if path != "/api/v1/vs" and _ROUTE_VS_PREFIX_RE.match(path) is not None:
            if verb != "GET":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            return ApiResponse.json_response(
                400,
                {
                    "error": "invalid_proof_id",
                    "detail": "Head-to-head route requires two valid proof IDs (/api/v1/vs/{proof_a}/{proof_b})",
                },
            )

        # 4. Opt-in Encrypted Sync Vault (/api/v1/sync & /api/v1/sync/{connection_id})
        if path == "/api/v1/sync":
            if verb != "POST":
                return _sync_json_response(405, {"error": "method_not_allowed"})
            ok, parsed = _parse_json_body(body)
            if not ok:
                return _sync_json_response(400, {"error": "invalid_json", "detail": parsed})
            st, resp = handle_post_sync(
                parsed,
                config=self.config,
                sync_vault=self.sync_vault,
                headers=req_headers,
            )
            return _sync_json_response(st, resp)

        sync_match = _ROUTE_SYNC_ITEM_RE.match(path)
        if sync_match is not None:
            conn_id = unquote(sync_match.group("connection_id"))
            if verb == "GET":
                st, resp = handle_get_sync(
                    conn_id,
                    sync_vault=self.sync_vault,
                    config=self.config,
                    headers=req_headers,
                )
                return _sync_json_response(st, resp)
            if verb == "DELETE":
                st, resp = handle_delete_sync(
                    conn_id,
                    sync_vault=self.sync_vault,
                    config=self.config,
                    headers=req_headers,
                )
                return _sync_json_response(st, resp)
            return _sync_json_response(405, {"error": "method_not_allowed"})

        # 5. Proofs & Dynamic Verification (/api/v1/proofs, /api/v1/proofs/verify, /api/v1/proofs/{proof_id})
        if path == "/api/v1/proofs":
            if verb != "POST":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            ok, parsed = _parse_json_body(body)
            if not ok:
                return ApiResponse.json_response(400, {"error": "invalid_json", "detail": parsed})
            st, resp = handle_post_proof(parsed, store=self.store)
            return ApiResponse.json_response(st, resp)

        if path == "/api/v1/proofs/verify":
            if verb != "POST":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            ok, parsed = _parse_json_body(body)
            if not ok:
                return ApiResponse.json_response(400, {"error": "invalid_json", "detail": parsed})
            st, resp = handle_post_verify_proof(parsed, store=self.store)
            return ApiResponse.json_response(st, resp)

        discord_embed_match = _ROUTE_PROOF_DISCORD_EMBED_RE.match(path)
        if discord_embed_match is not None:
            if verb != "GET":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            proof_id = unquote(discord_embed_match.group("proof_id"))
            q_map = _flatten_query_params(query_string)
            st, resp, hdrs = handle_get_discord_embed(
                proof_id,
                store=self.store,
                now_utc=q_map.get("now_utc"),
            )
            return ApiResponse.json_response(st, resp, headers=hdrs)

        qr_payload_match = _ROUTE_PROOF_QR_PAYLOAD_RE.match(path)
        if qr_payload_match is not None:
            if verb != "GET":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            proof_id = unquote(qr_payload_match.group("proof_id"))
            q_map = _flatten_query_params(query_string)
            st, resp, hdrs = handle_get_qr_payload(
                proof_id,
                store=self.store,
                now_utc=q_map.get("now_utc"),
            )
            return ApiResponse.json_response(st, resp, headers=hdrs)

        proof_match = _ROUTE_PROOF_ITEM_RE.match(path)
        if proof_match is not None:
            proof_id = unquote(proof_match.group("proof_id"))
            if verb != "GET":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            st, resp = handle_get_proof(proof_id, store=self.store)
            return ApiResponse.json_response(st, resp)

        # 6. Prospective Chains & Continuity Log
        if path == "/api/v1/chains":
            if verb != "POST":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            ok, parsed = _parse_json_body(body)
            if not ok:
                return ApiResponse.json_response(400, {"error": "invalid_json", "detail": parsed})
            st, resp = handle_post_enroll_chain(parsed, store=self.store)
            return ApiResponse.json_response(st, resp)

        chain_append_match = _ROUTE_CHAIN_APPEND_RE.match(path)
        if chain_append_match is not None:
            chain_id = unquote(chain_append_match.group("chain_id"))
            if verb != "POST":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            ok, parsed = _parse_json_body(body)
            if not ok:
                return ApiResponse.json_response(400, {"error": "invalid_json", "detail": parsed})
            st, resp = handle_post_append_chain(chain_id, parsed, store=self.store)
            return ApiResponse.json_response(st, resp)

        chain_item_match = _ROUTE_CHAIN_ITEM_RE.match(path)
        if chain_item_match is not None:
            chain_id = unquote(chain_item_match.group("chain_id"))
            if verb != "GET":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            q_map = _flatten_query_params(query_string)
            st, resp = handle_get_chain(
                chain_id, store=self.store, now_utc=q_map.get("now_utc")
            )
            return ApiResponse.json_response(st, resp)

        continuity_match = _ROUTE_CONTINUITY_RE.match(path)
        if continuity_match is not None:
            acct_tag = unquote(continuity_match.group("blinded_account_tag"))
            if verb != "GET":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            st, resp = handle_get_continuity_for_account(acct_tag, store=self.store)
            return ApiResponse.json_response(st, resp)

        # 7. SVG Badge (/api/v1/badges/{proof_id}.svg)
        badge_match = _ROUTE_BADGE_RE.match(path)
        if badge_match is not None:
            if verb != "GET":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            proof_id = unquote(badge_match.group("proof_id"))
            q_map = _flatten_query_params(query_string)
            st, svg_bytes, hdrs = handle_get_badge_svg(
                proof_id, store=self.store, query_params=q_map
            )
            return ApiResponse(status_code=st, body=svg_bytes, headers=hdrs)

        # 8. Opt-in Leaderboard (/api/v1/leaderboard)
        if path == "/api/v1/leaderboard":
            if verb != "GET":
                return ApiResponse.json_response(405, {"error": "method_not_allowed"})
            q_map = _flatten_query_params(query_string)
            st, resp = handle_get_leaderboard(q_map, store=self.store)
            return ApiResponse.json_response(st, resp)

        return ApiResponse.json_response(
            404, {"error": "not_found", "detail": f"No route matching {verb} {path}"}
        )

    async def __call__(self, scope: Mapping[str, Any], receive: Any, send: Any) -> None:
        """Standard ASGI 3.0 interface compatible with Uvicorn, Hypercorn, and httpx ASGITransport."""
        scope_type = scope.get("type")
        if scope_type == "lifespan":
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif msg["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
            return

        if scope_type != "http":
            raise RuntimeError(f"Unsupported ASGI scope type: {scope_type!r}")

        method = str(scope.get("method", "GET"))
        raw_path_bytes = scope.get("raw_path")
        if isinstance(raw_path_bytes, (bytes, bytearray)) and raw_path_bytes:
            raw_full = bytes(raw_path_bytes).decode("latin-1")
            raw_path = raw_full.split("?", 1)[0]
        else:
            raw_path = str(scope.get("path", "/"))

        qs_bytes = scope.get("query_string", b"")
        query_string = (
            bytes(qs_bytes).decode("latin-1")
            if isinstance(qs_bytes, (bytes, bytearray))
            else str(qs_bytes)
        )

        req_headers: dict[str, str] = {}
        for k_b, v_b in scope.get("headers", ()):
            req_headers[bytes(k_b).decode("latin-1")] = bytes(v_b).decode("latin-1")

        max_body_bytes = MAX_STATEMENT_UPLOAD_BYTES + 65_536
        cl_raw = req_headers.get("Content-Length") or req_headers.get("content-length")
        if cl_raw is not None:
            try:
                if int(cl_raw.strip()) > max_body_bytes:
                    await _send_asgi_response(send, _payload_too_large_response())
                    return
            except ValueError:
                pass

        chunks: list[bytes] = []
        total_bytes = 0
        while True:
            event = await receive()
            if event["type"] == "http.request":
                chunk = event.get("body", b"")
                if chunk:
                    chunk_bytes = bytes(chunk)
                    total_bytes += len(chunk_bytes)
                    if total_bytes > max_body_bytes:
                        await _send_asgi_response(send, _payload_too_large_response())
                        return
                    chunks.append(chunk_bytes)
                if not event.get("more_body", False):
                    break
            elif event["type"] == "http.disconnect":
                return

        body_bytes = b"".join(chunks)
        api_resp = await asyncio.to_thread(
            self.dispatch,
            method,
            raw_path,
            query_string=query_string,
            headers=req_headers,
            body=body_bytes,
        )
        await _send_asgi_response(send, api_resp)


def _payload_too_large_response() -> ApiResponse:
    return ApiResponse.json_response(
        413,
        {
            "error": "payload_too_large",
            "detail": f"Request exceeds maximum upload limit ({MAX_STATEMENT_UPLOAD_BYTES} bytes)",
        },
    )


async def _send_asgi_response(send: Any, resp: ApiResponse) -> None:
    asgi_headers = [
        (k.lower().encode("latin-1"), v.encode("latin-1"))
        for k, v in resp.headers.items()
        if k.lower() != "set-cookie"
    ]
    asgi_headers.append((b"content-length", str(len(resp.body)).encode("ascii")))
    await send({"type": "http.response.start", "status": resp.status_code, "headers": asgi_headers})
    await send({"type": "http.response.body", "body": resp.body, "more_body": False})


def mount_onto_fastapi(verify_app: VerifyApiApplication) -> Any:
    """Mount all N170 Verify routes onto a ``fastapi.FastAPI`` instance when FastAPI is installed."""
    if not _HAS_FASTAPI:
        raise RuntimeError("fastapi package is not installed in this Python environment")

    fapp = _FastAPI(
        title="N170 Verify API",
        version=__version__,
        description="Cryptographic brokerage verification, isolated workers, and C2SP continuity log",
    )
    fapp.state.verify_app = verify_app
    fapp.verify_app = verify_app  # type: ignore[attr-defined]
    fapp.config = verify_app.config  # type: ignore[attr-defined]
    fapp.store = verify_app.store  # type: ignore[attr-defined]
    fapp.sync_vault = verify_app.sync_vault  # type: ignore[attr-defined]

    def _to_fastapi_response(resp: ApiResponse) -> _FastAPIResponse:
        sanitized = {k: v for k, v in resp.headers.items() if k.lower() != "set-cookie"}
        return _FastAPIResponse(
            content=resp.body, status_code=resp.status_code, headers=sanitized
        )

    async def _proxy(request: _FastAPIRequest) -> _FastAPIResponse:
        max_body_bytes = MAX_STATEMENT_UPLOAD_BYTES + 65_536
        cl_header = request.headers.get("content-length")
        if cl_header is not None:
            try:
                if int(cl_header.strip()) > max_body_bytes:
                    return _to_fastapi_response(_payload_too_large_response())
            except ValueError:
                pass

        stream_chunks: list[bytes] = []
        stream_total = 0
        async for chunk in request.stream():
            if chunk:
                stream_total += len(chunk)
                if stream_total > max_body_bytes:
                    return _to_fastapi_response(_payload_too_large_response())
                stream_chunks.append(bytes(chunk))
        body = b"".join(stream_chunks)
        raw_path_bytes = request.scope.get("raw_path")
        if isinstance(raw_path_bytes, (bytes, bytearray)) and raw_path_bytes:
            raw_path = bytes(raw_path_bytes).decode("latin-1").split("?", 1)[0]
        else:
            raw_path = request.url.path
        qs = request.url.query
        resp = await asyncio.to_thread(
            verify_app.dispatch,
            request.method,
            raw_path,
            query_string=qs,
            headers=dict(request.headers),
            body=body,
        )
        return _to_fastapi_response(resp)

    for route_path, methods in (
        ("/healthz", ["GET", "OPTIONS"]),
        ("/.well-known/n170-verify-keys.json", ["GET", "OPTIONS"]),
        ("/api/v1/sign", ["POST", "OPTIONS"]),
        ("/api/v1/proofs/sign", ["POST", "OPTIONS"]),
        ("/api/v1/verify", ["POST", "OPTIONS"]),
        ("/api/v1/verify/auto-detect", ["POST", "OPTIONS"]),
        ("/api/v1/connect/ibkr-flex-guide", ["GET", "OPTIONS"]),
        ("/api/v1/tools/plausibility", ["POST", "OPTIONS"]),
        ("/api/v1/challenge-card", ["GET", "OPTIONS"]),
        ("/api/v1/vs/{proof_a}/{proof_b}", ["GET", "OPTIONS"]),
        ("/api/v1/vs/{rest:path}", ["GET", "OPTIONS"]),
        ("/api/v1/sync", ["POST", "OPTIONS"]),
        ("/api/v1/sync/{connection_id}", ["GET", "DELETE", "OPTIONS"]),
        ("/api/v1/proofs", ["POST", "OPTIONS"]),
        ("/api/v1/proofs/verify", ["POST", "OPTIONS"]),
        ("/api/v1/proofs/{proof_id:path}/discord-embed", ["GET", "OPTIONS"]),
        ("/api/v1/proofs/{proof_id:path}/qr-payload", ["GET", "OPTIONS"]),
        ("/api/v1/proofs/{proof_id}", ["GET", "OPTIONS"]),
        ("/api/v1/chains", ["POST", "OPTIONS"]),
        ("/api/v1/chains/{chain_id}/append", ["POST", "OPTIONS"]),
        ("/api/v1/chains/{chain_id}", ["GET", "OPTIONS"]),
        ("/api/v1/continuity/{blinded_account_tag}", ["GET", "OPTIONS"]),
        ("/api/v1/badges/{proof_id:path}.svg", ["GET", "OPTIONS"]),
        ("/api/v1/leaderboard", ["GET", "OPTIONS"]),
    ):
        fapp.add_api_route(route_path, _proxy, methods=methods)

    return fapp


def create_app(
    config: ApiConfig | None = None,
    *,
    store: ProofStore | None = None,
    sync_vault: SyncVault | None = None,
    pipeline_spec: WorkerPipelineSpec = None,
    oauth_revocation_callbacks: Mapping[str, OAuthRevocationCallback] | None = None,
    prefer_fastapi: bool = True,
) -> Any:
    """Create the N170 Verify application (FastAPI when installed, zero-dep ASGI otherwise)."""
    core_app = VerifyApiApplication(
        config=config,
        store=store,
        sync_vault=sync_vault,
        pipeline_spec=pipeline_spec,
        oauth_revocation_callbacks=oauth_revocation_callbacks,
    )
    if prefer_fastapi and _HAS_FASTAPI:
        return mount_onto_fastapi(core_app)
    return core_app


@dataclass(slots=True)
class TestClientResponse:
    """Ergonomic response object returned by ``VerifyApiTestClient``."""

    status_code: int
    content: bytes
    headers: CaseInsensitiveHeaders

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.content.decode("utf-8"))


class VerifyApiTestClient:
    """In-process zero-dependency HTTP test client for ``VerifyApiApplication`` and ``FastAPI``."""

    def __init__(self, target_app: Any) -> None:
        if isinstance(target_app, VerifyApiApplication):
            self._verify_app: VerifyApiApplication | None = target_app
            self._asgi_app: Any = target_app
        elif hasattr(target_app, "verify_app") and isinstance(
            target_app.verify_app, VerifyApiApplication
        ):
            self._verify_app = target_app.verify_app
            self._asgi_app = target_app
        elif hasattr(getattr(target_app, "state", None), "verify_app"):
            self._verify_app = target_app.state.verify_app
            self._asgi_app = target_app
        else:
            self._verify_app = None
            self._asgi_app = target_app

    def __enter__(self) -> VerifyApiTestClient:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Any = None,
        json: Any = None,
        content: bytes | str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> TestClientResponse:
        import json as _json

        split = urlsplit(url)
        raw_path = split.path or "/"
        qs = split.query
        if params:
            encoded_params = urlencode(
                {k: str(v) for k, v in params.items() if v is not None}
            )
            qs = f"{qs}&{encoded_params}" if qs else encoded_params

        req_headers = dict(headers or {})
        payload_obj = json if json is not None else json_body
        if payload_obj is not None:
            body_bytes = _json.dumps(payload_obj).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        elif isinstance(content, bytes):
            body_bytes = content
        elif isinstance(content, str):
            body_bytes = content.encode("utf-8")
        else:
            body_bytes = b""

        if self._verify_app is not None:
            resp = self._verify_app.dispatch(
                method,
                raw_path,
                query_string=qs,
                headers=req_headers,
                body=body_bytes,
            )
            return TestClientResponse(
                status_code=resp.status_code,
                content=resp.body,
                headers=CaseInsensitiveHeaders(resp.headers),
            )

        return asyncio.run(self._dispatch_asgi(method, raw_path, qs, req_headers, body_bytes))

    async def _dispatch_asgi(
        self,
        method: str,
        raw_path: str,
        query_string: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> TestClientResponse:
        status_code = 500
        resp_headers: dict[str, str] = {}
        chunks: list[bytes] = []
        sent_body = False

        async def _receive() -> dict[str, Any]:
            nonlocal sent_body
            if not sent_body:
                sent_body = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        async def _send(event: Mapping[str, Any]) -> None:
            nonlocal status_code
            if event["type"] == "http.response.start":
                status_code = int(event["status"])
                for k_b, v_b in event.get("headers", ()):
                    resp_headers[bytes(k_b).decode("latin-1")] = bytes(v_b).decode("latin-1")
            elif event["type"] == "http.response.body":
                part = event.get("body", b"")
                if part:
                    chunks.append(bytes(part))

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method.upper(),
            "scheme": "http",
            "path": unquote(raw_path),
            "raw_path": raw_path.encode("latin-1"),
            "query_string": query_string.encode("latin-1"),
            "headers": [
                (k.lower().encode("latin-1"), v.encode("latin-1"))
                for k, v in headers.items()
            ],
        }
        await self._asgi_app(scope, _receive, _send)
        return TestClientResponse(
            status_code=status_code,
            content=b"".join(chunks),
            headers=CaseInsensitiveHeaders(resp_headers),
        )

    def get(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> TestClientResponse:
        return self.request("GET", url, params=params, headers=headers)

    def post(
        self,
        url: str,
        *,
        json: Any = None,
        content: bytes | str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> TestClientResponse:
        return self.request("POST", url, json=json, content=content, headers=headers)

    def delete(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> TestClientResponse:
        return self.request("DELETE", url, headers=headers)

    def options(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> TestClientResponse:
        return self.request("OPTIONS", url, headers=headers)


def create_stdlib_http_server(
    verify_app: VerifyApiApplication,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
) -> ThreadingHTTPServer:
    """Create a multi-threaded stdlib ``http.server`` instance backed by ``verify_app``."""

    class _VerifyHttpRequestHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _write_response(self, resp: ApiResponse, *, close: bool = False) -> None:
            if close:
                self.close_connection = True
            self.send_response(resp.status_code)
            for hk, hv in resp.headers.items():
                self.send_header(hk, hv)
            self.send_header("Content-Length", str(len(resp.body)))
            self.end_headers()
            if resp.body:
                self.wfile.write(resp.body)

        def _handle_all(self) -> None:
            split = urlsplit(self.path)
            try:
                content_len = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                content_len = -1
            if content_len < 0:
                self._write_response(
                    ApiResponse.json_response(
                        400,
                        {"error": "invalid_content_length", "detail": "Invalid Content-Length header"},
                    ),
                    close=True,
                )
                return
            if content_len > MAX_STATEMENT_UPLOAD_BYTES + 65_536:
                self._write_response(_payload_too_large_response(), close=True)
                return

            req_body = self.rfile.read(content_len) if content_len > 0 else b""
            resp = verify_app.dispatch(
                self.command,
                split.path or "/",
                query_string=split.query,
                headers=dict(self.headers.items()),
                body=req_body,
            )
            self._write_response(resp)

        def do_GET(self) -> None:  # noqa: N802
            self._handle_all()

        def do_POST(self) -> None:  # noqa: N802
            self._handle_all()

        def do_DELETE(self) -> None:  # noqa: N802
            self._handle_all()

        def do_OPTIONS(self) -> None:  # noqa: N802
            self._handle_all()

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            # Redacted zero-PII silent access log by default
            del format, args

    return ThreadingHTTPServer((host, port), _VerifyHttpRequestHandler)


def run_cli(argv: list[str] | None = None) -> int:
    """CLI entrypoint running uvicorn if installed or stdlib ``ThreadingHTTPServer``."""
    parser = argparse.ArgumentParser(description="Run the N170 Verify v3 HTTP API server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    args = parser.parse_args(argv)

    cfg = ApiConfig.from_env()
    verify_app = VerifyApiApplication(cfg)
    try:
        import uvicorn  # type: ignore[import-not-found]

        asgi_target = mount_onto_fastapi(verify_app) if _HAS_FASTAPI else verify_app
        uvicorn.run(asgi_target, host=args.host, port=args.port)
        return 0
    except ImportError:
        httpd = create_stdlib_http_server(verify_app, host=args.host, port=args.port)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
            verify_app.close()
        return 0


app = create_app()


__all__ = [
    "ApiResponse",
    "CaseInsensitiveHeaders",
    "TestClientResponse",
    "VerifyApiApplication",
    "VerifyApiTestClient",
    "app",
    "create_app",
    "create_stdlib_http_server",
    "mount_onto_fastapi",
    "run_cli",
]


if __name__ == "__main__":
    raise SystemExit(run_cli())
