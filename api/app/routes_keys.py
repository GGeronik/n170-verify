"""Public C2SP-checkpointed publisher & notary key registry endpoint (/.well-known)."""

from __future__ import annotations

from typing import Any

from app.store import ProofStore


WELL_KNOWN_KEYS_HEADERS: dict[str, str] = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Accept, Content-Type",
    "Cache-Control": "public, max-age=300",
    "X-Content-Type-Options": "nosniff",
}


def handle_get_well_known_keys(*, store: ProofStore) -> tuple[int, dict[str, Any], dict[str, str]]:
    """Serve ``PublisherKeyRegistryDocument`` at ``GET /.well-known/n170-verify-keys.json``."""
    doc = store.build_registry_document()
    return 200, doc.to_dict(), dict(WELL_KNOWN_KEYS_HEADERS)


def handle_options_well_known_keys() -> tuple[int, bytes, dict[str, str]]:
    """Respond to browser WebCrypto CORS preflight on ``/.well-known/n170-verify-keys.json``."""
    return 204, b"", dict(WELL_KNOWN_KEYS_HEADERS)


__all__ = [
    "WELL_KNOWN_KEYS_HEADERS",
    "handle_get_well_known_keys",
    "handle_options_well_known_keys",
]
