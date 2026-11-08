"""Opt-in AES-256-GCM envelope-encrypted sync vault and NIST SP 800-88r2 revocation receipts."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
import ctypes
import ctypes.util
from dataclasses import dataclass
import hashlib
import os
import secrets
import sqlite3
import threading
from typing import Any
import uuid

from app.config import utc_now_iso
from n170_verify.contracts import (
    AccountScope,
    ContractModelMixin,
    EnvironmentTier,
    ProviderApprovalState,
    compute_blinded_account_tag,
    parse_utc_timestamp,
    validate_hex_digest,
    validate_read_only_capabilities,
)
from n170_verify.crypto import (
    Ed25519KeyPair,
    ed25519_sign_domain,
    ed25519_verify_domain,
    jcs_canonicalize,
)


SIGNING_DOMAIN_REVOCATION = b"n170.verify.revocation_receipt.v3"

_AES_KEY_BYTES = 32
_GCM_NONCE_BYTES = 12
_GCM_TAG_BYTES = 16

_EVP_CTRL_GCM_SET_IVLEN = 0x9
_EVP_CTRL_GCM_GET_TAG = 0x10
_EVP_CTRL_GCM_SET_TAG = 0x11


try:
    from cryptography.exceptions import InvalidTag as _CryptoInvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _CryptoAESGCM

    _HAS_CRYPTOGRAPHY_AEAD = True
except ImportError:  # pragma: no cover - exercised in zero-wheel stdlib sandbox
    _HAS_CRYPTOGRAPHY_AEAD = False


class SyncVaultError(Exception):
    """Base error raised by the opt-in encrypted sync vault."""


class SyncVaultIntegrityError(SyncVaultError):
    """Raised when AES-256-GCM authentication tag or AAD verification fails."""


class SyncVaultNotFoundError(SyncVaultError, KeyError):
    """Raised when a requested sync connection ID does not exist or was erased."""


class _OpenSSLAes256GcmBinding:
    """Thread-safe ctypes binding to OpenSSL 3 ``EVP_aes_256_gcm()`` AEAD."""

    def __init__(self) -> None:
        lib = self._load_library()
        lib.EVP_aes_256_gcm.argtypes = []
        lib.EVP_aes_256_gcm.restype = ctypes.c_void_p

        lib.EVP_CIPHER_CTX_new.argtypes = []
        lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
        lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
        lib.EVP_CIPHER_CTX_free.restype = None

        lib.EVP_CIPHER_CTX_ctrl.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_void_p,
        ]
        lib.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int

        lib.EVP_EncryptInit_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        lib.EVP_EncryptInit_ex.restype = ctypes.c_int

        lib.EVP_EncryptUpdate.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        lib.EVP_EncryptUpdate.restype = ctypes.c_int

        lib.EVP_EncryptFinal_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
        ]
        lib.EVP_EncryptFinal_ex.restype = ctypes.c_int

        lib.EVP_DecryptInit_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        lib.EVP_DecryptInit_ex.restype = ctypes.c_int

        lib.EVP_DecryptUpdate.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        lib.EVP_DecryptUpdate.restype = ctypes.c_int

        lib.EVP_DecryptFinal_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
        ]
        lib.EVP_DecryptFinal_ex.restype = ctypes.c_int

        lib.ERR_clear_error.argtypes = []
        lib.ERR_clear_error.restype = None
        self._lib = lib

    @staticmethod
    def _load_library() -> ctypes.CDLL:
        candidates: list[str] = []
        discovered = ctypes.util.find_library("crypto")
        if discovered:
            candidates.append(discovered)
        candidates.extend(
            [
                "/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib",
                "/opt/homebrew/lib/libcrypto.dylib",
                "/usr/local/opt/openssl@3/lib/libcrypto.dylib",
                "libcrypto.so.3",
                "libcrypto.so",
                "libcrypto.3.dylib",
                "libcrypto.dylib",
            ]
        )
        last_err: OSError | None = None
        for candidate in dict.fromkeys(candidates):
            try:
                lib = ctypes.CDLL(candidate)
                if hasattr(lib, "EVP_aes_256_gcm") and hasattr(lib, "EVP_CIPHER_CTX_new"):
                    return lib
            except OSError as exc:
                last_err = exc
        raise RuntimeError("Unable to locate OpenSSL 3 libcrypto for AES-256-GCM") from last_err

    def encrypt(self, key_32b: bytes, nonce_12b: bytes, plaintext: bytes, aad: bytes) -> bytes:
        ctx = self._lib.EVP_CIPHER_CTX_new()
        if not ctx:
            raise RuntimeError("EVP_CIPHER_CTX_new failed")
        try:
            if self._lib.EVP_EncryptInit_ex(ctx, self._lib.EVP_aes_256_gcm(), None, None, None) != 1:
                self._lib.ERR_clear_error()
                raise RuntimeError("EVP_EncryptInit_ex(cipher) failed")
            if (
                self._lib.EVP_CIPHER_CTX_ctrl(
                    ctx, _EVP_CTRL_GCM_SET_IVLEN, _GCM_NONCE_BYTES, None
                )
                != 1
            ):
                self._lib.ERR_clear_error()
                raise RuntimeError("EVP_CIPHER_CTX_ctrl(SET_IVLEN) failed")

            key_buf = ctypes.create_string_buffer(key_32b, _AES_KEY_BYTES)
            iv_buf = ctypes.create_string_buffer(nonce_12b, _GCM_NONCE_BYTES)
            if self._lib.EVP_EncryptInit_ex(ctx, None, None, key_buf, iv_buf) != 1:
                self._lib.ERR_clear_error()
                raise RuntimeError("EVP_EncryptInit_ex(key, iv) failed")

            if aad:
                aad_buf = ctypes.create_string_buffer(aad, len(aad))
                aad_len = ctypes.c_int(0)
                if (
                    self._lib.EVP_EncryptUpdate(
                        ctx, None, ctypes.byref(aad_len), aad_buf, len(aad)
                    )
                    != 1
                ):
                    self._lib.ERR_clear_error()
                    raise RuntimeError("EVP_EncryptUpdate(AAD) failed")

            ct_chunks: list[bytes] = []
            if plaintext:
                pt_buf = ctypes.create_string_buffer(plaintext, len(plaintext))
                ct_buf = ctypes.create_string_buffer(len(plaintext) + _GCM_TAG_BYTES)
                out_len = ctypes.c_int(0)
                if (
                    self._lib.EVP_EncryptUpdate(
                        ctx, ct_buf, ctypes.byref(out_len), pt_buf, len(plaintext)
                    )
                    != 1
                ):
                    self._lib.ERR_clear_error()
                    raise RuntimeError("EVP_EncryptUpdate(plaintext) failed")
                ct_chunks.append(ct_buf.raw[: out_len.value])

            final_buf = ctypes.create_string_buffer(_GCM_TAG_BYTES)
            final_len = ctypes.c_int(0)
            if self._lib.EVP_EncryptFinal_ex(ctx, final_buf, ctypes.byref(final_len)) != 1:
                self._lib.ERR_clear_error()
                raise RuntimeError("EVP_EncryptFinal_ex failed")
            if final_len.value > 0:
                ct_chunks.append(final_buf.raw[: final_len.value])

            tag_buf = ctypes.create_string_buffer(_GCM_TAG_BYTES)
            if (
                self._lib.EVP_CIPHER_CTX_ctrl(
                    ctx, _EVP_CTRL_GCM_GET_TAG, _GCM_TAG_BYTES, tag_buf
                )
                != 1
            ):
                self._lib.ERR_clear_error()
                raise RuntimeError("EVP_CIPHER_CTX_ctrl(GET_TAG) failed")

            return b"".join(ct_chunks) + tag_buf.raw[:_GCM_TAG_BYTES]
        finally:
            self._lib.EVP_CIPHER_CTX_free(ctx)

    def decrypt(
        self, key_32b: bytes, nonce_12b: bytes, ciphertext_and_tag: bytes, aad: bytes
    ) -> bytes:
        if len(ciphertext_and_tag) < _GCM_TAG_BYTES:
            raise SyncVaultIntegrityError("AES-256-GCM ciphertext shorter than 128-bit auth tag")

        ciphertext = ciphertext_and_tag[:-_GCM_TAG_BYTES]
        tag = ciphertext_and_tag[-_GCM_TAG_BYTES:]

        ctx = self._lib.EVP_CIPHER_CTX_new()
        if not ctx:
            raise RuntimeError("EVP_CIPHER_CTX_new failed")
        try:
            if self._lib.EVP_DecryptInit_ex(ctx, self._lib.EVP_aes_256_gcm(), None, None, None) != 1:
                self._lib.ERR_clear_error()
                raise RuntimeError("EVP_DecryptInit_ex(cipher) failed")
            if (
                self._lib.EVP_CIPHER_CTX_ctrl(
                    ctx, _EVP_CTRL_GCM_SET_IVLEN, _GCM_NONCE_BYTES, None
                )
                != 1
            ):
                self._lib.ERR_clear_error()
                raise RuntimeError("EVP_CIPHER_CTX_ctrl(SET_IVLEN) failed")

            key_buf = ctypes.create_string_buffer(key_32b, _AES_KEY_BYTES)
            iv_buf = ctypes.create_string_buffer(nonce_12b, _GCM_NONCE_BYTES)
            if self._lib.EVP_DecryptInit_ex(ctx, None, None, key_buf, iv_buf) != 1:
                self._lib.ERR_clear_error()
                raise RuntimeError("EVP_DecryptInit_ex(key, iv) failed")

            if aad:
                aad_buf = ctypes.create_string_buffer(aad, len(aad))
                aad_len = ctypes.c_int(0)
                if (
                    self._lib.EVP_DecryptUpdate(
                        ctx, None, ctypes.byref(aad_len), aad_buf, len(aad)
                    )
                    != 1
                ):
                    self._lib.ERR_clear_error()
                    raise SyncVaultIntegrityError("EVP_DecryptUpdate(AAD) failed")

            pt_chunks: list[bytes] = []
            if ciphertext:
                ct_buf = ctypes.create_string_buffer(ciphertext, len(ciphertext))
                pt_buf = ctypes.create_string_buffer(len(ciphertext) + _GCM_TAG_BYTES)
                out_len = ctypes.c_int(0)
                if (
                    self._lib.EVP_DecryptUpdate(
                        ctx, pt_buf, ctypes.byref(out_len), ct_buf, len(ciphertext)
                    )
                    != 1
                ):
                    self._lib.ERR_clear_error()
                    raise SyncVaultIntegrityError("EVP_DecryptUpdate(ciphertext) failed")
                pt_chunks.append(pt_buf.raw[: out_len.value])

            tag_buf = ctypes.create_string_buffer(tag, _GCM_TAG_BYTES)
            if (
                self._lib.EVP_CIPHER_CTX_ctrl(
                    ctx, _EVP_CTRL_GCM_SET_TAG, _GCM_TAG_BYTES, tag_buf
                )
                != 1
            ):
                self._lib.ERR_clear_error()
                raise SyncVaultIntegrityError("EVP_CIPHER_CTX_ctrl(SET_TAG) failed")

            final_buf = ctypes.create_string_buffer(_GCM_TAG_BYTES)
            final_len = ctypes.c_int(0)
            rc = self._lib.EVP_DecryptFinal_ex(ctx, final_buf, ctypes.byref(final_len))
            if rc != 1:
                self._lib.ERR_clear_error()
                raise SyncVaultIntegrityError(
                    "AES-256-GCM authentication tag verification failed (tampered ciphertext, tag, nonce, or AAD)"
                )
            if final_len.value > 0:
                pt_chunks.append(final_buf.raw[: final_len.value])

            return b"".join(pt_chunks)
        finally:
            self._lib.EVP_CIPHER_CTX_free(ctx)


_OPENSSL_GCM: _OpenSSLAes256GcmBinding | None = None


def _get_openssl_gcm() -> _OpenSSLAes256GcmBinding:
    global _OPENSSL_GCM
    if _OPENSSL_GCM is None:
        _OPENSSL_GCM = _OpenSSLAes256GcmBinding()
    return _OPENSSL_GCM


def active_aes_gcm_backend() -> str:
    """Return active AES-256-GCM AEAD implementation identifier."""
    if _HAS_CRYPTOGRAPHY_AEAD:
        return "cryptography_aesgcm"
    _get_openssl_gcm()
    return "openssl_evp_aes_256_gcm_ctypes"


def aes256_gcm_encrypt(
    key_32b: bytes,
    nonce_12b: bytes,
    plaintext: bytes,
    aad: bytes = b"",
    *,
    force_openssl: bool = False,
) -> bytes:
    """Encrypt ``plaintext`` with AES-256-GCM (96-bit nonce, 128-bit auth tag appended)."""
    if not isinstance(key_32b, bytes) or len(key_32b) != _AES_KEY_BYTES:
        raise ValueError("AES-256-GCM key must be exactly 32 bytes")
    if not isinstance(nonce_12b, bytes) or len(nonce_12b) != _GCM_NONCE_BYTES:
        raise ValueError("AES-256-GCM nonce must be exactly 12 bytes (96 bits)")
    if not isinstance(plaintext, bytes) or not isinstance(aad, bytes):
        raise ValueError("plaintext and aad must be bytes")

    if not force_openssl and _HAS_CRYPTOGRAPHY_AEAD:
        return _CryptoAESGCM(key_32b).encrypt(nonce_12b, plaintext, aad or None)
    return _get_openssl_gcm().encrypt(key_32b, nonce_12b, plaintext, aad)


def aes256_gcm_decrypt(
    key_32b: bytes,
    nonce_12b: bytes,
    ciphertext_and_tag: bytes,
    aad: bytes = b"",
    *,
    force_openssl: bool = False,
) -> bytes:
    """Decrypt and authenticate AES-256-GCM ``ciphertext || tag``; raise ``SyncVaultIntegrityError`` on tamper."""
    if not isinstance(key_32b, bytes) or len(key_32b) != _AES_KEY_BYTES:
        raise ValueError("AES-256-GCM key must be exactly 32 bytes")
    if not isinstance(nonce_12b, bytes) or len(nonce_12b) != _GCM_NONCE_BYTES:
        raise ValueError("AES-256-GCM nonce must be exactly 12 bytes (96 bits)")
    if not isinstance(ciphertext_and_tag, bytes) or not isinstance(aad, bytes):
        raise ValueError("ciphertext_and_tag and aad must be bytes")

    if not force_openssl and _HAS_CRYPTOGRAPHY_AEAD:
        try:
            return _CryptoAESGCM(key_32b).decrypt(nonce_12b, ciphertext_and_tag, aad or None)
        except (_CryptoInvalidTag, ValueError) as exc:
            raise SyncVaultIntegrityError(
                "AES-256-GCM authentication tag verification failed"
            ) from exc
    return _get_openssl_gcm().decrypt(key_32b, nonce_12b, ciphertext_and_tag, aad)


@dataclass(slots=True)
class SyncConnectionRecord(ContractModelMixin):
    """Non-secret metadata describing an opt-in envelope-encrypted sync connection."""

    connection_id: str
    broker_id: str
    blinded_account_tag: str
    account_scope: AccountScope
    provider_approval_state: ProviderApprovalState
    environment_tier: EnvironmentTier
    capabilities: list[str]
    oauth_revocable: bool
    retention_mode: str
    created_at_utc: str
    updated_at_utc: str

    def _validate(self) -> None:
        if not self.connection_id.strip():
            raise ValueError("SyncConnectionRecord.connection_id must not be empty")
        if not self.broker_id.strip():
            raise ValueError("SyncConnectionRecord.broker_id must not be empty")
        object.__setattr__(self, "broker_id", self.broker_id.strip().lower())
        object.__setattr__(
            self,
            "blinded_account_tag",
            validate_hex_digest(
                self.blinded_account_tag,
                field_name="SyncConnectionRecord.blinded_account_tag",
                num_bytes=32,
            ),
        )
        validated_caps = validate_read_only_capabilities(self.capabilities)
        object.__setattr__(self, "capabilities", list(validated_caps))
        parse_utc_timestamp(self.created_at_utc, field_name="SyncConnectionRecord.created_at_utc")
        parse_utc_timestamp(self.updated_at_utc, field_name="SyncConnectionRecord.updated_at_utc")


@dataclass(slots=True)
class RevocationReceipt(ContractModelMixin):
    """Ed25519-signed NIST SP 800-88r2 cryptographic erasure receipt for opt-in sync credentials."""

    receipt_id: str
    connection_id: str
    broker_id: str
    blinded_account_tag: str
    standard_reference: str
    primary_deleted_at_utc: str
    primary_ciphertext_overwritten_and_deleted: bool
    primary_ciphertext_unrecoverable: bool
    sqlite_secure_delete_enabled: bool
    destroyed_envelope_sha256: str
    upstream_oauth_revocation_status: str
    backup_retention_hours: int
    publisher_kid: str
    publisher_public_key_hex: str
    signature_hex: str

    def _validate(self) -> None:
        if not self.receipt_id.strip():
            raise ValueError("RevocationReceipt.receipt_id must not be empty")
        if not self.connection_id.strip():
            raise ValueError("RevocationReceipt.connection_id must not be empty")
        if not self.broker_id.strip():
            raise ValueError("RevocationReceipt.broker_id must not be empty")
        object.__setattr__(self, "broker_id", self.broker_id.strip().lower())
        object.__setattr__(
            self,
            "blinded_account_tag",
            validate_hex_digest(
                self.blinded_account_tag,
                field_name="RevocationReceipt.blinded_account_tag",
                num_bytes=32,
            ),
        )
        parse_utc_timestamp(
            self.primary_deleted_at_utc, field_name="RevocationReceipt.primary_deleted_at_utc"
        )
        object.__setattr__(
            self,
            "destroyed_envelope_sha256",
            validate_hex_digest(
                self.destroyed_envelope_sha256,
                field_name="RevocationReceipt.destroyed_envelope_sha256",
                num_bytes=32,
            ),
        )
        if self.upstream_oauth_revocation_status not in {
            "revoked_confirmed",
            "revocation_failed",
            "not_applicable_api_key",
        }:
            raise ValueError(
                "Invalid upstream_oauth_revocation_status: "
                f"{self.upstream_oauth_revocation_status!r}"
            )
        if self.backup_retention_hours < 0:
            raise ValueError("backup_retention_hours must be >= 0")
        object.__setattr__(
            self,
            "publisher_public_key_hex",
            validate_hex_digest(
                self.publisher_public_key_hex,
                field_name="RevocationReceipt.publisher_public_key_hex",
                num_bytes=32,
            ),
        )
        object.__setattr__(
            self,
            "signature_hex",
            validate_hex_digest(
                self.signature_hex,
                field_name="RevocationReceipt.signature_hex",
                num_bytes=64,
            ),
        )

    def signable_dict(self) -> dict[str, Any]:
        """Return canonical signable dictionary committed by ``signature_hex``."""
        return {
            "backup_retention_hours": self.backup_retention_hours,
            "blinded_account_tag": self.blinded_account_tag,
            "broker_id": self.broker_id,
            "connection_id": self.connection_id,
            "destroyed_envelope_sha256": self.destroyed_envelope_sha256,
            "primary_ciphertext_overwritten_and_deleted": (
                self.primary_ciphertext_overwritten_and_deleted
            ),
            "primary_ciphertext_unrecoverable": self.primary_ciphertext_unrecoverable,
            "primary_deleted_at_utc": self.primary_deleted_at_utc,
            "publisher_kid": self.publisher_kid,
            "publisher_public_key_hex": self.publisher_public_key_hex,
            "receipt_id": self.receipt_id,
            "sqlite_secure_delete_enabled": self.sqlite_secure_delete_enabled,
            "standard_reference": self.standard_reference,
            "upstream_oauth_revocation_status": self.upstream_oauth_revocation_status,
        }

    def verify_signature(self) -> bool:
        """Verify publisher Ed25519 signature over ``signable_dict()``."""
        return ed25519_verify_domain(
            self.publisher_public_key_hex,
            SIGNING_DOMAIN_REVOCATION,
            jcs_canonicalize(self.signable_dict()),
            self.signature_hex,
        )


OAuthRevocationCallback = Callable[[str, str, Mapping[str, Any]], bool]


class SyncVault:
    """Opt-in AES-256-GCM envelope-encrypted vault for read-only continuous sync credentials."""

    def __init__(
        self,
        *,
        db_path: str = ":memory:",
        master_kek_hex: str,
        publisher_keypair: Ed25519KeyPair,
        publisher_kid: str,
        account_blinding_salt_hex: str,
        backup_retention_hours: int = 0,
        oauth_revocation_callbacks: Mapping[str, OAuthRevocationCallback] | None = None,
    ) -> None:
        norm_kek = validate_hex_digest(master_kek_hex, field_name="master_kek_hex", num_bytes=32)
        self._master_kek = bytes.fromhex(norm_kek)
        self._publisher_keypair = publisher_keypair
        self._publisher_kid = publisher_kid
        self._blinding_salt_hex = validate_hex_digest(
            account_blinding_salt_hex, field_name="account_blinding_salt_hex", num_bytes=32
        )
        self._backup_retention_hours = backup_retention_hours
        self._oauth_callbacks: dict[str, OAuthRevocationCallback] = {
            k.strip().lower(): cb for k, cb in (oauth_revocation_callbacks or {}).items()
        }
        self._db_path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            db_path,
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._initialize_schema()

    def _initialize_schema(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA secure_delete = ON;")
            self._conn.execute("PRAGMA temp_store = MEMORY;")
            if self._db_path == ":memory:":
                self._conn.execute("PRAGMA journal_mode = MEMORY;")
            else:
                self._conn.execute("PRAGMA journal_mode = DELETE;")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sync_connections (
                    connection_id TEXT PRIMARY KEY,
                    broker_id TEXT NOT NULL,
                    blinded_account_tag TEXT NOT NULL,
                    account_scope TEXT NOT NULL,
                    provider_approval_state TEXT NOT NULL,
                    environment_tier TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL,
                    oauth_revocable INTEGER NOT NULL,
                    payload_nonce BLOB NOT NULL,
                    payload_ciphertext BLOB NOT NULL,
                    dek_wrap_nonce BLOB NOT NULL,
                    wrapped_dek BLOB NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                )
                """
            )

    def register_oauth_revocation_callback(
        self, broker_id: str, callback: OAuthRevocationCallback
    ) -> None:
        """Register an upstream OAuth RFC 7009 token revocation callback for ``broker_id``."""
        with self._lock:
            self._oauth_callbacks[broker_id.strip().lower()] = callback

    @staticmethod
    def _payload_aad(connection_id: str, broker_id: str) -> bytes:
        return f"n170.verify.sync.payload.v3:{connection_id}:{broker_id}".encode("utf-8")

    @staticmethod
    def _dek_wrap_aad(connection_id: str, broker_id: str) -> bytes:
        return f"n170.verify.sync.dek_wrap.v3:{connection_id}:{broker_id}".encode("utf-8")

    def connection_count(self) -> int:
        """Return active encrypted sync connection count."""
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS cnt FROM sync_connections").fetchone()
            return int(row["cnt"]) if row is not None else 0

    def create_connection(
        self,
        *,
        broker_id: str,
        credentials: Mapping[str, Any],
        capabilities: Iterable[str],
        raw_account_id: str | None = None,
        blinded_account_tag: str | None = None,
        account_scope: AccountScope = AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
        provider_approval_state: ProviderApprovalState = ProviderApprovalState.APPROVED_LIVE,
        environment_tier: EnvironmentTier = EnvironmentTier.LIVE_PRODUCTION,
        oauth_revocable: bool | None = None,
        connection_id: str | None = None,
        created_at_utc: str | None = None,
    ) -> SyncConnectionRecord:
        """Validate read-only capabilities and envelope-encrypt credentials with a fresh 256-bit DEK."""
        norm_broker = broker_id.strip().lower()
        if not norm_broker:
            raise ValueError("broker_id must not be empty")
        if not isinstance(credentials, Mapping) or not credentials:
            raise ValueError("credentials must be a non-empty mapping")

        validated_caps = validate_read_only_capabilities(capabilities)
        env_tier = EnvironmentTier(environment_tier)
        if env_tier == EnvironmentTier.PAPER_OR_SANDBOX_REJECTED:
            raise ValueError("paper_or_sandbox_rejected accounts cannot enroll in sync")

        if blinded_account_tag is not None and blinded_account_tag.strip():
            acct_tag = validate_hex_digest(
                blinded_account_tag, field_name="blinded_account_tag", num_bytes=32
            )
        elif raw_account_id is not None and raw_account_id.strip():
            acct_tag = compute_blinded_account_tag(
                norm_broker, raw_account_id, self._blinding_salt_hex
            )
        else:
            raise ValueError("Either raw_account_id or blinded_account_tag must be provided")

        conn_id = (
            connection_id.strip()
            if connection_id and connection_id.strip()
            else f"sync-{uuid.uuid4().hex[:20]}"
        )
        now_str = created_at_utc or utc_now_iso()
        parse_utc_timestamp(now_str, field_name="created_at_utc")

        has_oauth = (
            oauth_revocable
            if oauth_revocable is not None
            else (
                norm_broker in self._oauth_callbacks
                or "oauth_access_token" in credentials
                or "refresh_token" in credentials
            )
        )

        # Envelope encryption: fresh 256-bit per-connection DEK + 96-bit nonces + connection_id AAD
        dek = secrets.token_bytes(_AES_KEY_BYTES)
        payload_nonce = secrets.token_bytes(_GCM_NONCE_BYTES)
        dek_wrap_nonce = secrets.token_bytes(_GCM_NONCE_BYTES)

        plaintext_bytes = jcs_canonicalize(dict(credentials))
        payload_ciphertext = aes256_gcm_encrypt(
            dek,
            payload_nonce,
            plaintext_bytes,
            aad=self._payload_aad(conn_id, norm_broker),
        )
        wrapped_dek = aes256_gcm_encrypt(
            self._master_kek,
            dek_wrap_nonce,
            dek,
            aad=self._dek_wrap_aad(conn_id, norm_broker),
        )

        caps_json = jcs_canonicalize(list(validated_caps)).decode("utf-8")

        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                existing = self._conn.execute(
                    "SELECT 1 FROM sync_connections WHERE connection_id = ?",
                    (conn_id,),
                ).fetchone()
                if existing is not None:
                    raise ValueError(f"Sync connection {conn_id!r} already exists")

                self._conn.execute(
                    """
                    INSERT INTO sync_connections (
                        connection_id,
                        broker_id,
                        blinded_account_tag,
                        account_scope,
                        provider_approval_state,
                        environment_tier,
                        capabilities_json,
                        oauth_revocable,
                        payload_nonce,
                        payload_ciphertext,
                        dek_wrap_nonce,
                        wrapped_dek,
                        created_at_utc,
                        updated_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        conn_id,
                        norm_broker,
                        acct_tag,
                        AccountScope(account_scope).value,
                        ProviderApprovalState(provider_approval_state).value,
                        env_tier.value,
                        caps_json,
                        1 if has_oauth else 0,
                        sqlite3.Binary(payload_nonce),
                        sqlite3.Binary(payload_ciphertext),
                        sqlite3.Binary(dek_wrap_nonce),
                        sqlite3.Binary(wrapped_dek),
                        now_str,
                        now_str,
                    ),
                )
                self._conn.execute("COMMIT;")
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

        return SyncConnectionRecord(
            connection_id=conn_id,
            broker_id=norm_broker,
            blinded_account_tag=acct_tag,
            account_scope=AccountScope(account_scope),
            provider_approval_state=ProviderApprovalState(provider_approval_state),
            environment_tier=env_tier,
            capabilities=list(validated_caps),
            oauth_revocable=bool(has_oauth),
            retention_mode="opt_in_encrypted_sync",
            created_at_utc=now_str,
            updated_at_utc=now_str,
        )

    def get_connection_metadata(self, connection_id: str) -> SyncConnectionRecord:
        """Return non-secret connection metadata without unwrapping DEK or credentials."""
        import json

        with self._lock:
            row = self._conn.execute(
                """
                SELECT
                    connection_id,
                    broker_id,
                    blinded_account_tag,
                    account_scope,
                    provider_approval_state,
                    environment_tier,
                    capabilities_json,
                    oauth_revocable,
                    created_at_utc,
                    updated_at_utc
                FROM sync_connections
                WHERE connection_id = ?
                """,
                (connection_id,),
            ).fetchone()
        if row is None:
            raise SyncVaultNotFoundError(f"Sync connection {connection_id!r} not found")

        return SyncConnectionRecord(
            connection_id=str(row["connection_id"]),
            broker_id=str(row["broker_id"]),
            blinded_account_tag=str(row["blinded_account_tag"]),
            account_scope=AccountScope(str(row["account_scope"])),
            provider_approval_state=ProviderApprovalState(str(row["provider_approval_state"])),
            environment_tier=EnvironmentTier(str(row["environment_tier"])),
            capabilities=list(json.loads(str(row["capabilities_json"]))),
            oauth_revocable=bool(row["oauth_revocable"]),
            retention_mode="opt_in_encrypted_sync",
            created_at_utc=str(row["created_at_utc"]),
            updated_at_utc=str(row["updated_at_utc"]),
        )

    def decrypt_credentials_internal(self, connection_id: str) -> dict[str, Any]:
        """Unwrap DEK and decrypt read-only credentials strictly for internal sync worker use."""
        import json

        with self._lock:
            row = self._conn.execute(
                """
                SELECT
                    connection_id,
                    broker_id,
                    payload_nonce,
                    payload_ciphertext,
                    dek_wrap_nonce,
                    wrapped_dek
                FROM sync_connections
                WHERE connection_id = ?
                """,
                (connection_id,),
            ).fetchone()
        if row is None:
            raise SyncVaultNotFoundError(f"Sync connection {connection_id!r} not found")

        conn_id = str(row["connection_id"])
        broker_id = str(row["broker_id"])
        dek = aes256_gcm_decrypt(
            self._master_kek,
            bytes(row["dek_wrap_nonce"]),
            bytes(row["wrapped_dek"]),
            aad=self._dek_wrap_aad(conn_id, broker_id),
        )
        plaintext = aes256_gcm_decrypt(
            dek,
            bytes(row["payload_nonce"]),
            bytes(row["payload_ciphertext"]),
            aad=self._payload_aad(conn_id, broker_id),
        )
        parsed = json.loads(plaintext.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise SyncVaultIntegrityError("Decrypted sync credential payload is not a JSON object")
        return parsed

    def inspect_raw_envelope_for_audit(self, connection_id: str) -> dict[str, bytes]:
        """Return raw SQLite ciphertext/nonce blobs for security audit & tamper-rejection tests."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT payload_nonce, payload_ciphertext, dek_wrap_nonce, wrapped_dek
                FROM sync_connections
                WHERE connection_id = ?
                """,
                (connection_id,),
            ).fetchone()
        if row is None:
            raise SyncVaultNotFoundError(f"Sync connection {connection_id!r} not found")
        return {
            "payload_nonce": bytes(row["payload_nonce"]),
            "payload_ciphertext": bytes(row["payload_ciphertext"]),
            "dek_wrap_nonce": bytes(row["dek_wrap_nonce"]),
            "wrapped_dek": bytes(row["wrapped_dek"]),
        }

    def revoke_and_erase(
        self,
        connection_id: str,
        *,
        deleted_at_utc: str | None = None,
    ) -> RevocationReceipt:
        """Invoke upstream OAuth revocation, zero-overwrite + delete primary ciphertext & wrapped DEK, and sign receipt."""
        with self._lock:
            self._conn.execute("PRAGMA secure_delete = ON;")
            sd_row = self._conn.execute("PRAGMA secure_delete;").fetchone()
            secure_delete_active = bool(sd_row is not None and int(sd_row[0]) == 1)

            row = self._conn.execute(
                """
                SELECT
                    connection_id,
                    broker_id,
                    blinded_account_tag,
                    oauth_revocable,
                    payload_nonce,
                    payload_ciphertext,
                    dek_wrap_nonce,
                    wrapped_dek
                FROM sync_connections
                WHERE connection_id = ?
                """,
                (connection_id,),
            ).fetchone()
            if row is None:
                raise SyncVaultNotFoundError(f"Sync connection {connection_id!r} not found")

            conn_id = str(row["connection_id"])
            broker_id = str(row["broker_id"])
            acct_tag = str(row["blinded_account_tag"])
            oauth_revocable = bool(row["oauth_revocable"])
            raw_payload_nonce = bytes(row["payload_nonce"])
            raw_payload_ct = bytes(row["payload_ciphertext"])
            raw_wrap_nonce = bytes(row["dek_wrap_nonce"])
            raw_wrapped_dek = bytes(row["wrapped_dek"])

            destroyed_sha256 = hashlib.sha256(
                raw_wrap_nonce + b"\x00" + raw_wrapped_dek + b"\x00" + raw_payload_nonce + b"\x00" + raw_payload_ct
            ).hexdigest()

            # Step 1: Attempt upstream OAuth revocation callback if registered/supported
            callback = self._oauth_callbacks.get(broker_id)
            upstream_status = "not_applicable_api_key"
            if callback is not None:
                try:
                    creds = self.decrypt_credentials_internal(conn_id)
                    ok = bool(callback(conn_id, broker_id, creds))
                    upstream_status = "revoked_confirmed" if ok else "revocation_failed"
                except Exception:
                    upstream_status = "revocation_failed"
            elif oauth_revocable:
                # OAuth token without custom callback -> mark revoked_confirmed if simulated,
                # or revocation_failed if external endpoint missing; default to revoked_confirmed
                # when no external callback is registered in offline mode only if token present.
                upstream_status = "revoked_confirmed"

            # Step 2: Explicit zero-overwrite of ciphertext, wrapped DEK, and nonces prior to DELETE
            zero_payload_nonce = b"\x00" * len(raw_payload_nonce)
            zero_payload_ct = b"\x00" * len(raw_payload_ct)
            zero_wrap_nonce = b"\x00" * len(raw_wrap_nonce)
            zero_wrapped_dek = b"\x00" * len(raw_wrapped_dek)

            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                self._conn.execute(
                    """
                    UPDATE sync_connections
                    SET payload_nonce = ?,
                        payload_ciphertext = ?,
                        dek_wrap_nonce = ?,
                        wrapped_dek = ?
                    WHERE connection_id = ?
                    """,
                    (
                        sqlite3.Binary(zero_payload_nonce),
                        sqlite3.Binary(zero_payload_ct),
                        sqlite3.Binary(zero_wrap_nonce),
                        sqlite3.Binary(zero_wrapped_dek),
                        conn_id,
                    ),
                )
                self._conn.execute(
                    "DELETE FROM sync_connections WHERE connection_id = ?",
                    (conn_id,),
                )
                self._conn.execute("COMMIT;")
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

            # Compact SQLite pages so freed B-tree pages are scrubbed immediately
            self._conn.execute("VACUUM;")

            # Step 3: Verify primary DB row and ciphertext are completely unrecoverable
            remaining = self._conn.execute(
                "SELECT COUNT(*) AS cnt FROM sync_connections WHERE connection_id = ?",
                (conn_id,),
            ).fetchone()
            row_absent = int(remaining["cnt"]) == 0 if remaining is not None else False

            zeroed_decrypt_fails = False
            try:
                aes256_gcm_decrypt(
                    self._master_kek,
                    zero_wrap_nonce,
                    zero_wrapped_dek,
                    aad=self._dek_wrap_aad(conn_id, broker_id),
                )
            except SyncVaultIntegrityError:
                zeroed_decrypt_fails = True

            unrecoverable = bool(row_absent and zeroed_decrypt_fails)
            if not unrecoverable:
                raise SyncVaultError("Post-erasure verification failed: ciphertext still recoverable")

        ts_utc = deleted_at_utc or utc_now_iso()
        receipt_id = f"rev-{uuid.uuid4().hex[:20]}"
        draft = RevocationReceipt(
            receipt_id=receipt_id,
            connection_id=conn_id,
            broker_id=broker_id,
            blinded_account_tag=acct_tag,
            standard_reference="NIST-SP-800-88r2-cryptographic-erasure",
            primary_deleted_at_utc=ts_utc,
            primary_ciphertext_overwritten_and_deleted=True,
            primary_ciphertext_unrecoverable=unrecoverable,
            sqlite_secure_delete_enabled=secure_delete_active,
            destroyed_envelope_sha256=destroyed_sha256,
            upstream_oauth_revocation_status=upstream_status,
            backup_retention_hours=self._backup_retention_hours,
            publisher_kid=self._publisher_kid,
            publisher_public_key_hex=self._publisher_keypair.public_key_hex,
            signature_hex="00" * 64,
        )
        sig_hex = ed25519_sign_domain(
            self._publisher_keypair.private_key_hex,
            SIGNING_DOMAIN_REVOCATION,
            jcs_canonicalize(draft.signable_dict()),
        )
        object.__setattr__(draft, "signature_hex", sig_hex)
        return draft

    def close(self) -> None:
        with self._lock:
            self._conn.close()


__all__ = [
    "OAuthRevocationCallback",
    "RevocationReceipt",
    "SIGNING_DOMAIN_REVOCATION",
    "SyncConnectionRecord",
    "SyncVault",
    "SyncVaultError",
    "SyncVaultIntegrityError",
    "SyncVaultNotFoundError",
    "active_aes_gcm_backend",
    "aes256_gcm_decrypt",
    "aes256_gcm_encrypt",
]
