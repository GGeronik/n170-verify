"""Ed25519 keygen, signing, and verification with OpenSSL 3 libcrypto zero-wheel fallback."""

from __future__ import annotations

import ctypes
import ctypes.util
from dataclasses import dataclass
import hashlib
import secrets

from n170_verify.contracts.assurance import ContractModelMixin, validate_hex_digest


SIGNING_DOMAIN_BUNDLE = b"n170.verify.bundle.v3"
SIGNING_DOMAIN_CHECKPOINT = b"n170.verify.checkpoint.v3"
SIGNING_DOMAIN_WITNESS = b"n170.verify.witness.v3"
SIGNING_DOMAIN_BROKER = b"n170.verify.broker.v3"

_EVP_PKEY_ED25519 = 1087

_ED25519_P = (1 << 255) - 19
_ED25519_L = (1 << 252) + 27742317777372353535851937790883648493
_ED25519_SMALL_ORDER_Y: frozenset[int] = frozenset(
    {
        0,
        1,
        _ED25519_P - 1,
        0x05FC536D880238B13933C6D305ACDFD5F098EFF289F4C345B027B2C28F95E826,
        0x7A03AC9277FDC74EC6CC392CFA53202A0F67100D760B3CBA4FD84D3D706A17C7,
    }
)


def _is_canonical_non_torsion_ed25519_point(point_32b: bytes) -> bool:
    """Reject non-canonical y >= p encodings and all 8-torsion small-order points."""
    if len(point_32b) != 32:
        return False
    y = int.from_bytes(point_32b, "little") & ((1 << 255) - 1)
    if y >= _ED25519_P:
        return False
    if y in _ED25519_SMALL_ORDER_Y:
        return False
    return True


def _is_canonical_ed25519_scalar(scalar_32b: bytes) -> bool:
    """Enforce RFC 8032 non-malleable scalar bounds 0 < S < L."""
    if len(scalar_32b) != 32:
        return False
    s_val = int.from_bytes(scalar_32b, "little")
    return 0 < s_val < _ED25519_L


try:
    from nacl.signing import SigningKey as _NaClSigningKey
    from nacl.signing import VerifyKey as _NaClVerifyKey

    _HAS_PYNACL = True
except ImportError:  # pragma: no cover - exercised in stdlib sandbox
    _HAS_PYNACL = False

try:
    from cryptography.hazmat.primitives import serialization as _crypto_serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as _CryptoEd25519PrivateKey,
        Ed25519PublicKey as _CryptoEd25519PublicKey,
    )

    _HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - exercised in stdlib sandbox
    _HAS_CRYPTOGRAPHY = False


class _OpenSSLEd25519Binding:
    """Minimal thread-safe ctypes binding to OpenSSL 3 EVP Ed25519 one-shot APIs."""

    def __init__(self) -> None:
        lib = self._load_library()
        lib.EVP_PKEY_new_raw_private_key.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        lib.EVP_PKEY_new_raw_private_key.restype = ctypes.c_void_p

        lib.EVP_PKEY_new_raw_public_key.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        lib.EVP_PKEY_new_raw_public_key.restype = ctypes.c_void_p

        lib.EVP_PKEY_get_raw_public_key.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.EVP_PKEY_get_raw_public_key.restype = ctypes.c_int

        lib.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
        lib.EVP_PKEY_free.restype = None

        lib.EVP_MD_CTX_new.argtypes = []
        lib.EVP_MD_CTX_new.restype = ctypes.c_void_p
        lib.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]
        lib.EVP_MD_CTX_free.restype = None

        lib.EVP_DigestSignInit.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        lib.EVP_DigestSignInit.restype = ctypes.c_int

        lib.EVP_DigestSign.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        lib.EVP_DigestSign.restype = ctypes.c_int

        lib.EVP_DigestVerifyInit.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        lib.EVP_DigestVerifyInit.restype = ctypes.c_int

        lib.EVP_DigestVerify.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        lib.EVP_DigestVerify.restype = ctypes.c_int

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
                if hasattr(lib, "EVP_PKEY_new_raw_private_key"):
                    return lib
            except OSError as exc:
                last_err = exc
        raise RuntimeError("Unable to locate OpenSSL 3 libcrypto for Ed25519") from last_err

    def derive_public_key(self, seed_32b: bytes) -> bytes:
        if len(seed_32b) != 32:
            raise ValueError("Ed25519 private seed must be 32 bytes")
        sk_buf = ctypes.create_string_buffer(seed_32b, 32)
        pkey = self._lib.EVP_PKEY_new_raw_private_key(_EVP_PKEY_ED25519, None, sk_buf, 32)
        if not pkey:
            self._lib.ERR_clear_error()
            raise RuntimeError("EVP_PKEY_new_raw_private_key failed")
        try:
            pub_buf = ctypes.create_string_buffer(32)
            pub_len = ctypes.c_size_t(32)
            rc = self._lib.EVP_PKEY_get_raw_public_key(pkey, pub_buf, ctypes.byref(pub_len))
            if rc != 1 or pub_len.value != 32:
                self._lib.ERR_clear_error()
                raise RuntimeError("EVP_PKEY_get_raw_public_key failed")
            return pub_buf.raw[:32]
        finally:
            self._lib.EVP_PKEY_free(pkey)

    def sign(self, seed_32b: bytes, message: bytes) -> bytes:
        if len(seed_32b) != 32:
            raise ValueError("Ed25519 private seed must be 32 bytes")
        sk_buf = ctypes.create_string_buffer(seed_32b, 32)
        pkey = self._lib.EVP_PKEY_new_raw_private_key(_EVP_PKEY_ED25519, None, sk_buf, 32)
        if not pkey:
            self._lib.ERR_clear_error()
            raise RuntimeError("EVP_PKEY_new_raw_private_key failed")
        ctx = self._lib.EVP_MD_CTX_new()
        if not ctx:
            self._lib.EVP_PKEY_free(pkey)
            raise RuntimeError("EVP_MD_CTX_new failed")
        try:
            if self._lib.EVP_DigestSignInit(ctx, None, None, None, pkey) != 1:
                self._lib.ERR_clear_error()
                raise RuntimeError("EVP_DigestSignInit failed")
            msg_buf = ctypes.create_string_buffer(message, max(len(message), 1))
            sig_buf = ctypes.create_string_buffer(64)
            sig_len = ctypes.c_size_t(64)
            rc = self._lib.EVP_DigestSign(
                ctx, sig_buf, ctypes.byref(sig_len), msg_buf, len(message)
            )
            if rc != 1 or sig_len.value != 64:
                self._lib.ERR_clear_error()
                raise RuntimeError("EVP_DigestSign failed")
            return sig_buf.raw[:64]
        finally:
            self._lib.EVP_MD_CTX_free(ctx)
            self._lib.EVP_PKEY_free(pkey)

    def verify(self, public_key_32b: bytes, message: bytes, signature_64b: bytes) -> bool:
        if len(public_key_32b) != 32 or len(signature_64b) != 64:
            return False
        pk_buf = ctypes.create_string_buffer(public_key_32b, 32)
        pkey = self._lib.EVP_PKEY_new_raw_public_key(_EVP_PKEY_ED25519, None, pk_buf, 32)
        if not pkey:
            self._lib.ERR_clear_error()
            return False
        ctx = self._lib.EVP_MD_CTX_new()
        if not ctx:
            self._lib.EVP_PKEY_free(pkey)
            return False
        try:
            if self._lib.EVP_DigestVerifyInit(ctx, None, None, None, pkey) != 1:
                self._lib.ERR_clear_error()
                return False
            msg_buf = ctypes.create_string_buffer(message, max(len(message), 1))
            sig_buf = ctypes.create_string_buffer(signature_64b, 64)
            rc = self._lib.EVP_DigestVerify(ctx, sig_buf, 64, msg_buf, len(message))
            if rc != 1:
                self._lib.ERR_clear_error()
                return False
            return True
        finally:
            self._lib.EVP_MD_CTX_free(ctx)
            self._lib.EVP_PKEY_free(pkey)


_OPENSSL_BINDING: _OpenSSLEd25519Binding | None = None


def _get_openssl_binding() -> _OpenSSLEd25519Binding:
    global _OPENSSL_BINDING
    if _OPENSSL_BINDING is None:
        _OPENSSL_BINDING = _OpenSSLEd25519Binding()
    return _OPENSSL_BINDING


def active_ed25519_backend() -> str:
    """Return the active Ed25519 backend identifier."""
    if _HAS_PYNACL:
        return "pynacl"
    if _HAS_CRYPTOGRAPHY:
        return "cryptography"
    _get_openssl_binding()
    return "openssl_ctypes"


def compute_key_id(public_key_hex: str) -> str:
    """Compute deterministic 16-hex-char key identifier from a 32-byte Ed25519 public key."""
    normalized = validate_hex_digest(public_key_hex, field_name="public_key_hex", num_bytes=32)
    return hashlib.sha256(bytes.fromhex(normalized)).hexdigest()[:16]


def derive_public_key_hex(private_key_hex: str, *, force_openssl: bool = False) -> str:
    """Derive 64-char hex Ed25519 public key from a 64-char hex 32-byte private seed."""
    norm_priv = validate_hex_digest(private_key_hex, field_name="private_key_hex", num_bytes=32)
    seed = bytes.fromhex(norm_priv)
    if not force_openssl and _HAS_PYNACL:
        return bytes(_NaClSigningKey(seed).verify_key).hex()
    if not force_openssl and _HAS_CRYPTOGRAPHY:
        priv = _CryptoEd25519PrivateKey.from_private_bytes(seed)
        pub_bytes = priv.public_key().public_bytes(
            encoding=_crypto_serialization.Encoding.Raw,
            format=_crypto_serialization.PublicFormat.Raw,
        )
        return pub_bytes.hex()
    return _get_openssl_binding().derive_public_key(seed).hex()


def ed25519_sign(private_key_hex: str, message: bytes, *, force_openssl: bool = False) -> str:
    """Sign raw ``message`` bytes with a 32-byte Ed25519 private seed; return 128-char hex signature."""
    if not isinstance(message, bytes):
        raise ValueError("message must be bytes")
    norm_priv = validate_hex_digest(private_key_hex, field_name="private_key_hex", num_bytes=32)
    seed = bytes.fromhex(norm_priv)
    if not force_openssl and _HAS_PYNACL:
        return _NaClSigningKey(seed).sign(message).signature.hex()
    if not force_openssl and _HAS_CRYPTOGRAPHY:
        priv = _CryptoEd25519PrivateKey.from_private_bytes(seed)
        return priv.sign(message).hex()
    return _get_openssl_binding().sign(seed, message).hex()


def ed25519_verify(
    public_key_hex: str,
    message: bytes,
    signature_hex: str,
    *,
    force_openssl: bool = False,
) -> bool:
    """Verify a 128-char hex Ed25519 signature over ``message`` against a 64-char hex public key."""
    if not isinstance(message, bytes):
        return False
    if not isinstance(public_key_hex, str) or not isinstance(signature_hex, str):
        return False
    try:
        pub_norm = validate_hex_digest(public_key_hex, field_name="public_key_hex", num_bytes=32)
        sig_norm = validate_hex_digest(signature_hex, field_name="signature_hex", num_bytes=64)
    except ValueError:
        return False

    pub_bytes = bytes.fromhex(pub_norm)
    sig_bytes = bytes.fromhex(sig_norm)
    if (
        not _is_canonical_non_torsion_ed25519_point(pub_bytes)
        or not _is_canonical_non_torsion_ed25519_point(sig_bytes[:32])
        or not _is_canonical_ed25519_scalar(sig_bytes[32:])
    ):
        return False

    if not force_openssl and _HAS_PYNACL:
        try:
            _NaClVerifyKey(pub_bytes).verify(message, sig_bytes)
            return True
        except Exception:
            return False
    if not force_openssl and _HAS_CRYPTOGRAPHY:
        try:
            pub = _CryptoEd25519PublicKey.from_public_bytes(pub_bytes)
            pub.verify(sig_bytes, message)
            return True
        except Exception:
            return False
    return _get_openssl_binding().verify(pub_bytes, message, sig_bytes)


def ed25519_sign_domain(private_key_hex: str, domain: bytes, payload: bytes) -> str:
    """Sign ``domain || 0x00 || payload`` using Ed25519."""
    if not isinstance(domain, bytes) or not domain:
        raise ValueError("domain must be non-empty bytes")
    if not isinstance(payload, bytes):
        raise ValueError("payload must be bytes")
    return ed25519_sign(private_key_hex, domain + b"\x00" + payload)


def ed25519_verify_domain(
    public_key_hex: str,
    domain: bytes,
    payload: bytes,
    signature_hex: str,
) -> bool:
    """Verify domain-separated ``domain || 0x00 || payload`` Ed25519 signature."""
    if not isinstance(domain, bytes) or not domain or not isinstance(payload, bytes):
        return False
    return ed25519_verify(public_key_hex, domain + b"\x00" + payload, signature_hex)


@dataclass(slots=True)
class Ed25519KeyPair(ContractModelMixin):
    """Ed25519 32-byte seed keypair with deterministic ``key_id``."""

    private_key_hex: str
    public_key_hex: str
    key_id: str | None = None

    def _validate(self) -> None:
        norm_priv = validate_hex_digest(
            self.private_key_hex, field_name="Ed25519KeyPair.private_key_hex", num_bytes=32
        )
        norm_pub = validate_hex_digest(
            self.public_key_hex, field_name="Ed25519KeyPair.public_key_hex", num_bytes=32
        )
        expected_pub = derive_public_key_hex(norm_priv)
        if norm_pub != expected_pub:
            raise ValueError("Ed25519KeyPair.public_key_hex does not match private_key_hex")
        object.__setattr__(self, "private_key_hex", norm_priv)
        object.__setattr__(self, "public_key_hex", norm_pub)
        if self.key_id is None or not self.key_id.strip():
            object.__setattr__(self, "key_id", compute_key_id(norm_pub))


def generate_ed25519_keypair(seed_bytes: bytes | None = None) -> Ed25519KeyPair:
    """Generate a new Ed25519 keypair (or deterministically derive from a 32-byte seed)."""
    if seed_bytes is None:
        seed = secrets.token_bytes(32)
    else:
        if not isinstance(seed_bytes, bytes) or len(seed_bytes) != 32:
            raise ValueError("seed_bytes must be exactly 32 bytes")
        seed = seed_bytes
    priv_hex = seed.hex()
    pub_hex = derive_public_key_hex(priv_hex)
    return Ed25519KeyPair(
        private_key_hex=priv_hex,
        public_key_hex=pub_hex,
        key_id=compute_key_id(pub_hex),
    )


__all__ = [
    "Ed25519KeyPair",
    "SIGNING_DOMAIN_BROKER",
    "SIGNING_DOMAIN_BUNDLE",
    "SIGNING_DOMAIN_CHECKPOINT",
    "SIGNING_DOMAIN_WITNESS",
    "active_ed25519_backend",
    "compute_key_id",
    "derive_public_key_hex",
    "ed25519_sign",
    "ed25519_sign_domain",
    "ed25519_verify",
    "ed25519_verify_domain",
    "generate_ed25519_keypair",
]
