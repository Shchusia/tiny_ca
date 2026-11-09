"""
signing.py

Pluggable CA signing: the CA private key does not have to live in this
process.

* :class:`CASigner` — the protocol every signer implements: expose the CA
  public key and sign raw bytes.
* :class:`KeySigner` — a signer backed by an in-memory private key (the
  classic file-based CA).
* :class:`Pkcs11Signer` — a signer backed by a key inside a hardware security
  module or smart card, reached through a PKCS#11 module (``tiny-ca[hsm]``).
* :func:`sign_builder` — signs any ``cryptography`` certificate or CRL builder
  with a :class:`CASigner`.

``cryptography`` can only sign with its own key objects.  For external
signers :func:`sign_builder` therefore builds the to-be-signed structure with
a throw-away key of the same algorithm, has the external signer sign those
exact bytes, splices the real signature into the DER encoding and verifies
the result against the CA public key before returning it.
"""

from __future__ import annotations

from collections.abc import Callable
import functools
import importlib
from pathlib import Path
import threading
from types import ModuleType
from typing import Any, Protocol, cast, runtime_checkable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from tiny_ca.exc import SignerError
from tiny_ca.utils.keys import PrivateKey, PublicKey, signing_hash

__all__ = [
    "CASigner",
    "KeySigner",
    "Pkcs11Signer",
    "sign_builder",
    "sign_bytes",
    "verify_signature",
]


@runtime_checkable
class CASigner(Protocol):
    """
    Anything that can sign on behalf of the CA.

    ``sign`` receives the exact bytes to sign and the digest chosen by
    :func:`tiny_ca.utils.keys.signing_hash` (``None`` for Ed25519) and must
    return the signature in X.509 form: PKCS#1 v1.5 for RSA, DER-encoded
    ``ECDSA-Sig-Value`` for ECDSA, the raw 64 bytes for Ed25519.
    """

    def public_key(self) -> PublicKey: ...

    def sign(self, data: bytes, algorithm: hashes.HashAlgorithm | None) -> bytes: ...


def sign_bytes(
    key: PrivateKey, data: bytes, algorithm: hashes.HashAlgorithm | None
) -> bytes:
    """Sign *data* with a software private key in X.509 signature form."""
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(data, padding.PKCS1v15(), algorithm)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(data, ec.ECDSA(algorithm))
    return key.sign(data)


def verify_signature(
    public_key: PublicKey,
    signature: bytes,
    data: bytes,
    algorithm: hashes.HashAlgorithm | None,
) -> bool:
    """Return True if *signature* over *data* is valid for *public_key*."""
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(algorithm))
        else:
            public_key.verify(signature, data)
    except InvalidSignature:
        return False
    return True


class KeySigner:
    """A :class:`CASigner` backed by an in-memory private key."""

    def __init__(self, private_key: PrivateKey) -> None:
        self.private_key = private_key

    def public_key(self) -> PublicKey:
        return self.private_key.public_key()

    def sign(self, data: bytes, algorithm: hashes.HashAlgorithm | None) -> bytes:
        return sign_bytes(self.private_key, data, algorithm)


# ---------------------------------------------------------------------------
# External signatures: DER surgery on certificates and CRLs
# ---------------------------------------------------------------------------

_SEQUENCE = 0x30
_BIT_STRING = 0x03


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _read_tlv(der: bytes, pos: int) -> tuple[int, int, int]:
    """Return ``(tag, content_start, end)`` of the TLV starting at *pos*."""
    tag = der[pos]
    first = der[pos + 1]
    if first < 0x80:
        return tag, pos + 2, pos + 2 + first
    count = first & 0x7F
    length = int.from_bytes(der[pos + 2 : pos + 2 + count], "big")
    start = pos + 2 + count
    return tag, start, start + length


def _split_signed(der: bytes) -> tuple[bytes, bytes]:
    """
    Split a signed X.509 structure (``SEQUENCE { tbs, algorithm, signature }``)
    into the encoded *tbs* and *algorithm* elements.
    """
    tag, start, end = _read_tlv(der, 0)
    if tag != _SEQUENCE or end != len(der):
        raise SignerError("unexpected DER structure while re-signing")
    _, _, tbs_end = _read_tlv(der, start)
    _, _, alg_end = _read_tlv(der, tbs_end)
    return der[start:tbs_end], der[tbs_end:alg_end]


def _assemble(tbs: bytes, algorithm: bytes, signature: bytes) -> bytes:
    bit_string = (
        bytes([_BIT_STRING]) + _der_length(len(signature) + 1) + b"\x00" + signature
    )
    body = tbs + algorithm + bit_string
    return bytes([_SEQUENCE]) + _der_length(len(body)) + body


@functools.cache
def _template_key(kind: type) -> PrivateKey:
    """A throw-away key whose only job is to produce the right algorithm OID."""
    if kind is rsa.RSAPublicKey:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if kind is ec.EllipticCurvePublicKey:
        return ec.generate_private_key(ec.SECP256R1())
    return ed25519.Ed25519PrivateKey.generate()


def _key_kind(public_key: PublicKey) -> type:
    for kind in (rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey):
        if isinstance(public_key, kind):
            return kind
    raise SignerError(f"unsupported CA public key type {type(public_key).__name__}")


_LOADERS: dict[type, Callable[[bytes], Any]] = {
    x509.Certificate: x509.load_der_x509_certificate,
    x509.CertificateRevocationList: x509.load_der_x509_crl,
}


def sign_builder(builder: Any, signer: CASigner) -> Any:
    """
    Sign a ``CertificateBuilder`` or ``CertificateRevocationListBuilder``.

    Raises
    ------
    SignerError
        If the external signer fails or returns a signature that does not
        verify against its public key.
    """
    public_key = signer.public_key()
    algorithm = signing_hash(public_key)
    if isinstance(signer, KeySigner):
        return builder.sign(signer.private_key, algorithm)

    template = builder.sign(_template_key(_key_kind(public_key)), algorithm)
    tbs, algorithm_id = _split_signed(template.public_bytes(serialization.Encoding.DER))
    try:
        signature = signer.sign(tbs, algorithm)
    except SignerError:
        raise
    except Exception as exc:
        raise SignerError(f"external signer failed: {exc}") from exc
    if not verify_signature(public_key, signature, tbs, algorithm):
        raise SignerError(
            "external signer returned a signature that does not match the CA "
            "public key"
        )
    loader = next(load for kind, load in _LOADERS.items() if isinstance(template, kind))
    return loader(_assemble(tbs, algorithm_id, signature))


# ---------------------------------------------------------------------------
# PKCS#11 (HSM / smart card)
# ---------------------------------------------------------------------------

_RSA_MECHANISMS = {
    "sha256": "SHA256_RSA_PKCS",
    "sha384": "SHA384_RSA_PKCS",
    "sha512": "SHA512_RSA_PKCS",
}
_ECDSA_MECHANISMS = {
    "sha256": "ECDSA_SHA256",
    "sha384": "ECDSA_SHA384",
    "sha512": "ECDSA_SHA512",
}


def _import_pkcs11() -> ModuleType:
    try:
        return importlib.import_module("pkcs11")
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ImportError(
            "PKCS#11 support requires python-pkcs11: pip install 'tiny-ca[hsm]'"
        ) from exc


class Pkcs11Signer:
    """
    A :class:`CASigner` whose private key never leaves a PKCS#11 token
    (HSM, smart card, SoftHSM, cloud HSM with a PKCS#11 module).

    Use :meth:`open` to log in to a token, or wrap an already opened
    ``python-pkcs11`` private key object.  The CA public key is taken from the
    CA certificate, so the token only needs to hold the private key.
    Signing is serialised with a lock because PKCS#11 sessions are not
    thread-safe.

    Parameters
    ----------
    key :
        A ``python-pkcs11`` private key object (anything with
        ``sign(data, mechanism=...)``).
    public_key : PublicKey
        The CA public key (``ca_cert.public_key()``).
    mechanisms :
        Namespace holding the PKCS#11 mechanism constants; defaults to
        ``pkcs11.Mechanism``.
    session :
        Session to close in :meth:`close` (set by :meth:`open`).
    """

    def __init__(
        self,
        key: Any,
        public_key: PublicKey,
        mechanisms: Any = None,
        session: Any = None,
    ) -> None:
        self._key = key
        self._public_key = public_key
        self._kind = _key_kind(public_key)
        self._mechanisms = (
            mechanisms if mechanisms is not None else _import_pkcs11().Mechanism
        )
        self._session = session
        self._lock = threading.Lock()

    @classmethod
    def open(
        cls,
        module_path: str | Path,
        token_label: str,
        pin: str,
        public_key: PublicKey,
        key_label: str | None = None,
        key_id: bytes | None = None,
    ) -> Pkcs11Signer:
        """
        Log in to *token_label* through the PKCS#11 *module_path* and find the
        CA private key by *key_label* and/or *key_id*.
        """
        if key_label is None and key_id is None:
            raise ValueError("key_label or key_id is required")
        pkcs11 = _import_pkcs11()
        token = pkcs11.lib(str(module_path)).get_token(token_label=token_label)
        session = token.open(user_pin=pin)
        try:
            key = session.get_key(
                object_class=pkcs11.ObjectClass.PRIVATE_KEY,
                label=key_label,
                id=key_id,
            )
        except Exception:
            session.close()
            raise
        return cls(key, public_key, pkcs11.Mechanism, session=session)

    def public_key(self) -> PublicKey:
        return self._public_key

    def _mechanism(self, algorithm: hashes.HashAlgorithm | None) -> Any:
        if self._kind is ed25519.Ed25519PublicKey:
            name = "EDDSA"
        else:
            table = (
                _RSA_MECHANISMS if self._kind is rsa.RSAPublicKey else _ECDSA_MECHANISMS
            )
            try:
                name = table[algorithm.name]
            except (KeyError, AttributeError):
                raise SignerError(
                    f"no PKCS#11 mechanism for digest {algorithm!r}"
                ) from None
        return getattr(self._mechanisms, name)

    def sign(self, data: bytes, algorithm: hashes.HashAlgorithm | None) -> bytes:
        mechanism = self._mechanism(algorithm)
        with self._lock:
            raw = bytes(self._key.sign(data, mechanism=mechanism))
        if self._kind is ec.EllipticCurvePublicKey:
            # PKCS#11 returns ECDSA signatures as r || s; X.509 wants DER.
            half = len(raw) // 2
            return encode_dss_signature(
                int.from_bytes(raw[:half], "big"), int.from_bytes(raw[half:], "big")
            )
        return raw

    def close(self) -> None:
        """Close the PKCS#11 session opened by :meth:`open` (if any)."""
        if self._session is not None:
            self._session.close()
            self._session = None

    def __enter__(self) -> Pkcs11Signer:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
