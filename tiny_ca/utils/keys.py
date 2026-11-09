"""
keys.py

Key-pair helpers shared by the factory, the CA loaders and the storage layer.

Supported algorithms: RSA, ECDSA (P-256 / P-384) and Ed25519 — see
:class:`tiny_ca.const.KeyAlgorithm`.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from tiny_ca.const import (
    DEFAULT_KEY_ALGORITHM,
    DEFAULT_RSA_KEY_SIZE,
    MAX_RSA_KEY_SIZE,
    MIN_RSA_KEY_SIZE,
    KeyAlgorithm,
)
from tiny_ca.settings import DEFAULT_LOGGER

#: Private key types this library can generate, store, load and sign with.
PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey

#: Public key counterparts of :data:`PrivateKey`.
PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey

#: Runtime tuples for ``isinstance`` checks.
PRIVATE_KEY_TYPES: tuple[type, ...] = (
    rsa.RSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
)
PUBLIC_KEY_TYPES: tuple[type, ...] = (
    rsa.RSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
)

_CURVES: dict[KeyAlgorithm, ec.EllipticCurve] = {
    KeyAlgorithm.EC_P256: ec.SECP256R1(),
    KeyAlgorithm.EC_P384: ec.SECP384R1(),
}


def generate_private_key(
    algorithm: KeyAlgorithm = DEFAULT_KEY_ALGORITHM,
    key_size: int = DEFAULT_RSA_KEY_SIZE,
) -> PrivateKey:
    """
    Generate a new private key.

    Parameters
    ----------
    algorithm : KeyAlgorithm
        Algorithm of the key pair.  Default: ECDSA P-384.
    key_size : int
        RSA modulus length in bits (2048–8192, default 3072); ignored for
        EC and Ed25519.  Sizes below 3072 log a warning.

    Returns
    -------
    PrivateKey
        The freshly generated private key.

    Raises
    ------
    ValueError
        If *key_size* is outside 2048–8192 for RSA.
    """
    if algorithm is KeyAlgorithm.RSA:
        if not MIN_RSA_KEY_SIZE <= key_size <= MAX_RSA_KEY_SIZE:
            raise ValueError(
                f"RSA key_size must be between {MIN_RSA_KEY_SIZE} and "
                f"{MAX_RSA_KEY_SIZE}, got {key_size}"
            )
        if key_size < DEFAULT_RSA_KEY_SIZE:
            DEFAULT_LOGGER.warning(
                "RSA-%d is below the recommended %d bits",
                key_size,
                DEFAULT_RSA_KEY_SIZE,
            )
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    if algorithm is KeyAlgorithm.ED25519:
        return ed25519.Ed25519PrivateKey.generate()
    return ec.generate_private_key(_CURVES[algorithm])


def signing_hash(key: PrivateKey | PublicKey) -> hashes.HashAlgorithm | None:
    """
    Return the digest to use when signing with *key* (private or public half).

    Ed25519 signs the message directly (``None``); P-384 and RSA keys of
    3072 bits or more use SHA-384; P-256 and smaller RSA keys use SHA-256.
    """
    if isinstance(key, ed25519.Ed25519PrivateKey | ed25519.Ed25519PublicKey):
        return None
    if isinstance(key, ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey):
        if isinstance(key.curve, ec.SECP384R1):
            return hashes.SHA384()
        return hashes.SHA256()
    if key.key_size >= DEFAULT_RSA_KEY_SIZE:
        return hashes.SHA384()
    return hashes.SHA256()


def public_key_info(public_key: object) -> tuple[str | None, int | None]:
    """
    Describe a public key as ``(algorithm_name, size_in_bits)``.

    Returns ``(None, None)`` for key types the library does not know about.
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        return "rsa", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"ec-{public_key.curve.name}", public_key.curve.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "ed25519", 256
    return None, None
