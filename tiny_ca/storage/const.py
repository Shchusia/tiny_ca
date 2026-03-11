"""
storage/const.py

Shared type aliases for the storage layer.

Exports ``CryptoObject``, a union type alias covering every cryptographic
object that ``BaseStorage.save_certificate`` is capable of serialising and
persisting.  Declaring it once here prevents duplication across
``base_storage.py``, ``local_storage.py``, and any future storage backends.
"""

from __future__ import annotations

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

#: Union of all cryptographic object types accepted by the storage layer.
#:
#: ======================================= =========
#: Type                                    Extension
#: ======================================= =========
#: ``x509.Certificate``                    ``.pem``
#: ``x509.CertificateRevocationList``      ``.pem``
#: ``CertificateSigningRequest`` (Rust)    ``.csr``
#: ``rsa.RSAPrivateKey``                   ``.key``
#: ``rsa.RSAPublicKey``                    ``.pub``
#: ======================================= =========
#:
#: The internal Rust-backed ``CertificateSigningRequest`` type is included
#: because the ``cryptography`` library exposes CSR objects through its Rust
#: bindings rather than a pure-Python class.
CryptoObject = (
    x509.Certificate
    | x509.CertificateRevocationList
    | cryptography.hazmat.bindings._rust.x509.CertificateSigningRequest  # type: ignore
    | rsa.RSAPrivateKey
    | rsa.RSAPublicKey
)
