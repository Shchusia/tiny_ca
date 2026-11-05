"""
storage/const.py

Shared type aliases and constants for the storage layer.

Exports ``CryptoObject``, a union type alias covering every cryptographic
object that ``BaseStorage.save_certificate`` is capable of serialising and
persisting, plus the POSIX permissions used for written files.
"""

from __future__ import annotations

from cryptography import x509

from tiny_ca.utils.keys import PrivateKey, PublicKey

#: Union of all cryptographic object types accepted by the storage layer.
#:
#: ======================================= =========
#: Type                                    Extension
#: ======================================= =========
#: ``x509.Certificate``                    ``.pem``
#: ``x509.CertificateRevocationList``      ``.pem``
#: ``x509.CertificateSigningRequest``      ``.csr``
#: RSA / EC / Ed25519 private key          ``.key``
#: RSA / EC / Ed25519 public key           ``.pub``
#: ======================================= =========
CryptoObject = (
    x509.Certificate
    | x509.CertificateRevocationList
    | x509.CertificateSigningRequest
    | PrivateKey
    | PublicKey
)

#: POSIX permissions for private key files (owner read/write only).
PRIVATE_FILE_MODE = 0o600

#: POSIX permissions for public artefacts (certificates, CSRs, CRLs).
PUBLIC_FILE_MODE = 0o644
