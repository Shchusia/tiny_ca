"""
const.py

Package-level constants and enumerations shared across all ``tiny_ca`` modules.

Module-level contents
---------------------
``ALLOWED_CERT_EXTENSIONS``  -- whitelist of file extensions accepted by the
                                 CA file loader and storage layer.
``CertType``                 -- enumeration of certificate categories used to
                                 embed a human-readable type prefix into X.509
                                 serial numbers.
"""

from __future__ import annotations

from enum import Enum

#: Tuple of file extensions that the CA loader and storage validator accept.
#:
#: Any path whose suffix is not in this tuple will be rejected by
#: ``CAFileLoader._validate_file`` with a ``WrongType`` exception.
#:
#: ======= ===========================
#: Ext     Contents
#: ======= ===========================
#: ``.key`` Private key (PEM)
#: ``.pem`` X.509 certificate or CRL (PEM)
#: ``.csr`` Certificate signing request (PEM)
#: ======= ===========================
ALLOWED_CERT_EXTENSIONS: tuple[str, ...] = (".key", ".pem", ".csr")


class CertType(Enum):
    """
    Enumeration of certificate categories issued by the CA.

    Each member carries a short string value that is used as a human-readable
    prefix when encoding serial numbers via ``_PrefixRegistry`` and
    ``SerialWithEncoding``.  The prefix makes it possible to identify the
    certificate category directly from a hex dump of the serial number without
    any additional tooling.

    Members
    -------
    USER : "USR"
        End-user personal certificate.  Issued to individual people for
        authentication, email signing, or client TLS.
    SERVICE : "SVC"
        Service or application certificate.  Issued to software services,
        microservices, or API endpoints that need mutual TLS or code signing.
    DEVICE : "DEV"
        Device certificate.  Issued to physical or virtual devices (IoT nodes,
        network equipment) that authenticate to the infrastructure.
    INTERNAL : "INT"
        Internal infrastructure certificate.  Issued to internal components
        such as monitoring agents, message brokers, or CI runners that need
        identity but are not user-facing.
    CA : "CA"
        Certificate Authority certificate.  Used for the root or intermediate
        CA itself; ``BasicConstraints(ca=True)`` is always set for this type.

    Notes
    -----
    The string values are also stored in the ``key_type`` column of
    ``CertificateRecord`` so that certificate categories are human-readable
    in direct SQL queries.

    Examples
    --------
    >>> CertType.SERVICE.value
    'SVC'
    >>> CertType("DEV")
    <CertType.DEVICE: 'DEV'>
    """

    USER = "USR"
    SERVICE = "SVC"
    DEVICE = "DEV"
    INTERNAL = "INT"
    CA = "CA"


class KeyAlgorithm(Enum):
    """
    Public-key algorithm used when generating a new key pair.

    Members
    -------
    RSA :
        RSA with the key length taken from ``key_size`` (2048 / 3072 / 4096).
    EC_P256 :
        ECDSA on NIST P-256 (secp256r1), signed with SHA-256.
    EC_P384 :
        ECDSA on NIST P-384 (secp384r1), signed with SHA-384.
    ED25519 :
        Ed25519 (RFC 8410).  ``key_size`` is ignored.

    Notes
    -----
    Ed25519 keys cannot be written in the ``TraditionalOpenSSL`` format, so
    ``LocalStorage`` transparently stores them as PKCS#8.
    """

    RSA = "rsa"
    EC_P256 = "ec-p256"
    EC_P384 = "ec-p384"
    ED25519 = "ed25519"


#: Algorithm used when the caller does not choose one: ECDSA P-384 with
#: SHA-384 (the curve/hash pair required by high-assurance profiles such as
#: CNSA).  It is also much faster to generate than RSA-3072.
DEFAULT_KEY_ALGORITHM = KeyAlgorithm.EC_P384

#: Default RSA modulus when RSA is chosen explicitly (≈128-bit security).
DEFAULT_RSA_KEY_SIZE = 3072

#: Smallest RSA modulus accepted at all; below ``DEFAULT_RSA_KEY_SIZE`` a
#: warning is logged.
MIN_RSA_KEY_SIZE = 2048

#: Largest RSA modulus accepted (bounds key-generation time).
MAX_RSA_KEY_SIZE = 8192

#: Upper bound for ``days_valid`` (100 years); larger values overflow dates.
MAX_DAYS_VALID = 36500

#: Default validity of end-entity certificates.
DEFAULT_LEAF_DAYS_VALID = 365
