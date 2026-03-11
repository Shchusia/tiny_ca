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
#: ``.key`` RSA private key (PEM)
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
