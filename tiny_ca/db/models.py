"""

SQLAlchemy ORM models and status enumerations for the certificate registry.

Module-level contents
---------------------
``CertificateStatus``  — ``StrEnum`` representing the lifecycle state of a
                         certificate row.
``CertificateRecord``  — ORM-mapped table that stores all metadata for issued,
                         revoked, and expired certificates.

Design notes
------------
- ``CertificateStatus`` uses ``StrEnum`` so that values are stored as plain
  strings in the database, making the column human-readable and compatible
  with non-Python tooling that queries the database directly.
- ``CertificateRecord`` stores the full PEM-encoded public certificate so the
  certificate can be reconstructed independently of the filesystem artefacts.
- ``serial_number`` is stored as ``String`` (not ``Integer``) because X.509
  serial numbers can be up to 20 bytes / 160 bits, exceeding the range of a
  64-bit SQL integer on most backends.
- ``uuid`` links the database record to the filesystem folder managed by
  ``BaseStorage``, enabling clean deletion of both the DB row and the
  corresponding files together.
"""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.orm import declarative_base

from tiny_ca.const import CertType

#: Shared declarative base; all ORM models in this package must use this instance.
Base = declarative_base()


class CertificateStatus(StrEnum):
    """
    Lifecycle state of a certificate record in the registry.

    Stored as a lowercase string in the ``status`` column of
    ``CertificateRecord`` so the value is human-readable in raw SQL output.

    Members
    -------
    VALID :
        The certificate was issued successfully and has not been revoked or
        expired.  Active certificates used for authentication or encryption
        are expected to be in this state.
    REVOKED :
        The certificate was explicitly revoked before its natural expiry.
        The ``revocation_date`` and ``revocation_reason`` columns on the
        corresponding ``CertificateRecord`` row must be non-null.
    EXPIRED :
        The certificate's ``not_valid_after`` date has passed.  This status
        may be set by a background job; alternatively, callers can detect
        expiry by comparing ``not_valid_after`` to the current time.
    UNKNOWN :
        The status could not be determined, typically because no record was
        found for the requested serial number.  Used as a safe sentinel value
        by ``CertLifecycleManager.get_certificate_status``.
    """

    VALID = "valid"
    REVOKED = "revoked"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class CertificateRecord(Base):  # type: ignore
    """
    ORM model for a single certificate entry in the registry.

    Maps to the ``certificates`` table.  Each row represents one certificate
    that has been issued by the CA, regardless of its current lifecycle state.

    Columns
    -------
    id : int
        Auto-incremented surrogate primary key.  Not exposed to application
        code; use ``serial_number`` as the business key.
    serial_number : str
        X.509 serial number stored as a decimal string.  Unique and indexed.
        String storage avoids integer overflow for 160-bit serials (RFC 5280).
    common_name : str
        Common Name (CN) extracted from the certificate Subject at issuance
        time.  Not unique; the same CN may appear across different certificate
        generations (e.g. after rotation).
    status : str
        Current lifecycle state.  One of the ``CertificateStatus`` values:
        ``"valid"``, ``"revoked"``, ``"expired"``, or ``"unknown"``.
        Defaults to ``CertificateStatus.VALID`` on insertion.
    not_valid_before : datetime
        Start of the certificate's validity period (UTC, naive datetime as
        stored by SQLAlchemy's ``DateTime`` column type).
    not_valid_after : datetime
        End of the certificate's validity period (UTC, naive datetime).
        Indexed to allow efficient queries for expired certificates.
    key_type : str
        Certificate category stored as the ``CertType`` enum's string value
        (e.g. ``"ca"``, ``"device"``, ``"service"``).
        Defaults to ``CertType.DEVICE.value``.
    certificate_pem : str
        Full PEM-encoded public certificate.  Allows reconstruction of the
        ``x509.Certificate`` object without accessing the filesystem.
    revocation_date : datetime | None
        UTC timestamp at which the certificate was revoked.  ``None`` for
        non-revoked certificates.
    revocation_reason : int | None
        RFC 5280 §5.3.1 revocation reason code stored as an integer.
        ``None`` for non-revoked certificates.  Maps to the integer value
        of the corresponding ``x509.ReasonFlags`` member.
    uuid : str | None
        UUID string that identifies the filesystem folder (managed by
        ``BaseStorage``) holding the ``.pem``, ``.key``, and ``.csr`` files
        for this certificate.  ``None`` if no filesystem artefacts exist.
    """

    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True)

    serial_number = Column(
        String,
        unique=True,
        nullable=False,
        index=True,
        comment="X.509 serial number as a decimal string (up to 160-bit value).",
    )
    common_name = Column(
        String,
        nullable=False,
        comment="CN extracted from the certificate Subject at issuance time.",
    )
    status = Column(
        String,
        default=CertificateStatus.VALID,
        comment="Lifecycle state: valid | revoked | expired | unknown.",
    )
    not_valid_before = Column(
        DateTime,
        nullable=False,
        comment="Start of the certificate validity window (UTC).",
    )
    not_valid_after = Column(
        DateTime,
        nullable=False,
        index=True,
        comment="End of the certificate validity window (UTC). Indexed for expiry queries.",
    )
    key_type = Column(
        String,
        default=CertType.DEVICE.value,
        comment="Certificate category: ca | device | service | user | internal.",
    )
    certificate_pem = Column(
        String,
        nullable=False,
        comment="Full PEM-encoded public certificate for offline reconstruction.",
    )
    revocation_date = Column(
        DateTime,
        nullable=True,
        comment="UTC timestamp of revocation. NULL for non-revoked certificates.",
    )
    revocation_reason = Column(
        Integer,
        nullable=True,
        comment="RFC 5280 §5.3.1 reason code integer. NULL for non-revoked certificates.",
    )
    uuid = Column(
        String,
        unique=True,
        comment="Filesystem folder UUID linking this record to its storage artefacts.",
    )
