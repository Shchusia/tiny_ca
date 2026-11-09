"""
db/utils.py

Helpers shared by the synchronous and asynchronous database handlers.
"""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from tiny_ca.const import CertType

from .const import CertificateStatus
from .models import CertificateRecord


def utc_naive(value: datetime.datetime) -> datetime.datetime:
    """
    Convert *value* to a naive datetime expressed in UTC.

    ``CertificateRecord`` uses ``DateTime`` columns *without* time zone, so
    every value written to or compared against them must be naive UTC.
    Passing aware datetimes breaks on asyncpg ("can't subtract offset-naive
    and offset-aware datetimes") and is silently shifted by PostgreSQL when
    the session time zone is not UTC.  Naive input is assumed to be UTC
    already.
    """
    if value.tzinfo is None:
        return value
    return value.astimezone(datetime.UTC).replace(tzinfo=None)


def utc_now_naive() -> datetime.datetime:
    """Current time as naive UTC (see :func:`utc_naive`)."""
    return utc_naive(datetime.datetime.now(datetime.UTC))


def certificate_common_name(cert: x509.Certificate) -> str:
    """
    CN of *cert*, or the full RFC 4514 Subject string when there is no CN
    (e.g. a co-signed third-party certificate identified by SAN only).
    """
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        return cert.subject.rfc4514_string()
    value = attrs[0].value
    return value if isinstance(value, str) else value.decode("utf-8")


def build_record(
    cert: x509.Certificate, uuid: str, key_type: CertType
) -> CertificateRecord:
    """Create a VALID ``CertificateRecord`` for a freshly issued certificate."""
    return CertificateRecord(
        serial_number=str(cert.serial_number),
        common_name=certificate_common_name(cert),
        not_valid_before=utc_naive(cert.not_valid_before_utc),
        not_valid_after=utc_naive(cert.not_valid_after_utc),
        certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        status=CertificateStatus.VALID,
        key_type=key_type.value,
        uuid=uuid,
    )


def is_revoked(record: CertificateRecord) -> bool:
    """True if *record* has been revoked (its status may since be ``expired``)."""
    return (
        record.revocation_date is not None or record.status == CertificateStatus.REVOKED
    )


def is_listed_in_crl(record: CertificateRecord) -> bool:
    """
    True if *record* still belongs on the CRL: revoked and not yet expired.

    Such rows are the only source of CRL entries, so deleting one would make
    a revoked certificate trusted again by CRL-based relying parties.
    """
    return is_revoked(record) and record.not_valid_after > utc_now_naive()
