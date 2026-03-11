"""
test_models.py

Tests for tiny_ca/db/models.py:
  - CertificateStatus StrEnum
  - CertificateRecord ORM model construction and defaults
"""

from __future__ import annotations

import datetime

import pytest

from tiny_ca.db.models import Base, CertificateRecord, CertificateStatus
from tiny_ca.const import CertType


# ---------------------------------------------------------------------------
# CertificateStatus
# ---------------------------------------------------------------------------


class TestCertificateStatus:
    def test_valid_value(self):
        assert CertificateStatus.VALID == "valid"

    def test_revoked_value(self):
        assert CertificateStatus.REVOKED == "revoked"

    def test_expired_value(self):
        assert CertificateStatus.EXPIRED == "expired"

    def test_unknown_value(self):
        assert CertificateStatus.UNKNOWN == "unknown"

    def test_all_four_members(self):
        names = {m.name for m in CertificateStatus}
        assert names == {"VALID", "REVOKED", "EXPIRED", "UNKNOWN"}

    def test_is_str(self):
        # StrEnum values behave as str
        assert isinstance(CertificateStatus.VALID, str)

    def test_str_comparison(self):
        assert CertificateStatus.VALID == "valid"
        assert CertificateStatus.REVOKED != "valid"

    def test_lookup_by_value(self):
        assert CertificateStatus("valid") is CertificateStatus.VALID

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            CertificateStatus("pending")


# ---------------------------------------------------------------------------
# CertificateRecord
# ---------------------------------------------------------------------------


class TestCertificateRecord:
    def test_tablename(self):
        assert CertificateRecord.__tablename__ == "certificates"

    def test_column_names(self):
        cols = {c.key for c in CertificateRecord.__table__.columns}
        expected = {
            "id",
            "serial_number",
            "common_name",
            "status",
            "not_valid_before",
            "not_valid_after",
            "key_type",
            "certificate_pem",
            "revocation_date",
            "revocation_reason",
            "uuid",
        }
        assert expected.issubset(cols)

    def test_instance_creation_with_required_fields(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        record = CertificateRecord(
            serial_number="12345",
            common_name="test.example.com",
            not_valid_before=now,
            not_valid_after=now + datetime.timedelta(days=365),
            certificate_pem="-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
        )
        assert record.serial_number == "12345"
        assert record.common_name == "test.example.com"

    def test_revocation_fields_default_to_none(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        record = CertificateRecord(
            serial_number="99",
            common_name="x",
            not_valid_before=now,
            not_valid_after=now + datetime.timedelta(days=1),
            certificate_pem="FAKE",
        )
        assert record.revocation_date is None
        assert record.revocation_reason is None

    def test_uuid_field_exists(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        record = CertificateRecord(
            serial_number="77",
            common_name="uuid-test",
            not_valid_before=now,
            not_valid_after=now + datetime.timedelta(days=1),
            certificate_pem="FAKE",
            uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        assert record.uuid == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def test_base_is_shared(self):
        # Ensure CertificateRecord uses the shared Base
        assert CertificateRecord.__table__ in Base.metadata.tables.values()

    def test_serial_number_indexed(self):
        col = CertificateRecord.__table__.c["serial_number"]
        assert col.index is True

    def test_not_valid_after_indexed(self):
        col = CertificateRecord.__table__.c["not_valid_after"]
        assert col.index is True
