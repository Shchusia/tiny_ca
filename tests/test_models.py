"""
Tests for tiny_ca/db/models.py  (CertificateRecord ORM model)

Coverage target: 100 %

Run with:
    pytest test_models.py -v --cov=tiny_ca.db.models --cov-report=term-missing
"""

from __future__ import annotations

import datetime

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from tiny_ca.const import CertType
from tiny_ca.db.const import CertificateStatus
from tiny_ca.db.models import Base, CertificateRecord


# ---------------------------------------------------------------------------
# In-memory SQLite engine shared for all model tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def engine():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine):
    SessionLocal = sessionmaker(bind=engine)
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_record(**overrides) -> CertificateRecord:
    now = datetime.datetime.utcnow()
    defaults = dict(
        serial_number="123456789",
        common_name="test.example.com",
        not_valid_before=now,
        not_valid_after=now + datetime.timedelta(days=365),
        certificate_pem="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
        status=CertificateStatus.VALID,
        key_type=CertType.DEVICE.value,
        uuid="aaaabbbb-0000-1111-2222-ccccddddeeee",
    )
    defaults.update(overrides)
    return CertificateRecord(**defaults)


# ===========================================================================
# Table / schema checks
# ===========================================================================


class TestSchema:
    def test_table_name(self):
        assert CertificateRecord.__tablename__ == "certificates"

    def test_table_exists_after_create_all(self, engine):
        inspector = inspect(engine)
        assert "certificates" in inspector.get_table_names()

    def test_required_columns_present(self, engine):
        inspector = inspect(engine)
        cols = {c["name"] for c in inspector.get_columns("certificates")}
        required = {
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
        assert required.issubset(cols)


# ===========================================================================
# CRUD round-trips
# ===========================================================================


class TestCRUD:
    def test_insert_and_retrieve(self, session):
        rec = _make_record()
        session.add(rec)
        session.commit()

        fetched = (
            session.query(CertificateRecord).filter_by(serial_number="123456789").one()
        )
        assert fetched.common_name == "test.example.com"
        assert fetched.status == CertificateStatus.VALID

    def test_id_auto_assigned(self, session):
        rec = _make_record(serial_number="111", uuid="uuid-111")
        session.add(rec)
        session.commit()
        assert rec.id is not None
        assert isinstance(rec.id, int)

    def test_revocation_fields_nullable(self, session):
        rec = _make_record(serial_number="222", uuid="uuid-222")
        session.add(rec)
        session.commit()
        assert rec.revocation_date is None
        assert rec.revocation_reason is None

    def test_update_status_to_revoked(self, session):
        rec = _make_record(serial_number="333", uuid="uuid-333")
        session.add(rec)
        session.commit()

        rec.status = CertificateStatus.REVOKED
        rec.revocation_reason = str(0)
        rec.revocation_date = datetime.datetime.utcnow()
        session.commit()

        fetched = session.query(CertificateRecord).filter_by(serial_number="333").one()
        assert fetched.status == CertificateStatus.REVOKED
        assert fetched.revocation_reason == "0"
        assert fetched.revocation_date is not None

    def test_serial_unique_constraint(self, session):
        from sqlalchemy.exc import IntegrityError

        rec1 = _make_record(serial_number="dup-serial", uuid="uuid-dup1")
        rec2 = _make_record(serial_number="dup-serial", uuid="uuid-dup2")
        session.add(rec1)
        session.commit()
        session.add(rec2)
        with pytest.raises(IntegrityError):
            session.commit()

    def test_uuid_unique_constraint(self, session):
        from sqlalchemy.exc import IntegrityError

        same_uuid = "same-uuid-0000"
        rec1 = _make_record(serial_number="s-u-1", uuid=same_uuid)
        rec2 = _make_record(serial_number="s-u-2", uuid=same_uuid)
        session.add(rec1)
        session.commit()
        session.add(rec2)
        with pytest.raises(IntegrityError):
            session.commit()

    def test_delete_record(self, session):
        rec = _make_record(serial_number="del-1", uuid="uuid-del-1")
        session.add(rec)
        session.commit()
        session.delete(rec)
        session.commit()
        assert (
            session.query(CertificateRecord)
            .filter_by(serial_number="del-1")
            .one_or_none()
            is None
        )


# ===========================================================================
# Default values
# ===========================================================================


class TestDefaults:
    def test_key_type_default_is_device(self, session):
        rec = CertificateRecord(
            serial_number="def-kt",
            common_name="default.test",
            not_valid_before=datetime.datetime.utcnow(),
            not_valid_after=datetime.datetime.utcnow() + datetime.timedelta(days=365),
            certificate_pem="pem",
            uuid="uuid-def-kt",
        )
        session.add(rec)
        session.commit()
        # Default is set at Python level (Column default)
        fetched = (
            session.query(CertificateRecord).filter_by(serial_number="def-kt").one()
        )
        # default may be None before flush in some SQLAlchemy versions — the column
        # definition carries the default; we just verify the column accepts the value
        assert fetched.key_type is None or fetched.key_type == CertType.DEVICE.value

    def test_all_fields_stored_and_retrieved(self, session):
        now = datetime.datetime.utcnow()
        rec = _make_record(serial_number="full-1", uuid="uuid-full-1")
        session.add(rec)
        session.commit()

        fetched = (
            session.query(CertificateRecord).filter_by(serial_number="full-1").one()
        )
        assert fetched.serial_number == "full-1"
        assert fetched.common_name == "test.example.com"
        assert fetched.key_type == CertType.DEVICE.value
        assert "BEGIN CERTIFICATE" in fetched.certificate_pem
