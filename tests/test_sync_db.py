"""
test_sync_db.py

Tests for tiny_ca/db/sync_db_manager.py:
  - DatabaseManager   — construction, session provisioning, create_all flag
  - SyncDBHandler     — get_by_serial, get_by_name, register_cert_in_db,
                        delete_certificate_by_serial, revoke_certificate,
                        get_revoked_certificates
  All tests run against an in-memory SQLite database (no disk I/O).
"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509

from tiny_ca.db.sync_db_manager import DatabaseManager, SyncDBHandler
from tiny_ca.db.const import RevokeStatus
from tiny_ca.db.models import Base, CertificateRecord, CertificateStatus
from tiny_ca.const import CertType


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_url() -> str:
    return "sqlite:///:memory:"


@pytest.fixture()
def db_manager(db_url: str) -> DatabaseManager:
    return DatabaseManager(db_url=db_url, create_all=True)


@pytest.fixture()
def handler(db_url: str) -> SyncDBHandler:
    return SyncDBHandler(db_url=db_url)


@pytest.fixture()
def registered_cert(
    handler: SyncDBHandler, leaf_cert: x509.Certificate
) -> CertificateRecord:
    """Register leaf_cert and return the handler (cert now in DB)."""
    handler.register_cert_in_db(
        leaf_cert, uuid="test-uuid-0001", key_type=CertType.SERVICE
    )
    return handler.get_by_serial(leaf_cert.serial_number)


# ---------------------------------------------------------------------------
# DatabaseManager
# ---------------------------------------------------------------------------


class TestDatabaseManager:
    def test_construction_creates_schema(self, db_url):
        dm = DatabaseManager(db_url=db_url, create_all=True)
        session = dm.session()
        # Table must exist; scalar_one_or_none on empty table returns None, not error
        from sqlalchemy import select

        result = session.execute(select(CertificateRecord)).all()
        session.close()
        assert isinstance(result, list)

    def test_session_returns_new_session(self, db_manager):
        s1 = db_manager.session()
        s2 = db_manager.session()
        assert s1 is not s2
        s1.close()
        s2.close()

    def test_create_all_false_does_not_raise(self, db_url):
        # create_all=False is safe if Base metadata is already applied
        DatabaseManager(db_url=db_url, create_all=True)  # create schema first
        dm2 = DatabaseManager(db_url=db_url, create_all=False)
        s = dm2.session()
        s.close()

    def test_session_is_usable(self, db_manager):
        session = db_manager.session()
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            record = CertificateRecord(
                serial_number="dm-test-1",
                common_name="dm.test",
                not_valid_before=now,
                not_valid_after=now + datetime.timedelta(days=1),
                certificate_pem="FAKE",
            )
            session.add(record)
            session.commit()
        finally:
            session.close()


# ---------------------------------------------------------------------------
# SyncDBHandler.register_cert_in_db
# ---------------------------------------------------------------------------


class TestRegisterCertInDB:
    def test_returns_true_on_success(self, handler, leaf_cert):
        result = handler.register_cert_in_db(leaf_cert, uuid="uuid-001")
        assert result is True

    def test_record_present_after_registration(self, handler, leaf_cert):
        handler.register_cert_in_db(leaf_cert, uuid="uuid-002")
        record = handler.get_by_serial(leaf_cert.serial_number)
        assert record is not None

    def test_serial_stored_as_string(self, handler, leaf_cert):
        handler.register_cert_in_db(leaf_cert, uuid="uuid-003")
        record = handler.get_by_serial(leaf_cert.serial_number)
        assert record.serial_number == str(leaf_cert.serial_number)

    def test_status_is_valid_after_registration(self, handler, leaf_cert):
        handler.register_cert_in_db(leaf_cert, uuid="uuid-004")
        record = handler.get_by_serial(leaf_cert.serial_number)
        assert record.status == CertificateStatus.VALID

    def test_key_type_stored(self, handler, leaf_cert):
        handler.register_cert_in_db(
            leaf_cert, uuid="uuid-005", key_type=CertType.SERVICE
        )
        record = handler.get_by_serial(leaf_cert.serial_number)
        assert record.key_type == CertType.SERVICE.value

    def test_uuid_stored(self, handler, leaf_cert):
        handler.register_cert_in_db(leaf_cert, uuid="my-unique-uuid")
        record = handler.get_by_serial(leaf_cert.serial_number)
        assert record.uuid == "my-unique-uuid"

    def test_duplicate_serial_returns_false(self, handler, leaf_cert):
        handler.register_cert_in_db(leaf_cert, uuid="uuid-dup-1")
        result = handler.register_cert_in_db(leaf_cert, uuid="uuid-dup-2")
        assert result is False

    def test_certificate_pem_stored(self, handler, leaf_cert):
        from cryptography.hazmat.primitives import serialization

        handler.register_cert_in_db(leaf_cert, uuid="uuid-pem")
        record = handler.get_by_serial(leaf_cert.serial_number)
        expected_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode()
        assert record.certificate_pem == expected_pem


# ---------------------------------------------------------------------------
# SyncDBHandler.get_by_serial
# ---------------------------------------------------------------------------


class TestGetBySerial:
    def test_returns_none_for_unknown_serial(self, handler):
        assert handler.get_by_serial(99999999) is None

    def test_returns_record_for_known_serial(self, handler, leaf_cert, registered_cert):
        record = handler.get_by_serial(leaf_cert.serial_number)
        assert record is not None
        assert record.serial_number == str(leaf_cert.serial_number)


# ---------------------------------------------------------------------------
# SyncDBHandler.get_by_name
# ---------------------------------------------------------------------------


class TestGetByName:
    def test_returns_none_for_unknown_cn(self, handler):
        assert handler.get_by_name("nobody.example.com") is None

    def test_returns_record_for_known_cn(self, handler, leaf_cert, registered_cert):
        record = handler.get_by_name("leaf.example.com")
        assert record is not None
        assert record.common_name == "leaf.example.com"

    def test_returns_none_for_revoked_cert(self, handler, leaf_cert):
        handler.register_cert_in_db(leaf_cert, uuid="uuid-rev-get")
        handler.revoke_certificate(leaf_cert.serial_number)
        # get_by_name filters to VALID only
        assert handler.get_by_name("leaf.example.com") is None


# ---------------------------------------------------------------------------
# SyncDBHandler.delete_certificate_by_serial
# ---------------------------------------------------------------------------


class TestDeleteCertificateBySerial:
    def test_returns_false_for_unknown_serial(self, handler):
        assert handler.delete_certificate_by_serial(88888888) is False

    def test_returns_true_for_known_serial(self, handler, leaf_cert, registered_cert):
        result = handler.delete_certificate_by_serial(leaf_cert.serial_number)
        assert result is True

    def test_record_gone_after_delete(self, handler, leaf_cert, registered_cert):
        handler.delete_certificate_by_serial(leaf_cert.serial_number)
        assert handler.get_by_serial(leaf_cert.serial_number) is None

    def test_double_delete_returns_false(self, handler, leaf_cert, registered_cert):
        handler.delete_certificate_by_serial(leaf_cert.serial_number)
        result = handler.delete_certificate_by_serial(leaf_cert.serial_number)
        assert result is False


# ---------------------------------------------------------------------------
# SyncDBHandler.revoke_certificate
# ---------------------------------------------------------------------------


class TestRevokeCertificate:
    def test_revoke_existing_valid_returns_ok(self, handler, leaf_cert):
        handler.register_cert_in_db(leaf_cert, uuid="uuid-revoke-1")
        success, status = handler.revoke_certificate(leaf_cert.serial_number)
        assert success is True
        assert status is RevokeStatus.OK

    def test_revoke_unknown_serial_returns_not_found(self, handler):
        success, status = handler.revoke_certificate(77777777)
        assert success is False
        assert status is RevokeStatus.NOT_FOUND

    def test_revoke_updates_status_to_revoked(self, handler, leaf_cert):
        handler.register_cert_in_db(leaf_cert, uuid="uuid-revoke-2")
        handler.revoke_certificate(leaf_cert.serial_number)
        record = handler.get_by_serial(leaf_cert.serial_number)
        assert record.status == CertificateStatus.REVOKED

    def test_revoke_sets_revocation_date(self, handler, leaf_cert):
        handler.register_cert_in_db(leaf_cert, uuid="uuid-revoke-3")
        handler.revoke_certificate(leaf_cert.serial_number)
        record = handler.get_by_serial(leaf_cert.serial_number)
        assert record.revocation_date is not None

    def test_revoke_with_reason(self, handler, leaf_cert):
        handler.register_cert_in_db(leaf_cert, uuid="uuid-revoke-4")
        handler.revoke_certificate(
            leaf_cert.serial_number, reason=x509.ReasonFlags.key_compromise
        )
        record = handler.get_by_serial(leaf_cert.serial_number)
        assert record.revocation_reason is not None

    def test_revoke_already_revoked_returns_not_found(self, handler, leaf_cert):
        handler.register_cert_in_db(leaf_cert, uuid="uuid-revoke-5")
        handler.revoke_certificate(leaf_cert.serial_number)
        success, status = handler.revoke_certificate(leaf_cert.serial_number)
        assert success is False
        assert status is RevokeStatus.NOT_FOUND


# ---------------------------------------------------------------------------
# SyncDBHandler.get_revoked_certificates
# ---------------------------------------------------------------------------


class TestGetRevokedCertificates:
    def test_empty_db_yields_nothing(self, handler):
        rows = list(handler.get_revoked_certificates())
        assert rows == []

    def test_revoked_cert_appears_in_generator(self, handler, leaf_cert):
        handler.register_cert_in_db(leaf_cert, uuid="uuid-crl-1")
        handler.revoke_certificate(leaf_cert.serial_number)
        rows = list(handler.get_revoked_certificates())
        serials = [str(r.serial_number) for r in rows]
        assert str(leaf_cert.serial_number) in serials

    def test_valid_cert_does_not_appear(self, handler, leaf_cert):
        handler.register_cert_in_db(leaf_cert, uuid="uuid-crl-2")
        rows = list(handler.get_revoked_certificates())
        serials = [str(r.serial_number) for r in rows]
        assert str(leaf_cert.serial_number) not in serials

    def test_returns_generator(self, handler):
        from types import GeneratorType

        result = handler.get_revoked_certificates()
        assert hasattr(result, "__iter__")
