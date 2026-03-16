"""
Tests for tiny_ca/db/sync_db_manager.py  (DatabaseManager + SyncDBHandler)

Coverage target: 100 %

Run with:
    pytest test_sync_db_manager.py -v --cov=tiny_ca.db.sync_db_manager --cov-report=term-missing
"""

from __future__ import annotations

import datetime
import logging
from collections.abc import Generator
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy.orm import Session

from tiny_ca.const import CertType
from tiny_ca.db.const import CertificateStatus, RevokeStatus
from tiny_ca.db.models import Base, CertificateRecord
from tiny_ca.db.sync_db_manager import DatabaseManager, SyncDBHandler
from tiny_ca.settings import DEFAULT_LOGGER


# ---------------------------------------------------------------------------
# SQLite in-memory URL used by all tests — fast and isolated
# ---------------------------------------------------------------------------

DB_URL = "sqlite:///:memory:"


# ---------------------------------------------------------------------------
# Real x509 certificate fixture (used for register tests)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def cert_and_key():
    key = rsa.generate_private_key(65537, 2048, default_backend())
    now = datetime.datetime.now(datetime.UTC)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "sync.test.svc"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256(), default_backend())
    )
    return cert, key


@pytest.fixture
def handler():
    """Fresh in-memory SyncDBHandler for every test."""
    return SyncDBHandler(db_url=DB_URL)


# ===========================================================================
# DatabaseManager
# ===========================================================================


class TestDatabaseManager:
    def test_creates_engine_and_session_factory(self):
        dm = DatabaseManager(db_url=DB_URL)
        assert dm._engine is not None
        assert dm._Session is not None

    def test_session_returns_session_instance(self):
        dm = DatabaseManager(db_url=DB_URL)
        s = dm.session()
        assert isinstance(s, Session)
        s.close()

    def test_create_all_false_skips_schema(self):
        # Should not raise even without schema
        dm = DatabaseManager(db_url=DB_URL, create_all=False)
        assert dm._engine is not None

    def test_create_all_true_creates_tables(self):
        from sqlalchemy import inspect

        dm = DatabaseManager(db_url=DB_URL, create_all=True)
        inspector = inspect(dm._engine)
        assert "certificates" in inspector.get_table_names()


# ===========================================================================
# SyncDBHandler.__init__
# ===========================================================================


class TestSyncDBHandlerInit:
    def test_default_logger(self):
        h = SyncDBHandler(db_url=DB_URL)
        assert h._logger is DEFAULT_LOGGER

    def test_custom_logger(self):
        lg = logging.getLogger("sync_test")
        h = SyncDBHandler(db_url=DB_URL, logger=lg)
        assert h._logger is lg

    def test_db_manager_created(self):
        h = SyncDBHandler(db_url=DB_URL)
        assert isinstance(h._db, DatabaseManager)


# ===========================================================================
# get_by_serial
# ===========================================================================


class TestGetBySerial:
    def test_returns_none_when_not_found(self, handler):
        assert handler.get_by_serial(99999999) is None

    def test_returns_record_when_found(self, handler, cert_and_key):
        cert, _ = cert_and_key
        handler.register_cert_in_db(cert, uuid="uuid-gbs-1")
        result = handler.get_by_serial(cert.serial_number)
        assert result is not None
        assert result.serial_number == str(cert.serial_number)

    def test_returns_none_on_db_error(self, handler):
        """Force an exception by breaking the session execute."""
        with patch.object(handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock()
            mock_sess.execute.side_effect = RuntimeError("db boom")
            mock_session_factory.return_value = mock_sess
            result = handler.get_by_serial(1)
        assert result is None
        mock_sess.close.assert_called_once()


# ===========================================================================
# get_by_name
# ===========================================================================


class TestGetByName:
    def test_returns_none_when_not_found(self, handler):
        assert handler.get_by_name("nobody.example.com") is None

    def test_returns_valid_record(self, handler, cert_and_key):
        cert, _ = cert_and_key
        handler.register_cert_in_db(cert, uuid="uuid-gbn-1")
        result = handler.get_by_name("sync.test.svc")
        assert result is not None
        assert result.common_name == "sync.test.svc"
        assert result.status == CertificateStatus.VALID

    def test_does_not_return_revoked(self, handler, cert_and_key):
        cert, _ = cert_and_key
        handler.register_cert_in_db(cert, uuid="uuid-gbn-rev")
        handler.revoke_certificate(cert.serial_number)
        # After revocation the VALID record is gone; get_by_name returns None
        assert handler.get_by_name("sync.test.svc") is None

    def test_returns_none_on_db_error(self, handler):
        with patch.object(handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock()
            mock_sess.execute.side_effect = RuntimeError("db boom")
            mock_session_factory.return_value = mock_sess
            result = handler.get_by_name("x")
        assert result is None
        mock_sess.close.assert_called_once()


# ===========================================================================
# register_cert_in_db
# ===========================================================================


class TestRegisterCertInDb:
    def test_returns_true_on_success(self, handler, cert_and_key):
        cert, _ = cert_and_key
        result = handler.register_cert_in_db(cert, uuid="uuid-reg-ok")
        assert result is True

    def test_record_persisted(self, handler, cert_and_key):
        cert, _ = cert_and_key
        handler.register_cert_in_db(cert, uuid="uuid-reg-fetch")
        rec = handler.get_by_serial(cert.serial_number)
        assert rec is not None
        assert rec.common_name == "sync.test.svc"

    def test_key_type_stored(self, handler, cert_and_key):
        cert, _ = cert_and_key
        handler.register_cert_in_db(cert, uuid="uuid-reg-kt", key_type=CertType.SERVICE)
        rec = handler.get_by_serial(cert.serial_number)
        assert rec.key_type == CertType.SERVICE.value

    def test_returns_false_on_duplicate_serial(self, handler, cert_and_key):
        cert, _ = cert_and_key
        handler.register_cert_in_db(cert, uuid="uuid-dup-a")
        result = handler.register_cert_in_db(cert, uuid="uuid-dup-b")
        assert result is False

    def test_returns_false_on_db_error(self, handler, cert_and_key):
        cert, _ = cert_and_key
        with patch.object(handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock()
            mock_sess.add.side_effect = RuntimeError("insert fail")
            mock_session_factory.return_value = mock_sess
            result = handler.register_cert_in_db(cert, uuid="uuid-err")
        assert result is False
        mock_sess.rollback.assert_called_once()
        mock_sess.close.assert_called_once()

    def test_bytes_common_name_decoded(self, handler):
        """Branch: common_name is bytes → decoded to str."""
        key = rsa.generate_private_key(65537, 2048, default_backend())
        now = datetime.datetime.now(datetime.UTC)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "bytes.test.svc"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256(), default_backend())
        )
        # Patch CN to return bytes
        with patch.object(
            cert.subject,
            "get_attributes_for_oid",
            return_value=[MagicMock(value=b"bytes.test.svc")],
        ):
            result = handler.register_cert_in_db(cert, uuid="uuid-bytes-cn")
        assert result is True


# ===========================================================================
# revoke_certificate
# ===========================================================================


class TestRevokeCertificate:
    def _register(self, handler, cert, suffix=""):
        handler.register_cert_in_db(cert, uuid=f"uuid-rev{suffix}")

    def test_success_returns_ok(self, handler, cert_and_key):
        cert, _ = cert_and_key
        self._register(handler, cert, "-ok")
        success, status = handler.revoke_certificate(cert.serial_number)
        assert success is True
        assert status == RevokeStatus.OK

    def test_record_marked_revoked(self, handler, cert_and_key):
        cert, _ = cert_and_key
        self._register(handler, cert, "-mark")
        handler.revoke_certificate(cert.serial_number)
        rec = handler.get_by_serial(cert.serial_number)
        assert rec.status == CertificateStatus.REVOKED
        assert rec.revocation_date is not None

    def test_not_found_returns_not_found(self, handler):
        success, status = handler.revoke_certificate(0xDEADBEEF)
        assert success is False
        assert status == RevokeStatus.NOT_FOUND

    def test_custom_reason_stored(self, handler, cert_and_key):
        cert, _ = cert_and_key
        self._register(handler, cert, "-reason")
        handler.revoke_certificate(
            cert.serial_number, reason=x509.ReasonFlags.key_compromise
        )
        rec = handler.get_by_serial(cert.serial_number)
        assert rec.revocation_reason == str(x509.ReasonFlags.key_compromise.value)

    def test_unknown_error_on_db_failure(self, handler, cert_and_key):
        cert, _ = cert_and_key
        with patch.object(handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock()
            mock_sess.execute.side_effect = RuntimeError("db doom")
            mock_session_factory.return_value = mock_sess
            success, status = handler.revoke_certificate(cert.serial_number)
        assert success is False
        assert status == RevokeStatus.UNKNOWN_ERROR
        mock_sess.rollback.assert_called_once()
        mock_sess.close.assert_called_once()


# ===========================================================================
# get_revoked_certificates
# ===========================================================================


class TestGetRevokedCertificates:
    def _make_and_revoke(self, handler, cn: str, uuid: str):
        key = rsa.generate_private_key(65537, 2048, default_backend())
        now = datetime.datetime.now(datetime.UTC)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256(), default_backend())
        )
        handler.register_cert_in_db(cert, uuid=uuid)
        handler.revoke_certificate(cert.serial_number)
        return cert

    def test_yields_revoked_entry(self, handler):
        cert = self._make_and_revoke(handler, "crl.svc1", "uuid-crl-1")
        rows = list(handler.get_revoked_certificates())
        serials = [str(r[0]) for r in rows]
        assert str(cert.serial_number) in serials

    def test_yields_nothing_when_no_revocations(self):
        fresh = SyncDBHandler(db_url=DB_URL)
        rows = list(fresh.get_revoked_certificates())
        assert rows == []

    def test_each_row_has_expected_fields(self, handler):
        self._make_and_revoke(handler, "crl.svc2", "uuid-crl-2")
        for row in handler.get_revoked_certificates():
            serial, revocation_date, revocation_reason = row
            assert serial is not None
            assert revocation_date is not None

    def test_error_logged_on_db_failure(self, handler):
        with patch.object(handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock()
            mock_sess.execute.side_effect = RuntimeError("crl boom")
            mock_session_factory.return_value = mock_sess
            rows = list(handler.get_revoked_certificates())
        assert rows == []
        mock_sess.close.assert_called_once()
