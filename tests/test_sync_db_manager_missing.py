"""
Additional tests for SyncDBHandler uncovered methods (list_all, get_expiring, delete_by_uuid, update_status_expired).
"""

from __future__ import annotations

import datetime
from datetime import UTC, timedelta
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from tiny_ca.db.const import CertificateStatus, RevokeStatus
from tiny_ca.db.models import CertificateRecord
from tiny_ca.db.sync_db_manager import SyncDBHandler

DB_URL = "sqlite:///:memory:"


class TestSyncDBHandlerListAll:
    """Test list_all method - covers lines 443-460."""

    def setup_method(self):
        self.handler = SyncDBHandler(db_url=DB_URL, logger=MagicMock())

    def test_list_all_no_filters(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = [
                MagicMock(),
                MagicMock(),
            ]
            mock_sess.execute.return_value = mock_result
            mock_session_factory.return_value = mock_sess

            results = self.handler.list_all()

            assert len(results) == 2
            mock_sess.close.assert_called_once()

    def test_list_all_with_status_filter(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = [MagicMock()]
            mock_sess.execute.return_value = mock_result
            mock_session_factory.return_value = mock_sess

            results = self.handler.list_all(status="valid")

            assert len(results) == 1

    def test_list_all_with_key_type_filter(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = [MagicMock()]
            mock_sess.execute.return_value = mock_result
            mock_session_factory.return_value = mock_sess

            results = self.handler.list_all(key_type="service")

            assert len(results) == 1

    def test_list_all_with_both_filters(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = [MagicMock()]
            mock_sess.execute.return_value = mock_result
            mock_session_factory.return_value = mock_sess

            results = self.handler.list_all(status="valid", key_type="service")

            assert len(results) == 1

    def test_list_all_with_pagination(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = [MagicMock()]
            mock_sess.execute.return_value = mock_result
            mock_session_factory.return_value = mock_sess

            results = self.handler.list_all(limit=10, offset=5)

            assert len(results) == 1

    def test_list_all_error_returns_empty(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_sess.execute.side_effect = Exception("Database error")
            mock_session_factory.return_value = mock_sess

            results = self.handler.list_all()

            assert results == []
            self.handler._logger.error.assert_called_once()
            mock_sess.close.assert_called_once()


class TestSyncDBHandlerGetExpiring:
    """Test get_expiring method - covers lines 476-498."""

    def setup_method(self):
        self.handler = SyncDBHandler(db_url=DB_URL, logger=MagicMock())

    def test_get_expiring_returns_records(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = [
                MagicMock(),
                MagicMock(),
            ]
            mock_sess.execute.return_value = mock_result
            mock_session_factory.return_value = mock_sess

            results = self.handler.get_expiring(within_days=30)

            assert len(results) == 2
            mock_sess.close.assert_called_once()

    def test_get_expiring_empty(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = []
            mock_sess.execute.return_value = mock_result
            mock_session_factory.return_value = mock_sess

            results = self.handler.get_expiring(within_days=30)

            assert results == []

    def test_get_expiring_error_returns_empty(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_sess.execute.side_effect = Exception("Database error")
            mock_session_factory.return_value = mock_sess

            results = self.handler.get_expiring(within_days=30)

            assert results == []
            self.handler._logger.error.assert_called_once()
            mock_sess.close.assert_called_once()


class TestSyncDBHandlerDeleteByUUID:
    """Test delete_by_uuid method - covers lines 514-529."""

    def setup_method(self):
        self.handler = SyncDBHandler(db_url=DB_URL, logger=MagicMock())

    def test_delete_by_uuid_success(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_result = MagicMock()
            mock_result.rowcount = 1
            mock_sess.execute.return_value = mock_result
            mock_sess.commit.return_value = None
            mock_session_factory.return_value = mock_sess

            result = self.handler.delete_by_uuid("test-uuid")

            assert result is True
            mock_sess.commit.assert_called_once()
            mock_sess.close.assert_called_once()

    def test_delete_by_uuid_not_found(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_result = MagicMock()
            mock_result.rowcount = 0
            mock_sess.execute.return_value = mock_result
            mock_sess.commit.return_value = None
            mock_session_factory.return_value = mock_sess

            result = self.handler.delete_by_uuid("nonexistent")

            assert result is False

    def test_delete_by_uuid_error(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_sess.execute.side_effect = Exception("Database error")
            mock_sess.rollback.return_value = None
            mock_session_factory.return_value = mock_sess

            result = self.handler.delete_by_uuid("test-uuid")

            assert result is False
            mock_sess.rollback.assert_called_once()
            self.handler._logger.error.assert_called_once()
            mock_sess.close.assert_called_once()


class TestSyncDBHandlerUpdateStatusExpired:
    """Test update_status_expired method - covers lines 540-563."""

    def setup_method(self):
        self.handler = SyncDBHandler(db_url=DB_URL, logger=MagicMock())

    def test_update_status_expired_success(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_result = MagicMock()
            mock_result.rowcount = 5
            mock_sess.execute.return_value = mock_result
            mock_sess.commit.return_value = None
            mock_session_factory.return_value = mock_sess

            count = self.handler.update_status_expired()

            assert count == 5
            mock_sess.commit.assert_called_once()
            mock_sess.close.assert_called_once()

    def test_update_status_expired_zero(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_result = MagicMock()
            mock_result.rowcount = 0
            mock_sess.execute.return_value = mock_result
            mock_sess.commit.return_value = None
            mock_session_factory.return_value = mock_sess

            count = self.handler.update_status_expired()

            assert count == 0

    def test_update_status_expired_error(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_sess.execute.side_effect = Exception("Database error")
            mock_sess.rollback.return_value = None
            mock_session_factory.return_value = mock_sess

            count = self.handler.update_status_expired()

            assert count == 0
            mock_sess.rollback.assert_called_once()
            self.handler._logger.error.assert_called_once()
            mock_sess.close.assert_called_once()


class TestSyncDBHandlerRevokeCertificateEdgeCases:
    """Additional revoke_certificate tests for coverage."""

    def setup_method(self):
        self.handler = SyncDBHandler(db_url=DB_URL, logger=MagicMock())

    def test_revoke_certificate_success(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_cert = MagicMock(spec=CertificateRecord)
            mock_cert.status = CertificateStatus.VALID
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = mock_cert
            mock_sess.execute.return_value = mock_result
            mock_sess.commit.return_value = None
            mock_session_factory.return_value = mock_sess

            from cryptography.x509 import ReasonFlags

            success, status = self.handler.revoke_certificate(
                12345, ReasonFlags.key_compromise
            )

            assert success is True
            assert status == RevokeStatus.OK
            assert mock_cert.status == CertificateStatus.REVOKED
            mock_sess.close.assert_called_once()

    def test_revoke_certificate_not_found(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = None
            mock_sess.execute.return_value = mock_result
            mock_session_factory.return_value = mock_sess

            success, status = self.handler.revoke_certificate(99999)

            assert success is False
            assert status == RevokeStatus.NOT_FOUND
            mock_sess.close.assert_called_once()

    def test_revoke_certificate_error(self):
        with patch.object(self.handler._db, "session") as mock_session_factory:
            mock_sess = MagicMock(spec=Session)
            mock_sess.execute.side_effect = Exception("Database error")
            mock_sess.rollback.return_value = None
            mock_session_factory.return_value = mock_sess

            success, status = self.handler.revoke_certificate(12345)

            assert success is False
            assert status == RevokeStatus.UNKNOWN_ERROR
            mock_sess.rollback.assert_called_once()
            mock_sess.close.assert_called_once()
