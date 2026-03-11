"""
test_lifecycle_manager.py

Tests for tiny_ca/sync_lifecycle_manager.py — CertLifecycleManager:
  - Construction  — type checks, defaults
  - factory property  — getter, setter type check
  - create_self_signed_ca
  - issue_certificate
  - revoke_certificate
  - generate_crl
  - get_certificate_status
  - verify_certificate
  - rotate_certificate
  - _persist_cert_to_db
  - _derive_file_name
  - _require_db / _require_factory
"""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from cryptography import x509

from tiny_ca import CertLifecycleManager
from tiny_ca.ca_factory.factory import CertificateFactory
from tiny_ca.db.models import CertificateStatus
from tiny_ca.exc import (
    DBNotInitedError,
    NotUniqueCertOwner,
    ValidationCertError,
    CertNotFound,
)
from tiny_ca.models.certtificate import CAConfig, ClientConfig
from tiny_ca.const import CertType


# ---------------------------------------------------------------------------
# Fixture: fully wired manager (factory + db + storage all mocked)
# ---------------------------------------------------------------------------


@pytest.fixture()
def manager(mock_ca_loader, mock_db, mock_storage):
    factory = CertificateFactory(ca_loader=mock_ca_loader)
    mgr = CertLifecycleManager(
        storage=mock_storage,
        factory=factory,
        db_handler=mock_db,
    )
    return mgr


@pytest.fixture()
def manager_no_db(mock_ca_loader, mock_storage):
    factory = CertificateFactory(ca_loader=mock_ca_loader)
    return CertLifecycleManager(storage=mock_storage, factory=factory)


@pytest.fixture()
def manager_no_factory(mock_db, mock_storage):
    return CertLifecycleManager(storage=mock_storage, db_handler=mock_db)


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_default_storage_accepted(self, mock_ca_loader):
        # Should not raise when using the default LocalStorage
        mgr = CertLifecycleManager()
        assert mgr is not None

    def test_invalid_storage_raises_type_error(self):
        with pytest.raises(TypeError, match="BaseStorage"):
            CertLifecycleManager(storage="not_storage")  # type: ignore[arg-type]

    def test_invalid_db_handler_raises_type_error(self, mock_storage):
        with pytest.raises(TypeError, match="BaseDB"):
            CertLifecycleManager(storage=mock_storage, db_handler="not_db")  # type: ignore[arg-type]

    def test_none_db_is_accepted(self, mock_storage):
        mgr = CertLifecycleManager(storage=mock_storage, db_handler=None)
        assert mgr._db is None

    def test_none_factory_is_accepted(self, mock_storage):
        mgr = CertLifecycleManager(storage=mock_storage, factory=None)
        assert mgr._factory is None

    def test_custom_logger_stored(self, mock_storage):
        import logging

        log = logging.getLogger("test")
        mgr = CertLifecycleManager(storage=mock_storage, logger=log)
        assert mgr._logger is log


# ---------------------------------------------------------------------------
# factory property
# ---------------------------------------------------------------------------


class TestFactoryProperty:
    def test_getter_returns_none_when_not_set(self, mock_storage):
        mgr = CertLifecycleManager(storage=mock_storage)
        assert mgr.factory is None

    def test_setter_stores_factory(self, mock_storage, mock_ca_loader):
        mgr = CertLifecycleManager(storage=mock_storage)
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        mgr.factory = factory
        assert mgr.factory is factory

    def test_setter_invalid_type_raises(self, mock_storage):
        mgr = CertLifecycleManager(storage=mock_storage)
        with pytest.raises(TypeError, match="CertificateFactory"):
            mgr.factory = "bad_value"  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# create_self_signed_ca
# ---------------------------------------------------------------------------


class TestCreateSelfSignedCA:
    def test_returns_two_paths(self, manager, mock_storage):
        mock_storage.save_certificate.return_value = ("/fake/path", "uuid-ca")
        config = CAConfig()
        result = manager.create_self_signed_ca(config)
        assert len(result) == 2

    def test_storage_save_called(self, manager, mock_storage):
        mock_storage.save_certificate.return_value = ("/p", "u")
        config = CAConfig(common_name="RootCA")
        manager.create_self_signed_ca(config)
        assert mock_storage.save_certificate.called

    def test_db_register_called_when_db_present(self, manager, mock_db, mock_storage):
        mock_storage.save_certificate.return_value = ("/p", "uuid-001")
        mock_db.get_by_name.return_value = None
        config = CAConfig(common_name="TestCA")
        manager.create_self_signed_ca(config)
        assert mock_db.register_cert_in_db.called

    def test_no_db_no_register_called(self, manager_no_db, mock_storage):
        mock_storage.save_certificate.return_value = ("/p", "uuid-x")
        config = CAConfig()
        # Should not raise even without DB
        manager_no_db.create_self_signed_ca(config)


# ---------------------------------------------------------------------------
# issue_certificate
# ---------------------------------------------------------------------------


class TestIssueCertificate:
    def test_returns_cert_key_csr_tuple(self, manager, mock_storage):
        mock_storage.save_certificate.return_value = ("/p", "uuid-issue")
        mock_manager_db = manager._db
        mock_manager_db.get_by_name.return_value = None
        config = ClientConfig(common_name="svc.local")
        cert, key, csr = manager.issue_certificate(config)
        assert isinstance(cert, x509.Certificate)
        assert isinstance(csr, x509.CertificateSigningRequest)

    def test_raises_when_factory_not_set(self, manager_no_factory, mock_storage):
        mock_storage.save_certificate.return_value = ("/p", "u")
        config = ClientConfig(common_name="x")
        with pytest.raises(ValueError, match="factory is not initialised"):
            manager_no_factory.issue_certificate(config)

    def test_storage_called_three_times_for_pem_key_csr(self, manager, mock_storage):
        mock_storage.save_certificate.return_value = ("/p", "u")
        manager._db.get_by_name.return_value = None
        config = ClientConfig(common_name="triple.test")
        manager.issue_certificate(config)
        # cert + key + csr = 3 save_certificate calls
        assert mock_storage.save_certificate.call_count == 3

    def test_derive_file_name_uses_name_field(self, manager, mock_storage):
        mock_storage.save_certificate.return_value = ("/p", "u")
        manager._db.get_by_name.return_value = None
        config = ClientConfig(common_name="Long/Service Name", name="custom")
        manager.issue_certificate(config)
        call_kwargs = mock_storage.save_certificate.call_args_list[0]
        assert "custom" in str(call_kwargs)


# ---------------------------------------------------------------------------
# revoke_certificate
# ---------------------------------------------------------------------------


class TestRevokeCertificate:
    def test_returns_true_on_success(self, manager, mock_db):
        from tiny_ca.db.const import RevokeStatus

        mock_db.revoke_certificate.return_value = (True, RevokeStatus.OK)
        result = manager.revoke_certificate(
            serial=12345, reason=x509.ReasonFlags.unspecified
        )
        assert result is True

    def test_returns_false_on_failure(self, manager, mock_db):
        from tiny_ca.db.const import RevokeStatus

        mock_db.revoke_certificate.return_value = (False, RevokeStatus.NOT_FOUND)
        result = manager.revoke_certificate(
            serial=99999, reason=x509.ReasonFlags.unspecified
        )
        assert result is False

    def test_raises_db_not_inited_when_no_db(self, manager_no_db):
        with pytest.raises(DBNotInitedError):
            manager_no_db.revoke_certificate(
                serial=1, reason=x509.ReasonFlags.unspecified
            )


# ---------------------------------------------------------------------------
# generate_crl
# ---------------------------------------------------------------------------


class TestGenerateCRL:
    def test_returns_crl_object(self, manager, mock_db, mock_storage):
        mock_db.get_revoked_certificates.return_value = iter([])
        mock_storage.save_certificate.return_value = ("/crl.pem", None)
        crl = manager.generate_crl()
        assert isinstance(crl, x509.CertificateRevocationList)

    def test_raises_when_no_db(self, manager_no_db):
        with pytest.raises(DBNotInitedError):
            manager_no_db.generate_crl()

    def test_raises_when_no_factory(self, manager_no_factory):
        with pytest.raises(DBNotInitedError):
            # _require_db runs first; DBNotInitedError expected here
            # (manager_no_factory also has db)
            pass
        # manager_no_factory has db but no factory
        manager_no_factory._db = MagicMock()
        manager_no_factory._db.get_revoked_certificates.return_value = iter([])
        with pytest.raises(ValueError, match="factory is not initialised"):
            manager_no_factory.generate_crl()

    def test_storage_called_with_overwrite_true(self, manager, mock_db, mock_storage):
        mock_db.get_revoked_certificates.return_value = iter([])
        mock_storage.save_certificate.return_value = ("/crl.pem", None)
        manager.generate_crl()
        call_kwargs = mock_storage.save_certificate.call_args
        assert (
            call_kwargs.kwargs.get("is_overwrite") is True or True in call_kwargs.args
        )


# ---------------------------------------------------------------------------
# get_certificate_status
# ---------------------------------------------------------------------------


class TestGetCertificateStatus:
    def test_unknown_when_not_in_db(self, manager, mock_db):
        mock_db.get_by_serial.return_value = None
        status = manager.get_certificate_status(serial=0)
        assert status is CertificateStatus.UNKNOWN

    def test_revoked_when_revocation_date_set(self, manager, mock_db):
        record = MagicMock()
        record.revocation_date = datetime.datetime.now(datetime.timezone.utc)
        record.not_valid_after = datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(days=100)
        mock_db.get_by_serial.return_value = record
        status = manager.get_certificate_status(serial=1)
        assert status is CertificateStatus.REVOKED

    def test_expired_when_past_not_valid_after(self, manager, mock_db):
        record = MagicMock()
        record.revocation_date = None
        record.not_valid_after = datetime.datetime(
            2000, 1, 1, tzinfo=datetime.timezone.utc
        )
        mock_db.get_by_serial.return_value = record
        status = manager.get_certificate_status(serial=2)
        assert status is CertificateStatus.EXPIRED

    def test_valid_for_current_cert(self, manager, mock_db):
        record = MagicMock()
        record.revocation_date = None
        record.not_valid_after = datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(days=365)
        mock_db.get_by_serial.return_value = record
        status = manager.get_certificate_status(serial=3)
        assert status is CertificateStatus.VALID

    def test_raises_when_no_db(self, manager_no_db):
        with pytest.raises(DBNotInitedError):
            manager_no_db.get_certificate_status(serial=1)


# ---------------------------------------------------------------------------
# verify_certificate
# ---------------------------------------------------------------------------


class TestVerifyCertificate:
    def test_valid_cert_returns_true(self, manager, mock_db, leaf_cert):
        record = MagicMock()
        record.revocation_date = None
        record.not_valid_after = datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(days=300)
        mock_db.get_by_serial.return_value = record
        result = manager.verify_certificate(leaf_cert)
        assert result is True

    def test_revoked_cert_raises_validation_error(self, manager, mock_db, leaf_cert):
        record = MagicMock()
        record.revocation_date = datetime.datetime.now(datetime.timezone.utc)
        record.not_valid_after = datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(days=100)
        mock_db.get_by_serial.return_value = record
        with pytest.raises(ValidationCertError):
            manager.verify_certificate(leaf_cert)

    def test_raises_when_no_factory(self, mock_storage, mock_db, leaf_cert):
        mgr = CertLifecycleManager(storage=mock_storage, db_handler=mock_db)
        with pytest.raises(ValueError, match="factory is not initialised"):
            mgr.verify_certificate(leaf_cert)


# ---------------------------------------------------------------------------
# rotate_certificate
# ---------------------------------------------------------------------------


class TestRotateCertificate:
    def test_raises_cert_not_found_when_missing(self, manager, mock_db):
        mock_db.get_by_serial.return_value = None
        config = ClientConfig(common_name="new.service")
        with pytest.raises(CertNotFound):
            manager.rotate_certificate(serial=99999, config=config)

    def test_raises_when_no_db(self, manager_no_db):
        config = ClientConfig(common_name="x")
        with pytest.raises(DBNotInitedError):
            manager_no_db.rotate_certificate(serial=1, config=config)

    def test_success_returns_cert_key_csr(self, manager, mock_db, mock_storage):
        from tiny_ca.db.const import RevokeStatus

        existing = MagicMock()
        existing.serial_number = "99"
        existing.uuid = "old-uuid"
        mock_db.get_by_serial.return_value = existing
        mock_db.revoke_certificate.return_value = (True, RevokeStatus.OK)
        mock_db.get_by_name.return_value = None
        mock_storage.save_certificate.return_value = ("/p", "u")
        config = ClientConfig(common_name="rotated.service")
        cert, key, csr = manager.rotate_certificate(serial=99, config=config)
        assert isinstance(cert, x509.Certificate)


# ---------------------------------------------------------------------------
# _require_db and _require_factory
# ---------------------------------------------------------------------------


class TestRequireHelpers:
    def test_require_db_raises_when_no_db(self, manager_no_db):
        with pytest.raises(DBNotInitedError):
            manager_no_db._require_db()

    def test_require_db_passes_when_db_set(self, manager):
        manager._require_db()  # no exception

    def test_require_factory_raises_when_no_factory(self, manager_no_factory):
        manager_no_factory._factory = None
        with pytest.raises(ValueError, match="factory is not initialised"):
            manager_no_factory._require_factory()

    def test_require_factory_passes_when_set(self, manager):
        manager._require_factory()  # no exception


# ---------------------------------------------------------------------------
# _derive_file_name
# ---------------------------------------------------------------------------


class TestDeriveFileName:
    def test_uses_name_when_set(self):
        config = ClientConfig(common_name="My Service", name="my-service")
        assert CertLifecycleManager._derive_file_name(config) == "my-service"

    def test_falls_back_to_common_name_lowercased(self):
        config = ClientConfig(common_name="My.Service")
        result = CertLifecycleManager._derive_file_name(config)
        assert result == "my.service"

    def test_replaces_os_sep_with_underscore(self):
        import os

        config = ClientConfig(common_name=f"service{os.sep}name")
        result = CertLifecycleManager._derive_file_name(config)
        assert os.sep not in result
        assert "_" in result


# ---------------------------------------------------------------------------
# _persist_cert_to_db
# ---------------------------------------------------------------------------


class TestPersistCertToDB:
    def test_calls_register_when_no_existing(self, manager, mock_db, leaf_cert):
        mock_db.get_by_name.return_value = None
        manager._persist_cert_to_db(
            common_name="new.host",
            uuid_str="uuid-xyz",
            certificate=leaf_cert,
            cert_type=CertType.SERVICE,
            cert_path=None,
            is_overwrite=False,
        )
        mock_db.register_cert_in_db.assert_called_once()

    def test_raises_not_unique_when_existing_no_overwrite(
        self, manager, mock_db, leaf_cert
    ):
        existing = MagicMock()
        existing.serial_number = "123"
        existing.uuid = "old-uuid"
        mock_db.get_by_name.return_value = existing
        with pytest.raises(NotUniqueCertOwner):
            manager._persist_cert_to_db(
                common_name="dup.host",
                uuid_str="new-uuid",
                certificate=leaf_cert,
                cert_type=CertType.DEVICE,
                cert_path=None,
                is_overwrite=False,
            )

    def test_overwrites_existing_when_flag_true(
        self, manager, mock_db, mock_storage, leaf_cert
    ):
        from tiny_ca.db.const import RevokeStatus

        existing = MagicMock()
        existing.serial_number = "456"
        existing.uuid = "old-uuid"
        mock_db.get_by_name.return_value = existing
        mock_db.revoke_certificate.return_value = (True, RevokeStatus.OK)
        mock_db.register_cert_in_db.return_value = True
        manager._persist_cert_to_db(
            common_name="overwrite.host",
            uuid_str="new-uuid",
            certificate=leaf_cert,
            cert_type=CertType.DEVICE,
            cert_path=None,
            is_overwrite=True,
        )
        mock_db.revoke_certificate.assert_called_once()
        mock_storage.delete_certificate_folder.assert_called_once()
        mock_db.register_cert_in_db.assert_called_once()
