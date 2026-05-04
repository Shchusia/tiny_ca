"""
Tests for tiny_ca/managers/sync_lifecycle_manager.py  (CertLifecycleManager)

Coverage target: 100 %

Run with:
    pytest test_sync_lifecycle_manager.py -v \
        --cov=tiny_ca.managers.sync_lifecycle_manager --cov-report=term-missing
"""

from __future__ import annotations

import datetime
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tiny_ca.ca_factory import CertificateFactory
from tiny_ca.const import CertType
from tiny_ca.db.base_db import BaseDB
from tiny_ca.db.const import CertificateStatus, RevokeStatus
from tiny_ca.exc import (
    CertNotFound,
    DBNotInitedError,
    NotUniqueCertOwner,
    ValidationCertError,
)
from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager
from tiny_ca.models.certtificate import CAConfig, ClientConfig
from tiny_ca.settings import DEFAULT_LOGGER
from tiny_ca.storage.base_storage import BaseStorage
from tiny_ca.storage.local_storage import LocalStorage


# ---------------------------------------------------------------------------
# Shared real crypto fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ca_key():
    return rsa.generate_private_key(65537, 2048, default_backend())


@pytest.fixture(scope="module")
def ca_cert(ca_key):
    now = datetime.datetime.now(datetime.UTC)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )


@pytest.fixture(scope="module")
def factory(ca_cert, ca_key):
    class _Loader:
        @property
        def ca_cert(self):
            return ca_cert

        @property
        def ca_key(self):
            return ca_key

        @property
        def base_info(self):
            from tiny_ca.models.certtificate import CertificateInfo

            return CertificateInfo(
                organization="Test Corp",
                organizational_unit=None,
                country="UA",
                state=None,
                locality=None,
            )

    return CertificateFactory(_Loader())


@pytest.fixture
def storage(tmp_path):
    return LocalStorage(base_folder=tmp_path)


@pytest.fixture
def mock_db():
    db = MagicMock(spec=BaseDB)
    db.get_by_name.return_value = None
    db.get_by_serial.return_value = None
    db.register_cert_in_db.return_value = True
    db.revoke_certificate.return_value = (True, RevokeStatus.OK)
    db.get_revoked_certificates.return_value = iter([])
    return db


@pytest.fixture
def mgr(storage, factory, mock_db):
    return CertLifecycleManager(storage=storage, factory=factory, db_handler=mock_db)


def _client_config(**kwargs) -> ClientConfig:
    defaults = dict(
        common_name="test.svc",
        serial_type=CertType.SERVICE,
        key_size=2048,
        days_valid=365,
        email=None,
        is_server_cert=False,
        is_client_cert=False,
        san_dns=None,
        san_ip=None,
        name=None,
    )
    defaults.update(kwargs)
    return ClientConfig(**defaults)


def _ca_config(**kwargs) -> CAConfig:
    defaults = dict(
        common_name="Test CA",
        organization="Test Corp",
        country="UA",
        key_size=2048,
        days_valid=3650,
    )
    defaults.update(kwargs)
    return CAConfig(**defaults)


# ===========================================================================
# __init__
# ===========================================================================


class TestInit:
    def test_valid_construction(self, storage):
        mgr = CertLifecycleManager(storage=storage)
        assert mgr._storage is storage

    def test_invalid_storage_raises_type_error(self):
        with pytest.raises(TypeError, match="BaseStorage"):
            CertLifecycleManager(storage="not-a-storage")  # type: ignore

    def test_invalid_db_handler_raises_type_error(self, storage):
        with pytest.raises(TypeError, match="BaseDB"):
            CertLifecycleManager(storage=storage, db_handler="not-a-db")  # type: ignore

    def test_none_db_accepted(self, storage):
        mgr = CertLifecycleManager(storage=storage, db_handler=None)
        assert mgr._db is None

    def test_default_logger(self, storage):
        mgr = CertLifecycleManager(storage=storage)
        assert mgr._logger is DEFAULT_LOGGER

    def test_custom_logger(self, storage):
        lg = logging.getLogger("mgr_test")
        mgr = CertLifecycleManager(storage=storage, logger=lg)
        assert mgr._logger is lg


# ===========================================================================
# factory property
# ===========================================================================


class TestFactoryProperty:
    def test_getter_returns_none_by_default(self, storage):
        mgr = CertLifecycleManager(storage=storage)
        assert mgr.factory is None

    def test_setter_accepts_certificate_factory(self, storage, factory):
        mgr = CertLifecycleManager(storage=storage)
        mgr.factory = factory
        assert mgr.factory is factory

    def test_setter_rejects_wrong_type(self, storage):
        mgr = CertLifecycleManager(storage=storage)
        with pytest.raises(TypeError, match="CertificateFactory"):
            mgr.factory = "not-a-factory"  # type: ignore


# ===========================================================================
# _require_db / _require_factory
# ===========================================================================


class TestRequireHelpers:
    def test_require_db_raises_when_no_db(self, storage):
        mgr = CertLifecycleManager(storage=storage)
        with pytest.raises(DBNotInitedError):
            mgr._require_db()

    def test_require_factory_raises_when_no_factory(self, storage):
        mgr = CertLifecycleManager(storage=storage)
        with pytest.raises(ValueError, match="factory"):
            mgr._require_factory()

    def test_require_db_passes_when_db_set(self, mgr):
        mgr._require_db()  # must not raise

    def test_require_factory_passes_when_factory_set(self, mgr):
        mgr._require_factory()  # must not raise


# ===========================================================================
# _derive_file_name
# ===========================================================================


class TestDeriveFileName:
    def test_uses_explicit_name(self):
        config = _client_config(name="my-service", common_name="test.svc")
        assert CertLifecycleManager._derive_file_name(config) == "my-service"

    def test_falls_back_to_common_name(self):
        config = _client_config(name=None, common_name="My.Service")
        result = CertLifecycleManager._derive_file_name(config)
        assert result == "my.service"

    def test_os_sep_replaced(self):
        import os

        config = _client_config(name=None, common_name=f"a{os.sep}b")
        assert os.sep not in CertLifecycleManager._derive_file_name(config)


# ===========================================================================
# create_self_signed_ca
# ===========================================================================


class TestCreateSelfSignedCA:
    def test_returns_two_paths(self, storage):
        mgr = CertLifecycleManager(storage=storage)
        cert_path, key_path = mgr.create_self_signed_ca(_ca_config())
        assert cert_path.exists()
        assert key_path.exists()

    def test_returns_pem_and_key(self, storage):
        mgr = CertLifecycleManager(storage=storage)
        cert_path, key_path = mgr.create_self_signed_ca(_ca_config())
        assert cert_path.suffix == ".pem"
        assert key_path.suffix == ".key"

    def test_with_db_registers_cert(self, storage, mock_db):
        mgr = CertLifecycleManager(storage=storage, db_handler=mock_db)
        mgr.create_self_signed_ca(_ca_config())
        mock_db.register_cert_in_db.assert_called_once()

    def test_without_db_skips_registration(self, storage):
        mgr = CertLifecycleManager(storage=storage)
        mgr.create_self_signed_ca(_ca_config())
        # No exception means DB path was skipped


# ===========================================================================
# issue_certificate
# ===========================================================================


class TestIssueCertificate:
    def test_raises_without_factory(self, storage):
        mgr = CertLifecycleManager(storage=storage)
        with pytest.raises(ValueError, match="factory"):
            mgr.issue_certificate(_client_config())

    def test_returns_cert_key_csr(self, mgr):
        cert, key, csr = mgr.issue_certificate(_client_config())
        assert isinstance(cert, x509.Certificate)
        assert isinstance(key, rsa.RSAPrivateKey)

    def test_files_written_to_storage(self, mgr, storage):
        mgr.issue_certificate(_client_config())
        # At least one .pem file should exist somewhere in the base folder
        pem_files = list(storage._base_folder.rglob("*.pem"))
        assert len(pem_files) >= 1

    def test_with_db_registers_cert(self, mgr, mock_db):
        mgr.issue_certificate(_client_config())
        mock_db.register_cert_in_db.assert_called()

    def test_without_db_skips_registration(self, storage, factory):
        mgr = CertLifecycleManager(storage=storage, factory=factory)
        cert, key, csr = mgr.issue_certificate(_client_config())
        assert cert is not None

    def test_explicit_name_used_as_filename(self, mgr, storage):
        mgr.issue_certificate(_client_config(name="explicit-name"))
        keys = list(storage._base_folder.rglob("explicit-name.key"))
        assert len(keys) == 1

    def test_cert_path_subdir_respected(self, mgr, storage):
        mgr.issue_certificate(_client_config(), cert_path="subdir")
        files = list((storage._base_folder / "subdir").rglob("*"))
        assert len(files) > 0


# ===========================================================================
# revoke_certificate
# ===========================================================================


class TestRevokeCertificate:
    def test_raises_without_db(self, storage, factory):
        mgr = CertLifecycleManager(storage=storage, factory=factory)
        with pytest.raises(DBNotInitedError):
            mgr.revoke_certificate(serial=1, reason=x509.ReasonFlags.unspecified)

    def test_returns_true_on_success(self, mgr, mock_db):
        mock_db.revoke_certificate.return_value = (True, RevokeStatus.OK)
        result = mgr.revoke_certificate(1, x509.ReasonFlags.unspecified)
        assert result is True

    def test_returns_false_on_failure(self, mgr, mock_db):
        mock_db.revoke_certificate.return_value = (False, RevokeStatus.NOT_FOUND)
        result = mgr.revoke_certificate(1, x509.ReasonFlags.unspecified)
        assert result is False

    def test_delegates_to_db(self, mgr, mock_db):
        mgr.revoke_certificate(42, x509.ReasonFlags.key_compromise)
        mock_db.revoke_certificate.assert_called_with(
            serial_number=42, reason=x509.ReasonFlags.key_compromise
        )


# ===========================================================================
# generate_crl
# ===========================================================================


class TestGenerateCRL:
    def test_raises_without_db(self, storage, factory):
        mgr = CertLifecycleManager(storage=storage, factory=factory)
        with pytest.raises(DBNotInitedError):
            mgr.generate_crl()

    def test_raises_without_factory(self, storage, mock_db):
        mgr = CertLifecycleManager(storage=storage, db_handler=mock_db)
        with pytest.raises(ValueError, match="factory"):
            mgr.generate_crl()

    def test_returns_crl_object(self, mgr):
        crl = mgr.generate_crl()
        assert isinstance(crl, x509.CertificateRevocationList)

    def test_crl_written_to_storage(self, mgr, storage):
        mgr.generate_crl()
        crls = list(storage._base_folder.rglob("crl.pem"))
        assert len(crls) == 1

    def test_custom_days_valid(self, mgr):
        crl = mgr.generate_crl(days_valid=7)
        delta = crl.next_update_utc - crl.last_update_utc
        assert delta.days == 7


# ===========================================================================
# get_certificate_status
# ===========================================================================


class TestGetCertificateStatus:
    def test_raises_without_db(self, storage):
        mgr = CertLifecycleManager(storage=storage)
        with pytest.raises(DBNotInitedError):
            mgr.get_certificate_status(1)

    def test_returns_unknown_when_not_found(self, mgr, mock_db):
        mock_db.get_by_serial.return_value = None
        assert mgr.get_certificate_status(1) == CertificateStatus.UNKNOWN

    def test_returns_revoked_when_revocation_date_set(self, mgr, mock_db):
        rec = MagicMock()
        rec.revocation_date = datetime.datetime.now(datetime.UTC)
        rec.not_valid_after = datetime.datetime.now(datetime.UTC) + datetime.timedelta(
            days=1
        )
        mock_db.get_by_serial.return_value = rec
        assert mgr.get_certificate_status(1) == CertificateStatus.REVOKED

    def test_returns_expired_when_past_valid_date(self, mgr, mock_db):
        rec = MagicMock()
        rec.revocation_date = None
        rec.not_valid_after = datetime.datetime.now(datetime.UTC) - datetime.timedelta(
            days=1
        )
        mock_db.get_by_serial.return_value = rec
        assert mgr.get_certificate_status(1) == CertificateStatus.EXPIRED

    def test_returns_valid_for_active_cert(self, mgr, mock_db):
        rec = MagicMock()
        rec.revocation_date = None
        rec.not_valid_after = datetime.datetime.now(datetime.UTC) + datetime.timedelta(
            days=365
        )
        mock_db.get_by_serial.return_value = rec
        assert mgr.get_certificate_status(1) == CertificateStatus.VALID


# ===========================================================================
# verify_certificate
# ===========================================================================


class TestVerifyCertificate:
    def test_raises_without_factory(self, storage, mock_db):
        mgr = CertLifecycleManager(storage=storage, db_handler=mock_db)
        cert = MagicMock(spec=x509.Certificate)
        with pytest.raises(ValueError, match="factory"):
            mgr.verify_certificate(cert)

    def test_returns_true_for_valid_cert(self, mgr, mock_db, ca_cert):
        rec = MagicMock()
        rec.revocation_date = None
        rec.not_valid_after = datetime.datetime.now(datetime.UTC) + datetime.timedelta(
            days=365
        )
        mock_db.get_by_serial.return_value = rec
        # Issue a real cert through the factory so validate_cert passes
        cert, _, _ = mgr.issue_certificate(_client_config())
        result = mgr.verify_certificate(cert)
        assert result is True

    def test_raises_validation_error_for_revoked_cert(self, mgr, mock_db):
        cert, _, _ = mgr.issue_certificate(_client_config())
        rec = MagicMock()
        rec.revocation_date = datetime.datetime.now(datetime.UTC)
        rec.not_valid_after = datetime.datetime.now(datetime.UTC) + datetime.timedelta(
            days=1
        )
        mock_db.get_by_serial.return_value = rec
        with pytest.raises(ValidationCertError, match="revoked"):
            mgr.verify_certificate(cert)

    # def test_raises_validation_error_for_wrong_issuer(self, storage, mock_db):
    #     other_key = rsa.generate_private_key(65537, 2048, default_backend())
    #     now = datetime.datetime.now(datetime.UTC)
    #     other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other CA")])
    #     foreign_cert = (
    #         x509.CertificateBuilder()
    #         .subject_name(other_name).issuer_name(other_name)
    #         .public_key(other_key.public_key())
    #         .serial_number(x509.random_serial_number())
    #         .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
    #         .sign(other_key, hashes.SHA256(), default_backend())
    #     )
    #     # Create fresh factory with real CA
    #     from tiny_ca.ca_factory.utils.file_loader import ICALoader
    #     from tiny_ca.models.certtificate import CertificateInfo
    #     other_factory_key = rsa.generate_private_key(65537, 2048, default_backend())
    #     other_ca_cert, _ = CertificateFactory.build_self_signed_ca()
    #     # Just use the existing mgr — foreign cert has wrong issuer
    #     from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager
    #     fresh_mgr = CertLifecycleManager(
    #         storage=LocalStorage(base_folder="/tmp/_test_verify"),
    #         factory=mgr._factory,
    #         db_handler=mock_db,
    #     )
    #     rec = MagicMock()
    #     rec.revocation_date = None
    #     rec.not_valid_after = now + datetime.timedelta(days=365)
    #     mock_db.get_by_serial.return_value = rec
    #     with pytest.raises(ValidationCertError):
    #         fresh_mgr.verify_certificate(foreign_cert)


# ===========================================================================
# rotate_certificate
# ===========================================================================


class TestRotateCertificate:
    def test_raises_without_db(self, storage, factory):
        mgr = CertLifecycleManager(storage=storage, factory=factory)
        with pytest.raises(DBNotInitedError):
            mgr.rotate_certificate(1, _client_config())

    def test_raises_cert_not_found(self, mgr, mock_db):
        mock_db.get_by_serial.return_value = None
        with pytest.raises(CertNotFound):
            mgr.rotate_certificate(9999, _client_config())

    def test_successful_rotation_returns_new_cert(self, mgr, mock_db):
        old_cert_rec = MagicMock()
        old_cert_rec.serial_number = "12345"
        mock_db.get_by_serial.return_value = old_cert_rec
        mock_db.revoke_certificate.return_value = (True, RevokeStatus.OK)
        mock_db.get_by_name.return_value = None

        new_cert, new_key, new_csr = mgr.rotate_certificate(12345, _client_config())
        assert isinstance(new_cert, x509.Certificate)


# ===========================================================================
# _persist_cert_to_db
# ===========================================================================


class TestPersistCertToDB:
    def test_no_existing_registers_directly(self, mgr, mock_db):
        mock_db.get_by_name.return_value = None
        cert, _, _ = mgr.issue_certificate(_client_config(common_name="fresh.svc"))
        mock_db.register_cert_in_db.assert_called()

    def test_existing_no_overwrite_raises(self, mgr, mock_db):
        existing = MagicMock()
        existing.serial_number = "111"
        existing.uuid = "old-uuid"
        mock_db.get_by_name.return_value = existing

        with pytest.raises(NotUniqueCertOwner):
            mgr.issue_certificate(
                _client_config(common_name="dup.svc"), is_overwrite=False
            )

    def test_existing_with_overwrite_revokes_and_re_registers(
        self, mgr, mock_db, storage
    ):
        existing = MagicMock()
        existing.serial_number = "222"
        existing.uuid = "old-uuid-to-delete"
        mock_db.get_by_name.return_value = existing
        mock_db.revoke_certificate.return_value = (True, RevokeStatus.OK)

        cert, _, _ = mgr.issue_certificate(
            _client_config(common_name="overwrite.svc"), is_overwrite=True
        )
        assert isinstance(cert, x509.Certificate)
        mock_db.revoke_certificate.assert_called()


# ===========================================================================
# inspect_certificate
# ===========================================================================


class TestInspectCertificate:
    def test_raises_without_factory(self, storage, mock_db):
        from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager

        mgr = CertLifecycleManager(storage=storage, db_handler=mock_db)
        with pytest.raises(ValueError):
            mgr.inspect_certificate(MagicMock(spec=x509.Certificate))

    def test_returns_certificate_details(self, mgr):
        from tiny_ca.models.certtificate import CertificateDetails

        cert, _, _ = mgr.issue_certificate(_client_config())
        details = mgr.inspect_certificate(cert)
        assert isinstance(details, CertificateDetails)

    def test_common_name_matches(self, mgr):
        cert, _, _ = mgr.issue_certificate(
            _client_config(common_name="inspect.sync.svc")
        )
        details = mgr.inspect_certificate(cert)
        assert details.common_name == "inspect.sync.svc"


# ===========================================================================
# cosign_certificate
# ===========================================================================


class TestCosignCertificate:
    def test_raises_without_factory(self, storage, mock_db):
        from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager

        mgr = CertLifecycleManager(storage=storage, db_handler=mock_db)
        with pytest.raises(ValueError):
            mgr.cosign_certificate(MagicMock(spec=x509.Certificate))

    def test_returns_certificate(self, mgr):
        cert, _, _ = mgr.issue_certificate(_client_config())
        cosigned = mgr.cosign_certificate(cert)
        assert isinstance(cosigned, x509.Certificate)

    def test_issuer_is_ca(self, mgr, factory):
        cert, _, _ = mgr.issue_certificate(_client_config())
        cosigned = mgr.cosign_certificate(cert)
        assert cosigned.issuer == factory._ca.ca_cert.subject

    def test_days_valid_override(self, mgr):
        cert, _, _ = mgr.issue_certificate(_client_config())
        cosigned = mgr.cosign_certificate(cert, days_valid=90)
        delta = cosigned.not_valid_after_utc - cosigned.not_valid_before_utc
        assert delta.days == 90
