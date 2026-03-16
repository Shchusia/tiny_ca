"""
Tests for tiny_ca/managers/async_lifecycle_manager.py  (AsyncCertLifecycleManager)

Coverage target: 100 %

Run with:
    pytest test_async_lifecycle_manager.py -v \
        --cov=tiny_ca.managers.async_lifecycle_manager --cov-report=term-missing
"""

from __future__ import annotations

import asyncio
import datetime
import logging
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tiny_ca.ca_factory import CertificateFactory
from tiny_ca.const import CertType
from tiny_ca.db.const import CertificateStatus, RevokeStatus
from tiny_ca.exc import (
    CertNotFound,
    DBNotInitedError,
    NotUniqueCertOwner,
    ValidationCertError,
)
from tiny_ca.managers.async_lifecycle_manager import AsyncCertLifecycleManager
from tiny_ca.models.certtificate import CAConfig, ClientConfig
from tiny_ca.settings import DEFAULT_LOGGER
from tiny_ca.storage.async_local_storage import AsyncLocalStorage


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


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
    return AsyncLocalStorage(base_folder=tmp_path)


@pytest.fixture
def mock_db():
    db = MagicMock()
    db.get_by_name = AsyncMock(return_value=None)
    db.get_by_serial = AsyncMock(return_value=None)
    db.register_cert_in_db = AsyncMock(return_value=True)
    db.revoke_certificate = AsyncMock(return_value=(True, RevokeStatus.OK))

    async def _empty_gen():
        return
        yield

    db.get_revoked_certificates = MagicMock(return_value=_empty_gen())
    return db


@pytest.fixture
def mgr(storage, factory, mock_db):
    return AsyncCertLifecycleManager(
        storage=storage, factory=factory, db_handler=mock_db
    )


def _client_config(**kwargs) -> ClientConfig:
    defaults = dict(
        common_name="async.test.svc",
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
        common_name="Async CA",
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


class TestAsyncInit:
    def test_default_storage_created(self):
        mgr = AsyncCertLifecycleManager()
        assert isinstance(mgr._storage, AsyncLocalStorage)

    def test_custom_storage_stored(self, storage):
        mgr = AsyncCertLifecycleManager(storage=storage)
        assert mgr._storage is storage

    def test_default_logger(self, storage):
        mgr = AsyncCertLifecycleManager(storage=storage)
        assert mgr._logger is DEFAULT_LOGGER

    def test_custom_logger(self, storage):
        lg = logging.getLogger("async_mgr_test")
        mgr = AsyncCertLifecycleManager(storage=storage, logger=lg)
        assert mgr._logger is lg

    def test_factory_none_by_default(self, storage):
        mgr = AsyncCertLifecycleManager(storage=storage)
        assert mgr._factory is None

    def test_db_none_by_default(self, storage):
        mgr = AsyncCertLifecycleManager(storage=storage)
        assert mgr._db is None


# ===========================================================================
# factory property
# ===========================================================================


class TestAsyncFactoryProperty:
    def test_getter_returns_current_factory(self, mgr, factory):
        assert mgr.factory is factory

    def test_setter_accepts_certificate_factory(self, storage, factory):
        mgr = AsyncCertLifecycleManager(storage=storage)
        mgr.factory = factory
        assert mgr.factory is factory

    def test_setter_rejects_wrong_type(self, storage):
        mgr = AsyncCertLifecycleManager(storage=storage)
        with pytest.raises(TypeError, match="CertificateFactory"):
            mgr.factory = "bad"  # type: ignore


# ===========================================================================
# _require_db / _require_factory
# ===========================================================================


class TestAsyncRequireHelpers:
    def test_require_db_raises_when_none(self, storage):
        mgr = AsyncCertLifecycleManager(storage=storage)
        with pytest.raises(DBNotInitedError):
            mgr._require_db()

    def test_require_factory_raises_when_none(self, storage):
        mgr = AsyncCertLifecycleManager(storage=storage)
        with pytest.raises(ValueError, match="factory"):
            mgr._require_factory()

    def test_require_db_passes_when_set(self, mgr):
        mgr._require_db()

    def test_require_factory_passes_when_set(self, mgr):
        mgr._require_factory()


# ===========================================================================
# _derive_file_name (static, async)
# ===========================================================================


class TestAsyncDeriveFileName:
    def test_uses_explicit_name(self):
        config = _client_config(name="my-svc")
        result = run(AsyncCertLifecycleManager._derive_file_name(config))
        assert result == "my-svc"

    def test_falls_back_to_common_name(self):
        config = _client_config(name=None, common_name="Async.Svc")
        result = run(AsyncCertLifecycleManager._derive_file_name(config))
        assert result == "async.svc"

    def test_os_sep_replaced(self):
        import os

        config = _client_config(name=None, common_name=f"a{os.sep}b")
        result = run(AsyncCertLifecycleManager._derive_file_name(config))
        assert os.sep not in result


# ===========================================================================
# create_self_signed_ca
# ===========================================================================


class TestAsyncCreateSelfSignedCA:
    def test_returns_two_paths(self, storage):
        mgr = AsyncCertLifecycleManager(storage=storage)
        cert_path, key_path = run(mgr.create_self_signed_ca(_ca_config()))
        assert cert_path.exists()
        assert key_path.exists()

    def test_with_db_registers_cert(self, storage, mock_db):
        mgr = AsyncCertLifecycleManager(storage=storage, db_handler=mock_db)
        run(mgr.create_self_signed_ca(_ca_config()))
        mock_db.register_cert_in_db.assert_called_once()

    def test_without_db_skips_registration(self, storage):
        mgr = AsyncCertLifecycleManager(storage=storage)
        run(mgr.create_self_signed_ca(_ca_config()))


# ===========================================================================
# issue_certificate
# ===========================================================================


class TestAsyncIssueCertificate:
    def test_raises_without_factory(self, storage):
        mgr = AsyncCertLifecycleManager(storage=storage)
        with pytest.raises(ValueError, match="factory"):
            run(mgr.issue_certificate(_client_config()))

    def test_returns_cert_key_csr(self, mgr):
        cert, key, csr = run(mgr.issue_certificate(_client_config()))
        assert isinstance(cert, x509.Certificate)
        assert isinstance(key, rsa.RSAPrivateKey)

    def test_files_written_to_storage(self, mgr, storage):
        run(mgr.issue_certificate(_client_config()))
        pem_files = list(storage._base_folder.rglob("*.pem"))
        assert len(pem_files) >= 1

    def test_with_db_registers_cert(self, mgr, mock_db):
        run(mgr.issue_certificate(_client_config()))
        mock_db.register_cert_in_db.assert_called()

    def test_without_db_no_registration(self, storage, factory):
        mgr = AsyncCertLifecycleManager(storage=storage, factory=factory)
        cert, key, csr = run(mgr.issue_certificate(_client_config()))
        assert cert is not None

    def test_cert_path_subdir(self, mgr, storage):
        run(mgr.issue_certificate(_client_config(), cert_path="sub"))
        files = list((storage._base_folder / "sub").rglob("*"))
        assert len(files) > 0

    def test_explicit_name_used(self, mgr, storage):
        run(mgr.issue_certificate(_client_config(name="explicit")))
        keys = list(storage._base_folder.rglob("explicit.key"))
        assert len(keys) == 1


# ===========================================================================
# revoke_certificate
# ===========================================================================


class TestAsyncRevokeCertificate:
    def test_raises_without_db(self, storage, factory):
        mgr = AsyncCertLifecycleManager(storage=storage, factory=factory)
        with pytest.raises(DBNotInitedError):
            run(mgr.revoke_certificate(1, x509.ReasonFlags.unspecified))

    def test_returns_true_on_success(self, mgr, mock_db):
        mock_db.revoke_certificate = AsyncMock(return_value=(True, RevokeStatus.OK))
        result = run(mgr.revoke_certificate(1, x509.ReasonFlags.unspecified))
        assert result is True

    def test_returns_false_on_failure(self, mgr, mock_db):
        mock_db.revoke_certificate = AsyncMock(
            return_value=(False, RevokeStatus.NOT_FOUND)
        )
        result = run(mgr.revoke_certificate(1, x509.ReasonFlags.unspecified))
        assert result is False

    def test_delegates_to_db(self, mgr, mock_db):
        mock_db.revoke_certificate = AsyncMock(return_value=(True, RevokeStatus.OK))
        run(mgr.revoke_certificate(42, x509.ReasonFlags.key_compromise))
        mock_db.revoke_certificate.assert_called_with(
            serial_number=42, reason=x509.ReasonFlags.key_compromise
        )


# ===========================================================================
# generate_crl
# ===========================================================================


class TestAsyncGenerateCRL:
    def test_raises_without_db(self, storage, factory):
        mgr = AsyncCertLifecycleManager(storage=storage, factory=factory)
        with pytest.raises(DBNotInitedError):
            run(mgr.generate_crl())

    def test_raises_without_factory(self, storage, mock_db):
        mgr = AsyncCertLifecycleManager(storage=storage, db_handler=mock_db)
        with pytest.raises(ValueError, match="factory"):
            run(mgr.generate_crl())

    def test_returns_crl(self, mgr):
        crl = run(mgr.generate_crl())
        assert isinstance(crl, x509.CertificateRevocationList)

    def test_crl_saved_to_storage(self, mgr, storage):
        run(mgr.generate_crl())
        crls = list(storage._base_folder.rglob("crl.pem"))
        assert len(crls) == 1


# ===========================================================================
# get_certificate_status
# ===========================================================================


class TestAsyncGetCertificateStatus:
    def test_raises_without_db(self, storage):
        mgr = AsyncCertLifecycleManager(storage=storage)
        with pytest.raises(DBNotInitedError):
            run(mgr.get_certificate_status(1))

    def test_unknown_when_not_found(self, mgr, mock_db):
        mock_db.get_by_serial = AsyncMock(return_value=None)
        assert run(mgr.get_certificate_status(1)) == CertificateStatus.UNKNOWN

    def test_revoked_when_revocation_date_set(self, mgr, mock_db):
        rec = MagicMock()
        rec.revocation_date = datetime.datetime.now(datetime.UTC)
        rec.not_valid_after = datetime.datetime.now(datetime.UTC) + datetime.timedelta(
            days=1
        )
        mock_db.get_by_serial = AsyncMock(return_value=rec)
        assert run(mgr.get_certificate_status(1)) == CertificateStatus.REVOKED

    def test_expired_when_past_valid_date(self, mgr, mock_db):
        rec = MagicMock()
        rec.revocation_date = None
        rec.not_valid_after = datetime.datetime.now(datetime.UTC) - datetime.timedelta(
            days=1
        )
        mock_db.get_by_serial = AsyncMock(return_value=rec)
        assert run(mgr.get_certificate_status(1)) == CertificateStatus.EXPIRED

    def test_valid_for_active_cert(self, mgr, mock_db):
        rec = MagicMock()
        rec.revocation_date = None
        rec.not_valid_after = datetime.datetime.now(datetime.UTC) + datetime.timedelta(
            days=365
        )
        mock_db.get_by_serial = AsyncMock(return_value=rec)
        assert run(mgr.get_certificate_status(1)) == CertificateStatus.VALID


# ===========================================================================
# verify_certificate
# ===========================================================================


class TestAsyncVerifyCertificate:
    def test_raises_without_factory(self, storage, mock_db):
        mgr = AsyncCertLifecycleManager(storage=storage, db_handler=mock_db)
        with pytest.raises(ValueError, match="factory"):
            run(mgr.verify_certificate(MagicMock(spec=x509.Certificate)))

    def test_returns_true_for_valid_cert(self, mgr, mock_db):
        cert, _, _ = run(mgr.issue_certificate(_client_config()))
        rec = MagicMock()
        rec.revocation_date = None
        rec.not_valid_after = datetime.datetime.now(datetime.UTC) + datetime.timedelta(
            days=365
        )
        mock_db.get_by_serial = AsyncMock(return_value=rec)
        assert run(mgr.verify_certificate(cert)) is True

    def test_raises_for_revoked_cert(self, mgr, mock_db):
        cert, _, _ = run(mgr.issue_certificate(_client_config()))
        rec = MagicMock()
        rec.revocation_date = datetime.datetime.now(datetime.UTC)
        rec.not_valid_after = datetime.datetime.now(datetime.UTC) + datetime.timedelta(
            days=1
        )
        mock_db.get_by_serial = AsyncMock(return_value=rec)
        with pytest.raises(ValidationCertError, match="revoked"):
            run(mgr.verify_certificate(cert))

    def test_raises_for_wrong_issuer(self, mgr, mock_db):
        other_key = rsa.generate_private_key(65537, 2048, default_backend())
        now = datetime.datetime.now(datetime.UTC)
        other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other CA")])
        foreign = (
            x509.CertificateBuilder()
            .subject_name(other_name)
            .issuer_name(other_name)
            .public_key(other_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(other_key, hashes.SHA256(), default_backend())
        )
        rec = MagicMock()
        rec.revocation_date = None
        rec.not_valid_after = now + datetime.timedelta(days=365)
        mock_db.get_by_serial = AsyncMock(return_value=rec)
        with pytest.raises(ValidationCertError):
            run(mgr.verify_certificate(foreign))


# ===========================================================================
# rotate_certificate
# ===========================================================================


class TestAsyncRotateCertificate:
    def test_raises_without_db(self, storage, factory):
        mgr = AsyncCertLifecycleManager(storage=storage, factory=factory)
        with pytest.raises(DBNotInitedError):
            run(mgr.rotate_certificate(1, _client_config()))

    def test_raises_cert_not_found(self, mgr, mock_db):
        mock_db.get_by_serial = AsyncMock(return_value=None)
        with pytest.raises(CertNotFound):
            run(mgr.rotate_certificate(9999, _client_config()))

    def test_successful_rotation(self, mgr, mock_db):
        old_rec = MagicMock()
        old_rec.serial_number = "12345"
        mock_db.get_by_serial = AsyncMock(return_value=old_rec)
        mock_db.revoke_certificate = AsyncMock(return_value=(True, RevokeStatus.OK))
        mock_db.get_by_name = AsyncMock(return_value=None)

        new_cert, new_key, new_csr = run(
            mgr.rotate_certificate(12345, _client_config())
        )
        assert isinstance(new_cert, x509.Certificate)


# ===========================================================================
# _persist_cert_to_db
# ===========================================================================


class TestAsyncPersistCertToDB:
    def test_no_existing_registers_directly(self, mgr, mock_db):
        mock_db.get_by_name = AsyncMock(return_value=None)
        run(mgr.issue_certificate(_client_config(common_name="fresh.async.svc")))
        mock_db.register_cert_in_db.assert_called()

    def test_existing_no_overwrite_raises(self, mgr, mock_db):
        existing = MagicMock()
        existing.serial_number = "111"
        existing.uuid = "old-uuid"
        mock_db.get_by_name = AsyncMock(return_value=existing)

        with pytest.raises(NotUniqueCertOwner):
            run(
                mgr.issue_certificate(
                    _client_config(common_name="dup.async.svc"), is_overwrite=False
                )
            )

    def test_existing_with_overwrite_revokes_and_registers(self, mgr, mock_db):
        existing = MagicMock()
        existing.serial_number = "222"
        existing.uuid = "old-uuid-async"
        mock_db.get_by_name = AsyncMock(return_value=existing)
        mock_db.revoke_certificate = AsyncMock(return_value=(True, RevokeStatus.OK))

        cert, _, _ = run(
            mgr.issue_certificate(
                _client_config(common_name="ow.async.svc"), is_overwrite=True
            )
        )
        assert isinstance(cert, x509.Certificate)
        mock_db.revoke_certificate.assert_called()
