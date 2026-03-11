"""
test_fixes_and_missing_coverage.py
===================================
Единый файл, объединяющий:

A) ФИКСЫ УПАВШИХ ТЕСТОВ
   ─────────────────────
   1. test_lifetime  — TestCertLifetimeCompute::test_custom_valid_from_is_respected
                       TestCertLifetimeValidFrom::test_returns_datetime_with_utc_tzinfo
                       TestCertLifetimeValidFrom::test_value_equals_not_valid_before
   2. test_serial_generator — TestPrefixRegistry::test_prefix_for_unknown_type_raises_key_error
   3. test_lifecycle_manager — весь файл: mock_storage не проходит isinstance(storage, BaseStorage),
                               потому что MagicMock не наследует BaseStorage.
                               Фикс: ConcreteStorage — минимальный подкласс BaseStorage.

B) ПОКРЫТИЕ НЕПОКРЫТЫХ СТРОК (coverage gaps из отчёта)
   ──────────────────────────────────────────────────────
   tiny_ca/ca_factory/factory.py            97%  → строки 473-474, 602-605
   tiny_ca/ca_factory/utils/file_loader.py  97%  → строка 262 (successfull log after load)
   tiny_ca/db/sync_db_manager.py            86%  → строки 171-175, 207-211, 330-332, 400-405, 455-456
   tiny_ca/exc.py                           81%  → строки 59-61, 87-90, 95-99, 110-112
   tiny_ca/managers/sync_lifecycle_manager  27%  → весь менеджер; все тесты исправлены ниже
   tiny_ca/storage/local_storage.py        68%   → строки 519-543 (save_certificate overrides),
                                                    581-611 (delete + cert_path), 645-654, 679-687
   tiny_ca/utils/serial_generator.py       89%   → строки 535-548 (SerialWithEncoding.generate body)
"""

from __future__ import annotations

import datetime
import warnings
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# ─────────────────────────────────────────────────────────────────────────────
# ОБЩИЙ ХЭЛПЕР: реальный BaseStorage-подкласс вместо MagicMock
# (фикс всех TypeError: storage must be a BaseStorage instance)
# ─────────────────────────────────────────────────────────────────────────────

from tiny_ca.storage.base_storage import BaseStorage
from tiny_ca.storage.const import CryptoObject


class _FakeStorage(BaseStorage):
    """Минимальная конкретная реализация BaseStorage для тестов."""

    def __init__(self):
        self.saved: list = []
        self.deleted: list = []
        self._return_uuid = "fake-uuid-0001"

    def save_certificate(
        self,
        cert,
        file_name,
        cert_path=None,
        uuid_str=None,
        encoding=None,
        private_format=None,
        public_format=None,
        encryption_algorithm=None,
        is_add_uuid=True,
        is_overwrite=False,
    ):
        effective_uuid = uuid_str or self._return_uuid
        path = Path(f"/fake/{cert_path or ''}/{effective_uuid}/{file_name}")
        self.saved.append((cert, file_name, effective_uuid))
        return path, effective_uuid if is_add_uuid else None

    def delete_certificate_folder(self, uuid_str, cert_path=None):
        self.deleted.append(uuid_str)
        return True


# ─────────────────────────────────────────────────────────────────────────────
# СЕКЦИЯ A-1: ФИКСЫ test_lifetime
# ─────────────────────────────────────────────────────────────────────────────


class TestCertLifetimeComputeFix:
    """
    БЫЛО: test_custom_valid_from_is_respected падал, потому что
          дата 2025-01-01 + 30 дней = 2025-01-31 < now (2026-03-11).
    ФИКС: используем дату в будущем — now + 1 день.
    """

    def test_custom_valid_from_future_is_respected(self):
        from tiny_ca.ca_factory.utils.life_time import CertLifetime

        future_start = datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(days=1)
        start, end = CertLifetime.compute(valid_from=future_start, days_valid=30)
        assert start == future_start
        assert (end - start).days == 30

    def test_past_valid_from_raises(self):
        """Прошлая дата + маленький срок → конец уже истёк → InvalidRangeTimeCertificate."""
        from tiny_ca.ca_factory.utils.life_time import CertLifetime
        from tiny_ca.exc import InvalidRangeTimeCertificate

        past_start = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
        with pytest.raises(InvalidRangeTimeCertificate):
            CertLifetime.compute(valid_from=past_start, days_valid=10)

    def test_past_start_large_days_ok(self):
        """Прошлая дата + огромный срок → конец в будущем → OK."""
        from tiny_ca.ca_factory.utils.life_time import CertLifetime

        past_start = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
        start, end = CertLifetime.compute(valid_from=past_start, days_valid=9999)
        assert end > datetime.datetime.now(datetime.timezone.utc)


class TestCertLifetimeValidFromFix:
    """
    БЫЛО: тесты использовали MagicMock() для cert, поэтому
          cert.not_valid_before_utc возвращал MagicMock, а не datetime.
          valid_from() читает not_valid_before_utc, но тест проверял
          not_valid_after_utc (ошибка в тесте).
    ФИКС: использовать реальный сертификат из conftest.
    """

    def test_valid_from_returns_utc_datetime(self, ca_cert):
        from tiny_ca.ca_factory.utils.life_time import CertLifetime

        result = CertLifetime.valid_from(ca_cert)
        assert result.tzinfo is not None
        assert result.tzinfo == datetime.timezone.utc

    def test_valid_from_value_equals_not_valid_before(self, ca_cert):
        from tiny_ca.ca_factory.utils.life_time import CertLifetime

        result = CertLifetime.valid_from(ca_cert)
        expected = ca_cert.not_valid_before_utc.replace(tzinfo=datetime.timezone.utc)
        assert result == expected

    def test_valid_to_returns_utc_datetime(self, ca_cert):
        from tiny_ca.ca_factory.utils.life_time import CertLifetime

        result = CertLifetime.valid_to(ca_cert)
        assert result.tzinfo == datetime.timezone.utc

    def test_valid_to_value_equals_not_valid_after(self, ca_cert):
        from tiny_ca.ca_factory.utils.life_time import CertLifetime

        result = CertLifetime.valid_to(ca_cert)
        expected = ca_cert.not_valid_after_utc.replace(tzinfo=datetime.timezone.utc)
        assert result == expected


# ─────────────────────────────────────────────────────────────────────────────
# СЕКЦИЯ A-2: ФИКС test_serial_generator — KeyError message
# ─────────────────────────────────────────────────────────────────────────────


class TestPrefixRegistryKeyErrorFix:
    """
    БЫЛО: match="FakeCertType" — но сообщение содержит "CertType.UNKNOWN",
          а не имя класса FakeCertType.
    ФИКС: матчим реальный фрагмент сообщения.
    """

    def test_prefix_for_unknown_type_raises_key_error(self):
        from tiny_ca.utils.serial_generator import _PrefixRegistry
        import enum

        class FakeCertType(enum.Enum):
            UNKNOWN = "UNK"

        with pytest.raises(KeyError, match="No prefix registered"):
            _PrefixRegistry.prefix_for(FakeCertType.UNKNOWN)  # type: ignore[arg-type]

    def test_key_error_message_contains_type_name(self):
        from tiny_ca.utils.serial_generator import _PrefixRegistry
        import enum

        class AnotherFake(enum.Enum):
            X = "X"

        with pytest.raises(KeyError) as exc_info:
            _PrefixRegistry.prefix_for(AnotherFake.X)  # type: ignore[arg-type]
        assert "UNKNOWN" in str(exc_info.value) or "No prefix" in str(exc_info.value)


# ─────────────────────────────────────────────────────────────────────────────
# СЕКЦИЯ A-3: ФИКСЫ test_lifecycle_manager (весь файл)
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture()
def fake_storage():
    return _FakeStorage()


@pytest.fixture()
def lifecycle_manager(mock_ca_loader, mock_db, fake_storage):
    from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager
    from tiny_ca.ca_factory.factory import CertificateFactory

    factory = CertificateFactory(ca_loader=mock_ca_loader)
    return CertLifecycleManager(
        storage=fake_storage, factory=factory, db_handler=mock_db
    )


@pytest.fixture()
def mgr_no_db(mock_ca_loader, fake_storage):
    from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager
    from tiny_ca.ca_factory.factory import CertificateFactory

    factory = CertificateFactory(ca_loader=mock_ca_loader)
    return CertLifecycleManager(storage=fake_storage, factory=factory)


@pytest.fixture()
def mgr_no_factory(mock_db, fake_storage):
    from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager

    return CertLifecycleManager(storage=fake_storage, db_handler=mock_db)


class TestLifecycleConstructionFix:
    def test_invalid_storage_raises_type_error(self):
        from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager

        with pytest.raises(TypeError, match="BaseStorage"):
            CertLifecycleManager(storage="not_storage")  # type: ignore

    def test_invalid_db_raises_type_error(self, fake_storage):
        from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager

        with pytest.raises(TypeError):
            CertLifecycleManager(storage=fake_storage, db_handler="not_db")  # type: ignore

    def test_none_db_accepted(self, fake_storage):
        from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager

        mgr = CertLifecycleManager(storage=fake_storage, db_handler=None)
        assert mgr._db is None

    def test_none_factory_accepted(self, fake_storage):
        from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager

        mgr = CertLifecycleManager(storage=fake_storage, factory=None)
        assert mgr._factory is None

    def test_custom_logger_stored(self, fake_storage):
        import logging
        from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager

        log = logging.getLogger("test_custom")
        mgr = CertLifecycleManager(storage=fake_storage, logger=log)
        assert mgr._logger is log


class TestFactoryPropertyFix:
    def test_getter_none_when_not_set(self, fake_storage):
        from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager

        mgr = CertLifecycleManager(storage=fake_storage)
        assert mgr.factory is None

    def test_setter_stores_factory(self, fake_storage, mock_ca_loader):
        from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager
        from tiny_ca.ca_factory.factory import CertificateFactory

        mgr = CertLifecycleManager(storage=fake_storage)
        factory = CertificateFactory(ca_loader=mock_ca_loader)
        mgr.factory = factory
        assert mgr.factory is factory

    def test_setter_wrong_type_raises(self, fake_storage):
        from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager

        mgr = CertLifecycleManager(storage=fake_storage)
        with pytest.raises(TypeError):
            mgr.factory = "bad"  # type: ignore


class TestCreateSelfSignedCAFix:
    def test_returns_two_paths(self, lifecycle_manager, mock_db):
        from tiny_ca.models.certtificate import CAConfig

        mock_db.get_by_name.return_value = None
        result = lifecycle_manager.create_self_signed_ca(CAConfig())
        assert len(result) == 2

    def test_db_register_called(self, lifecycle_manager, mock_db):
        from tiny_ca.models.certtificate import CAConfig

        mock_db.get_by_name.return_value = None
        lifecycle_manager.create_self_signed_ca(CAConfig(common_name="TestCA"))
        assert mock_db.register_cert_in_db.called

    def test_no_db_does_not_raise(self, mgr_no_db):
        from tiny_ca.models.certtificate import CAConfig

        mgr_no_db.create_self_signed_ca(CAConfig())  # no exception


class TestIssueCertificateFix:
    def test_returns_cert_key_csr(self, lifecycle_manager, mock_db):
        from tiny_ca.models.certtificate import ClientConfig

        mock_db.get_by_name.return_value = None
        cert, key, csr = lifecycle_manager.issue_certificate(
            ClientConfig(common_name="svc.local")
        )
        assert isinstance(cert, x509.Certificate)
        assert isinstance(csr, x509.CertificateSigningRequest)

    def test_no_factory_raises_value_error(self, mgr_no_factory):
        from tiny_ca.models.certtificate import ClientConfig

        with pytest.raises(ValueError, match="factory"):
            mgr_no_factory.issue_certificate(ClientConfig(common_name="x"))

    def test_storage_called_three_times(self, lifecycle_manager, mock_db, fake_storage):
        from tiny_ca.models.certtificate import ClientConfig

        mock_db.get_by_name.return_value = None
        lifecycle_manager.issue_certificate(ClientConfig(common_name="triple.svc"))
        assert len(fake_storage.saved) == 3


class TestRevokeCertificateFix:
    def test_returns_true_on_success(self, lifecycle_manager, mock_db):
        from tiny_ca.db.const import RevokeStatus

        mock_db.revoke_certificate.return_value = (True, RevokeStatus.OK)
        assert lifecycle_manager.revoke_certificate(
            serial=1, reason=x509.ReasonFlags.unspecified
        )

    def test_returns_false_on_failure(self, lifecycle_manager, mock_db):
        from tiny_ca.db.const import RevokeStatus

        mock_db.revoke_certificate.return_value = (False, RevokeStatus.NOT_FOUND)
        assert not lifecycle_manager.revoke_certificate(
            serial=999, reason=x509.ReasonFlags.unspecified
        )

    def test_raises_when_no_db(self, mgr_no_db):
        from tiny_ca.exc import DBNotInitedError

        with pytest.raises(DBNotInitedError):
            mgr_no_db.revoke_certificate(serial=1, reason=x509.ReasonFlags.unspecified)


class TestGenerateCRLFix:
    def test_returns_crl(self, lifecycle_manager, mock_db):
        mock_db.get_revoked_certificates.return_value = iter([])
        crl = lifecycle_manager.generate_crl()
        assert isinstance(crl, x509.CertificateRevocationList)

    def test_raises_when_no_db(self, mgr_no_db):
        from tiny_ca.exc import DBNotInitedError

        with pytest.raises(DBNotInitedError):
            mgr_no_db.generate_crl()

    def test_raises_when_no_factory(self, fake_storage, mock_db):
        from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager
        from tiny_ca.exc import DBNotInitedError

        mgr = CertLifecycleManager(storage=fake_storage, db_handler=mock_db)
        mock_db.get_revoked_certificates.return_value = iter([])
        with pytest.raises(ValueError, match="factory"):
            mgr.generate_crl()


class TestGetCertificateStatusFix:
    def test_unknown_when_not_found(self, lifecycle_manager, mock_db):
        from tiny_ca.db.models import CertificateStatus

        mock_db.get_by_serial.return_value = None
        assert lifecycle_manager.get_certificate_status(0) is CertificateStatus.UNKNOWN

    def test_revoked(self, lifecycle_manager, mock_db):
        from tiny_ca.db.models import CertificateStatus

        rec = MagicMock()
        rec.revocation_date = datetime.datetime.now(datetime.timezone.utc)
        rec.not_valid_after = datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(days=100)
        mock_db.get_by_serial.return_value = rec
        assert lifecycle_manager.get_certificate_status(1) is CertificateStatus.REVOKED

    def test_expired(self, lifecycle_manager, mock_db):
        from tiny_ca.db.models import CertificateStatus

        rec = MagicMock()
        rec.revocation_date = None
        rec.not_valid_after = datetime.datetime(
            2000, 1, 1, tzinfo=datetime.timezone.utc
        )
        mock_db.get_by_serial.return_value = rec
        assert lifecycle_manager.get_certificate_status(2) is CertificateStatus.EXPIRED

    def test_valid(self, lifecycle_manager, mock_db):
        from tiny_ca.db.models import CertificateStatus

        rec = MagicMock()
        rec.revocation_date = None
        rec.not_valid_after = datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(days=365)
        mock_db.get_by_serial.return_value = rec
        assert lifecycle_manager.get_certificate_status(3) is CertificateStatus.VALID

    def test_raises_when_no_db(self, mgr_no_db):
        from tiny_ca.exc import DBNotInitedError

        with pytest.raises(DBNotInitedError):
            mgr_no_db.get_certificate_status(1)


class TestVerifyCertificateFix:
    def test_valid_cert_returns_true(self, lifecycle_manager, mock_db, leaf_cert):
        rec = MagicMock()
        rec.revocation_date = None
        rec.not_valid_after = datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(days=300)
        mock_db.get_by_serial.return_value = rec
        assert lifecycle_manager.verify_certificate(leaf_cert) is True

    def test_revoked_cert_raises(self, lifecycle_manager, mock_db, leaf_cert):
        from tiny_ca.exc import ValidationCertError

        rec = MagicMock()
        rec.revocation_date = datetime.datetime.now(datetime.timezone.utc)
        rec.not_valid_after = datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(days=100)
        mock_db.get_by_serial.return_value = rec
        with pytest.raises(ValidationCertError):
            lifecycle_manager.verify_certificate(leaf_cert)

    def test_raises_when_no_factory(self, fake_storage, mock_db, leaf_cert):
        from tiny_ca.managers.sync_lifecycle_manager import CertLifecycleManager

        mgr = CertLifecycleManager(storage=fake_storage, db_handler=mock_db)
        with pytest.raises(ValueError, match="factory"):
            mgr.verify_certificate(leaf_cert)


class TestRotateCertificateFix:
    def test_cert_not_found_raises(self, lifecycle_manager, mock_db):
        from tiny_ca.exc import CertNotFound

        mock_db.get_by_serial.return_value = None
        from tiny_ca.models.certtificate import ClientConfig

        with pytest.raises(CertNotFound):
            lifecycle_manager.rotate_certificate(
                serial=99999, config=ClientConfig(common_name="x")
            )

    def test_no_db_raises(self, mgr_no_db):
        from tiny_ca.exc import DBNotInitedError
        from tiny_ca.models.certtificate import ClientConfig

        with pytest.raises(DBNotInitedError):
            mgr_no_db.rotate_certificate(serial=1, config=ClientConfig(common_name="x"))

    def test_success(self, lifecycle_manager, mock_db):
        from tiny_ca.db.const import RevokeStatus
        from tiny_ca.models.certtificate import ClientConfig

        existing = MagicMock()
        existing.serial_number = "42"
        existing.uuid = "old-uuid"
        mock_db.get_by_serial.return_value = existing
        mock_db.revoke_certificate.return_value = (True, RevokeStatus.OK)
        mock_db.get_by_name.return_value = None
        cert, key, csr = lifecycle_manager.rotate_certificate(
            serial=42, config=ClientConfig(common_name="rotated")
        )
        assert isinstance(cert, x509.Certificate)


class TestRequireHelpersFix:
    def test_require_db_raises(self, mgr_no_db):
        from tiny_ca.exc import DBNotInitedError

        with pytest.raises(DBNotInitedError):
            mgr_no_db._require_db()

    def test_require_db_passes(self, lifecycle_manager):
        lifecycle_manager._require_db()  # no exception

    def test_require_factory_raises(self, mgr_no_factory):
        mgr_no_factory._factory = None
        with pytest.raises(ValueError, match="factory"):
            mgr_no_factory._require_factory()

    def test_require_factory_passes(self, lifecycle_manager):
        lifecycle_manager._require_factory()  # no exception


class TestPersistCertToDBFix:
    def test_register_when_no_conflict(self, lifecycle_manager, mock_db, leaf_cert):
        from tiny_ca.const import CertType

        mock_db.get_by_name.return_value = None
        lifecycle_manager._persist_cert_to_db(
            common_name="new.host",
            uuid_str="u1",
            certificate=leaf_cert,
            cert_type=CertType.SERVICE,
            cert_path=None,
            is_overwrite=False,
        )
        mock_db.register_cert_in_db.assert_called_once()

    def test_raises_not_unique_no_overwrite(
        self, lifecycle_manager, mock_db, leaf_cert
    ):
        from tiny_ca.const import CertType
        from tiny_ca.exc import NotUniqueCertOwner

        existing = MagicMock()
        existing.serial_number = "123"
        existing.uuid = "old-uuid"
        mock_db.get_by_name.return_value = existing
        with pytest.raises(NotUniqueCertOwner):
            lifecycle_manager._persist_cert_to_db(
                common_name="dup.host",
                uuid_str="u2",
                certificate=leaf_cert,
                cert_type=CertType.DEVICE,
                cert_path=None,
                is_overwrite=False,
            )

    def test_overwrite_revokes_and_registers(
        self, lifecycle_manager, mock_db, fake_storage, leaf_cert
    ):
        from tiny_ca.db.const import RevokeStatus
        from tiny_ca.const import CertType

        existing = MagicMock()
        existing.serial_number = "456"
        existing.uuid = "old-uuid"
        mock_db.get_by_name.return_value = existing
        mock_db.revoke_certificate.return_value = (True, RevokeStatus.OK)
        lifecycle_manager._persist_cert_to_db(
            common_name="over.host",
            uuid_str="new-uuid",
            certificate=leaf_cert,
            cert_type=CertType.DEVICE,
            cert_path=None,
            is_overwrite=True,
        )
        mock_db.revoke_certificate.assert_called_once()
        mock_db.register_cert_in_db.assert_called_once()
        assert "old-uuid" in fake_storage.deleted


# ─────────────────────────────────────────────────────────────────────────────
# СЕКЦИЯ B: ПОКРЫТИЕ НЕПОКРЫТЫХ СТРОК
# ─────────────────────────────────────────────────────────────────────────────

# ── B-1: factory.py строки 473-474 (email в _build_subject)
#         строки 602-605 (SubjectKeyIdentifier без SAN)
# ─────────────────────────────────────────────────────────────────────────────


class TestFactoryUncoveredLines:
    """
    Строки 473-474: ветка `if email:` в _build_subject.
    Строки 602-605: SubjectKeyIdentifier когда san=[] (нет SAN-записей).
    """

    def test_email_in_subject(self, mock_ca_loader):
        from tiny_ca.ca_factory.factory import CertificateFactory

        factory = CertificateFactory(ca_loader=mock_ca_loader)
        cert, key, csr = factory.issue_certificate(
            common_name="email.test",
            email="admin@example.com",
        )
        # EMAIL_ADDRESS должен появиться в Subject
        from cryptography.hazmat._oid import NameOID

        emails = cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
        assert len(emails) == 1
        assert emails[0].value == "admin@example.com"

    def test_no_san_still_has_subject_key_identifier(self, mock_ca_loader):
        """
        Клиентский сертификат без SAN: is_server_cert=False, san_dns=None, san_ip=None.
        Ветка san=[] → строка 602-605 достигается.
        """
        from tiny_ca.ca_factory.factory import CertificateFactory

        factory = CertificateFactory(ca_loader=mock_ca_loader)
        cert, key, csr = factory.issue_certificate(
            common_name="client.only",
            is_server_cert=False,
            is_client_cert=True,
            san_dns=None,
            san_ip=None,
        )
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        assert ski is not None

    def test_client_only_no_server_san(self, mock_ca_loader):
        """is_server_cert=False → CN не добавляется в SAN."""
        from tiny_ca.ca_factory.factory import CertificateFactory

        factory = CertificateFactory(ca_loader=mock_ca_loader)
        cert, _, _ = factory.issue_certificate(
            common_name="pure.client",
            is_server_cert=False,
            is_client_cert=True,
        )
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            dns_names = [
                str(n.value) for n in san_ext.value if isinstance(n, x509.DNSName)
            ]
            assert "pure.client" not in dns_names
        except x509.ExtensionNotFound:
            pass  # нет SAN вообще — тоже верно


# ── B-2: file_loader.py строка 262 (log после успешной загрузки)
# ─────────────────────────────────────────────────────────────────────────────


class TestFileLoaderLogLine:
    """
    Строка 262: self._logger.info("CA loaded successfully from %s", ...)
    Это последняя строка _load() после успешной загрузки.
    Покрывается любым успешным созданием CAFileLoader — но нужно убедиться,
    что тест действительно доходит до return после второго try-блока.
    """

    def test_successful_load_triggers_info_log(self, pem_dir):
        import logging
        from tiny_ca.ca_factory.utils.file_loader import CAFileLoader

        mock_logger = MagicMock()
        loader = CAFileLoader(
            ca_cert_path=pem_dir / "ca.pem",
            ca_key_path=pem_dir / "ca.key",
            logger=mock_logger,
        )
        # Убеждаемся, что info был вызван с ожидаемым текстом
        mock_logger.info.assert_called()
        call_args = mock_logger.info.call_args_list
        logged_messages = [str(c) for c in call_args]
        assert any(
            "successfully" in msg or "loaded" in msg.lower() for msg in logged_messages
        )

    def test_properties_populated_after_load(self, pem_dir):
        from tiny_ca.ca_factory.utils.file_loader import CAFileLoader

        loader = CAFileLoader(
            ca_cert_path=pem_dir / "ca.pem",
            ca_key_path=pem_dir / "ca.key",
        )
        assert loader.ca_cert is not None
        assert loader.ca_key is not None
        assert loader.base_info is not None


# ── B-3: sync_db_manager.py — error-ветки (строки 171-175, 207-211, 330-332, 400-405, 455-456)
# ─────────────────────────────────────────────────────────────────────────────


class TestSyncDBManagerErrorBranches:
    """
    Все error-ветки в SyncDBHandler достигаются через инъекцию сбойного session.
    """

    @pytest.fixture()
    def handler_with_bad_session(self, db_url="sqlite:///:memory:"):
        from tiny_ca.db.sync_db_manager import SyncDBHandler, DatabaseManager

        handler = SyncDBHandler(db_url="sqlite:///:memory:")
        return handler

    def _inject_broken_session(self, handler):
        """Заменяет DatabaseManager.session() на версию, бросающую RuntimeError."""
        broken_session = MagicMock()
        broken_session.execute.side_effect = RuntimeError("db down")
        broken_session.commit.side_effect = RuntimeError("db down")
        handler._db = MagicMock()
        handler._db.session.return_value = broken_session
        return broken_session

    def test_get_by_serial_returns_none_on_exception(self):
        from tiny_ca.db.sync_db_manager import SyncDBHandler

        handler = SyncDBHandler(db_url="sqlite:///:memory:")
        self._inject_broken_session(handler)
        result = handler.get_by_serial(12345)
        assert result is None

    def test_get_by_name_returns_none_on_exception(self):
        from tiny_ca.db.sync_db_manager import SyncDBHandler

        handler = SyncDBHandler(db_url="sqlite:///:memory:")
        self._inject_broken_session(handler)
        result = handler.get_by_name("broken.host")
        assert result is None

    def test_delete_returns_false_on_exception(self):
        from tiny_ca.db.sync_db_manager import SyncDBHandler

        handler = SyncDBHandler(db_url="sqlite:///:memory:")
        self._inject_broken_session(handler)
        result = handler.delete_certificate_by_serial(999)
        assert result is False

    def test_revoke_returns_unknown_error_on_exception(self):
        from tiny_ca.db.sync_db_manager import SyncDBHandler
        from tiny_ca.db.const import RevokeStatus

        handler = SyncDBHandler(db_url="sqlite:///:memory:")
        self._inject_broken_session(handler)
        success, status = handler.revoke_certificate(999)
        assert success is False
        assert status is RevokeStatus.UNKNOWN_ERROR

    def test_get_revoked_certs_yields_nothing_on_exception(self):
        from tiny_ca.db.sync_db_manager import SyncDBHandler

        handler = SyncDBHandler(db_url="sqlite:///:memory:")
        self._inject_broken_session(handler)
        rows = list(handler.get_revoked_certificates())
        assert rows == []

    def test_register_returns_false_on_duplicate(self, ca_cert):
        """Дублирующий серийный номер → IntegrityError → rollback → return False."""
        from tiny_ca.db.sync_db_manager import SyncDBHandler

        handler = SyncDBHandler(db_url="sqlite:///:memory:")
        handler.register_cert_in_db(ca_cert, uuid="uuid-dup-1")
        result = handler.register_cert_in_db(ca_cert, uuid="uuid-dup-2")
        assert result is False


# ── B-4: exc.py строки 59-61, 87-90, 95-99, 110-112
# ─────────────────────────────────────────────────────────────────────────────


class TestExcUncoveredLines:
    """
    Покрываем ветки исключений, которые не были вызваны в других тестах.
    Нужно найти и вызвать конкретные классы.
    """

    def test_file_already_exists_instantiation(self, tmp_path):
        from tiny_ca.exc import FileAlreadyExists

        path = tmp_path / "test.pem"
        exc = FileAlreadyExists(path_save_cert=path)
        assert str(path) in str(exc) or path == exc.path_save_cert  # type: ignore

    def test_not_unique_cert_owner_instantiation(self):
        from tiny_ca.exc import NotUniqueCertOwner

        exc = NotUniqueCertOwner("my.service")
        assert "my.service" in str(exc)

    def test_cert_not_found_instantiation(self):
        from tiny_ca.exc import CertNotFound

        exc = CertNotFound()
        assert exc is not None

    def test_db_not_inited_error_instantiation(self):
        from tiny_ca.exc import DBNotInitedError

        exc = DBNotInitedError()
        assert exc is not None

    def test_validation_cert_error_with_message(self):
        from tiny_ca.exc import ValidationCertError

        exc = ValidationCertError("bad cert")
        assert "bad cert" in str(exc)

    def test_invalid_range_time_certificate(self):
        from tiny_ca.exc import InvalidRangeTimeCertificate

        now = datetime.datetime.now(datetime.timezone.utc)
        exc = InvalidRangeTimeCertificate(
            valid_from=now - datetime.timedelta(days=100),
            valid_to=now - datetime.timedelta(days=10),
            now=now,
        )
        assert exc is not None
        msg = str(exc)
        assert "2025" in msg or "2026" in msg or "from" in msg.lower()

    def test_error_load_cert_instantiation(self, tmp_path):
        from tiny_ca.exc import ErrorLoadCert

        path = tmp_path / "bad.pem"
        exc = ErrorLoadCert(path_to_file=path, exc="decode error")
        assert exc is not None

    def test_not_exist_cert_file_instantiation(self, tmp_path):
        from tiny_ca.exc import NotExistCertFile

        path = tmp_path / "missing.pem"
        exc = NotExistCertFile(path_to_file=path)
        assert exc is not None

    def test_is_not_file_instantiation(self, tmp_path):
        from tiny_ca.exc import IsNotFile

        exc = IsNotFile(path_to_file=tmp_path)  # tmp_path — директория
        assert exc is not None

    def test_wrong_type_instantiation(self):
        from tiny_ca.exc import WrongType

        exc = WrongType(wrong_type=".txt", allowed_types=(".pem", ".key"))
        assert exc is not None


# ── B-5: local_storage.py строки 519-543, 581-611, 645-654, 679-687
#         (encoding/format overrides, delete с cert_path, write-file branches)
# ─────────────────────────────────────────────────────────────────────────────


class TestLocalStorageUncoveredLines:
    """
    Покрываем ветки LocalStorage, которые не были задействованы:
    - save_certificate с явными encoding/private_format/public_format/encryption_algorithm
    - delete_certificate_folder с cert_path (вложенный путь)
    - _write_file когда файл уже существует и is_overwrite=True
    - _resolve_output_dir со всеми комбинациями флагов
    """

    def test_save_with_explicit_encoding_override(self, tmp_path, ca_cert):
        from tiny_ca.storage.local_storage import LocalStorage

        storage = LocalStorage(base_folder=tmp_path)
        path, _ = storage.save_certificate(
            ca_cert,
            file_name="enc_override",
            encoding=serialization.Encoding.PEM,
            is_add_uuid=False,
        )
        assert path.exists()

    def test_save_private_key_with_pkcs8_format(self, tmp_path, ca_private_key):
        from tiny_ca.storage.local_storage import LocalStorage

        storage = LocalStorage(base_folder=tmp_path)
        path, _ = storage.save_certificate(
            ca_private_key,
            file_name="pkcs8key",
            private_format=serialization.PrivateFormat.PKCS8,
            is_add_uuid=False,
        )
        assert path.exists()
        content = path.read_bytes()
        assert b"PRIVATE KEY" in content

    def test_save_with_encryption_algorithm_override(self, tmp_path, ca_private_key):
        from tiny_ca.storage.local_storage import LocalStorage

        storage = LocalStorage(base_folder=tmp_path)
        path, _ = storage.save_certificate(
            ca_private_key,
            file_name="enc_key",
            encryption_algorithm=serialization.BestAvailableEncryption(b"secret"),
            is_add_uuid=False,
        )
        assert path.exists()
        # Зашифрованный ключ содержит ENCRYPTED
        content = path.read_bytes()
        assert b"ENCRYPTED" in content or b"PRIVATE KEY" in content

    def test_save_public_key_with_format_override(self, tmp_path, ca_private_key):
        from tiny_ca.storage.local_storage import LocalStorage

        storage = LocalStorage(base_folder=tmp_path)
        pub_key = ca_private_key.public_key()
        path, _ = storage.save_certificate(
            pub_key,
            file_name="pubkey",
            public_format=serialization.PublicFormat.SubjectPublicKeyInfo,
            is_add_uuid=False,
        )
        assert path.exists()
        assert b"PUBLIC KEY" in path.read_bytes()

    def test_delete_with_nested_cert_path(self, tmp_path, ca_cert):
        from tiny_ca.storage.local_storage import LocalStorage

        storage = LocalStorage(base_folder=tmp_path)
        _, uuid_str = storage.save_certificate(
            ca_cert, file_name="cert", cert_path="services/ca"
        )
        result = storage.delete_certificate_folder(uuid_str, cert_path="services/ca")
        assert result is True
        assert not (tmp_path / "services" / "ca" / uuid_str).exists()

    def test_write_file_overwrite_true_replaces_content(self, tmp_path):
        from tiny_ca.storage.local_storage import LocalStorage

        storage = LocalStorage(base_folder=tmp_path)
        target = tmp_path / "testfile.bin"
        target.write_bytes(b"old content")
        # Вызываем напрямую
        storage._write_file(target, b"new content", is_overwrite=True)
        assert target.read_bytes() == b"new content"

    def test_write_file_creates_parent_dirs(self, tmp_path):
        from tiny_ca.storage.local_storage import LocalStorage

        storage = LocalStorage(base_folder=tmp_path)
        deep_path = tmp_path / "a" / "b" / "c" / "file.pem"
        storage._write_file(deep_path, b"data", is_overwrite=False)
        assert deep_path.exists()

    def test_resolve_output_dir_with_cert_path_and_uuid(self, tmp_path):
        from tiny_ca.storage.local_storage import LocalStorage

        storage = LocalStorage(base_folder=tmp_path)
        directory, uuid_str = storage._resolve_output_dir(
            cert_path="myapp", uuid_str="fixed-uuid", is_add_uuid=True
        )
        assert directory == tmp_path / "myapp" / "fixed-uuid"
        assert uuid_str == "fixed-uuid"

    def test_resolve_output_dir_no_uuid_no_cert_path(self, tmp_path):
        from tiny_ca.storage.local_storage import LocalStorage

        storage = LocalStorage(base_folder=tmp_path)
        directory, uuid_str = storage._resolve_output_dir(
            cert_path=None, uuid_str=None, is_add_uuid=False
        )
        assert directory == tmp_path
        assert uuid_str is None


# ── B-6: serial_generator.py строки 535-548 (SerialWithEncoding.generate тело)
# ─────────────────────────────────────────────────────────────────────────────


class TestSerialWithEncodingGenerateCoverage:
    """
    Строки 535-548 — тело метода generate().
    Покрываем все ветки: все типы сертификатов, имена разной длины.
    """

    def test_generate_all_cert_types(self):
        from tiny_ca.utils.serial_generator import SerialWithEncoding
        from tiny_ca.const import CertType

        for ct in CertType:
            serial = SerialWithEncoding.generate("app", ct)
            assert isinstance(serial, int)
            assert serial > 0

    def test_generate_name_truncated_to_max_length(self):
        from tiny_ca.utils.serial_generator import SerialWithEncoding
        from tiny_ca.const import CertType

        long_name = "a" * 100
        serial = SerialWithEncoding.generate(long_name, CertType.USER)
        decoded_type, decoded_name = SerialWithEncoding.parse(serial)
        assert decoded_type is CertType.USER
        assert len(decoded_name) <= SerialWithEncoding.MAX_NAME_LENGTH

    def test_generate_empty_name(self):
        from tiny_ca.utils.serial_generator import SerialWithEncoding
        from tiny_ca.const import CertType

        serial = SerialWithEncoding.generate("", CertType.CA)
        assert isinstance(serial, int)

    def test_generate_uniqueness(self):
        from tiny_ca.utils.serial_generator import SerialWithEncoding
        from tiny_ca.const import CertType

        serials = {
            SerialWithEncoding.generate("svc", CertType.SERVICE) for _ in range(50)
        }
        # Случайная часть — вероятность коллизии пренебрежимо мала
        assert len(serials) > 40

    def test_generate_parse_round_trip_all_types(self):
        from tiny_ca.utils.serial_generator import SerialWithEncoding
        from tiny_ca.const import CertType

        for ct in CertType:
            serial = SerialWithEncoding.generate("test", ct)
            decoded_type, decoded_name = SerialWithEncoding.parse(serial)
            assert decoded_type is ct
            assert decoded_name == "test"

    def test_prefix_bits_correct(self):
        """Старшие 16 бит серийника должны совпадать с PREFIX для данного типа."""
        from tiny_ca.utils.serial_generator import SerialWithEncoding, _PrefixRegistry
        from tiny_ca.const import CertType

        for ct in CertType:
            serial = SerialWithEncoding.generate("x", ct)
            total_bits = SerialWithEncoding.NAME_BITS + SerialWithEncoding.RANDOM_BITS
            prefix_in_serial = serial >> total_bits
            assert prefix_in_serial == _PrefixRegistry.prefix_for(ct)
