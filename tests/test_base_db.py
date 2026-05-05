"""
Tests for tiny_ca/db/base_db.py  (BaseDB abstract class)

Coverage target: 100 %

Run with:
    pytest test_base_db.py -v --cov=tiny_ca.db.base_db --cov-report=term-missing
"""

from __future__ import annotations

from abc import ABC
from collections.abc import Generator

import pytest
from cryptography import x509

from tiny_ca.const import CertType
from tiny_ca.db.base_db import BaseDB
from tiny_ca.db.models import CertificateRecord


# ===========================================================================
# BaseDB is abstract
# ===========================================================================


class TestBaseDBIsAbstract:
    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            BaseDB()  # type: ignore

    def test_is_abc_subclass(self):
        assert issubclass(BaseDB, ABC)

    def test_abstract_methods_declared(self):
        abstract = BaseDB.__abstractmethods__
        assert "get_by_serial" in abstract
        assert "get_by_name" in abstract
        assert "register_cert_in_db" in abstract
        assert "revoke_certificate" in abstract
        assert "get_revoked_certificates" in abstract


# ===========================================================================
# Concrete subclass satisfies the contract
# ===========================================================================


class _ConcreteDB(BaseDB):
    """Minimal concrete implementation for contract testing."""

    def get_by_serial(self, serial: int) -> CertificateRecord | None:
        return None

    def get_by_name(self, common_name: str) -> CertificateRecord | None:
        return None

    def register_cert_in_db(
        self,
        cert: x509.Certificate,
        uuid: str,
        key_type: CertType = CertType.DEVICE,
    ) -> bool:
        return True

    def revoke_certificate(
        self,
        serial_number: int,
        reason: x509.ReasonFlags = x509.ReasonFlags.unspecified,
    ) -> tuple[bool, object]:
        return True, "ok"

    def get_revoked_certificates(self) -> Generator[CertificateRecord, None, None]:
        return
        yield  # make it a generator

    def list_all(self, status=None, key_type=None, limit=100, offset=0):
        return []

    def get_expiring(self, within_days=30):
        return []

    def delete_by_uuid(self, uuid):
        return False

    def update_status_expired(self):
        return 0


class TestConcreteDBSubclass:
    def test_can_instantiate_concrete_subclass(self):
        db = _ConcreteDB()
        assert isinstance(db, BaseDB)

    def test_get_by_serial_returns_none(self):
        db = _ConcreteDB()
        assert db.get_by_serial(12345) is None

    def test_get_by_name_returns_none(self):
        db = _ConcreteDB()
        assert db.get_by_name("test.example.com") is None

    def test_register_cert_in_db_returns_true(self):
        from unittest.mock import MagicMock

        db = _ConcreteDB()
        cert = MagicMock(spec=x509.Certificate)
        assert db.register_cert_in_db(cert, "uuid-123") is True

    def test_revoke_certificate_returns_tuple(self):
        db = _ConcreteDB()
        result = db.revoke_certificate(99999)
        assert isinstance(result, tuple)
        assert result[0] is True

    def test_get_revoked_certificates_is_generator(self):
        db = _ConcreteDB()
        gen = db.get_revoked_certificates()
        assert list(gen) == []

    def test_list_all_returns_empty_list(self):
        db = _ConcreteDB()
        assert db.list_all() == []
        assert db.list_all(status="valid", key_type="service", limit=10, offset=5) == []

    def test_get_expiring_returns_empty_list(self):
        db = _ConcreteDB()
        assert db.get_expiring() == []
        assert db.get_expiring(within_days=7) == []

    def test_delete_by_uuid_returns_false(self):
        db = _ConcreteDB()
        assert db.delete_by_uuid("some-uuid") is False

    def test_update_status_expired_returns_zero(self):
        db = _ConcreteDB()
        assert db.update_status_expired() == 0


# ===========================================================================
# Partial implementation still raises TypeError
# ===========================================================================


class TestPartialSubclassRaisesTypeError:
    def test_missing_one_method_raises(self):
        class _Partial(BaseDB):
            def get_by_serial(self, serial): ...
            def get_by_name(self, common_name): ...
            def register_cert_in_db(self, cert, uuid, key_type=CertType.DEVICE): ...
            def revoke_certificate(
                self, serial_number, reason=x509.ReasonFlags.unspecified
            ): ...
            def get_revoked_certificates(self): ...
            def list_all(self, status=None, key_type=None, limit=100, offset=0): ...
            def get_expiring(self, within_days=30): ...
            def delete_by_uuid(self, uuid): ...

            # update_status_expired intentionally omitted

        with pytest.raises(TypeError):
            _Partial()  # type: ignore
