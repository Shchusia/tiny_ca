"""
Tests for tiny_ca/storage/base_storage.py  (BaseStorage ABC)

Coverage target: 100 %

Run with:
    pytest test_base_storage.py -v --cov=tiny_ca.storage.base_storage --cov-report=term-missing
"""

from __future__ import annotations

from abc import ABC
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from tiny_ca.storage.base_storage import BaseStorage
from tiny_ca.storage.const import CryptoObject


# ===========================================================================
# BaseStorage is abstract
# ===========================================================================


class TestBaseStorageIsAbstract:
    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            BaseStorage()  # type: ignore

    def test_is_abc_subclass(self):
        assert issubclass(BaseStorage, ABC)

    def test_abstract_methods_declared(self):
        abstract = BaseStorage.__abstractmethods__
        assert "save_certificate" in abstract
        assert "delete_certificate_folder" in abstract


# ===========================================================================
# Concrete subclass satisfies the contract
# ===========================================================================


class _ConcreteStorage(BaseStorage):
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
        return Path("/tmp/fake.pem"), "fake-uuid"

    def delete_certificate_folder(self, uuid_str, cert_path=None):
        return True


class TestConcreteStorageSubclass:
    def test_can_instantiate(self):
        s = _ConcreteStorage()
        assert isinstance(s, BaseStorage)

    def test_save_certificate_returns_tuple(self):
        s = _ConcreteStorage()
        result = s.save_certificate(MagicMock(), "test")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_delete_certificate_folder_returns_bool(self):
        s = _ConcreteStorage()
        assert s.delete_certificate_folder("some-uuid") is True


# ===========================================================================
# Partial implementation raises TypeError
# ===========================================================================


class TestPartialSubclassRaisesTypeError:
    def test_missing_delete_raises(self):
        class _Partial(BaseStorage):
            def save_certificate(self, cert, file_name, **kwargs):
                return Path("/tmp/x"), None

            # delete_certificate_folder intentionally omitted

        with pytest.raises(TypeError):
            _Partial()  # type: ignore

    def test_missing_save_raises(self):
        class _Partial(BaseStorage):
            def delete_certificate_folder(self, uuid_str, cert_path=None):
                return True

            # save_certificate intentionally omitted

        with pytest.raises(TypeError):
            _Partial()  # type: ignore
