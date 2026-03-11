"""
test_local_storage.py

Tests for tiny_ca/storage/local_storage.py:
  - _CertSerializer.serialise  — each crypto type, unsupported type
  - LocalStorage.save_certificate  — happy path, overwrite, FileAlreadyExists,
                                     no-uuid mode, custom cert_path, reuse uuid
  - LocalStorage.delete_certificate_folder — happy path, missing dir, file (not dir),
                                             os error
  - LocalStorage._resolve_output_dir
  - LocalStorage._write_file
"""

from __future__ import annotations

import warnings
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tiny_ca.storage.local_storage import LocalStorage, _CertSerializer
from tiny_ca.exc import FileAlreadyExists


# ---------------------------------------------------------------------------
# _CertSerializer.serialise
# ---------------------------------------------------------------------------


class TestCertSerializer:
    def test_certificate_gives_pem_extension(self, ca_cert):
        data, ext = _CertSerializer.serialise(
            ca_cert,
            encoding=serialization.Encoding.PEM,
            private_format=serialization.PrivateFormat.TraditionalOpenSSL,
            public_format=serialization.PublicFormat.SubjectPublicKeyInfo,
            encryption_algorithm=serialization.NoEncryption(),
        )
        assert ext == ".pem"
        assert data.startswith(b"-----BEGIN CERTIFICATE-----")

    def test_private_key_gives_key_extension(self, ca_private_key):
        data, ext = _CertSerializer.serialise(
            ca_private_key,
            encoding=serialization.Encoding.PEM,
            private_format=serialization.PrivateFormat.TraditionalOpenSSL,
            public_format=serialization.PublicFormat.SubjectPublicKeyInfo,
            encryption_algorithm=serialization.NoEncryption(),
        )
        assert ext == ".key"
        assert b"PRIVATE KEY" in data

    def test_csr_gives_csr_extension(self, mock_ca_loader):
        """Issue a real CSR via the factory and test its serialisation."""
        from tiny_ca.ca_factory.factory import CertificateFactory

        factory = CertificateFactory(ca_loader=mock_ca_loader)
        _, _, csr = factory.issue_certificate(common_name="csr.test")
        data, ext = _CertSerializer.serialise(
            csr,
            encoding=serialization.Encoding.PEM,
            private_format=serialization.PrivateFormat.TraditionalOpenSSL,
            public_format=serialization.PublicFormat.SubjectPublicKeyInfo,
            encryption_algorithm=serialization.NoEncryption(),
        )
        assert ext == ".csr"
        assert b"CERTIFICATE REQUEST" in data

    def test_public_key_gives_pub_extension(self, ca_private_key):
        pub_key = ca_private_key.public_key()
        data, ext = _CertSerializer.serialise(
            pub_key,
            encoding=serialization.Encoding.PEM,
            private_format=serialization.PrivateFormat.TraditionalOpenSSL,
            public_format=serialization.PublicFormat.SubjectPublicKeyInfo,
            encryption_algorithm=serialization.NoEncryption(),
        )
        assert ext == ".pub"
        assert b"PUBLIC KEY" in data

    def test_crl_gives_pem_extension(self, mock_ca_loader):
        from tiny_ca.ca_factory.factory import CertificateFactory

        factory = CertificateFactory(ca_loader=mock_ca_loader)
        crl = factory.build_crl(iter([]))
        data, ext = _CertSerializer.serialise(
            crl,
            encoding=serialization.Encoding.PEM,
            private_format=serialization.PrivateFormat.TraditionalOpenSSL,
            public_format=serialization.PublicFormat.SubjectPublicKeyInfo,
            encryption_algorithm=serialization.NoEncryption(),
        )
        assert ext == ".pem"

    def test_unsupported_type_raises_type_error(self):
        with pytest.raises(TypeError, match="Unsupported"):
            _CertSerializer.serialise(
                "not_a_cert",  # type: ignore[arg-type]
                encoding=serialization.Encoding.PEM,
                private_format=serialization.PrivateFormat.TraditionalOpenSSL,
                public_format=serialization.PublicFormat.SubjectPublicKeyInfo,
                encryption_algorithm=serialization.NoEncryption(),
            )


# ---------------------------------------------------------------------------
# LocalStorage.save_certificate
# ---------------------------------------------------------------------------


class TestLocalStorageSaveCertificate:
    def test_writes_file_to_disk(self, tmp_path, ca_cert):
        storage = LocalStorage(base_folder=tmp_path)
        path, uuid_str = storage.save_certificate(ca_cert, file_name="ca")
        assert path.exists()

    def test_extension_is_pem_for_certificate(self, tmp_path, ca_cert):
        storage = LocalStorage(base_folder=tmp_path)
        path, _ = storage.save_certificate(ca_cert, file_name="cert")
        assert path.suffix == ".pem"

    def test_returns_uuid(self, tmp_path, ca_cert):
        storage = LocalStorage(base_folder=tmp_path)
        _, uuid_str = storage.save_certificate(ca_cert, file_name="cert")
        assert uuid_str is not None
        assert len(uuid_str) == 36  # standard UUID4

    def test_reuses_uuid_when_provided(self, tmp_path, ca_cert, ca_private_key):
        storage = LocalStorage(base_folder=tmp_path)
        _, uuid_str = storage.save_certificate(ca_cert, file_name="cert")
        path2, uuid_str2 = storage.save_certificate(
            ca_private_key, file_name="cert", uuid_str=uuid_str
        )
        assert uuid_str2 == uuid_str
        assert path2.parent.name == uuid_str

    def test_no_uuid_when_is_add_uuid_false(self, tmp_path, ca_cert):
        storage = LocalStorage(base_folder=tmp_path)
        path, uuid_str = storage.save_certificate(
            ca_cert, file_name="crl", is_add_uuid=False
        )
        assert uuid_str is None
        assert path == tmp_path / "crl.pem"

    def test_custom_cert_path(self, tmp_path, ca_cert):
        storage = LocalStorage(base_folder=tmp_path)
        path, _ = storage.save_certificate(
            ca_cert, file_name="cert", cert_path="myservice", is_add_uuid=False
        )
        assert "myservice" in str(path)

    def test_file_already_exists_raises(self, tmp_path, ca_cert):
        storage = LocalStorage(base_folder=tmp_path)
        storage.save_certificate(ca_cert, file_name="dup", is_add_uuid=False)
        with pytest.raises(FileAlreadyExists):
            storage.save_certificate(ca_cert, file_name="dup", is_add_uuid=False)

    def test_overwrite_replaces_existing_file(self, tmp_path, ca_cert):
        storage = LocalStorage(base_folder=tmp_path)
        storage.save_certificate(ca_cert, file_name="over", is_add_uuid=False)
        # Second write with is_overwrite=True must not raise
        path, _ = storage.save_certificate(
            ca_cert, file_name="over", is_add_uuid=False, is_overwrite=True
        )
        assert path.exists()

    def test_file_content_is_valid_pem(self, tmp_path, ca_cert):
        storage = LocalStorage(base_folder=tmp_path)
        path, _ = storage.save_certificate(
            ca_cert, file_name="valid", is_add_uuid=False
        )
        content = path.read_bytes()
        assert content.startswith(b"-----BEGIN CERTIFICATE-----")

    def test_private_key_written_with_key_extension(self, tmp_path, ca_private_key):
        storage = LocalStorage(base_folder=tmp_path)
        path, _ = storage.save_certificate(
            ca_private_key, file_name="mykey", is_add_uuid=False
        )
        assert path.suffix == ".key"

    def test_parent_dirs_created_automatically(self, tmp_path, ca_cert):
        storage = LocalStorage(base_folder=tmp_path)
        path, _ = storage.save_certificate(
            ca_cert,
            file_name="cert",
            cert_path="deep/nested/path",
            is_add_uuid=False,
        )
        assert path.exists()


# ---------------------------------------------------------------------------
# LocalStorage.delete_certificate_folder
# ---------------------------------------------------------------------------


class TestLocalStorageDeleteCertificateFolder:
    def test_deletes_existing_dir(self, tmp_path, ca_cert):
        storage = LocalStorage(base_folder=tmp_path)
        _, uuid_str = storage.save_certificate(ca_cert, file_name="cert")
        result = storage.delete_certificate_folder(uuid_str)
        assert result is True
        assert not (tmp_path / uuid_str).exists()

    def test_returns_true_for_missing_dir(self, tmp_path):
        storage = LocalStorage(base_folder=tmp_path)
        with warnings.catch_warnings(record=True):
            result = storage.delete_certificate_folder("nonexistent-uuid")
        assert result is True

    def test_emits_warning_for_missing_dir(self, tmp_path):
        storage = LocalStorage(base_folder=tmp_path)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            storage.delete_certificate_folder("ghost-uuid")
        assert any("not exist" in str(warning.message) for warning in w)

    def test_returns_true_for_path_that_is_a_file(self, tmp_path):
        # Create a file where a directory would be expected
        fake_uuid = "file-not-dir"
        (tmp_path / fake_uuid).write_text("oops")
        storage = LocalStorage(base_folder=tmp_path)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = storage.delete_certificate_folder(fake_uuid)
        assert result is True
        assert any("not a directory" in str(warning.message) for warning in w)

    def test_returns_false_on_os_error(self, tmp_path, ca_cert):
        storage = LocalStorage(base_folder=tmp_path)
        _, uuid_str = storage.save_certificate(ca_cert, file_name="cert")
        target = tmp_path / uuid_str
        with patch("shutil.rmtree", side_effect=OSError("permission denied")):
            result = storage.delete_certificate_folder(uuid_str)
        assert result is False

    def test_with_cert_path(self, tmp_path, ca_cert):
        storage = LocalStorage(base_folder=tmp_path)
        _, uuid_str = storage.save_certificate(
            ca_cert, file_name="cert", cert_path="subdir"
        )
        result = storage.delete_certificate_folder(uuid_str, cert_path="subdir")
        assert result is True


# ---------------------------------------------------------------------------
# LocalStorage._resolve_output_dir
# ---------------------------------------------------------------------------


class TestResolveOutputDir:
    def test_no_cert_path_no_uuid(self, tmp_path):
        storage = LocalStorage(base_folder=tmp_path)
        directory, uuid_str = storage._resolve_output_dir(
            cert_path=None, uuid_str=None, is_add_uuid=False
        )
        assert directory == tmp_path
        assert uuid_str is None

    def test_with_cert_path(self, tmp_path):
        storage = LocalStorage(base_folder=tmp_path)
        directory, _ = storage._resolve_output_dir(
            cert_path="myservice", uuid_str=None, is_add_uuid=False
        )
        assert directory == tmp_path / "myservice"

    def test_auto_generates_uuid(self, tmp_path):
        storage = LocalStorage(base_folder=tmp_path)
        _, uuid_str = storage._resolve_output_dir(
            cert_path=None, uuid_str=None, is_add_uuid=True
        )
        assert uuid_str is not None

    def test_reuses_provided_uuid(self, tmp_path):
        storage = LocalStorage(base_folder=tmp_path)
        _, uuid_str = storage._resolve_output_dir(
            cert_path=None, uuid_str="my-fixed-uuid", is_add_uuid=True
        )
        assert uuid_str == "my-fixed-uuid"
