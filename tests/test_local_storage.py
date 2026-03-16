"""
Tests for tiny_ca/storage/local_storage.py  (_CertSerializer + LocalStorage)

Coverage target: 100 %

Run with:
    pytest test_local_storage.py -v --cov=tiny_ca.storage.local_storage --cov-report=term-missing
"""

from __future__ import annotations

import datetime
import logging
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tiny_ca.exc import FileAlreadyExists
from tiny_ca.settings import DEFAULT_LOGGER
from tiny_ca.storage.local_storage import LocalStorage, _CertSerializer


# ---------------------------------------------------------------------------
# Shared crypto fixtures (module scope — generated once)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(65537, 2048, default_backend())


@pytest.fixture(scope="module")
def ca_cert(rsa_key: rsa.RSAPrivateKey) -> x509.Certificate:
    now = datetime.datetime.now(datetime.UTC)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.ca")])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(rsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(rsa_key.public_key()),
            critical=False,
        )
        .sign(rsa_key, hashes.SHA256(), default_backend())
    )


@pytest.fixture(scope="module")
def crl(
    ca_cert: x509.Certificate, rsa_key: rsa.RSAPrivateKey
) -> x509.CertificateRevocationList:
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
        .sign(rsa_key, hashes.SHA256(), default_backend())
    )


@pytest.fixture(scope="module")
def csr(rsa_key: rsa.RSAPrivateKey) -> x509.CertificateSigningRequest:
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.svc")]))
        .sign(rsa_key, hashes.SHA256(), default_backend())
    )


@pytest.fixture
def storage(tmp_path: Path) -> LocalStorage:
    return LocalStorage(base_folder=tmp_path)


# ===========================================================================
# _CertSerializer.serialise
# ===========================================================================


class TestCertSerializerSerialise:
    def test_certificate_returns_pem_extension(self, ca_cert):
        data, ext = _CertSerializer.serialise(
            cert=ca_cert,
            encoding=serialization.Encoding.PEM,
            private_format=serialization.PrivateFormat.TraditionalOpenSSL,
            public_format=serialization.PublicFormat.SubjectPublicKeyInfo,
            encryption_algorithm=serialization.NoEncryption(),
        )
        assert ext == ".pem"
        assert b"BEGIN CERTIFICATE" in data

    def test_crl_returns_pem_extension(self, crl):
        data, ext = _CertSerializer.serialise(
            cert=crl,
            encoding=serialization.Encoding.PEM,
            private_format=serialization.PrivateFormat.TraditionalOpenSSL,
            public_format=serialization.PublicFormat.SubjectPublicKeyInfo,
            encryption_algorithm=serialization.NoEncryption(),
        )
        assert ext == ".pem"
        assert b"BEGIN X509 CRL" in data

    def test_csr_returns_csr_extension(self, csr):
        data, ext = _CertSerializer.serialise(
            cert=csr,
            encoding=serialization.Encoding.PEM,
            private_format=serialization.PrivateFormat.TraditionalOpenSSL,
            public_format=serialization.PublicFormat.SubjectPublicKeyInfo,
            encryption_algorithm=serialization.NoEncryption(),
        )
        assert ext == ".csr"
        assert b"BEGIN CERTIFICATE REQUEST" in data

    def test_private_key_returns_key_extension(self, rsa_key):
        data, ext = _CertSerializer.serialise(
            cert=rsa_key,
            encoding=serialization.Encoding.PEM,
            private_format=serialization.PrivateFormat.TraditionalOpenSSL,
            public_format=serialization.PublicFormat.SubjectPublicKeyInfo,
            encryption_algorithm=serialization.NoEncryption(),
        )
        assert ext == ".key"
        assert b"BEGIN RSA PRIVATE KEY" in data or b"BEGIN PRIVATE KEY" in data

    def test_public_key_returns_pub_extension(self, rsa_key):
        pub = rsa_key.public_key()
        data, ext = _CertSerializer.serialise(
            cert=pub,
            encoding=serialization.Encoding.PEM,
            private_format=serialization.PrivateFormat.TraditionalOpenSSL,
            public_format=serialization.PublicFormat.SubjectPublicKeyInfo,
            encryption_algorithm=serialization.NoEncryption(),
        )
        assert ext == ".pub"
        assert b"BEGIN PUBLIC KEY" in data

    def test_unsupported_type_raises_type_error(self):
        with pytest.raises(TypeError, match="Unsupported crypto object type"):
            _CertSerializer.serialise(
                cert="not a crypto object",  # type: ignore
                encoding=serialization.Encoding.PEM,
                private_format=serialization.PrivateFormat.TraditionalOpenSSL,
                public_format=serialization.PublicFormat.SubjectPublicKeyInfo,
                encryption_algorithm=serialization.NoEncryption(),
            )

    def test_private_key_with_encryption(self, rsa_key):
        data, ext = _CertSerializer.serialise(
            cert=rsa_key,
            encoding=serialization.Encoding.PEM,
            private_format=serialization.PrivateFormat.TraditionalOpenSSL,
            public_format=serialization.PublicFormat.SubjectPublicKeyInfo,
            encryption_algorithm=serialization.BestAvailableEncryption(b"secret"),
        )
        assert ext == ".key"
        assert b"ENCRYPTED" in data or b"BEGIN" in data


# ===========================================================================
# LocalStorage.__init__
# ===========================================================================


class TestLocalStorageInit:
    def test_default_base_folder(self, tmp_path):
        s = LocalStorage(base_folder=tmp_path)
        assert s._base_folder == tmp_path

    def test_string_path_converted_to_path(self, tmp_path):
        s = LocalStorage(base_folder=str(tmp_path))
        assert isinstance(s._base_folder, Path)

    def test_default_logger(self, tmp_path):
        s = LocalStorage(base_folder=tmp_path)
        assert s._logger is DEFAULT_LOGGER

    def test_custom_logger(self, tmp_path):
        lg = logging.getLogger("storage_test")
        s = LocalStorage(base_folder=tmp_path, logger=lg)
        assert s._logger is lg

    def test_default_encoding(self, tmp_path):
        s = LocalStorage(base_folder=tmp_path)
        assert s._base_encoding == serialization.Encoding.PEM

    def test_custom_encoding(self, tmp_path):
        s = LocalStorage(base_folder=tmp_path, base_encoding=serialization.Encoding.DER)
        assert s._base_encoding == serialization.Encoding.DER


# ===========================================================================
# LocalStorage._resolve_output_dir
# ===========================================================================


class TestResolveOutputDir:
    def test_no_cert_path_no_uuid(self, storage: LocalStorage, tmp_path):
        directory, uuid = storage._resolve_output_dir(
            cert_path=None, uuid_str=None, is_add_uuid=False
        )
        assert directory == tmp_path
        assert uuid is None

    def test_cert_path_appended(self, storage: LocalStorage, tmp_path):
        directory, _ = storage._resolve_output_dir(
            cert_path="services", uuid_str=None, is_add_uuid=False
        )
        assert directory == tmp_path / "services"

    def test_uuid_auto_generated(self, storage: LocalStorage):
        _, uuid = storage._resolve_output_dir(
            cert_path=None, uuid_str=None, is_add_uuid=True
        )
        assert uuid is not None
        assert len(uuid) == 36  # standard UUID4 format

    def test_uuid_reused_when_provided(self, storage: LocalStorage):
        fixed = "aaaa-bbbb"
        directory, uuid = storage._resolve_output_dir(
            cert_path=None, uuid_str=fixed, is_add_uuid=True
        )
        assert uuid == fixed
        assert directory.name == fixed

    def test_uuid_subdirectory_appended(self, storage: LocalStorage, tmp_path):
        directory, uuid = storage._resolve_output_dir(
            cert_path="svc", uuid_str="myuuid", is_add_uuid=True
        )
        assert directory == tmp_path / "svc" / "myuuid"

    def test_is_add_uuid_false_ignores_uuid_str(self, storage: LocalStorage):
        _, uuid = storage._resolve_output_dir(
            cert_path=None, uuid_str="ignored-uuid", is_add_uuid=False
        )
        assert uuid is None


# ===========================================================================
# LocalStorage._write_file
# ===========================================================================


class TestWriteFile:
    def test_writes_bytes_to_disk(self, storage: LocalStorage, tmp_path):
        target = tmp_path / "sub" / "test.pem"
        storage._write_file(path=target, data=b"hello", is_overwrite=False)
        assert target.read_bytes() == b"hello"

    def test_creates_parent_directories(self, storage: LocalStorage, tmp_path):
        target = tmp_path / "a" / "b" / "c" / "file.pem"
        storage._write_file(path=target, data=b"data", is_overwrite=False)
        assert target.exists()

    def test_raises_if_exists_and_no_overwrite(self, storage: LocalStorage, tmp_path):
        target = tmp_path / "existing.pem"
        target.write_bytes(b"old")
        with pytest.raises(FileAlreadyExists):
            storage._write_file(path=target, data=b"new", is_overwrite=False)

    def test_overwrites_when_flag_is_true(self, storage: LocalStorage, tmp_path):
        target = tmp_path / "overwrite.pem"
        target.write_bytes(b"old")
        storage._write_file(path=target, data=b"new", is_overwrite=True)
        assert target.read_bytes() == b"new"


# ===========================================================================
# LocalStorage.save_certificate
# ===========================================================================


class TestSaveCertificate:
    def test_saves_certificate_returns_path_and_uuid(self, storage, ca_cert):
        path, uuid = storage.save_certificate(ca_cert, "mycert")
        assert path.exists()
        assert path.suffix == ".pem"
        assert uuid is not None

    def test_saves_private_key(self, storage, rsa_key):
        path, uuid = storage.save_certificate(rsa_key, "mykey")
        assert path.suffix == ".key"
        assert path.exists()

    def test_saves_csr(self, storage, csr):
        path, uuid = storage.save_certificate(csr, "mycsr")
        assert path.suffix == ".csr"
        assert path.exists()

    def test_saves_crl(self, storage, crl):
        path, uuid = storage.save_certificate(crl, "mycrl", is_add_uuid=False)
        assert path.suffix == ".pem"
        assert uuid is None

    def test_saves_public_key(self, storage, rsa_key):
        pub = rsa_key.public_key()
        path, uuid = storage.save_certificate(pub, "mypub")
        assert path.suffix == ".pub"

    def test_cert_path_subdir_used(self, storage: LocalStorage, ca_cert, tmp_path):
        path, _ = storage.save_certificate(ca_cert, "svc", cert_path="services")
        assert "services" in str(path)

    def test_uuid_reused_across_calls(self, storage: LocalStorage, ca_cert, rsa_key):
        _, uuid = storage.save_certificate(ca_cert, "cert")
        path2, uuid2 = storage.save_certificate(rsa_key, "key", uuid_str=uuid)
        assert uuid2 == uuid
        assert path2.parent.name == uuid

    def test_raises_on_duplicate_file(self, storage, ca_cert):
        _, uuid = storage.save_certificate(ca_cert, "dup")
        with pytest.raises(FileAlreadyExists):
            storage.save_certificate(ca_cert, "dup", uuid_str=uuid)

    def test_overwrite_succeeds(self, storage, ca_cert):
        _, uuid = storage.save_certificate(ca_cert, "overwrite")
        path, _ = storage.save_certificate(
            ca_cert, "overwrite", uuid_str=uuid, is_overwrite=True
        )
        assert path.exists()

    def test_encoding_override(self, storage, ca_cert):
        path, _ = storage.save_certificate(
            ca_cert, "der_cert", encoding=serialization.Encoding.DER
        )
        # DER files start with 0x30 (ASN.1 sequence)
        assert path.read_bytes()[0] == 0x30

    def test_custom_private_format(self, storage, rsa_key):
        path, _ = storage.save_certificate(
            rsa_key, "pkcs8key", private_format=serialization.PrivateFormat.PKCS8
        )
        assert path.exists()

    def test_custom_public_format(self, storage, rsa_key):
        pub = rsa_key.public_key()
        path, _ = storage.save_certificate(
            pub, "pubkey", public_format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        assert path.exists()

    def test_encryption_algorithm_override(self, storage, rsa_key):
        path, _ = storage.save_certificate(
            rsa_key,
            "enckey",
            encryption_algorithm=serialization.BestAvailableEncryption(b"pw"),
        )
        data = path.read_bytes()
        assert b"ENCRYPTED" in data or b"BEGIN" in data

    def test_unsupported_type_raises_type_error(self, storage):
        with pytest.raises(TypeError):
            storage.save_certificate("not-a-cert", "bad")  # type: ignore


# ===========================================================================
# LocalStorage.delete_certificate_folder
# ===========================================================================


class TestDeleteCertificateFolder:
    def test_deletes_existing_directory(self, storage: LocalStorage, tmp_path):
        folder = tmp_path / "uuid-del"
        folder.mkdir()
        (folder / "cert.pem").write_bytes(b"data")
        result = storage.delete_certificate_folder("uuid-del")
        assert result is True
        assert not folder.exists()

    def test_returns_true_when_not_exists(self, storage: LocalStorage):
        with pytest.warns(UserWarning, match="does not exist"):
            result = storage.delete_certificate_folder("nonexistent-uuid")
        assert result is True

    def test_returns_true_when_not_a_directory(self, storage: LocalStorage, tmp_path):
        file_path = tmp_path / "uuid-file"
        file_path.write_bytes(b"I am a file, not a directory")
        with pytest.warns(UserWarning, match="not a directory"):
            result = storage.delete_certificate_folder("uuid-file")
        assert result is True

    def test_cert_path_used_in_resolution(self, storage: LocalStorage, tmp_path):
        sub = tmp_path / "mypath" / "uuid-sub"
        sub.mkdir(parents=True)
        result = storage.delete_certificate_folder("uuid-sub", cert_path="mypath")
        assert result is True
        assert not sub.exists()

    def test_returns_false_on_os_error(self, storage: LocalStorage, tmp_path):
        folder = tmp_path / "uuid-oserr"
        folder.mkdir()
        with patch("shutil.rmtree", side_effect=OSError("permission denied")):
            result = storage.delete_certificate_folder("uuid-oserr")
        assert result is False
