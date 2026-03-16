"""
Tests for tiny_ca/storage/async_local_storage.py  (AsyncLocalStorage)

Coverage target: 100 %

Run with:
    pytest test_async_local_storage.py -v --cov=tiny_ca.storage.async_local_storage --cov-report=term-missing

Requires: aiofiles  (pip install aiofiles)
"""

from __future__ import annotations

import asyncio
import datetime
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tiny_ca.exc import FileAlreadyExists
from tiny_ca.storage.async_local_storage import AsyncLocalStorage


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(65537, 2048, default_backend())


@pytest.fixture(scope="module")
def ca_cert(rsa_key: rsa.RSAPrivateKey) -> x509.Certificate:
    now = datetime.datetime.now(datetime.UTC)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "async.ca")])
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
def crl(ca_cert, rsa_key) -> x509.CertificateRevocationList:
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
        .sign(rsa_key, hashes.SHA256(), default_backend())
    )


@pytest.fixture(scope="module")
def csr(rsa_key) -> x509.CertificateSigningRequest:
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "async.svc")]))
        .sign(rsa_key, hashes.SHA256(), default_backend())
    )


@pytest.fixture
def storage(tmp_path: Path) -> AsyncLocalStorage:
    return AsyncLocalStorage(base_folder=tmp_path)


# ===========================================================================
# AsyncLocalStorage._write_file
# ===========================================================================


class TestAsyncWriteFile:
    def test_writes_bytes_to_disk(self, storage, tmp_path):
        target = tmp_path / "sub" / "test.pem"
        run(storage._write_file(path=target, data=b"hello async", is_overwrite=False))
        assert target.read_bytes() == b"hello async"

    def test_creates_parent_directories(self, storage, tmp_path):
        target = tmp_path / "a" / "b" / "c" / "file.pem"
        run(storage._write_file(path=target, data=b"data", is_overwrite=False))
        assert target.exists()

    def test_raises_if_exists_and_no_overwrite(self, storage, tmp_path):
        target = tmp_path / "existing.pem"
        target.write_bytes(b"old")
        with pytest.raises(FileAlreadyExists):
            run(storage._write_file(path=target, data=b"new", is_overwrite=False))

    def test_overwrites_when_flag_is_true(self, storage, tmp_path):
        target = tmp_path / "overwrite.pem"
        target.write_bytes(b"old")
        run(storage._write_file(path=target, data=b"new", is_overwrite=True))
        assert target.read_bytes() == b"new"


# ===========================================================================
# AsyncLocalStorage.save_certificate
# ===========================================================================


class TestAsyncSaveCertificate:
    def test_saves_certificate(self, storage, ca_cert):
        path, uuid = run(storage.save_certificate(ca_cert, "cert"))
        assert path.exists()
        assert path.suffix == ".pem"
        assert uuid is not None

    def test_saves_private_key(self, storage, rsa_key):
        path, uuid = run(storage.save_certificate(rsa_key, "key"))
        assert path.suffix == ".key"
        assert path.exists()

    def test_saves_csr(self, storage, csr):
        path, _ = run(storage.save_certificate(csr, "csr"))
        assert path.suffix == ".csr"
        assert path.exists()

    def test_saves_crl_without_uuid(self, storage, crl):
        path, uuid = run(storage.save_certificate(crl, "crl", is_add_uuid=False))
        assert path.suffix == ".pem"
        assert uuid is None

    def test_saves_public_key(self, storage, rsa_key):
        pub = rsa_key.public_key()
        path, _ = run(storage.save_certificate(pub, "pub"))
        assert path.suffix == ".pub"

    def test_cert_path_subdir_used(self, storage, ca_cert, tmp_path):
        path, _ = run(storage.save_certificate(ca_cert, "svc", cert_path="services"))
        assert "services" in str(path)

    def test_uuid_reused_across_calls(self, storage, ca_cert, rsa_key):
        _, uuid = run(storage.save_certificate(ca_cert, "cert2"))
        path2, uuid2 = run(storage.save_certificate(rsa_key, "key2", uuid_str=uuid))
        assert uuid2 == uuid
        assert path2.parent.name == uuid

    def test_raises_on_duplicate_file(self, storage, ca_cert):
        _, uuid = run(storage.save_certificate(ca_cert, "dup"))
        with pytest.raises(FileAlreadyExists):
            run(storage.save_certificate(ca_cert, "dup", uuid_str=uuid))

    def test_overwrite_succeeds(self, storage, ca_cert):
        _, uuid = run(storage.save_certificate(ca_cert, "ow"))
        path, _ = run(
            storage.save_certificate(ca_cert, "ow", uuid_str=uuid, is_overwrite=True)
        )
        assert path.exists()

    def test_encoding_override(self, storage, ca_cert):
        path, _ = run(
            storage.save_certificate(
                ca_cert, "der_cert", encoding=serialization.Encoding.DER
            )
        )
        assert path.read_bytes()[0] == 0x30  # DER ASN.1 sequence tag

    def test_custom_private_format(self, storage, rsa_key):
        path, _ = run(
            storage.save_certificate(
                rsa_key, "pkcs8key", private_format=serialization.PrivateFormat.PKCS8
            )
        )
        assert path.exists()

    def test_custom_public_format(self, storage, rsa_key):
        pub = rsa_key.public_key()
        path, _ = run(
            storage.save_certificate(
                pub,
                "pubkey",
                public_format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        assert path.exists()

    def test_encryption_algorithm_override(self, storage, rsa_key):
        path, _ = run(
            storage.save_certificate(
                rsa_key,
                "enckey",
                encryption_algorithm=serialization.BestAvailableEncryption(b"pw"),
            )
        )
        data = path.read_bytes()
        assert b"ENCRYPTED" in data or b"BEGIN" in data

    def test_unsupported_type_raises_type_error(self, storage):
        with pytest.raises(TypeError):
            run(storage.save_certificate("not-a-cert", "bad"))  # type: ignore


# ===========================================================================
# AsyncLocalStorage.delete_certificate_folder
# ===========================================================================


class TestAsyncDeleteCertificateFolder:
    def test_deletes_existing_directory(self, storage, tmp_path):
        folder = tmp_path / "uuid-del"
        folder.mkdir()
        (folder / "cert.pem").write_bytes(b"data")
        result = run(storage.delete_certificate_folder("uuid-del"))
        assert result is True
        assert not folder.exists()

    def test_returns_true_when_not_exists(self, storage):
        with pytest.warns(UserWarning, match="does not exist"):
            result = run(storage.delete_certificate_folder("nonexistent-uuid"))
        assert result is True

    def test_returns_true_when_not_a_directory(self, storage, tmp_path):
        file_path = tmp_path / "uuid-file"
        file_path.write_bytes(b"I am a file")
        with pytest.warns(UserWarning, match="not a directory"):
            result = run(storage.delete_certificate_folder("uuid-file"))
        assert result is True

    def test_cert_path_used_in_resolution(self, storage, tmp_path):
        sub = tmp_path / "mypath" / "uuid-sub"
        sub.mkdir(parents=True)
        result = run(storage.delete_certificate_folder("uuid-sub", cert_path="mypath"))
        assert result is True
        assert not sub.exists()

    def test_returns_false_on_os_error(self, storage, tmp_path):
        folder = tmp_path / "uuid-oserr"
        folder.mkdir()
        with patch("shutil.rmtree", side_effect=OSError("permission denied")):
            result = run(storage.delete_certificate_folder("uuid-oserr"))
        assert result is False

    def test_no_cert_path_resolves_under_base(self, storage, tmp_path):
        folder = tmp_path / "direct-uuid"
        folder.mkdir()
        result = run(storage.delete_certificate_folder("direct-uuid", cert_path=None))
        assert result is True
        assert not folder.exists()
