"""
Tests for tiny_ca/utils/afile_loader.py  (AsyncCAFileLoader)

Coverage target: 100 %

Run with:
    pytest test_afile_loader.py -v --cov=tiny_ca.utils.afile_loader --cov-report=term-missing
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import UTC, datetime, timedelta

from tiny_ca.ca_factory.utils.afile_loader import AsyncCAFileLoader
from tiny_ca.exc import ErrorLoadCert


# ---------------------------------------------------------------------------
# Module-scoped CA fixtures (generated once for the whole test session)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ca_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(65537, 2048, default_backend())


@pytest.fixture(scope="module")
def ca_cert(ca_key: rsa.RSAPrivateKey) -> x509.Certificate:
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Async Org"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "AsyncUnit"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "AsyncState"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "AsyncCity"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Async CA"),
        ]
    )
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )


@pytest.fixture(scope="module")
def pem_dir(ca_cert: x509.Certificate, ca_key: rsa.RSAPrivateKey):
    """Temporary directory with unencrypted cert + key PEM files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path = Path(tmpdir) / "ca.pem"
        key_path = Path(tmpdir) / "ca_key.pem"
        cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        yield cert_path, key_path


@pytest.fixture(scope="module")
def pem_dir_encrypted(ca_cert: x509.Certificate, ca_key: rsa.RSAPrivateKey):
    """Temporary directory with password-protected key PEM."""
    password = b"async_secret"
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path = Path(tmpdir) / "ca.pem"
        key_path = Path(tmpdir) / "ca_key.pem"
        cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.BestAvailableEncryption(password),
            )
        )
        yield cert_path, key_path, password


# ---------------------------------------------------------------------------
# Helper: run coroutine synchronously
# ---------------------------------------------------------------------------


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ===========================================================================
# __init__  —  synchronous validation happens before load()
# ===========================================================================


class TestInit:
    def test_wrong_extension_raises_at_init(self, tmp_path):
        bad = tmp_path / "cert.txt"
        bad.write_text("x")
        from tiny_ca.exc import WrongType

        with pytest.raises(WrongType):
            AsyncCAFileLoader(bad, bad)

    def test_missing_file_raises_at_init(self, tmp_path):
        from tiny_ca.exc import NotExistCertFile

        missing = tmp_path / "nope.pem"
        pem = tmp_path / "dummy.pem"  # will fail on cert path first
        with pytest.raises(NotExistCertFile):
            AsyncCAFileLoader(missing, pem)

    def test_before_load_ca_cert_raises_runtime(self, pem_dir):
        cert_path, key_path = pem_dir
        loader = AsyncCAFileLoader(cert_path, key_path)
        with pytest.raises(RuntimeError, match="load"):
            _ = loader.ca_cert

    def test_before_load_ca_key_raises_runtime(self, pem_dir):
        cert_path, key_path = pem_dir
        loader = AsyncCAFileLoader(cert_path, key_path)
        with pytest.raises(RuntimeError, match="load"):
            _ = loader.ca_key

    def test_before_load_base_info_raises_runtime(self, pem_dir):
        cert_path, key_path = pem_dir
        loader = AsyncCAFileLoader(cert_path, key_path)
        with pytest.raises(RuntimeError, match="load"):
            _ = loader.base_info

    def test_string_paths_accepted(self, pem_dir):
        cert_path, key_path = pem_dir
        # Should not raise during __init__
        AsyncCAFileLoader(str(cert_path), str(key_path))

    def test_custom_logger_stored(self, pem_dir):
        import logging

        cert_path, key_path = pem_dir
        lg = logging.getLogger("my_test")
        loader = AsyncCAFileLoader(cert_path, key_path, logger=lg)
        assert loader._logger is lg

    def test_default_logger_when_none(self, pem_dir):
        from tiny_ca.settings import DEFAULT_LOGGER

        cert_path, key_path = pem_dir
        loader = AsyncCAFileLoader(cert_path, key_path)
        assert loader._logger is DEFAULT_LOGGER

    def test_password_str_converted_to_bytes(self, pem_dir_encrypted):
        cert_path, key_path, password = pem_dir_encrypted
        loader = AsyncCAFileLoader(
            cert_path, key_path, ca_key_password=password.decode()
        )
        assert loader._password_bytes == password

    def test_password_bytes_kept_as_is(self, pem_dir_encrypted):
        cert_path, key_path, password = pem_dir_encrypted
        loader = AsyncCAFileLoader(cert_path, key_path, ca_key_password=password)
        assert loader._password_bytes == password

    def test_none_password_stays_none(self, pem_dir):
        cert_path, key_path = pem_dir
        loader = AsyncCAFileLoader(cert_path, key_path, ca_key_password=None)
        assert loader._password_bytes is None


# ===========================================================================
# load() — happy paths
# ===========================================================================


class TestLoad:
    def test_load_populates_ca_cert(self, pem_dir):
        cert_path, key_path = pem_dir
        loader = AsyncCAFileLoader(cert_path, key_path)
        run(loader.load())
        assert isinstance(loader.ca_cert, x509.Certificate)

    def test_load_populates_ca_key(self, pem_dir):
        cert_path, key_path = pem_dir
        loader = AsyncCAFileLoader(cert_path, key_path)
        run(loader.load())
        assert isinstance(loader.ca_key, rsa.RSAPrivateKey)

    def test_load_populates_base_info(self, pem_dir):
        cert_path, key_path = pem_dir
        loader = AsyncCAFileLoader(cert_path, key_path)
        run(loader.load())
        info = loader.base_info
        assert info.organization == "Async Org"
        assert info.country == "UA"
        assert info.state == "AsyncState"
        assert info.locality == "AsyncCity"
        assert info.organizational_unit == "AsyncUnit"

    def test_load_with_encrypted_key(self, pem_dir_encrypted):
        cert_path, key_path, password = pem_dir_encrypted
        loader = AsyncCAFileLoader(cert_path, key_path, ca_key_password=password)
        run(loader.load())
        assert isinstance(loader.ca_key, rsa.RSAPrivateKey)

    def test_load_with_str_password(self, pem_dir_encrypted):
        cert_path, key_path, password = pem_dir_encrypted
        loader = AsyncCAFileLoader(
            cert_path, key_path, ca_key_password=password.decode()
        )
        run(loader.load())
        assert loader.ca_cert is not None


# ===========================================================================
# classmethod create()
# ===========================================================================


class TestCreate:
    def test_create_returns_loaded_instance(self, pem_dir):
        cert_path, key_path = pem_dir
        loader = run(AsyncCAFileLoader.create(cert_path, key_path))
        assert isinstance(loader, AsyncCAFileLoader)
        assert isinstance(loader.ca_cert, x509.Certificate)
        assert isinstance(loader.ca_key, rsa.RSAPrivateKey)

    def test_create_with_logger(self, pem_dir):
        import logging

        cert_path, key_path = pem_dir
        lg = logging.getLogger("create_test")
        loader = run(AsyncCAFileLoader.create(cert_path, key_path, logger=lg))
        assert loader._logger is lg

    def test_create_with_password(self, pem_dir_encrypted):
        cert_path, key_path, password = pem_dir_encrypted
        loader = run(
            AsyncCAFileLoader.create(cert_path, key_path, ca_key_password=password)
        )
        assert loader.ca_key is not None


# ===========================================================================
# _load_sync — error paths
# ===========================================================================


class TestLoadSyncErrors:
    def test_corrupt_cert_raises_error_load_cert(self, tmp_path):
        bad_cert = tmp_path / "bad.pem"
        bad_cert.write_bytes(b"not pem")
        key = rsa.generate_private_key(65537, 2048, default_backend())
        key_file = tmp_path / "key.pem"
        key_file.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        loader = AsyncCAFileLoader(bad_cert, key_file)
        with pytest.raises(ErrorLoadCert):
            run(loader.load())

    def test_corrupt_key_raises_error_load_cert(self, tmp_path, ca_cert):
        cert_file = tmp_path / "ca.pem"
        bad_key = tmp_path / "bad.pem"
        cert_file.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        bad_key.write_bytes(b"not a key")
        loader = AsyncCAFileLoader(cert_file, bad_key)
        with pytest.raises(ErrorLoadCert):
            run(loader.load())

    def test_non_rsa_key_raises_type_error(self, tmp_path, ca_cert):
        from cryptography.hazmat.primitives.asymmetric import ec

        ec_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        cert_file = tmp_path / "ca.pem"
        key_file = tmp_path / "ec.pem"
        cert_file.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(
            ec_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        loader = AsyncCAFileLoader(cert_file, key_file)
        with pytest.raises(TypeError, match="RSA"):
            run(loader.load())


# ===========================================================================
# _extract_info — missing Subject OIDs
# ===========================================================================


class TestExtractInfoMissing:
    def test_missing_oids_are_none(self, tmp_path):
        key = rsa.generate_private_key(65537, 2048, default_backend())
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Minimal Async CA"),
            ]
        )
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(key, hashes.SHA256(), default_backend())
        )
        cert_file = tmp_path / "min.pem"
        key_file = tmp_path / "min_k.pem"
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        loader = run(AsyncCAFileLoader.create(cert_file, key_file))
        info = loader.base_info
        assert info.organization is None
        assert info.country is None
        assert info.state is None
        assert info.locality is None
        assert info.organizational_unit is None
