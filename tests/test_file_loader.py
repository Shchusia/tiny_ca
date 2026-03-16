"""
Tests for tiny_ca/utils/file_loader.py  (ICALoader Protocol + CAFileLoader)

Coverage target: 100 %

Run with:
    pytest test_file_loader.py -v --cov=tiny_ca.utils.file_loader --cov-report=term-missing
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import UTC, datetime, timedelta

from tiny_ca import CAFileLoader, ICALoader
from tiny_ca.exc import ErrorLoadCert, IsNotFile, NotExistCertFile, WrongType
from tiny_ca.models.certtificate import CertificateInfo


# ---------------------------------------------------------------------------
# Fixtures: generate a real in-memory CA cert + key, write to tmp PEM files
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ca_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )


@pytest.fixture(scope="module")
def ca_cert(ca_key: rsa.RSAPrivateKey) -> x509.Certificate:
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Dev"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Kyiv Oblast"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Kyiv"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
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
def pem_files(ca_cert: x509.Certificate, ca_key: rsa.RSAPrivateKey):
    """Write cert and key to temporary .pem files; yield paths; clean up."""
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
def pem_files_encrypted(ca_cert: x509.Certificate, ca_key: rsa.RSAPrivateKey):
    """Key PEM encrypted with a password."""
    password = b"s3cret"
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


# ===========================================================================
# ICALoader Protocol
# ===========================================================================


class TestICALoaderProtocol:
    def test_satisfying_class_passes_isinstance(self):
        class FakeLoader:
            @property
            def ca_cert(self) -> x509.Certificate:
                return MagicMock(spec=x509.Certificate)

            @property
            def ca_key(self) -> rsa.RSAPrivateKey:
                return MagicMock(spec=rsa.RSAPrivateKey)

            @property
            def base_info(self) -> CertificateInfo:
                return CertificateInfo(
                    organization=None,
                    organizational_unit=None,
                    country=None,
                    state=None,
                    locality=None,
                )

        assert isinstance(FakeLoader(), ICALoader)

    def test_missing_property_fails_isinstance(self):
        class Incomplete:
            @property
            def ca_cert(self): ...

            # missing ca_key and base_info

        assert not isinstance(Incomplete(), ICALoader)


# ===========================================================================
# CAFileLoader._validate_file (static)
# ===========================================================================


class TestValidateFile:
    def test_valid_file_returns_path(self, pem_files):
        cert_path, _ = pem_files
        result = CAFileLoader._validate_file(cert_path)
        assert result == cert_path

    def test_non_existent_raises_not_exist(self, tmp_path):
        missing = tmp_path / "nope.pem"
        with pytest.raises(NotExistCertFile):
            CAFileLoader._validate_file(missing)

    def test_directory_raises_is_not_file(self, tmp_path):
        with pytest.raises(IsNotFile):
            CAFileLoader._validate_file(tmp_path)

    def test_wrong_extension_raises_wrong_type(self, tmp_path):
        bad = tmp_path / "cert.txt"
        bad.write_text("data")
        with pytest.raises(WrongType):
            CAFileLoader._validate_file(bad)


# ===========================================================================
# CAFileLoader.__init__ / construction
# ===========================================================================


class TestCAFileLoaderInit:
    def test_successful_load(self, pem_files, ca_cert, ca_key):
        cert_path, key_path = pem_files
        loader = CAFileLoader(cert_path, key_path)
        assert isinstance(loader.ca_cert, x509.Certificate)
        assert isinstance(loader.ca_key, rsa.RSAPrivateKey)

    def test_base_info_populated(self, pem_files):
        cert_path, key_path = pem_files
        loader = CAFileLoader(cert_path, key_path)
        info = loader.base_info
        assert info.organization == "Test Org"
        assert info.country == "UA"
        assert info.state == "Kyiv Oblast"
        assert info.locality == "Kyiv"
        assert info.organizational_unit == "Dev"

    def test_str_password_is_accepted(self, pem_files_encrypted):
        cert_path, key_path, password = pem_files_encrypted
        loader = CAFileLoader(cert_path, key_path, ca_key_password=password.decode())
        assert loader.ca_key is not None

    def test_bytes_password_is_accepted(self, pem_files_encrypted):
        cert_path, key_path, password = pem_files_encrypted
        loader = CAFileLoader(cert_path, key_path, ca_key_password=password)
        assert loader.ca_key is not None

    def test_accepts_string_paths(self, pem_files):
        cert_path, key_path = pem_files
        loader = CAFileLoader(str(cert_path), str(key_path))
        assert loader.ca_cert is not None

    def test_custom_logger_is_used(self, pem_files):
        import logging

        cert_path, key_path = pem_files
        custom_logger = logging.getLogger("custom_test_logger")
        loader = CAFileLoader(cert_path, key_path, logger=custom_logger)
        assert loader._logger is custom_logger

    def test_default_logger_when_none(self, pem_files):
        from tiny_ca.settings import DEFAULT_LOGGER

        cert_path, key_path = pem_files
        loader = CAFileLoader(cert_path, key_path, logger=None)
        assert loader._logger is DEFAULT_LOGGER


# ===========================================================================
# CAFileLoader._load  —  error paths
# ===========================================================================


class TestCAFileLoaderLoadErrors:
    def test_corrupt_cert_raises_error_load_cert(self, tmp_path):
        """Covers lines 249-250: except branch for cert loading."""
        cert_file = tmp_path / "bad_cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_bytes(b"not a valid pem")
        from cryptography.hazmat.primitives import serialization as ser

        key = rsa.generate_private_key(65537, 2048, default_backend())
        key_file.write_bytes(
            key.private_bytes(
                ser.Encoding.PEM,
                ser.PrivateFormat.TraditionalOpenSSL,
                ser.NoEncryption(),
            )
        )
        with pytest.raises(ErrorLoadCert):
            CAFileLoader(ca_cert_path=cert_file, ca_key_path=key_file)

    def test_corrupt_key_raises_error_load_cert(self, tmp_path, ca_cert):
        """Covers lines 257-258: except branch for key loading."""
        cert_file = tmp_path / "ca.pem"
        key_file = tmp_path / "bad_key.pem"
        cert_file.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(b"not a valid key pem")
        with pytest.raises(ErrorLoadCert):
            CAFileLoader(ca_cert_path=cert_file, ca_key_path=key_file)

    def test_non_rsa_key_raises_type_error(self, tmp_path, ca_cert):
        """Covers line 262: isinstance check for non-RSA key."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization as ser

        ec_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        cert_file = tmp_path / "ca.pem"
        key_file = tmp_path / "ec_key.pem"
        cert_file.write_bytes(ca_cert.public_bytes(ser.Encoding.PEM))
        key_file.write_bytes(
            ec_key.private_bytes(
                ser.Encoding.PEM,
                ser.PrivateFormat.TraditionalOpenSSL,
                ser.NoEncryption(),
            )
        )
        with pytest.raises(TypeError, match="RSA"):
            CAFileLoader(ca_cert_path=cert_file, ca_key_path=key_file)


# ===========================================================================
# CAFileLoader._extract_info  — certificate with absent OIDs
# ===========================================================================


class TestExtractInfoMissingAttributes:
    def test_missing_oids_stored_as_none(self, tmp_path):
        """A cert with only CN should yield None for all other info fields."""
        key = rsa.generate_private_key(65537, 2048, default_backend())
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Minimal CA"),
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
        cert_file = tmp_path / "minimal.pem"
        key_file = tmp_path / "minimal_key.pem"
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        loader = CAFileLoader(cert_file, key_file)
        info = loader.base_info
        assert info.organization is None
        assert info.country is None
        assert info.state is None
        assert info.locality is None
        assert info.organizational_unit is None


# ===========================================================================
# Properties re-check (for completeness)
# ===========================================================================


class TestProperties:
    def test_ca_cert_property(self, pem_files):
        cert_path, key_path = pem_files
        loader = CAFileLoader(cert_path, key_path)
        assert loader.ca_cert is loader._ca_cert

    def test_ca_key_property(self, pem_files):
        cert_path, key_path = pem_files
        loader = CAFileLoader(cert_path, key_path)
        assert loader.ca_key is loader._ca_key

    def test_base_info_property(self, pem_files):
        cert_path, key_path = pem_files
        loader = CAFileLoader(cert_path, key_path)
        assert loader.base_info is loader._base_info
