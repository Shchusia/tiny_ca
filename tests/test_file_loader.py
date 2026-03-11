"""
test_file_loader.py

Tests for tiny_ca/ca_factory/utils/file_loader.py:
  - ICALoader Protocol structural checks
  - CAFileLoader._validate_file — exists / is_file / extension
  - CAFileLoader construction   — happy path, str password, bytes password
  - CAFileLoader._extract_info  — OID extraction
  - CAFileLoader properties     — ca_cert, ca_key, base_info
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from cryptography.hazmat.primitives import serialization

from tiny_ca.ca_factory.utils.file_loader import CAFileLoader, ICALoader
from tiny_ca.exc import NotExistCertFile, IsNotFile, WrongType, ErrorLoadCert


# ---------------------------------------------------------------------------
# ICALoader Protocol
# ---------------------------------------------------------------------------


class TestICALoaderProtocol:
    def test_object_without_properties_fails(self):
        assert not isinstance(object(), ICALoader)

    def test_mock_with_required_properties_passes(self):
        loader = MagicMock(spec=["ca_cert", "ca_key", "base_info"])
        # runtime_checkable only checks attribute presence, not type
        type(loader).ca_cert = PropertyMock(return_value=MagicMock())
        type(loader).ca_key = PropertyMock(return_value=MagicMock())
        type(loader).base_info = PropertyMock(return_value=MagicMock())
        assert isinstance(loader, ICALoader)


# ---------------------------------------------------------------------------
# CAFileLoader._validate_file (static method)
# ---------------------------------------------------------------------------


class TestValidateFile:
    def test_valid_pem_file_returns_path(self, tmp_path):
        f = tmp_path / "cert.pem"
        f.write_text("FAKE")
        result = CAFileLoader._validate_file(f)
        assert result == f

    def test_valid_key_file_returns_path(self, tmp_path):
        f = tmp_path / "key.key"
        f.write_text("FAKE")
        result = CAFileLoader._validate_file(f)
        assert result == f

    def test_valid_csr_file_returns_path(self, tmp_path):
        f = tmp_path / "req.csr"
        f.write_text("FAKE")
        result = CAFileLoader._validate_file(f)
        assert result == f

    def test_nonexistent_file_raises_not_exist(self, tmp_path):
        ghost = tmp_path / "ghost.pem"
        with pytest.raises(NotExistCertFile):
            CAFileLoader._validate_file(ghost)

    def test_directory_raises_is_not_file(self, tmp_path):
        d = tmp_path / "subdir"
        d.mkdir()
        # Need .pem suffix on dir name to pass extension check
        pem_dir = tmp_path / "subdir.pem"
        pem_dir.mkdir()
        with pytest.raises(IsNotFile):
            CAFileLoader._validate_file(pem_dir)

    def test_wrong_extension_raises_wrong_type(self, tmp_path):
        f = tmp_path / "cert.der"
        f.write_text("FAKE")
        with pytest.raises(WrongType):
            CAFileLoader._validate_file(f)

    def test_txt_extension_raises_wrong_type(self, tmp_path):
        f = tmp_path / "notes.txt"
        f.write_text("FAKE")
        with pytest.raises(WrongType):
            CAFileLoader._validate_file(f)

    def test_custom_allowed_extensions(self, tmp_path):
        f = tmp_path / "cert.der"
        f.write_text("FAKE")
        result = CAFileLoader._validate_file(f, allowed=(".der",))
        assert result == f


# ---------------------------------------------------------------------------
# CAFileLoader construction — full integration with real PEM files
# ---------------------------------------------------------------------------


class TestCAFileLoaderConstruction:
    def test_loads_successfully(self, pem_dir):
        loader = CAFileLoader(
            ca_cert_path=pem_dir / "ca.pem",
            ca_key_path=pem_dir / "ca.key",
        )
        assert loader.ca_cert is not None
        assert loader.ca_key is not None
        assert loader.base_info is not None

    def test_ca_cert_has_correct_cn(self, pem_dir):
        loader = CAFileLoader(
            ca_cert_path=pem_dir / "ca.pem",
            ca_key_path=pem_dir / "ca.key",
        )
        from cryptography.x509.oid import NameOID

        cn = loader.ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "Test CA"

    def test_base_info_organization(self, pem_dir):
        loader = CAFileLoader(
            ca_cert_path=pem_dir / "ca.pem",
            ca_key_path=pem_dir / "ca.key",
        )
        assert loader.base_info.organization == "Test Org"

    def test_base_info_country(self, pem_dir):
        loader = CAFileLoader(
            ca_cert_path=pem_dir / "ca.pem",
            ca_key_path=pem_dir / "ca.key",
        )
        assert loader.base_info.country == "UA"

    def test_str_password_accepted(self, tmp_path, ca_private_key):
        """A str password is converted to bytes internally."""
        from cryptography.hazmat.primitives import serialization as ser

        password = "secret123"
        # Write key encrypted with the password
        enc_key = tmp_path / "enc.key"
        enc_key.write_bytes(
            ca_private_key.private_bytes(
                encoding=ser.Encoding.PEM,
                format=ser.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=ser.BestAvailableEncryption(password.encode()),
            )
        )
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        import datetime
        from cryptography.x509.oid import NameOID

        # Write cert
        now = datetime.datetime.now(datetime.timezone.utc)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "PWD CA")]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_private_key.public_key())
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(ca_private_key, hashes.SHA256(), default_backend())
        )
        enc_cert = tmp_path / "enc.pem"
        enc_cert.write_bytes(cert.public_bytes(ser.Encoding.PEM))

        loader = CAFileLoader(
            ca_cert_path=enc_cert,
            ca_key_path=enc_key,
            ca_key_password=password,  # str
        )
        assert loader.ca_key is not None

    def test_bytes_password_accepted(self, tmp_path, ca_private_key):
        """Bytes password passes through unchanged."""
        from cryptography.hazmat.primitives import serialization as ser

        password = b"bytesecret"
        enc_key = tmp_path / "enc2.key"
        enc_key.write_bytes(
            ca_private_key.private_bytes(
                encoding=ser.Encoding.PEM,
                format=ser.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=ser.BestAvailableEncryption(password),
            )
        )
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        import datetime
        from cryptography.x509.oid import NameOID

        now = datetime.datetime.now(datetime.timezone.utc)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Bytes CA")]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_private_key.public_key())
            .serial_number(2)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(ca_private_key, hashes.SHA256(), default_backend())
        )
        enc_cert = tmp_path / "enc2.pem"
        enc_cert.write_bytes(cert.public_bytes(ser.Encoding.PEM))
        loader = CAFileLoader(
            ca_cert_path=enc_cert,
            ca_key_path=enc_key,
            ca_key_password=password,
        )
        assert loader.ca_key is not None

    def test_corrupt_cert_raises_error_load_cert(self, tmp_path, pem_dir):
        bad_cert = tmp_path / "bad.pem"
        bad_cert.write_bytes(b"NOT A CERT")
        with pytest.raises(ErrorLoadCert):
            CAFileLoader(
                ca_cert_path=bad_cert,
                ca_key_path=pem_dir / "ca.key",
            )

    def test_corrupt_key_raises_error_load_cert(self, tmp_path, pem_dir):
        bad_key = tmp_path / "bad.key"
        bad_key.write_bytes(b"NOT A KEY")
        with pytest.raises(ErrorLoadCert):
            CAFileLoader(
                ca_cert_path=pem_dir / "ca.pem",
                ca_key_path=bad_key,
            )

    def test_satisfies_ica_loader_protocol(self, pem_dir):
        loader = CAFileLoader(
            ca_cert_path=pem_dir / "ca.pem",
            ca_key_path=pem_dir / "ca.key",
        )
        assert isinstance(loader, ICALoader)
