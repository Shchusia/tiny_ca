"""
conftest.py

Shared pytest fixtures for the tiny_ca test suite.

All expensive objects (CA key pair, signed certificate, CRL) are created once
per test session and reused across all test modules via session-scoped fixtures.
Cheap, mutable objects (mock DB, mock storage) are recreated per test function
so tests remain isolated.
"""

from __future__ import annotations

import datetime
import tempfile
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock, PropertyMock

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID


# ---------------------------------------------------------------------------
# RSA key pair (session scope — expensive to generate)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def ca_private_key() -> rsa.RSAPrivateKey:
    """Generate a 2048-bit RSA private key once per test session."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )


@pytest.fixture(scope="session")
def leaf_private_key() -> rsa.RSAPrivateKey:
    """Generate a second RSA key for leaf certificates."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )


# ---------------------------------------------------------------------------
# Self-signed CA certificate
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def ca_cert(ca_private_key: rsa.RSAPrivateKey) -> x509.Certificate:
    """Build a self-signed CA certificate for use in tests."""
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(0x434100000000000000001234)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256(), default_backend())
    )


@pytest.fixture(scope="session")
def leaf_cert(
    ca_cert: x509.Certificate,
    ca_private_key: rsa.RSAPrivateKey,
    leaf_private_key: rsa.RSAPrivateKey,
) -> x509.Certificate:
    """Build a leaf certificate signed by the test CA."""
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example.com"),
        ]
    )
    ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_private_key.public_key())
        .serial_number(0x535600000000000000005678)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256(), default_backend())
    )


# ---------------------------------------------------------------------------
# PEM files on disk (session-scoped temp dir)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def pem_dir(
    ca_cert: x509.Certificate,
    ca_private_key: rsa.RSAPrivateKey,
) -> Generator[Path, None, None]:
    """Write CA cert and key as PEM files; yield the directory path."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        cert_path = d / "ca.pem"
        key_path = d / "ca.key"

        cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        yield d


# ---------------------------------------------------------------------------
# ICALoader mock (function scope — safe to mutate per test)
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_ca_loader(
    ca_cert: x509.Certificate,
    ca_private_key: rsa.RSAPrivateKey,
) -> MagicMock:
    """
    Return a MagicMock that satisfies the ICALoader Protocol.

    Provides ``ca_cert``, ``ca_key``, and ``base_info`` as properties.
    """
    from tiny_ca.models.certtificate import CertificateInfo

    loader = MagicMock()
    type(loader).ca_cert = PropertyMock(return_value=ca_cert)
    type(loader).ca_key = PropertyMock(return_value=ca_private_key)
    type(loader).base_info = PropertyMock(
        return_value=CertificateInfo(
            organization="Test Org",
            country="UA",
            organizational_unit="IT",
            state=None,
            locality=None,
        )
    )
    return loader


# ---------------------------------------------------------------------------
# Fake DB / Storage (function scope)
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_db() -> MagicMock:
    """Return a MagicMock that mimics BaseDB."""
    db = MagicMock()
    db.get_by_serial.return_value = None
    db.get_by_name.return_value = None
    db.register_cert_in_db.return_value = True
    db.delete_certificate_by_serial.return_value = True
    db.revoke_certificate.return_value = (True, MagicMock(name="OK"))
    db.get_revoked_certificates.return_value = iter([])
    return db


@pytest.fixture()
def mock_storage() -> MagicMock:
    """Return a MagicMock that mimics BaseStorage."""
    storage = MagicMock()
    storage.save_certificate.return_value = (Path("/tmp/cert.pem"), "test-uuid")
    storage.delete_certificate_folder.return_value = True
    return storage
