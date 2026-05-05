"""
conftest.py — shared fixtures for the tiny_ca test suite.

Placing module-scoped CA crypto fixtures here avoids generating the same
RSA key pair 4+ times across test files.  All fixtures are available to
every test file in the same directory without any explicit import.

Note: the ``run()`` helper is intentionally NOT defined here — pytest does
not export plain functions from conftest, only fixtures.  Each async test
file that needs ``run()`` defines it locally as a one-liner.
"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tiny_ca.ca_factory import CertificateFactory
from tiny_ca.models.certificate import CertificateInfo


# ---------------------------------------------------------------------------
# Module-scoped RSA key and CA certificate (generated once per session)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def ca_key() -> rsa.RSAPrivateKey:
    """2048-bit RSA key — generated once for the whole test session."""
    return rsa.generate_private_key(65537, 2048, default_backend())


@pytest.fixture(scope="session")
def ca_cert(ca_key: rsa.RSAPrivateKey) -> x509.Certificate:
    """Self-signed CA certificate signed with *ca_key*."""
    now = datetime.datetime.now(datetime.UTC)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Corp"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )


@pytest.fixture(scope="session")
def ca_loader(ca_cert, ca_key):
    """Minimal ICALoader stub backed by the session-scoped CA fixtures."""

    class _Loader:
        @property
        def ca_cert(self):
            return ca_cert

        @property
        def ca_key(self):
            return ca_key

        @property
        def base_info(self):
            return CertificateInfo(
                organization="Test Corp",
                organizational_unit=None,
                country="UA",
                state=None,
                locality=None,
            )

    return _Loader()


@pytest.fixture(scope="session")
def factory(ca_loader) -> CertificateFactory:
    """CertificateFactory backed by the session-scoped CA loader."""
    return CertificateFactory(ca_loader)
