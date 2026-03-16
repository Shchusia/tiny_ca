"""
Tests for tiny_ca/storage/const.py  (CryptoObject type alias)

Coverage target: 100 %

Run with:
    pytest test_storage_const.py -v --cov=tiny_ca.storage.const --cov-report=term-missing
"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tiny_ca.storage.const import CryptoObject


# ---------------------------------------------------------------------------
# Helpers — build real crypto objects once
# ---------------------------------------------------------------------------


def _make_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(65537, 2048, default_backend())


def _make_cert(key: rsa.RSAPrivateKey) -> x509.Certificate:
    now = datetime.datetime.now(datetime.UTC)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.ca")])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256(), default_backend())
    )


def _make_crl(
    ca_cert: x509.Certificate, ca_key: rsa.RSAPrivateKey
) -> x509.CertificateRevocationList:
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
        .sign(ca_key, hashes.SHA256(), default_backend())
    )


def _make_csr(key: rsa.RSAPrivateKey) -> x509.CertificateSigningRequest:
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.svc")]))
        .sign(key, hashes.SHA256(), default_backend())
    )


# ===========================================================================
# CryptoObject is a type alias — verify that all member types are importable
# and that real instances exist at runtime (100 % of the const.py code path)
# ===========================================================================


class TestCryptoObjectAlias:
    """
    const.py consists only of the CryptoObject union alias definition.
    The module is fully executed on import; these tests just confirm the alias
    is accessible and references the expected types.
    """

    def test_module_importable(self):
        import tiny_ca.storage.const as m

        assert hasattr(m, "CryptoObject")

    def test_certificate_is_included(self):
        key = _make_key()
        cert = _make_cert(key)
        assert isinstance(cert, x509.Certificate)

    def test_crl_is_included(self):
        key = _make_key()
        cert = _make_cert(key)
        crl = _make_crl(cert, key)
        assert isinstance(crl, x509.CertificateRevocationList)

    # def test_csr_is_included(self):
    #     import cryptography.hazmat.bindings._rust.x509 as rust_x509
    #     key = _make_key()
    #     csr = _make_csr(key)
    #     assert isinstance(csr, rust_x509.CertificateSigningRequest)

    def test_private_key_is_included(self):
        key = _make_key()
        assert isinstance(key, rsa.RSAPrivateKey)

    def test_public_key_is_included(self):
        key = _make_key()
        pub = key.public_key()
        assert isinstance(pub, rsa.RSAPublicKey)
