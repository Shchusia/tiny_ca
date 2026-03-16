"""
Tests for tiny_ca/utils/serial.py  (CertSerialParser)

Coverage target: 100 %

Run with:
    pytest test_serial.py -v --cov=tiny_ca.utils.serial --cov-report=term-missing
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import UTC, datetime, timedelta

from tiny_ca.ca_factory.utils.serial import CertSerialParser
from tiny_ca.const import CertType
from tiny_ca.utils.serial_generator import SerialWithEncoding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cert_with_serial(serial: int) -> MagicMock:
    """Return a minimal mock x509.Certificate with the given serial number."""
    cert = MagicMock(spec=x509.Certificate)
    cert.serial_number = serial
    return cert


def _real_cert(
    name: str = "testservice", cert_type: CertType = CertType.SERVICE
) -> x509.Certificate:
    """Generate a real signed certificate whose serial was created by SerialWithEncoding."""
    key = rsa.generate_private_key(65537, 2048, default_backend())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]
    )
    now = datetime.now(UTC)
    serial = SerialWithEncoding.generate(name=name, serial_type=cert_type)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256(), default_backend())
    )


# ===========================================================================
# CertSerialParser.raw
# ===========================================================================


class TestRaw:
    def test_returns_integer(self):
        cert = _make_cert_with_serial(42)
        assert CertSerialParser.raw(cert) == 42

    def test_returns_plain_int_type(self):
        cert = _make_cert_with_serial(999_999)
        assert type(CertSerialParser.raw(cert)) is int

    def test_large_serial(self):
        big = 2**128 - 1
        cert = _make_cert_with_serial(big)
        assert CertSerialParser.raw(cert) == big

    def test_real_cert_serial(self):
        cert = _real_cert("mysvc")
        raw = CertSerialParser.raw(cert)
        assert raw == cert.serial_number
        assert isinstance(raw, int)


# ===========================================================================
# CertSerialParser.typed
# ===========================================================================


class TestTyped:
    def test_returns_tuple(self):
        cert = _real_cert("nginx", CertType.SERVICE)
        result = CertSerialParser.typed(cert)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_cert_type_is_correct(self):
        cert = _real_cert("nginx", CertType.SERVICE)
        cert_type, _ = CertSerialParser.typed(cert)
        assert cert_type == CertType.SERVICE

    def test_name_prefix_starts_with_name(self):
        cert = _real_cert("nginx", CertType.SERVICE)
        _, name = CertSerialParser.typed(cert)
        # Serial encodes up to 10 chars of the name
        assert "nginx".startswith(name) or name.startswith("nginx")

    def test_ca_cert_type(self):
        cert = _real_cert("myca", CertType.CA)
        cert_type, _ = CertSerialParser.typed(cert)
        assert cert_type == CertType.CA

    def test_delegates_to_serial_with_encoding(self):
        """typed() must call SerialWithEncoding.parse with the raw serial."""
        cert = _real_cert("svc1", CertType.SERVICE)
        expected = SerialWithEncoding.parse(cert.serial_number)
        assert CertSerialParser.typed(cert) == expected


# ===========================================================================
# CertSerialParser.raw_async
# ===========================================================================


class TestRawAsync:
    def test_async_returns_same_as_sync(self):
        cert = _make_cert_with_serial(12345)
        result = asyncio.get_event_loop().run_until_complete(
            CertSerialParser.raw_async(cert)
        )
        assert result == CertSerialParser.raw(cert)

    def test_async_result_is_int(self):
        cert = _make_cert_with_serial(0)
        result = asyncio.get_event_loop().run_until_complete(
            CertSerialParser.raw_async(cert)
        )
        assert type(result) is int

    def test_async_large_serial(self):
        big = 2**100
        cert = _make_cert_with_serial(big)
        result = asyncio.get_event_loop().run_until_complete(
            CertSerialParser.raw_async(cert)
        )
        assert result == big


# ===========================================================================
# CertSerialParser.typed_async
# ===========================================================================


class TestTypedAsync:
    def test_async_returns_same_as_sync(self):
        cert = _real_cert("asyncsvc", CertType.SERVICE)
        sync_result = CertSerialParser.typed(cert)
        async_result = asyncio.get_event_loop().run_until_complete(
            CertSerialParser.typed_async(cert)
        )
        assert async_result == sync_result

    def test_async_cert_type_matches(self):
        cert = _real_cert("asyncca", CertType.CA)
        cert_type, _ = asyncio.get_event_loop().run_until_complete(
            CertSerialParser.typed_async(cert)
        )
        assert cert_type == CertType.CA

    def test_async_result_is_tuple(self):
        cert = _real_cert("tuplesvc", CertType.SERVICE)
        result = asyncio.get_event_loop().run_until_complete(
            CertSerialParser.typed_async(cert)
        )
        assert isinstance(result, tuple) and len(result) == 2
