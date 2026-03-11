"""
test_serial_parser.py

Tests for tiny_ca/ca_factory/utils/serial.py:
  - CertSerialParser.raw   — direct passthrough of cert.serial_number
  - CertSerialParser.typed — delegated decoding via SerialWithEncoding
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tiny_ca.ca_factory.utils.serial import CertSerialParser
from tiny_ca.const import CertType
from tiny_ca.utils.serial_generator import SerialWithEncoding


class TestCertSerialParserRaw:
    def test_returns_integer(self):
        cert = MagicMock()
        cert.serial_number = 12345
        assert CertSerialParser.raw(cert) == 12345

    def test_returns_large_serial(self):
        big = 2**159 + 7
        cert = MagicMock()
        cert.serial_number = big
        assert CertSerialParser.raw(cert) == big

    def test_returns_zero(self):
        cert = MagicMock()
        cert.serial_number = 0
        assert CertSerialParser.raw(cert) == 0

    def test_passes_value_unchanged(self):
        cert = MagicMock()
        cert.serial_number = 0xDEADBEEF
        result = CertSerialParser.raw(cert)
        assert result is cert.serial_number


class TestCertSerialParserTyped:
    def test_returns_tuple(self, ca_cert):
        result = CertSerialParser.typed(ca_cert)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_typed_known_serial(self):
        """Generate a serial via SerialWithEncoding, put it in a mock cert,
        and verify CertSerialParser.typed decodes it correctly."""
        serial = SerialWithEncoding.generate("myapp", CertType.SERVICE)
        cert = MagicMock()
        cert.serial_number = serial
        cert_type, name = CertSerialParser.typed(cert)
        assert cert_type is CertType.SERVICE
        assert name == "myapp"

    def test_typed_unknown_serial_returns_none_type(self):
        cert = MagicMock()
        # Serial with an unregistered prefix
        cert.serial_number = 0x1234_0000_0000_0000_0000_0000_0000_0000_0000_0000
        cert_type, name = CertSerialParser.typed(cert)
        assert cert_type is None

    @pytest.mark.parametrize("cert_type_val", list(CertType))
    def test_typed_all_cert_types(self, cert_type_val):
        serial = SerialWithEncoding.generate("tst", cert_type_val)
        cert = MagicMock()
        cert.serial_number = serial
        decoded_type, decoded_name = CertSerialParser.typed(cert)
        assert decoded_type is cert_type_val
        assert decoded_name == "tst"
