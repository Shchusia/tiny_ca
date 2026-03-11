"""
test_const.py

Tests for tiny_ca/const.py:
  - ALLOWED_CERT_EXTENSIONS tuple
  - CertType enum members, values, and lookup behaviour
"""

from __future__ import annotations

import pytest

from tiny_ca.const import ALLOWED_CERT_EXTENSIONS, CertType


# ---------------------------------------------------------------------------
# ALLOWED_CERT_EXTENSIONS
# ---------------------------------------------------------------------------


class TestAllowedCertExtensions:
    def test_is_tuple(self):
        assert isinstance(ALLOWED_CERT_EXTENSIONS, tuple)

    def test_contains_pem(self):
        assert ".pem" in ALLOWED_CERT_EXTENSIONS

    def test_contains_key(self):
        assert ".key" in ALLOWED_CERT_EXTENSIONS

    def test_contains_csr(self):
        assert ".csr" in ALLOWED_CERT_EXTENSIONS

    def test_does_not_contain_der(self):
        assert ".der" not in ALLOWED_CERT_EXTENSIONS

    def test_all_entries_start_with_dot(self):
        for ext in ALLOWED_CERT_EXTENSIONS:
            assert ext.startswith("."), f"Extension {ext!r} does not start with '.'"


# ---------------------------------------------------------------------------
# CertType
# ---------------------------------------------------------------------------


class TestCertType:
    def test_user_value(self):
        assert CertType.USER.value == "USR"

    def test_service_value(self):
        assert CertType.SERVICE.value == "SVC"

    def test_device_value(self):
        assert CertType.DEVICE.value == "DEV"

    def test_internal_value(self):
        assert CertType.INTERNAL.value == "INT"

    def test_ca_value(self):
        assert CertType.CA.value == "CA"

    def test_lookup_by_value_user(self):
        assert CertType("USR") is CertType.USER

    def test_lookup_by_value_service(self):
        assert CertType("SVC") is CertType.SERVICE

    def test_lookup_by_value_device(self):
        assert CertType("DEV") is CertType.DEVICE

    def test_lookup_by_value_internal(self):
        assert CertType("INT") is CertType.INTERNAL

    def test_lookup_by_value_ca(self):
        assert CertType("CA") is CertType.CA

    def test_all_five_members_exist(self):
        members = {m.name for m in CertType}
        assert members == {"USER", "SERVICE", "DEVICE", "INTERNAL", "CA"}

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            CertType("UNKNOWN")

    def test_members_are_distinct(self):
        values = [m.value for m in CertType]
        assert len(values) == len(set(values))
