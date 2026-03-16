"""
Tests for tiny_ca/db/const.py  (RevokeStatus, CertificateStatus)

Coverage target: 100 %

Run with:
    pytest test_db_const.py -v --cov=tiny_ca.db.const --cov-report=term-missing
"""

from __future__ import annotations

from enum import Enum

import pytest

from tiny_ca.db.const import CertificateStatus, RevokeStatus


# ===========================================================================
# RevokeStatus
# ===========================================================================


class TestRevokeStatus:
    def test_is_enum(self):
        assert issubclass(RevokeStatus, Enum)

    def test_members_exist(self):
        assert RevokeStatus.NOT_FOUND
        assert RevokeStatus.UNKNOWN_ERROR
        assert RevokeStatus.OK

    def test_ok_value(self):
        assert RevokeStatus.OK.value == "success"

    def test_not_found_value_is_string(self):
        assert isinstance(RevokeStatus.NOT_FOUND.value, str)
        assert "serial number" in RevokeStatus.NOT_FOUND.value.lower()

    def test_unknown_error_value_is_string(self):
        assert isinstance(RevokeStatus.UNKNOWN_ERROR.value, str)
        assert "internal error" in RevokeStatus.UNKNOWN_ERROR.value.lower()

    def test_members_are_distinct(self):
        statuses = list(RevokeStatus)
        assert len(statuses) == len(set(s.value for s in statuses))

    def test_enum_lookup_by_value(self):
        assert RevokeStatus("success") == RevokeStatus.OK


# ===========================================================================
# CertificateStatus
# ===========================================================================


class TestCertificateStatus:
    def test_is_str_enum(self):
        from enum import StrEnum

        assert issubclass(CertificateStatus, StrEnum)

    def test_values(self):
        assert CertificateStatus.VALID == "valid"
        assert CertificateStatus.REVOKED == "revoked"
        assert CertificateStatus.EXPIRED == "expired"
        assert CertificateStatus.UNKNOWN == "unknown"

    def test_str_behaviour(self):
        # StrEnum instances must compare equal to their string values
        assert str(CertificateStatus.VALID) == "valid"
        assert CertificateStatus.REVOKED == "revoked"

    def test_all_members_present(self):
        names = {m.name for m in CertificateStatus}
        assert names == {"VALID", "REVOKED", "EXPIRED", "UNKNOWN"}

    def test_lookup_by_string(self):
        assert CertificateStatus("valid") == CertificateStatus.VALID
        assert CertificateStatus("revoked") == CertificateStatus.REVOKED

    def test_usable_as_dict_key(self):
        d = {CertificateStatus.VALID: 1, CertificateStatus.REVOKED: 2}
        assert d["valid"] == 1  # StrEnum keys compare equal to plain strings
