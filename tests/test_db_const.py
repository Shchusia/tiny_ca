"""
test_db_const.py

Tests for tiny_ca/db/const.py:
  - RevokeStatus enum members and their string values
"""

from __future__ import annotations

import pytest

from tiny_ca.db.const import RevokeStatus


class TestRevokeStatus:
    def test_ok_member_exists(self):
        assert hasattr(RevokeStatus, "OK")

    def test_not_found_member_exists(self):
        assert hasattr(RevokeStatus, "NOT_FOUND")

    def test_unknown_error_member_exists(self):
        assert hasattr(RevokeStatus, "UNKNOWN_ERROR")

    def test_ok_value_is_success(self):
        assert RevokeStatus.OK.value == "success"

    def test_not_found_value_contains_serial(self):
        assert (
            "serial" in RevokeStatus.NOT_FOUND.value.lower()
            or "valid" in RevokeStatus.NOT_FOUND.value.lower()
        )

    def test_unknown_error_value_mentions_logs(self):
        assert (
            "log" in RevokeStatus.UNKNOWN_ERROR.value.lower()
            or "error" in RevokeStatus.UNKNOWN_ERROR.value.lower()
        )

    def test_all_three_members(self):
        names = {m.name for m in RevokeStatus}
        assert names == {"OK", "NOT_FOUND", "UNKNOWN_ERROR"}

    def test_members_are_distinct(self):
        values = [m.value for m in RevokeStatus]
        assert len(values) == len(set(values))

    def test_truthiness_ok(self):
        # Enum members are always truthy
        assert RevokeStatus.OK

    def test_equality(self):
        assert RevokeStatus.OK == RevokeStatus.OK
        assert RevokeStatus.OK != RevokeStatus.NOT_FOUND
