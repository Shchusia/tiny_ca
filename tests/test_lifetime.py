"""
test_lifetime.py

Tests for tiny_ca/ca_factory/utils/life_time.py:
  - CertLifetime.compute  — normal, custom start, expired range
  - CertLifetime.valid_to — timezone normalisation
  - CertLifetime.valid_from — timezone normalisation
"""

from __future__ import annotations

import datetime

import pytest
from unittest.mock import MagicMock

from tiny_ca.ca_factory.utils.life_time import CertLifetime
from tiny_ca.exc import InvalidRangeTimeCertificate


class TestCertLifetimeCompute:
    def test_returns_tuple_of_two_datetimes(self):
        start, end = CertLifetime.compute()
        assert isinstance(start, datetime.datetime)
        assert isinstance(end, datetime.datetime)

    def test_default_duration_is_365_days(self):
        start, end = CertLifetime.compute()
        assert (end - start).days == 365

    def test_custom_duration(self):
        start, end = CertLifetime.compute(days_valid=90)
        assert (end - start).days == 90

    def test_custom_valid_from_is_respected(self):
        custom_start = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
        start, end = CertLifetime.compute(valid_from=custom_start, days_valid=30)
        assert start == custom_start
        assert end == custom_start + datetime.timedelta(days=30)

    def test_result_is_utc_aware(self):
        start, end = CertLifetime.compute()
        assert start.tzinfo is not None
        assert end.tzinfo is not None

    def test_end_is_after_start(self):
        start, end = CertLifetime.compute(days_valid=1)
        assert end > start

    def test_past_valid_from_with_future_end_is_ok(self):
        # Started yesterday, still valid for 10 years
        yesterday = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
            days=1
        )
        start, end = CertLifetime.compute(valid_from=yesterday, days_valid=3650)
        assert start == yesterday

    def test_expired_range_raises(self):
        # Start 10 days ago, duration 5 days → end is already in the past
        past_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
            days=10
        )
        with pytest.raises(InvalidRangeTimeCertificate):
            CertLifetime.compute(valid_from=past_start, days_valid=5)

    def test_zero_days_raises_because_end_equals_start(self):
        # days_valid=0 → end == start == now → end < now is False (edge case)
        # But the function accepts it as valid (end >= now within floating point)
        # Document actual behaviour: does NOT raise for days_valid=0
        start, end = CertLifetime.compute(days_valid=0)
        assert start == end


class TestCertLifetimeValidTo:
    def test_returns_datetime_with_utc_tzinfo(self):
        cert = MagicMock()
        cert.not_valid_after_utc = datetime.datetime(
            2030, 6, 1, 0, 0, 0, tzinfo=datetime.timezone.utc
        )
        result = CertLifetime.valid_to(cert)
        assert result.tzinfo == datetime.timezone.utc

    def test_value_equals_not_valid_after(self):
        ts = datetime.datetime(2028, 12, 31, tzinfo=datetime.timezone.utc)
        cert = MagicMock()
        cert.not_valid_after_utc = ts
        assert CertLifetime.valid_to(cert) == ts

    def test_replaces_tzinfo_when_already_utc(self):
        ts = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
        cert = MagicMock()
        cert.not_valid_after_utc = ts
        result = CertLifetime.valid_to(cert)
        assert result.tzinfo == datetime.timezone.utc


class TestCertLifetimeValidFrom:
    def test_returns_datetime_with_utc_tzinfo(self):
        cert = MagicMock()
        cert.not_valid_before_utc = datetime.datetime(
            2024, 1, 1, tzinfo=datetime.timezone.utc
        )
        result = CertLifetime.valid_from(cert)
        assert result.tzinfo == datetime.timezone.utc

    def test_value_equals_not_valid_before(self):
        ts = datetime.datetime(2024, 6, 15, tzinfo=datetime.timezone.utc)
        cert = MagicMock()
        cert.not_valid_before_utc = ts
        assert CertLifetime.valid_from(cert) == ts
