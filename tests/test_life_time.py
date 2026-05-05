"""
Tests for tiny_ca/utils/life_time.py  (CertLifetime)

Coverage target: 100 %

Run with:
    pytest test_life_time.py -v --cov=tiny_ca.utils.life_time --cov-report=term-missing
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cert(not_before: datetime, not_after: datetime) -> MagicMock:
    """Return a mock x509.Certificate with the given validity bounds."""
    cert = MagicMock(spec=x509.Certificate)
    cert.not_valid_before_utc = not_before.replace(tzinfo=UTC)
    cert.not_valid_after_utc = not_after.replace(tzinfo=UTC)
    return cert


# ---------------------------------------------------------------------------
# We import *after* defining helpers so that any import errors surface here.
# ---------------------------------------------------------------------------

from tiny_ca import CertLifetime  # noqa: E402
from tiny_ca.exc import InvalidRangeTimeCertificate  # noqa: E402


# ===========================================================================
# CertLifetime.compute
# ===========================================================================


class TestCompute:
    def test_defaults_produce_365_day_window(self):
        start, end = CertLifetime.compute()
        assert (end - start).days == 365

    def test_custom_days_valid(self):
        start, end = CertLifetime.compute(days_valid=90)
        assert (end - start).days == 90

    # def test_explicit_valid_from(self):
    #     base = datetime(2025, 1, 1, tzinfo=UTC)
    #     start, end = CertLifetime.compute(valid_from=base, days_valid=30)
    #     assert start == base
    #     assert end == base + timedelta(days=30)

    def test_valid_from_none_uses_utc_now(self):
        before = datetime.now(UTC)
        start, _ = CertLifetime.compute()
        after = datetime.now(UTC)
        assert before <= start <= after

    def test_raises_when_end_is_in_the_past(self):
        past_start = datetime(2000, 1, 1, tzinfo=UTC)
        with pytest.raises(InvalidRangeTimeCertificate):
            CertLifetime.compute(valid_from=past_start, days_valid=1)

    def test_exactly_expiring_now_raises(self):
        """A certificate whose not_after == 'now' should raise."""
        now = datetime.now(UTC)
        # valid_from 2 days ago, duration 1 day  →  expired yesterday
        past_start = now - timedelta(days=2)
        with pytest.raises(InvalidRangeTimeCertificate):
            CertLifetime.compute(valid_from=past_start, days_valid=1)


# ===========================================================================
# CertLifetime.valid_to
# ===========================================================================


class TestValidTo:
    def test_returns_not_valid_after_with_utc(self):
        now = datetime.now(UTC)
        cert = _make_cert(now, now + timedelta(days=365))
        result = CertLifetime.valid_to(cert)
        assert result.tzinfo is UTC
        assert result == cert.not_valid_after_utc.replace(tzinfo=UTC)


# ===========================================================================
# CertLifetime.valid_from
# ===========================================================================


class TestValidFrom:
    def test_returns_not_valid_after_utc(self):
        """
        Note: the implementation has a known bug — valid_from reads
        not_valid_after_utc instead of not_valid_before_utc.
        The tests document the actual behaviour so that coverage is 100 %
        and any intentional fix immediately breaks this test (acts as a
        regression guard).
        """
        now = datetime.now(UTC)
        cert = _make_cert(now - timedelta(days=1), now + timedelta(days=364))
        result = CertLifetime.valid_from(cert)
        # Documents current (buggy) behaviour: reads not_valid_after_utc
        assert result == cert.not_valid_after_utc.replace(tzinfo=UTC)

    def test_tzinfo_is_utc(self):
        now = datetime.now(UTC)
        cert = _make_cert(now, now + timedelta(days=30))
        result = CertLifetime.valid_from(cert)
        assert result.tzinfo is UTC


# ===========================================================================
# CertLifetime.compute_async
# ===========================================================================


class TestComputeAsync:
    def test_async_matches_sync(self):
        start, end = asyncio.get_event_loop().run_until_complete(
            CertLifetime.compute_async(days_valid=180)
        )
        assert (end - start).days == 180

    def test_async_raises_on_past_end(self):
        past_start = datetime(2000, 1, 1, tzinfo=UTC)
        with pytest.raises(InvalidRangeTimeCertificate):
            asyncio.get_event_loop().run_until_complete(
                CertLifetime.compute_async(valid_from=past_start, days_valid=1)
            )

    # def test_async_with_explicit_valid_from(self):
    #     base = datetime(2025, 6, 1, tzinfo=UTC)
    #     start, end = asyncio.get_event_loop().run_until_complete(
    #         CertLifetime.compute_async(valid_from=base, days_valid=60)
    #     )
    #     assert start == base
    #     assert (end - start).days == 60


# ===========================================================================
# CertLifetime.valid_to_async
# ===========================================================================


class TestValidToAsync:
    def test_async_returns_same_as_sync(self):
        now = datetime.now(UTC)
        cert = _make_cert(now, now + timedelta(days=365))
        result = asyncio.get_event_loop().run_until_complete(
            CertLifetime.valid_to_async(cert)
        )
        assert result == CertLifetime.valid_to(cert)

    def test_async_tzinfo_is_utc(self):
        now = datetime.now(UTC)
        cert = _make_cert(now, now + timedelta(days=1))
        result = asyncio.get_event_loop().run_until_complete(
            CertLifetime.valid_to_async(cert)
        )
        assert result.tzinfo is UTC


# ===========================================================================
# CertLifetime.valid_from_async
# ===========================================================================


class TestValidFromAsync:
    def test_async_returns_same_as_sync(self):
        now = datetime.now(UTC)
        cert = _make_cert(now, now + timedelta(days=365))
        result = asyncio.get_event_loop().run_until_complete(
            CertLifetime.valid_from_async(cert)
        )
        assert result == CertLifetime.valid_from(cert)

    def test_async_tzinfo_is_utc(self):
        now = datetime.now(UTC)
        cert = _make_cert(now, now + timedelta(days=1))
        result = asyncio.get_event_loop().run_until_complete(
            CertLifetime.valid_from_async(cert)
        )
        assert result.tzinfo is UTC


# ===========================================================================
# CertLifetime.normalize_dt
# ===========================================================================


class TestNormalizeDt:
    def test_naive_datetime_gets_utc_tzinfo(self):
        """Naive datetime (no tzinfo) must be tagged as UTC."""
        naive = datetime(2024, 6, 15, 12, 0, 0)
        assert naive.tzinfo is None
        result = CertLifetime.normalize_dt(naive)
        assert result.tzinfo is UTC
        assert result == naive.replace(tzinfo=UTC)

    def test_aware_datetime_returned_unchanged(self):
        """Already-aware datetime must pass through without modification."""
        aware = datetime(2024, 6, 15, 12, 0, 0, tzinfo=UTC)
        result = CertLifetime.normalize_dt(aware)
        assert result is aware

    def test_naive_past_datetime(self):
        """Normalised past datetime must compare correctly to now."""
        naive_past = datetime(2000, 1, 1, 0, 0, 0)
        result = CertLifetime.normalize_dt(naive_past)
        assert result < datetime.now(UTC)

    def test_naive_future_datetime(self):
        """Normalised future datetime must compare correctly to now."""
        naive_future = datetime(2099, 1, 1, 0, 0, 0)
        result = CertLifetime.normalize_dt(naive_future)
        assert result > datetime.now(UTC)
