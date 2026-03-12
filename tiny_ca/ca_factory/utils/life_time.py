"""
Stateless utilities for computing and inspecting X.509 certificate validity
periods.

All methods are ``@staticmethod``; the class carries no instance state and
exists purely as a logical namespace.  It can be used from any module without
instantiation.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import cast

from cryptography import x509

from tiny_ca.exc import InvalidRangeTimeCertificate


class CertLifetime:
    """
    Stateless helper that computes and inspects X.509 certificate validity windows.

    All operations are pure functions (no side effects, no shared state) and are
    therefore safe to call from multiple threads simultaneously.

    Use this class to:
    - Compute a ``(not_before, not_after)`` pair for a new certificate.
    - Extract the ``not_valid_after`` / ``not_valid_before`` timestamps from an
      existing certificate as timezone-aware UTC ``datetime`` objects.
    """

    @staticmethod
    def compute(
        valid_from: datetime | None = None,
        days_valid: int = 365,
    ) -> tuple[datetime, datetime]:
        """
        Calculate the ``(not_before, not_after)`` validity interval for a new
        certificate.

        If *valid_from* is ``None`` the current UTC time is used as the start
        of the interval.  The end of the interval is *valid_from* plus
        *days_valid* calendar days.

        The result is validated to ensure the computed end date has not already
        passed (which would produce an immediately-invalid certificate).

        Parameters
        ----------
        valid_from : datetime | None
            Start of the validity period as a timezone-aware ``datetime``.
            Pass ``None`` to use ``datetime.now(timezone.utc)`` automatically.
        days_valid : int
            Number of calendar days the certificate should remain valid.
            Default: ``365`` (one year).

        Returns
        -------
        tuple[datetime, datetime]
            ``(not_before, not_after)`` both expressed in UTC with
            ``tzinfo=timezone.utc``.

        Raises
        ------
        InvalidRangeTimeCertificate
            If the computed *not_after* is earlier than the current UTC time,
            meaning the certificate would be expired immediately upon issuance.

        Examples
        --------
        >>> start, end = CertLifetime.compute(days_valid=90)
        >>> assert (end - start).days == 90
        """
        now = datetime.now(UTC)
        start = valid_from or now
        end = start + timedelta(days=days_valid)
        if end < now:
            raise InvalidRangeTimeCertificate(valid_from=start, valid_to=end, now=now)
        return start, end

    @staticmethod
    def valid_to(cert: x509.Certificate) -> datetime:
        """
        Return the expiry timestamp of *cert* as a timezone-aware UTC datetime.

        Wraps ``cert.not_valid_after_utc`` and ensures the returned value
        always carries ``tzinfo=timezone.utc`` for safe comparison with other
        aware datetimes.

        Parameters
        ----------
        cert : x509.Certificate
            The certificate whose expiry date should be read.

        Returns
        -------
        datetime
            ``cert.not_valid_after_utc`` with ``tzinfo`` explicitly set to
            ``timezone.utc``.
        """
        return cert.not_valid_after_utc.replace(tzinfo=UTC)

    @staticmethod
    def valid_from(cert: x509.Certificate) -> datetime:
        """
        Return the activation timestamp of *cert* as a timezone-aware UTC datetime.

        Wraps ``cert.not_valid_before_utc`` and ensures the returned value
        always carries ``tzinfo=timezone.utc`` for safe comparison with other
        aware datetimes.

        Parameters
        ----------
        cert : x509.Certificate
            The certificate whose activation date should be read.

        Returns
        -------
        datetime
            ``cert.not_valid_before_utc`` with ``tzinfo`` explicitly set to
            ``timezone.utc``.
        """
        return cert.not_valid_after_utc.replace(tzinfo=UTC)

    @staticmethod
    async def compute_async(
        valid_from: datetime | None = None,
        days_valid: int = 365,
    ) -> tuple[datetime, datetime]:
        """
        Async-версія :meth:`compute`.

        Виконує обчислення в пулі потоків, щоб не блокувати event loop.

        Parameters
        ----------
        valid_from : datetime | None
            Початок вікна дійсності (UTC). ``None`` → поточний UTC-час.
        days_valid : int
            Тривалість у календарних днях. За замовчуванням: ``365``.

        Returns
        -------
        tuple[datetime, datetime]
            ``(not_before, not_after)`` в UTC.

        Raises
        ------
        InvalidRangeTimeCertificate
            Якщо обчислена дата закінчення вже в минулому.

        Examples
        --------
        #>>> start, end = await CertLifetime.compute_async(days_valid=90)
        #>>> assert (end - start).days == 90
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: CertLifetime.compute(valid_from, days_valid),
        )

    @staticmethod
    async def valid_to_async(cert: x509.Certificate) -> datetime:
        """
        Async-версія :meth:`valid_to`.

        Parameters
        ----------
        cert : x509.Certificate
            Сертифікат, дату закінчення якого потрібно прочитати.

        Returns
        -------
        datetime
            ``cert.not_valid_after_utc`` з ``tzinfo=UTC``.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, CertLifetime.valid_to, cert)

    @staticmethod
    async def valid_from_async(cert: x509.Certificate) -> datetime:
        """
        Async-версія :meth:`valid_from`.

        Parameters
        ----------
        cert : x509.Certificate
            Сертифікат, дату початку дії якого потрібно прочитати.

        Returns
        -------
        datetime
            ``cert.not_valid_before_utc`` з ``tzinfo=UTC``.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, CertLifetime.valid_from, cert)
