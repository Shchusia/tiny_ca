"""
async_db_manager.py

Asynchronous SQLAlchemy-backed implementation of the certificate registry
(``AsyncDBHandler``).  Behaviour and error policy mirror
:class:`tiny_ca.db.sync_db_manager.SyncDBHandler`.
"""

from collections.abc import AsyncGenerator, Sequence
from datetime import datetime, timedelta
from logging import Logger
from typing import Any

from cryptography import x509
from sqlalchemy import asc, delete, desc, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from tiny_ca.const import CertType
from tiny_ca.exc import DBOperationError

from ..settings import DEFAULT_LOGGER
from .base_db import BaseDB
from .const import CertificateStatus, RevokeStatus
from .models import Base, CertificateRecord
from .utils import build_record, utc_now_naive


class DatabaseManager:
    """
    Manages the SQLAlchemy engine and ``sessionmaker`` factory.

    Responsibility: connection lifecycle *only*.  This class creates the
    engine, optionally initialises the schema, and hands out new ``Session``
    objects on request.  It performs no queries and contains no domain logic.

    Parameters
    ----------
    db_url : str
        SQLAlchemy database URL.  Supports any SQLAlchemy-compatible backend,
        e.g. ``"sqlite:///ca.db"`` or
        ``"postgresql+psycopg2://user:pass@host/dbname"``.
        Default: ``"sqlite:///ca_repository.db"``.
    create_all : bool
        When ``True`` (default), calls ``Base.metadata.create_all`` at
        construction so the schema is present before the first query.
        Set to ``False`` when using Alembic or another migration tool that
        manages the schema independently.
    """

    def __init__(self, db_url: str = "sqlite+aiosqlite:///ca_repository.db"):
        self.engine = create_async_engine(db_url, echo=False)
        self.async_session = async_sessionmaker(
            self.engine, expire_on_commit=False, class_=AsyncSession
        )

    async def init_db(self) -> None:
        """Create the schema (``Base.metadata.create_all``) if it is missing."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    def get_session(self) -> AsyncSession:
        return self.async_session()


class AsyncDBHandler(BaseDB):
    """
    Asynchronous, SQLAlchemy-backed certificate registry.

    Implements the full ``BaseDB`` contract with explicit, atomic transaction
    management.  Every public method follows the same pattern:

    1. Open a new session via ``self._db.session()``.
    2. Execute the query / mutation inside a ``try`` block.
    3. Commit on success or roll back on any exception.
    4. Always close the session in the ``finally`` block.

    This guarantees that no session is leaked regardless of outcome, and that
    partial writes are never visible to other readers.

    Parameters
    ----------
    db_url : str
        SQLAlchemy database URL forwarded to ``DatabaseManager``.
    logger : Logger | None
        Logger for operational and diagnostic messages.
        Falls back to ``DEFAULT_LOGGER`` when ``None``.
    """

    def __init__(self, db_url: str, logger: Logger | None = None) -> None:
        self._logger = logger or DEFAULT_LOGGER
        self._db = DatabaseManager(db_url=db_url)

    # Error policy: identical to ``SyncDBHandler`` — read operations raise
    # ``DBOperationError`` instead of returning "not found" / "empty".

    async def get_by_serial(self, serial: int) -> CertificateRecord | None:  # type: ignore
        """
        Fetch a single certificate record by its X.509 serial number.

        Raises
        ------
        DBOperationError
            If the database query fails.
        """
        async with self._db.get_session() as session:
            try:
                stmt = select(CertificateRecord).where(
                    CertificateRecord.serial_number == str(serial)
                )
                result = await session.execute(stmt)
                cert: CertificateRecord | None = result.scalar_one_or_none()
                self._logger.debug("get_by_serial(%d) → %s", serial, cert)
                return cert
            except Exception as exc:
                self._logger.error(
                    "get_by_serial(%d) failed: %s", serial, exc, exc_info=True
                )
                raise DBOperationError("get_by_serial", exc) from exc

    async def get_by_name(self, common_name: str) -> CertificateRecord | None:  # type: ignore[override]
        """
        Fetch the newest VALID certificate record for the given Common Name.

        Raises
        ------
        DBOperationError
            If the database query fails.
        """
        async with self._db.get_session() as session:
            try:
                stmt = (
                    select(CertificateRecord)
                    .where(
                        CertificateRecord.common_name == common_name,
                        CertificateRecord.status == CertificateStatus.VALID,
                    )
                    .order_by(desc(CertificateRecord.id))
                    .limit(1)
                )
                result = await session.execute(stmt)
                cert: CertificateRecord | None = result.scalars().first()
                self._logger.debug("get_by_name(%r) → %s", common_name, cert)
                return cert
            except Exception as exc:
                self._logger.error(
                    "get_by_name(%r) failed: %s", common_name, exc, exc_info=True
                )
                raise DBOperationError("get_by_name", exc) from exc

    async def register_cert_in_db(  # type: ignore[override]
        self,
        cert: x509.Certificate,
        uuid: str,
        key_type: CertType = CertType.DEVICE,
    ) -> bool:
        """
        Persist a newly issued certificate to the registry.

        Returns
        -------
        bool
            ``True`` on commit, ``False`` on rollback (logged).  Callers must
            check the result.
        """
        async with self._db.get_session() as session:
            try:
                record = build_record(cert, uuid, key_type)
                session.add(record)
                await session.commit()
                self._logger.info(
                    "Certificate registered: CN=%r, serial=%s, uuid=%s",
                    record.common_name,
                    cert.serial_number,
                    uuid,
                )
                return True
            except Exception as exc:
                await session.rollback()
                self._logger.error(
                    "register_cert_in_db failed (serial=%s): %s",
                    cert.serial_number,
                    exc,
                    exc_info=True,
                )
                return False

    async def revoke_certificate(  # type: ignore[override]
        self,
        serial_number: int,
        reason: x509.ReasonFlags = x509.ReasonFlags.unspecified,
    ) -> tuple[bool, RevokeStatus]:
        """
        Mark a VALID certificate as revoked and record the reason and timestamp.

        Returns
        -------
        tuple[bool, RevokeStatus]
            ``(True, OK)``, ``(False, NOT_FOUND)`` or ``(False, UNKNOWN_ERROR)``.
        """
        async with self._db.get_session() as session:
            try:
                stmt = select(CertificateRecord).where(
                    CertificateRecord.serial_number == str(serial_number),
                    CertificateRecord.status == CertificateStatus.VALID,
                )
                result = await session.execute(stmt)
                cert: CertificateRecord | None = result.scalar_one_or_none()

                if cert is None:
                    self._logger.warning(
                        "revoke_certificate: no VALID record found for serial=%d",
                        serial_number,
                    )
                    return False, RevokeStatus.NOT_FOUND

                cert.status = CertificateStatus.REVOKED
                cert.revocation_reason = reason.value
                cert.revocation_date = utc_now_naive()

                await session.commit()
                self._logger.info(
                    "Certificate revoked: serial=%d, reason=%s", serial_number, reason
                )
                return True, RevokeStatus.OK

            except Exception as exc:
                await session.rollback()
                self._logger.error(
                    "revoke_certificate(%d) failed: %s",
                    serial_number,
                    exc,
                    exc_info=True,
                )
                return False, RevokeStatus.UNKNOWN_ERROR

    async def get_revoked_certificates(  # type: ignore
        self,
    ) -> AsyncGenerator[Sequence[Any], None]:
        """
        Yield every revoked certificate that has not yet expired.

        There is no age cut-off on the revocation date (RFC 5280 §3.3): a
        revoked certificate stays on the CRL until its own ``notAfter``.

        Raises
        ------
        DBOperationError
            If the query fails at any point — the caller must not publish a
            CRL built from a partial result.
        """
        now = utc_now_naive()
        async with self._db.get_session() as session:
            try:
                stmt = select(
                    CertificateRecord.serial_number,
                    CertificateRecord.revocation_date,
                    CertificateRecord.revocation_reason,
                ).where(
                    CertificateRecord.revocation_date.isnot(None),
                    CertificateRecord.not_valid_after > now,
                )
                result = await session.stream(stmt)
                async for row in result:
                    yield row
            except Exception as exc:
                self._logger.error(
                    "get_revoked_certificates failed: %s", exc, exc_info=True
                )
                raise DBOperationError("get_revoked_certificates", exc) from exc

    async def list_all(  # type: ignore[override]
        self,
        status: str | None = None,
        key_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CertificateRecord]:
        """
        Return a paginated list of certificate records with optional filters.

        Raises
        ------
        DBOperationError
            If the query fails.
        """
        async with self._db.get_session() as session:
            try:
                stmt = select(CertificateRecord)
                if status is not None:
                    stmt = stmt.where(CertificateRecord.status == status)
                if key_type is not None:
                    stmt = stmt.where(CertificateRecord.key_type == key_type)
                stmt = (
                    stmt.order_by(desc(CertificateRecord.id))
                    .limit(limit)
                    .offset(offset)
                )
                result = await session.execute(stmt)
                rows = result.scalars().all()
                self._logger.debug(
                    "list_all(status=%r, key_type=%r) → %d rows",
                    status,
                    key_type,
                    len(rows),
                )
                return list(rows)
            except Exception as exc:
                self._logger.error("list_all failed: %s", exc, exc_info=True)
                raise DBOperationError("list_all", exc) from exc

    async def get_expiring(self, within_days: int = 30) -> list[CertificateRecord]:  # type: ignore[override]
        """
        Return VALID certificates expiring within *within_days* calendar days.

        Raises
        ------
        DBOperationError
            If the query fails.
        """
        now = utc_now_naive()
        cutoff = now + timedelta(days=within_days)
        async with self._db.get_session() as session:
            try:
                stmt = (
                    select(CertificateRecord)
                    .where(
                        CertificateRecord.status == CertificateStatus.VALID,
                        CertificateRecord.not_valid_after > now,
                        CertificateRecord.not_valid_after <= cutoff,
                    )
                    .order_by(asc(CertificateRecord.not_valid_after))
                )
                result = await session.execute(stmt)
                rows = result.scalars().all()
                self._logger.debug(
                    "get_expiring(within_days=%d) → %d rows", within_days, len(rows)
                )
                return list(rows)
            except Exception as exc:
                self._logger.error("get_expiring failed: %s", exc, exc_info=True)
                raise DBOperationError("get_expiring", exc) from exc

    async def delete_by_uuid(self, uuid: str) -> bool:  # type: ignore[override]
        """
        Permanently delete the certificate record identified by *uuid*.

        Returns
        -------
        bool
            ``True`` if a row was deleted; ``False`` otherwise (errors logged).
        """
        async with self._db.get_session() as session:
            try:
                stmt = delete(CertificateRecord).where(CertificateRecord.uuid == uuid)
                result = await session.execute(stmt)
                await session.commit()
                deleted = bool(result.rowcount > 0)  # type: ignore[attr-defined]
                self._logger.info("delete_by_uuid(%r) → deleted=%s", uuid, deleted)
                return deleted
            except Exception as exc:
                await session.rollback()
                self._logger.error(
                    "delete_by_uuid(%r) failed: %s", uuid, exc, exc_info=True
                )
                return False

    async def update_status_expired(self) -> int:  # type: ignore[override]
        """
        Bulk-set status=expired for all VALID certs whose validity has passed.

        Raises
        ------
        DBOperationError
            If the update fails (the transaction is rolled back).
        """
        now = utc_now_naive()
        async with self._db.get_session() as session:
            try:
                stmt = (
                    update(CertificateRecord)
                    .where(
                        CertificateRecord.status == CertificateStatus.VALID,
                        CertificateRecord.not_valid_after < now,
                    )
                    .values(status=CertificateStatus.EXPIRED)
                )
                result = await session.execute(stmt)
                await session.commit()
                count = int(result.rowcount)  # type: ignore[attr-defined]
                self._logger.info(
                    "update_status_expired: %d rows marked expired", count
                )
                return count
            except Exception as exc:
                await session.rollback()
                self._logger.error(
                    "update_status_expired failed: %s", exc, exc_info=True
                )
                raise DBOperationError("update_status_expired", exc) from exc
