from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from logging import Logger

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import serialization
from sqlalchemy import Row, asc, delete, desc, select
from sqlalchemy import delete as sa_delete
from sqlalchemy import update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from tiny_ca.const import CertType

from ..settings import DEFAULT_LOGGER
from .base_db import BaseDB
from .const import CertificateStatus, RevokeStatus
from .models import Base, CertificateRecord


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

    async def init_db(self) -> None:  # pragma: no cover
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

    async def get_by_serial(self, serial: int) -> CertificateRecord | None:  # type: ignore
        """
        Fetch a single certificate record by its X.509 serial number.

        The serial is stored as a string in the database (to avoid integer
        overflow across all backends); the conversion is handled internally.

        Parameters
        ----------
        serial : int
            Integer serial number to look up.

        Returns
        -------
        CertificateRecord | None
            The matching ORM record, or ``None`` if no record exists for
            *serial* or if a database error occurs.
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
                return None

    async def get_by_name(self, common_name: str) -> CertificateRecord | None:  # type: ignore[override]
        """
        Fetch the active VALID certificate record for the given Common Name.

        Only records with ``status == CertificateStatus.VALID`` are returned.
        Revoked and expired records are ignored so that the caller always
        receives the currently-active certificate for a given CN, or ``None``
        if no active certificate exists.

        Parameters
        ----------
        common_name : str
            The CN (Common Name) value from the certificate Subject field.

        Returns
        -------
        CertificateRecord | None
            The matching VALID record, or ``None`` if absent or on DB error.
        """

        async with self._db.get_session() as session:
            try:
                stmt = select(CertificateRecord).where(
                    CertificateRecord.common_name == common_name,
                    CertificateRecord.status == CertificateStatus.VALID,
                )

                result = await session.execute(stmt)
                print(result)
                cert: CertificateRecord | None = result.scalar_one_or_none()
                self._logger.debug("get_by_name(%r) → %s", common_name, cert)
                print(cert)
                return cert
            except Exception as exc:
                self._logger.error(
                    "get_by_name(%r) failed: %s", common_name, exc, exc_info=True
                )
            return None

    async def register_cert_in_db(  # type: ignore[override]
        self,
        cert: x509.Certificate,
        uuid: str,
        key_type: CertType = CertType.DEVICE,
    ) -> bool:
        """
        Persist a newly issued certificate to the registry.

        Creates a new ``CertificateRecord`` row with ``status=VALID`` from the
        metadata and PEM encoding of *cert*.  The full PEM is stored so the
        certificate can be reconstructed independently of the filesystem.

        Parameters
        ----------
        cert : x509.Certificate
            The issued X.509 certificate.  Its Subject must contain at least
            one ``commonName`` (CN) attribute.
        uuid : str
            UUID string that identifies the storage folder holding the
            corresponding ``.pem``, ``.key``, and ``.csr`` files.
        key_type : CertType
            Certificate category.  Stored as its ``str`` value (e.g.
            ``"device"``).  Default: ``CertType.DEVICE``.

        Returns
        -------
        bool
            ``True`` if the record was committed successfully;
            ``False`` if the operation was rolled back due to an error
            (e.g. duplicate serial, constraint violation).

        Raises
        ------
        IndexError
            Re-raised if the certificate contains no CN attribute, indicating
            a malformed certificate that should not be stored.
        """

        async with self._db.get_session() as session:
            try:
                common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
                    0
                ].value
                common_name = (
                    common_name
                    if isinstance(common_name, str)
                    else common_name.decode("utf-8")
                )
                new_cert = CertificateRecord(
                    serial_number=str(cert.serial_number),
                    common_name=common_name,
                    not_valid_before=cert.not_valid_before_utc,
                    not_valid_after=cert.not_valid_after_utc,
                    certificate_pem=cert.public_bytes(
                        serialization.Encoding.PEM
                    ).decode("utf-8"),
                    status=CertificateStatus.VALID,
                    key_type=key_type.value,
                    uuid=uuid,
                )
                session.add(new_cert)
                await session.commit()
                self._logger.info(
                    "Certificate registered: CN=%r, serial=%s, uuid=%s",
                    common_name,
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
        Mark a certificate as revoked and record the reason and timestamp.

        Looks up the certificate by *serial_number* filtered to
        ``status == VALID`` — already-revoked or unknown serials are treated
        as not found.  On success the record is updated in-place:
        - ``status``            → ``CertificateStatus.REVOKED``
        - ``revocation_reason`` → integer value of *reason*
        - ``revocation_date``   → current UTC timestamp

        The change is committed atomically; a rollback is performed on any
        unexpected error.

        Parameters
        ----------
        serial_number : int
            Serial number of the certificate to revoke.
        reason : x509.ReasonFlags
            RFC 5280 §5.3.1 revocation reason code.
            Default: ``x509.ReasonFlags.unspecified`` (code 0).

        Returns
        -------
        tuple[bool, RevokeStatus]
            ``(True,  RevokeStatus.OK)``            — revocation committed.
            ``(False, RevokeStatus.NOT_FOUND)``     — no VALID cert with that serial.
            ``(False, RevokeStatus.UNKNOWN_ERROR)`` — unexpected internal error.
        """

        async with self._db.get_session() as session:
            try:
                stmt = select(CertificateRecord).where(
                    CertificateRecord.serial_number == str(serial_number),
                    CertificateRecord.status == CertificateStatus.VALID,
                )

                result = await session.execute(stmt)
                cert: CertificateRecord | None = result.scalar_one_or_none()
                self._logger.debug("get_by_serial(%d) → %s", serial_number, cert)

                if cert is None:
                    self._logger.warning(
                        "revoke_certificate: no VALID record found for serial=%d",
                        serial_number,
                    )
                    return False, RevokeStatus.NOT_FOUND
                cert.status = CertificateStatus.REVOKED
                cert.revocation_reason = reason.value if hasattr(reason, "value") else 0  # type: ignore
                cert.revocation_date = datetime.now(UTC)  # type: ignore

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
    ) -> AsyncGenerator[Row[tuple[str, datetime, str]], None]:  # type: ignore
        """
        Yield revoked certificate rows relevant for the current CRL window.

        A record is included when **all** of the following conditions hold:

        1. ``revocation_date`` is not ``NULL`` — the certificate was actually revoked.
        2. ``not_valid_after > now`` — the certificate has not yet expired; expired
           certificates need not appear in a CRL because relying parties will
           reject them regardless.
        3. ``revocation_date > now - 365 days`` — the revocation is recent enough
           to be relevant.  This prevents unbounded CRL growth from very old
           entries that no relying party could still encounter.

        Only three columns are selected (``serial_number``, ``revocation_date``,
        ``revocation_reason``) to minimise data transfer; callers must not
        access other ``CertificateRecord`` attributes on the yielded rows.

        Yields
        ------
        CertificateRecord
            SQLAlchemy ``Row`` objects with ``serial_number``,
            ``revocation_date``, and ``revocation_reason`` attributes.

        Notes
        -----
        All rows are fetched in a single query before yielding begins.  The
        session is closed in the ``finally`` block; do not use the yielded
        rows after the generator has been exhausted or abandoned.
        """

        now = datetime.now(UTC)
        cutoff = now - timedelta(days=365)

        async with self._db.get_session() as session:
            stmt = select(
                CertificateRecord.serial_number,
                CertificateRecord.revocation_date,
                CertificateRecord.revocation_reason,
            ).where(
                CertificateRecord.revocation_date.isnot(None),
                CertificateRecord.not_valid_after > now,
                CertificateRecord.revocation_date > cutoff,
            )
            result = await session.stream(stmt)

            async for row in result:
                yield row

    async def list_all(  # type: ignore[override]
        self,
        status: str | None = None,
        key_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CertificateRecord]:
        """
        Return a paginated list of certificate records with optional filters.

        Parameters
        ----------
        status : str | None
            Filter by lifecycle state.  ``None`` returns all statuses.
        key_type : str | None
            Filter by certificate category.  ``None`` returns all types.
        limit : int
            Maximum records to return.  Default: ``100``.
        offset : int
            Records to skip (pagination).  Default: ``0``.

        Returns
        -------
        list[CertificateRecord]
            Records ordered by ``id`` descending.  Empty list on error.
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
                return []

    async def get_expiring(self, within_days: int = 30) -> list[CertificateRecord]:  # type: ignore[override]
        """
        Return VALID certificates expiring within *within_days* calendar days.

        Parameters
        ----------
        within_days : int
            Look-ahead window in days.  Default: ``30``.

        Returns
        -------
        list[CertificateRecord]
            Records ordered by ``not_valid_after`` ascending.  Empty list on error.
        """

        now = datetime.now(UTC)
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
                return []

    async def delete_by_uuid(self, uuid: str) -> bool:  # type: ignore[override]
        """
        Permanently delete the certificate record identified by *uuid*.

        Parameters
        ----------
        uuid : str
            Storage folder UUID of the certificate to delete.

        Returns
        -------
        bool
            ``True`` if a row was deleted; ``False`` otherwise.
        """

        async with self._db.get_session() as session:
            try:
                stmt = sa_delete(CertificateRecord).where(
                    CertificateRecord.uuid == uuid
                )
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

        Returns
        -------
        int
            Number of rows updated.  ``0`` on error.
        """

        now = datetime.now(UTC)
        async with self._db.get_session() as session:
            try:
                stmt = (
                    sa_update(CertificateRecord)
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
                return 0
