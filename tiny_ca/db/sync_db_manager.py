"""
Synchronous SQLAlchemy-backed implementation of the certificate registry.

Module-level contents
---------------------
``DatabaseManager``  — owns the SQLAlchemy engine and session factory.
                       No domain logic; connection lifecycle only.
``SyncDBHandler``    — implements ``BaseDB``; all certificate registry
                       operations with explicit, atomic transaction management.

SOLID notes
-----------
SRP : ``DatabaseManager`` handles engine creation and session provisioning.
      ``SyncDBHandler`` handles domain operations on ``CertificateRecord`` rows.
      Neither class knows about the other's internal details.
OCP : Additional query methods are added to ``SyncDBHandler`` without touching
      ``DatabaseManager`` or ``BaseDB``.
LSP : ``SyncDBHandler`` satisfies the full ``BaseDB`` contract and is
      transparently substitutable in any consumer that depends on ``BaseDB``.
ISP : ``BaseDB`` is declared in ``db/base_db.py``; this module imports and
      extends it without adding unrelated methods visible to callers.
DIP : ``CertLifecycleManager`` depends on ``BaseDB``, never on
      ``SyncDBHandler`` directly.
"""

from __future__ import annotations

from collections.abc import Generator
import datetime
from logging import Logger

from cryptography import x509
from sqlalchemy import asc, create_engine, delete, desc, select, update
from sqlalchemy.orm import Session, sessionmaker

from tiny_ca.const import CertType
from tiny_ca.exc import DBOperationError
from tiny_ca.settings import DEFAULT_LOGGER

from .base_db import BaseDB
from .const import CertificateStatus, RevokeStatus
from .models import Base, CertificateRecord
from .utils import build_record, utc_now_naive

# ---------------------------------------------------------------------------
# SRP: engine and session-factory management
# ---------------------------------------------------------------------------


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

    def __init__(
        self,
        db_url: str = "sqlite:///ca_repository.db",
        create_all: bool = True,
    ) -> None:
        self._engine = create_engine(db_url)
        if create_all:
            Base.metadata.create_all(self._engine)
        self._Session: sessionmaker[Session] = sessionmaker(bind=self._engine)

    def session(self) -> Session:
        """
        Provision a new SQLAlchemy ``Session`` bound to the managed engine.

        The caller is fully responsible for the session lifecycle: committing
        successful transactions, rolling back on errors, and closing the
        session in a ``finally`` block.  Example::

            session = db_manager.session()
            try:
                session.add(record)
                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

        Returns
        -------
        Session
            A new, uncommitted SQLAlchemy ORM session.
        """
        return self._Session()


# ---------------------------------------------------------------------------
# SRP: domain operations on CertificateRecord rows
# ---------------------------------------------------------------------------


class SyncDBHandler(BaseDB):
    """
    Synchronous, SQLAlchemy-backed certificate registry.

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

    # ------------------------------------------------------------------
    # BaseDB interface
    # ------------------------------------------------------------------
    #
    # Error policy
    # ~~~~~~~~~~~~
    # Read operations raise ``DBOperationError`` on any database failure.
    # They never turn an error into "not found" / "empty": for a CA that
    # would make a revoked certificate look valid or produce an empty CRL.

    def get_by_serial(self, serial: int) -> CertificateRecord | None:
        """
        Fetch a single certificate record by its X.509 serial number.

        Returns
        -------
        CertificateRecord | None
            The matching record, or ``None`` if no record exists for *serial*.

        Raises
        ------
        DBOperationError
            If the database query fails.
        """
        session = self._db.session()
        try:
            stmt = select(CertificateRecord).where(
                CertificateRecord.serial_number == str(serial)
            )
            cert: CertificateRecord | None = session.execute(stmt).scalar_one_or_none()
            self._logger.debug("get_by_serial(%d) → %s", serial, cert)
            return cert
        except Exception as exc:
            self._logger.error(
                "get_by_serial(%d) failed: %s", serial, exc, exc_info=True
            )
            raise DBOperationError("get_by_serial", exc) from exc
        finally:
            session.close()

    def get_by_name(self, common_name: str) -> CertificateRecord | None:
        """
        Fetch the active VALID certificate record for the given Common Name.

        If several VALID records share the CN (e.g. created by an older
        version of the library), the most recently inserted one is returned.

        Raises
        ------
        DBOperationError
            If the database query fails.
        """
        session = self._db.session()
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
            cert: CertificateRecord | None = session.execute(stmt).scalars().first()
            self._logger.debug("get_by_name(%r) → %s", common_name, cert)
            return cert
        except Exception as exc:
            self._logger.error(
                "get_by_name(%r) failed: %s", common_name, exc, exc_info=True
            )
            raise DBOperationError("get_by_name", exc) from exc
        finally:
            session.close()

    def register_cert_in_db(
        self,
        cert: x509.Certificate,
        uuid: str,
        key_type: CertType = CertType.DEVICE,
    ) -> bool:
        """
        Persist a newly issued certificate to the registry.

        Creates a new ``CertificateRecord`` row with ``status=VALID``.  When
        the Subject has no CN, the RFC 4514 Subject string is stored as
        ``common_name``.

        Returns
        -------
        bool
            ``True`` if the record was committed; ``False`` if the operation
            was rolled back (e.g. duplicate serial or UUID).  Callers must
            check the result — ``CertLifecycleManager`` raises
            ``DBOperationError`` on ``False``.
        """
        session = self._db.session()
        try:
            record = build_record(cert, uuid, key_type)
            session.add(record)
            session.commit()
            self._logger.info(
                "Certificate registered: CN=%r, serial=%s, uuid=%s",
                record.common_name,
                cert.serial_number,
                uuid,
            )
            return True
        except Exception as exc:
            session.rollback()
            self._logger.error(
                "register_cert_in_db failed (serial=%s): %s",
                cert.serial_number,
                exc,
                exc_info=True,
            )
            return False
        finally:
            session.close()

    def revoke_certificate(
        self,
        serial_number: int,
        reason: x509.ReasonFlags = x509.ReasonFlags.unspecified,
    ) -> tuple[bool, RevokeStatus]:
        """
        Mark a VALID certificate as revoked and record the reason and timestamp.

        Returns
        -------
        tuple[bool, RevokeStatus]
            ``(True,  RevokeStatus.OK)``            — revocation committed.
            ``(False, RevokeStatus.NOT_FOUND)``     — no VALID cert with that serial.
            ``(False, RevokeStatus.UNKNOWN_ERROR)`` — unexpected internal error.
        """
        session = self._db.session()
        try:
            stmt = select(CertificateRecord).where(
                CertificateRecord.serial_number == str(serial_number),
                CertificateRecord.status == CertificateStatus.VALID,
            )
            cert: CertificateRecord | None = session.execute(stmt).scalar_one_or_none()

            if cert is None:
                self._logger.warning(
                    "revoke_certificate: no VALID record found for serial=%d",
                    serial_number,
                )
                return False, RevokeStatus.NOT_FOUND

            cert.status = CertificateStatus.REVOKED
            cert.revocation_reason = reason.value
            cert.revocation_date = utc_now_naive()

            session.commit()
            self._logger.info(
                "Certificate revoked: serial=%d, reason=%s", serial_number, reason
            )
            return True, RevokeStatus.OK

        except Exception as exc:
            session.rollback()
            self._logger.error(
                "revoke_certificate(%d) failed: %s", serial_number, exc, exc_info=True
            )
            return False, RevokeStatus.UNKNOWN_ERROR
        finally:
            session.close()

    def get_revoked_certificates(self) -> Generator[CertificateRecord, None, None]:
        """
        Yield every revoked certificate that has not yet expired.

        A revoked certificate stays on the CRL until its own ``notAfter``
        passes (RFC 5280 §3.3) — there is **no** age cut-off on the
        revocation date, otherwise a long-lived certificate revoked long ago
        would silently become trusted again.

        Yields
        ------
        Row
            SQLAlchemy rows with ``serial_number``, ``revocation_date`` and
            ``revocation_reason`` attributes.

        Raises
        ------
        DBOperationError
            If the query fails.  The CRL must not be built from a partial or
            empty result in that case.
        """
        now = utc_now_naive()
        session = self._db.session()
        try:
            stmt = select(
                CertificateRecord.serial_number,
                CertificateRecord.revocation_date,
                CertificateRecord.revocation_reason,
            ).where(
                CertificateRecord.revocation_date.isnot(None),
                CertificateRecord.not_valid_after > now,
            )
            rows = session.execute(stmt).all()
        except Exception as exc:
            self._logger.error(
                "get_revoked_certificates failed: %s", exc, exc_info=True
            )
            raise DBOperationError("get_revoked_certificates", exc) from exc
        finally:
            session.close()
        yield from rows  # type: ignore[misc]

    def list_all(
        self,
        status: str | None = None,
        key_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CertificateRecord]:
        """
        Return a paginated list of certificate records with optional filters.

        Returns
        -------
        list[CertificateRecord]
            Records ordered by ``id`` descending.

        Raises
        ------
        DBOperationError
            If the query fails.
        """
        session = self._db.session()
        try:
            stmt = select(CertificateRecord)
            if status is not None:
                stmt = stmt.where(CertificateRecord.status == status)
            if key_type is not None:
                stmt = stmt.where(CertificateRecord.key_type == key_type)
            stmt = stmt.order_by(desc(CertificateRecord.id)).limit(limit).offset(offset)
            rows = session.execute(stmt).scalars().all()
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
        finally:
            session.close()

    def get_expiring(self, within_days: int = 30) -> list[CertificateRecord]:
        """
        Return VALID certificates expiring within *within_days* calendar days.

        Raises
        ------
        DBOperationError
            If the query fails.
        """
        now = utc_now_naive()
        cutoff = now + datetime.timedelta(days=within_days)
        session = self._db.session()
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
            rows = session.execute(stmt).scalars().all()
            self._logger.debug(
                "get_expiring(within_days=%d) → %d rows", within_days, len(rows)
            )
            return list(rows)
        except Exception as exc:
            self._logger.error("get_expiring failed: %s", exc, exc_info=True)
            raise DBOperationError("get_expiring", exc) from exc
        finally:
            session.close()

    def delete_by_uuid(self, uuid: str) -> bool:
        """
        Permanently delete the certificate record identified by *uuid*.

        Returns
        -------
        bool
            ``True`` if a row was deleted; ``False`` otherwise (including errors,
            which are logged).
        """
        session = self._db.session()
        try:
            stmt = delete(CertificateRecord).where(CertificateRecord.uuid == uuid)
            result = session.execute(stmt)
            session.commit()
            deleted = bool(result.rowcount > 0)  # type: ignore[attr-defined]
            self._logger.info("delete_by_uuid(%r) → deleted=%s", uuid, deleted)
            return deleted
        except Exception as exc:
            session.rollback()
            self._logger.error(
                "delete_by_uuid(%r) failed: %s", uuid, exc, exc_info=True
            )
            return False
        finally:
            session.close()

    def update_status_expired(self) -> int:
        """
        Bulk-set status=expired for all VALID certs whose validity has passed.

        Returns
        -------
        int
            Number of rows updated.

        Raises
        ------
        DBOperationError
            If the update fails (the transaction is rolled back).
        """
        now = utc_now_naive()
        session = self._db.session()
        try:
            stmt = (
                update(CertificateRecord)
                .where(
                    CertificateRecord.status == CertificateStatus.VALID,
                    CertificateRecord.not_valid_after < now,
                )
                .values(status=CertificateStatus.EXPIRED)
            )
            result = session.execute(stmt)
            session.commit()
            count = int(result.rowcount)  # type: ignore[attr-defined]
            self._logger.info("update_status_expired: %d rows marked expired", count)
            return count
        except Exception as exc:
            session.rollback()
            self._logger.error("update_status_expired failed: %s", exc, exc_info=True)
            raise DBOperationError("update_status_expired", exc) from exc
        finally:
            session.close()
