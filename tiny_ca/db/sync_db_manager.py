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
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import serialization
from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session, sessionmaker

from tiny_ca.const import CertType
from tiny_ca.settings import DEFAULT_LOGGER

from .base_db import BaseDB
from .const import RevokeStatus
from .models import Base, CertificateRecord, CertificateStatus

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

    def get_by_serial(self, serial: int) -> CertificateRecord | None:
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
            return None
        finally:
            session.close()

    def get_by_name(self, common_name: str) -> CertificateRecord | None:
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
        session = self._db.session()
        try:
            stmt = select(CertificateRecord).where(
                CertificateRecord.common_name == common_name,
                CertificateRecord.status == CertificateStatus.VALID,
            )
            cert: CertificateRecord | None = session.execute(stmt).scalar_one_or_none()
            self._logger.debug("get_by_name(%r) → %s", common_name, cert)
            return cert
        except Exception as exc:
            self._logger.error(
                "get_by_name(%r) failed: %s", common_name, exc, exc_info=True
            )
            return None
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
        session = self._db.session()
        try:
            common_name: str = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
                0
            ].value

            record = CertificateRecord(
                serial_number=str(cert.serial_number),
                common_name=common_name,
                not_valid_before=cert.not_valid_before_utc,
                not_valid_after=cert.not_valid_after_utc,
                certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode(
                    "utf-8"
                ),
                status=CertificateStatus.VALID,
                key_type=key_type.value,
                uuid=uuid,
            )
            session.add(record)
            session.commit()
            self._logger.info(
                "Certificate registered: CN=%r, serial=%s, uuid=%s",
                common_name,
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

    def delete_certificate_by_serial(self, serial: int) -> bool:
        """
        Hard-delete the certificate record identified by *serial*.

        .. warning::
            This permanently removes the row from the database and cannot be
            undone.  For audit-compliant revocation use
            :meth:`revoke_certificate` instead, which retains the record with
            a ``REVOKED`` status and timestamps.

        Parameters
        ----------
        serial : int
            Serial number of the record to delete.

        Returns
        -------
        bool
            ``True`` if at least one row was deleted (i.e. the serial existed).
            ``False`` if no matching row was found, or if the operation failed.
        """
        session = self._db.session()
        try:
            stmt = delete(CertificateRecord).where(
                CertificateRecord.serial_number == str(serial)
            )
            result = session.execute(stmt)
            session.commit()
            deleted = bool(result.rowcount > 0)
            self._logger.info(
                "delete_certificate_by_serial(%d) → deleted=%s", serial, deleted
            )
            return deleted
        except Exception as exc:
            session.rollback()
            self._logger.error(
                "delete_certificate_by_serial(%d) failed: %s",
                serial,
                exc,
                exc_info=True,
            )
        finally:
            session.close()
        return False

    def revoke_certificate(
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
            cert.revocation_reason = reason.value if hasattr(reason, "value") else 0
            cert.revocation_date = datetime.datetime.now(datetime.UTC)

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
        now = datetime.datetime.now(datetime.UTC)
        cutoff = now - datetime.timedelta(days=365)

        session = self._db.session()
        try:
            stmt = select(
                CertificateRecord.serial_number,
                CertificateRecord.revocation_date,
                CertificateRecord.revocation_reason,
            ).where(
                CertificateRecord.revocation_date.isnot(None),
                CertificateRecord.not_valid_after > now,
                CertificateRecord.revocation_date > cutoff,
            )
            rows = session.execute(stmt).all()
            self._logger.debug("get_revoked_certificates → %d rows", len(rows))
            yield from rows
        except Exception as exc:
            self._logger.error(
                "get_revoked_certificates failed: %s", exc, exc_info=True
            )
        finally:
            session.close()
