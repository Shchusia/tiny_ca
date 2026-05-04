"""

Abstract base class that defines the contract for all certificate registry
database adapters.

Any class that inherits from ``BaseDB`` and implements all six abstract methods
can be used wherever the application expects a database layer, without requiring
any changes to the calling code (LSP / DIP).

SOLID notes
-----------
SRP : ``BaseDB`` declares *what* the registry must be able to do; concrete
      subclasses decide *how*.
OCP : New query operations are added by extending ``BaseDB``; existing
      implementations are not modified.
LSP : Every concrete subclass must honour the documented pre- and post-conditions
      of each method so callers can substitute implementations freely.
ISP : The interface is intentionally narrow — only operations that callers
      actually need are declared here.
DIP : High-level modules (e.g. ``CertLifecycleManager``) depend on ``BaseDB``,
      never on ``SyncDBHandler`` or any other concrete implementation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Generator

from cryptography import x509

from tiny_ca.const import CertType

from .models import CertificateRecord


class BaseDB(ABC):
    """
    Abstract contract for the certificate registry database adapter.

    Defines all operations that the application layer requires from the
    persistence tier.  Concrete implementations (e.g. ``SyncDBHandler``)
    provide the actual SQL queries and transaction management.

    All methods that return a ``CertificateRecord`` must return ``None``
    (not raise an exception) when the requested record simply does not exist.
    Exceptions are reserved for genuine infrastructure failures (connection
    errors, constraint violations, etc.).
    """

    @abstractmethod
    def get_by_serial(self, serial: int) -> CertificateRecord | None:
        """
        Retrieve a certificate record by its X.509 serial number.

        Parameters
        ----------
        serial : int
            Integer serial number to look up.  Implementations are responsible
            for any type conversion required by the underlying storage format
            (e.g. converting to ``str`` for string-typed database columns).

        Returns
        -------
        CertificateRecord | None
            The matching record regardless of its current status (VALID,
            REVOKED, EXPIRED), or ``None`` if no record exists for *serial*.
        """

    @abstractmethod
    def get_by_name(self, common_name: str) -> CertificateRecord | None:
        """
        Retrieve the currently active certificate record for a given Common Name.

        Implementations must filter to only ``VALID`` records so that the
        caller always receives the live certificate or ``None`` — never a
        revoked or expired one.

        Parameters
        ----------
        common_name : str
            The CN (Common Name) field from the certificate Subject to look up.

        Returns
        -------
        CertificateRecord | None
            The active VALID record for *common_name*, or ``None`` if no such
            record exists.
        """

    @abstractmethod
    def register_cert_in_db(
        self,
        cert: x509.Certificate,
        uuid: str,
        key_type: CertType = CertType.DEVICE,
    ) -> bool:
        """
        Persist a newly issued certificate to the registry.

        Creates a new record with ``status=VALID`` populated from the
        certificate metadata.  The implementation must extract the CN from
        ``cert.subject`` and store the full PEM encoding for later retrieval.

        Parameters
        ----------
        cert : x509.Certificate
            The issued X.509 certificate object to register.
        uuid : str
            UUID that identifies the filesystem folder containing the
            corresponding ``.pem``, ``.key``, and ``.csr`` artefact files.
        key_type : CertType
            Certificate category (CA, USER, SERVICE, DEVICE, INTERNAL).
            Default: ``CertType.DEVICE``.

        Returns
        -------
        bool
            ``True`` if the record was persisted successfully;
            ``False`` if the operation failed (the implementation must log
            the reason and roll back any partial changes).
        """

    @abstractmethod
    def revoke_certificate(
        self,
        serial_number: int,
        reason: x509.ReasonFlags = x509.ReasonFlags.unspecified,
    ) -> tuple[bool, object]:
        """
        Mark a certificate as revoked and record the reason and timestamp.

        Implementations must:
        1. Look up the record by *serial_number* filtered to ``status=VALID``.
        2. If not found, return ``(False, <NOT_FOUND status>)`` without error.
        3. Update ``status``, ``revocation_reason``, and ``revocation_date``.
        4. Commit atomically; roll back on any exception.

        Parameters
        ----------
        serial_number : int
            Serial number of the certificate to revoke.
        reason : x509.ReasonFlags
            RFC 5280 §5.3.1 revocation reason code.
            Default: ``x509.ReasonFlags.unspecified`` (code 0).

        Returns
        -------
        tuple[bool, object]
            ``(success, status_value)`` where *status_value* is implementation-
            defined (typically a ``RevokeStatus`` enum member).
            ``True`` indicates the revocation was committed; ``False`` means it
            was not (reason encoded in *status_value*).
        """

    @abstractmethod
    def get_revoked_certificates(self) -> Generator[CertificateRecord, None, None]:
        """
        Yield certificate records that should appear in the current CRL.

        Implementations define their own freshness window (e.g. only records
        revoked within the past 365 days and not yet expired), but must yield
        objects that expose at minimum:

        - ``serial_number`` — castable to ``int``
        - ``revocation_date`` — a ``datetime`` object
        - ``revocation_reason`` — an integer RFC 5280 reason code

        Yields
        ------
        CertificateRecord
            Records (or row-like objects) for each revoked certificate that
            falls within the implementation's CRL inclusion window.
        """

    @abstractmethod
    def list_all(
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
            Filter by lifecycle state (``"valid"``, ``"revoked"``,
            ``"expired"``).  ``None`` returns all statuses.
        key_type : str | None
            Filter by certificate category (``"ca"``, ``"service"``,
            ``"device"``, etc.).  ``None`` returns all types.
        limit : int
            Maximum number of records to return.  Default: ``100``.
        offset : int
            Number of records to skip (for pagination).  Default: ``0``.

        Returns
        -------
        list[CertificateRecord]
            Matching records ordered by ``id`` descending (newest first).
            Returns an empty list on error.
        """

    @abstractmethod
    def get_expiring(self, within_days: int = 30) -> list[CertificateRecord]:
        """
        Return VALID certificates that expire within *within_days* calendar days.

        Only records with ``status == VALID`` are considered — already-revoked
        or expired records are excluded.

        Parameters
        ----------
        within_days : int
            Look-ahead window in calendar days.  Default: ``30``.

        Returns
        -------
        list[CertificateRecord]
            Records ordered by ``not_valid_after`` ascending (soonest first).
            Returns an empty list on error.
        """

    @abstractmethod
    def delete_by_uuid(self, uuid: str) -> bool:
        """
        Permanently delete the certificate record identified by *uuid*.

        This is a hard delete — the row is removed from the database.  The
        caller is responsible for also removing the corresponding filesystem
        artefacts via ``BaseStorage.delete_certificate_folder``.

        Parameters
        ----------
        uuid : str
            The storage folder UUID that uniquely identifies the certificate.

        Returns
        -------
        bool
            ``True`` if a row was found and deleted; ``False`` if no matching
            record existed or if a database error occurred.
        """

    @abstractmethod
    def update_status_expired(self) -> int:
        """
        Bulk-update all VALID certificates whose ``not_valid_after`` has passed.

        Sets ``status = "expired"`` for every record where:
        - ``status == "valid"``
        - ``not_valid_after < now (UTC)``

        This method is intended to be called periodically by a background task
        (e.g. a cron job or an APScheduler job) so that status queries reflect
        reality without per-request date comparisons.

        Returns
        -------
        int
            Number of rows updated.  Returns ``0`` on error (after logging).
        """
