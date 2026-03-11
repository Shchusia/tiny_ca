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
    def delete_certificate_by_serial(self, serial: int) -> bool:
        """
        Permanently remove the certificate record identified by *serial*.

        .. warning::
            This is a hard delete that cannot be undone.  For audit-compliant
            workflows use :meth:`revoke_certificate` instead, which retains
            the record with a ``REVOKED`` status.

        Parameters
        ----------
        serial : int
            Serial number of the record to delete.

        Returns
        -------
        bool
            ``True`` if at least one row was deleted (i.e. *serial* existed).
            ``False`` if no matching record was found or the operation failed.
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
