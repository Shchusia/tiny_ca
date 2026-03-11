"""
db/const.py

Shared constants for the database layer.

Currently exports ``RevokeStatus``, the value object that encodes the
possible outcomes of a certificate revocation attempt.  Keeping it in a
dedicated module prevents circular imports between ``base_db``, the ORM
models, and the concrete handler implementations.
"""

from __future__ import annotations

from enum import Enum, StrEnum


class RevokeStatus(Enum):
    """
    Enumerated outcomes for a certificate revocation attempt.

    Used as the second element of the ``(bool, RevokeStatus)`` tuple returned
    by ``BaseDB.revoke_certificate`` implementations.  The boolean indicates
    overall success; this enum provides the machine-readable reason when the
    operation did not succeed, and a confirmation token when it did.

    Members
    -------
    NOT_FOUND :
        No active (``VALID``) certificate with the requested serial number
        exists in the registry.  The certificate may already be revoked,
        expired, or was never registered.
    UNKNOWN_ERROR :
        An unexpected internal error (e.g. database constraint violation,
        connection failure) prevented the revocation.  The implementation must
        log the underlying exception before returning this status.
    OK :
        The revocation was committed successfully.  The certificate record has
        been updated with ``status=REVOKED``, a ``revocation_date``, and the
        provided ``revocation_reason``.

    Examples
    --------
    >>> success, status = db.revoke_certificate(serial=12345, reason=ReasonFlags.key_compromise)
    >>> if not success:
    ...     if status == RevokeStatus.NOT_FOUND:
    ...         logger.warning("Certificate not found")
    ...     else:
    ...         logger.error("Internal revocation error")
    """

    NOT_FOUND = (
        "The certificate was not revoked because there is no valid certificate "
        "with the specified serial number."
    )
    UNKNOWN_ERROR = (
        "The certificate was not revoked due to an internal error. "
        "Please review the service logs."
    )
    OK = "success"


class CertificateStatus(StrEnum):
    """
    Lifecycle state of a certificate record in the registry.

    Stored as a lowercase string in the ``status`` column of
    ``CertificateRecord`` so the value is human-readable in raw SQL output.

    Members
    -------
    VALID :
        The certificate was issued successfully and has not been revoked or
        expired.  Active certificates used for authentication or encryption
        are expected to be in this state.
    REVOKED :
        The certificate was explicitly revoked before its natural expiry.
        The ``revocation_date`` and ``revocation_reason`` columns on the
        corresponding ``CertificateRecord`` row must be non-null.
    EXPIRED :
        The certificate's ``not_valid_after`` date has passed.  This status
        may be set by a background job; alternatively, callers can detect
        expiry by comparing ``not_valid_after`` to the current time.
    UNKNOWN :
        The status could not be determined, typically because no record was
        found for the requested serial number.  Used as a safe sentinel value
        by ``CertLifecycleManager.get_certificate_status``.
    """

    VALID = "valid"
    REVOKED = "revoked"
    EXPIRED = "expired"
    UNKNOWN = "unknown"
