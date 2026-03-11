"""
db/const.py

Shared constants for the database layer.

Currently exports ``RevokeStatus``, the value object that encodes the
possible outcomes of a certificate revocation attempt.  Keeping it in a
dedicated module prevents circular imports between ``base_db``, the ORM
models, and the concrete handler implementations.
"""

from __future__ import annotations

from enum import Enum


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
