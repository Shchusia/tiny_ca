from datetime import datetime
from pathlib import Path

from tiny_ca.settings import DT_STR_FORMAT


class CryptoException(Exception):
    """Raised when certificate validation fails."""

    message: str

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)

    def __str__(self) -> str:
        return f"Error `{self.message}`"


class NotExistCertFile(CryptoException):
    def __init__(
        self,
        path_to_file: Path | str,
    ) -> None:
        message = f"Not found cert file by path `{path_to_file}`"
        super().__init__(message)
        self.message = message


class IsNotFile(CryptoException):
    def __init__(
        self,
        path_to_file: Path | str,
    ) -> None:
        message = f"The specified path `{path_to_file}` does not contain a file "
        super().__init__(message)
        self.message = message


class WrongType(CryptoException):
    def __init__(
        self, wrong_type: str, allowed_types: tuple[str, ...] = (".key", ".pem", ".csr")
    ) -> None:
        message = f"The specified type `{wrong_type}` is invalid for the key. Available types: `{allowed_types}`"
        super().__init__(message)
        self.message = message


class ErrorLoadCert(CryptoException):
    def __init__(self, path_to_file: Path | str, exc: str) -> None:
        message = f"Error in time load cert {path_to_file}. Error: {exc}"
        super().__init__(message)
        self.message = message


class InvalidRangeTimeCertificate(CryptoException):
    def __init__(self, valid_from: datetime, valid_to: datetime, now: datetime) -> None:
        message = f"""The data provided for certificate generation is not valid.
         The desired certificate lifetime is from: `{valid_from.strftime(DT_STR_FORMAT)}`
         to: `{valid_to.strftime(DT_STR_FORMAT)}`; now: `{now.strftime(DT_STR_FORMAT)}`.
          Please specify a valid lifetime.
"""
        super().__init__(message)
        self.message = message


class FileAlreadyExists(CryptoException):
    def __init__(self, path_save_cert: Path) -> None:
        message = (
            f"A certificate at the specified path `{path_save_cert}` already exists."
        )

        super().__init__(message)
        self.message = message


class NotUniqueCertOwner(CryptoException):
    def __init__(self, common_name: str) -> None:
        message = f"Not unique common name - `{common_name}`. Change common_name or use is_overwrite=True"

        super().__init__(message)
        self.message = message


class DBNotInitedError(CryptoException):
    def __init__(self) -> None:
        message = (
            "The action cannot be performed because the database is not initialized."
        )
        super().__init__(message)
        self.message = message


class ValidationCertError(CryptoException):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class CertNotFound(CryptoException):
    def __init__(self) -> None:
        message = "Certificate not found"
        super().__init__(message)
        self.message = message


class DBOperationError(CryptoException):
    """
    Raised when the certificate registry cannot be read or written.

    Database failures are never converted into "not found" / "empty" results:
    for a CA that would mean treating a revoked certificate as valid or
    publishing an empty CRL (fail-open).
    """

    def __init__(self, operation: str, exc: BaseException | str) -> None:
        message = f"Database operation `{operation}` failed: {exc}"
        super().__init__(message)
        self.message = message


class CertRevocationError(CryptoException):
    """Raised when a revocation that an operation depends on did not succeed."""

    def __init__(self, serial: int, reason: str) -> None:
        message = f"Failed to revoke certificate serial={serial}: {reason}"
        super().__init__(message)
        self.message = message


class InvalidPathError(CryptoException, ValueError):
    """Raised when a storage path component would escape the storage root."""

    def __init__(self, value: str) -> None:
        message = f"Unsafe path component `{value}`"
        super().__init__(message)
        self.message = message


class CertificateRevokedError(CryptoException):
    """Raised when an operation is not allowed on a revoked certificate."""

    def __init__(self, serial: int, operation: str) -> None:
        message = f"Cannot {operation} certificate serial={serial}: it is revoked"
        super().__init__(message)
        self.message = message


class SignerError(CryptoException):
    """Raised when an external CA signer (e.g. an HSM) fails or misbehaves."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NameConstraintViolation(ValidationCertError):
    """Raised when a certificate name falls outside an issuer's NameConstraints."""


class AuditLogError(CryptoException):
    """Raised when the audit log cannot be written or fails verification."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message
