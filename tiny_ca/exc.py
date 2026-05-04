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
