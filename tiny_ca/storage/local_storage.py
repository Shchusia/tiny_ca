"""
local_storage.py

Local filesystem implementation of ``BaseStorage``.

Module-level contents
---------------------
``_CertSerializer``  — stateless helper that converts a cryptographic object
                       to raw bytes and determines the correct file extension.
                       Private to this module; not part of the public API.
``LocalStorage``     — concrete ``BaseStorage`` that writes artefacts to
                       a configurable directory tree on the local filesystem.

Security notes
--------------
- Private keys are written with mode ``0600`` (owner read/write only); other
  artefacts with ``0644``.  Files are created with ``O_EXCL`` when
  overwriting is not allowed, so an existing file is never clobbered by a
  race between the existence check and the write.
- Every path component supplied by the caller (``file_name``, ``cert_path``,
  ``uuid_str``) is validated so the resulting path can never escape
  ``base_folder``.
- Private keys are stored unencrypted unless ``base_encryption_algorithm``
  (or a per-call ``encryption_algorithm``) is supplied; a warning is logged
  once per storage instance in that case.

SOLID notes
-----------
SRP : ``_CertSerializer`` is responsible for serialisation only.
      ``LocalStorage``   is responsible for path resolution and file I/O only.
OCP : New crypto object types are handled by adding a branch in
      ``_CertSerializer.serialise`` without modifying ``LocalStorage``.
LSP : ``LocalStorage`` fully honours the ``BaseStorage`` contract, including
      the idempotent-delete and ``FileAlreadyExists`` raise semantics.
DIP : Consumers depend on ``BaseStorage``; ``LocalStorage`` is injected
      at construction time.
"""

from __future__ import annotations

from logging import Logger
import os
from pathlib import Path
import shutil
from uuid import uuid4
import warnings

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from tiny_ca.exc import FileAlreadyExists, InvalidPathError
from tiny_ca.settings import DEFAULT_LOGGER
from tiny_ca.utils.keys import PRIVATE_KEY_TYPES

from .base_storage import BaseStorage
from .const import PRIVATE_FILE_MODE, PUBLIC_FILE_MODE, CryptoObject


class _CertSerializer:
    """
    Converts a ``CryptoObject`` to raw bytes and the matching file extension.

    Supported types
    ~~~~~~~~~~~~~~~
    ======================================= ======== ============================
    Type                                    Ext      Method called
    ======================================= ======== ============================
    ``x509.Certificate``                    ``.pem`` ``public_bytes``
    ``x509.CertificateRevocationList``      ``.pem`` ``public_bytes``
    ``x509.CertificateSigningRequest``      ``.csr`` ``public_bytes``
    RSA / EC / Ed25519 private key          ``.key`` ``private_bytes``
    RSA / EC / Ed25519 public key           ``.pub`` ``public_bytes``
    ======================================= ======== ============================

    Format adjustments
    ~~~~~~~~~~~~~~~~~~
    - Ed25519 private keys cannot be written as ``TraditionalOpenSSL`` — PKCS#8
      is used instead.
    - The ``PKCS1`` public format only exists for RSA — non-RSA public keys
      fall back to ``SubjectPublicKeyInfo``.
    """

    @staticmethod
    def serialise(
        cert: CryptoObject,
        encoding: serialization.Encoding,
        private_format: serialization.PrivateFormat,
        public_format: serialization.PublicFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> tuple[bytes, str]:
        """
        Serialise *cert* to raw bytes and return its file extension.

        Returns
        -------
        tuple[bytes, str]
            ``(raw_bytes, file_extension)`` where *file_extension* is one of
            ``".pem"``, ``".csr"``, ``".key"``, or ``".pub"``.

        Raises
        ------
        TypeError
            If *cert* is not one of the supported cryptographic types.
        """
        if isinstance(cert, (x509.Certificate, x509.CertificateRevocationList)):
            return cert.public_bytes(encoding=encoding), ".pem"
        if isinstance(cert, x509.CertificateSigningRequest):
            return cert.public_bytes(encoding=encoding), ".csr"
        if isinstance(
            cert,
            (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey),
        ):
            if isinstance(cert, ed25519.Ed25519PrivateKey) and (
                private_format is serialization.PrivateFormat.TraditionalOpenSSL
            ):
                private_format = serialization.PrivateFormat.PKCS8
            return (
                cert.private_bytes(
                    encoding=encoding,
                    format=private_format,
                    encryption_algorithm=encryption_algorithm,
                ),
                ".key",
            )
        if isinstance(
            cert,
            (rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey),
        ):
            if not isinstance(cert, rsa.RSAPublicKey) and (
                public_format is serialization.PublicFormat.PKCS1
            ):
                public_format = serialization.PublicFormat.SubjectPublicKeyInfo
            return (
                cert.public_bytes(encoding=encoding, format=public_format),
                ".pub",
            )

        raise TypeError(
            f"Unsupported crypto object type: {type(cert)!r}. "
            "Expected one of: x509.Certificate, x509.CertificateRevocationList, "
            "CertificateSigningRequest, or an RSA / EC / Ed25519 key."
        )


def _validate_component(value: str, *, allow_nested: bool = False) -> str:
    """
    Ensure *value* is a safe relative path component.

    Rejects absolute paths, ``..`` segments, empty names and (unless
    *allow_nested*) path separators.

    Raises
    ------
    InvalidPathError
        If *value* is unsafe.
    """
    text = str(value)
    # Backslashes are separators on Windows; reject them everywhere so the
    # same input behaves identically on every platform.
    if not text or "\x00" in text or "\\" in text:
        raise InvalidPathError(text)
    path = Path(text)
    parts = path.parts
    if path.is_absolute() or path.drive or not parts or ".." in parts:
        raise InvalidPathError(text)
    if not allow_nested and len(parts) != 1:
        raise InvalidPathError(text)
    return text


def _write_bytes(path: Path, data: bytes, is_overwrite: bool, mode: int) -> None:
    """
    Write *data* to *path* with permissions *mode*.

    Missing parent directories are created.  Without *is_overwrite* the file
    is opened with ``O_EXCL`` so an existing file is never replaced.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    if not is_overwrite:
        flags |= os.O_EXCL
    try:
        fd = os.open(path, flags, mode)
    except FileExistsError:
        raise FileAlreadyExists(path_save_cert=path) from None
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    # ``mode`` passed to os.open is filtered by the umask and ignored for
    # pre-existing files — enforce it explicitly.
    os.chmod(path, mode)


class LocalStorage(BaseStorage):
    """
    Local filesystem storage backend for certificate artefacts.

    Each issuance group (certificate + key + CSR) is placed in a dedicated
    UUID subdirectory so that all artefacts for a given certificate can be
    found and deleted together.

    Directory layout
    ~~~~~~~~~~~~~~~~
    ::

        <base_folder>/
        └── [cert_path/]
            └── [<uuid>/]
                ├── <file_name>.pem   # x509.Certificate or CRL
                ├── <file_name>.key   # private key (mode 0600)
                ├── <file_name>.csr   # certificate signing request
                └── <file_name>.pub   # public key (if applicable)

    Parameters
    ----------
    base_folder : str | Path
        Root directory under which all certificates are stored.
        Default: ``"./certs"``.
    base_encoding : serialization.Encoding
        Default encoding for all serialised objects.  Default: PEM.
    base_private_format : serialization.PrivateFormat
        Default format for private-key files.  Default: ``TraditionalOpenSSL``
        (Ed25519 keys always use PKCS#8).
    base_public_format : serialization.PublicFormat
        Default format for public-key files.  Default: ``SubjectPublicKeyInfo``.
    base_encryption_algorithm : serialization.KeySerializationEncryption
        Default encryption applied to private-key files.  Default:
        ``NoEncryption()`` — pass ``BestAvailableEncryption(password)`` in
        production.
    logger : Logger | None
        Logger for diagnostic messages.  Falls back to ``DEFAULT_LOGGER``.
    """

    def __init__(
        self,
        base_folder: str | Path = "./certs",
        base_encoding: serialization.Encoding = serialization.Encoding.PEM,
        base_private_format: serialization.PrivateFormat = serialization.PrivateFormat.TraditionalOpenSSL,
        base_public_format: serialization.PublicFormat = serialization.PublicFormat.SubjectPublicKeyInfo,
        base_encryption_algorithm: serialization.KeySerializationEncryption = serialization.NoEncryption(),
        logger: Logger | None = None,
    ) -> None:
        self._base_folder = Path(base_folder)
        self._base_encoding = base_encoding
        self._base_private_format = base_private_format
        self._base_public_format = base_public_format
        self._base_encryption_algorithm = base_encryption_algorithm
        self._logger = logger or DEFAULT_LOGGER
        self._warned_plaintext_key = False

    def save_certificate(
        self,
        cert: CryptoObject,
        file_name: str,
        cert_path: str | Path | None = None,
        uuid_str: str | None = None,
        encoding: serialization.Encoding | None = None,
        private_format: serialization.PrivateFormat | None = None,
        public_format: serialization.PublicFormat | None = None,
        encryption_algorithm: serialization.KeySerializationEncryption | None = None,
        is_add_uuid: bool = True,
        is_overwrite: bool = False,
    ) -> tuple[Path, str | None]:
        """
        Serialise *cert* and write the result to the local filesystem.

        The output path is::

            <base_folder> / [cert_path/] / [<uuid>/] / <file_name><ext>

        Parameters
        ----------
        cert : CryptoObject
            Cryptographic object to serialise and persist.
        file_name : str
            Base filename without extension (e.g. ``"ca"``, ``"nginx"``).
            Must not contain path separators.
        cert_path : str | Path | None
            Optional relative sub-directory under *base_folder*.
        uuid_str : str | None
            Reuse an existing UUID directory.  ``None`` auto-generates one.
            Ignored when *is_add_uuid* is ``False``.
        encoding, private_format, public_format, encryption_algorithm
            Per-call overrides of the instance defaults.
        is_add_uuid : bool
            When ``True`` (default), a UUID subdirectory is inserted.
        is_overwrite : bool
            When ``True``, replace an existing file; otherwise raise
            ``FileAlreadyExists``.

        Returns
        -------
        tuple[Path, str | None]
            ``(path_to_written_file, uuid_used)``.

        Raises
        ------
        FileAlreadyExists
            If the target exists and *is_overwrite* is ``False``.
        InvalidPathError
            If *file_name*, *cert_path* or *uuid_str* would escape
            *base_folder*.
        TypeError
            If *cert* is not a supported cryptographic type.
        """
        output_path, data, mode, effective_uuid = self._prepare(
            cert=cert,
            file_name=file_name,
            cert_path=cert_path,
            uuid_str=uuid_str,
            encoding=encoding,
            private_format=private_format,
            public_format=public_format,
            encryption_algorithm=encryption_algorithm,
            is_add_uuid=is_add_uuid,
        )
        self._write_file(
            path=output_path, data=data, is_overwrite=is_overwrite, mode=mode
        )
        self._logger.debug(
            "Saved %s → %s (uuid=%s)", type(cert).__name__, output_path, effective_uuid
        )
        return output_path, effective_uuid

    def delete_certificate_folder(
        self,
        uuid_str: str,
        cert_path: str | Path | None = None,
    ) -> bool:
        """
        Recursively remove the directory identified by *uuid_str*.

        The operation is idempotent: if the directory does not exist (or is
        not a directory) a ``UserWarning`` is emitted and ``True`` returned.
        Only a genuine ``OSError`` during removal causes ``False``.

        Raises
        ------
        InvalidPathError
            If *uuid_str* or *cert_path* would escape *base_folder*.
        """
        target = self._delete_target(uuid_str, cert_path)
        if target is None:
            return True
        try:
            shutil.rmtree(target)
            self._logger.info("Deleted certificate folder: %s", target)
            return True
        except OSError as exc:
            self._logger.error(
                "Failed to delete certificate folder %s: %s", target, exc
            )
            return False

    # ------------------------------------------------------------------
    # Helpers shared with AsyncLocalStorage
    # ------------------------------------------------------------------

    def _prepare(
        self,
        cert: CryptoObject,
        file_name: str,
        cert_path: str | Path | None,
        uuid_str: str | None,
        encoding: serialization.Encoding | None,
        private_format: serialization.PrivateFormat | None,
        public_format: serialization.PublicFormat | None,
        encryption_algorithm: serialization.KeySerializationEncryption | None,
        is_add_uuid: bool,
    ) -> tuple[Path, bytes, int, str | None]:
        """Resolve the output path and serialise *cert* (no I/O)."""
        _validate_component(file_name)
        output_dir, effective_uuid = self._resolve_output_dir(
            cert_path=cert_path,
            uuid_str=uuid_str,
            is_add_uuid=is_add_uuid,
        )
        effective_encryption = encryption_algorithm or self._base_encryption_algorithm
        data, extension = _CertSerializer.serialise(
            cert=cert,
            encoding=encoding or self._base_encoding,
            private_format=private_format or self._base_private_format,
            public_format=public_format or self._base_public_format,
            encryption_algorithm=effective_encryption,
        )
        is_private = isinstance(cert, PRIVATE_KEY_TYPES)
        if (
            is_private
            and isinstance(effective_encryption, serialization.NoEncryption)
            and not self._warned_plaintext_key
        ):
            self._warned_plaintext_key = True
            self._logger.warning(
                "Private keys are stored unencrypted (mode 0600). Pass "
                "base_encryption_algorithm=BestAvailableEncryption(password) "
                "to LocalStorage to encrypt them at rest."
            )
        mode = PRIVATE_FILE_MODE if is_private else PUBLIC_FILE_MODE
        return output_dir / f"{file_name}{extension}", data, mode, effective_uuid

    def _resolve_output_dir(
        self,
        cert_path: str | Path | None,
        uuid_str: str | None,
        is_add_uuid: bool,
    ) -> tuple[Path, str | None]:
        """
        Compute the directory path where the certificate file will be written.

        Builds ``base_folder / [cert_path] / [uuid]``.  The UUID is taken from
        *uuid_str* if provided, otherwise a new UUID4 string is generated.
        When *is_add_uuid* is ``False`` the second return value is ``None``.

        Raises
        ------
        InvalidPathError
            If *cert_path* or *uuid_str* would escape *base_folder*.
        """
        directory = self._base_folder
        if cert_path:
            directory = directory / _validate_component(
                str(cert_path), allow_nested=True
            )

        effective_uuid: str | None = None
        if is_add_uuid:
            effective_uuid = uuid_str or str(uuid4())
            directory = directory / _validate_component(effective_uuid)

        return directory, effective_uuid

    def _delete_target(
        self, uuid_str: str, cert_path: str | Path | None
    ) -> Path | None:
        """Validated folder to delete, or ``None`` (with a warning) if absent."""
        target = self._base_folder
        if cert_path:
            target = target / _validate_component(str(cert_path), allow_nested=True)
        target = target / _validate_component(uuid_str)

        if not target.exists():
            warnings.warn(
                f"Certificate folder not deleted — path does not exist: {target}",
                UserWarning,
                stacklevel=3,
            )
            return None

        if not target.is_dir():
            warnings.warn(
                f"Certificate folder not deleted — path is not a directory: {target}",
                UserWarning,
                stacklevel=3,
            )
            return None
        return target

    def _write_file(
        self,
        path: Path,
        data: bytes,
        is_overwrite: bool,
        mode: int = PUBLIC_FILE_MODE,
    ) -> None:
        """
        Write *data* to *path*, creating any missing parent directories.

        Raises
        ------
        FileAlreadyExists
            If *path* already exists on disk and *is_overwrite* is ``False``.
        """
        _write_bytes(path, data, is_overwrite, mode)
        self._logger.debug("Written %d bytes → %s", len(data), path)
