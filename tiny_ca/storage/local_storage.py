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

SOLID notes
-----------
SRP : ``_CertSerializer`` is responsible for serialisation only.
      ``LocalStorage``   is responsible for path resolution and file I/O only.
      Neither class performs cryptographic operations or database access.
OCP : New crypto object types are handled by adding a branch in
      ``_CertSerializer.serialise`` without modifying ``LocalStorage``.
LSP : ``LocalStorage`` fully honours the ``BaseStorage`` contract, including
      the idempotent-delete and ``FileAlreadyExists`` raise semantics.
DIP : Consumers depend on ``BaseStorage``; ``LocalStorage`` is injected
      at construction time.
"""

from __future__ import annotations

from logging import Logger
from pathlib import Path
import shutil
from uuid import uuid4
import warnings

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tiny_ca.exc import FileAlreadyExists
from tiny_ca.settings import DEFAULT_LOGGER

from .base_storage import BaseStorage
from .const import CryptoObject

# ---------------------------------------------------------------------------
# SRP: serialisation logic isolated from storage logic
# ---------------------------------------------------------------------------


class _CertSerializer:
    """
    Converts a ``CryptoObject`` to raw bytes and the matching file extension.

    This is a private, stateless helper used exclusively by ``LocalStorage``.
    Isolating serialisation here keeps ``LocalStorage`` free of type-dispatch
    logic and makes it trivial to add support for new cryptographic types
    (OCP: add one branch here, nothing else changes).

    Supported types
    ~~~~~~~~~~~~~~~
    ======================================= ======== ============================
    Type                                    Ext      Method called
    ======================================= ======== ============================
    ``x509.Certificate``                    ``.pem`` ``public_bytes``
    ``x509.CertificateRevocationList``      ``.pem`` ``public_bytes``
    ``CertificateSigningRequest`` (Rust)    ``.csr`` ``public_bytes``
    ``rsa.RSAPrivateKey``                   ``.key`` ``private_bytes``
    ``rsa.RSAPublicKey``                    ``.pub`` ``public_bytes``
    ======================================= ======== ============================
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

        Dispatches to the appropriate serialisation method based on the
        runtime type of *cert*.  All format/encoding parameters are passed
        through regardless of type; the ones irrelevant to the object type
        (e.g. *private_format* for a certificate) are silently ignored by the
        cryptography library's own methods.

        Parameters
        ----------
        cert : CryptoObject
            The cryptographic object to serialise.
        encoding : serialization.Encoding
            Target encoding, e.g. ``Encoding.PEM`` or ``Encoding.DER``.
        private_format : serialization.PrivateFormat
            Format for RSA private-key output
            (``TraditionalOpenSSL`` / ``PKCS8``).
        public_format : serialization.PublicFormat
            Format for RSA public-key output
            (``SubjectPublicKeyInfo`` / ``PKCS1``).
        encryption_algorithm : serialization.KeySerializationEncryption
            Encryption wrapper applied to private-key output
            (``NoEncryption`` / ``BestAvailableEncryption``).

        Returns
        -------
        tuple[bytes, str]
            ``(raw_bytes, file_extension)`` where *file_extension* is one of
            ``".pem"``, ``".csr"``, ``".key"``, or ``".pub"``, including the
            leading dot.

        Raises
        ------
        TypeError
            If *cert* is not one of the five supported cryptographic types.
        """
        if isinstance(cert, (x509.Certificate, x509.CertificateRevocationList)):
            return cert.public_bytes(encoding=encoding), ".pem"

        if isinstance(
            cert,
            cryptography.hazmat.bindings._rust.x509.CertificateSigningRequest,
        ):
            return cert.public_bytes(encoding=encoding), ".csr"

        if isinstance(cert, rsa.RSAPrivateKey):
            return (
                cert.private_bytes(
                    encoding=encoding,
                    format=private_format,
                    encryption_algorithm=encryption_algorithm,
                ),
                ".key",
            )

        if isinstance(cert, rsa.RSAPublicKey):
            return cert.public_bytes(encoding=encoding, format=public_format), ".pub"

        raise TypeError(
            f"Unsupported crypto object type: {type(cert)!r}. "
            "Expected one of: x509.Certificate, x509.CertificateRevocationList, "
            "CertificateSigningRequest, rsa.RSAPrivateKey, rsa.RSAPublicKey."
        )


# ---------------------------------------------------------------------------
# SRP: filesystem persistence
# ---------------------------------------------------------------------------


class LocalStorage(BaseStorage):
    """
    Local filesystem storage backend for certificate artefacts.

    Writes serialised cryptographic objects to a configurable directory tree.
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
                ├── <file_name>.key   # RSA private key
                ├── <file_name>.csr   # certificate signing request
                └── <file_name>.pub   # RSA public key (if applicable)

    Parameters
    ----------
    base_folder : str | Path
        Root directory under which all certificates are stored.  The directory
        is created on first write if it does not exist.
        Default: ``"./certs"``.
    base_encoding : serialization.Encoding
        Default encoding for all serialised objects.
        Default: ``Encoding.PEM``.
    base_private_format : serialization.PrivateFormat
        Default format for RSA private-key files.
        Default: ``PrivateFormat.TraditionalOpenSSL`` (PKCS#1, OpenSSL-compatible).
    base_public_format : serialization.PublicFormat
        Default format for RSA public-key files.
        Default: ``PublicFormat.SubjectPublicKeyInfo`` (PKCS#8 / X.509 SubjectPublicKeyInfo).
    base_encryption_algorithm : serialization.KeySerializationEncryption
        Default encryption applied to private-key files.
        Default: ``NoEncryption()`` — keys are stored in plaintext.
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

    # ------------------------------------------------------------------
    # BaseStorage interface
    # ------------------------------------------------------------------

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

        Assembles the output path as::

            <base_folder> / [cert_path/] / [<uuid>/] / <file_name><ext>

        Where *ext* is determined automatically from the type of *cert*.

        Parameters
        ----------
        cert : CryptoObject
            Cryptographic object to serialise and persist.
        file_name : str
            Base filename without extension (e.g. ``"ca"``, ``"nginx"``).
        cert_path : str | Path | None
            Optional sub-directory appended after *base_folder*.
        uuid_str : str | None
            Reuse an existing UUID directory by passing the value returned by
            a previous ``save_certificate`` call.  ``None`` auto-generates a
            new UUID.  Ignored when *is_add_uuid* is ``False``.
        encoding : serialization.Encoding | None
            Encoding override.  ``None`` uses *base_encoding*.
        private_format : serialization.PrivateFormat | None
            Private-key format override.  ``None`` uses *base_private_format*.
        public_format : serialization.PublicFormat | None
            Public-key format override.  ``None`` uses *base_public_format*.
        encryption_algorithm : serialization.KeySerializationEncryption | None
            Private-key encryption override.  ``None`` uses
            *base_encryption_algorithm*.
        is_add_uuid : bool
            When ``True`` (default), a UUID subdirectory is inserted.
            Set to ``False`` for singleton files such as CRL that are
            regenerated in-place.
        is_overwrite : bool
            When ``True``, silently replace an existing file.
            When ``False`` (default), raise ``FileAlreadyExists``.

        Returns
        -------
        tuple[Path, str | None]
            ``(absolute_path_to_written_file, uuid_used)``.
            *uuid_used* is ``None`` when *is_add_uuid* is ``False``.

        Raises
        ------
        FileAlreadyExists
            If the computed target path already exists and *is_overwrite*
            is ``False``.
        TypeError
            If *cert* is not a supported cryptographic type.
        """
        output_dir, effective_uuid = self._resolve_output_dir(
            cert_path=cert_path,
            uuid_str=uuid_str,
            is_add_uuid=is_add_uuid,
        )

        cert_data, extension = _CertSerializer.serialise(
            cert=cert,
            encoding=encoding or self._base_encoding,
            private_format=private_format or self._base_private_format,
            public_format=public_format or self._base_public_format,
            encryption_algorithm=encryption_algorithm
            or self._base_encryption_algorithm,
        )

        output_path = output_dir / f"{file_name}{extension}"
        self._write_file(path=output_path, data=cert_data, is_overwrite=is_overwrite)

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

        The target path is resolved as::

            <base_folder> / [cert_path/] / <uuid_str>

        The operation is idempotent: if the directory does not exist a
        ``UserWarning`` is emitted and ``True`` is returned (no action needed).
        If the path exists but is a regular file rather than a directory, a
        ``UserWarning`` is emitted and ``True`` is returned (not our directory).
        Only a genuine ``OSError`` during ``shutil.rmtree`` causes ``False``.

        Parameters
        ----------
        uuid_str : str
            UUID sub-directory name to remove.
        cert_path : str | Path | None
            Optional sub-path under *base_folder* containing *uuid_str*.

        Returns
        -------
        bool
            ``True``  — directory removed, or path was already absent.
            ``False`` — ``OSError`` occurred; check logs for details.

        Warns
        -----
        UserWarning
            If the target path does not exist or is not a directory.
        """
        target = self._base_folder
        if cert_path:
            target = target / cert_path
        target = target / uuid_str

        if not target.exists():
            warnings.warn(
                f"Certificate folder not deleted — path does not exist: {target}",
                UserWarning,
                stacklevel=2,
            )
            return True

        if not target.is_dir():
            warnings.warn(
                f"Certificate folder not deleted — path is not a directory: {target}",
                UserWarning,
                stacklevel=2,
            )
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
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_output_dir(
        self,
        cert_path: str | Path | None,
        uuid_str: str | None,
        is_add_uuid: bool,
    ) -> tuple[Path, str | None]:
        """
        Compute the directory path where the certificate file will be written.

        Builds the path incrementally:
        1. Start from *base_folder*.
        2. Append *cert_path* if provided.
        3. Append a UUID segment if *is_add_uuid* is ``True``.

        The UUID is taken from *uuid_str* if provided, otherwise a new UUID4
        string is generated.  When *is_add_uuid* is ``False`` the second return
        value is always ``None``.

        Parameters
        ----------
        cert_path : str | Path | None
            Optional sub-path under *base_folder*.
        uuid_str : str | None
            Explicit UUID for the sub-directory, or ``None`` to auto-generate.
        is_add_uuid : bool
            Whether to append a UUID segment to the path.

        Returns
        -------
        tuple[Path, str | None]
            ``(resolved_output_directory, uuid_used_or_None)``.
        """
        directory = self._base_folder
        if cert_path:
            directory = directory / cert_path

        effective_uuid: str | None = None
        if is_add_uuid:
            effective_uuid = uuid_str or str(uuid4())
            directory = directory / effective_uuid

        return directory, effective_uuid

    def _write_file(self, path: Path, data: bytes, is_overwrite: bool) -> None:
        """
        Write *data* to *path*, creating any missing parent directories.

        Parent directories are created with ``mkdir(parents=True,
        exist_ok=True)`` so the caller never needs to pre-create the
        directory tree manually.

        Parameters
        ----------
        path : Path
            Absolute target path for the output file.
        data : bytes
            Raw serialised bytes to write.
        is_overwrite : bool
            When ``False``, raise ``FileAlreadyExists`` if *path* already
            exists.  When ``True``, the existing file is silently replaced.

        Raises
        ------
        FileAlreadyExists
            If *path* already exists on disk and *is_overwrite* is ``False``.
        """
        if path.exists() and not is_overwrite:
            raise FileAlreadyExists(path_save_cert=path)

        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "wb") as fh:
            fh.write(data)

        self._logger.debug("Written %d bytes → %s", len(data), path)
